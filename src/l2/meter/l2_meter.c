/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <netinet/in.h>
#include <rte_time.h>
#include <time.h>

#include "dpdk.h"
#include "baseype.h"
#include "conf/common.h"
#include "conf/inet.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "ether_input.h"
#include "l3_node_priv.h"
#include "l2.h"

#include "../../access_control/secpolicy_common.h"
#include "../../access_control/secpolicy_match.h"

/*
 * Traffic metering configuration
 *
 */
#define METER_HTABLE_NAME_SIZE            32
#define METER_HTABLE_ENTRIES              256

#define APP_MODE_FWD                    0
#define APP_MODE_SRTCM_COLOR_BLIND      1
#define APP_MODE_SRTCM_COLOR_AWARE      2
#define APP_MODE_TRTCM_COLOR_BLIND      3
#define APP_MODE_TRTCM_COLOR_AWARE      4

#define APP_MODE	APP_MODE_SRTCM_COLOR_BLIND

#define TYPE_AUTO 0
#define TYPE_SPECFY 1


#include "../include/l2_meter.h"

#define APP_PKT_FLOW_POS                33
#define APP_PKT_COLOR_POS               5


enum l2_policer_action l2_policer_table[RTE_COLORS] = {
    [RTE_COLOR_GREEN] = GREEN,
    [RTE_COLOR_YELLOW] = YELLOW,
    [RTE_COLOR_RED] = DROP
};

#if APP_PKT_FLOW_POS > 64 || APP_PKT_COLOR_POS > 64
#error Byte offset needs to be less than 64
#endif

//单速率三颜色标记
struct rte_meter_srtcm_params app_srtcm_params = {
	.cir = 1000000 * 46, // 令牌桶每秒增加的令牌数量，单位字节
	.cbs = 2048, // 令牌桶C的最大大小
	.ebs = 2048 // 令牌桶E的最大大小
};

/*
颜色有三种：绿、黄、红。简单来说，颜色与参数的对应关系是这样的：

    如果没有超过CBS就是绿的。
    超过了CBS但没有超过EBS就是黄的。
    超过了EBS就是红的。

算法流程图：
               +------------+
                |   Result   |
                |            V
            +-------+    +--------+
            |       |    |        |
Packet Stream ===>| Meter |===>| Marker |===> Marked Stream
            |       |    |        |
            +-------+    +--------+
Meter（限速器）用于限速，具体的逻辑因不同的具体设定而异（例如，红色丢包，黄色正常发送，绿色往特定队列发送等）。
而且Meter会对每一个packet进行计算，将得到的结果交给Marker（标记器）。Marker收到的是每一个packet和其对应的结果值，
根据计算结果在所有packet的IP header的DS field中标记上不同的“颜色”（上色，mark，或者说tag）。

Meter有两种工作模式：

色盲模式（Color-Blind mode），假定所有incoming packet是无色的。
非色盲模式（Color-Aware mode），假定所有incoming packet已经被先前的网络元素上了色。
如果Meter工作在非色盲模式，它会认为每一个packet都有一种颜色，要么绿要么黄要么红。

Meter动作由两个令牌桶来表示（C和E）。C和E有共同的CIR。令牌桶的C的size是CBS，E的size是EBS。
用Tc(t)表示t时刻，令牌桶C中有的令牌数量，Te(t)同理。起始时，Tc(0)=CBS，Te(0)=EBS。

If Tc is less than CBS, Tc is incremented by one, else
if Te is less then EBS, Te is incremented by one, else
neither Tc nor Te is incremented.
Meter的工作算法如下：

如果工作在色盲模式下，且大小为B字节的包在t时间到达，算法工作如下：若令牌桶C足以让B通过，则tag此包为绿色，
并减去对应的Tc；若C不足以让B通过而E足以让B通过，则tag此包为黄色，并减去对应的Te；否则tag此包为红色。

If Tc(t)-B >= 0, the packet is green and Tc is decremented by B down to the minimum value of 0, else
if Te(t)-B >= 0, the packets is yellow and Te is decremented by B down to the minimum value of 0, else
the packet is red and neither Tc nor Te is decremented.

如果工作在非色盲模式下，大小为B字节的包在t时间到达，算法工作如下：若包先前tag成绿色，且令牌桶C足以让B通过，
则此包依旧tag成绿色，减去对应的Tc；若令牌桶C不足以让B通过，且该包先前tag的是绿色或黄色，且令牌桶E足以让B通过，
就tag成黄色，并减去对应的Te；否则（两种情况：先前此包tag成红色或令牌桶E不足以让B通过）tag为红色。

If the packet has been precolored as green and Tc(t)-B >= 0, the packet is green and Tc is decremented by B down to the minimum value of 0, else
If the packet has been precolored as green or yellow and if Te(t)-B >= 0, the packets is yellow and Te is decremented by B down to the minimum value of 0, else
the packet is red and neither Tc nor Te is decremented.

*/

struct rte_meter_srtcm_profile app_srtcm_profile;

//双速率三颜色标记
/*
四个参数
    Peak Information Rate (PIR)，峰值信息率。
    Peak Burst Size (PBS)，峰值Burst大小。
    Committed Information Rate (CIR)，提交信息率。
    Committed Burst Size (CBS)，提交Burst大小。
    PIR和CIR用于表示每秒IP包的字节数。PBS和CBS以字节为单位，必须大于0，推荐设置成大于当前路径MTU。
*/
struct rte_meter_trtcm_params app_trtcm_params = {
	.cir = 100000 * 46, // 令牌桶C的增长速率，单位字节每秒
	.pir = 150000 * 46, // 令牌桶P的增长速率
	.cbs = 2048, // 令牌桶C的最大大小
	.pbs = 2048 // 令牌桶P的最大大小
};
/*
Meter同样分为色盲模式和非色盲模式。

由两个令牌桶来表示，P和C。P和C的速率分别是PIR和CIR，大小分别是PBS和CBS。起始时，Tp(0)=PBS，Tc(0)=CBS。
之后，若令牌桶没满，则桶P递增1，每秒PIR次。桶C递增1，每秒CIR次。

工作算法如下：

如果工作在色盲模式下，且大小为B字节的包在t时间到达，算法工作如下：
若令牌桶P不足以让B通过，则tag为红色，否则：若令牌桶C不足以让B通过，
则tag为黄色且扣除桶P的令牌；若令牌桶C足以让B通过，则tag为绿色且同时扣除桶C和桶P的令牌。

If Tp(t)-B < 0, the packet is red, else
if Tc(t)-B < 0, the packet is yellow and Tp is decremented by B, else
the packet is green and both Tp and Tc are decremented by B.
如果工作在非色盲模式下，大小为B字节的包在t时间到达，算法工作如下：若先前tag成红色，
或令牌桶P不足以让B通过，则tag为红色，否则：若先前tag成黄色，或令牌桶C不足以让B通过，则tag为黄色且扣除桶P的令牌；若令牌桶C足以让B通过且先前标记成绿色，则tag为绿色且同时扣除桶C和桶P的令牌。

If the packet has been precolored as red or if Tp(t)-B < 0, the packet is red, else
if the packet has been precolored as yellow or if Tc(t)-B < 0, the packet is yellow and Tp is decremented by B, else
the packet is green and both Tp and Tc are decremented by B.

可以看出srTCM算法是根据 length of burst 来进行限速的。“单速率”指的是这个算法里两个令牌桶的增长速率都是一样的每秒CIR。
两个令牌桶拥有不同的大小，就好像一条数轴用两个点分成了三个阶段，对应绿、黄、红。

trTCM的“双速率”是指两个令牌桶有不同的增长速率。
增长的较慢的令牌桶是发放绿色标记的较为严苛的指标，增长的较快的令牌桶是一个下限，若这个令牌桶也handle不过来的流量就要无情的tag为红色，
两者之间的就是黄色。

*/
struct rte_meter_trtcm_profile app_trtcm_profile;

#define APP_FLOWS_MAX  256

// 一种flow对应一组令牌桶。
FLOW_METER app_flows[APP_FLOWS_MAX];
uint64_t g_clock_hz;
BOOL_T g_muti_thread = BOOL_FALSE;

BOOL_T isMutiThread(void){
    return g_muti_thread;
}
struct meter_hash_key {
	 UCHAR  szTenantID[TENANT_ID_MAX+1];
};

struct rte_hash *g_meter_htable = NULL;

rte_spinlock_t	 g_meter_lock;

struct meter_table_entry
{
    UCHAR  szTenantID[TENANT_ID_MAX+1];
    uint32_t bandwith;
    struct rte_meter_srtcm flow_meter_table;
    struct rte_meter_srtcm_profile strcm_profile;
    struct rte_meter_srtcm_params srtcm_params;
    unsigned char  type;
};

struct meter_table_cfg
{
    uint32_t flow_id;
    UCHAR  szTenantID[TENANT_ID_MAX+1];
    uint32_t bandwith;
    struct rte_meter_srtcm_profile srtcm_profile;
    struct rte_meter_srtcm_params srtcm_params;
    unsigned char  type;
};

static inline void
meter_key_init(struct meter_hash_key *key, UCHAR *pucTenantID)
{
    memset(key->szTenantID, 0, sizeof(key->szTenantID));
	strlcpy(key->szTenantID, pucTenantID, TENANT_ID_MAX+1);
}

/*int smp case, the clock source is per-cpu,  
so the the of muti-threads is not synchornized. As a result,  
the function of rate-limiting fails. 

To solve this problem, 
we must abandon the TSC clock and use the system call getTime instead .*/
int
l2_get_clock_freq(void)
{

#define L2_NS_PER_SEC 1E9
#define L2_CYC_PER_10MHZ 1E7

	struct timespec sleeptime = {.tv_nsec = L2_NS_PER_SEC / 10 }; /* 1/10 second */

	struct timespec t_start, t_end;
    uint64_t ns;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &t_start) == 0) {
		nanosleep(&sleeptime, NULL);
		clock_gettime(CLOCK_MONOTONIC_RAW, &t_end);
		
		ns = ((t_end.tv_sec - t_start.tv_sec) * L2_NS_PER_SEC);
		ns += (t_end.tv_nsec - t_start.tv_nsec);

        g_clock_hz = ns;
		g_clock_hz *= 10;

		/* Round up to 10Mhz. 1E7 ~ 10Mhz */
	    g_clock_hz = RTE_ALIGN_MUL_NEAR(g_clock_hz, L2_CYC_PER_10MHZ);
        return 0;
	}
	return -1;
}


#ifndef L2_METER_TB_PERIOD_MIN
#define L2_METER_TB_PERIOD_MIN      100
#endif

unsigned int my_strlcpy(unsigned char *dst, const unsigned char *src, unsigned int siz)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    unsigned int n = siz;

    /* Copy as many bytes as will fit */
    if (n != 0) {
         while (--n != 0) {
            if ((*d++ = *s++) == '\0')
                break;
        }
    }

    /* Not enough room in dst, add NUL and traverse rest of src */
    if (n == 0) {
        if (siz != 0)
            *d = '\0';                /* NUL-terminate dst */
        while (*s++)
            ;
    }

    return(s - src - 1);        /* count does not include NUL */
}

static void
l2_meter_get_tb_params(uint64_t hz, uint64_t rate, uint64_t *tb_period, uint64_t *tb_bytes_per_period)
{
	double period;

	if (rate == 0) {
		*tb_bytes_per_period = 0;
		*tb_period = L2_METER_TB_PERIOD_MIN;
		return;
	}

	period = ((double) hz) / ((double) rate);

	if (period >= L2_METER_TB_PERIOD_MIN) {
		*tb_bytes_per_period = 1;
		*tb_period = (uint64_t) period;
	} else {
		*tb_bytes_per_period = (uint64_t) ceil(L2_METER_TB_PERIOD_MIN / period);
		*tb_period = (hz * (*tb_bytes_per_period)) / rate;
	}
}

int
l2_meter_srtcm_profile_config(struct rte_meter_srtcm_profile *p,
	struct rte_meter_srtcm_params *params)
{
    uint64_t hz = rte_get_tsc_hz();
	/* Check input parameters */
	if ((p == NULL) ||
		(params == NULL) ||
		(params->cir == 0) ||
		((params->cbs == 0) && (params->ebs == 0)))
		return -EINVAL;

    if(BOOL_TRUE == isMutiThread()){
        hz = g_clock_hz;
    }
    
	/* Initialize srTCM run-time structure */
	p->cbs = params->cbs;
	p->ebs = params->ebs;
	l2_meter_get_tb_params(hz, params->cir, &p->cir_period,
		&p->cir_bytes_per_period);

	return 0;
}

int
l2_meter_srtcm_config_muti(struct rte_meter_srtcm *m,
	struct rte_meter_srtcm_profile *p)
{
    struct timespec time;
    uint64_t current_time;
	/* Check input parameters */
	if ((m == NULL) || (p == NULL))
		return -EINVAL;

    clock_gettime(CLOCK_MONOTONIC, &time);
    current_time = rte_timespec_to_ns(&time);
	/* Initialize srTCM run-time structure */
	m->time = current_time;
	m->tc = p->cbs;
	m->te = p->ebs;

	return 0;
}

int
l2_meter_srtcm_config_single(struct rte_meter_srtcm *m, struct rte_meter_srtcm_profile *p)
{
	/* Check input parameters */
	if ((m == NULL) || (p == NULL))
		return -EINVAL;

	/* Initialize srTCM run-time structure */
	m->time = rte_get_tsc_cycles();
	m->tc = p->cbs;
	m->te = p->ebs;

	return 0;
}

int
l2_meter_srtcm_config(struct rte_meter_srtcm *m, struct rte_meter_srtcm_profile *p)
{
    if(BOOL_TRUE == isMutiThread()){
        return l2_meter_srtcm_config_muti(m, p);
    }else{
        return l2_meter_srtcm_config_single(m, p);
    }
}

/* Find a rule */
static inline int
meter_table_entry_find_with_key(const struct meter_hash_key *hash_key,
		  struct meter_table_entry **entry)
{
	void *hash_val;
	int ret;

	/* lookup for a rule */
	ret = rte_hash_lookup_data(g_meter_htable, (const void *) hash_key,
		(void **) &hash_val);
	if (ret >= 0) {
		*entry = (struct meter_table_entry *) hash_val;
		return 1;
	}

	return 0;
}

static struct meter_table_entry *meter_table_entry_find(UCHAR *pucTenantID)
{
	struct meter_table_entry *entry;
	struct meter_hash_key hash_key;
	int find=0;
	
	meter_key_init(&hash_key, pucTenantID);
	find = meter_table_entry_find_with_key(&hash_key, &entry);
	if(find != 0)
		return entry;
	else
		return NULL;
}

static struct meter_table_entry *_meter_entry_create(struct meter_table_cfg *cfg){
	struct meter_table_entry *entry;
    int ret = 0;
	entry = (struct meter_table_entry *)rte_malloc(NULL, sizeof(struct meter_table_entry), 0);
	if (entry) {
        strlcpy(entry->szTenantID, cfg->szTenantID, TENANT_ID_MAX+1);
        entry->bandwith = cfg->bandwith;
        entry->type = cfg->type;
	}

    ret = l2_meter_srtcm_config(&entry->flow_meter_table, &cfg->srtcm_profile);
    if(ret != 0){
        rte_free(entry);
        entry = NULL;
    }

    memcpy(&entry->strcm_profile, &cfg->srtcm_profile, sizeof(entry->strcm_profile));
    memcpy(&entry->srtcm_params, &cfg->srtcm_params, sizeof(entry->srtcm_params));
	return entry;
}

static struct meter_table_entry * meter_entry_create(struct meter_table_cfg *cfg)
{
	int err = 0;
	struct meter_table_entry *meter_entry = NULL;
	struct meter_hash_key key;

	meter_entry = _meter_entry_create(cfg);
	if(meter_entry == NULL){
		RTE_LOG(ERR, METER_LOG, "create meter table failed, name : %s .\n",cfg->szTenantID);
		return NULL;
	}

	/* 初始化key*/
	meter_key_init(&key, cfg->szTenantID);
	/* 插入hash*/
	err = rte_hash_add_key_data(g_meter_htable, &key,
		(void *)meter_entry);
	if (err < 0){
		RTE_LOG(ERR, METER_LOG, "adding meter entry %s failed\n", cfg->szTenantID);
		rte_free(meter_entry);
		meter_entry = NULL;
	}
	
	return meter_entry;
}

static int 
meter_entry_modify(struct meter_table_entry *exist_entry, struct meter_table_cfg *cfg){
    int ret = 0;

    rte_spinlock_lock(&g_meter_lock);
    ret = l2_meter_srtcm_config(&exist_entry->flow_meter_table, &cfg->srtcm_profile);
    if(ret != 0){
        goto rollback;
    }

    memcpy(&exist_entry->strcm_profile, &cfg->srtcm_profile, sizeof(exist_entry->strcm_profile));
    memcpy(&exist_entry->srtcm_params, &cfg->srtcm_params, sizeof(exist_entry->srtcm_params));  
    exist_entry->type = cfg->type;
    exist_entry->bandwith = cfg->bandwith;

rollback:
    rte_spinlock_unlock(&g_meter_lock);
    
    return ret;
}
/* 添加租户的flow_meter表 */
static int
meter_table_entry_insert_update(struct meter_table_cfg *cfg)
{
	int entry_exist;
	struct meter_hash_key key;	
	struct meter_table_entry *exist_entry = NULL;
	struct meter_table_entry *new_entry = NULL;
	int ret = EDPVS_OK;
	/* 初始化key*/
	meter_key_init(&key, cfg->szTenantID);

	/* 查重，判断是否有重复,重复则修改*/
	entry_exist = meter_table_entry_find_with_key(&key, &exist_entry);

	if (entry_exist) {
        ret = meter_entry_modify(exist_entry, cfg);
        return ret;
	}

	/* 创建一个新的entry*/
	new_entry = meter_entry_create(cfg);
	if(!new_entry){
		ret = EDPVS_FAILED;
	}

	return ret;
}

inline void __print_entry_detail(struct meter_table_entry *entry)
{
	if(!entry){
		return;
	}
	
	printf("\n");
	printf(" 	-------------szTenantID : %s. -----------------\n", entry->szTenantID);
    printf("		bandwith : %u\n",entry->bandwith);
    if(entry->type == TYPE_AUTO)
	    printf("		type     : auto\n");
    else
        printf("		type     : specify\n");
    
	printf("		cir      : %lu\n", entry->srtcm_params.cir);
	printf("		cbs      : %lu\n", entry->srtcm_params.cbs);
	printf("		ebs      : %lu\n", entry->srtcm_params.ebs);
	printf("	--------------------------------------------\n");
}

void show_all_meter_entrys(void){
	uint32_t iter = 0;
	struct meter_table_entry *f;
	struct meter_hash_key *key;
	
	/* Search all chains since old address/hash is unknown */
	while (rte_hash_iterate(g_meter_htable, (const void **)&key,(void **)&f, &iter) >= 0) {
		__print_entry_detail(f);
	}
}

static inline void
app_set_pkt_color(uint8_t *pkt_data, enum l2_policer_action color)
{
	pkt_data[APP_PKT_COLOR_POS] = (uint8_t)color;
}

int meter_get_flow_id_by_pkt(struct rte_mbuf *pkt, uint16_t pkt_type, UCHAR *pucTenantID){
    struct rte_ipv4_hdr *iph;
    struct rte_ipv6_hdr *ip6h;
    union inet_addr ip_tmp;
    SECPOLICY_PACKET_IP4_S stSecPolicyPacketIP4;
    SECPOLICY_PACKET_IP6_S stSecPolicyPacketIP6;
    SECPOLICY_CONF_NODE_S *pstNode = NULL;
    int ret = 0;
    
    stSecPolicyPacketIP4.uiVxlanID = GET_MBUF_PRIV_DATA(pkt)->priv_data_vxlan_hdr.vx_vni;
    stSecPolicyPacketIP6.uiVxlanID = stSecPolicyPacketIP4.uiVxlanID;
    
    if(pkt_type == RTE_ETHER_TYPE_IPV4) {
        iph = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, RTE_ETHER_HDR_LEN);
        memcpy(&stSecPolicyPacketIP4.stSrcIP, &iph->src_addr, sizeof(stSecPolicyPacketIP4.stSrcIP));
        ret = secpolicy_find4_TenantID(&stSecPolicyPacketIP4, pucTenantID);
    }else{
        ip6h = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv6_hdr *, RTE_ETHER_HDR_LEN);
        memcpy(&stSecPolicyPacketIP6.stSrcIP6, &ip6h->src_addr, sizeof(stSecPolicyPacketIP6.stSrcIP6));
        ret = secpolicy_find6_TenantID(&stSecPolicyPacketIP6, pucTenantID);
    }
    return ret;
}

/*
static inline int
meter_pkt_handle(struct rte_mbuf *pkt, uint16_t pkt_type)
{
    uint8_t input_color, output_color;
        //uint8_t *pkt_data = rte_pktmbuf_mtod(pkt, uint8_t *);
    uint32_t pkt_len = rte_pktmbuf_pkt_len(pkt) - sizeof(struct rte_ether_hdr);
    struct meter_table_entry *meter_table;
    uint32_t flow_id;
    enum l2_policer_action action;

    uint64_t current_time;
    struct timespec time;
    uint64_t tsc_time;
    struct timespec tsc_spec;
    static uint64_t last_time[DPVS_MAX_LCORE];

   // return GREEN;
    if(pkt_type != RTE_ETHER_TYPE_IPV4 && pkt_type != RTE_ETHER_TYPE_IPV6)
        return GREEN;

    flow_id = meter_get_flow_id_by_pkt(pkt, pkt_type);

    rte_spinlock_lock(&g_meter_lock);
    clock_gettime(CLOCK_MONOTONIC_RAW, &time);
    current_time = rte_timespec_to_ns(&time);

    tsc_time  = rte_rdtsc_precise();
    tsc_spec  = rte_ns_to_timespec(tsc_time);
    last_time[rte_lcore_id()] = tsc_time;

    // printf("cur_time = %lu, tsc_time = %lu, cur_spec = {tv_sec = %lu, tv_nsec = %lu}, tsc_spec = {tv_sec = %lu, tv_nsec = %lu}\n", 
    // current_time, tsc_time, time.tv_sec, time.tv_nsec, tsc_spec.tv_sec, tsc_spec.tv_nsec);
    // printf("last_time[%u] = %lu\n", rte_lcore_id(), last_time[rte_lcore_id()]);
    //rte_spinlock_lock(&g_meter_lock);
    meter_table = meter_table_entry_find(flow_id);
    if(!meter_table){
        rte_spinlock_unlock(&g_meter_lock);
        return GREEN;
    }
    output_color = (uint8_t) FUNC_METER(
                &meter_table->flow_meter_table,
                &meter_table->strcm_profile,
                current_time,
                pkt_len,
                (enum rte_color) input_color);
    rte_spinlock_unlock(&g_meter_lock);

    /* Apply policing and set the output color *
    action = l2_policer_table[output_color];
    //app_set_pkt_color(pkt_data, action);
    //printf("action is = %d\n", action);
    return action;
}
*/

static inline int
meter_pkt_handle(struct rte_mbuf *pkt, uint16_t pkt_type)
{
    uint8_t input_color, output_color;
    uint32_t pkt_len = rte_pktmbuf_pkt_len(pkt) - sizeof(struct rte_ether_hdr);
    struct meter_table_entry *meter_table;
    uint32_t flow_id;
    enum l2_policer_action action;
    UCHAR szTenantID[TENANT_ID_MAX+1];
    
    int ret = 0;
    
    uint64_t current_time;
    struct timespec time;
    uint64_t tsc_time;

    if(pkt_type != RTE_ETHER_TYPE_IPV4 && pkt_type != RTE_ETHER_TYPE_IPV6)
        return GREEN;
    
    ret = meter_get_flow_id_by_pkt(pkt, pkt_type, szTenantID);    
    if(ret != 0){
        return GREEN;
    }

    meter_table = meter_table_entry_find(szTenantID);
    if(!meter_table){
        return GREEN;
    }

    rte_spinlock_lock(&g_meter_lock);
    if(BOOL_TRUE == isMutiThread()){
        clock_gettime(CLOCK_MONOTONIC_RAW, &time);
        current_time = rte_timespec_to_ns(&time);
    }else{
        current_time = rte_rdtsc_precise();
    }

    output_color = (uint8_t) FUNC_METER(
                &meter_table->flow_meter_table,
                &meter_table->strcm_profile,
                current_time,
                pkt_len,
                (enum rte_color) input_color);
    rte_spinlock_unlock(&g_meter_lock);

    action = l2_policer_table[output_color];
    return action;
}

enum ether_input_next_nodes
l2_meter_proc(struct rte_mbuf *pkt, uint16_t pkt_type)
{
    enum ether_input_next_nodes ret = ETHER_INPUT_NEXT_MAX;
	/* Handle current packet */
	if (meter_pkt_handle(pkt, pkt_type) == DROP){
		ret = ETHER_INPUT_NEXT_PKT_DROP;
	}

    return ret;
}

int 
proc_auto_meter_recover(UCHAR       *pcTenantID, uint32_t bandwith){
    uint64_t cir = 0;
    uint64_t cbs = 0;
    uint64_t ebs = 0;
    int ret = 0;
    int i=0;
    struct meter_table_cfg meter_cfg;
    uint32_t tempbandwith;
    uint32_t bais = 0;
    /*
        桶深(Bytes)=带宽(kbps) * RTT(ms) / 8，其中的RTT是TCP协议的往返时间，通常取200ms。
        
        对华为交换机总结的经验性公式为：(cbs)
        带宽<=100Mbps 时，桶深(Bytes)=带宽(Kbps) * 1000(ms)/8
        带宽>100Mbps 时，桶深(Bytes)=100,000(Kbps) * 1000(ms)/8

        在工程上 PIR 的速率一般定义为 CIR 的 1.5 倍 (ebs)
    */
    memset(&meter_cfg, 0, sizeof(meter_cfg));
    
    tempbandwith = bandwith;
    bais += (bandwith/10);
    if(bandwith < 200){
        bais *= 2;
    }
    tempbandwith += bais;
    
    cir = (tempbandwith * 1000000)/8; 
    if(tempbandwith <= 100){
        cbs = (1000*tempbandwith)/8;
        cbs *= 1000;
    }else{
        cbs = (100000 * 1000)/8;
    }

    ebs = cbs;
    ebs += cbs>>1;

    meter_cfg.srtcm_params.cbs = cbs;
    meter_cfg.srtcm_params.cir = cir;
    meter_cfg.srtcm_params.ebs = ebs;
    meter_cfg.type = TYPE_AUTO;
    ret = l2_meter_srtcm_profile_config(&meter_cfg.srtcm_profile, &meter_cfg.srtcm_params);
    if(ret != 0){
        return ret;
    }

    meter_cfg.bandwith = bandwith;
    my_strlcpy(meter_cfg.szTenantID, pcTenantID, TENANT_ID_MAX+1);
    ret = meter_table_entry_insert_update(&meter_cfg);
    if(ret != 0){
        printf("failed to set meter table, %d\n", ret);
    }else{
        printf("success, finial cir = %lu, cbs = %lu, ebs = %lu, and the actual badwith is %u\n", cir, cbs, ebs, tempbandwith);
    }
    return ret;
}

static int 
proc_auto_meter_type(cmd_blk_t *cbt, uint32_t bandwith){
    uint64_t cir = 0;
    uint64_t cbs = 0;
    uint64_t ebs = 0;
    int ret = 0;
    int i=0;
    struct meter_table_cfg meter_cfg;
    uint32_t tempbandwith;
    uint32_t bais = 0;
    /*
        桶深(Bytes)=带宽(kbps) * RTT(ms) / 8，其中的RTT是TCP协议的往返时间，通常取200ms。
        
        对华为交换机总结的经验性公式为：(cbs)
        带宽<=100Mbps 时，桶深(Bytes)=带宽(Kbps) * 1000(ms)/8
        带宽>100Mbps 时，桶深(Bytes)=100,000(Kbps) * 1000(ms)/8

        在工程上 PIR 的速率一般定义为 CIR 的 1.5 倍 (ebs)
    */
    memset(&meter_cfg, 0, sizeof(meter_cfg));
    
    tempbandwith = bandwith;
    bais += (bandwith/10);
    if(bandwith < 200){
        bais *= 2;
    }
    tempbandwith += bais;
    
    cir = (tempbandwith * 1000000)/8; 
    if(tempbandwith <= 100){
        cbs = (1000*tempbandwith)/8;
        cbs *= 1000;
    }else{
        cbs = (100000 * 1000)/8;
    }

    ebs = cbs;
    ebs += cbs>>1;

    meter_cfg.srtcm_params.cbs = cbs;
    meter_cfg.srtcm_params.cir = cir;
    meter_cfg.srtcm_params.ebs = ebs;
    meter_cfg.type = TYPE_AUTO;
    ret = l2_meter_srtcm_profile_config(&meter_cfg.srtcm_profile, &meter_cfg.srtcm_params);
    if(ret != 0){
        return ret;
    }

    meter_cfg.bandwith = bandwith;
    my_strlcpy(meter_cfg.szTenantID, cbt->string[0], TENANT_ID_MAX+1);
    ret = meter_table_entry_insert_update(&meter_cfg);
    if(ret != 0){
        tyflow_cmdline_printf(cbt->cl, "failed to set meter table, %d\n", ret);
    }else{
        tyflow_cmdline_printf(cbt->cl, "success, finial cir = %lu, cbs = %lu, ebs = %lu, and the actual badwith is %u\n", cir, cbs, ebs, tempbandwith);
    }
    return ret;
}

static int
proc_meter_precise_type(cmd_blk_t *cbt, uint32_t bandwith, struct rte_meter_srtcm_params *srtcm_param){
    struct meter_table_cfg meter_cfg;
    uint32_t tempbandwith;
    uint64_t cir = 0;
    int ret = 0;

    tempbandwith = bandwith;
    cir = (tempbandwith * 1000000)/8; 

    meter_cfg.srtcm_params.cir = cir;
    meter_cfg.srtcm_params.cbs = srtcm_param->cbs;
    meter_cfg.srtcm_params.ebs = srtcm_param->ebs;

    ret = l2_meter_srtcm_profile_config(&meter_cfg.srtcm_profile, &meter_cfg.srtcm_params);
    if(ret != 0){
        return ret;
    }

    meter_cfg.bandwith = bandwith;
    my_strlcpy(meter_cfg.szTenantID, cbt->string[0], TENANT_ID_MAX+1);
    meter_cfg.type = TYPE_SPECFY;
    
    ret = meter_table_entry_insert_update(&meter_cfg);
    if(ret != 0){
        tyflow_cmdline_printf(cbt->cl, "failed to set meter table, %d\n", ret);
    }else{
        tyflow_cmdline_printf(cbt->cl, "success, finial cir = %lu, cbs = %lu, ebs = %lu, and the actual badwith is %u\n",
                              cir, srtcm_param->cbs, srtcm_param->ebs, tempbandwith);
    }

    return ret;
}


static int 
set_meter_cli (cmd_blk_t *cbt)
{
	struct rte_meter_srtcm_params srtcm_param;
    uint32_t bandwith;
    uint64_t cir, cbs, ebs;
	int i,ret;
	if (cbt->mode & MODE_UNDO) {
		tyflow_cmdline_printf(cbt->cl, "unset the speed, flow number is %u\n", cbt->number[0]);
		return 0;
	}

    bandwith = cbt->number[0];
    tyflow_cmdline_printf(cbt->cl, "bandwith is %u\n", cbt->number[0]);
	if (cbt->which[0] == 1) {
        tyflow_cmdline_printf(cbt->cl, "adopt auto\n");
        ret = proc_auto_meter_type(cbt, bandwith);
        return ret;
	}else{
        cbs = (uint64_t)cbt->number[1];
        ebs = (uint64_t)cbt->number[2];
        srtcm_param.cbs = cbs;
        srtcm_param.ebs = ebs;
        proc_meter_precise_type(cbt, bandwith, &srtcm_param);
        tyflow_cmdline_printf(cbt->cl, "specify, cbs is %lu, ebs is %lu\n", cbs, ebs);
    }

	return 0;
}

static int
show_meter_entrys_cli(cmd_blk_t *cbt)
{
	show_all_meter_entrys();
    tyflow_cmdline_printf(cbt->cl, "\n");
    return 0;
}

EOL_NODE_NEED_MAIN_EXEC(set_meter_eol, set_meter_cli);

VALUE_NODE(meter_speed_type_specify_ebs_val, set_meter_eol, none, "specfic the ebs", 3, NUM);
KW_NODE(meter_speed_type_specify_ebs, meter_speed_type_specify_ebs_val, none, "ebs", "the size of brust token bucket measured by Byte.");
VALUE_NODE(meter_speed_type_specify_cbs_val, meter_speed_type_specify_ebs, none, "specify the cbs", 2, NUM);
KW_NODE(meter_speed_type_specify_cbs, meter_speed_type_specify_cbs_val, none, "cbs", "the size of speend-limiting token bucket measured by Byte.");
KW_NODE(meter_speed_type_specify, meter_speed_type_specify_cbs, none, "specify", "this choice means that you will specify the para of token bucket algorithm by yourself.");
KW_NODE_WHICH(meter_speed_type_auto, set_meter_eol, meter_speed_type_specify,
	"auto", "this choice means that you will adopt the recommanded algorithm we support automatically to specify the para of token bucket algorithm.", 1, 1);

KW_NODE(meter_speed_type, meter_speed_type_auto, none,
	"type", "there are two choice about the style of speed-limit that you can choose: limit automatically or specify parameter by yourself.");

VALUE_NODE(meter_speed_val, meter_speed_type, none, "the value of bandwith measured by Mbps.for example, 10 means 10Mpbs", 1, NUM);
KW_NODE(meter_speed, meter_speed_val, none, "bandwith", "specify the bandwith that you need to limit.");
VALUE_NODE(meter_flow_id_val, meter_speed, none, "specify flow id", 1, STR);
KW_NODE(meter_flow_id, meter_flow_id_val, none, "TenantID", "specify the flow that you need to limit by id.");
VALUE_NODE(unset_meter_id, set_meter_eol, none, "TenantID", 1, STR);
TEST_UNSET(test_unset_meter, unset_meter_id, meter_flow_id);
KW_NODE(set_meter, test_unset_meter, none, "rate-limiting", "rate-limiting by meter");


EOL_NODE_NEED_MAIN_EXEC(meter_show_eol, show_meter_entrys_cli);
KW_NODE(get_meter, meter_show_eol, none, "rate-limiting", "show all the meter tables.");

void 
cmd_meter_init (void)
{
	add_set_cmd(&cnode(set_meter));
	add_get_cmd(&cnode(get_meter));
}

static void
print_usage(const char *prgname)
{
	printf ("%s [EAL options] -- -p PORTMASK\n"
		"  -p PORTMASK: hexadecimal bitmask of ports to configure\n",
		prgname);
}

static int
parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return pm;
}

int meter_table_hash_init(void){
	int err = 0;
	char name[METER_HTABLE_NAME_SIZE];

    /* Initialize hash */
	snprintf(name, METER_HTABLE_NAME_SIZE,
		 "%s's hash struct", "meter_table");

	struct rte_hash_parameters hash_tbl_params = {
		.entries = METER_HTABLE_ENTRIES,
		.key_len = sizeof(struct meter_hash_key),
		.hash_func = rte_jhash,
		.hash_func_init_val = rte_rand(),
		.name = name,
		.reserved = 0,
		.socket_id = SOCKET_ID_ANY,
		//.extra_flag = RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD,
	};

	g_meter_htable = rte_hash_create(&hash_tbl_params);
	if(g_meter_htable == NULL){
		RTE_LOG(ERR, METER_LOG, "failed to create %", name);
		return -1;
	}

	return 0;
}


int
l2_meter_init(void)
{
    int ret;
	/* App configuration */
    cmd_meter_init();

    ret = l2_get_clock_freq();
    if (ret < 0){
        printf("l2_get_clock_freq failed\n");
        return ret;
    }
    rte_spinlock_init(&g_meter_lock);
	//ret = l2_configure_flow_table();
	ret = meter_table_hash_init();
    if (ret < 0)
        printf("Invalid configure flow table\n");

    if(netif_get_graph_need_to_create() > 1){
        g_muti_thread = BOOL_TRUE;
    }
	
	return ret;
}

