/*
 * Copyright (C) 2021 TYyun.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include "dpdk.h"
#include "conf/common.h"
#include "netif.h"
#include "netif_addr.h"
#include "vlan.h"
#include "ctrl.h"
#include "list.h"
#include "kni.h"
#include <rte_version.h>
#include "conf/netif.h"
#include "timer.h"
#include "parser/parser.h"
#include "neigh.h"
#include "scheduler.h"

#include <rte_arp.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "ipv4.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "flow.h"
#include "debug_flow.h"


/*Head/hdr is never need to be protected since we make it per lcore*/
/*other wants to use it need to be careful, maybe add a new lock version?*/
static inline void lifo_enqueue (void *head, void *y, int nxt_offset)
{
    char *yy = (char *)y;
    uint64_t **hdr = (uint64_t **)head;
	*(uint64_t *)(yy + nxt_offset) = (uint64_t)*hdr;
	*hdr = (uint64_t *)y;
}

static inline void *lifo_dequeue (void *head, int offset)
{
    uint64_t **hdr = (uint64_t **)head;
    uint64_t *y;
    y = *hdr;
	if (y == NULL) {
		goto end;
	}

	*hdr = (uint64_t *)(*(uint64_t *)((uint64_t)y + offset));

end:
	return (void *)y;
}

#if 0
flow_connection_t *flowConnTable[RTE_MAX_LCORE];
flow_connection_t *flowConnHead[RTE_MAX_LCORE];
flow_connection_t **flow_conn_hash_base[RTE_MAX_LCORE];    /* per lcore flow connection hash tab base*/
uint32_t *flow_conn_hash_cnt_base[RTE_MAX_LCORE];       /* per lcore flow connection hash cnt table base */
#endif

/* per lcore flow connection table */
RTE_DEFINE_PER_LCORE(flow_connection_t *, flowConnTable);
/* per lcore flow connection lifo head */
RTE_DEFINE_PER_LCORE(flow_connection_t *, flowConnHead);
/* per lcore flow connection hash tab base*/
RTE_DEFINE_PER_LCORE(struct hlist_head * /* conn_sub_t** */, flow_conn_hash_base);
/* per lcore flow connection hash cnt table base */
RTE_DEFINE_PER_LCORE(uint32_t *, flow_conn_hash_cnt_base);

/* per lcore flow connection statistics */
RTE_DEFINE_PER_LCORE(uint32_t, flow_curr_conn);
RTE_DEFINE_PER_LCORE(uint32_t, flow_invalid_conn);
RTE_DEFINE_PER_LCORE(uint32_t, flow_no_conn);
RTE_DEFINE_PER_LCORE(uint32_t, flow_free_conn);

/* flow is ready to go? */
RTE_DEFINE_PER_LCORE(uint32_t, flow_status);

/* per lcore flow connection ager */
RTE_DEFINE_PER_LCORE(struct rte_timer, flow_conn_ager);

/* per lcore flow vector list */
RTE_DEFINE_PER_LCORE(flow_vector_t *, flow_vector_list);

/* per lcore flow connection control prototype */
RTE_DEFINE_PER_LCORE(flow_connection_t, flow_conn_crt_t);

/*
 * Clean up leftovers in conn_sub_t block.
 * This cleanup is very important
 * as the conn_sub_t block will be allocated
 * later and most of its content will be used as is.
 */
static void 
init_conn_sub (conn_sub_t *csp)
{
	memset((void*)&csp->start,0,sizeof(conn_sub_t)-offsetof(conn_sub_t, start));
	csp->cspflag = CSP_FREE | CSP_INVALID;
}

/*
 * free a flow_connection_t into free pool. 
 * this function may be called from the flow, or from the ager.
 * NOTE: this function is not protected by the lock. 
 */
static inline void 
flow_free_conn_into_free_pool(flow_connection_t *fcp)
{
	int offset = (int)(uint64_t)&(((flow_connection_t *)0)->next);
	
	lifo_enqueue(&this_flowConnHead, fcp, offset);

	this_flow_curr_conn--;
}
/*
 * this function initializes the flow connection before put it back
 * to the free pool.
 */
static inline void 
flow_init_connection (flow_connection_t *fcp)
{
	conn_sub_t *csp = &fcp->conn_sub0;
	conn_sub_t *csp2 = &fcp->conn_sub1;

    init_conn_sub(csp);
    init_conn_sub(csp2);

	if (fcp->fcflag & FC_INVALID) {
		/* decrease invalid flow connection counter */
        this_flow_invalid_conn--;
	}
		
    fcp->time = 0;
    fcp->time_const = 0;
    fcp->start_time = 0;
    fcp->duration = 0;
    fcp->fcflag = 0;
    fcp->byte_cnt = 0;
    fcp->pkt_cnt = 0;
    fcp->reason = 0;
    fcp->fwsession = 0;
}

/* all resource attached to the flow connection should be freed here */
void 
flow_free_this_conn (flow_connection_t *fcp)
{
#if 0
    if(is_csp_l2info_arp(&fcp->conn_sub0))
        clear_csp_l2info_arp(&fcp->conn_sub0);

    /* clear arp ref_cnt for wing 2*/
    if(is_csp_l2info_arp(&fcp->conn_sub1))
        clear_csp_l2info_arp(&fcp->conn_sub1);
#endif

    flow_init_connection(fcp);

    flow_free_conn_into_free_pool(fcp);
}

extern uint64_t g_cycles_per_sec;
/* 
 * called during sys init time.
 */
static int
flow_conn_init (__rte_unused void *arg)
{
    flow_connection_t *fcp;
	uint32_t cnt;
	conn_sub_t *csp0;
	conn_sub_t *csp1;
    lcoreid_t cid = rte_lcore_id();

    if (g_lcore_role[cid] != LCORE_ROLE_FWD_WORKER) {
        RTE_LOG(INFO, FLOW, "%s: lcore %d: skip non-worker.\n",
                            __FUNCTION__, cid);
        return 0;
    }
    RTE_LOG(INFO, FLOW, "%s: start on lcore %d.\n", __FUNCTION__, cid);
    this_flowConnTable = (flow_connection_t *)rte_malloc("flow_conn_table", sizeof(flow_connection_t)*FLOW_CONN_MAX_NUMBER, 0);
    if (!this_flowConnTable) {
        RTE_LOG(ERR, FLOW, "%s: no memory for flow connection\n",
                __FUNCTION__);
        goto bad;
    }

    this_flow_conn_hash_base = (struct hlist_head *)rte_zmalloc("flow_conn_hash", sizeof(struct hlist_head)*FLOW_CONN_HASH_TAB_SIZE, 0); 
    if (!this_flow_conn_hash_base) {
        RTE_LOG(ERR, FLOW, "%s: no memory for flow conn hash\n",
                __FUNCTION__);
        goto bad;
    }

    this_flow_conn_hash_cnt_base = (uint32_t *)rte_zmalloc("flow_conn_hash_cnt", sizeof(uint32_t)*FLOW_CONN_HASH_TAB_SIZE, 0);
    if (!this_flow_conn_hash_cnt_base) {
        RTE_LOG(ERR, FLOW, "%s: no memory for flow conn hash cnt\n",
                __FUNCTION__);
        goto bad;
    }

    /*
     * init flow conn control prototype
     */
    csp0 = &this_flow_conn_crt->conn_sub0;
    csp1 = &this_flow_conn_crt->conn_sub1;
    csp0->peer_offset = (uint64_t)csp1 - (uint64_t)csp0;
    csp1->peer_offset = (uint64_t)csp0 - (uint64_t)csp1;
    csp0->base_offset = (uint64_t)this_flow_conn_crt - (uint64_t)csp0;
    csp1->base_offset = (uint64_t)this_flow_conn_crt - (uint64_t)csp1;
    csp0->resv = RESV_AA;
    csp1->resv = RESV_BB;

	/*
	 * init flow conn table.
	 * we do not use the 0th flow conn entry since
	 * its index is 0, and 0 in udp/tcp lookup table
	 * means no entry.
	 */
	this_flowConnHead = NULL;
	fcp = this_flowConnTable + 1;
	for (cnt = 1; cnt < FLOW_CONN_MAX_NUMBER; cnt++) {
		memset(fcp, 0, sizeof(flow_connection_t));
		/* assign session id, but not for 1000 */
		csp0 = &fcp->conn_sub0;
		csp1 = &fcp->conn_sub1;
		csp0->peer_offset = (uint64_t)csp1 - (uint64_t)csp0;
		csp1->peer_offset = (uint64_t)csp0 - (uint64_t)csp1;
		csp0->base_offset = (uint64_t)fcp - (uint64_t)csp0;
		csp1->base_offset = (uint64_t)fcp - (uint64_t)csp1;
        csp0->resv = RESV_AA;
        csp1->resv = RESV_BB;
		/*
		 * put into free pool.
		 */
		flow_free_this_conn(fcp);

		fcp++;
	}

    this_flow_curr_conn = 0;
    this_flow_invalid_conn = 0;
    this_flow_no_conn = 0;
    this_flow_free_conn = FLOW_CONN_MAX_NUMBER-1;

	/*
	 * notify me if a policy is gone.
	 */
	//add_policy_delete_registry((void *)flow_age_conn_by_policy);

	/*
	 * notify me if ha peer state change
	 */
	//add_ha_peer_state_change_registry(flow_ha_peer_state_change);

	/*
	 * notify me if an interface is gone
	 */
	//add_delete_if_registry((void *)flow_clear_conn_by_ifp);

    //dpvs_timer_sched(&g_minute_timer, &tv, minute_timer_expire, NULL, true);
    //rte_timer_init(&this_flow_conn_ager);
    //rte_timer_reset(&timer0, g_cycles_per_sec*2, PERIODICAL, lcore_id, timer0_cb, NULL);
    this_flow_status = 1;
    RTE_LOG(INFO, FLOW, "  finish on lcore %d/%d\n", cid, this_flow_status);
    return 0;
bad:
    if (this_flowConnTable) {
        rte_free(this_flowConnTable);
    }
    if (this_flow_conn_hash_base) {
        rte_free(this_flow_conn_hash_base);
    }
    if (this_flow_conn_hash_cnt_base) {
        rte_free(this_flow_conn_hash_cnt_base);
    }
    return EDPVS_NOMEM;
}

static flow_vector_t flow_first_vector_list[] =
{
    flow_first_sanity_check,
    flow_first_hole_search,
    flow_first_for_self,
    flow_first_routing,
    flow_first_fw_entry,
    flow_first_alloc_connection,
    NULL
};

static flow_vector_t flow_fast_vector_list[] =
{
    flow_fast_reinject_out,
    flow_fast_fw_entry,
    flow_fast_send_out,
    NULL
};

static flow_vector_t flow_ipv4_vector_list[] = 
{
    flow_filter_vector,
    flow_decap_vector,
    flow_main_body_vector,
    NULL
};

static inline int 
flow_set_pak_vector(flow_vector_t *vector)
{
    this_flow_vector_list = vector;
    return 0;
}

static inline int 
flow_terminate_vector(void)
{
    this_flow_vector_list = NULL;
    return 0;
}

/*
 * resume packet processing from the where it stops.
 * make the vector pacing by flow_next_pak_vector
 */
static inline int 
flow_walk_vector_list (struct rte_mbuf *mbuf)
{
	int rc;

    if (flow_debug_flag & FLOW_DEBUG_BASIC) {
        char saddr[16], daddr[16];
        struct rte_ipv4_hdr *iph;
        uint32_t iphdrlen;
        uint32_t *iptr;

        iph = ip4_hdr(mbuf);
        iphdrlen = ip4_hdrlen(mbuf);
        iptr = rte_pktmbuf_mtod_offset(mbuf, uint32_t *, iphdrlen);
        inet_ntop(AF_INET, &iph->src_addr, saddr, sizeof(saddr));
        inet_ntop(AF_INET, &iph->dst_addr, daddr, sizeof(daddr));
        flow_debug_trace_no_flag("**** jump to packet: %s/%d->%s/%d@%d\n",
                                 saddr,
                                 ntohs(ip_src_port(*iptr)),
                                 daddr,
                                 ntohs(ip_dst_port(*iptr)),
                                 iph->next_proto_id);
    }

	while (*this_flow_vector_list) {
		if ((rc = (*this_flow_vector_list)(mbuf))) {
			flow_debug_trace(FLOW_DEBUG_BASIC, "**** pak processing end(%d).\n", rc);
			return rc;
		}
	}
	flow_debug_trace(FLOW_DEBUG_BASIC, "**** pak processing end.\n");
	return 0;
}

/* goto next vector */
static inline int 
flow_next_pak_vector(struct rte_mbuf *mbuf)
{
    this_flow_vector_list++;
    return 0;
}

#define IS_ICMP_REQ(tt)  (tt== ICMP_ECHO || tt== ICMP_TIMESTAMP || tt== ICMP_ADDRESS || tt== ICMP_INFO_REQUEST)
#define IS_ICMP_RSP(tt)  (tt== ICMP_ECHOREPLY || tt== ICMP_TIMESTAMPREPLY || tt== ICMP_ADDRESSREPLY || tt== ICMP_INFO_REPLY)
#define HAS_EMBEDDED_IP(tt) (tt== ICMP_DEST_UNREACH || tt== ICMP_SOURCE_QUENCH || tt== ICMP_REDIRECT || tt== ICMP_TIME_EXCEEDED || tt== ICMP_PARAMETERPROB)

/*
 * use seq number in icmp req, and id number in icmp rsp.
 * returns - the src port number in network byte order.
 */
static inline int ping_src_port (struct rte_icmp_hdr *icmp)
{
	if (icmp->icmp_type == ICMP_ECHO ||
		icmp->icmp_type == ICMP_TIMESTAMP ||
		icmp->icmp_type == ICMP_INFO_REQUEST)
		return icmp->icmp_seq_nb;
	else if (icmp->icmp_type == ICMP_ECHOREPLY ||
		     icmp->icmp_type == ICMP_TIMESTAMPREPLY ||
             icmp->icmp_type == ICMP_INFO_REPLY)
		return icmp->icmp_ident;
	return 0;
}

/*
 * use id number in icmp req, and seq number in icmp rsp.
 * returns - the dst port number in network byte order.
 */
static inline int ping_dst_port (struct rte_icmp_hdr *icmp)
{
	if (icmp->icmp_type == ICMP_ECHO      ||
		icmp->icmp_type == ICMP_TIMESTAMP ||
		icmp->icmp_type == ICMP_INFO_REQUEST)
		return icmp->icmp_ident;
	else if (icmp->icmp_type == ICMP_ECHOREPLY||
             icmp->icmp_type == ICMP_TIMESTAMPREPLY||
             icmp->icmp_type == ICMP_INFO_REPLY)
		return icmp->icmp_seq_nb;
	else
		return 0;
}

/* Forms ports for ICMP req/resp packets. */
static inline uint32_t 
icmp_ping_ports_form (struct rte_icmp_hdr *icmp)
{
    if (RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN)
        return (ping_dst_port(icmp) << 16) | ping_src_port(icmp);
    else 
        return (ping_src_port(icmp) << 16) | ping_dst_port(icmp);
}

/* To ensure proper endianness use icmp_ping_ports_form to extract src/
 * dst ports from the value returned by this function. */
int 
icmp_ports (struct rte_icmp_hdr *icmp)
{
	if (icmp->icmp_type == ICMP_ECHO || icmp->icmp_type == ICMP_ECHOREPLY ||
		icmp->icmp_type == ICMP_TIMESTAMP || icmp->icmp_type == ICMP_TIMESTAMPREPLY ||
		icmp->icmp_type == ICMP_INFO_REQUEST || icmp->icmp_type== ICMP_INFO_REPLY) {
        return icmp_ping_ports_form (icmp);
	}

	/*
	 * the following value needs to be consistent with default
	 * return value of ip_proto_ports().
	 */
	return htonl(0x00010001);
}

static inline uint32_t 
ip_proto_ports_embed_icmp (uint8_t prot, uint32_t *iptr)
{
	if (prot == IPPROTO_TCP || prot == IPPROTO_UDP || prot == IPPROTO_ESP) {
		return *iptr;
	}
	else if (prot == IPPROTO_AH) {
		return *(iptr+1);			/* spi of AH is the second LONG of the header */
	}
	else if (prot == IPPROTO_ICMP) {
		return icmp_ports((struct rte_icmp_hdr *)iptr);
	}
	return htonl(0x00010001);
}

static void 
swap_ip_port (struct rte_ipv4_hdr *iphdr, uint32_t *iptr, uint32_t *ports)
{
	uint32_t value;

	value = iphdr->src_addr;
	iphdr->src_addr = iphdr->dst_addr;
	iphdr->dst_addr = value;
	value = ip_proto_ports_embed_icmp(iphdr->next_proto_id, iptr);
	value = ip_ports_form(ip_dst_port(value), ip_src_port(value));
	*ports = value;
}

/*
 * generate iphdr and ports info for flow connection lookup
 */
struct rte_ipv4_hdr *
gen_icmp_lookup_info (struct rte_ipv4_hdr *iphdr, uint32_t *iptr, struct rte_mbuf *mbuf, struct rte_ipv4_hdr *iphdr_inner, uint32_t *ports)
{
	struct rte_icmp_hdr *icmp;

	icmp = (struct rte_icmp_hdr *)iptr;
	if (IS_ICMP_REQ(icmp->icmp_type) ||
		IS_ICMP_RSP(icmp->icmp_type)) {
		*ports = icmp_ping_ports_form(icmp);
	}
    else if (HAS_EMBEDDED_IP(icmp->icmp_type)) { 
        /*
         * for these icmp message, use embedded ip header
         * for session lookup
         */
        iphdr = (struct rte_ipv4_hdr *)(iptr + sizeof(struct rte_icmp_hdr));
        /*
         * we copy the original iphdr out so only alter
         * the copy not the original.
         */
        memcpy(iphdr_inner, iphdr, sizeof(struct rte_ipv4_hdr));
        iptr = ((uint32_t *)iphdr + (iphdr->version_ihl & 0xf));
        swap_ip_port(iphdr_inner, iptr, ports);
        /* todo
         * add some debug trace here
         */

        if (icmp->icmp_type == ICMP_REDIRECT) {
            return (struct rte_ipv4_hdr *)-1;
        }

        iphdr = iphdr_inner;

        /* we don't want to refresh flow connection for ICMP error cases */
        //mbuf->flag |= PAK_NO_REFRESH | PAK_EMBED_ICMP ;

    } else
        *ports = htonl(0x00010001);
    return iphdr;
}

/*
 * hash packet for flow conn_sub_t.
 * need to tune it in accordance with the real traffic
 */
static inline uint32_t _conn_hash (uint32_t s, uint32_t d, uint32_t p)
{
	register uint32_t a;
	register uint32_t m = 0xffff; /* mask for a short int */

	a = ((s>>16) ^ ((s<<8)&m));
	a = a ^ ((d>>15) ^ ((d<<7)&m));
	a = a ^ ((p>>16) ^ ((p<<8)&m));
	
	return a;
}

static inline int conn_hash (uint32_t s, uint32_t d, uint32_t p)
{
	return (_conn_hash(s, d, p) & FLOW_CONN_HASH_TAB_MASK);
}

/* generic way for flow conn_sub_t comparison */
#define FOR_ALL_NAT_SESSION(node, src_adr, dst_adr, ports, head, csp, cnt)  					      \
    cnt = conn_hash(src_adr, dst_adr, ports);                                                         \
    for (node = (this_flow_conn_hash_base + cnt)->first,	                                          \
         csp = container_of(node, conn_sub_t, hnode), head = csp,                                     \
         cnt = *(this_flow_conn_hash_cnt_base + cnt);           					                  \
         node && (csp = container_of(node, conn_sub_t, hnode)) && ({ rte_prefetch0(node->next); 1;}); \
         node = node->next, csp = container_of(node, conn_sub_t, hnode))

/*
 * first path packet processing
 * similar to flow_walk_vector_list
 * give a meaningful wrapper name 
 * need to add some performance counter
 */
int
flow_proc_first_pak(struct rte_mbuf *mbuf)
{
    /* add some performance counter here */
    int rc;
    flow_debug_trace(FLOW_DEBUG_BASIC, "  ---- first path entry.\n");
	while (*this_flow_vector_list) {
		if ((rc = (*this_flow_vector_list)(mbuf))) {
            break;
		}
	}
    flow_debug_trace(FLOW_DEBUG_BASIC, "  ---- first path end (%d).\n", rc);
    return rc;
}

int
flow_first_install_connection(struct rte_mbuf *mbuf)
{
    flow_connection_t *fcp = GET_FC_FROM_MBUF(mbuf);
    if (fcp->fcflag & FC_INSTALLED) {
        /* fw may help us to install the connection */
        return 0;
    }

    flow_install_conn(fcp);
    fcp->fcflag &= ~FC_TIME_NO_REFRESH;
    return 0;
}

static void 
flow_dump_hash(conn_sub_t *csp, int cnt)
{
    int hash;
    hash = conn_hash(csp->csp_src_ip, csp->csp_dst_ip, *(uint32_t *)&csp->csp_src_port);

	/* we only show hash bucket with connections to reduce the output */
	if (cnt > 0) {
		conn_sub_t *csp_next;
		int i = 0, line = 0;
		flow_print("  hash %6d header: %8llx, cnt %4d: ", hash, (uint64_t)csp, cnt); 
		while (csp && i++ < cnt) {
			flow_connection_t *fcp = csp2base(csp);
			int fcp_id = fcp2id(fcp);
			csp_next = container_of(csp->hnode.next, conn_sub_t, hnode);
			flow_print("%8d ", fcp_id);
			if (!line) {
				if (!(i & 0x7)) {
					line++;
					flow_print("\n    ");
				}
			} else if(!(i & 0x1f)) {
				line++;
				flow_print("\n    ");
			}
			csp = csp_next;
		}
		flow_print("\n");
	}
}

static int 
is_connection_list_loop(int cnt, int i, conn_sub_t *head)
{
/* to make sure we don't omit any thing */
#define MIN_HASH_COUNT 0x7F
/* to make sure we don't do stupid loop too much */
#define MAX_HASH_COUNT 0x1FFF
	int count = MAX(MIN_HASH_COUNT, MIN(MAX_HASH_COUNT, cnt<<1));
	if (i > count) {
		if (flow_debug_flag & FLOW_DEBUG_DETAIL) {
            flow_print("hash(0x%llx) abnormal, hash counter %d, hash connecetion wings %d.\n", head, cnt, i);
			flow_dump_hash(head, MIN(cnt + 1, 100));
		}
		return 1;
	}
	return 0;
}

int 
flow_first_fcp_crt_init(struct rte_mbuf *mbuf, uint32_t ports)
{
    conn_sub_t *csp1, *csp2;
    uint32_t len = sizeof(flow_connection_t)-offsetof(flow_connection_t, start);

    struct rte_ipv4_hdr *iph;

    flow_print("  %s entry, init fcp len %d\n", __FUNCTION__, len);
    /*
     * reset flow connection control prototype
     */
    csp1 = &this_flow_conn_crt->conn_sub0;
    csp2 = &this_flow_conn_crt->conn_sub1;
    init_conn_sub(csp1);
    init_conn_sub(csp2);
    memset(&this_flow_conn_crt->start, 0, len); 

    /* set the this_flow_conn_crt on the basis of mbuf */
    iph = ip4_hdr(mbuf);
    csp1->csp_src_ip = csp2->csp_dst_ip = iph->src_addr;
    csp1->csp_dst_ip = csp2->csp_src_ip = iph->dst_addr;
    csp1->csp_src_port = csp2->csp_dst_port = ip_src_port(ports);
    csp1->csp_dst_port = csp2->csp_src_port = ip_dst_port(ports);
    csp1->csp_proto = csp2->csp_proto = iph->next_proto_id;
    csp1->csp_token = csp2->csp_token = 1; /* should be set to vrf */
    this_flow_conn_crt->start_time = rte_get_tsc_cycles();
    SET_CSP_TO_MBUF(mbuf, (uint64_t)csp1);
    return 0;
}

/*
 * main entry point for first path
 * in this function we'll try to find a connection for incoming packet
 *
 */
int 
flow_find_connection(struct rte_mbuf *mbuf)
{
	flow_vector_t *vector;
	int rc, cnt, i;
	conn_sub_t *csp = NULL, *head;
    flow_connection_t *fcp = NULL;
    struct rte_ipv4_hdr *iph;
    struct rte_ipv4_hdr iph_r;
    uint32_t iphdrlen, ports;
    uint32_t *iptr;
    struct hlist_node *node;

    iph = ip4_hdr(mbuf);
    iphdrlen = ip4_hdrlen(mbuf);
    iptr = rte_pktmbuf_mtod_offset(mbuf, uint32_t *, iphdrlen);

    switch (iph->next_proto_id) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_ESP:
        case IPPROTO_SCTP:
            ports = *iptr;
            break;
        case IPPROTO_AH:
            ports = *(iptr+1);         /* spi of AH is the second LONG of the header */
            break;
        case IPPROTO_ICMP:
            /*
             * for icmp, we return pointer to embedded ip packet,
             * address/port in the packet are also swapped to make
             * it appear as an returning packet for subsequent xlate.
             * icmp decoder can also decide abort session match by return NULL.
             */
            iph = gen_icmp_lookup_info(iph, iptr, mbuf, &iph_r, &ports);
            if (iph == NULL) {
                return -1;
            } else if (iph == (struct rte_ipv4_hdr *)-1) {
                return -1;
            }
            break;
        default:
            break;
    }

    FOR_ALL_NAT_SESSION(node, iph->src_addr, iph->dst_addr, ports, head, csp, cnt) {
        if (CONN_SUB_COMP(csp, iph, ports, 1)) {
            fcp = csp2base(csp);
            if ((fcp->fcflag & FC_INVALID) == 0) {
                break;
            }
        }
        if (!(++i & 0x7F) && is_connection_list_loop(cnt, i, head)) {
            break;
        }
    }

    if (fcp) {
        flow_debug_trace(FLOW_DEBUG_BASIC, "  existing connection found. id %d\n", fcp2id(fcp));
        SET_CSP_TO_MBUF(mbuf, (uint64_t)csp);
        if (IS_CSP_DISABLE(csp)) {
            /* do something */
        }
    } else {
        /* 
         * first pak, try to creat a new one 
         */
        flow_debug_trace(FLOW_DEBUG_BASIC, "  no session found\n");

        /*
         * keep original vector list
         */
        vector = this_flow_vector_list;
        flow_set_pak_vector(flow_first_vector_list);
        flow_first_fcp_crt_init(mbuf, ports);
        rc = flow_proc_first_pak(mbuf);
        /* restor vector list */
        flow_set_pak_vector(vector);
        if (rc) {
            return rc;
        }

        flow_first_install_connection(mbuf);
    }
    return 0;
}

int 
flow_first_sanity_check(struct rte_mbuf *mbuf)
{
    flow_print("  %s entry\n", __FUNCTION__);
    return flow_next_pak_vector(mbuf);
}

int
flow_first_alloc_connection(struct rte_mbuf *mbuf)
{
    flow_connection_t *fcp;
    conn_sub_t *csp1, *csp2;
    uint32_t len;

    fcp = lifo_dequeue(&this_flowConnHead, offsetof(flow_connection_t, next));
    if (fcp) {
        this_flow_curr_conn++;
        this_flow_free_conn--;
        flow_debug_trace(FLOW_DEBUG_BASIC, "  alloc flow connection from pool\n");
    } else {
        this_flow_no_conn++;
        flow_debug_trace(FLOW_DEBUG_BASIC, "  failed to alloc flow connection\n");
        return -1;
    }

    len = sizeof(conn_sub_t)-offsetof(conn_sub_t, start);
    csp1 = &fcp->conn_sub0; 
    csp2 = &fcp->conn_sub1;
    memcpy(&csp1->start, &this_flow_conn_crt->conn_sub0.start, len);
    memcpy(&csp2->start, &this_flow_conn_crt->conn_sub1.start, len);

    len = sizeof(flow_connection_t)-offsetof(flow_connection_t, start);
    memcpy(&fcp->start, &this_flow_conn_crt->start, len);
    SET_CSP_TO_MBUF(mbuf, (uint64_t)csp1);
    return flow_next_pak_vector(mbuf);
}

int 
flow_first_hole_search(struct rte_mbuf *mbuf)
{
    flow_print("  %s entry\n", __FUNCTION__);
    return flow_next_pak_vector(mbuf);
}

extern uint16_t g_nports;
extern struct inet_device *dev_get_idev(const struct netif_port *dev);
extern struct inet_ifaddr *ifa_lookup(struct inet_device *idev,
        const union inet_addr *addr,
        uint8_t plen, int af);
int
pak_to_my_addrs(struct rte_ipv4_hdr *iph, uint32_t id)
{
    struct netif_port *dev;
    struct inet_device *idev;
    union inet_addr addr;
    struct inet_ifaddr *ifa;

    addr.in.s_addr = iph->dst_addr;

    for (id = 0; id < g_nports; id++) {
        dev = netif_port_get(id);
        if (!dev) {
            continue;
        }
        idev = dev_get_idev(dev);
        if (!idev) {
            continue;
        }
        /* we do not care about the prefix mask */
        ifa = ifa_lookup(idev, &addr, 0, AF_INET);
        if (ifa) {
            return 1;
        }
    }
    return 0;
}

static int g_is_ping_enable = 1;
static int
is_ping_on_(void)
{
    return g_is_ping_enable;
}

static int 
is_for_ping (struct rte_ipv4_hdr *iph, struct rte_icmp_hdr *icmp)
{
	if (iph->next_proto_id == IPPROTO_ICMP &&
        icmp->icmp_type == ICMP_ECHO) {
		/* regular ping */
		if (is_ping_on_()) {
			return 1;
		} 
	}
    return 0;
}

int
pak_for_self(struct rte_ipv4_hdr *iph, uint32_t *iptr)
{
    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)iptr;
    /* currently only support ping
     * need to add more and make it dynamic register */
    if (is_for_ping(iph, icmp)) {
        /* todo
         * better to create a to-self session here
         */
        return 1;
    }
    return 0;
}

static int
flow_reply_ping(struct rte_ipv4_hdr *iph, uint32_t iphdrlen, uint32_t *iptr, struct rte_mbuf *mbuf)
{
    uint16_t csum;
    uint32_t temp;
    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)iptr;

    icmp->icmp_type = ICMP_ECHOREPLY;
    icmp->icmp_cksum = 0;
    csum = rte_raw_cksum(icmp, mbuf->pkt_len-iphdrlen);
    icmp->icmp_cksum = (csum == 0xffff) ? csum : ~csum;

    iph->fragment_offset = 0;
    iph->time_to_live = INET_DEF_TTL;
    temp = iph->src_addr;
    iph->src_addr = iph->dst_addr;
    iph->dst_addr = temp;
    iph->packet_id = ip4_select_id(iph);
    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM)) {
        iph->hdr_checksum = 0;
    } else {
        ip4_send_csum(iph);
    }
    return 0;
}

int
flow_first_for_self(struct rte_mbuf *mbuf)
{
    conn_sub_t *csp;
    conn_sub_t *host_csp;
    int my_pak = 0;
    struct rte_ipv4_hdr *iph;
    uint32_t iphdrlen;
    uint32_t *iptr;
    struct flow4 fl4;

    iph = ip4_hdr(mbuf);
    iphdrlen = ip4_hdrlen(mbuf);
    iptr = rte_pktmbuf_mtod_offset(mbuf, uint32_t *, iphdrlen);

    my_pak = pak_to_my_addrs(iph, mbuf->port);
    if (my_pak) {
        flow_debug_trace(FLOW_DEBUG_BASIC, "   the packet is destined to us\n");
        my_pak=pak_for_self(iph, iptr);
        if (my_pak) {
            /* since we have no user-mode stack, we hack the icmp echo here
             * for other to-self packet, we just drop them, we may handle
             * later after having the user-mode stack
             */
            if (is_for_ping(iph, (struct rte_icmp_hdr *)iptr)) {
                flow_reply_ping(iph, iphdrlen, iptr, mbuf);

                csp = GET_CSP_FROM_MBUF(mbuf);
                host_csp = csp2peer(csp);
                memset(&fl4, 0, sizeof(struct flow4));
                fl4.fl4_daddr.s_addr = iph->dst_addr;
                fl4.fl4_oif          = netif_port_get(mbuf->port);
                fl4.fl4_proto        = IPPROTO_ICMP;
                csp->route = route4_output(&fl4);
                SET_CSP_TO_MBUF(mbuf, host_csp);
                flow_debug_trace(FLOW_DEBUG_BASIC, "   to self ping handle\n");
                return FLOW_RET_BREAK;
            } else {
                flow_debug_trace(FLOW_DEBUG_BASIC, "   to self but not ready to handle, drop the packet\n");
                return FLOW_RET_ERR;
            }
        }
    }
    return flow_next_pak_vector(mbuf);
}

int
flow_first_routing(struct rte_mbuf *mbuf)
{
    struct route_entry *rt = NULL;
    struct netif_port *ifp = NULL;
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);
    conn_sub_t *csp, *peer;

    ifp = netif_port_get(mbuf->port);
    rt = route4_input(mbuf, (struct in_addr *)&iph->dst_addr,
                      (struct in_addr *)&iph->src_addr,
                      iph->type_of_service, ifp);
    if (!rt || !rt->port) {
        flow_debug_trace(FLOW_DEBUG_BASIC, "  no route to 0x%x\n", ntohl(iph->dst_addr));
        return FLOW_RET_ERR;
    } else if (!rt->port) {
        flow_debug_trace(FLOW_DEBUG_BASIC, "  route 0x%llx have no interface\n", rt);
        return FLOW_RET_ERR;
    }

    csp = GET_CSP_FROM_MBUF(mbuf);
    peer = csp2peer(csp);
    peer->route = rt;

    flow_debug_trace(FLOW_DEBUG_BASIC, "  routed(0x%x) from %s to %s\n", 
                     ntohl(iph->dst_addr),
                     ifp->name,
                     rt->port->name);

    return flow_next_pak_vector(mbuf);
}

int
flow_first_fw_entry(struct rte_mbuf *mbuf)
{
    flow_print("  %s entry\n", __FUNCTION__);
    return flow_next_pak_vector(mbuf);
}

static int is_flow_conn_init_log  = 1;
static int
need_log_for_connection(flow_connection_t *fcp)
{
    return 0;
}

static int
gen_conn_log(flow_connection_t *fcp, int init)
{
    return 0;
}

static void
add_to_conn_hash(conn_sub_t *csp)
{
	int hash_value;
    uint32_t cnt;
	flow_connection_t *fcp = csp2base(csp);

	hash_value = conn_hash(csp->csp_src_ip, csp->csp_dst_ip, *(uint32_t *)&csp->csp_src_port);

    hlist_add_head(&csp->hnode, this_flow_conn_hash_base+hash_value);
    cnt = *(this_flow_conn_hash_cnt_base+hash_value);
    *(this_flow_conn_hash_cnt_base+hash_value) = cnt+1;
    if (flow_debug_flag & FLOW_DEBUG_BASIC) {
        char saddr[16], daddr[16];
        inet_ntop(AF_INET, &csp->csp_src_ip, saddr, sizeof(saddr));
        inet_ntop(AF_INET, &csp->csp_dst_ip, daddr, sizeof(daddr));
        flow_debug_trace_no_flag("++ csp add %d(0x%llx): %s/%d->%s/%d,%d, time %d, cspflag 0x%x\n",
                                 hash_value, csp, 
                                 saddr, ntohs(csp->csp_src_port),
                                 daddr, ntohs(csp->csp_dst_port),
                                 csp->csp_proto, fcp->time, csp->cspflag);
    }
}

/* install a flow connection
 * this vector never fail
 */
void
flow_install_conn(flow_connection_t *fcp)
{
    add_to_conn_hash(&fcp->conn_sub0);
    add_to_conn_hash(&fcp->conn_sub1);

    /* Set the reason in the new connection to creation: this is used for traffic logging */	
    fcp->reason = FC_CREATION;

    /*
     * Generate flow connection init log
     */
    if (is_flow_conn_init_log) {
        if (need_log_for_connection(fcp)) {
            gen_conn_log(fcp, 1/* init log */);
        }
    }

    fcp->fcflag |= FC_INSTALLED;
}

int
flow_filter_vector(struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *iph;
    uint32_t iphdrlen;
    uint32_t *iptr;
    char saddr[16], daddr[16];

    iph = ip4_hdr(mbuf);
    iphdrlen = ip4_hdrlen(mbuf);
    iptr = rte_pktmbuf_mtod_offset(mbuf, uint32_t *, iphdrlen);

    flow_mark_pak(iph, iptr);
    if (flow_debug_flag & FLOW_DEBUG_BASIC) {
    if (!inet_ntop(AF_INET, &iph->src_addr, saddr, sizeof(saddr)))
        return -1;
    if (!inet_ntop(AF_INET, &iph->dst_addr, daddr, sizeof(daddr)))
        return -1;
#if 0
    flow_print("%s mark this packet %d/%d->%d/%d, %d\n",
                __FUNCTION__,
                saddr, ip_src_port(*iptr),
                daddr, ip_dst_port(*iptr),
                iph->next_proto_id);
#else
    flow_print("%s mark this packet.\n", __FUNCTION__);
#endif
    }
    return flow_next_pak_vector(mbuf);
}

/*
 * flow tunnel vector
 */
int
flow_tunnel_handling(struct rte_mbuf *mbuf)
{
    return 0;
}

static inline int
is_tunnel_session(flow_connection_t *fcp)
{
    return (fcp->fcflag & FC_TUNNEL);
}

/*
 * flow decap vetor
 * in this vector we will handle tunnel decrypt & session lookup
 */
int
flow_decap_vector(struct rte_mbuf *mbuf)
{
    conn_sub_t *csp;
    flow_connection_t *fcp;
    uint32_t fcid;

    flow_print("%s entry\n", __FUNCTION__);
    csp = GET_CSP_FROM_MBUF(mbuf);
    if (!csp) {
        if (flow_find_connection(mbuf) < 0) {
            return -1;
        }
    } else {
        flow_print("  flow packet already have connection.\n");
    }

    fcp = GET_FC_FROM_MBUF(mbuf);
    if (fcp == this_flow_conn_crt) {
        fcid = 0;
    } else {
        fcid = fcp2id(fcp);
    }
    flow_print("  flow connection id %u\n", fcid);

    if (!is_tunnel_session(fcp)) {
        return flow_next_pak_vector(mbuf);
    }

    return flow_tunnel_handling(mbuf);
}

struct rte_mbuf *
flow_gen_icmp_pak(uint8_t __rte_unused type, uint8_t __rte_unused code)
{
#if 0
    struct rte_mempool *pool;
    struct rte_mbuf *mbuf = NULL;
    pool = get_mbuf_pool(this_flow);
    mbuf = rte_pktmbuf_alloc(pool);
    if (!mbuf) {
        flow_print("  %s failed, no enough mbuf\n", __FUNCTION__);
        return NULL;
    }

    flow_set_icmp_pak();

#endif
    return 0;
}

int
flow_fast_reinject_out(struct rte_mbuf *mbuf)
{
    flow_print(" %s entry.\n", __FUNCTION__);
    return flow_next_pak_vector(mbuf);
}

int
flow_fast_fw_entry(struct rte_mbuf *mbuf)
{
    flow_print(" %s entry.\n", __FUNCTION__);
    return flow_next_pak_vector(mbuf);
}

extern int ipv4_output_fin2(struct rte_mbuf *mbuf);
int
flow_fast_send_out(struct rte_mbuf *mbuf)
{
    int rc;

    flow_print(" %s entry.\n", __FUNCTION__);
    conn_sub_t *csp = GET_CSP_FROM_MBUF(mbuf);
    struct route_entry *rt = csp2peer(csp)->route;
    if (!rt->port) {
        flow_print(" route 0x%llx no interface, dest 0x%x, refcnt %d.\n",
                   rt, rt->dest, rte_atomic32_read(&rt->refcnt));
        return FLOW_RET_ERR;
    }
    rc = ipv4_output_fin2(mbuf);
    if (rc)
        return FLOW_RET_ERR;
    return flow_next_pak_vector(mbuf);
}

int
flow_send_return_pak(struct rte_mbuf *mbuf)
{
    return 0;
}

/*
 * main flow functions.
 */
int 
flow_main_body_vector (struct rte_mbuf *mbuf)
{
    flow_connection_t *fcp;
    conn_sub_t *csp;

    flow_print("%s entry\n", __FUNCTION__);
    csp = GET_CSP_FROM_MBUF(mbuf);
    fcp = csp2base(csp);
    rte_prefetch0(csp);
    rte_prefetch0(fcp);

    if (is_tunnel_conn(fcp)) {
        /* tunnel handling here */
    }

    /* check mtu here */
    /*
     * 0. packet does not terminate at us
     * 1. packet has DF bit on
     * 2. packet is bigger than min mtu size
     */
    if (0/* need to send icmp */) {
        struct rte_mbuf *npak;
        npak = flow_gen_icmp_pak(ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED);
        if (npak)
            flow_send_return_pak(npak);
        return -1;
    }

    csp->pkt_cnt ++;
    csp->byte_cnt += rte_pktmbuf_pkt_len(mbuf);

    /* goto fast path */
    flow_set_pak_vector(flow_fast_vector_list);
    return 0;
}

int
flow_drop_packet(struct rte_mbuf *mbuf)
{
    flow_debug_trace(FLOW_DEBUG_BASIC, "  drop the packet 0x%llx\n", mbuf);
    rte_pktmbuf_free(mbuf);
    return 0;
}

/*
 * the entry for one packet processing
 * give a meaningful wrapper name 
 * need to add some performance counter
 */
static void
flow_proc_one_pak(struct rte_mbuf *mbuf)
{
    int rc = FLOW_RET_OK;

    this_flow_vector_list = flow_ipv4_vector_list;

    rc = flow_walk_vector_list(mbuf);
    if (rc < 0) {
        flow_drop_packet(mbuf);
    }
    /* 
     * we do not actually send the packet out in this loop 
     * instead we call netif_hard_xmit to queue the packet 
     * in the xmit queue
     */
    /*
    if (rc == FLOW_RET_OK) {
        flow_free_packet(mbuf);
    }
    */
}

int
flow_handle_other_queue()
{
    return 0;
}
/*
 * top level pak processing scheduler.
 * better to add a poll queue
 */
int
flow_processing_paks(struct rte_mbuf *mbuf)
{
    flow_debug_trace_no_flag("%s entry, packet 0x%llx\n", 
                             __FUNCTION__, mbuf); 
    flow_debug_packet(0, mbuf);

    /* clear the mbuf dynfield1 */
    SET_CSP_TO_MBUF(mbuf, 0);

    /* add some performance counter */
    /* add some cpu constraint */
    /* add some queue handling */
    if (this_flow_status) {
        flow_proc_one_pak(mbuf);

        flow_handle_other_queue();
    }
    flow_debug_trace_no_flag("%s exit\n\n", __FUNCTION__);
    return 0;
}

int
flow_init(void)
{
    lcoreid_t cid;
    int err;

    rte_eal_mp_remote_launch(flow_conn_init, NULL, SKIP_MAIN);
    RTE_LCORE_FOREACH_WORKER(cid) {
        if ((err = rte_eal_wait_lcore(cid)) < 0) {
            RTE_LOG(ERR, FLOW, "%s: lcore %d: %s.\n",
                    __func__, cid, dpvs_strerror(err));
            return err;
        }
    }
    return 0;
}
