
#ifndef __NODE_COMMON_CLI_PRIV_H__
#define __NODE_COMMON_CLI_PRIV_H__

#include <rte_rwlock.h>

#include "route_priv.h"
#include "neigh_priv.h"
#include "vrf_priv.h"
#include "vxlan_ctrl_priv.h"
#include "conf/route6.h"
#include "route6_priv.h"
#include "conf/inetaddr.h"
#include "conf/vlan.h"
#include "inetaddr.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"

#include "../../l2_meter.h"


extern struct rte_ring *g_lcores_l3_cmd_ring[RTE_MAX_LCORE]; // for cmd pthread

typedef int (*t_dump_func)(cmd_blk_t *cbt, uint32_t lcore_id, uint32_t table_id);
typedef int (*t_cmd_func)(uint16_t type, void *str, uint32_t lcore_id);

enum common_cmd_notice_type {
    NT_SET_RT = 0,
    NT_DEL_RT,
    NT_CLEAR_RT_TBL,
    NT_CLEAR_RT_TBLS,
    NT_SET_NEI,
    NT_DEL_NEI,
    NT_CLEAR_NEI_TBL,
    NT_CLEAR_NEI_TBLS,
    NT_CREATE_VRF,
    NT_SET_VRF,
    NT_CLEAR_VRF,
    NT_CLEAR_VRFS,
    NT_DEL_VRF,
    NT_DEL_VRFS,
    NT_UNBIND_VRF,
    NT_CREATE_VXLAN_TUNN,
    NT_CLEAR_VXLAN_TUNN,
    NT_DEL_VXLAN_TUNN,
    NT_SET_RT_AUTO,
    NT_DEL_RT_AUTO,
    NT_SET_SW_NF,
    NT_SET_SW_FWD,    
    NT_SET_SW_ARP,
    NT_SET_RT6,
    NT_DEL_RT6,
    NT_CLEAR_RT6_TBL,
    NT_CLEAR_RT6_TBLS,
    NT_SET_RT6_AUTO,
    NT_DEL_RT6_AUTO,
    NT_SET_IP4,
    NT_SET_IP6,
    NT_SET_VLAN,
    NT_SET_METER,
    NT_DUMP,

    NT_MAX,
};

struct common_cmd_switch {
    uint8_t nf;
    uint8_t fwd;
    uint8_t arp;
};

struct common_cmd_notice_data {
    struct route_entry route_node;
    struct neigh_entry neigh_node;
    struct vrf_map_elem vrf_node;
    struct net_vrf vrf_bind_node;
    struct vxlan_tunnel_entry vxlan_tunnel_node;
    struct route_ifa_entry ifa;
    struct common_cmd_switch sw;
    struct dp_vs_route6_conf route6_conf;
    struct route6_ifa_entry ifa6;
    struct inet_addr_param port_ip;
    struct vlan_param vlan;
    struct meter_param meter;
};

struct common_cmd_notice_entry {
    cmd_blk_t *cbt;
    uint32_t lcore_id;
    uint32_t table_id;
    uint32_t type;
    t_dump_func dump;
    struct common_cmd_notice_data data;
    rte_rwlock_t rwlock;
};

enum common_cmd_type {
    TYPE_TBL = 1,
    TYPE_TBLS,
    TYPE_LCORE,
    TYPE_LCORES,
    TYPE_FLAG_NET,
    TYPE_FLAG_LOCAL,
    TYPE_VRFS,
    TYPE_VRFS_ELEMS,
    TYPE_VRF_ELEMS,
    TYPE_DEV_VRF,
    TYPE_VNI_VRF,
    TYPE_IP_VRF,
    TYPE_SW_NF,
    TYPE_SW_FWD,
    TYPE_SW_ARP,
    TYPE_SW_ON,
    TYPE_SW_OFF,
    TYPE_IPV4,
    TYPE_IPV6,
};

enum common_cmd_num_pos {
    POS_NUM_TBL_ID = 1,
    POS_NUM_FLAG,
    POS_NUM_MASK,
    POS_NUM_VNI,
    POS_NUM_LCORE_ID,
    POS_NUM_MAX = MAX_CMD_NUM,
};

enum common_cmd_str_pos {
    POS_STR_SIP = 1,
    POS_STR_DIP,
    POS_STR_GW,
    POS_STR_PORT,
    POS_STR_MAC,
    POS_STR_MAX = MAX_CMD_NUM,
};

enum common_cmd_which_pos {
    POS_WH_TBL = 1,
    POS_WH_LCORE,
    POS_WH_ROUTE_FLAG,
    POS_WH_SW_1,
    POS_WH_SW_2,
    POS_WH_IPV,
    POS_WH_VRF,
    POS_WH_MAX = MAX_CMD_NUM,
};

static inline int common_notice_lcores(uint32_t lcore_id,
    uint16_t type_or_size, void *src, t_cmd_func func)
{
    int ret = 0;

    if (lcore_id < RTE_MAX_LCORE) {
        if (rte_lcore_is_enabled(lcore_id) == 0) {
            return -EINVAL;
        }

        ret = func(type_or_size, src, lcore_id);
    } else {
        RTE_LCORE_FOREACH(lcore_id) {
            if (rte_lcore_is_enabled(lcore_id) == 0) {
                continue;
            }

            if (lcore_id == rte_get_main_lcore()) {
                continue;
            }

            if (netif_lcore_is_fwd_worker(lcore_id) == false) {
                continue;
            }

            if (unlikely((ret = func(type_or_size, src, lcore_id))))
                return ret;
        }
    }

    return ret;
}

static inline int dump_lcore_tbl(cmd_blk_t *cbt,
    uint32_t tbl_cnt, t_dump_func func)
{   
    int ret;
    uint32_t table_id;
    uint32_t lcore_id;

    if ((table_id = cbt->number[POS_NUM_TBL_ID - 1]) >= tbl_cnt) {
        return -EINVAL;
    }

    lcore_id = cbt->number[POS_NUM_LCORE_ID - 1];
    if (rte_lcore_is_enabled(lcore_id) == 0) {
        return -EINVAL;
    }

    if (lcore_id == rte_get_main_lcore()) {
        return -EINVAL;
    }

    if (netif_lcore_is_fwd_worker(lcore_id) == false) {
        return -EINVAL;
    }

    if ((ret = func(cbt, lcore_id, table_id)) < 0) {
        return ret;
    }

    return 0;
}

static inline int dump_lcore_tbls(cmd_blk_t *cbt, 
    uint32_t tbl_cnt, t_dump_func func)
{
    int ret;
    uint32_t table_id;
    uint32_t lcore_id;

    lcore_id = cbt->number[POS_NUM_LCORE_ID - 1];
    if (rte_lcore_is_enabled(lcore_id) == 0) {
        return -EINVAL;
    }
    if (lcore_id == rte_get_main_lcore()) {
        return -EINVAL;
    }    
    if (netif_lcore_is_fwd_worker(lcore_id) == false) {
        return -EINVAL;
    }

    for (table_id = 0; table_id < tbl_cnt; table_id++) {
        if ((ret = func(cbt, lcore_id, table_id)) < 0) {
            return ret;
        }
    }

    return 0;
}

static inline int dump_lcores_tbl(cmd_blk_t *cbt, 
    uint32_t tbl_cnt, t_dump_func func)
{   
    int ret;
    uint32_t lcore_id;
    uint32_t table_id;

    if ((table_id = cbt->number[POS_NUM_TBL_ID - 1]) >= tbl_cnt) {
        return -EINVAL;
    }

    RTE_LCORE_FOREACH(lcore_id) {
        if (rte_lcore_is_enabled(lcore_id) == 0) {
            continue;
        }

        if (lcore_id == rte_get_main_lcore()) {
            continue;
        }

        if (netif_lcore_is_fwd_worker(lcore_id) == false) {
            continue;
        }

        if ((ret = func(cbt, lcore_id, table_id)) < 0) {
            return ret;
        }
    }

    return 0;
}

static inline int dump_lcores_tbls(cmd_blk_t *cbt, 
    uint32_t tbl_cnt, t_dump_func func)
{
    int ret = -EINVAL;
    uint32_t table_id;
    uint32_t lcore_id;

    RTE_LCORE_FOREACH(lcore_id) {
        if (rte_lcore_is_enabled(lcore_id) == 0) {
            continue;
        }

        if (lcore_id == rte_get_main_lcore()) {
            continue;
        }

        if (netif_lcore_is_fwd_worker(lcore_id) == false) {
            continue;
        }

        for (table_id = 0; table_id < tbl_cnt; table_id++) {
            if ((ret = func(cbt, lcore_id, table_id)) < 0) {
                return ret;
            }
        }
    }

    return 0;
}

static inline int common_dump_sync(cmd_blk_t *cbt, 
    uint32_t tbl_cnt, t_dump_func func)
{
    int ret = -EINVAL;
    uint32_t type1, type2;

    type1 = cbt->which[POS_WH_LCORE - 1];
    type2 = cbt->which[POS_WH_TBL - 1];

    if ((type1 == TYPE_LCORE) && (type2 == TYPE_TBL)) {
        ret = dump_lcore_tbl(cbt, tbl_cnt, func);
    } else if ((type1 == TYPE_LCORE) && (type2 == TYPE_TBLS)) {
        ret = dump_lcore_tbls(cbt, tbl_cnt, func);
    } else if ((type1 == TYPE_LCORES) && (type2 == TYPE_TBL)) {
        ret = dump_lcores_tbl(cbt, tbl_cnt, func);
    } else if ((type1 == TYPE_LCORES) && (type2 == TYPE_TBLS)) {
        ret = dump_lcores_tbls(cbt, tbl_cnt, func);
    } else {
        tyflow_cmdline_printf(cbt->cl, "unknown cmd type:%u,%u\n", type1, type2);
    }

    return ret;
}

static inline int do_cmd_entry_enq(uint16_t size,
    void *str, uint32_t lcore_id)
{   
    char *cmd_noti_ent =
        (char *)rte_zmalloc_socket(
            "new_cmd_entry",
            size,
            RTE_CACHE_LINE_SIZE,
            rte_lcore_to_socket_id(lcore_id));
    if (cmd_noti_ent == NULL) {
        L3_DEBUG_TRACE(L3_ERR,
            "%s: malloc dump entry failed!!!\n", __func__);
        return -ENOMEM;
    }

    rte_memcpy(cmd_noti_ent, str, size);
    ((struct common_cmd_notice_entry *)cmd_noti_ent)->lcore_id = lcore_id;

    if (unlikely(rte_ring_enqueue(g_lcores_l3_cmd_ring[lcore_id],
            cmd_noti_ent))) {
        L3_DEBUG_TRACE(L3_ERR,
            "%s: rte_ring_enqueue failed!!!\n", __func__);
        return -EINVAL;
    }

    return 0;
}

static inline int common_cmd_entry_enq(uint32_t lcore_id,
    void *src, uint16_t size)
{
    return(common_notice_lcores(lcore_id,
        size, src, do_cmd_entry_enq));
}

static inline int common_dump_async(cmd_blk_t *cbt,
    uint32_t tbl_cnt, t_dump_func func)
{
    int ret = 0;
    uint32_t type1, type2;
    uint32_t table_id, lcore_id;
    bool table_id_v = false;
    bool lcore_id_v = false;
    
    type1 = cbt->which[POS_WH_LCORE - 1];
    type2 = cbt->which[POS_WH_TBL - 1];

    if ((type1 == TYPE_LCORE) && (type2 == TYPE_TBL)) {
        table_id = cbt->number[POS_NUM_TBL_ID - 1];
        lcore_id = cbt->number[POS_NUM_LCORE_ID - 1];
        table_id_v = true;
        lcore_id_v = true;
    } else if ((type1 == TYPE_LCORE) && (type2 == TYPE_TBLS)) {
        table_id = tbl_cnt;
        lcore_id = cbt->number[POS_NUM_LCORE_ID - 1];
        lcore_id_v = true;
    } else if ((type1 == TYPE_LCORES) && (type2 == TYPE_TBL)) {
        table_id = cbt->number[POS_NUM_TBL_ID - 1];
        table_id_v = true;
    } else if ((type1 == TYPE_LCORES) && (type2 == TYPE_TBLS)) {
        table_id = tbl_cnt;
    } else {
        tyflow_cmdline_printf(cbt->cl, "unknown cmd type:%u,%u\n", type1, type2);
        return -EINVAL;
    }

    if (table_id_v) {
        if (table_id >= tbl_cnt) {
            return -EINVAL;
        }
    }

    struct common_cmd_notice_entry cmd_noti_ent;
    cmd_noti_ent.cbt = cbt;
    cmd_noti_ent.type = NT_DUMP;
    cmd_noti_ent.table_id = table_id;
    cmd_noti_ent.dump = func;

    if (lcore_id_v) {
        ret = common_cmd_entry_enq(lcore_id, &cmd_noti_ent,
            sizeof(struct common_cmd_notice_entry));
    } else {
        ret = common_cmd_entry_enq(LCORE_ID_ANY, &cmd_noti_ent,
            sizeof(struct common_cmd_notice_entry));
    }

    return ret;
}

static inline int
neigh_atoi(uint8_t *d_mac, char *s_mac)
{
    int i;
    char *end;
    unsigned long o[RTE_ETHER_ADDR_LEN];

    i = 0;
    do {
        errno = 0;
        o[i] = strtoul(s_mac, &end, 16);
        if (errno != 0 || end == s_mac || (end[0] != ':' && end[0] != 0))
            return -1;
        s_mac = end + 1;
    } while (++i != RTE_DIM(o) / sizeof(o[0]) && end[0] != 0);

    /* Junk at the end of line */
    if (end[0] != 0)
        return -1;

    /* Support the format XX:XX:XX:XX:XX:XX */
    if (i == RTE_ETHER_ADDR_LEN) {
        while (i-- != 0) {
            if (o[i] > UINT8_MAX)
                return -1;
            d_mac[i] = (uint8_t)o[i];
        }
    /* Support the format XXXX:XXXX:XXXX */
    } else if (i == RTE_ETHER_ADDR_LEN / 2) {
        while (i-- != 0) {
            if (o[i] > UINT16_MAX)
                return -1;
            d_mac[i * 2] =
                (uint8_t)(o[i] >> 8);
            d_mac[i * 2 + 1] =
                (uint8_t)(o[i] & 0xff);
        }
    /* unknown format */
    } else
        return -1;

    return 0;
}

static inline int neigh_atoi_bak(uint8_t *d_mac, char *s_mac)
{
    int i;
    char *start, *end;

    if (unlikely(s_mac == NULL) || (d_mac == NULL)) {
        return -EINVAL;
    }

    start = s_mac;
    for (i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
        if (start == NULL) {
            return -EINVAL;
        }

        d_mac[i] = strtoul(start, &end, 16);
        if (end == NULL) {
            return -EINVAL;
        }
        start = end + 1;
    }

    return 0;
}

#endif
