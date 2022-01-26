#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

/* Internal header files */
#include "vxlan_ctrl_priv.h"
#include "vxlan_cli_priv.h"
#include "common_priv.h"
#include "common_cli_priv.h"

/* External header files */
#include "netif.h"
#include "list.h"

extern struct common_cmd_notice_entry cmd_notice_entry;
extern struct vxlan_tunnel_table *g_lcores_vxlan_tunnel_table_p[RTE_MAX_LCORE]; // for cmd pthread
typedef int (*t_v_func)(uint32_t lcore_id, cmd_blk_t *cbt, void **tbl);

static inline int do_vxlan_tunnel_vni_dump_node(
    cmd_blk_t *cbt,
    struct vxlan_tunnel_entry *vxlan_tunnel_node)
{    
    char s_ip[INET_ADDRSTRLEN] = {0};
    char r_ip[INET_ADDRSTRLEN] = {0};
    char dst_addr[64] = {0};

    if (vxlan_tunnel_node->family == AF_INET) {
        inet_ntop(AF_INET, &vxlan_tunnel_node->saddr,
                        dst_addr, sizeof(dst_addr));
        snprintf(s_ip, INET_ADDRSTRLEN, "%s", dst_addr);

        memset(dst_addr, 0, sizeof(dst_addr));
        inet_ntop(AF_INET, &vxlan_tunnel_node->remote_ip,
                dst_addr, sizeof(dst_addr));
        snprintf(r_ip, INET_ADDRSTRLEN, "%s", dst_addr);

        tyflow_cmdline_printf(cbt->cl, "ipv4 tunnel,vni:%u,source ip is %s,remote ip is %s\n", 
            vxlan_tunnel_node->vni, s_ip, r_ip);

        return 0;
    } else if (vxlan_tunnel_node->family == AF_INET6) {
        inet_ntop(AF_INET6, &vxlan_tunnel_node->saddr,
                        dst_addr, sizeof(dst_addr));

        snprintf(s_ip, INET6_ADDRSTRLEN, "%s", dst_addr);

        memset(dst_addr, 0, sizeof(dst_addr));
        inet_ntop(AF_INET6, &vxlan_tunnel_node->remote_ip,
                dst_addr, sizeof(dst_addr));
        snprintf(r_ip, INET6_ADDRSTRLEN, "%s", dst_addr);

        tyflow_cmdline_printf(cbt->cl, "ipv6 tunnel,vni:%u,source ip is %s,remote ip is %s\n", 
            vxlan_tunnel_node->vni, s_ip, r_ip);

        return 0;
    }

    tyflow_cmdline_printf(cbt->cl, "unknown family:%u\n", vxlan_tunnel_node->family); 
    return -1;
}

static inline int vxlan_tunnel_vnis_dump_node(uint32_t lcore_id, cmd_blk_t *cbt, void **tbl)
{
    int i;
    struct vxlan_tunnel_table *vxlan_tunnel_table = (struct vxlan_tunnel_table *)tbl;
    struct vxlan_tunnel_entry *vxlan_tunnel_node;

    if (vxlan_tunnel_table->cnt.cnt) {
        tyflow_cmdline_printf(cbt->cl, "lcore id:%u\n", lcore_id);
        tyflow_cmdline_printf(cbt->cl, "vxlan tunnel table cnt:%u\n", vxlan_tunnel_table->cnt.cnt);
        for (i = 0; i < VXLAN_TUNNEL_BUCKETS_NUM; i++) {
            hlist_for_each_entry(vxlan_tunnel_node, &vxlan_tunnel_table->ht[i], hnode){
                do_vxlan_tunnel_vni_dump_node(cbt, vxlan_tunnel_node);
            }
        }
    }

    return 0;   
}

static inline struct vxlan_tunnel_entry * vxlan_tunnel_lookup_cli(
    uint32_t vni_val,
    struct vxlan_tunnel_table *tbl)
{
    struct vxlan_tunnel_entry *pos;
    HLIST_TABLE_LOOKUP(vni_val, VXLAN_TUNNEL_BUCKETS_NUM, my_hash1, 
        pos, *tbl, ht, hnode, vni);
}

static inline int vxlan_tunnel_vni_dump_node(uint32_t lcore_id, cmd_blk_t *cbt, void **tbl)
{
    struct vxlan_tunnel_table *vxlan_tunnel_table = (struct vxlan_tunnel_table *)tbl;
    struct vxlan_tunnel_entry *vxlan_tunnel_node;
    uint32_t vni = cbt->number[POS_NUM_VNI - 1];

    vxlan_tunnel_node = vxlan_tunnel_lookup_cli(vni, vxlan_tunnel_table);
    if (unlikely(vxlan_tunnel_node == NULL)) {
        return -EINVAL;
    }

    tyflow_cmdline_printf(cbt->cl, "lcore id:%u\n", lcore_id);
    do_vxlan_tunnel_vni_dump_node(cbt, vxlan_tunnel_node);

    return 0;
}

static inline int common_vxlan_dump_lcore(uint32_t lcore_id, cmd_blk_t *cbt, void **tbl, t_v_func func)
{
    void *tbl_find = NULL;

    if (unlikely(rte_lcore_is_enabled(lcore_id) == 0)) {
        return -EINVAL;
    }

    if (unlikely(lcore_id == rte_get_main_lcore())) {
        return -EINVAL;
    }

    if (unlikely(netif_lcore_is_fwd_worker(lcore_id) == false)) {
        return -EINVAL;
    }

    if (unlikely(tbl == NULL)) {
        return -EINVAL;
    }

    tbl_find = tbl[lcore_id];
    return(func(lcore_id, cbt, tbl_find));
}

static inline int common_vxlan_dump_all_lcore(cmd_blk_t *cbt, void **tbl, t_v_func func)
{
    int ret;
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

        if (unlikely((ret = common_vxlan_dump_lcore(lcore_id, cbt, tbl, func)))) {
            return ret;
        }
    }

    return 0;
}

static inline int common_vxlan_dump(cmd_blk_t *cbt, void **tbl, t_v_func func)
{
    int ret = -EINVAL;

    switch (cbt->which[POS_WH_LCORE - 1]) {
        case TYPE_LCORE:
            ret = common_vxlan_dump_lcore(cbt->number[POS_NUM_LCORE_ID - 1], cbt, tbl, func);
            break;
        case TYPE_LCORES:
            ret = common_vxlan_dump_all_lcore(cbt, tbl, func);
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "unknown cmd id:%u\n", cbt->which[POS_WH_LCORE - 1]);
            break;
    }

    return ret;
}

static inline int show_vxlan_cli(cmd_blk_t *cbt)
{  
    int ret = -EINVAL;

    switch (cbt->which[POS_WH_TBL - 1]) {
        case TYPE_TBL:
            ret = common_vxlan_dump(cbt, (void *)g_lcores_vxlan_tunnel_table_p, vxlan_tunnel_vni_dump_node);
            break;
        case TYPE_TBLS:
            ret = common_vxlan_dump(cbt, (void *)g_lcores_vxlan_tunnel_table_p, vxlan_tunnel_vnis_dump_node);
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "unknown cmd id:%u\n", cbt->which[POS_WH_TBL - 1]);
            break;
    }

    return ret;
}

EOL_NODE(show_vxlan_eol, show_vxlan_cli);
KW_NODE_WHICH(show_vxlan_tunnel_vnis, show_vxlan_eol, none, "vnis", "all vxlan tunnel", POS_WH_TBL, TYPE_TBLS);
VALUE_NODE(show_vxlan_tunnel_vni_val, show_vxlan_eol, none, "vni value", POS_NUM_VNI, NUM);
KW_NODE_WHICH(show_vxlan_tunnel_vni, show_vxlan_tunnel_vni_val, show_vxlan_tunnel_vnis, "vni", "vxlan net id", POS_WH_TBL, TYPE_TBL);
KW_NODE_WHICH(show_vxlan_tunnel_cids, show_vxlan_tunnel_vni, none, "lcores", "all lcore id", POS_WH_LCORE, TYPE_LCORES);
VALUE_NODE(show_vxlan_tunnel_cid_val, show_vxlan_tunnel_vni, none, "lcore id value", POS_NUM_LCORE_ID, NUM);
KW_NODE_WHICH(show_vxlan_tunnel_cid, show_vxlan_tunnel_cid_val, show_vxlan_tunnel_cids, "lcore", "lcore id", POS_WH_LCORE, TYPE_LCORE);

KW_NODE(show_vxlan_tunnel, show_vxlan_tunnel_cid, none, "tunnel", "show vxlan tunnel");
KW_NODE(show_vxlan, show_vxlan_tunnel, none, "vxlan", "show vxlan related items");

static inline int clear_vxlan_notice(cmd_blk_t *cbt)
{
    uint16_t lcore_id;
    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    cmd_notice_entry.type = NT_CLEAR_VXLAN_TUNN;
    cmd_notice_entry.cbt = cbt;
    rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);

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

        cmd_notice_entry.lcore_id = lcore_id;
        while(rte_get_main_lcore() != cmd_notice_entry.lcore_id);
    }

    return 0;
}

static int clear_vxlan_cli(cmd_blk_t *cbt)
{   
    return(clear_vxlan_notice(cbt));
}

EOL_NODE(clear_vxlan_eol, clear_vxlan_cli);
KW_NODE(clear_vxlan_tunnel, clear_vxlan_eol, none, "vnis", "all vxlan tunnel");
//KW_NODE(clear_vxlan, clear_vxlan_tunnel, none, "vxlan", "clear vxlan related items");

static inline int vxlan_tunnel_cpy(
    struct vxlan_tunnel_entry *vxlan_tunnel_node,
    cmd_blk_t *cbt)
{
    vxlan_tunnel_node->vni = cbt->number[POS_NUM_VNI - 1];
    memset(&vxlan_tunnel_node->saddr, 0, sizeof(union inet_addr));
    memset(&vxlan_tunnel_node->remote_ip, 0, sizeof(union inet_addr));

    switch (cbt->which[POS_WH_IPV - 1]) {
        case TYPE_IPV4:
            if (strlen(cbt->string[POS_STR_DIP - 1]) <= 0) {
                return -1;
            }
            if (strlen(cbt->string[POS_STR_SIP - 1]) <= 0) {
                return -2;
            }
            if (unlikely(inet_pton(AF_INET, cbt->string[POS_STR_SIP - 1],
                &vxlan_tunnel_node->saddr) != 1)) {
                return -4;
            }
            if (unlikely(inet_pton(AF_INET, cbt->string[POS_STR_DIP - 1],
                &vxlan_tunnel_node->remote_ip) != 1)) {
                return -3;
            }   
            vxlan_tunnel_node->family = AF_INET;
            break;
        case TYPE_IPV6:            
            if (strlen(cbt->string[POS_STR_DIP - 1]) <= 0) {
                return -11;
            }
            if (strlen(cbt->string[POS_STR_SIP - 1]) <= 0) {
                return -22;
            }
            if (unlikely(inet_pton(AF_INET6, cbt->string[POS_STR_SIP - 1],
                &vxlan_tunnel_node->saddr) != 1)) {
                return -44;
            }
            if (unlikely(inet_pton(AF_INET6, cbt->string[POS_STR_DIP - 1],
                &vxlan_tunnel_node->remote_ip) != 1)) {
                return -33;
            }   
            vxlan_tunnel_node->family = AF_INET6;
            break;
        default:
            return -5;
    }
    return 0;
}

static inline int del_vxlan_notice(cmd_blk_t *cbt)
{
    int ret;
    uint16_t lcore_id;

    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    if (unlikely((ret = vxlan_tunnel_cpy(&cmd_notice_entry.data.vxlan_tunnel_node, cbt)))) {
        tyflow_cmdline_printf(cbt->cl, "vxlan_tunnel_cpy err %d\n", ret);
        rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);
        return -EINVAL;
    }
    cmd_notice_entry.type = NT_DEL_VXLAN_TUNN;
    cmd_notice_entry.cbt = cbt;
    rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);

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

        cmd_notice_entry.lcore_id = lcore_id;
        while(rte_get_main_lcore() != cmd_notice_entry.lcore_id);
    }

    return 0;
}

static int del_vxlan_cli(cmd_blk_t *cbt)
{   
    return(del_vxlan_notice(cbt));
}

EOL_NODE(del_vxlan_eol, del_vxlan_cli);
VALUE_NODE(del_vxlan_tunnel_vni_val, del_vxlan_eol, none, "vni value", POS_NUM_VNI, NUM);
//KW_NODE(del_vxlan_tunnel, del_vxlan_tunnel_vni_val, none, "tunnel", "del vxlan tunnel");
//KW_NODE(del_vxlan, del_vxlan_tunnel, none, "vxlan", "del vxlan related items");

static inline int create_vxlan_tunnel_notice(cmd_blk_t *cbt)
{
    uint32_t lcore_id;
    int ret;

    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    if (unlikely((ret = vxlan_tunnel_cpy(&cmd_notice_entry.data.vxlan_tunnel_node, cbt)))) {
        tyflow_cmdline_printf(cbt->cl, "vxlan_tunnel_cpy err %d\n", ret);
        rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);
        return -EINVAL;
    }
    cmd_notice_entry.type = NT_CREATE_VXLAN_TUNN;
    cmd_notice_entry.cbt = cbt;
    rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);

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

        cmd_notice_entry.lcore_id = lcore_id;
        while(rte_get_main_lcore() != cmd_notice_entry.lcore_id);
    }

    return 0;
}

static inline int create_vxlan_cli(cmd_blk_t *cbt)
{  
    return(create_vxlan_tunnel_notice(cbt));
}

EOL_NODE(create_vxlan_eol, create_vxlan_cli);
VALUE_NODE(create_vxlan_tunnel_v6_rip_val, create_vxlan_eol, none, "remote ip,IPv6 address", POS_STR_DIP, STR);
KW_NODE(create_vxlan_tunnel_v6_rip, create_vxlan_tunnel_v6_rip_val, none, "rip", "remote ip");
VALUE_NODE(create_vxlan_tunnel_v6_sip_val, create_vxlan_tunnel_v6_rip, none, "source ip,IPv6 address", POS_STR_SIP, STR);
KW_NODE(create_vxlan_tunnel_v6_sip, create_vxlan_tunnel_v6_sip_val, none, "sip", "source ip");
KW_NODE_WHICH(create_vxlan_tunnel_ipv6, create_vxlan_tunnel_v6_sip, none, "v6", "IPv6 address", POS_WH_IPV, TYPE_IPV6);
VALUE_NODE(create_vxlan_tunnel_v4_rip_val, create_vxlan_eol, none, "remote ip,IPv4 address", POS_STR_DIP, STR);
KW_NODE(create_vxlan_tunnel_v4_rip, create_vxlan_tunnel_v4_rip_val, none, "rip", "remote ip");
VALUE_NODE(create_vxlan_tunnel_v4_sip_val, create_vxlan_tunnel_v4_rip, none, "source ip,IPv4 address", POS_STR_SIP, STR);
KW_NODE(create_vxlan_tunnel_v4_sip, create_vxlan_tunnel_v4_sip_val, none, "sip", "source ip");
KW_NODE_WHICH(create_vxlan_tunnel_ipv4, create_vxlan_tunnel_v4_sip, create_vxlan_tunnel_ipv6, "v4", "IPv4 address", POS_WH_IPV, TYPE_IPV4);
VALUE_NODE(create_vxlan_tunnel_vni_val, create_vxlan_tunnel_ipv4, none, "vni value", POS_NUM_VNI, NUM);
KW_NODE(create_vxlan_tunnel_vni, create_vxlan_tunnel_vni_val, none, "vni", "vxlan net id");
KW_NODE(create_vxlan_tunnel, create_vxlan_tunnel_vni, none, "tunnel", "create vxlan tunnel");
KW_NODE_WHICH(del_vxlan_tunnel_vni, del_vxlan_tunnel_vni_val, clear_vxlan_tunnel, "vni", "vxlan net id", POS_WH_TBL, TYPE_TBL);
KW_NODE(unset_vxlan_tunnel, del_vxlan_tunnel_vni, none, "tunnel", "unset vxlan tunnel");
TEST_UNSET(test_unset_vxlan_tunnel, unset_vxlan_tunnel, create_vxlan_tunnel);
KW_NODE(create_vxlan, test_unset_vxlan_tunnel, none, "vxlan", "create vxlan related items");

void vxlan_cli_init(void)
{
    add_get_cmd(&cnode(show_vxlan));
    //add_create_cmd(&cnode(create_vxlan));
    add_set_cmd(&cnode(create_vxlan));
    //add_clear_cmd(&cnode(clear_vxlan));
    //add_move_cmd(&cnode(del_vxlan));
    return;
}

