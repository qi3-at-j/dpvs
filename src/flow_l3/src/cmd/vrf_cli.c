#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

/* Internal header files */
#include "vrf_priv.h"
#include "vrf_cli_priv.h"
#include "route_priv.h"
#include "common_cli_priv.h"

/* External header files */
#include "netif.h"
#include "list.h"

extern struct common_cmd_notice_entry cmd_notice_entry;
extern struct vrf_map *g_lcores_vrf_table_p[RTE_MAX_LCORE];
#if VRF_USE_VNI_HASH
extern struct vrf_vni_map *g_lcores_vrf_vni_table_p[RTE_MAX_LCORE];
#endif
#if VRF_USE_IP_HASH
extern struct vrf_ip_map *g_lcores_vrf_ip_table_p[RTE_MAX_LCORE];
#endif

typedef int (*t_f_func)(uint32_t lcore_id, cmd_blk_t *cbt, void **tbl);

static inline int vrfs_dump_node(uint32_t lcore_id,
    cmd_blk_t *cbt, void **tbl)
{    
    int i;
    struct vrf_map_elem *vrf_node;
    struct vrf_map *vrf_map = (struct vrf_map *)tbl;

    if (vrf_map->cnt.cnt) {
        tyflow_cmdline_printf(cbt->cl, "lcore id:%u\n", lcore_id);
        tyflow_cmdline_printf(cbt->cl, "vrf table cnt:%u\n",
            vrf_map->cnt.cnt);
        tyflow_cmdline_printf(cbt->cl, "VRF_ID\n");
        for (i = 0; i < VRF_BUCKETS_NUM; i++) {
            hlist_for_each_entry(vrf_node, &vrf_map->ht[i], hnode){
                tyflow_cmdline_printf(cbt->cl, "%u\n",
                    vrf_node->table_id);
            }
        }
    }

    return 0;
}

static inline int elems_dump_node(cmd_blk_t *cbt,
    struct list_head *vrf_list)
{
    struct net_vrf *net_vrf_node;
    char dst_addr[64] = {0};

    list_for_each_entry(net_vrf_node, vrf_list, me_list) {
        if (net_vrf_node) {          
            switch (net_vrf_node->type) {
#if VRF_USE_DEV_HASH
                case VRF_TYPE_PORT:
                    tyflow_cmdline_printf(cbt->cl, "(port_id)%u,(port_name)%s\n",
                        net_vrf_node->port->id, net_vrf_node->port->name);
                break;
#endif
#if VRF_USE_VNI_HASH
                case VRF_TYPE_VNI:
                    tyflow_cmdline_printf(cbt->cl, "(vni)%u\n", net_vrf_node->vni);
                break;
#endif
#if VRF_USE_IP_HASH
                case VRF_TYPE_IP:
                    inet_ntop(net_vrf_node->family, &net_vrf_node->ip,
                        dst_addr, sizeof(dst_addr));
                    tyflow_cmdline_printf(cbt->cl, "(ip%u)%s\n",
                        (net_vrf_node->family == AF_INET)?4:6,
                        dst_addr);
                break;
#endif
                default:
                    return -EINVAL;
            }
            
        }
    }

    return 0;
}

static inline int vrfs_elems_dump_node(uint32_t lcore_id,
    cmd_blk_t *cbt, void **tbl)
{
    struct vrf_map_elem *vrf_node;
    int i;
    struct vrf_map *vrf_map = (struct vrf_map *)tbl;

    if (vrf_map->cnt.cnt) {
        tyflow_cmdline_printf(cbt->cl, "lcore id:%u\n", lcore_id);
        tyflow_cmdline_printf(cbt->cl, "vrf table cnt:%u\n", vrf_map->cnt.cnt);
        for (i = 0; i < VRF_BUCKETS_NUM; i++) {
            hlist_for_each_entry(vrf_node, &vrf_map->ht[i], hnode){
                tyflow_cmdline_printf(cbt->cl, "vrf id:%u,vrf bind cnt:%u\n", 
                    vrf_node->table_id, vrf_node->cnt.cnt);
                elems_dump_node(cbt, &vrf_node->vrf_list);
            }
        }
    }

    return 0;
}

static inline struct vrf_map_elem *vrf_lookup_cli(uint32_t table_id,
    struct vrf_map *vrf_map)
{
    uint32_t key;
    struct vrf_map_elem *vrf_node;
    
    key = my_hash1(table_id, VRF_BUCKETS_NUM);
    hlist_for_each_entry(vrf_node, &vrf_map->ht[key], hnode) {
        if (vrf_node->table_id == table_id) {
            return vrf_node;
        }
    }

    return NULL;
}

static inline int vrf_elems_dump_node(uint32_t lcore_id,
    cmd_blk_t *cbt, void **tbl)
{
    struct vrf_map_elem *vrf_node;
    uint32_t table_id;
    struct vrf_map *vrf_map = (struct vrf_map *)tbl;

    table_id = cbt->number[POS_NUM_TBL_ID - 1];
    vrf_node = vrf_lookup_cli(table_id, vrf_map);
    if (unlikely(vrf_node == NULL)) {
        return -EINVAL;
    }

    tyflow_cmdline_printf(cbt->cl, "lcore id:%u\n", lcore_id);
    tyflow_cmdline_printf(cbt->cl, "vrf id:%u,vrf bind cnt:%u\n", 
        vrf_node->table_id, vrf_node->cnt.cnt);
    return(elems_dump_node(cbt, &vrf_node->vrf_list));

    return 0;
}

#if VRF_USE_DEV_HASH
static inline int dev_vrf_dump_node(uint32_t lcore_id,
    cmd_blk_t *cbt, void **tbl)
{
    RTE_SET_USED(tbl);
    struct netif_port *port = netif_port_get_by_name(cbt->string[POS_VRF_PORT - 1]);
    if (unlikely(port == NULL)) {
        return -EINVAL;
    }

    if (port->table_id != GLOBAL_ROUTE_TBL_ID) {
        tyflow_cmdline_printf(cbt->cl, "lcore id:%u\n", lcore_id);
        tyflow_cmdline_printf(cbt->cl, "(pid)%u,(port name)%s->(vid)%u\n",
            port->id, port->name, port->table_id);
    } else {
        tyflow_cmdline_printf(cbt->cl, "not bind to vrf\n");
    }

    return 0;
}
#endif

#if VRF_USE_VNI_HASH
static inline struct net_vrf *vni_lookup_cli(uint32_t vni,
    struct vrf_vni_map *vni_map)
{
    uint32_t key = my_hash1(vni, VNI_BUCKETS_NUM);
    struct net_vrf *vni_node;

    hlist_for_each_entry(vni_node, &vni_map->ht[key], hnode) {
        if (vni_node->vni == vni) {
            return vni_node;
        }
    }

    return NULL; 
}

static inline int vni_vrf_dump_node(uint32_t lcore_id,
    cmd_blk_t *cbt, void **tbl)
{
    struct vrf_vni_map *vni_map = (struct vrf_vni_map *)tbl;
    struct net_vrf *net_vrf_node;
    uint32_t vni = cbt->number[POS_NUM_VNI - 1];

    net_vrf_node = vni_lookup_cli(vni, vni_map);

    if (likely(net_vrf_node)) {
        tyflow_cmdline_printf(cbt->cl, "lcore id:%u\n", lcore_id);
        tyflow_cmdline_printf(cbt->cl, "(vni)%u->(vid)%u\n",
            vni, net_vrf_node->table_id);
    } else {
        tyflow_cmdline_printf(cbt->cl, "not bind to vrf\n");
    }

    return 0;
}
#endif

#if VRF_USE_IP_HASH
static inline struct net_vrf *ip_lookup_cli(uint8_t af,
    union inet_addr *ip, struct vrf_ip_map *vrf_ip_map)
{
#if USE_HASH_3
    uint32_t key = my_hash3(af, ip, IP_BUCKETS_NUM);
#else
    uint32_t key = my_hash2(ip, sizeof(union inet_addr), IP_BUCKETS_NUM);
#endif

    struct net_vrf *net_vrf;

    hlist_for_each_entry(net_vrf, &vrf_ip_map->ht[key], hnode) {
        if ((af == net_vrf->family) &&
            (inet_addr_eq(af, &net_vrf->ip, ip))) {
                return net_vrf;
        }
    }

    return NULL; 
}

static inline int ip_vrf_dump_node(uint32_t lcore_id,
    cmd_blk_t *cbt, void **tbl)
{
    struct vrf_ip_map *vrf_ip_map = (struct vrf_ip_map *)tbl;
    struct net_vrf *net_vrf_node;
    union inet_addr ip;
    char dst_addr[64] = {0};
    uint8_t af;

    memset(&ip, 0, sizeof(union inet_addr));
    if (cbt->which[POS_WH_IPV - 1] == TYPE_IPV4) {
        af = AF_INET;
    } else {
        af = AF_INET6;
    }

    if (unlikely(inet_pton(af, cbt->string[POS_STR_DIP - 1], &ip) != 1)) {            
        tyflow_cmdline_printf(cbt->cl,
            "the ip address is not available\n");
        return -EINVAL;
    }

    net_vrf_node = ip_lookup_cli(af, &ip, vrf_ip_map);
    if (likely(net_vrf_node)) {
        inet_ntop(net_vrf_node->family, &net_vrf_node->ip,
            dst_addr, sizeof(dst_addr));
        tyflow_cmdline_printf(cbt->cl, "lcore id:%u\n", lcore_id);
        tyflow_cmdline_printf(cbt->cl, "(ip%u)%s->(vid)%u\n",
            (net_vrf_node->family == AF_INET)?4:6,
            dst_addr, net_vrf_node->table_id);
    } else {
        tyflow_cmdline_printf(cbt->cl, "not bind to vrf\n");
    }

    return 0;
}
#endif

static inline int common_vrf_dump_lcore(uint32_t lcore_id, cmd_blk_t *cbt, void **tbl, t_f_func func)
{
    void *tbl_find = NULL;

    if (rte_lcore_is_enabled(lcore_id) == 0) {
        return -EINVAL;
    }

    if (lcore_id == rte_get_main_lcore()) {
        return -EINVAL;
    }    

    if (netif_lcore_is_fwd_worker(lcore_id) == false) {
        return -EINVAL;
    }

    if (tbl) {
        tbl_find = tbl[lcore_id];
    }

    return(func(lcore_id, cbt, tbl_find));
}

static inline int common_vrf_dump_all_lcore(cmd_blk_t *cbt, void **tbl, t_f_func func)
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

        if (unlikely((ret = common_vrf_dump_lcore(lcore_id, cbt, tbl, func)))) {
            return ret;
        }
    }

    return 0;
}

static inline int common_vrf_dump(cmd_blk_t *cbt, void **tbl, t_f_func func)
{
    int ret = -EINVAL;

    switch (cbt->which[POS_WH_LCORE - 1]) {
        case TYPE_LCORE:
            ret = common_vrf_dump_lcore(cbt->number[POS_NUM_LCORE_ID - 1], cbt, tbl, func);
            break;
        case TYPE_LCORES:
            ret = common_vrf_dump_all_lcore(cbt, tbl, func);
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "unknown cmd id:%u\n", cbt->which[POS_NUM_LCORE_ID - 1]);
            break;
    }

    return ret;
}

static int show_vrf_cli(cmd_blk_t *cbt)
{  
    int ret = -EINVAL;

    switch (cbt->which[POS_WH_TBL - 1]) {
        case TYPE_VRFS:
            ret = common_vrf_dump(cbt, (void *)g_lcores_vrf_table_p,
                vrfs_dump_node);
            break;
        case TYPE_VRFS_ELEMS:
            ret = common_vrf_dump(cbt, (void *)g_lcores_vrf_table_p,
                vrfs_elems_dump_node);
            break;
        case TYPE_VRF_ELEMS:
            ret = common_vrf_dump(cbt, (void *)g_lcores_vrf_table_p,
                vrf_elems_dump_node);
            break;
#if VRF_USE_DEV_HASH
        case TYPE_DEV_VRF:
            ret = common_vrf_dump(cbt, NULL, dev_vrf_dump_node);
            break;
#endif
#if VRF_USE_VNI_HASH
        case TYPE_VNI_VRF:
            ret = common_vrf_dump(cbt, (void *)g_lcores_vrf_vni_table_p,
                vni_vrf_dump_node);
            break;
#endif
#if VRF_USE_IP_HASH
        case TYPE_IP_VRF:
            ret = common_vrf_dump(cbt, (void *)g_lcores_vrf_ip_table_p,
                ip_vrf_dump_node);
            break;
#endif
        default:
            tyflow_cmdline_printf(cbt->cl, "unknown cmd id:%u\n", cbt->which[POS_WH_TBL - 1]);
            break;
    }

    return ret;
}

EOL_NODE(show_vrf_eol, show_vrf_cli);

#if VRF_USE_IP_HASH
VALUE_NODE(show_ip6_vrf_val, show_vrf_eol, none, "ip6 addr value", POS_STR_DIP, STR);
KW_NODE_WHICH(show_ip6_vrf, show_ip6_vrf_val, none, "v6", "ip6 addr", POS_WH_IPV, TYPE_IPV6);
VALUE_NODE(show_ip4_vrf_val, show_vrf_eol, none, "ip4 addr value", POS_STR_DIP, STR);
KW_NODE_WHICH(show_ip4_vrf, show_ip4_vrf_val, show_ip6_vrf, "v4", "ip4 addr", POS_WH_IPV, TYPE_IPV4);
KW_NODE_WHICH(show_ip_vrf, show_ip4_vrf, none, "ip_vrf", "ip of vrf", POS_WH_TBL, TYPE_IP_VRF);
#endif

#if VRF_USE_DEV_HASH
VALUE_NODE(show_elem_vrf_val, show_vrf_eol, none, "dev(port) name", POS_STR_PORT, STR);
#if VRF_USE_IP_HASH
KW_NODE_WHICH(show_elem_vrf, show_elem_vrf_val, show_ip_vrf, "dev_vrf", "dev of vrf", POS_WH_TBL, TYPE_DEV_VRF);
#else
KW_NODE_WHICH(show_elem_vrf, show_elem_vrf_val, none, "dev_vrf", "dev of vrf", POS_WH_TBL, TYPE_DEV_VRF);
#endif
#endif

#if VRF_USE_VNI_HASH
VALUE_NODE(show_elem_vrf_val, show_vrf_eol, none, "vni value", POS_NUM_VNI, NUM);
#if VRF_USE_IP_HASH
KW_NODE_WHICH(show_elem_vrf, show_elem_vrf_val, show_ip_vrf, "vni_vrf", "vni of vrf", POS_WH_TBL, TYPE_VNI_VRF);
#else
KW_NODE_WHICH(show_elem_vrf, show_elem_vrf_val, none, "vni_vrf", "vni of vrf", POS_WH_TBL, TYPE_VNI_VRF);
#endif
#endif

VALUE_NODE(show_vrf_id_val, show_vrf_eol, none, "vrf id value <[1, MAX]>", POS_NUM_TBL_ID, NUM);
KW_NODE_WHICH(show_vrf_elems, show_vrf_id_val, show_elem_vrf, "vrf_elems", "all elem of vrf", POS_WH_TBL, TYPE_VRF_ELEMS);

KW_NODE_WHICH(show_vrfs_vnis, show_vrf_eol, show_vrf_elems, "vrfs_elems", "all elem of vrfs", POS_WH_TBL, TYPE_VRFS_ELEMS);
KW_NODE_WHICH(show_vrfs, show_vrf_eol, show_vrfs_vnis, "vrfs", "all vrf id", POS_WH_TBL, TYPE_VRFS);
KW_NODE_WHICH(show_vrf_cids, show_vrfs, none, "lcores", "vrf lcore ids", POS_WH_LCORE, TYPE_LCORES);
VALUE_NODE(show_vrf_cid_val, show_vrfs, none, "lcore id value", POS_NUM_LCORE_ID, NUM);
KW_NODE_WHICH(show_vrf_cid, show_vrf_cid_val, show_vrf_cids, "lcore", "vrf lcore id", POS_WH_LCORE, TYPE_LCORE);
KW_NODE(show_vrf, show_vrf_cid, none, "vrf_l3", "show vrf related items");

#if 0
static inline int clear_vrf_notice(cmd_blk_t *cbt)
{
    uint16_t lcore_id;
    extern uint32_t g_table_id;

    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    cmd_notice_entry.data.vrf_bind_node.table_id = cbt->number[POS_NUM_TBL_ID - 1];
    cmd_notice_entry.type = NT_CLEAR_VRF;
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

static inline int clear_vrfs_notice(cmd_blk_t *cbt)
{
    uint16_t lcore_id;

    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    cmd_notice_entry.type = NT_CLEAR_VRFS;
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

static int clear_vrf_cli(cmd_blk_t *cbt)
{   
    int ret = -EINVAL;

    switch (cbt->which[POS_WH_TBL - 1]) {
        case TYPE_TBL:
            ret = clear_vrf_notice(cbt);
            break;
        case TYPE_TBLS:
            ret = clear_vrfs_notice(cbt);
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "unknown cmd id:%u\n", cbt->which[POS_WH_TBL - 1]);
            break;
    }

    return ret;
}

EOL_NODE(clear_VRFxxx_eol, clear_vrf_cli);
KW_NODE_WHICH(clear_VRFxxx_ids, clear_VRFxxx_eol, none, "vids", "clear all vrf id", POS_WH_TBL, TYPE_TBLS);
VALUE_NODE(clear_VRFxxx_id_val, clear_VRFxxx_eol, none, "vrf id value <[1, MAX]>", POS_NUM_TBL_ID, NUM);
KW_NODE_WHICH(clear_VRFxxx_id, clear_VRFxxx_id_val, clear_VRFxxx_ids, "vid", "clear vrf id", POS_WH_TBL, TYPE_TBL);
KW_NODE(clear_VRFxxx, clear_VRFxxx_id, none, "vrf_l3", "clear vrf related items");
#endif

static inline int vrf_bind_cpy(struct net_vrf *vrf_bind_node,
    cmd_blk_t *cbt)
{
    vrf_bind_node->table_id = cbt->number[POS_NUM_TBL_ID - 1];

    switch (cbt->which[POS_WH_VRF - 1]) {
#if VRF_USE_DEV_HASH
        case TYPE_DEV_VRF:
            vrf_bind_node->type = VRF_TYPE_PORT;
            if (cbt->string_cnt) {
                vrf_bind_node->port = netif_port_get_by_name(
                    cbt->string[POS_STR_PORT - 1]);
                if (unlikely(vrf_bind_node->port == NULL)) {
                    return -ENOENT;
                }
            } else {
                return -EINVAL;
            }
            break;
#endif
#if VRF_USE_VNI_HASH
        case TYPE_VNI_VRF:
            vrf_bind_node->type = VRF_TYPE_VNI;
            if (cbt->number_cnt) {
                vrf_bind_node->vni = cbt->number[POS_NUM_VNI - 1];
            } else {
                return -EINVAL;
            }
            break;
#endif
#if VRF_USE_IP_HASH
        case TYPE_IP_VRF:
            vrf_bind_node->type = VRF_TYPE_IP;
            if (cbt->which[POS_WH_IPV - 1] == TYPE_IPV4) {
                vrf_bind_node->family = AF_INET;
            } else {
                vrf_bind_node->family = AF_INET6;
            }
            memset(&vrf_bind_node->ip, 0, sizeof(union inet_addr));
            if (unlikely(inet_pton(vrf_bind_node->family,
                cbt->string[POS_STR_DIP - 1],
                &vrf_bind_node->ip) != 1)) {
                    tyflow_cmdline_printf(cbt->cl,
                        "the ip address is not available\n");
                    return -EINVAL;
            }
            break;
#endif
        default:
            return -EINVAL;
    }

    return 0;
}

static inline int unbind_vrf_notice(cmd_blk_t *cbt)
{
    int ret;
    uint16_t lcore_id;

    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    if (unlikely((ret = vrf_bind_cpy(&cmd_notice_entry.data.vrf_bind_node, cbt)))) {
        tyflow_cmdline_printf(cbt->cl, "vrf_bind_cpy err %d\n", ret);
        rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);
        return -EINVAL;
    }
    cmd_notice_entry.type = NT_UNBIND_VRF;
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

static int unbind_vrf_cli(cmd_blk_t *cbt)
{  
    return(unbind_vrf_notice(cbt));
}

EOL_NODE(unbind_VRFxxx_eol, unbind_vrf_cli);

static inline int del_vrf_notice(cmd_blk_t *cbt)
{
    uint16_t lcore_id;

    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    cmd_notice_entry.data.vrf_node.table_id = cbt->number[POS_NUM_TBL_ID - 1];
    cmd_notice_entry.type = NT_DEL_VRF;
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

static inline int del_vrfs_notice(cmd_blk_t *cbt)
{
    uint16_t lcore_id;
    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    cmd_notice_entry.type = NT_DEL_VRFS;
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

static int del_vrf_cli(cmd_blk_t *cbt)
{   
    int ret = -EINVAL;

    switch (cbt->which[POS_WH_TBL - 1]) {
        case TYPE_TBL:
            ret = del_vrf_notice(cbt);
            break;
        case TYPE_TBLS:
            ret = del_vrfs_notice(cbt);
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "unknown cmd id:%u\n", cbt->which[POS_WH_TBL - 1]);
            break;
    }

    return ret;
}

EOL_NODE(del_VRFxxx_eol, del_vrf_cli);
KW_NODE_WHICH(del_VRFxxx_ids, del_VRFxxx_eol, none, "vids", "all vrf id", POS_WH_TBL, TYPE_TBLS);

#if VRF_USE_IP_HASH
VALUE_NODE(del_VRFxxx_ip6_val, unbind_VRFxxx_eol, none, "ip6 addr value", POS_STR_DIP, STR);
KW_NODE_WHICH(del_VRFxxx_ip6, del_VRFxxx_ip6_val, none, "v6", "ip6 addr", POS_WH_IPV, TYPE_IPV6);
VALUE_NODE(del_VRFxxx_ip4_val, unbind_VRFxxx_eol, none, "ip4 addr value", POS_STR_DIP, STR);
KW_NODE_WHICH(del_VRFxxx_ip4, del_VRFxxx_ip4_val, del_VRFxxx_ip6, "v4", "ip4 addr", POS_WH_IPV, TYPE_IPV4);
KW_NODE_WHICH(del_VRFxxx_ip, del_VRFxxx_ip4, del_VRFxxx_eol, "ip", "ip", POS_WH_VRF, TYPE_IP_VRF);
#endif

#if VRF_USE_DEV_HASH
VALUE_NODE(unbind_VRFxxx_vni_val, unbind_VRFxxx_eol, none, "port name", POS_STR_PORT, STR);
#if VRF_USE_IP_HASH
KW_NODE_WHICH(del_VRFxxx_op, unbind_VRFxxx_vni_val, del_VRFxxx_ip, "dev", "nic port", POS_WH_VRF, TYPE_DEV_VRF);
#else
KW_NODE_WHICH(del_VRFxxx_op, unbind_VRFxxx_vni_val, del_VRFxxx_eol, "dev", "nic port", POS_WH_VRF, TYPE_DEV_VRF);
#endif
#endif

#if VRF_USE_VNI_HASH
VALUE_NODE(unbind_VRFxxx_vni_val, unbind_VRFxxx_eol, none, "vni value", POS_NUM_VNI, NUM);
#if VRF_USE_IP_HASH
KW_NODE_WHICH(del_VRFxxx_op, unbind_VRFxxx_vni_val, del_VRFxxx_ip, "vni", "vxlan net id", POS_WH_VRF, TYPE_VNI_VRF);
#else
KW_NODE_WHICH(del_VRFxxx_op, unbind_VRFxxx_vni_val, del_VRFxxx_eol, "vni", "vxlan net id", POS_WH_VRF, TYPE_VNI_VRF);
#endif
#endif

VALUE_NODE(del_VRFxxx_vid_val, del_VRFxxx_op, none, "vrf id value <[1, MAX]>", POS_NUM_TBL_ID, NUM);
KW_NODE_WHICH(del_VRFxxx_vid, del_VRFxxx_vid_val, del_VRFxxx_ids, "vid", "vrf id", POS_WH_TBL, TYPE_TBL);

static inline int vrf_cpy(struct vrf_map_elem *vrf_node, cmd_blk_t *cbt)
{
    vrf_node->table_id = cbt->number[POS_NUM_TBL_ID - 1];
    return 0;
}

static inline int create_vrf_notice(cmd_blk_t *cbt)
{
    uint32_t lcore_id;
    int ret;

    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    if (unlikely((ret = vrf_cpy(&cmd_notice_entry.data.vrf_node, cbt)))) {
        tyflow_cmdline_printf(cbt->cl, "vrf_cpy err %d\n", ret);
        rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);
        return -EINVAL;
    }
    cmd_notice_entry.type = NT_CREATE_VRF;
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

static int create_vrf_cli(cmd_blk_t *cbt)
{  
    return(create_vrf_notice(cbt));
}

EOL_NODE(create_VRFxxx_eol, create_vrf_cli);

static inline int set_vrf_notice(cmd_blk_t *cbt)
{
    uint32_t lcore_id;
    int ret;

    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    if (unlikely((ret = vrf_bind_cpy(&cmd_notice_entry.data.vrf_bind_node, cbt)))) {
        tyflow_cmdline_printf(cbt->cl, "vrf_bind_cpy err %d\n", ret);
        rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);
        return -EINVAL;
    }
    cmd_notice_entry.type = NT_SET_VRF;
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

static inline int set_vrf_cli(cmd_blk_t *cbt)
{
    return(set_vrf_notice(cbt));
}

EOL_NODE(set_VRFxxx_eol, set_vrf_cli);

#if VRF_USE_IP_HASH
VALUE_NODE(set_VRFxxx_ip6_val, set_VRFxxx_eol, none, "ip6 addr value", POS_STR_DIP, STR);
KW_NODE_WHICH(set_VRFxxx_ip6, set_VRFxxx_ip6_val, none, "v6", "ip6 addr", POS_WH_IPV, TYPE_IPV6);
VALUE_NODE(set_VRFxxx_ip4_val, set_VRFxxx_eol, none, "ip4 addr value", POS_STR_DIP, STR);
KW_NODE_WHICH(set_VRFxxx_ip4, set_VRFxxx_ip4_val, set_VRFxxx_ip6, "v4", "ip4 addr", POS_WH_IPV, TYPE_IPV4);
KW_NODE_WHICH(set_VRFxxx_ip, set_VRFxxx_ip4, create_VRFxxx_eol, "ip", "ip addr", POS_WH_VRF, TYPE_IP_VRF);
#endif

#if VRF_USE_DEV_HASH
VALUE_NODE(set_VRFxxx_dev_val, set_VRFxxx_eol, none, "port name", POS_STR_PORT, STR);
//KW_NODE(set_VRFxxx_dev, set_VRFxxx_dev_val, none, "dev", "nic port");
#if VRF_USE_IP_HASH
KW_NODE_WHICH(set_VRFxxx_op, set_VRFxxx_dev_val, set_VRFxxx_ip, "dev", "nic port", POS_WH_VRF, TYPE_DEV_VRF);
#else
KW_NODE_WHICH(set_VRFxxx_op, set_VRFxxx_dev_val, create_VRFxxx_eol, "dev", "nic port", POS_WH_VRF, TYPE_DEV_VRF);
#endif
#endif

#if VRF_USE_VNI_HASH
VALUE_NODE(set_VRFxxx_vni_val, set_VRFxxx_eol, none, "vni value", POS_NUM_VNI, NUM);
//KW_NODE(set_VRFxxx_vni, set_VRFxxx_vni_val, none, "vni", "vxlan net id");
#if VRF_USE_IP_HASH
KW_NODE_WHICH(set_VRFxxx_op, set_VRFxxx_vni_val, set_VRFxxx_ip, "vni", "vxlan net id", POS_WH_VRF, TYPE_VNI_VRF);
#else
KW_NODE_WHICH(set_VRFxxx_op, set_VRFxxx_vni_val, create_VRFxxx_eol, "vni", "vxlan net id", POS_WH_VRF, TYPE_VNI_VRF);
#endif
#endif

VALUE_NODE(set_VRFxxx_vid_val, set_VRFxxx_op, none, "vrf id value <[1, MAX]>", POS_NUM_TBL_ID, NUM);
KW_NODE(set_VRFxxx_vid, set_VRFxxx_vid_val, none, "vid", "vrf id");
TEST_UNSET(test_unset_VRFxxx, del_VRFxxx_vid, set_VRFxxx_vid);

KW_NODE(set_VRFxxx, test_unset_VRFxxx, none, "vrf_l3", "set vrf related items");
/////////

void vrf_cli_init(void)
{
    add_get_cmd(&cnode(show_vrf));
    add_set_cmd(&cnode(set_VRFxxx));
    //add_move_cmd(&cnode(del_VRFxxx));
    //add_clear_cmd(&cnode(clear_VRFxxx));
    return;
}

