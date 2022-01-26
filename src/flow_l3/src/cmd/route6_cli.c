#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

/* Internal header files */
#include "conf/flow.h"
#include "route6_priv.h"
#include "route_priv.h"
#include "route_cli_priv.h"
#include "vrf_priv.h"
#include "common_cli_priv.h"
#include "flow_l3_cli_priv.h"
#include "conf/route6.h"
#include "parser/flow_cmdline_parse.h"

/* External header files */
#include "netif.h"
#include "list.h"
#include "dev.h"

extern struct common_cmd_notice_entry cmd_notice_entry;
extern struct route6_htable *g_lcores_route6_tables_p[RTE_MAX_LCORE];

#if 0
static inline uint32_t __attribute__((pure))
        depth_to_mask(uint8_t depth)
{
    if (depth>0) {
        return (int)0x80000000 >> (depth - 1);
    }
    else
        return (int)0x0;
}
#endif

static inline void route6_entry_dump_cli(cmd_blk_t *cbt,
    struct route6_entry *route)
{    
    route6_entry_dump(route);
}

static int route6_hlist_dump_cli(cmd_blk_t *cbt,
    uint16_t lcore_id, uint32_t table_id)
{    
    int i;
    struct route6_entry *route_entry;
    struct route6_hlist *hlist = NULL;
    struct route6_htable *route_table = &g_lcores_route6_tables_p[lcore_id][table_id];

    if(route_table->nroutes>0){
        tyflow_cmdline_printf(cbt->cl, "net route table cnt:%u\n", route_table->nroutes);       
        list_for_each_entry(hlist, &route_table->htable, node) {
            for (i = 0; i < hlist->nbuckets; i++) {
                list_for_each_entry(route_entry, &hlist->hlist[i], hnode) {
                    route6_entry_dump_cli(cbt, route_entry);
                }
            }
        }
    }
    return 0;
}

static int show_route6_tbl_cli(cmd_blk_t *cbt)
{  
    return(common_dump_sync(cbt, MAX_ROUTE_TBLS, route6_hlist_dump_cli));
}

EOL_NODE(show_route6_eol, show_route6_tbl_cli);
KW_NODE_WHICH(show_route6_tbls, show_route6_eol, none, "tids", "all route tables", POS_WH_TBL, TYPE_TBLS);
VALUE_NODE(show_route6_tbl_val, show_route6_eol, none, "route table id", POS_NUM_TBL_ID, NUM);
KW_NODE_WHICH(show_route6_tbl, show_route6_tbl_val, show_route6_tbls, "tid", "single route table", POS_WH_TBL, TYPE_TBL);
KW_NODE_WHICH(show_route6_lcores, show_route6_tbl, none, "lcores", "all lcores", POS_WH_LCORE, TYPE_LCORES);
VALUE_NODE(show_route6_lcore_val, show_route6_tbl, none, "lcore id value", POS_NUM_LCORE_ID, NUM);
KW_NODE_WHICH(show_route6_lcore, show_route6_lcore_val, show_route6_lcores, "lcore", "single lcore", POS_WH_LCORE, TYPE_LCORE);
KW_NODE(show_route6, show_route6_lcore, none, "route6", "show route related items");

static inline int clear_route6_tbl_notice(cmd_blk_t *cbt)
{
    uint16_t lcore_id;

    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    cmd_notice_entry.type = NT_CLEAR_RT6_TBL;
    cmd_notice_entry.cbt = cbt;
    cmd_notice_entry.data.route6_conf.table_id = cbt->number[POS_NUM_TBL_ID - 1];
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

static inline int clear_route6_tbls_notice(cmd_blk_t *cbt)
{
    uint16_t lcore_id;
    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    cmd_notice_entry.type = NT_CLEAR_RT6_TBLS;
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

static int clear_route6_tbl_cli(cmd_blk_t *cbt)
{   
    int ret = -EINVAL;

    switch (cbt->which[POS_WH_TBL - 1]) {
        case TYPE_TBL:
            ret = clear_route6_tbl_notice(cbt);
            break;
        case TYPE_TBLS:
            ret = clear_route6_tbls_notice(cbt);
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "unknown cmd id:%u\n", cbt->which[POS_WH_TBL - 1]);
            break;
    }

    return ret;
}

EOL_NODE(clear_route6_eol, clear_route6_tbl_cli);

static inline int route6_cpy(struct dp_vs_route6_conf *route_conf, cmd_blk_t *cbt)
{
    char   ifname[IFNAMSIZ];
    const char *ifName = cbt->string[POS_STR_PORT - 1];
    
    memset(route_conf, 0, sizeof(struct dp_vs_route6_conf));
    ifname[0] = '\0';
    
    if (strlen(cbt->string[POS_STR_DIP - 1]) > 0){ 
        if (unlikely(inet_pton(AF_INET6, cbt->string[POS_STR_DIP - 1], &route_conf->dst.addr) ==  0)){
            return -1;
        }
        route_conf->dst.plen = cbt->number[POS_NUM_MASK - 1]; 
    }
    
    if (strlen(cbt->string[POS_STR_GW - 1]) > 0) {
        if (unlikely(inet_pton(AF_INET6, cbt->string[POS_STR_GW - 1], &route_conf->gateway) == 0)) {
            return -2;
        }
    }
  
    if (strlen(cbt->string[POS_STR_PORT - 1]) > 0) {
        if(unlikely(!netif_port_get_by_name(cbt->string[POS_STR_PORT - 1]))){
            return -3;
        }
        strlcpy(route_conf->ifname, ifName, sizeof(route_conf->ifname));
    }

    if (cbt->which[POS_WH_ROUTE_FLAG - 1] == TYPE_FLAG_NET) {
        route_conf->flags = RTF_FORWARD;
    } else if (cbt->which[POS_WH_ROUTE_FLAG - 1] == TYPE_FLAG_LOCAL) {
        route_conf->flags = RTF_LOCALIN;
    } else {
        return -3;
    }

    route_conf->table_id = cbt->number[POS_NUM_TBL_ID - 1];
    return 0;
}

static inline int del_route6_notice(cmd_blk_t *cbt)
{
    uint16_t lcore_id;
    int ret;

    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    if (unlikely((ret = route6_cpy(&cmd_notice_entry.data.route6_conf, cbt)))) {
        tyflow_cmdline_printf(cbt->cl, "route_cpy err %d\n", ret);        
        rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);
        return -EINVAL;
    }
    cmd_notice_entry.type = NT_DEL_RT6;
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

static int del_route6_tbl_cli(cmd_blk_t *cbt)
{   
    return(del_route6_notice(cbt));
}

EOL_NODE(del_route6_eol, del_route6_tbl_cli);
KW_NODE_WHICH(del_route6_flag_local, del_route6_eol, none, "local", "local route", POS_WH_ROUTE_FLAG, TYPE_FLAG_LOCAL);
KW_NODE_WHICH(del_route6_flag_net, del_route6_eol, del_route6_flag_local, "net", "net route", POS_WH_ROUTE_FLAG, TYPE_FLAG_NET);
VALUE_NODE(del_route6_port_val, del_route6_flag_net, none, "interface name", POS_STR_PORT, STR);
KW_NODE(del_route6_port, del_route6_port_val, none, "port", "interface");
VALUE_NODE(del_route6_prefix_len_val, del_route6_port, none, "prefix-len value <0-128>", POS_NUM_MASK, NUM);
KW_NODE(del_route6_prefix_len, del_route6_prefix_len_val, none, "prefix-len", "prefix len");
VALUE_NODE(del_route6_dip_val, del_route6_prefix_len, none, "IPv6 address", POS_STR_DIP, STR);
KW_NODE(del_route6_dip, del_route6_dip_val, clear_route6_eol, "dip", "destination IP");
VALUE_NODE(del_route6_tbl_id_val, del_route6_dip, none, "route table id value", POS_NUM_TBL_ID, NUM);
KW_NODE_WHICH(del_route6_tbls, clear_route6_eol, none, "tids", "all route tables", POS_WH_TBL, TYPE_TBLS);
KW_NODE_WHICH(del_route6_tbl, del_route6_tbl_id_val, del_route6_tbls, "tid", "route table id", POS_WH_TBL, TYPE_TBL);

static inline int set_route6_notice(cmd_blk_t *cbt)
{
    uint16_t lcore_id;
    int ret;

    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    if (unlikely((ret = route6_cpy(&cmd_notice_entry.data.route6_conf, cbt)))) {
        tyflow_cmdline_printf(cbt->cl, "route_cpy err %d\n", ret);        
        rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);
        return -EINVAL;
    }
    cmd_notice_entry.type = NT_SET_RT6;
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

static int set_route6_tbl_cli(cmd_blk_t *cbt)
{   
    return(set_route6_notice(cbt));
}

EOL_NODE(set_route6_eol, set_route6_tbl_cli);
KW_NODE_WHICH(set_route6_flag_local, set_route6_eol, none, "local", "local route", POS_WH_ROUTE_FLAG, TYPE_FLAG_LOCAL);
KW_NODE_WHICH(set_route6_flag_net, set_route6_eol, set_route6_flag_local, "net", "net route", POS_WH_ROUTE_FLAG, TYPE_FLAG_NET);
VALUE_NODE(set_route6_port_val, set_route6_flag_net, none, "interface name", POS_STR_PORT, STR);
KW_NODE(set_route6_port, set_route6_port_val, none, "port", "interface");
VALUE_NODE(set_route6_gw_val, set_route6_port, none, "IPv6 address", POS_STR_GW, STR);
KW_NODE(set_route6_gw, set_route6_gw_val, none, "gw", "gateway");
VALUE_NODE(set_route6_prefix_len_val, set_route6_gw, none, "prefix len value <0-128>", POS_NUM_MASK, NUM);
KW_NODE(set_route6_prefix_len, set_route6_prefix_len_val, none, "prefix-len", "prefix len");
VALUE_NODE(set_route6_dip_val, set_route6_prefix_len, none, "IPv6 address", POS_STR_DIP, STR);
KW_NODE(set_route6_dip, set_route6_dip_val, none, "dip", "destination IP");
VALUE_NODE(set_route6_tbl_id_val, set_route6_dip, none, "route table id value", POS_NUM_TBL_ID, NUM);
KW_NODE(set_route6_tbl, set_route6_tbl_id_val, none, "tid", "set route table id value");
TEST_UNSET(test_unset_route6, del_route6_tbl, set_route6_tbl);
KW_NODE(set_route6, test_unset_route6, none, "route6", "set route related items");

void route6_cli_init(void)
{
    add_get_cmd(&cnode(show_route6));
    add_set_cmd(&cnode(set_route6));
    return;
}

int route6_add_ifaddr(struct inet_ifaddr *s_ifa)
{
    int ret = 0;

    if (unlikely(s_ifa == NULL)) {
        printf("%s:s_ifa is null!\n", __func__);
        return -EINVAL;
    }

    pthread_mutex_lock(&mutex); //for cmd and main lcore
    rte_rwlock_write_lock(&cmd_notice_entry.rwlock); //for multi work lcore or r/w mutual exclusion
    cmd_notice_entry.data.ifa6.port = s_ifa->idev->dev;
    cmd_notice_entry.data.ifa6.addr = s_ifa->addr.in6;
    cmd_notice_entry.data.ifa6.bcast = s_ifa->bcast.in6;
    cmd_notice_entry.data.ifa6.plen = s_ifa->plen;
    cmd_notice_entry.type = NT_SET_RT_AUTO;
    rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);

#if 0
    uint16_t lcore_id;
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
#else
    ret = common_cmd_entry_enq(LCORE_ID_ANY,
        &cmd_notice_entry, sizeof(struct common_cmd_notice_entry));
#endif

    pthread_mutex_unlock(&mutex);

    return ret;
}

int route6_del_ifaddr(struct inet_ifaddr *s_ifa, uint8_t local_keep)
{
    int ret = 0;

    if (unlikely(s_ifa == NULL)) {
        printf("%s:s_ifa is null!\n", __func__);
        return -EINVAL;
    }

    pthread_mutex_lock(&mutex); //for cmd and main lcore
    rte_rwlock_write_lock(&cmd_notice_entry.rwlock); //for multi work lcore or r/w mutual exclusion
    cmd_notice_entry.data.ifa6.port = s_ifa->idev->dev;
    cmd_notice_entry.data.ifa6.addr = s_ifa->addr.in6;
    cmd_notice_entry.data.ifa6.bcast = s_ifa->bcast.in6;
    cmd_notice_entry.data.ifa6.plen = s_ifa->plen;
    cmd_notice_entry.data.ifa6.local_keep = local_keep;
    cmd_notice_entry.type = NT_DEL_RT6_AUTO;
    rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);

#if 0
    uint16_t lcore_id;
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
#else
    ret = common_cmd_entry_enq(LCORE_ID_ANY,
        &cmd_notice_entry, sizeof(struct common_cmd_notice_entry));
#endif

    pthread_mutex_unlock(&mutex);
    
    return ret;
}

extern struct inet_device *dev_get_idev(const struct netif_port *dev);
int route6_device_event(struct notifier_block *unused, unsigned long event, void *ptr)
{
    struct inet_ifaddr *ifa;
    RTE_SET_USED(unused);

    struct netif_port *port = (struct netif_port *)ptr;
    if (unlikely(port == NULL)) {
        printf("%s:port is null!\n", __func__);
        return -EINVAL;
    }

    struct inet_device *idev = dev_get_idev(port);
    if (unlikely(idev == NULL)) {
        printf("%s:port %s idev is null!\n", port->name, __func__);
        return -EINVAL;
    }

    switch (event) {
        case NETDEV_UP:           
            //list_for_each_entry(ifa, &idev->this_ifa_list, d_list) {
            list_for_each_entry(ifa, &idev->ifa_list[0], d_list) {
                route6_add_ifaddr(ifa);
            }           
            break;
        case NETDEV_DOWN:           
            //list_for_each_entry(ifa, &idev->this_ifa_list, d_list) {
            list_for_each_entry(ifa, &idev->ifa_list[0], d_list) {
                route6_del_ifaddr(ifa, 1);
            }
            break;
        case NETDEV_UNREGISTER:
            //list_for_each_entry(ifa, &idev->this_ifa_list, d_list) {
            list_for_each_entry(ifa, &idev->ifa_list[0], d_list) {
                route6_del_ifaddr(ifa, 0);
            }
            break;
        default:
            break;
    }

    if (likely(idev))
        rte_atomic32_dec(&idev->refcnt);

    return 0;
}


