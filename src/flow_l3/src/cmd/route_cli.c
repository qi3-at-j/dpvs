#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

/* Internal header files */
#include "route_cli_priv.h"
#include "vrf_priv.h"
#include "common_cli_priv.h"
#include "route_priv.h"

/* External header files */
#include "netif.h"
#include "list.h"
#include "dev.h"

extern struct common_cmd_notice_entry cmd_notice_entry;
extern struct route_table *g_lcores_route_tables_p[RTE_MAX_LCORE];

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

static inline void route_node_dump_cli(cmd_blk_t *cbt,
    struct route_entry *route_node)
{    
    char d_ip[INET_ADDRSTRLEN] = {0};
    char g_ip[INET_ADDRSTRLEN] = {0};
    char m_ip[INET_ADDRSTRLEN] = {0};
    char flag[10] = {0};
    char dst_addr[64] = {0};

    inet_ntop(AF_INET, &route_node->dest,
                dst_addr, sizeof(dst_addr));

    snprintf(d_ip, INET_ADDRSTRLEN, "%s", dst_addr);

    memset(dst_addr, 0, sizeof(dst_addr));
    inet_ntop(AF_INET, &route_node->gw,
                dst_addr, sizeof(dst_addr));
    snprintf(g_ip, INET_ADDRSTRLEN, "%s", dst_addr);

    uint32_t net_mask = depth_to_mask(route_node->netmask);
    net_mask = rte_be_to_cpu_32(net_mask);
    memset(dst_addr, 0, sizeof(dst_addr));
    inet_ntop(AF_INET, &net_mask,
                dst_addr, sizeof(dst_addr));
    snprintf(m_ip, INET_ADDRSTRLEN, "%s", dst_addr);

    strcpy(flag, "U");
    if (route_node->gw.s_addr != htonl(INADDR_ANY)) {
        strcat(flag, "G");
    }
    if (route_node->netmask == 32) {
        strcat(flag, "H");
    }
    tyflow_cmdline_printf(cbt->cl, "%s     %s         %s(%u)         %s %d %u    %s\n",
            d_ip, g_ip, m_ip, route_node->netmask, flag, route_node->metric, route_node->refcnt.cnt, route_node->port->name);
}

static int route_table_dump_cli(cmd_blk_t *cbt,
    uint32_t lcore_id, uint32_t table_id)
{    
    int i;
    struct route_entry *route_node;
    struct route_table *route_table = &g_lcores_route_tables_p[lcore_id][table_id];

    if (route_table->cnt_local.cnt || route_table->cnt_net.cnt) {      
        tyflow_cmdline_printf(cbt->cl, "lcore id:%u\n", lcore_id);
        tyflow_cmdline_printf(cbt->cl, "route table id:%u\n", route_table->table_id);
    }

    if (route_table->cnt_local.cnt) {
        tyflow_cmdline_printf(cbt->cl, "local route table cnt:%u\n", route_table->cnt_local.cnt);
        tyflow_cmdline_printf(cbt->cl, "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n");
        for (i = 0; i < LOCAL_ROUTE_TAB_SIZE; i++) {
            list_for_each_entry(route_node, &route_table->local_route_table[i], list){
                route_node_dump_cli(cbt, route_node);
            }
        }
    }

    if (route_table->cnt_net.cnt) {
        tyflow_cmdline_printf(cbt->cl, "net route table cnt:%u\n", route_table->cnt_net.cnt);       
        tyflow_cmdline_printf(cbt->cl, "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n");
        list_for_each_entry(route_node, &route_table->net_route_table, list) {
            route_node_dump_cli(cbt, route_node);
        }
    }

    return 0;
}

static int show_route_tbl_cli(cmd_blk_t *cbt)
{  
    return(common_dump_sync(cbt, MAX_ROUTE_TBLS, route_table_dump_cli));
}

EOL_NODE(show_route_eol, show_route_tbl_cli);
KW_NODE_WHICH(show_route_tbls, show_route_eol, none, "tids", "all route tables", POS_WH_TBL, TYPE_TBLS);
VALUE_NODE(show_route_tbl_val, show_route_eol, none, "route table id", POS_NUM_TBL_ID, NUM);
KW_NODE_WHICH(show_route_tbl, show_route_tbl_val, show_route_tbls, "tid", "single route table", POS_WH_TBL, TYPE_TBL);
KW_NODE_WHICH(show_route_lcores, show_route_tbl, none, "lcores", "all lcores", POS_WH_LCORE, TYPE_LCORES);
VALUE_NODE(show_route_lcore_val, show_route_tbl, none, "lcore id value", POS_NUM_LCORE_ID, NUM);
KW_NODE_WHICH(show_route_lcore, show_route_lcore_val, show_route_lcores, "lcore", "single lcore", POS_WH_LCORE, TYPE_LCORE);
KW_NODE(show_route, show_route_lcore, none, "route", "show route related items");

static inline int clear_route_tbl_notice(cmd_blk_t *cbt)
{
    uint32_t lcore_id;

    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    cmd_notice_entry.type = NT_CLEAR_RT_TBL;
    cmd_notice_entry.cbt = cbt;
    cmd_notice_entry.data.route_node.table_id = cbt->number[POS_NUM_TBL_ID - 1];
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

static inline int clear_route_tbls_notice(cmd_blk_t *cbt)
{
    uint32_t lcore_id;
    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    cmd_notice_entry.type = NT_CLEAR_RT_TBLS;
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

static int clear_route_tbl_cli(cmd_blk_t *cbt)
{   
    int ret = -EINVAL;

    switch (cbt->which[POS_WH_TBL - 1]) {
        case TYPE_TBL:
            ret = clear_route_tbl_notice(cbt);
            break;
        case TYPE_TBLS:
            ret = clear_route_tbls_notice(cbt);
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "unknown cmd id:%u\n", cbt->which[POS_WH_TBL - 1]);
            break;
    }

    return ret;
}

EOL_NODE(clear_route_eol, clear_route_tbl_cli);

static inline int route_cpy(struct route_entry *route_node, cmd_blk_t *cbt)
{
    memset(route_node, 0, sizeof(struct route_entry));
    if (strlen(cbt->string[POS_STR_DIP - 1]) > 0) {
        if (unlikely(inet_pton(AF_INET, cbt->string[POS_STR_DIP - 1],
            &route_node->dest) != 1)) {
            return -1;
        }
    }

    if (strlen(cbt->string[POS_STR_GW - 1]) > 0) {
        if (unlikely(inet_pton(AF_INET, cbt->string[POS_STR_GW - 1],
            &route_node->gw) != 1)) {
            return -2;
        }
    }

    route_node->netmask = cbt->number[POS_NUM_MASK - 1];    
    if (strlen(cbt->string[POS_STR_PORT - 1]) > 0) {
        route_node->port = netif_port_get_by_name(cbt->string[POS_STR_PORT - 1]);
    }

    //route_node->flag = cbt->number[POS_NUM_FLAG - 1];
    if (cbt->which[POS_WH_ROUTE_FLAG - 1] == TYPE_FLAG_NET) {
        route_node->flag = ROUTE_FLAG_FORWARD;
    } else if (cbt->which[POS_WH_ROUTE_FLAG - 1] == TYPE_FLAG_LOCAL) {
        route_node->flag = ROUTE_FLAG_LOCALIN;
    } else {
        return -3;
    }

    if (route_node->flag == ROUTE_FLAG_LOCALIN) {
        route_node->netmask = 32;
    }
    route_node->table_id = cbt->number[POS_NUM_TBL_ID - 1];
    if (unlikely(route_node->port == NULL)) {
        return -4;
    }

    return 0;
}

static inline int del_route_notice(cmd_blk_t *cbt)
{
    uint32_t lcore_id;
    int ret;

    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    if (unlikely((ret = route_cpy(&cmd_notice_entry.data.route_node, cbt)))) {
        tyflow_cmdline_printf(cbt->cl, "route_cpy err %d\n", ret);        
        rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);
        return -EINVAL;
    }
    cmd_notice_entry.type = NT_DEL_RT;
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

static int del_route_tbl_cli(cmd_blk_t *cbt)
{   
    return(del_route_notice(cbt));
}

EOL_NODE(del_route_eol, del_route_tbl_cli);
//VALUE_NODE(del_route_flag_val, del_route_eol, none, "route flag value <1:net,2:local>", POS_NUM_FLAG, NUM);
//KW_NODE(del_route_flag, del_route_flag_val, none, "flag", "route flag");
KW_NODE_WHICH(del_route_flag_local, del_route_eol, none, "local", "local route", POS_WH_ROUTE_FLAG, TYPE_FLAG_LOCAL);
KW_NODE_WHICH(del_route_flag_net, del_route_eol, del_route_flag_local, "net", "net route", POS_WH_ROUTE_FLAG, TYPE_FLAG_NET);
VALUE_NODE(del_route_port_val, del_route_flag_net, none, "interface name", POS_STR_PORT, STR);
KW_NODE(del_route_port, del_route_port_val, none, "port", "interface");
VALUE_NODE(del_route_netmask_val, del_route_port, none, "netmask value <0-32>", POS_NUM_MASK, NUM);
KW_NODE(del_route_netmask, del_route_netmask_val, none, "netmask", "netmask");
//VALUE_NODE(del_route_gw_val, del_route_netmask, none, "IPv4 address", POS_STR_GW, STR);
//KW_NODE(del_route_gw, del_route_gw_val, none, "gw", "gateway");
VALUE_NODE(del_route_dip_val, del_route_netmask, none, "IPv4 address", POS_STR_DIP, STR);
KW_NODE(del_route_dip, del_route_dip_val, clear_route_eol, "dip", "destination IP");
VALUE_NODE(del_route_tbl_id_val, del_route_dip, none, "route table id value", POS_NUM_TBL_ID, NUM);
//KW_NODE(del_route_tbl, del_route_tbl_id_val, none, "tid", "del route table id value");
//KW_NODE(del_route, del_route_tbl_id_val, none, "route", "del route related items");
KW_NODE_WHICH(del_route_tbls, clear_route_eol, none, "tids", "all route tables", POS_WH_TBL, TYPE_TBLS);
KW_NODE_WHICH(del_route_tbl, del_route_tbl_id_val, del_route_tbls, "tid", "route table id", POS_WH_TBL, TYPE_TBL);

static inline int set_route_notice(cmd_blk_t *cbt)
{
    uint32_t lcore_id;
    int ret;

    rte_rwlock_write_lock(&cmd_notice_entry.rwlock);
    if (unlikely((ret = route_cpy(&cmd_notice_entry.data.route_node, cbt)))) {
        tyflow_cmdline_printf(cbt->cl, "route_cpy err %d\n", ret);        
        rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);
        return -EINVAL;
    }
    cmd_notice_entry.type = NT_SET_RT;
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

static int set_route_tbl_cli(cmd_blk_t *cbt)
{   
    return(set_route_notice(cbt));
}

EOL_NODE(set_route_eol, set_route_tbl_cli);
//VALUE_NODE(set_route_flag_val, set_route_eol, none, "route flag value <1:net,2:local>", POS_NUM_FLAG, NUM);
//KW_NODE(set_route_flag, set_route_flag_val, none, "flag", "route flag");
KW_NODE_WHICH(set_route_flag_local, set_route_eol, none, "local", "local route", POS_WH_ROUTE_FLAG, TYPE_FLAG_LOCAL);
KW_NODE_WHICH(set_route_flag_net, set_route_eol, set_route_flag_local, "net", "net route", POS_WH_ROUTE_FLAG, TYPE_FLAG_NET);
VALUE_NODE(set_route_port_val, set_route_flag_net, none, "interface name", POS_STR_PORT, STR);
KW_NODE(set_route_port, set_route_port_val, none, "port", "interface");
VALUE_NODE(set_route_netmask_val, set_route_port, none, "netmask value <0-32>", POS_NUM_MASK, NUM);
KW_NODE(set_route_netmask, set_route_netmask_val, none, "netmask", "netmask");
VALUE_NODE(set_route_gw_val, set_route_netmask, none, "IPv4 address", POS_STR_GW, STR);
KW_NODE(set_route_gw, set_route_gw_val, none, "gw", "gateway");
VALUE_NODE(set_route_dip_val, set_route_gw, none, "IPv4 address", POS_STR_DIP, STR);
KW_NODE(set_route_dip, set_route_dip_val, none, "dip", "destination IP");
VALUE_NODE(set_route_tbl_id_val, set_route_dip, none, "route table id value", POS_NUM_TBL_ID, NUM);
KW_NODE(set_route_tbl, set_route_tbl_id_val, none, "tid", "set route table id value");
TEST_UNSET(test_unset_route, del_route_tbl, set_route_tbl);
KW_NODE(set_route, test_unset_route, none, "route", "set route related items");

void route_cli_init(void)
{
    add_get_cmd(&cnode(show_route));
    add_set_cmd(&cnode(set_route));
    //add_clear_cmd(&cnode(clear_route));
    //add_move_cmd(&cnode(del_route));
    return;
}

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int route_add_ifaddr(struct inet_ifaddr *s_ifa)
{
    int ret = 0;

    if (unlikely(s_ifa == NULL)) {
        printf("%s:s_ifa is null!\n", __func__);
        return -EINVAL;
    }

    pthread_mutex_lock(&mutex); //for cmd and main lcore
    rte_rwlock_write_lock(&cmd_notice_entry.rwlock); //for multi work lcore or r/w mutual exclusion
    cmd_notice_entry.data.ifa.port = s_ifa->idev->dev;
    cmd_notice_entry.data.ifa.addr = s_ifa->addr.in;
    cmd_notice_entry.data.ifa.bcast = s_ifa->bcast.in;
    cmd_notice_entry.data.ifa.plen = s_ifa->plen;
    cmd_notice_entry.type = NT_SET_RT_AUTO;
    rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);

#if 0
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

int route_del_ifaddr(struct inet_ifaddr *s_ifa, uint8_t local_keep)
{
    int ret = 0;

    if (unlikely(s_ifa == NULL)) {
        printf("%s:s_ifa is null!\n", __func__);
        return -EINVAL;
    }

    pthread_mutex_lock(&mutex); //for cmd and main lcore
    rte_rwlock_write_lock(&cmd_notice_entry.rwlock); //for multi work lcore or r/w mutual exclusion
    cmd_notice_entry.data.ifa.port = s_ifa->idev->dev;
    cmd_notice_entry.data.ifa.addr = s_ifa->addr.in;
    cmd_notice_entry.data.ifa.bcast = s_ifa->bcast.in;
    cmd_notice_entry.data.ifa.plen = s_ifa->plen;
    cmd_notice_entry.data.ifa.local_keep = local_keep;
    cmd_notice_entry.type = NT_DEL_RT_AUTO;
    rte_rwlock_write_unlock(&cmd_notice_entry.rwlock);

#if 0
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
int route_device_event(struct notifier_block *unused, unsigned long event, void *ptr)
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
                route_add_ifaddr(ifa);
            }           
            break;
        case NETDEV_DOWN:
            //list_for_each_entry(ifa, &idev->this_ifa_list, d_list) {
            list_for_each_entry(ifa, &idev->ifa_list[0], d_list) {
                route_del_ifaddr(ifa, 1);
            }
            break;
        case NETDEV_UNREGISTER:
            //list_for_each_entry(ifa, &idev->this_ifa_list, d_list) {
            list_for_each_entry(ifa, &idev->ifa_list[0], d_list) {
                route_del_ifaddr(ifa, 0);
            }
            break;
        default:
            break;
    }

    if (likely(idev))
        rte_atomic32_dec(&idev->refcnt);

    return 0;
}

static int vrrp_route_cmd_noti(union inet_addr *dst_addr,
    uint8_t family, uint8_t netmask, struct netif_port *port,
    uint32_t type)
{
    struct common_cmd_notice_entry cmd_ety;

    cmd_ety.type = type;
    if (family == AF_INET) {
        struct route_entry route_ety;
        memset(&route_ety, 0, sizeof(struct route_entry));
        route_ety.flag = ROUTE_FLAG_LOCALIN;
        route_ety.dest = dst_addr->in;
        route_ety.netmask = netmask;
        route_ety.port = port;
        route_ety.table_id = GLOBAL_ROUTE_TBL_ID;
        rte_memcpy(&cmd_ety.data.route_node, &route_ety,
            sizeof(struct route_entry));
    } else {
        struct dp_vs_route6_conf route6_conf;
        memset(&route6_conf, 0, sizeof(struct dp_vs_route6_conf));
        route6_conf.flags = ROUTE_FLAG_LOCALIN;
        route6_conf.dst.addr = dst_addr->in6;
        route6_conf.dst.plen = netmask;
        strcpy(route6_conf.ifname, port->name);
        route6_conf.table_id = GLOBAL_ROUTE_TBL_ID;
        rte_memcpy(&cmd_ety.data.route6_conf, &route6_conf,
            sizeof(struct dp_vs_route6_conf));
    }

    return(common_cmd_entry_enq(LCORE_ID_ANY, &cmd_ety,
        sizeof(struct common_cmd_notice_entry)));
}

int vrrp_add_route(union inet_addr *dst_addr, uint8_t family,
    uint8_t netmask, struct netif_port *port)
{
    uint32_t type;

    if (family == AF_INET) {
        type = NT_SET_RT;
    } else if (family == AF_INET6) {
        type = NT_SET_RT6;
    } else {
        return -EINVAL;
    }

    return(vrrp_route_cmd_noti(dst_addr, family, netmask, port, type));
}

int vrrp_del_route(union inet_addr *dst_addr, uint8_t family,
    uint8_t netmask, struct netif_port *port)
{
    uint32_t type;

    if (family == AF_INET) {
        type = NT_DEL_RT;
    } else if (family == AF_INET6) {
        type = NT_DEL_RT6;
    } else {
        return -EINVAL;
    }

    return(vrrp_route_cmd_noti(dst_addr, family, netmask, port, type));
}
