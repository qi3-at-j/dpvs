
#include "route_cli_priv.h"
#include "route6_cli_priv.h"
#include "neigh_cli_priv.h"
#include "vrf_cli_priv.h"
#include "vxlan_cli_priv.h"
#include "flow_l3_cli_priv.h"
#include "common_cli_priv.h"
#include "switch_cli_priv.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"

#include "notifier.h"
#include "vlan.h"

#define CMD_RING_SIZE 64

#define this_lcore_cmd_ring       (RTE_PER_LCORE(cmd_ring_lcore))
static RTE_DEFINE_PER_LCORE(struct rte_ring *, cmd_ring_lcore);
struct rte_ring *g_lcores_l3_cmd_ring[RTE_MAX_LCORE]; // for cmd pthread

struct common_cmd_notice_entry cmd_notice_entry;
struct notifier_block route_device_notifier = {
	.notifier_call = route_device_event,
    .priority = NOTI_PRIO_MAX,
};

void resp_flow_l3_cmd_notice(struct rte_graph *graph, lcoreid_t cid)
{
    int ret;
    struct vrf_map_elem vrf_node;

    if (cid == cmd_notice_entry.lcore_id) {
        if (likely(graph)) {
            rte_rwlock_read_lock(&cmd_notice_entry.rwlock);
            cmd_notice_entry.lcore_id = rte_get_main_lcore();

            switch (cmd_notice_entry.type) {
                case NT_SET_RT:
                    if ((ret = new_route_add((void *)&cmd_notice_entry.data.route_node))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "set route err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "set route success\n");
                    }                   
                    break;
                case NT_SET_RT6:
                    if ((ret = route6_hlist_add_lcore((void *)&cmd_notice_entry.data.route6_conf))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "set route6 err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "set route6 success\n");
                    }                   
                    break;
                case NT_DEL_RT:
                    if ((ret = new_route_del((void *)&cmd_notice_entry.data.route_node))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "del route err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "del route success\n");
                    }
                    break;
                case NT_DEL_RT6:
                    if ((ret = route6_hlist_del_lcore((void *)&cmd_notice_entry.data.route6_conf))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "del route6 err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "del route6 success\n");
                    }
                    break;
                case NT_CLEAR_RT_TBL:
                    if ((ret = route_table_clear((void *)&cmd_notice_entry.data.route_node.table_id))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "clear route table err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "clear route table success\n");
                    }
                    break;
                case NT_CLEAR_RT_TBLS:
                    if ((ret = route_tables_clear(NULL))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "clear route tables err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "clear route tables success\n");
                    }
                    break;
               case NT_CLEAR_RT6_TBL:
                    if ((ret = route6_hlist_clear_lcore((void *)&cmd_notice_entry.data.route6_conf.table_id))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "clear route table err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "clear route table success\n");
                    }
                    break;
                case NT_CLEAR_RT6_TBLS:
                    if ((ret = route6_hlists_clear_lcore(NULL))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "clear route tables err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "clear route tables success\n");
                    }
                    break;
                case NT_SET_NEI:
                    if ((ret = neigh_add((void *)&cmd_notice_entry.data.neigh_node))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "set neigh err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "set neigh success\n");
                    }
                    break;
                case NT_DEL_NEI:
                    if ((ret = neigh_del((void *)&cmd_notice_entry.data.neigh_node))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "del neigh err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "del neigh success\n");
                    }
                    break;
                case NT_CLEAR_NEI_TBL:
                    if ((ret = neigh_table_clear((void *)&cmd_notice_entry.data.neigh_node.table_id))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "clear neigh table err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "clear neigh table success\n");
                    }
                    break;
                case NT_CLEAR_NEI_TBLS:
                    if ((ret = neigh_tables_clear(NULL))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "clear neigh tables err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "clear neigh tables success\n");
                    }
                    break;
                case NT_CREATE_VRF:
                    if ((ret = api_vrf_add((void *)&cmd_notice_entry.data.vrf_node))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "create vrf err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "create vrf success\n");
                    }
                    break;
                case NT_SET_VRF:
                    vrf_node.table_id = cmd_notice_entry.data.vrf_bind_node.table_id;
                    ret = api_vrf_add((void *)&vrf_node);
                    if ((ret != 0) && (ret != -EEXIST)) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "create vrf err %d\n", ret);
                        break;
                    } else if (ret == 0) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "create vrf success\n");
                    }

                    if ((ret = api_vrf_bind((void *)&cmd_notice_entry.data.vrf_bind_node))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "set vrf err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "set vrf success\n");
                    }
                    break;
                case NT_CLEAR_VRF:
                    if ((ret = api_vrf_clear_id((void *)&cmd_notice_entry.data.vrf_bind_node.table_id))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "clear vrf err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "clear vrf success\n");
                    }
                    break;
                case NT_CLEAR_VRFS:
                    if ((ret = api_vrf_clear_all(NULL))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "clear vrfs err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "clear vrfs success\n");
                    }
                    break;
                    break;
                case NT_DEL_VRF:
                    if ((ret = api_vrf_del_id((void *)&cmd_notice_entry.data.vrf_node.table_id))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "del vrf err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "del vrf success\n");
                    }
                    break;
                case NT_DEL_VRFS:
                    if ((ret = api_vrf_del_all(NULL))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "del vrfs err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "del vrfs success\n");
                    }
                    break;
                case NT_UNBIND_VRF:
                    if ((ret = api_vrf_unbind((void *)&cmd_notice_entry.data.vrf_bind_node))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "unbind vrf err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "unbind vrf success\n");
                    }
                    break;
                case NT_CREATE_VXLAN_TUNN:
                    if ((ret = api_vxlan_tunnel_add((void *)&cmd_notice_entry.data.vxlan_tunnel_node))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "create vxlan tunnel err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "create vxlan tunnel success\n");
                    }
                    break;
                case NT_CLEAR_VXLAN_TUNN:
                    if ((ret = api_vxlan_tunnel_clear(NULL))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "clear vxlan tunnel err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "clear vxlan tunnel success\n");
                    }
                    break;
                case NT_DEL_VXLAN_TUNN:
                    if ((ret = api_vxlan_tunnel_del((void *)&cmd_notice_entry.data.vxlan_tunnel_node))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "del vxlan tunnel err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "del vxlan tunnel success\n");
                    }
                    break;
                case NT_SET_RT_AUTO:
                    if ((ret  = route_add_auto(&cmd_notice_entry.data.ifa))) {
                        printf("set route auto err %d\n", ret);
                    }
                    break;
                case NT_DEL_RT_AUTO:
                    if ((ret  = route_del_auto(&cmd_notice_entry.data.ifa))) {
                        printf("del route auto err %d\n", ret);
                    }
                    break;
                case NT_SET_SW_NF:
                    if ((ret = set_switch_nf((void *)&cmd_notice_entry.data.sw))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "set switch nf err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "set switch nf success\n");
                    }
                    break;
                case NT_SET_SW_FWD:
                    if ((ret = set_switch_fwd((void *)&cmd_notice_entry.data.sw))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "set switch fwd err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "set switch fwd success\n");
                    }
                    break;
                case NT_SET_SW_ARP:
                    if ((ret = set_switch_arp((void *)&cmd_notice_entry.data.sw))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "set switch arp err %d\n", ret);
                    } else {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "set switch arp success\n");
                    }
                    break;
                case NT_SET_RT6_AUTO:
                    if ((ret = route6_hlist_add_lcore_auto(&cmd_notice_entry.data.route6_conf))) {
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "set route6 auto err %d\n", ret);
                    }
                    break;
                case NT_DEL_RT6_AUTO:
                    if ((ret = route6_hlist_del_lcore_auto(&cmd_notice_entry.data.route6_conf))) {
                        printf("del route auto err %d\n", ret);
                        tyflow_cmdline_printf(cmd_notice_entry.cbt->cl, "del route6 auto err %d\n", ret);
                    }
                    break;
                default:
                    printf("unknown cmd type:%u\n", cmd_notice_entry.type);
            }
            rte_rwlock_read_unlock(&cmd_notice_entry.rwlock);
        }else {
            cmd_notice_entry.lcore_id = rte_get_main_lcore();
        }
    }
}

static inline int flow_cmd_ring_init(void)
{
    char ring_name[16];

    snprintf(ring_name, sizeof(ring_name), "l3_cmd_ring_%u",
        rte_lcore_id());
    this_lcore_cmd_ring = rte_ring_create(ring_name, CMD_RING_SIZE,
        rte_socket_id(), RING_F_SC_DEQ);
    if (unlikely(NULL == this_lcore_cmd_ring)) {
        printf("%s:create l3 cmd ring error\n",
            __FUNCTION__);
        return -ENOMEM;
    }

    g_lcores_l3_cmd_ring[rte_lcore_id()] = this_lcore_cmd_ring;

    return 0;
}

static int deal_l3_cmd(void *arg)
{
    int ret = 0;
    int p_ok = 0;
    struct vrf_map_elem vrf_node;
    struct common_cmd_notice_entry *cmd_notice_entry =
        (struct common_cmd_notice_entry *)arg;
    cmd_blk_t cbt;
    struct cmdline cl;
    cbt.cl = &cl;
    cbt.cl->s_out = 1;
    if (cmd_notice_entry->lcore_id == rte_lcore_id()) {
        //if (likely(graph)) {
            //rte_rwlock_read_lock(&cmd_notice_entry->rwlock);
            //cmd_notice_entry->lcore_id = rte_get_main_lcore();

            switch (cmd_notice_entry->type) {
                case NT_SET_RT:
                    if ((ret = new_route_add((void *)&cmd_notice_entry->data.route_node))) {
                        printf("set route err %d\n", ret);
                    } else if (p_ok) {
                        printf("set route success\n");
                    }
                    break;
                case NT_SET_RT6:
                    if ((ret = route6_hlist_add_lcore((void *)&cmd_notice_entry->data.route6_conf))) {
                        printf("set route6 err %d\n", ret);
                    } else if (p_ok) {
                        printf("set route6 success\n");
                    }
                    break;
                case NT_DEL_RT:
                    if ((ret = new_route_del((void *)&cmd_notice_entry->data.route_node))) {
                        printf("del route err %d\n", ret);
                    } else if (p_ok) {
                        printf("del route success\n");
                    }
                    break;
                case NT_DEL_RT6:
                    if ((ret = route6_hlist_del_lcore((void *)&cmd_notice_entry->data.route6_conf))) {
                        printf("del route6 err %d\n", ret);
                    } else if (p_ok) {
                        printf("del route6 success\n");
                    }
                    break;
                case NT_CLEAR_RT_TBL:
                    if ((ret = route_table_clear((void *)&cmd_notice_entry->data.route_node.table_id))) {
                        printf("clear route table err %d\n", ret);
                    } else if (p_ok) {
                        printf("clear route table success\n");
                    }
                    break;
                case NT_CLEAR_RT_TBLS:
                    if ((ret = route_tables_clear(NULL))) {
                        printf("clear route tables err %d\n", ret);
                    } else if (p_ok) {
                        printf("clear route tables success\n");
                    }
                    break;
               case NT_CLEAR_RT6_TBL:
                    if ((ret = route6_hlist_clear_lcore((void *)&cmd_notice_entry->data.route6_conf.table_id))) {
                        printf("clear route table err %d\n", ret);
                    } else if (p_ok) {
                        printf("clear route table success\n");
                    }
                    break;
                case NT_CLEAR_RT6_TBLS:
                    if ((ret = route6_hlists_clear_lcore(NULL))) {
                        printf("clear route tables err %d\n", ret);
                    } else if (p_ok) {
                        printf("clear route tables success\n");
                    }
                    break;
                case NT_SET_NEI:
                    if ((ret = neigh_add((void *)&cmd_notice_entry->data.neigh_node))) {
                        printf("set neigh err %d\n", ret);
                    } else if (p_ok) {
                        printf("set neigh success\n");
                    }
                    break;
                case NT_DEL_NEI:
                    if ((ret = neigh_del((void *)&cmd_notice_entry->data.neigh_node))) {
                        printf("del neigh err %d\n", ret);
                    } else if (p_ok) {
                        printf("del neigh success\n");
                    }
                    break;
                case NT_CLEAR_NEI_TBL:
                    if ((ret = neigh_table_clear((void *)&cmd_notice_entry->data.neigh_node.table_id))) {
                        printf("clear neigh table err %d\n", ret);
                    } else if (p_ok) {
                        printf("clear neigh table success\n");
                    }
                    break;
                case NT_CLEAR_NEI_TBLS:
                    if ((ret = neigh_tables_clear(NULL))) {
                        printf("clear neigh tables err %d\n", ret);
                    } else if (p_ok) {
                        printf("clear neigh tables success\n");
                    }
                    break;
                case NT_CREATE_VRF:
                    if ((ret = api_vrf_add((void *)&cmd_notice_entry->data.vrf_node))) {
                        printf("create vrf err %d\n", ret);
                    } else if (p_ok) {
                        printf("create vrf success\n");
                    }
                    break;
                case NT_SET_VRF:
                    vrf_node.table_id = cmd_notice_entry->data.vrf_bind_node.table_id;
                    ret = api_vrf_add((void *)&vrf_node);
                    if ((ret != 0) && (ret != -EEXIST)) {
                        printf("create vrf err %d\n", ret);
                        break;
                    } else if ((ret == 0) && (p_ok)) {
                        printf("create vrf success\n");
                    }

                    if ((ret = api_vrf_bind((void *)&cmd_notice_entry->data.vrf_bind_node))) {
                        printf("set vrf err %d\n", ret);
                    } else if (p_ok) {
                        printf("set vrf success\n");
                    }
                    break;
                case NT_CLEAR_VRF:
                    if ((ret = api_vrf_clear_id((void *)&cmd_notice_entry->data.vrf_bind_node.table_id))) {
                        printf("clear vrf err %d\n", ret);
                    } else if (p_ok) {
                        printf("clear vrf success\n");
                    }
                    break;
                case NT_CLEAR_VRFS:
                    if ((ret = api_vrf_clear_all(NULL))) {
                        printf("clear vrfs err %d\n", ret);
                    } else if (p_ok) {
                        printf("clear vrfs success\n");
                    }
                    break;
                case NT_DEL_VRF:
                    if ((ret = api_vrf_del_id((void *)&cmd_notice_entry->data.vrf_node.table_id))) {
                        printf("del vrf err %d\n", ret);
                    } else if (p_ok) {
                        printf("del vrf success\n");
                    }
                    break;
                case NT_DEL_VRFS:
                    if ((ret = api_vrf_del_all(NULL))) {
                        printf("del vrfs err %d\n", ret);
                    } else if (p_ok) {
                        printf("del vrfs success\n");
                    }
                    break;
                case NT_UNBIND_VRF:
                    if ((ret = api_vrf_unbind((void *)&cmd_notice_entry->data.vrf_bind_node))) {
                        printf("unbind vrf err %d\n", ret);
                    } else if (p_ok) {
                        printf("unbind vrf success\n");
                    }
                    break;
                case NT_CREATE_VXLAN_TUNN:
                    if ((ret = api_vxlan_tunnel_add((void *)&cmd_notice_entry->data.vxlan_tunnel_node))) {
                        printf("create vxlan tunnel err %d\n", ret);
                    } else if (p_ok) {
                        printf("create vxlan tunnel success\n");
                    }
                    break;
                case NT_CLEAR_VXLAN_TUNN:
                    if ((ret = api_vxlan_tunnel_clear(NULL))) {
                        printf("clear vxlan tunnel err %d\n", ret);
                    } else if (p_ok) {
                        printf("clear vxlan tunnel success\n");
                    }
                    break;
                case NT_DEL_VXLAN_TUNN:
                    if ((ret = api_vxlan_tunnel_del((void *)&cmd_notice_entry->data.vxlan_tunnel_node))) {
                        printf("del vxlan tunnel err %d\n", ret);
                    } else if (p_ok) {
                        printf("del vxlan tunnel success\n");
                    }
                    break;
                case NT_SET_RT_AUTO:
                    if ((ret  = route_add_auto(&cmd_notice_entry->data.ifa))) {
                        printf("set route auto err %d\n", ret);
                    }
                    break;
                case NT_DEL_RT_AUTO:
                    if ((ret  = route_del_auto(&cmd_notice_entry->data.ifa))) {
                        printf("del route auto err %d\n", ret);
                    }
                    break;
                case NT_SET_SW_NF:
                    if ((ret = set_switch_nf((void *)&cmd_notice_entry->data.sw))) {
                        printf("set switch nf err %d\n", ret);
                    } else if (p_ok) {
                        printf("set switch nf success\n");
                    }
                    break;
                case NT_SET_SW_FWD:
                    if ((ret = set_switch_fwd((void *)&cmd_notice_entry->data.sw))) {
                        printf("set switch fwd err %d\n", ret);
                    } else if (p_ok) {
                        printf("set switch fwd success\n");
                    }
                    break;
                case NT_SET_SW_ARP:
                    if ((ret = set_switch_arp((void *)&cmd_notice_entry->data.sw))) {
                        printf("set switch arp err %d\n", ret);
                    } else if (p_ok) {
                        printf("set switch arp success\n");
                    }
                    break;
                case NT_SET_RT6_AUTO:
                    if ((ret = route6_hlist_add_lcore_auto(&cmd_notice_entry->data.route6_conf))) {
                        printf("set route6 auto err %d\n", ret);
                    }
                    break;
                case NT_DEL_RT6_AUTO:
                    if ((ret = route6_hlist_del_lcore_auto(&cmd_notice_entry->data.route6_conf))) {
                        printf("del route6 auto err %d\n", ret);
                    }
                    break;
                case NT_DUMP:
                    cmd_notice_entry->dump(cmd_notice_entry->cbt,
                        cmd_notice_entry->lcore_id, cmd_notice_entry->table_id);
                    break;
                case NT_SET_IP4:
                case NT_SET_IP6:
                        cbt.mode = MODE_DO;
                        if(ret = add_netif_addr(&cmd_notice_entry->data.port_ip, &cbt)){
                            printf("del ip recover err %d\n", ret);
                        }
                        struct inet_ifaddr ifa;
                        struct inet_device idev;
                        ifa.idev = &idev;

                        if (cmd_notice_entry->data.port_ip.ifa_entry.af == AF_INET){
                            ifa.addr = cmd_notice_entry->data.port_ip.ifa_entry.addr;
                            ifa.bcast = cmd_notice_entry->data.port_ip.ifa_entry.bcast;
                            ifa.plen = cmd_notice_entry->data.port_ip.ifa_entry.plen;
                            ifa.idev->dev = netif_port_get_by_name(cmd_notice_entry->data.port_ip.ifa_entry.ifname);
                            route_add_ifaddr(&ifa);
                        }else{
                            route_add_ifaddr_v6(&cmd_notice_entry->data.port_ip);
                        } 
                    break;
                case NT_SET_VLAN:
                    {
                        if(ret = vlan_conf_recover(&cmd_notice_entry->data.vlan)){
                            printf("del vlan recover err %d\n", ret);
                        }
                    }
                    break;
                case NT_SET_METER:
                    {
                        if(ret = proc_auto_meter_recover(cmd_notice_entry->data.meter.szTenantID, 
                                      cmd_notice_entry->data.meter.bandwith));
                    }
                    break;
                default:
                    printf("unknown cmd type:%u\n", cmd_notice_entry->type);
            }
            //rte_rwlock_read_unlock(&cmd_notice_entry->rwlock);
        //}
    }

    return ret;
}

static inline int deq_l3_cmd_ring(void)
{
    struct common_cmd_notice_entry *cmd_notice_entry = NULL;

    while (rte_ring_dequeue(this_lcore_cmd_ring,
            (void **)&cmd_notice_entry) == 0) {
        deal_l3_cmd(cmd_notice_entry);
        rte_free(cmd_notice_entry);
    }

    return 0;
}

int api_flow_cmd_ring_init(void *arg)
{   
    RTE_SET_USED(arg);
    return(flow_cmd_ring_init());
}

int api_deq_l3_cmd_ring(void *arg)
{
    RTE_SET_USED(arg);
    return(deq_l3_cmd_ring());
}

extern int
register_netdevice_notifier(struct notifier_block *nb);
void flow_l3_cli_init(void)
{
    cmd_notice_entry.lcore_id = UINT32_MAX;    
    cmd_notice_entry.type = NT_MAX;
    rte_rwlock_init(&cmd_notice_entry.rwlock);
    route_cli_init();
    route6_cli_init();
    neigh_cli_init();
    vrf_cli_init();
    vxlan_cli_init();
    switch_cli_init();
    if (register_netdevice_notifier(&route_device_notifier)) {
        printf("%s:register_netdevice_notifier failed!\n", __func__);
        exit(1);
    }
}

