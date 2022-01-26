
#include "flow_l3_cfg_init_priv.h"
#include "flow_l3_cli_priv.h"
#include "route_cli_priv.h"
#include "route6_cli_priv.h"
#include "neigh_cli_priv.h"
#include "vrf_cli_priv.h"
#include "vxlan_cli_priv.h"
#include "common_cli_priv.h"
#include "switch_cli_priv.h"

#include "notifier.h"
#include "parser/parser.h"
#include "vrrp_parser.h"

#define FLOW_CFG_FILE_NAME CFG_FILE_NAME

struct common_cmd_notice_entry *conf_entry[RTE_MAX_LCORE];

extern struct rte_ring *g_lcores_l3_cmd_ring[RTE_MAX_LCORE]; // for cmd pthread

struct _tmp_val {
    uint32_t table_id;
    uint32_t vni;
} tmp_val;

static void create_conf_entry(uint16_t lcore_id)
{    
    uint16_t lcore_id_tmp;

    conf_entry[lcore_id] =
        (struct common_cmd_notice_entry *)rte_zmalloc_socket(
            "new_conf_entry",
            sizeof(struct common_cmd_notice_entry),
            RTE_CACHE_LINE_SIZE,
            rte_lcore_to_socket_id(lcore_id));
    if (conf_entry[lcore_id] == NULL) {
        printf("%s: malloc conf entry failed!!!\n", __func__);
        exit(1);
    }
    
    if (rte_ring_enqueue(g_lcores_l3_cmd_ring[lcore_id],
            conf_entry[lcore_id])) {
        /* Launch per-lcore init on every worker lcore */
        printf("%s: call api_deq_l3_cmd_ring\n", __func__);
        rte_eal_mp_remote_launch(api_deq_l3_cmd_ring, NULL, SKIP_MAIN);            
        RTE_LCORE_FOREACH_WORKER(lcore_id_tmp) {
            if (rte_eal_wait_lcore(lcore_id_tmp) < 0) {
                printf("%s: api_deq_l3_cmd_ring failed!!!\n", __func__);
            }
        }
    
        if (unlikely(rte_ring_enqueue(g_lcores_l3_cmd_ring[lcore_id],
                conf_entry[lcore_id]))) {
            printf("%s: rte_ring_enqueue failed!!!\n", __func__);
            exit(1);
        }
    }

    conf_entry[lcore_id]->lcore_id = lcore_id;
}

static inline int get_ip(void *dst, char *src, int af)
{
    if (unlikely((dst == NULL) || (src == NULL))) {
        printf("%s: para is NULL!!!\n", __func__);
        return -1;
    }

    if (unlikely(inet_pton(af, src, dst) != 1)) {
        printf("%s: ip %s is not available!!!\n", __func__, src);
        return -1;
    }

    return 0;
}

static inline int get_route_type(void *dst, char *src)
{
    if (unlikely((dst == NULL) || (src == NULL))) {
        printf("%s: para is NULL!!!\n", __func__);
        return -1;
    }

    if (strcmp(src, "net") == 0)
        *(uint32_t *)dst = ROUTE_FLAG_FORWARD;
    else if (strcmp(src, "local") == 0)
        *(uint32_t *)dst = ROUTE_FLAG_LOCALIN;
    else {
        printf("%s: route type %s is unknown!!!\n", __func__, src);
        return -1;
    }

    return 0;
}

static int do_deal_conf_data(uint16_t type, void *src, uint32_t lcore_id)
{
    int ret = 0;
    char *str = src;

    switch (type) {
    case GET_ROUTE_V4:
        create_conf_entry(lcore_id);
        conf_entry[lcore_id]->type = NT_SET_RT;
        conf_entry[lcore_id]->data.route_node.table_id = tmp_val.table_id;
        break;
    case GET_ROUTE_V4_DIP:
        ret = get_ip(&conf_entry[lcore_id]->data.route_node.dest, str, AF_INET);
        break;
    case GET_ROUTE_V4_MASK:
        conf_entry[lcore_id]->data.route_node.netmask = atoi(str);
        break;
    case GET_ROUTE_V4_GW:
        ret = get_ip(&conf_entry[lcore_id]->data.route_node.gw, str, AF_INET);
        break;
    case GET_ROUTE_V4_PORT:
        conf_entry[lcore_id]->data.route_node.port =
            netif_port_get_by_name(str);
        if (unlikely(conf_entry[lcore_id]->data.route_node.port == NULL)) {
            printf("%s: port %s is null!!!\n", __func__, str);
            ret = -1;
        }
        break;
    case GET_ROUTE_V4_TYPE:
        ret = get_route_type(&conf_entry[lcore_id]->data.route_node.flag, str);
        break;
    case GET_ROUTE_V6:
        create_conf_entry(lcore_id);
        conf_entry[lcore_id]->type = NT_SET_RT6;
        conf_entry[lcore_id]->data.route6_conf.table_id = tmp_val.table_id;
        break;
    case GET_ROUTE_V6_DIP:
        ret = get_ip(&conf_entry[lcore_id]->data.route6_conf.dst.addr,
            str, AF_INET6);
        break;
    case GET_ROUTE_V6_MASK:
        conf_entry[lcore_id]->data.route6_conf.dst.plen = atoi(str);
        break;
    case GET_ROUTE_V6_GW:
        ret = get_ip(&conf_entry[lcore_id]->data.route6_conf.gateway,
            str, AF_INET6);
        break;
    case GET_ROUTE_V6_PORT:
        strncpy(conf_entry[lcore_id]->data.route6_conf.ifname,
            str, IFNAMSIZ - 1);
        break;
    case GET_ROUTE_V6_TYPE:
        ret = get_route_type(&conf_entry[lcore_id]->data.route6_conf.flags, str);
        break;
    case GET_VXLAN_TUN_V4:
        create_conf_entry(lcore_id);
        conf_entry[lcore_id]->type = NT_CREATE_VXLAN_TUNN;
        conf_entry[lcore_id]->data.vxlan_tunnel_node.vni = tmp_val.vni;
        conf_entry[lcore_id]->data.vxlan_tunnel_node.family = AF_INET;
        break;
    case GET_VXLAN_TUN_V4_SIP:
        ret = get_ip(&conf_entry[lcore_id]->data.vxlan_tunnel_node.saddr.in,
            str, AF_INET);
        break;
    case GET_VXLAN_TUN_V4_DIP:
        ret = get_ip(&conf_entry[lcore_id]->data.vxlan_tunnel_node.remote_ip.in,
            str, AF_INET);
        break;
    case GET_VXLAN_TUN_V6:
        create_conf_entry(lcore_id);
        conf_entry[lcore_id]->type = NT_CREATE_VXLAN_TUNN;
        conf_entry[lcore_id]->data.vxlan_tunnel_node.vni = tmp_val.vni;
        conf_entry[lcore_id]->data.vxlan_tunnel_node.family = AF_INET6;
        break;
    case GET_VXLAN_TUN_V6_SIP:
        ret = get_ip(&conf_entry[lcore_id]->data.vxlan_tunnel_node.saddr.in6,
            str, AF_INET6);
        break;
    case GET_VXLAN_TUN_V6_DIP:
        ret = get_ip(&conf_entry[lcore_id]->data.vxlan_tunnel_node.remote_ip.in6,
            str, AF_INET6);
        break;
#if VRF_USE_VNI_HASH
    case GET_VRF_BIND_VNI:
        create_conf_entry(lcore_id);
        conf_entry[lcore_id]->type = NT_SET_VRF;
        conf_entry[lcore_id]->data.vrf_bind_node.type = VRF_TYPE_VNI;
        conf_entry[lcore_id]->data.vrf_bind_node.table_id = tmp_val.table_id;
        conf_entry[lcore_id]->data.vrf_bind_node.vni = atoi(str);
        break;
#endif
#if VRF_USE_IP_HASH
    case GET_VRF_BIND_IP:
        create_conf_entry(lcore_id);
        conf_entry[lcore_id]->type = NT_SET_VRF;
        conf_entry[lcore_id]->data.vrf_bind_node.type = VRF_TYPE_IP;
        conf_entry[lcore_id]->data.vrf_bind_node.family = AF_INET;
        conf_entry[lcore_id]->data.vrf_bind_node.table_id = tmp_val.table_id;
        ret = get_ip(&conf_entry[lcore_id]->data.vrf_bind_node.ip.in,
            str, AF_INET);
        break;
    case GET_VRF_BIND_IP6:
        create_conf_entry(lcore_id);
        conf_entry[lcore_id]->type = NT_SET_VRF;
        conf_entry[lcore_id]->data.vrf_bind_node.type = VRF_TYPE_IP;
        conf_entry[lcore_id]->data.vrf_bind_node.family = AF_INET6;
        conf_entry[lcore_id]->data.vrf_bind_node.table_id = tmp_val.table_id;
        ret = get_ip(
            &conf_entry[lcore_id]->data.vrf_bind_node.ip.in6, str, AF_INET6);
        break;
#endif
#if VRF_USE_DEV_HASH
    case GET_VRF_BIND_PORT:
        create_conf_entry(lcore_id);
        conf_entry[lcore_id]->type = NT_SET_VRF;
        conf_entry[lcore_id]->data.vrf_bind_node.type = VRF_TYPE_PORT;
        conf_entry[lcore_id]->data.vrf_bind_node.table_id = tmp_val.table_id;
        conf_entry[lcore_id]->data.vrf_bind_node.port =
            netif_port_get_by_name(str);
        if (unlikely(conf_entry[lcore_id]->data.vrf_bind_node.port == NULL)) {
            printf("%s: port %s is null!!!\n", __func__, str);
            ret = -1;
        }
        break;
#endif
    case GET_ARP_V4:
        create_conf_entry(lcore_id);
        conf_entry[lcore_id]->type = NT_SET_NEI;
        conf_entry[lcore_id]->data.neigh_node.table_id = tmp_val.table_id;
        conf_entry[lcore_id]->data.neigh_node.af = AF_INET;
        conf_entry[lcore_id]->data.neigh_node.flag |= NEIGH_STATIC;
        conf_entry[lcore_id]->data.neigh_node.state = CLI_NUD_S_STATIC;
        break;
    case GET_ARP_IP:
        ret = get_ip(
            &conf_entry[lcore_id]->data.neigh_node.next_hop.in, str, AF_INET);
        break;
    case GET_ARP_V6:
        create_conf_entry(lcore_id);
        conf_entry[lcore_id]->type = NT_SET_NEI;
        conf_entry[lcore_id]->data.neigh_node.table_id = tmp_val.table_id;
        conf_entry[lcore_id]->data.neigh_node.af = AF_INET6;
        conf_entry[lcore_id]->data.neigh_node.flag |= NEIGH_STATIC;
        conf_entry[lcore_id]->data.neigh_node.state = CLI_NUD_S_STATIC;
        break;
    case GET_ARP_IP6:
        ret = get_ip(
            &conf_entry[lcore_id]->data.neigh_node.next_hop.in6, str, AF_INET6);
        break;
    case GET_ARP_MAC:
        ret = neigh_atoi(
            conf_entry[lcore_id]->data.neigh_node.d_mac.addr_bytes, str);
        if (unlikely(ret))
            printf("%s: mac %s is not available!!!\n", __func__, str);
        break;
    case GET_SW_ARP:
        create_conf_entry(lcore_id);
        conf_entry[lcore_id]->type = NT_SET_SW_ARP;
        conf_entry[lcore_id]->data.sw.arp = atoi(str);
        break;
    case GET_SW_FWD:
        create_conf_entry(lcore_id);
        conf_entry[lcore_id]->type = NT_SET_SW_FWD;
        conf_entry[lcore_id]->data.sw.fwd = atoi(str);
        break;
    case GET_SW_NF:
        create_conf_entry(lcore_id);
        conf_entry[lcore_id]->type = NT_SET_SW_NF;
        conf_entry[lcore_id]->data.sw.nf = atoi(str);
        break;
    default:
        printf("unknown deal data type: %u\n", type);
    }

    if (unlikely(ret)) {
        conf_entry[lcore_id]->type = NT_MAX;
        return -1;
    }

    return 0;
}

static inline void deal_conf_data(uint16_t type, char *src)
{
    common_notice_lcores(LCORE_ID_ANY, type, src, do_deal_conf_data);
}

static inline void route_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    tmp_val.table_id = atoi(str);
    FREE_PTR(str);
}

static inline void route_v4_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_ROUTE_V4, str);
    FREE_PTR(str);
}

static inline void route_v4_dip_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_ROUTE_V4_DIP, str);
    FREE_PTR(str);
}

static inline void route_v4_mask_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_ROUTE_V4_MASK, str);
    FREE_PTR(str);
}

static inline void route_v4_gw_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_ROUTE_V4_GW, str);
    FREE_PTR(str);
}

static inline void route_v4_port_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_ROUTE_V4_PORT, str);
    FREE_PTR(str);
}

static inline void route_v4_type_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_ROUTE_V4_TYPE, str);
    FREE_PTR(str);
}

static inline void route_v6_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_ROUTE_V6, str);
    FREE_PTR(str);
}

static inline void route_v6_dip_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_ROUTE_V6_DIP, str);
    FREE_PTR(str);
}

static inline void route_v6_mask_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_ROUTE_V6_MASK, str);
    FREE_PTR(str);
}

static inline void route_v6_gw_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_ROUTE_V6_GW, str);
    FREE_PTR(str);
}

static inline void route_v6_port_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_ROUTE_V6_PORT, str);
    FREE_PTR(str);
}

static inline void route_v6_type_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_ROUTE_V6_TYPE, str);
    FREE_PTR(str);
}

static inline void vxlan_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    tmp_val.vni = atoi(str);
    FREE_PTR(str);
}

static inline void vxlan_tun_v4_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_VXLAN_TUN_V4, str);
    FREE_PTR(str);
}

static inline void vxlan_tun_v4_sip_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_VXLAN_TUN_V4_SIP, str);
    FREE_PTR(str);
}

static inline void vxlan_tun_v4_rip_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_VXLAN_TUN_V4_DIP, str);
    FREE_PTR(str);
}

static inline void vxlan_tun_v6_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_VXLAN_TUN_V6, str);
    FREE_PTR(str);
}

static inline void vxlan_tun_v6_sip_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_VXLAN_TUN_V6_SIP, str);
    FREE_PTR(str);
}

static inline void vxlan_tun_v6_rip_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_VXLAN_TUN_V6_DIP, str);
    FREE_PTR(str);
}

static inline void vrf_bind_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    tmp_val.table_id = atoi(str);
    FREE_PTR(str);
}

#if VRF_USE_VNI_HASH
static inline void vrf_bind_vni_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_VRF_BIND_VNI, str);
    FREE_PTR(str);
}
#endif

#if VRF_USE_IP_HASH
static inline void vrf_bind_ip_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_VRF_BIND_IP, str);
    FREE_PTR(str);
}

static inline void vrf_bind_ip6_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_VRF_BIND_IP6, str);
    FREE_PTR(str);
}
#endif

#if VRF_USE_DEV_HASH
static inline void vrf_bind_port_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_VRF_BIND_PORT, str);
    FREE_PTR(str);
}
#endif

static inline void arp_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    tmp_val.table_id = atoi(str);
    FREE_PTR(str);
}

static inline void arp_v4_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_ARP_V4, str);
    FREE_PTR(str);
}

static inline void arp_ip_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_ARP_IP, str);
    FREE_PTR(str);
}

static inline void arp_v6_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_ARP_V6, str);
    FREE_PTR(str);
}

static inline void arp_ip6_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_ARP_IP6, str);
    FREE_PTR(str);
}

static inline void arp_mac_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_ARP_MAC, str);
    FREE_PTR(str);
}

static inline void switch_arp_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_SW_ARP, str);
    FREE_PTR(str);
}

static inline void switch_fwd_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_SW_FWD, str);
    FREE_PTR(str);
}

static inline void switch_nf_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    deal_conf_data(GET_SW_NF, str);
    FREE_PTR(str);
}

static inline void install_route(void)
{
    install_keyword("route", route_handler, KW_TYPE_NORMAL);
    install_sublevel();

    install_keyword("v4", route_v4_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("dip", route_v4_dip_handler, KW_TYPE_NORMAL);
    install_keyword("netmask", route_v4_mask_handler, KW_TYPE_NORMAL);
    install_keyword("gw", route_v4_gw_handler, KW_TYPE_NORMAL);
    install_keyword("port", route_v4_port_handler, KW_TYPE_NORMAL);
    install_keyword("type", route_v4_type_handler, KW_TYPE_NORMAL);
    install_sublevel_end();

    install_keyword("v6", route_v6_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("dip", route_v6_dip_handler, KW_TYPE_NORMAL);
    install_keyword("prefix_len", route_v6_mask_handler, KW_TYPE_NORMAL);
    install_keyword("gw", route_v6_gw_handler, KW_TYPE_NORMAL);
    install_keyword("port", route_v6_port_handler, KW_TYPE_NORMAL);
    install_keyword("type", route_v6_type_handler, KW_TYPE_NORMAL);
    install_sublevel_end();

    install_sublevel_end();
}

static inline void install_vxlan(void)
{
    install_keyword("vxlan", vxlan_handler, KW_TYPE_NORMAL);
    install_sublevel();

    install_keyword("v4", vxlan_tun_v4_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("sip", vxlan_tun_v4_sip_handler, KW_TYPE_NORMAL);
    install_keyword("rip", vxlan_tun_v4_rip_handler, KW_TYPE_NORMAL);
    install_sublevel_end();

    install_keyword("v6", vxlan_tun_v6_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("sip", vxlan_tun_v6_sip_handler, KW_TYPE_NORMAL);
    install_keyword("rip", vxlan_tun_v6_rip_handler, KW_TYPE_NORMAL);
    install_sublevel_end();

    install_sublevel_end();
}

static inline void install_vrf_bind(void)
{
    install_keyword("vrf_bind", vrf_bind_handler, KW_TYPE_NORMAL);
    install_sublevel();

#if VRF_USE_VNI_HASH
    install_keyword("vni", vrf_bind_vni_handler, KW_TYPE_NORMAL);
#endif
#if VRF_USE_IP_HASH
    install_keyword("ip", vrf_bind_ip_handler, KW_TYPE_NORMAL);
    install_keyword("ip6", vrf_bind_ip6_handler, KW_TYPE_NORMAL);
#endif
#if VRF_USE_DEV_HASH
    install_keyword("port", vrf_bind_port_handler, KW_TYPE_NORMAL);
#endif

    install_sublevel_end();
}

static inline void install_arp(void)
{
    install_keyword("arp", arp_handler, KW_TYPE_NORMAL);
    install_sublevel();

    install_keyword("v4", arp_v4_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("ip", arp_ip_handler, KW_TYPE_NORMAL);
    install_keyword("mac", arp_mac_handler, KW_TYPE_NORMAL);
    install_sublevel_end();

    install_keyword("v6", arp_v6_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("ip", arp_ip6_handler, KW_TYPE_NORMAL);
    install_keyword("mac", arp_mac_handler, KW_TYPE_NORMAL);
    install_sublevel_end();

    install_sublevel_end();
}

static inline void install_switch(void)
{
    install_keyword("switch", NULL, KW_TYPE_NORMAL);
    install_sublevel();

    install_keyword("arp", switch_arp_handler, KW_TYPE_NORMAL);
    install_keyword("fwd", switch_fwd_handler, KW_TYPE_NORMAL);
    install_keyword("nf", switch_nf_handler, KW_TYPE_NORMAL);

    install_sublevel_end();
}

static inline void install_flow_l3_keywords(void)
{
    install_keyword_root("flow_l3_cfg", NULL);
    install_route();
    install_vxlan();
    install_vrf_bind();
    install_arp();
    install_switch();
}

static inline void install_flow_keywords(void)
{
    vrrp_init_keywords();
    install_flow_l3_keywords();
}

int flow_cfgfile_init(void)
{
    init_data(FLOW_CFG_FILE_NAME, install_flow_keywords);
    return EDPVS_OK;
}

int flow_l3_init(void)
{
    uint32_t lcore_id;

    if (1) {
        /* Launch per-lcore init on every worker lcore */
        printf("call new_route_init\n");
        rte_eal_mp_remote_launch(new_route_init, NULL, SKIP_MAIN);
        RTE_LCORE_FOREACH_WORKER(lcore_id) {
    		if (rte_eal_wait_lcore(lcore_id) < 0) {
                printf("new_route_init failed!!!\n");
                return -rte_errno;
            }
    	}

        /* Launch per-lcore init on every worker lcore */
        printf("call new_route6_init\n");
        rte_eal_mp_remote_launch(new_route6_init, NULL, SKIP_MAIN);
        RTE_LCORE_FOREACH_WORKER(lcore_id) {
    		if (rte_eal_wait_lcore(lcore_id) < 0) {
                printf("new_route6_init failed!!!\n");
                return -rte_errno;
            }
    	}

        /* Launch per-lcore init on every worker lcore */
        printf("call new_neigh_init\n");
        rte_eal_mp_remote_launch(new_neigh_init, NULL, SKIP_MAIN);
        RTE_LCORE_FOREACH_WORKER(lcore_id) {
    		if (rte_eal_wait_lcore(lcore_id) < 0) {
                printf("new_neigh_init failed!!!\n");
                return -rte_errno;
            }
    	}

        /* Launch per-lcore init on every worker lcore */
        printf("call api_vrf_init\n");
        rte_eal_mp_remote_launch(api_vrf_init, NULL, SKIP_MAIN);
        RTE_LCORE_FOREACH_WORKER(lcore_id) {
    		if (rte_eal_wait_lcore(lcore_id) < 0) {
                printf("api_vrf_init failed!!!\n");
                return -rte_errno;
            }
    	}
        
        /* Launch per-lcore init on every worker lcore */
        printf("call api_vxlan_tunnel_init\n");
        rte_eal_mp_remote_launch(api_vxlan_tunnel_init, NULL, SKIP_MAIN);
        RTE_LCORE_FOREACH_WORKER(lcore_id) {
    		if (rte_eal_wait_lcore(lcore_id) < 0) {
                printf("api_vxlan_tunnel_init failed!!!\n");
                return -rte_errno;
            }
    	}

        /* Launch per-lcore init on every worker lcore */
        printf("call switch_init\n");
        rte_eal_mp_remote_launch(switch_init, NULL, SKIP_MAIN);
        RTE_LCORE_FOREACH_WORKER(lcore_id) {
    		if (rte_eal_wait_lcore(lcore_id) < 0) {
                printf("switch_init failed!!!\n");
                return -rte_errno;
            }
    	}

        /* Launch per-lcore init on every worker lcore */
        printf("call api_flow_cmd_ring_init\n");
        rte_eal_mp_remote_launch(api_flow_cmd_ring_init, NULL, SKIP_MAIN);
        RTE_LCORE_FOREACH_WORKER(lcore_id) {
            if (rte_eal_wait_lcore(lcore_id) < 0) {
                printf("api_flow_cmd_ring_init failed!!!\n");
                return -rte_errno;
            }
        }
	}

    return EDPVS_OK;
}

