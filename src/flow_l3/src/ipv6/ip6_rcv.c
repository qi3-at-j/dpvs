#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#include "conf/common.h"
#include "mbuf.h"
#include "inet.h"
#include "ipv6.h"
#include "route6.h"
#include "parser/parser.h"
#include "neigh.h"
#include "icmp6.h"
#include "iftraf.h"

#include "ip6_graph.h"
#include "ip6_rcv_priv.h"
#include "l3_node_priv.h"
#include "common_priv.h"
#include "log_priv.h"
#include "ip6_debug.h"
#include "route6_priv.h"
#include "vrf_priv.h"
#include "vrrp_send_priv.h"

static uint8_t g_cnf_fw_on;
static bool conf_ipv6_disable = false;


static __rte_always_inline uint16_t
ip6_rcv(s_nc_param_l3 *param){
    const struct rte_ipv6_hdr *hdr;
    uint32_t pkt_len, tot_len;
    struct netif_port *dev = NULL;
    struct rte_mbuf *mbuf = param->mbuf;    

    if(mbuf == NULL){
        return IP6_RCV_NEXT_DROP;
    }
    dev = mbuf_dev_get(mbuf);
    eth_type_t etype = mbuf->packet_type;

    if (unlikely(etype == ETH_PKT_OTHERHOST || !dev)) {
        return IP6_RCV_NEXT_DROP;
    }

    if (unlikely(rte_pktmbuf_adj(mbuf, RTE_ETHER_HDR_LEN) == NULL)) {
        return IP6_RCV_NEXT_DROP;
    }

    IPv6_UPD_PO_STATS(in, mbuf->pkt_len);
    //iftraf_pkt_in(AF_INET6, mbuf, dev);

    if (unlikely(conf_ipv6_disable)) {
        IPv6_INC_STATS(indiscards);
        return IP6_RCV_NEXT_DROP;
    }

    if (new_mbuf_may_pull(mbuf, sizeof(*hdr)) != 0) {
        L3_DEBUG_TRACE(L3_ERR, "v6 %s:new_mbuf_may_pull error 1\n", __FUNCTION__);
        goto err;
    }

    hdr = rte_ip6_hdr(mbuf);
    if(false == ipv6_version_check(hdr)){
        goto err;
    }

    if (unlikely((get_vrrp_status() == VRRP_ST_SLAVE) &&
        (lookup_vrrp_ip((union inet_addr *)hdr->dst_addr, AF_INET6)))) {
        L3_DEBUG_TRACE(L3_ERR, "%s:is vrrp slave virtual dip,drop!!!\n",
            __FUNCTION__);
        return IP6_RCV_NEXT_DROP;
    }

    /*
     * we do not have loopback dev for DPVS at all,
     * as RFC4291, loopback must be send/recv from lo dev.
     * so let's drop all pkt with loopback address.
     */
    if (rte_ipv6_addr_loopback(hdr->src_addr) ||
        rte_ipv6_addr_loopback(hdr->dst_addr))
        goto err;

    /*
     * RFC4291 Errata ID: 3480
     * interface-local scope is useful only for loopback transmission of
     * multicast but we do not have loopback dev.
     */
    if (rte_ipv6_addr_is_multicast(hdr->dst_addr) && RTE_IPV6_ADDR_MC_SCOPE(hdr->dst_addr) == 1)
        goto err;

    /*
     * drop unicast encapsulated in link-layer multicast/broadcast.
     * kernel is configurable, so need we ?
     */
    if (!rte_ipv6_addr_is_multicast(hdr->dst_addr) &&
        (etype == ETH_PKT_BROADCAST || etype == ETH_PKT_MULTICAST))
        goto err;

    /* RFC4291 2.7 */
    if (rte_ipv6_addr_is_multicast(hdr->dst_addr) &&
        RTE_IPV6_ADDR_MC_SCOPE(hdr->dst_addr) == 0)
        goto err;

    /*
     * RFC4291 2.7
     * source address must not be multicast.
     */
    if (rte_ipv6_addr_is_multicast(hdr->src_addr))
        goto err;

    pkt_len = rte_be_to_cpu_16(hdr->payload_len);
    tot_len = pkt_len + sizeof(*hdr);

    /* check pkt_len, note it's zero if jumbo payload option is present. */
    if (pkt_len || hdr->proto != NEXTHDR_HOP) {
        if (tot_len > mbuf->pkt_len) {
            IPv6_INC_STATS(intruncatedpkts);
            goto drop;
        }

        if (mbuf->pkt_len > tot_len) {
            if (rte_pktmbuf_trim(mbuf, mbuf->pkt_len - tot_len) != 0)
                goto err;
        }
    }

    /*
     * now @l3_len record fix header only,
     * it may change, when parsing extension headers.
     * @userdata is used to save route info in L3.
     */
    mbuf->l3_len = sizeof(*hdr);
	mbuf_userdata_set(mbuf, NULL);
    GET_MBUF_PRIV_DATA(mbuf)->priv_data_family = AF_INET6;
    rte_memcpy(&GET_MBUF_PRIV_DATA(mbuf)->priv_data_src_addr.in6,
        hdr->src_addr, sizeof(hdr->src_addr));
    rte_memcpy(&GET_MBUF_PRIV_DATA(mbuf)->priv_data_dst_addr.in6,
        hdr->dst_addr, sizeof(hdr->dst_addr));

#if VRF_USE_IP_HASH
    if (!GET_MBUF_PRIV_DATA(mbuf)->priv_data_is_vxlan) {
        struct net_vrf * vrf_node = vrf_ip_lookup(AF_INET6,
            (union inet_addr *)hdr->dst_addr);
        if (vrf_node) {
            GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id =
                vrf_node->table_id;
        }
    }
#endif

    L3_DEBUG_TRACE(L3_INFO, "%s node:table id is %u\n",
        __func__, GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id);

    /* hop-by-hop option header */
    if (hdr->proto == NEXTHDR_HOP) {
        if (ipv6_parse_hopopts(mbuf) != EDPVS_OK)
            goto err;
    }

#ifdef CONFIG_DPVS_IP_HEADER_DEBUG
    ip6_show_hdr(__func__, mbuf);
#endif

    if (likely(g_cnf_fw_on)) {
        return IP6_RCV_NEXT_FW;
    }
    
    return IP6_RCV_NEXT_FINISH;
    
err:
    IPv6_INC_STATS(inhdrerrors);
    L3_DEBUG_TRACE(L3_ERR, "%s:[v6]inhdr error\n", __FUNCTION__);
drop:
    return IP6_RCV_NEXT_DROP;
}

static uint16_t
ip6_rcv_node_process(struct rte_graph *graph, 
                              struct rte_node *node,
                              void **objs, 
                              uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs, 
        nb_objs, IP6_RCV_NEXT_FW, ip6_rcv);
}

static int
ip6_rcv_node_init(const struct rte_graph *graph, struct rte_node *node){
    //static uint8_t init_once = 0;
    //uint32_t lcore_id;

    RTE_SET_USED(graph);
    RTE_SET_USED(node);    
    g_cnf_fw_on = 1;

#if 0
	if (!init_once) {
        /* Launch per-lcore init on every worker lcore */
        RTE_LOG(INFO, TYPE_L3, "call new_route6_init\n");
        rte_eal_mp_remote_launch(new_route6_init, NULL, SKIP_MAIN);
        RTE_LCORE_FOREACH_WORKER(lcore_id) {
    		if (rte_eal_wait_lcore(lcore_id) < 0)
    			return -rte_errno;
    	}

        init_once = 1;
   }
#endif

    return 0;
}

/* Packet Classification Node */
struct rte_node_register ipv6_rcv_node = {
	.process = ip6_rcv_node_process,
	.name = NODE_NAME_IP6_RCV,

    .init = ip6_rcv_node_init,
    
	.nb_edges = IP6_RCV_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[IP6_RCV_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[IP6_RCV_NEXT_FINISH] = NODE_NAME_IP6_RCV_FINISH,
		[IP6_RCV_NEXT_FW] = NODE_NAME_NF_IP6_PRE_ROUTING,
	},
};

RTE_NODE_REGISTER(ipv6_rcv_node);

