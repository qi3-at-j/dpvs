/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021 chc.
 */

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#include "ip4_rcv_priv.h"
#include "l3_node_priv.h"
#include "common_priv.h"
#include "log_priv.h"
#include "route_priv.h"
#include "vrf_priv.h"
#include "neigh_priv.h"
#include "vxlan_ctrl_priv.h"
#include "switch_cli_priv.h"
#include "flow_l3_cli_priv.h"
#include "vrrp_send_priv.h"

static __rte_always_inline uint16_t
ip4_rcv(s_nc_param_l3 *param)
{
    uint16_t hlen, len;
    struct rte_mbuf *mbuf = param->mbuf;
    struct rte_ipv4_hdr *iph;

    L3_DEBUG_TRACE(L3_INFO, "%s node recieved mbuf...\n", __func__);
    /* new_mbuf_may_pull not call,so dont print iph */
    PrintMbufPkt(mbuf, 1, 0);

    if (unlikely(mbuf->packet_type == ETH_PKT_OTHERHOST)) {
        L3_DEBUG_TRACE(L3_ERR, "%s:other host,drop!!!\n",
            __FUNCTION__);
        return IP4_RCV_NEXT_DROP;
    }

    //this should be done by L2
    if (unlikely(rte_pktmbuf_adj(mbuf, RTE_ETHER_HDR_LEN) == NULL)) {
        L3_DEBUG_TRACE(L3_ERR, "%s:rte_pktmbuf_adj error\n",
            __FUNCTION__);
        return IP4_RCV_NEXT_DROP;
    }
    mbuf->l2_len = 0;

    //IP4_UPD_PO_STATS(in, mbuf->pkt_len);
    //iftraf_pkt_in(AF_INET, mbuf, port);
    if (new_mbuf_may_pull(mbuf, sizeof(struct rte_ipv4_hdr)) != 0) {
        L3_DEBUG_TRACE(L3_ERR, "%s:new_mbuf_may_pull error 1\n",
            __FUNCTION__);
        goto inhdr_error;
    }
    PrintMbufPkt(mbuf, 0, 1);

    iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);

    if (unlikely((get_vrrp_status() == VRRP_ST_SLAVE) &&
        (lookup_vrrp_ip((union inet_addr *)&iph->dst_addr, AF_INET)))) {
        L3_DEBUG_TRACE(L3_ERR, "%s:is vrrp slave virtual dip,drop!!!\n",
            __FUNCTION__);
        return IP4_RCV_NEXT_DROP;
    }

    hlen = (iph->version_ihl & RTE_IPV4_HDR_IHL_MASK) << 2;
    //hlen = rte_ipv4_hdr_len(iph);

    if (((iph->version_ihl) >> 4) != IPVERSION ||
        hlen < sizeof(struct rte_ipv4_hdr)) {
            L3_DEBUG_TRACE(L3_ERR, "%s:version_ihl is %u,hlen is %u\n",
                __FUNCTION__, iph->version_ihl >> 4, hlen);
            goto inhdr_error;
    }

    if (new_mbuf_may_pull(mbuf, hlen)) {
        L3_DEBUG_TRACE(L3_ERR, "%s:new_mbuf_may_pull error 2\n",
            __FUNCTION__);
        goto inhdr_error;
    }

    if (unlikely(rte_raw_cksum(iph, hlen) != 0xFFFF))
        goto csum_error;

    len = ntohs(iph->total_length);
    if (unlikely(mbuf->pkt_len < len)) {
        //IP4_INC_STATS(intruncatedpkts);
        L3_DEBUG_TRACE(L3_ERR, "%s:pkt len:%u < ip total len:%u\n",
            __FUNCTION__, mbuf->pkt_len, len);
        goto drop;
    } else if (unlikely(len < hlen)) {
        L3_DEBUG_TRACE(L3_ERR, "%s:len:%u < hlen:%u\n",
            __FUNCTION__, len, hlen);
        goto inhdr_error;
    }
    
    /* trim padding if needed */
    if (unlikely(mbuf->pkt_len > len)) {
        if (unlikely(rte_pktmbuf_trim(mbuf, mbuf->pkt_len - len) != 0)) {
            //IP4_INC_STATS(indiscards);
            L3_DEBUG_TRACE(L3_ERR, "%s:rte_pktmbuf_trim error\n",
                __FUNCTION__);
            goto drop;
        }
    }

    if (unlikely(iph->next_proto_id == IPPROTO_OSPF)) {
        L3_DEBUG_TRACE(L3_ERR, "%s:ospf protocal pkt!!!drop now!!!\n",
            __FUNCTION__);
		goto drop;
    }

    mbuf->l3_len = hlen;
    memset(&GET_MBUF_PRIV_DATA(mbuf)->priv_data_src_addr,
        0, sizeof(union inet_addr));
    memset(&GET_MBUF_PRIV_DATA(mbuf)->priv_data_dst_addr,
        0, sizeof(union inet_addr));
    GET_MBUF_PRIV_DATA(mbuf)->priv_data_family = AF_INET;
    GET_MBUF_PRIV_DATA(mbuf)->priv_data_src_addr.in.s_addr =
        iph->src_addr;
    GET_MBUF_PRIV_DATA(mbuf)->priv_data_dst_addr.in.s_addr =
        iph->dst_addr;

#if VRF_USE_IP_HASH
    if (!GET_MBUF_PRIV_DATA(mbuf)->priv_data_is_vxlan) {
        union inet_addr ip_tmp;
        memset(&ip_tmp, 0, sizeof(union inet_addr));
        ip_tmp.in.s_addr = iph->dst_addr;
        struct net_vrf * vrf_node = vrf_ip_lookup(AF_INET, &ip_tmp);
        if (vrf_node) {
            GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id = 
                vrf_node->table_id;
        }
    }
#endif

    L3_DEBUG_TRACE(L3_INFO, "%s node:table id is %u\n",
        __func__, GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id);

    if (unlikely(get_switch_nf())) {
    //if (unlikely(this_lcore_switch.nf)) {
        return IP4_RCV_NEXT_FW;
    }

    return IP4_RCV_NEXT_FINISH;
	
csum_error:
    //IP4_INC_STATS(csumerrors);
    L3_DEBUG_TRACE(L3_ERR, "%s:csum error\n", __FUNCTION__);
    //return IP4_RCV_NEXT_DROP;
inhdr_error:
    //IP4_INC_STATS(inhdrerrors);
    L3_DEBUG_TRACE(L3_ERR, "%s:inhdr error\n", __FUNCTION__);
    return IP4_RCV_NEXT_DROP;
drop:
    L3_DEBUG_TRACE(L3_ERR, "%s:drop\n", __FUNCTION__);
    return IP4_RCV_NEXT_DROP;
}

static uint16_t
ip4_rcv_node_process(struct rte_graph *graph, 
                              struct rte_node *node,
                              void **objs, 
                              uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs, 
        nb_objs, IP4_RCV_NEXT_FINISH, ip4_rcv);
}

static int
ip4_rcv_node_init(const struct rte_graph *graph, 
                          struct rte_node *node)
{
    static uint8_t init_once = 0;
    uint32_t lcore_id;

    RTE_SET_USED(graph);
    RTE_SET_USED(node);

	if (!init_once) {
        /* Launch per-lcore init on every worker lcore */
        printf("call api_deq_l3_cmd_ring\n");
        rte_eal_mp_remote_launch(api_deq_l3_cmd_ring, NULL, SKIP_MAIN);            
        RTE_LCORE_FOREACH_WORKER(lcore_id) {
            if (rte_eal_wait_lcore(lcore_id) < 0) {
    			return -rte_errno;
            }
        }
        api_deq_l3_cmd_ring(NULL);
		init_once = 1;
	}

    return 0;
}

/* Packet Classification Node */
struct rte_node_register ip4_rcv_node = {
	.process = ip4_rcv_node_process,
	.name = NODE_NAME_IP4_RCV,

    .init = ip4_rcv_node_init,
    
	.nb_edges = IP4_RCV_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[IP4_RCV_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[IP4_RCV_NEXT_FINISH] = NODE_NAME_IP4_RCV_FINISH,
		[IP4_RCV_NEXT_FW] = NODE_NAME_NF_IP_PRE_ROUTING,
	},
};
RTE_NODE_REGISTER(ip4_rcv_node);
