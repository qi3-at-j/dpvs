/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021 chc.
 */

#include <rte_vxlan.h>
#include <rte_jhash.h>
#include <rte_errno.h>

#include "l3_node_priv.h"
#include "common_priv.h"
#include "vrf_priv.h"
#include "vxlan_send_priv.h"
#include "vxlan_ctrl_priv.h"
#include "log_priv.h"
#include "route6_priv.h"

static __rte_always_inline uint16_t pack_v4_header(
    struct rte_mbuf *mbuf, struct rte_udp_hdr *udph)

{   
    static uint16_t packet_id;
    static uint8_t first_run = 1;
    char dst_addr[64] = {0};

    if (unlikely(first_run)) {
        first_run = 0;
        packet_id = rte_rand();
    }

    if (unlikely(rte_pktmbuf_prepend(mbuf, sizeof(struct rte_ipv4_hdr)) == NULL)) {
        L3_DEBUG_TRACE(L3_ERR, "%s:rte_pktmbuf_prepend fail!!!\n", __func__);
        return VXLAN_SEND_NEXT_DROP;
    }

    struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
    if (unlikely(iph == NULL)) {
        L3_DEBUG_TRACE(L3_ERR, "%s:ip header is null!!!\n", __func__);
        return VXLAN_SEND_NEXT_DROP;
    }

    iph->version_ihl = 0x45;
    iph->type_of_service = 0;
    iph->total_length = rte_cpu_to_be_16(rte_pktmbuf_pkt_len(mbuf));
    iph->packet_id = rte_cpu_to_be_16(packet_id++);
    iph->fragment_offset = 0;
    iph->time_to_live = INET_DEF_TTL;
    iph->next_proto_id = IPPROTO_UDP;
    iph->src_addr = GET_MBUF_PRIV_DATA(mbuf)->priv_data_vxlan_src_addr.in.s_addr;
    iph->dst_addr = GET_MBUF_PRIV_DATA(mbuf)->priv_data_vxlan_dst_addr.in.s_addr;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    RTE_SET_USED(udph);
    /* don't chsum */
    //udph->dgram_cksum = rte_ipv4_udptcp_cksum(iph, udph);

    struct route_entry *route_node = route_lookup(
        ROUTE_FLAG_LOCALIN | ROUTE_FLAG_FORWARD,
        GLOBAL_ROUTE_TBL_ID, iph->dst_addr);
    if (unlikely(route_node == NULL)) {
        inet_ntop(AF_INET, &iph->dst_addr,
                dst_addr, sizeof(dst_addr));
        L3_DEBUG_TRACE(L3_ERR, "%s:lookup %s failed!!!\n",
            __func__, dst_addr);
        return VXLAN_SEND_NEXT_DROP;
    }

    GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route = route_node;
    GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id = GLOBAL_ROUTE_TBL_ID;
    GET_MBUF_PRIV_DATA(mbuf)->priv_data_is_vxlan = false;
    mbuf_dev_set(mbuf, (void *)(route_node->port));

    return VXLAN_SEND_NEXT_OUTPUT_V4;
}

static __rte_always_inline uint16_t pack_v6_header(
    struct rte_mbuf *mbuf, struct rte_udp_hdr *udph)
{   
    char dst_addr[64] = {0};

    if (unlikely(rte_pktmbuf_prepend(mbuf, sizeof(struct rte_ipv6_hdr)) == NULL)) {
        L3_DEBUG_TRACE(L3_ERR, "%s:rte_pktmbuf_prepend fail!!!\n", __func__);
        return VXLAN_SEND_NEXT_DROP;
    }

    struct rte_ipv6_hdr *iph6 = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);
    if (unlikely(iph6 == NULL)) {
        L3_DEBUG_TRACE(L3_ERR, "%s:ip6 header is null!!!\n", __func__);
        return VXLAN_SEND_NEXT_DROP;
    }

    iph6->vtc_flow = rte_cpu_to_be_32(0x60000000);
    iph6->payload_len = rte_cpu_to_be_16(rte_pktmbuf_pkt_len(mbuf) - 
        sizeof(struct rte_ipv6_hdr));
    iph6->proto = IPPROTO_UDP;
    iph6->hop_limits = INET_DEF_TTL;
    rte_memcpy(iph6->src_addr,
        &(GET_MBUF_PRIV_DATA(mbuf)->priv_data_vxlan_src_addr.in6),
        sizeof(iph6->src_addr));
    rte_memcpy(iph6->dst_addr,
        &(GET_MBUF_PRIV_DATA(mbuf)->priv_data_vxlan_dst_addr.in6),
        sizeof(iph6->dst_addr));

    udph->dgram_cksum = rte_ipv6_udptcp_cksum(iph6, udph);

    GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id = GLOBAL_ROUTE_TBL_ID;

    struct route6_entry *route6_node = flow_route6_lookup(mbuf);
    if (unlikely(route6_node == NULL)) {
        inet_ntop(AF_INET6, iph6->dst_addr,
            dst_addr, sizeof(dst_addr));
        L3_DEBUG_TRACE(L3_ERR, "%s:lookup %s failed!!!\n",
            __func__, dst_addr);
        return VXLAN_SEND_NEXT_DROP;
    }

    GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route = route6_node;
    GET_MBUF_PRIV_DATA(mbuf)->priv_data_is_vxlan = false;
    mbuf_dev_set(mbuf, (void *)(route6_node->rt6_dev));

    return VXLAN_SEND_NEXT_OUTPUT_V6;
}

static __rte_always_inline uint16_t 
vxlan_send(s_nc_param_l3 *param)
{
    struct rte_mbuf *mbuf = param->mbuf;
    uint16_t next_node = VXLAN_SEND_NEXT_DROP;

    L3_DEBUG_TRACE(L3_INFO, "%s node recieved mbuf...\n", __func__);
    PrintMbufPkt(mbuf, 1, 1);

    struct rte_ether_hdr *eth_h = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    if (unlikely(eth_h == NULL)) {
        L3_DEBUG_TRACE(L3_ERR, "%s node:eth header is null!!!\n", __func__);
        return next_node;
    }

    if (unlikely(!GET_MBUF_PRIV_DATA(mbuf)->priv_data_is_vxlan)) {
        L3_DEBUG_TRACE(L3_ERR, "%s node:is not vxlan pack!!!\n", __func__);
        return next_node;
    }

    if (unlikely(rte_pktmbuf_prepend(mbuf, RTE_ETHER_VXLAN_HLEN) == NULL)) {
        L3_DEBUG_TRACE(L3_ERR, "%s node:rte_pktmbuf_prepend fail!!!\n", __func__);
        return next_node;
    }

    struct rte_udp_hdr *udph = rte_pktmbuf_mtod(mbuf, struct rte_udp_hdr *);
    if (unlikely(udph == NULL)) {
        L3_DEBUG_TRACE(L3_ERR, "%s node:udp header is null!!!\n", __func__);
        return next_node;
    }

    struct rte_vxlan_hdr *vxlanh = rte_pktmbuf_mtod_offset(mbuf,
        struct rte_vxlan_hdr *, sizeof(struct rte_udp_hdr));
    if (unlikely(vxlanh == NULL)) {
        L3_DEBUG_TRACE(L3_ERR, "%s node:vxlan header is null!!!\n", __func__);
        return next_node;
    }

#if 0
    uint32_t hash = rte_jhash(eth_h, RTE_ETHER_ADDR_LEN * 2, 0);
    hash ^= hash << 16;
    udph->src_port = rte_cpu_to_be_16(
        (((uint64_t) hash * (5000 - 1024)) >> 32) + 1024);
#else
    udph->src_port = rte_cpu_to_be_16(9999);
#endif
    udph->dst_port = rte_cpu_to_be_16(RTE_VXLAN_DEFAULT_PORT);
    udph->dgram_len = rte_cpu_to_be_16(rte_pktmbuf_pkt_len(mbuf));
    udph->dgram_cksum = 0;

    vxlanh->vx_flags = GET_MBUF_PRIV_DATA(mbuf)->priv_data_vxlan_hdr.vx_flags;  
    vxlanh->vx_vni = GET_MBUF_PRIV_DATA(mbuf)->priv_data_vxlan_hdr.vx_vni;

    if (GET_MBUF_PRIV_DATA(mbuf)->priv_data_vxlan_family == AF_INET) {
        L3_DEBUG_TRACE(L3_INFO, "%s node:ipv4 tunnel\n", __func__);
        next_node = pack_v4_header(mbuf, udph);
    } else if (GET_MBUF_PRIV_DATA(mbuf)->priv_data_vxlan_family == AF_INET6) {
        L3_DEBUG_TRACE(L3_INFO, "%s node:ipv6 tunnel\n", __func__);
        next_node = pack_v6_header(mbuf, udph);
    } else {
        L3_DEBUG_TRACE(L3_ERR, "%s node:ip version %u unknown!!!\n",
            __func__, GET_MBUF_PRIV_DATA(mbuf)->priv_data_vxlan_family);
        return next_node;
    }

    return next_node;
}

static uint16_t
vxlan_send_node_process(struct rte_graph *graph, 
                              struct rte_node *node,
                              void **objs, 
                              uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs, 
        nb_objs, VXLAN_SEND_NEXT_OUTPUT_V4, vxlan_send);
}

/* udp rcv Node */
struct rte_node_register vxlan_send_node = {
	.process = vxlan_send_node_process,
	.name = NODE_NAME_VXLAN_SEND,

	.nb_edges = VXLAN_SEND_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[VXLAN_SEND_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[VXLAN_SEND_NEXT_OUTPUT_V4] = NODE_NAME_IP4_OUTPUT,
        [VXLAN_SEND_NEXT_OUTPUT_V6] = NODE_NAME_IP6_OUTPUT_FINISH,
    },
};
RTE_NODE_REGISTER(vxlan_send_node);
