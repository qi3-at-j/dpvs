/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021 chc.
 */

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_net.h>
#include <rte_mbuf.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_vxlan.h>

#include "ip4_output_finish_priv.h"
#include "l3_node_priv.h"
#include "route_priv.h"
#include "neigh_priv.h"
#include "vrf_priv.h"
#include "arp_priv.h"
#include "common_priv.h"
#include "log_priv.h"
#include "switch_cli_priv.h"

static __rte_always_inline uint16_t
ip4_output_finish(s_nc_param_l3 *param)
{    
    union inet_addr next_hop;
    struct rte_ipv4_hdr *iph;
    struct rte_node *node = param->node;
    struct rte_mbuf *mbuf = param->mbuf;
    struct rte_mbuf **mbuf2 = param->mbuf2;
    struct rte_graph *graph = param->graph;
    struct route_entry *route_node = 
        (struct route_entry *)GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route;
    rte_edge_t next;
    char dst_addr[64] = {0};

    L3_DEBUG_TRACE(L3_INFO, "%s node recieved mbuf...\n", __func__);
    PrintMbufPkt(mbuf, 0, 1);

    if (likely(route_node)) {
        iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
        if (route_node->gw.s_addr == htonl(INADDR_ANY))
            next_hop.in.s_addr = iph->dst_addr;
        else
            next_hop.in = route_node->gw;

        inet_ntop(AF_INET, &next_hop.in, dst_addr, sizeof(dst_addr));
        L3_DEBUG_TRACE(L3_INFO, "%s node:next_hop:%s\n",
            __func__, dst_addr);

        struct netif_port* port = route_node->port;
        graph_route4_put(route_node);
        if (unlikely(port == NULL)) {
            L3_DEBUG_TRACE(L3_ERR, "%s node:out port is null!\n", __FUNCTION__);
            return IP4_OUTPUT_FINISH_NEXT_DROP;
        }

        uint32_t table_id = GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id;

        next = GET_MBUF_PRIV_DATA(mbuf)->priv_data_is_vxlan?
               IP4_OUTPUT_FINISH_NEXT_VXLAN_SEND:
               IP4_OUTPUT_FINISH_NEXT_L2;

        if (unlikely(!get_switch_arp())) {
            struct neigh_entry *neighbour;
            neighbour = neigh_lookup(table_id, AF_INET, &next_hop);
            if (likely(neighbour)) {
                neigh_populate_mac(neighbour, mbuf, port, AF_INET);                
                L3_DEBUG_TRACE(L3_INFO, "%s node:populate mbuf neigh\n", __func__);
                PrintMbufPkt(mbuf, 1, 0);
                return next;
            } else {
                L3_DEBUG_TRACE(L3_INFO, "%s node:find neigh failed!arp switch is off,dont send arp!drop!\n", __func__);
                return IP4_OUTPUT_FINISH_NEXT_DROP;
            }
        }

        struct rte_mbuf *arp_req = NULL;
        int ret = neigh_output_graph(table_id, AF_INET, &next_hop,
                                     mbuf, port, &arp_req,
                                     graph, node, next);

        if (arp_req) {
            L3_DEBUG_TRACE(L3_INFO, "%s node:send arp request\n", __func__);
            PrintMbufPkt(arp_req, 1, 0);
            pktmbuf_copy_hdr(arp_req, mbuf);
            rte_node_enqueue_x1(graph, node, next, arp_req);           
        }

        if (ret != NEIGH_OUT_RS_OK) {
            if (ret == NEIGH_OUT_RS_HANG) {
                *mbuf2 = NULL;
            }
            return IP4_OUTPUT_FINISH_NEXT_DROP;
        }

        L3_DEBUG_TRACE(L3_INFO, "%s node:send mbuf\n", __func__);
        PrintMbufPkt(mbuf, 1, 0);
        return next;
    } else {
        L3_DEBUG_TRACE(L3_ERR, "route is null\n");
        return IP4_OUTPUT_FINISH_NEXT_DROP;
    }
}

static uint16_t
ip4_output_finish_node_process(struct rte_graph *graph, 
                              struct rte_node *node,
                              void **objs, 
                              uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs, 
        nb_objs, IP4_OUTPUT_FINISH_NEXT_DROP, ip4_output_finish);
}

#if 0
static int
ip4_output_finish_node_init(const struct rte_graph *graph, 
                          struct rte_node *node)
{
    static uint8_t init_once;
    static int offset;
    RTE_SET_USED(graph);
    RTE_BUILD_BUG_ON(sizeof(struct node_common_off_ctx) > RTE_NODE_CTX_SZ);

    if (!init_once) {
		offset = rte_mbuf_dynfield_register(
				&node_mbuf_priv_l3_dynfield_desc);
		if (offset < 0)
			return -rte_errno;

        init_once = 1;
    }

    /* Update socket's mbuf dyn priv1 offset in node ctx */
    NODE_MBUF_PRIV_L3_OFF(node->ctx) = offset;    
    RTE_LOG(INFO, TYPE_L3, "Initialized ip4_output_finish node");

    return 0;
}
#endif

struct rte_node_register ip4_output_finish_node = {
	.process = ip4_output_finish_node_process,
	.name = NODE_NAME_IP4_OUTPUT_FINISH,

    //.init = ip4_output_finish_node_init,
    
	.nb_edges = IP4_OUTPUT_FINISH_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[IP4_OUTPUT_FINISH_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[IP4_OUTPUT_FINISH_NEXT_VXLAN_SEND] = NODE_NAME_VXLAN_SEND,
		[IP4_OUTPUT_FINISH_NEXT_L2] = NODE_NAME_L2_OUT,
	},
};
RTE_NODE_REGISTER(ip4_output_finish_node);
