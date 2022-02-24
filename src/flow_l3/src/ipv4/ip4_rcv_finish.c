/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021 chc.
 */
#include <arpa/inet.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf_dyn.h>

#include "ip4_rcv_finish_priv.h"
#include "l3_node_priv.h"
#include "log_priv.h"
#include "common_priv.h"
#include "route_priv.h"
#include "vrf_priv.h"
#include "neigh_priv.h"
#include "vxlan_ctrl_priv.h"


#ifndef TYFLOW_LEGACY
#include "flow.h"
extern struct route_entry *
flow_route_lookup(struct rte_mbuf *mbuf, uint32_t dst_ip);
struct route_entry *
flow_route_lookup(struct rte_mbuf *mbuf, uint32_t dst_ip)
{
    struct route_entry *route_node = NULL;
    uint32_t table_id = GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id;
    route_node = route_lookup(ROUTE_FLAG_LOCALIN | ROUTE_FLAG_FORWARD,
        table_id, dst_ip);
    return route_node;
}
#endif

static __rte_always_inline uint16_t 
ip4_rcv_finish(s_nc_param_l3 *param)
{    
    uint16_t next_node = IP4_RCV_FINISH_NEXT_DROP;
    struct rte_mbuf *mbuf = param->mbuf;
    /* Extract DIP of mbuf0 */
    struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr *)rte_pktmbuf_mtod(mbuf, void *);
    char dst_addr[64] = {0};
    uint32_t table_id;
    struct route_entry *route_node;

    L3_DEBUG_TRACE(L3_INFO, "%s node recieved mbuf...\n", __func__);
    PrintMbufPkt(mbuf, 0, 0);

    table_id = GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id;
    route_node = route_lookup(ROUTE_FLAG_LOCALIN | ROUTE_FLAG_FORWARD,
        table_id, iph->dst_addr);
    inet_ntop(AF_INET, &iph->dst_addr,
        dst_addr, sizeof(dst_addr));

    if (likely(route_node)) {
        mbuf_dev_set(mbuf, (void *)route_node->port);

        switch (route_node->flag) {
            case ROUTE_FLAG_LOCALIN:
                L3_DEBUG_TRACE(L3_INFO, "%s node:lookup %s success,flag:local\n",
                    __func__, dst_addr);
                break;
            case ROUTE_FLAG_FORWARD:
                L3_DEBUG_TRACE(L3_INFO, "%s node:lookup %s success,flag:net\n",
                    __func__, dst_addr);
                break;
            default:
                L3_DEBUG_TRACE(L3_INFO, "%s node:lookup %s success,flag:%u\n",
                    __func__, dst_addr, route_node->flag);
        }

        if (route_node->flag == ROUTE_FLAG_LOCALIN &&
            !(iph->next_proto_id == IPPROTO_ICMP)) {
            next_node = IP4_RCV_FINISH_NEXT_LOCAL;
            graph_route4_put(route_node);
        } else if (route_node->flag == ROUTE_FLAG_FORWARD ||
                   iph->next_proto_id == IPPROTO_ICMP) {
            if (mbuf->packet_type == ETH_PKT_HOST) {
                next_node = IP4_RCV_FINISH_NEXT_FORWARD;
                GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route = route_node;
            } else { /* dont forward multicast or broadcast */
                graph_route4_put(route_node);
            }
        } else {
            graph_route4_put(route_node);
        }
    }else {
        L3_DEBUG_TRACE(L3_ERR, "%s node:lookup %s failed!!!\n",
            __func__, dst_addr);
    }

    /* ip options to do... */

    return next_node;
}

static uint16_t
ip4_rcv_finish_node_process(struct rte_graph *graph, 
                                        struct rte_node *node,
		                                void **objs, 
		                                uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs, 
        nb_objs, IP4_RCV_FINISH_NEXT_FORWARD, ip4_rcv_finish);
}

static int
ip4_rcv_finish_node_init(const struct rte_graph *graph, struct rte_node *node)
{
    RTE_SET_USED(graph);
    RTE_SET_USED(node);

	return 0;
}

/* Packet Classification Node */
struct rte_node_register ip4_rcv_finish_node = {
	.process = ip4_rcv_finish_node_process,
	.name = NODE_NAME_IP4_RCV_FINISH,

    .init = ip4_rcv_finish_node_init,
    
	.nb_edges = IP4_RCV_FINISH_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[IP4_RCV_FINISH_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[IP4_RCV_FINISH_NEXT_LOCAL] = NODE_NAME_IP4_LOCAL_DELIVER,
		[IP4_RCV_FINISH_NEXT_FORWARD] = NODE_NAME_IP4_FORWARD,
		[IP4_RCV_FINISH_NEXT_ICMP] = NODE_NAME_ICMP_SEND,
	},
};
RTE_NODE_REGISTER(ip4_rcv_finish_node);
