/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021 chc.
 */

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#include "icmp_send_priv.h"
#include "l3_node_priv.h"

static uint8_t g_cnf_fw_on;

static __rte_always_inline uint16_t 
icmp_send(s_nc_param_l3 *param)
{
    RTE_SET_USED(param);

    return ICMP_SEND_NEXT_DROP;
}

static uint16_t
icmp_send_node_process(struct rte_graph *graph, 
            struct rte_node *node, void **objs, uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs, 
        nb_objs, ICMP_SEND_NEXT_DROP, icmp_send);
}

static int
icmp_send_node_init(const struct rte_graph *graph, 
                                struct rte_node *node)
{
    RTE_SET_USED(graph);
    RTE_SET_USED(node);
    
    g_cnf_fw_on = 1;

    return 0;
}

/* Packet Classification Node */
struct rte_node_register icmp_send_node = {
	.process = icmp_send_node_process,
	.name = "icmp_send",

    .init = icmp_send_node_init,
    
	.nb_edges = ICMP_SEND_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[ICMP_SEND_NEXT_DROP] = "pkt_drop",
	},
};
RTE_NODE_REGISTER(icmp_send_node);
