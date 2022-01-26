/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021 chc.
 */

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#include "l3_nf_ip6_pre_routing_priv.h"
#include "l3_node_priv.h"

static __rte_always_inline uint16_t
l3_nf_ip6_pre_routing(s_nc_param_l3 *param)
{
    RTE_SET_USED(param);

    /* work to do... */

    return L3_NF_IP6_PRE_ROUTING_NEXT_FINISH;
}

static uint16_t
l3_nf_ip6_pre_routing_node_process(struct rte_graph *graph, 
            struct rte_node *node, void **objs, uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs, 
        nb_objs, L3_NF_IP6_PRE_ROUTING_NEXT_FINISH, l3_nf_ip6_pre_routing);
}

static int
l3_nf_ip6_pre_routing_node_init(const struct rte_graph *graph, 
                          struct rte_node *node)
{
    RTE_SET_USED(graph);
    RTE_SET_USED(node);

    /* init to do... */
    
    return 0;
}

/* Packet Classification Node */
struct rte_node_register l3_nf_ip6_pre_routing_node = {
	.process = l3_nf_ip6_pre_routing_node_process,
	.name = NODE_NAME_NF_IP6_PRE_ROUTING,

    .init = l3_nf_ip6_pre_routing_node_init,
    
	.nb_edges = L3_NF_IP6_PRE_ROUTING_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[L3_NF_IP6_PRE_ROUTING_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[L3_NF_IP6_PRE_ROUTING_NEXT_FINISH] = NODE_NAME_IP6_RCV_FINISH,
	},
};
RTE_NODE_REGISTER(l3_nf_ip6_pre_routing_node);

