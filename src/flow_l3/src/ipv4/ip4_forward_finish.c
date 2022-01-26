/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021 chc.
 */

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#include "ip4_forward_finish_priv.h"
#include "l3_node_priv.h"
#include "log_priv.h"

static __rte_always_inline uint16_t 
ip4_forward_finish(s_nc_param_l3 *param)
{
    struct rte_mbuf *mbuf = param->mbuf;

    L3_DEBUG_TRACE(L3_INFO, "%s node recieved mbuf...\n", __func__);
    PrintMbufPkt(mbuf, 0, 0);

    //IP4_INC_STATS(outforwdatagrams);
    //IP4_ADD_STATS(outoctets, mbuf->pkt_len);

    /* ip options... */

    return IP4_FORWARD_FINISH_NEXT_OUTPUT;
}

static uint16_t
ip4_forward_finish_node_process(struct rte_graph *graph, 
            struct rte_node *node, void **objs, uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs, 
        nb_objs, IP4_FORWARD_FINISH_NEXT_OUTPUT, ip4_forward_finish);
}

static int
ip4_forward_finish_node_init(const struct rte_graph *graph, 
                                struct rte_node *node)
{
    RTE_SET_USED(graph);
    RTE_SET_USED(node);

    return 0;
}

/* Packet Classification Node */
struct rte_node_register ip4_forward_finish_node = {
	.process = ip4_forward_finish_node_process,
	.name = NODE_NAME_IP4_FORWARD_FINISH,

    .init = ip4_forward_finish_node_init,
    
	.nb_edges = IP4_FORWARD_FINISH_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[IP4_FORWARD_FINISH_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[IP4_FORWARD_FINISH_NEXT_OUTPUT] = NODE_NAME_IP4_OUTPUT,
	},
};
RTE_NODE_REGISTER(ip4_forward_finish_node);
