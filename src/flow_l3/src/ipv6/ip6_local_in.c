/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021 chc.
 */

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_ip_frag.h>

#include "ip6_local_in_priv.h"
#include "l3_node_priv.h"
#include "log_priv.h"

static uint8_t g_cnf_fw_on;

static int ip6_local_in(s_nc_param_l3 *param)
{
    if (likely(g_cnf_fw_on)) {
        return IP6_LOCAL_IN_NEXT_FW;
    }else{
        return IP6_LOCAL_IN_NEXT_FINISH;
    }
}

static uint16_t
ip6_local_in_node_process(struct rte_graph *graph, 
            struct rte_node *node, void **objs, uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs, 
        nb_objs, IP6_LOCAL_IN_NEXT_FW, ip6_local_in);
}

static int
ip6_local_in_node_init(const struct rte_graph *graph, 
        struct rte_node *node)
{   
    static uint8_t init_once;

    RTE_SET_USED(graph);
    RTE_SET_USED(node);

    if (!init_once) {
        g_cnf_fw_on = 1;//netfilter switch
        init_once = 1;        
    }


    return 0;
}

struct rte_node_register ip6_local_in_node = {
	.process = ip6_local_in_node_process,
	.name = NODE_NAME_IP6_LOCAL_IN,

    .init = ip6_local_in_node_init,
    
	.nb_edges = IP6_LOCAL_IN_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[IP6_LOCAL_IN_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[IP6_LOCAL_IN_NEXT_FINISH] = NODE_NAME_IP6_LOCAL_IN_FINISH,
        [IP6_LOCAL_IN_NEXT_FW] = NODE_NAME_NF_IP6_LOCAL_IN,
    },
};
RTE_NODE_REGISTER(ip6_local_in_node);

