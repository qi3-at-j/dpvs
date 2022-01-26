/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021 chc.
 */

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#include "ip4_local_deliver_finish_priv.h"
#include "l3_node_priv.h"
#include "common_priv.h"
#include "route_priv.h"

__thread uint16_t per_lcore_inet_protos_lcore[MAX_INET_PROTOS] =
    {[IPPROTO_UDP] = IP4_LOCAL_DELIVER_FINISH_NEXT_UDP,
     [IPPROTO_VRRP] = IP4_LOCAL_DELIVER_FINISH_NEXT_VRRP};
#define this_lcore_inet_protos (RTE_PER_LCORE(inet_protos_lcore))

static __rte_always_inline uint16_t
ip4_local_deliver_finish(s_nc_param_l3 *param)
{
    struct rte_mbuf *mbuf = param->mbuf;
    struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
    uint16_t hlen = (iph->version_ihl & RTE_IPV4_HDR_IHL_MASK) << 2;    
    //struct rte_node *node = param->node;

    L3_DEBUG_TRACE(L3_INFO, "%s node recieved mbuf...\n", __func__);
    PrintMbufPkt(mbuf, 0, 0);

    //IP4_UPD_PO_STATS(in, mbuf->pkt_len);
    //iftraf_pkt_in(AF_INET, mbuf, port);
    if (iph->next_proto_id != IPPROTO_VRRP) {
        if (unlikely(rte_pktmbuf_adj(mbuf, hlen) == NULL)) {
            return IP4_LOCAL_DELIVER_FINISH_NEXT_DROP;
        }
    }

    if (unlikely((this_lcore_inet_protos[iph->next_proto_id] ==
        IP4_LOCAL_DELIVER_FINISH_NEXT_DROP) ||
        (iph->next_proto_id >= MAX_INET_PROTOS))) {
        L3_DEBUG_TRACE(L3_INFO, "%s node:unsupported next protocol id:%u\n",
            __func__, iph->next_proto_id);
        return IP4_LOCAL_DELIVER_FINISH_NEXT_DROP;
    }

    return(this_lcore_inet_protos[iph->next_proto_id]);
}

static uint16_t
ip4_local_deliver_finish_node_process
                             (struct rte_graph *graph, 
                              struct rte_node *node,
                              void **objs, 
                              uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs, 
        nb_objs, IP4_LOCAL_DELIVER_FINISH_NEXT_DROP, ip4_local_deliver_finish);
}

#if 0
static int
ip4_local_deliver_finish_node_init(const struct rte_graph *graph, 
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
    RTE_LOG(INFO, TYPE_L3, "Initialized ip4_local_deliver_finish node");

    return 0;
}
#endif

struct rte_node_register ip4_local_deliver_finish_node = {
	.process = ip4_local_deliver_finish_node_process,
	.name = NODE_NAME_IP4_LOCAL_DELIVER_FINISH,

    //.init = ip4_local_deliver_finish_node_init,

	.nb_edges = IP4_LOCAL_DELIVER_FINISH_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[IP4_LOCAL_DELIVER_FINISH_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[IP4_LOCAL_DELIVER_FINISH_NEXT_UDP] = NODE_NAME_VXLAN_RCV,
		[IP4_LOCAL_DELIVER_FINISH_NEXT_VRRP] = NODE_NAME_VRRP_RCV,
    },
};
RTE_NODE_REGISTER(ip4_local_deliver_finish_node);
