/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021 chc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <arpa/inet.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf_dyn.h>

#include "conf/flow.h"
#include "conf/common.h"
#include "inetaddr.h"
#include "mbuf.h"
#include "inet.h"
#include "ipv6.h"
#include "route6.h"
#include "parser/parser.h"
#include "neigh.h"
#include "icmp6.h"
#include "iftraf.h"

#include "ip6_rcv_finish_priv.h"
#include "l3_node_priv.h"
#include "log_priv.h"
#include "common_priv.h"
#include "route_priv.h"
#include "ip6_debug.h"
#include "ip6_graph.h"
#include "route6_priv.h"

static uint16_t ip6_mc_local_in(struct rte_mbuf *mbuf)
{
    struct rte_ipv6_hdr *iph = rte_ip6_hdr(mbuf);

    IPv6_UPD_PO_STATS(inmcast, mbuf->pkt_len);

    if (inet_chk_mcast_addr(AF_INET6, netif_port_get(mbuf->port),
                            (union inet_addr *)iph->dst_addr, NULL))
        return IP6_RCV_FINISH_NEXT_LOCAL;
    else
        return IP6_RCV_FINISH_NEXT_DROP; /* not drop */
}

static __rte_always_inline uint16_t 
ip6_rcv_fin(s_nc_param_l3 *param)
{   
    struct rte_mbuf *mbuf = param->mbuf;
    
    struct route6_entry *rt = NULL;
    eth_type_t etype = mbuf->packet_type;
    struct rte_ipv6_hdr *iph = rte_ip6_hdr(mbuf);

    L3_DEBUG_TRACE(L3_INFO, "[v6]%s node recieved mbuf...\n", __func__);
    PrintMbufPkt(mbuf, 0, 0);

    if (rte_ipv6_addr_type(iph->dst_addr) & RTE_IPV6_ADDR_MULTICAST)
        return ip6_mc_local_in(mbuf);

    uint32_t table_id = GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id;
    rt = route6_hlist_input(table_id, mbuf);
    if (!rt) {
        IPv6_INC_STATS(innoroutes);
        goto drop;
    }

    /*
     * @userdata is used for route info in L3.
     * someday, we may use extended mbuf if have more L3 info
     * then route need to be saved into mbuf.
     */
	//mbuf_userdata_set(mbuf, (void *)rt);
    GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route = rt;

    if (rt->rt6_flags & RTF_LOCALIN) {
        return IP6_RCV_FINISH_NEXT_LOCAL; // ip6_local_in(mbuf);
    } else if (rt->rt6_flags & RTF_FORWARD) {
        /* pass multi-/broad-cast to kni */
        if (etype != ETH_PKT_HOST)
            goto drop;
        return  IP6_RCV_FINISH_NEXT_FORWARD; //ip6_forward(mbuf);
    }

    IPv6_INC_STATS(innoroutes);

drop:
    if (rt) {
        graph_route6_put(rt);
		//mbuf_userdata_set(mbuf, NULL);
        GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route = NULL;
    }
    return IP6_RCV_FINISH_NEXT_DROP;
}

static uint16_t
ip6_rcv_finish_node_process(struct rte_graph *graph, 
                                        struct rte_node *node,
		                                void **objs, 
		                                uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs, 
        nb_objs, IP6_RCV_FINISH_NEXT_FORWARD, ip6_rcv_fin);
}

/* Packet Classification Node */
struct rte_node_register ip6_rcv_finish_node = {
	.process = ip6_rcv_finish_node_process,
	.name = NODE_NAME_IP6_RCV_FINISH,

    //.init = ip4_rcv_finish_node_init,
    
	.nb_edges = IP6_RCV_FINISH_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[IP6_RCV_FINISH_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[IP6_RCV_FINISH_NEXT_LOCAL] = NODE_NAME_IP6_LOCAL_IN,
		[IP6_RCV_FINISH_NEXT_FORWARD] = NODE_NAME_IP6_FORWARD,
		[IP6_RCV_FINISH_NEXT_ICMP] = NODE_NAME_ICMP_SEND,
	},
};
RTE_NODE_REGISTER(ip6_rcv_finish_node);

