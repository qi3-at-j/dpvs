/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021 chc.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <netinet/ip6.h>

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_net.h>
#include <rte_mbuf.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#include "ip6_output_finish_priv.h"
#include "ip6_graph.h"
#include "route6_priv.h"
#include "l3_node_priv.h"
#include "vrf_priv.h"
#include "common_priv.h"
#include "log_priv.h"
#include "ip6_debug.h"


#include "conf/common.h"
#include "mbuf.h"
#include "inet.h"
#include "parser/parser.h"
#include "neigh_priv.h"
#include "icmp6.h"
#include "iftraf.h"

static inline struct in6_addr *rte_ip6_rt_nexthop(struct route6_entry *rt,
                                              struct in6_addr *daddr)
{
    if (ipv6_addr_any(&rt->rt6_gateway))
        return daddr;
    else
        return &rt->rt6_gateway;
}

static __rte_always_inline 
uint16_t ip6_fragment(struct rte_mbuf *mbuf, uint32_t mtu,
                        int (*out)(struct rte_mbuf *))
{
    struct route6 *rt = mbuf_userdata_get(mbuf);

    /* TODO: */

    IPv6_INC_STATS(fragfails);
    route6_put(rt);
    return IP6_OUTPUT_FINISH_NEXT_DROP;
}

static __rte_always_inline 
uint16_t ip6_output_fin2(s_nc_param_l3 *param)
{
    struct rte_ipv6_hdr *hdr;
    struct route6_entry *rt = NULL;
    struct in6_addr *nexthop;
    struct netif_port *dev;
    struct rte_mbuf **nd_req = NULL;
    struct rte_mbuf *mbuf;
    struct rte_mbuf **mbuf2;
    uint16_t ret = IP6_OUTPUT_FINISH_NEXT_DROP;
    rte_edge_t next;

    mbuf = param->mbuf;
    mbuf2 = param->mbuf2;
    hdr = rte_ip6_hdr(mbuf);
    uint32_t table_id = GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id;
    if (rte_ipv6_addr_is_multicast(hdr->dst_addr)) {
        IPv6_UPD_PO_STATS(outmcast, mbuf->pkt_len);

        if (RTE_IPV6_ADDR_MC_SCOPE(hdr->dst_addr) <= IPV6_ADDR_SCOPE_NODELOCAL) {
            IPv6_INC_STATS(outdiscards);
            return IP6_OUTPUT_FINISH_NEXT_DROP;
        }

        dev = mbuf_dev_get(mbuf);
        /* only support linklocal! */
        nexthop = hdr->dst_addr;

    } else {
        rt = (struct route6_entry *)GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route;
        dev = rt->rt6_dev;
        nexthop = rte_ip6_rt_nexthop(rt, hdr->dst_addr);
    }

    char dst_addr[64] = {0};
    inet_ntop(AF_INET6, nexthop,
        dst_addr, sizeof(dst_addr));
    L3_DEBUG_TRACE(L3_INFO, "%s node:nexthop is %s\n",
        __func__, dst_addr);

    mbuf->packet_type = RTE_ETHER_TYPE_IPV6;

    next = GET_MBUF_PRIV_DATA(mbuf)->priv_data_is_vxlan?
           IP6_OUTPUT_FINISH_NEXT_VXLAN_SEND:
           IP6_OUTPUT_FINISH_NEXT_L2;
    ret = neigh_output_graph(table_id, AF_INET6, 
                             (union inet_addr *)nexthop, 
                             mbuf, dev, &nd_req,
                             param->graph, param->node, next);
    if (nd_req) {
        L3_DEBUG_TRACE(L3_INFO, "%s node send nd request\n", __func__);
        pktmbuf_copy_hdr(nd_req, mbuf);
        rte_node_enqueue_x1(param->graph, param->node, next, nd_req);
    }
    if (ret != NEIGH_OUT_RS_OK) {
        if (ret == NEIGH_OUT_RS_HANG) {
            *mbuf2 = NULL;
        }
        return IP6_OUTPUT_FINISH_NEXT_DROP;
    }
    
    if (rt)
        graph_route6_put(rt);

    L3_DEBUG_TRACE(L3_INFO, "%s node send mbuf\n", __func__);

    return next;
}

static __rte_always_inline uint16_t
ip6_output_fin(s_nc_param_l3 *param)
{
    uint16_t mtu;
    uint16_t ret = IP6_OUTPUT_FINISH_NEXT_DROP;
    struct rte_mbuf *mbuf = param->mbuf;
    struct rte_ipv6_hdr *hdr = rte_ip6_hdr(mbuf);
    struct route6_entry *rt = NULL;
    
    if (ipv6_addr_is_multicast(hdr->dst_addr)){
        mtu = ((struct netif_port *)mbuf_dev_get(mbuf))->mtu;
    }else{
        //mtu = ((struct route6 *)mbuf_userdata_get(mbuf))->rt6_mtu;
        rt = (struct route6_entry *)GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route;
        mtu = rt->rt6_dev->mtu;
    }
    if (mbuf->pkt_len > mtu)
        return ip6_fragment(mbuf, mtu, ip6_output_fin2);
    else
        return ip6_output_fin2(param);
}

static uint16_t
ip6_output_finish_node_process(struct rte_graph *graph, 
                              struct rte_node *node,
                              void **objs, 
                              uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs, 
        nb_objs, IP6_OUTPUT_FINISH_NEXT_DROP, ip6_output_fin);
}


struct rte_node_register ip6_output_finish_node = {
	.process = ip6_output_finish_node_process,
	.name = NODE_NAME_IP6_OUTPUT_FINISH,

    //.init = ip6_output_finish_node_init,
    
	.nb_edges = IP6_OUTPUT_FINISH_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[IP6_OUTPUT_FINISH_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[IP6_OUTPUT_FINISH_NEXT_VXLAN_SEND] = NODE_NAME_VXLAN_SEND,
		[IP6_OUTPUT_FINISH_NEXT_L2] = NODE_NAME_L2_OUT,
	},
};
RTE_NODE_REGISTER(ip6_output_finish_node);

