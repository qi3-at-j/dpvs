/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021 chc.
 */

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#include "ipv6.h"
#include "route6.h"
#include "ip6_local_in_finish_priv.h"
#include "ip6_debug.h"
#include "l3_node_priv.h"
#include "common_priv.h"
#include "route_priv.h"

static int ip6_dummy_hdr_rcv(struct rte_mbuf *mbuf)
{
    struct ip6_hdr *hdr = mbuf_userdata_get(mbuf);
    struct ip6_ext *exthdr;

    if (mbuf_may_pull(mbuf, 8) != 0)
        goto drop;

    exthdr = rte_pktmbuf_mtod(mbuf, struct ip6_ext *);

    if (mbuf_may_pull(mbuf, 8 + (exthdr->ip6e_len<<3)) != 0)
        goto drop;

    if (ipv6_addr_is_multicast(&hdr->ip6_dst) ||
        mbuf->packet_type != ETH_PKT_HOST)
        goto drop;

    /* handle nothing */

    /* set current ext-header length and return next header.
     * note l3_len record current header length only. */
    mbuf->l3_len = 8 + (exthdr->ip6e_len<<3);
    return exthdr->ip6e_nxt;

drop:
    return -1;
}

static int ip6_rthdr_rcv(struct rte_mbuf *mbuf)
{
    /* TODO: handle route header */
    return ip6_dummy_hdr_rcv(mbuf);
}

static int ip6_destopt_rcv(struct rte_mbuf *mbuf)
{
    /* TODO: handle dest option header */
    return ip6_dummy_hdr_rcv(mbuf);
}

static int ip6_nodata_rcv(struct rte_mbuf *mbuf)
{
    /* no payload ? just consume it. */
    rte_pktmbuf_free(mbuf);
    return 0;
}

__thread const struct inet6_protocol per_lcore_inet6_protos_lcore[MAX_INET6_PROTOS] = {
    [IPPROTO_ICMPV6] = {
        .handler = NULL,
        .flags   = INET6_PROTO_F_FINAL,
    },
    [IPPROTO_UDP]   = {
        .handler = NULL,
        .flags   = INET6_PROTO_F_FINAL,
    },
    [IPPROTO_ROUTING] = {
        .handler = ip6_rthdr_rcv,
    },
    [IPPROTO_DSTOPTS] = {
        .handler = ip6_destopt_rcv,
    },
    [IPPROTO_NONE] = {
        .handler = ip6_nodata_rcv,
    }
};
#define this_lcore_inet6_protos (RTE_PER_LCORE(inet6_protos_lcore))


static __rte_always_inline uint16_t
ip6_local_in_fin(s_nc_param_l3 *param)
{
    struct rte_mbuf *mbuf = param->mbuf;
    uint8_t nexthdr;
    int (*handler)(struct rte_mbuf *mbuf) = NULL;
    bool is_final, have_final = false;
    const struct inet6_protocol *prot;
    struct ip6_hdr *hdr = ip6_hdr(mbuf);
    int ret = EDPVS_INVAL;

    /*
     * release route info saved in @userdata
     * and set it to IPv6 fixed header for upper layer.
     */
    if (!ipv6_addr_is_multicast(&hdr->ip6_dst)) {
        struct route6 *rt = mbuf_userdata_get(mbuf);
        if (rt) {
            route6_put(rt);
            mbuf_userdata_set(mbuf, (void *)hdr);
        }
    }

    mbuf_userdata_set(mbuf, (void *)hdr);
    nexthdr = hdr->ip6_nxt;

    /* parse extension headers */
resubmit:
    /*
     * l3_len is not the transport header length.
     * we just borrow it to save info for each step when processing
     * fixed header and extension header.
     *
     * l3_len is initially the fix header size (ipv6_rcv),
     * and being set to ext-header size by each non-final protocol.
     */
    if (rte_pktmbuf_adj(mbuf, mbuf->l3_len) == NULL)
        goto discard;

resubmit_final:

    prot = &this_lcore_inet6_protos[nexthdr];
    if (unlikely(!prot)) {
        /* no proto, kni may like it.*/
        IPv6_INC_STATS(inunknownprotos);
        goto kni;
    }

    is_final = (prot->flags & INET6_PROTO_F_FINAL);

    if (have_final) {
        /* final proto don't allow encap non-final */
        if (!is_final) {
            goto discard;
        }
    } else if (is_final) {
        have_final = true;

        /* check mcast, if failed, kni may like it. */
        if (ipv6_addr_is_multicast(&hdr->ip6_dst) &&
            !inet_chk_mcast_addr(AF_INET6, netif_port_get(mbuf->port),
                                 (union inet_addr *)&hdr->ip6_dst,
                                 (union inet_addr *)&hdr->ip6_src)) {
            goto kni;
        }

        if (nexthdr == IPPROTO_ICMPV6)
            return IP6_LOCAL_IN_FINISH_NEXT_ICMP6;
        else if(nexthdr == IPPROTO_UDP)
            return IP6_LOCAL_IN_FINISH_NEXT_UDP;
    }

    handler = prot->handler;
    if (!handler) {
        rte_pktmbuf_prepend(mbuf, mbuf->l3_len);
        return IP6_LOCAL_IN_FINISH_NEXT_FORWARD;
    }
    ret = handler(mbuf);

    /*
     * 1. if return > 0, it's always "nexthdr",
     *    no matter if proto is final or not.
     * 2. if return == 0, the pkt is consumed.
     * 3. should not return < 0, or it'll be ignored.
     * 4. mbuf->l3_len must be adjusted by handler.
     */
    if (ret > 0) {
        nexthdr = ret;

        if (is_final)
            goto resubmit_final;
        else
            goto resubmit;
    } else {
        IPv6_INC_STATS(indelivers);
    }

    //return ret;

kni:
    //return EDPVS_KNICONTINUE;

discard:
    IPv6_INC_STATS(indiscards);
    return IP6_LOCAL_IN_FINISH_NEXT_DROP;
}

static uint16_t
ip6_local_in_finish_node_process(struct rte_graph *graph, 
                              struct rte_node *node,
                              void **objs, 
                              uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs, 
        nb_objs, IP6_LOCAL_IN_FINISH_NEXT_DROP, ip6_local_in_fin);
}

struct rte_node_register ip6_local_in_finish_node = {
	.process = ip6_local_in_finish_node_process,
	.name = NODE_NAME_IP6_LOCAL_IN_FINISH,
	.nb_edges = IP6_LOCAL_IN_FINISH_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[IP6_LOCAL_IN_FINISH_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[IP6_LOCAL_IN_FINISH_NEXT_UDP] = NODE_NAME_VXLAN_RCV,
		[IP6_LOCAL_IN_FINISH_NEXT_ICMP6] = NODE_NAME_ICMP6,
        [IP6_LOCAL_IN_FINISH_NEXT_FORWARD] = NODE_NAME_IP6_FORWARD,
    },
};
RTE_NODE_REGISTER(ip6_local_in_finish_node);

