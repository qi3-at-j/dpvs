/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021 chc.
 */

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#include "ip4_forward_priv.h"
#include "l3_node_priv.h"
#include "log_priv.h"
#include "switch_cli_priv.h"
#include "flow.h"

extern pthread_mutex_t ip_reassemble_mutex;

#define this_lcore_frag_tbl        (RTE_PER_LCORE(frag_tbl))
#define this_lcore_death_row        (RTE_PER_LCORE(death_row))
extern RTE_DEFINE_PER_LCORE(struct rte_ip_frag_tbl *, frag_tbl);
extern RTE_DEFINE_PER_LCORE(struct rte_ip_frag_death_row, death_row);

static __rte_always_inline uint16_t 
ip4_forward(s_nc_param_l3 *param)
{
    uint16_t next_node = IP4_FORWARD_NEXT_DROP;
    struct rte_mbuf *mbuf = param->mbuf;
    struct rte_mbuf **mbuf2 = param->mbuf2;
    struct rte_node *node = param->node;
    struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
    uint32_t chksum;
    uint32_t lcore_id = rte_lcore_id();
    struct rte_graph *graph = param->graph;

    L3_DEBUG_TRACE(L3_INFO, "%s node recieved mbuf...\n", __func__);
    PrintMbufPkt(mbuf, 0, 0);

    if (unlikely(!get_switch_fwd())) {
        L3_DEBUG_TRACE(L3_INFO, "%s node:forward switch is off,dont forward!drop!\n", __func__);
        return next_node;
    }

    /*  check here or before...
    if (broadcast or multicast) {
        return next_node;
    }
    */

    if (iph->time_to_live <= 1) {
        //icmp_send(mbuf, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
        //IP4_INC_STATS(inhdrerrors);
        return IP4_FORWARD_NEXT_ICMP;
    }

    /* ip options to do... */

    if(unlikely(rte_ipv4_frag_pkt_is_fragmented(iph))) {
        L3_DEBUG_TRACE(L3_INFO, "%s node:is frag\n", __func__);

        uint64_t cur_tsc = rte_rdtsc();

#ifndef IP_REASSEMBLE_USE_PER_LCORE_TBL
        pthread_mutex_lock(&ip_reassemble_mutex);
#endif
        struct rte_mbuf *mo = rte_ipv4_frag_reassemble_packet(
            this_lcore_frag_tbl, &this_lcore_death_row,
            mbuf, cur_tsc, iph);
#ifndef IP_REASSEMBLE_USE_PER_LCORE_TBL
        pthread_mutex_unlock(&ip_reassemble_mutex);
#endif

        if (this_lcore_death_row.cnt) {
            rte_node_enqueue(graph, node, IP4_FORWARD_NEXT_DROP,
                (void **)this_lcore_death_row.row, this_lcore_death_row.cnt);
            this_lcore_death_row.cnt = 0;
        }

        *mbuf2 = mo;
        /* defrag not complete or err */
        if (mo == NULL) {
            /* rte_pktmbuf_free_bulk can deal NULL */
            return next_node;
        }

        mbuf = *mbuf2;
        /* update offloading flags */
        mbuf->ol_flags |= (PKT_TX_IPV4 | PKT_TX_IP_CKSUM);
    }

    int rc;
    rc = flow_processing_paks(mbuf);
    if (rc == FLOW_RET_OK) {
        next_node = IP4_FORWARD_NEXT_FINISH;           
        /* flow reply ping may change the route */
        if (GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route !=
            (csp2peer(GET_CSP_FROM_MBUF(mbuf)))->route) {
            route4_put(GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route);
            GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route = (csp2peer(GET_CSP_FROM_MBUF(mbuf)))->route;
            route4_get(GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route);
        }
    } else if (rc >= FLOW_RET_FWD_BAR && rc <= FLOW_RET_FWD_BAR2) {
        *mbuf2 = NULL;
        return next_node;
    } else {
        L3_DEBUG_TRACE(L3_ERR, "%s node:flow check err,drop!!!\n", __func__);
        return next_node;
    }

    /* Update ttl and chksum*/
    chksum = iph->hdr_checksum + rte_cpu_to_be_16(0x0100);
    chksum += chksum >= 0xffff;
    iph->hdr_checksum = chksum;
    iph->time_to_live--;

    if (unlikely(get_switch_nf())) {
        return IP4_FORWARD_NEXT_FW;
    }

    return next_node;
}

static uint16_t
ip4_forward_node_process(struct rte_graph *graph, 
            struct rte_node *node, void **objs, uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs, 
        nb_objs, IP4_FORWARD_NEXT_FINISH, ip4_forward);
}

/* Packet Classification Node */
struct rte_node_register ip4_forward_node = {
	.process = ip4_forward_node_process,
	.name = NODE_NAME_IP4_FORWARD,

	.nb_edges = IP4_FORWARD_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[IP4_FORWARD_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[IP4_FORWARD_NEXT_ICMP] = NODE_NAME_ICMP_SEND,
		[IP4_FORWARD_NEXT_FW] = NODE_NAME_NF_IP_FORWARD,
		[IP4_FORWARD_NEXT_FINISH] = NODE_NAME_IP4_FORWARD_FINISH,
	},
};
RTE_NODE_REGISTER(ip4_forward_node);
