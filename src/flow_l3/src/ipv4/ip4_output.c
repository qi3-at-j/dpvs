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

#include "ip4_output_priv.h"
#include "l3_node_priv.h"
#include "route_priv.h"
#include "switch_cli_priv.h"
#include "common_priv.h"

#define USE_FRAG_POOL 1
#define NUM_MBUFS 128
#define BURST 32

#if USE_FRAG_POOL
static struct rte_mempool *g_direct_pool, *g_indirect_pool;
#endif

extern int32_t
rte_ipv4_fragment_packet_new(struct rte_mbuf *pkt_in,
	struct rte_mbuf **pkts_out,
	uint16_t nb_pkts_out,
	uint16_t mtu_size,
	struct rte_mempool *pool_direct,
	struct rte_mempool *pool_indirect);

static __rte_always_inline void **
ip4_output(struct rte_graph *graph, 
               struct rte_node *node, 
               struct rte_mbuf *mbuf, 
               uint16_t next_id,
               void **from,
               uint16_t *held,
               struct rte_mbuf **pkts_frag_out,
               uint16_t nb_pkts_out,
               struct rte_mbuf **pkts_drop_out,
               uint16_t *drop_pos,
               struct rte_mbuf **pkts_icmp_out,
               uint16_t *icmp_pos)
{
    int i;
    int32_t frag_nb;
    uint64_t mtu = 1500; //RTE_ETHER_MIN_MTU

    struct netif_port *port = (struct netif_port*)mbuf_dev_get(mbuf);
    if ((port) && (port->mtu)) {
        mtu = port->mtu;
    }

    L3_DEBUG_TRACE(L3_INFO, "%s node recieved mbuf...\n", __func__);
    PrintMbufPkt(mbuf, 0, 0);
    L3_DEBUG_TRACE(L3_INFO, "%s node:mtu is %u\n", __func__, mtu);

    struct route_entry *route_node =
        (struct route_entry *)GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route;

    if (mbuf->pkt_len > mtu) {
        if (*held) {
            rte_node_enqueue(graph, node, next_id, from, *held);
        }
        (*held)++;
        from = from + *held;
        *held = 0;

#if USE_FRAG_POOL
        frag_nb = rte_ipv4_fragment_packet_new(mbuf, pkts_frag_out,
                                           nb_pkts_out,
                                           mtu,
                                           g_direct_pool,
                                           g_indirect_pool);
#else
        frag_nb = rte_ipv4_fragment_packet_new(mbuf, pkts_frag_out,
                                           nb_pkts_out,
                                           mtu,
                                           mbuf->pool,
                                           mbuf->pool);
#endif

        L3_DEBUG_TRACE(L3_INFO, "%s node:frag_nb:%d\n", __func__, frag_nb);

        if (likely(frag_nb > 0)) {
            for (i = 0; i < frag_nb; i++) {
                pktmbuf_copy_hdr(pkts_frag_out[i], mbuf);
                struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod(pkts_frag_out[i],
                    struct rte_ipv4_hdr *);
                if (unlikely(!(pkts_frag_out[i]->ol_flags & PKT_TX_IP_CKSUM))) {
                    iph->hdr_checksum = 0;
                    iph->hdr_checksum = rte_ipv4_cksum(iph);
                }
                route4_get(route_node);
            }
            route4_put(route_node);
            rte_node_enqueue(graph, node, next_id, (void **)pkts_frag_out, frag_nb);
        }

        if (unlikely(frag_nb == -ENOTSUP)) {
            L3_DEBUG_TRACE(L3_ERR, "%s node:need fragment,but DF is set\n", __func__);
            //ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu)
            pkts_icmp_out[(*icmp_pos)++] = mbuf;
        } else {
            pkts_drop_out[(*drop_pos)++] = mbuf;
        }
    } else {
        (*held)++;
    }

    return from;
}

static uint16_t
ip4_output_node_process(struct rte_graph *graph, 
            struct rte_node *node, void **objs, uint16_t nb_objs)
{
    struct rte_mbuf *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
    struct rte_mbuf *pkts_frag_out[FRAG_NUM_MAX];
    struct rte_mbuf *pkts_drop_out[nb_objs];
    struct rte_mbuf *pkts_icmp_out[nb_objs];
    void **from;
    uint16_t drop_pos = 0;
    uint16_t icmp_pos = 0;
    uint16_t held = 0;
    uint16_t n_left_from, next_id;
    uint32_t i;

    if (unlikely(get_switch_nf())) {
        next_id = IP4_OUTPUT_NEXT_FW;
    } else {
        next_id = IP4_OUTPUT_NEXT_FINISH;
    }

    pkts = (struct rte_mbuf **)objs;
	from = objs;
    n_left_from = nb_objs;
    
    for (i = OBJS_PER_CLINE; i < RTE_GRAPH_BURST_SIZE; i += OBJS_PER_CLINE)
		rte_prefetch0(&objs[i]);

#if RTE_GRAPH_BURST_SIZE > 64
	for (i = 0; i < 4 && i < n_left_from; i++)
		rte_prefetch0(pkts[i]);
#endif

    while (n_left_from >= 4) {
#if RTE_GRAPH_BURST_SIZE > 64
		if (likely(n_left_from > 7)) {
			rte_prefetch0(pkts[4]);
			rte_prefetch0(pkts[5]);
			rte_prefetch0(pkts[6]);
			rte_prefetch0(pkts[7]);
		}
#endif

		mbuf0 = pkts[0];
		mbuf1 = pkts[1];
		mbuf2 = pkts[2];
		mbuf3 = pkts[3];
        pkts += 4;
        n_left_from -= 4;

        from = ip4_output(graph, node, mbuf0, next_id, from, &held, pkts_frag_out, 
            sizeof(pkts_frag_out), pkts_drop_out, &drop_pos, pkts_icmp_out, &icmp_pos);
        from = ip4_output(graph, node, mbuf1, next_id, from, &held, pkts_frag_out, 
            sizeof(pkts_frag_out), pkts_drop_out, &drop_pos, pkts_icmp_out, &icmp_pos);
        from = ip4_output(graph, node, mbuf2, next_id, from, &held, pkts_frag_out, 
            sizeof(pkts_frag_out), pkts_drop_out, &drop_pos, pkts_icmp_out, &icmp_pos);
        from = ip4_output(graph, node, mbuf3, next_id, from, &held, pkts_frag_out, 
            sizeof(pkts_frag_out), pkts_drop_out, &drop_pos, pkts_icmp_out, &icmp_pos);
    }

    while (n_left_from > 0) {
		mbuf0 = pkts[0];
		pkts += 1;
		n_left_from -= 1;

        from = ip4_output(graph, node, mbuf0, next_id, from, &held, pkts_frag_out, 
            sizeof(pkts_frag_out), pkts_drop_out, &drop_pos, pkts_icmp_out, &icmp_pos);
    }

    if (unlikely(drop_pos)) {
        rte_node_enqueue(graph, node, IP4_OUTPUT_NEXT_DROP, (void **)pkts_drop_out, drop_pos);
    } else if (unlikely(icmp_pos)) {       
        rte_node_enqueue(graph, node, IP4_OUTPUT_NEXT_ICMP, (void **)pkts_icmp_out, icmp_pos);
    } else {
        rte_node_next_stream_move(graph, node, next_id);
        return nb_objs;
    }

    if (held) {
        rte_node_enqueue(graph, node, next_id, from, held);
    }

    return nb_objs;
}

static int
ip4_output_node_init(const struct rte_graph *graph, 
                                struct rte_node *node)
{
    RTE_SET_USED(graph);
    RTE_SET_USED(node);

#if USE_FRAG_POOL
    static uint8_t init_once = 0;

    if (!init_once) {
        init_once = 1;

        g_direct_pool = rte_pktmbuf_pool_create("FRAG_D_MBUF_POOL",
    					      NUM_MBUFS, BURST, MBUF_PRIV2_MIN_SIZE,
    					      RTE_MBUF_DEFAULT_BUF_SIZE,
    					      SOCKET_ID_ANY);
    	if (g_direct_pool == NULL) {
            node_err(NODE_NAME_IP4_OUTPUT, 
                "%s: Error creating direct mempool\n", __func__);
    		goto fail_create;
    	}

    	g_indirect_pool = rte_pktmbuf_pool_create("FRAG_I_MBUF_POOL",
    						NUM_MBUFS, BURST, 0,
    						0, SOCKET_ID_ANY);
    	if (g_indirect_pool == NULL) {
    		node_err(NODE_NAME_IP4_OUTPUT, 
                "%s: Error creating indirect mempool\n", __func__);
    		goto fail_create;
    	}

        return 0;

    fail_create:
    	rte_mempool_free(g_direct_pool);
    	g_direct_pool = NULL;
        
        return -rte_errno;
    }
#endif

    return 0;
}

/* Packet Classification Node */
struct rte_node_register ip4_output_node = {
	.process = ip4_output_node_process,
	.name = NODE_NAME_IP4_OUTPUT,

    .init = ip4_output_node_init,
    
	.nb_edges = IP4_OUTPUT_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[IP4_OUTPUT_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[IP4_OUTPUT_NEXT_FW] = NODE_NAME_NF_IP_POST_ROUTING,
		[IP4_OUTPUT_NEXT_ICMP] = NODE_NAME_ICMP_SEND,		
		[IP4_OUTPUT_NEXT_FINISH] = NODE_NAME_IP4_OUTPUT_FINISH,
	},
};
RTE_NODE_REGISTER(ip4_output_node);
