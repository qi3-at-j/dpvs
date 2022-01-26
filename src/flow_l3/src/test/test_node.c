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

#include "test_node_priv.h"
#include "l3_node_priv.h"
#include "log_priv.h"

#if NODE_TEST_INSERT

#define USE_FRAG_POOL 1
#define NUM_MBUFS 128
#define BURST 32

#if USE_FRAG_POOL
static struct rte_mempool *g_direct_pool, *g_indirect_pool;
#endif

/* internal */
static inline void
pktmbuf_copy_hdr(struct rte_mbuf *mdst, struct rte_mbuf *msrc)
{
    mdst->port = msrc->port;
    mdst->vlan_tci = msrc->vlan_tci;
    mdst->vlan_tci_outer = msrc->vlan_tci_outer;
    mdst->tx_offload = msrc->tx_offload;
    mdst->hash = msrc->hash;
    mdst->packet_type = msrc->packet_type;
    rte_memcpy(&mdst->dynfield1, msrc->dynfield1,
        sizeof(mdst->dynfield1));
    rte_memcpy(rte_mbuf_to_priv(mdst),
        rte_mbuf_to_priv(msrc), msrc->priv_size);

    struct rte_eth_dev *dev = &rte_eth_devices[mdst->port];
    struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod(mdst, struct rte_ipv4_hdr *);
    //if (unlikely(!(dev->data->dev_conf.rxmode.offloads & DEV_RX_OFFLOAD_IPV4_CKSUM))) {
    //if (unlikely(mdst->ol_flags & PKT_TX_IP_CKSUM)) {
        iph->hdr_checksum = 0
        iph->hdr_checksum = rte_ipv4_cksum(iph);
    //}
}

extern int32_t
rte_ipv4_fragment_packet_new(struct rte_mbuf *pkt_in,
	struct rte_mbuf **pkts_out,
	uint16_t nb_pkts_out,
	uint16_t mtu_size,
	struct rte_mempool *pool_direct,
	struct rte_mempool *pool_indirect);

static __rte_always_inline void **
test(struct rte_graph *graph, 
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

    if (unlikely(rte_pktmbuf_adj(mbuf, RTE_ETHER_HDR_LEN) == NULL)) {//this should be done by L2
        L3_DEBUG_TRACE(L3_ERR, "%s:rte_pktmbuf_adj error\n", __FUNCTION__);
        return TEST_NEXT_DROP;
    }
    mbuf->l2_len = 0;
    L3_DEBUG_TRACE(L3_INFO, "%s node recieved mbuf...\n", __func__);
    PrintMbufPkt(mbuf, 0, 1);

    mtu = RTE_ETHER_MIN_MTU;
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

        L3_DEBUG_TRACE(L3_INFO, "frag_nb:%d\n", frag_nb);

        if (likely(frag_nb > 0)) {
            for (i = 0; i < frag_nb; i++) {               
                pktmbuf_copy_hdr(pkts_frag_out[i], mbuf);
                rte_pktmbuf_prepend(pkts_frag_out[i], RTE_ETHER_HDR_LEN);
            }

            struct rte_mbuf *tmp_mbuf = pkts_frag_out[0];
            pkts_frag_out[0] = pkts_frag_out[2];
            pkts_frag_out[2] = tmp_mbuf;
            tmp_mbuf = pkts_frag_out[1];
            pkts_frag_out[1] = pkts_frag_out[2];
            pkts_frag_out[2] = tmp_mbuf;

            rte_node_enqueue(graph, node, next_id, (void **)pkts_frag_out, frag_nb);
        }

        if (unlikely(frag_nb == -ENOTSUP)) {
            //ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu)
            pkts_icmp_out[(*icmp_pos)++] = mbuf;
        } else {
            pkts_drop_out[(*drop_pos)++] = mbuf;
        }
    } else {
        rte_pktmbuf_prepend(mbuf, RTE_ETHER_HDR_LEN);
        (*held)++;
    }

    return from;
}

static uint16_t
test_node_process(struct rte_graph *graph, 
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
    nb_objs = 1;//for test

    next_id = TEST_NEXT_IP_RCV;

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

        from = test(graph, node, mbuf0, next_id, from, &held, pkts_frag_out, 
            sizeof(pkts_frag_out), pkts_drop_out, &drop_pos, pkts_icmp_out, &icmp_pos);
        from = test(graph, node, mbuf1, next_id, from, &held, pkts_frag_out, 
            sizeof(pkts_frag_out), pkts_drop_out, &drop_pos, pkts_icmp_out, &icmp_pos);
        from = test(graph, node, mbuf2, next_id, from, &held, pkts_frag_out, 
            sizeof(pkts_frag_out), pkts_drop_out, &drop_pos, pkts_icmp_out, &icmp_pos);
        from = test(graph, node, mbuf3, next_id, from, &held, pkts_frag_out, 
            sizeof(pkts_frag_out), pkts_drop_out, &drop_pos, pkts_icmp_out, &icmp_pos);
    }

    while (n_left_from > 0) {
		mbuf0 = pkts[0];
		pkts += 1;
		n_left_from -= 1;

        from = test(graph, node, mbuf0, next_id, from, &held, pkts_frag_out, 
            sizeof(pkts_frag_out), pkts_drop_out, &drop_pos, pkts_icmp_out, &icmp_pos);
    }

    if (unlikely(drop_pos)) {
        rte_node_enqueue(graph, node, TEST_NEXT_DROP, (void **)pkts_drop_out, drop_pos);
    } else if (unlikely(icmp_pos)) {       
        rte_node_enqueue(graph, node, TEST_NEXT_ICMP, (void **)pkts_icmp_out, icmp_pos);
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
test_node_init(const struct rte_graph *graph, 
                                struct rte_node *node)
{
    RTE_SET_USED(graph);
    RTE_SET_USED(node);

#if USE_FRAG_POOL
    g_direct_pool = rte_pktmbuf_pool_create("FRAG_D_MBUF_POOL_TEST",
					      NUM_MBUFS, BURST, MBUF_PRIV2_MIN_SIZE,
					      RTE_MBUF_DEFAULT_BUF_SIZE,
					      SOCKET_ID_ANY);
	if (g_direct_pool == NULL) {
        node_err(NODE_NAME_IP4_OUTPUT, 
            "%s: Error creating direct mempool\n", __func__);
		goto fail_create;
	}

	g_indirect_pool = rte_pktmbuf_pool_create("FRAG_I_MBUF_POOL_TEST",
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
#endif

    return 0;
}

/* Packet Classification Node */
struct rte_node_register test_node = {
	.process = test_node_process,
	.name = NODE_NAME_TEST,

    .init = test_node_init,
    
	.nb_edges = TEST_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[TEST_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[TEST_NEXT_IP_RCV] = NODE_NAME_IP4_RCV,
        [TEST_NEXT_ICMP] = NODE_NAME_ICMP_SEND,
	},
};
RTE_NODE_REGISTER(test_node);
#endif
