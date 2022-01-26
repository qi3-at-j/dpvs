
/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2020 Marvell.
 */

#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include "dpdk.h"
#include "ether_input.h"
#include "conf/common.h"
#include "netif.h"
#include "netif_addr.h"
#include "ctrl.h"
#include "list.h"
#include "kni.h"
#include <rte_version.h>
#include "conf/netif.h"
#include "timer.h"
#include "parser/parser.h"
#include "neigh.h"
#include "scheduler.h"
#include "../include/br_node.h"
#include "../include/br_private.h"

/* Next node for each ptype, default is '0' is "pkt_drop" */

static inline uint16_t bridge_deal_and_trans_to_next_index(s_nc_param *param)
{
	//假设缓存已经预取，没有的话，需要在外面预取。
	uint16_t index = BRIDGE_NEXT_PKT_DROP;
	struct rte_mbuf *mbuf = param->mbuf;

	/*eth_hdr0 = rte_pktmbuf_mtod(mbuf0, struct ether_hdr *);
	eth_hdr1 = rte_pktmbuf_mtod(mbuf1, struct ether_hdr *);
	eth_hdr2 = rte_pktmbuf_mtod(mbuf2, struct ether_hdr *);
	eth_hdr3 = rte_pktmbuf_mtod(mbuf3, struct ether_hdr *);
	*/
	if(!mbuf)
		rte_panic("mbuf = 0x0\n");
	
	struct netif_port *dev = netif_port_get(mbuf->port);
	if (unlikely(!dev)) {
        return index;
    }

	index = br_handle_frame(param);

	return index;
}
static uint16_t
bridge_node_process(struct rte_graph *graph, struct rte_node *node,
		     void **objs, uint16_t nb_objs)
{
	struct rte_mbuf **pkts;
	uint16_t n0, n1, n2, n3;
	uint16_t last_index, next_index, n_left_from;
	uint16_t held = 0, last_spec = 0;
	struct bridge_node_ctx *ctx;
	void **to_next, **from;
	uint32_t i;
	s_nc_param param[4];

	pkts = (struct rte_mbuf **)objs;
	from = objs;
	n_left_from = nb_objs;

	for (i = OBJS_PER_CLINE; i < RTE_GRAPH_BURST_SIZE; i += OBJS_PER_CLINE)
		rte_prefetch0(&objs[i]);

#if RTE_GRAPH_BURST_SIZE > 64
	for (i = 0; i < 4 && i < n_left_from; i++)
		rte_prefetch0(pkts[i]);
#endif

	ctx = (struct bridge_node_ctx *)node->ctx;
	last_index = ctx->last_index;
	//printf("last_index = %d\n", last_index);
	next_index = last_index;

	/* Get stream for the speculated next node */
	to_next = rte_node_next_stream_get(graph, node,
					   next_index, nb_objs);
	while (n_left_from >= 4) {
#if RTE_GRAPH_BURST_SIZE > 64
		if (likely(n_left_from > 7)) {
			rte_prefetch0(pkts[4]);
			rte_prefetch0(pkts[5]);
			rte_prefetch0(pkts[6]);
			rte_prefetch0(pkts[7]);
		}
#endif

		param[0].mbuf = pkts[0];
        param[0].mbuf2 = &pkts[0];

        param[1].mbuf = pkts[1];
        param[1].mbuf2 = &pkts[1];

        param[2].mbuf = pkts[2];
        param[2].mbuf2 = &pkts[2];

        param[3].mbuf = pkts[3];
        param[3].mbuf2 = &pkts[3];

        param[0].node = node;
        param[1].node = node;
        param[2].node = node;
        param[3].node = node;

        param[0].graph = graph;
        param[1].graph = graph;
        param[2].graph = graph;
        param[3].graph = graph;
		
		pkts += 4;
		n_left_from -= 4;

		/* Check if they are destined to same
		 * next node based on l2l3 packet type.
		 */
		
	 	n0 = bridge_deal_and_trans_to_next_index(&param[0]);
		n1 = bridge_deal_and_trans_to_next_index(&param[1]);
		n2 = bridge_deal_and_trans_to_next_index(&param[2]);
		n3 = bridge_deal_and_trans_to_next_index(&param[3]);
		//printf("n0 = %d, n1 = %d, n2 = %d, n3 = %d\n", n0, n1, n2, n3);
		uint32_t fix_spec = (n0 ^ last_index) | (n1 ^ last_index) |
			(n2 ^ last_index) | (n3 ^ last_index);

		if (unlikely(fix_spec)) {
			/* Copy things successfully speculated till now */
			rte_memcpy(to_next, from,
				   last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;

			/* l0 */
			if (n0 == next_index) {
				to_next[0] = from[0];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node,
						    n0, from[0]);
			}

			/* l1 */
			if (n1 == next_index) {
				to_next[0] = from[1];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node,
						    n1, from[1]);
			}

			/* l2 */
			if (n2 == next_index) {
				to_next[0] = from[2];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node,
						    n2, from[2]);
			}

			/* l3 */
			if (n3 == next_index) {
				to_next[0] = from[3];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node,
						    n3, from[3]);
			}

			/* Update speculated ptype */
			if ((last_index != n3) && (n2 == n3) &&
			    (next_index != n3)) {
				/* Put the current stream for
				 * speculated ltype.
				 */
				rte_node_next_stream_put(graph, node,
							 next_index, held);

				held = 0;

				/* Get next stream for new ltype */
				next_index = n3;
				last_index = n3;
				to_next = rte_node_next_stream_get(graph, node,
								   next_index,
								   nb_objs);
			} else if (next_index == n3) {
				last_index = n3;
			}

			from += 4;
		} else {
			last_spec += 4;
		}
	}

	while (n_left_from > 0) {
		param[0].mbuf = pkts[0];
		param[0].mbuf2 = &pkts[0];
		param[0].node = node;
		param[0].graph = graph;

		pkts += 1;
		n_left_from -= 1;
		
		n0 = bridge_deal_and_trans_to_next_index(&param[0]);
		//printf("n0 = %d\n", n0);
		if (unlikely((n0 != last_index) && (n0 != next_index))) {
			/* Copy things successfully speculated till now */
			rte_memcpy(to_next, from,
				   last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;

			rte_node_enqueue_x1(graph, node,
					    n0, from[0]);
			from += 1;
		} else {
			last_spec += 1;
		}
	}

	/* !!! Home run !!! */
	if (likely(last_spec == nb_objs)) {
		rte_node_next_stream_move(graph, node, next_index);
		return nb_objs;
	}

	held += last_spec;
	/* Copy things successfully speculated till now */
	rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
	rte_node_next_stream_put(graph, node, next_index, held);

	ctx->last_index = last_index;
	return nb_objs;
}

/* Packet Classification Node */
struct rte_node_register bridge_node = {
	.process = bridge_node_process,
	.name = "bridge",

	.nb_edges = BRIDGE_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[BRIDGE_NEXT_PKT_DROP] = "pkt_drop",
		//[ETHER_INPUT_NEXT_L2_BOND] = "bond",
		[BRIDGE_NEXT_L2_XMIT] = "L2_xmit",
		[BRIDGE_NEXT_L3_TEMP] = "L3_temp",
	},
};
RTE_NODE_REGISTER(bridge_node);


