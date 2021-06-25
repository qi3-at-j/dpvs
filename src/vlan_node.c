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
#include "conf/common.h"
#include "netif.h"
#include "netif_addr.h"
#include "vlan.h"
#include "vlan_node.h"
#include "ctrl.h"
#include "list.h"
#include "kni.h"
#include <rte_version.h>
#include "conf/netif.h"


static inline enum vlan_node_next_nodes vlan_deal_and_trans_to_next_index(struct rte_mbuf *mbuf)
{
	enum vlan_node_next_nodes index = VLAN_NODE_NEXT_PKT_DROP;
	int err = EDPVS_OK;
	err = vlan_rcv(mbuf, netif_port_get(mbuf->port));
	if(err != EDPVS_OK){
		index = VLAN_NODE_NEXT_PKT_DROP;
	}else{
		index = VLAN_NODE_NEXT_L2_ETHER_OUTPUT;
	}
		
	return index;
}

static uint16_t
vlan_node_process(struct rte_graph *graph, struct rte_node *node,
		     void **objs, uint16_t nb_objs)
{
	struct rte_mbuf *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
	enum vlan_node_next_nodes n0, n1, n2, n3;
	enum vlan_node_next_nodes last_index, next_index, n_left_from;
	uint16_t held = 0, last_spec = 0;
	struct vlan_node_ctx *ctx;
	void **to_next, **from;
	uint32_t i;

	pkts = (struct rte_mbuf **)objs;
	from = objs;
	n_left_from = nb_objs;

	for (i = OBJS_PER_CLINE; i < RTE_GRAPH_BURST_SIZE; i += OBJS_PER_CLINE)
		rte_prefetch0(&objs[i]);

#if RTE_GRAPH_BURST_SIZE > 64
	for (i = 0; i < 4 && i < n_left_from; i++)
		rte_prefetch0(pkts[i]);
#endif

	ctx = (struct vlan_node_ctx *)node->ctx;
	last_index = ctx->last_index;
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

		mbuf0 = pkts[0];
		mbuf1 = pkts[1];
		mbuf2 = pkts[2];
		mbuf3 = pkts[3];
		pkts += 4;
		n_left_from -= 4;

		/* Check if they are destined to same
		 * next node based on l2l3 packet type.
		 */
	 	n0 = vlan_deal_and_trans_to_next_index(mbuf0);
		n1 = vlan_deal_and_trans_to_next_index(mbuf1);
		n2 = vlan_deal_and_trans_to_next_index(mbuf2);
		n3 = vlan_deal_and_trans_to_next_index(mbuf3);
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
		mbuf0 = pkts[0];

		pkts += 1;
		n_left_from -= 1;
		
		n0 = vlan_deal_and_trans_to_next_index(mbuf0);
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
struct rte_node_register vlan_node = {
	.process = vlan_node_process,
	.name = "vlan",

	.nb_edges = VLAN_NODE_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[VLAN_NODE_NEXT_PKT_DROP] = "pkt_drop",
		[VLAN_NODE_NEXT_L2_ETHER_OUTPUT] = "ether_output",
	},
};
RTE_NODE_REGISTER(vlan_node);


