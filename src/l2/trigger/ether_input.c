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
#include "vlan.h"
#include "ctrl.h"
#include "list.h"
#include "kni.h"
#include <rte_version.h>
#include "conf/netif.h"
#include "timer.h"
#include "parser/parser.h"
#include "neigh.h"
#include "scheduler.h"

#include <rte_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ipvs/redirect.h>
#include "../include/l2_debug.h"

/* Next node for each ptype, default is '0' is "pkt_drop" */
char const* ether_input_next_node_str[] = {
	[ETHER_INPUT_NEXT_PKT_DROP] = "drop",
	[ETHER_INPUT_NEXT_L2_VLAN]  = "vlan",
	[ETHER_INPUT_NEXT_L2_BRIDGE] = "bridge",
	[ETHER_INPUT_NEXT_L3_IPV4] =  "ip4_rcv",
	[ETHER_INPUT_NEXT_L3_IPV6] =  "ip6_rcv",
	[ETHER_INPUT_NEXT_ARP] = "arp",
};

char const *get_index_prinf(int index){
    char const *p = NULL;
    if ((index == ETHER_INPUT_NEXT_PKT_DROP )||
        (index == ETHER_INPUT_NEXT_L2_VLAN ) ||
        (index == ETHER_INPUT_NEXT_L2_BRIDGE ) ||
        (index == ETHER_INPUT_NEXT_L3_IPV4 ) ||
        (index == ETHER_INPUT_NEXT_L3_IPV6 ) ||
        (index == ETHER_INPUT_NEXT_ARP ))
        {
            p = ether_input_next_node_str[index];
        }else{
            p = "unknow now.";
        }

    return p;
}
static inline enum ether_input_next_nodes ether_input_deal_and_trans_to_next_index(struct rte_mbuf *mbuf)
{
	enum ether_input_next_nodes index = ETHER_INPUT_NEXT_PKT_DROP;
	struct rte_ether_hdr *eth_hdr;
    uint16_t ether_type;

    /* recv from nic,not vxlan node */
    if (mbuf->packet_type != -1) {
        memset(rte_mbuf_to_priv(mbuf), 0, mbuf->priv_size);
    }

	/*eth_hdr0 = rte_pktmbuf_mtod(mbuf0, struct ether_hdr *);
	eth_hdr1 = rte_pktmbuf_mtod(mbuf1, struct ether_hdr *);
	eth_hdr2 = rte_pktmbuf_mtod(mbuf2, struct ether_hdr *);
	eth_hdr3 = rte_pktmbuf_mtod(mbuf3, struct ether_hdr *);
	*/
	struct netif_port *dev = netif_port_get(mbuf->port);
	if (unlikely(!dev)) {
		debug_l2_packet_trace(L2_DEBUG_ETH_INPUT, mbuf, DETAIL_ON, "[ether_input] can't get dev by port=%u, drop!\n", mbuf->port);
        return index;
    }
	eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	mbuf->packet_type = eth_type_parse(eth_hdr, dev);
	mbuf->l2_len = sizeof(struct rte_ether_hdr);

    ether_type = ntohs(eth_hdr->ether_type);
    index = l2_meter_proc(mbuf, ether_type);
    if(ETHER_INPUT_NEXT_PKT_DROP == index){
        return index;
    }
    
	switch(ether_type){
		case RTE_ETHER_TYPE_VLAN:
			index = ETHER_INPUT_NEXT_L2_VLAN;
			break;
        case RTE_ETHER_TYPE_IPV4:
            index = ETHER_INPUT_NEXT_L3_IPV4;
            break;
        case RTE_ETHER_TYPE_ARP:
            index = ETHER_INPUT_NEXT_ARP;
            break;
        case RTE_ETHER_TYPE_IPV6:
            index = ETHER_INPUT_NEXT_L3_IPV6;
            break;
		default:
			index = ETHER_INPUT_NEXT_PKT_DROP;
	}

	
	if (dev->type == PORT_TYPE_BOND_SLAVE) {
        dev = dev->bond->slave.master;
        mbuf->port = dev->id;
		//index = ETHER_INPUT_NEXT_L2_BOND;
    }

	if (dev->br_port != NULL){
		index = ETHER_INPUT_NEXT_L2_BRIDGE;
	}
		
	if (mbuf->ol_flags & PKT_RX_VLAN_STRIPPED){
		index = ETHER_INPUT_NEXT_L2_VLAN;
	}

    debug_l2_packet_trace(L2_DEBUG_ETH_INPUT, mbuf, DETAIL_OFF, "[ether_input] next node is %s!\n", get_index_prinf(index));	
	
	mbuf_dev_set(mbuf, dev);
	return index;
}
static uint16_t
ether_input_node_process(struct rte_graph *graph, struct rte_node *node,
		     void **objs, uint16_t nb_objs)
{
	struct rte_mbuf *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
	enum ether_input_next_nodes n0, n1, n2, n3;
	enum ether_input_next_nodes last_index, next_index, n_left_from;
	uint16_t held = 0, last_spec = 0;
	struct ether_input_node_ctx *ctx;
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

	ctx = (struct ether_input_node_ctx *)node->ctx;
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

		mbuf0 = pkts[0];
		mbuf1 = pkts[1];
		mbuf2 = pkts[2];
		mbuf3 = pkts[3];
		pkts += 4;
		n_left_from -= 4;

		/* Check if they are destined to same
		 * next node based on l2l3 packet type.
		 */
	 	n0 = ether_input_deal_and_trans_to_next_index(mbuf0);
		n1 = ether_input_deal_and_trans_to_next_index(mbuf1);
		n2 = ether_input_deal_and_trans_to_next_index(mbuf2);
		n3 = ether_input_deal_and_trans_to_next_index(mbuf3);
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
		mbuf0 = pkts[0];

		pkts += 1;
		n_left_from -= 1;
		
		n0 = ether_input_deal_and_trans_to_next_index(mbuf0);
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
struct rte_node_register ether_input_node = {
	.process = ether_input_node_process,
	.name = "ether_input",

	.nb_edges = ETHER_INPUT_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[ETHER_INPUT_NEXT_PKT_DROP] = "pkt_drop",
		//[ETHER_INPUT_NEXT_L2_BOND] = "bond",
		[ETHER_INPUT_NEXT_L2_VLAN] = "vlan",
		[ETHER_INPUT_NEXT_L3_IPV4] = "ip4_rcv",
		[ETHER_INPUT_NEXT_L3_IPV6] = "ip6_rcv",
		[ETHER_INPUT_NEXT_L2_BRIDGE] = "bridge",
		[ETHER_INPUT_NEXT_ARP] = "arp_rcv"
	},
};
RTE_NODE_REGISTER(ether_input_node);

