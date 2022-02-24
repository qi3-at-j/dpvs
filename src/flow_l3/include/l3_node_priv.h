/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#ifndef __NODE_L3_PRIVATE_H__
#define __NODE_L3_PRIVATE_H__

#include <rte_common.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

/* External header files */
#include "netif.h"

/* use per lcore ip reassemble table*/
#define IP_REASSEMBLE_USE_PER_LCORE_TBL

/*****test node switch*****/
#define NODE_TEST_INSERT 0
/**************************/

#define ROUTE_USE_FIB 0
#if ROUTE_USE_FIB
#define ROUTE_USE_HASH 0
#else
#define ROUTE_USE_HASH 1
#endif

#define NODE_NAME_IP4_RCV "ip4_rcv"
#if NODE_TEST_INSERT
#define NODE_NAME_TEST "ip4_rcv"
#define NODE_NAME_IP4_RCV "ip4_rcv_bak"
#endif
#define NODE_NAME_IP4_RCV_FINISH "ip4_rcv_finish"
#define NODE_NAME_IP4_LOCAL_DELIVER "ip4_local_deliver"
#define NODE_NAME_IP4_LOCAL_DELIVER_FINISH "ip4_local_deliver_finish"
#define NODE_NAME_IP4_FORWARD "ip4_forward"
#define NODE_NAME_IP4_FORWARD_FINISH "ip4_forward_finish"
#define NODE_NAME_IP4_OUTPUT "ip4_output"
#define NODE_NAME_IP4_OUTPUT_FINISH "ip4_output_finish"
#define NODE_NAME_ICMP_SEND "icmp_send"
#define NODE_NAME_VXLAN_RCV "vxlan_rcv"
#define NODE_NAME_VXLAN_SEND "vxlan_send"
#define NODE_NAME_ARP_RCV "arp_rcv"
#define NODE_NAME_VRRP_RCV "vrrp_rcv"
#define NODE_NAME_VRRP_SEND "vrrp_send"
#define NODE_NAME_CMD_RING_DEQ "cmd_ring_deq"
#define NODE_NAME_PKT_DROP "pkt_drop"

#define NODE_NAME_L2_RCV "ether_input"
#define NODE_NAME_L2_OUT "L2_xmit"

#define NODE_NAME_NF_IP_PRE_ROUTING "nf_ip_pre_routing"
#define NODE_NAME_NF_IP_LOCAL_IN "nf_ip_local_in"
#define NODE_NAME_NF_IP_FORWARD "nf_ip_forward"
#define NODE_NAME_NF_IP_LOCAL_OUT "nf_ip_local_out"
#define NODE_NAME_NF_IP_POST_ROUTING "nf_ip_post_routing"

#define NODE_NAME_IP6_RCV "ip6_rcv"
#define NODE_NAME_IP6_RCV_FINISH "ip6_rcv_finish"
#define NODE_NAME_IP6_LOCAL_IN "ip6_local_in"
#define NODE_NAME_IP6_FORWARD "ip6_forward"
#define NODE_NAME_IP6_FORWARD_FINISH "ip6_forward_finish"
#define NODE_NAME_IP6_LOCAL_IN_FINISH "ip6_local_in_finish"
#define NODE_NAME_ICMP6 "icmp6"
#define NODE_NAME_IP6_OUTPUT_FINISH "ip6_output_finish"

#define NODE_NAME_NF_IP6_PRE_ROUTING "nf_ip6_pre_routing"
#define NODE_NAME_NF_IP6_LOCAL_IN "nf_ip6_local_in"
#define NODE_NAME_NF_IP6_FORWARD "nf_ip6_forward"
#define NODE_NAME_NF_IP6_LOCAL_OUT "nf_ip6_local_out"
#define NODE_NAME_NF_IP6_POST_ROUTING "nf_ip6_post_routing"
#define NODE_NAME_IP6_OUTPUT          "ip6_output"

#define GET_MBUF_PRIV_DATA(m) \
    ((struct mbuf_priv_data *)rte_mbuf_to_priv(m))

#define OBJS_PER_CLINE (RTE_CACHE_LINE_SIZE / sizeof(void *))

typedef struct _node_common_param_l3 {
    struct rte_mbuf *mbuf;
    struct rte_mbuf **mbuf2;
    struct rte_node *node;
    struct rte_graph *graph;
}s_nc_param_l3;

#if 0
static __rte_always_inline uint16_t
node_proc_com(struct rte_graph *graph, 
            struct rte_node *node, void **objs, uint16_t nb_objs, 
            uint16_t *next_id, uint16_t (*func)(s_nc_param_l3 *))
{
	struct rte_mbuf **pkts;
	uint16_t ret0, ret1, ret2, ret3;
    /* Speculative next */
    uint16_t next_index;
	uint16_t n_left_from;
	uint16_t held = 0, last_spec = 0;
	void **to_next, **from;
	uint32_t i;
    s_nc_param_l3 param[4];

    next_index = *next_id;
	pkts = (struct rte_mbuf **)objs;
	from = objs;
	n_left_from = nb_objs;

	for (i = OBJS_PER_CLINE; i < RTE_GRAPH_BURST_SIZE; i += OBJS_PER_CLINE)\
		rte_prefetch0(&objs[i]);
    
#if RTE_GRAPH_BURST_SIZE > 64
    for (i = 0; i < 4 && i < n_left_from; i++)
        rte_prefetch0(pkts[i]);
#endif

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
        
        ret0 = func(&param[0]);
        ret1 = func(&param[1]);
        ret2 = func(&param[2]);
        ret3 = func(&param[3]);

		/* Check if they are destined to same
		 * next node based on ret next index.
		 */

        uint8_t fix_spec = (next_index ^ ret0) | (next_index ^ ret1) |
			(next_index ^ ret2) | (next_index ^ ret3);

		if (unlikely(fix_spec)) {
			/* Copy things successfully speculated till now */
			rte_memcpy(to_next, from,
				   last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;

			/* ret0 */
			if (ret0 == next_index) {
				to_next[0] = from[0];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node,
						    ret0, from[0]);
			}

			/* ret1 */
			if (ret1 == next_index) {
				to_next[0] = from[1];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node,
						    ret1, from[1]);
			}

			/* ret2 */
			if (ret2 == next_index) {
				to_next[0] = from[2];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node,
						    ret2, from[2]);
			}

			/* ret3 */
			if (ret3 == next_index) {
				to_next[0] = from[3];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node,
						    ret3, from[3]);
			}

			/* Update speculated ptype */
			if ((next_index != ret3) && (ret2 == ret3)) {
				/* Put the current stream for
				 * speculated ltype.
				 */

				rte_node_next_stream_put(graph, node,
							 next_index, held);

				held = 0;

				/* Get next stream for new ltype */
				next_index = ret3;
                *next_id = next_index;
				to_next = rte_node_next_stream_get(graph, node,
								   next_index,
								   nb_objs);
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

        ret0 = func(&param[0]);
		if (unlikely(ret0 != next_index)) {
			/* Copy things successfully speculated till now */
			rte_memcpy(to_next, from,
				   last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;

			rte_node_enqueue_x1(graph, node,
					    ret0, from[0]);
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
    
	return nb_objs;
}
#endif

#if RTE_GRAPH_BURST_SIZE > 64
#define NODE_PROC_COM(graph, node, objs, nb_objs, next_id, func) do {\
	struct rte_mbuf **pkts;\
	uint16_t ret0, ret1, ret2, ret3;\
    /* Speculative next */\
    static __thread uint16_t next_index = next_id;\
	uint16_t n_left_from;\
	uint16_t held = 0, last_spec = 0;\
	void **to_next, **from;\
	uint32_t i;\
    s_nc_param_l3 param[4];\
\
	pkts = (struct rte_mbuf **)objs;\
	from = objs;\
	n_left_from = nb_objs;\
\
	for (i = OBJS_PER_CLINE; i < RTE_GRAPH_BURST_SIZE; i += OBJS_PER_CLINE)\
		rte_prefetch0(&objs[i]);\
\
/* #if RTE_GRAPH_BURST_SIZE > 64 */\
    for (i = 0; i < 4 && i < n_left_from; i++)\
        rte_prefetch0(pkts[i]);\
/* #endif */\
\
	/* Get stream for the speculated next node */\
	to_next = rte_node_next_stream_get(graph, node, next_index, nb_objs);\
	while (n_left_from >= 4) {\
/* #if RTE_GRAPH_BURST_SIZE > 64 */\
		if (likely(n_left_from > 7)) {\
			rte_prefetch0(pkts[4]);\
			rte_prefetch0(pkts[5]);\
			rte_prefetch0(pkts[6]);\
			rte_prefetch0(pkts[7]);\
		}\
/* #endif */\
\
        param[0].mbuf = pkts[0];\
        param[0].mbuf2 = &pkts[0];\
\
        param[1].mbuf = pkts[1];\
        param[1].mbuf2 = &pkts[1];\
\
        param[2].mbuf = pkts[2];\
        param[2].mbuf2 = &pkts[2];\
\
        param[3].mbuf = pkts[3];\
        param[3].mbuf2 = &pkts[3];\
\
        param[0].node = node;\
        param[1].node = node;\
        param[2].node = node;\
        param[3].node = node;\
\
        param[0].graph = graph;\
        param[1].graph = graph;\
        param[2].graph = graph;\
        param[3].graph = graph;\
\
		pkts += 4;\
		n_left_from -= 4;\
\
        ret0 = func(&param[0]);\
        ret1 = func(&param[1]);\
        ret2 = func(&param[2]);\
        ret3 = func(&param[3]);\
\
		/* Check if they are destined to same\
		 * next node based on ret next index.\
		 */\
\
        uint8_t fix_spec = (next_index ^ ret0) | (next_index ^ ret1) |\
			(next_index ^ ret2) | (next_index ^ ret3);\
\
		if (unlikely(fix_spec)) {\
			/* Copy things successfully speculated till now */\
			rte_memcpy(to_next, from,\
				   last_spec * sizeof(from[0]));\
			from += last_spec;\
			to_next += last_spec;\
			held += last_spec;\
			last_spec = 0;\
\
			/* ret0 */\
			if (ret0 == next_index) {\
				to_next[0] = from[0];\
				to_next++;\
				held++;\
			} else {\
				rte_node_enqueue_x1(graph, node,\
						    ret0, from[0]);\
			}\
\
			/* ret1 */\
			if (ret1 == next_index) {\
				to_next[0] = from[1];\
				to_next++;\
				held++;\
			} else {\
				rte_node_enqueue_x1(graph, node,\
						    ret1, from[1]);\
			}\
\
			/* ret2 */\
			if (ret2 == next_index) {\
				to_next[0] = from[2];\
				to_next++;\
				held++;\
			} else {\
				rte_node_enqueue_x1(graph, node,\
						    ret2, from[2]);\
			}\
\
			/* ret3 */\
			if (ret3 == next_index) {\
				to_next[0] = from[3];\
				to_next++;\
				held++;\
			} else {\
				rte_node_enqueue_x1(graph, node,\
						    ret3, from[3]);\
			}\
\
			/* Update speculated ptype */\
			if ((next_index != ret3) && (ret2 == ret3)) {\
				/* Put the current stream for\
				 * speculated ltype.\
				 */\
\
				rte_node_next_stream_put(graph, node,\
							 next_index, held);\
\
				held = 0;\
\
				/* Get next stream for new ltype */\
				next_index = ret3;\
				to_next = rte_node_next_stream_get(graph, node,\
								   next_index,\
								   nb_objs);\
			}\
\
			from += 4;\
		} else {\
			last_spec += 4;\
		}\
	}\
\
    while (n_left_from > 0) {\
        param[0].mbuf = pkts[0];\
        param[0].mbuf2 = &pkts[0];\
        param[0].node = node;\
        param[0].graph = graph;\
\
        pkts += 1;\
        n_left_from -= 1;\
\
        ret0 = func(&param[0]);\
		if (unlikely(ret0 != next_index)) {\
			/* Copy things successfully speculated till now */\
			rte_memcpy(to_next, from,\
				   last_spec * sizeof(from[0]));\
			from += last_spec;\
			to_next += last_spec;\
			held += last_spec;\
			last_spec = 0;\
\
			rte_node_enqueue_x1(graph, node,\
					    ret0, from[0]);\
			from += 1;\
		} else {\
			last_spec += 1;\
		}\
	}\
\
	/* !!! Home run !!! */\
	if (likely(last_spec == nb_objs)) {\
		rte_node_next_stream_move(graph, node, next_index);\
		return nb_objs;\
	}\
\
	held += last_spec;\
	/* Copy things successfully speculated till now */\
	rte_memcpy(to_next, from, last_spec * sizeof(from[0]));\
	rte_node_next_stream_put(graph, node, next_index, held);\
\
	return nb_objs;\
} while(0)
#else
#define NODE_PROC_COM(graph, node, objs, nb_objs, next_id, func) do {\
	struct rte_mbuf **pkts;\
	uint16_t ret0, ret1, ret2, ret3;\
    /* Speculative next */\
    static __thread uint16_t next_index = next_id;\
	uint16_t n_left_from;\
	uint16_t held = 0, last_spec = 0;\
	void **to_next, **from;\
	uint32_t i;\
    s_nc_param_l3 param[4];\
\
	pkts = (struct rte_mbuf **)objs;\
	from = objs;\
	n_left_from = nb_objs;\
\
	for (i = OBJS_PER_CLINE; i < RTE_GRAPH_BURST_SIZE; i += OBJS_PER_CLINE)\
		rte_prefetch0(&objs[i]);\
\
	/* Get stream for the speculated next node */\
	to_next = rte_node_next_stream_get(graph, node, next_index, nb_objs);\
	while (n_left_from >= 4) {\
        param[0].mbuf = pkts[0];\
        param[0].mbuf2 = &pkts[0];\
\
        param[1].mbuf = pkts[1];\
        param[1].mbuf2 = &pkts[1];\
\
        param[2].mbuf = pkts[2];\
        param[2].mbuf2 = &pkts[2];\
\
        param[3].mbuf = pkts[3];\
        param[3].mbuf2 = &pkts[3];\
\
        param[0].node = node;\
        param[1].node = node;\
        param[2].node = node;\
        param[3].node = node;\
\
        param[0].graph = graph;\
        param[1].graph = graph;\
        param[2].graph = graph;\
        param[3].graph = graph;\
\
		pkts += 4;\
		n_left_from -= 4;\
\
        ret0 = func(&param[0]);\
        ret1 = func(&param[1]);\
        ret2 = func(&param[2]);\
        ret3 = func(&param[3]);\
\
		/* Check if they are destined to same\
		 * next node based on ret next index.\
		 */\
\
        uint8_t fix_spec = (next_index ^ ret0) | (next_index ^ ret1) |\
			(next_index ^ ret2) | (next_index ^ ret3);\
\
		if (unlikely(fix_spec)) {\
			/* Copy things successfully speculated till now */\
			rte_memcpy(to_next, from,\
				   last_spec * sizeof(from[0]));\
			from += last_spec;\
			to_next += last_spec;\
			held += last_spec;\
			last_spec = 0;\
\
			/* ret0 */\
			if (ret0 == next_index) {\
				to_next[0] = from[0];\
				to_next++;\
				held++;\
			} else {\
				rte_node_enqueue_x1(graph, node,\
						    ret0, from[0]);\
			}\
\
			/* ret1 */\
			if (ret1 == next_index) {\
				to_next[0] = from[1];\
				to_next++;\
				held++;\
			} else {\
				rte_node_enqueue_x1(graph, node,\
						    ret1, from[1]);\
			}\
\
			/* ret2 */\
			if (ret2 == next_index) {\
				to_next[0] = from[2];\
				to_next++;\
				held++;\
			} else {\
				rte_node_enqueue_x1(graph, node,\
						    ret2, from[2]);\
			}\
\
			/* ret3 */\
			if (ret3 == next_index) {\
				to_next[0] = from[3];\
				to_next++;\
				held++;\
			} else {\
				rte_node_enqueue_x1(graph, node,\
						    ret3, from[3]);\
			}\
\
			/* Update speculated ptype */\
			if ((next_index != ret3) && (ret2 == ret3)) {\
				/* Put the current stream for\
				 * speculated ltype.\
				 */\
\
				rte_node_next_stream_put(graph, node,\
							 next_index, held);\
\
				held = 0;\
\
				/* Get next stream for new ltype */\
				next_index = ret3;\
				to_next = rte_node_next_stream_get(graph, node,\
								   next_index,\
								   nb_objs);\
			}\
\
			from += 4;\
		} else {\
			last_spec += 4;\
		}\
	}\
\
    while (n_left_from > 0) {\
        param[0].mbuf = pkts[0];\
        param[0].mbuf2 = &pkts[0];\
        param[0].node = node;\
        param[0].graph = graph;\
\
        pkts += 1;\
        n_left_from -= 1;\
\
        ret0 = func(&param[0]);\
		if (unlikely(ret0 != next_index)) {\
			/* Copy things successfully speculated till now */\
			rte_memcpy(to_next, from,\
				   last_spec * sizeof(from[0]));\
			from += last_spec;\
			to_next += last_spec;\
			held += last_spec;\
			last_spec = 0;\
\
			rte_node_enqueue_x1(graph, node,\
					    ret0, from[0]);\
			from += 1;\
		} else {\
			last_spec += 1;\
		}\
	}\
\
	/* !!! Home run !!! */\
	if (likely(last_spec == nb_objs)) {\
		rte_node_next_stream_move(graph, node, next_index);\
		return nb_objs;\
	}\
\
	held += last_spec;\
	/* Copy things successfully speculated till now */\
	rte_memcpy(to_next, from, last_spec * sizeof(from[0]));\
	rte_node_next_stream_put(graph, node, next_index, held);\
\
	return nb_objs;\
} while(0)

#endif

#if RTE_GRAPH_BURST_SIZE > 64
#define NODE_PROC_COM_1(graph, node, objs, nb_objs, next_id, func) do {\
    struct rte_mbuf *pkts_out[PKT_OUT_NUM_MAX];\
	struct rte_mbuf **pkts;\
	uint16_t ret0, ret1, ret2, ret3;\
    /* Speculative next */\
	static uint16_t next_index = next_id;\
	uint16_t n_left_from;\
	uint16_t held = 0, last_spec = 0;\
	void **to_next, **from;\
	uint32_t i;\
    s_nc_param_l3 param[4];\
\
	pkts = (struct rte_mbuf **)objs;\
	from = objs;\
	n_left_from = nb_objs;\
\
	for (i = OBJS_PER_CLINE; i < RTE_GRAPH_BURST_SIZE; i += OBJS_PER_CLINE)\
		rte_prefetch0(&objs[i]);\
\
/* #if RTE_GRAPH_BURST_SIZE > 64 */\
    for (i = 0; i < 4 && i < n_left_from; i++)\
        rte_prefetch0(pkts[i]);\
/* #endif */\
\
	/* Get stream for the speculated next node */\
	to_next = rte_node_next_stream_get(graph, node, next_index, nb_objs);\
	while (n_left_from >= 4) {\
/* #if RTE_GRAPH_BURST_SIZE > 64 */\
		if (likely(n_left_from > 7)) {\
			rte_prefetch0(pkts[4]);\
			rte_prefetch0(pkts[5]);\
			rte_prefetch0(pkts[6]);\
			rte_prefetch0(pkts[7]);\
		}\
/* #endif */\
\
        param[0].mbuf = pkts[0];\
        param[0].mbuf2 = &pkts[0];\
\
        param[1].mbuf = pkts[1];\
        param[1].mbuf2 = &pkts[1];\
\
        param[2].mbuf = pkts[2];\
        param[2].mbuf2 = &pkts[2];\
\
        param[3].mbuf = pkts[3];\
        param[3].mbuf2 = &pkts[3];\
\
        param[0].node = node;\
        param[1].node = node;\
        param[2].node = node;\
        param[3].node = node;\
\
        param[0].graph = graph;\
        param[1].graph = graph;\
        param[2].graph = graph;\
        param[3].graph = graph;\
\
		pkts += 4;\
		n_left_from -= 4;\
\
        ret0 = func(&param[0]);\
        ret1 = func(&param[1]);\
        ret2 = func(&param[2]);\
        ret3 = func(&param[3]);\
\
		/* Check if they are destined to same\
		 * next node based on ret next index.\
		 */\
\
        uint8_t fix_spec = (next_index ^ ret0) | (next_index ^ ret1) |\
			(next_index ^ ret2) | (next_index ^ ret3);\
\
		if (unlikely(fix_spec)) {\
			/* Copy things successfully speculated till now */\
			rte_memcpy(to_next, from,\
				   last_spec * sizeof(from[0]));\
			from += last_spec;\
			to_next += last_spec;\
			held += last_spec;\
			last_spec = 0;\
\
			/* ret0 */\
			if (ret0 == next_index) {\
				to_next[0] = from[0];\
				to_next++;\
				held++;\
			} else {\
				rte_node_enqueue_x1(graph, node,\
						    ret0, from[0]);\
			}\
\
			/* ret1 */\
			if (ret1 == next_index) {\
				to_next[0] = from[1];\
				to_next++;\
				held++;\
			} else {\
				rte_node_enqueue_x1(graph, node,\
						    ret1, from[1]);\
			}\
\
			/* ret2 */\
			if (ret2 == next_index) {\
				to_next[0] = from[2];\
				to_next++;\
				held++;\
			} else {\
				rte_node_enqueue_x1(graph, node,\
						    ret2, from[2]);\
			}\
\
			/* ret3 */\
			if (ret3 == next_index) {\
				to_next[0] = from[3];\
				to_next++;\
				held++;\
			} else {\
				rte_node_enqueue_x1(graph, node,\
						    ret3, from[3]);\
			}\
\
			/* Update speculated ptype */\
			if ((next_index != ret3) && (ret2 == ret3)) {\
				/* Put the current stream for\
				 * speculated ltype.\
				 */\
\
				rte_node_next_stream_put(graph, node,\
							 next_index, held);\
\
				held = 0;\
\
				/* Get next stream for new ltype */\
				next_index = ret3;\
				to_next = rte_node_next_stream_get(graph, node,\
								   next_index,\
								   nb_objs);\
			}\
\
			from += 4;\
		} else {\
			last_spec += 4;\
		}\
	}\
\
    while (n_left_from > 0) {\
        param[0].mbuf = pkts[0];\
        param[0].mbuf2 = &pkts[0];\
        param[0].node = node;\
        param[0].graph = graph;\
\
        pkts += 1;\
        n_left_from -= 1;\
\
        ret0 = func(&param[0]);\
		if (unlikely(ret0 != next_index)) {\
			/* Copy things successfully speculated till now */\
			rte_memcpy(to_next, from,\
				   last_spec * sizeof(from[0]));\
			from += last_spec;\
			to_next += last_spec;\
			held += last_spec;\
			last_spec = 0;\
\
			rte_node_enqueue_x1(graph, node,\
					    ret0, from[0]);\
			from += 1;\
		} else {\
			last_spec += 1;\
		}\
	}\
\
	/* !!! Home run !!! */\
	if (likely(last_spec == nb_objs)) {\
		rte_node_next_stream_move(graph, node, next_index);\
		return nb_objs;\
	}\
\
	held += last_spec;\
	/* Copy things successfully speculated till now */\
	rte_memcpy(to_next, from, last_spec * sizeof(from[0]));\
	rte_node_next_stream_put(graph, node, next_index, held);\
\
	return nb_objs;\
} while(0)
#else
#define NODE_PROC_COM_1(graph, node, objs, nb_objs, next_id, FUNC) do {\
	struct rte_mbuf **pkts;\
	uint16_t ret0, ret1, ret2, ret3;\
    /* Speculative next */\
	static uint16_t next_index = next_id;\
	uint16_t n_left_from;\
	uint16_t held = 0, last_spec = 0;\
	void **to_next, **from;\
	uint32_t i;\
    s_nc_param_l3 param[4];\
\
	pkts = (struct rte_mbuf **)objs;\
	from = objs;\
	n_left_from = nb_objs;\
\
	for (i = OBJS_PER_CLINE; i < RTE_GRAPH_BURST_SIZE; i += OBJS_PER_CLINE)\
		rte_prefetch0(&objs[i]);\
\
	/* Get stream for the speculated next node */\
	to_next = rte_node_next_stream_get(graph, node, next_index, nb_objs);\
	while (n_left_from >= 4) {\
        param[0].mbuf = pkts[0];\
        param[0].mbuf2 = &pkts[0];\
\
        param[1].mbuf = pkts[1];\
        param[1].mbuf2 = &pkts[1];\
\
        param[2].mbuf = pkts[2];\
        param[2].mbuf2 = &pkts[2];\
\
        param[3].mbuf = pkts[3];\
        param[3].mbuf2 = &pkts[3];\
\
        param[0].node = node;\
        param[1].node = node;\
        param[2].node = node;\
        param[3].node = node;\
\
        param[0].graph = graph;\
        param[1].graph = graph;\
        param[2].graph = graph;\
        param[3].graph = graph;\
\
		pkts += 4;\
		n_left_from -= 4;\
\
        ret0 = func(&param[0]);\
        ret1 = func(&param[1]);\
        ret2 = func(&param[2]);\
        ret3 = func(&param[3]);\
\
		/* Check if they are destined to same\
		 * next node based on ret next index.\
		 */\
\
        uint8_t fix_spec = (next_index ^ ret0) | (next_index ^ ret1) |\
			(next_index ^ ret2) | (next_index ^ ret3);\
\
		if (unlikely(fix_spec)) {\
			/* Copy things successfully speculated till now */\
			rte_memcpy(to_next, from,\
				   last_spec * sizeof(from[0]));\
			from += last_spec;\
			to_next += last_spec;\
			held += last_spec;\
			last_spec = 0;\
\
			/* ret0 */\
			if (ret0 == next_index) {\
				to_next[0] = from[0];\
				to_next++;\
				held++;\
			} else {\
				rte_node_enqueue_x1(graph, node,\
						    ret0, from[0]);\
			}\
\
			/* ret1 */\
			if (ret1 == next_index) {\
				to_next[0] = from[1];\
				to_next++;\
				held++;\
			} else {\
				rte_node_enqueue_x1(graph, node,\
						    ret1, from[1]);\
			}\
\
			/* ret2 */\
			if (ret2 == next_index) {\
				to_next[0] = from[2];\
				to_next++;\
				held++;\
			} else {\
				rte_node_enqueue_x1(graph, node,\
						    ret2, from[2]);\
			}\
\
			/* ret3 */\
			if (ret3 == next_index) {\
				to_next[0] = from[3];\
				to_next++;\
				held++;\
			} else {\
				rte_node_enqueue_x1(graph, node,\
						    ret3, from[3]);\
			}\
\
			/* Update speculated ptype */\
			if ((next_index != ret3) && (ret2 == ret3)) {\
				/* Put the current stream for\
				 * speculated ltype.\
				 */\
\
				rte_node_next_stream_put(graph, node,\
							 next_index, held);\
\
				held = 0;\
\
				/* Get next stream for new ltype */\
				next_index = ret3;\
				to_next = rte_node_next_stream_get(graph, node,\
								   next_index,\
								   nb_objs);\
			}\
\
			from += 4;\
		} else {\
			last_spec += 4;\
		}\
	}\
\
    while (n_left_from > 0) {\
        param[0].mbuf = pkts[0];\
        param[0].mbuf2 = &pkts[0];\
        param[0].node = node;\
        param[0].graph = graph;\
\
        pkts += 1;\
        n_left_from -= 1;\
\
        ret0 = func(&param[0]);\
		if (unlikely(ret0 != next_index)) {\
			/* Copy things successfully speculated till now */\
			rte_memcpy(to_next, from,\
				   last_spec * sizeof(from[0]));\
			from += last_spec;\
			to_next += last_spec;\
			held += last_spec;\
			last_spec = 0;\
\
			rte_node_enqueue_x1(graph, node,\
					    ret0, from[0]);\
			from += 1;\
		} else {\
			last_spec += 1;\
		}\
	}\
\
	/* !!! Home run !!! */\
	if (likely(last_spec == nb_objs)) {\
		rte_node_next_stream_move(graph, node, next_index);\
		return nb_objs;\
	}\
\
	held += last_spec;\
	/* Copy things successfully speculated till now */\
	rte_memcpy(to_next, from, last_spec * sizeof(from[0]));\
	rte_node_next_stream_put(graph, node, next_index, held);\
\
	return nb_objs;\
} while(0)

#endif

#endif /* __NODE_L3_PRIVATE_H__ */