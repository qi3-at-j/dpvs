#include <unistd.h>
#include <fcntl.h>
#include "dpdk.h"
#include "netif.h"
#include "ether_input.h"
#include "conf/common.h"
#include "conf/netif.h"
#include "parser/parser.h"
#include "../include/L2_xmit.h"
#include "../include/l2_debug.h"


/* Next node for each ptype, default is '0' is "pkt_drop" */

static inline uint16_t L2_xmit_deal_to_next_index(s_nc_param *param)
{
	/*Assuming the cache is already prefetched, if it is not, it needs to be prefetched outside. */
	uint16_t index = L2_XMIT_NEXT_PKT_DROP;
	struct rte_mbuf *mbuf = param->mbuf;
	struct netif_port *real_dev = NULL;
	int err = 0;
	int loopcnt = 0;

	if(unlikely(!mbuf)){
		
		return index;
	}
	/*Before shipping to L2, you need to set the proper dev for mbuf*/
	struct netif_port *dev = mbuf_dev_get(mbuf);
	if (unlikely(!dev)){
		return index;
	}

loop:
	/*Loops more than three times must be something wrong with the code, and then we have to exit the loop with an error message, right*/
	if(loopcnt > 3){
		debug_l2_packet_trace(L2_DEBUG_L2_XMIT, mbuf, DETAIL_OFF, "[L2 xmit]loopcnt exceed 3, drop!, loopcnt = %d.\n", loopcnt);
		return L2_XMIT_NEXT_PKT_DROP;
	}

	/*If dev is not set, an error is returned */
	if(unlikely(NULL == dev)){
		debug_l2_packet_trace(L2_DEBUG_L2_XMIT, mbuf, DETAIL_OFF, "[L2 xmit]can't get dev from mbuf_dev_get, drop!, loopcnt = %d.\n", loopcnt);
		return L2_XMIT_NEXT_PKT_DROP;
	}

	/*The task of XMIT is to point the dev of mbuf to the real device;*/
	if (unlikely(NULL == dev->netif_ops)){
		debug_l2_packet_trace(L2_DEBUG_L2_XMIT, mbuf, DETAIL_OFF, "[L2 xmit]can't get dev netif_ops, drop!, loopcnt = %d.\n", loopcnt);
		return L2_XMIT_NEXT_PKT_DROP;
	}

	/*If it's a real device, you don't have to go to op_graph_xmit, because what op_graph_xmit is supposed to do is find the real device, 
	and there's already a real device, so op_graph_xmit is not necessary.*/
	if(dev->type == PORT_TYPE_GENERAL){
		real_dev = dev;
		index = L2_XMIT_NEXT_ETHER_OUTPUT;
		goto done;
	}

	/*The task of XMIT is to point the dev of mbuf to the real device;*/
	if (unlikely(NULL == dev->netif_ops->op_graph_xmit)){
		debug_l2_packet_trace(L2_DEBUG_L2_XMIT, mbuf, DETAIL_OFF, "[L2 xmit]can't get dev op_graph_xmit, drop!, loopcnt = %d.\n", loopcnt);
		return L2_XMIT_NEXT_PKT_DROP;
	}

	/*Execute the XMIT function*/
	index = dev->netif_ops->op_graph_xmit(param, mbuf, dev);

	/*Place the port-id of the real device in the mbuf field*/
	real_dev = mbuf_dev_get(mbuf);
	if(unlikely(real_dev == NULL)){
		debug_l2_packet_trace(L2_DEBUG_L2_XMIT, mbuf, DETAIL_OFF, "[L2 xmit]after xmit, can't get real_dev, drop!, loopcnt = %d.\n", loopcnt);
		return L2_XMIT_NEXT_PKT_DROP;
	}

	/*Note that this is not a real device yet, 
	so you need to continue executing the XMIT operation for the virtual device, 
	which is most likely a virtual device that acts as a bridge subinterface, such as VLAN or Bond*/
	if(real_dev->type != PORT_TYPE_GENERAL){
		loopcnt++;
		dev = real_dev;
		goto loop;
	}
	
done:
	/*The actual device, but not the sending device, is very unlikely, it is an code error*/
	if(unlikely(real_dev->id >= ether_output_real_port_cnt_get())){
		debug_l2_packet_trace(L2_DEBUG_L2_XMIT, mbuf, DETAIL_OFF, "[L2 xmit]not real tx dev, drop!, id = %d\n.", real_dev->id);
		return L2_XMIT_NEXT_PKT_DROP;
	}

	mbuf->port = real_dev->id;
	if (L2_XMIT_NEXT_PKT_DROP != index){
		index = L2_XMIT_NEXT_ETHER_OUTPUT;
	}

	return index;
}
static uint16_t
L2_xmit_node_process(struct rte_graph *graph, struct rte_node *node,
		     void **objs, uint16_t nb_objs)
{
	struct rte_mbuf **pkts;
	uint16_t n0, n1, n2, n3;
	uint16_t last_index, next_index, n_left_from;
	uint16_t held = 0, last_spec = 0;
	struct L2_xmit_node_ctx *ctx;
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

	ctx = (struct L2_xmit_node_ctx *)node->ctx;
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
		
	 	n0 = L2_xmit_deal_to_next_index(&param[0]);
		n1 = L2_xmit_deal_to_next_index(&param[1]);
		n2 = L2_xmit_deal_to_next_index(&param[2]);
		n3 = L2_xmit_deal_to_next_index(&param[3]);
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
		
		n0 = L2_xmit_deal_to_next_index(&param[0]);
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
struct rte_node_register L2_xmit_node = {
	.process = L2_xmit_node_process,
	.name = "L2_xmit",

	.nb_edges = L2_XMIT_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[L2_XMIT_NEXT_PKT_DROP] = "pkt_drop",
		[L2_XMIT_NEXT_ETHER_OUTPUT] = "ether_output",
	},
};


RTE_NODE_REGISTER(L2_xmit_node);


