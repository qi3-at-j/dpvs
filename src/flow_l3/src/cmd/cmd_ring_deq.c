#include <rte_graph.h>

#include "cmd_ring_deq_priv.h"
#include "l3_node_priv.h"
#include "flow_l3_cli_priv.h"

static uint16_t
cmd_ring_deq_process(struct rte_graph *graph, struct rte_node *node,
    void **objs, uint16_t nb_objs)
{
    RTE_SET_USED(graph);
    RTE_SET_USED(node);
    RTE_SET_USED(objs);
    RTE_SET_USED(nb_objs);

    api_deq_l3_cmd_ring(NULL);

    return 0;
}

struct rte_node_register cmd_ring_deq_node = {
	.process = cmd_ring_deq_process,
	.flags = RTE_NODE_SOURCE_F,
	.name = NODE_NAME_CMD_RING_DEQ,

	.nb_edges = CMD_RING_DEQ_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[CMD_RING_DEQ_NEXT_DROP] = NODE_NAME_PKT_DROP,
	},
};
RTE_NODE_REGISTER(cmd_ring_deq_node);
