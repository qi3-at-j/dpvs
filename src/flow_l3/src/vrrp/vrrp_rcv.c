#include <rte_graph.h>
#include <rte_mbuf.h>

#include "vrrp_rcv_priv.h"
#include "l3_node_priv.h"
#include "log_priv.h"
#include "vrrp_send_priv.h"

extern unsigned int
vrrp_ring_enqueue(unsigned int uiExpireNum, void *pVrrpMbuf[]);
extern int
vrrp_eventfd_notify(unsigned int uiCount);

static uint16_t
vrrp_rcv_process(struct rte_graph *graph, struct rte_node *node, void **objs,
		 uint16_t nb_objs)
{
    uint16_t enq_nb = 0;

	RTE_SET_USED(node);
	RTE_SET_USED(graph);

    L3_DEBUG_TRACE(L3_INFO, "vrrp_rcv node recieved %u mbuf\n", nb_objs);
    if (likely(get_vrrp_status() != VRRP_ST_NONE)) {
        enq_nb = vrrp_ring_enqueue(nb_objs, (struct rte_mbuf **)objs);
        vrrp_eventfd_notify(enq_nb);
    }

    if (unlikely(enq_nb < nb_objs)) {
        L3_DEBUG_TRACE(L3_ERR, "vrrp enq num %u,total %u!!!\n", enq_nb, nb_objs);
        objs += enq_nb;
        rte_node_enqueue(graph, node, VRRP_RCV_NEXT_DROP,
            objs, nb_objs - enq_nb);
    }

	return nb_objs;
}

/* vrrp rcv Node */
struct rte_node_register vrrp_rcv_node = {
	.process = vrrp_rcv_process,
	.name = NODE_NAME_VRRP_RCV,

	.nb_edges = VRRP_RCV_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[VRRP_RCV_NEXT_DROP] = NODE_NAME_PKT_DROP,
	},
};
RTE_NODE_REGISTER(vrrp_rcv_node);
