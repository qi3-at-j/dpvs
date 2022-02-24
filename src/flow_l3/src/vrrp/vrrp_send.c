#include <rte_graph.h>
#include <rte_mbuf.h>

#include "vrrp_send_priv.h"
#include "l3_node_priv.h"
#include "common_priv.h"
#include "log_priv.h"
#include "route_priv.h"
#include "route.h"
#include "vrf_priv.h"

static __rte_always_inline uint16_t
vrrp_send(s_nc_param_l3 *param)
{    
    struct rte_mbuf *mbuf = param->mbuf;
    uint16_t next_node = VRRP_SEND_NEXT_DROP;
    char dst_addr[64] = {0};
    struct rte_ipv4_hdr *iph;
    struct route_entry *route_node;

    switch (GET_MBUF_PRIV_DATA(mbuf)->priv_data_vrrp_type) {
    case VRRP_TYPE_IP4:
        iph = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
        inet_ntop(AF_INET, &iph->dst_addr, dst_addr, sizeof(dst_addr));
        route_node = route_lookup(ROUTE_FLAG_FORWARD,
            GLOBAL_ROUTE_TBL_ID, iph->dst_addr);
        if (likely(route_node)) {
            mbuf_dev_set(mbuf, (void *)route_node->port);
            switch (route_node->flag) {
                case ROUTE_FLAG_LOCALIN:
                    L3_DEBUG_TRACE(L3_INFO,
                        "%s node:lookup %s success,flag:local\n",
                        __func__, dst_addr);
                    break;
                case ROUTE_FLAG_FORWARD:
                    L3_DEBUG_TRACE(L3_INFO,
                        "%s node:lookup %s success,flag:net\n",
                        __func__, dst_addr);
                    break;
                default:
                    L3_DEBUG_TRACE(L3_INFO,
                        "%s node:lookup %s success,flag:%u\n",
                        __func__, dst_addr, route_node->flag);
            }
            
            if (route_node->flag == ROUTE_FLAG_FORWARD) {
                GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route = route_node;
                next_node = VRRP_SEND_NEXT_IP4_OUTPUT;
            } else {
                graph_route4_put(route_node);
            }
        } else {
            L3_DEBUG_TRACE(L3_ERR, "%s node:lookup %s failed!!!\n",
                __func__, dst_addr);
        }
        break;
    case VRRP_TYPE_IP6:
        break;
    case VRRP_TYPE_ARP:
    case VRRP_TYPE_ND:
        next_node = VRRP_SEND_NEXT_L2_OUT;
        break;
    }

    return next_node;
}

extern unsigned int
vrrp_ring_dequeue(unsigned int uiExpireNum, void *pVrrpMbuf[]);

static uint16_t
vrrp_send_process(struct rte_graph *graph, struct rte_node *node,
    void **objs, uint16_t nb_objs)
{
    nb_objs = vrrp_ring_dequeue(node->size - node->idx, objs);

    if (unlikely(nb_objs)) {
        node->idx = nb_objs;
        NODE_PROC_COM(graph, node, objs,
            nb_objs, VRRP_SEND_NEXT_IP4_OUTPUT, vrrp_send);
    }
}

/* vrrp send Node */
struct rte_node_register vrrp_send_node = {
	.process = vrrp_send_process,
	.flags = RTE_NODE_SOURCE_F,
	.name = NODE_NAME_VRRP_SEND,

	.nb_edges = VRRP_SEND_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[VRRP_SEND_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[VRRP_SEND_NEXT_IP4_OUTPUT] = NODE_NAME_IP4_OUTPUT,
		[VRRP_SEND_NEXT_IP6_OUTPUT] = NODE_NAME_IP6_OUTPUT,
		[VRRP_SEND_NEXT_L2_OUT] = NODE_NAME_L2_OUT,
	},
};
RTE_NODE_REGISTER(vrrp_send_node);
