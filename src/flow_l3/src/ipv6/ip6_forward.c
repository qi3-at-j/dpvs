#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#include "ipv6.h"
#include "route6_priv.h"
#include "ip6_debug.h"
#include "ip6_forward_priv.h"
#include "l3_node_priv.h"
#include "ip6_graph.h"
#include "flow.h"

static uint8_t g_cnf_forwarding_on; 
static uint8_t g_cnf_fw_on;

static int ip6_forward(s_nc_param_l3 *param)
{
    struct rte_mbuf * mbuf = param->mbuf;
    struct rte_ipv6_hdr *hdr = rte_ip6_hdr(mbuf);
    //struct route6_entry *rt = mbuf_userdata_get(mbuf);
    struct route6_entry *rt = (struct route6_entry *)GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route;
    int addrtype, rc;
    uint32_t mtu;

    if (unlikely(!g_cnf_forwarding_on))
        goto error;

    if (mbuf->packet_type != ETH_PKT_HOST)
        goto drop;

    /* not support forward multicast */
    if (rte_ipv6_addr_is_multicast(hdr->dst_addr))
        goto error;

    if (hdr->hop_limits <= 1) {
        mbuf->port = rt->rt6_dev->id;
        //icmp6_send(mbuf, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, 0);
        //IP6_INC_STATS(inhdrerrors);
        goto drop;
        /* dont move to IP6_FORWARD_NEXT_ICMP. Because the assertion */
        /* in ip6_icmp(assert(iph)) is triggered to take effect */
        //return IP6_FORWARD_NEXT_ICMP;
    }

    /* security critical */
    addrtype = rte_ipv6_addr_type(hdr->src_addr);

    if (addrtype == RTE_IPV6_ADDR_ANY ||
        addrtype & (RTE_IPV6_ADDR_MULTICAST | RTE_IPV6_ADDR_LOOPBACK))
        goto error;

    if (addrtype & RTE_IPV6_ADDR_LINKLOCAL) {
        //icmp6_send(mbuf, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_BEYONDSCOPE, 0);
        goto drop;
        /* dont move to IP6_FORWARD_NEXT_ICMP. Because the assertion */
        /* in ip6_icmp(assert(iph)) is triggered to take effect */
        //return IP6_FORWARD_NEXT_ICMP;
    }

    /* is packet too big ? */
    mtu = rte_ipv6_mtu_forward(rt);
    if (mtu < IPV6_MIN_MTU)
        mtu = IPV6_MIN_MTU;

    if (mbuf->pkt_len > mtu) {
        mbuf->port = rt->rt6_dev->id;
        //icmp6_send(mbuf, ICMP6_PACKET_TOO_BIG, 0, mtu);

        //IP6_INC_STATS(intoobigerrors);
        //IP6_INC_STATS(fragfails);
        goto drop;
        /* dont move to IP6_FORWARD_NEXT_ICMP. Because the assertion */
        /* in ip6_icmp(assert(iph)) is triggered to take effect */
        //return IP6_FORWARD_NEXT_ICMP;
    }

    rc = flow_processing_paks(mbuf);
    if (rc < FLOW_RET_OK) {
        goto drop;
    } else if (rc >= FLOW_RET_FWD_BAR && rc <= FLOW_RET_FWD_BAR2) {
        *param->mbuf2 = NULL;
        return IP6_FORWARD_NEXT_DROP;
    }
    if (GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route != 
        (csp2peer(GET_CSP_FROM_MBUF(mbuf)))->route) {
        route6_put(GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route);
        GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route = (csp2peer(GET_CSP_FROM_MBUF(mbuf)))->route;
        route6_get(GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route);
    }

    /* decrease TTL */
    hdr->hop_limits--;

    if (likely(g_cnf_fw_on)) {
        return IP6_FORWARD_NEXT_FW;
    } else {
        return IP6_FORWARD_NEXT_FINISH;
    }

error:
    IPv6_INC_STATS(inaddrerrors);
drop:
    return IP6_FORWARD_NEXT_DROP;
}

static uint16_t
ip6_forward_node_process(struct rte_graph *graph, 
            struct rte_node *node, void **objs, uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs, 
        nb_objs, IP6_FORWARD_NEXT_FW, ip6_forward);
}

static int
ip6_forward_node_init(const struct rte_graph *graph, 
                                struct rte_node *node)
{
    RTE_SET_USED(graph);
    RTE_SET_USED(node);

    g_cnf_forwarding_on = 1;
    g_cnf_fw_on = 1;

    return 0;
}

/* Packet Classification Node */
struct rte_node_register ip6_forward_node = {
	.process = ip6_forward_node_process,
	.name = NODE_NAME_IP6_FORWARD,

    .init = ip6_forward_node_init,
    
	.nb_edges = IP6_FORWARD_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[IP6_FORWARD_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[IP6_FORWARD_NEXT_ICMP] = NODE_NAME_ICMP6,
		[IP6_FORWARD_NEXT_FW] = NODE_NAME_NF_IP6_FORWARD,
		[IP6_FORWARD_NEXT_FINISH] = NODE_NAME_IP6_FORWARD_FINISH,
	},
};
RTE_NODE_REGISTER(ip6_forward_node);


