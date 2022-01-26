#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <netinet/ip6.h>

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#include "ip6_output_priv.h"
#include "l3_node_priv.h"
#include "route6_priv.h"
#include "ip6_debug.h"
#include "ip6_graph.h"

#include "conf/common.h"
#include "mbuf.h"
#include "inet.h"
#include "ipv6.h"
#include "route6.h"
#include "parser/parser.h"
#include "neigh.h"
#include "icmp6.h"
#include "iftraf.h"

static bool conf_ipv6_disable = false;
static uint8_t g_cnf_fw_on;

/*
    NOTE:
    if return EDPVS_OK, the  caller is responsible for sending.
    otherwise, mbuf will be release in thid function.
*/
int ipv6_xmit_for_graph(struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    struct route6 *rt = NULL;
    struct ip6_hdr *hdr;
    struct netif_port *dev;

    if (unlikely(!mbuf || !fl6 || ipv6_addr_any(&fl6->fl6_daddr))) {
        if (mbuf)
            rte_pktmbuf_free(mbuf);
        return EDPVS_INVAL;
    }

    /* TODO: to support jumbo packet */
    if (mbuf->pkt_len > IPV6_MAXPLEN) {
        IPv6_INC_STATS(outdiscards);
        rte_pktmbuf_free(mbuf);
        return EDPVS_NOROOM;
    }

    if (unlikely(ipv6_addr_is_multicast(&fl6->fl6_daddr))) {
        /* only support linklocal now */
        if (IPV6_ADDR_MC_SCOPE(&fl6->fl6_daddr)
            != IPV6_ADDR_SCOPE_LINKLOCAL) {
            IPv6_INC_STATS(outnoroutes);
            rte_pktmbuf_free(mbuf);
            return EDPVS_NOTSUPP;
        }
        assert(fl6->fl6_oif);
		mbuf_userdata_set(mbuf, (void *)fl6->fl6_oif);
        dev = fl6->fl6_oif;

    } else {
        /* route decision */
        rt = route6_output(mbuf, fl6);
        if (!rt) {
            IPv6_INC_STATS(outnoroutes);
            rte_pktmbuf_free(mbuf);
            return EDPVS_NOROUTE;
        }
		mbuf_userdata_set(mbuf, (void *)rt);
        dev = rt->rt6_dev;
    }

    hdr = (void *)rte_pktmbuf_prepend(mbuf, sizeof(*hdr));
    if (unlikely(!hdr)) {
        if (rt)
            route6_put(rt);
        rte_pktmbuf_free(mbuf);
        IPv6_INC_STATS(outdiscards);
        return EDPVS_NOROOM;
    }

    memset(hdr, 0, sizeof(*hdr));
    hdr->ip6_vfc    = 0x60;
    hdr->ip6_flow  |= htonl(((uint64_t)fl6->fl6_tos<<20) | \
                            (ntohl(fl6->fl6_flow)&0xfffffUL));
    hdr->ip6_plen   = htons(mbuf->pkt_len - sizeof(*hdr));
    hdr->ip6_nxt    = fl6->fl6_proto;
    hdr->ip6_hlim   = fl6->fl6_ttl ? : INET_DEF_TTL;
    hdr->ip6_src    = fl6->fl6_saddr;
    hdr->ip6_dst    = fl6->fl6_daddr;

    if (ipv6_addr_any(&hdr->ip6_src) &&
        hdr->ip6_nxt != IPPROTO_ICMPV6) {
        union inet_addr saddr;

        inet_addr_select(AF_INET6, dev, (void *)&fl6->fl6_daddr,
                         fl6->fl6_scope, &saddr);
        hdr->ip6_src = saddr.in6;
    }

    return EDPVS_OK;
}

static __rte_always_inline uint16_t
ip6_output_graph(s_nc_param_l3 *param)
{
    struct netif_port *dev;
    struct rte_mbuf *mbuf = param->mbuf;
    struct rte_ipv6_hdr *hdr = rte_ip6_hdr(mbuf);
    struct route6_entry *rt = NULL;
        
    uint16_t ret = IP6_OUTPUT_NEXT_DROP;
    if (rte_ipv6_addr_is_multicast(hdr->dst_addr)) {
        //dev = mbuf_userdata_get(mbuf);
        dev = mbuf_dev_get(mbuf);
    } else {
        //rt = mbuf_userdata_get(mbuf);
        rt = (struct route6_entry *)GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route;
        dev = rt->rt6_dev;
    }

    IPv6_UPD_PO_STATS(out, mbuf->pkt_len);
    mbuf->port = dev->id;
    mbuf_dev_set(mbuf, dev);
#if 0
    iftraf_pkt_out(AF_INET6, mbuf, dev);
    if (unlikely(conf_ipv6_disable)) {
        IP6_INC_STATS(outdiscards);
        if (rt)
            route6_put(rt);
        return ret;
    }
#endif

    if(!g_cnf_fw_on){
        ret = IP6_OUTPUT_NEXT_FINISH;
    }else{
        ret = IP6_OUTPUT_NEXT_FW;
    }

    return ret;
}

static uint16_t
ip6_output_node_process(struct rte_graph *graph, 
                              struct rte_node *node,
                              void **objs, 
                              uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs, 
        nb_objs, IP6_OUTPUT_NEXT_FW, ip6_output_graph);
}

static int
ip6_output_node_init(const struct rte_graph *graph, struct rte_node *node){

    g_cnf_fw_on = 0;
    return 0;
}


/* Packet Classification Node */
struct rte_node_register ip6_output_node = {
	.process = ip6_output_node_process,
	.name = NODE_NAME_IP6_OUTPUT,

    .init = ip6_output_node_init,
    
	.nb_edges = IP6_OUTPUT_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[IP6_OUTPUT_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[IP6_OUTPUT_NEXT_FW] = NODE_NAME_NF_IP6_POST_ROUTING,
		[IP6_OUTPUT_NEXT_ICMP] = NODE_NAME_ICMP6,		
		[IP6_OUTPUT_NEXT_FINISH] = NODE_NAME_IP6_OUTPUT_FINISH,
	},
};
RTE_NODE_REGISTER(ip6_output_node);

