#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#include "ipv6.h"
#include "ndisc.h"
#include "route6.h"
#include "ip6_debug.h"
#include "ip6_forward_priv.h"
#include "l3_node_priv.h"
#include "vrf_priv.h"
#include "ip6_icmp_priv.h"
#include "neigh_priv.h"
#include "arp_priv.h"

static struct rte_mbuf *
ndisc_send_na_graph(struct netif_port *dev,
                    const struct in6_addr *daddr,
                    const struct in6_addr *solicited_addr,
                    int solicited, int override, int inc_opt,
                    struct vrrp_entry *vrrp_node)
{
    struct inet_ifaddr *ifa;
    const struct in6_addr *src_addr;
    struct rte_mbuf *mbuf;
    struct icmp6_hdr icmp6h;
    struct ip6_hdr *hdr;

    /* solicited_addr is not always src_addr, just not support now */
    ifa = inet_addr_ifa_get(AF_INET6, dev, (union inet_addr *)solicited_addr);
    if (ifa) {
        src_addr = solicited_addr;
        inet_addr_ifa_put(ifa);
    } else {
        return NULL;
    }

    memset(&icmp6h, 0, sizeof(icmp6h));
    icmp6h.icmp6_type = ND_NEIGHBOR_ADVERT;
    if (solicited)
        icmp6h.icmp6_pptr |= ND_NA_FLAG_SOLICITED;
    if (override)
        icmp6h.icmp6_pptr |= ND_NA_FLAG_OVERRIDE;

    /*ndisc*/
    mbuf = ndisc_build_mbuf_graph(dev, daddr, src_addr, &icmp6h, solicited_addr,
                                     inc_opt ? ND_OPT_TARGET_LINKADDR : 0,
                                     vrrp_node);
    if (!mbuf)
        return NULL;

    hdr = (void *)rte_pktmbuf_prepend(mbuf, sizeof(*hdr));
    if (unlikely(!hdr)) {
        return mbuf;
    }

    memset(hdr, 0, sizeof(*hdr));
    hdr->ip6_vfc    = 0x60;
    /*
     * na packet do not need to set tos and flow-lable
    hdr->ip6_flow  |= htonl(((uint64_t)fl6->fl6_tos<<20) | \
                            (ntohl(fl6->fl6_flow)&0xfffffUL));
    */
    hdr->ip6_plen   = htons(mbuf->pkt_len - sizeof(*hdr));
    hdr->ip6_nxt    = IPPROTO_ICMPV6;
    hdr->ip6_hlim   = 255;
    hdr->ip6_src    = *src_addr;
    hdr->ip6_dst    = *daddr;
    return mbuf;
}

static int 
ndisc_recv_ns_graph(struct rte_mbuf *mbuf, 
                    struct netif_port *dev, 
                    uint32_t table_id,
                    struct rte_graph *graph, 
                    struct rte_node *node)
{
    uint8_t *lladdr = NULL;
    struct ndisc_options ndopts;
    struct neigh_entry *neigh;
    struct inet_ifaddr *ifa = NULL;
    int inc = 0;
    uint32_t ndoptlen = 0;
    struct rte_mbuf *mbuf2;

    struct in6_addr *saddr = &((struct ip6_hdr *)mbuf_userdata_get(mbuf))->ip6_src;
    struct in6_addr *daddr = &((struct ip6_hdr *)mbuf_userdata_get(mbuf))->ip6_dst;

    struct nd_msg *msg = rte_pktmbuf_mtod(mbuf, struct nd_msg *);
    int dad = ipv6_addr_any(saddr);

#ifdef CONFIG_NDISC_DEBUG
    ndisc_show_addr(__func__, saddr, daddr);
#endif

    if (mbuf_may_pull(mbuf, sizeof(struct nd_msg)))
        return IP6_ICMP_NEXT_DROP;

    ndoptlen = mbuf->data_len - offsetof(struct nd_msg, opt);

    if (ipv6_addr_is_multicast(&msg->target)) {
        return IP6_ICMP_NEXT_DROP;
    }

    if (dad && !ipv6_addr_is_solict_mult(daddr)) {
        return IP6_ICMP_NEXT_DROP;
    }

    if (!ndisc_parse_options(msg->opt, ndoptlen, &ndopts)) {
        return IP6_ICMP_NEXT_DROP;
    }

    uint8_t not_vrrp_flag = 1;
    struct vrrp_entry *vrrp_node = NULL;

    vrrp_node = lookup_vrrp_ip(
        (union inet_addr*)&msg->target, AF_INET6);
    if (vrrp_node) {
        if (vrrp_node->status == VRRP_ST_SLAVE) {
            L3_DEBUG_TRACE(L3_ERR, "%s:is vrrp slave,drop!!!\n",
                __FUNCTION__);
            return IP6_ICMP_NEXT_DROP;
        } else if (vrrp_node->status == VRRP_ST_MASTER) {
            not_vrrp_flag = 0;
        }
    }

    if (not_vrrp_flag) {
        vrrp_node = NULL;
        ifa = inet_addr_ifa_get(AF_INET6, dev,
            (union inet_addr *)&msg->target);
        if (!ifa) {
            return IP6_ICMP_NEXT_DROP;
        }
    }

    if (ndopts.nd_opts_src_lladdr) {
        lladdr = ndisc_opt_addr_data(ndopts.nd_opts_src_lladdr, dev);
        if (!lladdr) {
            inet_addr_ifa_put(ifa);
            return IP6_ICMP_NEXT_DROP;
        }
        /*
         * RFC2461 7.1.1:
         * IP source address should not be unspecified address in NS
         * if ther is source link-layer address option in the message
         */
        if (dad) {
            inet_addr_ifa_put(ifa);
            return IP6_ICMP_NEXT_DROP;
        }
    } else {
        /* ingnore mbuf without opt */
        inet_addr_ifa_put(ifa);
        return IP6_ICMP_NEXT_DROP;
    }

    inc = ipv6_addr_is_multicast(daddr);

    /*
     * dad response src_addr should be link local, daddr should be multi ff02::1
     * optimistic addr not support
     */
    if (dad) {
        if (ifa->flags & (IFA_F_TENTATIVE | IFA_F_OPTIMISTIC)) {
            inet_ifaddr_dad_failure(ifa);
            inet_addr_ifa_put(ifa);
            return IP6_ICMP_NEXT_DROP;
        }
        /* 
         * comment it out in advance
        ndisc_send_na(dev, &in6addr_linklocal_allnodes, &msg->target, 0, 1, 1);
        */
        inet_addr_ifa_put(ifa);
        return IP6_ICMP_NEXT_DROP;
    }

    inet_addr_ifa_put(ifa);

    /* update/create neighbour */
    neigh = neigh_lookup(table_id, AF_INET6, (union inet_addr *)saddr);
    if (neigh && !(neigh->flag & NEIGH_STATIC)) {
        rte_memcpy(&neigh->d_mac, lladdr, 6);
        neigh_entry_state_trans_graph(neigh, 1);
        neigh_sync_core((void *)neigh, 1, NEIGH_GRAPH);
    } else {
        neigh = neigh_add_tbl(table_id, AF_INET6, 
                              (union inet_addr *)saddr,
                              (struct rte_ether_addr *)lladdr, 
                              dev, 0);
        if (!neigh){
            return IP6_ICMP_NEXT_DROP;
        }
        neigh_entry_state_trans_graph(neigh, 1);
        neigh_sync_core((void *)neigh, 1, NEIGH_GRAPH);
    }
    /* 
     * we temporarily restrain sending the neighbor mbuf list
    neigh_send_mbuf_cach_graph(neigh);
    */

    mbuf2 = ndisc_send_na_graph(dev, saddr, &msg->target,
                            1, inc, inc, vrrp_node);

    if (!mbuf2) {
        return IP6_ICMP_NEXT_DROP;
    }
    neigh_populate_mac(neigh, mbuf2, dev, AF_INET6);
    mbuf2->l2_len = sizeof(struct rte_ether_hdr);
    mbuf2->l3_len = sizeof(struct ip6_hdr);
    /* set out port to L2 */
    mbuf_dev_set(mbuf2, dev);
    /* copy mbuf header info */
    pktmbuf_copy_hdr(mbuf2, mbuf);
    if (GET_MBUF_PRIV_DATA(mbuf2)->priv_data_is_vxlan) {
        rte_node_enqueue_x1(graph, node, IP6_ICMP_NEXT_VXLAN, mbuf2);
    } else {
        rte_node_enqueue_x1(graph, node, IP6_ICMP_NEXT_L2, mbuf2);
    }

    return IP6_ICMP_NEXT_DROP;
}

static int 
ndisc_recv_na_graph(struct rte_mbuf *mbuf, 
                    struct netif_port *dev,
                    uint32_t table_id,
                    struct rte_graph *graph, 
                    struct rte_node *node)
{
    uint8_t *lladdr = NULL;
    struct ndisc_options ndopts;
    struct neigh_entry *neigh;
    struct inet_ifaddr *ifa;
    struct in6_addr *daddr = &((struct ip6_hdr *)mbuf_userdata_get(mbuf))->ip6_dst;
    struct nd_msg *msg = rte_pktmbuf_mtod(mbuf, struct nd_msg *);
    uint32_t ndoptlen = mbuf->data_len - offsetof(struct nd_msg, opt);

#ifdef CONFIG_NDISC_DEBUG
    struct in6_addr *saddr = &((struct ip6_hdr *)mbuf_userdata_get(mbuf))->ip6_src;
    ndisc_show_addr(__func__, saddr, daddr);
#endif

    if (mbuf_may_pull(mbuf, sizeof(struct nd_msg))) {
        return IP6_ICMP_NEXT_DROP;
    }

    if (ipv6_addr_is_multicast(&msg->target)) {
        return IP6_ICMP_NEXT_DROP;
    }

    if (ipv6_addr_is_multicast(daddr) && (msg->icmph.icmp6_pptr & ND_NA_FLAG_SOLICITED)) {
        return IP6_ICMP_NEXT_DROP;
    }

    if (!ndisc_parse_options(msg->opt, ndoptlen, &ndopts)) {
        return IP6_ICMP_NEXT_DROP;
    }

    ifa = inet_addr_ifa_get(AF_INET6, dev, (union inet_addr *)&msg->target);
    if (ifa) {
        if (ifa->flags & (IFA_F_TENTATIVE | IFA_F_OPTIMISTIC)) {
            inet_ifaddr_dad_failure(ifa);
        }
        inet_addr_ifa_put(ifa);
        return IP6_ICMP_NEXT_DROP;
    }

    if (ndopts.nd_opts_tgt_lladdr) {
        lladdr = ndisc_opt_addr_data(ndopts.nd_opts_tgt_lladdr, dev);
        if (!lladdr) {
            return IP6_ICMP_NEXT_DROP;
        }
    } else {
        /* ingnore mbuf without opt */
        return IP6_ICMP_NEXT_DROP;
    }

#ifdef CONFIG_NDISC_DEBUG
    ndisc_show_target(__func__, &msg->target, lladdr, dev);
#endif

    /* notice: override flag ignored */
    neigh = neigh_lookup(table_id, AF_INET6, (union inet_addr *)&msg->target);
    if (neigh && !(neigh->flag & NEIGH_STATIC)) {
        rte_memcpy(&neigh->d_mac, lladdr, 6);
        neigh_entry_state_trans_graph(neigh, 1);
        neigh_sync_core((void *)neigh, 1, NEIGH_GRAPH);
    } else {
        neigh = neigh_add_tbl(table_id, AF_INET6, 
                              (union inet_addr *)&msg->target,
                              (struct rte_ether_addr *)lladdr, 
                              dev, 0);
        if (!neigh) {
           return IP6_ICMP_NEXT_DROP;
        }
        neigh_entry_state_trans_graph(neigh, 1);
        neigh_sync_core((void *)neigh, 1, NEIGH_GRAPH);
    }
    neigh_send_mbuf_cach_graph(neigh);

    return IP6_ICMP_NEXT_DROP;
}

static int 
ndisc_rcv_graph(struct rte_mbuf *mbuf, 
                struct netif_port *dev, 
                struct rte_graph *graph, 
                struct rte_node *node)
{
    struct nd_msg *msg;
    int ret = IP6_ICMP_NEXT_DROP;
    struct ip6_hdr *ipv6_hdr = mbuf_userdata_get(mbuf);
    uint32_t table_id = GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id;

    if (mbuf_may_pull(mbuf, sizeof(struct icmp6_hdr)) != 0) {
        return IP6_ICMP_NEXT_DROP;
    }

    msg = (struct nd_msg *)rte_pktmbuf_mtod(mbuf, struct nd_msg *);

    if (ipv6_hdr->ip6_hlim != 255) {
        return IP6_ICMP_NEXT_DROP;
    }

    if (msg->icmph.icmp6_code != 0) {
        return IP6_ICMP_NEXT_DROP;
    }

    switch (msg->icmph.icmp6_type) {
    case ND_NEIGHBOR_SOLICIT:
        ret = ndisc_recv_ns_graph(mbuf, dev, table_id, graph, node);
        break;

    case ND_NEIGHBOR_ADVERT:
        ret = ndisc_recv_na_graph(mbuf, dev, table_id, graph, node);
        break;

    /* not support yet */
    case ND_ROUTER_SOLICIT:
    case ND_ROUTER_ADVERT:
    case ND_REDIRECT:
    default:
        break;
    }

    return ret;
}

extern uint16_t
icmp6_csum(struct ip6_hdr *iph, struct icmp6_hdr *ich);

static __rte_always_inline uint16_t
ip6_icmp(s_nc_param_l3 *param)
{
    struct rte_mbuf *mbuf = param->mbuf;
    struct rte_node *node = param->node;
    struct rte_graph *graph = param->graph;
    struct ip6_hdr *iph = mbuf_userdata_get(mbuf);
    struct icmp6_hdr *ich;

    assert(iph);

    if (mbuf_may_pull(mbuf, sizeof(struct icmp6_hdr)) != 0)
        goto drop;

    ich = rte_pktmbuf_mtod(mbuf, struct icmp6_hdr *);
    if (unlikely(!ich))
        goto drop;

    if (mbuf_may_pull(mbuf, mbuf->pkt_len) != 0)
        goto drop;

    if (icmp6_csum(iph, ich) != 0xffff)
        goto drop;

#ifdef CONFIG_DPVS_ICMP_DEBUG
    icmp6_dump_hdr(mbuf);
#endif
    switch (ich->icmp6_type) {
        case ICMP6_ECHO_REQUEST:
            /* make flow handle icmp6 ping */
            rte_pktmbuf_prepend(mbuf, mbuf->l3_len);
            return IP6_ICMP_NEXT_ICMP_PING_FORWARD;

        case ND_ROUTER_SOLICIT:
        case ND_ROUTER_ADVERT:
        case ND_NEIGHBOR_SOLICIT:
        case ND_NEIGHBOR_ADVERT:
        case ND_REDIRECT:
            return ndisc_rcv_graph(mbuf, netif_port_get(mbuf->port), graph, node);

        default :
            break;
    }

drop:
    return IP6_ICMP_NEXT_DROP;
}


static uint16_t
ip6_icmp_node_process(struct rte_graph *graph, 
                              struct rte_node *node,
                              void **objs, 
                              uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs, 
        nb_objs, IP6_ICMP_NEXT_DROP, ip6_icmp);
}

struct rte_node_register ip6_icmp_node = {
	.process = ip6_icmp_node_process,
	.name = NODE_NAME_ICMP6,
	.nb_edges = IP6_ICMP_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[IP6_ICMP_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[IP6_ICMP_NEXT_ICMP_PING_FORWARD] = NODE_NAME_IP6_FORWARD,
		[IP6_ICMP_NEXT_VXLAN] = NODE_NAME_VXLAN_SEND,
		[IP6_ICMP_NEXT_L2] = NODE_NAME_L2_OUT,
    },
};
RTE_NODE_REGISTER(ip6_icmp_node);

