/*
 * Copyright (C) 2021 TYyun.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <unistd.h>
#include <stdint.h>
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
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "ipv6.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "flow.h"
#include "flow_v6.h"
#include "debug_flow.h"
#include "flow_cli.h"
#include "flow_profile.h"
#include "route6.h"
#include "icmp6.h"
#include "flow_frag.h"
#include "l3_node_priv.h"
#include "route6_priv.h"

flow_vector_t flow_first_vector_list_v6[] =
{
    flow_first_sanity_check_v6,
    flow_first_hole_search_v6,
    flow_first_routing_v6,
    flow_first_for_self_v6,
    flow_first_alloc_connection,
    flow_first_fw_entry,
    NULL
};

flow_vector_t flow_fast_vector_list_v6[] =
{
    flow_fast_for_self_v6,
    flow_fast_check_routing_v6,
    flow_fast_reinject_out_v6,
    flow_fast_fw_entry,
#ifdef TYFLOW_LEGACY
    flow_fast_send_out_v6,
#endif
    NULL
};

flow_vector_t flow_ipv6_vector_list[] = 
{
    flow_parse_vector_v6,
    flow_filter_vector_v6,
#ifdef TYFLOW_PER_THREAD
    flow_fwd_vector,
#endif
    flow_decap_vector_v6,
    flow_main_body_vector,
    NULL
};

/* mask for ICMP6 message class */
#define ICMP6_TYPE_CLASS_MASK       0x80
/* ICMP6 error message */
#define is_icmp6_err_msg(type)      (!((type) & ICMP6_TYPE_CLASS_MASK))
/* ICMP6 informational message */
#define is_icmp6_info_msg(type)     ((type) & ICMP6_TYPE_CLASS_MASK)

/*
 * use seq number in icmp req, and id number in icmp rsp.
 * returns - the src port number in network byte order.
 */
static inline int ping6_src_port(struct icmp6_hdr *icmp6)
{
    if (icmp6->icmp6_type == ICMP6_ECHO_REQUEST)
        return icmp6->icmp6_seq;
    else if (icmp6->icmp6_type == ICMP6_ECHO_REPLY)
        return icmp6->icmp6_id;
    return 0;
}

/*
 * use id number in icmp req, and seq number in icmp rsp.
 * returns - the dst port number in network byte order.
 */
static inline int ping6_dst_port(struct icmp6_hdr *icmp6)
{
    if (icmp6->icmp6_type == ICMP6_ECHO_REQUEST)
        return icmp6->icmp6_id;
    else if (icmp6->icmp6_type == ICMP6_ECHO_REPLY)
        return icmp6->icmp6_seq;
    return 0;
}

/* Forms ports for ICMP req/resp packets. */
static inline uint32_t 
icmp6_ping_ports_form (struct icmp6_hdr *icmp6)
{
    if (RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN)
        return (ping6_dst_port(icmp6) << 16) | ping6_src_port(icmp6);
    else 
        return (ping6_src_port(icmp6) << 16) | ping6_dst_port(icmp6);
}

/* To ensure proper endianness use icmp_ping_ports_form to extract src/
 * dst ports from the value returned by this function. */
int 
icmp6_ports (struct icmp6_hdr *icmp6)
{
	if (icmp6->icmp6_type == ICMP6_ECHO_REQUEST || 
        icmp6->icmp6_type == ICMP6_ECHO_REPLY) {
        return icmp6_ping_ports_form(icmp6);
	}

	/*
	 * the following value needs to be consistent with default
	 * return value of ip_proto_ports().
	 */
	return htonl(0x00010001);
}

static void 
swap_ip_port_v6 (MBUF_IP_HDR_S *lhdr)
{
    struct in6_addr value;
    uint16_t port;

    ipv6_addr_copy(&value, (struct in6_addr *)lhdr->lhdr_src_ip_6);
    ipv6_addr_copy((struct in6_addr *)lhdr->lhdr_src_ip_6, (struct in6_addr *)lhdr->lhdr_dst_ip_6);
    ipv6_addr_copy((struct in6_addr *)lhdr->lhdr_dst_ip_6, &value);
    port = lhdr->lhdr_src_port;
    lhdr->lhdr_src_port = lhdr->lhdr_dst_port;
    lhdr->lhdr_dst_port = port;
}

/* return value:
 * 0: everything is parsed okay, can continue processing.
 * -1: something is not right in the header
 */
static int 
ip6hdr_info_extract(struct ip6_hdr *iphdr, MBUF_IP_HDR_S *lhdr, uint32_t l3_len) 
{
    int done = 0, rc = -1, other_headers = 0;
    uint32_t ext_len, ports;
    uint8_t next_prot, *pd, *plimit;

    ipv6_addr_copy((struct in6_addr *)lhdr->lhdr_src_ip_6, &iphdr->ip6_src);
    ipv6_addr_copy((struct in6_addr *)lhdr->lhdr_dst_ip_6, &iphdr->ip6_dst);

    next_prot = iphdr->ip6_nxt;
    ext_len = sizeof(struct rte_ipv6_hdr);
    pd = (uint8_t *)iphdr;
    plimit = pd + l3_len;
    do {
        pd += ext_len;
    	switch (next_prot) {
            case IPPROTO_TCP:
            case IPPROTO_UDP:
            case IPPROTO_ESP:
                lhdr->ucNextHdr = next_prot;
                ports = *((uint32_t *)pd);
                lhdr->lhdr_src_port = ip_src_port(ports);
                lhdr->lhdr_dst_port = ip_dst_port(ports);
				rc = 0;
				done = 1;
				break;
            case IPPROTO_AH:
                lhdr->ucNextHdr = next_prot;
				 /* spi of AH is the second int of the header */
                ports = *((uint32_t *)pd+1);
                lhdr->lhdr_src_port = ip_src_port(ports);
                lhdr->lhdr_dst_port = ip_dst_port(ports);
				rc = 0;
				done = 1;
				break;
            case IPPROTO_ICMPV6:
                {
                    struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)pd;
                    lhdr->ucNextHdr = next_prot;
                    if (icmp6->icmp6_type == ICMP6_ECHO_REQUEST  ||
                        icmp6->icmp6_type == ICMP6_ECHO_REPLY) {
                        ports = icmp6_ping_ports_form(icmp6);
                        lhdr->lhdr_src_port = ip_src_port(ports);
                        lhdr->lhdr_dst_port = ip_dst_port(ports);
                        lhdr->lhdr_icmp_id = icmp6->icmp6_id;
                    } else if (!(icmp6->icmp6_type & ICMP6_INFOMSG_MASK)) {
                        lhdr->ucIsIcmpErr = 1;
                    }
                    lhdr->lhdr_icmp_type = icmp6->icmp6_type;
                    lhdr->lhdr_icmp_code = icmp6->icmp6_code;
                    rc = 0;
                    done = 1;
                    break;
                }
            case IPPROTO_HOPOPTS:
                /* per RFC2460, 
                 * hop-by-hop extensions can only appear right after
                 * ipv6 header and before any other extension headers
                 */
                if (other_headers == 1) {
                    rc = -1;
                    done = 1;
                    this_flow_counter[FLOW_ERR_PARSE_IPV6_HBH].counter++;
                    break;
                }
                next_prot = rte_ipv6_get_next_ext(pd, next_prot, (size_t *)(&ext_len));
                break;
            case IPPROTO_ROUTING:
            case IPPROTO_DSTOPTS:
                other_headers = 1;
                next_prot = rte_ipv6_get_next_ext(pd, next_prot, (size_t *)(&ext_len));
                break;
            case IPPROTO_FRAGMENT:
            {
                struct ip6_frag *frag;
                other_headers = 1;
                next_prot = rte_ipv6_get_next_ext(pd, next_prot, (size_t *)(&ext_len));
                lhdr->ucIsFragment = 1;
                frag = (struct ip6_frag *)pd;
                lhdr->ucIsFirstFrag = !(frag->ip6f_offlg & IP6F_OFF_MASK);
                lhdr->ucIsLastFrag  = !(frag->ip6f_offlg & IP6F_MORE_FRAG);
                lhdr->ipid = frag->ip6f_ident;
                /* if it is not the first fragment, the upper layer protocol
                 * is the only field deserving to obtain */
                if (!lhdr->ucIsFirstFrag) {
                    lhdr->ucNextHdr = next_prot;
                    rc = 0;
                    done = 1;
                    /* shift the packet data since we need to set lhdr->iptr */
                    pd += ext_len;
                }
                break;
            }
            /* per RFC 8200 section 4.7
             * these octets after next header 59 must be ignored and passed on
             * that is we have no idea about the content means, 
             * so we shall not pick the ports info from the successive bytes, 
             * instead we use a pair of specific number in case to create many connections
             */
            case IPPROTO_NONE:
                lhdr->ucNextHdr = next_prot;
                lhdr->lhdr_src_port = htons(0x0001);
                lhdr->lhdr_dst_port = htons(0x0001);
				rc = 0;
				done = 1;
				break;
            default:
                /* per RFC 4443 section 2.4
                 * In cases where it is not possible to retrieve the upper-layer
                 * protocol type from the ICMPv6 message, the ICMPv6 message is
                 * silently dropped after any IPv6-layer processing.
                 */
                lhdr->ucNextHdr = 0xff;
                lhdr->lhdr_src_port = htons(0x0001);
                lhdr->lhdr_dst_port = htons(0x0001);
                rc = -1;
                done = 1;
                this_flow_counter[FLOW_ERR_PARSE_NO_SUPPORT_PROT].counter++;
                break;
        }
    } while(!done && pd+ext_len <= plimit);

    if (rc == 0) {
        lhdr->iptr = (uint32_t *)pd;
    }
    return rc;
}

/*
 * generate iphdr and ports info of icmp6 error message for flow connection lookup
 * lhdr hold the extern ip header and will be rewritten to the intern one
 */
static int
gen_icmp6_lookup_info (struct ip6_hdr *iphdr, 
                       uint32_t *iptr, 
                       MBUF_IP_HDR_S *lhdr,
                       int *icmp_err)
{
    int rc;
    struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)iptr;
    struct ip6_hdr *iphdr_inner;

    if (is_icmp6_err_msg(icmp6->icmp6_type)) {
        *icmp_err = 1;
        iphdr_inner = (struct ip6_hdr *)(icmp6 + 1);
        if ((flow_debug_flag & FLOW_DEBUG_DETAIL) &&
            this_ffilter_show_this_pak > 0) {
            flow_debug_trace_no_flag("  icmp6 embed extern: \n");
            flow_print_packet_any((void *)iphdr, sizeof(struct rte_ipv6_hdr));
            flow_print_packet_any((void *)icmp6, sizeof(struct icmp6_hdr));
        }
        /*
         * if the embedded packet is not an IPv6 packet, the
         * whole packet should be dropped.
         */
        if ((iphdr_inner->ip6_vfc & htonl(0xf0)) != 6) {
            this_flow_counter[FLOW_ERR_PARSE_ICMP_HEADER].counter++;
            return -1;
        }
        rc = ip6hdr_info_extract(iphdr_inner, lhdr, ntohs(iphdr_inner->ip6_plen));
        if (!rc) {
            swap_ip_port_v6(lhdr);
            if ((flow_debug_flag & FLOW_DEBUG_DETAIL) &&
                this_ffilter_show_this_pak > 0) {
                flow_debug_trace_no_flag("  intern: \n");
                flow_print_packet_any((void *)iphdr_inner, sizeof(struct rte_ipv6_hdr));
                flow_debug_trace_no_flag("  %d, %d, %d: \n", 
                                         ntohs(lhdr->lhdr_src_port), 
                                         ntohs(lhdr->lhdr_dst_port), 
                                         lhdr->ucNextHdr);
            }
        } else {
            return -1;
        }
    }
    return 0;
}

/*
 * hash packet for nat session block.
 */
static inline uint32_t
conn_hash_v6(uint32_t *src_addr, uint32_t *dst_addr, uint32_t ports)
{
    register uint32_t value;

    value  = _conn_hash(src_addr[0], dst_addr[0], src_addr[1]);
    value ^= _conn_hash(dst_addr[1], src_addr[2], dst_addr[2]);
    value ^= _conn_hash(src_addr[3], dst_addr[3], ports);

    return (value & FLOW_CONN_HASH_TAB_MASK);
}

void
add_to_conn_hash_v6(conn_sub_t *csp)
{
	int hash_value;
    uint32_t cnt;
	flow_connection_t *fcp = csp2base(csp);

    clr_csp_invalid(csp);
	hash_value = conn_hash_v6(&csp->csp_src_ip, &csp->csp_dst_ip, *(uint32_t *)&csp->csp_src_port);

    fcc_rwl_write_lock(hash_value);
    hlist_add_head(&csp->hnode, &((this_flow_conn_hash_base+hash_value)->hash_base));
    fcc_rwl_write_unlock(hash_value);

    cnt = rte_atomic32_add_return(&((this_flow_conn_hash_base+hash_value)->conn_cnt), 1);
    if (flow_debug_flag & FLOW_DEBUG_BASIC) {
        char saddr[INET6_ADDRSTRLEN], daddr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &csp->csp_src_ip, saddr, sizeof(saddr));
        inet_ntop(AF_INET6, &csp->csp_dst_ip, daddr, sizeof(daddr));
        flow_print("++ csp add %d/%d(0x%llx): %s/%d->%s/%d,%d, time %d, cspflag 0x%x\n",
                   hash_value, cnt, csp, 
                   saddr, ntohs(csp->csp_src_port),
                   daddr, ntohs(csp->csp_dst_port),
                   csp->csp_proto, fcp->time, csp->cspflag);
    }
}

void
del_from_conn_hash_v6(conn_sub_t *csp)
{
	int hash_value;
    uint32_t cnt;
	flow_connection_t *fcp = csp2base(csp);

	hash_value = conn_hash_v6(&csp->csp_src_ip, &csp->csp_dst_ip, *(uint32_t *)&csp->csp_src_port);

    fcc_rwl_write_lock(hash_value);
    hlist_del(&csp->hnode);
    fcc_rwl_write_unlock(hash_value);

    cnt = rte_atomic32_sub_return(&((this_flow_conn_hash_base+hash_value)->conn_cnt), 1);
    if (flow_debug_flag & FLOW_DEBUG_AGER) {
        char saddr[INET6_ADDRSTRLEN], daddr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &csp->csp_src_ip, saddr, sizeof(saddr));
        inet_ntop(AF_INET6, &csp->csp_dst_ip, daddr, sizeof(daddr));
        flow_debug_trace_no_flag("-- csp del %d/%d(0x%llx): %s/%d->%s/%d,%d, time %d, cspflag 0x%x\n",
                                 hash_value, cnt, csp, 
                                 saddr, ntohs(csp->csp_src_port),
                                 daddr, ntohs(csp->csp_dst_port),
                                 csp->csp_proto, flow_get_fcp_time(fcp), csp->cspflag);
    }
}

#define FOR_ALL_CSP_V6(node, src_adr, dst_adr, ports, head, csp, hash, cnt) \
    hash = conn_hash_v6((uint32_t *)src_adr, (uint32_t *)dst_adr, ports);   \
    fcc_rwl_read_lock(hash);                                                \
    FOR_ALL_CSP2(node, src_adr, dst_adr, ports, head, csp, hash, cnt)

conn_sub_t *
flow_find_connection_by_key_v6(csp_key_t *key)
{
    int cnt, hash, i;
    struct hlist_node *node;
	conn_sub_t *csp = NULL, *head;
    flow_connection_t *fcp = NULL;

    FOR_ALL_CSP_V6(node, &key->src_ip, &key->dst_ip, *(uint32_t *)(&key->src_port), head, csp, hash, cnt) {
        if (CONN_SUB_COMP_V6(csp, key)) {
            fcp = csp2base(csp);
            if ((fcp->fcflag & FC_INVALID) == 0) {
                break;
            } else {
                fcp = NULL;
            }
        }
        if (!(++i & 0x7F) && is_connection_list_loop(cnt, i, head)) {
            break;
        }
    }
    FOR_ALL_CSP_END(hash);
    return fcp?csp:NULL;
}

/*
 * find a match session for ipv6 .
 */
int
flow_find_connection_v6(struct rte_mbuf *mbuf)
{
	flow_vector_t *vector;
	int rc;
	conn_sub_t *csp = NULL;
    flow_connection_t *fcp = NULL;
    csp_key_t key = {0};
    MBUF_S *lbuf = mbuf_from_rte_mbuf(mbuf);
    MBUF_IP_HDR_S *lhdr = &lbuf->stIpHdr;

    ipv6_addr_copy((struct in6_addr *)&key.src_ip, (struct in6_addr *)lhdr->lhdr_src_ip_6);
    ipv6_addr_copy((struct in6_addr *)&key.dst_ip, (struct in6_addr *)lhdr->lhdr_dst_ip_6);
    key.src_port = lhdr->lhdr_src_port;
    key.dst_port = lhdr->lhdr_dst_port;
    key.proto = lhdr->ucNextHdr;
    key.token = GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id;

    csp = flow_find_connection_by_key_v6(&key);
    fcp = csp?csp2base(csp):NULL;

    if (fcp) {
        flow_print_basic("  existing connection found. id %d\n", fcp2id(fcp));
        SET_CSP_TO_MBUF(mbuf, csp);
        if (IS_CSP_DISABLE(csp)) {
            /* do something */
        }
    } else {
        if (SESSION_MBUF_HAVE_FLAG(lbuf, SESSION_MBUF_ICMPERR)) {
            flow_print_basic("  icmp error packet match no connection\n");
            return FLOW_RET_ERR;
        }
        /* 
         * first pak, try to creat a new one 
         */
        flow_print_basic("  no connection found\n");

        /*
         * keep original vector list
         */
        vector = this_flow_vector_list;
        flow_set_pak_vector(flow_first_vector_list_v6);
        flow_first_fcp_crt_init(mbuf, lhdr);
        rc = flow_proc_first_pak(mbuf);
        /* restor vector list */
        flow_set_pak_vector(vector);
        if (rc) {
            return rc;
        }

        flow_first_install_connection(mbuf);
    }
    return 0;
}

int 
flow_first_sanity_check_v6(struct rte_mbuf *mbuf)
{
    VECTOR_PROFILE(flow_first_sanity_check_v6);
    flow_print_basic("  %s entry\n", __FUNCTION__);
    return flow_next_pak_vector(mbuf);
}

int 
flow_first_hole_search_v6(struct rte_mbuf *mbuf)
{
    VECTOR_PROFILE(flow_first_hole_search_v6);
    flow_print_basic("  %s entry\n", __FUNCTION__);
    return flow_next_pak_vector(mbuf);
}

extern struct route6 *route6_input(const struct rte_mbuf *mbuf, struct flow6 *fl6);
int
flow_first_routing_v6(struct rte_mbuf *mbuf)
{
#ifndef TYFLOW_LEGACY
    struct route6_entry *rt = NULL;
#else 
    struct route6 *rt = NULL;
#endif
    MBUF_S *lbuf = mbuf_from_rte_mbuf(mbuf);;
    MBUF_IP_HDR_S *lhdr = &lbuf->stIpHdr;
    struct flow6 fl6;
    conn_sub_t *csp, *peer;

    VECTOR_PROFILE(flow_first_routing_v6);

#ifndef TYFLOW_LEGACY
    rt = (struct route6_entry *)GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route;
    fl6.fl6_iif   = netif_port_get(mbuf->port);
#else
    memset(&fl6, 0, sizeof(fl6));
    fl6.fl6_iif   = netif_port_get(mbuf->port);
    ipv6_addr_copy(&fl6.fl6_daddr, (struct in6_addr *)lhdr->lhdr_dst_ip_6);
    ipv6_addr_copy(&fl6.fl6_saddr, (struct in6_addr *)lhdr->lhdr_src_ip_6);
    fl6.fl6_proto = lhdr->ucNextHdr;
    rt = route6_input(mbuf, &fl6);
#endif
    if (!rt) {
        flow_print_basic("  no route to 0x%x:%x:%x:%x:%x:%x:%x:%x\n", 
                         ntohl(lhdr->lhdr_dst_ip_6_0),
                         ntohl(lhdr->lhdr_dst_ip_6_1),
                         ntohl(lhdr->lhdr_dst_ip_6_2),
                         ntohl(lhdr->lhdr_dst_ip_6_3));
        this_flow_counter[FLOW_ERR_NO_ROUTE].counter++;
        return FLOW_RET_ERR;
    } else if (!rt->rt6_dev) {
        flow_print_basic("  route 0x%llx have no interface\n", rt);
        this_flow_counter[FLOW_ERR_NO_ROUTE_IFP].counter++;
        return FLOW_RET_ERR;
    }

    csp = GET_CSP_FROM_MBUF(mbuf);
    peer = csp2peer(csp);
    peer->route = rt;
#ifndef TYFLOW_LEGACY
    graph_route6_get(rt);
#endif
    peer->ifp = rt->rt6_dev;

    flow_print_basic("  routed(0x%x.%x.%x.%x) from %s to %s\n", 
                     ntohl(lhdr->lhdr_dst_ip_6_0),
                     ntohl(lhdr->lhdr_dst_ip_6_1),
                     ntohl(lhdr->lhdr_dst_ip_6_2),
                     ntohl(lhdr->lhdr_dst_ip_6_3),
                     fl6.fl6_iif->name,
                     rt->rt6_dev->name);

    return flow_next_pak_vector(mbuf);
}

static int
is_for_ping6(MBUF_IP_HDR_S *lhdr)
{
    /* currently only support ping
     * need to add more and make it dynamic register */
    if (lhdr->ucNextHdr == IPPROTO_ICMPV6 &&
        lhdr->lhdr_icmp_type == ICMP6_ECHO_REQUEST) {
        if (is_ping_on_()) {
            /* todo
             * better to create a to-self session here
             */
            return 1;
        }
    }
    return 0;
}

static int
is_for_nd(MBUF_IP_HDR_S *lhdr)
{
    /* currently only support ping
     * need to add more and make it dynamic register */
    if (lhdr->ucNextHdr == IPPROTO_ICMPV6 &&
        (lhdr->lhdr_icmp_type == ND_NEIGHBOR_SOLICIT ||
         lhdr->lhdr_icmp_type == ND_NEIGHBOR_ADVERT)) {
        return 1;
    }
    return 0;
}

static inline int 
modify_ipcksum (int cksum, ushort old, ushort new)
{
    cksum = cksum - (~old & 0xffff);
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum -= new;
    return (cksum >> 16) + (cksum & 0xffff);
}

static int
flow_reply_ping6(struct ip6_hdr *iph, struct rte_mbuf *mbuf)
{
    struct icmp6_hdr *icmp6;
    struct in6_addr value;
    MBUF_S *lbuf = mbuf_from_rte_mbuf(mbuf);
    MBUF_IP_HDR_S *lhdr = &lbuf->stIpHdr;

    ipv6_addr_copy(&value, &iph->ip6_src);
    ipv6_addr_copy(&iph->ip6_src, &iph->ip6_dst);
    ipv6_addr_copy(&iph->ip6_dst, &value);

    /* 
     * first fragment or non-fragment should make the icmp header as echo reply
     * non-first fragment will do nothing
     */
    if (!lhdr->ucIsFragment || lhdr->ucIsFirstFrag) {
        icmp6 = (struct icmp6_hdr *)lhdr->iptr;
        icmp6->icmp6_type = ICMP6_ECHO_REPLY;
        //icmp6_send_csum(iph, icmp6);
        icmp6->icmp6_cksum = modify_ipcksum(icmp6->icmp6_cksum, 
                                            htons(ICMP6_ECHO_REQUEST<<8),
                                            htons(ICMP6_ECHO_REPLY<<8));
    }

    return 0;
}

int
flow_first_for_self_v6(struct rte_mbuf *mbuf)
{
    MBUF_S *lbuf = mbuf_from_rte_mbuf(mbuf);
    MBUF_IP_HDR_S *lhdr = &lbuf->stIpHdr;
    conn_sub_t *csp = GET_CSP_FROM_LBUF(lbuf);
    conn_sub_t *host_csp = csp2peer(csp);
#ifndef TYFLOW_LEGACY
    struct route6_entry *rt = host_csp->route;
#else 
    struct route6 *rt = host_csp->route;
#endif
    int my_pak = 0;

    VECTOR_PROFILE(flow_first_for_self_v6);

    my_pak = rt->rt6_flags & RTF_LOCALIN;
    if (my_pak) {
        flow_print_basic("   the packet is destined to us\n");
        /* since we have no user-mode stack, we hack the icmp echo here
         * for other to-self packet, we just drop them, we may handle
         * later after having the user-mode stack
         */
        if (is_for_ping6(lhdr)) {
            csp = GET_CSP_FROM_MBUF(mbuf);
            csp->cspflag |= CSP_TO_SELF | CSP_TO_SELF_PING;
            host_csp = csp2peer(csp);
            host_csp->cspflag |= CSP_FROM_SELF;
            flow_print_basic("   to self ping6 handle with fcp\n");
            this_flow_counter[FLOW_BRK_TO_SELF].counter++;
        } else if (is_for_nd(lhdr)) {
            flow_print_basic("   to self nd handle with fcp\n");
        } else {
            flow_print_basic("   to self but not ready to handle, drop the packet\n");
            this_flow_counter[FLOW_ERR_TO_SELF_DROP].counter++;
            return FLOW_RET_ERR;
        }
    }
    return flow_next_pak_vector(mbuf);
}

int
flow_parse_vector_v6(struct rte_mbuf *mbuf)
{
    int rc, icmp_err = 0;
    struct ip6_hdr *iph;
    uint32_t iphdrlen;
    uint32_t *iptr;
    MBUF_S *lbuf;
    MBUF_IP_HDR_S *lhdr;

    VECTOR_PROFILE(flow_parse_vector_v6);

    lbuf = mbuf_from_rte_mbuf(mbuf);
    lhdr = &lbuf->stIpHdr;
    if (lhdr->ucFwd) {
        return flow_next_pak_vector(mbuf);
    }
    iph = ip6_hdr(mbuf);
    iphdrlen = mbuf->l3_len;
    iptr = rte_pktmbuf_mtod_offset(mbuf, uint32_t *, iphdrlen);

    rc = ip6hdr_info_extract(iph, lhdr, ntohs(iph->ip6_plen));
    if (rc) {
        return -1;
    }

    if (lhdr->ucIsIcmpErr) {
        rc = gen_icmp6_lookup_info(iph, iptr, lhdr, &icmp_err);
        if (rc) {
            this_flow_counter[FLOW_ERR_PARSE_ICMP_HEADER].counter++;
            return -1;
        }
    }
    flow_update_statistic(lhdr);

    return flow_next_pak_vector(mbuf);
}

int
flow_filter_vector_v6(struct rte_mbuf *mbuf)
{
    struct ip6_hdr *iph;
    MBUF_S *lbuf;
    MBUF_IP_HDR_S *lhdr;

    VECTOR_PROFILE(flow_filter_vector_v6);

    iph  = ip6_hdr(mbuf);
    lbuf = mbuf_from_rte_mbuf(mbuf);
    lhdr = &lbuf->stIpHdr;

    if (lhdr->ucFwd) {
        this_ffilter_show_this_pak = lhdr->ucMark;
    } else {
        flow_mark_pak(lhdr, 1);
    }
    flow_print_packet_v6(iph, ntohs(iph->ip6_plen));
    flow_print_basic("%s mark this packet.\n", __FUNCTION__);

    return flow_next_pak_vector(mbuf);
}

/*
 * flow decap vetor v6
 * in this vector we will handle tunnel decrypt & flow connection lookup
 */
int
flow_decap_vector_v6(struct rte_mbuf *mbuf)
{
    conn_sub_t *csp;
    flow_connection_t *fcp;
    uint32_t fcid;
    MBUF_S *lbuf;
    MBUF_IP_HDR_S *lhdr;

    VECTOR_PROFILE(flow_decap_vector_v6);

    flow_print_basic("%s entry\n", __FUNCTION__);
    lbuf = mbuf_from_rte_mbuf(mbuf);
    lhdr = &lbuf->stIpHdr;
    csp = GET_CSP_FROM_LBUF(lbuf);
    if (!csp) {
        /* ip non-first fragment */
        if (lhdr->ucIsFragment && !lhdr->ucIsFirstFrag) {
            flow_defrag_nonfirst_vector(mbuf);
            /* non-first fragment without csp will be dropped */
            csp = GET_CSP_FROM_LBUF(lbuf);
            if (!csp) {
                flow_print_basic("  non-first fragment packet do not have connection.\n");
                return -1;
            } else {
                flow_print_basic("  non-first fragment packet re-enter, fcp id %d\n", fcp2id(csp2base(csp)));
                return 0;
            }
        }
        if (flow_find_connection_v6(mbuf) < 0) {
            return -1;
        }
        if (lhdr->ucIsFragment && lhdr->ucIsFirstFrag) {
            /* 
             * for the first fragment, it's going to create fcb 
             * we do not check the rc since the following fragments
             * will not match the fcb and then be dropped always
             */
            flow_defrag_first_vector(mbuf);
        }
    } else {
        flow_print_basic("  flow packet already have connection.\n");
    }

    fcp = GET_FC_FROM_LBUF(lbuf);
    if (fcp == this_flow_conn_crt) {
        fcid = 0;
    } else {
        fcid = fcp2id(fcp);
        flow_refresh_connection(fcp);
    }
    flow_print_basic("  flow connection id %u\n", fcid);

    if (!is_tunnel_conn(fcp)) {
        return flow_next_pak_vector(mbuf);
    }

    return flow_tunnel_handling(mbuf);
}

int
flow_fast_for_self_v6(struct rte_mbuf *mbuf)
{
    conn_sub_t *csp, *peer;
    struct ip6_hdr *iph;

    VECTOR_PROFILE(flow_fast_for_self_v6);

    flow_print_basic(" %s entry.\n", __FUNCTION__);

    csp  = GET_CSP_FROM_MBUF(mbuf);
    peer = csp2peer(csp);
    if (csp->cspflag & CSP_TO_SELF_PING &&
        peer->cspflag & CSP_FROM_SELF) {
        iph = ip6_hdr(mbuf);

        flow_reply_ping6(iph, mbuf);
        SET_CSP_TO_MBUF(mbuf, peer);
    }

    return flow_next_pak_vector(mbuf);
}

int
flow_fast_check_routing_v6(struct rte_mbuf *mbuf)
{
    conn_sub_t *csp, *peer;
#ifndef TYFLOW_LEGACY
    struct route6_entry *rt = NULL;
#else
    struct route6 *rt = NULL;
    struct flow6 fl6;
#endif

    VECTOR_PROFILE(flow_fast_check_routing_v6);

    flow_print_basic(" %s entry.\n", __FUNCTION__);
    csp = GET_CSP_FROM_MBUF(mbuf);
    peer = csp2peer(csp);
#ifndef TYFLOW_LEGACY
    if (csp->cspflag & CSP_FROM_SELF &&
        peer->cspflag & CSP_TO_SELF_PING &&
        !peer->route) {
        rt = flow_route6_lookup(mbuf);
        flow_print_basic("  flow echo find route to %s\n",
                         rt?rt->rt6_dev->name:"null");
        peer->route = rt;
        peer->ifp = rt?rt->rt6_dev:NULL;
        return flow_next_pak_vector(mbuf);
    }
    rt = GET_MBUF_PRIV_DATA(mbuf)->p_priv_data_route;
#else
    memset(&fl6, 0, sizeof(fl6));
    ipv6_addr_copy(&fl6.fl6_daddr, (struct in6_addr *)&peer->csp_src_ip);
    rt = route6_output(mbuf, &fl6);
#endif
    if (peer->route != (void *)rt) {
        if (peer->route) {
            graph_route6_put(peer->route);
            peer->cspflag |= CSP_IFP_UPDATE;
            flow_print_basic("  csp update the ifp %s->%s\n", 
                             (peer->ifp)?peer->ifp->name:"uncertain", 
                             (rt->rt6_dev)?rt->rt6_dev->name:"uncertain");
        }

        peer->route = (void *)rt;
#ifndef TYFLOW_LEGACY
        graph_route6_get(rt);
#endif
        peer->ifp = rt->rt6_dev;
    }
#if FLOW_B4_FORWARD
    csp = GET_CSP_FROM_MBUF(mbuf);
    peer = csp2peer(csp);
    if (peer->route) {
        if (peer->route->rt6_dev == peer->ifp) {
            flow_print_basic("  csp had been set already %s\n", peer->ifp->name);
        } else {
            flow_print_basic("  csp update the ifp %s->%s\n", 
                       (peer->ifp)?peer->ifp->name:"uncertain", 
                       (peer->route->rt6_dev)?peer->route->rt6_dev->name:"uncertain");
            peer->ifp = peer->route->rt6_dev;
            peer->cspflag |= CSP_IFP_UPDATE;
        }
    } else {
#ifndef TYFLOW_LEGACY
        //rt = flow_route_lookup(mbuf, peer->csp_src_ip);
#else
        memset(&fl6, 0, sizeof(fl6));
        ipv6_addr_copy(&fl6.fl6_daddr, (struct in6_addr *)&peer->csp_src_ip);
        rt = route6_output(mbuf, &fl6);
#endif
        if (!rt) {
            flow_print_basic("  no reverse route to 0x%x.%x.%x.%x\n", 
                             ntohl(peer->csp_src_ip),
                             ntohl(peer->key.src_ip3[0]),
                             ntohl(peer->key.src_ip3[1]),
                             ntohl(peer->key.src_ip3[2]));
            this_flow_counter[FLOW_ERR_NO_R_ROUTE].counter++;
            return FLOW_RET_ERR;
        } else if (!rt->rt6_dev) {
            flow_print_basic("  reverse route 0x%llx have no interface\n", rt);
            this_flow_counter[FLOW_ERR_NO_R_ROUTE_IFP].counter++;
            return FLOW_RET_ERR;
        }
        peer->route = rt;
        if (rt->rt6_dev != peer->ifp) {
            flow_print_basic("  csp update the ifp %s->%s\n", 
                             (peer->ifp)?peer->ifp->name:"uncertain", 
                             (rt->rt6_dev)?rt->rt6_dev->name:"uncertain");
            peer->ifp = rt->rt6_dev;
            peer->cspflag |= CSP_IFP_UPDATE;
        }
    }
#endif

    return flow_next_pak_vector(mbuf);
}

int
flow_fast_reinject_out_v6(struct rte_mbuf *mbuf)
{
    VECTOR_PROFILE(flow_fast_reinject_out_v6);
    flow_print_basic(" %s entry.\n", __FUNCTION__);
    return flow_next_pak_vector(mbuf);
}

#ifdef TYFLOW_LEGACY
int
flow_fast_send_out_v6(struct rte_mbuf *mbuf)
{
    VECTOR_PROFILE(flow_fast_send_out_v6);
    flow_print_basic(" %s entry.\n", __FUNCTION__);
    return flow_next_pak_vector(mbuf);
}
#endif
