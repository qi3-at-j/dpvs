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
 */

#ifndef __TYFLOW_FLOW_H__
#define __TYFLOW_FLOW_H__

#include <sys/types.h>
#include <rte_mbuf.h>

#include "conf/common.h"
#include "conf/flow.h"
#include "dpdk.h"
#include "netif.h"
#include "inet.h"

/* common flow info of upper layer (l4) */
union flow_ul {
    struct {
        __be16          dport;
        __be16          sport;
    } ports;

    struct {
        __u8            type;
        __u8            code;
    } icmpt;

    __be32              gre_key;
};

/* common flow info */
struct flow_common {
    struct netif_port   *flc_oif;
    struct netif_port   *flc_iif;
    uint8_t             flc_tos;
    uint8_t             flc_proto;
    uint8_t             flc_scope;
    uint8_t             flc_ttl;
    uint32_t            flc_mark;
    uint32_t            flc_flags;
};

struct flow4 {
    struct flow_common  __fl_common;
#define fl4_oif         __fl_common.flc_oif
#define fl4_iif         __fl_common.flc_iif
#define fl4_tos         __fl_common.flc_tos
#define fl4_proto       __fl_common.flc_proto
#define fl4_scope       __fl_common.flc_scope
#define fl4_ttl         __fl_common.flc_ttl
#define fl4_mark        __fl_common.flc_mark
#define fl4_flags       __fl_common.flc_flags

    struct in_addr      fl4_saddr;
    struct in_addr      fl4_daddr;

    union flow_ul       __fl_ul;
#define fl4_sport       __fl_ul.ports.sport
#define fl4_dport       __fl_ul.ports.dport
};

struct flow6 {
    struct flow_common  __fl_common;
#define fl6_oif         __fl_common.flc_oif
#define fl6_iif         __fl_common.flc_iif
#define fl6_tos         __fl_common.flc_tos
#define fl6_proto       __fl_common.flc_proto
#define fl6_scope       __fl_common.flc_scope
#define fl6_ttl         __fl_common.flc_ttl
#define fl6_mark        __fl_common.flc_mark
#define fl6_flags       __fl_common.flc_flags

    struct in6_addr     fl6_daddr;
    struct in6_addr     fl6_saddr;
    __be32              fl6_flow;

    union flow_ul       __fl_ul;
#define fl6_sport       __fl_ul.ports.sport
#define fl6_dport       __fl_ul.ports.dport
};

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t proto:8;
    uint32_t csp_token:24;
} csp_key_t;

typedef struct conn_sub_ {
    char peer_offset;
    char base_offset;
    char resv;
#define RESV_AA 0xAA
#define RESV_BB 0xBB
    /* fields below "start" is variable */
    char start[0];
    uint8_t  wsf;            /* the window scale factor */
    uint32_t  cspflag;
#define CSP_INITIATE_SIDE       0x01    /* set if this csp is at initiate side */
#define CSP_FLAG_IPV6           0x02    /* indicate this is a v6 wing */
#define CSP_VLAN_TAG            0x04    /* indicate this leg has vlan id */
#define CSP_FROM_SELF           0x08    /* set if pak is from ourself */
#define CSP_DISABLE             0x10    /* this wing cannot do the fast path */
#define CSP_FREE                0x20    /* csp is in free pool */
#define CSP_INVALID             0x40    /* csp is aged out or invalid */
#define CSP_SYN_OPEN            0x80
#define CSP_L2_READY            0x100
#define CSP_L2INFO_IS_ARP       0x200
    csp_key_t key;
#define csp_src_ip    key.src_ip
#define csp_dst_ip    key.dst_ip
#define csp_src_port  key.src_port
#define csp_dst_port  key.dst_port
#define csp_proto     key.proto
#define csp_token     key.csp_token
    uint16_t win;            /* window size before scaling */
    uint16_t pmtu;           /* path mtu */
    uint64_t byte_cnt;
    uint64_t pkt_cnt;
    struct hlist_node hnode; /* used to link connsubs */
    struct route_entry *route;
    //conn_l2info_t csp_l2info;
    struct netif_port *ifp;
} conn_sub_t;

#define IS_CSP_DISABLE(x)    ((x)->cspflag & CSP_DISABLE)
#define SET_CSP_DISABLE(x)   ((x)->cspflag |= CSP_DISABLE)
#define CLEAR_CSP_DISABLE(x) ((x)->cspflag &= ~CSP_DISABLE)

//#define is_csp_l2info_arp(x) ((x)->cspflag & CSP_L2INFO_IS_ARP)
//#define set_csp_l2info_arp_flag(x) ((x)->cspflag |= CSP_L2INFO_IS_ARP)
//#define clear_csp_l2info_arp_flag(x) ((x)->cspflag &= ~CSP_L2INFO_IS_ARP)

typedef struct flow_connection_ {
    conn_sub_t conn_sub0;
    conn_sub_t conn_sub1;
    struct flow_connection_ *next;
    /* fields below "start" is variable */
    char start[0];
    uint16_t  time;
    uint16_t  time_const;
    uint64_t  start_time;
    uint32_t  duration;
    uint32_t  fcflag;
#define FC_TIME_NO_REFRESH     0x80000000  /* don't refresh timeout if this bit set */
#define FC_TO_BE_INVALID       0x40000000  /* wait for killing children rtp/rtcp session */
#define FC_LOOP                0x20000000
#define FC_GEN_GATE            0x10000000  /* set when created a gate */
#define FC_FROM_GATE           0x08000000  /* set when created from gate */
#define FC_SEND_RESET          0x04000000
#define FC_INVALID             0x02000000
#define FC_HALF_OPEN           0x01000000
#define FC_CONTROL_CHANNEL     0x00800000
#define FC_DATA_CHANNEL        0x00400000
#define FC_INSTALLED           0x00200000
#define FC_TUNNEL              0x00100000  /* it is a tunnel connection */
    uint64_t byte_cnt;
    uint64_t pkt_cnt;
    uint32_t reason; /* Reasons for closing down a session */
#define FC_CREATION                       0
#define FC_CLOSE_TCP_RST                  1
#define FC_SESSION_CLOSE_TCP_FIN          2
#define FC_SESSION_CLOSE_RESP_RECV        3
#define FC_SESSION_CLOSE_ICMP_ERR         4
#define FC_CLOSE_AGEOUT                   5
#define FC_SESSION_CLOSE_PARENT_CLOSED    6
#define FC_CLOSE_CLI                      7
#define FC_SESSION_CLOSE_SYN_CHECK_STRICT 8
#define FC_CLOSE_OTHER                    9
    void *mbuf;
    void *fwsession;
} flow_connection_t;

typedef int (* flow_vector_t)(struct rte_mbuf *mbuf);

#if 0
#define FLOW_CONN_MAX_NUMBER       (0x80000)   /*512K*/
#else
#define FLOW_CONN_MAX_NUMBER       (0x800)   /*512K*/
#endif
#define FLOW_CONN_HASH_TAB_SIZE    (FLOW_CONN_MAX_NUMBER>>3)   /*64K*/
#define FLOW_CONN_HASH_TAB_MASK    (FLOW_CONN_HASH_TAB_SIZE-1)

#define FLOW_CONN_NOTIMEOUT   65535     /* indicate no timeout */

/* per lcore flow connection table */
RTE_DECLARE_PER_LCORE(flow_connection_t *, flowConnTable);
/* per lcore flow connection lifo head */
RTE_DECLARE_PER_LCORE(flow_connection_t *, flowConnHead);
/* per lcore flow connection hash tab base*/
RTE_DECLARE_PER_LCORE(struct hlist_head * /* conn_sub_t** */, flow_conn_hash_base);
/* per lcore flow connection hash cnt table base */
RTE_DECLARE_PER_LCORE(uint32_t *, flow_conn_hash_cnt_base);

/* per lcore flow connection statistics */
RTE_DECLARE_PER_LCORE(uint32_t, flow_curr_conn);
RTE_DECLARE_PER_LCORE(uint32_t, flow_invalid_conn);
RTE_DECLARE_PER_LCORE(uint32_t, flow_no_conn);
RTE_DECLARE_PER_LCORE(uint32_t, flow_free_conn);

/* flow is ready to go? */
RTE_DECLARE_PER_LCORE(uint32_t, flow_status);

/* per lcore flow connection ager */
RTE_DECLARE_PER_LCORE(struct rte_timer, flow_conn_ager);

/* per lcore flow vector list */
RTE_DECLARE_PER_LCORE(flow_vector_t *, flow_vector_list);

/* per lcore flow connection control prototype */
RTE_DECLARE_PER_LCORE(flow_connection_t, flow_conn_crt_t);

#define this_flowConnTable           (RTE_PER_LCORE(flowConnTable))
#define this_flowConnHead            (RTE_PER_LCORE(flowConnHead))
#define this_flow_conn_hash_base     (RTE_PER_LCORE(flow_conn_hash_base))
#define this_flow_conn_hash_cnt_base (RTE_PER_LCORE(flow_conn_hash_cnt_base))
#define this_flow_curr_conn          (RTE_PER_LCORE(flow_curr_conn))
#define this_flow_invalid_conn       (RTE_PER_LCORE(flow_invalid_conn))
#define this_flow_no_conn            (RTE_PER_LCORE(flow_no_conn))
#define this_flow_free_conn          (RTE_PER_LCORE(flow_free_conn))
#define this_flow_status             (RTE_PER_LCORE(flow_status))
#define this_flow_conn_ager          (RTE_PER_LCORE(flow_conn_ager))
#define this_flow_conn_crt           (&RTE_PER_LCORE(flow_conn_crt_t))
#define this_flow_vector_list        (RTE_PER_LCORE(flow_vector_list))

#define csp2base(x) ((flow_connection_t *)((uint64_t)(x) + (x)->base_offset))
#define csp2peer(x) ((conn_sub_t *)((uint64_t)(x) + (x)->peer_offset))

/*
 *	connection_id to fcp.
 */
static inline flow_connection_t* id2fcp_(uint32_t conn_id)
{
	return (this_flowConnTable + conn_id);
}

/*
 *	fcp to connection_id.
 */
static inline uint32_t fcp2id(flow_connection_t *fcp)
{
	return (fcp? (fcp-this_flowConnTable):-1);
}

static inline int is_tunnel_conn(flow_connection_t *fcp)
{
    return (fcp->fcflag & FC_TUNNEL);
}

#define is_csp_invalid(x)      ((x)->cspflag & CSP_INVALID)
#define set_csp_invalid(x)     ((x)->cspflag |= CSP_INVALID)
#define is_fcp_valid(x) \
        (!is_csp_invalid(&x->conn_sub0) && !is_csp_invalid(&x->conn_sub1))

#define is_csp_free(x)      ((x)->cspflag & CSP_FREE)
#define set_csp_free(x)     ((x)->cspflag |= CSP_FREE)

enum {
    RTE_MBUF_CONN_SUB  = 0,
    RTE_MBUF_CONN_SUB1 = 1,
    RTE_MBUF_MAX = 9,
};
#define GET_CSP_FROM_MBUF(x) ((conn_sub_t *)*((uint64_t *)&((x)->dynfield1[RTE_MBUF_CONN_SUB])))
#define SET_CSP_TO_MBUF(x, csp) \
    do {                                                                                    \
        if (flow_debug_flag & FLOW_DEBUG_BASIC) {                                           \
            conn_sub_t *temp_csp = GET_CSP_FROM_MBUF(x);                                    \
            flow_debug_trace_no_flag("  set csp to mbuf 0x%llx->0x%llx.\n", temp_csp, csp); \
        }                                                                                   \
        (*((uint64_t *)&(x)->dynfield1[RTE_MBUF_CONN_SUB]) = (uint64_t)(csp));              \
    } while(0)
#define GET_FC_FROM_MBUF(x) csp2base(GET_CSP_FROM_MBUF(x))

/*----------------------------------------------*/
/* Return 1 if match found; 0 if not matched    */
/*----------------------------------------------*/
static inline int CONN_SUB_COMP (conn_sub_t *csp, struct rte_ipv4_hdr *iphdr,
uint32_t ports, uint32_t token)
{
    /* The src_port and dst_port in csp will be in NBO and
     * the lports, which is basically the src/dst port from pkt,
     * will also be in NBO */
    if (csp->csp_token == token &&
        *(uint32_t *)&csp->csp_src_port == ports &&
        csp->csp_src_ip == iphdr->src_addr &&
        csp->csp_dst_ip == iphdr->dst_addr &&
        csp->csp_proto  == iphdr->next_proto_id)
        return 1;

    return 0;
}

enum {
    /* something error */
    FLOW_RET_ERR   = -1,
    /* good to go next */
    FLOW_RET_OK    = 0,
    /* break through */
    FLOW_RET_BREAK = 1,
};

/*
 * return proper src port for udp/tcp
 */
static inline uint32_t ip_src_port (uint32_t ports)
{
    if (RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN)
        return ports & 0xffff;
    else 
        return ports >> 16;
}
/*
 * return proper dst port for udp/tcp
 */
static inline uint32_t ip_dst_port (uint32_t ports)
{
    if (RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN)
        return ports >> 16;
    else
        return ports & 0xffff;
}

/*
 * Endian safe way to form ports from src and dst ports.
 */
static inline uint32_t ip_ports_form(uint16_t src_port, uint16_t dst_port)
{
    if (RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN)
        return (dst_port << 16) | src_port;
    else 
        return (src_port << 16) | dst_port;
}

extern void 
flow_free_this_conn (flow_connection_t *fcp);
extern int
flow_init (void);
int 
icmp_ports (struct rte_icmp_hdr *icmp);
struct rte_ipv4_hdr *
gen_icmp_lookup_info (struct rte_ipv4_hdr *iphdr, uint32_t *iptr, struct rte_mbuf *mbuf, struct rte_ipv4_hdr *iphdr_inner, uint32_t *ports);
int
flow_proc_first_pak(struct rte_mbuf *mbuf);
int
flow_first_install_connection(struct rte_mbuf *mbuf);
int 
flow_find_connection(struct rte_mbuf *mbuf);
int 
flow_first_sanity_check(struct rte_mbuf *mbuf);
int 
flow_first_fcp_crt_init(struct rte_mbuf *mbuf, uint32_t ports);
int
flow_first_alloc_connection(struct rte_mbuf *mbuf);
int 
flow_first_hole_search(struct rte_mbuf *mbuf);
int
pak_to_my_addrs(struct rte_ipv4_hdr *iph, uint32_t id);
int
pak_for_self(struct rte_ipv4_hdr *iph, uint32_t *iptr);
int
flow_first_for_self(struct rte_mbuf *mbuf);
int
flow_first_routing(struct rte_mbuf *mbuf);
int
flow_first_fw_entry(struct rte_mbuf *mbuf);
int
flow_fast_reinject_out(struct rte_mbuf *mbuf);
int
flow_fast_fw_entry(struct rte_mbuf *mbuf);
int
flow_fast_send_out(struct rte_mbuf *mbuf);
void
flow_install_conn(flow_connection_t *fcp);
int
flow_filter_vector(struct rte_mbuf *mbuf);
int
flow_tunnel_handling(struct rte_mbuf *mbuf);
int
flow_decap_vector(struct rte_mbuf *mbuf);
struct rte_mbuf *
flow_gen_icmp_pak(uint8_t __rte_unused type, uint8_t __rte_unused code);
int
flow_send_return_pak(struct rte_mbuf *mbuf);
int
flow_drop_packet(struct rte_mbuf *mbuf);
int 
flow_main_body_vector (struct rte_mbuf *mbuf);
int
flow_handle_other_queue(void);
int
flow_processing_paks(struct rte_mbuf *mbuf);

#endif /* __TYFLOW_FLOW_H__ */
