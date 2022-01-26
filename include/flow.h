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
#include <rte_mbuf_dyn.h>

#include "conf/common.h"
#include "conf/flow.h"
#include "dpdk.h"
#include "netif.h"
#include "inet.h"

#include "session_public.h"

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

/*
 * hash packet for flow conn_sub_t.
 * need to tune it in accordance with the real traffic
 */
static inline uint32_t 
_conn_hash (uint32_t sIP, uint32_t dIP, uint32_t ports)
{
    uint32_t hash;

#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
    hash = sIP >> 8;
    hash = hash ^ ((hash << 5) + (hash >> 3) + ((sIP << 24) | (dIP >> 8)));
    hash = hash ^ ((hash << 5) + (hash >> 3) + ((dIP << 24) | (ports >> 8)));
    hash = hash ^ ((hash << 5) + (hash >> 4) + (ports >> 24));
    hash = hash ^ ((hash << 5) + (hash >> 4) + ports);
#else
    hash = sIP >> 24;
    hash = hash ^ ((hash << 5) + (hash >> 3) + ((sIP << 8) | (dIP >> 24)));
    hash = hash ^ ((hash << 5) + (hash >> 3) + ((dIP << 8) | (ports >> 24)));
    hash = hash ^ ((hash << 5) + (hash >> 4) + (ports >> 8));
    hash = hash ^ ((hash << 5) + (hash >> 4) + ports);
#endif
	
	return hash;
}

/* generic way for flow conn_sub_t traverse */
#define FOR_ALL_CSP2(node, src_adr, dst_adr, ports, head, csp, hash, cnt)  					          \
    for (node = ((this_flow_conn_hash_base + hash)->hash_base).first,	                              \
         csp = container_of(node, conn_sub_t, hnode), head = csp,                                     \
         cnt = rte_atomic32_read(&(this_flow_conn_hash_base + hash)->conn_cnt);           		      \
         node && (csp = container_of(node, conn_sub_t, hnode)) && ({ rte_prefetch0(node->next); 1;}); \
         node = node->next, csp = container_of(node, conn_sub_t, hnode))

#ifdef TYFLOW_PER_THREAD
/* flow connection head lock */
#define fch_sl_lock()
#define fch_sl_unlock()

/* fcp lock */
#define fcp_rwl_read_lock(fcp)
#define fcp_rwl_read_unlock(fcp)
#define fcp_rwl_write_lock(fcp)
#define fcp_rwl_write_unlock(fcp)

/* flow connection context lock */
#define fcc_rwl_read_lock(hash)
#define fcc_rwl_read_unlock(hash)
#define fcc_rwl_write_lock(hash)
#define fcc_rwl_write_unlock(hash)

/* flow connection ager context lock */
#define fca_rwl_read_lock(hash)
#define fca_rwl_read_unlock(hash)
#define fca_rwl_write_lock(hash)
#define fca_rwl_write_unlock(hash)

#else
/* flow connection head lock */
#define fch_sl_lock()    rte_spinlock_lock(&flowConnHead_sl)
#define fch_sl_unlock()  rte_spinlock_unlock(&flowConnHead_sl)

/* fcp lock */
#define fcp_rwl_read_lock(fcp) rte_rwlock_read_lock(&((fcp)->rwl))
#define fcp_rwl_read_unlock(fcp) rte_rwlock_read_unlock(&((fcp)->rwl)) 
#define fcp_rwl_write_lock(fcp) rte_rwlock_write_lock(&(fcp)->rwl)
#define fcp_rwl_write_unlock(fcp) rte_rwlock_write_unlock(&(fcp)->rwl)

/* flow connection context lock */
#define fcc_rwl_read_lock(hash)    \
    rte_rwlock_read_lock(&((this_flow_conn_hash_base+(hash))->rwl))
#define fcc_rwl_read_unlock(hash)  \
    rte_rwlock_read_unlock(&((this_flow_conn_hash_base+(hash))->rwl))
#define fcc_rwl_write_lock(hash)   \
    rte_rwlock_write_lock(&((this_flow_conn_hash_base+(hash))->rwl))
#define fcc_rwl_write_unlock(hash) \
    rte_rwlock_write_unlock(&((this_flow_conn_hash_base+(hash))->rwl))

/* flow connection ager context lock */
#define fca_rwl_read_lock(index)    \
    rte_rwlock_read_lock((this_flow_conn_ager_ctx.rwl+index))
#define fca_rwl_read_unlock(index)  \
    rte_rwlock_read_unlock((this_flow_conn_ager_ctx.rwl+index))
#define fca_rwl_write_lock(index)   \
    rte_rwlock_write_lock((this_flow_conn_ager_ctx.rwl+index))
#define fca_rwl_write_unlock(index) \
    rte_rwlock_write_unlock((this_flow_conn_ager_ctx.rwl+index))

#endif

/* generic way for flow conn_sub_t traverse end */
#define FOR_ALL_CSP_END(hash)      \
    do {                           \
        fcc_rwl_read_unlock(hash); \
    } while(0)

typedef struct {
    uint32_t src_ip;
    uint32_t src_ip3[3];
    uint32_t dst_ip;
    uint32_t dst_ip3[3];
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t proto:8;
    uint32_t token:24;
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
#define CSP_ECHO_SIDE           0x01    /* set if this csp is at echo side */
#define CSP_FLAG_IPV6           0x02    /* indicate this is a v6 wing */
#define CSP_VLAN_TAG            0x04    /* indicate this leg has vlan id */
#define CSP_FROM_SELF           0x08    /* set if pak is from ourself */
#define CSP_DISABLE             0x10    /* this wing cannot do the fast path, only used by fw */
#define CSP_FREE                0x20    /* csp is in free pool */
#define CSP_INVALID             0x40    /* csp is aged out or invalid */
#define CSP_SYN_OPEN            0x80
#define CSP_L2_READY            0x100
#define CSP_L2INFO_IS_ARP       0x200
#define CSP_IFP_UPDATE          0x400   /* csp ifp is updated */
#define CSP_TO_SELF             0x800   /* set if pak is to ourself */
#define CSP_TO_SELF_PING        0x1000  /* set if pak is to ping us */
    csp_key_t key;
#define csp_src_ip    key.src_ip
#define csp_dst_ip    key.dst_ip
#define csp_src_port  key.src_port
#define csp_dst_port  key.dst_port
#define csp_proto     key.proto
#define csp_token     key.token
    union {
        uint16_t win;            /* window size before scaling */
        struct {
            uint8_t  type;
            uint8_t  code;
        } u_s;
    } u;
#define csp_win       u.win
#define csp_type      u.u_s.type
#define csp_code      u.u_s.code
    uint16_t pmtu;           /* path mtu */
    uint32_t csp_ipid;       /* to self ping id */
    uint64_t byte_cnt;
    uint64_t pkt_cnt;
    struct hlist_node hnode; /* used to link connsubs */
    void *route;
    /* the route is representing below
    union {
        struct route_entry *route;
        struct route6 *route_6;
        struct route6_entry *route;
    }
    */
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
#ifndef TYFLOW_PER_THREAD
    rte_rwlock_t rwl;
#endif
    struct flow_connection_ *next;
    struct hlist_node ager_node; /* used to link ager */
    /* fields below "start" is variable */
    char start[0];
    uint64_t  start_time;
    uint64_t  duration;
    uint16_t  time;
    uint16_t  time_const;
    uint32_t  fcflag;
#define FC_TIME_NO_REFRESH     0x80000000  /* don't refresh timeout if this bit set */
#define FC_TO_BE_INVALID       0x40000000  /* wait for killing children control/data connection */
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
#define FC_IN_AGER             0x00080000  /* it is a tunnel connection */
    uint64_t byte_cnt;
    uint64_t pkt_cnt;
    uint64_t policy_seq;
    uint32_t ager_index;
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

typedef struct flow_conn_context_ {
    struct hlist_head hash_base;
    rte_atomic32_t conn_cnt;
#ifndef TYFLOW_PER_THREAD
    rte_rwlock_t rwl;
#endif
} __rte_cache_aligned flow_conn_context_t;

typedef struct flow_conn_ager_context_ {
    rte_atomic32_t key;
    struct hlist_head *hash;
#ifndef TYFLOW_PER_THREAD
    rte_rwlock_t *rwl;
#endif
    uint32_t index;
    rte_atomic32_t cid;
} __rte_cache_aligned flow_conn_ager_context_t;

typedef int (* flow_vector_t)(struct rte_mbuf *mbuf);

#if 1
#define FLOW_CONN_MAX_NUMBER       (0x80000)   /*512K*/
#else
#define FLOW_CONN_MAX_NUMBER       (0x800)   /*512K*/
#endif
#define FLOW_CONN_HASH_TAB_SIZE    (FLOW_CONN_MAX_NUMBER>>3)   /*64K*/
#define FLOW_CONN_HASH_TAB_MASK    (FLOW_CONN_HASH_TAB_SIZE-1)

#define FLOW_CONN_AGER_RATE    2        /* indicate ager will be triggered every 2 seconds */
#define FLOW_CONN_MAXTIMEOUT   64800    /* 129600 sec, exact 36 hours, use this value as hash bucket too */
#define FLOW_CONN_NOTIMEOUT    65535    /* indicate no timeout */
#define FLOW_CONN_TCP_TIMEOUT  900      /* 1800 sec, or 30 minutes */
#define FLOW_CONN_UDP_TIMEOUT  30       /* 60 sec, or 1 minute */
#define FLOW_CONN_PING_TIMEOUT 5        /* 10 sec */
#define FLOW_CONN_DEF_TIMEOUT  5        /* 10 sec */

#ifdef TYFLOW_PER_THREAD
/* per lcore flow connection table */
RTE_DECLARE_PER_LCORE(flow_connection_t *, flowConnTable);
/* per lcore flow connection lifo head */
RTE_DECLARE_PER_LCORE(flow_connection_t *, flowConnHead);
/* per lcore flow connection hash context */
RTE_DECLARE_PER_LCORE(flow_conn_context_t *, flow_conn_ctx);

/* flow is ready to go? */
RTE_DECLARE_PER_LCORE(rte_atomic32_t, flow_status);
/* per lcore flow connection ager context */
RTE_DECLARE_PER_LCORE(flow_conn_ager_context_t, flow_conn_ager_ctx);

#else
extern flow_connection_t *flowConnTable;
extern flow_connection_t *flowConnHead;
extern rte_spinlock_t flowConnHead_sl;
extern flow_conn_context_t *flow_conn_ctx;
extern rte_atomic32_t flow_status;
extern flow_conn_ager_context_t flow_conn_ager_ctx;
#endif


/* per lcore flow connection ager */
RTE_DECLARE_PER_LCORE(struct rte_timer, flow_conn_ager);

/* per lcore flow vector list */
RTE_DECLARE_PER_LCORE(flow_vector_t *, flow_vector_list);

/* per lcore flow connection control prototype */
RTE_DECLARE_PER_LCORE(flow_connection_t, flow_conn_crt_t);

enum {
    /* flow connection counter related */
    FLOW_TOTAL_CONN,
    FLOW_CURR_CONN,
    FLOW_INVALID_CONN,
    FLOW_NO_CONN,
    FLOW_FREE_CONN,
    FLOW_COUNTER_G_MAX
};

enum {
    /* below counter are mutable */
    FLOW_COUNTER_MUTAB_START,
    /* flow statistics related */
    FLOW_STAT_PAK,
    FLOW_STAT_TCP,
    FLOW_STAT_TCP_FRAG_FST,
    FLOW_STAT_TCP_FRAG_LST,
    FLOW_STAT_TCP_FRAG_MID,
    FLOW_STAT_UDP,
    FLOW_STAT_UDP_FRAG_FST,
    FLOW_STAT_UDP_FRAG_LST,
    FLOW_STAT_UDP_FRAG_MID,
    FLOW_STAT_ICMP,
    FLOW_STAT_ICMP_FRAG_FST,
    FLOW_STAT_ICMP_FRAG_LST,
    FLOW_STAT_ICMP_FRAG_MID,
    FLOW_STAT_ICMP6,
    FLOW_STAT_ICMP6_FRAG_FST,
    FLOW_STAT_ICMP6_FRAG_LST,
    FLOW_STAT_ICMP6_FRAG_MID,
    FLOW_STAT_OTHER,
    FLOW_STAT_OTHER_FRAG_FST,
    FLOW_STAT_OTHER_FRAG_LST,
    FLOW_STAT_OTHER_FRAG_MID,
    FLOW_STAT_ICMP_ERR_TCP,
    FLOW_STAT_ICMP_ERR_UDP,
    FLOW_STAT_ICMP_ERR_ICMP,
    FLOW_STAT_ICMP_ERR_OTHER,
    FLOW_STAT_FWD,

    FLOW_ERR_PARSE_ICMP_HEADER,
    FLOW_ERR_PARSE_ICMP_REDIRECT,
    FLOW_ERR_PARSE_NO_SUPPORT_PROT,
    FLOW_ERR_PARSE_IPV6_HBH, /* hop-by-hop */
    /* flow handle error related */
    FLOW_ERR_FLOW_START,
    FLOW_ERR_ICMP_GEN,
    FLOW_ERR_TO_SELF_DROP,
    FLOW_ERR_FCB_NO,
    FLOW_ERR_FCB_NO_MATCH,
    FLOW_ERR_FCB_NO_CSP,
    FLOW_ERR_FCB_INVAL_CSP,
    FLOW_ERR_NO_ROUTE,
    FLOW_ERR_NO_ROUTE_IFP,
    FLOW_ERR_NO_R_ROUTE,
    FLOW_ERR_NO_R_ROUTE_IFP,
    FLOW_ERR_FIRST_FW,
    FLOW_ERR_FAST_FW,
    FLOW_ERR_SEND_OUT,
    FLOW_ERR_FWD,

    /* other */
    FLOW_BRK_TO_SELF,

    /* above counter are mutable */
    FLOW_COUNTER_MUTAB_END,
    FLOW_COUNTER_MAX = FLOW_COUNTER_MUTAB_END
};

typedef struct {
    char *name;
    uint32_t index;
    rte_atomic32_t counter;
} name_n_cnt_g[FLOW_COUNTER_G_MAX];

static name_n_cnt_g flow_counter_g_template __rte_unused = {
    {"total connection counter:", FLOW_TOTAL_CONN, {FLOW_CONN_MAX_NUMBER-1}},
    {"current connection counter:", FLOW_CURR_CONN, {0}},
    {"invalid connection counter:", FLOW_INVALID_CONN, {0}},
    {"no connection counter:", FLOW_NO_CONN, {0}},
    {"free connection counter:", FLOW_FREE_CONN, {0}},
};

typedef struct {
    char *name;
    uint32_t index;
    uint32_t counter;
} name_n_cnt[FLOW_COUNTER_MAX];

static name_n_cnt flow_counter_template __rte_unused = {
    {"---------packet related statistics----------", FLOW_COUNTER_MUTAB_START, 0},
    {"statistics all:", FLOW_STAT_PAK, 0},
    {"           tcp:", FLOW_STAT_TCP, 0},
    {"           tcp frag first:", FLOW_STAT_TCP_FRAG_FST, 0},
    {"           tcp frag last:", FLOW_STAT_TCP_FRAG_LST, 0},
    {"           tcp frag middle:", FLOW_STAT_TCP_FRAG_MID, 0},
    {"           udp:", FLOW_STAT_UDP, 0},
    {"           udp frag first:", FLOW_STAT_UDP_FRAG_FST, 0},
    {"           udp frag last:", FLOW_STAT_UDP_FRAG_LST, 0},
    {"           udp frag middle:", FLOW_STAT_UDP_FRAG_MID, 0},
    {"           icmp:", FLOW_STAT_ICMP, 0},
    {"           icmp frag first:", FLOW_STAT_ICMP_FRAG_FST, 0},
    {"           icmp frag last:", FLOW_STAT_ICMP_FRAG_LST, 0},
    {"           icmp frag middle:", FLOW_STAT_ICMP_FRAG_MID, 0},
    {"           icmpv6:", FLOW_STAT_ICMP6, 0},
    {"           icmpv6 frag first:", FLOW_STAT_ICMP6_FRAG_FST, 0},
    {"           icmpv6 frag last:", FLOW_STAT_ICMP6_FRAG_LST, 0},
    {"           icmpv6 frag middle:", FLOW_STAT_ICMP6_FRAG_MID, 0},
    {"           other:", FLOW_STAT_OTHER, 0},
    {"           other frag first:", FLOW_STAT_OTHER_FRAG_FST, 0},
    {"           other frag last:", FLOW_STAT_OTHER_FRAG_LST, 0},
    {"           other frag middle:", FLOW_STAT_OTHER_FRAG_MID, 0},
    {"           icmp err(tcp):", FLOW_STAT_ICMP_ERR_TCP, 0},
    {"           icmp err(udp):", FLOW_STAT_ICMP_ERR_UDP, 0},
    {"           icmp err(icmp):", FLOW_STAT_ICMP_ERR_ICMP, 0},
    {"           icmp err(other):", FLOW_STAT_ICMP_ERR_OTHER, 0},
    {"       fwd to other thread:", FLOW_STAT_FWD, 0},

    {"error parse embed icmp header:", FLOW_ERR_PARSE_ICMP_HEADER, 0},
    {"error parse embed icmp redirect:", FLOW_ERR_PARSE_ICMP_REDIRECT, 0},
    {"error parse not support protocol:", FLOW_ERR_PARSE_NO_SUPPORT_PROT, 0},
    {"error parse ipv6 hop-by-hop eh:", FLOW_ERR_PARSE_IPV6_HBH, 0},

    {"---------flow handling related statistics----------", FLOW_ERR_FLOW_START, 0},
    {"error icmp generated:", FLOW_ERR_ICMP_GEN, 0},
    {"error to-self drop:", FLOW_ERR_TO_SELF_DROP, 0},
    {"error no fcb:", FLOW_ERR_FCB_NO, 0},
    {"error no match fcb:", FLOW_ERR_FCB_NO_MATCH, 0},
    {"error fcb no csp:", FLOW_ERR_FCB_NO_CSP, 0},
    {"error fcb invalid csp:", FLOW_ERR_FCB_INVAL_CSP, 0},
    {"error no route:", FLOW_ERR_NO_ROUTE, 0},
    {"error no route ifp:", FLOW_ERR_NO_ROUTE_IFP, 0},
    {"error no reverse route:", FLOW_ERR_NO_R_ROUTE, 0},
    {"error no reverse route ifp:", FLOW_ERR_NO_R_ROUTE_IFP, 0},
    {"error first firewall:", FLOW_ERR_FIRST_FW, 0},
    {"error fast firewall:", FLOW_ERR_FAST_FW, 0},
    {"error send out:", FLOW_ERR_SEND_OUT, 0},
    {"error fwd:", FLOW_ERR_FWD, 0},

    {"break to-self:", FLOW_BRK_TO_SELF, 0},
};
     
/* per lcore flow connection statistics */
RTE_DECLARE_PER_LCORE(name_n_cnt, flow_counter);

#ifdef TYFLOW_PER_THREAD
#define this_flowConnTable           (RTE_PER_LCORE(flowConnTable))
#define this_flowConnHead            (RTE_PER_LCORE(flowConnHead))
#define this_flow_conn_hash_base     (RTE_PER_LCORE(flow_conn_ctx))
#define this_flow_status             (RTE_PER_LCORE(flow_status))
#define this_flow_conn_ager_ctx      (RTE_PER_LCORE(flow_conn_ager_ctx))
/* per lcore flow summary counter */
RTE_DECLARE_PER_LCORE(name_n_cnt_g, flow_counter_g);
#define this_flow_counter_g          (RTE_PER_LCORE(flow_counter_g))

#else
#define this_flowConnTable           flowConnTable
#define this_flowConnHead            flowConnHead
#define this_flow_conn_hash_base     flow_conn_ctx
#define this_flow_status             flow_status
#define this_flow_conn_ager_ctx      flow_conn_ager_ctx
extern name_n_cnt_g   flow_counter_g;
#define this_flow_counter_g          flow_counter_g
#endif
#define this_flow_conn_ager          (RTE_PER_LCORE(flow_conn_ager))
#define this_flow_conn_crt           (&RTE_PER_LCORE(flow_conn_crt_t))
#define this_flow_vector_list        (RTE_PER_LCORE(flow_vector_list))
#define this_flow_counter            (RTE_PER_LCORE(flow_counter))
#define this_flow_curr_conn          (this_flow_counter_g[FLOW_CURR_CONN].counter)
#define this_flow_invalid_conn       (this_flow_counter_g[FLOW_INVALID_CONN].counter)
#define this_flow_no_conn            (this_flow_counter_g[FLOW_NO_CONN].counter)
#define this_flow_free_conn          (this_flow_counter_g[FLOW_FREE_CONN].counter)

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
#define clr_csp_invalid(x)     ((x)->cspflag &= ~CSP_INVALID)
#define is_fcp_valid(x) \
        (!is_csp_invalid(&x->conn_sub0) && !is_csp_invalid(&x->conn_sub1))

#define is_csp_free(x)      ((x)->cspflag & CSP_FREE)
#define set_csp_free(x)     ((x)->cspflag |= CSP_FREE)

enum {
    RTE_MBUF_CONN_SUB  = 0,
    RTE_MBUF_CONN_SUB1 = 1,
    RTE_MBUF_MAX = 9,
};

//#define GET_CSP_FROM_MBUF(x) *RTE_MBUF_DYNFIELD(x, flow_in_mbuf_offset, conn_sub_t **)
#define GET_CSP_FROM_MBUF(x) (*((conn_sub_t **)&(mbuf_from_rte_mbuf(x)->csp)))
#define GET_CSP_FROM_LBUF(x) (*((conn_sub_t **)&((x)->csp)))
#define SET_CSP_TO_MBUF(x, csp) \
    do {                                                                        \
        conn_sub_t *temp_csp = GET_CSP_FROM_MBUF(x);                            \
        flow_print_basic("  set csp to mbuf 0x%llx->0x%llx.\n", temp_csp, csp); \
        (GET_CSP_FROM_MBUF(x)) = csp;                                           \
    } while(0)
#define SET_CSP_TO_LBUF(x, csp) \
    do {                                                                        \
        conn_sub_t *temp_csp = GET_CSP_FROM_LBUF(x);                            \
        flow_print_basic("  set csp to mbuf 0x%llx->0x%llx.\n", temp_csp, csp); \
        (GET_CSP_FROM_LBUF(x)) = csp;                                           \
    } while(0)
#define GET_FC_FROM_MBUF(x) csp2base(GET_CSP_FROM_MBUF(x))
#define GET_FC_FROM_LBUF(x) csp2base(GET_CSP_FROM_LBUF(x))
#define GET_PACKETDIR_FROM_CSP(csp) ((csp)->cspflag & CSP_ECHO_SIDE)
#define GET_CSP_KEY(csp) &((csp)->key)
#define SET_FWSESSION_TO_FC(fcp, session) ((fcp)->fwsession = session)
#define GET_FWSESSION_FROM_FC(fcp) ((fcp)->fwsession)
#define GET_FWSESSION_FROM_LBUF(x) (GET_FC_FROM_LBUF(x)->fwsession)
#define GET_FWSESSION_FROM_MBUF(x) (GET_FC_FROM_MBUF(x)->fwsession)
#define GET_CSP_FAMILY(csp) ((csp->cspflag & CSP_FLAG_IPV6)?AF_INET6:AF_INET)

/*----------------------------------------------*/
/* Return 1 if match found; 0 if not matched    */
/*----------------------------------------------*/
static inline int 
CONN_SUB_COMP (conn_sub_t *csp, csp_key_t *key)
{
    /* The src_port and dst_port in csp will be in NBO and
     * the key, which is basically the src/dst port from pkt,
     * will also be in NBO */
    if (memcmp(&csp->key, key, sizeof(csp->key))) {
        return 0;
    }
    return 1;
}

enum {
    /* something error */
    FLOW_RET_ERR   = -1,
    /* good to go next */
    FLOW_RET_OK    = 0,
    /* break through */
    FLOW_RET_BREAK = 1,
    /* forward to other thread */
    FLOW_RET_FWD_BAR  = 0x10000,
    FLOW_RET_FWD_BAR2 = FLOW_RET_FWD_BAR+DPVS_MAX_LCORE,
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

extern int g_is_ping_enable;
static inline int
is_ping_on_(void)
{
    return g_is_ping_enable;
}

/* goto next vector */
static inline int 
flow_next_pak_vector(struct rte_mbuf *mbuf)
{
    this_flow_vector_list++;
    return 0;
}

/* set flow processing vector */
static inline int 
flow_set_pak_vector(flow_vector_t *vector)
{
    this_flow_vector_list = vector;
    return 0;
}

extern void 
flow_free_this_conn (flow_connection_t *fcp);
uint16_t
flow_get_fcp_time(flow_connection_t *fcp);
void 
flow_refresh_connection(flow_connection_t *fcp);
void
set_fcp_invalid(flow_connection_t *fcp, uint32_t reason);
extern uint16_t flow_protocol_timeout[IPPROTO_MAX];
uint16_t
flow_get_default_time(uint8_t proto);
extern int
flow_init (void);
int 
icmp_ports (struct rte_icmp_hdr *icmp);
struct rte_ipv4_hdr *
gen_icmp_lookup_info (struct rte_ipv4_hdr *iphdr, 
                      uint32_t *iptr, 
                      struct rte_ipv4_hdr *iphdr_inner, 
                      uint32_t *ports,
                      uint32_t *icmp_err);
int
flow_proc_first_pak(struct rte_mbuf *mbuf);
int
flow_first_install_connection(struct rte_mbuf *mbuf);
int 
is_connection_list_loop(int cnt, int i, conn_sub_t *head);
conn_sub_t *
flow_find_connection_by_key(csp_key_t *key);
int 
flow_find_connection(struct rte_mbuf *mbuf);
int 
flow_first_sanity_check(struct rte_mbuf *mbuf);
int 
flow_first_fcp_crt_init(struct rte_mbuf *mbuf, MBUF_IP_HDR_S *lhdr);
int
flow_first_alloc_connection(struct rte_mbuf *mbuf);
int 
flow_first_hole_search(struct rte_mbuf *mbuf);
int
pak_to_my_addrs(struct rte_ipv4_hdr *iph, uint32_t id);
int
flow_first_for_self(struct rte_mbuf *mbuf);
int
flow_first_routing(struct rte_mbuf *mbuf);

extern int flow_skip_fw;
int
flow_first_fw_entry(struct rte_mbuf *mbuf);
int
flow_fast_for_self(struct rte_mbuf *mbuf);
int
flow_fast_check_routing(struct rte_mbuf *mbuf);
int
flow_fast_reinject_out(struct rte_mbuf *mbuf);
int
flow_fast_fw_entry(struct rte_mbuf *mbuf);
#ifdef TYFLOW_LEGACY
int
flow_fast_send_out(struct rte_mbuf *mbuf);
#endif
void
flow_install_conn_no_refresh(flow_connection_t *fcp);
void
flow_install_conn(flow_connection_t *fcp);
void
flow_update_statistic(MBUF_IP_HDR_S *lhdr);
int
flow_parse_vector(struct rte_mbuf *mbuf);
int
flow_filter_vector(struct rte_mbuf *mbuf);
extern int flow_worker_num;
#ifdef TYFLOW_PER_THREAD
int
flow_fwd_vector(struct rte_mbuf *mbuf);
#endif
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
void
flow_update_policy_seq(void);
int
flow_handle_other_queue(void);
int
flow_processing_paks(struct rte_mbuf *mbuf);

#endif /* __TYFLOW_FLOW_H__ */
