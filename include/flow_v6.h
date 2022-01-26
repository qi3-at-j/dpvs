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

#ifndef __TYFLOW_FLOW_V6_H__
#define __TYFLOW_FLOW_V6_H__

#include <sys/types.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

#include "conf/common.h"
#include "conf/flow.h"
#include "dpdk.h"
#include "netif.h"
#include "inet.h"

#include "session_public.h"

#define FLOW_V6ADDR_MAX_NUMBER (4*FLOW_CONN_MAX_NUMBER)

typedef struct flow_ip6_addr_list_ {
    struct flow_ip6_addr_list_ *next;
} flow_ip6_addr_list_t;

/* per lcore flow ipv6 address entry table */
RTE_DECLARE_PER_LCORE(struct in6_addr *, flowV6addrTable);
/* per lcore flow ipv6 address entry list head */
RTE_DECLARE_PER_LCORE(flow_ip6_addr_list_t *, flowV6addrHead);
/* per lcore flow ipv6 address entry list tail */
RTE_DECLARE_PER_LCORE(flow_ip6_addr_list_t *, flowV6addrTail);

#define this_flowV6addrTable   (RTE_PER_LCORE(flowV6addrTable))
#define this_flowV6addrHead    (RTE_PER_LCORE(flowV6addrHead))
#define this_flowV6addrTail    (RTE_PER_LCORE(flowV6addrTail))

static inline int 
CONN_SUB_COMP_V6 (conn_sub_t *csp, csp_key_t *key)
{
    /* The src_port and dst_port in csp will be in NBO and
     * the key, which is basically the src/dst port from pkt,
     * will also be in NBO */
    if (memcmp(&csp->key, key, sizeof(csp->key))) {
        return 0;
    }
    return 1;
}

extern flow_vector_t flow_first_vector_list_v6[];
extern flow_vector_t flow_fast_vector_list_v6[];
extern flow_vector_t flow_ipv6_vector_list[];
int 
icmp6_ports (struct icmp6_hdr *icmp6);
void
add_to_conn_hash_v6(conn_sub_t *csp);
void
del_from_conn_hash_v6(conn_sub_t *csp);
conn_sub_t *
flow_find_connection_by_key_v6(csp_key_t *key);
int
flow_find_connection_v6(struct rte_mbuf *mbuf);
int 
flow_first_sanity_check_v6(struct rte_mbuf *mbuf);
int 
flow_first_hole_search_v6(struct rte_mbuf *mbuf);
int
flow_first_routing_v6(struct rte_mbuf *mbuf);
int
flow_first_for_self_v6(struct rte_mbuf *mbuf);
int
flow_parse_vector_v6(struct rte_mbuf *mbuf);
int
flow_filter_vector_v6(struct rte_mbuf *mbuf);
int
flow_decap_vector_v6(struct rte_mbuf *mbuf);
int
flow_fast_for_self_v6(struct rte_mbuf *mbuf);
int
flow_fast_check_routing_v6(struct rte_mbuf *mbuf);
int
flow_fast_reinject_out_v6(struct rte_mbuf *mbuf);
int
flow_fast_send_out_v6(struct rte_mbuf *mbuf);

#endif /* __TYFLOW_FLOW_V6_H__ */
