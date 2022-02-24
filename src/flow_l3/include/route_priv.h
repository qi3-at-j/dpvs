/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2021 iQIYI (www.iqiyi.com).
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
#ifndef __NODE_ROUTE_PRIV_H__
#define __NODE_ROUTE_PRIV_H__

#include <arpa/inet.h>
#include <rte_malloc.h>
#include <rte_ether.h>

#include "common_priv.h"
#include "list.h"
#include "netif.h"
#include "flow.h"
#include "route.h"

#define LOCAL_ROUTE_TAB_SIZE    (1 << 8)

#define LOCAL_ROUTE_TAB_MASK    (LOCAL_ROUTE_TAB_SIZE - 1)

#if 0
#define ROUTE_FLAG_DEL          0x0001
#define ROUTE_FLAG_FORWARD      0x0400
#define ROUTE_FLAG_LOCALIN      0x0800
#define ROUTE_FLAG_DEFAULT      0x1000
#define ROUTE_FLAG_KNI          0X2000
#define ROUTE_FLAG_OUTWALL      0x4000
#else
#define ROUTE_FLAG_DEL          0x0001
#define ROUTE_FLAG_FORWARD      RTF_FORWARD
#define ROUTE_FLAG_LOCALIN      RTF_LOCALIN
#define ROUTE_FLAG_DEFAULT      RTF_DEFAULT
#define ROUTE_FLAG_KNI          RTF_KNI
#define ROUTE_FLAG_OUTWALL      RTF_OUTWALL
#endif

#if 0
struct route_entry {
    uint8_t netmask;
    short metric;
    uint32_t flag;
    unsigned long mtu;
    struct list_head list;
    struct in_addr dest;
    struct in_addr gw;//0 means this a direct route
    struct in_addr src;
    struct netif_port *port;
    rte_atomic32_t refcnt;
    uint32_t table_id;//for vrf
};
#endif

struct route_ifa_entry {
    struct netif_port   *port;
    struct in_addr      addr;
    struct in_addr      bcast;
    uint8_t             plen;
    uint8_t             local_keep;
};

/**
 * use per-lcore structure for lockless
 * to improve performance.
 */
struct route_table {
    struct list_head local_route_table[LOCAL_ROUTE_TAB_SIZE];
    struct list_head net_route_table;
    rte_atomic32_t cnt_local;
    rte_atomic32_t cnt_net;
    uint32_t table_id;//for vrf
};

static inline void graph_route4_put(struct route_entry *route)
{
    if (likely(route)) {
        if (rte_atomic32_dec_and_test(&route->refcnt)) {
#ifdef ROUTE_USE_MEMPOOL
            rte_mempool_put(route->mp, route);
#else
            rte_free((void *)route);
#endif
        }
    }
}

static inline void graph_route4_get(struct route_entry *route)
{
    if (likely(route)) {
        rte_atomic32_inc(&route->refcnt);
    }
}

int new_route_init(void *arg);
int new_route_add(void *arg);
int new_route_del(void *arg);
int route_table_clear(void *arg);
int route_tables_clear(void *arg);
struct route_entry *route_lookup(uint32_t flag,
    uint32_t table_id, uint32_t dest_addr);
int route_table_dump(void *arg);
int route_tables_dump(void *arg);
int route_add_auto(struct route_ifa_entry *ifa);
int route_del_auto(struct route_ifa_entry *ifa);

#endif

