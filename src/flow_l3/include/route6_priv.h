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
#ifndef __NODE_ROUTE6_PRIV_H__
#define __NODE_ROUTE6_PRIV_H__

#include <rte_malloc.h>
#include <rte_ether.h>
#include <net/if.h>

#include "flow.h"
#include "linux_ipv6.h"
#include "common_priv.h"
#include "list.h"
#include "netif.h"
#include "conf/inetaddr.h"

#define RTE_LOGTYPE_ROUTE6         RTE_LOGTYPE_USER1

#define LOCAL_ROUTE6_TAB_SIZE    (1 << 8)

#define LOCAL_ROUTE6_TAB_MASK    (LOCAL_ROUTE6_TAB_SIZE - 1)

/*
#define ROUTE6_FLAG_DEL          0x0001
#define ROUTE6_FLAG_FORWARD      0x0400
#define ROUTE6_FLAG_LOCALIN      0x0800
#define ROUTE6_FLAG_DEFAULT      0x1000
#define ROUTE6_FLAG_KNI          0X2000
#define ROUTE6_FLAG_OUTWALL      0x4000
*/
#define ROUTE6_RECYCLE_TIME_DEF    10
#define ROUTE6_RECYCLE_TIME_MAX    36000
#define ROUTE6_RECYCLE_TIME_MIN    1

struct route6_entry {
    struct rt6_prefix   rt6_dst;
    struct rt6_prefix   rt6_src;
    struct rt6_prefix   rt6_prefsrc;
    struct in6_addr     rt6_gateway;
    struct netif_port   *rt6_dev;
    uint32_t            rt6_mtu;
    uint32_t            rt6_flags;  /* RTF_XXX */

    /* private members */
    uint32_t            arr_idx;    /* lpm6 array index */
    struct list_head    hnode;      /* hash list node */
    rte_atomic32_t      refcnt;
    uint32_t table_id;  //for vrf
};

/**
 * use per-lcore structure for lockless
 * to improve performance.
 */

struct route6_dustbin {
    struct list_head routes;
    struct dpvs_timer tm;
};

struct route6_hlist
{
    int plen;
    int nroutes;
    int nbuckets;               /* never change after init */
    struct list_head node;      /* list node of htable */
    struct list_head hlist[0];
};

struct route6_htable
{
    int nroutes;
    struct list_head htable;    /* list head of rt6_hlist */
};

struct route6_ifa_entry {
    struct netif_port   *port;
    struct in6_addr      addr;
    struct in6_addr      bcast;
    uint8_t             plen;
    uint8_t             local_keep;
};

void route6_entry_dump(const struct route6_entry *route);
extern struct route6_entry*
flow_route6_lookup(struct rte_mbuf *mbuf);
struct route6_entry *route6_hlist_input(uint32_t table_id, struct rte_mbuf *mbuf);
struct route6_entry *route6_hlist_output(uint32_t table_id, const struct rte_mbuf *mbuf);
int 
route6_hlist_add_lcore(void *arg);
int 
route6_hlist_del_lcore(void *arg);
int route6_hlist_del_lcore_auto(void *arg);
int route6_hlist_add_lcore_auto(void *arg);
int route6_hlist_clear_lcore(void *arg);
int route6_hlists_clear_lcore(void *arg);
int new_route6_init(void *arg);


int
route_add_ifaddr_v6(struct inet_addr_param *param);
int
route_del_ifaddr_v6(struct inet_addr_param *param);

static inline void graph_route6_put(struct route6_entry *route)
{
    if(route){
        if (rte_atomic32_dec_and_test(&route->refcnt)) {
            rte_free((void *)route);
        }
    }
}

static inline void graph_route6_get(struct route6_entry *route)
{
    if(route){
        rte_atomic32_inc(&route->refcnt);
    }
}

static inline int dump_route6_prefix(const struct rt6_prefix *rt6_p, char *buf, int len)
{
    size_t rlen;

    if (!inet_ntop(AF_INET6, &rt6_p->addr, buf, len))
        return 0;

    rlen = strlen(buf);
    rlen += snprintf(buf+rlen, len-rlen, "/%d", rt6_p->plen);

    return rlen;
}

static inline unsigned int rte_ipv6_mtu_forward(struct route6_entry *rt)
{
    if (rt->rt6_mtu)
        return rt->rt6_mtu;
    else if (rt->rt6_dev && rt->rt6_dev->mtu)
        return rt->rt6_dev->mtu;
    else
        return IPV6_MIN_MTU;
}


#endif  //__NODE_ROUTE6_PRIV_H__


