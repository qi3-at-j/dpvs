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

#include <rte_byteorder.h>

#include "route_priv.h"
#include "vrf_priv.h"
#include "log_priv.h"

#define ZERONET(x)	(((x) & rte_be_to_cpu_32(0xff000000)) == rte_be_to_cpu_32(0x00000000))
#define LOCAL_OK	1
#define BRD_OK		2
#define BRD0_OK		4
#define BRD1_OK		8

struct route_table *g_lcores_route_tables_p[RTE_MAX_LCORE]; // for cmd pthread

#define this_lcore_route_tables_p      (RTE_PER_LCORE(route_tables_lcore))
#define this_lcore_socket_id        (RTE_PER_LCORE(socket_id_lcore))

static RTE_DEFINE_PER_LCORE(struct route_table *, route_tables_lcore);
static RTE_DEFINE_PER_LCORE(uint32_t, socket_id_lcore);

static inline void route4_put_self(struct route_entry *route)
{
    if(route){
        if (rte_atomic32_dec_and_test(&route->refcnt)) {
            rte_free((void *)route);
        }
    }
}

#if 0
static inline uint32_t __attribute__((pure))
        depth_to_mask(uint8_t depth)
{
    if (depth>0) {
        return (int)0x80000000 >> (depth - 1);
    }
    else
        return (int)0x0;
}

static inline bool ip_addr_netcmp(uint32_t dest, uint8_t mask,
                                  const struct route_entry *route_node)
{
    uint32_t net_mask = depth_to_mask(route_node->netmask);
    uint32_t dest_mask = depth_to_mask(mask);

    return  ((rte_be_to_cpu_32(dest) & dest_mask) == \
            (rte_be_to_cpu_32(route_node->dest.s_addr) & net_mask))?1:0;
}
#endif

static inline bool net_cmp(const struct netif_port *port, uint32_t dest,
                           uint8_t mask, const struct route_entry *route_node)
{
    if ((port->id == route_node->port->id)&&
        (ip_addr_netcmp(dest, mask, route_node)))
        return 1;
    return 0;
}

static inline uint32_t
route_local_hashkey(struct in_addr *ip_addr)
{
    return rte_be_to_cpu_32(ip_addr->s_addr)&LOCAL_ROUTE_TAB_MASK;
}

static struct route_entry *route_new_entry(struct in_addr* dest,
                                           uint8_t netmask, uint32_t flag,
                                           struct in_addr* gw, struct netif_port *port,
                                           struct in_addr* src, unsigned long mtu,
                                           short metric)
{
    struct route_entry *new_route=NULL;
    if(!dest)
        return NULL;
    new_route = (struct route_entry *)rte_zmalloc_socket("new_route_entry", 
        sizeof(struct route_entry), RTE_CACHE_LINE_SIZE, this_lcore_socket_id);
    if (new_route == NULL){
        return NULL;
    }
    
    new_route->dest.s_addr = dest->s_addr;
    new_route->netmask = netmask;
    new_route->flag = flag;
    if(!gw)
        new_route->gw.s_addr = 0;
    else
        new_route->gw = *gw;
    new_route->port = port;
    if(!src)
        new_route->src.s_addr = 0;
    else
        new_route->src = *src;
    if(mtu != 0)
        new_route->mtu = mtu;
    else
        new_route->mtu = port->mtu;
    new_route->metric = metric;
    rte_atomic32_set(&new_route->refcnt, 0);
    return new_route;

}

static struct route_entry *route_local_lookup(struct route_table *route_table, 
    struct in_addr *dest, struct netif_port *port)
{
    unsigned hashkey;
    struct route_entry *route_node;
    hashkey = route_local_hashkey(dest);
    list_for_each_entry(route_node, &route_table->local_route_table[hashkey], list) {
        if (port ? ((dest->s_addr == route_node->dest.s_addr)
                && (port->id == route_node->port->id)) : 
                (dest->s_addr == route_node->dest.s_addr)) {
            rte_atomic32_inc(&route_node->refcnt);
            return route_node;
        }
    }
    return NULL;
}

static struct route_entry *route_net_lookup(struct route_table *route_table, 
    struct in_addr *dest, struct netif_port *port, uint8_t netmask)
{
    struct route_entry *route_node;
    struct netif_port *port_tmp = port;
    uint8_t netmask_tmp = netmask;

    list_for_each_entry(route_node, &route_table->net_route_table, list) {
        if (likely(port == NULL)) {
            port_tmp = route_node->port;
            netmask_tmp = route_node->netmask;
        }
        if (net_cmp(port_tmp, dest->s_addr, netmask_tmp, route_node)) {
            rte_atomic32_inc(&route_node->refcnt);
            return route_node;
        }
    }
    return NULL;
}

static int route_net_add(struct route_table *route_table,
    struct in_addr *dest, uint8_t netmask, uint32_t flag,
    struct in_addr *gw, struct netif_port *port,
    struct in_addr *src, unsigned long mtu,short metric)
{
    struct route_entry *route_node, *route;

    list_for_each_entry(route_node, &route_table->net_route_table, list) {
        if (net_cmp(port, dest->s_addr, netmask, route_node)
                && (netmask == route_node->netmask)){
            return -EEXIST;
        }
        if (route_node->netmask < netmask){
            route = route_new_entry(dest, netmask, flag,
                                    gw, port, src, mtu, metric);
            if (!route){
                return -ENOMEM;
            }
            list_add(&route->list, (&route_node->list)->prev);
            rte_atomic32_inc(&route_table->cnt_net);
            rte_atomic32_inc(&route->refcnt);            
            return 0;
        }
    }

    route = route_new_entry(dest,netmask, flag,
                      gw, port, src, mtu, metric);
    if (!route){
        return -ENOMEM;
    }

    list_add_tail(&route->list, &route_table->net_route_table);
    rte_atomic32_inc(&route_table->cnt_net);
    rte_atomic32_inc(&route->refcnt);
    return 0;
}

static int route_local_add(struct route_table *route_table, 
    struct in_addr* dest, uint8_t netmask, uint32_t flag,
    struct in_addr* gw, struct netif_port *port,
    struct in_addr* src, unsigned long mtu,short metric)
{
    unsigned hashkey;
    struct route_entry *route;

    hashkey = route_local_hashkey(dest);
    list_for_each_entry(route, &route_table->local_route_table[hashkey], list) {
        if (port ? ((dest->s_addr == route->dest.s_addr)
                && (port->id == route->port->id)) : 
                (dest->s_addr == route->dest.s_addr)) {
            return -EEXIST;
        }
    }

    route = route_new_entry(dest,netmask, flag,
                      gw, port, src, mtu,metric);
    if (!route){
        return -ENOMEM;
    }

    list_add(&route->list, &route_table->local_route_table[hashkey]);
    rte_atomic32_inc(&route->refcnt);
    rte_atomic32_inc(&route_table->cnt_local);
    return 0;
}

static int route_add_lcore(struct route_table *route_table, 
    struct in_addr* dest,uint8_t netmask, uint32_t flag,
    struct in_addr* gw, struct netif_port *port,
    struct in_addr* src, unsigned long mtu,short metric)
{

    if((flag & ROUTE_FLAG_LOCALIN) || (flag & ROUTE_FLAG_KNI))
        return route_local_add(route_table, dest, netmask, flag, gw,
			      port, src, mtu, metric);

    if((flag & ROUTE_FLAG_FORWARD) || (flag & ROUTE_FLAG_DEFAULT))
        return route_net_add(route_table, dest, netmask, flag, gw,
                             port, src, mtu, metric); 

    return -EINVAL;
}

/* del route node in list, then mbuf next will never find it;
 * route4_put will delete route when refcnt is 0.
 * refcnt:
 * 1, new route is set to 0;
 * 2, add list will be 1;
 * 3, find route and ref it will +1;
 * 4, put route will -1;
 */
static int route_del_lcore(struct route_table *route_table, 
    struct in_addr* dest,uint8_t netmask, uint32_t flag,
    struct in_addr* gw, struct netif_port *port,
    struct in_addr* src, unsigned long mtu,short metric)
{
    struct route_entry *route = NULL;
    RTE_SET_USED(gw);
    RTE_SET_USED(src);
    RTE_SET_USED(mtu);
    RTE_SET_USED(metric);

    if(flag & ROUTE_FLAG_LOCALIN || (flag & ROUTE_FLAG_KNI)){
        route = route_local_lookup(route_table, dest, port);
        if (!route)
            return -ENOENT;
        list_del(&route->list);
        rte_atomic32_dec(&route->refcnt);
        rte_atomic32_dec(&route_table->cnt_local);
        route->flag |= ROUTE_FLAG_DEL;
        route4_put_self(route);
        return 0;
    }

    if(flag & ROUTE_FLAG_FORWARD || (flag & ROUTE_FLAG_DEFAULT)){
        route = route_net_lookup(route_table, dest, port, netmask);
        if (!route)
            return -ENOENT;
        list_del(&route->list);
        rte_atomic32_dec(&route->refcnt);
        rte_atomic32_dec(&route_table->cnt_net);
        route->flag |= ROUTE_FLAG_DEL;
        route4_put_self(route);
        return 0;
    }

    return -EINVAL;
}

static void route_local_dump(struct route_table *route_table)
{
    struct route_entry *route_node;
    int i;
    char dst_addr[64];

    for (i = 0; i < LOCAL_ROUTE_TAB_SIZE; i++) {
        list_for_each_entry(route_node, &route_table->local_route_table[i], list){
            if (route_node)
                L3_DEBUG_TRACE(L3_INFO, "==local=====dest:%s,netmast:%u\n", 
                    inet_ntop(AF_INET, &route_node->dest,
                        dst_addr, sizeof(dst_addr)), route_node->netmask);
        }
    }
}

static void route_net_dump(struct route_table *route_table)
{
    struct route_entry *route_node;
    char dst_addr[64];

    list_for_each_entry(route_node, &route_table->net_route_table, list){
        if (route_node)
            L3_DEBUG_TRACE(L3_INFO, "==net=====dest:%s,netmast:%u\n", 
            inet_ntop(AF_INET, &route_node->dest,
                dst_addr, sizeof(dst_addr)), route_node->netmask);
    }
}

/**
 * control plane
 */

struct route_entry *route_lookup(uint32_t flag,
    uint32_t table_id, uint32_t dest_addr)
{
    struct in_addr dest;
    struct route_entry *route_node = NULL;
    
    dest.s_addr = dest_addr;
    struct route_table *route_table = &this_lcore_route_tables_p[table_id];

    if (flag & ROUTE_FLAG_LOCALIN || (flag & ROUTE_FLAG_KNI))
        route_node = route_local_lookup(route_table, &dest, NULL);

    if (route_node == NULL) {
        if (flag & ROUTE_FLAG_FORWARD || (flag & ROUTE_FLAG_DEFAULT))
            route_node = route_net_lookup(route_table, &dest, NULL, 0);
    }

    return route_node;
}

int new_route_init(void *arg)
{
    int i, j;

    RTE_SET_USED(arg);

    this_lcore_socket_id = rte_lcore_to_socket_id(rte_lcore_id());
    this_lcore_route_tables_p = (struct route_table *)rte_zmalloc_socket
        ("new_route_table", sizeof(struct route_table) * MAX_ROUTE_TBLS, 
        RTE_CACHE_LINE_SIZE, this_lcore_socket_id);
    if (this_lcore_route_tables_p == NULL){
        return -ENOMEM;
    }
        
    for (j = 0; j < MAX_ROUTE_TBLS; j++) {
        for (i = 0; i < LOCAL_ROUTE_TAB_SIZE; i++) {
            INIT_LIST_HEAD(&this_lcore_route_tables_p[j].local_route_table[i]);
        }
        INIT_LIST_HEAD(&this_lcore_route_tables_p[j].net_route_table);
        rte_atomic32_set(&this_lcore_route_tables_p[j].cnt_local, 0);
        rte_atomic32_set(&this_lcore_route_tables_p[j].cnt_net, 0);
        this_lcore_route_tables_p[j].table_id = j;
    }

    g_lcores_route_tables_p[rte_lcore_id()] = this_lcore_route_tables_p;

    return 0;
}

int new_route_add(void *arg)
{
    struct route_table *route_table;
    struct route_entry *route_entry;

    if (unlikely(arg == NULL)) {
        return -EINVAL;
    }

    route_entry = (struct route_entry *)arg;
    route_table = &this_lcore_route_tables_p[route_entry->table_id];

    return(route_add_lcore(route_table, &route_entry->dest, route_entry->netmask, 
        route_entry->flag, &route_entry->gw, route_entry->port, 
        &route_entry->src, route_entry->mtu, route_entry->metric));
}

int new_route_del(void *arg)
{
    struct route_table *route_table;
    struct route_entry *route_entry;
    
    if (unlikely(arg == NULL)) {
        return -EINVAL;
    }

    route_entry = (struct route_entry *)arg;
    route_table = &this_lcore_route_tables_p[route_entry->table_id];

    return(route_del_lcore(route_table, &route_entry->dest, route_entry->netmask, 
        route_entry->flag, &route_entry->gw, route_entry->port, 
        &route_entry->src, route_entry->mtu, route_entry->metric));
}

int route_table_clear(void *arg)
{
    int i;
    uint32_t table_id;
    struct route_entry *route_node, *next_route_node;

    if (unlikely((arg == NULL) || ((table_id = *(uint32_t *)arg) >= MAX_ROUTE_TBLS))) {
        return -EINVAL;
    }

    RTE_SET_USED(arg);
    if (this_lcore_route_tables_p[table_id].cnt_local.cnt) {
        for (i = 0; i < LOCAL_ROUTE_TAB_SIZE; i++){
            list_for_each_entry_safe(route_node, next_route_node,
                &this_lcore_route_tables_p[table_id].local_route_table[i], list){
                list_del(&route_node->list);
                rte_atomic32_dec(&this_lcore_route_tables_p[table_id].cnt_local);
                route4_put_self(route_node);
            }
        }
    }

    if (this_lcore_route_tables_p[table_id].cnt_net.cnt) {
        list_for_each_entry_safe(route_node, next_route_node,
            &this_lcore_route_tables_p[table_id].net_route_table, list){
            list_del(&route_node->list);
            rte_atomic32_dec(&this_lcore_route_tables_p[table_id].cnt_net);
            route4_put_self(route_node);
        }
    }

    return 0;
}

int route_tables_clear(void *arg)
{
    uint32_t table_id;
    int ret;

    RTE_SET_USED(arg);
    for (table_id = 0; table_id < MAX_ROUTE_TBLS; table_id++) {
        if ((ret = route_table_clear((void *)&table_id)) < 0) {
            return ret;
        }
    }

    return 0;
}

int route_table_dump(void *arg)
{
    uint32_t table_id;

    if (unlikely((arg == NULL) || ((table_id = *(uint32_t *)arg) >= MAX_ROUTE_TBLS))) {
        return -EINVAL;
    }

    struct route_table *route_table = &this_lcore_route_tables_p[table_id];
    if (route_table->cnt_local.cnt || route_table->cnt_net.cnt) {
        L3_DEBUG_TRACE(L3_INFO, "==route table id:%u\n", table_id);
    }

    if (route_table->cnt_local.cnt) {
        L3_DEBUG_TRACE(L3_INFO, "==local=====cnt:%d\n", route_table->cnt_local.cnt);
        route_local_dump(route_table);
    }

    if (route_table->cnt_net.cnt) {
        L3_DEBUG_TRACE(L3_INFO, "==net=====cnt:%d\n", route_table->cnt_net.cnt);
        route_net_dump(route_table);
    }

    return 0;
}

int route_tables_dump(void *arg)
{
    uint32_t table_id;
    int ret;

    RTE_SET_USED(arg);
    for (table_id = 0; table_id < MAX_ROUTE_TBLS; table_id++) {
        if ((ret = route_table_dump((void *)&table_id)) < 0) {
            return ret;
        }
    }
    return 0;
}

int route_add_auto(struct route_ifa_entry *ifa)
{
    struct route_entry route_node_auto;
    uint32_t mask = rte_be_to_cpu_32(depth_to_mask(ifa->plen));
    uint32_t addr = ifa->addr.s_addr;
    uint32_t prefix = ifa->addr.s_addr & mask;
    if (unlikely(ifa->port == NULL)) {
        printf("%s:port is null!\n", __func__);
        return -EINVAL;
    }

    memset(&route_node_auto, 0, sizeof(struct route_entry));
    route_node_auto.mtu = ifa->port->mtu;

    route_node_auto.flag = ROUTE_FLAG_LOCALIN;
    route_node_auto.dest = ifa->addr;
    route_node_auto.netmask = 32;
    route_node_auto.port = ifa->port;
    new_route_add(&route_node_auto);

    if (ifa->port->flags & NETIF_PORT_FLAG_UP) {
        if (ifa->bcast.s_addr && ifa->bcast.s_addr != 0xFFFFFFFF) {
            route_node_auto.flag = ROUTE_FLAG_LOCALIN;
            route_node_auto.dest = ifa->bcast;
            route_node_auto.netmask = 32;
            route_node_auto.port = ifa->port;
            new_route_add(&route_node_auto);
        }

        if (!ZERONET(prefix) && (prefix != addr || ifa->plen < 32)) {
            route_node_auto.flag = ROUTE_FLAG_FORWARD;
            route_node_auto.dest.s_addr = prefix;
            route_node_auto.netmask = ifa->plen;
            route_node_auto.port = ifa->port;
            new_route_add(&route_node_auto);

            if (ifa->plen < 31) {               
                route_node_auto.flag = ROUTE_FLAG_LOCALIN;
                route_node_auto.dest.s_addr = prefix;
                route_node_auto.netmask = 32;
                route_node_auto.port = ifa->port;
                new_route_add(&route_node_auto);

                route_node_auto.flag = ROUTE_FLAG_LOCALIN;
                route_node_auto.dest.s_addr = prefix|~mask;
                route_node_auto.netmask = 32;
                route_node_auto.port = ifa->port;
               new_route_add(&route_node_auto);
           }
        }        
    }

    return 0;
}

extern struct inet_device *dev_get_idev(const struct netif_port *dev);
int route_del_auto(struct route_ifa_entry *ifa)
{   
    struct route_entry route_node_auto;
    uint32_t mask = rte_be_to_cpu_32(depth_to_mask(ifa->plen));
	uint32_t brd = ifa->addr.s_addr|~mask;
	uint32_t any = ifa->addr.s_addr&mask;
    if (unlikely(ifa->port == NULL)) {
        printf("%s:port is null!\n", __func__);
        return -EINVAL;
    }

    memset(&route_node_auto, 0, sizeof(struct route_entry));
    route_node_auto.mtu = ifa->port->mtu;

    route_node_auto.flag = ROUTE_FLAG_FORWARD;
    route_node_auto.dest.s_addr = any;
    route_node_auto.netmask = ifa->plen;
    route_node_auto.port = ifa->port;
    new_route_del((void *)&route_node_auto);

    struct inet_device *idev = dev_get_idev(ifa->port);
    if (unlikely(idev == NULL)) {
        printf("%s:port %s idev is null!\n", ifa->port->name, __func__);
        return -EINVAL;
    }
    struct inet_ifaddr *ifa1;
    uint32_t ok = 0;
    //list_for_each_entry(ifa1, &idev->this_ifa_list, d_list) {
    list_for_each_entry(ifa1, &idev->ifa_list[0], d_list) {
        if (ifa->addr.s_addr == ifa1->addr.in.s_addr) {
            ok |= LOCAL_OK;
        }
        if (ifa->bcast.s_addr == ifa1->bcast.in.s_addr) {
            ok |= BRD_OK;
        }
        if (brd == ifa1->bcast.in.s_addr) {
            ok |= BRD1_OK;
        }
        if (any== ifa1->bcast.in.s_addr) {
            ok |= BRD0_OK;
        }
    }

    if (likely(idev))
        rte_atomic32_dec(&idev->refcnt);

    if (!(ok&BRD_OK) && ifa->bcast.s_addr && ifa->bcast.s_addr != 0xFFFFFFFF) {
        route_node_auto.flag = ROUTE_FLAG_LOCALIN;
        route_node_auto.dest = ifa->bcast;
        route_node_auto.netmask = 32;
        route_node_auto.port = ifa->port;
        new_route_del((void *)&route_node_auto);
    }
    if (!(ok&BRD1_OK)) {
        route_node_auto.flag = ROUTE_FLAG_LOCALIN;
        route_node_auto.dest.s_addr = brd;
        route_node_auto.netmask = 32;
        route_node_auto.port = ifa->port;
        new_route_del((void *)&route_node_auto);
    }
    if (!(ok&BRD0_OK)) {
        route_node_auto.flag = ROUTE_FLAG_LOCALIN;
        route_node_auto.dest.s_addr = any;
        route_node_auto.netmask = 32;
        route_node_auto.port = ifa->port;
        new_route_del((void *)&route_node_auto);
    }
    if (!(ok&LOCAL_OK) && !ifa->local_keep) {       
        route_node_auto.flag = ROUTE_FLAG_LOCALIN;
        route_node_auto.dest = ifa->addr;
        route_node_auto.netmask = 32;
        route_node_auto.port = ifa->port;
        new_route_del((void *)&route_node_auto);
    }

    return 0;
}

extern int
is_route_del(struct route_entry *route);
int
is_route_del(struct route_entry *route)
{
    return route->flag & ROUTE_FLAG_DEL;
}
