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

#ifndef __TYFLOW_NEIGH_SYNC_H__
#define __TYFLOW_NEIGH_SYNC_H__

#define RTE_LOGTYPE_NEIGHBOUR RTE_LOGTYPE_USER2

struct raw_neigh {
    int               af;
    uint32_t          table_id;
    union inet_addr   ip_addr;
    struct rte_ether_addr eth_addr;
    struct netif_port *port;
    bool              add;
    uint8_t           flag;
    uint8_t           type;
#define NEIGH_ENTRY 1
#define NEIGH_PARAM 2
#define NEIGH_GRAPH 3
} __rte_cache_aligned;

int
neigh_sync_core(const void *param, bool add_del, uint32_t type);
int
neigh_sync_init(void);
void
neigh_sync_term(void);

#endif /* __TYFLOW_NEIGH_SYNC_H__ */
