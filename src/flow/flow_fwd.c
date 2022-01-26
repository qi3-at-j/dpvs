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

#include "ipv4.h"
#include "ipv6.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "flow.h"
#include "debug_flow.h"
#include "flow_cli.h"
#include "flow_profile.h"
#include "flow_fwd.h"
#include "l3_node_priv.h"
#include "ip4_forward_priv.h"

uint16_t fwd_i[RTE_MAX_LCORE][RTE_MAX_LCORE];
#define MAX_BUFS_PERq (RTE_GRAPH_BURST_SIZE<<2)
typedef struct {
    struct rte_mbuf *q[MAX_BUFS_PERq];
    uint16_t prod;
    uint16_t cons;
} flow_fwd_mbuf_t;
flow_fwd_mbuf_t *ffmb_list;

typedef struct {
    struct rte_graph *graph;
    struct rte_node *node;
} flow_fwd_ctx_t;
/* per lcore flow forward packet to each other */
RTE_DEFINE_PER_LCORE(flow_fwd_ctx_t, ffctx);
#define this_ffctx (RTE_PER_LCORE(ffctx))

int
flow_fwd_enq(lcoreid_t sid, lcoreid_t did, struct rte_mbuf *mbuf)
{
    uint16_t i = fwd_i[sid][did], prod, cons, space;
    flow_fwd_mbuf_t *fwd_m = ffmb_list + i;

    prod = fwd_m->prod;
    cons = fwd_m->cons;
    space = prod-cons;
    if (space >= MAX_BUFS_PERq-1) {
        flow_print_basic("%s no room left, %d-%d\n", 
                         __FUNCTION__, prod, cons);
        return -1;
    }

    fwd_m->q[prod%MAX_BUFS_PERq] = mbuf;
    fwd_m->prod++;
    return 0;
}

struct rte_mbuf *
flow_fwd_deq(lcoreid_t sid, lcoreid_t did)
{
    uint16_t i = fwd_i[sid][did], prod, cons, item;
    flow_fwd_mbuf_t *fwd_m = ffmb_list + i;
    struct rte_mbuf *mbuf;

    prod = fwd_m->prod;
    cons = fwd_m->cons;
    item = prod-cons;
    if (item == 0) {
        return NULL;
    }
    fwd_m->cons++;
    mbuf = fwd_m->q[cons%MAX_BUFS_PERq];
    fwd_m->q[cons%MAX_BUFS_PERq] = NULL;
    return mbuf;
}

void
flow_flush_fwd_q(lcoreid_t did)
{
    lcoreid_t sid;
    struct rte_mbuf *mbuf;
    int rc;

    if (flow_worker_num <= 1) {
        return;
    }
    RTE_LCORE_FOREACH_SLAVE(sid) {
        if (did == sid) continue;
        if (g_lcore_role[sid] != LCORE_ROLE_FWD_WORKER) {
            continue;
        }
        mbuf = flow_fwd_deq(sid, did);
        if (!mbuf) continue;
        rc = flow_processing_paks(mbuf);
        if (rc == 0) {
            rte_node_enqueue_x1(this_ffctx.graph, this_ffctx.node, IP4_FORWARD_NEXT_FINISH, mbuf);
        } else {
            rte_node_enqueue_x1(this_ffctx.graph, this_ffctx.node, IP4_FORWARD_NEXT_DROP, mbuf);
        }
    }
}

int
flow_fwd_init_lcore(lcoreid_t cid)
{
    char graph_name[RTE_GRAPH_NAMESIZE];

    snprintf(graph_name, RTE_GRAPH_NAMESIZE, "worker_%u", cid);
    this_ffctx.graph = rte_graph_lookup(graph_name);
    if (!this_ffctx.graph) {
        RTE_LOG(ERR, FLOW, "%s: no graph for %s\n",
                __func__, graph_name);
        return -1;
    }
    this_ffctx.node = rte_graph_node_get_by_name(graph_name, NODE_NAME_IP4_FORWARD);
    if (!this_ffctx.node) {
        RTE_LOG(ERR, FLOW, "%s: no node for %s - %s\n",
                __func__, graph_name, NODE_NAME_IP4_FORWARD);
        return -1;
    }
    return 0;
}

uint8_t flow_worker_hash[UINT8_MAX];
int flow_worker_num;
int
flow_fwd_init(void)
{
    uint32_t i;
    uint16_t j, k;

    i = 0;
    RTE_LCORE_FOREACH_SLAVE(j) {
        if (g_lcore_role[j] != LCORE_ROLE_FWD_WORKER) {
            continue;
        }
        flow_worker_hash[flow_worker_num] = j;
        flow_worker_num++;
        RTE_LCORE_FOREACH_SLAVE(k) {
            if (k == j) continue;
            if (g_lcore_role[k] != LCORE_ROLE_FWD_WORKER) {
                continue;
            }
            fwd_i[j][k] = i++;
        }
    }

    RTE_LOG(INFO, FLOW, "%s: fwd queue number %d.\n",
            __FUNCTION__, i);
    if (!i)
        return 0;

    for (j = flow_worker_num; j < UINT8_MAX; j++) {
        flow_worker_hash[j] = flow_worker_hash[j%flow_worker_num];
    }

    ffmb_list = (flow_fwd_mbuf_t *)rte_zmalloc("flow_fwd_m", sizeof(flow_fwd_mbuf_t)*i, 0);
    if (!ffmb_list) {
        RTE_LOG(ERR, FLOW, "%s: no memory for flow_fwd_m\n",
                __FUNCTION__);
        return -1;
    }

    return 0;
}
