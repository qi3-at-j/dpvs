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
#include <stdio.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <rte_ether.h>
#include <rte_arp.h>

#include "dpdk.h"
#include "parser/parser.h"
#include "netif.h"
#include "conf/common.h"
#include "route.h"
#include "ctrl.h"
#include "scheduler.h"
#include "mempool.h"
#include "neigh_sync.h"

/****************************master core sync*******************************************/
static struct rte_ring *neigh_ring[DPVS_MAX_LCORE];

#define MAC_RING_SIZE 2048

static int neigh_ring_init(void)
{
    char name_buf[RTE_RING_NAMESIZE];
    int socket_id;
    uint8_t cid;
    socket_id = rte_socket_id();
    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        snprintf(name_buf, RTE_RING_NAMESIZE, "neigh_ring_c%d", cid);
        neigh_ring[cid] = rte_ring_create(name_buf, MAC_RING_SIZE,
                                          socket_id, RING_F_SC_DEQ);
        if (neigh_ring[cid] == NULL)
            rte_panic("create ring:%s failed!\n", name_buf);
    }
    return EDPVS_OK;
}

static lcoreid_t master_cid = 0;
extern struct dpvs_mempool *neigh_mempool;

struct raw_neigh* 
neigh_ring_clone_entry(void *param, bool add);
struct raw_neigh* 
neigh_ring_clone_param(void *param, bool add);
struct raw_neigh* 
neigh_ring_clone_graph(void *param, bool add);
int 
neigh_sync_core(const void *param, bool add_del, uint32_t type)
{
    struct raw_neigh *mac_param;
    int ret = 0;
    lcoreid_t cid, i;
    cid = rte_lcore_id();

    for (i = 0; i < DPVS_MAX_LCORE; i++) {
        if ((i == cid) || (!is_lcore_id_valid(i)) || (i == master_cid))
            continue;
        switch (type) {
        case NEIGH_ENTRY:
            mac_param = neigh_ring_clone_entry(param, add_del);
            break;
        case NEIGH_PARAM:
            mac_param = neigh_ring_clone_param(param, add_del);
            break;
        case NEIGH_GRAPH:
            mac_param = neigh_ring_clone_graph(param, add_del);
            break;
        default:
            return EDPVS_NOTSUPP;
        }

        if (mac_param) {
            ret = rte_ring_enqueue(neigh_ring[i], mac_param);
            if (unlikely(-EDQUOT == ret)) {
                RTE_LOG(WARNING, NEIGHBOUR, "%s: neigh ring quota exceeded\n",
                __func__);
            } else if (ret < 0) {
                dpvs_mempool_put(neigh_mempool, mac_param);
                RTE_LOG(WARNING, NEIGHBOUR, "%s: neigh ring enqueue failed\n",
                __func__);
                return EDPVS_DPDKAPIFAIL;
            }
        } else {
            RTE_LOG(WARNING, NEIGHBOUR, "%s: clone mac faild\n", __func__);
            return EDPVS_NOMEM;
        }
    }

    return EDPVS_OK;
}

void 
neigh_add_by_param(struct raw_neigh *param);
void 
neigh_add_by_param_graph(struct raw_neigh *param);
/*
 *1, master core static neighbour sync slave core;
 *2, ipv6 slave core sync slave core when recieve ns/na
 */
static void neigh_process_ring(void *arg)
{
    struct raw_neigh *params[NETIF_MAX_PKT_BURST];
    uint16_t nb_rb;
    struct raw_neigh *param;
    lcoreid_t cid = rte_lcore_id();

    nb_rb = rte_ring_dequeue_burst(neigh_ring[cid], (void **)params,
                                   NETIF_MAX_PKT_BURST, NULL);
    if (nb_rb > 0) {
        int i;
        for (i = 0; i < nb_rb; i++) {
            param = params[i];
            if (param->type == NEIGH_ENTRY) {
                neigh_add_by_param(param);
            } else {
                neigh_add_by_param_graph(param);
            }
            dpvs_mempool_put(neigh_mempool, param);
        }
    }
}

#define NEIGH_PROCESS_MAC_RING_INTERVAL 100

#define NEIGH_LCORE_JOB_MAX     2

static struct dpvs_lcore_job_array neigh_sync_jobs[NEIGH_LCORE_JOB_MAX] = {
    [0] = {
        .role = LCORE_ROLE_FWD_WORKER,
        .job.name = "neigh_sync",
        .job.type = LCORE_JOB_SLOW,
        .job.func = neigh_process_ring,
        .job.skip_loops = NEIGH_PROCESS_MAC_RING_INTERVAL,
    },

    [1] = {
        .role = LCORE_ROLE_MASTER,
        .job.name = "neigh_sync",
        .job.type = LCORE_JOB_LOOP,
        .job.func = neigh_process_ring,
    }
};

int
neigh_sync_init(void)
{
    int i, err;

    master_cid = rte_lcore_id();
    neigh_ring_init();
    for (i = 0; i < NELEMS(neigh_sync_jobs); i++) {
        if ((err = dpvs_lcore_job_register(&neigh_sync_jobs[i].job,
                                           neigh_sync_jobs[i].role)) != EDPVS_OK)
            return err;
    }

    return EDPVS_OK;
}

void
neigh_sync_term(void)
{
    int i;

    for (i = 0; i < NELEMS(neigh_sync_jobs); i++)
        dpvs_lcore_job_unregister(&neigh_sync_jobs[i].job, neigh_sync_jobs[i].role);
}
