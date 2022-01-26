/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021 chc.
 */

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_ip_frag.h>

#include "ip4_local_deliver_priv.h"
#include "l3_node_priv.h"
#include "log_priv.h"
#include "switch_cli_priv.h"

/* Should be power of two. */
#define	IP_FRAG_TBL_BUCKET_ENTRIES	16
#define	DEF_FLOW_NUM	0x1000

#define	DEF_FLOW_TTL	MS_PER_S
#define	DEF_FLOW_NUM_MIN	0x10

static uint32_t max_flow_num = DEF_FLOW_NUM;
static uint32_t max_flow_ttl = DEF_FLOW_TTL;

pthread_mutex_t ip_reassemble_mutex = PTHREAD_MUTEX_INITIALIZER;

#define this_lcore_frag_tbl        (RTE_PER_LCORE(frag_tbl))
#define this_lcore_death_row        (RTE_PER_LCORE(death_row))
RTE_DEFINE_PER_LCORE(struct rte_ip_frag_tbl *, frag_tbl);
RTE_DEFINE_PER_LCORE(struct rte_ip_frag_death_row, death_row);

static __rte_always_inline uint16_t
ip4_local_deliver(s_nc_param_l3 *param)
{
    struct rte_mbuf *mbuf = param->mbuf;
    struct rte_mbuf **mbuf2 = param->mbuf2;
    struct rte_node *node = param->node;
    struct rte_graph *graph = param->graph;
    struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod(mbuf,
        struct rte_ipv4_hdr *);

    L3_DEBUG_TRACE(L3_INFO, "%s node recieved mbuf...\n", __func__);
    PrintMbufPkt(mbuf, 0, 0);

    if(unlikely(rte_ipv4_frag_pkt_is_fragmented(iph))) {
        uint64_t cur_tsc = rte_rdtsc();
        /* prepare mbuf: ip4_rcv already setup l2_len/l3_len. */
        /* process this fragment. */

#ifndef IP_REASSEMBLE_USE_PER_LCORE_TBL
        pthread_mutex_lock(&ip_reassemble_mutex);
#endif
        struct rte_mbuf *mo = rte_ipv4_frag_reassemble_packet(
            this_lcore_frag_tbl, &this_lcore_death_row,
            mbuf, cur_tsc, iph);
#ifndef IP_REASSEMBLE_USE_PER_LCORE_TBL
        pthread_mutex_unlock(&ip_reassemble_mutex);
#endif

        if (this_lcore_death_row.cnt) {
            rte_node_enqueue(graph, node, IP4_LOCAL_DELIVER_NEXT_DROP,
                (void **)this_lcore_death_row.row, this_lcore_death_row.cnt);
            this_lcore_death_row.cnt = 0;
        }
        *mbuf2 = mo;
        /* defrag not complete or err */
        if (mo == NULL) {
            /* rte_pktmbuf_free_bulk can deal NULL */
            return IP4_LOCAL_DELIVER_NEXT_DROP;
        }
        mbuf = *mbuf2;

        /* update offloading flags */
        mbuf->ol_flags |= (PKT_TX_IPV4 | PKT_TX_IP_CKSUM);

        //iph = rte_pktmbuf_mtod(*mbuf2, struct rte_ipv4_hdr *);
        //iph->hdr_checksum = 0;
        //iph->hdr_checksum = rte_ipv4_cksum(iph);
        L3_DEBUG_TRACE(L3_INFO, "%s node:ip reassemble success\n", __func__);
        PrintMbufPkt(mbuf, 0, 1);
    }

    if (unlikely(get_switch_nf())) {
        return IP4_LOCAL_DELIVER_NEXT_FW;
    }

    return IP4_LOCAL_DELIVER_NEXT_FINISH;
}

static uint16_t
ip4_local_deliver_node_process(struct rte_graph *graph, 
            struct rte_node *node, void **objs, uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs, 
        nb_objs, IP4_LOCAL_DELIVER_NEXT_FINISH, ip4_local_deliver);
}

static struct rte_ip_frag_tbl *
create_frag_tbl(void)
{
    struct rte_ip_frag_tbl *frag_tbl;

    uint16_t socket = rte_lcore_to_socket_id(rte_lcore_id());
    uint64_t frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S *
            max_flow_ttl;

    if ((frag_tbl = rte_ip_frag_table_create(
        max_flow_num, IP_FRAG_TBL_BUCKET_ENTRIES, max_flow_num, 
        frag_cycles, socket)) == NULL) {
        RTE_LOG(INFO, TYPE_L3, "%s:lcore %d "
            "socket %d create frag table failed!\n",
            __FUNCTION__, rte_lcore_id(), socket);
        printf("%s:lcore %d "
            "socket %d create frag table failed!\n",
            __FUNCTION__, rte_lcore_id(), socket);
        return NULL;
    }

    size_t tbl_size = 0;
    if (rte_malloc_validate(frag_tbl, &tbl_size) == 0) {
        RTE_LOG(INFO, TYPE_L3,
            "lcore %d socket %d create frag table success,max_flow_num:%u,size:%zu\n", 
            rte_lcore_id(), socket, max_flow_num, tbl_size);
        printf(
            "lcore %d socket %d create frag table success,max_flow_num:%u,size:%zu\n", 
            rte_lcore_id(), socket, max_flow_num, tbl_size);
    }

    return frag_tbl;
}

#ifdef IP_REASSEMBLE_USE_PER_LCORE_TBL
static int
free_frag_tbl_per_lcore(void *arg)
{
    RTE_SET_USED(arg);
    if (this_lcore_frag_tbl) {
        RTE_LOG(INFO, TYPE_L3, "free frag_tbl\n");
        rte_ip_frag_table_destroy(this_lcore_frag_tbl);
        this_lcore_frag_tbl = NULL;
    }

    return 0;
}

static int
init_frag_tbl_per_lcore(void *arg)
{
    RTE_SET_USED(arg);

    if (netif_lcore_is_fwd_worker(rte_lcore_id()) == false) {
        this_lcore_frag_tbl == NULL;
        return 0;
    }

    this_lcore_frag_tbl = create_frag_tbl();
    if (this_lcore_frag_tbl == NULL) {
        return -ENOSPC;
    }

    return 0;
}
#else
static int
init_frag_tbl_global(void *arg)
{
    this_lcore_frag_tbl = (struct rte_ip_frag_tbl *)arg;
    return 0;
}
#endif

static int
ip4_local_deliver_node_init(const struct rte_graph *graph, 
        struct rte_node *node)
{   
    uint16_t lcore_id;
    static uint8_t init_once;

    RTE_SET_USED(graph);
    RTE_SET_USED(node);

    if (!init_once) {
        init_once = 1;

        uint8_t run = 1;
        while(run) {
            run = 0;
#ifdef IP_REASSEMBLE_USE_PER_LCORE_TBL
            /* Launch per-lcore init on every worker lcore */
            printf("call init_frag_tbl_per_lcore\n");
            rte_eal_mp_remote_launch(init_frag_tbl_per_lcore, NULL, SKIP_MAIN);            
            RTE_LCORE_FOREACH_WORKER(lcore_id) {
                if (rte_eal_wait_lcore(lcore_id) < 0) {
                    run = 1;
                }
            }

            if (run) {
                /* Launch per-lcore init on every worker lcore */
                printf("call free_frag_tbl_per_lcore\n");
                rte_eal_mp_remote_launch(free_frag_tbl_per_lcore, NULL, SKIP_MAIN);                    
                RTE_LCORE_FOREACH_WORKER(lcore_id) {
                    if (rte_eal_wait_lcore(lcore_id) < 0) {
                        return -rte_errno;
                    }
                }
                
                max_flow_num /= 2;
                if (max_flow_num < DEF_FLOW_NUM_MIN) {
                    RTE_LOG(ERR, TYPE_L3, 
                        "%s:create frag table failed!!!need:%u,act:%u\n",
                        __FUNCTION__, DEF_FLOW_NUM_MIN, max_flow_num);
                    printf(
                        "%s:create frag table failed!!!need:%u,act:%u\n",
                        __FUNCTION__, DEF_FLOW_NUM_MIN, max_flow_num);
                    return -ENOSPC;
                }
                printf("create frag table again,max_flow_num:%u\n", max_flow_num);
            }
#else
            struct rte_ip_frag_tbl *frag_tbl = create_frag_tbl();
            if (frag_tbl == NULL) {
                max_flow_num /= 2;
                if (max_flow_num < DEF_FLOW_NUM_MIN) {
                    RTE_LOG(ERR, TYPE_L3, 
                        "%s:create frag table failed!!!need:%u,act:%u\n",
                        __FUNCTION__, DEF_FLOW_NUM_MIN, max_flow_num);
                    printf(
                        "%s:create frag table failed!!!need:%u,act:%u\n",
                        __FUNCTION__, DEF_FLOW_NUM_MIN, max_flow_num);
                    return -ENOSPC;
                }
                run = 1;
                printf("create frag table again,max_flow_num:%u\n", max_flow_num);
            } else {
                /* Launch per-lcore init on every worker lcore */
                printf("call init_frag_tbl_global\n");
                rte_eal_mp_remote_launch(init_frag_tbl_global, frag_tbl, SKIP_MAIN);                    
                RTE_LCORE_FOREACH_WORKER(lcore_id) {
                    if (rte_eal_wait_lcore(lcore_id) < 0) {
                        return -rte_errno;
                    }
                }
                run = 0;
            }
#endif
        }

    }

    return 0;
}

struct rte_node_register ip4_local_deliver_node = {
	.process = ip4_local_deliver_node_process,
	.name = NODE_NAME_IP4_LOCAL_DELIVER,

    .init = ip4_local_deliver_node_init,
    
	.nb_edges = IP4_LOCAL_DELIVER_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[IP4_LOCAL_DELIVER_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[IP4_LOCAL_DELIVER_NEXT_FINISH] = NODE_NAME_IP4_LOCAL_DELIVER_FINISH,
        [IP4_LOCAL_DELIVER_NEXT_FW] = NODE_NAME_NF_IP_LOCAL_IN,
    },
};
RTE_NODE_REGISTER(ip4_local_deliver_node);
