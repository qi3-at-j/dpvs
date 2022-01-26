/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021 chc.
 */

#include <rte_arp.h>

#include "arp_rcv_priv.h"
#include "arp_priv.h"
#include "neigh_priv.h"
#include "vrf_priv.h"
#include "l3_node_priv.h"
#include "log_priv.h"
#include "switch_cli_priv.h"
#include "vrrp_send_priv.h"

#include "netif.h"
#include "inet.h"
#include "inetaddr.h"
#include "mempool.h"

static __rte_always_inline uint16_t
arp_update(struct rte_arp_hdr *arp, uint32_t table_id,
    struct netif_port* port, struct rte_graph *graph,
    struct rte_node *node)
{   
    struct in_addr in_ipaddr;
    struct neigh_entry *neighbour = NULL;

    in_ipaddr.s_addr = arp->arp_data.arp_sip;
    neighbour = neigh_lookup(table_id, AF_INET, (union inet_addr *)&in_ipaddr);
    if (neighbour) {
        if (!(neighbour->flag & NEIGH_STATIC)) {
            rte_memcpy(&neighbour->d_mac, &arp->arp_data.arp_sha, 6);
        }
    } else {
        neighbour = neigh_add_tbl(table_id, AF_INET, (union inet_addr *)&in_ipaddr,
            &arp->arp_data.arp_sha, port, 0);
        if (!neighbour) {
            L3_DEBUG_TRACE(L3_ERR, "%s: add neighbour wrong\n", __func__);
            return -1;
        }
    }

    if (!(neighbour->flag & NEIGH_STATIC)) {
        neigh_entry_state_trans_graph(neighbour, 1);
        neigh_send_mbuf_cach_graph(neighbour);
        neigh_sync_core(neighbour, 1, NEIGH_GRAPH);
#if 0
        struct rte_mbuf *m;
        struct neigh_mbuf_entry *mbuf_entry, *mbuf_next;
        list_for_each_entry_safe(mbuf_entry, mbuf_next,
            &neighbour->queue_list, neigh_mbuf_list) {
            list_del(&mbuf_entry->neigh_mbuf_list);
            m = mbuf_entry->m;
            neigh_populate_mac(neighbour, m, neighbour->port, AF_INET);
            if (GET_MBUF_PRIV_DATA(m)->priv_data_is_vxlan) {
                rte_node_enqueue_x1(mbuf_entry->graph, mbuf_entry->node, ARP_RCV_NEXT_VXLAN, m);
            } else {
                rte_node_enqueue_x1(mbuf_entry->graph, mbuf_entry->node, ARP_RCV_NEXT_L2, m);
            }
            neighbour->que_num--;
            dpvs_mempool_put(get_neigh_mempool(), mbuf_entry);
        }
#endif
    }

    return 0;
}

static __rte_always_inline void
arp_pack_rep(struct rte_arp_hdr *arp,
    struct rte_mbuf *mbuf, struct netif_port* port, struct vrrp_entry *vrrp_node)
{   
    uint32_t ipaddr;
    struct rte_ether_hdr *eth= rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

    rte_ether_addr_copy(&eth->s_addr, &eth->d_addr);
    rte_memcpy(&eth->s_addr, &port->addr, RTE_ETHER_ADDR_LEN);
    arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

    rte_ether_addr_copy(&arp->arp_data.arp_sha, &arp->arp_data.arp_tha);

    if (vrrp_node) {
        rte_memcpy(&arp->arp_data.arp_sha, vrrp_node->mac, RTE_ETHER_ADDR_LEN);
    } else {
        rte_ether_addr_copy(&eth->s_addr, &arp->arp_data.arp_sha);
    }

    ipaddr = arp->arp_data.arp_sip;
    arp->arp_data.arp_sip = arp->arp_data.arp_tip;
    arp->arp_data.arp_tip = ipaddr;
    mbuf->l2_len = sizeof(struct rte_ether_hdr);
    mbuf->l3_len = sizeof(struct rte_arp_hdr);
}

static __rte_always_inline uint16_t
arp_rcv(s_nc_param_l3 *param)
{
    struct rte_mbuf *mbuf = param->mbuf;
    struct rte_node *node = param->node;
    struct rte_graph *graph = param->graph;
    uint16_t next_id = ARP_RCV_NEXT_DROP;

    L3_DEBUG_TRACE(L3_INFO, "%s node recieved mbuf...\n", __func__);
    PrintMbufPkt(mbuf, 1, 0);

    if (unlikely(!get_switch_arp())) {
        L3_DEBUG_TRACE(L3_INFO, "%s node:arp switch is off,drop!\n", __func__);
        return ARP_RCV_NEXT_DROP;
    }

    struct netif_port* port = (struct netif_port*)mbuf_dev_get(mbuf);
    if (port ? (port->flags & NETIF_PORT_FLAG_NO_ARP) : 1) {
        return ARP_RCV_NEXT_DROP;
    }

    if (unlikely(mbuf->packet_type == ETH_PKT_OTHERHOST)) {
        return ARP_RCV_NEXT_DROP;
    }

    if (new_mbuf_may_pull(mbuf, sizeof(struct rte_arp_hdr))) {
        L3_DEBUG_TRACE(L3_ERR, "%s:new_mbuf_may_pull error\n", __FUNCTION__);
        return ARP_RCV_NEXT_DROP;
    }

    struct rte_arp_hdr *arp = rte_pktmbuf_mtod_offset(mbuf,
        struct rte_arp_hdr *, RTE_ETHER_HDR_LEN);
    struct inet_ifaddr *ifa;
    uint32_t table_id = GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id;
    
    if (unlikely((arp->arp_opcode != htons(RTE_ARP_OP_REQUEST)) &&
        (arp->arp_opcode != htons(RTE_ARP_OP_REPLY)))) {
        return ARP_RCV_NEXT_DROP;
    }

    uint8_t local_flag = 1;
    uint8_t not_vrrp_flag = 1;
    struct vrrp_entry *vrrp_node = NULL;

    vrrp_node = lookup_vrrp_ip((union inet_addr*)&arp->arp_data.arp_tip, AF_INET);
    if (vrrp_node) {
        if (vrrp_node->status == VRRP_ST_SLAVE) {
            L3_DEBUG_TRACE(L3_ERR, "%s:is vrrp slave,drop!!!\n", __FUNCTION__);
            return ARP_RCV_NEXT_DROP;
        } else if (vrrp_node->status == VRRP_ST_MASTER) {
            not_vrrp_flag = 0;
        }
    }

    if (not_vrrp_flag) {
        vrrp_node = NULL;
        ifa = inet_addr_ifa_get(AF_INET, port, (union inet_addr*)&arp->arp_data.arp_tip);
        if (!ifa) {
            /* not Gratuitous ARP */
            if (arp->arp_data.arp_sip != arp->arp_data.arp_tip) {
                if (GET_MBUF_PRIV_DATA(mbuf)->priv_data_is_vxlan) {
                    return ARP_RCV_NEXT_VXLAN;//drop or vxlan?
                } else {
                    return ARP_RCV_NEXT_DROP;
                }
            }
            local_flag = 0;
        } else {
            inet_addr_ifa_put(ifa);
        }
    }

    uint8_t update_flag = 0;
    uint8_t rep_flag = 0;
    /* Need to process Gratuitous ARP */
    if (arp->arp_data.arp_sip == arp->arp_data.arp_tip) {
        L3_DEBUG_TRACE(L3_INFO, "%s node rcv arp announcement\n", __func__);
        if ((!local_flag) && (arp->arp_data.arp_sip != 0)) {
            update_flag = 1;
            rep_flag = 0;
        } else if (unlikely((!local_flag) && (arp->arp_data.arp_sip == 0))) {
            return ARP_RCV_NEXT_DROP;
        } else {
            update_flag = 0;
            rep_flag = 1;
        }
    } else { /* local_flag == 1 */
        if (arp->arp_data.arp_sip == 0) {
            L3_DEBUG_TRACE(L3_INFO, "%s node rcv arp probe\n", __func__);
            update_flag = 0;
            rep_flag = 1;
        } else {
            update_flag = 1;
            rep_flag = 1;
        }
    }

    if (likely(update_flag)) {
        L3_DEBUG_TRACE(L3_INFO, "%s node update arp\n", __func__);
        if (unlikely(arp_update(arp, table_id, port, graph, node)))  {            
            L3_DEBUG_TRACE(L3_ERR, "%s node update arp failed!!!\n", __func__);
            return ARP_RCV_NEXT_DROP;
        }
    }

    if ((rte_be_to_cpu_16(arp->arp_opcode) == RTE_ARP_OP_REQUEST) && (rep_flag)) {       
        arp_pack_rep(arp, mbuf, port, vrrp_node);
        if (GET_MBUF_PRIV_DATA(mbuf)->priv_data_is_vxlan) {
            next_id = ARP_RCV_NEXT_VXLAN;
        } else {
            next_id = ARP_RCV_NEXT_L2;
        }
        L3_DEBUG_TRACE(L3_INFO, "%s node recv arp request\n", __func__);
        L3_DEBUG_TRACE(L3_INFO, "%s node send arp reply\n", __func__);
        PrintMbufPkt(mbuf, 1, 0);
    } else if (rte_be_to_cpu_16(arp->arp_opcode) == RTE_ARP_OP_REPLY) {
        L3_DEBUG_TRACE(L3_INFO, "%s node recv arp reply\n", __func__);
    }

    return next_id;
}

static uint16_t
arp_rcv_node_process(struct rte_graph *graph, 
                              struct rte_node *node,
                              void **objs, 
                              uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs,
        nb_objs, ARP_RCV_NEXT_L2, arp_rcv);
}

static int
arp_rcv_node_init(const struct rte_graph *graph, 
                          struct rte_node *node)
{
    static uint8_t init_once;
    RTE_SET_USED(graph);
    RTE_SET_USED(node);
    int ret = 0;

    if (!init_once) {
        ret = arp_init();
        init_once = 1;
    }

    return ret;
}

/* arp rcv Node */
struct rte_node_register arp_rcv_node = {
	.process = arp_rcv_node_process,
	.name = NODE_NAME_ARP_RCV,

    .init = arp_rcv_node_init,

	.nb_edges = ARP_RCV_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[ARP_RCV_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[ARP_RCV_NEXT_L2] = NODE_NAME_L2_OUT,
		[ARP_RCV_NEXT_VXLAN] = NODE_NAME_VXLAN_SEND,
    },
};
RTE_NODE_REGISTER(arp_rcv_node);
