/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021 chc.
 */

//#include <rte_debug.h>
//#include <rte_ether.h>
//#include <rte_ethdev.h>
#include <rte_vxlan.h>
//#include <rte_mbuf.h>
//#include <rte_graph.h>
//#include <rte_graph_worker.h>

#include "l3_node_priv.h"
#include "common_priv.h"
#include "vxlan_rcv_priv.h"
#include "vxlan_ctrl_priv.h"
#include "vrf_priv.h"
#include "log_priv.h"

static __rte_always_inline uint16_t 
vxlan_rcv(s_nc_param_l3 *param)
{
    struct rte_mbuf *mbuf = param->mbuf;
    char dst_addr[64] = {0};

    L3_DEBUG_TRACE(L3_INFO, "%s node recieved mbuf...\n", __func__);
    PrintMbufPkt(mbuf, 0, 0);

    if (new_mbuf_may_pull(mbuf, RTE_ETHER_VXLAN_HLEN)) {
        L3_DEBUG_TRACE(L3_ERR, "%s:new_mbuf_may_pull error 2\n", __FUNCTION__);
        return VXLAN_RCV_NEXT_DROP;
    }

    struct rte_udp_hdr *udph = rte_pktmbuf_mtod(mbuf, struct rte_udp_hdr *);
    L3_DEBUG_TRACE(L3_INFO, "udp d_port:%u\n", rte_be_to_cpu_16(udph->dst_port));
    if (rte_be_to_cpu_16(udph->dst_port) != RTE_VXLAN_DEFAULT_PORT) {
        L3_DEBUG_TRACE(L3_ERR, "%s:not vxlan pack,drop!\n", __FUNCTION__);
        return VXLAN_RCV_NEXT_DROP;
    }
    rte_pktmbuf_adj(mbuf, sizeof(struct rte_udp_hdr));

    struct rte_vxlan_hdr *vxlanh = rte_pktmbuf_mtod(mbuf, struct rte_vxlan_hdr *);
    if (unlikely(!vxlanh->vx_flags)) {
        L3_DEBUG_TRACE(L3_ERR, "%s:vni invalid,drop!\n", __FUNCTION__);
        return VXLAN_RCV_NEXT_DROP;
    }

    uint32_t vx_vni = rte_be_to_cpu_32(vxlanh->vx_vni) >> 8;
    L3_DEBUG_TRACE(L3_INFO, "vxlan vni:%u\n", vx_vni);

#if VRF_USE_VNI_HASH
    struct vxlan_tunnel_entry *vxlan_tunnel_dst_node;
    struct vxlan_tunnel_entry vxlan_tunnel_src_node;
    vxlan_tunnel_src_node.vni = vx_vni;
    vxlan_tunnel_dst_node = vxlan_tunnel_lookup(&vxlan_tunnel_src_node);
    if (unlikely(!vxlan_tunnel_dst_node)) {
        L3_DEBUG_TRACE(L3_ERR, "%s node:vni:%u,vxlan tunnel is null!!!\n",
            __func__, vx_vni);
        return VXLAN_RCV_NEXT_DROP;
    }
    if (unlikely(GET_MBUF_PRIV_DATA(mbuf)->priv_data_family !=
        vxlan_tunnel_dst_node->family)) {
        L3_DEBUG_TRACE(L3_ERR,
            "%s node:vni:%u,vxlan tunnel family not match!!!\n",
            __func__, vx_vni);
        return VXLAN_RCV_NEXT_DROP;
    }

    if (unlikely(!inet_addr_eq(GET_MBUF_PRIV_DATA(mbuf)->priv_data_family,
            &GET_MBUF_PRIV_DATA(mbuf)->priv_data_src_addr,
            &vxlan_tunnel_dst_node->remote_ip))) {
        L3_DEBUG_TRACE(L3_ERR,
            "%s node:vni:%u,vxlan tunnel src addr not match!!!\n",
            __func__, vx_vni);

        inet_ntop(vxlan_tunnel_dst_node->family,
            &GET_MBUF_PRIV_DATA(mbuf)->priv_data_src_addr,
            dst_addr, sizeof(dst_addr));
        L3_DEBUG_TRACE(L3_ERR, "%s node:src ip is %s\n", __func__, dst_addr);

        memset(dst_addr, 0, sizeof(dst_addr));
        inet_ntop(vxlan_tunnel_dst_node->family,
            &vxlan_tunnel_dst_node->remote_ip,
            dst_addr, sizeof(dst_addr));
        L3_DEBUG_TRACE(L3_ERR, "%s node:remote ip is %s\n", __func__, dst_addr);

        return VXLAN_RCV_NEXT_DROP;
    }

    GET_MBUF_PRIV_DATA(mbuf)->priv_data_vxlan_src_addr =
        vxlan_tunnel_dst_node->saddr;
    GET_MBUF_PRIV_DATA(mbuf)->priv_data_vxlan_dst_addr =
        vxlan_tunnel_dst_node->remote_ip;
    GET_MBUF_PRIV_DATA(mbuf)->priv_data_vxlan_hdr.vx_flags =
        vxlanh->vx_flags;
    GET_MBUF_PRIV_DATA(mbuf)->priv_data_vxlan_hdr.vx_vni =
        vxlanh->vx_vni;
    GET_MBUF_PRIV_DATA(mbuf)->priv_data_is_vxlan = true;
    GET_MBUF_PRIV_DATA(mbuf)->priv_data_vxlan_family =
        GET_MBUF_PRIV_DATA(mbuf)->priv_data_family;

    struct net_vrf *vni_node = NULL;
    vni_node = vrf_vni_lookup(vx_vni);
    /* if not bind to vrf,use GLOBAL_ROUTE_TBL_ID */
    if (likely(vni_node)) {
        GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id = vni_node->table_id;
    }
#endif

#if VRF_USE_DEV_HASH
    //mbuf->port = vxlan_dev;
    struct netif_port* port = (struct netif_port*)mbuf_dev_get(mbuf);
    if (!port) {
        return VXLAN_RCV_NEXT_DROP;
    }
    GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id = port->table_id;
#endif

    if (unlikely(rte_pktmbuf_adj(mbuf, sizeof(struct rte_vxlan_hdr)) == NULL)) {
        return VXLAN_RCV_NEXT_DROP;
    }

    /* tell L2 node this mbuf from vxlan node */
    mbuf->packet_type = -1;

    L3_DEBUG_TRACE(L3_INFO, "vxlan table id:%u\n",
        GET_MBUF_PRIV_DATA(mbuf)->priv_data_table_id);

    return VXLAN_RCV_NEXT_L2;
}

static uint16_t
vxlan_rcv_node_process(struct rte_graph *graph, 
                              struct rte_node *node,
                              void **objs, 
                              uint16_t nb_objs)
{
    NODE_PROC_COM(graph, node, objs, 
        nb_objs, VXLAN_RCV_NEXT_L2, vxlan_rcv);
}

#if 0
static int
vxlan_rcv_node_init(const struct rte_graph *graph, 
                          struct rte_node *node)
{
    static uint8_t init_once;
    static int offset;
    RTE_SET_USED(graph);
    RTE_BUILD_BUG_ON(sizeof(struct node_common_off_ctx) > RTE_NODE_CTX_SZ);

    if (!init_once) {
		offset = rte_mbuf_dynfield_register(
				&node_mbuf_priv_l3_dynfield_desc);
		if (offset < 0)
			return -rte_errno;

        init_once = 1;
    }

    /* Update socket's mbuf dyn priv1 offset in node ctx */
    NODE_MBUF_PRIV_L3_OFF(node->ctx) = offset;    
    RTE_LOG(INFO, TYPE_L3, "Initialized vxlan_rcv node");

    return 0;
}
#endif

/* udp rcv Node */
struct rte_node_register vxlan_rcv_node = {
	.process = vxlan_rcv_node_process,
	.name = NODE_NAME_VXLAN_RCV,

    //.init = vxlan_rcv_node_init,

	.nb_edges = VXLAN_RCV_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[VXLAN_RCV_NEXT_DROP] = NODE_NAME_PKT_DROP,
		[VXLAN_RCV_NEXT_L2] = NODE_NAME_L2_RCV,
    },
};
RTE_NODE_REGISTER(vxlan_rcv_node);
