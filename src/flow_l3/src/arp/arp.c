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
#include <stdio.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <rte_ether.h>
#include <rte_arp.h>

#include "arp_priv.h"
#include "neigh_priv.h"
#include "log_priv.h"
#include "vrrp_send_priv.h"

#include "netif.h"
#include "timer.h"
#include "mempool.h"

/* inetAddrCopy( void * t, void * f ) - Copy IPv4 address */
static __inline__ void
inetAddrCopy(void *t, void *f) {
    uint32_t *d = (uint32_t *)t;
    uint32_t *s = (uint32_t *)f;

    *d = *s;
}

struct rte_mbuf *
arp_pack_req(struct netif_port *port, uint32_t src_ip, uint32_t dst_ip)
{
    struct rte_mbuf *m;
    struct rte_ether_hdr *eth;
    struct rte_arp_hdr *arp;

    uint32_t addr;

    m = rte_pktmbuf_alloc(port->mbuf_pool);
    if (unlikely(m == NULL)) {
        return NULL;
    }

    mbuf_dev_set(m, port);

    eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    arp = (struct rte_arp_hdr *)&eth[1];

    memset(&eth->d_addr, 0xFF, RTE_ETHER_ADDR_LEN);
    rte_ether_addr_copy(&port->addr, &eth->s_addr);
    eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    memset(arp, 0, sizeof(struct rte_arp_hdr));

    addr = src_ip;
    struct vrrp_entry *vrrp_node = NULL;
    vrrp_node = lookup_vrrp_ip((union inet_addr*)&addr, AF_INET);
    if (vrrp_node) {       
        rte_memcpy(&arp->arp_data.arp_sha, vrrp_node->mac, RTE_ETHER_ADDR_LEN);
    } else {
        rte_memcpy(&arp->arp_data.arp_sha, &port->addr, RTE_ETHER_ADDR_LEN);
    }
    inetAddrCopy(&arp->arp_data.arp_sip, &addr);

    memset(&arp->arp_data.arp_tha, 0, RTE_ETHER_ADDR_LEN);
    addr = dst_ip;
    inetAddrCopy(&arp->arp_data.arp_tip, &addr);

    arp->arp_hardware = RTE_BE16(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = RTE_BE16(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = 6;
    arp->arp_plen = 4;
    arp->arp_opcode  = RTE_BE16(RTE_ARP_OP_REQUEST);
    m->pkt_len   = 60;
    m->data_len  = 60;
    m->l2_len    = sizeof(struct rte_ether_hdr);
    m->l3_len    = sizeof(struct rte_arp_hdr);

    memset(&arp[1], 0, 18);

    return m;
}

#if 0
int neigh_free_arp(struct in_addr *src_ip, struct netif_port *port)
{
    uint32_t sip = src_ip->s_addr;
    return arp_pack_req(port, sip, sip);
}
#endif

int arp_init(void)
{
    neigh_init_graph();
    return 0;
}

