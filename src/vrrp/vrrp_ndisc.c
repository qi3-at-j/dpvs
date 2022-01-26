/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        IPv6 Neighbour Discovery part.
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */
 
/* system includes */
#include <unistd.h>
#ifdef _HAVE_LINUX_IF_ETHER_H_COLLISION_
#include <netinet/in.h>
#endif
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <stdint.h>
#include <errno.h>

#include <rte_mbuf.h>


/* local includes */
#include "netif.h"
#include "../lib/logger.h"
//#include "utils.h"
//#include "vrrp_if_config.h"
#include "vrrp_scheduler.h"
#include "vrrp_ndisc.h"
//#include "bitops.h"
#include "l3_node_priv.h"
#include "vrrp_send_priv.h"
#include "vrrp_ring.h"

/*
 *	Build an unsolicited Neighbour Advertisement.
 *	As explained in rfc4861.4.4, a node sends unsolicited
 *	Neighbor Advertisements in order to (unreliably) propagate
 *	new information quickly.
 */
void
ndisc_send_unsolicited_na_immediate(vrrp_t * vrrp)
{	
    struct rte_mbuf *mbuf;		
	struct ether_header *eth;	
	struct ip6hdr *ip6h;	
    struct icmp6_hdr *icmp6hdr;
	struct in6_addr *target;
	struct nd_opt_hdr *nd_opt_h; 
	uint8_t *mac;		
	struct netif_port *dev = (struct netif_port *)vrrp->ifp;	
	struct mbuf_priv_data *pstMbufPrivData;	
	unsigned int iSendPktNum;

	/*build rte_mbuf*/	
    mbuf = rte_pktmbuf_alloc(dev->mbuf_pool);
	if (!mbuf) {
        //RTE_LOG(ERR, NEIGHBOUR, "mbuf_pool alloc failed\n");
		return;
	}	
    mbuf_userdata_set(mbuf, NULL);
	
	eth = (struct ether_header *)rte_pktmbuf_append(mbuf, sizeof(*eth));	
    eth->ether_dhost[0] = 0x33;
	eth->ether_dhost[1] = 0x33;
	eth->ether_dhost[2] = 0x0;
	eth->ether_dhost[3] = 0x0;
	eth->ether_dhost[4] = 0x0;	
	eth->ether_dhost[5] = 0x1;	
	memcpy(eth->ether_shost, vrrp->vmac, 6);	
	eth->ether_type = htons(ETHERTYPE_IPV6);	

	
	ip6h = (struct ip6hdr *)rte_pktmbuf_append(mbuf, sizeof(*ip6h));	
	memset(ip6h, 0, sizeof(*ip6h));
	ip6h->version = 6;
	ip6h->nexthdr = IPPROTO_ICMPV6;
	ip6h->hop_limit = 255;
	
	ip6h->payload_len = htons(sizeof(struct icmp6_hdr) + sizeof(struct in6_addr) + sizeof(struct nd_opt_hdr) + 6);
	memcpy(&(ip6h->saddr), vrrp->vip6, sizeof(struct in6_addr));
	ip6h->daddr.s6_addr16[0] = htons(0xff02);
	ip6h->daddr.s6_addr16[7] = htons(1);

	/* ICMPv6 Header */	
	icmp6hdr = (struct icmp6_hdr *)rte_pktmbuf_append(mbuf, sizeof(*icmp6hdr));		
    memset(icmp6hdr, 0, sizeof(*icmp6hdr));	
    icmp6hdr->icmp6_type = ND_NEIGHBOR_ADVERT;
    icmp6hdr->icmp6_pptr |= ND_NA_FLAG_ROUTER;
    icmp6hdr->icmp6_pptr |= ND_NA_FLAG_OVERRIDE;

    /*target*/
	target = (struct in6_addr *)rte_pktmbuf_append(mbuf, sizeof(*target));		
	memcpy(target, vrrp->vip6, sizeof(struct in6_addr));

	/*opt*/
	nd_opt_h = (struct nd_opt_hdr *)rte_pktmbuf_append(mbuf, sizeof(*nd_opt_h));	
	nd_opt_h->nd_opt_type = ND_OPT_TARGET_LINKADDR;
	nd_opt_h->nd_opt_len = 1; 

	
	/* MAC address */
	mac = (uint8_t *)rte_pktmbuf_append(mbuf, 6);	
	memcpy(mac, vrrp->vmac, 6);	


	icmp6hdr->icmp6_cksum = 0;
    icmp6hdr->icmp6_cksum = rte_ipv6_udptcp_cksum((struct rte_ipv6_hdr *)ip6h, icmp6hdr);

	pstMbufPrivData = GET_MBUF_PRIV_DATA(mbuf);
	pstMbufPrivData->priv_data_vrrp_type = VRRP_TYPE_ND;
    rte_memcpy(pstMbufPrivData->priv_data_smac, vrrp->vmac, 6);	
	mbuf_dev_set(mbuf, dev);


    /* 入队列发走 */	
    iSendPktNum = vrrp_ring_send(1, (void **)&mbuf);	
	if(1 != iSendPktNum)
	{
		/* 打印失败日志 */
		;
	}
	
	return ;
	
}
