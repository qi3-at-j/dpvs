/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        ARP primitives.
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
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <errno.h>


#include <rte_mbuf.h>


/* local includes */
#include "netif.h"
#include "memory.h"
//#include "utils.h"
//#include "bitops.h"
//#include "vrrp_scheduler.h"
#include "vrrp_arp.h"
#include "l3_node_priv.h"
#include "vrrp_send_priv.h"
#include "../lib/align.h"
#include "vrrp_ring.h"

/* Build a gratuitous ARP message over a specific interface */
void send_gratuitous_arp_immediate(vrrp_t * vrrp)
{
    struct rte_mbuf *mbuf;	
	struct arphdr *arph;
	char *arp_ptr;
	struct ether_header *eth;	
	struct mbuf_priv_data *pstMbufPrivData;
	struct netif_port *dev = (struct netif_port *)vrrp->ifp;	
	unsigned int iSendPktNum;
	char *padding;

	/*build rte_mbuf*/	
    mbuf = rte_pktmbuf_alloc(dev->mbuf_pool);
	if (!mbuf) {
        //RTE_LOG(ERR, NEIGHBOUR, "mbuf_pool alloc failed\n");
		return;
	}	
    mbuf_userdata_set(mbuf, NULL);
	
	eth = (struct ether_header *)rte_pktmbuf_append(mbuf, sizeof(*eth));	
	eth->ether_dhost[0] = 0xff;
	eth->ether_dhost[1] = 0xff;
	eth->ether_dhost[2] = 0xff;
	eth->ether_dhost[3] = 0xff;
	eth->ether_dhost[4] = 0xff;	
	eth->ether_dhost[5] = 0xff;
	memcpy(eth->ether_shost, vrrp->vmac, 6);
	eth->ether_type = htons(ETHERTYPE_ARP);	
	
	arph = (struct arphdr *)rte_pktmbuf_append(mbuf, sizeof(*arph)+20);	

	/* ARP payload */
	arph->ar_hrd = htons(0x01);
	arph->ar_pro = htons(ETHERTYPE_IP);
	arph->ar_hln = 0x06;
	arph->ar_pln = 0x04;
	arph->ar_op = htons(ARPOP_REQUEST);
	arp_ptr = PTR_CAST(char, (arph + 1));
	memcpy(arp_ptr, vrrp->vmac, 6);
	arp_ptr += 6;
	memcpy(arp_ptr, &vrrp->vip, 4);
	arp_ptr += 4;
	memcpy(arp_ptr,  vrrp->vmac, 6);
	arp_ptr += 6;
	memcpy(arp_ptr, &vrrp->vip, 4);

	/* ip报文最小长度要求有46个字节  ，46+14个长度的以太首部是60个字节，上面免费arp报文总共42个字节，所以还需要填充18个无效字节*/	
	padding = (char *)rte_pktmbuf_append(mbuf, 18);
	memset(padding, 0, 18);


	pstMbufPrivData = GET_MBUF_PRIV_DATA(mbuf);
	pstMbufPrivData->priv_data_vrrp_type = VRRP_TYPE_ARP;
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

