/*
 *	Handle incoming frames
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_input.c,v 1.10 2001/12/24 04:50:20 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include "dpdk.h"
#include "if_bridge.h"
#include "netfilter_bridge.h"
#include "../include/br_private.h"
#include "../include/l2_debug.h"

const unsigned char bridge_ula[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };

static uint16_t br_pass_frame_up_finish(struct rte_mbuf *mbuf)
{
/*
#ifdef CONFIG_NETFILTER_DEBUG
	skb->nf_debug = 0;
#endif*/

	return BRIDGE_NEXT_L3_TEMP; //BRIDGE_NEXT_L3_IP4;
}

static uint16_t br_pass_frame_up(struct net_bridge *br, struct rte_mbuf *mbuf)
{
	struct netif_port *indev;
	struct br_cpu_netstats *stat = &br->br_cpu_netstats[rte_lcore_id()];

	stat->rx_packets++;
	stat->rx_bytes += rte_pktmbuf_pkt_len(mbuf);

	indev = mbuf_dev_get(mbuf);
	RTE_SET_USED(indev);
	//mbuf-dev change into bridge dev. before up to l3.
	mbuf_dev_set(mbuf, br->dev);
	mbuf->port = br->dev->id;

	//二层防火墙现在不支持
	/*INET_HOOK(AF_BRIDGE, NF_BR_LOCAL_IN, mbuf, indev, NULL,
			br_pass_frame_up_finish);
	*/
	debug_l2_packet_trace(L2_DEBUG_BRIDGE, mbuf, DETAIL_OFF, "[br]receive mbuf send to local send to ipv4 deal it.\n");
	return br_pass_frame_up_finish(mbuf);
}


/* note: already called with rcu_read_lock (preempt_disabled) */
uint16_t br_handle_frame_finish(s_nc_param *param)
{
	struct rte_mbuf *mbuf = param->mbuf;
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	struct rte_ether_addr *dest = &eth_hdr->d_addr;
	struct netif_port *dev = mbuf_dev_get(mbuf);	
	struct net_bridge_port *p = br_port_get_rcu(dev);
	struct net_bridge *br = p->br;
	struct net_bridge_fdb_entry *dst;
	struct rte_mbuf *mbuf2;
	uint16_t index = BRIDGE_NEXT_PKT_DROP;

	if (!p || p->state == BR_STATE_DISABLED)
		goto drop;


	/* insert into forwarding database after filtering to avoid spoofing */
	br = p->br;
	br_fdb_update(br, p, &eth_hdr->s_addr);

	if (p->state == BR_STATE_LEARNING)
		goto drop;

	/* The packet skb2 goes to the local host (NULL to skip). */
	mbuf2 = NULL;

	if (br->dev->flags & NETIF_PORT_FLAG_PROMISC)
		mbuf2 = mbuf;

	dst = NULL;

	if (rte_is_broadcast_ether_addr(dest))
		mbuf2 = mbuf;
	//组播暂时不支持
	else if(rte_is_multicast_ether_addr(dest)){
		goto drop;
	}
	else if((dst = __br_fdb_get(br, dest)) && dst->is_local) {
		mbuf2 = mbuf;
		/* Do not forward the packet since it's local. */
		debug_l2_packet_trace(L2_DEBUG_BRIDGE, mbuf, DETAIL_OFF, "[br]receive mbuf send to local.receive port is %s\n", dev->name);
		mbuf = NULL;
	}

	if (mbuf) {
		if (dst) {
			dst->used = jiffies;
			//fdb exist, but not local, suo wo forward out. mbuf2 now is null,
			index = br_forward(param, br, dst->dst, mbuf, mbuf2);
		} else
			//fdb not exist ,we need flood.
			index = br_flood_forward(param, br, mbuf, mbuf2);
	}

	//local in
	if (mbuf2)
		return br_pass_frame_up(br, mbuf2);

out:
	return index;
drop:
	//rte_pktmbuf_free(mbuf);
	index = BRIDGE_NEXT_PKT_DROP;
	goto out;
}

/*
 * Called via br_handle_frame_hook.
 * Return 0 if *pskb should be processed furthur
 *	  1 if *pskb is handled
 * note: already called with rcu_read_lock (preempt_disabled) 
 */
uint16_t br_handle_local_finish(struct rte_mbuf *mbuf)
{
	struct netif_port *dev = mbuf_dev_get(mbuf);
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	struct net_bridge_port *p = br_port_get_rcu(dev);
	struct rte_ether_addr *src = &eth_hdr->s_addr;

	br_fdb_update(p->br, p, src);
	return BRIDGE_NEXT_L3_TEMP; //BRIDGE_NEXT_L3_TEMP;	 /* process further */
}
uint16_t br_handle_frame(s_nc_param *param)
{
	struct rte_mbuf *mbuf = param->mbuf;
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	struct rte_ether_addr *dest = &eth_hdr->d_addr;
	struct netif_port *dev = mbuf_dev_get(mbuf);
	
	struct net_bridge_port *p = br_port_get_rcu(dev);
	if (!p){
		RTE_LOG(ERR, BR, "get null port from mbuf->dev in bridge node, dev is %s.", dev->name);
		goto err;
	}
		
	
	if (p->state == BR_STATE_DISABLED)
		goto err;

	if (eth_hdr->s_addr.addr_bytes[0] & 1)  //h_source[0] & 1)
		goto err;

	if (unlikely(is_link_local_ether_addr(dest->addr_bytes))) {
		/*
		 * See IEEE 802.1D Table 7-10 Reserved addresses
		 *
		 * Assignment		 		Value
		 * Bridge Group Address		01-80-C2-00-00-00
		 * (MAC Control) 802.3		01-80-C2-00-00-01
		 * (Link Aggregation) 802.3	01-80-C2-00-00-02
		 * 802.1X PAE address		01-80-C2-00-00-03
		 *
		 * 802.1AB LLDP 		01-80-C2-00-00-0E
		 *
		 * Others reserved for future standardization
		 */
		switch (dest->addr_bytes[5]) {
		case 0x00:	/* Bridge Group Address */
			/* If STP is turned off,
			   then must forward to keep loop detection */
			/*if (p->br->stp_enabled == BR_NO_STP)
				goto forward;*/
			break;

		case 0x01:	/* IEEE MAC (Pause) */
			goto drop;

		default:
			/* Allow selective forwarding for most other protocols */
			if (p->br->group_fwd_mask & (1u << dest->addr_bytes[5]))
				goto forward;
		}

		/* Deliver packet to local host only *
		if (NF_HOOK(NFPROTO_BRIDGE, NF_BR_LOCAL_IN, skb, skb->dev,
			    NULL, br_handle_local_finish)) {
			return RX_HANDLER_CONSUMED; /* consumed by filter *
		} else {
			*pskb = skb;
			return RX_HANDLER_PASS;	/* continue processing *
		}*/

		return br_handle_local_finish(mbuf);
	}

forward:

	if (p->state == BR_STATE_FORWARDING) {
		/*
		if (br_should_route_hook) {
			if (br_should_route_hook(pskb)) 
				return 0;
			skb = *pskb;
			dest = eth_hdr(skb)->h_dest;
		}*/

		if (!rte_is_same_ether_addr(&p->br->dev->addr, dest))
			mbuf->packet_type = ETH_PKT_HOST;
		//二层防火墙目前也不支持
		/*
		INET_HOOK(AF_BRIDGE, NF_BR_PRE_ROUTING, mbuf, dev, NULL,
				br_handle_frame_finish);
		*/
		return br_handle_frame_finish(param);
	}
drop:
err:
	//rte_pktmbuf_free(mbuf);
	return BRIDGE_NEXT_PKT_DROP;
}

