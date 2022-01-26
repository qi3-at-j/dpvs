/*
 *	Forwarding decision
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_forward.c,v 1.4 2001/08/14 22:05:57 davem Exp $
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
#include "../include/L2_xmit.h"

static inline int should_deliver(const struct net_bridge_port *p, 
				 const struct rte_mbuf *mbuf)
{
	if (mbuf_dev_get(mbuf) == p->dev ||
	    p->state != BR_STATE_FORWARDING)
		return 0;

	return 1;
}

uint16_t br_dev_queue_push_xmit(struct rte_mbuf *mbuf)
{
/*
	if (skb->len > skb->dev->mtu) 
		kfree_skb(skb);
	else {
/*
#ifdef CONFIG_BRIDGE_NETFILTER
		/* ip_refrag calls ip_fragment, doesn't copy the MAC header. *
		nf_bridge_maybe_copy_header(skb);
#endif
*
		skb_push(skb, ETH_HLEN);

		dev_queue_xmit(skb);
	}
*/
	if(!mbuf)
		rte_panic("mbuf = 0x0\n");
	return BRIDGE_NEXT_L2_XMIT;
}

uint16_t br_forward_finish(struct rte_mbuf *mbuf)
{
	//防火墙先不支持。
	/*
	INET_HOOK(AF_BRIDGE, NF_BR_POST_ROUTING, mbuf, NULL, mbuf_dev_get(mbuf),
			br_dev_queue_push_xmit);
	*/
	return br_dev_queue_push_xmit(mbuf);
}

uint16_t br_deliver_finish(struct rte_mbuf *mbuf){
	if(!mbuf)
		rte_panic("mbuf = 0x0\n");
	return L2_XMIT_NEXT_ETHER_OUTPUT;
}
static uint16_t __br_deliver(const struct net_bridge_port *to, struct rte_mbuf *mbuf)
{
	mbuf_dev_set(mbuf,to->dev);
/*
#ifdef CONFIG_NETFILTER_DEBUG
	skb->nf_debug = 0;
#endif
*/
	//防火墙先不支持
	/*
	INET_HOOK(AF_BRIDGE, NF_BR_LOCAL_OUT, mbuf, NULL, mbuf_dev_get(mbuf),
			br_forward_finish);
	*/

	return br_deliver_finish(mbuf);
}

static uint16_t __br_forward(const struct net_bridge_port *to, struct rte_mbuf *mbuf)
{
	struct netif_port *indev;

	RTE_SET_USED(indev);

	indev = mbuf_dev_get(mbuf);
	//set mbuf->dev into to dev before forward.
	mbuf_dev_set(mbuf, to->dev);
	//skb->ip_summed = CHECKSUM_NONE;

	//先不支持 二层防火墙。
	/*
	INET_HOOK(AF_BRIDGE, NF_BR_FORWARD, mbuf, indev, to->dev,
			  br_forward_finish);
	*/
	return br_forward_finish(mbuf);
}

/* called with rcu_read_lock */
uint16_t br_deliver(const struct net_bridge_port *to, struct rte_mbuf *mbuf)
{
	if (should_deliver(to, mbuf)) {
		return __br_deliver(to, mbuf);
	}

	return BRIDGE_NEXT_PKT_DROP; //rte_pktmbuf_free(mbuf);
}

static int deliver_clone(s_nc_param *param, const struct net_bridge_port *prev,
			 struct rte_mbuf *mbuf,
			 uint16_t (*__packet_hook)(const struct net_bridge_port *p,
					       struct rte_mbuf *mbuf))
{
	struct net_bridge *br = prev->br;
	struct br_cpu_netstats *stat = &br->br_cpu_netstats[rte_lcore_id()];
	struct rte_mempool *pool = get_mbuf_mempool();
	struct rte_mbuf *clone_buf;
	uint16_t index = BRIDGE_NEXT_PKT_DROP;

	clone_buf = rte_pktmbuf_clone(mbuf, pool);
	if (!clone_buf) {
		stat->tx_dropped++;
		return BRIDGE_NEXT_PKT_DROP;
	}

	index = __packet_hook(prev, clone_buf);
	//将克隆后的报文直接传给下一个节点
	rte_node_enqueue_x1(param->graph, param->node, index, (void *)clone_buf);
	return 0;
}

/* called with rcu_read_lock */
uint16_t br_forward(s_nc_param *param, struct net_bridge *br, const struct net_bridge_port *to, struct rte_mbuf *mbuf, struct rte_mbuf *mbuf0)
{
	uint16_t index = BRIDGE_NEXT_PKT_DROP;
	if (should_deliver(to, mbuf)) {
		if(mbuf0)
			deliver_clone(param, to, mbuf, __br_forward);
		else{
			index = __br_forward(to, mbuf);
			debug_l2_packet_trace(L2_DEBUG_BRIDGE, DETAIL_OFF, mbuf, "[br]fdb exist, but not local, so we forward out. out port is %s\n", to->dev->name);
		}
		return index;
	}

	if(!mbuf0){
		//rte_pktmbuf_free(mbuf);
		index = BRIDGE_NEXT_PKT_DROP;
	}

	return index;
}

static struct net_bridge_port *
maybe_deliver(s_nc_param *param,
	struct net_bridge_port *prev, struct net_bridge_port *p,
	struct rte_mbuf *mbuf,
	uint16_t (*__packet_hook)(const struct net_bridge_port *p,
			      struct rte_mbuf *mbuf))
{
	int err;

	if (!should_deliver(p, mbuf))
		return prev;

	if (!prev)
		goto out;

	err = deliver_clone(param, prev, mbuf, __packet_hook);
	debug_l2_packet_trace(L2_DEBUG_BRIDGE, mbuf, DETAIL_OFF, "[br]fdb not exist ,we need flood to port %s, err = %d\n", prev->dev->name, err);
	if (err)
		return ERR_PTR(err);

out:
	return p;
}


/* called under bridge lock */
static uint16_t br_flood(s_nc_param *param, struct net_bridge *br, struct rte_mbuf *mbuf, struct rte_mbuf *mbuf0,
	uint16_t (*__packet_hook)(const struct net_bridge_port *p, 
			      struct rte_mbuf *mbuf))
{
	struct net_bridge_port *p;
	struct net_bridge_port *prev;
	uint16_t index = BRIDGE_NEXT_PKT_DROP;
	prev = NULL;

	list_for_each_entry(p, &br->port_list, list) {
		prev = maybe_deliver(param, prev, p, mbuf, __packet_hook);
		if (IS_ERR(prev))
			goto out;
	}

	if (!prev)
		goto out;

	if (mbuf0){
		//进入此分支的应该是全ff的报文，所以我们需要克隆，将克隆的报文泛洪给其他端口之后，上层需要处理，所以此时的策略是交给上层；
		deliver_clone(param, prev, mbuf, __packet_hook);
		debug_l2_packet_trace(L2_DEBUG_BRIDGE, mbuf, DETAIL_OFF, "[br]recv broadcast mbuf, before flood, we also del it by L3.\n");
		index = BRIDGE_NEXT_L3_TEMP; //BRIDGE_NEXT_L3_TEMP;
	}else{
		//进入此分支的报文就是有明确目的地址的，但是地址没有在fdb中，桥只好泛洪，此时本机不处理，理论上需要丢弃。
		index = __packet_hook(prev, mbuf);
	}
	debug_l2_packet_trace(L2_DEBUG_BRIDGE, mbuf, DETAIL_OFF, "[br]fdb not exist ,we need flood to port %s, index = %d\n", prev->dev->name, index);
	return index;
	
out:
	if (!mbuf0)
		index = BRIDGE_NEXT_PKT_DROP;//rte_pktmbuf_free(mbuf);

	return index;
}


/* called with rcu_read_lock */
uint16_t br_flood_deliver(s_nc_param *param, struct net_bridge *br, struct rte_mbuf *mbuf)
{
	return br_flood(param, br, mbuf, NULL, __br_deliver);
}

/* called under bridge lock */
uint16_t br_flood_forward(s_nc_param *param, struct net_bridge *br, struct rte_mbuf *mbuf,  struct rte_mbuf *mbuf2)
{
	return br_flood(param, br, mbuf, mbuf2, __br_forward);
}

