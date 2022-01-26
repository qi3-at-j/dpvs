#include <assert.h>
#include "list.h"
#include "netif.h"
#include "netif_addr.h"
#include "kni.h"
#include "ctrl.h"
#include "../include/br_private.h"
#include "../include/L2_xmit.h"
#include "timer.h"
#include "conf/br.h"


/* net device transmit always called with BH disabled */
uint16_t br_dev_graph_xmit(s_nc_param *param, struct rte_mbuf *mbuf, struct netif_port *dev)
{

	struct net_bridge *br = netif_priv(dev);
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	struct net_bridge_fdb_entry *dst;
	//struct net_bridge_mdb_entry *mdst;
	struct br_cpu_netstats *brstats = &br->br_cpu_netstats[rte_lcore_id()];
	uint16_t index = L2_XMIT_NEXT_PKT_DROP;
	
	//rcu_read_lock();

/*
#ifdef CONFIG_BRIDGE_NETFILTER
	if (skb->nf_bridge && (skb->nf_bridge->mask & BRNF_BRIDGED_DNAT)) {
		br_nf_pre_routing_finish_bridge_slow(skb);
		rcu_read_unlock();
		return NETDEV_TX_OK;
	}
#endif
*/

	//u64_stats_update_begin(&brstats->syncp);
	brstats->tx_packets++;
	brstats->tx_bytes += rte_pktmbuf_pkt_len(mbuf);
	//u64_stats_update_end(&brstats->syncp);

	if (rte_is_broadcast_ether_addr(&eth_hdr->d_addr))
		index = br_flood_deliver(param, br, mbuf);
		//暂时还不支持组播
	else if(rte_is_multicast_ether_addr(&eth_hdr->d_addr)){
		index = L2_XMIT_NEXT_PKT_DROP;
	}
	else if ((dst = __br_fdb_get(br, &eth_hdr->d_addr)) != NULL)
		index = br_deliver(dst->dst, mbuf);
	else
		index = br_flood_deliver(param, br, mbuf);
	//rcu_read_unlock();
	return index;
}

static int br_dev_init(struct netif_port *dev)
{
	struct net_bridge *br = netif_priv(dev);

	RTE_SET_USED(br);	
	return 0;
}

static int br_dev_open(struct netif_port *dev)
{
	struct net_bridge *br = netif_priv(dev);
	assert(br);

	/*netdev_update_features(dev);
	netif_start_queue(dev);
	br_stp_enable_bridge(br);
	br_multicast_open(br);*/

	return 0;
}

void br_dev_set_multicast_list(struct netif_port *dev)
{
}

static int br_dev_stop(struct netif_port *dev)
{
	struct net_bridge *br = netif_priv(dev);
	assert(br);

	//br_stp_disable_bridge(br);
	//br_multicast_stop(br);

	//netif_stop_queue(dev);

	return 0;
}

int br_get_stats(struct netif_port *dev, struct rte_eth_stats *stats)
{
	struct net_bridge *br = netif_priv(dev);
	struct br_cpu_netstats *tmp, sum = { 0 };

	int i;

	tmp = br->br_cpu_netstats;
	for(i=0; i<DPVS_MAX_LCORE; i++) {
		sum.tx_bytes   += tmp[i].tx_bytes;
		sum.tx_packets += tmp[i].tx_packets;
		sum.rx_bytes   += tmp[i].rx_bytes;
		sum.rx_packets += tmp[i].rx_packets;
	}

	stats->obytes   = sum.tx_bytes;
	stats->opackets = sum.tx_packets;
	stats->ibytes   = sum.rx_bytes;
	stats->ipackets = sum.rx_packets;

	return 0;
}

static int br_change_mtu(struct netif_port *dev, int new_mtu)
{
	struct net_bridge *br = netif_priv(dev);
	if (new_mtu < 68 || new_mtu > br_min_mtu(br))
		return -EDPVS_INVAL;

	dev->mtu = new_mtu;

#ifdef CONFIG_BRIDGE_NETFILTER
	/* remember the MTU in the rtable for PMTU */
	//dst_metric_set(&br->fake_rtable.dst, RTAX_MTU, new_mtu);
#endif

	return 0;
}

/* Allow setting mac address to any valid ethernet address. */
static int br_set_mac_address(struct netif_port *dev, void *p)
{
	struct net_bridge *br = netif_priv(dev);
	struct rte_ether_addr *addr = p;
	
	if (!rte_is_valid_assigned_ether_addr(addr))
		return -EDPVS_INVAL;

	netif_mc_add(dev, addr);

	rte_spinlock_lock(&br->lock);
	if (!eth_addr_equal(&dev->addr, addr)) {
		memcpy(&dev->addr, addr, ETH_ALEN);
		br_fdb_change_mac_address(br, addr);
		//br_stp_change_bridge_id(br, addr->sa_data);
	}
	rte_spinlock_lock(&br->lock);

	return 0;
}

/*
static void br_getinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	strlcpy(info->driver, "bridge", sizeof(info->driver));
	strlcpy(info->version, BR_VERSION, sizeof(info->version));
	strlcpy(info->fw_version, "N/A", sizeof(info->fw_version));
	strlcpy(info->bus_info, "N/A", sizeof(info->bus_info));
}
*/

/*static netdev_features_t br_fix_features(struct net_device *dev,
	netdev_features_t features)
{
	struct net_bridge *br = netdev_priv(dev);

	return br_features_recompute(br, features);
}*/

/* called with RTNL */

static int br_add_slave(struct netif_port *dev, struct netif_port *slave_dev)

{
	struct net_bridge *br = netif_priv(dev);
	assert(br);

	return br_add_if(br, slave_dev);
}

static int br_del_slave(struct netif_port *dev, struct netif_port *slave_dev)
{
	struct net_bridge *br = netif_priv(dev);
	assert(br);

	return br_del_if(br, slave_dev);
	return EDPVS_OK;
}

static struct netif_ops br_netif_ops = {
	.op_open		 = br_dev_open,
	.op_stop		 = br_dev_stop,
	.op_init		 = br_dev_init,
	.op_graph_xmit   = br_dev_graph_xmit,
	.op_get_stats	 = br_get_stats,
	//.op_set_mc_list	 = 
	.op_set_mac_address	 = br_set_mac_address,
	.op_change_mtu		 = br_change_mtu,
	.op_add_slave		 = br_add_slave,
	.op_del_slave		 = br_del_slave,
	.op_fdb_add		 	 = br_fdb_add,
	.op_fdb_del		     = br_fdb_delete,
	//.ndo_fdb_dump		 = br_fdb_dump,
};

static void br_dev_free(struct netif_port *dev)
{
	struct net_bridge *br = netif_priv(dev);
	assert(br);

	rte_hash_free(br->fdb.fdb_hash);
	
	//free_percpu(br->stats);
	//free_netdev(dev);
}

/*
static struct device_type br_type = {
	.name	= "bridge",
};
*/

void br_dev_setup(struct netif_port *dev)
{
	struct net_bridge *br = netif_priv(dev);	
	struct timeval tv;
	assert(br);

	rte_eth_random_addr(dev->addr.addr_bytes);
	//ether_setup(dev);

	dev->mtu = ETH_DATA_LEN;
	dev->hw_header_len = sizeof(struct rte_ether_hdr);
	dev->netif_ops = &br_netif_ops;
	dev->destructor = br_dev_free;
	//SET_ETHTOOL_OPS(dev, &br_ethtool_ops);
	//SET_NETDEV_DEVTYPE(dev, &br_type);
	//dev->tx_queue_len = 0;
	
	dev->priv_flags = PRIV_FLAG_EBRIDGE;
	/*

	dev->features = NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_HIGHDMA |
			NETIF_F_GSO_MASK | NETIF_F_HW_CSUM | NETIF_F_LLTX |
			NETIF_F_NETNS_LOCAL | NETIF_F_HW_VLAN_CTAG_TX;
	dev->hw_features = NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_HIGHDMA |
			   NETIF_F_GSO_MASK | NETIF_F_HW_CSUM |
			   NETIF_F_HW_VLAN_CTAG_TX;
	*/
	
	br->dev = dev;
	rte_spinlock_init(&br->lock);
	INIT_LIST_HEAD(&br->port_list);
	rte_spinlock_init(&br->hash_lock);

	br->bridge_id.prio[0] = 0x80;
	br->bridge_id.prio[1] = 0x00;

	memcpy(br->group_addr, eth_reserved_addr_base, ETH_ALEN);

	//br->stp_enabled = BR_NO_STP;
	br->group_fwd_mask = BR_GROUPFWD_DEFAULT;

	br->designated_root = br->bridge_id;
	br->bridge_max_age = br->max_age = 20 * DPVS_TIMER_HZ;
	br->bridge_hello_time = br->hello_time = 2 * DPVS_TIMER_HZ;
	br->bridge_forward_delay = br->forward_delay = 15 * DPVS_TIMER_HZ;
	br->ageing_time = 300 * DPVS_TIMER_HZ;

	//br_netfilter_rtable_init(br);
	//br_stp_timer_init(br);
	//br_multicast_init(br);

	tv.tv_sec = 300;//br->ageing_time/DPVS_TIMER_HZ;
    tv.tv_usec = 0;
	dpvs_timer_sched_period(&br->gc_timer, &tv, br_fdb_cleanup, br, true);
}

