#include "if_bridge.h"
#include "dpdk.h"
#include "general_rcu.h"
#include "if_ether.h"
#include "netif.h"
#include "conf/common.h"
#include "ipvs/kcompat.h"
#include "../include/br_private.h"
#include "../include/l2_debug.h"
#include "../include/dev.h"
#include "../include/rtnl.h"


static int port_cost(struct netif_port *dev)
{
#if 0
	struct ethtool_cmd ecmd;

	if (!__ethtool_get_settings(dev, &ecmd)) {
		switch (ethtool_cmd_speed(&ecmd)) {
		case SPEED_10000:
			return 2;
		case SPEED_1000:
			return 4;
		case SPEED_100:
			return 19;
		case SPEED_10:
			return 100;
		}
	}

	/* Old silly heuristics based on name */
	if (!strncmp(dev->name, "lec", 3))
		return 7;

	if (!strncmp(dev->name, "plip", 4))
		return 2500;
#endif
	return 100;	/* assume old 10Mbps */
}

/* find an available port number */
static int find_portno(struct net_bridge *br)
{
	int index;
	struct net_bridge_port *p;
	unsigned long *inuse;

	inuse =  rte_malloc(NULL, BITS_TO_LONGS(BR_MAX_PORTS)*sizeof(unsigned long), RTE_CACHE_LINE_SIZE);
	if (!inuse)
		return EDPVS_NOMEM;
	memset(inuse, 0, BITS_TO_LONGS(BR_MAX_PORTS)*sizeof(unsigned long));
	
	__set_bit(0, inuse);	/* zero is reserved */
	list_for_each_entry(p, &br->port_list, list) {
		__set_bit(p->port_no, inuse);
	}
	index = find_first_zero_bit(inuse, BR_MAX_PORTS);
	
	rte_free(inuse);

	return (index >= BR_MAX_PORTS) ? EDPVS_FULL : index;
}

static void destroy_nbp(struct net_bridge_port *p)
{
	struct netif_port *dev = p->dev;

	//dev->br_port = NULL;�?.10已经不在这里释放了，应嘎是发现这样做有问题了吧，
	//什么问题？原因是待释放的数据引用别的正在使用的数据是不合适的,别的数据在宽限期可能改变，所以dev->br_port不一定就是原来的�?
	p->br = NULL;
	p->dev = NULL;
	netif_put(dev);

	//br_sysfs_freeif(p);
	rte_free(p);
}

 void destroy_nbp_rcu(void *data)
{
	struct net_bridge_port *p = (struct net_bridge_port *)data;
	debug_brctl_event(BRCTL_EVENT_BRIDGE_IF_DEL, NULL, "destory nbp %s success", p->dev->name);
	destroy_nbp(p);
}

/* c
alled with RTNL but without bridge lock */
static struct net_bridge_port *new_nbp(struct net_bridge *br,
				       struct netif_port *dev)
{
	int index;
	struct net_bridge_port *p;

	index = find_portno(br);
	if (index < 0)
		return ERR_PTR(index);

	p = rte_malloc(NULL, sizeof(*p), RTE_CACHE_LINE_SIZE);
	if (p == NULL)
		return ERR_PTR(EDPVS_NOMEM);

	p->br = br;
	netif_hold(dev);
	p->dev = dev;
	p->path_cost = port_cost(dev);
	p->priority = 0x8000 >> BR_PORT_BITS;
	p->port_no = index;
	p->flags = 0;
	//br_init_port(p);
	p->state = BR_STATE_FORWARDING; //本来应为BR_STATE_DISABLED，暂时先设置成转发状�?
	//br_stp_port_timer_init(p);
	//br_multicast_add_port(p);

	return p;
}


/* Delete port(interface) from bridge is done in two steps.
 * via RCU. First step, marks device as down. That deletes
 * all the timers and stops new packets from flowing through.
 *
 * Final cleanup doesn't occur until after all CPU's finished
 * processing packets.
 *
 * Protected from multiple admin operations by RTNL mutex
 */
static void del_nbp(struct net_bridge_port *p)
{
	struct net_bridge *br = p->br;
	struct netif_port *dev = p->dev;

	//sysfs_remove_link(br->ifobj, p->dev->name);

	//dev_set_promiscuity(dev, -1);

	//spin_lock_bh(&br->lock);
	//br_stp_disable_port(p);
	//spin_unlock_bh(&br->lock);

	//br_ifinfo_notify(RTM_DELLINK, p);

	//nbp_vlan_flush(p);
	br_fdb_delete_by_port(br, p, 1);

	list_del_rcu(&p->list);

	dev->priv_flags &= ~PRIV_FLAG_BRIDGE_PORT;

	//netdev_rx_handler_unregister(dev);

	debug_brctl_event(BRCTL_EVENT_BRIDGE_IF_DEL_SYNC_WAIT, NULL, "before del net_bridge_port %s, waiting reference cnt.............", p->dev->name);
	general_rcu_qsbr_synchronize(rte_lcore_id());
	RCU_INIT_POINTER(dev->br_port, NULL);
	debug_brctl_event(BRCTL_EVENT_BRIDGE_IF_DEL_SYNC_DONE, NULL, "before del net_bridge_port %s, waiting reference cnt done.", p->dev->name);
	
	netdev_upper_dev_unlink(dev, br->dev);

	//br_multicast_del_port(p);

	//kobject_uevent(&p->kobj, KOBJ_REMOVE);
	//kobject_del(&p->kobj);

	//br_netpoll_disable(p);

	//call_rcu(&p->rcu, destroy_nbp_rcu);

	general_rcu_qsbr_dq_enqueue(p, destroy_nbp_rcu);

	
}

int br_add_if(struct net_bridge *br, struct netif_port *dev)
{
	struct net_bridge_port *p;
	int err = 0;

	/* Don't allow bridging non-ethernet like devices */
	if ((dev->flags == NETIF_PORT_FLAG_LOOPBACK) /*||
	    dev->type != ARPHRD_ETHER || dev->addr_len != ETH_ALEN */||
	    !rte_is_valid_assigned_ether_addr(&dev->addr))
		return -EDPVS_INVAL;

	/* No bridging of bridges */
	if (dev->netif_ops->op_graph_xmit == br_dev_graph_xmit)
		return -EDPVS_LOOP;

	/* Device is already being bridged */
	if (br_port_exists(dev))
		return -EDPVS_BUSY;

	/* No bridging devices that dislike that (e.g. wireless) */
	if (dev->priv_flags & PRIV_FLAG_DONT_BRIDGE)
		return -EDPVS_NOTSUPP;

	p = new_nbp(br, dev);
	if (IS_ERR(p))
		return PTR_ERR(p);

	call_netdevice_notifiers(NETDEV_JOIN, dev);

	//const uint8_t promisc = rte_eth_promiscuous_get(dev->id);
	//只有真实设备才能下驱动设置混杂模式，其他虚拟设备设置混杂模式没有意义�?
	if(dev->id < ether_output_real_port_cnt_get()){
		err = rte_eth_promiscuous_enable(dev->id);
		if (err)
			goto put_back;
	}

	dev->flags |= NETIF_PORT_FLAG_PROMISC;
	/*
	err = kobject_init_and_add(&p->kobj, &brport_ktype, &(dev->dev.kobj),
				   SYSFS_BRIDGE_PORT_ATTR);
	if (err)
		goto err1;

	err = br_sysfs_addif(p);
	if (err)
		goto err2;

	if (br_netpoll_info(br) && ((err = br_netpoll_enable(p, GFP_KERNEL))))
		goto err3;
	*/
	err = netdev_master_upper_dev_link(dev, br->dev);
	if (err)
		goto err1;

	rcu_assign_pointer(dev->br_port, p);
	/*err = netdev_rx_handler_register(dev, br_handle_frame, p);
	if (err)
		goto err5;
	*/
	dev->priv_flags |= PRIV_FLAG_BRIDGE_PORT;

	//dev_disable_lro(dev);

	list_add_rcu(&p->list, &br->port_list);

	//netdev_update_features(br->dev);

	rte_spinlock_lock(&br->lock);
	//changed_addr = br_stp_recalculate_bridge_id(br);

	/*if (netif_running(dev) && netif_oper_up(dev) &&
	    (br->dev->flags & IFF_UP))*/
		//br_stp_enable_port(p);
	rte_spinlock_unlock(&br->lock);

	//br_ifinfo_notify(RTM_NEWLINK, p);

	//if (changed_addr)
		//call_netdevice_notifiers(NETDEV_CHANGEADDR, br->dev);

	netif_set_mtu(br->dev, br_min_mtu(br));

	if (br_fdb_insert(br, p, &dev->addr, 1, 1)){
		RTE_LOG(ERR, BR, "failed insert local address bridge forwarding table\n");
		return err;
	}
		
	//kobject_uevent(&p->kobj, KOBJ_ADD);

	return EDPVS_OK;

/*
err5:
	netdev_upper_dev_unlink(dev, br->dev);
err4:
	br_netpoll_disable(p);
err3:
	sysfs_remove_link(br->ifobj, p->dev->name);
err2:
	kobject_put(&p->kobj);
	p = NULL;  kobject_put frees */
err1:
	//dev_set_promiscuity(dev, -1);
put_back:
	netif_put(dev);
	rte_free(p);
	return err;
}

/* called with RTNL */
int br_del_if(struct net_bridge *br, struct netif_port *dev)
{
	bool changed_addr;
	struct net_bridge_port *p = dev->br_port;

	//p = br_port_get_rtnl(dev);
	if (!p || p->br != br)
		return -EDPVS_INVAL;

	/* Since more than one interface can be attached to a bridge,
	 * there still maybe an alternate path for netconsole to use;
	 * therefore there is no reason for a NETDEV_RELEASE event.
	 */
	del_nbp(p);

	//spin_lock_bh(&br->lock);
	//changed_addr = br_stp_recalculate_bridge_id(br);
	//spin_unlock_bh(&br->lock);

	//if (changed_addr)
		//call_netdevice_notifiers(NETDEV_CHANGEADDR, br->dev);

	//netdev_update_features(br->dev);

	return 0;
}


int br_add_bridge(const char *name)
{
	struct netif_port *dev;
	struct net_bridge *br;
	int res;

	//dev_net_set(dev, net);
	//dev->rtnl_link_ops = &br_link_ops;

    /* allocate and register netif device */
    if (netif_port_get_by_name(name) != NULL)
    	return EDPVS_EXIST;

	dev = netif_alloc(sizeof(struct net_bridge), name,
            1, 1, br_dev_setup);
    if (!dev) {
        res = EDPVS_NOMEM;
        goto out;
    }

    /* XXX: dpdk NIC not support csum offload for VLAN. */
    dev->offload &= ~NETIF_PORT_TX_IP_CSUM_OFFLOAD;
    dev->offload &= ~NETIF_PORT_TX_TCP_CSUM_OFFLOAD;
    dev->offload &= ~NETIF_PORT_TX_UDP_CSUM_OFFLOAD;

	dev->type = PORT_TYPE_BRIDGE;

	//初始化fdb hash;
	br = netif_priv(dev);
	assert(br);

	res = br_fdb_hash_init(br);
	if (res != 0){
		netif_free(dev);
		goto out;
	}
    res = netif_port_register(dev);
	res |= bridge_global_list_add(br);
    if (res != EDPVS_OK) {
        netif_free(dev);
        goto out;
    }

	/*
    res = kni_add_dev(dev, NULL);
    if (res != EDPVS_OK) {
        netif_port_unregister(dev);
        netif_free(dev);
        goto out;
    }
	*/
	
    res = EDPVS_OK;

out:

    return res;
}

/* Delete bridge device */
int br_dev_delete(struct netif_port *dev, struct list_head *head)
{
	struct net_bridge *br = netif_priv(dev);
	struct net_bridge_port *p, *n;
	int ret = 0;
	list_for_each_entry_safe(p, n, &br->port_list, list) {
		del_nbp(p);
	}

	dpvs_timer_cancel(&br->gc_timer, true);

    bridge_global_list_del(br);
	unregister_netdevice_queue(br->dev, head);
    rte_hash_free(br->fdb.fdb_hash);
	return ret;
	
}

int br_del_bridge(const char *name)
{
	struct netif_port *dev;
	int ret = 0;

	rtnl_lock();
	dev = netif_port_get_by_name(name);
    if (!dev || dev->type != PORT_TYPE_BRIDGE)
        return EDPVS_NOTEXIST;

	if (dev->flags & NETIF_PORT_FLAG_RUNNING) {
		/* Not shutdown yet. */
		return EDPVS_BUSY;
	}

	ret = br_dev_delete(dev, NULL);

	rtnl_unlock();
	return ret;
}

/* MTU of the bridge pseudo-device: ETH_DATA_LEN or the minimum of the ports */
int br_min_mtu(const struct net_bridge *br)
{
	const struct net_bridge_port *p;
	int mtu = 0;

	//ASSERT_RTNL();

	if (list_empty(&br->port_list))
		mtu = ETH_DATA_LEN;
	else {
		list_for_each_entry(p, &br->port_list, list) {
			if (!mtu  || p->dev->mtu < mtu)
				mtu = p->dev->mtu;
		}
	}
	return mtu;
}

