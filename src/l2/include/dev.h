
#ifndef __INCLUDE_L2_DEV_H__
#define __INCLUDE_L2_DEV_H__

#ifdef __cplusplus
    extern "C" {
#endif

#include "./net_namespace.h"

int unregister_netdevice_queue(struct netif_port *dev, struct list_head *head);
#define NETDEV_UP	0x0001	/* For now you can't veto a device up/down */
#define NETDEV_DOWN	0x0002
#define NETDEV_REBOOT	0x0003	/* Tell a protocol stack a network interface
                       detected a hardware crash and restarted
                       - we can use this eg to kick tcp sessions
                       once done */
#define NETDEV_CHANGE	0x0004	/* Notify device state change */
#define NETDEV_REGISTER 0x0005
#define NETDEV_UNREGISTER	0x0006
#define NETDEV_CHANGEMTU	0x0007
#define NETDEV_CHANGEADDR	0x0008
#define NETDEV_GOING_DOWN	0x0009
#define NETDEV_CHANGENAME	0x000A
#define NETDEV_FEAT_CHANGE	0x000B
#define NETDEV_BONDING_FAILOVER 0x000C
#define NETDEV_PRE_UP		0x000D
#define NETDEV_PRE_TYPE_CHANGE	0x000E
#define NETDEV_POST_TYPE_CHANGE	0x000F
#define NETDEV_POST_INIT	0x0010
#define NETDEV_UNREGISTER_FINAL 0x0011
#define NETDEV_RELEASE		0x0012
#define NETDEV_NOTIFY_PEERS	0x0013
#define NETDEV_JOIN		0x0014


static inline
struct net *dev_net(const struct netif_port *dev)
{
    return read_pnet(&dev->nd_net);
}

#define for_each_netdev(net, d)		\
            list_for_each_entry(d, &(net)->dev_base_head, dev_list)
static inline
void dev_net_set(struct netif_port *dev, struct net *net)
{
#ifdef CONFIG_NET_NS
        release_net(dev->nd_net);
        dev->nd_net = hold_net(net);
#endif
}
    

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_L2_DEV_H__ */


