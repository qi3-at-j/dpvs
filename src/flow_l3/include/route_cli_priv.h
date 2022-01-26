#ifndef __NODE_ROUTE_CLI_PRIV_H__
#define __NODE_ROUTE_CLI_PRIV_H__

#include "inetaddr.h"
#include "notifier.h"

void route_cli_init(void);
int route_add_ifaddr(struct inet_ifaddr *s_ifa);
int route_del_ifaddr(struct inet_ifaddr *s_ifa, uint8_t local_keep);
int route_device_event(struct notifier_block *unused, unsigned long event, void *ptr);
int vrrp_add_route(union inet_addr *dst_addr, uint8_t family,
    uint8_t netmask, struct netif_port *port);
int vrrp_del_route(union inet_addr *dst_addr, uint8_t family,
    uint8_t netmask, struct netif_port *port);

extern pthread_mutex_t mutex;

#endif

