
#ifndef __NODE_ARP_PRIV_H__
#define __NODE_ARP_PRIV_H__

#include "neigh_priv.h"

struct rte_mbuf *
arp_pack_req(struct netif_port *port, uint32_t src_ip, uint32_t dst_ip);
int arp_init(void);

#endif
