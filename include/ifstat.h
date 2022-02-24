
#ifndef __DPVS_IFSTAT_H__
#define __DPVS_IFSTAT_H__
#include "list.h"
#include "dpdk.h"


int ifstate_get_link(struct netif_port *dev, struct rte_eth_link *link);


#endif /* __DPVS_IFSTAT_H__ */

