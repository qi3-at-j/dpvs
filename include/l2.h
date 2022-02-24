#ifndef  __L2_H__
#define  __L2_H__

#include "netif.h"

int br_init(void);

int slave_fdb_rcu_reader_register_and_online(void);
void fdb_rcu_report_quiescent(lcoreid_t cid);

int l2_init(void);

int
port_id_pool_init(int phy_nb);

int
port_id_alloc(uint32_t *pid);
void 
port_id_free(uint32_t pid);

void register_namespace_net(struct netif_port* dev);
void unregister_namespace_net(struct netif_port* dev);
int call_netdevice_notifiers(unsigned long val, struct netif_port *dev);
int register_netdevice_notifier(struct notifier_block *nb);
int proc_auto_meter_recover(UCHAR        *pcTenantID, uint32_t bandwith);


#endif /*__L2_H__*/
