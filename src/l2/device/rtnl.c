#include"dpdk.h"
#include"netif.h"
#include"../include/l2_compat.h"

void rtnl_lock(void)
{
	//mutex_lock(&rtnl_mutex);
}


void rtnl_unlock(void)
{
	/* This fellow will unlock it for us. */
	netdev_run_todo();
}

void __rtnl_unlock(void)
{
	//mutex_unlock(&rtnl_mutex);
}


