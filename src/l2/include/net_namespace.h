#ifndef __DPVS_NET_NAMESPACE_H
#define __DPVS_NET_NAMESPACE_H

#include <rte_spinlock.h>
#include "list.h"

extern struct net init_net;
extern struct list_head net_namespace_list;

struct net {
	rte_atomic32_t		passive;	/* To decided when the network
						 * namespace should be freed.
						 */
	rte_atomic32_t		count;		/* To decided when the network
						 *  namespace should be shut down.
						 */
#ifdef NETNS_REFCNT_DEBUG
	rte_atomic32_t		use_count;	/* To track references we
						 * destroy on demand
						 */
#endif
	rte_spinlock_t		rules_mod_lock;

	struct list_head	list;		/* list of network namespaces */
	struct list_head	cleanup_list;	/* namespaces on death row */
	struct list_head	exit_list;	/* Use only net_mutex */

	

	unsigned int		proc_inum;

	struct list_head 	dev_base_head;
	struct hlist_head 	*dev_name_head;
	struct hlist_head	*dev_index_head;
	unsigned int		dev_base_seq;	/* protected by rtnl_mutex */
	int			ifindex;

	/* core fib_rules */
	struct list_head	rules_ops;

};

#ifdef CONFIG_NET_NS
    
    static inline void write_pnet(struct net **pnet, struct net *net)
    {
        *pnet = net;
    }
    
    static inline struct net *read_pnet(struct net * const *pnet)
    {
        return *pnet;
    }
    
#else
    
#define write_pnet(pnet, net)	do { (void)(net);} while (0)
#define read_pnet(pnet)		(&init_net)
    
#endif

#define for_each_net(VAR)				\
	list_for_each_entry(VAR, &net_namespace_list, list)

#define for_each_net_rcu(VAR)				\
	list_for_each_entry_rcu(VAR, &net_namespace_list, list)


#ifdef NETNS_REFCNT_DEBUG
static inline struct net *hold_net(struct net *net)
{
	if (net)
		rte_atomic32_inc(&net->use_count);
	return net;
}

static inline void release_net(struct net *net)
{
	if (net)
		rte_atomic32_dec(&net->use_count);
}

#else
static inline struct net *hold_net(struct net *net)
{
	return net;
}

static inline void release_net(struct net *net)
{
}
#endif

#endif

