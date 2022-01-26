
#include"dpdk.h"
#include"netif.h"
#include"timer.h"
#include"ipvs/kcompat.h"
#include"netif_addr.h"
#include"general_rcu.h"
#include"../include/l2_compat.h"
#include"../include/rtnl.h"
#include"../include/notifier.h"
#include"../include/dev.h"

static LIST_HEAD(net_todo_list);
static LIST_HEAD(net_wait_to_delete_list);
static ATOMIC_NOTIFIER_HEAD(netdev_chain);

static struct dpvs_timer		g_wait_ref_timer;
static bool                     g_set_timer;


/**
 *	register_netdevice_notifier - register a network notifier block
 *	@nb: notifier
 *
 *	Register a notifier to be called when network device events occur.
 *	The notifier passed is linked into the kernel structures and must
 *	not be reused until it has been unregistered. A negative errno code
 *	is returned on a failure.
 *
 * 	When registered all registration and up events are replayed
 *	to the new notifier to allow device to have a race free
 *	view of the network device list.
 */

int register_netdevice_notifier(struct notifier_block *nb)
{
	struct netif_port *dev;
	struct netif_port *last;
	struct net *net;
	int err;

	rtnl_lock();
    //rtnl is null , so womast use atomic_notifier_chain_register not raw_notifier_chain_register
	err = atomic_notifier_chain_register(&netdev_chain, nb);
	if (err)
		goto unlock;
	//if (dev_boot_phase)
		//goto unlock;
	for_each_net(net) {
		for_each_netdev(net, dev) {
			err = nb->notifier_call(nb, NETDEV_REGISTER, dev);
			err = notifier_to_errno(err);
			if (err)
				goto rollback;

			if (!(dev->flags & NETIF_PORT_FLAG_UP))
				continue;

			nb->notifier_call(nb, NETDEV_UP, dev);
		}
	}

unlock:
	rtnl_unlock();
	return err;

rollback:
	last = dev;
	for_each_net(net) {
		for_each_netdev(net, dev) {
			if (dev == last)
				goto outroll;

			if (dev->flags & NETIF_PORT_FLAG_UP) {
				nb->notifier_call(nb, NETDEV_GOING_DOWN, dev);
				nb->notifier_call(nb, NETDEV_DOWN, dev);
			}
			nb->notifier_call(nb, NETDEV_UNREGISTER, dev);
		}
	}

outroll:
	atomic_notifier_chain_unregister(&netdev_chain, nb);
	goto unlock;
}


/**
 *	unregister_netdevice_notifier - unregister a network notifier block
 *	@nb: notifier
 *
 *	Unregister a notifier previously registered by
 *	register_netdevice_notifier(). The notifier is unlinked into the
 *	kernel structures and may then be reused. A negative errno code
 *	is returned on a failure.
 *
 * 	After unregistering unregister and down device events are synthesized
 *	for all devices on the device list to the removed notifier to remove
 *	the need for special case cleanup code.
 */

int unregister_netdevice_notifier(struct notifier_block *nb)
{
	struct netif_port *dev;
	struct net *net;
	int err;

	rtnl_lock();
	err = raw_notifier_chain_unregister(&netdev_chain, nb);
	if (err)
		goto unlock;

	for_each_net(net) {
		for_each_netdev(net, dev) {
			if (dev->flags & NETIF_PORT_FLAG_UP) {
				nb->notifier_call(nb, NETDEV_GOING_DOWN, dev);
				nb->notifier_call(nb, NETDEV_DOWN, dev);
			}
			nb->notifier_call(nb, NETDEV_UNREGISTER, dev);
		}
	}
unlock:
	rtnl_unlock();
	return err;
}

int call_netdevice_notifiers(unsigned long val, struct netif_port *dev)
{
	ASSERT_RTNL();
	return atomic_notifier_call_chain(&netdev_chain, val, dev);
}

static int netdev_wait_allrefs(void *arg)
{
    struct netif_port *dev = NULL;
    struct netif_port *tmp;

	int refcnt;

    //linkwatch_forget_dev(dev);

    list_for_each_entry_safe(dev, tmp, &net_wait_to_delete_list, todo_list){
        refcnt = netif_refcnt_read(dev);
        if (refcnt != 0) {
		
			rtnl_lock();

			/* Rebroadcast unregister notification */
			call_netdevice_notifiers(NETDEV_UNREGISTER, dev);

			__rtnl_unlock();
			//rcu_barrier();
			rtnl_lock();

		    call_netdevice_notifiers(NETDEV_UNREGISTER_FINAL, dev);
			/*if (test_bit(__LINK_STATE_LINKWATCH_PENDING,
				     &dev->state)) {
				/* We must not have linkwatch events
				 * pending on unregister. If this
				 * happens, we simply run the queue
				 * unscheduled, resulting in a noop
				 * for this device.
				 *
				linkwatch_run_queue();
			}*/

			__rtnl_unlock();

    		printf("unregister_netdevice: waiting for %s to become free. Usage count = %d\n",dev->name, refcnt);
	    }else{
            list_del(&dev->todo_list);
            netif_free_rcu(dev);
        }
    }

    if(list_empty_careful(&net_wait_to_delete_list)){
        if(g_set_timer == true){
            dpvs_timer_cancel_nolock(&g_wait_ref_timer, true);
            g_wait_ref_timer.is_period = false;
            g_set_timer = false;
        }
    }

    return EDPVS_OK;
}

void set_wait_ref_timer_sched(void){
    struct timeval tv;
    if(g_set_timer == true){
        return;
    }
    g_set_timer = true;
    g_wait_ref_timer.is_period = true;
    tv.tv_sec = 1;//br->ageing_time/DPVS_TIMER_HZ;
    tv.tv_usec = 0;
    dpvs_timer_sched_period(&g_wait_ref_timer, &tv, netdev_wait_allrefs, NULL, true);
}


static int __dev_close_many(struct list_head *head)
{
	struct netif_port *dev;

	ASSERT_RTNL();
	//might_sleep();

    
	list_for_each_entry(dev, head, unreg_list) {
		call_netdevice_notifiers(NETDEV_GOING_DOWN, dev);

		//clear_bit(__LINK_STATE_START, &dev->state);

		/* Synchronize to scheduled poll. We cannot touch poll list, it
		 * can be even on different cpu. So just clear netif_running().
		 *
		 * dev->stop() will invoke napi_disable() on all of it's
		 * napi_struct instances on this device.
		 *
		smp_mb__after_clear_bit(); * Commit netif_running(). */
	}
    
	//dev_deactivate_many(head);

	list_for_each_entry(dev, head, unreg_list) {
		const struct netif_ops *ops = dev->netif_ops;

		/*
		 *	Call the device specific close. This cannot fail.
		 *	Only if device is UP
		 *
		 *	We allow it to be called even after a DETACH hot-plug
		 *	event.
		 */
		if (ops->op_stop)
			ops->op_stop(dev);

		dev->flags &= ~NETIF_PORT_FLAG_RUNNING;
		//net_dmaengine_put();
	}

	return 0;
}

static int dev_close_many(struct list_head *head)
{
	struct netif_port *dev, *tmp;
	LIST_HEAD(tmp_list);

	list_for_each_entry_safe(dev, tmp, head, unreg_list){
        if (!(dev->flags & NETIF_PORT_FLAG_RUNNING))
            list_move(&dev->unreg_list, &tmp_list);
    }

	__dev_close_many(head);

	list_for_each_entry(dev, head, unreg_list) {
		//rtmsg_ifinfo(RTM_NEWLINK, dev, IFF_UP|IFF_RUNNING);
		call_netdevice_notifiers(NETDEV_DOWN, dev);
	}

	/* rollback_registered_many needs the complete original list */
	list_splice(&tmp_list, head);
	return 0;
}

static void unlist_netdevice(struct netif_port *dev)
{
    int rte = EDPVS_OK;
	ASSERT_RTNL();

	/* Unlink dev from the device chain */
	rte = netif_port_unregister(dev);
	//dev_base_seq_inc(dev_net(dev));
	if(rte != EDPVS_OK){
        printf("unregister_netdevice: device %s/%p was not exist on global list\n",
				 dev->name, dev);
    }
}

bool netdev_has_any_upper_dev(struct netif_port *dev)
{
	ASSERT_RTNL();

	return !list_empty(&dev->upper_dev_list);
}

static void rollback_registered_many(struct list_head *head)
{
	struct netif_port *dev, *tmp;

	ASSERT_RTNL();

	list_for_each_entry_safe(dev, tmp, head, unreg_list) {
		/* Some devices call without registering
		 * for initialization unwind. Remove those
		 * devices and proceed with the remaining.
		 */
		if (dev->reg_state == NETREG_UNINITIALIZED) {
			printf("unregister_netdevice: device %s/%p never was registered\n",
				 dev->name, dev);

			//WARN_ON(1);
			list_del(&dev->unreg_list);
			continue;
		}
		dev->dismantle = true;
		BUG_ON(dev->reg_state != NETREG_REGISTERED);
	}

	/* If device is running, close it first. */
	dev_close_many(head);

	list_for_each_entry(dev, head, unreg_list) {
		/* And unlink it from device chain. */
		unlist_netdevice(dev);

		dev->reg_state = NETREG_UNREGISTERING;
	}

	//synchronize_net();

	list_for_each_entry(dev, head, unreg_list) {
		/* Shutdown queueing discipline. */
		//dev_shutdown(dev);


		/* Notify protocols, that we are about to destroy
		   this device. They should clean all the things.
		*/
		call_netdevice_notifiers(NETDEV_UNREGISTER, dev);

        /*
		if (!dev->rtnl_link_ops ||
		    dev->rtnl_link_state == RTNL_LINK_INITIALIZED)
			rtmsg_ifinfo(RTM_DELLINK, dev, ~0U);
        */
		/*
		 *	Flush the unicast and multicast chains
		 */
		//dev_uc_flush(dev);
        netif_mc_flush(dev);

		if (dev->netif_ops->op_uninit)
			dev->netif_ops->op_uninit(dev);

		/* Notifier chain MUST detach us all upper devices. */
		WARN_ON(netdev_has_any_upper_dev(dev));

		/* Remove entries from kobject tree */
		//netdev_unregister_kobject(dev);
#ifdef CONFIG_XPS
		/* Remove XPS queueing entries */
		//netif_reset_xps_queues_gt(dev, 0);
#endif
	}

	//synchronize_net();
    /*
	list_for_each_entry(dev, head, unreg_list){
        netif_put(dev);
    }*/
}

static void rollback_registered(struct netif_port *dev)
{
	LIST_HEAD(single);

	list_add(&dev->unreg_list, &single);
	rollback_registered_many(&single);
	list_del(&single);
}

static void net_set_todo(struct netif_port *dev)
{
	list_add_tail(&dev->todo_list, &net_todo_list);
}

int unregister_netdevice_queue(struct netif_port *dev, struct list_head *head)
{
	//该类型的设备是实际的网卡设备，在设备运行之初就创建了，不允许删除。
	if(dev->type == PORT_TYPE_GENERAL){
		return EDPVS_NOTSUPP;
	}

	ASSERT_RTNL();

	if (head) {
		list_move_tail(&dev->unreg_list, head);
	} else {
		rollback_registered(dev);
		/* Finish processing unregister after unlock */
		net_set_todo(dev);
	}
}

void netdev_run_todo(void)
{
	struct list_head list;

	/* Snapshot list, allow later requests */
	list_replace_init(&net_todo_list, &list);

	__rtnl_unlock();


	/* Wait for rcu callbacks to finish before next phase */
	if (!list_empty(&list))
		//rcu_barrier();

	while (!list_empty(&list)) {
		struct netif_port *dev
			= list_first_entry(&list, struct netif_port, todo_list);
		list_del(&dev->todo_list);

		rtnl_lock();
		call_netdevice_notifiers(NETDEV_UNREGISTER_FINAL, dev);
		__rtnl_unlock();

		if (unlikely(dev->reg_state != NETREG_UNREGISTERING)) {
			pr_err("network todo '%s' but state %d\n",
			       dev->name, dev->reg_state);
			rte_dump_stack();
			continue;
		}

		dev->reg_state = NETREG_UNREGISTERED;

		//on_each_cpu(flush_backlog, dev, 1);

		
        //netdev_wait_allrefs(dev);
		if(0 != rte_atomic32_read(&dev->refcnt)){
            set_wait_ref_timer_sched();
            list_add_tail(&dev->todo_list, &net_wait_to_delete_list);
            continue;
        }
		WARN_ON(rcu_access_pointer(dev->in_ptr));
		//WARN_ON(dev->dn_ptr);

        netif_free_rcu(dev);
		/* Free network device */
		//kobject_put(&dev->dev.kobj);
	}
}



