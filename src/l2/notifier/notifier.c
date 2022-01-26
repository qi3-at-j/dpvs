
#include <stdio.h>
#include "../include/notifier.h"
#include "dpdk.h"
#include "list.h"

/*
 *	Notifier list for kernel code which wants to be called
 *	at shutdown. This is used to stop any idling DMA operations
 *	and the like.
 */
//BLOCKING_NOTIFIER_HEAD(reboot_notifier_list);

/*
 *	Notifier chain core routines.  The exported routines below
 *	are layered on top of these, with appropriate locking added.
 */

static int notifier_chain_register(struct notifier_block **nl,
		struct notifier_block *n)
{
	while ((*nl) != NULL) {
		if (n->priority > (*nl)->priority)
			break;
		nl = &((*nl)->next);
	}
	n->next = *nl;
	rcu_assign_pointer(*nl, n);
	return 0;
}

static int notifier_chain_cond_register(struct notifier_block **nl,
		struct notifier_block *n)
{
	while ((*nl) != NULL) {
		if ((*nl) == n)
			return 0;
		if (n->priority > (*nl)->priority)
			break;
		nl = &((*nl)->next);
	}
	n->next = *nl;
	rcu_assign_pointer(*nl, n);
	return 0;
}

static int notifier_chain_unregister(struct notifier_block **nl,
		struct notifier_block *n)
{
	while ((*nl) != NULL) {
		if ((*nl) == n) {
			rcu_assign_pointer(*nl, n->next);
			return 0;
		}
		nl = &((*nl)->next);
	}
	return -ENOENT;
}

/**
 * notifier_call_chain - Informs the registered notifiers about an event.
 *	@nl:		Pointer to head of the blocking notifier chain
 *	@val:		Value passed unmodified to notifier function
 *	@v:		Pointer passed unmodified to notifier function
 *	@nr_to_call:	Number of notifier functions to be called. Don't care
 *			value of this parameter is -1.
 *	@nr_calls:	Records the number of notifications sent. Don't care
 *			value of this field is NULL.
 *	@returns:	notifier_call_chain returns the value returned by the
 *			last notifier function called.
 */
static int  notifier_call_chain(struct notifier_block **nl,
					unsigned long val, void *v,
					int nr_to_call,	int *nr_calls)
{
	int ret = NOTIFY_DONE;
	struct notifier_block *nb, *next_nb;

	nb = rcu_dereference_raw(*nl);

	while (nb && nr_to_call) {
		next_nb = rcu_dereference_raw(nb->next);

#ifdef CONFIG_DEBUG_NOTIFIERS
		if (unlikely(!func_ptr_is_kernel_text(nb->notifier_call))) {
			WARN(1, "Invalid notifier called!");
			nb = next_nb;
			continue;
		}
#endif
		ret = nb->notifier_call(nb, val, v);

		if (nr_calls)
			(*nr_calls)++;

		if ((ret & NOTIFY_STOP_MASK) == NOTIFY_STOP_MASK)
			break;
		nb = next_nb;
		nr_to_call--;
	}
	return ret;
}

/*
 *	Atomic notifier chain routines.  Registration and unregistration
 *	use a spinlock, and call_chain is synchronized by RCU (no locks).
 */

/**
 *	atomic_notifier_chain_register - Add notifier to an atomic notifier chain
 *	@nh: Pointer to head of the atomic notifier chain
 *	@n: New entry in notifier chain
 *
 *	Adds a notifier to an atomic notifier chain.
 *
 *	Currently always returns zero.
 */
int atomic_notifier_chain_register(struct atomic_notifier_head *nh,
		struct notifier_block *n)
{
	int ret;

	rte_spinlock_lock(&nh->lock);
	ret = notifier_chain_register(&nh->head, n);
	rte_spinlock_unlock(&nh->lock);
	return ret;
}

/**
 *	atomic_notifier_chain_unregister - Remove notifier from an atomic notifier chain
 *	@nh: Pointer to head of the atomic notifier chain
 *	@n: Entry to remove from notifier chain
 *
 *	Removes a notifier from an atomic notifier chain.
 *
 *	Returns zero on success or %-ENOENT on failure.
 */
int atomic_notifier_chain_unregister(struct atomic_notifier_head *nh,
		struct notifier_block *n)
{
	int ret;

	rte_spinlock_lock(&nh->lock);
	ret = notifier_chain_unregister(&nh->head, n);
	rte_spinlock_unlock(&nh->lock);
	general_rcu_qsbr_synchronize(rte_lcore_id());
	return ret;
}

/**
 *	__atomic_notifier_call_chain - Call functions in an atomic notifier chain
 *	@nh: Pointer to head of the atomic notifier chain
 *	@val: Value passed unmodified to notifier function
 *	@v: Pointer passed unmodified to notifier function
 *	@nr_to_call: See the comment for notifier_call_chain.
 *	@nr_calls: See the comment for notifier_call_chain.
 *
 *	Calls each function in a notifier chain in turn.  The functions
 *	run in an atomic context, so they must not block.
 *	This routine uses RCU to synchronize with changes to the chain.
 *
 *	If the return value of the notifier can be and'ed
 *	with %NOTIFY_STOP_MASK then atomic_notifier_call_chain()
 *	will return immediately, with the return value of
 *	the notifier function which halted execution.
 *	Otherwise the return value is the return value
 *	of the last notifier function called.
 */
int  __atomic_notifier_call_chain(struct atomic_notifier_head *nh,
					unsigned long val, void *v,
					int nr_to_call, int *nr_calls)
{
	int ret;

	//rcu_read_lock();
	ret = notifier_call_chain(&nh->head, val, v, nr_to_call, nr_calls);
	//rcu_read_unlock();
	return ret;
}


int  atomic_notifier_call_chain(struct atomic_notifier_head *nh,
		unsigned long val, void *v)
{
	return __atomic_notifier_call_chain(nh, val, v, -1, NULL);
}


/*
 *	Raw notifier chain routines.  There is no protection;
 *	the caller must provide it.  Use at your own risk!
 */

/**
 *	raw_notifier_chain_register - Add notifier to a raw notifier chain
 *	@nh: Pointer to head of the raw notifier chain
 *	@n: New entry in notifier chain
 *
 *	Adds a notifier to a raw notifier chain.
 *	All locking must be provided by the caller.
 *
 *	Currently always returns zero.
 */
int raw_notifier_chain_register(struct raw_notifier_head *nh,
		struct notifier_block *n)
{
	return notifier_chain_register(&nh->head, n);
}
  

/**
 *	raw_notifier_chain_unregister - Remove notifier from a raw notifier chain
 *	@nh: Pointer to head of the raw notifier chain
 *	@n: Entry to remove from notifier chain
 *
 *	Removes a notifier from a raw notifier chain.
 *	All locking must be provided by the caller.
 *
 *	Returns zero on success or %-ENOENT on failure.
 */
int raw_notifier_chain_unregister(struct raw_notifier_head *nh,
		struct notifier_block *n)
{
	return notifier_chain_unregister(&nh->head, n);
}


/**
 *	__raw_notifier_call_chain - Call functions in a raw notifier chain
 *	@nh: Pointer to head of the raw notifier chain
 *	@val: Value passed unmodified to notifier function
 *	@v: Pointer passed unmodified to notifier function
 *	@nr_to_call: See comment for notifier_call_chain.
 *	@nr_calls: See comment for notifier_call_chain
 *
 *	Calls each function in a notifier chain in turn.  The functions
 *	run in an undefined context.
 *	All locking must be provided by the caller.
 *
 *	If the return value of the notifier can be and'ed
 *	with %NOTIFY_STOP_MASK then raw_notifier_call_chain()
 *	will return immediately, with the return value of
 *	the notifier function which halted execution.
 *	Otherwise the return value is the return value
 *	of the last notifier function called.
 */
int __raw_notifier_call_chain(struct raw_notifier_head *nh,
			      unsigned long val, void *v,
			      int nr_to_call, int *nr_calls)
{
	return notifier_call_chain(&nh->head, val, v, nr_to_call, nr_calls);
}


int raw_notifier_call_chain(struct raw_notifier_head *nh,
		unsigned long val, void *v)
{
	return __raw_notifier_call_chain(nh, val, v, -1, NULL);
}


