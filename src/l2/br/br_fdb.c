/*
 *	Forwarding database
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include "dpdk.h"
#include "ipvs/kcompat.h"
#include "if_bridge.h"
#include "neigh.h"
#include "timer.h"
#include "../include/br_private.h"
#include "../include/l2_debug.h"


static struct rte_rcu_qsbr *g_fdb_qsv = NULL;
struct rte_mempool *br_fdb_cache[DPVS_MAX_SOCKET];
static bool fdb_rcu_switch = false;


typedef void (*rte_hash_free_key_data)(void *p, void *key_data);

struct rte_rcu_qsbr *get_fdb_rcu(void)
{
	return g_fdb_qsv;
}

static void fdb_rcu_free(void *p, void *key_data)
{
	RTE_SET_USED(p);
	
	struct net_bridge_fdb_entry *fdb = (struct net_bridge_fdb_entry *) key_data;
	int socket_id = rte_socket_id();
	if (socket_id == SOCKET_ID_ANY){
		socket_id = 0;
	}
	rte_mempool_put(br_fdb_cache[socket_id], fdb);
}

static u32 fdb_salt; //read_mostly;
static struct rte_hash_rcu_config g_fdb_rcu_cfg = 
{
		.v    = NULL,
		.mode = RTE_HASH_QSBR_MODE_DQ,
		.free_key_data_func = fdb_rcu_free,
		.key_data_ptr       = NULL,
		.dq_size            = FDB_RCU_DQ_SIZE,
		.trigger_reclaim_limit = FDB_RCU_DQ_RECLAIM_THD,
		.max_reclaim_size      = FDB_RCU_DQ_RECLAIM_MAX,
};

void fdb_rcu_report_quiescent(lcoreid_t cid){

	if (fdb_rcu_switch == true){
		rte_rcu_qsbr_quiescent(g_fdb_qsv, cid);
	}

	return;
}

int slave_fdb_rcu_reader_register_and_online(void){
	int err = 0;
	static bool on = false;

	lcoreid_t cid = rte_lcore_id();
	if(on == false){

		err = rte_rcu_qsbr_thread_register(g_fdb_qsv, cid);
		if(err != 0)
			return err;
		
		rte_rcu_qsbr_thread_online(g_fdb_qsv, cid);
		on = true;
		fdb_rcu_switch = true;
	}

	return EDPVS_OK;
}

int br_fdb_hash_init(struct net_bridge *br){
	int err = 0;
	char name[BR_FDB_NAME_SIZE];
	int32_t status;
	
	struct rte_hash_parameters hash_tbl_params = {
		.entries = BR_FDB_HASH_ENTRIES,
		.key_len = sizeof(struct fdb_hash_key),
		.hash_func = rte_jhash,
		.hash_func_init_val = rte_rand(),
		.name = name,
		.reserved = 0,
		.socket_id = SOCKET_ID_ANY,
		.extra_flag = RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD|RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF|RTE_HASH_EXTRA_FLAGS_EXT_TABLE,
	};

	/* Initialize hash */
	snprintf(name, BR_FDB_NAME_SIZE,
		 "%s's fdb", br->dev->name);
	br->fdb.fdb_hash = rte_hash_create(&hash_tbl_params);
	if(br->fdb.fdb_hash == NULL){
		RTE_LOG(ERR, BR, "failed to create fdb of br %", br->dev->name);
		return -1;
	}

	/* Attach RCU QSBR to hash table */
	status = rte_hash_rcu_qsbr_add(br->fdb.fdb_hash, &g_fdb_rcu_cfg);
	if(status != 0){
		RTE_LOG(ERR, BR, "failed to create fdb dq of br %", br->dev->name);
		return -1;
	}
	rte_atomic32_init(&br->fdb.entries_nb);
	return 0;
}


int br_fdb_init(void)
{
	int i=0;
	int err=0;
	int32_t status;
	char br_fdb_mbufpool_name[32];
	size_t sz;
	uint32_t nb_lcores = 0;

	fdb_salt = (uint32_t)rte_rand();

    for (i = 0; i < get_numa_nodes(); i++) {
    	snprintf(br_fdb_mbufpool_name, sizeof(br_fdb_mbufpool_name), "bridge_fdb_cache_%d", i);
    	br_fdb_cache[i] = rte_mempool_create(br_fdb_mbufpool_name,
            BR_FDB_MBUFPOOL_SIZE,
            sizeof(struct net_bridge_fdb_entry),
            BR_FDB_CACHE_SIZE,
            0, 
            NULL, 
            NULL, 
            NULL, 
            NULL,
            i, 0);
	    if (!br_fdb_cache[i]) {
	        err = EDPVS_NOMEM;
			goto failed2;
	    }
    }

	nb_lcores = netif_get_all_enabled_fwd_cores_nb();
    //main_thread also as a number.
    nb_lcores += 1;

	sz = rte_rcu_qsbr_get_memsize(nb_lcores);
	g_fdb_qsv = (struct rte_rcu_qsbr *)rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE, SOCKET_ID_ANY);
	if(!g_fdb_qsv){
		goto failed2;
	}

	
	status = rte_rcu_qsbr_init(g_fdb_qsv, nb_lcores);
	if(status != 0){
		goto failed1;
	}

	g_fdb_rcu_cfg.v = g_fdb_qsv;

	status = rte_rcu_qsbr_thread_register(g_fdb_qsv, 0);
	if(status != 0){
		goto failed1;
	}

	rte_rcu_qsbr_thread_online(g_fdb_qsv, 0);
	goto success;

failed1:
	rte_free(g_fdb_qsv);
failed2:
	for (i = i - 1; i >= 0; i--){
		rte_mempool_free(br_fdb_cache[i]);
	}
success:

	return err;
}

int br_fdb_fini(void)
{
    int i;

    for (i = 0; i < get_numa_nodes(); i++)
        rte_mempool_free(br_fdb_cache[i]);

    return EDPVS_OK;
}


/* if topology_changing then use forward_delay (default 15 sec)
 * otherwise keep longer (default 5 minutes)
 */
static inline unsigned long hold_time(const struct net_bridge *br)
{
	return br->topology_change ? br->forward_delay : br->ageing_time;
}

static inline int has_expired(const struct net_bridge *br,
				  const struct net_bridge_fdb_entry *fdb)
{
	return !fdb->is_static &&
		time_before_eq(fdb->updated + hold_time(br), jiffies);
}


/*
static inline int br_mac_hash(const unsigned char *mac, u16 vid)
{
	* use 1 byte of OUI and 3 bytes of NIC *
	u32 key = ((u32 *)(mac + 2));
	return rte_jhash_2words(key, vid, fdb_salt) & (BR_HASH_SIZE - 1);
}
*/

static int fdb_delete_with_key(struct rte_hash *h, struct fdb_hash_key *key)
{
	//fdb_notify(br, f, RTM_DELNEIGH); 这是给用户态通知的，目前不需要，或许给控制器发送报告需要这么个接口吧，不管怎样，目前不需要�?
	int err = 0;
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, &key->addr);

	err = rte_hash_del_key(h, key);
	debug_brctl_event(BRCTL_EVENT_FDB_DELETE, NULL, "fdb_delete: %s, ret = %d.", buf, err);
	return err;
}

static inline void
fdb_key_init(struct fdb_hash_key *key, struct rte_ether_addr *addr)
{
	rte_memcpy(&key->addr, addr, sizeof(struct rte_ether_addr));
}

static void fdb_delete(struct rte_hash *h, struct rte_ether_addr *addr){
	struct fdb_hash_key key;

	fdb_key_init(&key, addr);
	(void)fdb_delete_with_key(h, &key);
}

/* Find a rule */
static inline int
fdb_find_with_key(struct rte_hash *fdb_hash,
		  const struct fdb_hash_key *hash_key,
		  struct net_bridge_fdb_entry **entry)
{
	void *hash_val;
	int ret;

	/* lookup for a rule */
	ret = rte_hash_lookup_data(fdb_hash, (const void *) hash_key,
		(void **) &hash_val);
	if (ret >= 0) {
		*entry = (struct net_bridge_fdb_entry *) hash_val;
		return 1;
	}

	return 0;
}

static struct net_bridge_fdb_entry *__fdb_create(struct net_bridge_port * source, 
													const struct rte_ether_addr * addr, bool is_local, bool is_static){
	struct net_bridge_fdb_entry *fdb;
	int socket_id = rte_socket_id();
	if (socket_id == SOCKET_ID_ANY){
		socket_id = 0;
	}
	if (rte_mempool_get(br_fdb_cache[socket_id], (void **)&fdb)) {
		RTE_LOG(ERR, BR, "couldn't get object from fdb mempool");
		return NULL;
	}
	
	if (fdb) {
		rte_memcpy(&fdb->addr, addr, sizeof(struct rte_ether_addr));
		fdb->dst = source;
		fdb->is_local = 0;
		fdb->is_static = 0;
		fdb->updated = fdb->used = jiffies;
		fdb->is_local = is_local;
		fdb->is_static = is_static;
	}
	return fdb;

}

void show_all_fdb_entrys(struct rte_hash *fdb_hash){
	uint32_t iter = 0;
	struct net_bridge_fdb_entry *f;
	struct fdb_hash_key *key;

	assert(fdb_hash != NULL);
	
	/* Search all chains since old address/hash is unknown */
	while (rte_hash_iterate(fdb_hash, (const void **)&key,(void **)&f, &iter) >= 0) {
		__print_fdb_detail(f);
	}
}

static struct net_bridge_fdb_entry * fdb_create(	struct    net_bridge *br,
						   struct net_bridge_port *source,
					       struct rte_ether_addr *addr,
                           bool is_local, bool is_static)
{
	int err = 0;
	struct rte_hash *fdb_hash = br->fdb.fdb_hash;
	struct net_bridge_fdb_entry *fdb_entry = NULL;
	struct fdb_hash_key key;
	struct net_bridge_fdb_entry *fdb;
	int socket_id = rte_socket_id();
	if (socket_id == SOCKET_ID_ANY){
		socket_id = 0;
	}

	fdb_entry = __fdb_create(source, addr, is_local, is_static);
	if(fdb_entry == NULL){
		RTE_LOG(ERR, BR, "create fdb entry failed, br : %s, port %s .\n", br->dev->name, source ? source->dev->name : "null");
			return NULL;
	}

	/* 初始化key的�?*/
	fdb_key_init(&key, addr);
	/* 插入hash�?*/
	err = rte_hash_add_key_data(fdb_hash, &key,
		(void *) fdb_entry);
	if (err < 0){
		RTE_LOG(ERR, BR, "adding interface %s failed\n", source ? source->dev->name : br->dev->name);
		rte_mempool_put(br_fdb_cache[socket_id], fdb_entry);
		fdb_entry = NULL;
	}
	
	debug_brctl_event(BRCTL_EVENT_FDB_CREATE, fdb_entry, "fdb_create : create a new fdb."); 
	return fdb_entry;
}


static int
fdb_insert(struct net_bridge *br, struct net_bridge_port *source, 
              struct rte_ether_addr *addr, int is_local, int is_static)
{
	int fdb_exist;
	struct fdb_hash_key key;	
	struct net_bridge_fdb_entry *exist_fdb = NULL;
	struct net_bridge_fdb_entry *new_fdb = NULL;
	
	struct rte_hash *fdb_hash = br->fdb.fdb_hash;

	assert(fdb_hash);
	
	/*判断地址是否有效*/
	if (!rte_is_valid_assigned_ether_addr(addr))
		return EDPVS_INVAL;
	/* 初始化key的�?*/
	fdb_key_init(&key, addr);

	/* 查重，判断是否有重复*/
	fdb_exist = fdb_find_with_key(fdb_hash, &key, &exist_fdb);

	if (fdb_exist) {
		/* it is okay to have multiple ports with same
		 * address, just use the first one.
		 */
		if (exist_fdb->is_local)
			return 0;
		RTE_LOG(WARNING, BR, "adding interface %s with same address "
			   "as a received packet\n",
			   source ? source->dev->name : br->dev->name);
		(void)fdb_delete_with_key(fdb_hash, &key);
	}

	/* 创建一个新的entry*/
	new_fdb = fdb_create(br, source, addr, is_local, is_static);
	if(!new_fdb){
		return EDPVS_FAILED;
	}

	/*通知其他模块*/
	//fdb_notify(br, fdb, RTM_NEWNEIGH);
	/*统计计数*/
	rte_atomic32_inc(&br->fdb.entries_nb);
	return 0;
}

void br_fdb_changeaddr(struct net_bridge_port *p, struct rte_ether_addr *newaddr)
{
	struct net_bridge *br = p->br;
	uint32_t iter = 0;
	struct net_bridge_fdb_entry *f;
	struct rte_hash *fdb_hash = br->fdb.fdb_hash;
	struct fdb_hash_key *key;
	
	rte_spinlock_lock(&br->hash_lock);
	/* Search all chains since old address/hash is unknown */
	while (rte_hash_iterate(fdb_hash, (const void **)&key, (void **)&f, &iter) >= 0) {
		if (f->dst == p && f->is_local) {
			/* maybe another port has same hw addr? */
			struct net_bridge_port *op;
			list_for_each_entry(op, &br->port_list, list) {
				if (op != p &&
				    rte_is_same_ether_addr(&op->dev->addr, &f->addr)){
					f->dst = op;
					goto insert;
				}
			}

			/* delete old one */
			(void)fdb_delete_with_key(fdb_hash, key);
			goto insert;

		}
	}

insert:
	fdb_insert(br, p, newaddr, 1, 1);
	rte_spinlock_unlock(&br->hash_lock);
}

int br_fdb_cleanup(void *arg)
{
	struct net_bridge *br = (struct net_bridge *)arg;
	unsigned long delay = hold_time(br);
	unsigned long next_timer = jiffies + br->ageing_time;
	uint32_t iter = 0;
	struct net_bridge_fdb_entry *f;
	struct rte_hash *fdb_hash = br->fdb.fdb_hash;
	struct fdb_hash_key *key;

	debug_brctl_event(BRCTL_EVENT_FDB_CLEANUP_SRART, NULL, "clean up old fdb---------------------start-----------------------");
	rte_spinlock_lock(&br->hash_lock);
	while (rte_hash_iterate(fdb_hash, (const void **)&key,(void **)&f, &iter) >= 0){
		unsigned long this_timer;
		if (f->is_static)
			continue;
		this_timer = f->updated + delay;
		if (time_before_eq(this_timer, jiffies)){
			print_fdb_detail(f);
			(void)fdb_delete_with_key(fdb_hash, key);
		}
		else if (time_before(this_timer, next_timer))
			next_timer = this_timer;
	}
	rte_spinlock_unlock(&br->hash_lock);
	debug_brctl_event(BRCTL_EVENT_FDB_CLEANUP_END, NULL, "clean up old fdb---------------------end------------------------");

	return DTIMER_OK;
	//mod_timer(&br->gc_timer, round_jiffies_up(next_timer), true);
}

/* Completely flush all dynamic entries in forwarding database.*/
void br_fdb_flush(struct net_bridge *br)
{
	uint32_t iter = 0;
	struct net_bridge_fdb_entry *f;
	struct rte_hash *fdb_hash = br->fdb.fdb_hash;
	struct fdb_hash_key *key;

	rte_spinlock_lock(&br->hash_lock);//因为设置了flag 并发写入，所以可能这里不需要加自旋锁�?
	while (rte_hash_iterate(fdb_hash, (const void **)&key,(void **)&f, &iter) >= 0) {
		if (!f->is_static){
			(void)fdb_delete_with_key(fdb_hash, key);
		}
	}
	rte_spinlock_unlock(&br->hash_lock);
}

/* Flush all entries referring to a specific port.
 * if do_all is set also flush static entries
 */
void br_fdb_delete_by_port(struct net_bridge *br,
			   const struct net_bridge_port *p,
			   int do_all)
{
	uint32_t iter = 0;
	int err  = 0;
	struct net_bridge_fdb_entry *f;
	struct rte_hash *fdb_hash = br->fdb.fdb_hash;
	struct fdb_hash_key *key = NULL;

	assert(fdb_hash);
	
	rte_spinlock_lock(&br->hash_lock);//因为设置了flag 并发写入，所以可能这里不需要加自旋锁�?
	while (rte_hash_iterate(fdb_hash, (const void **)&key,(void **)&f, &iter) >= 0) {
		if (f->dst != p) 
			continue;

		if (f->is_static && !do_all)
			continue;
		/*
		 * if multiple ports all have the same device address
		 * then when one port is deleted, assign
		 * the local entry to other port
		 */

		if (f->is_local) {
			struct net_bridge_port *op;
			list_for_each_entry(op, &br->port_list, list) {
				if (op != p &&
				    rte_is_same_ether_addr(&op->dev->addr, &f->addr)) {
					f->dst = op;
					goto skip_delete;
				}
			}
		}
		
		err = fdb_delete_with_key(fdb_hash, key);
		RTE_SET_USED(err);
		skip_delete: ;
	}	
	rte_spinlock_unlock(&br->hash_lock);
}

/* No locking or refcounting, assumes caller has rcu_read_lock */
struct net_bridge_fdb_entry *__br_fdb_get(struct net_bridge *br,
					  struct rte_ether_addr *addr)
{
	struct net_bridge_fdb_entry *fdb;
	struct fdb_hash_key key;
	struct rte_hash *fdb_hash = br->fdb.fdb_hash;

	fdb_key_init(&key, addr);
	rte_hash_lookup_data(fdb_hash, &key, (void *)&fdb);
	if(!fdb)
		return NULL;
	
	if(unlikely(has_expired(br, fdb)))
		return NULL;
	else
		return fdb;
}

//#if IS_ENABLED(CONFIG_ATM_LANE)
/* Interface used by ATM LANE hook to test
 * if an addr is on some other bridge port */
int br_fdb_test_addr(struct netif_port *dev,  struct rte_ether_addr *addr)
{
	struct net_bridge_fdb_entry *fdb;
	struct net_bridge_port *port;
	int ret;

	rte_rcu_qsbr_lock(get_fdb_rcu(), rte_lcore_id());
	//port = br_port_get_rcu(dev);
	port = dev->br_port;
	if (!port)
		ret = 0;
	else {
		fdb = __br_fdb_get(port->br, addr);
		ret = fdb && fdb->dst && fdb->dst->dev != dev &&
			fdb->dst->state == BR_STATE_FORWARDING;
	}
	rte_rcu_qsbr_unlock(get_fdb_rcu(), rte_lcore_id());

	return ret;
}
//#endif /* CONFIG_ATM_LANE */

/*
 * Fill buffer with forwarding table records in
 * the API format.
 */
int br_fdb_fillbuf(struct net_bridge *br, void *buf,
		   unsigned long maxnum, unsigned long skip)
{
	struct __fdb_entry *fe = buf;
	int num = 0;
	struct net_bridge_fdb_entry *f;
	uint32_t iter = 0;
	struct rte_hash *fdb_hash = br->fdb.fdb_hash;
	struct fdb_hash_key *key;

	memset(buf, 0, maxnum*sizeof(struct __fdb_entry));

	rte_rcu_qsbr_lock(get_fdb_rcu(), rte_lcore_id());
	while (rte_hash_iterate(fdb_hash, (const void **)&key,(void **)&f, &iter) >= 0){
		if (num >= maxnum)
			goto out;

		if (has_expired(br, f))
			continue;

		/* ignore pseudo entry for local MAC address */
		if (!f->dst)
			continue;

		if (skip) {
			--skip;
			continue;
		

			/* convert from internal format to API */
			rte_memcpy(fe->mac_addr, f->addr.addr_bytes, ETH_ALEN);

			/* due to ABI compat need to split into hi/lo */
			fe->port_no = f->dst->port_no;
			fe->port_hi = f->dst->port_no >> 8;

			fe->is_local = f->is_local;
			if (!f->is_static)
				fe->ageing_timer_value = /*jiffies_delta_to_clock_t*/(jiffies - f->updated);
			++fe;
			++num;
		}
	}
 out:
	rte_rcu_qsbr_lock(get_fdb_rcu(), rte_lcore_id());

	return num;
}

static struct net_bridge_fdb_entry *fdb_find(struct rte_hash * fdb_hash,
					     struct rte_ether_addr *addr)
{
	struct net_bridge_fdb_entry *fdb;
	struct fdb_hash_key hash_key;
	int find=0;
	
	fdb_key_init(&hash_key, addr);
	find = fdb_find_with_key(fdb_hash, &hash_key, &fdb);
	if(find != 0)
		return fdb;
	else
		return NULL;
}


static struct net_bridge_fdb_entry *fdb_find_rcu(struct rte_hash * fdb_hash,
						 struct rte_ether_addr *addr)
{
	struct net_bridge_fdb_entry *fdb;

	//加点rcu的保护？
	fdb = fdb_find(fdb_hash, addr);
	return fdb;
}



/* Add entry for local address of interface */
int br_fdb_insert(struct net_bridge *br, struct net_bridge_port *source,
		   struct rte_ether_addr *addr, int is_local, int is_static)
{
	int ret;

	rte_spinlock_lock(&br->hash_lock);
	ret = fdb_insert(br, source, addr, is_local, is_static);
	rte_spinlock_unlock(&br->hash_lock);
	return ret;
}

void br_fdb_update(struct net_bridge *br, struct net_bridge_port *source,
		   struct rte_ether_addr *addr)
{
	struct rte_hash *fdb_hash = br->fdb.fdb_hash;
	struct net_bridge_fdb_entry *fdb;

	/* some users want to always flood. */
	if (hold_time(br) == 0)
		return;

	/* ignore packets unless we are using this port */
	if (!(source->state == BR_STATE_LEARNING ||
	      source->state == BR_STATE_FORWARDING))
		return;

	fdb = fdb_find_rcu(fdb_hash, addr);
	if (likely(fdb)) {
		/* attempt to update an entry for a local interface */
		if (unlikely(fdb->is_local)) {
			/*if (net_ratelimit())*/
				RTE_LOG(WARNING, BR, "received packet on %s with "
					"own address as source address\n",
					source->dev->name);
		} else {
			/* fastpath: update of existing entry */
			fdb->dst = source;
			fdb->updated = jiffies;
		}
	} else {
		rte_spinlock_lock(&br->hash_lock);
		if(likely(!fdb_find(fdb_hash, addr))){
			if(!fdb_insert(br, source, addr, 0, 0)){
				//fdb_notify(br, fdb, RTM_NEWNEIGH);
				RTE_LOG(ERR, BR, "add fdb on %s wrong \n",
					source->dev->name);
			}
				
		}
		/* else  we lose race and someone else inserts
		 * it first, don't bother updating
		 */
		rte_spinlock_unlock(&br->hash_lock);
	}
}

static int fdb_to_nud(const struct net_bridge_fdb_entry *fdb)
{
	if (fdb->is_local)
		return NUD_PERMANENT;
	else if (fdb->is_static)
		return NUD_NOARP;
	else if (has_expired(fdb->dst->br, fdb))
		return NUD_STALE;
	else
		return NUD_REACHABLE;
}

/*
static int fdb_fill_info(struct sk_buff *skb, const struct net_bridge *br,
			 const struct net_bridge_fdb_entry *fdb,
			 u32 portid, u32 seq, int type, unsigned int flags)
{
	unsigned long now = jiffies;
	struct nda_cacheinfo ci;
	struct nlmsghdr *nlh;
	struct ndmsg *ndm;

	nlh = nlmsg_put(skb, portid, seq, type, sizeof(*ndm), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	ndm = nlmsg_data(nlh);
	ndm->ndm_family	 = AF_BRIDGE;
	ndm->ndm_pad1    = 0;
	ndm->ndm_pad2    = 0;
	ndm->ndm_flags	 = 0;
	ndm->ndm_type	 = 0;
	ndm->ndm_ifindex = fdb->dst ? fdb->dst->dev->ifindex : br->dev->ifindex;
	ndm->ndm_state   = fdb_to_nud(fdb);

	if (nla_put(skb, NDA_LLADDR, ETH_ALEN, &fdb->addr))
		goto nla_put_failure;
	ci.ndm_used	 = jiffies_to_clock_t(now - fdb->used);
	ci.ndm_confirmed = 0;
	ci.ndm_updated	 = jiffies_to_clock_t(now - fdb->updated);
	ci.ndm_refcnt	 = 0;
	if (nla_put(skb, NDA_CACHEINFO, sizeof(ci), &ci))
		goto nla_put_failure;

	if (nla_put(skb, NDA_VLAN, sizeof(u16), &fdb->vlan_id))
		goto nla_put_failure;

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static inline size_t fdb_nlmsg_size(void)
{
	return NLMSG_ALIGN(sizeof(struct ndmsg))
		+ nla_total_size(ETH_ALEN) /* NDA_LLADDR *
		+ nla_total_size(sizeof(u16)) * NDA_VLAN *
		+ nla_total_size(sizeof(struct nda_cacheinfo));
}


static void fdb_notify(struct net_bridge *br,
		       const struct net_bridge_fdb_entry *fdb, int type)
{
	struct net *net = dev_net(br->dev);
	struct sk_buff *skb;
	int err = -ENOBUFS;

	skb = nlmsg_new(fdb_nlmsg_size(), GFP_ATOMIC);
	if (skb == NULL)
		goto errout;

	err = fdb_fill_info(skb, br, fdb, 0, 0, type, 0);
	if (err < 0) {
		/* -EMSGSIZE implies BUG in fdb_nlmsg_size() *
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(skb);
		goto errout;
	}
	rtnl_notify(skb, net, 0, RTNLGRP_NEIGH, NULL, GFP_ATOMIC);
	return;
errout:
	if (err < 0)
		rtnl_set_sk_err(net, RTNLGRP_NEIGH, err);
}
*

/* Dump information about entries, in response to GETNEIGH *
int br_fdb_dump(struct sk_buff *skb,
		struct netlink_callback *cb,
		struct net_device *dev,
		int idx)
{
	struct net_bridge *br = netdev_priv(dev);
	int i;

	if (!(dev->priv_flags & IFF_EBRIDGE))
		goto out;

	for (i = 0; i < BR_HASH_SIZE; i++) {
		struct net_bridge_fdb_entry *f;

		hlist_for_each_entry_rcu(f, &br->hash[i], hlist) {
			if (idx < cb->args[0])
				goto skip;

			if (fdb_fill_info(skb, br, f,
					  NETLINK_CB(cb->skb).portid,
					  cb->nlh->nlmsg_seq,
					  RTM_NEWNEIGH,
					  NLM_F_MULTI) < 0)
				break;
skip:
			++idx;
		}
	}

out:
	return idx;
}

/* Update (create or replace) forwarding database entry */
static int fdb_add_entry(struct net_bridge_port *source, struct rte_ether_addr *addr,
			 __u16 state, __u16 flags)
{
	struct net_bridge *br = source->br;
	struct net_bridge_fdb_entry *fdb;
	bool modified = false;

	fdb = fdb_find(br->fdb.fdb_hash, addr);
	if (fdb == NULL) {
		/*if (!(flags & NLM_F_CREATE))
			return -ENOENT;
		*/
		fdb = fdb_create(br, source, addr, 0, 0);
		if (!fdb)
			return EDPVS_NOMEM;

		modified = true;
	} else {
		/*if (flags & NLM_F_EXCL)
			return -EEXIST;*/

		if (fdb->dst != source) {
			fdb->dst = source;
			modified = true;
		}
	}

	if (fdb_to_nud(fdb) != state) {
		if (state & NUD_PERMANENT)
			fdb->is_local = fdb->is_static = 1;
		else if (state & NUD_NOARP) {
			fdb->is_local = 0;
			fdb->is_static = 1;
		} else
			fdb->is_local = fdb->is_static = 0;

		modified = true;
	}

	fdb->used = jiffies;
	if (modified) {
		fdb->updated = jiffies;
		//fdb_notify(br, fdb, RTM_NEWNEIGH);
	}

	return 0;
}

static int __br_fdb_add(struct dpvs_ndmsg *ndm, struct net_bridge_port *p,
	        struct rte_ether_addr *addr, u16 nlh_flags)
{
	int err = 0;

	if (ndm->ndm_flags & NTF_USE) {
		rte_rcu_qsbr_lock(get_fdb_rcu(), rte_lcore_id());
		br_fdb_update(p->br, p, addr);
		rte_rcu_qsbr_unlock(get_fdb_rcu(), rte_lcore_id());
	} else {
		rte_spinlock_lock(&p->br->hash_lock);
		err = fdb_add_entry(p, addr, ndm->ndm_state, nlh_flags);
		rte_spinlock_unlock(&p->br->hash_lock);
	}

	return err;
}

/* Add new permanent fdb entry with RTM_NEWNEIGH */
int br_fdb_add(struct dpvs_ndmsg *ndm,
	       struct netif_port *dev,
	       struct rte_ether_addr *addr, u16 nlh_flags)
{
	struct net_bridge_port *p;
	int err = 0;
	

	if (!(ndm->ndm_state & (NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE))) {
		RTE_LOG(ERR, BR, "bridge: RTM_NEWNEIGH with invalid state %#x\n", ndm->ndm_state);
		return EDPVS_INVAL;
	}

	//p = br_port_get_rtnl(dev);
	p = dev->br_port;
	if (p == NULL) {
		RTE_LOG(ERR, BR, "bridge: RTM_NEWNEIGH %s not a bridge port\n",
			dev->name);
		return EDPVS_INVAL;
	}

	
	err = __br_fdb_add(ndm, p, addr, nlh_flags);
	return err;
}

int fdb_delete_by_addr(struct net_bridge *br, struct rte_ether_addr *addr)
{
	struct net_bridge_fdb_entry *fdb;
	struct rte_hash *h = br->fdb.fdb_hash;

	fdb = fdb_find(h, addr);
	if (!fdb)
		return -EDPVS_NOTEXIST;

	fdb_delete(h, addr);
	return 0;
}

static int __br_fdb_delete(struct net_bridge_port *p,
			   struct rte_ether_addr *addr)
{
	int err;

	rte_spinlock_lock(&p->br->hash_lock);
	err = fdb_delete_by_addr(p->br, addr);
	rte_spinlock_unlock(&p->br->hash_lock);

	return err;
}

/* Remove neighbor entry with RTM_DELNEIGH */
int br_fdb_delete(struct dpvs_ndmsg *ndm,
					struct netif_port  *dev,
		  			struct rte_ether_addr *addr)
{
	struct net_bridge_port *p;
	int err;
	
	p = dev->br_port;
	if (p == NULL) {
		RTE_LOG(ERR, BR, "bridge: RTM_DELNEIGH %s not a bridge port\n",
			dev->name);
		return EDPVS_INVAL;
	}

	err = __br_fdb_delete(p, addr);
	return err;
}

		  
void br_fdb_change_mac_address(struct net_bridge *br, struct rte_ether_addr *newaddr)
{
	struct net_bridge_fdb_entry *f;
	struct rte_hash *fdb_hash = br->fdb.fdb_hash;
	u16 vid = 0;

	/* If old entry was unassociated with any port, then delete it. */
	f = __br_fdb_get(br, &br->dev->addr);
	if (f && f->is_local && !f->dst){
		fdb_delete(fdb_hash, &f->addr);
	}


	fdb_insert(br, NULL, newaddr, 1, 1);

	/* Now remove and add entries for every VLAN configured on the
	 * bridge.  This function runs under RTNL so the bitmap will not
	 * change from under us.
	 */
	
}

