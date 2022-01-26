
#ifndef __DPVS_BR_H__
#define __DPVS_BR_H__

#include "conf/common.h"
#include "ipvs/kcompat.h"
#include "general_rcu.h"
#include "list.h"
#include "dpdk.h"
#include "netif.h"
#include "vlan.h"
#include "br_node.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "debug_flow.h"

#define BR
#define RTE_LOGTYPE_BR    RTE_LOGTYPE_USER1

#define this_br_stats(br)       ((br)->lcore_stats[rte_lcore_id()])

/* Control of forwarding link local multicast */
#define BR_GROUPFWD_DEFAULT	0

#define BR_HASH_BITS 8
#define BR_HASH_SIZE (1 << BR_HASH_BITS)

extern struct notifier_block br_device_notifier;

/* Reserved Ethernet Addresses per IEEE 802.1Q */
static const u8 eth_reserved_addr_base[ETH_ALEN] __rte_aligned(2) =
{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };

#define br_port_exists(dev) (dev->priv_flags & PRIV_FLAG_BRIDGE_PORT)
static inline bool is_link_local_ether_addr(const u8 *addr)
{
	__be16 *a = (__be16 *)addr;
	 __be16 *b = ( __be16 *)eth_reserved_addr_base;
	 __be16 m = rte_cpu_to_be_16(0xfff0);

	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | ((a[2] ^ b[2]) & m)) == 0;
}

typedef __u16 port_id;

typedef struct bridge_id bridge_id;

#define BR_PORT_BITS	10
#define BR_MAX_PORTS	(1<<BR_PORT_BITS)
#define BR_VLAN_BITMAP_LEN	BITS_TO_LONGS(VLAN_N_VID)

struct bridge_id
{
	unsigned char	prio[2];
	unsigned char	addr[6];
};

struct br_cpu_netstats {
	uint64_t            rx_packets;
    uint64_t            rx_bytes;
    uint64_t            rx_multicast;
    uint64_t            tx_packets;
    uint64_t            tx_bytes;
    uint64_t            rx_errors;
    uint64_t            tx_dropped;
};


/**********************************fdb相关*****************************************/
#define BR_FDB_MBUFPOOL_SIZE        8192  // 2^20 - 1
#define BR_FDB_CACHE_SIZE           256

#define BR_FDB_HASH_ENTRIES         256
#define BR_FDB_NAME_SIZE            32

#define FDB_RCU_DQ_SIZE				1024
#define FDB_RCU_DQ_RECLAIM_THD	    256//64
#define FDB_RCU_DQ_RECLAIM_MAX	    16

struct fdb_hash_key {
	//uint8_t addr[RTE_ETHER_ADDR_LEN]; /**< 以太网的mac地址，我看内核代码，在br_mac_hash中，用的是get_unaligned，因此我也不用rte_ether_addr了，因为该结构是经过aligned之后的恐有问题 */
	struct rte_ether_addr addr;
};

struct net_bridge_fdb_entry
{
	struct hlist_node		hlist;
	struct net_bridge_port		*dst;

	//struct rcu_head			rcu;
	unsigned long			updated;
	unsigned long			used;
	struct rte_ether_addr	addr;
	unsigned char			is_local;
	unsigned char			is_static;
};

struct br_fdb{
	struct rte_hash 		*fdb_hash;
	rte_atomic32_t 			entries_nb;            /**< Used rules so far. */
};

struct net_bridge
{
	rte_spinlock_t			lock;
	struct list_head		port_list;
	struct list_head        br_list;
	struct netif_port		*dev;
	rte_spinlock_t			hash_lock;
	struct br_cpu_netstats  br_cpu_netstats[DPVS_MAX_LCORE];
	//struct hlist_head		hash[BR_HASH_SIZE];
	struct br_fdb           fdb;
/*
#ifdef CONFIG_BRIDGE_NETFILTER
	struct rtable 			fake_rtable;
	bool				nf_call_iptables;
	bool				nf_call_ip6tables;
	bool				nf_call_arptables;
#endif
*/
	u16				group_fwd_mask;

	/* STP */
	struct bridge_id			designated_root;
	struct bridge_id			bridge_id;
	u32				root_path_cost;
	unsigned long			max_age;
	unsigned long			hello_time;
	unsigned long			forward_delay;
	unsigned long			bridge_max_age;
	unsigned long			ageing_time;
	unsigned long			bridge_hello_time;
	unsigned long			bridge_forward_delay;

	u8				group_addr[ETH_ALEN];
	u16				root_port;

	enum {
		BR_NO_STP, 		/* no spanning tree */
		BR_KERNEL_STP,		/* old STP in kernel */
		BR_USER_STP,		/* new RSTP in userspace */
	} stp_enabled;

	unsigned char			topology_change;
	unsigned char			topology_change_detected;

/*#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
	unsigned char			multicast_router;

	u8				multicast_disabled:1;
	u8				multicast_querier:1;

	u32				hash_elasticity;
	u32				hash_max;

	u32				multicast_last_member_count;
	u32				multicast_startup_queries_sent;
	u32				multicast_startup_query_count;

	unsigned long			multicast_last_member_interval;
	unsigned long			multicast_membership_interval;
	unsigned long			multicast_querier_interval;
	unsigned long			multicast_query_interval;
	unsigned long			multicast_query_response_interval;
	unsigned long			multicast_startup_query_interval;

	spinlock_t			multicast_lock;
	struct net_bridge_mdb_htable __rcu *mdb;
	struct hlist_head		router_list;

	struct timer_list		multicast_router_timer;
	struct timer_list		multicast_querier_timer;
	struct timer_list		multicast_query_timer;
#endif
*/
	struct dpvs_timer       hello_timer;
	struct dpvs_timer		tcn_timer;
	struct dpvs_timer		topology_change_timer;
	struct dpvs_timer		gc_timer;
//#ifdef CONFIG_BRIDGE_VLAN_FILTERING
	u8				vlan_enabled;
	struct net_port_vlans __rcu	*vlan_info;
//#endif

};

struct net_bridge_port
{
	struct net_bridge		*br;
	struct netif_port		*dev;
	struct list_head		list;

	/* STP */
	u8				priority;
	u8				state;
	u16				port_no;
	unsigned char			topology_change_ack;
	unsigned char			config_pending;
	port_id				port_id;
	port_id				designated_port;
	bridge_id			designated_root;
	bridge_id			designated_bridge;
	u32				path_cost;
	u32				designated_cost;
	unsigned long			designated_age;

	struct dpvs_timer		forward_delay_timer;
	struct dpvs_timer		hold_timer;
	struct dpvs_timer		message_age_timer;
	//struct rcu_head			rcu;

	unsigned long 			flags;
#define BR_HAIRPIN_MODE		0x00000001
#define BR_BPDU_GUARD           0x00000002
#define BR_ROOT_BLOCK		0x00000004
#define BR_MULTICAST_FAST_LEAVE	0x00000008
#define BR_ADMIN_COST		0x00000010

/*

#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
	u32				multicast_startup_queries_sent;
	unsigned char			multicast_router;
	struct timer_list		multicast_router_timer;
	struct timer_list		multicast_query_timer;
	struct hlist_head		mglist;
	struct hlist_node		rlist;
#endif



#ifdef CONFIG_SYSFS
	char				sysfs_name[IFNAMSIZ];
#endif

#ifdef CONFIG_NET_POLL_CONTROLLER
	struct netpoll			*np;
#endif
	*/

//#ifdef CONFIG_BRIDGE_VLAN_FILTERING
	//struct net_port_vlans __rcu	*vlan_info;
//#endif

};

/*日后做成rcu的形式参考内核*/
static inline struct net_bridge_port *
br_port_get_rcu(const struct netif_port *dev)
{
	struct net_bridge_port *port = dev->br_port;
	return port;
}
int br_add_bridge(const char *name);
int br_del_bridge(const char *name);
extern void br_dev_setup(struct netif_port *dev);
int br_add_if(struct net_bridge *br, struct netif_port *dev);
uint16_t br_dev_graph_xmit(s_nc_param *param, struct rte_mbuf *mbuf, struct netif_port *dev);
				
int br_min_mtu(const struct net_bridge *br);
int br_fdb_hash_init(struct net_bridge *br);

struct rte_rcu_qsbr *get_fdb_rcu(void);

struct net_bridge_fdb_entry *__br_fdb_get(struct net_bridge *br,
					  struct rte_ether_addr *addr);

uint16_t br_deliver(const struct net_bridge_port *to, struct rte_mbuf *mbuf);
void br_fdb_change_mac_address(struct net_bridge *br, struct rte_ether_addr *newaddr);
int br_del_if(struct net_bridge *br, struct netif_port *dev);

int br_fdb_add(struct dpvs_ndmsg *ndm,
	       struct netif_port *dev,
	       struct rte_ether_addr *addr, u16 nlh_flags);
int br_fdb_delete(struct dpvs_ndmsg *ndm,
					struct netif_port  *dev,
		  			struct rte_ether_addr *addr);

int br_fdb_insert(struct net_bridge *br, struct net_bridge_port *source,
		   struct rte_ether_addr *addr, int is_local, int is_static);
uint16_t br_flood_deliver(s_nc_param *param, struct net_bridge *br, struct rte_mbuf *mbuf);

void br_fdb_update(struct net_bridge *br, struct net_bridge_port *source,
		   struct rte_ether_addr *addr);
uint16_t br_forward(s_nc_param *param, struct net_bridge *br, 
			const struct net_bridge_port *to, struct rte_mbuf *mbuf, struct rte_mbuf *mbuf0);

uint16_t br_flood_forward(s_nc_param *param, struct net_bridge *br, struct rte_mbuf *mbuf,  struct rte_mbuf *mbuf2);
uint16_t br_handle_frame(s_nc_param *param);
void show_all_fdb_entrys(struct rte_hash *fdb_hash);
int br_fdb_cleanup(void *arg);

int bridge_global_list_add(struct       net_bridge *br);
struct net_bridge* bridge_get_by_name(const char *name);
int bridge_global_list_del(struct net_bridge *br);
int br_get_stats(struct netif_port *dev, struct rte_eth_stats *stats);
int br_fdb_init(void);
void br_dev_set_multicast_list(struct netif_port *dev);



#endif /* __DPVS_BR_H__ */

