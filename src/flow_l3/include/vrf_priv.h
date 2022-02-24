
#ifndef __NODE_VRF_PRIV_H__
#define __NODE_VRF_PRIV_H__

#include "route_priv.h"
#include "list.h"
#include "flow_l3_cfg_init_priv.h"

#ifndef TYFLOW_LEGACY
#ifndef FLOW_L3_DONT_USE_MEMPOOL
#define VRF_USE_MEMPOOL
#endif
#endif

#define VRF_USE_DEV_HASH 0
#if VRF_USE_DEV_HASH
#define VRF_USE_VNI_HASH 0
#else
#define VRF_USE_VNI_HASH 1
#endif
#define VRF_USE_IP_HASH 1

extern struct conf_tbl_entry_size g_conf_tbl_entry_size;
//#define MAX_ROUTE_TBLS (1 << 10)
#define MAX_ROUTE_TBLS (g_conf_tbl_entry_size.tbl_size)

#define GLOBAL_ROUTE_TBL_ID 0

#define VRF_BUCKETS_NUM (1 << 4)
//#define HASH_INITVAL	((uint32_t)0xcafef00d)
//#define JHASH_INITVAL		0xdeadbeef

#define VNI_BUCKETS_NUM (1 << 8)
#define IP_BUCKETS_NUM (1 << 8)

enum VRF_NODE_TYPE {
#if VRF_USE_DEV_HASH
    VRF_TYPE_PORT,
#endif
#if VRF_USE_VNI_HASH
    VRF_TYPE_VNI,
#endif
#if VRF_USE_IP_HASH
    VRF_TYPE_IP,
#endif
};

struct net_vrf {
    uint8_t type;
#if VRF_USE_DEV_HASH
    struct netif_port *port;
#endif
#if VRF_USE_VNI_HASH
    uint32_t vni;
#endif
#if VRF_USE_IP_HASH    
    uint8_t family;
    union inet_addr ip;
#endif
    uint32_t table_id;
    //uint16_t port_id;
    /* entry in vrf_map_elem */
	struct list_head me_list;
    /* entry in vni or ip map */
    struct hlist_node hnode;

#ifdef VRF_USE_MEMPOOL
    struct rte_mempool *mp;
#endif
};

struct vrf_map_elem {
    struct hlist_node hnode;
    struct list_head vrf_list; /* VRFs registered to this table */
	uint32_t table_id;
    rte_atomic32_t cnt;

#ifdef VRF_USE_MEMPOOL
    struct rte_mempool *mp;
#endif
};

struct vrf_map {
	struct hlist_head ht[VRF_BUCKETS_NUM];
    rte_atomic32_t cnt;
};

#if VRF_USE_VNI_HASH
struct vrf_vni_map {
	struct hlist_head ht[VNI_BUCKETS_NUM];
    rte_atomic32_t cnt;
};
#endif

#if VRF_USE_IP_HASH
struct vrf_ip_map {
	struct hlist_head ht[IP_BUCKETS_NUM];
    rte_atomic32_t cnt;
};
#endif

#if VRF_USE_VNI_HASH
struct net_vrf *vrf_vni_lookup(uint32_t vni);
#endif

#if VRF_USE_IP_HASH
struct net_vrf *vrf_ip_lookup(uint8_t af, union inet_addr *ip);
#endif

int api_vrf_init(void *arg);
int api_vrf_add(void *arg);
int api_vrf_bind(void *arg);
int api_vrf_unbind(void *arg);
int api_vrf_dump(void *arg);
int api_vrf_del_id(void *arg);
int api_vrf_del_all(void *arg);
int api_vrf_clear_id(void *arg);
int api_vrf_clear_all(void *arg);
#endif
