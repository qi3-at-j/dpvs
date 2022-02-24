
#ifndef __VXLAN_CTRL_PRIV_H__
#define __VXLAN_CTRL_PRIV_H__

#include <arpa/inet.h>
#include "conf/inet.h"

#include "list.h"

#define VXLAN_TUNNEL_BUCKETS_NUM (1 << 4)

#ifndef TYFLOW_LEGACY
#ifndef FLOW_L3_DONT_USE_MEMPOOL
#define VXLAN_TUNN_USE_MEMPOOL
#endif
#endif

struct vxlan_tunnel_entry {
    struct hlist_node hnode;
	uint32_t vni;
    uint8_t family;
    union inet_addr remote_ip;
    union inet_addr saddr;
    uint16_t dst_port;

    /* ipv4 */
    uint8_t ttl;
    uint8_t tos;

#ifdef VXLAN_TUNN_USE_MEMPOOL
    struct rte_mempool *mp;
#endif
};

struct vxlan_tunnel_table {
	struct hlist_head ht[VXLAN_TUNNEL_BUCKETS_NUM];
    rte_atomic32_t cnt;
};

int api_vxlan_tunnel_init(void *);
int api_vxlan_tunnel_lookup(void *);
int api_vxlan_tunnel_add(void *);
int api_vxlan_tunnel_del(void *);
int api_vxlan_tunnel_clear(void *);
int api_vxlan_tunnel_dump(void *);
struct vxlan_tunnel_entry * vxlan_tunnel_lookup(struct vxlan_tunnel_entry *);

#endif
