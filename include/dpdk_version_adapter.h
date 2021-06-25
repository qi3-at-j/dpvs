/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2021 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#ifndef __DPVS_DPDK_VERSON_ADAPTER_H__
#define __DPVS_DPDK_VERSON_ADAPTER_H__
#include <rte_common.h>
#include <rte_version.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ethdev_driver.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_string_fns.h>
#include <rte_malloc.h>
#include <rte_rwlock.h>
#include <rte_timer.h>
#include <rte_jhash.h>
#include <rte_kni.h>
#include <rte_ip_frag.h>
#include <rte_eth_bond.h>
#include <rte_eth_bond_8023ad.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_node_eth_api.h>
#include <rte_hash.h>
//#include <rte_cuckoo_hash.h>
#include <rte_rcu_qsbr.h>

struct mbuf_priv_userdata {
	RTE_STD_C11
	union {
		void *userdata;   /**< Can be used for external metadata */
		uint64_t udata64; /**< Allow 8-byte userdata on 32-bit */
	};
};

static const struct rte_mbuf_dynfield mbuf_userdata_dynfield_desc = {
	.name = "mbuf_userdata_dynfield",
	.size = sizeof(struct mbuf_priv_userdata),
	.align = __alignof__(struct mbuf_priv_userdata),
};


extern int mbuf_userdata_dynfield_offset;

int dpdk_priv_userdata_register(void);
__rte_always_inline  void *mbuf_userdata_get(struct rte_mbuf *m);
__rte_always_inline void mbuf_userdata_set(struct rte_mbuf *m, void *userdata);

__rte_always_inline  uint64_t mbuf_udata64_get(struct rte_mbuf *m);
__rte_always_inline void mbuf_udata64_set(struct rte_mbuf *m, uint64_t udata64);
#endif /* __DPVS_DPDK_VERSON_ADAPTER_H__ */

