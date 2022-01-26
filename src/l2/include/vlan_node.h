/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2020 Marvell.
 */
#ifndef __INCLUDE_VLAN_NODE_H__
#define __INCLUDE_VLAN_NODE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#define OBJS_PER_CLINE (RTE_CACHE_LINE_SIZE / sizeof(void *))

enum vlan_node_next_nodes {
	VLAN_NODE_NEXT_PKT_DROP,
	//VLAN_NODE_NEXT_L2_ETHER_INPUT,
	VLAN_NODE_NEXT_BRIDGE,
	VLAN_NODE_NEXT_L3_TEMP,
	VLAN_NODE_NEXT_MAX,
};

struct vlan_node_ctx {
	enum vlan_node_next_nodes last_index;
};



#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_VLAN_NODE_H__ */


