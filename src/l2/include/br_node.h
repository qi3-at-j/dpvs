/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2020 Marvell.
 */
#ifndef __INCLUDE_BR_NODE_H__
#define __INCLUDE_BR_NODE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#define OBJS_PER_CLINE (RTE_CACHE_LINE_SIZE / sizeof(void *))

enum bridge_next_nodes {
	//drop
	BRIDGE_NEXT_PKT_DROP,

	//forward
	BRIDGE_NEXT_L2_XMIT,

	//up to temp l3
	BRIDGE_NEXT_L3_TEMP,

	BRIDGE_NEXT_MAX,
};

struct bridge_node_ctx {
	enum bridge_next_nodes last_index;
};



#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_ETHER_INPUT_H__ */


