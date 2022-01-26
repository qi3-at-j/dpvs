/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2020 Marvell.
 */
#ifndef __INCLUDE_ETHER_INPUT_H__
#define __INCLUDE_ETHER_INPUT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#define OBJS_PER_CLINE (RTE_CACHE_LINE_SIZE / sizeof(void *))

enum ether_input_next_nodes {
	ETHER_INPUT_NEXT_PKT_DROP,
	//PKT_CLS_NEXT_IP4_LOOKUP,
	//ETHER_INPUT_NEXT_L2_BOND,
	ETHER_INPUT_NEXT_L2_VLAN,
	ETHER_INPUT_NEXT_L2_BRIDGE,
	ETHER_INPUT_NEXT_L3_IPV4,
	ETHER_INPUT_NEXT_L3_IPV6,
	ETHER_INPUT_NEXT_ARP,
	ETHER_INPUT_NEXT_MAX,
};	

struct ether_input_node_ctx {
	enum ether_input_next_nodes last_index;
};



#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_ETHER_INPUT_H__ */

