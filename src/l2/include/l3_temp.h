/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2020 Marvell.
 */
#ifndef __INCLUDE_L3_TEMP_H__
#define __INCLUDE_L3_TEMP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#define OBJS_PER_CLINE (RTE_CACHE_LINE_SIZE / sizeof(void *))

enum l3_temp_next_nodes {
	//drop
	L3_TEMP_NEXT_PKT_DROP,

	//forward
	L3_TEMP_NEXT_L2_XMIT,

	L3_TEMP_NEXT_IPV4,
	
	L3_TEMP_NEXT_MAX,
};

struct l3_temp_node_ctx {
	enum l3_temp_next_nodes last_index;
};



#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_L3_TEMP_H__ */



