/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2020 Marvell.
 */
#ifndef __INCLUDE_L2_XMIT_H__
#define __INCLUDE_L2_XMIT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#define OBJS_PER_CLINE (RTE_CACHE_LINE_SIZE / sizeof(void *))

#define L2_XMIT
#define RTE_LOGTYPE_L2_XMIT   RTE_LOGTYPE_USER1

enum L2_xmit_next_nodes {
	//drop
	L2_XMIT_NEXT_PKT_DROP,

	//ether_output
	L2_XMIT_NEXT_ETHER_OUTPUT,

	L2_XMIT_NEXT_MAX,
};

struct L2_xmit_node_ctx {
	enum L2_xmit_next_nodes last_index;
};



#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_L2_XMIT_H__ */

