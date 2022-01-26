/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 chc.
 */
#ifndef __INCLUDE_TEST_NODE_PRIV_H__
#define __INCLUDE_TEST_NODE_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

//#define NUM_MBUFS RTE_GRAPH_BURST_SIZE
//#define BURST 128
#define FRAG_NUM_MAX 128

enum test_node_next_nodes {
    TEST_NEXT_DROP,
    TEST_NEXT_IP_RCV,
    TEST_NEXT_ICMP,
    TEST_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_TEST_NODE_PRIV_H__ */
