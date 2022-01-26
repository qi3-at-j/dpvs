/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 chc.
 */
#ifndef __INCLUDE_IP4_OUTPUT_PRIV_H__
#define __INCLUDE_IP4_OUTPUT_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

//#define NUM_MBUFS RTE_GRAPH_BURST_SIZE
//#define BURST 128
#define FRAG_NUM_MAX 128

enum ip4_output_next_nodes {
    IP4_OUTPUT_NEXT_DROP,
    IP4_OUTPUT_NEXT_FW,
    IP4_OUTPUT_NEXT_ICMP,
    IP4_OUTPUT_NEXT_FINISH,
    IP4_OUTPUT_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP4_OUTPUT_PRIV_H__ */
