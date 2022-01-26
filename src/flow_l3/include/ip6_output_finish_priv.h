/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 chc.
 */
#ifndef __INCLUDE_IP6_OUTPUT_FINISH_PRIV_H__
#define __INCLUDE_IP6_OUTPUT_FINISH_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

enum ip6_output_finish_next_nodes {
    IP6_OUTPUT_FINISH_NEXT_DROP,
    IP6_OUTPUT_FINISH_NEXT_VXLAN_SEND,
    IP6_OUTPUT_FINISH_NEXT_L2,
    IP6_OUTPUT_FINISH_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP6_OUTPUT_FINISH_PRIV_H__ */

