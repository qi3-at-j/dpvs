/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 chc.
 */
#ifndef __INCLUDE_IP6_FORWARD_PRIV_H__
#define __INCLUDE_IP6_FORWARD_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

enum ip6_forward_next_nodes {
    IP6_FORWARD_NEXT_DROP,
    IP6_FORWARD_NEXT_ICMP,
    IP6_FORWARD_NEXT_FW,
    IP6_FORWARD_NEXT_FINISH,
    IP6_FORWARD_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP6_FORWARD_PRIV_H__ */

