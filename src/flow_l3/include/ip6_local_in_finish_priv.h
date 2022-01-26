/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 chc.
 */
#ifndef __INCLUDE_IP6_LOCAL_IN_FINISH_PRIV_H__
#define __INCLUDE_IP6_LOCAL_IN_FINISH_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

#define MAX_INET6_PROTOS		256

enum ip6_local_in_finish_next_nodes {
    IP6_LOCAL_IN_FINISH_NEXT_DROP,
    IP6_LOCAL_IN_FINISH_NEXT_UDP,
    IP6_LOCAL_IN_FINISH_NEXT_ICMP6,
    IP6_LOCAL_IN_FINISH_NEXT_FORWARD,
    IP6_LOCAL_IN_FINISH_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP6_LOCAL_IN_FINISH_PRIV_H__ */

