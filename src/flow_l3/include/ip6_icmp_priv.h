/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 chc.
 */
#ifndef __INCLUDE_IP6_ICMP_PRIV_H__
#define __INCLUDE_IP6_ICMP_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

enum ip6_icmp_next_nodes {
    IP6_ICMP_NEXT_DROP,
    IP6_ICMP_NEXT_ICMP_PING_FORWARD,
    IP6_ICMP_NEXT_VXLAN,
    IP6_ICMP_NEXT_L2,
    IP6_ICMP_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP6_ICMP_PRIV_H__ */


