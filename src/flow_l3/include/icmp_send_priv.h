/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 chc.
 */
#ifndef __INCLUDE_ICMP_SEND_PRIV_H__
#define __INCLUDE_ICMP_SEND_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

enum icmp_send_next_nodes {
    ICMP_SEND_NEXT_DROP,
    ICMP_SEND_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_ICMP_SEND_PRIV_H__ */
