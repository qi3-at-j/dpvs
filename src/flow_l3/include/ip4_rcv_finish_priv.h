/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 chc.
 */
#ifndef __INCLUDE_IP4_RCV_FINISH_PRIV_H__
#define __INCLUDE_IP4_RCV_FINISH_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

enum ip4_rcv_finish_next_nodes {
    IP4_RCV_FINISH_NEXT_DROP,
    IP4_RCV_FINISH_NEXT_LOCAL,
    IP4_RCV_FINISH_NEXT_FORWARD,
    IP4_RCV_FINISH_NEXT_ICMP,
    IP4_RCV_FINISH_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP4_RCV_FINISH_PRIV_H__ */
