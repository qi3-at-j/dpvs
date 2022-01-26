/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 chc.
 */
#ifndef __INCLUDE_IP4_LOCAL_DELIVER_FINISH_PRIV_H__
#define __INCLUDE_IP4_LOCAL_DELIVER_FINISH_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

#define MAX_INET_PROTOS		256
#define IPPROTO_VRRP		112

enum ip4_local_deliver_finish_next_nodes {
    IP4_LOCAL_DELIVER_FINISH_NEXT_DROP,
    IP4_LOCAL_DELIVER_FINISH_NEXT_UDP,
    IP4_LOCAL_DELIVER_FINISH_NEXT_VRRP,
    IP4_LOCAL_DELIVER_FINISH_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP4_LOCAL_DELIVER_FINISH_PRIV_H__ */
