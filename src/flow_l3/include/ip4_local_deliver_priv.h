/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 chc.
 */
#ifndef __INCLUDE_IP4_LOCAL_DELIVER_PRIV_H__
#define __INCLUDE_IP4_LOCAL_DELIVER_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

enum ip4_local_deliver_next_nodes {
	IP4_LOCAL_DELIVER_NEXT_DROP,
    IP4_LOCAL_DELIVER_NEXT_FINISH,
    IP4_LOCAL_DELIVER_NEXT_FW,
	IP4_LOCAL_DELIVER_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP4_LOCAL_DELIVER_PRIV_H__ */
