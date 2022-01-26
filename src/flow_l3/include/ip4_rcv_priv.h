/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 chc.
 */
#ifndef __INCLUDE_IP4_RCV_PRIV_H__
#define __INCLUDE_IP4_RCV_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

#define IPPROTO_OSPF        89 /* OSPF protocol */

enum ip4_rcv_next_nodes {
	IP4_RCV_NEXT_DROP,
	IP4_RCV_NEXT_FINISH,
	IP4_RCV_NEXT_FW,
	IP4_RCV_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP4_RCV_PRIV_H__ */
