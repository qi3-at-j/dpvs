/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 chc.
 */
#ifndef __INCLUDE_IP6_RCV_PRIV_H__
#define __INCLUDE_IP6_RCV_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>


enum ip6_rcv_next_nodes {
	IP6_RCV_NEXT_DROP,
	IP6_RCV_NEXT_FINISH,
	IP6_RCV_NEXT_FW,
	IP6_RCV_NEXT_MAX,
};


#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP6_RCV_PRIV_H__ */

