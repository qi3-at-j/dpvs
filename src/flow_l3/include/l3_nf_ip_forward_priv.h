/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 chc.
 */
#ifndef __INCLUDE_L3_NF_IP_FORWARD_PRIV_H__
#define __INCLUDE_L3_NF_IP_FORWARD_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

enum l3_nf_ip_forward_next_nodes {
	L3_NF_IP_FORWARD_NEXT_DROP,
    L3_NF_IP_FORWARD_NEXT_FINISH,
	L3_NF_IP_FORWARD_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_L3_NF_IP_FORWARD_PRIV_H__ */
