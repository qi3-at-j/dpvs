/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 chc.
 */
#ifndef __INCLUDE_L3_NF_IP_LOCAL_IN_PRIV_H__
#define __INCLUDE_L3_NF_IP_LOCAL_IN_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

enum l3_nf_ip_local_in_next_nodes {
	L3_NF_IP_LOCAL_IN_NEXT_DROP,
    L3_NF_IP_LOCAL_IN_NEXT_FINISH,
	L3_NF_IP_LOCAL_IN_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_L3_NF_IP_LOCAL_IN_PRIV_H__ */
