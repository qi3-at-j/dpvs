/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 chc.
 */
#ifndef __INCLUDE_VXLAN_SEND_PRIV_H__
#define __INCLUDE_VXLAN_SEND_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

enum vxlan_send_next_nodes {
    VXLAN_SEND_NEXT_DROP,
    VXLAN_SEND_NEXT_OUTPUT_V4,
    VXLAN_SEND_NEXT_OUTPUT_V6,
    VXLAN_SEND_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_VXLAN_SEND_PRIV_H__ */
