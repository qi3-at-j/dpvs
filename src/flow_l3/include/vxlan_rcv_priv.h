/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 chc.
 */
#ifndef __INCLUDE_VXLAN_RCV_PRIV_H__
#define __INCLUDE_VXLAN_RCV_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

enum vxlan_rcv_next_nodes {
    VXLAN_RCV_NEXT_DROP,
    VXLAN_RCV_NEXT_L2,
    VXLAN_RCV_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_VXLAN_RCV_PRIV_H__ */
