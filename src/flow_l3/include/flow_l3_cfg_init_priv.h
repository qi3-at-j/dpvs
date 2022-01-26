/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 chc.
 */
#ifndef __INCLUDE_FLOW_L3_CFG_INIT_PRIV_H__
#define __INCLUDE_FLOW_L3_CFG_INIT_PRIV_H__

#include "vrf_priv.h"

#ifdef __cplusplus
extern "C" {
#endif

enum cfg_type {
    GET_ROUTE_V4 = 0,
    GET_ROUTE_V4_DIP,
    GET_ROUTE_V4_MASK,
    GET_ROUTE_V4_GW,
    GET_ROUTE_V4_PORT,
    GET_ROUTE_V4_TYPE,
    GET_ROUTE_V6,
    GET_ROUTE_V6_DIP,
    GET_ROUTE_V6_MASK,
    GET_ROUTE_V6_GW,
    GET_ROUTE_V6_PORT,
    GET_ROUTE_V6_TYPE,
    GET_VXLAN_TUN_V4,
    GET_VXLAN_TUN_V4_SIP,
    GET_VXLAN_TUN_V4_DIP,
    GET_VXLAN_TUN_V6,
    GET_VXLAN_TUN_V6_SIP,
    GET_VXLAN_TUN_V6_DIP,
#if VRF_USE_VNI_HASH
    GET_VRF_BIND_VNI,
#endif
#if VRF_USE_IP_HASH
    GET_VRF_BIND_IP,
    GET_VRF_BIND_IP6,
#endif
#if VRF_USE_DEV_HASH
    GET_VRF_BIND_PORT,
#endif
    GET_ARP_V4,
    GET_ARP_V6,
    GET_ARP_IP,
    GET_ARP_IP6,
    GET_ARP_MAC,
    GET_SW_ARP,
    GET_SW_FWD,
    GET_SW_NF,
};

int flow_cfgfile_init(void);
int flow_l3_init(void);
int cmd_route(uint8_t type, void *route_ety);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_FLOW_L3_CFG_INIT_PRIV_H__ */
