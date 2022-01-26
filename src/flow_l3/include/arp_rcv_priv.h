/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 chc.
 */
#ifndef __INCLUDE_ARP_RCV_PRIV_H__
#define __INCLUDE_ARP_RCV_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

enum arp_rcv_next_nodes {
    ARP_RCV_NEXT_DROP,
    ARP_RCV_NEXT_L2,
    ARP_RCV_NEXT_VXLAN,
    ARP_RCV_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_ARP_RCV_PRIV_H__ */
