/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 chc.
 */
#ifndef __INCLUDE_IP6_OUTPUT_PRIV_H__
#define __INCLUDE_IP6_OUTPUT_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#include <flow.h>
enum ip6_output_next_nodes {
    IP6_OUTPUT_NEXT_DROP,
    IP6_OUTPUT_NEXT_FW,
    IP6_OUTPUT_NEXT_ICMP,
    IP6_OUTPUT_NEXT_FINISH,
    IP6_OUTPUT_NEXT_MAX,
};

int ipv6_xmit_for_graph(struct rte_mbuf *mbuf, struct flow6 *fl6);
uint16_t ip6_neigh_output(int af, union inet_addr *nexhop,
                     struct rte_mbuf *m, struct netif_port *port,
                     struct rte_mbuf **nd_req);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP6_OUTPUT_PRIV_H__ */

