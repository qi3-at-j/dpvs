/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2021 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#ifndef __DPVS_NDISC_H__
#define __DPVS_NDISC_H__

//#include "neigh.h"
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include "linux_ipv6.h"
#include "vrrp_send_priv.h"

#define NDISC_OPT_SPACE(len) (((len)+2+7)&~7)

struct nd_msg {
    struct icmp6_hdr    icmph;
    struct in6_addr    target;
    uint8_t            opt[0];
};

/*
 * netinet/icmp6.h define ND_OPT by '#define', ND_OPT_MAX is not defined.
 * kernel define ND_OPT_ARRAY_MAX by enum, just define 256 here.
 */
#define __ND_OPT_ARRAY_MAX 256

struct ndisc_options {
    struct nd_opt_hdr *nd_opt_array[__ND_OPT_ARRAY_MAX];
    struct nd_opt_hdr *nd_useropts;
    struct nd_opt_hdr *nd_useropts_end;
};

#define nd_opts_src_lladdr      nd_opt_array[ND_OPT_SOURCE_LINKADDR]
#define nd_opts_tgt_lladdr      nd_opt_array[ND_OPT_TARGET_LINKADDR]
#define nd_opts_pi              nd_opt_array[ND_OPT_PREFIX_INFORMATION]
#define nd_opts_pi_end          nd_opt_array[0]  //__ND_OPT_PREFIX_INFO_END
#define nd_opts_rh              nd_opt_array[ND_OPT_REDIRECTED_HEADER]
#define nd_opts_mtu             nd_opt_array[ND_OPT_MTU]

/* ipv6 neighbour */
static inline uint8_t *ndisc_opt_addr_data(struct nd_opt_hdr *p,
                                           struct netif_port *dev)
{
    uint8_t *lladdr = (uint8_t *)(p + 1);
    int lladdrlen = p->nd_opt_len << 3;

    /* support rte_ether_addr only */
    if (lladdrlen != NDISC_OPT_SPACE(sizeof(dev->addr)))
        return NULL;

    return lladdr;
}

int ndisc_rcv(struct rte_mbuf *mbuf,
              struct netif_port *dev);

void ndisc_send_dad(struct netif_port *dev,
                    const struct in6_addr* solicit);

void ndisc_solicit(struct netif_port *dev,
                   struct in6_addr *target,
                   const struct in6_addr *saddr);

struct ndisc_options *ndisc_parse_options(uint8_t *opt, int opt_len,
                                                struct ndisc_options *ndopts);
struct rte_mbuf *ndisc_build_mbuf(struct netif_port *dev,
                                  const struct in6_addr *daddr,
                                  const struct in6_addr *saddr,
                                  const struct icmp6_hdr *icmp6h,
                                  const struct in6_addr *target,
                                  int llinfo);

struct rte_mbuf *ndisc_build_mbuf_graph(struct netif_port *dev,
                                         const struct in6_addr *daddr,
                                         const struct in6_addr *saddr,
                                         const struct icmp6_hdr *icmp6h,
                                         const struct in6_addr *target,
                                         int llinfo,
                                         struct vrrp_entry *vrrp_node);

#endif /* __DPVS_NDISC_H__ */
