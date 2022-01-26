/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        VRRP implementation of VRRPv2 as specified in rfc2338.
 *              VRRP is a protocol which elect a master server on a LAN. If the
 *              master fails, a backup server takes over.
 *              The original implementation has been made by jerome etienne.
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

/* System includes */
#include <errno.h>

#include <unistd.h>
#include <sys/time.h>
#include <inttypes.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdint.h>
#include <net/if_arp.h>
#include <net/ethernet.h>

/* local include */
#include "parser/parser.h"
#include "l3_node_priv.h"
#include "vrrp_arp.h"
#include "vrrp_ndisc.h"
#include "vrrp_scheduler.h"
#include "vrrp.h"
#include "vrrp_data.h"
#include "vrrp_parser.h"
#include "list.h"
#include "../lib/logger.h"
#include "parser/utils.h"
#include "vrrp_send_priv.h"
#include "conf/inet.h"
#include "conf/inetaddr.h"
#include "vrrp_ring.h"
#include "netif.h"
#include "route_cli_priv.h"
#include "route6_priv.h"


#define	DEFAULT_MTU	1500

struct vrrp_entry g_vrrp_entry_ipv4;
struct vrrp_entry g_vrrp_entry_ipv6;

#if 0
extern int vrrp_add_route(union inet_addr *dst_addr, uint8_t family,
    uint8_t netmask, struct netif_port *port);
extern int vrrp_del_route(union inet_addr *dst_addr, uint8_t family,
    uint8_t netmask, struct netif_port *port);
#endif

static inline INT IN6ADDR_Cmp(IN const struct in6_addr *pstAddr1, IN const struct in6_addr *pstAddr2)
{
    UINT i;
    INT iRet;

    for(i=0; i < INET_ADDRSTRLEN; i++)
    {
        iRet = pstAddr1->s6_addr[i] - pstAddr2->s6_addr[i];
        if(0 != iRet)
        {
            break;
        }
    }

    return iRet;
}


void vrrp_state_refresh(uint8_t status)
{
	g_vrrp_entry_ipv4.status = status;	
	g_vrrp_entry_ipv6.status = status;
}

struct vrrp_entry *lookup_vrrp_mac(uint8_t *mac)
{
	const uint16_t *a = (const uint16_t *)mac;	
	const uint16_t *b = (const uint16_t *) (g_vrrp_entry_ipv4.mac);

	if(((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) == 0)
	{
		return &g_vrrp_entry_ipv4;
	}
	
	return NULL;
}

struct vrrp_entry *lookup_vrrp_ip(union inet_addr *addr, uint8_t family)
{
	if(AF_INET == family)
	{
		if(addr->in.s_addr == g_vrrp_entry_ipv4.addr.in.s_addr)
		{
			return &g_vrrp_entry_ipv4;
		}
	}
	else if(AF_INET6 == family)
	{
		if(0 == IN6ADDR_Cmp(&addr->in6, & g_vrrp_entry_ipv6.addr.in6))
		{
			return &g_vrrp_entry_ipv6;
		}
	}
	
	return NULL;
}

int get_vrrp_status(void)
{
	return g_vrrp_entry_ipv4.status;
}

/* VRRP header length */
size_t
vrrp_pkt_len(const vrrp_t *vrrp)
{
	size_t len = sizeof(vrrphdr_t);

	if (vrrp->family == AF_INET) {
		if (vrrp->version == VRRP_VERSION_2)
			len += VRRP_AUTH_LEN;
		len += vrrp->vip_cnt * sizeof(struct in_addr);
	}
	return len;
}

size_t __attribute__ ((pure))
vrrp_adv_len(const vrrp_t *vrrp)
{
	size_t len = vrrp_pkt_len(vrrp);

	if (vrrp->family == AF_INET) {
		len += sizeof(struct iphdr);
	}

	return len;
}

/* VRRP header pointer from buffer */
const vrrphdr_t *
vrrp_get_header(struct rte_mbuf *mbuf, uint32_t len)
{
	const struct iphdr *iph;	
	const vrrphdr_t *hd;
	
	iph = rte_pktmbuf_mtod_offset(mbuf, struct iphdr *, 0);

	/* Ensure we have received the full vrrp header */
	if (len < sizeof(struct iphdr) ||
	    len < (iph->ihl << 2) + sizeof(vrrphdr_t)) {
		log_message(LOG_INFO, "IPv4 VRRP packet too short - %u bytes", len);
		return NULL;
	}

	hd = rte_pktmbuf_mtod_offset(mbuf, vrrphdr_t *, (iph->ihl << 2));

	return hd;
}

static size_t
expected_vrrp_pkt_len(const vrrphdr_t *vh, int family)
{
	size_t len = sizeof(vrrphdr_t);

	if (family == AF_INET) {
		if (vh->vers_type >> 4 == VRRP_VERSION_2)
			len += VRRP_AUTH_LEN;
		len += vh->naddr * sizeof(struct in_addr);
	}
	else if (family == AF_INET6)
		len += vh->naddr * sizeof(struct in6_addr);

	return len;
}

static void
vrrp_update_pkt(vrrp_t *vrrp, uint8_t prio)
{
	char *bufptr = vrrp->send_buffer;
	vrrphdr_t *hd;

	if (vrrp->family == AF_INET) {
		bufptr += sizeof(struct iphdr);
	}

	hd = PTR_CAST(vrrphdr_t, bufptr);
	if (hd->priority != prio) {
		if (vrrp->family == AF_INET) {
			/* HC' = ~(~HC + ~m + m') */
			uint16_t *prio_addr = PTR_CAST(uint16_t, ((char *)&hd->priority - (((char *)hd -(char *)&hd->priority) & 1)));
			uint16_t old_val = *prio_addr;

			hd->priority = prio;
			hd->chksum = csum_incremental_update16(hd->chksum, old_val, *prio_addr);
		}
	}

	if (vrrp->family == AF_INET) {
		struct iphdr *ip = PTR_CAST(struct iphdr, (vrrp->send_buffer));
		
		if (!++vrrp->ip_id)
			++vrrp->ip_id;
		
		ip->id = htons(vrrp->ip_id);

		/* ip地址发生变更的话，需要更新 */
		if(ip->saddr != vrrp->saddr) {
			
			ip->saddr = vrrp->saddr;
		}

		if(ip->daddr != vrrp->unicast_peer) {
			
			ip->daddr = vrrp->unicast_peer;
		}

		ip->check = 0;
		ip->check = rte_ipv4_cksum((struct rte_ipv4_hdr *)ip);
	}

	return;
}

/*
 * VRRP incoming packet check.
 * return VRRP_PACKET_OK if the pkt is valid, or
 *	  VRRP_PACKET_KO if packet invalid or
 *	  VRRP_PACKET_DROP if packet not relevant to us
 *	  VRRP_PACKET_OTHER if packet has wrong vrid
 *
 * Note: If we return anything other that VRRP_PACKET_OK, we should log the reason why
 *
 * On entry, we have already checked that sufficient data has been received for the
 * IP header (if IPv4), the ipsec_ah header (if IPv4 and the ip header protocol
 * is IPPROTO_AH), and the VRRP protocol header. We haven't yet checked that there is
 * suficient data received for all the VIPs.
 */
static int
vrrp_check_packet(vrrp_t *vrrp, const vrrphdr_t *hd, struct rte_mbuf *mbuf, UINT buflen_ret)
{
	const struct iphdr *ip = rte_pktmbuf_mtod_offset(mbuf, struct iphdr *, 0);	
	int ihl = 0;
	size_t vrrppkt_len;
	uint32_t acc_csum = 0;
	UINT buflen, expected_len;
	uint16_t csum_calc;

	buflen = buflen_ret;

	/* IPv4 related */
	if (vrrp->family == AF_INET) {
		/* To begin with, we just concern ourselves with the protocol headers */
		ihl = ip->ihl << 2;

		expected_len = ihl;
	}

	/* Now calculate expected_len to include everything */
	expected_len += expected_vrrp_pkt_len(hd, vrrp->family);

	/* 6 is padding fileds length */
	expected_len += 6;

	/*
	 * MUST verify that the received packet contains the complete VRRP
	 * packet (including fixed fields, and IPvX address(es)).
	 */
	if (buflen != expected_len) {
		log_message(LOG_INFO, "(%s) vrrp packet too %s, length %u and expect %u",
			      vrrp->iname,
			      buflen > expected_len ? "long" : "short",
			      buflen, expected_len);
		++vrrp->stats.packet_len_err;
		return VRRP_PACKET_KO;
	}

	/* MUST verify that the IPv4 TTL/IPv6 HL is 255 (but not if unicast) */

	/* MUST verify the VRRP version */
	if ((hd->vers_type >> 4) != vrrp->version) {
		log_message(LOG_INFO, "(%s) wrong version. Received %d and expect %d",
		       vrrp->iname, (hd->vers_type >> 4), vrrp->version);
		return VRRP_PACKET_KO;
	}

	if (vrrp->version == VRRP_VERSION_2) {
		/*
		 * MUST verify that the Adver Interval in the packet is the same as
		 * the locally configured for this virtual router if VRRPv2
		 */
		if (vrrp->adver_int != hd->v2.adver_int * TIMER_HZ) {
			log_message(LOG_INFO, "(%s) advertisement interval mismatch mine=%u sec rcv'd=%d sec",
				vrrp->iname, vrrp->adver_int / TIMER_HZ, hd->v2.adver_int);
			/* to prevent concurent VRID running => multiple master in 1 VRID */
			return VRRP_PACKET_DROP;
		}

	}

	/* verify packet type */
	if ((hd->vers_type & 0x0f) != VRRP_PKT_ADVERT) {
		log_message(LOG_INFO, "(%s) Invalid packet type. %d and expect %d",
			vrrp->iname, (hd->vers_type & 0x0f), VRRP_PKT_ADVERT);
		++vrrp->stats.invalid_type_rcvd;
		return VRRP_PACKET_KO;
	}

	/* Check the IP header total packet length matches what we received */
	if (vrrp->family == AF_INET && ntohs(ip->tot_len) != buflen) {
		log_message(LOG_INFO,
		       "(%s) ip_tot_len mismatch against received length. %d and received %u",
		       vrrp->iname, ntohs(ip->tot_len), buflen);
		++vrrp->stats.packet_len_err;
		return VRRP_PACKET_KO;
	}

	/* MUST verify the VRRP checksum. */
	if (vrrp->family == AF_INET) {
		vrrppkt_len = sizeof(vrrphdr_t) + hd->naddr * sizeof(struct in_addr);
		if (vrrp->version == VRRP_VERSION_2)
		{
			vrrppkt_len += VRRP_AUTH_LEN;
			csum_calc = in_csum(PTR_CAST_CONST(uint16_t, hd), vrrppkt_len, 0, &acc_csum);
			if (csum_calc) {
				log_message(LOG_INFO, "(%s) Invalid VRRPv2 checksum", vrrp->iname);
				return VRRP_PACKET_KO;
			}
		}
	}

	/* check that destination address is multicast if don't have any unicast peers
	 * and vice versa */

	/* Correct type, version, and length. Count as VRRP advertisement */
	++vrrp->stats.advert_rcvd;

	if (hd->priority == 0)
		++vrrp->stats.pri_zero_rcvd;

	return VRRP_PACKET_OK;
}

/* build IP header */
static void
vrrp_build_ip4(vrrp_t *vrrp, char *buffer)
{
	struct iphdr *ip = PTR_CAST(struct iphdr, (buffer));

	ip->ihl = sizeof(struct iphdr) >> 2;
	ip->version = 4;
	/* set tos to internet network control */
	ip->tos = 0xc0;
	/* 6 is padding fileds length */
	ip->tot_len = (uint16_t)(sizeof (struct iphdr) + vrrp_pkt_len(vrrp) + 6);
	ip->tot_len = htons(ip->tot_len);
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = vrrp->ttl;

	/* fill protocol type --rfc2402.2 */
	ip->protocol = IPPROTO_VRRP;

	ip->saddr = vrrp->saddr;
	ip->daddr = vrrp->unicast_peer;

	ip->check = 0;
}

/* build VRRPv2 header */
static void
vrrp_build_vrrp_v2(vrrp_t *vrrp, char *buffer)
{
	vrrphdr_t *hd = PTR_CAST(vrrphdr_t, buffer);
	struct in_addr *iparr;

	/* Family independant */
	hd->vers_type = (VRRP_VERSION_2 << 4) | VRRP_PKT_ADVERT;
	hd->vrid = vrrp->vrid;
	hd->priority = vrrp->effective_priority;
	hd->naddr = (uint8_t)(vrrp->vip_cnt);
	hd->v2.auth_type = VRRP_AUTH_NONE;
	hd->v2.adver_int = (uint8_t)(vrrp->adver_int / TIMER_HZ);

	/* Family specific */
	if (vrrp->family == AF_INET) {
		/* copy the ip addresses */
		iparr = PTR_CAST(struct in_addr, ((char *)hd + sizeof (*hd)));
		iparr->s_addr = vrrp->vip;	 

		/* finally compute vrrp checksum */
		hd->chksum = 0;
		hd->chksum = in_csum(PTR_CAST(uint16_t, hd), vrrp_pkt_len(vrrp), 0, NULL);
	} 
}

/* build VRRP header */
static void
vrrp_build_vrrp(vrrp_t *vrrp, char *buffer)
{
	if (vrrp->version == VRRP_VERSION_2)
		vrrp_build_vrrp_v2(vrrp, buffer);
}

/* build VRRP packet */
static void
vrrp_build_pkt(vrrp_t * vrrp)
{
	char *bufptr;

	if (vrrp->family == AF_INET) {
		/* save reference values */
		bufptr = vrrp->send_buffer;

		/* build the ip header */
		vrrp_build_ip4(vrrp, vrrp->send_buffer);

		/* build the vrrp header */
		bufptr += sizeof(struct iphdr);

		vrrp_build_vrrp(vrrp, bufptr);
	}
}

static void
vrrp_send_pkt(vrrp_t * vrrp)
{	
    struct rte_mbuf *mbuf;	
	struct iphdr *ip;
	vrrphdr_t *hd;		
	struct in_addr *iparr;
	struct iphdr *ip_mbuf;	
	vrrphdr_t *hd_mbuf;		
	struct in_addr *iparr_mbuf;
	struct mbuf_priv_data * pstMbufPrivData;
	struct netif_port *dev = (struct netif_port *)vrrp->ifp;	
	char *bufptr           = vrrp->send_buffer;
	unsigned int iSendPktNum;
	unsigned int *puiAuthData1;	
	unsigned int *puiAuthData2;
	char * padding;

	ip = PTR_CAST(struct iphdr, bufptr);

	bufptr += sizeof(struct iphdr);
	hd = PTR_CAST(vrrphdr_t, bufptr);

	bufptr += sizeof(vrrphdr_t);	
	iparr = PTR_CAST(struct in_addr, bufptr);
	
	
	/*build rte_mbuf*/	
    mbuf = rte_pktmbuf_alloc(dev->mbuf_pool);
	if (!mbuf) {
        //RTE_LOG(ERR, NEIGHBOUR, "mbuf_pool alloc failed\n");
		return;
	}	
    mbuf_userdata_set(mbuf, NULL);

	ip_mbuf = (struct iphdr *)rte_pktmbuf_append(mbuf, sizeof(*ip));	
    rte_memcpy(ip_mbuf, ip, sizeof(*ip));

	hd_mbuf = (vrrphdr_t *)rte_pktmbuf_append(mbuf, sizeof(*hd));
    rte_memcpy(hd_mbuf, hd, sizeof(*hd));

	iparr_mbuf = (struct in_addr *)rte_pktmbuf_append(mbuf, sizeof(*iparr));
    rte_memcpy(iparr_mbuf, iparr, sizeof(*iparr));

	puiAuthData1 = (unsigned int *)rte_pktmbuf_append(mbuf, sizeof(unsigned int));
    *puiAuthData1 = 0;

	puiAuthData2 = (unsigned int *)rte_pktmbuf_append(mbuf, sizeof(unsigned int));
    *puiAuthData2 = 0;

	/* ip报文最小要求46个字节，上面共封了40个字节了，还需要填充6个无效字节*/	
	padding = (char *)rte_pktmbuf_append(mbuf, 6);
	memset(padding, 0, 6);

	pstMbufPrivData = GET_MBUF_PRIV_DATA(mbuf);

	pstMbufPrivData->priv_data_vrrp_type = VRRP_TYPE_IP4;
    rte_memcpy(pstMbufPrivData->priv_data_smac, vrrp->vmac, 6);
	mbuf_dev_set(mbuf, dev);

	/* 调用入队函数 */
    iSendPktNum = vrrp_ring_send(1, (void **)&mbuf);
	if(1 != iSendPktNum)
	{
		/* 打印失败日志 */
	    ;
	}

	return;
}

/* Allocate the sending buffer */
static void
vrrp_alloc_send_buffer(vrrp_t * vrrp)
{
	vrrp->send_buffer_size = vrrp_adv_len(vrrp);

	vrrp->send_buffer = MALLOC(vrrp->send_buffer_size);
}

/* send VRRP advertisement */
void
vrrp_send_adv(vrrp_t * vrrp, uint8_t prio)
{
	/* build the packet */
	vrrp_update_pkt(vrrp, prio);

	vrrp_send_pkt(vrrp);

	++vrrp->stats.advert_sent;
}

/* Gratuitous ARP on each VIP */
static void
vrrp_send_update(vrrp_t * vrrp)
{
	send_gratuitous_arp_immediate(vrrp);

    if (vrrp->vip6_added)
	    ndisc_send_unsolicited_na_immediate(vrrp);
}

void
vrrp_send_link_update(vrrp_t * vrrp, unsigned rep)
{
	/* Only send gratuitous ARP if VIP are set */
	if (!VRRP_VIP_ISSET(vrrp))
		return;

	/* send gratuitous arp for each virtual ip */
	vrrp_send_update(vrrp);
    ++vrrp->stats.garp_sent;
}

/* becoming master */
static void
vrrp_state_become_master(vrrp_t * vrrp)
{
	union inet_addr dst_addr;
	struct netif_port *port;
	struct inet_addr_param param;
	
	++vrrp->stats.become_master;

	vrrp->vipset = true;

	dst_addr.in.s_addr = vrrp->vip;
	port = (struct netif_port *)vrrp->ifp;

	/* 给蔡专家下表项 */
	vrrp_state_refresh(VRRP_ST_MASTER);
    (void)vrrp_add_route(&dst_addr, AF_INET, 32, port);

	if((vrrp->vip6[0] != 0) || (vrrp->vip6[1] != 0) || (vrrp->vip6[2] != 0) || (vrrp->vip6[3] != 0))
	{				
		memset(&param, 0, sizeof(struct inet_addr_param));
        param.ifa_entry.af = AF_INET6;
        param.ifa_entry.plen = 0;
        memcpy(&param.ifa_entry.addr, vrrp->vip6, sizeof(param.ifa_entry.addr));
        snprintf(param.ifa_entry.ifname, sizeof(param.ifa_entry.ifname), "%s", port->name);
        route_add_ifaddr_v6(&param);

        vrrp->vip6_added = true;
	}
							   
	vrrp_send_link_update(vrrp, vrrp->garp_rep);

	/* set GARP/NA refresh timer */
	if (timerisset(&vrrp->garp_refresh))
		vrrp->garp_refresh_timer = timer_add_now(vrrp->garp_refresh);

	vrrp->last_transition = timer_now();
}

void
vrrp_state_goto_master(vrrp_t * vrrp)
{
	vrrp->state = VRRP_STATE_MAST;
	vrrp_init_instance_sands(vrrp);
	vrrp_state_master_tx(vrrp);
}

/* leaving master state */
void
vrrp_restore_interface(vrrp_t * vrrp, bool advF, bool force)
{
	/* if we stop vrrp, warn the other routers to speed up the recovery */
	if (advF) {
		vrrp_send_adv(vrrp, VRRP_PRIO_STOP);
		++vrrp->stats.pri_zero_sent;
	    #if 0
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "(%s) sent 0 priority", vrrp->iname);
		#endif
	}

	/* empty the delayed arp list */


	/*
	 * Remove the ip addresses.
	 *
	 * If started with "--dont-release-vrrp" then try to remove
	 * addresses even if we didn't add them during this run.
	 *
	 * If "--release-vips" is set then try to release any virtual addresses.
	 * kill -1 tells keepalived to reread its config.  If a config change
	 * (such as lower priority) causes a state transition to backup then
	 * keepalived doesn't remove the VIPs.  Then we have duplicate IP addresses
	 * on both master/backup.
	 */
	if (force || VRRP_VIP_ISSET(vrrp)) {
		vrrp->vipset = false;
	}
}

void
vrrp_state_leave_master(vrrp_t * vrrp, bool advF)
{
	union inet_addr dst_addr;
	struct netif_port *port;
	struct inet_addr_param param;
	
	/* set the new vrrp state */
	if (vrrp->wantstate == VRRP_STATE_BACK) {
		log_message(LOG_INFO, "(%s) Entering BACKUP STATE", vrrp->iname);
		vrrp->preempt_time.tv_sec = 0;
	}
	else {
		log_message(LOG_INFO, "(%s) vrrp_state_leave_master called with invalid wantstate %d", vrrp->iname, vrrp->wantstate);
		return;
	}

	dst_addr.in.s_addr = vrrp->vip;
	port = (struct netif_port *)vrrp->ifp;
	
    vrrp_state_refresh(VRRP_ST_SLAVE);    
    (void)vrrp_del_route(&dst_addr, AF_INET, 24, port);

    if((vrrp->vip6[0] != 0) || (vrrp->vip6[1] != 0) || (vrrp->vip6[2] != 0) || (vrrp->vip6[3] != 0))
	{				
		memset(&param, 0, sizeof(struct inet_addr_param));
        param.ifa_entry.af = AF_INET6;
        param.ifa_entry.plen = 0;
        memcpy(&param.ifa_entry.addr, vrrp->vip6, sizeof(param.ifa_entry.addr));
        snprintf(param.ifa_entry.ifname, sizeof(param.ifa_entry.ifname), "%s", port->name);
        route_del_ifaddr_v6(&param);

        vrrp->vip6_added = false;
	}
		
	
	if (VRRP_VIP_ISSET(vrrp)) {
		vrrp->vipset = false;
	}

	vrrp->state = vrrp->wantstate;

	/* Set the down timer */
	vrrp->ms_down_timer = VRRP_MS_DOWN_TIMER(vrrp);
	vrrp_init_instance_sands(vrrp);
	++vrrp->stats.release_master;
	vrrp->last_transition = timer_now();
}

/* BACKUP state processing */
void
vrrp_state_backup(vrrp_t *vrrp, const vrrphdr_t *hd, struct rte_mbuf *mbuf, uint32_t buflen)
{
	ssize_t ret = 0;
	timeval_t new_ms_down_timer;
	bool ignore_advert = false;

	/* Process the incoming packet */
	ret = vrrp_check_packet(vrrp, hd, mbuf, buflen);

	if (ret != VRRP_PACKET_OK)
		ignore_advert = true;
	else if (hd->priority == 0) {
		#if 0
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "(%s) Backup received priority 0 advertisement", vrrp->iname);
		#endif
		vrrp->ms_down_timer = VRRP_TIMER_SKEW(vrrp);
	} else if ((!vrrp->preempt) ||
		   hd->priority >= vrrp->effective_priority ||
		   (vrrp->preempt_delay &&
		    (!vrrp->preempt_time.tv_sec ||
		     timercmp(&vrrp->preempt_time, &time_now, >)))) {
		vrrp->ms_down_timer = VRRP_MS_DOWN_TIMER(vrrp);
		vrrp->master_saddr = vrrp->pkt_saddr;
		vrrp->master_priority = hd->priority;
		
		if (vrrp->preempt_delay) {
			if (hd->priority >= vrrp->effective_priority) {
				if (vrrp->preempt_time.tv_sec) {
					#if 0
					if (__test_bit(LOG_DETAIL_BIT, &debug))
						log_message(LOG_INFO,
							"(%s) stop preempt delay", vrrp->iname);
					#endif
					vrrp->preempt_time.tv_sec = 0;
				}
			} else if (!vrrp->preempt_time.tv_sec) {
			    #if 0
				if (__test_bit(LOG_DETAIL_BIT, &debug))
					log_message(LOG_INFO,
						"(%s) start preempt delay (%lu.%6.6lu)", vrrp->iname,
						vrrp->preempt_delay / TIMER_HZ, vrrp->preempt_delay % TIMER_HZ);
				#endif
				vrrp->preempt_time = timer_add_long(timer_now(), vrrp->preempt_delay);
			}
		}

		/* We might have been held in backup by a sync group, but if
		 * ms_down_timer had expired, we would have wanted MASTER state.
		 * Now we have received a backup, we want to be in BACKUP state. */
		vrrp->wantstate = VRRP_STATE_BACK;
	} else {
		/* !nopreempt and lower priority advert and any preempt delay timer has expired */
	    #if 0
		log_message(LOG_INFO, "(%s) received lower priority (%d) advert from %s - discarding", vrrp->iname, hd->priority, inet_sockaddrtos(&vrrp->pkt_saddr));
        #endif
		
		ignore_advert = true;

		/* We still want to record the master's address for SNMP purposes */
		vrrp->master_saddr = vrrp->pkt_saddr;
	}

	if (ignore_advert) {
		/* We need to reduce the down timer since we have ignored the advert */
		set_time_now();
		timersub(&vrrp->sands, &time_now, &new_ms_down_timer);
		vrrp->ms_down_timer = new_ms_down_timer.tv_sec < 0 ? 0 : (uint32_t)(new_ms_down_timer.tv_sec * TIMER_HZ + new_ms_down_timer.tv_usec);
	}
}

/* MASTER state processing */
void
vrrp_state_master_tx(vrrp_t * vrrp)
{
	/* If we are transitioning to master the old master needs to
	 * remove the VIPs before we send the gratuitous ARPs, so send
	 * the advert first.
	 */
	vrrp_send_adv(vrrp, vrrp->effective_priority);

	if (!VRRP_VIP_ISSET(vrrp)) {
		log_message(LOG_INFO, "(%s) Entering MASTER STATE"
				    , vrrp->iname);
		vrrp_state_become_master(vrrp);
	} else {
		if (timerisset(&vrrp->garp_refresh) &&
		    timercmp(&time_now, &vrrp->garp_refresh_timer, >)) {
			vrrp_send_link_update(vrrp, vrrp->garp_refresh_rep);
			vrrp->garp_refresh_timer = timer_add_now(vrrp->garp_refresh);
		}
	}
}

static int
vrrp_saddr_cmp(uint32_t	pkt_saddr, vrrp_t *vrrp)
{
	int addr_cmp;

	addr_cmp = pkt_saddr - vrrp->saddr;
	if (addr_cmp > 0)
		return 1;
	if (addr_cmp < 0)
		return -1;
	return 0;
}

// TODO Return true to leave master state, false to remain master
// TODO check all uses of master_adver_int (and simplify for VRRPv2)
// TODO check all uses of effective_priority
// TODO wantstate must be >= state
// TODO SKEW_TIME should use master_adver_int USUALLY!!!
// TODO check all use of ipsecah_counter, including cycle, and when we set seq_number
bool
vrrp_state_master_rx(vrrp_t * vrrp, const vrrphdr_t *hd, struct rte_mbuf *mbuf, uint32_t buflen)
{
	ssize_t ret;
	int addr_cmp;

	/* Process the incoming packet */
	ret = vrrp_check_packet(vrrp, hd, mbuf, buflen);

	if (ret != VRRP_PACKET_OK)
		return false;

	addr_cmp = vrrp_saddr_cmp(vrrp->pkt_saddr, vrrp);

	if (hd->priority == 0) {
		vrrp_send_adv(vrrp, vrrp->effective_priority);		
		vrrp_init_instance_sands(vrrp);

		#if 0
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "(%s) Master received priority 0 message", vrrp->iname);
		#endif
		
		return false;
	}

	if (hd->priority > vrrp->effective_priority ||
	    (hd->priority == vrrp->effective_priority && addr_cmp > 0)) {

		#if 0
		if (hd->priority > vrrp->effective_priority)
			log_message(LOG_INFO, "(%s) Master received advert from %s with higher priority %d, ours %d",
						vrrp->iname,
						inet_sockaddrtos(&vrrp->pkt_saddr),
						hd->priority,
						vrrp->effective_priority);
		else
			log_message(LOG_INFO, "(%s) Master received advert from %s with same priority %d but higher IP address than ours",
						vrrp->iname,
						inet_sockaddrtos(&vrrp->pkt_saddr),
						hd->priority);
		#endif
		
		vrrp->ms_down_timer = VRRP_MS_DOWN_TIMER(vrrp);
		vrrp->master_priority = hd->priority;
		vrrp->wantstate = VRRP_STATE_BACK;
		vrrp->state = VRRP_STATE_BACK;
		return true;
	}

	return false;
}

/* check for minimum configuration requirements */
bool
chk_min_cfg(vrrp_t *vrrp)
{
    if (!vrrp_data->enable || 
        (vrrp->vrid < VRRP_VRID_DFL) || (vrrp->vrid > VRRP_VRID_MAX) ||
        (vrrp->vip == 0) ||
        (vrrp->unicast_peer == 0) ||
        (vrrp->ifp == NULL) ||
        (vrrp->saddr == 0))
        return false;

	return true;
}

/* complete vrrp structure */
static bool
vrrp_complete_instance(vrrp_t * vrrp)
{
	vrrp->family = AF_INET;
	vrrp->version = VRRP_VERSION_2;
	vrrp->ttl = VRRP_IP_TTL;

	if (!(vrrp->vip)) {
		if (vrrp->strict_mode) {
			log_message(LOG_ERR, "(%s) No VIP specified; at least one is required"
								, vrrp->iname);
			return false;
		}
		log_message(LOG_ERR, "(%s) No VIP specified; at least one is sensible", vrrp->iname);
	}

	/* If no priority has been set, derive it from the initial state */
	if (vrrp->base_priority == 0) {
		if (vrrp->wantstate == VRRP_STATE_MAST)
			vrrp->base_priority = VRRP_PRIO_OWNER;
		else
			vrrp->base_priority = VRRP_PRIO_DFL;
	}

	/* If no initial state has been set, derive it from the priority */
	if (vrrp->wantstate == VRRP_STATE_INIT)
		vrrp->wantstate = (vrrp->base_priority == VRRP_PRIO_OWNER ? VRRP_STATE_MAST : VRRP_STATE_BACK);
	else if (vrrp->strict_mode &&
		 ((vrrp->wantstate == VRRP_STATE_MAST) != (vrrp->base_priority == VRRP_PRIO_OWNER))) {
			log_message(LOG_ERR, "(%s) State MASTER must match being address owner"
								, vrrp->iname);
			vrrp->wantstate = (vrrp->base_priority == VRRP_PRIO_OWNER ? VRRP_STATE_MAST : VRRP_STATE_BACK);
	}

	if (vrrp->base_priority == VRRP_PRIO_OWNER && !vrrp->preempt) {
		log_message(LOG_ERR, "(%s) nopreempt is incompatible with priority %d."
							  " resetting preempt"
							, vrrp->iname, VRRP_PRIO_OWNER);
		vrrp->preempt = true;
	}

	vrrp->effective_priority = vrrp->base_priority;

	if (vrrp->wantstate == VRRP_STATE_MAST) {
		if (!vrrp->preempt) {
			log_message(LOG_ERR, "(%s) Warning - nopreempt will not work"
								  " with initial state MASTER - clearing"
								, vrrp->iname);
			vrrp->preempt = true;
		}
		if (vrrp->preempt_delay) {
			log_message(LOG_ERR, "(%s) Warning - preempt delay will not work"
								  " with initial state MASTER - clearing"
								, vrrp->iname);
			vrrp->preempt_delay = false;
		}
	}
	if (vrrp->preempt_delay) {
		if (vrrp->strict_mode) {
			log_message(LOG_ERR, "(%s) preempt_delay is incompatible with"
								  " strict mode - resetting"
								, vrrp->iname);
			vrrp->preempt_delay = 0;
		}
		if (!vrrp->preempt) {
			log_message(LOG_ERR, "(%s) preempt_delay is incompatible with"
								  " nopreempt mode - resetting"
								, vrrp->iname);
			vrrp->preempt_delay = 0;
		}
	}

	if (vrrp->down_timer_adverts != VRRP_DOWN_TIMER_ADVERTS && vrrp->strict_mode) {
		log_message(LOG_ERR, "(%s) down_timer_adverts is incompatible with"
							  " strict mode - resetting"
							, vrrp->iname);
		vrrp->down_timer_adverts = VRRP_DOWN_TIMER_ADVERTS;
	}

	vrrp->state = VRRP_STATE_INIT;

	/* Check that the advertisement interval is valid */
	if (!vrrp->adver_int)
		vrrp->adver_int = VRRP_ADVER_DFL * TIMER_HZ;

	if (vrrp->adver_int >= (1<<8) * TIMER_HZ) {
		log_message(LOG_ERR, "(%s) VRRPv2 advertisement interval %.2fs"
							  " is out of range. Must be less than %ds."
							  " Setting to %ds"
							, vrrp->iname
							, vrrp->adver_int / TIMER_HZ_DOUBLE
							, 1<<8, (1<<8) - 1);
		vrrp->adver_int = ((1<<8) - 1) * TIMER_HZ;
	}
	else if (vrrp->adver_int % TIMER_HZ) {
		log_message(LOG_ERR, "(%s) VRRPv2 advertisement interval %fs"
							  " must be an integer. rounding"
							, vrrp->iname
							, vrrp->adver_int / TIMER_HZ_DOUBLE);
		vrrp->adver_int = vrrp->adver_int + (TIMER_HZ / 2);
		vrrp->adver_int -= vrrp->adver_int % TIMER_HZ;
		if (vrrp->adver_int == 0)
			vrrp->adver_int = TIMER_HZ;
	}

	vrrp->master_adver_int = vrrp->adver_int;

	/* alloc send buffer */
	vrrp_alloc_send_buffer(vrrp);
	vrrp_build_pkt(vrrp);

	return true;
}

bool
vrrp_complete_init(void)
{
	/* Make sure minimal instance configuration as been done.
       Wait util minimum configuration requirements met */
	while (!chk_min_cfg(&vrrp_data->vrrp)) {
		sleep(1);
		vrrp_sync_conf();
	}

	/* Complete VRRP instance initialization */
	vrrp_complete_instance(&vrrp_data->vrrp);

	alloc_vrrp_buffer(DEFAULT_MTU);

	return true;
}

void vrrp_restore_interfaces_startup(void)
{
	vrrp_t *vrrp = &vrrp_data->vrrp;

/* We don't know which VMACs are ours at startup. Delete all irrelevant addresses from VMACs here. But,
 * since if we configure a VMAC on a VMAC, it ends up on the underlying interface, we don't need to
 * have addresses for VMACs, accept the link local address based on the MAC of the underlying i/f. */
	if (vrrp->vipset)
		vrrp_restore_interface(vrrp, false, true);
}

