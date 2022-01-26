/*
 * Soft:        Vrrpd is an implementation of VRRPv2 as specified in rfc2338.
 *              VRRP is a protocol which elect a master server on a LAN. If the
 *              master fails, a backup server takes over.
 *              The original implementation has been made by jerome etienne.
 *
 * Part:        vrrp.c program include file.
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

#ifndef _VRRP_H
#define _VRRP_H

/* system include */
#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>

#include <rte_mbuf_core.h>


/* local include */
#include "../lib/timer.h"

struct _ip_address;

typedef struct _vrrphdr {			/* rfc2338.5.1 */
	uint8_t			vers_type;	/* 0-3=type, 4-7=version */
	uint8_t			vrid;		/* virtual router id */
	uint8_t			priority;	/* router priority */
	uint8_t			naddr;		/* address counter */
	union {
		struct {
			uint8_t	auth_type;	/* authentification type */
			uint8_t adver_int;	/* advertisement interval (in sec) */
		} v2;
		struct {
			uint16_t adver_int;	/* advertisement interval (in centi-sec (100ms)) */
		} v3;
	};
	uint16_t		chksum;		/* checksum (ip-like one) */
	/* here <naddr> ip addresses */
	/* here authentification infos */
} vrrphdr_t;

typedef struct {
	uint32_t src;
	uint32_t dst;
	uint8_t  zero;
	uint8_t  proto;
	uint16_t len;
} ipv4_phdr_t;

/* protocol constants */
#define INADDR_VRRP_GROUP	"224.0.0.18"	/* multicast IPv4 addr - rfc2338.5.2.2 */
#define INADDR6_VRRP_GROUP	"ff02::12"	/* multicast IPv6 addr - rfc5798.5.1.2.2 */
#define VRRP_IP_TTL		255		/* in and out pkt ttl -- rfc2338.5.2.3 */
#define IPPROTO_VRRP		112		/* IP protocol number -- rfc2338.5.2.4 */
#define VRRP_VERSION_2		2		/* VRRP version 2 -- rfc2338.5.3.1 */
#define VRRP_VERSION_3		3		/* VRRP version 3 -- rfc5798.5.2.1 */
#define VRRP_PKT_ADVERT		1		/* packet type -- rfc2338.5.3.2 */
#define VRRP_PRIO_OWNER		255		/* priority of the ip owner -- rfc2338.5.3.4 */
#define VRRP_PRIO_DFL		100		/* default priority -- rfc2338.5.3.4 */
#define VRRP_PRIO_STOP		0		/* priority to stop -- rfc2338.5.3.4 */
#define VRRP_MAX_ADDR		0xFF		/* count addr field is 8 bits wide */
#define VRRP_AUTH_NONE		0		/* no authentification -- rfc2338.5.3.6 */
#define VRRP_ADVER_DFL		1		/* advert. interval (in sec) -- rfc2338.5.3.7 */
#define VRRP_DOWN_TIMER_ADVERTS 3		/* number of adverts to miss before master down -- rfc5798.6.1 & rfc3768.6.1 */
#define VRRP_GARP_DELAY	(5 * TIMER_HZ)	/* Default delay to launch gratuitous arp */
#define VRRP_GARP_REP		5		/* Default repeat value for MASTER state gratuitous arp */
#define VRRP_GARP_REFRESH	0		/* Default interval for refresh gratuitous arp (0 = none) */
#define VRRP_GARP_REFRESH_REP	1	/* Default repeat value for refresh gratuitous arp */
#define VRRP_VRID_DFL	    1		/* Default vrid */
#define VRRP_VRID_MAX	    255

/* Statistics */
typedef struct _vrrp_stats {
	uint64_t	advert_rcvd;
	uint32_t	advert_sent;
	uint32_t	garp_sent;

	uint32_t	become_master;
	uint32_t	release_master;

	uint64_t	packet_len_err;
	uint64_t	advert_interval_err;
	uint64_t	ip_ttl_err;
	uint64_t	invalid_type_rcvd;
	uint64_t	addr_list_err;

	uint32_t	invalid_authtype;

	uint64_t	pri_zero_rcvd;
	uint64_t	pri_zero_sent;
} vrrp_stats;

/* parameters per virtual router -- rfc2338.6.1.2 */
typedef struct _vrrp_t {
	sa_family_t		family;			/* AF_INET|AF_INET6 */
	char		    iname[32];		/* Instance Name */
	vrrp_stats		stats;			/* Statistics */
	void		    *ifp;			/* Interface we belong to */
	bool			skip_check_adv_addr;	/* If set, don't check the VIPs in subsequent
							 * adverts from the same master */
	bool		    strict_mode;		/* Enforces strict VRRP compliance */
	uint32_t	    saddr;			    /* Src IP address to use in VRRP IP header */
	uint32_t	    pkt_saddr;		    /* Src IP address received in VRRP IP header */
	int			    rx_ttl_hop_limit;	/* Received TTL/hop limit returned */
	uint32_t		unicast_peer;		/* The peer to send unicast advert to */
	int			    ttl;			    /* TTL to send packet with if unicasting */
	bool			check_unicast_src;	/* It set, check the source address of a unicast advert */
	uint32_t        master_saddr;		/* Store last heard Master address */
	uint8_t			master_priority;	/* Store last heard priority */
	timeval_t		last_transition;	/* Store transition time */
	unsigned		garp_delay;		    /* Delay to launch gratuitous ARP */
	timeval_t		garp_refresh;		/* Next scheduled gratuitous ARP refresh */
	timeval_t		garp_refresh_timer;	/* Next scheduled gratuitous ARP timer */
	unsigned		garp_rep;		    /* gratuitous ARP repeat value */
	unsigned		garp_refresh_rep;	/* refresh gratuitous ARP repeat value */
	unsigned		garp_lower_prio_delay;	/* Delay to second set or ARP messages */
	bool			garp_pending;		/* Are there gratuitous ARP messages still to be sent */
	bool			gna_pending;		/* Are there gratuitous NA messages still to be sent */
	unsigned		garp_lower_prio_rep;	/* Number of ARP messages to send at a time */
	unsigned		down_timer_adverts;	/* Number of adverts missed before backup takes over as master */
	unsigned		lower_prio_no_advert;	/* Don't send advert after lower prio advert received */
	unsigned		higher_prio_send_advert; /* Send advert after higher prio advert received */
	uint8_t			vrid;			    /* virtual id. from 1(!) to 255 */
	uint8_t			base_priority;		/* configured priority value */
	uint8_t			effective_priority;	/* effective priority value */
	bool			vipset;			/* All the vips are set ? */
	uint32_t		vip;			/* virtual ip address */
	unsigned		vip_cnt;		/* Number of vip's */
	uint32_t		vip6[4];		/* virtual ip6 address */
	bool            vip6_added;     /* virtual ip6 address added to the forwarding table */
	unsigned		adver_int;		/* Seconds*TIMER_HZ, locally configured delay between advertisements*/
	unsigned		master_adver_int;	/* In v3, when we become BACKUP, we use the MASTER's
							 * adver_int. If we become MASTER again, we use the
							 * value we were originally configured with.
							 * In v2, this will always be the configured adver_int.
							 */
	bool			preempt;		/* true if higher prio preempts lower */
	unsigned long	preempt_delay;		/* Seconds*TIMER_HZ after startup until
							 * preemption based on higher prio over lower
							 * prio is allowed.  0 means no delay.
							 */
	timeval_t		preempt_time;		/* Time after which preemption can happen */
	int			state;			/* internal state (init/backup/master/fault) */
	int			wantstate;		/* user explicitly wants a state (back/mast) */

	int			debug;			/* Debug level 0-4 */

	int			version;		/* VRRP version (2 or 3) */

	/* rfc2338.6.2 */
	uint32_t		ms_down_timer;
	timeval_t		sands;

	/* Sending buffer */
	char			*send_buffer;		/* Allocated send buffer */
	size_t			send_buffer_size;
	uint32_t		ipv4_csum;		/* Checksum ip IPv4 pseudo header for VRRPv3 */

	/*
	 * To have my own ip_id creates collision with kernel ip->id
	 * but it should be ok because the packets are unlikely to be
	 * fragmented (they are non routable and small)
	 * This packet isnt routed, i can check the outgoing MTU
	 * to warn the user only if the outoing mtu is too small
	 */
	int			ip_id;
	uint8_t     vmac[6];    /* Virtual Router MAC Address, 00-00-5E-00-01-{VRID} */
} vrrp_t;

/* VRRP state machine -- rfc2338.6.4 */
#define VRRP_STATE_INIT			0	/* rfc2338.6.4.1 */
#define VRRP_STATE_BACK			1	/* rfc2338.6.4.2 */
#define VRRP_STATE_MAST			2	/* rfc2338.6.4.3 */
#define VRRP_STATE_FAULT		3	/* internal */
#define VRRP_STATE_DELETED		97	/* internal */
#define VRRP_STATE_STOP			98	/* internal */
#define VRRP_EVENT_MASTER_RX_LOWER_PRI	1000	/* Dummy state for sending event notify */
#define VRRP_EVENT_MASTER_PRIORITY_CHANGE 1001	/* Dummy state for sending event notify */
#define VRRP_EVENT_BACKUP_PRIORITY_CHANGE 1002	/* Dummy state for sending event notify */

/* VRRP packet handling */
#define VRRP_PACKET_OK       0
#define VRRP_PACKET_KO       1
#define VRRP_PACKET_DROP     2
#define VRRP_PACKET_NULL     3
#define VRRP_PACKET_OTHER    4	/* Multiple VRRP on LAN, Identify "other" VRRP */

/* VRRP Packet fixed length */
#define VRRP_AUTH_LEN		8
#define VRRP_VIP_TYPE		(1 << 0)
#define VRRP_EVIP_TYPE		(1 << 1)

/* We have to do some reduction of the calculation for VRRPv3 in order not to overflow a uint32; 625 / 16 == TIMER_CENTI_HZ / 256 */
#define VRRP_TIMER_SKEW_CALC(svr, pri_val) ((svr)->version == VRRP_VERSION_3 ? (((pri_val) * ((svr)->master_adver_int / TIMER_CENTI_HZ) * 625U) / 16U) : ((pri_val) * TIMER_HZ/256U))
#define VRRP_TIMER_SKEW(svr)		VRRP_TIMER_SKEW_CALC(svr, 256U - (svr)->effective_priority)
#define VRRP_TIMER_SKEW_MIN(svr)	VRRP_TIMER_SKEW_CALC(svr, 1)
#define VRRP_MS_DOWN_TIMER(XX)		((XX)->down_timer_adverts * (XX)->master_adver_int + VRRP_TIMER_SKEW(XX))

#define VRRP_VIP_ISSET(V)	((V)->vipset)

#define VRRP_MIN(a, b)	((a) < (b)?(a):(b))
#define VRRP_MAX(a, b)	((a) > (b)?(a):(b))

#define VRRP_CONFIGURED_IFP(V)	((V)->ifp)

#define VRRP_PKT_SADDR(V) (((V)->saddr.ss_family) ? ((struct sockaddr_in *) &(V)->saddr)->sin_addr.s_addr : IF_ADDR(VRRP_CONFIGURED_IFP(V)))

#define VRRP_ISUP(V)		(!(V)->num_script_if_fault)


/* prototypes */
extern size_t vrrp_adv_len(const vrrp_t *) __attribute__ ((pure));
extern const vrrphdr_t *vrrp_get_header(struct rte_mbuf *mbuf, uint32_t len);
extern void vrrp_send_adv(vrrp_t *, uint8_t);
extern void vrrp_send_link_update(vrrp_t *, unsigned);
extern bool vrrp_state_master_rx(vrrp_t * vrrp, const vrrphdr_t *hd, struct rte_mbuf *mbuf, uint32_t buflen);
extern void vrrp_state_master_tx(vrrp_t *);
extern void vrrp_state_backup(vrrp_t *vrrp, const vrrphdr_t *hd, struct rte_mbuf *mbuf, uint32_t buflen);
extern void vrrp_state_goto_master(vrrp_t *);
extern void vrrp_state_leave_master(vrrp_t *, bool);
extern bool vrrp_complete_init(void);
extern void vrrp_restore_interfaces_startup(void);
extern void vrrp_restore_interface(vrrp_t *, bool, bool);
extern bool chk_min_cfg(vrrp_t *vrrp);
extern size_t vrrp_pkt_len(const vrrp_t *vrrp);
extern void vrrp_state_refresh(uint8_t status);

#endif
