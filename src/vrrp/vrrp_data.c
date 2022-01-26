/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Dynamic data structure definition.
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

#include <unistd.h>
#include <time.h>
#include <sys/eventfd.h>

#include "netif.h"
#include "parser/utils.h"
#include "parser/parser.h"
#include "parser/flow_cmdline.h"
#include "vrrp.h"
#include "../lib/logger.h"
#include "../lib/scheduler.h"
#include "vrrp_data.h"
#include "vrrp_send_priv.h"

/* global vars */
vrrp_data_t vrrp_data_global;
vrrp_data_t *vrrp_data = &vrrp_data_global;
void *vrrp_buffer;
size_t vrrp_buffer_len;
vrrp_conf_chg_t vrrp_conf_chg;

extern struct vrrp_entry g_vrrp_entry_ipv4;
extern struct vrrp_entry g_vrrp_entry_ipv6;

static const char *
get_state_str(int state)
{
	if (state == VRRP_STATE_INIT) return "INIT";
	if (state == VRRP_STATE_BACK) return "BACKUP";
	if (state == VRRP_STATE_MAST) return "MASTER";
	if (state == VRRP_STATE_FAULT) return "FAULT";
	return "unknown";
}

void
show_vrrp_stats_proc(void *cmdline, bool clear_stats)
{
	vrrp_t *vrrp = &vrrp_data->vrrp;
	struct cmdline *cl = (struct cmdline *)cmdline;

    if (clear_stats) {
        memset(&vrrp->stats, 0, sizeof(vrrp->stats));
        return;
    }
            
	tyflow_cmdline_printf(cl, "VRRP Instance:              %s\n", vrrp->iname);
	tyflow_cmdline_printf(cl, "  Advertisements:\n");
	tyflow_cmdline_printf(cl, "    Received:               %" PRIu64 "\n", vrrp->stats.advert_rcvd);
	tyflow_cmdline_printf(cl, "    Sent:                   %u\n", vrrp->stats.advert_sent);
	tyflow_cmdline_printf(cl, "  Gratuitous ARP Sent:      %u\n", vrrp->stats.garp_sent);
	tyflow_cmdline_printf(cl, "  Became master:            %u\n", vrrp->stats.become_master);
	tyflow_cmdline_printf(cl, "  Released master:          %u\n", vrrp->stats.release_master);
	tyflow_cmdline_printf(cl, "  Packet Errors:\n");
	tyflow_cmdline_printf(cl, "    Length:                 %" PRIu64 "\n", vrrp->stats.packet_len_err);
	tyflow_cmdline_printf(cl, "    TTL:                    %" PRIu64 "\n", vrrp->stats.ip_ttl_err);
	tyflow_cmdline_printf(cl, "    Invalid Type:           %" PRIu64 "\n", vrrp->stats.invalid_type_rcvd);
	tyflow_cmdline_printf(cl, "    Advertisement Interval: %" PRIu64 "\n", vrrp->stats.advert_interval_err);
	tyflow_cmdline_printf(cl, "    Address List:           %" PRIu64 "\n", vrrp->stats.addr_list_err);
	tyflow_cmdline_printf(cl, "  Authentication Errors:\n");
	tyflow_cmdline_printf(cl, "    Invalid Type:           %u\n",	vrrp->stats.invalid_authtype);
	tyflow_cmdline_printf(cl, "  Priority Zero:\n");
	tyflow_cmdline_printf(cl, "    Received:               %" PRIu64 "\n", vrrp->stats.pri_zero_rcvd);
	tyflow_cmdline_printf(cl, "    Sent:                   %" PRIu64 "\n", vrrp->stats.pri_zero_sent);

    return;
}

void
show_vrrp_proc(void *cmdline)
{
    struct cmdline *cl = (struct cmdline *)cmdline;
    const vrrp_t *vrrp = &vrrp_data->vrrp;
	struct netif_port* pstNetif = (struct netif_port *)(vrrp->ifp);
	char time_str[26];
	char ipv6_str[INET6_ADDRSTRLEN];

	tyflow_cmdline_printf(cl, " VRRP Instance:        %s (%s)\n", vrrp->iname, vrrp_data->enable ? "Enabled" : "Disabled!!!");
    if (vrrp->strict_mode)
            tyflow_cmdline_printf(cl, "   Enforcing strict VRRP compliance\n");
	tyflow_cmdline_printf(cl, "   VRRP Version:       %d\n", vrrp->version);
	tyflow_cmdline_printf(cl, "   State:              %s\n", get_state_str(vrrp->state));
	if (vrrp->state == VRRP_STATE_BACK) {
        strlcpy(ipv6_str, "-", sizeof(ipv6_str));
        inet_ntop(AF_INET, &vrrp->master_saddr, ipv6_str, sizeof(ipv6_str));
		tyflow_cmdline_printf(cl, "   Master router:      %s\n", ipv6_str);
		tyflow_cmdline_printf(cl, "   Master priority:    %d\n", vrrp->master_priority);
	}
	tyflow_cmdline_printf(cl, "   Wantstate:          %s\n", get_state_str(vrrp->wantstate));
	ctime_r(&vrrp->last_transition.tv_sec, time_str);
	tyflow_cmdline_printf(cl, "   Last transition:    %ld.%6.6ld (%.24s.%6.6ld)\n", vrrp->last_transition.tv_sec, vrrp->last_transition.tv_usec, time_str, vrrp->last_transition.tv_usec);
	if (!ctime_r(&vrrp->sands.tv_sec, time_str))
		strcpy(time_str, "invalid time ");
	if (vrrp->sands.tv_sec == TIMER_DISABLED)
		tyflow_cmdline_printf(cl, "   Read timeout:       DISABLED\n");
	else
		tyflow_cmdline_printf(cl, "   Read timeout:       %ld.%6.6ld (%.19s.%6.6ld)\n", vrrp->sands.tv_sec, vrrp->sands.tv_usec, time_str, vrrp->sands.tv_usec);
	tyflow_cmdline_printf(cl, "   Master down timer:  %u usecs\n", vrrp->ms_down_timer);
	tyflow_cmdline_printf(cl, "   Interface:          %s\n", vrrp->ifp ? (pstNetif->name) : "not configured");
	if (vrrp->skip_check_adv_addr)
		tyflow_cmdline_printf(cl, "   Skip checking advert IP addresses\n");
    tyflow_cmdline_printf(cl, "   Virtual Router ID:  %d\n", vrrp->vrid);
	tyflow_cmdline_printf(cl, "   Priority:           %d\n", vrrp->base_priority);
	tyflow_cmdline_printf(cl, "   Effective priority: %d\n", vrrp->effective_priority);
	tyflow_cmdline_printf(cl, "   Advert interval:    %u sec\n", vrrp->adver_int / TIMER_HZ);
	tyflow_cmdline_printf(cl, "   Down timer adverts: %u\n", vrrp->down_timer_adverts);
	tyflow_cmdline_printf(cl, "   Preempt:            %s\n", vrrp->preempt ? "enabled" : "disabled");
    if (vrrp->preempt_delay)
	    tyflow_cmdline_printf(cl, "   Preempt delay:      %g secs\n", vrrp->preempt_delay / TIMER_HZ_DOUBLE);
    strlcpy(ipv6_str, "-", sizeof(ipv6_str));
    inet_ntop(AF_INET6, &vrrp->vip6, ipv6_str, sizeof(ipv6_str));
    tyflow_cmdline_printf(cl, "   Virtual IPv6 :      %s\n", ipv6_str);
    strlcpy(ipv6_str, "-", sizeof(ipv6_str));
    inet_ntop(AF_INET, &vrrp->vip, ipv6_str, sizeof(ipv6_str));
    tyflow_cmdline_printf(cl, "   Virtual IP :        %s\n", ipv6_str);
    strlcpy(ipv6_str, "-", sizeof(ipv6_str));
    inet_ntop(AF_INET, &vrrp->unicast_peer, ipv6_str, sizeof(ipv6_str));
    tyflow_cmdline_printf(cl, "   Unicast Peer:       %s\n", ipv6_str);
    strlcpy(ipv6_str, "-", sizeof(ipv6_str));
    inet_ntop(AF_INET, &vrrp->saddr, ipv6_str, sizeof(ipv6_str));
	tyflow_cmdline_printf(cl, "   Using src_ip:       %s\n", ipv6_str);
	tyflow_cmdline_printf(cl, "   Unicast TTL:        %d\n", vrrp->ttl);
	tyflow_cmdline_printf(cl, "   Check unicast src:  %s\n\n", vrrp->check_unicast_src ? "yes" : "no");

	tyflow_cmdline_printf(cl, "   Gratuitous ARP delay:                             %u\n", vrrp->garp_delay/TIMER_HZ);
	tyflow_cmdline_printf(cl, "   Gratuitous ARP repeat:                            %u\n", vrrp->garp_rep);
	tyflow_cmdline_printf(cl, "   Gratuitous ARP refresh:                           %ld secs\n", vrrp->garp_refresh.tv_sec);
	tyflow_cmdline_printf(cl, "   Gratuitous ARP refresh repeat:                    %u\n", vrrp->garp_refresh_rep);
    if (vrrp->garp_lower_prio_delay == PARAMETER_UNSET)
        tyflow_cmdline_printf(cl, "   Gratuitous ARP lower priority delay:              unset\n");
    else
	    tyflow_cmdline_printf(cl, "   Gratuitous ARP lower priority delay:              %u\n", vrrp->garp_lower_prio_delay / TIMER_HZ);
    if (vrrp->garp_lower_prio_delay == PARAMETER_UNSET)
        tyflow_cmdline_printf(cl, "   Gratuitous ARP lower priority repeat:             unset\n");
    else
	    tyflow_cmdline_printf(cl, "   Gratuitous ARP lower priority repeat:             %u\n", vrrp->garp_lower_prio_rep);
	
	tyflow_cmdline_printf(cl, "   Send advert after receive lower priority advert:  %s\n", vrrp->lower_prio_no_advert ? "false" : "true");
	tyflow_cmdline_printf(cl, "   Send advert after receive higher priority advert: %s\n\n", vrrp->higher_prio_send_advert ? "true" : "false");

	tyflow_cmdline_printf(cl, "   Forwarding entry:\n");
    strlcpy(ipv6_str, "-", sizeof(ipv6_str));
    inet_ntop(AF_INET, &g_vrrp_entry_ipv4.addr.in, ipv6_str, sizeof(ipv6_str));
    tyflow_cmdline_printf(cl, "     Addr:   %s\n", ipv6_str);
    if (vrrp->vip6_added) {
        strlcpy(ipv6_str, "-", sizeof(ipv6_str));
        inet_ntop(AF_INET6, &g_vrrp_entry_ipv6.addr.in6, ipv6_str, sizeof(ipv6_str));
        tyflow_cmdline_printf(cl, "     Addr6:  %s\n", ipv6_str);
    }
    tyflow_cmdline_printf(cl, "     MAC:    %02x-%02x-%02x-%02x-%02x-%02x\n", 
        g_vrrp_entry_ipv4.mac[0], g_vrrp_entry_ipv4.mac[1], g_vrrp_entry_ipv4.mac[2], 
        g_vrrp_entry_ipv4.mac[3], g_vrrp_entry_ipv4.mac[4], g_vrrp_entry_ipv4.mac[5]);
    tyflow_cmdline_printf(cl, "     Port:   %s\n", g_vrrp_entry_ipv4.port ? g_vrrp_entry_ipv4.port->name : "NULL");
    tyflow_cmdline_printf(cl, "     Status: %s\n", get_state_str(g_vrrp_entry_ipv4.status));

    return;
}

/* data facility functions */
void
alloc_vrrp_buffer(size_t len)
{
	if (len <= vrrp_buffer_len)
		return;

	if (vrrp_buffer)
		FREE(vrrp_buffer);

	vrrp_buffer = MALLOC(len);
	vrrp_buffer_len = (vrrp_buffer) ? len : 0;
}

/* Set default values, MUST be called before reading the configuration file */
void
init_vrrp_data(void)
{
	vrrp_t *vrrp = &vrrp_data->vrrp;

#ifdef ENABLE_LOG_TO_FILE
    if (log_file_name) {
        open_log_file(log_file_name, "vrrp", NULL, NULL);
        set_flush_log_file();
    }
#endif

    memset(vrrp_data, 0, sizeof(*vrrp_data));
    memset(&vrrp_conf_chg, 0, sizeof(vrrp_conf_chg));
    rte_rwlock_init(&vrrp_conf_chg.rwlock);

    vrrp_data->thread = NULL;
    vrrp_data->garp_interval = 0;
    vrrp_data->gna_interval = 0;
    vrrp_data->vrrp_startup_delay = 0;
    vrrp_data->fd_cfg_chg = eventfd(0, 0);
    if (vrrp_data->fd_cfg_chg == -1)
    {
        log_message(LOG_ERR, "%s: failed to create eventfd.", __func__);
    }

    vrrp_conf_chg.enable = vrrp_data->enable = true;
    vrrp_conf_chg.ifp = vrrp->ifp = NULL;
    vrrp_conf_chg.vrid = vrrp->vrid = VRRP_VRID_DFL;
    vrrp_conf_chg.vip = vrrp->vip = 0;
	vrrp_conf_chg.unicast_peer = vrrp->unicast_peer = 0;
	vrrp_conf_chg.adver_int = vrrp->adver_int = VRRP_ADVER_DFL * TIMER_HZ;
	vrrp_conf_chg.preempt = vrrp->preempt = true;
	vrrp_conf_chg.preempt_delay = vrrp->preempt_delay = 0;
	vrrp_conf_chg.base_priority = vrrp->effective_priority = vrrp->base_priority = 0;

    vrrp->family = AF_INET;
	vrrp->saddr = 0;
	vrrp->wantstate = VRRP_STATE_INIT;
	vrrp->version = VRRP_VERSION_2;
	vrrp->master_priority = 0;
	strncpy(vrrp->iname, "vrrp_default", sizeof(vrrp->iname) - 1);
	vrrp->ttl = VRRP_IP_TTL;
	vrrp->garp_rep = VRRP_GARP_REP;
	vrrp->garp_refresh_rep = VRRP_GARP_REFRESH_REP;
	vrrp->garp_delay = VRRP_GARP_DELAY;
	vrrp->garp_lower_prio_delay = PARAMETER_UNSET;
	vrrp->garp_lower_prio_rep = PARAMETER_UNSET;
	vrrp->down_timer_adverts = VRRP_DOWN_TIMER_ADVERTS;
	vrrp->lower_prio_no_advert = PARAMETER_UNSET;
	vrrp->higher_prio_send_advert = PARAMETER_UNSET;
	vrrp->skip_check_adv_addr = false;
	vrrp->strict_mode = true;
	vrrp->vmac[0] = 0x00;
	vrrp->vmac[1] = 0x00;
	vrrp->vmac[2] = 0x5E;
	vrrp->vmac[3] = 0x00;
	vrrp->vmac[4] = 0x01;
	vrrp->vmac[5] = 0x01;
	vrrp->vip_cnt = 1;
    vrrp->garp_refresh.tv_sec = 10;
    vrrp->vip6_added = false;

    g_vrrp_entry_ipv4.family = AF_INET;
    memcpy(g_vrrp_entry_ipv4.mac, vrrp->vmac, sizeof(g_vrrp_entry_ipv4.mac));
    g_vrrp_entry_ipv6.family = AF_INET6;
    memcpy(g_vrrp_entry_ipv6.mac, vrrp->vmac, sizeof(g_vrrp_entry_ipv6.mac));
    vrrp_state_refresh(VRRP_STATE_INIT);

	return;
}

