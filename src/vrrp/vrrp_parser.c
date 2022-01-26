/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Configuration file parser/reader. Place into the dynamic
 *              data structure representation the conf file representing
 *              the loadbalanced server pool.
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
#include <string.h>
#include <stdint.h>
#include <net/if_arp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <ctype.h>
#include <net/if.h>
#include <netinet/ip.h>

#include "netif.h"
#include "parser/vector.h"
#include "parser/parser.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "vrrp_parser.h"
#include "../lib/logger.h"
#include "../lib/scheduler.h"
#include "vrrp.h"
#include "vrrp_data.h"
#include "vrrp_scheduler.h"
#include "vrrp_send_priv.h"
#include "conf/inetaddr.h"
#include "route_cli_priv.h"
#include "route6_priv.h"


extern struct inet_device *dev_get_idev(const struct netif_port *dev);
extern vrrp_conf_chg_t vrrp_conf_chg;
extern struct vrrp_entry g_vrrp_entry_ipv4;
extern struct vrrp_entry g_vrrp_entry_ipv6;


static bool
local_router_is_addr_owner(uint32_t addr, struct netif_port *port)
{
    struct inet_ifaddr *ifa;
    struct inet_device *idev;
    bool ret = false;

    if (unlikely(port == NULL))
        return false;

    idev = dev_get_idev(port);
    if (unlikely(idev == NULL))
        return false;

    list_for_each_entry(ifa, &idev->ifa_list[0], d_list) {
        if ((ifa->af == AF_INET) && (ifa->addr.in.s_addr == addr)) {
            ret = true;
            break;
        }
    }

    /* Increased when calling dev_get_idev() */
    rte_atomic32_dec(&idev->refcnt);

    return ret;
}

/* Update v4 route */
static void
vrrp_update_v4_route(uint32_t vip, struct netif_port *ifp)
{
    vrrp_t *vrrp = &vrrp_data->vrrp;
    uint32_t old_vip = vrrp->vip;
    struct netif_port *old_ifp = (struct netif_port *)vrrp->ifp;
    int res;
    char ipv4_str[INET_ADDRSTRLEN];

    /* Delete old v4 route */
    if ((old_vip != 0) && (old_ifp != NULL) && !local_router_is_addr_owner(old_vip, old_ifp)) {
        res = vrrp_del_route((union inet_addr *)&old_vip, AF_INET, 32, old_ifp);
        if (res != 0) {
            strlcpy(ipv4_str, "-", sizeof(ipv4_str));
            inet_ntop(AF_INET, &old_vip, ipv4_str, sizeof(ipv4_str));
            log_message(LOG_INFO, "%s: Error calling vrrp_del_route(), res=%d, vip=%s, if_name=%s", 
                __func__, res, ipv4_str, old_ifp->name);
        }
    }

    /* Add new v4 route */
    if ((vip != 0) && (ifp != NULL) && !local_router_is_addr_owner(vip, ifp)) {
        res = vrrp_add_route((union inet_addr *)&vip, AF_INET, 32, ifp);
        if (res != 0) {
            strlcpy(ipv4_str, "-", sizeof(ipv4_str));
            inet_ntop(AF_INET, &vip, ipv4_str, sizeof(ipv4_str));
            log_message(LOG_INFO, "%s: Error calling vrrp_add_route(), res=%d, vip=%s, if_name=%s", 
                __func__, res, ipv4_str, ifp->name);
        }
    }

    return;
}

/* Update v6 route */
static void
vrrp_update_v6_route(uint32_t *vip6, struct netif_port *ifp, bool mod_addr)
{
    vrrp_t *vrrp = &vrrp_data->vrrp;
    uint32_t *old_vip6 = vrrp->vip6;
    struct netif_port *old_ifp = (struct netif_port *)vrrp->ifp;
    int res;
    struct inet_addr_param param;
    char ipv6_str[INET6_ADDRSTRLEN];

    /* Delete old v6 route */
    if (((old_vip6[0] != 0) || (old_vip6[1] != 0) || (old_vip6[2] != 0) || (old_vip6[3] != 0)) && 
        (old_ifp != NULL)) {
        if (mod_addr) {
            res = inet_addr_del(AF_INET6, old_ifp, (union inet_addr *)old_vip6, 0);
            if (res != 0) {
                strlcpy(ipv6_str, "-", sizeof(ipv6_str));
                inet_ntop(AF_INET6, old_vip6, ipv6_str, sizeof(ipv6_str));
                log_message(LOG_INFO, "%s: Error calling inet_addr_del(), res=%d, vip6=%s, if_name=%s", 
                    __func__, res, ipv6_str, old_ifp->name);
            }
        }

        memset(&param, 0, sizeof(struct inet_addr_param));
        param.ifa_entry.af = AF_INET6;
        param.ifa_entry.plen = 0;
        memcpy(&param.ifa_entry.addr, old_vip6, sizeof(param.ifa_entry.addr));
        snprintf(param.ifa_entry.ifname, sizeof(param.ifa_entry.ifname), "%s", old_ifp->name);
        route_del_ifaddr_v6(&param);

        vrrp->vip6_added = false;
    }

    /* Add new v6 route */
    if ((vip6 != NULL) &&
        ((vip6[0] != 0) || (vip6[1] != 0) || (vip6[2] != 0) || (vip6[3] != 0)) && 
        (ifp != NULL)) {
        if (mod_addr) {
            res = inet_addr_add(AF_INET6, ifp, (union inet_addr *)vip6, 0, NULL, 0, 0, IFA_SCOPE_GLOBAL, 0);
            if (res != 0) {
                strlcpy(ipv6_str, "-", sizeof(ipv6_str));
                inet_ntop(AF_INET6, vip6, ipv6_str, sizeof(ipv6_str));
                log_message(LOG_INFO, "%s: Error calling inet_addr_add(), res=%d, vip6=%s, if_name=%s", 
                    __func__, res, ipv6_str, ifp->name);
            }
        }

        memset(&param, 0, sizeof(struct inet_addr_param));
        param.ifa_entry.af = AF_INET6;
        param.ifa_entry.plen = 0;
        memcpy(&param.ifa_entry.addr, vip6, sizeof(param.ifa_entry.addr));
        snprintf(param.ifa_entry.ifname, sizeof(param.ifa_entry.ifname), "%s", ifp->name);
        route_add_ifaddr_v6(&param);

        vrrp->vip6_added = true;
    }

    return;
}

static uint32_t
vrrp_get_intf_primary_addr(void)
{
    vrrp_t *vrrp = &vrrp_data->vrrp;
    struct inet_ifaddr *ifa;
    struct inet_device *idev;
    uint32_t ret = 0;
    struct netif_port *port = (struct netif_port *)vrrp->ifp;

    if (unlikely(port == NULL))
        return ret;

    idev = dev_get_idev(port);
    if (unlikely(idev == NULL))
        return ret;

    list_for_each_entry(ifa, &idev->ifa_list[0], d_list) {
        if (ifa->af == AF_INET) {
            ret = ifa->addr.in.s_addr;
            break;
        }
    }

    /* Increased when calling dev_get_idev() */
    rte_atomic32_dec(&idev->refcnt);

    return ret;
}

static void
vrrp_notify_config_chg(void)
{
    uint64_t u = 20;
    ssize_t s;

    if (vrrp_data->fd_cfg_chg != -1) {
        s = write(vrrp_data->fd_cfg_chg, &u, sizeof(uint64_t));
        if (s != sizeof(uint64_t))
            log_message(LOG_ERR, "%s: failed to write to eventfd %d, res=%zd.", __func__, vrrp_data->fd_cfg_chg, s);
    }

    return;
}

static void
vrrp_update_vrrphdr(void)
{
    vrrphdr_t *hd;
    struct in_addr *iparr;
    vrrp_t *vrrp = &vrrp_data->vrrp;

    if (!chk_min_cfg(vrrp))
        return;

    if (NULL == vrrp->send_buffer)
        return;

    hd = (vrrphdr_t *)(vrrp->send_buffer + sizeof(struct iphdr));
    
    if (hd->vrid != vrrp->vrid)
	    hd->vrid = vrrp->vrid;
	    
    if (hd->priority != vrrp->effective_priority)
	    hd->priority = vrrp->effective_priority;
	    
    if (hd->v2.adver_int != (uint8_t)(vrrp->adver_int / TIMER_HZ))
	    hd->v2.adver_int = (uint8_t)(vrrp->adver_int / TIMER_HZ);

	iparr = PTR_CAST(struct in_addr, ((char *)hd + sizeof (*hd)));
    if (iparr->s_addr != vrrp->vip)
	    iparr->s_addr = vrrp->vip;

    /* Compute vrrp checksum */
	hd->chksum = 0;
	hd->chksum = in_csum(PTR_CAST(uint16_t, hd), vrrp_pkt_len(vrrp), 0, NULL);

    return;
}

static void
vrrp_update_unicast_peer(uint32_t peer)
{
    rte_rwlock_write_lock(&vrrp_conf_chg.rwlock);
    if (vrrp_conf_chg.unicast_peer != peer) {
        vrrp_conf_chg.unicast_peer = peer;
        vrrp_conf_chg.changed = true;
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);
        vrrp_notify_config_chg();
    } else
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);
    
    return;
}

static void
vrrp_update_vrid(uint32_t vrid)
{
    if ((vrid < VRRP_VRID_DFL) || (vrid > VRRP_VRID_MAX))
        RTE_LOG(INFO, CFG_FILE, "%s: Invalid vrid %u\n", __func__, vrid);

    rte_rwlock_write_lock(&vrrp_conf_chg.rwlock);
    if (vrrp_conf_chg.vrid != vrid) {
        vrrp_conf_chg.vrid = vrid;
        vrrp_conf_chg.changed = true;
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);
        vrrp_notify_config_chg();
    } else
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);

    return;
}

static void
vrrp_update_prio(uint32_t prio)
{
    if ((prio == VRRP_PRIO_STOP) || (prio >= VRRP_PRIO_OWNER))
        RTE_LOG(INFO, CFG_FILE, "%s: Invalid priority %u\n", __func__, prio);

    rte_rwlock_write_lock(&vrrp_conf_chg.rwlock);
    if (vrrp_conf_chg.base_priority != prio) {
        vrrp_conf_chg.base_priority = prio;
        vrrp_conf_chg.changed = true;
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);
        vrrp_notify_config_chg();
    } else
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);

    return;
}

static void
vrrp_update_adv(uint32_t adv)
{
    if ((adv == 0) || (adv > 41))
        RTE_LOG(INFO, CFG_FILE, "%s: Invalid advert interval %u\n", __func__, adv);

    rte_rwlock_write_lock(&vrrp_conf_chg.rwlock);
    if (vrrp_conf_chg.adver_int != adv * TIMER_HZ) {
        vrrp_conf_chg.adver_int = adv * TIMER_HZ;
        vrrp_conf_chg.changed = true;
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);
        vrrp_notify_config_chg();
    } else
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);

    return;
}

static void
vrrp_update_preempt(bool preempt)
{
    rte_rwlock_write_lock(&vrrp_conf_chg.rwlock);
    if (vrrp_conf_chg.preempt != preempt) {
        vrrp_conf_chg.preempt = preempt;
        vrrp_conf_chg.changed = true;
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);
        vrrp_notify_config_chg();
    } else
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);

    return;
}

static void
vrrp_update_preempt_delay(uint32_t preempt_delay)
{
    rte_rwlock_write_lock(&vrrp_conf_chg.rwlock);
    if (vrrp_conf_chg.preempt_delay != preempt_delay * TIMER_HZ) {
        vrrp_conf_chg.preempt_delay = preempt_delay * TIMER_HZ;
        vrrp_conf_chg.changed = true;
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);
        vrrp_notify_config_chg();
    } else
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);

    return;
}

static void
vrrp_update_vip(uint32_t vip)
{
    rte_rwlock_write_lock(&vrrp_conf_chg.rwlock);
    if (vrrp_conf_chg.vip != vip) {
        vrrp_conf_chg.vip = vip;
        vrrp_conf_chg.changed = true;
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);
        vrrp_update_v4_route(vip, (struct netif_port *)vrrp_conf_chg.ifp);
        vrrp_notify_config_chg();
    } else
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);

    return;
}

static void
vrrp_update_vip6(const char *str)
{
    uint32_t vip6[4];
    int res;

    if (str) {
        res = inet_pton(AF_INET6, str, vip6);
        if (!res)
            return;
    } else {
        vip6[0] = 0;
        vip6[1] = 0;
        vip6[2] = 0;
        vip6[3] = 0;
    }

    rte_rwlock_write_lock(&vrrp_conf_chg.rwlock);
    if ((vrrp_conf_chg.vip6[0] != vip6[0]) || (vrrp_conf_chg.vip6[1] != vip6[1]) ||
        (vrrp_conf_chg.vip6[2] != vip6[2]) || (vrrp_conf_chg.vip6[3] != vip6[3])) {
        vrrp_conf_chg.vip6[0] = vip6[0];
        vrrp_conf_chg.vip6[1] = vip6[1];
        vrrp_conf_chg.vip6[2] = vip6[2];
        vrrp_conf_chg.vip6[3] = vip6[3];
        vrrp_conf_chg.changed = true;
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);
        vrrp_update_v6_route(vip6, (struct netif_port *)vrrp_conf_chg.ifp, true);
        vrrp_notify_config_chg();
    } else
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);

    return;
}

static void
vrrp_update_enable(bool enable)
{
    rte_rwlock_write_lock(&vrrp_conf_chg.rwlock);
    if (vrrp_conf_chg.enable != enable) {
        vrrp_conf_chg.enable = enable;
        vrrp_conf_chg.changed = true;
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);
        vrrp_notify_config_chg();
    } else
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);

    return;
}

static void
vrrp_update_int(const char *name)
{
    void *ifp = NULL;

    if (name != NULL) {
        ifp = netif_port_get_by_name(name);
    	if (NULL == ifp) {
            RTE_LOG(ERR, CFG_FILE, "%s: Interface %s doesn't exist\n", __func__, name);
            return;
    	}
    }

    rte_rwlock_write_lock(&vrrp_conf_chg.rwlock);
    if (vrrp_conf_chg.ifp != ifp) {
        vrrp_conf_chg.ifp = ifp;
        vrrp_conf_chg.changed = true;
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);
        vrrp_update_v4_route(vrrp_conf_chg.vip, (struct netif_port *)ifp);
        vrrp_update_v6_route(vrrp_conf_chg.vip6, (struct netif_port *)ifp, true);
        vrrp_notify_config_chg();
    } else
        rte_rwlock_write_unlock(&vrrp_conf_chg.rwlock);

    return;
}

static void
vrrp_unicast_peer_handler(vector_t tokens)
{
    int res;
    uint32_t peer;
	char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);
    res = inet_pton(AF_INET, str, &peer);
    if (!res)
        RTE_LOG(INFO, CFG_FILE, "%s: Invalid ip address %s\n", __func__, str);
    else
        vrrp_update_unicast_peer(peer);

    FREE_PTR(str);

    return;
}

static void
vrrp_vrid_handler(vector_t tokens)
{
	char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);
    vrrp_update_vrid(atoi(str));

    FREE_PTR(str);

    return;
}

static void
vrrp_prio_handler(vector_t tokens)
{
	char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);
    vrrp_update_prio(atoi(str));

    FREE_PTR(str);

    return;
}

static void
vrrp_adv_handler(vector_t tokens)
{
	char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);
    vrrp_update_adv(atoi(str));

    FREE_PTR(str);

    return;
}

static void
vrrp_preempt_handler(vector_t tokens)
{
	char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);
    if (0 == strncmp(str, "enable", strlen("enable"))) {
        vrrp_update_preempt(true);
    } else {
        vrrp_update_preempt(false);
        vrrp_update_preempt_delay(0);
    }

    FREE_PTR(str);

    return;
}

static void
vrrp_preempt_delay_handler(vector_t tokens)
{
	char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);
    vrrp_update_preempt_delay(atoi(str));

    FREE_PTR(str);

    return;
}

static void
vrrp_vip_handler(vector_t tokens)
{
    int res;
	char *str = set_value(tokens);
	uint32_t vip;

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);
    res = inet_pton(AF_INET, str, &vip);
    if (!res)
        RTE_LOG(INFO, CFG_FILE, "%s: Invalid ip address %s\n", __func__, str);
    else
        vrrp_update_vip(vip);

    FREE_PTR(str);

    return;
}

static void
vrrp_vip6_handler(vector_t tokens)
{
	char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);
    vrrp_update_vip6(str);

    FREE_PTR(str);

    return;
}

static void
vrrp_enable_handler(vector_t tokens)
{
	char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);
    vrrp_update_enable(0 == strncmp(str, "enable", strlen("enable")));

    FREE_PTR(str);

    return;
}

static void
vrrp_int_handler(vector_t tokens)
{
	char *str = set_value(tokens);

	RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);
	vrrp_update_int(str);

	FREE_PTR(str);

    return;
}

void
vrrp_init_keywords(void)
{
    install_keyword_root("vrrp_cfg", NULL);
    install_keyword("vrrp_enable", vrrp_enable_handler, KW_TYPE_NORMAL);
	install_keyword("vrrp_interface", vrrp_int_handler, KW_TYPE_NORMAL);
	install_keyword("vrrp_unicast_peer", vrrp_unicast_peer_handler, KW_TYPE_NORMAL);
	install_keyword("vrrp_virtual_router_id", vrrp_vrid_handler, KW_TYPE_NORMAL);
	install_keyword("vrrp_priority", vrrp_prio_handler, KW_TYPE_NORMAL);
	install_keyword("vrrp_advert_int", vrrp_adv_handler, KW_TYPE_NORMAL);
	install_keyword("vrrp_virtual_ipaddress", vrrp_vip_handler, KW_TYPE_NORMAL);
	install_keyword("vrrp_virtual_ipv6", vrrp_vip6_handler, KW_TYPE_NORMAL);
	install_keyword("vrrp_preempt", vrrp_preempt_handler, KW_TYPE_NORMAL);
	install_keyword("vrrp_preempt_delay", vrrp_preempt_delay_handler, KW_TYPE_NORMAL);
#if 0
    install_keyword("vrrp_down_timer_adverts", vrrp_down_timer_adverts_handler, KW_TYPE_NORMAL);
    install_keyword("state", vrrp_state_handler, KW_TYPE_NORMAL);
	install_keyword("check_unicast_src", vrrp_check_unicast_src_handler, KW_TYPE_NORMAL);
	install_keyword("unicast_ttl", vrrp_ttl_handler, KW_TYPE_NORMAL);
	install_keyword("version", vrrp_version_handler, KW_TYPE_NORMAL);
	install_keyword("skip_check_adv_addr", vrrp_skip_check_adv_addr_handler, KW_TYPE_NORMAL);
	install_keyword("strict_mode", vrrp_strict_mode_handler, KW_TYPE_NORMAL);
	install_keyword("debug", vrrp_debug_handler, KW_TYPE_NORMAL);
	install_keyword("garp_master_delay", vrrp_garp_delay_handler, KW_TYPE_NORMAL);
	install_keyword("garp_master_refresh", vrrp_garp_refresh_handler, KW_TYPE_NORMAL);
	install_keyword("garp_master_repeat", vrrp_garp_rep_handler, KW_TYPE_NORMAL);
	install_keyword("garp_master_refresh_repeat", vrrp_garp_refresh_rep_handler, KW_TYPE_NORMAL);
	install_keyword("garp_lower_prio_delay", vrrp_garp_lower_prio_delay_handler, KW_TYPE_NORMAL);
	install_keyword("garp_lower_prio_repeat", vrrp_garp_lower_prio_rep_handler, KW_TYPE_NORMAL);
	install_keyword("lower_prio_no_advert", vrrp_lower_prio_no_advert_handler, KW_TYPE_NORMAL);
	install_keyword("higher_prio_send_advert", vrrp_higher_prio_send_advert_handler, KW_TYPE_NORMAL);
#endif

	return;
}

static void 
vrrp_enable_proc(void)
{
    vrrp_t *vrrp = &vrrp_data->vrrp;

    if (!vrrp_initialised)
        return;

    /* Start vrrp */
    if (chk_min_cfg(vrrp) && (vrrp->state == VRRP_STATE_INIT)) {
        vrrp->wantstate = (vrrp->base_priority == VRRP_PRIO_OWNER ? VRRP_STATE_MAST : VRRP_STATE_BACK);
        /* Init the VRRP instances state */
        vrrp_init_state(vrrp);
        /* Init VRRP instances sands */
        vrrp_init_sands(vrrp);

        log_message(LOG_INFO, "%s: Start vrrp", __func__);
    }

    /* Stop vrrp */
    if (!chk_min_cfg(vrrp) && (vrrp->state != VRRP_STATE_INIT)) {
        vrrp->state = vrrp->wantstate = VRRP_STATE_INIT;
        /* Init VRRP instances sands */
        vrrp_init_sands(vrrp);
        /* Calculate and set wait timer. Take care of timeouted fd. */
    	thread_set_timer(master);
    	/* Update forwarding entry */
    	vrrp_state_refresh(VRRP_STATE_INIT);
    	/* Set interface state */
        vrrp_restore_interface(vrrp, false, false);
        /* Delete v4/v6 route of vip */
        vrrp_update_v4_route(0, NULL);
        vrrp_update_v6_route(NULL, NULL, false);

    	log_message(LOG_INFO, "%s: Stop vrrp", __func__);
    }

    return;
}

/* Synchronize configuration changes from vrrp_conf_chg to vrrp_data */
void
vrrp_sync_conf(void)
{
    vrrp_t *vrrp = &vrrp_data->vrrp;
    bool update_vrrphdr = false;
    uint8_t old_priority = vrrp->effective_priority;

    rte_rwlock_read_lock(&vrrp_conf_chg.rwlock);
    if (vrrp_conf_chg.changed) {
        vrrp_conf_chg.changed = false;

        if (vrrp_data->enable != vrrp_conf_chg.enable)
            vrrp_data->enable  = vrrp_conf_chg.enable;

        if (vrrp->unicast_peer != vrrp_conf_chg.unicast_peer)
            vrrp->unicast_peer = vrrp_conf_chg.unicast_peer;

        if (vrrp->vrid != vrrp_conf_chg.vrid) {
            vrrp->vrid = vrrp_conf_chg.vrid;
            vrrp->vmac[5] = vrrp->vrid;
        	g_vrrp_entry_ipv4.mac[5] = vrrp->vrid;
        	g_vrrp_entry_ipv6.mac[5] = vrrp->vrid;
            update_vrrphdr = true;
        }

        if ((vrrp_conf_chg.base_priority != 0) && (vrrp->base_priority != vrrp_conf_chg.base_priority)) {
            vrrp->effective_priority = vrrp->base_priority = vrrp_conf_chg.base_priority;
            vrrp_conf_chg.base_priority = 0;
            update_vrrphdr = true;
        }

        if (vrrp->adver_int != vrrp_conf_chg.adver_int)
            vrrp->adver_int = vrrp_conf_chg.adver_int;
            update_vrrphdr = true;

        if (vrrp->preempt != vrrp_conf_chg.preempt)
            vrrp->preempt = vrrp_conf_chg.preempt;

        if (vrrp->preempt_delay != vrrp_conf_chg.preempt_delay)
            vrrp->preempt_delay = vrrp_conf_chg.preempt_delay;

        if (vrrp->vip != vrrp_conf_chg.vip) {
            g_vrrp_entry_ipv4.addr.in.s_addr = vrrp->vip = vrrp_conf_chg.vip;
            update_vrrphdr = true;
        }

        if ((vrrp->vip6[0] != vrrp_conf_chg.vip6[0]) || (vrrp->vip6[1] != vrrp_conf_chg.vip6[1]) ||
            (vrrp->vip6[2] != vrrp_conf_chg.vip6[2]) || (vrrp->vip6[3] != vrrp_conf_chg.vip6[3])) {
            memcpy(vrrp->vip6, vrrp_conf_chg.vip6, sizeof(vrrp->vip6));			
			memcpy(&g_vrrp_entry_ipv6.addr.in6, vrrp_conf_chg.vip6, sizeof(struct in6_addr));
        }

        if (vrrp->ifp != vrrp_conf_chg.ifp) {
            g_vrrp_entry_ipv6.port = g_vrrp_entry_ipv4.port = vrrp->ifp = vrrp_conf_chg.ifp;
        }
    }
    rte_rwlock_read_unlock(&vrrp_conf_chg.rwlock);

    /* Update interface primary addr */
    vrrp->saddr = vrrp_get_intf_primary_addr();

    /* Update effective priority based on whether local is vip owner or not */
    if (local_router_is_addr_owner(vrrp->vip, (struct netif_port *)vrrp->ifp)) {
        if (vrrp->effective_priority != VRRP_PRIO_OWNER) {
            vrrp->effective_priority = vrrp->base_priority = VRRP_PRIO_OWNER;
            log_message(LOG_INFO, "%s: Local router is vip owner, changing priority from %d to %d.", 
                __func__, old_priority, vrrp->effective_priority);
            update_vrrphdr = true;
        }
    }
    else if (VRRP_PRIO_OWNER == vrrp->effective_priority) {
        vrrp->effective_priority = vrrp->base_priority = VRRP_PRIO_DFL;
        log_message(LOG_INFO, "%s: Local router is NOT vip owner, changing priority from %d to %d.", 
                __func__, old_priority, vrrp->effective_priority);
        update_vrrphdr = true;
    }

    if (update_vrrphdr)
        vrrp_update_vrrphdr();

    vrrp_enable_proc();

    return;
}

/*
set   vrrp < enable | disable >
unset vrrp enable
set   vrrp vrid <virtual-router-id>
unset vrrp vrid
set   vrrp unicast-peer <x.x.x.x>
unset vrrp unicast-peer
set   vrrp interface <dpdk0>
unset vrrp interface
set   vrrp virtual-ip <x.x.x.x>
unset vrrp virtual-ip
set   vrrp priority <priority-value>
unset vrrp priority
set   vrrp preempt-mode [ delay <delay-value> ]
unset vrrp preempt-mode
set   vrrp timer advertise <adver-interval>
unset vrrp timer advertise
*/
typedef enum __vrrp_cli_which__ {
    vrrp_which_enable = 1,
    vrrp_which_disable,
    vrrp_which_vip,
    vrrp_which_vip6,
    vrrp_which_vrid,
    vrrp_which_uc_peer,
    vrrp_which_if,
    vrrp_which_pri,
    vrrp_which_preempt,
    vrrp_which_preempt_delay,
    vrrp_which_timer,
    vrrp_which_advert_interval,
    vrrp_which_show_vrrp,
    vrrp_which_show_vrrp_stats,
    vrrp_which_clear_vrrp_stats,
    vrrp_which_show_ring

} VRRP_CLI_WHICH_E;

typedef enum __vrrp_cli_numid__ {
    vrrp_numid_vrid = 0,
    vrrp_numid_pri,
    vrrp_numid_preempt_delay,
    vrrp_numid_advert_interval,

} VRRP_CLI_NUMID_E;

typedef enum __vrrp_cli_ipv4id__ {
    vrrp_ipv4id_vip = 0,
    vrrp_ipv4id_uc_peer,

} VRRP_CLI_IPV4ID_E;

typedef enum __vrrp_cli_strid__ {
    vrrp_strid_if = 0,
    vrrp_strid_vip6,

} VRRP_CLI_STRID_E;

extern void vrrp_ring_show(char *);

static int vrrp_cli_proc(cmd_blk_t *cbt)
{	
    switch (cbt->which[0]) {
        case vrrp_which_enable:
            vrrp_update_enable(true);
            break;
        case vrrp_which_disable:
            vrrp_update_enable(false);
            break;
        case vrrp_which_vrid:
            vrrp_update_vrid((MODE_DO == cbt->mode) ? cbt->number[vrrp_numid_vrid] : VRRP_VRID_DFL);
            break;
        case vrrp_which_vip:
            vrrp_update_vip(htonl((MODE_DO == cbt->mode) ? cbt->ipv4[vrrp_ipv4id_vip] : 0));
            break;
        case vrrp_which_vip6:
            vrrp_update_vip6((MODE_DO == cbt->mode) ? cbt->string[vrrp_strid_vip6] : NULL);
            break;
        case vrrp_which_uc_peer:
            vrrp_update_unicast_peer(htonl((MODE_DO == cbt->mode) ? cbt->ipv4[vrrp_ipv4id_uc_peer] : 0));
            break;
        case vrrp_which_if:
            vrrp_update_int((MODE_DO == cbt->mode) ? cbt->string[vrrp_strid_if] : NULL);
            break;
        case vrrp_which_pri:
            vrrp_update_prio((MODE_DO == cbt->mode) ? cbt->number[vrrp_numid_pri] : VRRP_PRIO_DFL);
            break;
        case vrrp_which_preempt:
            if (MODE_DO == cbt->mode) {
                vrrp_update_preempt(true);
            } else {
                vrrp_update_preempt(false);
                vrrp_update_preempt_delay(0);
            }
            break;
        case vrrp_which_preempt_delay:
            vrrp_update_preempt(true);
            vrrp_update_preempt_delay(cbt->number[vrrp_numid_preempt_delay]);
            break;
        case vrrp_which_advert_interval:
            vrrp_update_adv((MODE_DO == cbt->mode) ? cbt->number[vrrp_numid_advert_interval] : VRRP_ADVER_DFL);
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "\tunknown command!\n");
    }

    return 0;
}

static int vrrp_cli_show_proc(cmd_blk_t *cbt)
{	
    switch (cbt->which[0]) {
        case vrrp_which_show_vrrp:
            show_vrrp_proc(cbt->cl);
            break;
        case vrrp_which_show_vrrp_stats:
            show_vrrp_stats_proc(cbt->cl, false);
            break;
        case vrrp_which_clear_vrrp_stats:
            show_vrrp_stats_proc(cbt->cl, true);
            break;
        case vrrp_which_show_ring:
            vrrp_ring_show(NULL);
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "\tunknown command!\n");
    }

    return 0;
}

EOL_NODE_NEED_MAIN_EXEC(vrrp_eol, vrrp_cli_proc);
EOL_NODE(vrrp_show_eol, vrrp_cli_show_proc);

/* used in unset */
/* unset vrrp timer [ advertise ] */
KW_NODE_WHICH(unset_vrrp_timer_advert, vrrp_eol, none, "advertise", "advertise interval", 1, vrrp_which_advert_interval);
KW_NODE(unset_vrrp_timer, unset_vrrp_timer_advert, none, "timer", "timer");
/* unset vrrp preempt-mode */
KW_NODE_WHICH(unset_vrrp_preempt, vrrp_eol, unset_vrrp_timer, "preempt-mode", "preempt mode", 1, vrrp_which_preempt);
/* unset vrrp priority */
KW_NODE_WHICH(unset_vrrp_pri, vrrp_eol, unset_vrrp_preempt, "priority", "priority", 1, vrrp_which_pri);
/* unset vrrp interface */
KW_NODE_WHICH(unset_vrrp_if, vrrp_eol, unset_vrrp_pri, "interface", "interface bound by the vrrp instance", 1, vrrp_which_if);
/* unset vrrp unicast-peer */
KW_NODE_WHICH(unset_vrrp_uc_peer, vrrp_eol, unset_vrrp_if, "unicast-peer", "unicast peer", 1, vrrp_which_uc_peer);
/* unset vrrp virtual-ipv6 */
KW_NODE_WHICH(unset_vrrp_vip6, vrrp_eol, unset_vrrp_uc_peer, "virtual-ipv6", "virtual ipv6 address", 1, vrrp_which_vip6);
/* unset vrrp virtual-ip */
KW_NODE_WHICH(unset_vrrp_vip, vrrp_eol, unset_vrrp_vip6, "virtual-ip", "virtual ip address", 1, vrrp_which_vip);
/* unset vrrp vrid */
KW_NODE_WHICH(unset_vrrp_vrid, vrrp_eol, unset_vrrp_vip, "vrid", "virtual router id", 1, vrrp_which_vrid);
/* unset vrrp enable */
KW_NODE_WHICH(unset_vrrp_enable, vrrp_eol, unset_vrrp_vrid, "enable", "disable vrrp globally", 1, vrrp_which_disable);

/* used in set */
/* set vrrp timer advertise <adver-interval> */
VALUE_NODE(vrrp_timer_advert_val, vrrp_eol, none, "advertise interval in seconds: <1..41>", vrrp_numid_advert_interval+1, NUM);
KW_NODE_WHICH(vrrp_timer_advert, vrrp_timer_advert_val, none, "advertise", "advertise interval", 1, vrrp_which_advert_interval);
KW_NODE(vrrp_timer, vrrp_timer_advert, none, "timer", "timer");
/* set vrrp preempt-mode [ delay <delay-value> ] */
VALUE_NODE(vrrp_preempt_delay_val, vrrp_eol, none, "preempt delay in seconds: <0..1000>", vrrp_numid_preempt_delay+1, NUM);
KW_NODE_WHICH(vrrp_preempt_delay, vrrp_preempt_delay_val, vrrp_eol, "delay", "preempt delay", 1, vrrp_which_preempt_delay);
KW_NODE_WHICH(vrrp_preempt, vrrp_preempt_delay, vrrp_timer, "preempt-mode", "preempt mode", 1, vrrp_which_preempt);
/* set vrrp priority <1..254> */
VALUE_NODE(vrrp_pri_val, vrrp_eol, none, "priority: <1..254>", vrrp_numid_pri+1, NUM);
KW_NODE_WHICH(vrrp_pri, vrrp_pri_val, vrrp_preempt, "priority", "priority", 1, vrrp_which_pri);
/* set vrrp interface <dpdk0> */
VALUE_NODE(vrrp_if_val, vrrp_eol, none, "interface name: dpdk0 dpdk1", vrrp_strid_if+1, STR);
KW_NODE_WHICH(vrrp_if, vrrp_if_val, vrrp_pri, "interface", "interface bound by this vrrp instance", 1, vrrp_which_if);
/* set vrrp unicast-peer <x.x.x.x> */
VALUE_NODE(vrrp_uc_peer_val, vrrp_eol, none, "ipv4 address: x.x.x.x", vrrp_ipv4id_uc_peer+1, IPV4);
KW_NODE_WHICH(vrrp_uc_peer, vrrp_uc_peer_val, vrrp_if, "unicast-peer", "unicast peer", 1, vrrp_which_uc_peer);
/* set vrrp virtual-ipv6 <x::x> */
VALUE_NODE(vrrp_vip6_val, vrrp_eol, none, "ipv6 address: x::x", vrrp_strid_vip6+1, STR);
KW_NODE_WHICH(vrrp_vip6, vrrp_vip6_val, vrrp_uc_peer, "virtual-ipv6", "virtual ipv6 address", 1, vrrp_which_vip6);
/* set vrrp virtual-ip <x.x.x.x> */
VALUE_NODE(vrrp_vip_val, vrrp_eol, none, "ipv4 address: x.x.x.x", vrrp_ipv4id_vip+1, IPV4);
KW_NODE_WHICH(vrrp_vip, vrrp_vip_val, vrrp_vip6, "virtual-ip", "virtual ip address", 1, vrrp_which_vip);
/* set vrrp vrid <virtual-router-id> */
VALUE_NODE(vrrp_vrid_val, vrrp_eol, none, "virtual router id: <1..255>", vrrp_numid_vrid+1, NUM);
KW_NODE_WHICH(vrrp_vrid, vrrp_vrid_val, vrrp_vip, "vrid", "virtual router id", 1, vrrp_which_vrid); 
/* set vrrp < enable | disable > */
KW_NODE_WHICH(vrrp_disable, vrrp_eol, vrrp_vrid, "disable", "disable vrrp globally", 1, vrrp_which_disable);
KW_NODE_WHICH(vrrp_enable, vrrp_eol, vrrp_disable, "enable", "enable vrrp globally (default)", 1, vrrp_which_enable);

TEST_UNSET(test_unset_vrrp, unset_vrrp_enable, vrrp_enable);
KW_NODE(vrrp, test_unset_vrrp, none, "vrrp", "vrrp related configurations");

/* show vrrp rings */
KW_NODE_WHICH(show_vrrp_ring, vrrp_show_eol, vrrp_show_eol, "rings", "show vrrp rings", 1, vrrp_which_show_ring);
/* show vrrp statistics */
KW_NODE_WHICH(show_vrrp_stats, vrrp_show_eol, show_vrrp_ring, "statistics", "show vrrp statistics", 1, vrrp_which_show_vrrp_stats);
/* show vrrp */
KW_NODE_WHICH(show_vrrp, show_vrrp_stats, none, "vrrp", "show vrrp data", 1, vrrp_which_show_vrrp);

/* show vrrp statistics */
KW_NODE_WHICH(clear_vrrp_stats, vrrp_show_eol, vrrp_show_eol, "statistics", "clear vrrp statistics", 1, vrrp_which_clear_vrrp_stats);
/* clear vrrp */
KW_NODE(clear_vrrp, clear_vrrp_stats, none, "vrrp", "clear vrrp statistics");


int
vrrp_cli_init(void)
{
    add_set_cmd(&cnode(vrrp));
    add_get_cmd(&cnode(show_vrrp));
    add_clear_cmd(&cnode(clear_vrrp));

    return 0;
}

