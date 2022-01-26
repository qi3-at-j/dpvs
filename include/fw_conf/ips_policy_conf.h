#ifndef __IPS_POLICY_CONF_H__
#define __IPS_POLICY_CONF_H__

#include <inttypes.h>
#include <netinet/in.h>

#include <rte_memory.h>
#include <rte_rwlock.h>

#include "list.h"

#define IPS_SOCKET_FILE "/run/suricata/suricata-command.socket"

extern void ips_policy_keyword_value_init(void);
extern void install_ips_policy_keywords(void);

extern int ips_policy_conf_init(uint32_t vrf);
extern int ips_policy_conf_term(uint32_t vrf);

extern int ips_policy_set_action(uint32_t vrf, uint32_t rule_id, char *action);
extern int ips_policy_get_action(uint32_t vrf, uint32_t rule_id);
extern int dpi_set_mode(uint32_t vrf, char *mode);
extern int dpi_get_mode(uint32_t vrf);
extern int dpi_set_vpatch_switch(uint32_t vrf, char *vpatch);
extern int dpi_get_vpatch_switch(uint32_t vrf);
extern int dpi_set_trace_switch(uint32_t module, uint32_t trace_switch);
extern int dpi_get_trace_switch(void);
#endif

