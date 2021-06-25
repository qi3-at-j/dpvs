#ifndef __SECURITY_POLICY_CONF_H__
#define __SECURITY_POLICY_CONF_H__

#include <inttypes.h>
#include <netinet/in.h>

#include <rte_memory.h>
#include <rte_rwlock.h>

#include "list.h"


#define SECPOLICY_MOVE_BEFORE   1
#define SECPOLICY_MOVE_AFTER    0
/*
   rules xx2 {
   status disable
   action drop
   service udp
   dst_ip6 [::]/128
   src_ip6 [::]/64
   dst_port 80-100
   src_port 1000
   }

 */

typedef struct _secpolicy_ipaddr_ {
	uint8_t family;
	union {
		struct in_addr  ip4;
		struct in6_addr ip6;
	} addr;
	unsigned int prefixlen;
}cidr_st;

typedef struct _secpolicy_rule_ {
    struct list_head list;
    uint32_t  id;
    uint32_t  status;
    uint32_t  action;
    uint32_t  service;
    cidr_st   dst_ip;
    cidr_st   dst_ip6;
    cidr_st   src_ip;
    cidr_st   src_ip6;
    uint32_t  dst_min_port;
    uint32_t  dst_max_port;
    uint32_t  src_min_port;
    uint32_t  src_max_port;
} __rte_cache_aligned secpolicy_rule_s;

typedef struct _security_policy_conf_ {
    struct list_head head_in;
    rte_rwlock_t rwlock_in;

    struct list_head head_out;
    rte_rwlock_t rwlock_out;
    struct rte_mempool *mp;
} __rte_cache_aligned security_policy_conf_s;

extern int security_policy_rule_modify_status(uint32_t vrf, uint32_t inbound, uint32_t id, uint32_t status);
extern int security_policy_rule_modify_action(uint32_t vrf, uint32_t inbound, uint32_t id, uint32_t action);
extern int security_policy_rule_modify_service(uint32_t vrf, uint32_t inbound, uint32_t id, uint32_t service);
extern int security_policy_rule_modify_dst_ip(uint32_t vrf, uint32_t inbound, uint32_t id, cidr_st *dst_ip);
extern int security_policy_rule_modify_src_ip(uint32_t vrf, uint32_t inbound, uint32_t id, cidr_st *src_ip);
extern int security_policy_rule_modify_dst_ip6(uint32_t vrf, uint32_t inbound, uint32_t id, cidr_st *dst_ip6);
extern int security_policy_rule_modify_src_ip6(uint32_t vrf, uint32_t inbound, uint32_t id, cidr_st *src_ip6);
extern int security_policy_rule_modify_dst_port(uint32_t vrf, uint32_t inbound, uint32_t id, uint32_t port_min, uint32_t port_max);
extern int security_policy_rule_modify_src_port(uint32_t vrf, uint32_t inbound, uint32_t id, uint32_t port_min, uint32_t port_max);


extern void security_policy_keyword_value_init(void);
extern void install_security_policy_keywords(void);

extern int security_policy_conf_init(uint32_t vrf);
extern int security_policy_conf_term(uint32_t vrf);
extern security_policy_conf_s *security_policy_conf_get(uint32_t vrf);

extern int security_policy_rule_create(uint32_t vrf, uint32_t inbound, uint32_t id);
extern int security_policy_rule_delete(uint32_t vrf, uint32_t inbound, uint32_t id);
extern int security_policy_rule_is_exist(uint32_t vrf, uint32_t inbound, uint32_t id);
extern int security_policy_rule_modify(uint32_t vrf, uint32_t inbound, secpolicy_rule_s *rule);
extern int security_policy_rule_get(uint32_t vrf, uint32_t inbound, uint32_t id, secpolicy_rule_s *rule);
extern int security_policy_rule_move(uint32_t vrf, uint32_t inbound, uint32_t id, uint32_t base_id, uint32_t action);


static inline int security_policy_read_lock(uint32_t vrf, uint32_t inbound)
{
    if (inbound) {
        rte_rwlock_read_lock(&security_policy_conf_get(vrf)->rwlock_in);
    } else {
        rte_rwlock_read_lock(&security_policy_conf_get(vrf)->rwlock_out);
    }
    return 0;
}

static inline int security_policy_read_unlock(uint32_t vrf, uint32_t inbound)
{
    if (inbound) {
        rte_rwlock_read_unlock(&security_policy_conf_get(vrf)->rwlock_in);
    } else {
        rte_rwlock_read_unlock(&security_policy_conf_get(vrf)->rwlock_out);
    }
    return 0;
}

static inline int security_policy_write_lock(uint32_t vrf, uint32_t inbound)
{
    if (inbound) {
        rte_rwlock_write_lock(&security_policy_conf_get(vrf)->rwlock_in);
    } else {
        rte_rwlock_write_lock(&security_policy_conf_get(vrf)->rwlock_out);
    }
    return 0;
}

static inline int security_policy_write_unlock(uint32_t vrf, uint32_t inbound)
{
    if (inbound) {
        rte_rwlock_write_unlock(&security_policy_conf_get(vrf)->rwlock_in);
    } else {
        rte_rwlock_write_unlock(&security_policy_conf_get(vrf)->rwlock_out);
    }
    return 0;
}

#endif
