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

//typedef struct _security_policy_conf_ {
//    struct list_head head_in;
//    rte_rwlock_t rwlock_in;
//
//    struct list_head head_out;
//    rte_rwlock_t rwlock_out;
//    struct rte_mempool *mp;
//} __rte_cache_aligned security_policy_conf_s;

extern void security_policy_keyword_value_init(void);
extern void install_security_policy_keywords(void);

#endif
