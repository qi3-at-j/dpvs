#ifndef __ASPF_POLICY_CONF_H__
#define __ASPF_POLICY_CONF_H__

#include <inttypes.h>

#include <rte_memory.h>
#include <rte_rwlock.h>

#include "list.h"

#define  ASPF_DETECT_FTP         0x0000000000000001
#define  ASPF_DETECT_HTTP        0x0000000000000002
#define  ASPF_DETECT_DNS         0x0000000000000004
#define  ASPF_DETECT_SIP         0x0000000000000008
#define  ASPF_DETECT_TFTP        0x0000000000000010


#define ASPF_DETECT_ALL (ASPF_DETECT_FTP | ASPF_DETECT_HTTP | \
                         ASPF_DETECT_DNS | ASPF_DETECT_SIP | \
                         ASPF_DETECT_TFTP)

typedef struct _aspf_policy_conf_ {
    uint64_t  detect;
    uint32_t  tcp_syn_check;
} __rte_cache_aligned aspf_policy_conf_s;


extern int aspf_policy_conf_init(uint32_t vrf);
extern int aspf_policy_conf_term(uint32_t vrf);

extern void aspf_policy_keyword_value_init(void);
extern void install_aspf_policy_keywords(void);


extern int aspf_policy_detect_modify(uint32_t vrf, uint32_t insert, uint64_t protocol);
extern int aspf_policy_tcpsyn_check_modify(uint32_t vrf, uint32_t enable);

#endif
