#ifndef __FW_CONF_H__
#define __FW_CONF_H__
/* standard */
#include <inttypes.h>
#include <limits.h>

/* dpdk */
#include <rte_memory.h>
#include <rte_atomic.h>
#include <rte_rwlock.h>

/* internal */
//#include "list.h"
#include "fw_conf/session_conf.h"
#include "fw_conf/security_policy_conf.h"
#include "fw_conf/aspf_policy_conf.h"

#define FW_VRF_MAX_SIZE  64
#define FW_VRF_INVALID   UINT_MAX

typedef enum _fw_status_ {
    fw_status_stop = 0,
    fw_status_running,
} fw_status_e;

typedef struct _fw_vrf_conf_ {
    fw_status_e status;
    security_policy_conf_s secpolicy_conf;
    aspf_policy_conf_s aspf_conf;
} __rte_cache_aligned fw_vrf_conf_s;

typedef struct _vfw_conf_ {
    /* global config */
    session_conf_s session_conf;
    rte_atomic32_t running_cnt; /* vrf cnt */

    /* vrf config */
    fw_vrf_conf_s vrf_conf[FW_VRF_MAX_SIZE];
} __rte_cache_aligned fw_conf_s;

extern int fw_log_type;
extern uint32_t fw_parse_vrf;

extern void fw_keyword_value_init(void);
extern void install_fw_keywords(void);

extern int fw_conf_init(void);
extern int fw_conf_term(void);

extern fw_conf_s *fw_conf_get(void);
extern fw_vrf_conf_s *fw_conf_get_vrf(uint32_t vrf);

extern int fw_vrf_create(uint32_t vrf);
extern int fw_vrf_delete(uint32_t vrf);

extern int fw_conf_init(void);
extern int fw_conf_term(void);

#endif
