#include <stdio.h>
#include <assert.h>

#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_malloc.h>

#include "baseype.h"
#include "conf/common.h"
#include "parser/parser.h"
#include "parser/flow_cmdline.h"
#include "fw_conf/session_conf.h"
#include "fw_conf/security_policy_conf.h"
#include "fw_conf/aspf_policy_conf.h"
#include "fw_conf/ips_policy_conf.h"
#include "fw_conf/fw_conf.h"
#include "proto_relation.h"
#include "app_rbt.h"
#include "fw_log.h"
#include "start_process.h"

/* access_control head */
#include "../access_control/basetype.h"
#include "../access_control/secpolicy_init.h"
#include "../access_control/error.h"
#include "../access_control/secpolicy_common.h"
#include "../access_control/secpolicy.h"
#include "../pfilter/pfilter.h"


#define FW_CONF_MEMZONE_NAME    "fw-conf-memzone"
#define FW_INFO_MEMZONE_NAME    "fw-info-memzone"

static fw_conf_s *fw_conf = NULL;
static fw_user_info_s *fw_user_info = NULL;

uint32_t fw_parse_vrf = FW_VRF_INVALID;
unsigned char szSecPolicyTenantID[64] = {0};
uint32_t secpolicy_fw_type = SECPOLICY_TYPE_VPCBODER;

fw_agent_cfg_s fw_agent_cfg = {{0}};

static void vrf_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);
    fw_parse_vrf = atoi(str);

    snprintf((char *)szSecPolicyTenantID, 64, "%s", str);

    //fw_vrf_create(fw_parse_vrf, NULL);

    //secpolicy_fw_type = SECPOLICY_TYPE_VPCBODER;

    FREE_PTR(str);
    return;
}

static void install_vrf_keywords(void)
{
    install_keyword_root("vrf_index", vrf_handler);
    install_security_policy_keywords();
    install_aspf_policy_keywords();
    install_ips_policy_keywords();

    return;
}

static void tenant_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);
    memcpy(szSecPolicyTenantID, str, TENANT_ID_MAX+1);
    //secpolicy_fw_type = SECPOLICY_TYPE_EXTBODER;
    FREE_PTR(str);
    return;
}

static void install_tenant_keywords(void)
{
    install_keyword_root("tenant", tenant_handler);
    install_security_policy_keywords();

    return;
}

static void secpolicy_status_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);

    if (!strncasecmp("enable", str, strlen("enable")))
    {
        g_bIsSecPolicyStatusOn = 1;
    }
    else
    {
        g_bIsSecPolicyStatusOn = 0;
    }

    FREE_PTR(str);
    return;
}

static void install_secpolicy_status(void)
{
    install_keyword_root("secpolicy_status", secpolicy_status_handler);
    return;
}

static void vrf_keyword_value_init(void)
{
    security_policy_keyword_value_init();
    aspf_policy_keyword_value_init();
    ips_policy_keyword_value_init();

    return;
}

static void userid_maps_cfg_handler(vector_t tokens)
{
    return;
}

static void map_handler(vector_t tokens)
{
    char *uuid = set_value(tokens);
    char *p;
    uint32_t vrf = 0;

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, uuid);

    p = strrchr(uuid, '-');
    if (p) {
        *p = 0;
        vrf = atoi(++p);

        fw_vrf_create(vrf, uuid);
    }

    FREE_PTR(uuid);

    return;
}

static void install_userid_maps_keywords(void)
{
    install_keyword_root("userid_maps", userid_maps_cfg_handler);
    install_keyword("map", map_handler, KW_TYPE_NORMAL);

    return;
}

static void global_conf_handler(vector_t tokens)
{
    return;
}

static void version_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);

    FREE_PTR(str);

    return;
}

static void fw_type_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);

    if (0 == strcmp(str, "external")) {
        secpolicy_fw_type = SECPOLICY_TYPE_EXTBODER;
    }

    if (0 == strcmp(str, "internal")) {
        secpolicy_fw_type = SECPOLICY_TYPE_VPCBODER;
    }

    FREE_PTR(str);

    return;
}

static void install_global_conf_keywords(void)
{
    install_keyword_root("fw_global_conf", global_conf_handler);
    install_keyword("version", version_handler, KW_TYPE_NORMAL);
    install_keyword("fw_type", fw_type_handler, KW_TYPE_NORMAL);

    return;
}

static void fw_agent_conf_handler(vector_t tokens)
{
    return;
}

static void ip_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);
    snprintf(fw_agent_cfg.ip, sizeof(fw_agent_cfg.ip), str);

    FREE_PTR(str);

    return;
}

static void port_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);

    snprintf(fw_agent_cfg.port, sizeof(fw_agent_cfg.port), str);

    FREE_PTR(str);

    return;
}

static void install_fw_agent_conf_keywords(void)
{
    install_keyword_root("fw_agent_conf", fw_agent_conf_handler);
    install_keyword("ip", ip_handler, KW_TYPE_NORMAL);
    install_keyword("port", port_handler, KW_TYPE_NORMAL);

    return;
}

void install_fw_keywords(void)
{
    install_global_conf_keywords();
    install_userid_maps_keywords();
    install_fw_agent_conf_keywords();
    install_log_keywords();
    install_session_keywords();
    install_secpolicy_status();
    install_vrf_keywords();
    install_tenant_keywords();
    return;
}

void fw_keyword_value_init(void)
{
    session_keyword_value_init();
    vrf_keyword_value_init();

    return;
}

fw_conf_s *fw_conf_get(void)
{
    return fw_conf;
}

fw_vrf_conf_s *fw_conf_get_vrf(uint32_t vrf)
{
    fw_conf_s *fw_conf;

    fw_conf = fw_conf_get();
    if (!fw_conf || vrf >= FW_VRF_MAX_SIZE) {
        printf("vrf:%u not exist.\n", vrf);
        return NULL;
    }

    if (fw_conf->vrf_conf[vrf].status != fw_status_running) {
        printf("vrf:%u not running.\n", vrf);
        return NULL;
    }

    return &fw_conf->vrf_conf[vrf];
}

int fw_vrf_create(uint32_t vrf, char *uuid)
{
    fw_vrf_conf_s *vrf_conf;

    if (vrf >= FW_VRF_MAX_SIZE) {
        printf("reachable max size.\n");
        return -1;
    }

    vrf_conf = &fw_conf->vrf_conf[vrf];
    if (vrf_conf->status == fw_status_running) {
        printf("vrf:%u already exist.\n", vrf);
        return -1;
    }

    /* record user id */
    if (fw_user_info) {
        snprintf(fw_user_info->data[vrf].uuid, 64, "%s", uuid);
    }

    /* vrf modules init */
    vrf_conf->status = fw_status_running;
    aspf_policy_conf_init(vrf);
    ips_policy_conf_init(vrf);

    rte_atomic32_inc(&fw_conf->running_cnt);

    SecPolicy_Conf_AddVxlanID(vrf, IPPROTO_IP);
    SecPolicy_Conf_AddVxlanID(vrf, IPPROTO_IPV6);
    return 0;
}

int fw_vrf_delete(uint32_t vrf, char *uuid)
{
    fw_vrf_conf_s *vrf_conf;

    if (vrf >= FW_VRF_MAX_SIZE) {
        return -1;
    }

    /* clear user id */
    if (fw_user_info) {
        fw_user_info->data[vrf].uuid[0] = 0;
    }

    vrf_conf = &fw_conf->vrf_conf[vrf];
    if (vrf_conf->status == fw_status_stop) {
        return 0;
    }

    /* vrf modules term */
    aspf_policy_conf_term(vrf);
    ips_policy_conf_term(vrf);
    vrf_conf->status = fw_status_stop;
    rte_atomic32_dec(&fw_conf->running_cnt);
    vrf_conf->status = fw_status_stop;

    SecPolicy_Conf_DelVxlanID(vrf);
    return 0;
}

const char *fw_get_user_id(uint32_t vrf)
{
    if (!fw_user_info || vrf >= FW_VRF_MAX_SIZE)
        return "";

    return fw_user_info->data[vrf].uuid;
}

int fw_conf_init(void)
{
    const struct rte_memzone *mem_zone;
    fw_vrf_conf_s *vrf_conf;
    int i;

    mem_zone = rte_memzone_lookup(FW_CONF_MEMZONE_NAME);
    if (!mem_zone) {
        mem_zone = rte_memzone_reserve(FW_CONF_MEMZONE_NAME, sizeof(fw_conf_s), SOCKET_ID_ANY, 0);
        if (!mem_zone) {
            printf("aspf policy reserve memory failed.\n");
            return EDPVS_NOMEM;
        }
    }

    fw_conf = mem_zone->addr;
    memset(fw_conf, 0, sizeof(fw_conf_s));

    /* global modules init */
    session_conf_init();

    SecPolicy_Init();

    Pfilter_Init();

    proto_relation_init();
    App_Rbt_Init();

    rte_atomic32_init(&fw_conf->running_cnt);

    /* vrf modules init */
    for (i = 0; i < FW_VRF_MAX_SIZE; ++i) {
        vrf_conf = &fw_conf->vrf_conf[i];
        vrf_conf->status = fw_status_stop;
    }

    mem_zone = rte_memzone_lookup(FW_INFO_MEMZONE_NAME);
    if (!mem_zone) {
        mem_zone = rte_memzone_reserve(FW_INFO_MEMZONE_NAME, sizeof(fw_user_info_s), SOCKET_ID_ANY, 0);
        if (!mem_zone) {
            printf("fw user info reserve memory failed.\n");
            return EDPVS_NOMEM;
        }
    }

    fw_user_info = mem_zone->addr;
    memset(fw_user_info, 0, sizeof(fw_user_info_s));

    /* default vrf:0 running */
    fw_vrf_create(0, "Reserved");

    return 0;
}

int fw_conf_term(void)
{
    const struct rte_memzone *mem_zone;
    fw_vrf_conf_s *vrf_conf;
    int i;

    mem_zone = rte_memzone_lookup(FW_INFO_MEMZONE_NAME);
    if (mem_zone) {
        rte_memzone_free(mem_zone);
        fw_user_info = NULL;
    }

    mem_zone = rte_memzone_lookup(FW_CONF_MEMZONE_NAME);
    if (!mem_zone) {
        fw_conf = NULL;
        return 0;
    }

    /* global modules term */
    session_conf_term();

    SecPolicy_Fini();

    Pfilter_Fini();

    /* vrf modules term */
    for (i = 0; i < FW_VRF_MAX_SIZE; ++i) {

        vrf_conf = &fw_conf->vrf_conf[i];
        if (vrf_conf->status == fw_status_running) {
            fw_vrf_delete(i, NULL);
        }
    }

    rte_memzone_free(mem_zone);
    fw_conf = NULL;

    return 0;
}

int fw_log_type = -1;

RTE_INIT(fw_log_init)
{
	fw_log_type = rte_log_register("fw_conf");
	if (fw_log_type >= 0) {
		rte_log_set_level(fw_log_type, RTE_LOG_DEBUG);
    }
}
