#include <stdio.h>
#include <assert.h>

#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_malloc.h>

#include "parser/parser.h"
#include "parser/flow_cmdline.h"
#include "fw_conf/session_conf.h"
#include "fw_conf/security_policy_conf.h"
#include "fw_conf/aspf_policy_conf.h"
#include "fw_conf/fw_conf.h"

#define FW_CONF_MEMZONE_NAME    "fw conf memzone"

static fw_conf_s *fw_conf = NULL;


uint32_t fw_parse_vrf = FW_VRF_INVALID;


static void vrf_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    printf("%s:%s\n", __func__, str);
    fw_parse_vrf = atoi(str);

    fw_vrf_create(fw_parse_vrf);
    printf("create vrf:%d\n", fw_parse_vrf);

    FREE_PTR(str);
    return;
}

static void install_vrf_keywords(void)
{
    install_keyword_root("vrf_index", vrf_handler);
    install_security_policy_keywords();
    install_aspf_policy_keywords();

    return;
}

static void vrf_keyword_value_init(void)
{
    security_policy_keyword_value_init();
    aspf_policy_keyword_value_init();

    return;
}

void install_fw_keywords(void)
{
    install_session_keywords();
    install_vrf_keywords();

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

int fw_vrf_create(uint32_t vrf)
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

    /* vrf modules init */
    vrf_conf->status = fw_status_running;
    security_policy_conf_init(vrf);
    aspf_policy_conf_init(vrf);

    rte_atomic32_inc(&fw_conf->running_cnt);

    return 0;
}

int fw_vrf_delete(uint32_t vrf)
{
    fw_vrf_conf_s *vrf_conf;

    if (vrf >= FW_VRF_MAX_SIZE) {
        return -1;
    }

    vrf_conf = &fw_conf->vrf_conf[vrf];
    if (vrf_conf->status == fw_status_stop) {
        return 0;
    }

    /* vrf modules term */
    vrf_conf->status = fw_status_stop;
    security_policy_conf_term(vrf);
    aspf_policy_conf_term(vrf);
    rte_atomic32_dec(&fw_conf->running_cnt);

    return 0;
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
            return -1;
        }
    }

    fw_conf = mem_zone->addr;
    memset(fw_conf, 0, sizeof(fw_conf_s));

    /* global modules init */
    session_conf_init();
    rte_atomic32_init(&fw_conf->running_cnt);

    /* vrf modules init */
    for (i = 0; i < FW_VRF_MAX_SIZE; ++i) {
        vrf_conf = &fw_conf->vrf_conf[i];
        vrf_conf->status = fw_status_stop;
    }

    /* default vrf:0 running */
    fw_vrf_create(0);

    return 0;
}

int fw_conf_term(void)
{
    const struct rte_memzone *mem_zone;
    fw_vrf_conf_s *vrf_conf;
    int i;

    mem_zone = rte_memzone_lookup(FW_CONF_MEMZONE_NAME);
    if (!mem_zone) {
        fw_conf = NULL;
        return 0;
    }

    /* global modules term */
    session_conf_term();

    /* vrf modules term */
    for (i = 0; i < FW_VRF_MAX_SIZE; ++i) {

        vrf_conf = &fw_conf->vrf_conf[i];
        if (vrf_conf->status == fw_status_running) {
            fw_vrf_delete(i);
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
