#include <stdio.h>
#include <assert.h>

#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_malloc.h>

#include "parser/parser.h"
#include "parser/flow_cmdline.h"
#include "fw_conf/fw_conf.h"
#include "fw_conf/aspf_policy_conf.h"


static void aspf_policy_handler(vector_t tokens)
{
    aspf_policy_detect_modify(fw_parse_vrf, 0, ASPF_DETECT_ALL);
    return;
}

static void detect_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    char buff[128] = {0};
    char *p;

    strcpy(buff, str);
    
    p = strtok(buff, " ");
    while (p) {
        RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, p);

        if (0 == strcmp(p, "ftp")) {
            aspf_policy_detect_modify(fw_parse_vrf, 1, ASPF_DETECT_FTP);
        }

        if (0 == strcmp(p, "http")) {
            aspf_policy_detect_modify(fw_parse_vrf, 1, ASPF_DETECT_HTTP);
        }

        if (0 == strcmp(p, "dns")) {
            aspf_policy_detect_modify(fw_parse_vrf, 1, ASPF_DETECT_DNS);
        }

        if (0 == strcmp(p, "sip")) {
            aspf_policy_detect_modify(fw_parse_vrf, 1, ASPF_DETECT_SIP);
        }

        if (0 == strcmp(p, "tftp")) {
            aspf_policy_detect_modify(fw_parse_vrf, 1, ASPF_DETECT_TFTP);
        }
        p = strtok(NULL, " ");
    }

    FREE_PTR(str);

    return;
}

static void tcpsyn_check_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);

    if (0 == strncmp(str, "enable", 6)) {
        aspf_policy_tcpsyn_check_modify(fw_parse_vrf, 1);
    } else {
        aspf_policy_tcpsyn_check_modify(fw_parse_vrf, 0);
    }

    FREE_PTR(str);

    return;
}

void install_aspf_policy_keywords(void)
{
    install_keyword("aspf_policy", aspf_policy_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("detect",  detect_handler, KW_TYPE_NORMAL);
    install_keyword("tcp_syn_check",  tcpsyn_check_handler, KW_TYPE_NORMAL);
    install_sublevel_end();
    return;
}

void aspf_policy_keyword_value_init(void)
{
    //printf("%s\n", __func__);
    return;
}

int aspf_policy_tcpsyn_check_modify(uint32_t vrf, uint32_t bTcpSynCheck)
{
    fw_vrf_conf_s *vrf_conf;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (vrf_conf) {
        vrf_conf->aspf_conf.bTcpSynCheck = bTcpSynCheck;
        return 0;
    }

    return -1;
}

int aspf_policy_detect_modify(uint32_t vrf, uint32_t insert, uint64_t protocol)
{
    fw_vrf_conf_s *vrf_conf;
    aspf_policy_conf_s *conf;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (vrf_conf) {
        conf = &vrf_conf->aspf_conf;
        if (insert) {
            conf->detect |= protocol;
        } else {
            conf->detect &= ~protocol;
        }

        return 0;
    }

    return -1;
}

aspf_policy_conf_s * aspf_policy_get_by_vrf(uint32_t vrf)
{
    fw_vrf_conf_s *vrf_conf = NULL;
    aspf_policy_conf_s *aspf_conf = NULL;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (NULL != vrf_conf) {
        aspf_conf = &vrf_conf->aspf_conf;       
    }

    return aspf_conf;
}

int aspf_policy_conf_init(uint32_t vrf)
{
    fw_vrf_conf_s *vrf_conf;
    aspf_policy_conf_s *conf;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (vrf_conf) {
        conf = &vrf_conf->aspf_conf;
        /* default enable ftp */
        conf->detect = ASPF_DETECT_FTP;
        conf->bTcpSynCheck = false;
        return 0;
    }

    return -1;
}

int aspf_policy_conf_term(uint32_t vrf)
{
    aspf_policy_conf_init(vrf);
    return 0;
}

