#include <stdio.h>

/* dpdk */
#include <rte_log.h>

#include "parser/parser.h"
#include "parser/flow_cmdline.h"
#include "fw_conf/fw_conf.h"
#include "fw_conf/session_cli.h"
#include "fw_conf/session_conf.h"
#include "../src/fw-base/session.h"


static void session_cfg_handler(vector_t tokens)
{
    return;
}

static void session_log_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);
    if (0 == strncmp(str, "enable", strlen("enable"))) {
        set_sess_conf_field(session_which_log, 1);
    } else {
        set_sess_conf_field(session_which_log, 0);
    }

    FREE_PTR(str);

    return;
}

static void session_statistics_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    SESSION_CTRL_S *pstSessionCtrl = SESSION_CtrlData_Get();

    RTE_LOG(INFO, CFG_FILE, "%s: %s\n", __func__, str);
    if (0 == strncmp(str, "enable", strlen("enable"))) {
        set_sess_conf_field(session_which_statistics, 1);
        pstSessionCtrl->bStatEnable = BOOL_TRUE;
    } else {
        set_sess_conf_field(session_which_statistics, 0);
        pstSessionCtrl->bStatEnable = BOOL_FALSE;
    }

    FREE_PTR(str);

    return;
}

static void dns_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);
    set_sess_conf_field(session_which_dns, v);

    FREE_PTR(str);
    return;
}

static void ftp_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);
    set_sess_conf_field(session_which_ftp, v);

    FREE_PTR(str);
    return;
}

static void sip_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);
    set_sess_conf_field(session_which_sip, v);
    
    FREE_PTR(str);
    return;
}

static void tftp_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);
    set_sess_conf_field(session_which_tftp, v);

    FREE_PTR(str);
    return;
}

static void ftp_data_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);
    set_sess_conf_field(session_which_ftp_data, v);

    FREE_PTR(str);
    return;
}

static void https_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);
    set_sess_conf_field(session_which_https, v);

    FREE_PTR(str);
    return;
}


static void others_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);
    set_sess_conf_field(session_which_others, v);

    FREE_PTR(str);
    return;
}

static void fin_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);
    set_sess_conf_field(session_which_fin, v);
    set_sess_l4_aging(session_which_fin, v);

    FREE_PTR(str);
    return;
}

static void icmp_reply_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);
    set_sess_conf_field(session_which_icmp_reply, v);
    set_sess_l4_aging(session_which_icmp_reply, v);

    FREE_PTR(str);
    return;
}

static void icmp_request_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);
    set_sess_conf_field(session_which_icmp_request, v);
    set_sess_l4_aging(session_which_icmp_request, v);

    FREE_PTR(str);
    return;
}

static void icmpv6_reply_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);
    set_sess_conf_field(session_which_icmpv6_reply, v);
    set_sess_l4_aging(session_which_icmpv6_reply, v);

    FREE_PTR(str);
    return;
}

static void icmpv6_request_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);
    set_sess_conf_field(session_which_icmpv6_request, v);
    set_sess_l4_aging(session_which_icmpv6_request, v);

    FREE_PTR(str);
    return;
}

static void rawip_open_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);
    set_sess_conf_field(session_which_rawip_open, v);
    set_sess_l4_aging(session_which_rawip_open, v);

    FREE_PTR(str);
    return;
}

static void rawip_ready_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);
    set_sess_conf_field(session_which_rawip_ready, v);
    set_sess_l4_aging(session_which_rawip_ready, v);

    FREE_PTR(str);
    return;
}

static void syn_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);
    set_sess_conf_field(session_which_syn, v);
    set_sess_l4_aging(session_which_syn, v);

    FREE_PTR(str);
    return;
}

static void tcp_close_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);
    set_sess_conf_field(session_which_tcp_close, v);
    set_sess_l4_aging(session_which_tcp_close, v);

    FREE_PTR(str);
    return;
}

static void tcp_est_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);
    set_sess_conf_field(session_which_tcp_est, v);
    set_sess_l4_aging(session_which_tcp_est, v);

    FREE_PTR(str);
    return;
}

static void tcp_time_wait_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);
    set_sess_conf_field(session_which_tcp_time_wait, v);
    set_sess_l4_aging(session_which_tcp_time_wait, v);

    FREE_PTR(str);
    return;
}


static void udp_open_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);
    set_sess_conf_field(session_which_udp_open, v);
    set_sess_l4_aging(session_which_udp_open, v);

    FREE_PTR(str);
    return;
}

static void udp_ready_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    RTE_LOG(INFO, CFG_FILE, "%s: %d\n", __func__, v);

    set_sess_conf_field(session_which_udp_ready, v);
    set_sess_l4_aging(session_which_udp_ready, v);

    FREE_PTR(str);
    return;
}

void install_session_keywords(void)
{
    install_keyword_root("session_cfg", session_cfg_handler);
    install_keyword("session_log", session_log_handler, KW_TYPE_NORMAL);
    install_keyword("session_statistics", session_statistics_handler, KW_TYPE_NORMAL);

    install_keyword("app_aging_time", NULL, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("dns",      dns_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("ftp",      ftp_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("sip",      sip_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("tftp",     tftp_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("https",    https_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("others",   others_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("ftp_data", ftp_data_timeout_handler, KW_TYPE_NORMAL);
    install_sublevel_end();

    install_keyword("state_aging_time", NULL, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("fin",            fin_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("syn",            syn_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("tcp_est",        tcp_est_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("tcp_close",      tcp_close_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("tcp_time_wait",  tcp_time_wait_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("udp_open",       udp_open_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("udp_ready",      udp_ready_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("icmp_replay",    icmp_reply_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("icmp_request",   icmp_request_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("icmpv6_replay",  icmpv6_reply_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("icmpv6_request", icmpv6_request_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("rawip_open",     rawip_open_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("rawip_ready",    rawip_ready_timeout_handler, KW_TYPE_NORMAL);
    install_sublevel_end();

    return;
}

void session_keyword_value_init(void)
{
    return;
}

session_conf_s *session_conf_get(void)
{
    fw_conf_s *fw_conf;

    fw_conf = fw_conf_get();
    if (fw_conf) {
        return &fw_conf->session_conf;
    }

    return NULL;
}

int session_conf_init(void)
{
    int i;

    if (NULL == session_conf_get())
        return -1;

    for (i = session_which_dns; i <= session_which_statistics; i++)
        reset_sess_conf_field(i);

    return 0;
}

int session_conf_term(void)
{
    /* restore to default */
    session_conf_init();

    return 0;
}

