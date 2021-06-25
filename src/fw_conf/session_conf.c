#include <stdio.h>

#include "parser/parser.h"
#include "parser/flow_cmdline.h"
#include "fw_conf/fw_conf.h"
#include "fw_conf/session_conf.h"

static void session_cfg_handler(vector_t tokens)
{
    return;
}

static void session_log_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    printf("%s: %s\n", __func__, str);
    if (0 == strncmp(str, "enable", strlen("enable"))) {
        session_conf_set_session_log(1);
    } else {
        session_conf_set_session_log(0);
    }

    FREE_PTR(str);

    return;
}

static void session_statistics_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    printf("%s:%s\n", __func__, str);
    if (0 == strncmp(str, "enable", strlen("enable"))) {
        session_conf_set_session_statistics(1);
    } else {
        session_conf_set_session_statistics(0);
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
    printf("%s: %d\n", __func__, v);
    session_conf_set_dns(v);

    FREE_PTR(str);
    return;
}

static void ftp_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    printf("%s: %d\n", __func__, v);
    session_conf_set_ftp(v);

    FREE_PTR(str);
    return;
}

static void sip_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    printf("%s: %d\n", __func__, v);
    session_conf_set_sip(v);

    FREE_PTR(str);
    return;
}

static void tftp_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    printf("%s: %d\n", __func__, v);
    session_conf_set_tftp(v);

    FREE_PTR(str);
    return;
}

static void ftp_data_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    printf("%s: %d\n", __func__, v);
    session_conf_set_ftp_data(v);

    FREE_PTR(str);
    return;
}

static void https_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    printf("%s: %d\n", __func__, v);
    session_conf_set_https(v);

    FREE_PTR(str);
    return;
}


static void others_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    printf("%s: %d\n", __func__, v);
    session_conf_set_others(v);

    FREE_PTR(str);
    return;
}

static void fin_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    printf("%s: %d\n", __func__, v);
    session_conf_set_fin(v);

    FREE_PTR(str);
    return;
}

static void icmp_replay_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    printf("%s: %d\n", __func__, v);
    session_conf_set_icmp_replay(v);

    FREE_PTR(str);
    return;
}

static void icmp_request_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    printf("%s: %d\n", __func__, v);
    session_conf_set_icmp_request(v);

    FREE_PTR(str);
    return;
}

static void rawip_open_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    printf("%s: %d\n", __func__, v);
    session_conf_set_rawip_open(v);

    FREE_PTR(str);
    return;
}

static void rawip_ready_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    printf("%s: %d\n", __func__, v);
    session_conf_set_rawip_ready(v);

    FREE_PTR(str);
    return;
}

static void syn_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    printf("%s: %d\n", __func__, v);
    session_conf_set_syn(v);

    FREE_PTR(str);
    return;
}

static void tcp_close_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    printf("%s: %d\n", __func__, v);
    session_conf_set_tcp_close(v);

    FREE_PTR(str);
    return;
}

static void tcp_est_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    printf("%s: %d\n", __func__, v);
    session_conf_set_tcp_est(v);

    FREE_PTR(str);
    return;
}

static void tcp_time_wait_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    printf("%s: %d\n", __func__, v);
    session_conf_set_tcp_time_wait(v);

    FREE_PTR(str);
    return;
}


static void udp_open_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    printf("%s: %d\n", __func__, v);
    session_conf_set_udp_open(v);

    FREE_PTR(str);
    return;
}

static void udp_ready_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t v;

    assert(str);
    v = atoi(str);
    printf("%s: %d\n", __func__, v);
    session_conf_set_udp_ready(v);

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
    install_keyword("fin",           fin_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("syn",           syn_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("tcp_est",       tcp_est_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("tcp_close",     tcp_close_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("tcp_time_wait", tcp_time_wait_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("udp_open",      udp_open_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("udp_ready",     udp_ready_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("icmp_replay",   icmp_replay_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("icmp_request",  icmp_request_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("rawip_open",    rawip_open_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("rawip_ready",   rawip_ready_timeout_handler, KW_TYPE_NORMAL);
    install_sublevel_end();

    return;
}

void session_keyword_value_init(void)
{
    printf("%s\n", __func__);
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
    fw_conf_s *fw_conf;
    session_conf_s *session_conf;

    fw_conf = fw_conf_get();
    if (!fw_conf) {
        return -1;
    }

    session_conf = &fw_conf->session_conf;

    /* set to default */
    session_conf->dns = 1;
    session_conf->ftp = 3600;
    session_conf->sip = 300;
    session_conf->tftp = 60;
    session_conf->ftp_data = 240;
    session_conf->https = 600;
    session_conf->others = 3600;

    session_conf->fin = 30;
    session_conf->icmp_replay = 30;
    session_conf->icmp_request = 60;
    session_conf->rawip_open  = 30;
    session_conf->rawip_ready = 60;
    session_conf->syn = 3600;
    session_conf->tcp_close = 2;
    session_conf->tcp_est = 3600;
    session_conf->tcp_time_wait = 2;
    session_conf->udp_open = 30;
    session_conf->udp_ready = 60;

    session_conf->session_log = 0;
    session_conf->session_statistics = 0;


    return 0;
}

int session_conf_term(void)
{
    /* restore to default */
    session_conf_init();

    return 0;
}
