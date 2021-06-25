#ifndef __SESSION_CONF_H__
#define __SESSION_CONF_H__

#include <inttypes.h>

#include <rte_memory.h>


typedef struct _session_conf_ {

    /* app_aging_time */
    uint32_t  dns;
    uint32_t  ftp;
    uint32_t  sip;
    uint32_t  tftp;
    uint32_t  ftp_data;
    uint32_t  https;
    uint32_t  others;

    /* state_aging_time */
    uint32_t  fin;
    uint32_t  icmp_replay;
    uint32_t  icmp_request;
    uint32_t  rawip_open;
    uint32_t  rawip_ready;
    uint32_t  syn;
    uint32_t  tcp_close;
    uint32_t  tcp_est;
    uint32_t  tcp_time_wait;
    uint32_t  udp_open;
    uint32_t  udp_ready;

    uint32_t  session_log;
    uint32_t  session_statistics;
} __rte_cache_aligned session_conf_s;


extern void session_keyword_value_init(void);
extern void install_session_keywords(void);

extern int session_conf_init(void);
extern int session_conf_term(void);
extern session_conf_s *session_conf_get(void);

static inline int session_conf_set_dns(uint32_t timeout)
{
    session_conf_get()->dns = timeout;
    return 0;
}

static inline int session_conf_set_ftp(uint32_t timeout)
{
    session_conf_get()->ftp = timeout;
    return 0;
}

static inline int session_conf_set_sip(uint32_t timeout)
{
    session_conf_get()->sip = timeout;
    return 0;
}

static inline int session_conf_set_tftp(uint32_t timeout)
{
    session_conf_get()->tftp = timeout;
    return 0;
}

static inline int session_conf_set_ftp_data(uint32_t timeout)
{
    session_conf_get()->ftp_data = timeout;
    return 0;
}

static inline int session_conf_set_https(uint32_t timeout)
{
    session_conf_get()->https = timeout;
    return 0;
}

static inline int session_conf_set_others(uint32_t timeout)
{
    session_conf_get()->others = timeout;
    return 0;
}

static inline int session_conf_set_fin(uint32_t timeout)
{
    session_conf_get()->fin = timeout;
    return 0;
}

static inline int session_conf_set_icmp_replay(uint32_t timeout)
{
    session_conf_get()->icmp_replay = timeout;
    return 0;
}

static inline int session_conf_set_icmp_request(uint32_t timeout)
{
    session_conf_get()->icmp_request = timeout;
    return 0;
}

static inline int session_conf_set_rawip_open(uint32_t timeout)
{
    session_conf_get()->rawip_open = timeout;
    return 0;
}

static inline int session_conf_set_rawip_ready(uint32_t timeout)
{
    session_conf_get()->rawip_ready = timeout;
    return 0;
}

static inline int session_conf_set_syn(uint32_t timeout)
{
    session_conf_get()->syn = timeout;
    return 0;
}

static inline int session_conf_set_tcp_close(uint32_t timeout)
{
    session_conf_get()->tcp_close = timeout;
    return 0;
}

static inline int session_conf_set_tcp_est(uint32_t timeout)
{
    session_conf_get()->tcp_est = timeout;
    return 0;
}

static inline int session_conf_set_tcp_time_wait(uint32_t timeout)
{
    session_conf_get()->tcp_time_wait = timeout;
    return 0;
}

static inline int session_conf_set_udp_open(uint32_t timeout)
{
    session_conf_get()->udp_open = timeout;
    return 0;
}

static inline int session_conf_set_udp_ready(uint32_t timeout)
{
    session_conf_get()->udp_ready = timeout;
    return 0;
}

static inline int session_conf_set_session_log(uint32_t enable)
{
    session_conf_get()->session_log = enable;
    return 0;
}

static inline int session_conf_set_session_statistics(uint32_t enable)
{
    session_conf_get()->session_statistics = enable;
    return 0;
}

#endif
