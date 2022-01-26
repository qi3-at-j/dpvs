#ifndef __SESSION_CONF_H__
#define __SESSION_CONF_H__

#include <inttypes.h>

#include <rte_memory.h>


/* !!!ע�⣺sess_conf_fileds[]����Ա�ĵ�һ���ֶ�nameҪ��session_conf_s�е��ֶ���һ�� */
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
    uint32_t  icmp_reply;
    uint32_t  icmp_request;
    uint32_t  icmpv6_reply;
    uint32_t  icmpv6_request;
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

#endif
