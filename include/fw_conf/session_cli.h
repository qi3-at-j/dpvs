#ifndef __SESSION_CLI_H__
#define __SESSION_CLI_H__

/* 其中session_which_dns ~ session_which_statistics也作为sess_conf_fileds[]的索引 */
typedef enum __session_which__ {
    session_which_unset_all = 0,
    session_which_dns,
    session_which_ftp,
    session_which_sip,
    session_which_tftp,
    session_which_ftp_data,
    session_which_https,
    session_which_others,
    session_which_fin,
    session_which_icmp_reply,
    session_which_icmp_request = 10,
    session_which_icmpv6_reply,
    session_which_icmpv6_request,
    session_which_rawip_open,
    session_which_rawip_ready,
    session_which_syn,
    session_which_tcp_close,
    session_which_tcp_est,
    session_which_tcp_time_wait,
    session_which_udp_open,
    session_which_udp_ready = 20,
    session_which_log,
    session_which_statistics,
    session_which_state,
    session_which_application,
    session_which_agingtime
} SET_SESSION_WHICH_E;

void session_cli_init(void);
void set_sess_conf_field(int i, uint32_t val);
void reset_sess_conf_field(int i);
void set_sess_l4_aging(int i, uint32_t val);

void Session_Print_Status(struct cmdline *cl);

#endif
