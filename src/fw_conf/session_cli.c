#include <stdio.h>

#include "parser/flow_cmdline.h"
#include "fw_conf/session_cli.h"
#include "fw_conf/session_conf.h"


#define ENABLE  1
#define DISABLE 2


enum __session_which__ {
    session_which_dns = 1,
    session_which_ftp,
    session_which_sip,
    session_which_tftp,
    session_which_ftp_data,
    session_which_https,
    session_which_others,
    session_which_fin,
    session_which_icmp_replay,
    session_which_icmp_request = 10,
    session_which_rawip_open,
    session_which_rawip_ready,
    session_which_syn,
    session_which_tcp_close,
    session_which_tcp_est,
    session_which_tcp_time_wait,
    session_which_udp_open,
    session_which_udp_ready,
    session_which_log,
    session_which_stat = 20
};

static int set_session_cli(cmd_blk_t *cbt)
{
    int i;

    printf("opt: %s\n", cbt->mode == MODE_DO ? "do":"undo");

    for (i = 0; i < cbt->which_cnt; i++) {
        switch (cbt->which[i]) {
        case session_which_dns:
            tyflow_cmdline_printf(cbt->cl, "\tdns: %d\n",  cbt->number[i]);
            session_conf_set_dns(cbt->number[i]);
            break;
        case session_which_ftp:
            tyflow_cmdline_printf(cbt->cl, "\tftp: %d\n",  cbt->number[i]);
            session_conf_set_ftp(cbt->number[i]);
            break;
        case session_which_sip:
            tyflow_cmdline_printf(cbt->cl, "\tsip: %d\n",  cbt->number[i]);
            session_conf_set_sip(cbt->number[i]);
            break;
        case session_which_tftp:
            tyflow_cmdline_printf(cbt->cl, "\ttftp: %d\n",  cbt->number[i]);
            session_conf_set_tftp(cbt->number[i]);
            break;
        case session_which_ftp_data:
            tyflow_cmdline_printf(cbt->cl, "\tftp_data: %d\n",  cbt->number[i]);
            session_conf_set_ftp_data(cbt->number[i]);
            break;
        case session_which_https:
            tyflow_cmdline_printf(cbt->cl, "\thttps: %d\n",  cbt->number[i]);
            session_conf_set_https(cbt->number[i]);
            break;
        case session_which_others:
            tyflow_cmdline_printf(cbt->cl, "\tothers: %d\n",  cbt->number[i]);
            session_conf_set_others(cbt->number[i]);
            break;
        case session_which_fin:
            tyflow_cmdline_printf(cbt->cl, "\tfin: %d\n",  cbt->number[i]);
            session_conf_set_fin(cbt->number[i]);
            break;
        case session_which_icmp_replay:
            tyflow_cmdline_printf(cbt->cl, "\ticmp_replay: %d\n",  cbt->number[i]);
            session_conf_set_icmp_replay(cbt->number[i]);
            break;
        case session_which_icmp_request:
            tyflow_cmdline_printf(cbt->cl, "\ticmp_request: %d\n",  cbt->number[i]);
            session_conf_set_icmp_request(cbt->number[i]);
            break;
        case session_which_rawip_open:
            tyflow_cmdline_printf(cbt->cl, "\trawip_open: %d\n",  cbt->number[i]);
            session_conf_set_rawip_open(cbt->number[i]);
            break;
        case session_which_rawip_ready:
            tyflow_cmdline_printf(cbt->cl, "\trawip_ready: %d\n",  cbt->number[i]);
            session_conf_set_rawip_ready(cbt->number[i]);
            break;
        case session_which_syn:
            tyflow_cmdline_printf(cbt->cl, "\tsyn: %d\n",  cbt->number[i]);
            session_conf_set_syn(cbt->number[i]);
            break;
        case session_which_tcp_close:
            tyflow_cmdline_printf(cbt->cl, "\ttcp_close: %d\n",  cbt->number[i]);
            session_conf_set_tcp_close(cbt->number[i]);
            break;
        case session_which_tcp_est:
            tyflow_cmdline_printf(cbt->cl, "\ttcp_est: %d\n",  cbt->number[i]);
            session_conf_set_tcp_est(cbt->number[i]);
            break;
        case session_which_tcp_time_wait:
            tyflow_cmdline_printf(cbt->cl, "\ttcp_time_wait: %d\n",  cbt->number[i]);
            session_conf_set_tcp_time_wait(cbt->number[i]);
            break;
        case session_which_udp_open:
            tyflow_cmdline_printf(cbt->cl, "\tudp_open: %d\n",  cbt->number[i]);
            session_conf_set_udp_open(cbt->number[i]);
            break;
        case session_which_udp_ready:
            tyflow_cmdline_printf(cbt->cl, "\tudp_ready: %d\n", cbt->number[i]);
            session_conf_set_udp_ready(cbt->number[i]);
            break;
        case session_which_log:
            ++i;
            tyflow_cmdline_printf(cbt->cl, "\tlog: %s\n", cbt->which[i]==ENABLE ? "enable":"disable");
            session_conf_set_session_log(cbt->which[i] == ENABLE ? 1 : 0);
            break;
        case session_which_stat:
            ++i;
            tyflow_cmdline_printf(cbt->cl, "\tstatistics: %s\n", cbt->which[i]==ENABLE ? "enable":"disable");
            session_conf_set_session_statistics(cbt->which[i] == ENABLE ? 1 : 0);
            break;
        }
    }

    return 0;
}


EOL_NODE(session_eol, set_session_cli);

KW_NODE_WHICH(session_stat_off, session_eol, none, "disable", "disable session statistics", 2, DISABLE);
KW_NODE_WHICH(session_stat_on,  session_eol, session_stat_off, "enable", "enable session statistics", 2, ENABLE);
KW_NODE_WHICH(session_stat, session_stat_on, none, "session-statistics", "session-statistics", 1, session_which_stat);

KW_NODE_WHICH(session_log_off, session_eol, none, "disable", "disable session log", 2, DISABLE);
KW_NODE_WHICH(session_log_on,  session_eol, session_log_off, "enable", "enable session log", 2, ENABLE);
KW_NODE_WHICH(session_log, session_log_on, session_stat, "session-log", "session-log", 1, session_which_log);

VALUE_NODE(udp_ready_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(udp_ready, udp_ready_value, session_log, "udp-ready", "udp-ready aging time", 1, session_which_udp_ready);

VALUE_NODE(udp_open_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(udp_open, udp_open_value, udp_ready, "udp-open", "udp-open aging time", 1, session_which_udp_open);

VALUE_NODE(tcp_time_wait_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(tcp_time_wait, tcp_time_wait_value, udp_open, "tcp-time-wait", "tcp-time-wait aging time", 1, session_which_tcp_time_wait);

VALUE_NODE(tcp_est_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(tcp_est, tcp_est_value, tcp_time_wait, "tcp-est", "tcp-est aging time", 1, session_which_tcp_est);

VALUE_NODE(tcp_close_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(tcp_close, tcp_close_value, tcp_est, "tcp-close", "tcp-close aging time", 1, session_which_tcp_close);

VALUE_NODE(syn_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(syn, syn_value, tcp_close, "syn", "syn aging time", 1, session_which_syn);

VALUE_NODE(rawip_ready_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(rawip_ready, rawip_ready_value, syn, "rawip-ready", "rawip-ready aging time", 1, session_which_rawip_ready);

VALUE_NODE(rawip_open_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(rawip_open, rawip_open_value, rawip_ready, "rawip-open", "rawip-open aging time", 1, session_which_rawip_open);

VALUE_NODE(icmp_request_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(icmp_request, icmp_request_value, rawip_open, "icmp-request", "icmp-request aging time", 1, session_which_icmp_request);

VALUE_NODE(icmp_replay_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(icmp_replay, icmp_replay_value, icmp_request, "icmp-replay", "icmp-replay aging time", 1, session_which_icmp_replay);

VALUE_NODE(fin_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(fin, fin_value, icmp_replay, "fin", "fin aging time", 1, session_which_fin);

VALUE_NODE(others_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(others, others_value, fin, "others", "others aging time", 1, session_which_others);

VALUE_NODE(https_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(https, https_value, others, "https", "https aging time", 1, session_which_https);

VALUE_NODE(ftp_data_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(ftp_data, ftp_data_value, https, "ftp-data", "ftp-data aging time", 1, session_which_ftp_data);

VALUE_NODE(tftp_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(tftp, tftp_value, ftp_data, "tftp", "tftp aging time", 1, session_which_tftp);

VALUE_NODE(sip_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(sip, sip_value, tftp, "sip", "sip aging time", 1, session_which_sip);

VALUE_NODE(ftp_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(ftp, ftp_value, sip, "ftp", "ftp aging time", 1, session_which_ftp);

VALUE_NODE(dns_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(dns, dns_value,  ftp, "dns", "dns aging time", 1, session_which_dns);

KW_NODE(session, dns, none, "session", "set session aging time");


void session_cli_init(void)
{
    add_set_cmd(&cnode(session));
}

