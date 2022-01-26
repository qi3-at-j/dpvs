#include <stdio.h>

#include "parser/flow_cmdline.h"
#include "fw_conf/fw_conf.h"
#include "fw_conf/session_cli.h"
#include "../src/fw-base/session.h"

typedef struct {
    char * name;
    uint32_t offset;  /* offsetof(session_conf_s, field) */
    uint32_t dflt;    /* default value */
} SESSION_CONF_FIELD_S;

/* !!!注意：各成员的第一个字段name要和session_conf_s中的字段名一致 */
SESSION_CONF_FIELD_S sess_conf_fileds[] = {
    [session_which_unset_all]   = {NULL,                  0,                                              0},
    [session_which_dns]         = {"dns",                 offsetof(session_conf_s, dns),                  SESSION_PRO_DNS_TIME},
    [session_which_ftp]         = {"ftp",                 offsetof(session_conf_s, ftp),                  SESSION_PRO_FTP_CTRL_TIME},
    [session_which_sip]         = {"sip",                 offsetof(session_conf_s, sip),                  SESSION_PRO_SIP_TIME},
    [session_which_tftp]        = {"tftp",                offsetof(session_conf_s, tftp),                 SESSION_PRO_TFTP_TIME},
    [session_which_ftp_data]    = {"ftp_data",            offsetof(session_conf_s, ftp_data),             240},
    [session_which_https]       = {"https",               offsetof(session_conf_s, https),                600},
    [session_which_others]      = {"others",              offsetof(session_conf_s, others),               SESSION_APP_DEFAULT_AGING},
    [session_which_fin]         = {"fin",                 offsetof(session_conf_s, fin),                  SESSION_TCP_FIN_CLOSE_TIME},
    [session_which_icmp_reply]  = {"icmp_reply",          offsetof(session_conf_s, icmp_reply),           SESSION_ICMP_REPLY_TIME},
    [session_which_icmp_request]= {"icmp_request",        offsetof(session_conf_s, icmp_request),         SESSION_ICMP_REQUEST_TIME},
    [session_which_icmpv6_reply]  = {"icmpv6_reply",      offsetof(session_conf_s, icmpv6_reply),         SESSION_ICMPV6_REPLY_TIME},
    [session_which_icmpv6_request]= {"icmpv6_request",    offsetof(session_conf_s, icmpv6_request),       SESSION_ICMPV6_REQUEST_TIME},
    [session_which_rawip_open]  = {"rawip_open",          offsetof(session_conf_s, rawip_open),           SESSION_RAWIP_OPEN_TIME},
    [session_which_rawip_ready] = {"rawip_ready",         offsetof(session_conf_s, rawip_ready),          SESSION_RAWIP_READY_TIME},
    [session_which_syn]         = {"syn",                 offsetof(session_conf_s, syn),                  SESSION_TCP_SYN_OPEN_TIME},
    [session_which_tcp_close]   = {"tcp_close",           offsetof(session_conf_s, tcp_close),            SESSION_TABLE_DEFAULT_TIMEOUT},
    [session_which_tcp_est]     = {"tcp_est",             offsetof(session_conf_s, tcp_est),              SESSION_TCP_ESTABILISHED_TIME},
    [session_which_tcp_time_wait]= {"tcp_time_wait",      offsetof(session_conf_s, tcp_time_wait),        SESSION_TABLE_DEFAULT_TIMEOUT},
    [session_which_udp_open]    = {"udp_open",            offsetof(session_conf_s, udp_open),             SESSION_UDP_OPEN_TIME},
    [session_which_udp_ready]   = {"udp_ready",           offsetof(session_conf_s, udp_ready),            SESSION_UDP_READY_TIME},
    [session_which_log]         = {"session_log",         offsetof(session_conf_s, session_log),          0},
    [session_which_statistics]  = {"session_statistics",  offsetof(session_conf_s, session_statistics),   0},
};

static uint32_t get_sess_conf_field(int i)
{
    return *(uint32_t *)((char *)session_conf_get() + sess_conf_fileds[i].offset);
}

void set_sess_conf_field(int i, uint32_t val)
{
    *(uint32_t *)((char *)session_conf_get() + sess_conf_fileds[i].offset) = val;
    return;
}

void reset_sess_conf_field(int i)
{
    set_sess_conf_field(i, sess_conf_fileds[i].dflt);
    return;
}

static SESSION_PROT_AGING_TYPE_E prot_aging_type_get(SET_SESSION_WHICH_E which)
{
    SESSION_PROT_AGING_TYPE_E ret;

    switch (which) {
        case session_which_fin:
            ret = SESSION_PROT_AGING_TCPFIN;
            break;
        case session_which_icmp_reply:
            ret = SESSION_PROT_AGING_ICMPREPLY;
            break;
        case session_which_icmp_request:
            ret = SESSION_PROT_AGING_ICMPREQUEST;
            break;
        case session_which_icmpv6_reply:
            ret = SESSION_PROT_AGING_ICMPV6REPLY;
            break;
        case session_which_icmpv6_request:
            ret = SESSION_PROT_AGING_ICMPV6REQUEST;
            break;
        case session_which_rawip_open:
            ret = SESSION_PROT_AGING_RAWIPOPEN;
            break;
        case session_which_rawip_ready:
            ret = SESSION_PROT_AGING_RAWIPREADY;
            break;
        case session_which_syn:
            ret = SESSION_PROT_AGING_TCPSYN;
            break;
        case session_which_tcp_est:
            ret = SESSION_PROT_AGING_TCPEST;
            break;
        case session_which_udp_open:
            ret = SESSION_PROT_AGING_UDPOPEN;
            break;
        case session_which_udp_ready:
            ret = SESSION_PROT_AGING_UDPREADY;
            break;
        default:
            ret = SESSION_PROT_AGING_MAX;
    }

    return ret;
}

void set_sess_l4_aging(int i, uint32_t val)
{
    SESSION_L4AGING_S stAging;
    SESSION_CTRL_S *pstSessionCtrl = SESSION_CtrlData_Get();

    memset(&stAging, 0, sizeof(SESSION_L4AGING_S));
    stAging.enL4Type = prot_aging_type_get(i);
    if (session_which_tcp_time_wait == i)
        stAging.uiTimeWaitAging = val;
    else if (session_which_tcp_close == i)
        stAging.uiCloseAging = val;
    else
        stAging.uiTimeValue = val;

    SESSION_KGCFG_SetL4Aging(pstSessionCtrl, &stAging);
    
    return;
}

static int set_session_cli(cmd_blk_t *cbt)
{
    uint32_t val = 0;
    int i;
    SESSION_CTRL_S *pstSessionCtrl = SESSION_CtrlData_Get();

    if (NULL == session_conf_get())
        return -1;

    switch (cbt->which[0]) {
        case session_which_fin:
        case session_which_icmp_reply:
        case session_which_icmp_request:
        case session_which_icmpv6_reply:
        case session_which_icmpv6_request:
        case session_which_rawip_open:
        case session_which_rawip_ready:
        case session_which_syn:
        case session_which_tcp_est:
        case session_which_udp_open:
        case session_which_udp_ready:
        case session_which_tcp_time_wait:
        case session_which_tcp_close:
            val = (MODE_DO == cbt->mode) ? cbt->number[0] : sess_conf_fileds[cbt->which[0]].dflt;
            tyflow_cmdline_printf(cbt->cl, "\tset aging time of %s to %d\n",  sess_conf_fileds[cbt->which[0]].name, val);
            set_sess_conf_field(cbt->which[0], val);
            set_sess_l4_aging(cbt->which[0], val);
            break;
        case session_which_log:
        case session_which_statistics:
            val = (MODE_DO == cbt->mode) ? 1 : 0;
            tyflow_cmdline_printf(cbt->cl, "\t%s %s\n",  val ? "enable" : "disable", sess_conf_fileds[cbt->which[0]].name);
            set_sess_conf_field(cbt->which[0], val);
            if (session_which_statistics == cbt->which[0])
                pstSessionCtrl->bStatEnable = val;
            break;
        case session_which_agingtime:
        case session_which_state:
        case session_which_unset_all:
            for (i = session_which_fin; i <= session_which_udp_ready; i++) {
                reset_sess_conf_field(i);
                set_sess_l4_aging(i, sess_conf_fileds[i].dflt);
            }

            if (session_which_unset_all == cbt->which[0]) {
                tyflow_cmdline_printf(cbt->cl, "\treset all session related conf\n");
                reset_sess_conf_field(session_which_log);
                reset_sess_conf_field(session_which_statistics);
                pstSessionCtrl->bStatEnable = BOOL_FALSE;
            } else {
                tyflow_cmdline_printf(cbt->cl, "\treset aging time of all states\n");
            }
            
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "\tunknown command\n");
    }

    return 0;
}

static int set_security_cli(cmd_blk_t *cbt)
{
    SESSION_CTRL_S *pstSessionCtrl = SESSION_CtrlData_Get();

    switch (cbt->which[0]) {
        case 1: /* set security enable */
            pstSessionCtrl->bSecEnable = BOOL_TRUE;
            break;
        case 2: /* set security disable */
        case 3: /* unset security enable */
            pstSessionCtrl->bSecEnable = BOOL_FALSE;
            break;
        default:
            tyflow_cmdline_printf(cbt->cl, "\tunknown command\n");
    }

    return 0;
}

/* 显示set session命令相关的参数值 */
void Session_Print_Status(struct cmdline *cl)
{
    SET_SESSION_WHICH_E en_which;

    tyflow_cmdline_printf(cl, "  Security:  %s\r\n", SESSION_CtrlData_Get()->bSecEnable ? "enable" : "disable");
    tyflow_cmdline_printf(cl, "  L4 state aging time:\r\n");
    for (en_which = session_which_fin; en_which <= session_which_statistics; en_which++) {
        if ((session_which_log == en_which) || (session_which_statistics == en_which))
            tyflow_cmdline_printf(cl, "  %s:  %s\r\n", 
                sess_conf_fileds[en_which].name, get_sess_conf_field(en_which) ? "enable" : "disable");
        else
            tyflow_cmdline_printf(cl, "    %s:  %d\r\n", 
                sess_conf_fileds[en_which].name, get_sess_conf_field(en_which));
    }

    return;
}


EOL_NODE(session_eol, set_session_cli);

/* used in unset */
KW_NODE_WHICH(unset_udp_ready, session_eol, session_eol, "udp-ready", "udp-ready aging time", 1, session_which_udp_ready);
KW_NODE_WHICH(unset_udp_open, session_eol, unset_udp_ready, "udp-open", "udp-open aging time", 1, session_which_udp_open);
KW_NODE_WHICH(unset_tcp_time_wait, session_eol, unset_udp_open, "tcp-time-wait", "tcp-time-wait aging time", 1, session_which_tcp_time_wait);
KW_NODE_WHICH(unset_tcp_est, session_eol, unset_tcp_time_wait, "tcp-est", "tcp-est aging time", 1, session_which_tcp_est);
KW_NODE_WHICH(unset_tcp_close, session_eol, unset_tcp_est, "tcp-close", "tcp-close aging time", 1, session_which_tcp_close);
KW_NODE_WHICH(unset_syn, session_eol, unset_tcp_close, "syn", "syn aging time", 1, session_which_syn);
KW_NODE_WHICH(unset_rawip_ready, session_eol, unset_syn, "rawip-ready", "rawip-ready aging time", 1, session_which_rawip_ready);
KW_NODE_WHICH(unset_rawip_open, session_eol, unset_rawip_ready, "rawip-open", "rawip-open aging time", 1, session_which_rawip_open);
KW_NODE_WHICH(unset_icmpv6_request, session_eol, unset_rawip_open, "icmpv6-request", "icmpv6-request aging time", 1, session_which_icmpv6_request);
KW_NODE_WHICH(unset_icmpv6_reply, session_eol, unset_icmpv6_request, "icmpv6-reply", "icmpv6-reply aging time", 1, session_which_icmpv6_reply);
KW_NODE_WHICH(unset_icmp_request, session_eol, unset_icmpv6_reply, "icmp-request", "icmp-request aging time", 1, session_which_icmp_request);
KW_NODE_WHICH(unset_icmp_reply, session_eol, unset_icmp_request, "icmp-reply", "icmp-reply aging time", 1, session_which_icmp_reply);
KW_NODE_WHICH(unset_fin, session_eol, unset_icmp_reply, "fin", "fin aging time", 1, session_which_fin);
/*
KW_NODE_WHICH(unset_others, session_eol, session_eol, "others", "others aging time", 1, session_which_others);
KW_NODE_WHICH(unset_https, session_eol, unset_others, "https", "https aging time", 1, session_which_https);
KW_NODE_WHICH(unset_ftp_data, session_eol, unset_https, "ftp-data", "ftp-data aging time", 1, session_which_ftp_data);
KW_NODE_WHICH(unset_tftp, session_eol, unset_ftp_data, "tftp", "tftp aging time", 1, session_which_tftp);
KW_NODE_WHICH(unset_sip, session_eol, unset_tftp, "sip", "sip aging time", 1, session_which_sip);
KW_NODE_WHICH(unset_ftp, session_eol, unset_sip, "ftp", "ftp aging time", 1, session_which_ftp);
KW_NODE_WHICH(unset_dns, session_eol, unset_ftp, "dns", "dns aging time", 1, session_which_dns);
KW_NODE_WHICH(unset_application, unset_fin, session_eol, "application", "application", 1, session_which_application);
*/
KW_NODE_WHICH(unset_state, unset_fin, /*unset_application*/session_eol, "state", "protocol state", 1, session_which_state);
KW_NODE(unset_session_stat_on, session_eol, session_eol, "enable", "enable session log");
KW_NODE_WHICH(unset_session_stat, unset_session_stat_on, session_eol, "statistics", "session statistics", 1, session_which_statistics);
KW_NODE(unset_session_log_on, session_eol, session_eol, "enable", "enable session log");
KW_NODE_WHICH(unset_session_log, unset_session_log_on, unset_session_stat, "log", "session log", 1, session_which_log);
KW_NODE_WHICH(unset_aging_time, unset_state, unset_session_log, "aging-time", "session aging time", 1, session_which_agingtime);

/* used in set */
VALUE_NODE(udp_ready_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(udp_ready, udp_ready_value, none, "udp-ready", "udp-ready aging time", 1, session_which_udp_ready);
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
VALUE_NODE(icmpv6_request_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(icmpv6_request, icmpv6_request_value, rawip_open, "icmpv6-request", "icmpv6-request aging time", 1, session_which_icmpv6_request);
VALUE_NODE(icmpv6_reply_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(icmpv6_reply, icmpv6_reply_value, icmpv6_request, "icmpv6-reply", "icmpv6-reply aging time", 1, session_which_icmpv6_reply);
VALUE_NODE(icmp_request_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(icmp_request, icmp_request_value, icmpv6_reply, "icmp-request", "icmp-request aging time", 1, session_which_icmp_request);
VALUE_NODE(icmp_reply_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(icmp_reply, icmp_reply_value, icmp_request, "icmp-reply", "icmp-reply aging time", 1, session_which_icmp_reply);
VALUE_NODE(fin_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(fin, fin_value, icmp_reply, "fin", "fin aging time", 1, session_which_fin);
/*
VALUE_NODE(others_value, session_eol, none, "time value", 1, NUM);
KW_NODE_WHICH(others, others_value, none, "others", "others aging time", 1, session_which_others);
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
KW_NODE_WHICH(dns, dns_value, ftp, "dns", "dns aging time", 1, session_which_dns);
*/
KW_NODE_WHICH(session_stat_on, session_eol, none, "enable", "enable session log", 1, session_which_statistics);
KW_NODE(session_stat, session_stat_on, none, "statistics", "session statistics");
KW_NODE_WHICH(session_log_on, session_eol, none, "enable", "enable session log", 1, session_which_log);
KW_NODE(session_log, session_log_on, session_stat, "log", "session log");
/*KW_NODE(application, dns, none, "application", "application");*/
KW_NODE(state, fin, /*application*/none, "state", "protocol state");
KW_NODE(aging_time, state, session_log, "aging-time", "session aging time");

TEST_UNSET(test_unset_session, unset_aging_time, aging_time);
KW_NODE(session, test_unset_session, none, "session", "session related items");

EOL_NODE(security_eol, set_security_cli);
KW_NODE_WHICH(unset_security_enable, security_eol, none, "enable", "disable security function", 1, 3);
KW_NODE_WHICH(security_disable, security_eol, none, "disable", "disable security function", 1, 2);
KW_NODE_WHICH(security_enable, security_eol, security_disable, "enable", "enable security function(default)", 1, 1);
TEST_UNSET(test_unset_security, unset_security_enable, security_enable);
KW_NODE(security, test_unset_security, none, "security", "enable/disable security function");

void session_cli_init(void)
{
    add_set_cmd(&cnode(session));
    add_set_cmd(&cnode(security));
}

