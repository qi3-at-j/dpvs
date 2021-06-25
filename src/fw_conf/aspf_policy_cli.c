#include <stdio.h>
#include <assert.h>

#include "parser/flow_cmdline.h"
#include "fw_conf/fw_cli.h"
#include "fw_conf/aspf_policy_conf.h"
#include "fw_conf/aspf_policy_cli.h"

typedef enum _aspf_detect_type_ {
    aspf_detect_tftp = 1,
    aspf_detect_sip,
    aspf_detect_dns,
    aspf_detect_http,
    aspf_detect_ftp
} aspf_detect_type_e;

static int set_aspf_cli(cmd_blk_t *cbt)
{
    int vrf;

    vrf = cbt->number[0];

    tyflow_cmdline_printf(cbt->cl, "opt: %s\n", cbt->mode == MODE_DO ? "do":"undo");
    tyflow_cmdline_printf(cbt->cl, "vrf: %d\n", vrf); 
    if (cbt->which[0] == 1) {
        switch (cbt->which[1]) {
        case aspf_detect_ftp:
            tyflow_cmdline_printf(cbt->cl, "\tdetect ftp\n");
            aspf_policy_detect_modify(vrf, cbt->mode==MODE_DO, ASPF_DETECT_FTP);
            break;
        case aspf_detect_http:
            tyflow_cmdline_printf(cbt->cl, "\tdetect http\n");
            aspf_policy_detect_modify(vrf, cbt->mode==MODE_DO, ASPF_DETECT_HTTP);
            break;
        case aspf_detect_dns:
            tyflow_cmdline_printf(cbt->cl, "\tdetect dns\n");
            aspf_policy_detect_modify(vrf, cbt->mode==MODE_DO, ASPF_DETECT_DNS);
            break;
        case aspf_detect_sip:
            tyflow_cmdline_printf(cbt->cl, "\tdetect sip\n");
            aspf_policy_detect_modify(vrf, cbt->mode==MODE_DO, ASPF_DETECT_SIP);
            break;
        case aspf_detect_tftp:
            tyflow_cmdline_printf(cbt->cl, "\tdetect tftp\n");
            aspf_policy_detect_modify(vrf, cbt->mode==MODE_DO, ASPF_DETECT_TFTP);
            break;
        default:
            assert(0);
            break;
        }
    } else {
        switch (cbt->which[1]) {
        case 1: /* disable */
            if (cbt->mode == MODE_DO){ 
                tyflow_cmdline_printf(cbt->cl, "\ttcp-syn-check disable\n");
                aspf_policy_tcpsyn_check_modify(vrf, 0);
            } else {
                tyflow_cmdline_printf(cbt->cl, "\ttcp-syn-check enable\n");
                aspf_policy_tcpsyn_check_modify(vrf, 1);
            }
            break;
        case 2: /* enable */
            if (cbt->mode == MODE_DO){ 
                tyflow_cmdline_printf(cbt->cl, "\ttcp-syn-check enable\n");
                aspf_policy_tcpsyn_check_modify(vrf, 1);
            } else {
                tyflow_cmdline_printf(cbt->cl, "\ttcp-syn-check disable\n");
                aspf_policy_tcpsyn_check_modify(vrf, 0);
            }
            break;
        default:
            assert(0);
            break;
        }
    }

    return 0;
}

EOL_NODE(aspf_eol, set_aspf_cli);

KW_NODE_WHICH(check_enable,  aspf_eol, none,  "enable", "enable", 2, 2);
KW_NODE_WHICH(check_disable, aspf_eol, check_enable,  "disable",  "disable",  2, 1);

KW_NODE_WHICH(detect_ftp,  aspf_eol, none,        "ftp",  "detect ftp",  2, aspf_detect_ftp);
KW_NODE_WHICH(detect_http, aspf_eol, detect_ftp,  "http", "detect http", 2, aspf_detect_http);
KW_NODE_WHICH(detect_dns,  aspf_eol, detect_http, "dns",  "detect dns",  2, aspf_detect_dns);
KW_NODE_WHICH(detect_sip,  aspf_eol, detect_dns,  "sip",  "detect sip",  2, aspf_detect_sip);
KW_NODE_WHICH(detect_tftp, aspf_eol, detect_sip,  "tftp", "detect tftp", 2, aspf_detect_tftp);

KW_NODE_WHICH(tcp_syn_check, check_disable, none, "tcp-syn-check", "tcp syn check", 1, 2);
KW_NODE_WHICH(detect, detect_tftp, tcp_syn_check, "detect", "detect protocol", 1, 1);

KW_NODE(set_aspf, detect, none, "aspf-policy", "set aspf policy configure");

void aspf_policy_cli_init(void)
{
    vrf_add_set_cmd(&cnode(set_aspf));
    return;
}

