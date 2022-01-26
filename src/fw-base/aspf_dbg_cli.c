
#include <unistd.h>
#include <stdint.h>
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "debug_flow.h"
#include "baseype.h"
#include "session_mbuf.h"
#include "aspf.h"
#include "aspf_dbg_cli.h"
#include "fw_conf/aspf_policy_conf.h"


static int debug_aspf_cli(cmd_blk_t *cbt)
{	
	ASPF_CTRL_S *pstAspfCtrl;	
	
    if (!cbt) {
        RTE_LOG(ERR, FLOW, "%s: the cbt is NULL!\n", __func__);
        return -1;
    }

	pstAspfCtrl = ASPF_CtrlData_Get();

    if (cbt->mode & MODE_DO) 
	{
	    if (0 == (pstAspfCtrl->stDbgInfo.uiDbgSwitch & ASPF_DBG_BIT_PACKET))
	    {
	        printf("aspf packet debug is enabled\n");
	        pstAspfCtrl->stDbgInfo.uiDbgSwitch |= ASPF_DBG_BIT_PACKET;
	    }
    } 
	else if (cbt->mode & MODE_UNDO) 
	{
	    if (0 != (pstAspfCtrl->stDbgInfo.uiDbgSwitch & ASPF_DBG_BIT_PACKET)) 
		{
	        printf("aspf packet debug is disabled\n");
	        pstAspfCtrl->stDbgInfo.uiDbgSwitch &= ~ASPF_DBG_BIT_PACKET;
	    }
	}
	
    return 0;
}

EOL_NODE(debug_aspf_eol, debug_aspf_cli);

KW_NODE(aspf_packet, debug_aspf_eol, none, "packet", "enable/disable aspf packet debug");

KW_NODE(debug_aspf, aspf_packet, none, "aspf", "enable/disable aspf related debug");

static int show_aspf_debug(cmd_blk_t *cbt)
{	
	ASPF_CTRL_S *pstAspfCtrl;	
	UINT uiDbgSwitch;

	pstAspfCtrl = ASPF_CtrlData_Get();
	uiDbgSwitch = pstAspfCtrl->stDbgInfo.uiDbgSwitch; 

    tyflow_cmdline_printf(cbt->cl, "aspf status:\n");
    tyflow_cmdline_printf(cbt->cl, "\tdebug:\n");
    if (0 == uiDbgSwitch) 
	{
        tyflow_cmdline_printf(cbt->cl, "\t\tnone.\n");
    } 
	else 
	{
        if (0 != (uiDbgSwitch & ASPF_DBG_BIT_PACKET))
        {
            tyflow_cmdline_printf(cbt->cl, "\t\tpacket enabled.\n");
        }
  
    }
    return 0;
}


static int show_aspf_statics(cmd_blk_t *cbt)
{	
	ASPF_CTRL_S *pstAspfCtrl;	

	pstAspfCtrl = ASPF_CtrlData_Get();
	
    printf("Abnormal packets:\r\n");	
    printf(" First packet dropped because SYN check failed: %u\r\n",                  rte_atomic32_read(&pstAspfCtrl->astDropCount[ASPF_STAT_IPV4][ASPF_FTRST_SYN]));										   
    printf(" First packet of child session dropped because SYN check failed: %u\r\n", rte_atomic32_read(&pstAspfCtrl->astDropCount[ASPF_STAT_IPV4][ASPF_CHILD_SYN]));										   
    printf(" Packet matches no session dropped because SYN check failed: %u\r\n",     rte_atomic32_read(&pstAspfCtrl->astDropCount[ASPF_STAT_IPV4][ASPF_NOSESSION_SYN]));	
    printf(" Packet matches no session dropped by sec-policy: %u\r\n",                rte_atomic32_read(&pstAspfCtrl->astDropCount[ASPF_STAT_IPV4][ASPF_NOSESSION_PFLT]));
    printf(" Non-first packet dropped by sec-policy: %u\r\n",                         rte_atomic32_read(&pstAspfCtrl->astDropCount[ASPF_STAT_IPV4][ASPF_FIRST_PFLT]));
    printf(" Non-first packet dropped by sec-policy: %u\r\n",                         rte_atomic32_read(&pstAspfCtrl->astDropCount[ASPF_STAT_IPV4][ASPF_NOFIRST_PFLT]));
    printf(" First packet of child session dropped by sec-policy: %u\r\n",            rte_atomic32_read(&pstAspfCtrl->astDropCount[ASPF_STAT_IPV4][ASPF_CHILDFIRST_PFLT]));
    printf(" Non-first packet of child session dropped by sec-policy: %u\r\n",        rte_atomic32_read(&pstAspfCtrl->astDropCount[ASPF_STAT_IPV4][ASPF_NOCHILDFIRST_PFLT]));
    printf(" Non-first packet dropped because of config changes: %u\r\n",             rte_atomic32_read(&pstAspfCtrl->astDropCount[ASPF_STAT_IPV4][ASPF_NOFIRST_CFG_CHANGE]));
    printf(" Non-first packet dropped for invalid status: %u\r\n",                    rte_atomic32_read(&pstAspfCtrl->astDropCount[ASPF_STAT_IPV4][ASPF_NOFIRST_IV_STATUS]));
    printf(" Non-first packet of child session dropped for invalid status: %u\r\n",   rte_atomic32_read(&pstAspfCtrl->astDropCount[ASPF_STAT_IPV4][ASPF_CHILD_IV_STATUS]));
    printf(" First packet dropped for invalid status: %u\r\n",                        rte_atomic32_read(&pstAspfCtrl->astDropCount[ASPF_STAT_IPV4][ASPF_FIRST_IV_STATUS]));
    printf(" DIM packet deep inspect dropped: %u\r\n",                                rte_atomic32_read(&pstAspfCtrl->astDropCount[ASPF_STAT_IPV4][ASPF_PFLT_DIM]));

    return 0;
}


static int show_aspf_cfg(cmd_blk_t *cbt)
{		
	aspf_policy_conf_s *pstAspfPolicy;
	UINT32 uiVrf = 0;
	UINT64 uiCfgDetectFlag;

	uiVrf = cbt->number[0];
	pstAspfPolicy = aspf_policy_get_by_vrf(uiVrf);
	if (NULL == pstAspfPolicy)
	{
		printf("VRF %d :No Aspf Policy Cfg.\r\n", uiVrf);
	}
	else
	{		
		printf("VRF %d aspf-policy cfg:\r\n", uiVrf);
		uiCfgDetectFlag  = pstAspfPolicy->detect;
		if((uiCfgDetectFlag & ASPF_DETECT_FTP) != 0)
		{
			printf("    detect ftp enable\r\n");
		}
		else
		{
			printf("    detect ftp disable\r\n");
		}

		if (1 == pstAspfPolicy->bTcpSynCheck)
		{
			printf("    tcp syn-check enbale\r\n");
		}
		else
		{
			printf("    tcp syn-check disable\r\n");
		}
		
	}

    return 0;
}


EOL_NODE(aspf_cfg_eol, show_aspf_cfg);


/* used in set */
VALUE_NODE(aspf_cfg_vrf_value, aspf_cfg_eol, none, "vrf num", 1, NUM);
KW_NODE(aspf_cfg_vrf, aspf_cfg_vrf_value, none, "vrf", "vrf");
KW_NODE(aspf_cfg, aspf_cfg_vrf, none, "cfg", "show aspf cfg items");
EOL_NODE(aspf_statics_eol, show_aspf_statics);
KW_NODE(aspf_statics, aspf_statics_eol, aspf_cfg, "statics", "show aspf drop packet statics");
EOL_NODE(aspf_status_eol, show_aspf_debug);
KW_NODE(aspf_status, aspf_status_eol, none, "status", "show aspf debug status");
KW_NODE(aspf_debug, aspf_status, aspf_statics, "debug", "show aspf debug");
KW_NODE(show_aspf, aspf_debug, none, "aspf", "show aspf related items");



static int clear_aspf_statics_cli(cmd_blk_t *cbt)
{   
	ASPF_CTRL_S *pstAspfCtrl;	
	ASPF_DROP_TYPE_E enAspfDropType;

	pstAspfCtrl = ASPF_CtrlData_Get();

	for(enAspfDropType = ASPF_FTRST_SYN; enAspfDropType < ASPF_DROP_TYPE_MAX; enAspfDropType++)
	{
        rte_atomic32_set(&(pstAspfCtrl->astDropCount[ASPF_STAT_IPV4][enAspfDropType]), 0); 
	}

    return 0;	
}


EOL_NODE(clear_aspf_eol, clear_aspf_statics_cli);
KW_NODE(clear_aspf_statics, clear_aspf_eol, none, "statics", "clear aspf drop packet statics");
KW_NODE(clear_aspf, clear_aspf_statics, none, "aspf", "clear aspf related items");

void debug_aspf_init(void)
{
    add_debug_cmd(&cnode(debug_aspf));
    add_get_cmd(&cnode(show_aspf));	
    add_clear_cmd(&cnode(clear_aspf));

	return;
}

