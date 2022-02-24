
#include "session_util.h"
#include "session.h"



/* ���е�0״̬����ӦSESSION_BAK_STATE_INACTIVE */
CHAR *g_apcSessionStatusName[SESSION_L4_TYPE_MAX][SESSION_PROTOCOL_STATE_MAX] = 
{
	/* TCP */
	{
		"INACTIVE",
		"TCP_SYN_SENT",
		"TCP_SYN_RECV",
		"TCP_ESTABLISHED",
		"TCP_FIN_WAIT",
		"TCP_CLOSE_WAIT",
		"TCP_LAST_ACK",
		"TCP_TIME_WAIT",
		"TCP_CLOSE",
		"TCP_SYN_SENT2"
	},
	/* UDP */
	{
		"INACTIVE",
	    "UDP_OPEN",
	    "UDP_READY",
	    "", "", "", "", "", "", ""
	},
	/* ICMP */
    {
		"INACTIVE",
	    "ICMP_REQUEST",
	    "ICMP_REPLY",
	    "", "", "", "", "", "", ""
	},
	/* ICMPV6 */
    {
		"INACTIVE",
	    "ICMPV6_REQUEST",
	    "ICMPV6_REPLY",
	    "", "", "", "", "", "", ""
	},
	/* UDPLITE */
	{"INACTIVE", "", "", "", "", "", "", "", "", ""},
	/* SCTP */
	{"INACTIVE", "", "", "", "", "", "", "", "", ""},
	/* DCCP */
	{"INACTIVE", "", "", "", "", "", "", "", "", ""},
	/* RAWIP */
	{
		"INACTIVE",
	    "RAWIP_OPEN",
	    "RAWIP_READY",
	    "", "", "", "", "", "", ""
	}
};

#if 0
STATIC CHAR *g_apcProtocolName[SESSION_L4_TYPE_MAX] = 
{
	"TCP",
	"UDP",
	"ICMP",
	"ICMPV6",
	"UDP-Lite",
	"SCTP",
	"DCCP",
	"RAWIP"
};

STATIC CHAR *g_apcL4AgingStatusName[SESSION_PROT_AGING_MAX] =
{
	"SYN",
	"TCP-EST",
	"FIN",
	"UDP-OPEN",
	"UDP-READY",
	"ICMP-REQUEST",
	"ICMP-REPLY",
	"RAWIP-OPEN",
	"RAWIP-READY",
	"UDPLITE-OPEN",
	"UDPLITE-READY",
	"DCCP-REQUEST",
	"DCCP-EST",
	"DCCP-CLOSEREQ",
	"SCTP-INIT",
	"SCTP-EST",
	"SCTP-SHUTDOWN",
	"ICMPV6-REQUEST",
	"ICMPV6-REPLY"
};

STATIC UINT g_auiProtocolStateCount[SESSION_L4_TYPE_MAX] =
{
	TCP_ST_MAX,
    UDP_ST_MAX,
    ICMP_ST_MAX,
    ICMP_ST_MAX,
    UDPLITE_ST_MAX,
    SCTP_ST_MAX,
    DCCP_ST_MAX,
    RAWIP_ST_MAX
};

/* Ӧ�ò�Э��Ĭ���ϻ�ʱ�� */
static UINT g_auiAppDefaultAgingTime[SESSION_APP_AGING_MAX] =
{
	[SESSION_APP_AGING_DNS] = SESSION_PRO_DNS_TIME,
	[SESSION_APP_AGING_FTP]= SESSION_PRO_FTP_CTRL_TIME,
	[SESSION_APP_AGING_SIP]= SESSION_PRO_SIP_TIME,
	[SESSION_APP_AGING_RAS]= SESSION_PRO_RAS_TIME,
	[SESSION_APP_AGING_H225]= SESSION_PRO_H225_TIME,
	[SESSION_APP_AGING_H245]= SESSION_PRO_H245_TIME,
	[SESSION_APP_AGING_TFTP]= SESSION_PRO_TFTP_TIME,
	[SESSION_APP_AGING_GTP]= SESSION_PRO_GTP_TIME,
	[SESSION_APP_AGING_RTSP]= SESSION_PRO_RTSP_TIME,
	[SESSION_APP_AGING_PPTP] = SESSION_PRO_PPTP_TIME,
	[SESSION_APP_AGING_ILS] = SESSION_PRO_ILS_TIME,
	[SESSION_APP_AGING_NBT] = SESSION_PRO_NBT_TIME,
	[SESSION_APP_AGING_SCCP] SESSION_PRO_SCCP_TIME,
	[SESSION_APP_AGING_SQLNET]= SESSION_PRO_SQLNET_TIME,
	[SESSION_APP_AGING_XDMCP]= SESSION_PRO_XDMCP_TIME,
	[SESSION_APP_AGING_MGCP] = SESSION_PRO_MGCP_TIME,
	[SESSION_APP_AGING_RSH] = SESSION_PRO_RSH_TIME
};
#endif