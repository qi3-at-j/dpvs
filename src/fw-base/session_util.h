#ifndef _SESSION_UTIL_H_
#define _SESSION_UTIL_H_

#include "baseype.h"
//#include "in.h"

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <rte_byteorder.h>

#if 0
#ifdef  _BIG_ENDIAN_
#define ntohs(x) (x)
#define htons(x) (x)
#define ntohl(x) (x)
#define htonl(x) (x)
#else
#define ntohs(x) rte_bswap16(x)
#define htons(x) rte_bswap16(x)
#define ntohl(x) rte_bswap32(x)
#define htonl(x) rte_bswap32(x)
#endif
#endif

#if 0
typedef struct tagSESSIONTempletInfo
{
    CHAR szTempletName[SESSION_CLI_TEMPLETNAME_LENGTH + 1];
}SESSION_TEMPELT_IFNO_S;

extern SESSION_TEMPELT_IFNO_S g_stSessionTempInfo[SESSION_TEMPLET_TYPE_MAX];
#endif

/*应用层老化时间特殊的App信息*/
#define SESSION_APP_AGING_COUNT 37 /*应用层老化时间特殊的App总数*/

typedef struct tagSessAppAgingTimeSpecial
{
	CHAR *pcStr;
	UINT uiTimeValue;
}SESS_AGINGSPECIAL_S;

typedef enum enSESSION_APP_DIS_TYPE
{
	SESSION_APP_DIS_STATIC_DNS = 0,
	SESSION_APP_DIS_STATIC_FTP,
	SESSION_APP_DIS_STATIC_GTP,
	SESSION_APP_DIS_STATIC_H323,
	SESSION_APP_DIS_STATIC_HTTP,
	SESSION_APP_DIS_STATIC_ILS,
	SESSION_APP_DIS_STATIC_MGCP,
	SESSION_APP_DIS_STATIC_NBT,
	SESsION_APP_DIS_STATIC_PPTP,
	SESSION_APP_DIS_STATIC_RSH,
	SESSION_APP_DIS_STATIC_RTSP,
	SESSION_APP_DIS_STATIC_SCGP,
	SESSION_APP_DIS_STATIC_SIP,
	SESSION_APP_DIS_STATIC_SMTP,
	SESSION_APP_DIS_STATIC_SQLNET,
	SESSION_APP_DIS_STATIC_SSH,
	SESSION_APP_DIS_STATIC_TELNET,
	SESSION_APP_DIS_STATIC_TFTP,
	SESSION_APP_DIS_STATIC_XDMCP,
	SESSION_APP_DIS_STATIC_MAX
}SESSION_APP_DIS_STATIC_TYPE_E;

#endif
