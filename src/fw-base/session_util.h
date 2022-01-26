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

/* 判断是否有ipv6扩展头 */
STATIC inline BOOL_T _session6_KOptionHasNxtHdr(IN UCHAR ucNxtHdr)
{
	BOOL_T bExtHead = BOOL_FALSE;

	switch (ucNxtHdr) /* 当前IPv6扩展头类型 */
	{
		case IPPROTO_HOPOPTS: /* 逐跳扩展头 */
		case IPPROTO_DSTOPTS: /* 目的地扩展头 */
		case IPPROTO_ROUTING: /* 路由扩展头 */
		case IPPROTO_FRAGMENT:/* 分片扩展头 */
		{
			bExtHead = BOOL_TRUE;
			break;
		}
		default:
		{
			break;
		}
	}

	return bExtHead;
}

/* 计算ipv6扩展头长度 */
STATIC inline UINT _session6_KGetOptionLength(IN const struct ip6_ext *pstExtHdr)
{
	UINT uiOptHdrLen;

	DBGASSERT(NULL != pstExtHdr);

	if (IPPROTO_FRAGMENT == pstExtHdr->ip6e_nxt)
	{
		uiOptHdrLen = 8;
	}
	else if (IPPROTO_AH == pstExtHdr->ip6e_nxt)
	{
		uiOptHdrLen = ((UINT)pstExtHdr->ip6e_len + 2) << 2;
	}
	else
	{
		uiOptHdrLen = ((UINT)(pstExtHdr->ip6e_len) + 1) << 3;
	}

	return uiOptHdrLen;
}

#endif
