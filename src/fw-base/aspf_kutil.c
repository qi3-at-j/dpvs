

#include "baseype.h"
#include "apr.h"
#include "icmp6.h"
#include "ip_icmp.h"
#include "session_mbuf.h"
#include "ip6fw.h"
#include "aspf_kutil.h"
#include "session.h"
#include "ip6_util.h"


#define ASPF_MAX_APP_NUM 4
#define ICMP_PKT_OTHER ICMP_PKT_MAX
#define ICMPV6_RANG_OFFSET 127

extern UCHAR g_aucIcmp6PktType[ICMP6_DHAAD_REPLY + 1 - ICMPV6_RANG_OFFSET];
/* 只考虑<=ICMP_MASKREPLY的type */
STATIC UCHAR g_aucAspfIcmpPktType[] = {
    ICMP_PKT_REPLY,         /* ICMP_ECHOREPLY      0  */
    ICMP_PKT_OTHER,         /*                        */
    ICMP_PKT_OTHER,         /*                        */
    ICMP_PKT_OTHER,         /* ICMP_UNREACH        3  */
    ICMP_PKT_OTHER,         /* ICMP_SOURCEQUENCH   4  */
    ICMP_PKT_OTHER,         /* ICMP_REDIRECT       5  */
    ICMP_PKT_OTHER,         /* ICMP_ALTHOSTADDR    6  */
    ICMP_PKT_OTHER,         /*                        */
    ICMP_PKT_REQUEST,       /* ICMP_ECHO           8  */
    ICMP_PKT_REPLY,         /* ICMP_ROUTERADVERT   9  */      
    ICMP_PKT_REQUEST,       /* ICMP_ROUTERSOLICIT  10 */
    ICMP_PKT_OTHER,         /* ICMP_TIMXCEED       11 */
    ICMP_PKT_OTHER,         /* ICMP_PARAMPROB      12 */
    ICMP_PKT_REQUEST,       /* ICMP_TSTAMP         13 */
    ICMP_PKT_REPLY,         /* ICMP_TSTAMPREPLY    14 */
    ICMP_PKT_REQUEST,       /* ICMP_IREQ           15 */
    ICMP_PKT_REPLY,         /* ICMP_IREQREPLY      16 */
    ICMP_PKT_REQUEST,       /* ICMP_MASKREQ        17 */    
    ICMP_PKT_REPLY,         /* ICMP_MASKREPLY      18 */
};

#if 0
/*只考虑[ICMP6_ECHO_REQUEST - 1, ICMP6_DHAAD_REPLY]之间的type，
  所以没有必要使用很大的数组来存放，所以将type-ICMPV6_RANG_OFFSET作为数组索引*/
STATIC UCHAR g_aucIcmp6PktType[ICMP6_DHAAD_REPLY + 1 - ICMPV6_RANG_OFFSET] = {
    ICMP_PKT_OTHER,    /*                        127                           */        
    ICMP_PKT_REQUEST,  /*ICMP6_ECHO_REQUEST      128  echo service             */    
    ICMP_PKT_REPLY,    /*ICMP6_ECHO_REPLY        129  echo reply               */
    ICMP_PKT_REQUEST,  /*ICMP6_MEMBERSHIP_QUERY  130  gruop membership query   */        
    ICMP_PKT_REPLY,    /*ICMP6_MEMBERSHIP_REPORT 131  gruop membership report  */    
    ICMP_PKT_OTHER,    /*                        132                           */        
    ICMP_PKT_OTHER,    /*                        133                           */            
    ICMP_PKT_OTHER,    /*                        134                           */        
    ICMP_PKT_OTHER,    /*                        135                           */     
    ICMP_PKT_OTHER,    /*                        136                           */            
    ICMP_PKT_OTHER,    /*                        137                           */        
    ICMP_PKT_OTHER,    /*                        138                           */     
    ICMP_PKT_REQUEST,  /*ICMP6_NI_QUERY          139  node information request */        
    ICMP_PKT_REPLY,    /*ICMP6_NI_REPLY          140  node information reply   */  
    ICMP_PKT_OTHER,    /*                        141                           */     
    ICMP_PKT_OTHER,    /*                        142                           */            
    ICMP_PKT_OTHER,    /*                        143                           */        
    ICMP_PKT_REQUEST,  /*ICMP6_DHAAD_REQUEST     144  DHAAD request            */        
    ICMP_PKT_REPLY,    /*ICMP6_DHAAD_REPLY       145  DHAAD reply              */   
};
#endif

/* ASPF支持的应用协议类型 */
typedef enum tagAspfAppidType
{
	ASPF_APPID_TYPE_FTP = 1,
	ASPF_APPID_TYPE_GTP,
	ASPF_APPID_TYPE_H323,
	ASPF_APPID_TYPE_RTSP,
	ASPF_APPID_TYPE_SIP,
	ASPF_APPID_TYPE_TFTP,
	ASPF_APPID_TYPE_ILS,
	ASPF_APPID_TYPE_MGCP,
    ASPF_APPID_TYPE_NBT,
	ASPF_APPID_TYPE_PPTP,
	ASPF_APPID_TYPE_RSH,
	ASPF_APPID_TYPE_SCCP,
	ASPF_APPID_TYPE_SQLNET,
	ASPF_APPID_TYPE_XDMCP,
	ASPF_APPID_TYPE_HTTP,
	ASPF_APPID_TYPE_SMTP,
	ASPF_APPID_TYPE_DNS,
	ASPF_APPID_TYPE_MAX
} ASPF_APPID_TYPE_E;

/*
STATIC UINT g_auiAppidRecord[ASPF_APPID_TYPE_MAX+1][ASPF_MAX_APP_NUM+1]=
{
	[ASPF_APPID_TYPE_FTP]  = {APP_ID_FTP,  0},
	[ASPF_APPID_TYPE_H323]  = {APP_ID_RAS, APP_ID_H225, APP_ID_H245, 0},
	[ASPF_APPID_TYPE_SIP]  = {APP_ID_SIP,  0},
	[ASPF_APPID_TYPE_TFTP]  = {APP_ID_TFTP,  0},
	[ASPF_APPID_TYPE_GTP]  = {APP_ID_GTPC,APP_ID_GTPU,APP_ID_GPRSDATA,APP_ID_GPRSSIG,0},
	[ASPF_APPID_TYPE_RSH]  = {APP_ID_RSH,  0},
	[ASPF_APPID_TYPE_RTSP]  = {APP_ID_RTSP,  0},
	[ASPF_APPID_TYPE_PPTP]  = {APP_ID_PPTP,  0},
	[ASPF_APPID_TYPE_ILS]  = {APP_ID_ILS,  0},
	[ASPF_APPID_TYPE_MGCP]  = {APP_ID_MGCPC, APP_ID_MGCPG, 0},
	[ASPF_APPID_TYPE_NBT]  = {APP_ID_NETBIOSNS, APP_ID_NETBIOSDGM, APP_ID_NETBIOSSSN, 0},
	[ASPF_APPID_TYPE_SCCP]  = {APP_ID_SCCP,  0},
	[ASPF_APPID_TYPE_SQLNET]  = {APP_ID_SQLNET,  0},
	[ASPF_APPID_TYPE_XDMCP]  = {APP_ID_XDMCP,  0},
	[ASPF_APPID_TYPE_HTTP]  = {APP_ID_HTTP,  0},
	[ASPF_APPID_TYPE_SMTP]  = {APP_ID_SMTP,  0},
	[ASPF_APPID_TYPE_DNS]  = {APP_ID_DNS,  0},
};*/


/* 根据报文的type 和code 判断是否是ICMP回应报文 */
BOOL_T ASPF_kutil_ipv4_IsIcmpReplay(IN UCHAR ucType, IN UCHAR ucCode)
{
    return ((ucType <= ICMP_MASKREPLY) && 
            (ICMP_PKT_REPLY == g_aucAspfIcmpPktType[ucType]) &&
            (0 == ucCode));
}


/* 根据报文的type和code判断是否是ICMPv6报文 */
BOOL_T ASPF_kutil_ipv6_IsIcmpv6Replay(IN UCHAR ucType, IN UCHAR ucCode)
{
	return ((ucType >= ICMP6_ECHO_REQUEST) &&
		    (ucType <= ICMP6_DHAAD_REPLY) &&
		    (ICMP_PKT_REPLY == g_aucIcmp6PktType[ucType - ICMPV6_RANG_OFFSET]) &&
		    (0 == ucCode));
}

/* 获取ipv6报文的l4的类型和偏移量 */
ULONG ASPF_kutil_ipv6_GetL4Proto(IN MBUF_S *pstMBuf,
                                 IN USHORT usL3Offset,
                                 OUT UCHAR *pucL4Proto,
                                 OUT USHORT *pusL4Offset)
{
    ULONG ulRet;
    IP6_S* pstIP6;
    UCHAR ucHdrProto;
    UINT uiHdrOff;

    pstIP6 = MBUF_BTOD_OFFSET(pstMBuf, usL3Offset, IP6_S *);
    uiHdrOff = sizeof(IP6_S) + usL3Offset;
    ucHdrProto = pstIP6->ip6_ucNxtHdr;

    ulRet = IP6_GetLastHdr(pstMBuf, &uiHdrOff, &ucHdrProto);
    if(ERROR_SUCCESS != ulRet)
    {
        return ERROR_FAILED;
    }

    *pucL4Proto = ucHdrProto;
    *pusL4Offset = (USHORT)uiHdrOff;

    return ERROR_SUCCESS;
}
								 
/********
Description∶根据报文的type和code判断是否是ICMPv6 ND报文
***/
STATIC BOOL_T aspf_kutil_ipv6Nd(IN UCHAR ucType, IN UCHAR ucCode)
{
	BOOL_T bIcmpv6Nd;

	if(0 != ucCode)
	{
		return BOOL_FALSE;
	}

	/*包括na、ns、ra、rs、redirect*/
	switch (ucType)
	{
		case ND_NEIGHBOR_SOLICIT:
		case ND_NEIGHBOR_ADVERT:
		case ND_ROUTER_SOLICIT:
		case ND_ROUTER_ADVERT:
		case ND_REDIRECT:
		{
			bIcmpv6Nd = BOOL_TRUE;
			break;
		}
		default:
		{
			bIcmpv6Nd = BOOL_FALSE;
			break;
		}
	}

	return bIcmpv6Nd;
}

/*** 判断是否为ND报文 ***/
BOOL_T ASPF_kutil_ipv6_IsIcmpv6Nd(IN MBUF_S *pstMBuf, IN USHORT usL3Offset)
{
	struct icmp6_hdr *pstIcmp6Hdr;
	UCHAR ucL4Proto;
	USHORT usL4Offset;
	BOOL_T bIcmpv6Nd = BOOL_FALSE;
	ULONG ulRet = ERROR_FAILED;

	ulRet = ASPF_kutil_ipv6_GetL4Proto(pstMBuf,usL3Offset,&ucL4Proto,&usL4Offset);
	if (ERROR_SUCCESS != ulRet)
	{
		return BOOL_FALSE;
	}

	if (IPPROTO_ICMPV6 == ucL4Proto)
	{
		pstIcmp6Hdr = MBUF_BTOD_OFFSET(pstMBuf,usL4Offset,struct icmp6_hdr *);
		bIcmpv6Nd = aspf_kutil_ipv6Nd(pstIcmp6Hdr->icmp6_type, pstIcmp6Hdr->icmp6_code);
	}

	return bIcmpv6Nd;
}

