

#include <stdlib.h>
#include <ctype.h>

#include <rte_malloc.h>
#include <rte_memcpy.h>


#include "session.h"
#include "session_kcore.h"
#include "ac.h"
#include "session_kalg.h"
#include "session_kalg_ftp.h"
#include "session_kdebug.h"
#include "session_kl4proto.h"
#include "session_ktable.h"
#include "session_krelation.h"
#include "apr.h"
#include "general_rcu.h"

#define IN_LOOPBACK(a)   (((in_addr_t)(a) & 0xff000000) == 0x7f000000)

extern struct rte_mempool *g_apstRelationPool;

extern struct rte_mempool *g_apstRelation6Pool;

/* FTP模式匹配数组 */
ALG_FTP_PATTERNS_S g_astAlgFtpPatternsReg[] = 
{
	[ALG_FTP_USER_CMD]           = {(UCHAR *)"USER", 4, ALG_FTP_USER_CMD},
	[ALG_FTP_PASS_CMD]           = {(UCHAR *)"PASS", 4, ALG_FTP_PASS_CMD},
	/* 对于port命令，需区别是客户端真正的port命令，还是服务器方响应help发出的port解释，因此保留空格*/
	[ALG_FTP_PORT_CMD]           = {(UCHAR *)"PORT ", 4, ALG_FTP_PORT_CMD},
	[ALG_FTP_EPRT_CMD]           = {(UCHAR *)"EPRT ", 4, ALG_FTP_EPRT_CMD},
	[ALG_FTP_PASV_CMD]           = {(UCHAR *)"PASV",  4, ALG_FTP_PASV_CMD},
	[ALG_FTP_EPSV_CMD]           = {(UCHAR *)"EPSV",  4, ALG_FTP_EPSV_CMD},
	[ALG_FTP_TYPE_CMD]           = {(UCHAR *)"TYPE",  4, ALG_FTP_TYPE_CMD},
	[ALG_FTP_MODE_CMD]           = {(UCHAR *)"MODE",  4, ALG_FTP_MODE_CMD},
	[ALG_FTP_STRU_CMD]           = {(UCHAR *)"STRU",  4, ALG_FTP_STRU_CMD},
	[ALG_FTP_ACCT_CMD]           = {(UCHAR *)"ACCT",  4, ALG_FTP_ACCT_CMD},
	[ALG_FTP_ABOR_CMD]           = {(UCHAR *)"ABOR",  4, ALG_FTP_ABOR_CMD},		
	[ALG_FTP_SYST_CMD]           = {(UCHAR *)"SYST",  4, ALG_FTP_SYST_CMD},
	[ALG_FTP_HELP_CMD]           = {(UCHAR *)"HELP",  4, ALG_FTP_HELP_CMD},
	[ALG_FTP_NOOP_CMD]           = {(UCHAR *)"NOOP",  4, ALG_FTP_NOOP_CMD},
	[ALG_FTP_QUIT_CMD]           = {(UCHAR *)"QUIT",  4, ALG_FTP_QUIT_CMD},
	[ALG_FTP_AUTH_CMD]           = {(UCHAR *)"AUTH",  4, ALG_FTP_AUTH_CMD},
	[ALG_FTP_ADAT_CMD]           = {(UCHAR *)"ADAT",  4, ALG_FTP_ADAT_CMD},
	[ALG_FTP_FEAT_CMD]           = {(UCHAR *)"FEAT",  4, ALG_FTP_FEAT_CMD},
	[ALG_FTP_SEVERREADY_CODE]    = {(UCHAR *)"220",   3, ALG_FTP_SEVERREADY_CODE},
	[ALG_FTP_USER_LOGGED_CODE]   = {(UCHAR *)"331",   3, ALG_FTP_USER_LOGGED_CODE},
	[ALG_FTP_PASS_LOGGED_CODE]   = {(UCHAR *)"230",   3, ALG_FTP_PASS_LOGGED_CODE},
	[ALG_FTP_PORT_GOOD_CODE]     = {(UCHAR *)"200",   3, ALG_FTP_PORT_GOOD_CODE},
	[ALG_FTP_PASV_GOOD_CODE]     = {(UCHAR *)"227",   3, ALG_FTP_PASV_GOOD_CODE},		
	[ALG_FTP_EPSV_GOOD_CODE]     = {(UCHAR *)"229",   3, ALG_FTP_EPSV_GOOD_CODE},
	[ALG_FTP_FEAT_END_CODE]      = {(UCHAR *)"221 ",  4, ALG_FTP_FEAT_END_CODE},
	[ALG_FTP_ERROR_RESP_TOK]     = {(UCHAR *)"5",     1, ALG_FTP_ERROR_RESP_TOK},
	[ALG_FTP_FAIL_RESP_TOK]      = {(UCHAR *)"4",     1, ALG_FTP_FAIL_RESP_TOK},	
};

#define FTP_PORT_PASV_NUMBER 6       /* port命令的数字个数 */
#define FTP_PORT_PASV_NUMBER_IPV6 3  /* port命令的数字个数 */

#define SESSION_ALG_FTP_MAXPKT  100  /* 定义FTP报文负载的最大长度 */

typedef INT (*SESSION_FTP_GETPAYLOAD_PF)(IN CHAR *pcData,
                                         IN UINT uiDataLen,
                                         IN CHAR cTerm,
                                         INOUT SESSION_FTPALG_PAYLOAD_S *pstPayload);

typedef struct tagSessFtpSearch
{
	UCHAR ucPatLen;
	CHAR cSkip;
	CHAR cTerm;
	SESSION_FTP_GETPAYLOAD_PF pfGetPayload;
}SESSION_FTP_SEARCH_S;

STATIC INT _session_KFtp_PORTAndPASVCmd(IN CHAR *pcPayload,
	                                    IN UINT uiDataLen,
	                                    IN CHAR cTerm,
	                                    INOUT SESSION_FTPALG_PAYLOAD_S *pstPayload);

STATIC INT _session_KFtp_EPRTCmd(IN CHAR *pcPayload,
	                             IN UINT uiDataLen,
	                             IN CHAR cTerm,
	                             INOUT SESSION_FTPALG_PAYLOAD_S *pstPayload);

STATIC INT  _session_KFtp_EPSVCmd(IN CHAR *pcPayload,
	                              IN UINT uiDataLen,
	                              IN CHAR cTerm,
	                              INOUT SESSION_FTPALG_PAYLOAD_S *pstPayload);

#define FTP_PATTERN_TYPE 2
STATIC SESSION_FTP_SEARCH_S g_astSessFtpSearch[SESSION_DIR_BOTH][FTP_PATTERN_TYPE] =
{
	[SESSION_DIR_ORIGINAL] =
	{
	    {
			.ucPatLen     = sizeof("PORT") - 1,
			.cSkip        = ' ',
			.cTerm        = '\r',
			.pfGetPayload = _session_KFtp_PORTAndPASVCmd,
	    },
		{
			.ucPatLen     = sizeof("EPRT") - 1,
			.cSkip        = ' ',
			.cTerm        = '\r',
			.pfGetPayload = _session_KFtp_EPRTCmd,
	    },
	},
	
	[SESSION_DIR_REPLY] =
	{
	    {
			.ucPatLen     = sizeof("227 ") - 1,
			.cSkip        = '(',
			.cTerm        = ')',
			.pfGetPayload = _session_KFtp_PORTAndPASVCmd,
	    },
		{
			.ucPatLen     = sizeof("229 ") - 1,
			.cSkip        = '(',
			.cTerm        = ')',
			.pfGetPayload = _session_KFtp_EPSVCmd,
	    },
	},
};

STATIC AC_HANDLE g_hFTPProtocolTrie = AC_HANDLE_INVALID;

static inline UCHAR SESSION_KGetProto(IN SESSION_HANDLE hSession)
{
	csp_key_t *pstcspkey;
	
    pstcspkey = SESSION_KGetIPfsKey(hSession, SESSION_DIR_ORIGINAL);

	return pstcspkey->proto;
}

/****************************************************************************
Description:  业务模块挂扩展信息处理, 在session中有固定指针
Input: SESSION_HANDLE hSession,
	   SESSION MODULE_E enModule,   业务模块
       VOID *pExtInfo,              扩展信息
****************************************************************************/
static inline VOID SESSION_KAddStaticExtInfo(IN SESSION_HANDLE hSession, 
											 IN SESSION_MODULE_E enModule, IN VOID *pExtInfo)
{
	SESSION_S *pstSession = (SESSION_S *)hSession;
	
	/*smp_wmb();*/
	
	switch(enModule)
	{
		case SESSION_MODULE_ALG:  /*会话管理-ALG子模块 */
		{
			pstSession->pAlgCb = pExtInfo;
			break;
		}

		/*
		case SESSION_MODULE_LOG:
		{
			pstSession->stSession.pLogCb = pExtInfo;
			break;
		}
		*/

		default:
		{
			break;
		}
	}

	SESSION_TABLE_SET_ATTACHFLAG((SESSION_S *)pstSession,enModule);

	/* 输出Debug信息 */
	SESSION_DBG_EXT_EVENT_SWTICH((SESSION_S *)pstSession,enModule,EVENT_ADD);

	return;
}
					  
VOID *SESSION_ALG_FtpExtCreate(IN SESSION_HANDLE hSession, IN ULONG ulPara)
{
	ALG_FTP_EXT_S *pstFtpAlgExt;
	
	IGNORE_PARAM(ulPara);

	pstFtpAlgExt =(ALG_FTP_EXT_S *)rte_zmalloc("ftp_alg_ext", sizeof(ALG_FTP_EXT_S), 0);
	if (NULL != pstFtpAlgExt)
	{
		/*spin_lock_init(&pstFtpAlgExt->stLock);*/
		/* 加屏障防止被编译器优化导致加入未初始化指针 */
		/*smp_wmb();*/
		SESSION_KAddStaticExtInfo(hSession, SESSION_MODULE_ALG, pstFtpAlgExt);
	}
	return pstFtpAlgExt;
}

STATIC VOID _session_KFtp_SetSegmentFlag(IN SESSION_HANDLE hSession, IN SESSION_PKT_DIR_E enDir)
{
	ALG_FTP_EXT_S *pstAlgFtpExt;

	pstAlgFtpExt = SESSION_KGetExtInfoSafe(hSession, SESSION_MODULE_ALG, SESSION_ALG_FtpExtCreate, (ULONG)0);
	if(NULL != pstAlgFtpExt)
	{
		if(SESSION_DIR_ORIGINAL == enDir)
		{
			pstAlgFtpExt->ucOriginalSeg = BOOL_TRUE;
		}
		else if (SESSION_DIR_REPLY == enDir)
		{
			pstAlgFtpExt->ucReplySeg = BOOL_TRUE;
		}
	}

	return;
}

/* 重置分段标记 */
STATIC ULONG _session_KFtp_ResetSegmentFlag(IN SESSION_HANDLE hSession, IN SESSION_PKT_DIR_E enDir)
{
	ULONG ulRet = ERROR_SUCCESS;
	ALG_FTP_EXT_S *pstAlgFtpExt;

	pstAlgFtpExt = (ALG_FTP_EXT_S *)SESSION_KGetStaticExtInfo(hSession, SESSION_MODULE_ALG);
	if(NULL == pstAlgFtpExt)
	{
		return ulRet;
	}

	if((SESSION_DIR_ORIGINAL == enDir) && (BOOL_TRUE == pstAlgFtpExt->ucOriginalSeg))
	{
		pstAlgFtpExt->ucOriginalSeg = BOOL_FALSE;
		ulRet = ERROR_INCOMPLETE;
	}
	else if((SESSION_DIR_REPLY == enDir) && (BOOL_TRUE == pstAlgFtpExt->ucOriginalSeg))
	{
		pstAlgFtpExt->ucOriginalSeg = BOOL_FALSE;
		ulRet = ERROR_INCOMPLETE;
	}
	else if((SESSION_DIR_REPLY == enDir) && (BOOL_TRUE == pstAlgFtpExt->ucReplySeg))
	{
		pstAlgFtpExt->ucReplySeg = BOOL_FALSE;
		ulRet = ERROR_INCOMPLETE;
	}
	return ulRet;
}
					  
/* FTP报文的解码函数 */
static inline ULONG _session_KFtp_Decode(IN SESSION_HANDLE hSession,
                                         IN const CHAR *pcFtpLoad,
                                         IN UINT uiFtpLoadLen,
                                         IN SESSION_PKT_DIR_E enDir,
                                         OUT UINT *puiPid)
{
	ULONG ulRet;
	UCHAR *pucFtpLoad = (UCHAR *)pcFtpLoad;
	UCHAR *pucFtpLoadEnd = pucFtpLoad + (ULONG)uiFtpLoadLen;
	VOID *pLineEnd;

	/* 应用层分段不处理 */
	pLineEnd = SESSION_KAlg_memmem(pcFtpLoad, (ULONG)uiFtpLoadLen, "\n", (ULONG)1);
	if(NULL == pLineEnd)
	{
		_session_KFtp_SetSegmentFlag(hSession, enDir);
		return ERROR_INCOMPLETE;
	}
	ulRet = _session_KFtp_ResetSegmentFlag(hSession, enDir);
	if(ERROR_SUCCESS != ulRet)
	{
		return ulRet;
	}

	/* 进行AC模式匹配 */
	ulRet = ANCHORAC_Search(g_hFTPProtocolTrie, pucFtpLoad, pucFtpLoadEnd, puiPid);

	return ulRet;
}

								
/* 
Description: 从一个有间隔符和结束符的字符串中获取一组数字
      Input: CHAR *pcPayload   载荷字符串
             UINT uiDataLen    字符串长度
             CHAR cSep         匹配间隔符
             CHAR cTerm        匹配结束符
             INT  iArraySize   数组大小
     Output: UINT auiArray[]   获取到的数字数组
*/

STATIC INT _session_KFtp_GetNum(IN CHAR *pcPayload,
                                IN UINT uiDataLen,
                                IN CHAR cSep,
                                IN CHAR cTerm,
                                IN INT iArraySize,
                                OUT UINT auiArray[])
{
	INT iLoop;
	INT iLen;
	INT iLength;
	CHAR *pcData = pcPayload;
	CHAR cData;
	INT iNum;

	memset(auiArray, 0, (sizeof(UINT) * (UINT)iArraySize));

	/* Keep data pointing at next char. */
	for(iLoop = 0, iLen = 0; ((UINT)iLen < uiDataLen) && (iLoop < iArraySize); iLen++, pcData++)
	{
		cData = *pcData;
		if((cData >= ALG_FTP_ASCII_ZERO) && (cData <= '9'))
		{
			iNum = cData - ALG_FTP_ASCII_ZERO;
			auiArray[iLoop] = (auiArray[iLoop] * 10) + (UINT)iNum;
		}
		else if(cData == cSep) /* 匹配间隔符 */
		{
			iLoop++;
		}
		else if ((cData == cTerm) && (iLoop == iArraySize - 1)) /* 匹配结束符并且数组全部获取完成 */
		{
			iLength = iLen;
			break;
		}
		else
		{
			iLength = 0;
			break;
		}
	}

	return iLength;
}

/* 从一个有间隔符和结束符的字符串中获取一组数字 */
STATIC INT _session_KFtp_GetNumIPv6(IN CHAR *pcPayload,
                                    IN UINT uiDataLen,
                                    IN CHAR cSep,
                                    IN CHAR cTerm,
                                    OUT struct in6_addr *pstDst,
                                    OUT USHORT *pusPort)
{
	INT iLoop;
	INT iLen;
	INT iLength = 0;
	CHAR *pcData = pcPayload;
	CHAR cData;
	INT iRet = 0;
	INT iIndex = 0;
	INT iArraySize = FTP_PORT_PASV_NUMBER_IPV6;
	UINT uiPortHigh = 0;
	UINT uiPortLow  = 0;
	CHAR szAddrArray[FTP_PORT_PASV_NUMBER_IPV6][INET6_ADDRSTRLEN];

	memset(szAddrArray, 0, sizeof(szAddrArray));

	/* Keep data pointing at next char. */
	for(iLoop = 0, iLen = 0; ((UINT)iLen < uiDataLen) &&(iLoop < iArraySize); iLen++, pcData++)
	{
		cData = *pcData;
		/* IPv6地址采用冒号十六进制记法 */
		if(((cData >= ALG_FTP_ASCII_ZERO) && (cData <= '9')) ||
		   ((cData >= 'a') && (cData <= 'f')) ||
		   ((cData >= 'A') && (cData <= 'F')) ||
		   cData == ':')
		{
			szAddrArray[iLoop][iIndex] = cData;
			iIndex ++;
			if(INET6_ADDRSTRLEN == iIndex)
			{
				/* 超出地址范围，返回错误 */
			    iLength = 0;
				break;
			}
		}
	    else if (cData == cSep) /* 匹配间隔符 */
	    {
			iLoop++;
			iIndex = 0;
	    }
		else if ((cData == cTerm) && (iLoop == iArraySize - 1)) /* 匹配结束符并且数组全部获取完成 */
		{
			iLength = iLen;
			break;
		}
		else
		{
			iLength = 0;
			break;
		}  
	}

	if(0 != iLength)
	{
		/*
		uiPortHigh = (UINT)simple_strtol(szAddrArray[1], NULL, 10);
		uiPortLow  = (UINT)simple_strtol(szAddrArray[2], NULL, 10);
		*/

	    uiPortHigh = (UINT)strtol(szAddrArray[1], NULL, 10);
		uiPortLow  = (UINT)strtol(szAddrArray[2], NULL, 10);
		*pusPort   = (USHORT)((uiPortHigh << 8) | uiPortLow);

		iRet = inet_pton(AF_INET6, szAddrArray[0], pstDst);
		if(1 != iRet)
		{
			return 0;
		}
	}

	return iLength;
}

/* 解析port命令和pasv命令携带的数据*/
STATIC INT _session_KFtp_PORTAndPASVCmd(IN CHAR *pcPayload,
                                        IN UINT uiDataLen,
                                        IN CHAR cTerm,
                                        INOUT SESSION_FTPALG_PAYLOAD_S *pstPayload)
{
	INT iLength;
	UINT auiArray[FTP_PORT_PASV_NUMBER]; /* 用于获取IPv4载荷中携带的数据 */
	struct in6_addr stAddr6;                   /* 用于获取IPv6载荷中的IP地址 */
	USHORT usPort6 = 0;                  /* 用于获取IPV6载荷中的端口 */

	if(AF_INET == pstPayload->ucFamily)
	{
		iLength = _session_KFtp_GetNum(pcPayload, uiDataLen, ',', cTerm, FTP_PORT_PASV_NUMBER, auiArray);
		if(0 != iLength)
		{
			pstPayload->unIp.uiIp = htonl((auiArray[0] << 24) |
				                          (auiArray[1] << 16) |
				                          (auiArray[2] << 8)  |
				                          auiArray[3]);
			
			pstPayload->unPort.usAll = (USHORT)htons((USHORT)((auiArray[4] << 8) | auiArray[5]));
			
		}
	}
	else
	{
		iLength = _session_KFtp_GetNumIPv6(pcPayload, uiDataLen, ',', cTerm, &stAddr6, &usPort6);
		if(0 != iLength)
		{
			pstPayload->unIp.stin6 = stAddr6;
			pstPayload->unPort.usAll = htons(usPort6);
		}
	}

	return iLength;
}

/* 
Description: 从字符串识别IPv6地址 
      Input: CHAR *pcSrc       输入字符串
             UINT uiDataLen    字符串长度
     Output: IN6ADDR_S *pstDst 转换后的ipv6地址
     Return: 0                 字符串不合法
             其他                ipv6地址
*/
STATIC UINT _session_KFtp_GetIpv6Addr(IN const CHAR *pcSrc,
                                      IN UINT uiDataLen,
                                      OUT struct in6_addr *pstDst)
{
	INT iRet;
	UINT uiAddrLen;
	CHAR cValue;
	CHAR szIPStr[INET6_ADDRSTRLEN];

	for(uiAddrLen = 0; uiAddrLen < uiDataLen; uiAddrLen++)
	{
		cValue = *(pcSrc + uiAddrLen);
		if (!isxdigit(cValue) && (cValue != ':') && (cValue != '.'))
		{
			break;
		}
	}
	if ((0 == uiAddrLen) || (uiAddrLen >= uiDataLen))
	{
		/* 字符串不合法，没有找到地址串结束符 */
	    return 0;
	}

	if(uiAddrLen >= sizeof(szIPStr))
	{
		return 0;		
	}

	memcpy(szIPStr, pcSrc, (size_t)uiAddrLen);
	szIPStr[uiAddrLen] = '\0';

	iRet = inet_pton(AF_INET6, szIPStr, pstDst);

	if(1 != iRet)
	{
		return 0;
	}

	return uiAddrLen;
}

/*
Description: 更新端口号和长度 
      Input: iLoop,     函数调用者的端口号
             usTmpPort, 获取出的端口号
     Output: pusPort,   需要返回的端口号
             piLength,  长度 
*/
STATIC inline VOID _session_KFtpUpdataPortAndLen(IN INT iLoop,
                                                 IN USHORT usTmpPort,
                                                 OUT USHORT *pusPort,
                                                 OUT INT *piLength)
{
	if(0 != iLoop)
	{
		/* get_port: return tmp_port. */
	    *pusPort = htons(usTmpPort);
		*piLength = iLoop + 1;
	}

	return;
}

/*
Description: 从一个有结束符的字符串中获取数字作为端口
      Input: pcPayload       载荷字符串
             uiDataLen       字符串长度
             cDelim          分隔符
             cTerm           结束符
     Output: USHORT *pusPort 获取到的端口号
     Return：0                获取端口号失败
             其他              获取端口号成功
*/
STATIC INT SESSION_KFtp_GetPort(IN CHAR *pcPayload,
                         IN UINT uiDataLen,
                         IN CHAR cDelim,
                         IN CHAR cTerm,
                         OUT USHORT *pusPort)
{
	CHAR *pcData = pcPayload;
	USHORT usTmpPort = 0;
	INT iLoop;
	CHAR cData;
	SHORT sNum;
	INT iLength = 0;

	for(iLoop = 0; (UINT)iLoop < uiDataLen; iLoop++)
	{
		/* Finished? */
	    cData = pcData[iLoop];
		if(cData == cDelim)
		{
			/* ASPF */
		    _session_KFtpUpdataPortAndLen(iLoop, usTmpPort, pusPort, &iLength);
			/* 如果第一个字符就是分隔符则出错ILength默认是0 */
			break;
		}
		else if ((cData >= ALG_FTP_ASCII_ZERO) && (cData <= '9'))
		{
			sNum = cData - ALG_FTP_ASCII_ZERO;
			usTmpPort = (USHORT)(usTmpPort * 10 + sNum);
		}
		else /* Some other crap */
		{
			/* get_port: invalid char.*/
		    iLength = 0;
			break;
		}
	}

	/* ASPF */
	/* 判断结束字符是否为\r */
	iLoop += 1;
	cData = pcData[iLoop];
	if(((UINT)iLoop >= uiDataLen) || (cData != cTerm))
	{
		iLength = 0;
	}

	return iLength;
}

/* 解析EPRT命令携带的数据 */
STATIC INT _session_KFtp_EPRTCmd(IN CHAR *pcPayload,
                                 IN UINT uiDataLen,
                                 IN CHAR cTerm,
                                 INOUT SESSION_FTPALG_PAYLOAD_S *pstPayload)
{
	CHAR *pcData = pcPayload;
	CHAR cDelim;
	CHAR cDelim2;
	CHAR cFlag;
	UINT uiLeftLen = uiDataLen;
	INT iLength;
	INT iPayloadLen;

	/* First character is delimiter, then "1" for IPv4 or "2" for IPv6,
	   then delimiter again. */
    if(uiDataLen <= 3)
    {
		/* EPRT: too short */
	    return 0;
    }

	/* 分段符检查:分段符不能为数字，必须为有效的ASCII码，并且标识V4、V6字段的前后两个分段符必须相同 */
	cDelim = *pcData; /**/
	pcData++;
	uiLeftLen--;
	cFlag = *pcData; /* 第二个字符标识是ipv4还是ipv6 */
	pcData++;
	uiLeftLen--;
	cDelim2 = *pcData; /* 取第二个分隔符 */
	pcData++;
    uiLeftLen--;

	if(isdigit(cDelim) || (cDelim < '!') || (cDelim > '~') || (cDelim2 != cDelim))
	{
		/* try_eprt: invalid delimitter. */
	    return 0;
	}

	/* 检查EPORT命令中family填写与会话表中记录是否一致，
	   禁止发起方为IPv6的EPORT命令携带IPv4地址，也禁止发起方为IPv4的EPROT命令携带IPv6地址 */
    if(((PF_INET  == pstPayload->ucFamily) && (cFlag != '1')) || 
	   ((PF_INET6 == pstPayload->ucFamily) && (cFlag != '2')))
    {
		/* EPRT: invalid protocol number. */
	    return 0;
    }

    /* EPRT: Got %c%c%c\n", delim, data[1], delim. */
    if(cFlag == '1')
    {
		UINT auiArray[4];

		/* Now we have IP address. */
		iLength = _session_KFtp_GetNum(pcData, uiLeftLen, '.', cDelim, 4, auiArray);
		if(iLength != 0)
		{
			pstPayload->unIp.uiIp = htonl((auiArray[0] << 24) |
				                          (auiArray[1] << 16) |
				                          (auiArray[2] << 8)  |
				                          auiArray[3]);
		}
    }
	else
	{
		/* Now we have IPv6 address. */
	    iLength = (INT)_session_KFtp_GetIpv6Addr(pcData, uiLeftLen, &pstPayload->unIp.stin6);
	}
	
	if(iLength == 0)
	{
		return 0;
	}

	/* EPRT: Got IP address! */

	pcData += iLength; /* 便宜到地址之后 */
	uiLeftLen -= (UINT)iLength;
	cDelim2 = *pcData; /* 取第三个分隔符 */
	if(cDelim2 != cDelim)
	{
		return 0;
	}
	pcData++; /* 偏移过地址之后的分隔符 */
	uiLeftLen--;

	/* Start offset includes initial "|1|", and trailing delimiter */
	iLength = SESSION_KFtp_GetPort(pcData, uiLeftLen, cDelim, cTerm, &pstPayload->unPort.usAll);
	if(iLength == 0)
	{
		return 0;
	}

	uiLeftLen -= (UINT)iLength;

	/* 返回命令数据总长度 */
	iPayloadLen = (INT)uiDataLen - (INT)uiLeftLen;

	return iPayloadLen;
}

STATIC INT _session_KFtp_EPSVCmd(IN CHAR * pcPayload, 
                                 IN UINT uiDataLen,
                                 IN CHAR cTerm, 
                                 INOUT SESSION_FTPALG_PAYLOAD_S * pstPayload)
{
	CHAR cDelim;
	CHAR cDelim2;
	CHAR cDelim3;
	CHAR *pcData = pcPayload;
	UINT uiLeftLen = uiDataLen;
	INT  iPayloadLen;
	INT  iLength;

	/* Three delimiters. */
	if(uiDataLen <= 3)
	{
		return 0;
	}

	cDelim = *pcData; /* 取首字符作为标准分隔符 */
	pcData++;
	uiLeftLen--;
	cDelim2 = *pcData; /* 取第二个分隔符 */
	pcData++;
	uiLeftLen--;
	cDelim3 = *pcData; /* 取第三个分隔符 */
	pcData++;
	uiLeftLen--;

	/* 分隔符合法性检查 */
	if(isdigit(cDelim) || (cDelim < '!') || (cDelim > '~') ||
	   (cDelim2 != cDelim) || (cDelim3 != cDelim))
	{
		return 0;
    }

    iLength = SESSION_KFtp_GetPort(pcData, uiLeftLen, cDelim, cTerm, &pstPayload->unPort.usAll);
	if(iLength == 0)
	{
		return 0;		
	}
	
	uiLeftLen -= (UINT)iLength;

	iPayloadLen = (INT)uiDataLen - (INT)uiLeftLen;

	return iPayloadLen;
}
								 
										
/* 从载荷匹配FTP命令 */
STATIC ULONG _session_KFtp_CheckPattern(IN CHAR * pcPayload,
                                        IN UINT uiDataLen,
                                        IN ALG_FTP_PATTERN_E enPattern,
                                        INOUT SESSION_FTPALG_PAYLOAD_S *pstPayload,
                                        OUT UINT *puiNumoff,
                                        OUT UINT *puiNumlen,
                                        OUT SESSION_ALG_FTP_TYPE_E *penFTPType)
{
	UINT uiIndex;
	CHAR *pcData = pcPayload;
	INT iNumLen;
	UINT uiPatLen;
	CHAR cSkip;
	SESSION_FTP_GETPAYLOAD_PF pfCmdProc;
	SESSION_FTP_SEARCH_S *pstSearchObj;
	ULONG ulRet = ERROR_SUCCESS;

	if(ALG_FTP_PORT_CMD == enPattern)
	{
		pstSearchObj = &g_astSessFtpSearch[SESSION_DIR_ORIGINAL][0];
		*penFTPType = SESSION_FTP_PORT;
	}
	else if(ALG_FTP_EPRT_CMD == enPattern)
	{
		pstSearchObj = &g_astSessFtpSearch[SESSION_DIR_ORIGINAL][1];
		*penFTPType = SESSION_FTP_EPRT;
	}
	else if(ALG_FTP_PASV_GOOD_CODE == enPattern)
	{
		pstSearchObj = &g_astSessFtpSearch[SESSION_DIR_REPLY][0];
		*penFTPType = SESSION_FTP_PASV;
	}
	else if(ALG_FTP_EPSV_GOOD_CODE == enPattern)
	{
		pstSearchObj = &g_astSessFtpSearch[SESSION_DIR_REPLY][1];
		*penFTPType = SESSION_FTP_EPSV;
	}
	else
	{
		return ERROR_NOTSUPPORT;
	}

	/* Pattern matches! */
	/* Now we've found the constant string, try to skip to the 'skip' character */
	cSkip = pstSearchObj->cSkip;
	uiPatLen = (UINT) pstSearchObj->ucPatLen;
	for(uiIndex = uiPatLen; pcData[uiIndex] != cSkip; uiIndex++)
	{
		if(uiIndex == uiDataLen -1)
		{
			ulRet = ERROR_FAILED;
			break;
		}
	}

	if(ERROR_SUCCESS != ulRet)
	{
		return ERROR_FAILED;
	}

	/* Skip over the last character */
	uiIndex++;

	/* Skipped up to 'skip' ! */
	pfCmdProc = pstSearchObj->pfGetPayload;
	iNumLen = pfCmdProc(pcData +uiIndex, uiDataLen - uiIndex, pstSearchObj->cTerm, pstPayload);
	if( iNumLen <=0 )
	{
		return ERROR_FAILED;
	}

	*puiNumlen = (UINT)iNumLen;
	*puiNumoff = uiIndex;

	/* Match succeeded! */
	return ERROR_SUCCESS;
}

/* Check unicast address validity. */
static inline BOOL_T INADDR_IsValidUCAddr(IN UINT32 uiIPAddr)
{
	if((INADDR_BROADCAST == uiIPAddr) || (INADDR_ANY == uiIPAddr))
	{
		return BOOL_FALSE;
	}

	/* 排除非法地址，0.0.0.1等 */
	if(IN_CLASSA(uiIPAddr))
	{
		if(0 == (uiIPAddr & IN_CLASSA_NET))
		{
			return BOOL_FALSE;
		}
	}

	if(IN_CLASSA(uiIPAddr) || IN_CLASSB(uiIPAddr) || (IN_CLASSC(uiIPAddr)))
	{
		return BOOL_TRUE;
	}

	return BOOL_FALSE;
}

STATIC ULONG SESSION_KFtp_CheckIpEqual(IN const SESSION_S *pstSession,
                                IN const csp_key_t *pstCspKey,
                                IN const SESSION_FTPALG_PAYLOAD_S *pstPayload,
                                IN ALG_FTP_PATTERN_E enPattern)
{
	ULONG ulRet = ERROR_SUCCESS;
	UINT uiIP = ntohl(pstPayload->unIp.uiIp);

	switch (enPattern)
	{
		case ALG_FTP_PORT_CMD:
	    case ALG_FTP_EPRT_CMD:
		{
			/* 检查PORT命令中的IP地址合法性 */
		    if((BOOL_TRUE != INADDR_IsValidUCAddr(uiIP)) || (IN_LOOPBACK(uiIP)))
		    {
				ulRet = ERROR_FAILED;
		    }
			break;
	    }
		case ALG_FTP_PASV_GOOD_CODE:
		{
			/* 检查PASV命令中的IP地址与报文源地址是否相同 */
		    if(pstPayload->unIp.uiIp != pstCspKey->src_ip)
		    {
				ulRet = ERROR_FAILED;
		    }
			break;
		}
		default:
		{
			/*
			SESSION_DBG_ALG_EVENT_ARGS(pstSession, "\r\n Ignore whether the packet's IP is correct. Packet type: %u", enPattern);
			*/
			break;
		}
		
	}

	return ulRet;
}

STATIC VOID _session_KFtp_InitRelation(IN RELATION_S *pstRelation,
                                       IN SESSION_S *pstSession,
                                       IN const SESSION_FTPALG_PAYLOAD_S *pstPayload,
                                       IN SESSION_PKT_DIR_E enDir,
                                       IN SESSION_ALG_FTP_TYPE_E enFTPType)
{
	csp_key_t *pstRelaKey;
	UINT uiMask = 0;
	SESSION_PKT_DIR_E enInvertDir;
	csp_key_t *pstIpfsCacheKey;

	STATIC SESSION_CHILD_DIR_E aenChildDir[SESSION_FTP_MAX] = 
	{
		[SESSION_FTP_PORT] = DIR_PARENT_DST_2_SRC,
		[SESSION_FTP_PASV] = DIR_PARENT_SRC_2_DST,
		[SESSION_FTP_EPRT] = DIR_PARENT_DST_2_SRC,
		[SESSION_FTP_EPSV] = DIR_PARENT_SRC_2_DST,
	};

	pstRelaKey = &pstRelation->stTupleHash.stIpfsKey;
	pstRelaKey->dst_ip   = pstPayload->unIp.uiIp;
	pstRelaKey->dst_port = pstPayload->unPort.usAll;

	enInvertDir = SESSION_GetInvertDir(enDir);
	pstIpfsCacheKey = SESSION_KGetIPfsKey((SESSION_HANDLE)pstSession, enInvertDir);
	if(NULL == pstIpfsCacheKey)
	{
		return;
	}

	pstRelaKey->src_ip = pstIpfsCacheKey->src_ip;
	pstRelaKey->proto  = pstIpfsCacheKey->proto;
	
	/*
	pstRelaKey->vrfIndex = pstIpfsCacheKey->vrfIndex;
	pstRelaKey->uiTunnelID = pstIpfsCacheKey->uiTunnelID;
	pstRelaKey->usMDCID = pstIpfsCacheKey->usMDCID;
	pstRelaKey->ucType = pstIpfsCacheKey->ucType;
	*/

	SESSION_SET_PARABIT(uiMask, SESSION_TUPLE_MASK_IP);
	pstRelation->stTupleHash.uiMask = uiMask;
	pstRelation->uiAppID = APP_ID_FTPDATA; /* 数据通道会话的APPID是FTPDATA */
	pstRelation->pstParent = pstSession;
	pstRelation->enChildDir = aenChildDir[enFTPType];
	pstRelation->bCareParentFlag = BOOL_TRUE;

	/*pstRelation->stRcu.pfCallback = SESSION_Relation_Destroy;*/

	return;
}

/**************************************************************************
Description:  FTP ALG处理主流程
****************************************************************************/
STATIC ULONG _session_KFtpAlgProc(IN MBUF_S *pstMBuf,
								  IN UINT uiL3OffSet,
								  IN UINT uiL4OffSet,
								  IN SESSION_HANDLE hSession)
{
	SESSION_FTPALG_PAYLOAD_S stPayload;
	RELATION_S *pstRelation;
	UINT uiPayloadOff;
	UINT uiPayloadLen;
	CHAR *pcFtpData;
	UCHAR ucProtocol;
	ULONG ulRet = ERROR_SUCCESS;
	SESSION_PKT_DIR_E enDir; 	
	csp_key_t *pstCspKey;
	UINT uiNumOff; 
	UINT uiNumLen;
	ALG_FTP_PATTERN_E enPattern = ALG_FTP_IGR_RESP;
	SESSION_ALG_FTP_TYPE_E enFTPType;
	SESSION_S *pstSession = (SESSION_S *)hSession;
    UINT uiDpIndex; 
    CHAR *pcNewFtpData;


	/* 获取载荷偏移, 完成字节序转换 */ 
	ucProtocol = SESSION_KGetProto(hSession); 
	if (IPPROTO_TCP != ucProtocol) /* 暂时仅支持TCP */
	{
		SESSION_KAlgFailInc(SESSION_ALG_STAT_TYPE_FTP, SESSION_ALG_FAIL_NOTSUPPORT_PROTOCOL);
		return ERROR_NOTSUPPORT;
	}

	enDir = SESSION_GetDirFromMBuf(pstMBuf);
	ulRet = SESSION_KGetValidL4Payload(pstMBuf, ucProtocol, uiL4OffSet, &uiPayloadOff, &uiPayloadLen);
	if ((ERROR_SUCCESS != ulRet) || (0 == uiPayloadLen))
	{
		SESSION_KAlgFailInc(SESSION_ALG_STAT_TYPE_FTP, SESSION_ALG_FAIL_GET_PAYLOAD_FAILED);
		return ERROR_NOTSUPPORT;
	}

	pcFtpData = MBUF_BTOD_OFFSET(pstMBuf, uiPayloadOff, CHAR *);

    /* 如果结尾的\r\n前面还有其它的\r\n的话将其跨过去 */
	pcNewFtpData = pcFtpData;
    for (uiDpIndex = 0; uiPayloadLen > uiDpIndex+2; uiDpIndex++)
    {
    	if (0x0a == pcFtpData[uiDpIndex] || 0x0d == pcFtpData[uiDpIndex])
    	{
    		pcNewFtpData = pcFtpData + uiDpIndex + 1;
    	}
    }
    uiPayloadLen -= (pcNewFtpData - pcFtpData); 
    uiPayloadOff += (pcNewFtpData - pcFtpData); 
    pcFtpData = pcNewFtpData;
	

	ulRet = _session_KFtp_Decode(hSession, pcFtpData, uiPayloadLen, enDir, (UINT *)(&enPattern));
	if (ERROR_SUCCESS != ulRet)
	{
		if (ERROR_INCOMPLETE == ulRet)
		{
			return ERROR_NOTSUPPORT;
		}
		/* 解码失败有可能是半匹配也有可能是遇到了无法识别的命令, 这里做忽略处理 
		SESSION_DBG_ALG_EVENT_ARGS((SESSION_S *)pstSession, "\r\n FTP: Ignore the partly matched command.");*/
		enPattern = ALG_FTP_IGR_RESP;
	}

	/* 预填写载荷信息字段 */
	memset(&stPayload, 0, sizeof(stPayload));
	stPayload.ucFamily = AF_INET;
	pstCspKey = SESSION_KGetIPfsKey(hSession,enDir);

	stPayload.unIp.uiIp = pstCspKey->src_ip;

	ulRet = _session_KFtp_CheckPattern(pcFtpData, uiPayloadLen, enPattern, &stPayload,
									   &uiNumOff, /* IP地址相对于pcFtpData位置的偏移 */
									   &uiNumLen, /* IP地址的ASCII长度 */
									   &enFTPType);
	if (ERROR_SUCCESS != ulRet)
	{
		if(ERROR_NOTSUPPORT != ulRet)
		{
			SESSION_DBG_ALG_ERROR_SWITCH(pstSession, DBG_ALG_ERROR_DECODE);
			SESSION_KAlgFailInc(SESSION_ALG_STAT_TYPE_FTP, SESSION_ALG_FAIL_DECODE_FAILED);
		}

		return ulRet;
	}

	ulRet = SESSION_KFtp_CheckIpEqual(pstSession, pstCspKey, &stPayload, enPattern);
	if (ERROR_SUCCESS != ulRet)
	{
		SESSION_DBG_ALG_ERROR_SWITCH(pstSession, DBG_ALG_ERROR_IP);
		return ulRet;
	}

	pstRelation = SESSION_Relation_Create(); 
	if (NULL == pstRelation)
	{
		SESSION_DBG_RELATION_ERROR_SWTICH(ERROR_RELATION_MEMORY_NOT_ENOUGH);
		SESSION_KAlgFailInc(SESSION_ALG_STAT_TYPE_FTP, SESSION_ALG_FAIL_ALLOC_RELATION);
		return ERROR_NOTSUPPORT;
	}

	_session_KFtp_InitRelation(pstRelation, pstSession, &stPayload, enDir, enFTPType);


	/* 关联表正式化处理 */
	ulRet = SESSION_Relation_Add(pstRelation,
								 pstSession,
								 RELATION_AGING_TYPE_FTPDATA);
	if (ERROR_SUCCESS != ulRet)
	{
		SESSION_KAlgFailInc(SESSION_ALG_STAT_TYPE_FTP, SESSION_ALG_FAIL_ADD_RELATION_HASH);
		
		/* 关联表可能加Local hash失败, 需要使用rcu释放 
		RCU_Call(&pstRelation->stRcu);*/
		
		general_rcu_qsbr_dq_enqueue((void *)pstRelation, SESSION_Relation_Destroy);		
	}
	else
	{
		/* 关联表正式化成功, 需要发送备份消息 */ 
	    ;
	}

	return ERROR_SUCCESS;
}

/******************************************************************
   Func Name:IN6ADDR_Cmp
Date Created:2021/04/25
      Author:wangxiaohua
 Description:比较IPv6地址大小
       INPUT:pstAddr1:待比较地址1
             pstAddr2:带比较地址2
      Output:无
      Return:大于0:地址1大于地址2
             小于0:地址1小于地址2
             等于0:地址1等于地址2
     Caution:IPV6地址按网络序输入
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline INT IN6ADDR_Cmp(IN const struct in6_addr *pstAddr1, IN const struct in6_addr *pstAddr2)
{
    UINT i;
    INT iRet;

    for(i=0; i < INET_ADDRSTRLEN; i++)
    {
        iRet = pstAddr1->s6_addr[i] - pstAddr2->s6_addr[i];
        if(0 != iRet)
        {
            break;
        }
    }

    return iRet;
}

/*****************************************************************************
Description∶ IPv6地址合法性检查函数
*****************************************************************************/
STATIC BOOL_T _session_KFtp_CheckIPv6Addr(IN const struct in6_addr *pstIP6)
{
	BOOL_T bRet = BOOL_TRUE;

	if (BOOL_TRUE == IN6ADDR_IsLoopback(pstIP6))
	{
		bRet = BOOL_FALSE;
	}
	else if (BOOL_TRUE == IN6ADDR_IsMulticast(pstIP6))
	{
		bRet = BOOL_FALSE;
	}
	else if (BOOL_TRUE == IN6ADDR_IsUnspecified(pstIP6))
	{
		bRet = BOOL_FALSE;
	}
	else if (BOOL_TRUE == IN6ADDR_IsLinkLocal(pstIP6))
	{
		bRet = BOOL_FALSE;
	}
	return bRet;
}

/*
FTP报文IPv6地址一致性检查函数
*****************************************************************************/
STATIC ULONG SESSION6_KFtp_CheckIpEqual(IN const SESSION_S *pstSession, 
                                 IN const csp_key_t *pstIP6Key,
                                 IN const SESSION_FTPALG_PAYLOAD_S *pstPayload, 
                                 IN const ALG_FTP_PATTERN_E enPattern)
{
	ULONG ulRet = ERROR_SUCCESS; 
	INT iRet = 0; 

	switch (enPattern)
	{
		case ALG_FTP_PORT_CMD:
		case ALG_FTP_EPRT_CMD:
		{
			/* 检查PORT命令中的IP地址合法性 */ 
			if (BOOL_TRUE != _session_KFtp_CheckIPv6Addr(&(pstPayload->unIp.stin6))) 
			{
				ulRet = ERROR_FAILED;
			}
			break;
		}
		case ALG_FTP_PASV_CMD:
		{
			/* 检查PASV命令中的IP地址与报文源地址是否相同 */
			iRet = IN6ADDR_Cmp(&(pstPayload->unIp.stin6), (struct in6_addr *)(&(pstIP6Key->src_ip))); 
			if (0 != iRet)
			{
				ulRet = ERROR_FAILED;
			}

			break;
		}
		default:
		{
			/* 有些报文我们不关心 
			SESSION_DBG_ALG_EVENT_ARGS(pstSession, "\r\n Ignore whether the packet's IP is correct. Packet type: %u",
									   enPattern); */
			break;
		}
	}

	return ulRet;
}

STATIC VOID _session6_KFtp_InitRelation(IN RELATION6_S *pstRelation6,
									   IN SESSION_S *pstSession,
									   IN const SESSION_FTPALG_PAYLOAD_S *pstPayload,
									   IN SESSION_PKT_DIR_E enDir,
									   IN SESSION_ALG_FTP_TYPE_E enFTPType)
{
	csp_key_t *pstRelaKey;
	UINT uiMask = 0;
	SESSION_PKT_DIR_E enInvertDir;
	csp_key_t *pstIpfsCacheKey;

	STATIC SESSION_CHILD_DIR_E aenChildDir[SESSION_FTP_MAX] =
	{
		[SESSION_FTP_PORT] = DIR_PARENT_DST_2_SRC,
		[SESSION_FTP_PASV] = DIR_PARENT_SRC_2_DST,
		[SESSION_FTP_EPRT] = DIR_PARENT_DST_2_SRC,
		[SESSION_FTP_EPSV] = DIR_PARENT_SRC_2_DST, };

	pstRelaKey = &pstRelation6->stTupleHash.stIp6fsKey;
	memcpy(&(pstRelaKey->dst_ip), &(pstPayload->unIp.stin6), sizeof(struct in6_addr));
	pstRelaKey->dst_port = pstPayload->unPort.usAll;

	enInvertDir = SESSION_GetInvertDir(enDir);
	pstIpfsCacheKey = SESSION_KGetIPfsKey((SESSION_HANDLE)pstSession, enInvertDir);
	if (NULL == pstIpfsCacheKey)
	{
		return;
	}

	memcpy(&(pstRelaKey->src_ip), &(pstIpfsCacheKey->src_ip), sizeof(struct in6_addr));
	pstRelaKey->proto = pstIpfsCacheKey->proto; 
	pstRelaKey->token = pstIpfsCacheKey->token; 

	SESSION_SET_PARABIT(uiMask, SESSION_TUPLE_MASK_IP);
	pstRelation6->stTupleHash.uiMask = uiMask;
	pstRelation6->uiAppID = APP_ID_FTPDATA; /* 数据通道会话的APPID是FTPDATA */ 
	pstRelation6->pstParent = pstSession; 
	pstRelation6->enChildDir = aenChildDir[enFTPType]; 
	pstRelation6->bCareParentFlag = BOOL_TRUE;
	
	/*pstRelation6->stRcu.pfCallback = SESSION6_Relation_Destroy;*/

	return;
}
								  
/*
Description∶ IPv6 FTP ALG处理主流程
****************************************************************************/
STATIC ULONG _session6_KFtpAlgProc(IN MBUF_S *pstMBuf,
                                   IN UINT uiL3OffSet, 
                                   IN UINT uiL4OffSet, 
                                   IN SESSION_HANDLE hSession)
{
	SESSION_FTPALG_PAYLOAD_S stPayload;
	RELATION6_S *pstRelation;
	UINT uiPayloadOff; 
	UINT uiPayloadLen;
	CHAR *pcFtpData;
	UCHAR ucProtocol;
	ULONG ulRet = ERROR_SUCCESS;
	SESSION_PKT_DIR_E enDir;
	csp_key_t *pstIP6Key;
	UINT uiNumOff;
	UINT uiNumLen;
	ALG_FTP_PATTERN_E enPattern; 
	SESSION_ALG_FTP_TYPE_E enFTPType;
	SESSION_S *pstSession = (SESSION_S *)hSession;

	/* 获取载荷偏移，完成字节序转换 */
	ucProtocol = SESSION_KGetProto(hSession); 
	if (IPPROTO_TCP != ucProtocol)  /* 暂时仅支持TCP */
	{
		SESSION6_KAlgFailInc(SESSION_ALG_FAIL_NOTSUPPORT_PROTOCOL);
		return ERROR_NOTSUPPORT;
	}
	enDir = SESSION_GetDirFromMBuf(pstMBuf);
	ulRet = SESSION_KGetValidL4Payload(pstMBuf, ucProtocol, uiL4OffSet, &uiPayloadOff, &uiPayloadLen);
	if ((ERROR_SUCCESS != ulRet) || (0 == uiPayloadLen))
	{
		SESSION6_KAlgFailInc(SESSION_ALG_FAIL_GET_PAYLOAD_FAILED);
		return ERROR_NOTSUPPORT;
	}

	pcFtpData = MBUF_BTOD_OFFSET(pstMBuf, uiPayloadOff, CHAR *);

	ulRet = _session_KFtp_Decode(hSession, pcFtpData, uiPayloadLen, enDir, (UINT *)(&enPattern));
	if (ERROR_SUCCESS != ulRet)
	{
		if (ERROR_INCOMPLETE == ulRet)
		{
			return ERROR_NOTSUPPORT;
		}
		/* 解码失败有可能是半匹配也有可能是遇到了无法识别的命令，这里做忽略处理 
		SESSION_DBG_ALG_EVENT_ARGS((SESSION_S *)pstSession, "\r\n FTP: Ignore the partly matched command.");*/
		enPattern = ALG_FTP_IGR_RESP;
	}

	/* 预填写载荷信息字段 */
	memset(&stPayload, 0, sizeof(stPayload)); 
	stPayload.ucFamily = AF_INET6;
	pstIP6Key = SESSION_KGetIPfsKey(hSession, enDir); 	
	memcpy(&stPayload.unIp.stin6, &(pstIP6Key->src_ip), sizeof(struct in6_addr));
	ulRet = _session_KFtp_CheckPattern(pcFtpData,
									   uiPayloadLen, 
									   enPattern,
									   &stPayload,
									   &uiNumOff, /* IP地址相对于peFtpData位置的偏移 */
									   &uiNumLen, /* IP地址的ASCII长度 */
									   &enFTPType);

	if (ERROR_SUCCESS != ulRet)
	{
		/* 看看这里是否应该返回这个值 */
		if (ERROR_NOTSUPPORT != ulRet)
		{
			SESSION_DBG_ALG_ERROR_SWITCH(pstSession, DBG_ALG_ERROR_DECODE);
			SESSION6_KAlgFailInc(SESSION_ALG_FAIL_DECODE_FAILED);		}
		return ulRet;
	}

	ulRet = SESSION6_KFtp_CheckIpEqual((SESSION_S *)pstSession, pstIP6Key, &stPayload, enPattern);
	if (ERROR_SUCCESS != ulRet)
	{
		SESSION_DBG_ALG_ERROR_SWITCH(pstSession, DBG_ALG_ERROR_IP); 
		return ulRet;
	}

	pstRelation = SESSION6_Relation_Create();
	if (NULL == pstRelation)
	{
		SESSION_DBG_RELATION_ERROR_SWTICH(ERROR_RELATION_MEMORY_NOT_ENOUGH); 
		SESSION6_KAlgFailInc(SESSION_ALG_FAIL_ALLOC_RELATION);
		return ERROR_NOTSUPPORT;
	}

	_session6_KFtp_InitRelation(pstRelation, pstSession, &stPayload, enDir, enFTPType);
	
	/* 关联表正式化处理 */
	ulRet = SESSION6_Relation_Add(pstRelation,
								  pstSession,
								  RELATION_AGING_TYPE_FTPDATA);
	if (ERROR_SUCCESS != ulRet)
	{
		SESSION6_KAlgFailInc(SESSION_ALG_FAIL_ADD_RELATION_HASH);
		
		/* 关联表可能加Local hash失败, 需要使用rcu释放 
		RCU_Call(&pstRelation->stRcu);*/
		
		general_rcu_qsbr_dq_enqueue((void *)pstRelation, SESSION6_Relation_Destroy);
	}
	else
	{
		/* 关联表正式化成功, 需要发送备份消息 */ 
	    ;
	}

	return ERROR_SUCCESS;
}

/*******************************************************************
Description:  初始化FTP待解析载荷字段, 向AC算法注册模式
*********************************************************************/
STATIC ULONG _alg_FTP_InitAc(VOID)
{
	ULONG ulRet; 
	UINT uiSigNum; 
	UINT uiCurPos;
	AC_HANDLE hProtocolTrie;

	hProtocolTrie = ANCHORAC_CreateTrie(AC_CASE_INSENSITIVE);
	if (AC_HANDLE_INVALID == hProtocolTrie)
	{
		return ERROR_FAILED;
	}

	ulRet = ERROR_SUCCESS;
	uiSigNum = sizeof(g_astAlgFtpPatternsReg) / sizeof(ALG_FTP_PATTERNS_S); 
	for (uiCurPos = 0; uiCurPos < uiSigNum; uiCurPos++) 
	{
		ulRet = ANCHORAC_AddPattern(hProtocolTrie, 
									g_astAlgFtpPatternsReg[uiCurPos].pucData, 
									g_astAlgFtpPatternsReg[uiCurPos].uiDataLen, 
									g_astAlgFtpPatternsReg[uiCurPos].uiPid); 
		if (ERROR_SUCCESS != ulRet)
		{
			break;
		}
	}


	if (ERROR_SUCCESS == ulRet)
	{
		if (ERROR_SUCCESS == ANCHORAC_Compile(hProtocolTrie))
		{
			g_hFTPProtocolTrie = hProtocolTrie; 
			return ERROR_SUCCESS;
		}
	}

	ANCHORAC_DestroyTrie(hProtocolTrie);
	
	return ERROR_FAILED;
}

/*****************************************************************************
Description:  会话管理FTP ALG处理初始化函数
*****************************************************************************/
ULONG SESSION_KFtpInit(VOID)
{
	SESSION_ALG_S stRegInfo;
	ULONG ulRet;

	/* FTP解码相关初始化 */
	ulRet = _alg_FTP_InitAc();

	/* 向会话管理总处理流程注册FTP ALG的处理 */
	memset(&stRegInfo, 0, sizeof(SESSION_ALG_S));
	stRegInfo.pfAlgProc      = _session_KFtpAlgProc;
	stRegInfo.pfAlg6Proc     = _session6_KFtpAlgProc;

	/*
	stRegInfo.pfExtDestroy   = kfree;
	stRegInfo.pfExtBackup    = _alg_FTP_BAK_ExtBackUp;
	stRegInfo.pfExtRestore   = _algFTP_BAK_ExtRestore;
	*/

	ulRet |= SESSION_KAlg_AppReg(&stRegInfo, SESSION_ALG_TYPE_FTP);

	return ulRet;
}

