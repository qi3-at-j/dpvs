



#include <ctype.h>

#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <netinet/ip.h>


#include "session.h"
#include "session_kcore.h"
#include "ac.h"
#include "ip6_util.h"
#include "session_kalg.h"
#include "session_kalg_ftp.h"
#include "session_ktable.h"
#include "apr.h"

#define SESSION_ALG_L2HEAD_BUFLEN 256

STATIC SESSION_ALG_S g_astSessionAlgProc[SESSION_ALG_TYPE_MAX];  /* 各种ALG报文处理函数 */

SESSION_KALG_IPV4_PROC_S g_stSessionIPv4KAlgProc = {NULL}; /* 各种ALG报文处理函数 */

SESSION_KALG_IPV6_PROC_S g_stSessionIPv6KAlgProc = {NULL}; /* 各种ALG报文处理函数 */

SESSION_KALG_PACKET_PROC_S g_stSessionKalgPacketProc = {NULL, NULL, NULL, NULL, NULL}; /* 各种ALG报文处理函数 */

SESSION_ALG_TYPE_E g_aenSessionGetAlgTypeByAppID[SESSION_APPID_MAX];

STATIC VOID session_kalg_InitMapAlgType(VOID)
{
    UINT uiLoop;

    for (uiLoop = 0; uiLoop < SESSION_APPID_MAX; uiLoop++)
    {
        g_aenSessionGetAlgTypeByAppID[uiLoop] = SESSION_ALG_TYPE_MAX;
    }

    g_aenSessionGetAlgTypeByAppID[APP_ID_FTP]        = SESSION_ALG_TYPE_FTP;    
    g_aenSessionGetAlgTypeByAppID[APP_ID_RAS]        = SESSION_ALG_TYPE_RAS;
    g_aenSessionGetAlgTypeByAppID[APP_ID_H225]       = SESSION_ALG_TYPE_H225;    
    g_aenSessionGetAlgTypeByAppID[APP_ID_H245]       = SESSION_ALG_TYPE_H245;
    g_aenSessionGetAlgTypeByAppID[APP_ID_SIP]        = SESSION_ALG_TYPE_SIP;    
    g_aenSessionGetAlgTypeByAppID[APP_ID_TFTP]       = SESSION_ALG_TYPE_TFTP;
    g_aenSessionGetAlgTypeByAppID[APP_ID_RTSP]       = SESSION_ALG_TYPE_RTSP;    
    g_aenSessionGetAlgTypeByAppID[APP_ID_GTPU]       = SESSION_ALG_TYPE_GTPU;
    g_aenSessionGetAlgTypeByAppID[APP_ID_GTPC]       = SESSION_ALG_TYPE_GTPC;    
    g_aenSessionGetAlgTypeByAppID[APP_ID_GPRSDATA]   = SESSION_ALG_TYPE_GTPVO_T;
    g_aenSessionGetAlgTypeByAppID[APP_ID_GPRSSIG]    = SESSION_ALG_TYPE_GTPVO_U;    
    g_aenSessionGetAlgTypeByAppID[APP_ID_PPTP]       = SESSION_ALG_TYPE_PPTP;
    g_aenSessionGetAlgTypeByAppID[APP_ID_ILS]        = SESSION_ALG_TYPE_ILS;    
    g_aenSessionGetAlgTypeByAppID[APP_ID_NETBIOSNS]  = SESSION_ALG_TYPE_NBNS;
    g_aenSessionGetAlgTypeByAppID[APP_ID_NETBIOSDGM] = SESSION_ALG_TYPE_NBDGM;    
    g_aenSessionGetAlgTypeByAppID[APP_ID_NETBIOSSSN] = SESSION_ALG_TYPE_NBSS;
    g_aenSessionGetAlgTypeByAppID[APP_ID_SCCP]       = SESSION_ALG_TYPE_SCCP;    
    g_aenSessionGetAlgTypeByAppID[APP_ID_SQLNET]     = SESSION_ALG_TYPE_SQLNET;
    g_aenSessionGetAlgTypeByAppID[APP_ID_XDMCP]      = SESSION_ALG_TYPE_XDMCP;    
    g_aenSessionGetAlgTypeByAppID[APP_ID_MGCPC]      = SESSION_ALG_TYPE_MGCP_C;
    g_aenSessionGetAlgTypeByAppID[APP_ID_MGCPG]      = SESSION_ALG_TYPE_MGCP_G;
    g_aenSessionGetAlgTypeByAppID[APP_ID_RSH]        = SESSION_ALG_TYPE_RSH;
    g_aenSessionGetAlgTypeByAppID[APP_ID_HTTP]       = SESSION_ALG_TYPE_HTTP;    
    g_aenSessionGetAlgTypeByAppID[APP_ID_SMTP]       = SESSION_ALG_TYPE_SMTP;
    g_aenSessionGetAlgTypeByAppID[APP_ID_DNS]        = SESSION_ALG_TYPE_DNS;
    return;
}

/*** 从appid获取会话的alg type ***/
USHORT SESSION_KGetSessionAlgType(IN UINT uiAppID)
{
    USHORT usAlgType = SESSION_ALG_TYPE_MAX;

    if(SESSION_APPID_MAX > uiAppID)
    {
        usAlgType = (USHORT)g_aenSessionGetAlgTypeByAppID[uiAppID];
    }

    return usAlgType;
}

/*****************************************************************************
Description: 会话扩展信息释放回调函数
*************************************************************************/
STATIC VOID session_kalg_ExtDestroy(IN SESSION_HANDLE hSession, IN VOID *pCb)
{
	USHORT usSessAlgType;
	SESSION_ALG_EXT_DESTROY_PF pfExtDestroy;
	SESSION_S *pstSession = (SESSION_S *)hSession;

	/* ALG类型检查 
	if (SESSION_TYPE_EXT != pstSession->stSessionBase.ucSessionType)
	{	
		usSessAlgType = SESSION_KGetSessionAlgType(pstSession->uiOriginalAppID);
	}
	else
	{
		usSessAlgType = pstSession->usSessAlgType;
	}
	*/
	
	usSessAlgType = pstSession->usSessAlgType;

	if (usSessAlgType >= SESSION_ALG_TYPE_MAX)
	{
		return;
	}

	if (NULL != pCb)
	{
		pfExtDestroy = g_astSessionAlgProc[usSessAlgType].pfExtDestroy;
		if (NULL != pfExtDestroy)
		{
			pfExtDestroy(pCb);
		}
	}

	SESSION_IGNORE_CONST(pCb); 

	return;
}

/*******************************************************************
Description:  获取IPv6 ALG处理函数指针
*****************************************************************************/
STATIC inline SESSION_ALG_PROC_PF session6_kalg_GetAlgProc(IN SESSION_HANDLE hSession)
{
	SESSION_S *pstSession = (SESSION_S *)hSession;
	SESSION_ALG_PROC_PF pfAlgProc = NULL;
	USHORT usSessAlgType;

	/* ALG类型检查 */
	usSessAlgType = SESSION_KGetSessionAlgType(pstSession->uiAppID);
	if (usSessAlgType < SESSION_ALG_TYPE_MAX)
	{
		pfAlgProc = g_astSessionAlgProc[usSessAlgType].pfAlg6Proc;
	}

	return pfAlgProc;
}

ULONG SESSION6_KAlgProc(IN MBUF_S *pstMbuf, IN UINT uiL3OffSet, IN SESSION_HANDLE hSession)
{
	SESSION_ALG_PROC_PF pfAlgProc = NULL;
	IP6_S *pstIP6Hdr;
	ULONG ulRet = ERROR_SUCCESS; 
	UINT uiL4_Offset; 
	UCHAR ucL4_Proto;

	pfAlgProc = session6_kalg_GetAlgProc(hSession);
	if (NULL == pfAlgProc)
	{
		return ERROR_SUCCESS;
	}

	/* ASPF */
	pstIP6Hdr = MBUF_BTOD(pstMbuf, IP6_S*);
	uiL4_Offset = sizeof(IP6_S);
	ucL4_Proto = pstIP6Hdr->ip6_ucNxtHdr;
	ulRet = IP6_GetLastHdr(pstMbuf, &uiL4_Offset, &ucL4_Proto); 
	if (ERROR_SUCCESS == ulRet)
	{
		/*local_bh_disable();*/
		ulRet = pfAlgProc(pstMbuf, 0, uiL4_Offset, hSession);
		/*local_bh_enable();*/
		if (ERROR_NOTSUPPORT == ulRet)
		{
			ulRet = ERROR_SUCCESS;
		}
	}
	else
	{
		/* 获取last hdr失败, 不处理, 不丢包 */
		ulRet = ERROR_SUCCESS;
	}
	
	return ulRet;
}

/****************************************************************************
Description:  会话的各种应用协议注册函数
*****************************************************************************/
ULONG SESSION_KAlg_AppReg(IN SESSION_ALG_S *pstRegInfo, IN SESSION_ALG_TYPE_E enType)
{
	g_astSessionAlgProc[enType] = *pstRegInfo;
	SESSION_IGNORE_CONST(pstRegInfo);

	return ERROR_SUCCESS;
}

/****************************************************************************
Description:  会话的各种应用协议去注册函数
***************************************************************************/
VOID SESSION_KAlg_AppDeReg (IN SESSION_ALG_TYPE_E enType)
{
	memset(&g_astSessionAlgProc[enType], 0, sizeof(SESSION_ALG_S));
	return;
}


/* 创建Trie */
AC_HANDLE ANCHORAC_CreateTrie(IN AC_CASE_E enCase)
{
	AC_KANCHOR_TRIE_S *pstKTrie;

	(VOID)enCase;

	pstKTrie = rte_zmalloc("ac_anchor_trie", sizeof(AC_KANCHOR_TRIE_S), 0);
	if (NULL != pstKTrie)
	{
		DTQ_Init(&(pstKTrie->stPattHead));
	}

	return (AC_HANDLE)pstKTrie;
}

/*****************************************************************************
Description:  释放双链表
*****************************************************************************/
STATIC VOID _KAnchorNodeFree(IN DTQ_NODE_S *pstNode)
{
	AC_KANCHOR_PATTERN_S *pstTmp = NULL;

	if (NULL != pstNode)
	{
		pstTmp = DTQ_ENTRY(pstNode, AC_KANCHOR_PATTERN_S, stNode);
		rte_free(pstTmp);
		pstTmp = NULL;
	}
	return;
}

/***************************************************************************
Description:  释放双链表
*****************************************************************************/
STATIC inline VOID _KAnchorRelease(IN DTQ_HEAD_S *pstPattHead)
{
	DTQ_FreeAll(pstPattHead, _KAnchorNodeFree);
	return;
}

/****************************************************************************
Description: 注销Trie
*****************************************************************************/
VOID ANCHORAC_DestroyTrie(IN AC_HANDLE hAcTrie)
{
	AC_KANCHOR_TRIE_S *pstTrie = (AC_KANCHOR_TRIE_S *)hAcTrie;

	if (NULL != pstTrie->puiStateArray)
	{
		rte_free(pstTrie->puiStateArray);
		pstTrie->puiStateArray = NULL;
	}

	if (NULL != pstTrie->puiPidArray)
	{
		rte_free(pstTrie->puiPidArray); 
		pstTrie->puiPidArray = NULL;
	}
	_KAnchorRelease(&pstTrie->stPattHead);

	rte_free(pstTrie);
	pstTrie = NULL; 
	return;
}

/****************************************************************************
Description: 分配Pattern内存
      Input: hAcTrie,    树Handle
             pucPatt,    Pattern
             uiPattLen,  Pattern length
             uiPid,      PID
     Return: 分配的内存
*********************************************************************/
STATIC AC_KANCHOR_PATTERN_S *_KAnchorMallocPattern(IN AC_HANDLE hAcTrie,
											IN const UCHAR *pucPatt,
											IN UINT uiPattLen,
											IN UINT uiPid)
{
	AC_KANCHOR_PATTERN_S *pstPattNode;
	AC_KANCHOR_TRIE_S *pstKTrie = (AC_KANCHOR_TRIE_S *)hAcTrie;
	
	pstPattNode = rte_zmalloc("ac_anchor_pattern_node", sizeof(AC_KANCHOR_PATTERN_S), 0);
	if (NULL != pstPattNode)
	{
		DTQ_NodeInit(&pstPattNode->stNode);
		
		rte_memcpy(pstPattNode->aucPattern, pucPatt, uiPattLen); 
		
		pstPattNode->uiPatternLen = uiPattLen;
		pstPattNode->uiPid = uiPid;

		DTQ_AddTail(&pstKTrie->stPattHead, &pstPattNode->stNode); 
		pstKTrie->uiPattLenSum += uiPattLen; 
		pstKTrie->uiPidSum++; 
	}
	return pstPattNode;
}

/*****************************************************************************
Description:  内核中提供的Anchor Search接口
*************************************************************************/
ULONG ANCHORAC_AddPattern(IN AC_HANDLE hAcTrie, IN const UCHAR *pucPatt, IN UINT uiPattLen, IN UINT uiPid)
{
	AC_KANCHOR_PATTERN_S *pstPattNode;

	if (uiPattLen > AC_MAX_PATTERN_LEN)
	{
		return ERROR_FAILED;
	}

	pstPattNode = _KAnchorMallocPattern(hAcTrie, pucPatt, uiPattLen, uiPid); 
	if (NULL == pstPattNode)
	{
		return ERROR_FAILED;
	}

	return ERROR_SUCCESS;
}

/**************************************************************************
Description: 生成表
      Input: uiStateNum,     状态个数
     Output: pstKTrie,        树
***************************************************************/ 
STATIC inline ULONG _KAnchorMallocSource(IN UINT uiStateNum, OUT AC_KANCHOR_TRIE_S *pstKTrie)
{
	UINT *puiPidArray; 
	UINT (*puiStateArray)[256];

	puiStateArray = rte_zmalloc("ac_anchor_state_array", sizeof(UINT)* 256 * uiStateNum, 0);
	if (NULL == puiStateArray)
	{
		return ERROR_FAILED;
	}
	
	puiPidArray = rte_zmalloc("ac_anchor_pid_array", sizeof(UINT) * uiStateNum, 0);
	if (NULL == puiPidArray)
	{
		rte_free(puiStateArray);
		return ERROR_FAILED;
	}

	pstKTrie->puiStateArray = puiStateArray;
	pstKTrie->puiPidArray = puiPidArray;

	return ERROR_SUCCESS;
}

/*****************************************************************************
Description: 添加状态
Input:	IN UINT uiCurArrayPos,  当前数组位置
		IN UCHAR ucPattAsci,    模式ASCII码
		IN UINT uiCurPattpos,   当前模式位置
		IN UINT uiPattLen,      模式长度
		IN UINT uiNextPos,      下一个位置
Output:	OUT UINT (*puiStateArray)[256], 状态数组
*******************************************************************/
STATIC inline VOID _KAnchorAddOneState(IN UINT uiCurArrayPos,
										IN UCHAR ucPattAsci,
										IN UINT uiCurPattpos, 
										IN UINT uiPattLen,
										IN UINT uiNextPos,
										OUT UINT (*puiStateArray)[256])
{
	UINT uiStateID;

	uiStateID = uiNextPos; 
	if ((uiCurPattpos + 1) == uiPattLen) /* 判断是否是尾状态 */
	{
		uiStateID = AC_SET_HASPIDFLAG(uiNextPos);
	}

	ucPattAsci = tolower(ucPattAsci);
	puiStateArray[uiCurArrayPos][ucPattAsci] = uiStateID;
	ucPattAsci = toupper(ucPattAsci);
	puiStateArray[uiCurArrayPos][ucPattAsci] = uiStateID; 
	return;
}

/***********************************************************************
Description: 生成表
      Input: pucPatt,        模式指针
             uiPattLen，      模式长度
             uiPid，          PID
             pstKTrie        树
             uiNextPos       下一个位置
     Output: puiNextPos      下一个位置
***********************************************************************/
STATIC VOID _KAnchorMakeTbl(IN const UCHAR *pucPatt,
							IN UINT uiPattLen,
							IN UINT uiPid,
							IN const AC_KANCHOR_TRIE_S *pstKTrie,
							IN UINT uiNextPos,
							OUT UINT *puiNextPos)
{
	UINT uiPattPos;
	UINT uiArrayPos = 0; 
	UINT uiStateID;
	UINT (*puiStateArray)[256];
	UINT *puiPidArray;

	puiPidArray = pstKTrie->puiPidArray;
	puiStateArray = pstKTrie->puiStateArray;

	for (uiPattPos = 0; uiPattPos < uiPattLen; uiPattPos++)
	{
		uiStateID = puiStateArray[uiArrayPos][pucPatt[uiPattPos]];
		if (0 == uiStateID)
		{
			_KAnchorAddOneState(uiArrayPos, pucPatt[uiPattPos], 
								uiPattPos, uiPattLen, uiNextPos, puiStateArray); 
			uiArrayPos = *puiNextPos;
			*puiNextPos += 1; 
			uiNextPos = *puiNextPos;
		}
		else
		{
			uiArrayPos = AC_GETID_NOFLAG(uiStateID);
		}
	}
	puiPidArray[uiArrayPos] = uiPid;

	return;
}


ULONG ANCHORAC_Compile(IN AC_HANDLE hAcTrie)
{
	UINT *puiPidArray; 
	UINT uiStateNum;
	UINT uiNextPos = 1;
	AC_KANCHOR_TRIE_S *pstKTrie;
	UINT(*puiStateArray)[256];
	AC_KANCHOR_PATTERN_S *pstCurPattNode;

	DBGASSERT(AC_KHANDLE_INVALID != hAcTrie);

	pstKTrie = (AC_KANCHOR_TRIE_S *)hAcTrie;

	uiStateNum = pstKTrie->uiPattLenSum;

	if (ERROR_SUCCESS != _KAnchorMallocSource(uiStateNum + 1, pstKTrie))
	{
		return ERROR_FAILED;
	}

	DTQ_FOREACH_ENTRY(&pstKTrie->stPattHead, pstCurPattNode, stNode)
	{
		_KAnchorMakeTbl(pstCurPattNode->aucPattern,
						pstCurPattNode->uiPatternLen,
						pstCurPattNode->uiPid,
						pstKTrie,
						uiNextPos,
						&uiNextPos);
	}

	uiStateNum = uiNextPos;
	pstKTrie->uiStateNum = uiStateNum;

	puiStateArray = rte_realloc(pstKTrie->puiStateArray, sizeof(UINT) * uiStateNum * 256, 0);
	if (NULL != puiStateArray)
	{
		pstKTrie->puiStateArray = puiStateArray;
		puiPidArray = rte_realloc(pstKTrie->puiPidArray, sizeof(UINT) * uiStateNum, 0); 

		if (NULL != puiPidArray)
		{
			pstKTrie->puiPidArray = puiPidArray;

			/* 释放无用资源 */
			_KAnchorRelease(&pstKTrie->stPattHead);

			return ERROR_SUCCESS;
		}
	}

	return ERROR_FAILED;
}

/* 获取ALG处理函数指针 */
STATIC inline SESSION_ALG_PROC_PF session_kalg_GetAlgProc(IN SESSION_HANDLE hSession)
{
    SESSION_S *pstSession = (SESSION_S *)hSession;
    SESSION_ALG_PROC_PF pfAlgProc = NULL;
    USHORT usSessAlgType;

    /* ALG类型检查 */
    usSessAlgType = SESSION_KGetSessionAlgType(pstSession->uiAppID);
    if (usSessAlgType < SESSION_ALG_TYPE_MAX)
    {
        pfAlgProc = g_astSessionAlgProc[usSessAlgType].pfAlgProc;
    }

    return pfAlgProc;
}



/* ipv4 alg异常统计计数增一 */
VOID SESSION_KAlgFailInc(IN SESSION_ALG_STAT_TYPE_E enAppType, IN SESSION_ALGFAIL_TYPE_E enAlgFailType)
{
	SESSION_CTRL_S *pstSessionCtrl;
	SESSION_ALGFAILCNT_VCPU_S *pstVcpuCnt;
	SESSION_ALGFAILCNT_S *pstCnt;

    pstSessionCtrl = SESSION_CtrlData_Get();

	pstCnt = &pstSessionCtrl->stAlgFail;

	pstVcpuCnt = SESSION_GET_PERCPU_PTR(pstCnt->pstVcpuAlgFailCnt, index_from_lcore_id());

	rte_atomic32_inc(&pstVcpuCnt->astAlgFailCntGlobal4[enAppType][enAlgFailType]);

	return;
}

/* ipv6 alg异常统计计数增一 */
VOID SESSION6_KAlgFailInc(IN SESSION_ALGFAIL_TYPE_E enAlgFailType)
{
	SESSION_CTRL_S *pstSessionCtrl;
	SESSION_ALGFAILCNT_VCPU_S *pstVcpuCnt;
	SESSION_ALGFAILCNT_S *pstCnt;
	
    pstSessionCtrl = SESSION_CtrlData_Get();

	pstCnt = &pstSessionCtrl->stAlgFail;

	pstVcpuCnt = SESSION_GET_PERCPU_PTR(pstCnt->pstVcpuAlgFailCnt, index_from_lcore_id());

	rte_atomic32_inc(&pstVcpuCnt->astAlgFailCntGlobal6[enAlgFailType]);

	return;
}

/* Description: 会话管理ALG处理主流程 */
ULONG SESSION_KAlgProc(IN MBUF_S *pstMbuf,IN UINT uiL3OffSet,IN SESSION_HANDLE hSession)
{
	SESSION_ALG_PROC_PF pfAlgProc;
	ULONG ulRet = ERROR_SUCCESS;
	UINT uiL4_Offset;
	struct iphdr *pstIPHdr;

	pfAlgProc = session_kalg_GetAlgProc(hSession);
	if (NULL == pfAlgProc)
	{
		return ERROR_SUCCESS;
	}

	pstIPHdr = MBUF_BTOD_OFFSET(pstMbuf, 0, struct iphdr *);
	uiL4_Offset = (UINT)pstIPHdr->ihl << 2;

	/*local_bh_disable();*/
	ulRet = pfAlgProc(pstMbuf, 0, uiL4_Offset, hSession);
	/*local_bh_enable();*/

	if (ERROR_NOTSUPPORT == ulRet)
	{
		ulRet = ERROR_SUCCESS;
	}

	return ulRet;
}

/**************************************************************************
Description: 会话管理ALG处理初始化函数
*****************************************************************************/
ULONG SESSION_KALG_Init(VOID)
{
	SESSION_MODULE_REG_S stRegInfo;
	ULONG ulRet = ERROR_SUCCESS;
	
	/* 各alg初始化 */
	memset(g_astSessionAlgProc, 0, sizeof(g_astSessionAlgProc));
	ulRet = SESSION_KFtpInit(); 
    
    /* 向会话注册alg扩展信息 */
    memset(&stRegInfo, 0, sizeof(SESSION_MODULE_REG_S));
    stRegInfo.pfExtDestroy = session_kalg_ExtDestroy;

    
    /* ALG使用1个ULONG挂指针, 结构类型根据ALG类型进行区分 */
    ulRet |= SESSION_KRegisterModule(SESSION_MODULE_ALG, &stRegInfo);
    
    session_kalg_InitMapAlgType();
    
    memset(&g_stSessionIPv4KAlgProc, 0, sizeof(SESSION_KALG_IPV4_PROC_S));
    g_stSessionIPv4KAlgProc.pfAlgIPv4Proc = SESSION_KAlgProc;
    
    memset(&g_stSessionIPv6KAlgProc, 0, sizeof(SESSION_KALG_IPV6_PROC_S));
    g_stSessionIPv6KAlgProc.pfAlgIPv6Proc = SESSION6_KAlgProc;
    
    return ulRet;
}

/*判断ulLen长度的内存是否相等，请保证两块内存不会越界*/
STATIC inline BOOL_T _mem_equal(IN const UCHAR *pucLeft, IN const UCHAR *pucRight, IN ULONG ulLen)
{
	BOOL_T bEqual = BOOL_FALSE;
	ULONG ulTempLen = 0;

	while(pucLeft[ulTempLen] == pucRight[ulTempLen])
    {
		ulTempLen++;
		if(ulTempLen == ulLen)
		{
			bEqual = BOOL_TRUE;
			break;
		}
	}

	return bEqual;
}

/*
Description:检查某块内存中是否包含另外一个内存中的内容 
     Return:子串的首地址，如果不包含则为NULL
*/
VOID *SESSION_KAlg_memmem(IN const VOID *pHaystack,
                          IN ULONG ulHaystacklen,
                          IN const VOID *pNeedle,
                          IN ULONG ulNeedlelen)
{
	UCHAR *pucH;
	UCHAR *pucN;
	UCHAR *pucLast;
	VOID  *pReturn = NULL;

	if(ulNeedlelen == 0)
	{
		return (VOID *)pHaystack;
	}

	if(ulHaystacklen < ulNeedlelen)
	{
		return NULL;
	}

	pucH = (UCHAR *)pHaystack;
	pucN = (UCHAR *)pNeedle;
	pucLast = pucH + (ulHaystacklen - ulNeedlelen);

	do
	{
		if(BOOL_TRUE == _mem_equal(pucH, pucN, ulNeedlelen))
		{
			pReturn = (VOID *)pucH;
			break;
		}
    }while(++pucH <= pucLast);

	return pReturn;
}

ULONG ANCHORAC_SearchWithState(IN AC_HANDLE hAcTrie,
                               IN UCHAR *pucBuf,
                               IN const UCHAR *pucBufEnd,
                               INOUT UINT *puiState,
                               OUT UINT *puiPid)
{
	AC_KANCHOR_TRIE_S *pstKTrie = (AC_KANCHOR_TRIE_S *)hAcTrie;
	ULONG ulRet;
	UINT (*puiStateArray)[256];
	UCHAR *pucCur;
	UINT uiStateID;

	DBGASSERT(*puiState < pstKTrie->uiStateNum);
	puiStateArray = pstKTrie->puiStateArray;

	pucCur = pucBuf;
	uiStateID = *puiState;

	for(;;)
	{
		/* 寻找命中的状态 */
	    uiStateID = puiStateArray[uiStateID][*pucCur];
		pucCur++;
		DBGASSERT(AC_GETID_NOFLAG(uiStateID) < pstKTrie->uiStateNum);
		if (0 == uiStateID)
		{
			ulRet = ERROR_FAILED;
			break;
		}

		if(unlikely(AC_IS_PIDFLAG_SET(uiStateID)))
		{
			/* 将命中的状态下的pid复制 */
		    uiStateID = AC_GETID_NOFLAG(uiStateID);
			*puiPid   = pstKTrie->puiPidArray[uiStateID];
			ulRet = ERROR_SUCCESS;
			break;
		}

		if(pucCur == pucBufEnd)
		{
			*puiState = uiStateID;
			ulRet = ERROR_INCOMPLETE;
			break;
		}
	}

	return ulRet;
}
							   
ULONG ANCHORAC_Search(IN AC_HANDLE hAcTrie,
                      IN UCHAR *pucBuf,
                      IN const UCHAR *pucBufEnd,
                      OUT UINT *puiPid)
{
    UINT uiState = 0;
	
	return ANCHORAC_SearchWithState(hAcTrie, pucBuf, pucBufEnd, &uiState, puiPid);
}

