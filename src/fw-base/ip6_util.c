#include "ip6fw.h"
#include "session_util.h"
#include "ip6_util.h"

/****************************************************************************    
      Input: MBUF_S *pstMBuf, MBuf指针 
             UINT *puiOff 当前扩展头偏移
             UCHAR *pucProto 当前扩展头类型
     Output: UINT *puiOff    下一报头偏移
             UCHAR *pucProto 下一报头类型
     return: ERROR_SUCCESS 获取下一报头成功
             ERROR_FAILED  获取下一报头失败
    Caution: 调用者需要保证IPv6头连续
Description: 根据输入的偏移和类型，获取下一报头的偏移和类型

******************************************************************************/
STATIC ULONG IP6_GetNextHdr(IN MBUF_S *pstMBuf,
                     INOUT UINT *puiOff,
                     INOUT UCHAR *pucProto)
{
    IP6_S *pstIp6  = NULL;
    struct ip6_frag *pstIp6Frag = NULL;
    struct ip6_ext  *pstIp6Ext  = NULL;
    ULONG ulRet;
    UINT uiNxtOff;
    UCHAR ucNxtProto;

    /* 检查参数的合法性 */
    DBGASSERT(NULL != pstMBuf);
    DBGASSERT(NULL != puiOff);
    DBGASSERT(NULL != pucProto);

    uiNxtOff = *puiOff;
    ucNxtProto = *pucProto;

    if (0 == uiNxtOff)
    {
        /* 得到IPv6头中的下一个扩展头类型和偏移 */
        pstIp6 = MBUF_BTOD(pstMBuf, IP6_S *);
        *puiOff = sizeof(IP6_S);
        *pucProto = pstIp6->ip6_ucNxtHdr;
        return ERROR_SUCCESS;
    }

    /* 根据前一个扩展头分别处理 */
    switch (ucNxtProto)
    {
        case IPPROTO_FRAGMENT:
        {
            /* 得到分片扩展头数据指针 */
            pstIp6Frag = IP6_GetExtHdr(pstMBuf, uiNxtOff, (UINT32)sizeof(struct ip6_frag));
            if (NULL == pstIp6Frag)
            {
                return ERROR_FAILED;
            }

            /* 目前只支持处理第一个分片报文 */
            if(0 != (ntohs(pstIp6Frag->ip6f_offlg) & IP6F_OFF_MASK))
            {
                /* 此时下一个扩展头无意义 */
                return ERROR_FAILED;
            }

            /* 得到下一个扩展头的类型和偏移 */
            ucNxtProto = pstIp6Frag->ip6f_nxt;
            uiNxtOff += sizeof(struct ip6_frag);
            break;
        }
        
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_DSTOPTS:
        {
            /* 得到扩展头数据指针 */
            pstIp6Ext = IP6_GetExtHdr(pstMBuf, uiNxtOff, (UINT32)sizeof(struct ip6_ext));
            if(NULL == pstIp6Ext)
            {
                return ERROR_FAILED;
            }
            
            /* 得到下一个扩展头的类型和偏移 */
            ucNxtProto = pstIp6Ext->ip6e_nxt;
            uiNxtOff += ((UINT)pstIp6Ext->ip6e_len + 1) << 3;

            /* 检查下一个扩展头的数据是否足够 */
            ulRet = MBUF_PULLUP(pstMBuf, uiNxtOff);
            if (ERROR_SUCCESS != ulRet)
            {
                return ERROR_FAILED;
            }

            break;
        }

        default :
        {
            /* 出参值未变 */
            break;
        }
    }

    /* 给出参赋值 */
    *pucProto = ucNxtProto;
    *puiOff = uiNxtOff;
    return ERROR_SUCCESS;
}



/****************************************************************************    
      Input: MBUF_S *pstMBuf, MBuf指针 
             UINT *puiOff 当前扩展头偏移
             UCHAR *pucProto 当前扩展头类型
     Output: UINT *puiOff 上层协议偏移
             UCHAR *pucProto 上层协议类型
     return: ERROR_SUCCESS 获取下一报头成功
             ERROR_FAILED  获取下一报头失败
    Caution: 本函数可以从某扩展头开始获取报文中的上层协议，也可以从IPv6头开始。
             从IPv6头开始时*puiOff = 0, *pucProto = IPPROTO_IPV6
Description: 获取报文中的上层协议类型和偏移

******************************************************************************/
ULONG IP6_GetLastHdr(IN MBUF_S *pstMBuf,
                     INOUT UINT *puiOff,
                     INOUT UCHAR *pucProto)
{
    ULONG ulResult = 0;
    UINT uiOff;
    UINT uiNewOff;
    UCHAR ucNxt;
    IP6_S *pstIp6;

    /* 检查参数的合法性 */
    if((NULL == pstMBuf) || (NULL == puiOff) || (NULL == pucProto))
    {
        return ERROR_FAILED;
    }

    ucNxt = *pucProto;
    uiOff = *puiOff;

    /* 支持IPv6头偏移不为0的情况 */
    if (IPPROTO_IPV6 == ucNxt)
    {
        /* 先偏移到下一个扩展头 */
        pstIp6 = (IP6_S *)IP6_GetExtHdr(pstMBuf, uiOff, (UINT32)sizeof(IP6_S));
        if (NULL == pstIp6)
        {
            return ERROR_FAILED;
        }

        uiOff += sizeof(IP6_S);
        ucNxt = pstIp6->ip6_ucNxtHdr;
    }

    uiNewOff = uiOff;

    for( ; ; )
    {
        ulResult = IP6_GetNextHdr(pstMBuf, &uiNewOff, &ucNxt);
        if(ERROR_SUCCESS != ulResult)
        {
            return ERROR_FAILED;
        }

        /* 已经获取到上层协议 */
        if (uiNewOff == uiOff)
        {
            break;
        }

        /* 下一头还是扩展头，需要继续遍历 */
        uiOff = uiNewOff;
    }
            
    *puiOff = uiNewOff;
    *pucProto = ucNxt;
    return ERROR_SUCCESS;
}

/************************************************************************ 
Input: 	FSBUF_BLOCKINFO_S *pstBlockInfo， Buf指针
		UINT *puiOff 当前扩展头偏移
		UCHAR *pucProto 当前扩展头类型

Output: UINT *puiOff 下一报头偏移
		UCHAR *pucProto 下一报头类型

Caution:
调用者需要保证IPv6头连续
软中断、内核线程或进程的内核态中调用此函数

Description∶ 根据输入的偏移和类型，获取下—报头的偏移和类型 
*****************************************************************************/
STATIC ULONG IP6_GetBufNextHdr
(
	IN const MBUF_S *pstMBuf,
	INOUT UINT *puiOff,
	INOUT UCHAR *pucProto
) 
{
	IP6_S *pstIp6 = NULL; 
	struct ip6_frag *pstIp6Frag = NULL;
	struct ip6_ext *pstIp6Ext = NULL;
	UINT uiNxtOff;
	UCHAR ucNxtProto;

	/* 检查参数的合法性 */
	DBGASSERT(NULL != pstMBuf);
	DBGASSERT(NULL != puiOff); 
	DBGASSERT(NULL != pucProto);

	uiNxtOff = *puiOff;
	ucNxtProto = *pucProto;

	if (0 == uiNxtOff)
	{
		/* 得到IPv6头中的下一个扩展头类型和偏移 */
		pstIp6 = MBUF_BTOD_OFFSET(pstMBuf, 0U, IP6_S *);
		*puiOff = sizeof(IP6_S);
		*pucProto = pstIp6->ip6_ucNxtHdr;
		return ERROR_SUCCESS;
	}

	/* 根据前—个扩展头分别处理 */
	switch (ucNxtProto)
	{
		case IPPROTO_FRAGMENT:
		{
			/* 得到分片扩展头数据指针 */
			pstIp6Frag = IP6_GetBufExtHdr(pstMBuf,uiNxtOff); 
			if (NULL == pstIp6Frag)
			{
				return ERROR_FAILED;
			}

			/* 目前只支持处理第一个分片报文 */
			if (0 != (ntohs(pstIp6Frag->ip6f_offlg) & IP6F_OFF_MASK))
			{
				/* 此时下一个扩展头无意义 */
				return ERROR_FAILED;
			}

			/* 得到下一个扩展头的类型和偏移 */
			ucNxtProto = pstIp6Frag->ip6f_nxt;
			uiNxtOff += sizeof(struct ip6_frag);
			break;
		}

		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
		{
			/* 得到扩展头数据指针 */
			pstIp6Ext = IP6_GetBufExtHdr(pstMBuf, uiNxtOff);
			if (NULL == pstIp6Ext)
			{
				return ERROR_FAILED;
			}

			/* 得到下一个扩展头的类型和偏移 */
			ucNxtProto = pstIp6Ext->ip6e_nxt;
			uiNxtOff += ((UINT)pstIp6Ext->ip6e_len + 1) << 3; 
			break;
		}

		default:
		{
			/* 出参值未变 */
			break;
		}
	}

	/* 给出参赋值 */
	*pucProto = ucNxtProto;
	*puiOff = uiNxtOff;

	return ERROR_SUCCESS;
}


/*****************************************************************************
      Input: FSBUF_BLOCKINFO_S *pstBlockInfo，Buf指针
		     UINT *puiOff 当前扩展头偏移
		     UCHAR *pucProto 当前扩展头类型
     Output：UINT *puiOff 上层协议偏移
		     UCHAR *pucProto 上层协议类型
    Caution: 本函数可以从某扩展头开始获取报文中的上层协议，也可以从IPv6头开始。
             从IPv6头开始时*puiOff = 0，*pucProto = IPPROTO_IPV6
Description: 获取报文中的上层协议类型和偏移
*****************************************************************************/
ULONG IP6_GetBufLastHdr 
(
	IN const MBUF_S *pstMBuf,
	INOUT UINT *puiOff,
	INOUT UCHAR *pucProto
)
{
	ULONG ulResult = 0;
	UINT uiOff;
	UINT uiNewOff;
	UCHAR ucNxt;
	IP6_S *pstIp6;

	/* 检查参数的合法性 */
	if ((NULL == pstMBuf) || (NULL == puiOff) || (NULL == pucProto))
	{
		return ERROR_FAILED;
	}

	ucNxt = *pucProto;
	uiOff = *puiOff;

	/* 支持IPv6头偏移不为0的情况 */
	if (IPPROTO_IPV6 == ucNxt)
	{
		/* 先偏移到下—个扩展头 */
		pstIp6 = (IP6_S*)IP6_GetBufExtHdr(pstMBuf, uiOff);
		if (NULL == pstIp6)
		{
			return ERROR_FAILED;
		}

		uiOff += sizeof(IP6_S);
		ucNxt = pstIp6->ip6_ucNxtHdr;
	}

	uiNewOff = uiOff;
	for ( ; ; )
	{
		ulResult = IP6_GetBufNextHdr(pstMBuf, &uiNewOff, &ucNxt);
		if (ERROR_SUCCESS != ulResult)
		{
			return ERROR_FAILED;
		}

		/* 已经获取到上层协议 */
		if (uiNewOff == uiOff)
		{
			break;
		}

		/* 下一头还是扩展头，需要继续遍历 */
		uiOff = uiNewOff;
	}

	*puiOff = uiNewOff;
	*pucProto = ucNxt;

	return ERROR_SUCCESS;
}
