#include "ip6fw.h"
#include "session_util.h"
#include "ip6_util.h"

/****************************************************************************    
      Input: MBUF_S *pstMBuf, MBufָ�� 
             UINT *puiOff ��ǰ��չͷƫ��
             UCHAR *pucProto ��ǰ��չͷ����
     Output: UINT *puiOff    ��һ��ͷƫ��
             UCHAR *pucProto ��һ��ͷ����
     return: ERROR_SUCCESS ��ȡ��һ��ͷ�ɹ�
             ERROR_FAILED  ��ȡ��һ��ͷʧ��
    Caution: ��������Ҫ��֤IPv6ͷ����
Description: ���������ƫ�ƺ����ͣ���ȡ��һ��ͷ��ƫ�ƺ�����

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

    /* �������ĺϷ��� */
    DBGASSERT(NULL != pstMBuf);
    DBGASSERT(NULL != puiOff);
    DBGASSERT(NULL != pucProto);

    uiNxtOff = *puiOff;
    ucNxtProto = *pucProto;

    if (0 == uiNxtOff)
    {
        /* �õ�IPv6ͷ�е���һ����չͷ���ͺ�ƫ�� */
        pstIp6 = MBUF_BTOD(pstMBuf, IP6_S *);
        *puiOff = sizeof(IP6_S);
        *pucProto = pstIp6->ip6_ucNxtHdr;
        return ERROR_SUCCESS;
    }

    /* ����ǰһ����չͷ�ֱ��� */
    switch (ucNxtProto)
    {
        case IPPROTO_FRAGMENT:
        {
            /* �õ���Ƭ��չͷ����ָ�� */
            pstIp6Frag = IP6_GetExtHdr(pstMBuf, uiNxtOff, (UINT32)sizeof(struct ip6_frag));
            if (NULL == pstIp6Frag)
            {
                return ERROR_FAILED;
            }

            /* Ŀǰֻ֧�ִ����һ����Ƭ���� */
            if(0 != (ntohs(pstIp6Frag->ip6f_offlg) & IP6F_OFF_MASK))
            {
                /* ��ʱ��һ����չͷ������ */
                return ERROR_FAILED;
            }

            /* �õ���һ����չͷ�����ͺ�ƫ�� */
            ucNxtProto = pstIp6Frag->ip6f_nxt;
            uiNxtOff += sizeof(struct ip6_frag);
            break;
        }
        
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_DSTOPTS:
        {
            /* �õ���չͷ����ָ�� */
            pstIp6Ext = IP6_GetExtHdr(pstMBuf, uiNxtOff, (UINT32)sizeof(struct ip6_ext));
            if(NULL == pstIp6Ext)
            {
                return ERROR_FAILED;
            }
            
            /* �õ���һ����չͷ�����ͺ�ƫ�� */
            ucNxtProto = pstIp6Ext->ip6e_nxt;
            uiNxtOff += ((UINT)pstIp6Ext->ip6e_len + 1) << 3;

            /* �����һ����չͷ�������Ƿ��㹻 */
            ulRet = MBUF_PULLUP(pstMBuf, uiNxtOff);
            if (ERROR_SUCCESS != ulRet)
            {
                return ERROR_FAILED;
            }

            break;
        }

        default :
        {
            /* ����ֵδ�� */
            break;
        }
    }

    /* �����θ�ֵ */
    *pucProto = ucNxtProto;
    *puiOff = uiNxtOff;
    return ERROR_SUCCESS;
}



/****************************************************************************    
      Input: MBUF_S *pstMBuf, MBufָ�� 
             UINT *puiOff ��ǰ��չͷƫ��
             UCHAR *pucProto ��ǰ��չͷ����
     Output: UINT *puiOff �ϲ�Э��ƫ��
             UCHAR *pucProto �ϲ�Э������
     return: ERROR_SUCCESS ��ȡ��һ��ͷ�ɹ�
             ERROR_FAILED  ��ȡ��һ��ͷʧ��
    Caution: ���������Դ�ĳ��չͷ��ʼ��ȡ�����е��ϲ�Э�飬Ҳ���Դ�IPv6ͷ��ʼ��
             ��IPv6ͷ��ʼʱ*puiOff = 0, *pucProto = IPPROTO_IPV6
Description: ��ȡ�����е��ϲ�Э�����ͺ�ƫ��

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

    /* �������ĺϷ��� */
    if((NULL == pstMBuf) || (NULL == puiOff) || (NULL == pucProto))
    {
        return ERROR_FAILED;
    }

    ucNxt = *pucProto;
    uiOff = *puiOff;

    /* ֧��IPv6ͷƫ�Ʋ�Ϊ0����� */
    if (IPPROTO_IPV6 == ucNxt)
    {
        /* ��ƫ�Ƶ���һ����չͷ */
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

        /* �Ѿ���ȡ���ϲ�Э�� */
        if (uiNewOff == uiOff)
        {
            break;
        }

        /* ��һͷ������չͷ����Ҫ�������� */
        uiOff = uiNewOff;
    }
            
    *puiOff = uiNewOff;
    *pucProto = ucNxt;
    return ERROR_SUCCESS;
}

/************************************************************************ 
Input: 	FSBUF_BLOCKINFO_S *pstBlockInfo�� Bufָ��
		UINT *puiOff ��ǰ��չͷƫ��
		UCHAR *pucProto ��ǰ��չͷ����

Output: UINT *puiOff ��һ��ͷƫ��
		UCHAR *pucProto ��һ��ͷ����

Caution:
��������Ҫ��֤IPv6ͷ����
���жϡ��ں��̻߳���̵��ں�̬�е��ô˺���

Description�� ���������ƫ�ƺ����ͣ���ȡ�¡���ͷ��ƫ�ƺ����� 
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

	/* �������ĺϷ��� */
	DBGASSERT(NULL != pstMBuf);
	DBGASSERT(NULL != puiOff); 
	DBGASSERT(NULL != pucProto);

	uiNxtOff = *puiOff;
	ucNxtProto = *pucProto;

	if (0 == uiNxtOff)
	{
		/* �õ�IPv6ͷ�е���һ����չͷ���ͺ�ƫ�� */
		pstIp6 = MBUF_BTOD_OFFSET(pstMBuf, 0U, IP6_S *);
		*puiOff = sizeof(IP6_S);
		*pucProto = pstIp6->ip6_ucNxtHdr;
		return ERROR_SUCCESS;
	}

	/* ����ǰ������չͷ�ֱ��� */
	switch (ucNxtProto)
	{
		case IPPROTO_FRAGMENT:
		{
			/* �õ���Ƭ��չͷ����ָ�� */
			pstIp6Frag = IP6_GetBufExtHdr(pstMBuf,uiNxtOff); 
			if (NULL == pstIp6Frag)
			{
				return ERROR_FAILED;
			}

			/* Ŀǰֻ֧�ִ����һ����Ƭ���� */
			if (0 != (ntohs(pstIp6Frag->ip6f_offlg) & IP6F_OFF_MASK))
			{
				/* ��ʱ��һ����չͷ������ */
				return ERROR_FAILED;
			}

			/* �õ���һ����չͷ�����ͺ�ƫ�� */
			ucNxtProto = pstIp6Frag->ip6f_nxt;
			uiNxtOff += sizeof(struct ip6_frag);
			break;
		}

		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
		{
			/* �õ���չͷ����ָ�� */
			pstIp6Ext = IP6_GetBufExtHdr(pstMBuf, uiNxtOff);
			if (NULL == pstIp6Ext)
			{
				return ERROR_FAILED;
			}

			/* �õ���һ����չͷ�����ͺ�ƫ�� */
			ucNxtProto = pstIp6Ext->ip6e_nxt;
			uiNxtOff += ((UINT)pstIp6Ext->ip6e_len + 1) << 3; 
			break;
		}

		default:
		{
			/* ����ֵδ�� */
			break;
		}
	}

	/* �����θ�ֵ */
	*pucProto = ucNxtProto;
	*puiOff = uiNxtOff;

	return ERROR_SUCCESS;
}


/*****************************************************************************
      Input: FSBUF_BLOCKINFO_S *pstBlockInfo��Bufָ��
		     UINT *puiOff ��ǰ��չͷƫ��
		     UCHAR *pucProto ��ǰ��չͷ����
     Output��UINT *puiOff �ϲ�Э��ƫ��
		     UCHAR *pucProto �ϲ�Э������
    Caution: ���������Դ�ĳ��չͷ��ʼ��ȡ�����е��ϲ�Э�飬Ҳ���Դ�IPv6ͷ��ʼ��
             ��IPv6ͷ��ʼʱ*puiOff = 0��*pucProto = IPPROTO_IPV6
Description: ��ȡ�����е��ϲ�Э�����ͺ�ƫ��
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

	/* �������ĺϷ��� */
	if ((NULL == pstMBuf) || (NULL == puiOff) || (NULL == pucProto))
	{
		return ERROR_FAILED;
	}

	ucNxt = *pucProto;
	uiOff = *puiOff;

	/* ֧��IPv6ͷƫ�Ʋ�Ϊ0����� */
	if (IPPROTO_IPV6 == ucNxt)
	{
		/* ��ƫ�Ƶ��¡�����չͷ */
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

		/* �Ѿ���ȡ���ϲ�Э�� */
		if (uiNewOff == uiOff)
		{
			break;
		}

		/* ��һͷ������չͷ����Ҫ�������� */
		uiOff = uiNewOff;
	}

	*puiOff = uiNewOff;
	*pucProto = ucNxt;

	return ERROR_SUCCESS;
}
