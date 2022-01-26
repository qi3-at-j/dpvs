
#include "baseype.h"
#include "session_mbuf.h"

MBUF_EXTINFOFREEFUNC_PF g_apfMBUF_ExtInfoFreeFunc[MBUF_CACHE_MAX]; /* �����չ��Ϣ�ͷ�֪ͨ���� */

#if 0

/* �ṩ����BUF ģ�飬���ڿ�BUF����ǰ�ͷ������չ��Ϣ */
VOID MBUF_FreeExtInfo(INOUT MBUF_S *pstMBuf)
{
    ULONG i;

    DBGASSERT(NULL != pstMBuf);

    /* �ͷ������չ��Ϣ */
    for (i = 0; i < MBUF_CACHE_MAX; i++)
    {
        if (NULL != pstMBuf->apCache[i])
        {
            DBGASSERT(NULL != g_apfMBUF_ExtInfoFreeFunc[i]);
            (VOID)g_apfMBUF_ExtInfoFreeFunc[i](pstMBuf);

            pstMBuf->apCache[i] = NULL;
        }
    }

    pstMBuf->ucCacheBitmap = 0;

    return;
}
#endif

VOID MBUF_RegExtCacheFreeFunc(IN MBUF_CACHE_ID_E enId, IN MBUF_EXTINFOFREEFUNC_PF pfFunc)
{
    if(enId < MBUF_CACHE_MAX)
    {
        g_apfMBUF_ExtInfoFreeFunc[enId] = pfFunc;
    }

    return;
}

