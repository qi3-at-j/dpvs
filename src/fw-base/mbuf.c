
#include "baseype.h"
#include "session_mbuf.h"

MBUF_EXTINFOFREEFUNC_PF g_apfMBUF_ExtInfoFreeFunc[MBUF_CACHE_MAX]; /* 外挂扩展信息释放通知函数 */

#if 0

/* 提供给快BUF 模块，用于快BUF回收前释放外挂扩展信息 */
VOID MBUF_FreeExtInfo(INOUT MBUF_S *pstMBuf)
{
    ULONG i;

    DBGASSERT(NULL != pstMBuf);

    /* 释放外挂扩展信息 */
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

