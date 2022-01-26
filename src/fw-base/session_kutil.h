#ifndef _SESSION_KUTIL_H_
#define _SESSION_KUTIL_H_

#include "session.h"
#include "apr.h"
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_atomic.h>

static inline VOID *_session_kmalloc_percpu(IN ULONG ulTypeSize)
{
    ULONG ulMemTotalLen;
    VOID *pBuf;

    /* TODO ��rte_lcore_count()������һ��ȫ�ֱ������� */
    ulMemTotalLen = ulTypeSize * worker_thread_total();
    pBuf = rte_zmalloc(NULL, ulMemTotalLen, 0);
    return pBuf;
}

#define SESSION_KMALLOC_PERCPU(_type)  _session_kmalloc_percpu(sizeof(_type))

static inline VOID *_session_kmalloc_percpu_two(IN ULONG ulTypeSize)
{
    ULONG ulMemTotalLen;
    VOID *pBuf;

    ulMemTotalLen = ulTypeSize * worker_thread_total();
    pBuf = rte_zmalloc(NULL, ulMemTotalLen, 0);
    return pBuf;
}

#define SESSION_KMALLOC_PERCPU_TWO(_type) _session_kmalloc_percpu_two(sizeof(_type))

#define SESSION_KFREE_PERCPU(_ptr) rte_free(_ptr)


/* ��ʼ������ͳ�� */
static inline VOID SESSION_KInitFlowRate(IN const MBUF_S *pstMBuf, OUT SESSION_S *pstSession)
{
    rte_atomic32_set(&(pstSession->_astBytes[SESSION_DIR_ORIGINAL]), (INT)MBUF_GET_TOTALDATASIZE(pstMBuf));    
    rte_atomic32_set(&(pstSession->_astPackets[SESSION_DIR_ORIGINAL]), (INT)1);

    return;
}

/******************************************************************
   Func Name:SESSION_KUpdateRateStat
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�л�����ͳ������
       INPUT:IN SESSION_RATE_STAT_S *pstRateStat
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline VOID SESSION_KUpdateRateStat(INOUT SESSION_RATE_STAT_S *pstRateStat)
{
    ULONG ulCycles = rte_get_timer_cycles();

    if (ulCycles < pstRateStat->ulLastJiffies)
    {
        pstRateStat->ulLastJiffies = 0;
    }

    /* �ȼ����ֵ����ֹ�豸��ʱ�����е���jiffiesǿ��LONG����Ϊ�� */
    if (time_after_eq(ulCycles, pstRateStat->ulLastJiffies+rte_get_timer_hz()*2))
    {
        pstRateStat->uiLastSecondRate = 0;
        pstRateStat->ulLastJiffies = ulCycles;
        pstRateStat->uiCurrCount = 0;
    }
    else if (time_after_eq(ulCycles, pstRateStat->ulLastJiffies+rte_get_timer_hz())) 
    { 
        pstRateStat->uiLastSecondRate = pstRateStat->uiCurrCount;
        pstRateStat->ulLastJiffies = ulCycles;
        pstRateStat->uiCurrCount = 0;
    }
    /* jiffies��ʼ��ffffff00ʱ��ǿתLONGΪ������ǰ������if�ж϶��᷵��FALSE*/
    else if ((pstRateStat->ulLastJiffies == 0) && (ulCycles < 0))
    {
        pstRateStat->uiLastSecondRate = 0;
        pstRateStat->ulLastJiffies = ulCycles;
        pstRateStat->uiCurrCount = 0;
    }

    return;
}

static inline SESSION_ALLSTAT_TYPE_E _session_get_allstat_type(IN SESSION_L4_TYPE_E enSessL4Type)
{
    SESSION_ALLSTAT_TYPE_E enSessAllStatType;

    switch(enSessL4Type)
    {
        case SESSION_L4_TYPE_TCP:
        {
            enSessAllStatType = SESSION_ALLSTAT_TYPE_TCP;
            break;
        }
        case SESSION_L4_TYPE_UDP:
        {
            enSessAllStatType = SESSION_ALLSTAT_TYPE_UDP;
            break;
        }
        default:
        {
            enSessAllStatType = SESSION_ALLSTAT_TYPE_RAWIP;
            break;
        }
    }
    return enSessAllStatType;
}

/******************************************************************
   Func Name:SESSION_GetAppIDIndex
Date Created:2021/04/25
      Author:wangxiaohua
 Description:��ȡAppID��Ӧ�������±�
       INPUT:IN UINT uiAppID
      Output:��
      Return:ƥ��ĻỰAppid type
             SESSION_ALG_TYPE_MAX ûƥ��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline USHORT SESSION_GetAppIDIndex (IN UINT uiAppID)
{
    USHORT usAppIDType = SESSION_APP_STATIC_MAX;

    if(SESSION_APPID_MAX > uiAppID)
    {
        usAppIDType = (USHORT)g_aenAppIndex[uiAppID];
    }

    return usAppIDType;
}

/******************************************************************
   Func Name:SESSION_InitMapAppType
Date Created:2021/04/25
      Author:wangxiaohua
 Description:��ʼ��AppID��������
       INPUT:
      Output:
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline VOID SESSION_InitMapAppType(VOID)
{
    UINT uiLoop;

    for (uiLoop = 0; uiLoop < SESSION_APPID_MAX; uiLoop++)
    {
        g_aenAppIndex[uiLoop] = SESSION_APP_STATIC_MAX;
    }    
    g_aenAppIndex[APP_ID_DNS]        = SESSION_APP_STATIC_DNS;
    g_aenAppIndex[APP_ID_FTP]        = SESSION_APP_STATIC_FTP;
    g_aenAppIndex[APP_ID_GTPC]       = SESSION_APP_STATIC_GTPC;
    g_aenAppIndex[APP_ID_GTPU]       = SESSION_APP_STATIC_GTPU;
    g_aenAppIndex[APP_ID_GPRSDATA]   = SESSION_APP_STATIC_GPRSDATA;
    g_aenAppIndex[APP_ID_GPRSSIG]    = SESSION_APP_STATIC_GPRSSIG;
    g_aenAppIndex[APP_ID_RAS]        = SESSION_APP_STATIC_RAS;
    g_aenAppIndex[APP_ID_H225]       = SESSION_APP_STATIC_H225;
    g_aenAppIndex[APP_ID_H245]       = SESSION_APP_STATIC_H245;
    g_aenAppIndex[APP_ID_HTTP]       = SESSION_APP_STATIC_HTTP;
    g_aenAppIndex[APP_ID_ILS]        = SESSION_APP_STATIC_ILS;
    g_aenAppIndex[APP_ID_MGCPC]      = SESSION_APP_STATIC_MGCPC;
    g_aenAppIndex[APP_ID_MGCPG]      = SESSION_APP_STATIC_MGCPG;
    g_aenAppIndex[APP_ID_NETBIOSNS]  = SESSION_APP_STATIC_NETBIOSNS;
    g_aenAppIndex[APP_ID_NETBIOSDGM] = SESSION_APP_STATIC_NETBIOSDGM;
    g_aenAppIndex[APP_ID_NETBIOSSSN] = SESSION_APP_STATIC_NETBIOSSSN;
    g_aenAppIndex[APP_ID_PPTP]       = SESSION_APP_STATIC_PPTP;
    g_aenAppIndex[APP_ID_RSH]        = SESSION_APP_STATIC_RSH;
    g_aenAppIndex[APP_ID_RTSP]       = SESSION_APP_STATIC_RTSP;
    g_aenAppIndex[APP_ID_SCCP]       = SESSION_APP_STATIC_SCCP;
    g_aenAppIndex[APP_ID_SIP]        = SESSION_APP_STATIC_SIP;
    g_aenAppIndex[APP_ID_SMTP]       = SESSION_APP_STATIC_SMTP;
    g_aenAppIndex[APP_ID_SQLNET]     = SESSION_APP_STATIC_SQLNET;
    g_aenAppIndex[APP_ID_SSH]        = SESSION_APP_STATIC_SSH;
    g_aenAppIndex[APP_ID_TELNET]     = SESSION_APP_STATIC_TELNET;
    g_aenAppIndex[APP_ID_TFTP]       = SESSION_APP_STATIC_TFTP;
    g_aenAppIndex[APP_ID_XDMCP]      = SESSION_APP_STATIC_XDMCP;

    return;
}

/******************************************************************
   Func Name:SESSION_KAppProtoCount
Date Created:2021/04/25
      Author:wangxiaohua
 Description:����Ӧ�ò�Ự��ͳ��
       INPUT:IN UINT uiAppID
      Output:OUT SESSION_K_STATISTICS_S *pstStat
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline VOID SESSION_KAppProtoCount(IN UINT uiAppID, OUT SESSION_K_STATISTICS_S *pstStat)
{
    USHORT usAppIDType;

    usAppIDType = SESSION_GetAppIDIndex(uiAppID);
    if(usAppIDType < SESSION_APP_STATIC_MAX)
    {
        rte_atomic32_inc(&pstStat->astAppCount[usAppIDType]);
    }

    return;
}

/******************************************************************
   Func Name:SESSION_KAppProtoDec
Date Created:2021/04/25
      Author:wangxiaohua
 Description:Ӧ�ò�Ự��ͳ�Ƽ���
       INPUT:IN UINT uiAppID
      Output:OUT SESSION_K_STATISTICS_S *pstStat
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline VOID SESSION_KAppProtoDec(IN UINT uiAppID, OUT SESSION_K_STATISTICS_S *pstStat)
{
    USHORT usAppIDType;

    usAppIDType = SESSION_GetAppIDIndex(uiAppID);
    if(usAppIDType < SESSION_APP_STATIC_MAX)
    {
        rte_atomic32_dec(&pstStat->astAppCount[usAppIDType]);
    }

    return;
}

/******************************************************************
   Func Name:SESSION_KAddStat
Date Created:2021/04/25
      Author:wangxiaohua
 Description:���ӻỰ��ͳ��
       INPUT:IN SESSION_CTRL_S *pstSessionCtrl
             IN SESSION_L4_TYPE_E enSessType
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline VOID SESSION_KAddStat(IN SESSION_CTRL_S *pstSessionCtrl, IN SESSION_L4_TYPE_E enSessType, IN UINT uiAppID)
{
    SESSION_K_STATISTICS_S *pstStat;
    SESSION_STAT_VCPU_S *pstVcpuStat;
    SESSION_ALLSTAT_TYPE_E enSessAllStatType;
    UINT uiCpuIndex;

    pstStat = &(pstSessionCtrl->stSessStat);

    /* ���ӻỰ�½�����ͳ�� */
    uiCpuIndex = index_from_lcore_id();
    pstVcpuStat = SESSION_GET_PERCPU_PTR(pstStat->pstVcpuStat, uiCpuIndex);
    SESSION_KUpdateRateStat(&pstVcpuStat->astRateStat[enSessType]);
    pstVcpuStat->astRateStat[enSessType].uiCurrCount++;
    rte_atomic32_add(&pstStat->astProtoCount[enSessType], 1);
    enSessAllStatType = _session_get_allstat_type(enSessType);
    rte_atomic64_add(&pstStat->astSessAllStatCount[enSessAllStatType], (LONG LONG)1);
    SESSION_KAppProtoCount(uiAppID, pstStat);
    
    return;
}

#endif