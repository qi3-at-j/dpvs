#include <sys/shm.h>
#include <sys/timeb.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include "ipfw.h"
#include "flow.h"
#include "session_mbuf.h"
#include "apr.h"
#include "dpi.h"

#include "../../include/start_process.h"

#define DPI_ETH_LEN 14
static DPI_GRP_S *g_pst_dpi = NULL;

UINT32 g_ips_enable;/*ips switch*/
UINT32 g_apr_enable;/*apr switch*/

UINT32 GetPktLenFromMbuf(IN const struct rte_mbuf *pstRteMbuf)
{
    UINT32 uiPktLen = rte_pktmbuf_data_len(pstRteMbuf) + DPI_ETH_LEN;
    return uiPktLen;
}

UCHAR* GetPktFromMbuf(IN const struct rte_mbuf *pstRteMbuf)
{
    UCHAR* pucPkt = pstRteMbuf->buf_addr + pstRteMbuf->data_off - DPI_ETH_LEN;
    return pucPkt;
}

UINT32 GetVrfIDFromMbuf(IN const MBUF_S *pstMbuf)
{
    conn_sub_t *csp;	
    csp_key_t *pstcspkey;
    UINT uiVrf;
    csp = GET_CSP_FROM_LBUF(pstMbuf);
    pstcspkey = GET_CSP_KEY(csp);
    uiVrf = pstcspkey->token;
    uiVrf = ntohl(uiVrf);
    return uiVrf;
}

UINT SuriToFWAction(IN UINT uiAction)
{
    UINT uiPktAction = PKT_CONTINUE;
    switch(uiAction)
    {
        case SURI_ACTION_DROP:
        case SURI_ACTION_REJECT:
        case SURI_ACTION_REJECT_DST:
        case SURI_ACTION_REJECT_BOTH:
            uiPktAction = PKT_DROPPED;
            break;
        case SURI_ACTION_ALERT:
        default:
            break;
    }
    return uiPktAction;
}

VOID DPI_Check(IN const MBUF_S *pstMbuf, IN UINT uiServiceMask, INOUT DPI_PARA_S *pstDPI)
{
    DPI_PKT_S *pstDpiPkt = NULL;
    UINT uiCoreID = rte_lcore_id();
    struct timeb stStart = {0, 0};
    struct timeb stEnd = {0, 0}; 
    UINT uiTimeSpace = 0;
    UINT32 uiAppOld = pstDPI->uiAppID;
    struct rte_mbuf *pstRteMbuf = rte_mbuf_from_mbuf(pstMbuf);

    if ((NULL == pstDPI) || (uiCoreID >= DPI_PKT_NUM_MAX))
    {
        return;
    }

    pstDPI->uiAction = PKT_CONTINUE;

    if (!DPI_IsRun() || (g_pst_dpi == NULL))
    {
        return;
    }

    if ((!g_apr_enable) || (pstDPI->uiTrustValue == APR_TRUST_SIG_FINAL))
    {
        BIT_CLEAR(uiServiceMask, PKT_SERVICE_TYPE_APR);
    }

    if (!g_ips_enable)
    {
        BIT_CLEAR(uiServiceMask, PKT_SERVICE_TYPE_IPS);
    }

    if (uiServiceMask == 0)
    {
        return;
    }

     /* 发生了超时、线程异常等处理错误 */
    BIT_CLEAR(g_pst_dpi->uiMask, uiCoreID);
    BIT_CLEAR(g_pst_dpi->uiRFMask, uiCoreID);
    pstDpiPkt = &(g_pst_dpi->astPktInfo[uiCoreID]);
    pstDpiPkt->uiAction = PKT_ACTION_INVALID;
    pstDpiPkt->uiLen = GetPktLenFromMbuf(pstRteMbuf);
    pstDpiPkt->uiVrfID = GetVrfIDFromMbuf(pstMbuf);
    //printf("vrfid %d\n", pstDpiPkt->uiVrfID);
    pstDpiPkt->uiServiceMask = uiServiceMask;
    pstDpiPkt->uiAppID = APR_ID_INVALID;
    pstDpiPkt->uiDirect = pstDPI->uiDirect;

    //printf("mempool\n");
    mbuf_may_pull(pstRteMbuf, pstDpiPkt->uiLen);
    pstDpiPkt->pucPktBuf = GetPktFromMbuf(pstRteMbuf);
    /* 避免suricata读取无效值，需后置 */
    BIT_SET(g_pst_dpi->uiMask, uiCoreID);

    ftime(&stStart);

    while ((uiServiceMask) && (uiTimeSpace < 1000))
    {
        if (BIT_TEST(uiServiceMask, PKT_SERVICE_TYPE_APR)
            && (pstDpiPkt->uiAppID != APR_ID_INVALID))
        {
            BIT_CLEAR(uiServiceMask, PKT_SERVICE_TYPE_APR);
        }
        if (BIT_TEST(uiServiceMask, PKT_SERVICE_TYPE_IPS)
            && (pstDpiPkt->uiAction != PKT_ACTION_INVALID))
        {
            BIT_CLEAR(uiServiceMask, PKT_SERVICE_TYPE_IPS);
        }

        ftime(&stEnd);
        uiTimeSpace = (stEnd.time - stStart.time) * 1000 + (stEnd.millitm - stStart.millitm);
    }

    BIT_CLEAR(g_pst_dpi->uiMask, uiCoreID);

    if (BIT_TEST(pstDpiPkt->uiServiceMask, PKT_SERVICE_TYPE_IPS) && 
        (pstDpiPkt->uiAction != PKT_ACTION_INVALID))
    {
        pstDPI->uiAction = SuriToFWAction(pstDpiPkt->uiAction);
        //printf("action %d\n", pstDPI->uiAction);
    }

    if (BIT_TEST(pstDpiPkt->uiServiceMask, PKT_SERVICE_TYPE_APR) && 
        (pstDpiPkt->uiAppID != APR_ID_INVALID))
    {
        if (pstDpiPkt->uiAppID == APR_ID_OTHER && uiAppOld != APR_ID_INVALID)
        {
            pstDPI->uiAppID = uiAppOld;
        }
        else if (BIT_TEST(pstDpiPkt->uiGrpID, DPI_GRP_FINAL))
        {
            pstDPI->uiTrustValue = APR_TRUST_SIG_FINAL;
            pstDPI->uiAppID = pstDpiPkt->uiAppID;
        }
        else if (pstDpiPkt->uiAppID != APR_ID_OTHER)
        {
            pstDPI->uiTrustValue = APR_TRUST_SIG_BASE;
            pstDPI->uiAppID = pstDpiPkt->uiAppID;
        }

        //printf("appid %d\n", pstDPI->uiAppID);
    }

    return;
}

VOID IPS_Check(IN const MBUF_S *pstMbuf, INOUT IPS_PARA_S *pstIPS)
{
    DPI_PARA_S stDPI;
    UINT32 uiMask = 0;
    BIT_SET(uiMask, PKT_SERVICE_TYPE_IPS);
    stDPI.uiDirect = pstIPS->uiDirect;
    DPI_Check(pstMbuf, uiMask, &stDPI);
    pstIPS->uiAction = stDPI.uiAction;
    return;
}

VOID APR_Check(IN const MBUF_S *pstMbuf, INOUT APR_PARA_S *pstAPR)
{
    DPI_PARA_S stRet;
    UINT32 uiMask = 0;
    BIT_SET(uiMask, PKT_SERVICE_TYPE_APR);
    stRet.uiAppID = pstAPR->uiAppID;
    stRet.uiTrustValue = pstAPR->uiTrustValue;
    DPI_Check(pstMbuf, uiMask, &stRet);
    pstAPR->uiAppID = stRet.uiAppID;
    pstAPR->uiTrustValue = stRet.uiTrustValue;
    return;
}

VOID DPI_Init(VOID)
{
    g_ips_enable = 1;
    g_apr_enable = 1;
    /*addzzz*/
    const struct rte_memzone *mz;
    mz = rte_memzone_reserve("share_mem_test", sizeof(DPI_GRP_S),
				rte_socket_id(), 0);
	if (mz == NULL)
		printf("Cannot reserve memory zone for IPC\n");
	memset(mz->addr, 0, sizeof(DPI_GRP_S));

    g_pst_dpi = (DPI_GRP_S *)mz->addr;

	printf("Finished Process Init. memzone %p\n", mz->addr);

    return;
}

