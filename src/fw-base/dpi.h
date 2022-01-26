#ifndef _DPI_H_
#define _DPI_H_

#define DPI_PKT_NUM_MAX     16

#define PKT_ACTION_INVALID (-1)

#define SURI_ACTION_ALERT        0x01
#define SURI_ACTION_DROP         0x02
#define SURI_ACTION_REJECT       0x04
#define SURI_ACTION_REJECT_DST   0x08
#define SURI_ACTION_REJECT_BOTH  0x10
#define SURI_ACTION_PASS         0x20
#define SURI_ACTION_CONFIG       0x40

enum PktServiceTypeEnum {
    PKT_SERVICE_TYPE_APR,
    PKT_SERVICE_TYPE_IPS,
    PKT_SERVICE_TYPE_NUM,
};

enum DpiGrpMask {
    DPI_GRP_BASE = 0,
    DPI_GRP_FINAL,
    DPI_GRP_VPATCH,
};

enum PktDirectEnum {
    PKT_DIRECT_INVALID,
    PKT_DIRECT_IN,
    PKT_DIRECT_OUT
};

typedef struct tagDpiPkt
{
    UINT32 uiLen;
    UINT32 uiVrfID;
    UINT32 uiServiceMask;  /* 1-APR; 2-IPS; */
    UINT32 uiDirect;
    UINT32 uiAction;
    UINT32 uiAppID;
    UINT32 uiGrpID;        /*group id = 1 need apr check continue*/
    UCHAR *pucPktBuf;
}DPI_PKT_S;

typedef struct tagDpiPktGrp
{
    volatile UINT32 uiMask;
    volatile UINT32 uiRFMask;
    DPI_PKT_S astPktInfo[DPI_PKT_NUM_MAX];
}DPI_GRP_S;

typedef struct tagDpiPara
{
    UINT32 uiAppID;
    UINT32 uiTrustValue;
    UINT32 uiDirect;
    UINT32 uiAction;
}DPI_PARA_S;

typedef struct tagAprPara
{
    UINT32 uiAppID;
    UINT32 uiTrustValue;
}APR_PARA_S;

typedef struct tagIpsPara
{
    UINT32 uiDirect;
    UINT32 uiAction;
}IPS_PARA_S;

VOID DPI_Init(VOID);
VOID DPI_Check(IN const MBUF_S *pstMbuf, UINT uiServiceMask, INOUT DPI_PARA_S *pstDPI);
void IPS_Check(IN const MBUF_S *pstMbuf, INOUT IPS_PARA_S *pstIPS);
VOID APR_Check(IN const MBUF_S *pstMbuf, INOUT APR_PARA_S *pstAPR);

#endif

