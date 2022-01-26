#ifndef _SESSION_KALG_H_
#define _SESSION_KALG_H_

#include "baseype.h"
#include "session_mbuf.h"

/* ALG扩展信息备份回调函数 */
typedef ULONG(*SESSION_KALG_IPV4_PROC_PF)(IN MBUF_S *pstMbuf,
                                          IN UINT uiL3OffSet,
                                          IN SESSION_HANDLE hSession);

/* ALG扩展信息备份回调函数 */
typedef ULONG(*SESSION_KALG_IPV4_FAST_PROC_PF)(IN SESSION_HANDLE hSession,
											   IN MBUF_S *pstMBuf,
											   IN UINT uiL3Offset,
											   INOUT struct iphdr *pstIPHdr);

/* ALG扩展信息备份回调函数 */
typedef ULONG(*SESSION_KALG_IPV6_PROC_PF)(IN MBUF_S *pstMbuf,
                                          IN UINT uiL3OffSet,
                                          IN SESSION_HANDLE hSession);


/* ALG扩展信息备份回调函数 */
typedef ULONG(*SESSION_KALG_IPV6_FAST_PROC_PF)(IN SESSION_HANDLE hSession,
											   IN MBUF_S *pstMBuf,
											   IN UINT uiL3Offset);
typedef struct tagSessionALGIPV4
{
	SESSION_KALG_IPV4_PROC_PF pfAlgIPv4Proc;  /* ALG的IPV4慢转转处理函数 */
}SESSION_KALG_IPV4_PROC_S;

typedef struct tagSessionALGIPV6
{
	SESSION_KALG_IPV6_PROC_PF pfAlgIPv6Proc;  /* ALG的IPV6慢转转处理函数 */
}SESSION_KALG_IPV6_PROC_S;

/* SESSION_ALG_TCPSEQ_S转序操作 */
#define SESSION_BAK_TCPSEQ_HTON(pstMsg, pstTcpSeq) \
{ \
	(pstMsg)->uiCurSeq = htonl((pstTcpSeq)->uiCurSeq); \
    (pstMsg)->uiCurAck = htonl((pstTcpSeq)->uiCurAck); \
    (pstMsg)->iCurAdj = (INT)htonl((UINT)((pstTcpSeq)->iCurAdj)); \
    (pstMsg)->iNextAdj = (INT)htonl((UINT)((pstTcpSeq)->iNextAdj)); \
}

#define SESSION_BAK_TCPSEQ_NTOH SESSION_BAK_TCPSEQ_HTON

#define SESSION_KALG_IS_NEED_TRANS_PROC(_pstExtSess) \
    ((SESSION_TABLE_IS_ALGFLAG_SET(_pstExtSess, SESSION_MODULE_NAT)) || \
     (SESSION_TABLE_IS_ALGFLAG_SET(_pstExtSess, SESSION_MODULE_LB)))

typedef ULONG SESSION_ALGFRAGSTAT_HANDLE;
#define SESSION_ALGFRAGSTAT_HANDLE_INVALID  0UL

extern SESSION_KALG_IPV6_PROC_S g_stSessionIPv6KAlgProc; /* 各种ALG报文处理函数 */
extern SESSION_KALG_IPV4_PROC_S g_stSessionIPv4KAlgProc; /* 各种ALG报文处理函数 */


extern ULONG SESSION_KAlgProc(IN MBUF_S *pstMbuf,IN UINT uiL3OffSet,IN SESSION_HANDLE hSession);
extern ULONG SESSION6_KAlgProc(IN MBUF_S *pstMbuf, IN UINT uiL3OffSet, IN SESSION_HANDLE hSession);
extern ULONG SESSION_KAlg_AppReg(IN SESSION_ALG_S *pstRegInfo, IN SESSION_ALG_TYPE_E enType);
extern VOID SESSION_KAlg_AppDeReg (IN SESSION_ALG_TYPE_E enType);
extern AC_HANDLE ANCHORAC_CreateTrie(IN AC_CASE_E enCase);
extern VOID ANCHORAC_DestroyTrie(IN AC_HANDLE hAcTrie);
extern ULONG ANCHORAC_AddPattern(IN AC_HANDLE hAcTrie, IN const UCHAR *pucPatt, IN UINT uiPattLen, IN UINT uiPid);
extern ULONG ANCHORAC_Compile(IN AC_HANDLE hAcTrie);
extern VOID SESSION_KAlgFailInc(IN SESSION_ALG_STAT_TYPE_E enAppType, IN SESSION_ALGFAIL_TYPE_E enAlgFailType);
extern VOID SESSION6_KAlgFailInc(IN SESSION_ALGFAIL_TYPE_E enAlgFailType);
extern VOID *SESSION_KAlg_memmem(IN const VOID *pHaystack,
                                 IN ULONG ulHaystacklen,
                                 IN const VOID *pNeedle,
                                 IN ULONG ulNeedlelen);

extern ULONG ANCHORAC_SearchWithState(IN AC_HANDLE hAcTrie,
                                      IN UCHAR *pucBuf,
                                      IN const UCHAR *pucBufEnd,
                                      INOUT UINT *puiState,
                                      OUT UINT *puiPid);

extern ULONG ANCHORAC_Search(IN AC_HANDLE hAcTrie,
                             IN UCHAR *pucBuf,
                             IN const UCHAR *pucBufEnd,
                             OUT UINT *puiPid);



#endif
