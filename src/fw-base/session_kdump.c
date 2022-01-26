
#include "session_kutil.h"
#include "session_kcore.h"
#include "agingqueue.h"
#include <rte_cycles.h>
#include <rte_atomic.h>

typedef struct tagSessionDumpKey
{
	SESSION_INET_ADDR_U unL3SrcStart;
	SESSION_INET_ADDR_U unL3SrcEnd;
	SESSION_INET_ADDR_U unL3DstStart;
	SESSION_INET_ADDR_U unL3DstEnd;
	SESSION_PROTO_SRC_U unL4Src;
	SESSION_PROTO_DST_U unL4Dst;
	VRF_INDEX vrfIndex;
	UINT uiModuleFlag;
	UINT uiMask;
	UCHAR ucL3Family;
	UCHAR ucProtocol;
	UINT uiIdentityID;
	UINT uiAppIDNum;
	UINT auiAppID[SESSION_MAX_APP_NUM];
	UINT uiAppID;
	UCHAR ucState;
    IF_INDEX ifIndex;
	UINT uiRuleID;
	UINT uiPolicyID;
}SESSION_DUMP_KEY_S;

/* 全局统计数据结构初始化 */
ULONG session_global_stat_init(IN SESSION_K_STATISTICS_S* pstGlobalStat)
{
    SESSION_STAT_VCPU_S* pstVcpuStat;
    INT iIndex;

    pstGlobalStat->ulLastJiffies = rte_get_timer_cycles();
    pstGlobalStat->pstVcpuStat = SESSION_KMALLOC_PERCPU(SESSION_STAT_VCPU_S);

    if(NULL == pstGlobalStat->pstVcpuStat)
    {
        return ERROR_FAILED;
    }

    /* 初始化每个VCPU的统计信息 */
    for(iIndex = 0; iIndex < worker_thread_total(); iIndex++)
    {
        pstVcpuStat = SESSION_GET_PERCPU_PTR(pstGlobalStat->pstVcpuStat, iIndex);
        memset(pstVcpuStat, 0, sizeof(SESSION_STAT_VCPU_S));
    }

    return ERROR_SUCCESS;
}

/* 全局alg fail统计数据结构初始化 */
ULONG session_global_algfail_cnt_init(IN SESSION_ALGFAILCNT_S* pstAlgFailCnt)
{
    INT iIndex;
    SESSION_ALGFAILCNT_VCPU_S *pstVcpuAlgFail;

    pstAlgFailCnt->pstVcpuAlgFailCnt = SESSION_KMALLOC_PERCPU(SESSION_ALGFAILCNT_VCPU_S);

    if(NULL == pstAlgFailCnt->pstVcpuAlgFailCnt)
    {
        return ERROR_FAILED;
    }

    /* 初始化每个VCPU的统计信息 */
    for(iIndex = 0; iIndex < worker_thread_total(); iIndex++)
    {
        pstVcpuAlgFail = SESSION_GET_PERCPU_PTR(pstAlgFailCnt->pstVcpuAlgFailCnt, iIndex);
        memset(pstVcpuAlgFail, 0, sizeof(SESSION_ALGFAILCNT_VCPU_S));
    }

    return ERROR_SUCCESS;
}

