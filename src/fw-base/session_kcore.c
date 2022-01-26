#include <time.h>
#include "session.h"
#include "session_kcore.h"
#include "session_ktable.h"
#include "session_kutil.h"
#include "session_kl3proto.h"
#include "tunnel.h"
#include "session_kdebug.h"
#include "session_ktableaging.h"
#include "ipfs.h"
#include "ac.h"
#include "session_kalg.h"
#include "session_ext.h"
#include "agingqueue.h"
#include "dpi.h"
#include "apr.h"
#include "../access_control/secpolicy_match.h"

SESSION_CONF_S g_stSessionConfInfo = {1000}; /* 初始化一个默认值 */
SESSION_MODULE_REG_S g_astModuleRegInfo[SESSION_MODULE_MAX];  /* 记录各业务模块注册信息 */
/* 各协议对应的会话类型 */
SESSION_L4_TYPE_E g_aenSessionType[IPPROTO_MAX];

extern UCHAR g_aucIcmpPktType[];
/*只考虑<=ICMP_MASKREPLY的type*/
extern UCHAR g_aucIcmpReverType[];

RELATION_S *SESSION_RelationHash_Find(IN const csp_key_t *pstcspkey);
BOOL_T SESSION_Relation_IsTupleMatch(IN const csp_key_t *pstTupleFromHash,
                                     IN const csp_key_t *pstNewTuple,
                                     IN UINT uiCmpMask);

VOID SESSION_init_l4type_map(VOID)
{
    UINT uiProto;

    /*首先将所有协议初始化为RAW_IP, 再对支持的协议赋值*/
    for(uiProto = 0; uiProto < IPPROTO_MAX; uiProto++)
    {
        g_aenSessionType[uiProto] = SESSION_L4_TYPE_RAWIP;
    }

    g_aenSessionType[IPPROTO_TCP]      = SESSION_L4_TYPE_TCP;
    g_aenSessionType[IPPROTO_UDP]      = SESSION_L4_TYPE_UDP;
    g_aenSessionType[IPPROTO_ICMP]     = SESSION_L4_TYPE_ICMP;    
    g_aenSessionType[IPPROTO_ICMPV6]   = SESSION_L4_TYPE_ICMPV6;

    return;
}

#define SESSION_SERVICE_INVALID_POS ((UINT64)-1)

/* 获取报文处理用的3层，4层处理模块 */
ULONG session_kGetModule(IN MBUF_S *pstMBuf,
                         IN UINT   uiL3Offset,
                         OUT UINT *puiL4Offset,
                         OUT UCHAR *pucL4ProtoNum,
                         OUT UINT *puiIPLen,
                         OUT SESSION_L3_PROTO_S **ppstL3Proto,
                         OUT SESSION_L4_PROTO_S **ppstL4Proto)
{
    SESSION_L3_PROTO_S *pstL3Proto;
    SESSION_L4_PROTO_S *pstL4Proto;
    UINT                uiL4_Off;
    UCHAR               ucL4Proto;
    ULONG               ulRet;
    UCHAR               ucFamily;
    UINT                uiIPLen;
    conn_sub_t *csp;
    
	csp = GET_CSP_FROM_LBUF(pstMBuf);
	ucFamily = GET_CSP_FAMILY(csp); 

    DBGASSERT((ucFamily == AF_INET) || (ucFamily == AF_INET6));

    pstL3Proto = SESSION_KGetL3Proto_Proc(ucFamily);

    if(NULL == pstL3Proto)
    {
        return ERROR_FAILED;
    }

    ulRet = pstL3Proto->pfGetL4Proto(pstMBuf, uiL3Offset, &uiL4_Off, &ucL4Proto, &uiIPLen);
    if (ERROR_SUCCESS != ulRet)
    {
        return ERROR_FAILED;
    }

    pstL4Proto = SESSION_KGetL4Proto_Proc(ucL4Proto);

    *puiL4Offset = uiL4_Off;
    *pucL4ProtoNum = ucL4Proto;
    *puiIPLen = uiIPLen;
    *ppstL3Proto = pstL3Proto;
    *ppstL4Proto = pstL4Proto;

    return ERROR_SUCCESS;
}

/* 从报文中提取tuple参数 */
VOID session_kGetTuple(IN const MBUF_S *pstMBuf,
                       IN UINT uiL3Offset,
                       IN UINT uiL4Offset,
                       IN UCHAR ucL4ProtoNum,
                       IN const SESSION_L3_PROTO_S *pstL3Proto,
                       IN const SESSION_L4_PROTO_S *pstL4Proto,
                       INOUT SESSION_TUPLE_S *pstTuple)
{
    /* 这里必须进行初始化，否则因其中v4和v6地址是union, 匹配会话时错误 */
    memset(pstTuple, 0, sizeof(SESSION_TUPLE_S));

    /*
     * 通过3层协议模块提供的函数填充session tuple的3层信息。
     *   3层信息包括
     *      地址族
     *      源地址、目的地址
     *      Tunnel ID
     *      VPN ID
     *      4层协议号.
     *  并返回4层协议头的起始由3层协议模块得到4层协议头的偏移位置，以及4层协议号。   
     */
    pstL3Proto->pfPktToTuple(pstMBuf, uiL3Offset, pstTuple);
    pstTuple->ucProtocol = ucL4ProtoNum;

    /*
     * 调用者需要保证pstMBuf长度有效。
     * 目前1、3层取tuple由转发保证pstMBuf至少ip头存在
     *     2、4层取tuple由4层协议模块的单包检查函数进行单包合法性检查来保证，
     *        如果单包合法，则填充session tuple的4层信息.
     *     3、4层取ICMP差错报文内嵌ip+port的tuple，在调用前也需要保证。
     */
    pstL4Proto->pfPktToTuple(pstMBuf, uiL3Offset, uiL4Offset, pstTuple);

    return;
}

/* 异常统计 */
VOID SESSION_KStatFailInc(IN SESSION_STAT_FAIL_TYPE_E enStatFailType,
                          INOUT SESSION_CTRL_S *pstSessionCtrl)
{
    rte_atomic32_inc(&pstSessionCtrl->astStatFailCnt[SESSION_STAT_IPV4][enStatFailType]);
    return;
}

static inline ULONG session_kCheckAddress(IN const csp_key_t *pstcskey)
{
    if(SESSION_IPv4Addr_IsInValid(ntohl(pstcskey->dst_ip)) ||
       SESSION_IPv4Addr_IsInValid(ntohl(pstcskey->src_ip))) 
    {
        return ERROR_FAILED;
    }

    return ERROR_SUCCESS;
}

static inline ULONG session_kcheckPacket(IN MBUF_S *pstMbuf,
                                         IN const csp_key_t *pstcskey,
                                         IN UCHAR ucSessL4Type,
                                         IN UINT uiL3OffSet,
                                         IN UINT uiL4OffSet,
                                         OUT UCHAR *pucNewState)
{
    ULONG ulRet;
    
    /*进行报文单包检查:可能是一个畸形包，或者是一个ICMP错误消息报文。
     *对于畸形报文，直接返回错误。
     *对于ICMP错误消息，需要检查是否属于某个会话引起的错误报文，但不进行统计以及状态机处理。
     *对于属于会话的ICMP Error 通知报文，标识出报文所属会话。
     *对于不属于会话的，按不匹配会话处理。
     */

    ulRet = session_kCheckAddress(pstcskey);

    if (BOOL_TRUE == SESSION_IsIPv4LatterFrag(uiL3OffSet, pstMbuf))
    {
        ulRet |= ERROR_FAILED;
    }

    if(SESSION_L4_TYPE_TCP == ucSessL4Type)
    {
        ulRet |= SESSION_KCheckTcpNew(pstMbuf, uiL4OffSet, pucNewState);
    }
    else if((SESSION_L4_TYPE_UDP != ucSessL4Type) && (SESSION_L4_TYPE_RAWIP != ucSessL4Type))
    {
        ulRet |= SESSION_KCheckOtherNew(pstMbuf, uiL3OffSet, uiL4OffSet, pstcskey->proto);
    }
    else
    {
        *pucNewState = UDP_ST_OPEN;
    }

    return ulRet;
}

static inline VOID session_kInitSession(IN UCHAR ucSessL4Type,
                                        IN UINT  uiAppID,                                        
										IN UINT uiTrustValue,
                                        IN const SESSION_CTRL_S *pstSessionVd,
                                        INOUT SESSION_S *pstSess)
{
    pstSess->stSessionBase.uiSessCreateTime = (UINT)time(NULL);

    pstSess->stSessionBase.ucSessionL4Type  = ucSessL4Type;

    SESSION_KAgingRefresh(pstSess);

    /*通过APPID识别会话的ALG类型*/
    pstSess->uiAppID = uiAppID;
	pstSess->uiTrustValue = uiTrustValue;

    /*记录会话的初始AppID(给alg扩展块老化来用)，后续不会随着appchange而变化*/
    pstSess->uiOriginalAppID = uiAppID;
       
    /*设置配置序号*/
    pstSess->usCfgSeq = pstSessionVd->usCfgSeq;

    /*设置临时会话标志位*/
    SESSION_TABLE_SET_TABLEFLAG(&pstSess->stSessionBase, SESSION_TEMP);
    
    return;
}

/******************************************************************
   Func Name:SESSION_KGetNotZero
Date Created:2021/04/25
      Author:wangxiaohua
 Description:会话引用计数增1，要求增加之前引用计数不能为0，否则返回失败
       INPUT:SESSION_S *pstSession, 会话
      Output:无
      Return:ERROR_SUCCESS
             ERROR_FAILED
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
ULONG SESSION_KGetNotZero(IN SESSION_S *pstSession)
{
    if(unlikely (0 == rte_atomic32_read(&pstSession->stSessionBase.stRefCount.stCount)))
    {
        /*增加引用计数的原子操作时计数清0，表示查找过程中会话被删除。*/
        return ERROR_FAILED;
    }

    rte_atomic32_inc(&pstSession->stSessionBase.stRefCount.stCount);
    return ERROR_SUCCESS;
}

STATIC SESSION_CHILD_DIR_E session_kGetChildDirWithParent(IN SESSION_S *pstParent,
                                                          IN SESSION_S *pstChild)
{
    SESSION_CHILD_DIR_E enChildDir = DIR_IGNORE_PARENT;
    csp_key_t *pstChildKey;
    csp_key_t *pstParentOrgKey;
    csp_key_t *pstParentRpyKey;
	
    /*
        Parent        OrgSrc        OrgDst        ReplySrc        ReplyDst
     Child Src        SRC_2_DST_1   DST_2_SRC_2   DST_2_SRC_1     SRC_2_DST_2 
     Child Dst        DST_2_SRC_2   SRC_2_DST_1   SRC_2_DST_3     DST_2_SRC_1    
    */

    /* 此处仅比较IP地址，不比较端口和VPN，VPN已经在匹配关联表时比较过了，
       另外子通道反向VPN暂无法获取 */

    DBGASSERT(NULL != pstParent);
    DBGASSERT(NULL != pstChild);

    pstChildKey = SESSION_KGetIPfsKey((SESSION_HANDLE)pstChild, SESSION_DIR_ORIGINAL);
    pstParentOrgKey = SESSION_KGetIPfsKey((SESSION_HANDLE)pstParent, SESSION_DIR_ORIGINAL);    
    pstParentRpyKey = SESSION_KGetIPfsKey((SESSION_HANDLE)pstParent, SESSION_DIR_REPLY);

    /* 优先比较正向源和反向目的 */
    if((pstChildKey->src_ip == pstParentOrgKey->src_ip) &&
       (pstChildKey->dst_ip == pstParentOrgKey->dst_ip))
    {
        enChildDir = DIR_PARENT_SRC_2_DST; /* 父子方向相同 */
    }
    else if((pstChildKey->src_ip == pstParentRpyKey->src_ip) &&
            (pstChildKey->dst_ip == pstParentRpyKey->dst_ip))
    {
        enChildDir = DIR_PARENT_DST_2_SRC; /* 父子方向相反 */
    }
    else
    {
        /* 对于LB父会话的反向源一般都是服务器地址，
           LB父会话反向目的一般是代理地址，不能用于比较 */
        if((pstChildKey->src_ip == pstParentOrgKey->src_ip) || 
           (pstChildKey->dst_ip == pstParentRpyKey->dst_ip))
        {
            enChildDir = DIR_PARENT_SRC_2_DST; /* 暂认为父子方向相同，不确定什么情况下会走这里 */
        }
        else if((pstChildKey->src_ip == pstParentRpyKey->src_ip) ||
                (pstChildKey->dst_ip == pstParentOrgKey->src_ip) ||
                (pstChildKey->dst_ip == pstParentRpyKey->dst_ip))
        {
            enChildDir = DIR_PARENT_DST_2_SRC; /* 暂认为父子方向相反，不确定什么情况下会走这里 */
        }
    }

    return enChildDir;
}

STATIC VOID session_kInitExtSession(IN const MBUF_S *pstMbuf,
                                    IN USHORT usSessAlgType,
                                    IN const RELATION_S *pstRelation,
                                    IN UINT uiL3OffSet,
                                    INOUT SESSION_S *pstSess)
{
    SESSION_S *pstParent;
    NEW_SESSION_BY_RELATION_PF pfNewNotify;
    ULONG ulRet;
    UCHAR ucDirChild;

    pstSess->usSessAlgType = usSessAlgType;
    rte_spinlock_init(&(pstSess->stLock));

    /*如果匹配关联表，根据关联表项设置会话的参数*/
    if(NULL == pstRelation)
    {
        return;
    }

    /*由于会话中指向了父会话，需要对父会话的引用计数 +1*/
    /*pstParent = RCU_Deref(pstRelation->pstParent);*/
	pstParent = pstRelation->pstParent;
    if(NULL != pstParent)
    {
        ulRet = SESSION_KGetNotZero((SESSION_S *)pstParent);
        if(ERROR_SUCCESS == ulRet)
        {
            pstSess->pstParent = pstParent;
            ucDirChild = (UCHAR)pstRelation->enChildDir;
            if(DIR_IGNORE_PARENT == pstRelation->enChildDir)
            {
                ucDirChild = (UCHAR)session_kGetChildDirWithParent(pstParent, pstSess);
            }

            pstSess->ucDirAssociateWithParent = ucDirChild;
        }
        
    }

    /*关联表匹配事件通知*/
    pfNewNotify = pstRelation->pfNewSession;
    if(NULL != pfNewNotify)
    {
        (VOID)pfNewNotify((SESSION_HANDLE)pstSess, &pstRelation->stAttachData, pstMbuf);
    }

    if(!RELATION_IS_PERSIST(pstRelation))
    {
        /* 子会话命中非persist关联表的时候，不立即删除关联表，
           需要等到子会话正式化的时候再删除关联表，因此先给会话设置一个标记 */
        SESSION_TABLE_SET_TABLEFLAG(&pstSess->stSessionBase, SESSION_DEL_NON_PERSIST_RELATION);
    }

    return;
}

static inline SESSION_S *session_kCreateWithRelation(IN MBUF_S *pstMbuf,
                                                     IN UCHAR ucSessL4Type,
                                                     IN VOID *pcsp,
                                                     IN SESSION_CTRL_S *pstSessionCtrl,
                                                     IN const RELATION_S *pstRelation,
                                                     IN UINT uiL3OffSet)
{
    SESSION_S *pstSession;
    UINT uiAppID;
	UINT uiTrustValue;
    USHORT usSessAlgType;
	flow_connection_t *fcp;
	conn_sub_t *csp, *peer;
	csp_key_t *pstcskey;
	USHORT usDport;
	struct in_addr stSrcIP;
    struct in_addr stDstIP;

	csp = (conn_sub_t *)pcsp;
	pstcskey = GET_CSP_KEY(csp);

    if ((NULL == pstRelation) || (NULL == pstRelation->pstParent))
    {
		usDport = htons(pstcskey->dst_port);
        uiAppID = APR_GetAppByPort(usDport, pstcskey->proto);
		uiTrustValue = APR_TRUST_PORT;
    }
    else
    {
        uiAppID = pstRelation->uiAppID;
		uiTrustValue = APR_TRUST_SIG_FINAL;
    }

    usSessAlgType = SESSION_KGetSessionAlgType(uiAppID);

    pstSession = SESSION_Malloc(SESSION_TYPE_NORMAL);
    if(NULL == pstSession)
    {
        return NULL;
    }

    peer = csp2peer(csp);
	fcp  = csp2base(csp);

    pstSession->stSessionBase.pCache[SESSION_DIR_ORIGINAL] = csp;
    pstSession->stSessionBase.pCache[SESSION_DIR_REPLY] = peer;    
	SET_FWSESSION_TO_FC(fcp, pstSession);

    session_kInitSession(ucSessL4Type, uiAppID, uiTrustValue, pstSessionCtrl, pstSession);

    session_kInitExtSession(pstMbuf, usSessAlgType, pstRelation, uiL3OffSet, pstSession);

    /*设置AppID到MBUF*/
    MBUF_SET_APP_ID(pstMbuf, uiAppID);

    /*设置流量方向 内到外 或 外到内 */
	memcpy(&stSrcIP, &(pstcskey->src_ip), sizeof(struct in_addr));
    memcpy(&stDstIP, &(pstcskey->dst_ip), sizeof(struct in_addr));
	pstSession->uiDirect = SecPolicy_IP4_FlowDirect(pstcskey->token, stSrcIP, stDstIP);

    SESSION_DBG_SESSION_EVENT_SWITCH(pstSession, EVENT_CREATE);

    return pstSession;
}

VOID SESSION_BAK_SetInvalidFlag(IN MBUF_S *pstMBuf)
{
    SESSION_MBUF_SET_FLAG(pstMBuf, (USHORT)SESSION_MBUF_INVALID);
    
	return;
}

static VOID session_kLayer4StateNewExt(IN SESSION_S *pstSession,
                                       IN USHORT usIPOffset,
                                       IN UINT uiL4Offset,
                                       IN MBUF_S *pstMbuf,
                                       IN UCHAR ucPro,
                                       IN SESSION_CTRL_S *pstSessionCtrl)
{
    SESSION_L4_PROTO_S *pstL4Proto;
    ULONG ulRet;

    pstL4Proto = SESSION_KGetL4Proto_Proc(ucPro);

    ulRet = pstL4Proto->pfFirstPacket(pstMbuf, uiL4Offset, pstSession);

    ulRet |= pstL4Proto->pfState(pstSession, pstMbuf, usIPOffset, uiL4Offset);
    if(ulRet != ERROR_SUCCESS)
    {
        SESSION_DBG_PACKETS_EVENT_SWITCH(pstMbuf, usIPOffset, DBG_ABNORM_PKT_INVALID);

        /* 设置非法报文标记，但报文还是属于会话，只不过状态不对 */
        SESSION_BAK_SetInvalidFlag(pstMbuf);
        SESSION_KStatFailInc(SESSION_STAT_FAIL_EXTNEW_STATE, pstSessionCtrl);
    }

    /* 重新设置老化类并更新老化时间 */
    SESSION_KAging_SetClassNew(pstSessionCtrl, pstSession);

    /*刷新父会话的老化时间*/
    SESSION_KRefreshParents(pstSession);

    return;
}

/******************************************************************
   Func Name:session_kGetL4Offset
Date Created:2021/04/25
      Author:wangxiaohua
 Description:获取四层偏移
       INPUT:IN MBUF_S *pstMbuf     ----报文
             IN UINT uiL3Offset     ----三层偏移
      Output:OUT UINt *puiL4Offset  ----4层头偏移位置
      Return:UINT                   ----报文总长度
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline UINT session_kGetL4Offset(IN const MBUF_S *pstMbuf,
                                        IN UINT uiL3Offset,
                                        OUT UINT *puiL4Offset)
{
    struct iphdr *pstIPHdr;

    pstIPHdr = MBUF_BTOD_OFFSET(pstMbuf, uiL3Offset, struct iphdr*);
    *puiL4Offset = (((UINT)pstIPHdr->ihl) << 2) + uiL3Offset;

    return (UINT)pstIPHdr->tot_len;
}

SESSION_HANDLE SESSION_KCreateProcess(INOUT MBUF_S *pstMbuf, IN UINT uiL3Offset)
{
    SESSION_S *pstSession;
    RELATION_S *pstRelation = NULL;
    SESSION_CTRL_S *pstSessionCtrl;	
    conn_sub_t *csp;
    csp_key_t *pstcskey;
    ULONG ulRet;
    UINT uiL4Offset;
    UINT uiIPLen;
    UCHAR ucSessL4Type;
    UCHAR ucNewState = UDP_ST_OPEN;	

    pstSessionCtrl = SESSION_CtrlData_Get();
	
	csp = GET_CSP_FROM_LBUF(pstMbuf);	
    if (unlikely (NULL == csp))
    {
        SESSION_MBUF_SET_FLAG(pstMbuf, SESSION_MBUF_PROCESSED);
        SESSION_KStatFailInc(SESSION_STAT_FAIL_CREATE_CACHE_NULL, pstSessionCtrl);
        return SESSION_INVALID_HANDLE;
    }
	
	pstcskey = GET_CSP_KEY(csp);

    /* 检查是否允许创建会话，如果不允许创建，则设置MBUF中会话 INVALID 标记 */
    ucSessL4Type = (UCHAR) SESSION_KGetSessTypeByProto(pstcskey->proto);

    /* 获取4层长度 */
    uiIPLen = session_kGetL4Offset(pstMbuf, uiL3Offset, &uiL4Offset);

    /* 检查不通过，直接返回NULL */
    ulRet = session_kcheckPacket(pstMbuf, pstcskey, ucSessL4Type, uiL3Offset, uiL4Offset, &ucNewState);
    if (unlikely (ERROR_SUCCESS != ulRet))
    {
        /*当前newsessioncheck提前,icm_err必然不会创建会话，会走此分支，
          但是icm_err 不能打invalid标记，否则aspf会直接丢包*/
        if(!SESSION_MBUF_TEST_FLAG(pstMbuf, SESSION_MBUF_ICMPERR))
        {
            SESSION_MBUF_SET_FLAG(pstMbuf, (USHORT)SESSION_MBUF_INVALID);          
            SESSION_MBUF_SET_FLAG(pstMbuf, (USHORT)SESSION_MBUF_PROCESSED);            
            SESSION_KStatFailInc(SESSION_STAT_FAIL_PKT_CHECK, pstSessionCtrl);
        }
        else
        {            
            SESSION_MBUF_SET_FLAG(pstMbuf, (USHORT)SESSION_MBUF_PROCESSED);               
        }
        return SESSION_INVALID_HANDLE;
    } 

    /*会话首报文处理*/
    pstRelation = SESSION_RelationHash_Find(pstcskey);
    pstSession = session_kCreateWithRelation(pstMbuf, ucSessL4Type, csp,
                                             pstSessionCtrl, pstRelation, uiL3Offset);
    if(unlikely (NULL == pstSession))
    {
        SESSION_MBUF_SET_FLAG(pstMbuf, (USHORT)SESSION_MBUF_PROCESSED);  
        SESSION_KStatFailInc(SESSION_STAT_FAIL_ALLOC_SESSION, pstSessionCtrl);
        return SESSION_INVALID_HANDLE;
    }

    /*设置首包标记到MBUF, 设置temp会话标记到MBUF, 报文为正向*/
    SESSION_MBUF_SET_FLAG(pstMbuf, SESSION_MBUF_FIRSTPKT | SESSION_MBUF_PROCESSED);

    /* 进行状态机处理 */
    session_kLayer4StateNewExt(pstSession, (USHORT)uiL3Offset, uiL4Offset, pstMbuf, pstcskey->proto, pstSessionCtrl);

    /*统计开关打开，会话增加统计信息*/
    if (unlikely(BOOL_TRUE == pstSessionCtrl->bStatEnable))
    {
        /*初始化会话的流量统计信息*/
        SESSION_KInitFlowRate(pstMbuf, pstSession);
        SESSION_KAddTotalState((SESSION_L4_TYPE_E)ucSessL4Type, 1, uiIPLen, pstSessionCtrl);
    }

    return (SESSION_HANDLE)pstSession;
}

#if 0
STATIC VOID session_kProcStateError(IN SESSION_CTRL_S *pstSessionCtrl,
                                    IN MBUF_S *pstMBuf,
                                    IN USHORT usIPOffset,
                                    IN SESSION_STAT_FAIL_TYPE_E enFailType)
{
    SESSION_DBG_PACKETS_EVENT_SWITCH(pstMBuf, usIPOffset, DBG_ABNORM_PKT_INVALID);

    /* 设置非法报文标记，但报文还是属于会话，只不过状态不对 */
    SESSION_BAK_SetInvalidFlag(pstMBuf);
    SESSION_KStatFailInc(enFailType, pstSessionCtrl);

    return;
}

STATIC VOID SESSION_KTcpState(IN SESSION_S *pstSession,
                              IN MBUF_S *pstMBuf,
                              IN SESSION_PKT_DIR_E enDir,
                              IN SESSION_CTRL_S *pstSessionCtrl,
                              IN USHORT usIPOffset,
                              IN UINT uiL4Offset)
{
    AGINGQUEUE_UNSTABLE_CLASS_S *pstClass;
    TCPHDR_S *pstTcpHdr;
    UCHAR ucFlags;
    UCHAR ucOldState;
    UCHAR ucNewState;
    INT iIndex;

    /* 进行单包合法性检查 */
    if(SESSION_MBUF_TEST_FLAG(pstMBuf, (USHORT)SESSION_MBUF_INVALID))
    {
        return;
    }

    pstTcpHdr = MBUF_BTOD_OFFSET(pstMBuf, uiL4Offset, TCPHDR_S *);
    ucFlags = (pstTcpHdr->th_flags) & TCP_FLAGS_CARE_MASK;

    ucOldState = pstSession->ucState;
    iIndex = (enDir*TCP_PKT_MAX*TCP_ST_MAX)+(g_aucTcpPktType[ucFlags]*TCP_ST_MAX)+ucOldState;
    ucNewState = (pstSessionCtrl->pucTcpStateTable)[iIndex];

    if (ucOldState == ucNewState)
    {
        /* 重新设置老化类并更新老化时间 */
        SESSION_KAgingRefresh(pstSession);
        return;
    }

    switch (ucNewState)
    {       
        case sTCP_IV:
        {    
            session_kProcStateError(pstSessionCtrl, pstMBuf, usIPOffset, SESSION_STAT_FAIL_TCP_STATE);
            break;
        }        
        case sTCP_IG:
        {    
            /*不更新状态和pstClass*/
            break;
        }
        default:
        {
            pstSession->ucState = ucNewState;
            pstClass = &pstSessionCtrl->astTableAgingClass[SESSION_L3_TYPE_IPV4][SESSION_L4_TYPE_TCP][ucNewState];   
            AGINGQUEUE_UnStable_Switch(&pstSession->stSessionBase.unAgingRcuInfo.stAgingInfo, pstClass);
            break;
        }         
    }

    /* 重新设置老化类并更新老化时间 */
    if(!SESSION_MBUF_TEST_FLAG(pstMBuf, (USHORT)SESSION_MBUF_INVALID))
    {
        SESSION_KAgingRefresh(pstSession);
    }
    return;
}

/* 获取协议稳态 */
STATIC UCHAR SESSION_KGetEstState(IN UCHAR ucSessionL4Type)
{
    UCHAR ucEstState;

    switch (ucSessionL4Type)
    {
        case SESSION_L4_TYPE_TCP:
        {
            ucEstState = TCP_ST_ESTABLISHED;
            break;
        }
        case SESSION_L4_TYPE_UDP:
        {
            ucEstState = UDP_ST_READY;
            break;
        }
        case SESSION_L4_TYPE_ICMP:
        case SESSION_L4_TYPE_ICMPV6:
        {            
            ucEstState = ICMP_ST_REPLY;
            break;
        }        
        case SESSION_L4_TYPE_UDPLITE:
        {
            ucEstState = UDPLITE_ST_READY;
            break;
        }        
        case SESSION_L4_TYPE_SCTP:
        {
            ucEstState = SCTP_ST_ESTABLISHED;
            break;
        }        
        case SESSION_L4_TYPE_DCCP:
        {
            ucEstState = DCCP_ST_RESPOND;
            break;
        }        
        case SESSION_L4_TYPE_RAWIP:
        {
            ucEstState = RAWIP_ST_READY;
            break;
        }
        default:
        {
            ucEstState = 0;
            break;
        }
    }

    return ucEstState;
}
#endif

STATIC VOID session_kStateProc(IN const SESSION_L4_PROTO_S *pstL4Proto,
                               IN USHORT               usIPOffset,
                               IN UINT                 uiL4_Offset,
                               IN SESSION_S            *pstSession,
                               IN MBUF_S               *pstMBuf,
                               IN SESSION_CTRL_S       *pstSessionCtrl)
{
    UCHAR ucOldState;
    UCHAR ucNewState;
    ULONG ulRet;

	//rte_spinlock_lock(&(pstSession->stLock));
	
    ucOldState = pstSession->ucState;
   
    ulRet = pstL4Proto->pfState(pstSession, pstMBuf, usIPOffset, uiL4_Offset);
    if(ulRet != ERROR_SUCCESS)
    {
        /* 设置非法报文标记，但报文还是属于会话，只不过状态不对 */
        SESSION_BAK_SetInvalidFlag(pstMBuf);
        SESSION_KStatFailInc(SESSION_STAT_FAIL_TOUCH_STATE, pstSessionCtrl);
    }

    ucNewState = pstSession->ucState;
    if (ucOldState != ucNewState)
    {
        /* 重新设置老化类并更新老化时间 */
        SESSION_KAging_SetClassNew(pstSessionCtrl, pstSession);
    }
    else
    {
        /* 刷新老化时间 */
        if (!SESSION_MBUF_TEST_FLAG(pstMBuf, (USHORT)SESSION_MBUF_INVALID))
        {
            SESSION_KAgingRefresh(pstSession);
        }
    }

    //rte_spinlock_unlock(&(pstSession->stLock));

    return;
}

/******************************************************************
   Func Name:session_kLayer4State
Date Created:2021/04/25
      Author:wangxiaohua
 Description:会话4层协议状态处理
       INPUT:IN csp_key_t        *pstcskey    ----快转Key
             IN UINT             uiL4_Offset  ----4层头偏移位置
             IN SESSION_S        *pstSession  ----报文所属会话             
             IN MBUF_S           *pstMBuf     ----报文
             IN SESSION_CTRL_S  *pstSessionCtrl      ----MDC
      Output:无
      Return:无
     Caution:协议状态处理结果直接设置在MBuf中
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline VOID session_kLayer4TouchState(IN const csp_key_t *pstcskey,
                                             IN USHORT          usIPOffset,
                                             IN UINT            uiL4_Offset,
                                             IN SESSION_S       *pstSession,
                                             IN MBUF_S          *pstMBuf,
                                             IN SESSION_CTRL_S  *pstSessionCtrl)
{
    SESSION_L4_PROTO_S *pstL4Proto;

    pstL4Proto = SESSION_KGetL4Proto_Proc(pstcskey->proto);

    /*多核并发时，为保证状态会话计数、Aging_setClass正确，需加锁*/
    if(!SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_DELETING))
    {
        /*进行状态机处理*/
        session_kStateProc(pstL4Proto, usIPOffset, uiL4_Offset, pstSession, pstMBuf, pstSessionCtrl);
    }

    /*刷新父会话的老化时间*/
    SESSION_KRefreshParents(pstSession);
	
    return;
}

VOID SESSION_KTouchProcess(INOUT MBUF_S *pstMbuf, IN SESSION_HANDLE hSession, IN UINT uiL3Offset)
{	
    SESSION_S        *pstSession;
    conn_sub_t       *csp;		
    csp_key_t        *pstcskey;
    SESSION_CTRL_S   *pstSessionCtrl;
    UINT              uiL4OffSet;
    UINT              uiIPLen;
    SESSION_PKT_DIR_E enDir;

    pstSession = (SESSION_S *)hSession;

    pstSessionCtrl = SESSION_CtrlData_Get();

	csp = GET_CSP_FROM_LBUF(pstMbuf);	
    if(NULL == csp)
    {
        SESSION_MBUF_SET_FLAG(pstMbuf, (USHORT)SESSION_MBUF_INVALID | (USHORT)SESSION_MBUF_PROCESSED);
        SESSION_KStatFailInc(SESSION_STAT_FAIL_TOUCH_CACHE_NULL, pstSessionCtrl);
        return;
    }
	
	pstcskey = GET_CSP_KEY(csp);

    enDir = (SESSION_PKT_DIR_E)GET_PACKETDIR_FROM_CSP(csp);

    /*配置序列变更*/
    if (unlikely(pstSession->usCfgSeq != pstSessionCtrl->usCfgSeq))
    {
        if(SESSION_DIR_ORIGINAL == enDir)
        {
            pstSession->usCfgSeq = pstSessionCtrl->usCfgSeq;
        }

        SESSION_MBUF_SET_FLAG(pstMbuf, (USHORT)SESSION_MBUF_CFGCHECK |
                                (USHORT)SESSION_MBUF_PROCESSED | enDir);
    }
    else
    {
        /*设置报文处理标志和方向标志*/
        SESSION_MBUF_SET_FLAG(pstMbuf, SESSION_MBUF_PROCESSED | enDir);
    }

    MBUF_SET_APP_ID(pstMbuf, SESSION_KGetAppID(hSession));

    /* 获取4层长度 */
    uiIPLen = session_kGetL4Offset(pstMbuf, uiL3Offset, &uiL4OffSet);

    /* 对非分片或者分片首片报文做状态机处理 */
    if (!SESSION_IsIPv4LatterFrag(uiL3Offset, pstMbuf))
    {
        /* 进行状态机处理 */		
		session_kLayer4TouchState(pstcskey, (USHORT)uiL3Offset, uiL4OffSet, pstSession, pstMbuf, pstSessionCtrl);
    }

    if(BOOL_TRUE == pstSessionCtrl->bStatEnable)
    {
        if(SESSION_DIR_REPLY == enDir)
        {
            SESSION_KAddReplyFlowStat(pstMbuf, pstSession);
        }
        else
        {
            SESSION_KAddOriginalFlowStat(pstMbuf, pstSession);
        }
        /* 更新会话的流量统计信息 */
        SESSION_KAddTotalState((SESSION_L4_TYPE_E)pstSession->stSessionBase.ucSessionL4Type,
                               1, uiIPLen, pstSessionCtrl);  
    }

    return ;
}

/******************************************************************
   Func Name:session_kIsNeedProc
Date Created:2021/04/25
      Author:wangxiaohua
 Description:判断报文是否需要处理
       INPUT:IN USHORT usIPOffset,    ----偏移
             IN MBUF_S *pstMBuf       ----报文
             IN SESSION_S *pstSession ----会话指针
      Output:无
      Return:BOOL_FALSE               ----继续转发
             BOOL_TRUE                ----需要后续处理
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline BOOL_T session_kIsNeedProc(IN USHORT usIPOffset, IN MBUF_S *pstMBuf, IN const SESSION_S *pstSession)
{
    BOOL_T bNeedProc = BOOL_TRUE;

    if(SESSION_MBUF_TEST_FLAG(pstMBuf, SESSION_MBUF_ICMPERR))
    {
        bNeedProc = BOOL_FALSE;
    }
    else if((SESSION_IsIPv4LatterFrag(usIPOffset, pstMBuf)) &&
            (APP_ID_HTTP != pstSession->uiAppID) &&
            (APP_ID_DNS  != pstSession->uiAppID))
    {
        bNeedProc = BOOL_FALSE;
    }

    return bNeedProc;
}

/******************************************************************
   Func Name:_session_KRate_IsTimeExceed
Date Created:2021/04/25
      Author:wangxiaohua
 Description:检查是否达到并发数上限
       INPUT:IN SESSION_CTRL_S *pstSessionCtrl
      Output:无
      Return:BOOL_TRUE             ----达到阈值
             BOOL_FALSE            ----未达到阈值
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline BOOL_T _session_KRate_IsTimeExceed(IN LONG lLastSendTime)
{
    LONG lTemp;

    lTemp = lLastSendTime + SESSION_RATE_TIME * rte_get_timer_cycles();
    if(lTemp - (LONG)rte_get_timer_cycles() <= 0)
    {
        return BOOL_TRUE;
    }
    else
    {
        return BOOL_FALSE;
    }
}

/******************************************************************
   Func Name:SESSION_KCapabitityTest
Date Created:2021/04/25
      Author:wangxiaohua
 Description:检查是否达到并发数和新建速率上限
       INPUT:IN SESSION_CTRL_S *pstSessionCtrl
      Output:无
      Return:PKT_CONTINUE             ----继续转发
             PKT_DROPPED              ----删除mbuf并丢包
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
STATIC ULONG SESSION_KCapabitityTest(IN SESSION_CTRL_S *pstSessionCtrl, IN const MBUF_S *pstMBuf)
{
    ULONG ulErrCode = ERROR_FAILED;

    /* 检测会话是否达到规格值，未达到软件规格数量则创建会话 */
    ulErrCode = SESSION_Info_Specification();
    if(ERROR_SUCCESS != ulErrCode)
    {
        return PKT_DROPPED;
    }

    rte_atomic32_inc(&pstSessionCtrl->stSessStat.stTotalSessNum);

    return PKT_CONTINUE;
}

/******************************************************************
   Func Name:session_kDeleteNonPersistRelation
Date Created:2021/04/25
      Author:wangxiaohua
 Description:删除该子会话在创建的时候命中的non-persist关联表
       INPUT:IN SESSION_S *pstSession    
      Output:
      Return:
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static VOID session_kDeleteNonPersistRelation(IN SESSION_S *pstSession)
{
    csp_key_t *pstcskey;
    RELATION_S *pstRelationEntry;
    BOOL_T bMatch;

    if(NULL == pstSession->pstParent)
    {
        SESSION_TABLE_CLEAR_TABLEFLAG(&pstSession->stSessionBase, SESSION_DEL_NON_PERSIST_RELATION);
        return;
    }

    /* 获取关联表的正向key */
    pstcskey = GET_CSP_KEY((conn_sub_t *)pstSession->stSessionBase.pCache[SESSION_DIR_ORIGINAL]);

    //rte_spinlock_lock(&pstSession->stLock);
    /* 遍历父会话的关联链表 */
    DL_FOREACH_ENTRY(&(pstSession->pstParent->stRelationList), pstRelationEntry, stNodeInSession)
    {
        bMatch = SESSION_Relation_IsTupleMatch(&(pstRelationEntry->stTupleHash.stIpfsKey),
                                               pstcskey,
                                               pstRelationEntry->stTupleHash.uiMask);
        if (BOOL_TRUE == bMatch)
        {
            DBGASSERT(!RELATION_IS_PERSIST(pstRelationEntry));

            RELATION_SET_DELETING(pstRelationEntry);

            SESSION_TABLE_CLEAR_TABLEFLAG(&pstSession->stSessionBase, SESSION_DEL_NON_PERSIST_RELATION);
            break;
        }
    }    
    //rte_spinlock_unlock(&pstSession->stLock);

    return;
}

/******************************************************************
   Func Name:session_kFirstPktEnd
Date Created:2021/04/25
      Author:wangxiaohua
 Description:将新建的临时会话加入会话表中，如果会话数已经超过规格，则添加失败.
             如果添加成功，通知注册模块会话创建事件.
       INPUT:IN MBUF_S *pstMBuf            ----报文       
             IN SESSION_CTRL_S *pstSessionCtrl    ----MDC
             IN USHORT usIPOffset          ----L3偏移
             INOUT SESSION_S *pstSession   ----会话
      Output:pstSession ---- 如果成功,会话被加入hash表中，并加入到老化链表中
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static VOID session_kFirstPktEnd(IN MBUF_S *pstMBuf,
                                 IN SESSION_CTRL_S *pstSessionCtrl,
                                 IN USHORT usIPOffset,
                                 INOUT SESSION_S *pstSession)
{
    SESSION_L4_TYPE_E enSessType = (SESSION_L4_TYPE_E)(pstSession->stSessionBase.ucSessionL4Type);

    /* 增加计数 */
    SESSION_KAddStat(pstSessionCtrl, enSessType, pstSession->uiOriginalAppID);

	
    if(SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_DEL_NON_PERSIST_RELATION))
    {
        session_kDeleteNonPersistRelation(pstSession);
    }

    /* 发送会话创建日志 */
    if(BOOL_TRUE == pstSessionCtrl->stSessionLogInfo.bLogSwitchEnable)
    {
        SESSION_KLOG_PROC_Create(pstMBuf, usIPOffset, pstSession, pstSessionCtrl);
    }

    /* 发送会话创建事件 */
    SESSION_KNotify_TableCreate((SESSION_HANDLE)pstSession);

    /* 会话加入老化队列 */
    SESSION_KAging_Add(&(g_stSessionstAgingQueue), pstSession);

    return;
}

/******************************************************************
   Func Name:SESSION_KDeleteSession
Date Created:2021/04/25
      Author:wangxiaohua
 Description:删除会话,会话标记SESSION_DELETING
       INPUT:IN SESSION_HANDLE hSession   ----会话句柄
      Output:无
      Return:无
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION_KDeleteSession(IN SESSION_HANDLE hSession)
{
    SESSION_S *pstSession = (SESSION_S *)hSession;

    if(NULL != pstSession)
    {
        SESSION_TABLE_SET_TABLEFLAG(&pstSession->stSessionBase, SESSION_DELETING);
    }

    return;
}

/******************************************************************
   Func Name:session_kFirstEnd
Date Created:2021/04/25
      Author:wangxiaohua
 Description:转发流程中基于会话处理结束处理点
       INPUT:IN MBUF_S *pstMBuf         ----报文
             IN USHORT usIPOffset       ----L3偏移
             IN SESSION_S *pstSession   ----会话
             IN SESSION_CTRL_S *pstSessionCtrl ----MDC
      Output:无
      Return:PKT_CONTINUE             ----继续转发
             PKT_DROPPED              ----删除mbuf并丢包
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static ULONG session_kFirstEnd(IN MBUF_S *pstMBuf,
                               IN USHORT usIPOffset,
                               IN SESSION_S *pstSession,
                               IN SESSION_CTRL_S *pstSessionCtrl)
{
    ULONG ulRet = ERROR_SUCCESS;
    SESSION_KALG_IPV4_PROC_PF  pfAlgIpv4Proc;

    /* 会话首包，会话计数增1，将临时会话加入hash表中，以及老化链表中 */
    session_kFirstPktEnd(pstMBuf, pstSessionCtrl, usIPOffset, pstSession);
    /* 会话ALG处理 */
    if (0 != pstSession->usAlgFlag)
    {
        pfAlgIpv4Proc = g_stSessionIPv4KAlgProc.pfAlgIPv4Proc;
        if(NULL != pfAlgIpv4Proc)
        {
            ulRet = pfAlgIpv4Proc(pstMBuf, usIPOffset, (SESSION_HANDLE)pstSession);
        }
    }

    if(ERROR_SUCCESS != ulRet)
    {
        SESSION_KDeleteSession((SESSION_HANDLE)pstSession);
        return PKT_DROPPED;
    }

    return PKT_CONTINUE;
}

#if 0
/******************************************************************
   Func Name:session_kTempSessionPut
Date Created:2021/04/25
      Author:wangxiaohua
 Description:删除temp会话
       INPUT:IN SESSION_S *pstSession ----临时会话指针
             IN USHORT usIPOffset     ----L3偏移
             IN BOOL_T bNeedSendIcmp  ----是否需要发送差错报文(NAT) 
             INOUT MBUF_S *pstMBuf    ----报文
      Output:pstMBuf                  ----报文可能被修改
      Return:PKT_CONTINUE             ----由外围调用者继续处理
             PKT_DROPPED              ----报文已经被丢弃
     Caution:MBUF可能会被修改.
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
STATIC ULONG session_kTempSessionPut(IN SESSION_S *pstSession,
                                     IN USHORT usIPOffset,
                                     INOUT MBUF_S *pstMBuf,
                                     INOUT SESSION_CTRL_S *pstSessionCtrl)
{
    ULONG ulPktRet = PKT_CONTINUE;

    rte_atomic32_dec(&(pstSessionCtrl->stSessStat.stTotalSessNum));

    /* 当前nat根据SESSION_TEMP判断是否减nat会话统计计数，由于前面清楚了temp标记，这里再加上 */
    SESSION_TABLE_SET_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP);

    /* 通知删除 */
    /*local_bh_disable();*/
    SESSION_KNotify_TableDelete((SESSION_HANDLE)pstSession);
    /*local_bh_enable();*/

    /* 清空MBUF中的会话指针和flag位*/
    MBUF_CLEAR_CACHE(pstMBuf, MBUF_CACHE_SESSION);
    MBUF_SET_SESSION_FLAG(pstMBuf, 0);

    /* 最新版本cache由会话释放: old--释放的时候仅仅需要释放会话，Cache已经释放了 */
    SESSION_KPut(pstSession);

    return ulPktRet;
}
#endif

/******************************************************************
   Func Name:session_kAfterEnd
Date Created:2021/04/25
      Author:wangxiaohua
 Description:转发流程中基于会话处理结束处理点，
             由IPv4/IPv6流程中的session end处理函数调用
             如果所属会话为临时会话，则加入会话表中。对于所有报文，还进行ALG处理
       INPUT:IN MBUF_S *pstMBuf       ----报文
             IN USHORT usIPOffset     ----L3偏移
             IN SESSION_S *pstSession ----会话指针
      Output:无
      Return:PKT_CONTINUE             ----继续转发
             PKT_DROPPED              ----删除mbuf并丢包
     Caution:MBUF可能会被修改.
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static ULONG session_kAfterEnd(IN MBUF_S *pstMBuf, IN USHORT usIPOffset, IN SESSION_S *pstSession)
{
    ULONG ulPktRet = PKT_CONTINUE;
    ULONG ulRet    = ERROR_SUCCESS;
    SESSION_KALG_IPV4_PROC_PF  pfAlgIPv4Proc;

    if(0 != pstSession->usAlgFlag)
    {
        /* 会话ALG处理 */
        pfAlgIPv4Proc = g_stSessionIPv4KAlgProc.pfAlgIPv4Proc;
        if (NULL != pfAlgIPv4Proc)
        {
            ulRet = pfAlgIPv4Proc(pstMBuf, usIPOffset, (SESSION_HANDLE)pstSession);
        }
    }

    if(ERROR_SUCCESS != ulRet)
    {
        ulPktRet = PKT_DROPPED;
    }

    return ulPktRet;
}

/******************************************************************
   Func Name:SESSION_IpfsEndProc
Date Created:2021/04/25
      Author:wangxiaohua
 Description:IPv4转发流程中Session End业务点的处理函数
       INPUT:IN VOID *pCache          ----Cache
             INOUT MBUF_S *pstMBuf    ----报文             
      Output:pstMBuf                  ----报文可能被修改
      Return:PKT_CONTINUE             ----继续转发
             PKT_DROPPED              ----删除mbuf并丢包
     Caution:MBUF可能会被修改.
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
ULONG SESSION_IpfsEndProc(IN USHORT usIPOffset, INOUT MBUF_S *pstMBuf)
{
    SESSION_S       *pstSession;
    SESSION_CTRL_S  *pstSessionCtrl;
    ULONG            ulPktRet = PKT_CONTINUE;
	flow_connection_t *fcp;
	
    /* 从报文获取会话pstSession */
    pstSession = GET_FWSESSION_FROM_LBUF(pstMBuf);
	
    pstSessionCtrl = SESSION_CtrlData_Get();

    if(NULL == pstSession)
    {
		/* 如果会话尝试处理但是建不了表项，则不创建快转表 */
	    /* 此处需要跟flow沟通，flow目前逻辑是 会话不安装快转，flow肯定就自己安装了， 但此处不希望flow安装 */
       MBUF_SET_SESSION_FLAG(pstMBuf, 0);
       SESSION_KStatFailInc(SESSION_STAT_FAIL_TRY_FAIL_UNICAST, pstSessionCtrl);
       return PKT_CONTINUE;
    }

    /* 两种报文不处理:1.ICMP差错 2.后续分片非首片报文 */
    if (BOOL_TRUE != session_kIsNeedProc(usIPOffset, pstMBuf, pstSession))
    {
        SESSION_DBG_PACKETS_EVENT_SWITCH(pstMBuf, usIPOffset, DBG_ABNORM_PKT_ICMPERR_OR_LATTERFRAG);
        if (!SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP))
        {
            /* 正式会话不能释放会话信息 */
            MBUF_SET_SESSION_FLAG(pstMBuf, 0);
        }
                
        return PKT_CONTINUE;
    }

    /* SESSION正式化 肯定是普通会话 */
    if(SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP))
    {
        ulPktRet = SESSION_KCapabitityTest(pstSessionCtrl, pstMBuf);
        if (PKT_DROPPED == ulPktRet)
        {
            SESSION_KStatFailInc(SESSION_STAT_FAIL_CAPABITITY_UNICAST, pstSessionCtrl);
            return PKT_DROPPED;
        }

        /* 增加引用计数 */
        rte_atomic32_set(&pstSession->stSessionBase.stRefCount.stCount, 1);

        /* 清除临时会话标志位 */
        SESSION_TABLE_CLEAR_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP);

		fcp = GET_FC_FROM_LBUF(pstMBuf);
		flow_install_conn_no_refresh(fcp);
		ulPktRet = session_kFirstEnd(pstMBuf, usIPOffset, pstSession, pstSessionCtrl);
    }
    else
    {
        ulPktRet = session_kAfterEnd(pstMBuf, usIPOffset, pstSession); 
    }

    /*正式化会话清除mbuf的会话指针*/
    if ((PKT_CONTINUE == ulPktRet) &&
        !SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP))
    {
        /* 清空MBUF中的会话指针和flag位 */
        MBUF_SET_SESSION_FLAG(pstMBuf, 0);		
		SESSION_MBUF_SET_FLAG(pstMBuf, (USHORT)SESSION_MBUF_SLOW_FORWARDING);
    }
    
    return ulPktRet;
}

#if 0
/******************************************************************
   Func Name:SESSION_FsOriginalState
Date Created:2021/04/25
      Author:wangxiaohua
 Description:快转正向状态机处理
       INPUT:IN SESSION_S *pstSession,                ----会话
             IN SESSION_CTRL_S *pstSessionCtrl               ----MDC
             IN const IP_S *pstIP                     ----IPv4报文头
             IN FSBUF_PKTINFO_S *pstPktInfo           ----报文信息
             IN const FSBUF_BLOCKINFO_S *pstBlockInfo ----数据快信息
             IN UINT uiL3Offset                       ----三层偏移
      Output:无
      Return:无
      Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline VOID SESSION_FsOriginalState(IN SESSION_S *pstSession,
                                           IN SESSION_CTRL_S *pstSessionCtrl,
                                           IN MBUF_S *pstMbuf,
                                           IN UINT uiL3Offset,
                                           IN UINT uiL4Offset)
{
    if (SESSION_L4_TYPE_TCP == pstSession->stSessionBase.ucSessionL4Type)
    {        
        SESSION_KTcpState(pstSession, pstMbuf, SESSION_DIR_ORIGINAL, pstSessionCtrl, uiL3Offset, uiL4Offset);
    }
    else /* RAWIP 和 UDP */
    {
        /* UDP的原始正方向状态不会有变换，仅仅刷新老化时间*/
        SESSION_KAgingRefresh(pstSession);
    }

    return;
}

static inline VOID SESSION_FsReplyState(IN SESSION_S *pstSession,
                                        IN SESSION_CTRL_S *pstSessionCtrl,
                                        IN UINT uiL3Offset,                                        
                                        IN UINT uiL4Offset,
                                        INOUT MBUF_S *pstMbuf)
{
    AGINGQUEUE_UNSTABLE_CLASS_S *pstClass;

    /* UDP */
    if (SESSION_L4_TYPE_UDP == pstSession->stSessionBase.ucSessionL4Type)
    {
        /* UDP无需加锁 */
        if(UDP_ST_OPEN == pstSession->ucState)
        {
            pstSession->ucState = UDP_ST_READY;
            pstClass = &pstSessionCtrl->astTableAgingClass[SESSION_L3_TYPE_IPV4][SESSION_L4_TYPE_UDP][UDP_ST_READY];
            AGINGQUEUE_UnStable_Switch(&pstSession->stSessionBase.unAgingRcuInfo.stAgingInfo, pstClass);
        }  
        SESSION_KAgingRefresh(pstSession);
    }
    else if(SESSION_L4_TYPE_TCP == pstSession->stSessionBase.ucSessionL4Type)
    {
        SESSION_KTcpState(pstSession, pstMbuf, SESSION_DIR_REPLY, pstSessionCtrl, uiL3Offset, uiL4Offset);
    }
    else /* RAWIP */
    {
        if(RAWIP_ST_OPEN == pstSession->ucState)
        {
            pstSession->ucState = RAWIP_ST_READY;
            pstClass = &pstSessionCtrl->astTableAgingClass[SESSION_L3_TYPE_IPV4][SESSION_L4_TYPE_RAWIP][RAWIP_ST_READY];            
            AGINGQUEUE_UnStable_Switch(&pstSession->stSessionBase.unAgingRcuInfo.stAgingInfo, pstClass);
        }
        SESSION_KAgingRefresh(pstSession);
    }
        
    
    return;
}
#endif

STATIC VOID session_kExtStateProc(IN SESSION_PKT_DIR_E enDir,
                                  IN SESSION_S *pstSession,
                                  IN MBUF_S *pstMbuf,
                                  IN SESSION_CTRL_S *pstSessionCtrl,
                                  IN UINT uiL3Offset,
                                  IN UINT uiL4Offset)
{
	csp_key_t *pstcspkey;
    SESSION_L4_PROTO_S *pstL4Proto;
    UCHAR ucOldState;
    UCHAR ucNewState;
    ULONG ulRet;

    pstcspkey = SESSION_KGetIPfsKey((SESSION_HANDLE)pstSession, enDir);
    pstL4Proto = SESSION_KGetL4Proto_Proc(pstcspkey->proto);


    //rte_spinlock_lock(&(pstSession->stLock));
		
    ucOldState = pstSession->ucState;
    
    ulRet = pstL4Proto->pfState(pstSession, pstMbuf, uiL3Offset, uiL4Offset);
    if (ulRet != ERROR_SUCCESS)
    {
        /* 设置非法报文标记，但报文还是属于会话，只不过状态不对 */
        SESSION_BAK_SetInvalidFlag(pstMbuf);
        SESSION_KStatFailInc(SESSION_STAT_FAIL_EXT_STATE, pstSessionCtrl);
    }

    ucNewState = pstSession->ucState;
    if (ucOldState != ucNewState)
    {
        /* 重新设置老化类并更新老换时间 */
        SESSION_KAging_SetClassNew(pstSessionCtrl, pstSession);
    }
    else
    {
        /* 刷新老化时间 */
        if (!SESSION_MBUF_TEST_FLAG(pstMbuf, SESSION_MBUF_INVALID))
        {
            SESSION_KAgingRefresh(pstSession);
        }
    }

    //rte_spinlock_unlock(&(pstSession->stLock));
    
    return;
}

static VOID session_kExtLayer4State(IN SESSION_PKT_DIR_E enDir,
                                    IN SESSION_S *pstSession,
                                    IN MBUF_S *pstMbuf,
                                    IN SESSION_CTRL_S   *pstSessionCtrl,
                                    IN UINT uiL3Offset,
                                    IN UINT uiL4Offset)
{
    /* 多核并发时，为保证状态会话计数、珹ging_setClass正确，需加锁 */
    if (!SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_DELETING))
    {
        /* 进行状态机处理 */
        session_kExtStateProc(enDir, pstSession, pstMbuf, pstSessionCtrl, uiL3Offset, uiL4Offset);
    }

    /* 刷新父会话的老化时间 */
    SESSION_KRefreshParents(pstSession);

    return;
}

#if 0
/******************************************************************
   Func Name:SESSION_KExtStateProcess
Date Created:2021/04/25
      Author:wangxiaohua
 Description:会话快转处理
       INPUT:IN SESSION_S *pstSession          ----会话指针
             IN const VOID *pCache             ----快转表
             IN SESSION_CTRL_S *pstSessionCtrlData    ----mdc控制块
             IN IP_S *pstIP                    ----IPv4报文头
             IN FSBUF_PKTINFO_S *pstPktInfo    ----报文信息
             IN const FSBUF_BLOCKINFO_S *pstBlockInfo ----数据块信息
             IN UINT uiL3Offset                ----三层偏移
      Output:无
      Return:SESSION_S
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
STATIC VOID SESSION_KExtStateProcess(IN SESSION_S *pstSession,
                                     IN const VOID *csp,
                                     IN SESSION_CTRL_S *pstSessionCtrl,
                                     IN MBUF_S *pstMbuf,
                                     IN UINT uiL3Offset,
                                     IN UINT uiL4Offset)
{
    SESSION_PKT_DIR_E enDir;

    enDir = (SESSION_PKT_DIR_E)GET_PACKETDIR_FROM_CSP((conn_sub_t *)csp);

    /* 更新报文方向 */    
    SESSION_MBUF_SET_FLAG(pstMbuf, enDir);  

    if(!SESSION_IsIPv4LatterFrag(uiL3Offset, pstMbuf))
    {
        /* 进行状态机处理 */
        session_kExtLayer4State(enDir, pstSession, pstMbuf,pstSessionCtrl, uiL3Offset, uiL4Offset);
    }

    return;
}
#endif

/* 不进行内联了 */
STATIC ULONG SESSION_KExtProc(IN SESSION_S *pstSession,
                              IN VOID *csp,
                              IN struct iphdr *pstIP,
                              IN MBUF_S *pstMbuf,
                              IN SESSION_CTRL_S *pstSessionCtrl,
                              IN UINT uiL3Offset,
                              IN UINT uiL4Offset)
{
    ULONG ulRet = PKT_CONTINUE;
    BOOL_T bIsLatterFrag;	
    SESSION_PKT_DIR_E enDir;

	enDir = (SESSION_PKT_DIR_E)GET_PACKETDIR_FROM_CSP((conn_sub_t *)csp);
    SESSION_MBUF_SET_FLAG(pstMbuf, enDir);  

    bIsLatterFrag = SESSION_IsIPv4LatterFrag(uiL3Offset, pstMbuf);
    if (BOOL_TRUE == bIsLatterFrag)
    {
        return ulRet;
    }
	else
	{				
        /* 进行状态机处理 */
        session_kExtLayer4State(enDir, pstSession, pstMbuf,pstSessionCtrl, uiL3Offset, uiL4Offset);
	}

    if((0 != pstSession->usAlgFlag) && 
       (!IN_MULTICAST(ntohl((*pstIP).daddr))))
    {
        /* 会话ALG处理 ASPF */
        if(NULL != g_stSessionIPv4KAlgProc.pfAlgIPv4Proc)
        {
            ulRet = g_stSessionIPv4KAlgProc.pfAlgIPv4Proc(pstMbuf, uiL3Offset, (SESSION_HANDLE)pstSession);
        }

        if(ERROR_SUCCESS != ulRet)
        {
            ulRet = PKT_DROPPED;
        }
    }

    return ulRet;
}

STATIC inline ULONG SESSION_FsModuleProc(IN SESSION_S *pstSession, 
                                         IN SESSION_CTRL_S *pstSessionCtrl,
										 IN MBUF_S *pstMbuf)
{
	ULONG ulRet = PKT_CONTINUE;

	/* ASPF快转 */
	if (unlikely(SESSION_MBUF_TEST_FLAG(pstMbuf, SESSION_MBUF_INVALID)))
	{
    	if (SESSION_TABLE_IS_MODULEFLAG_SET(pstSession, SESSION_MODULE_ASPF))
    	{
    		ulRet = SESSION_Proc_Aspf(pstSession, pstMbuf);
    	}
	}

	/* 发送日志 */
	if (SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase,
		((USHORT)SESSION_LOG_FLOW_PACKET | (USHORT)SESSION_LOG_FLOW_BYTE)) &&
		(PKT_CONTINUE == ulRet))
	{
		SESSION_KLOG_PROC_ActiveFlow(pstSession, pstSessionCtrl);
	}

	return ulRet;
}

STATIC ULONG SESSION_FsSecpolicyMatch(IN SESSION_S *pstSession)
{
	SECPOLICY_PACKET_IP4_S stSecPolicyPacketIP4;
	conn_sub_t *csp;
	csp_key_t *pstcspkey;
	SECPOLICY_ACTION_E enAction;  
		
	csp       = SESSION_KGetCsp((SESSION_HANDLE)pstSession, SESSION_DIR_ORIGINAL);
    pstcspkey = &csp->key;
	stSecPolicyPacketIP4.ucProtocol     = pstcspkey->proto;
	stSecPolicyPacketIP4.stDstIP.s_addr = pstcspkey->dst_ip;
	stSecPolicyPacketIP4.stSrcIP.s_addr = pstcspkey->src_ip;
	stSecPolicyPacketIP4.uiVxlanID      = pstcspkey->token;
    stSecPolicyPacketIP4.uiAppID        = pstSession->uiAppID;    
	switch (stSecPolicyPacketIP4.ucProtocol)
	{
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		{
			stSecPolicyPacketIP4.usDPort = pstcspkey->dst_port;
			stSecPolicyPacketIP4.usSPort = pstcspkey->src_port;
			break;
		}
		case IPPROTO_ICMP:
		{
			stSecPolicyPacketIP4.stIcmp.ucType = csp->csp_type;
			stSecPolicyPacketIP4.stIcmp.ucCode = csp->csp_code;
			break;
		}
		default:
		{
			break;
		}
	}
	
	enAction = SecPolicy_Match_IP4(&stSecPolicyPacketIP4);
	if(SECPOLICY_ACTION_PERMIT == enAction)
	{
		return PKT_CONTINUE;
	}
	else
	{
		return PKT_DROPPED;
	}
}

STATIC ULONG SESSION_FsService(struct rte_mbuf *pstRteMbuf)
{
    MBUF_S            *pstMbuf;
    SESSION_S         *pstSession;	
    SESSION_CTRL_S    *pstSessionCtrl;		
	conn_sub_t        *csp;	
	struct iphdr      *pstIP;
    SESSION_PKT_DIR_E enPktDir;    
    UINT              uiL4Offset;    
	UINT              uiL3Offset = 0;       
    ULONG             ulRet      = PKT_CONTINUE;	
	csp_key_t  *pstcspkey;
	struct in_addr stSrcIP;
    struct in_addr stDstIP;
	UINT uiVrf;
	UINT uiPreAppID;
	BOOL_T bNeedApr;
	APR_PARA_S stAprPara;
	IPS_PARA_S stIpsPara;
	pstMbuf = mbuf_from_rte_mbuf(pstRteMbuf);
    /* 本报文已经经过FW慢转处理过了，快转无需处理了直接返回continue即可 */
    if(SESSION_MBUF_TEST_FLAG(pstMbuf, SESSION_MBUF_SLOW_FORWARDING))
    {
        return PKT_CONTINUE;
    }
	
    pstSessionCtrl = SESSION_CtrlData_Get();
    pstSession = GET_FWSESSION_FROM_MBUF(pstRteMbuf);
	csp        = GET_CSP_FROM_MBUF(pstRteMbuf);	
    enPktDir   = (SESSION_PKT_DIR_E)GET_PACKETDIR_FROM_CSP(csp);

    if (NULL == pstSession)
        return PKT_CONTINUE;
	
    /* 获取4层长度 */
    (VOID)session_kGetL4Offset(pstMbuf, uiL3Offset, &uiL4Offset);

	/* 取报文数据域的IP头 */
	pstIP = rte_pktmbuf_mtod_offset(pstRteMbuf, struct iphdr *, uiL3Offset);

    /* 扩展方式的安全业务处理，无需快 */
    ulRet = SESSION_KExtProc(pstSession, csp, pstIP, pstMbuf, pstSessionCtrl, uiL3Offset, uiL4Offset);
		
    if(unlikely(PKT_CONTINUE != ulRet))
    {
        /* 丢包处理 */
        return ulRet;
    }

	uiPreAppID = pstSession->uiAppID;

	/* 是否需要做应用识别 */		
    pstcspkey = GET_CSP_KEY(csp);

	uiVrf = pstcspkey->token;
	stSrcIP.s_addr = pstcspkey->src_ip;
	stDstIP.s_addr = pstcspkey->dst_ip;

	bNeedApr = SecPolicy_IP4_IsNeedAPR(uiVrf, &stSrcIP, &stDstIP);	
    if(bNeedApr)
    {
		
		stAprPara.uiAppID      = pstSession->uiAppID;
		stAprPara.uiTrustValue = pstSession->uiTrustValue;
		
		APR_Check(pstMbuf, &stAprPara);
		
	    pstSession->uiAppID = stAprPara.uiAppID;
		pstSession->uiTrustValue = stAprPara.uiTrustValue;
    }

    /* APPID发生变更，需要重新做一遍安全策略 */ 
	if(uiPreAppID != pstSession->uiAppID)
	{
		ulRet = SESSION_FsSecpolicyMatch(pstSession);
		if(unlikely(PKT_CONTINUE != ulRet))
	    {
	        /* 丢包处理 */		
			SESSION_KDeleteSession((SESSION_HANDLE)pstSession);
	        return ulRet;
	    }
	}

    /* 调用dpi处理 */	
	stIpsPara.uiDirect = pstSession->uiDirect;
	IPS_Check(pstMbuf, &stIpsPara);
    ulRet = stIpsPara.uiAction;
	if(unlikely(PKT_CONTINUE != ulRet))
    {
        /* 丢包处理 */
        return ulRet;
    }

    if(unlikely(BOOL_TRUE == pstSessionCtrl->bStatEnable))
    {
        SESSION_FsAddStat(pstSession, pstMbuf, pstSessionCtrl, enPktDir);
    }

    /* 业务处理 */
    ulRet = SESSION_FsModuleProc(pstSession, pstSessionCtrl, pstMbuf);

    return ulRet;
}


INT SESSION_FsServiceProc(struct rte_mbuf *pstRteMbuf)
{
	ULONG ulRet;
	INT iRet;

    if (unlikely(!SESSION_CtrlData_Get()->bSecEnable))
    {
        return FLOW_RET_OK;
    }

	ulRet = SESSION_FsService(pstRteMbuf);
	if(PKT_CONTINUE != ulRet)
	{
        SESSION_KStatFailInc(SESSION_STAT_FAIL_FAST_PATH, SESSION_CtrlData_Get());
		iRet = FLOW_RET_ERR;
	}
	else
    {
		iRet = FLOW_RET_OK;
	}

	return iRet;
}

#if 0
ULONG SESSION_KL2ExtProc(IN SESSION_S *pstSession,
						IN const VOID *pCache,
						IN IP_S **ppstIP,
						IN MBUF_S *pstMBuf,
                        IN SESSION_CTRL_S *pstSessionCtrl,
						IN UINT uiL3Offset)
{
	ULONG ulRet = PKT_CONTINUE;
	BOOL_T bIsLatterFrag;

	/* 会话处理 */
	SESSION_KExtStateProcess(pstSession,pCache,pstSessionCtrl,*ppstIP,pstMBuf,uiL3Offset);

	bIsLatterFrag = SESSION_IsIPv4LatterFrag(uiL3Offset, pstMBuf);
	if ((BOOL_TRUE == bIsLatterFrag) &&
		(APP_ID_HTTP != pstSession->uiAppID) &&
		(APP_ID_DNS != pstSession->uiAppID))
	{
		return ulRet;
	}

	if ((0 != pstSession->usAlgFlag) &&
	    (!IN_MULTICAST(ntohl((**ppstIP).stIpDst.s_addr))))
	{
		/* 会话ALG处理 ASPF */
		if (NULL != g_stSessionIPv4KAlgProc.pfAlgIPv4FastProc)
		{
			ulRet = g_stSessionIPv4KAlgProc.pfAlgIPv4FastProc((SESSION_HANDLE)pstSession, pstMBuf,
													uiL3Offset, *ppstIP);
		}

		if (ERROR_SUCCESS != ulRet) 
		{
			ulRet = PKT_DROPPED;
		}
	}

	SESSION_IGNORE_CONST(ppstIP);

	return ulRet;
}

ULONG SESSION_L2FsService(IN IF_INDEX ifIndex, 
                          IN VOID *pCache,
						  INOUT MBUF_S *pstMBuf)
{
	SESSION_S *pstSession;
	SESSION_PKT_DIR_E enPktDir;    
    SESSION_CTRL_S *pstSessionCtrl;
	UCHAR ucLinkLen; 
	IP_S *pstIP;
	ULONG ulRet = PKT_CONTINUE;
	UINT uiL2Type = MACFW_TYPE_VLAN;
	IF_INDEX ifIndexRcv= IF_INVALID_INDEX;

	IGNORE_PARAM(ifIndex);

	DBGASSERT(NULL != pCache);

	pstSession = IPFS_GET_CACHE_SESSION(pCache);

	pstSessionCtrl = SESSION_CtrlData_Get();

	ucLinkLen = FSBUF_GET_LINKHEADSIZE(pstMBuf);
	pstIP = MBUF_BTOD_OFFSET(pstMBuf, ucLinkLen, IP_S*);
	enPktDir = (SESSION_PKT_DIR_E)IPFS_GET_CACHE_DIR(pCache);
	


	/*二层处理传进的是网络序，需转为主机序，各个业务处理ip头都认为是主机序*/
	pstIP->usLen = ntohs(pstIP->usLen);
	pstIP->usOff = ntohs(pstIP->usOff);

	/* 当前只有普通的TCP/UDP/RAWIP会进入这个处理 */
	if (likely((SESSION_TYPE_NORMAL == pstSession->stSessionBase.ucSessionType)
			   && (APP_ID_DNS != pstSession->uiAppID)
			   && (BOOL_TRUE != SESSION_IsIPv4LatterFrag(0, pstMBuf))))
	{
		/* 进入这里就按照方向进行区分，因此以上三个协议的处理能够更简化 */
		if (SESSION_DIR_ORIGINAL == enPktDir)
		{
			SESSION_FsOriginalState(pstSession,pstSessionCtrl,pstIP,pstMBuf,ucLinkLen);
		}
		else
		{
			SESSION_FsReplyState(pstSession, pstSessionCtrl,pstIP,pstMBuf,ucLinkLen);
		}
	}
	else
	{
		/* 扩展方式的安全业务处理，无需快 */
		ulRet = SESSION_KL2ExtProc(pstSession,pCache,&pstIP,pstMBuf,pstSessionCtrl,ucLinkLen);
		if (unlikely (PKT_CONTINUE != ulRet))
		{
			/* 丢包处理 */
			return ulRet;
		}
	}

	/* 用户态dpi上送报文给进程 */
	UDPI_KCAP_Ipv4FsCapturePacket(enPktDir,ucLinkLen,pstMBuf);

	/* add dim fs proc*/
	if (unlikely(SESSION_TABLE_IS_MODULEFLAG_SET(pstSession, SESSION_MODULE_DIM) &&
				 SESSION_TABLE_IS_ATTACHFLAG_SET(pstSession, SESSION_MODULE_DIM)))
	{
		ulRet = DIM_KPKT_IPv4FastProc((SESSION_HANDLE)pstSession,enPktDir,ucLinkLen,
										&pstIP, pstMBuf);

		if (unlikely(PKT_CONTINUE != ulRet))
		{
			/* 丢包处理 */
			return ulRet;
		}
	}

	/*增加会话统计信息*/
	if (unlikely(BOOL_TRUE == pstSessionCtrl->bStatEnable))
	{
		SESSION_FsAddStat(pstSession, pstMBuf, pstSessionCtrl, enPktDir, IPFS_GET_CACHE_MCTYPE(pCache));
	}

	/*业务处理*/
	ulRet = SESSION_FsModuleProc(pstSession,pstSessionCtrl,pCache,pstMBuf);

	/*转会网络序*/
	pstIP->usLen = htons(pstIP->usLen);
	pstIP->usOff = htons(pstIP->usOff);

	SESSION_IGNORE_CONST(pCache);

	return ulRet;
}
#endif

/* 根据报文填充Tuple信息 */
ULONG SESSION_KGetTupleFromMbuf(IN MBUF_S *pstMBuf, IN UINT uiL3OffSet, INOUT SESSION_TUPLE_S *pstTuple)
{
    UINT uiL4OffSet;
    UCHAR ucL4Proto;
    UINT uiIPLen;
    SESSION_L3_PROTO_S *pstL3Proto;
    SESSION_L4_PROTO_S *pstL4Proto;
    ULONG ulRet;

    /* 获取3层、4层协议处理模块 */
    ulRet = session_kGetModule(pstMBuf, uiL3OffSet, &uiL4OffSet, &ucL4Proto, &uiIPLen, &pstL3Proto, &pstL4Proto);
    if(ERROR_SUCCESS != ulRet)
    {
        return ERROR_FAILED;
    }

    /* 保证至少要能取到8字节的端口信息且连续 */
    ulRet = MBUF_PULLUP(pstMBuf, uiL4OffSet + 8);
    if(ERROR_SUCCESS != ulRet)
    {
        return ERROR_FAILED;
    }

    /* 获取报文的Tuple信息 */
    session_kGetTuple(pstMBuf, uiL3OffSet, uiL4OffSet, ucL4Proto, pstL3Proto, pstL4Proto, pstTuple);

    return ERROR_SUCCESS;
}


