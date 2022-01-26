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

SESSION_CONF_S g_stSessionConfInfo = {1000}; /* ��ʼ��һ��Ĭ��ֵ */
SESSION_MODULE_REG_S g_astModuleRegInfo[SESSION_MODULE_MAX];  /* ��¼��ҵ��ģ��ע����Ϣ */
/* ��Э���Ӧ�ĻỰ���� */
SESSION_L4_TYPE_E g_aenSessionType[IPPROTO_MAX];

extern UCHAR g_aucIcmpPktType[];
/*ֻ����<=ICMP_MASKREPLY��type*/
extern UCHAR g_aucIcmpReverType[];

RELATION_S *SESSION_RelationHash_Find(IN const csp_key_t *pstcspkey);
BOOL_T SESSION_Relation_IsTupleMatch(IN const csp_key_t *pstTupleFromHash,
                                     IN const csp_key_t *pstNewTuple,
                                     IN UINT uiCmpMask);

VOID SESSION_init_l4type_map(VOID)
{
    UINT uiProto;

    /*���Ƚ�����Э���ʼ��ΪRAW_IP, �ٶ�֧�ֵ�Э�鸳ֵ*/
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

/* ��ȡ���Ĵ����õ�3�㣬4�㴦��ģ�� */
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

/* �ӱ�������ȡtuple���� */
VOID session_kGetTuple(IN const MBUF_S *pstMBuf,
                       IN UINT uiL3Offset,
                       IN UINT uiL4Offset,
                       IN UCHAR ucL4ProtoNum,
                       IN const SESSION_L3_PROTO_S *pstL3Proto,
                       IN const SESSION_L4_PROTO_S *pstL4Proto,
                       INOUT SESSION_TUPLE_S *pstTuple)
{
    /* ���������г�ʼ��������������v4��v6��ַ��union, ƥ��Ựʱ���� */
    memset(pstTuple, 0, sizeof(SESSION_TUPLE_S));

    /*
     * ͨ��3��Э��ģ���ṩ�ĺ������session tuple��3����Ϣ��
     *   3����Ϣ����
     *      ��ַ��
     *      Դ��ַ��Ŀ�ĵ�ַ
     *      Tunnel ID
     *      VPN ID
     *      4��Э���.
     *  ������4��Э��ͷ����ʼ��3��Э��ģ��õ�4��Э��ͷ��ƫ��λ�ã��Լ�4��Э��š�   
     */
    pstL3Proto->pfPktToTuple(pstMBuf, uiL3Offset, pstTuple);
    pstTuple->ucProtocol = ucL4ProtoNum;

    /*
     * ��������Ҫ��֤pstMBuf������Ч��
     * Ŀǰ1��3��ȡtuple��ת����֤pstMBuf����ipͷ����
     *     2��4��ȡtuple��4��Э��ģ��ĵ�����麯�����е����Ϸ��Լ������֤��
     *        ��������Ϸ��������session tuple��4����Ϣ.
     *     3��4��ȡICMP�������Ƕip+port��tuple���ڵ���ǰҲ��Ҫ��֤��
     */
    pstL4Proto->pfPktToTuple(pstMBuf, uiL3Offset, uiL4Offset, pstTuple);

    return;
}

/* �쳣ͳ�� */
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
    
    /*���б��ĵ������:������һ�����ΰ���������һ��ICMP������Ϣ���ġ�
     *���ڻ��α��ģ�ֱ�ӷ��ش���
     *����ICMP������Ϣ����Ҫ����Ƿ�����ĳ���Ự����Ĵ����ģ���������ͳ���Լ�״̬������
     *�������ڻỰ��ICMP Error ֪ͨ���ģ���ʶ�����������Ự��
     *���ڲ����ڻỰ�ģ�����ƥ��Ự����
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

    /*ͨ��APPIDʶ��Ự��ALG����*/
    pstSess->uiAppID = uiAppID;
	pstSess->uiTrustValue = uiTrustValue;

    /*��¼�Ự�ĳ�ʼAppID(��alg��չ���ϻ�����)��������������appchange���仯*/
    pstSess->uiOriginalAppID = uiAppID;
       
    /*�����������*/
    pstSess->usCfgSeq = pstSessionVd->usCfgSeq;

    /*������ʱ�Ự��־λ*/
    SESSION_TABLE_SET_TABLEFLAG(&pstSess->stSessionBase, SESSION_TEMP);
    
    return;
}

/******************************************************************
   Func Name:SESSION_KGetNotZero
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�Ự���ü�����1��Ҫ������֮ǰ���ü�������Ϊ0�����򷵻�ʧ��
       INPUT:SESSION_S *pstSession, �Ự
      Output:��
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
        /*�������ü�����ԭ�Ӳ���ʱ������0����ʾ���ҹ����лỰ��ɾ����*/
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

    /* �˴����Ƚ�IP��ַ�����Ƚ϶˿ں�VPN��VPN�Ѿ���ƥ�������ʱ�ȽϹ��ˣ�
       ������ͨ������VPN���޷���ȡ */

    DBGASSERT(NULL != pstParent);
    DBGASSERT(NULL != pstChild);

    pstChildKey = SESSION_KGetIPfsKey((SESSION_HANDLE)pstChild, SESSION_DIR_ORIGINAL);
    pstParentOrgKey = SESSION_KGetIPfsKey((SESSION_HANDLE)pstParent, SESSION_DIR_ORIGINAL);    
    pstParentRpyKey = SESSION_KGetIPfsKey((SESSION_HANDLE)pstParent, SESSION_DIR_REPLY);

    /* ���ȱȽ�����Դ�ͷ���Ŀ�� */
    if((pstChildKey->src_ip == pstParentOrgKey->src_ip) &&
       (pstChildKey->dst_ip == pstParentOrgKey->dst_ip))
    {
        enChildDir = DIR_PARENT_SRC_2_DST; /* ���ӷ�����ͬ */
    }
    else if((pstChildKey->src_ip == pstParentRpyKey->src_ip) &&
            (pstChildKey->dst_ip == pstParentRpyKey->dst_ip))
    {
        enChildDir = DIR_PARENT_DST_2_SRC; /* ���ӷ����෴ */
    }
    else
    {
        /* ����LB���Ự�ķ���Դһ�㶼�Ƿ�������ַ��
           LB���Ự����Ŀ��һ���Ǵ����ַ���������ڱȽ� */
        if((pstChildKey->src_ip == pstParentOrgKey->src_ip) || 
           (pstChildKey->dst_ip == pstParentRpyKey->dst_ip))
        {
            enChildDir = DIR_PARENT_SRC_2_DST; /* ����Ϊ���ӷ�����ͬ����ȷ��ʲô����»������� */
        }
        else if((pstChildKey->src_ip == pstParentRpyKey->src_ip) ||
                (pstChildKey->dst_ip == pstParentOrgKey->src_ip) ||
                (pstChildKey->dst_ip == pstParentRpyKey->dst_ip))
        {
            enChildDir = DIR_PARENT_DST_2_SRC; /* ����Ϊ���ӷ����෴����ȷ��ʲô����»������� */
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

    /*���ƥ����������ݹ����������ûỰ�Ĳ���*/
    if(NULL == pstRelation)
    {
        return;
    }

    /*���ڻỰ��ָ���˸��Ự����Ҫ�Ը��Ự�����ü��� +1*/
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

    /*������ƥ���¼�֪ͨ*/
    pfNewNotify = pstRelation->pfNewSession;
    if(NULL != pfNewNotify)
    {
        (VOID)pfNewNotify((SESSION_HANDLE)pstSess, &pstRelation->stAttachData, pstMbuf);
    }

    if(!RELATION_IS_PERSIST(pstRelation))
    {
        /* �ӻỰ���з�persist�������ʱ�򣬲�����ɾ��������
           ��Ҫ�ȵ��ӻỰ��ʽ����ʱ����ɾ������������ȸ��Ự����һ����� */
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

    /*����AppID��MBUF*/
    MBUF_SET_APP_ID(pstMbuf, uiAppID);

    /*������������ �ڵ��� �� �⵽�� */
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

        /* ���÷Ƿ����ı�ǣ������Ļ������ڻỰ��ֻ����״̬���� */
        SESSION_BAK_SetInvalidFlag(pstMbuf);
        SESSION_KStatFailInc(SESSION_STAT_FAIL_EXTNEW_STATE, pstSessionCtrl);
    }

    /* ���������ϻ��ಢ�����ϻ�ʱ�� */
    SESSION_KAging_SetClassNew(pstSessionCtrl, pstSession);

    /*ˢ�¸��Ự���ϻ�ʱ��*/
    SESSION_KRefreshParents(pstSession);

    return;
}

/******************************************************************
   Func Name:session_kGetL4Offset
Date Created:2021/04/25
      Author:wangxiaohua
 Description:��ȡ�Ĳ�ƫ��
       INPUT:IN MBUF_S *pstMbuf     ----����
             IN UINT uiL3Offset     ----����ƫ��
      Output:OUT UINt *puiL4Offset  ----4��ͷƫ��λ��
      Return:UINT                   ----�����ܳ���
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

    /* ����Ƿ��������Ự���������������������MBUF�лỰ INVALID ��� */
    ucSessL4Type = (UCHAR) SESSION_KGetSessTypeByProto(pstcskey->proto);

    /* ��ȡ4�㳤�� */
    uiIPLen = session_kGetL4Offset(pstMbuf, uiL3Offset, &uiL4Offset);

    /* ��鲻ͨ����ֱ�ӷ���NULL */
    ulRet = session_kcheckPacket(pstMbuf, pstcskey, ucSessL4Type, uiL3Offset, uiL4Offset, &ucNewState);
    if (unlikely (ERROR_SUCCESS != ulRet))
    {
        /*��ǰnewsessioncheck��ǰ,icm_err��Ȼ���ᴴ���Ự�����ߴ˷�֧��
          ����icm_err ���ܴ�invalid��ǣ�����aspf��ֱ�Ӷ���*/
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

    /*�Ự�ױ��Ĵ���*/
    pstRelation = SESSION_RelationHash_Find(pstcskey);
    pstSession = session_kCreateWithRelation(pstMbuf, ucSessL4Type, csp,
                                             pstSessionCtrl, pstRelation, uiL3Offset);
    if(unlikely (NULL == pstSession))
    {
        SESSION_MBUF_SET_FLAG(pstMbuf, (USHORT)SESSION_MBUF_PROCESSED);  
        SESSION_KStatFailInc(SESSION_STAT_FAIL_ALLOC_SESSION, pstSessionCtrl);
        return SESSION_INVALID_HANDLE;
    }

    /*�����װ���ǵ�MBUF, ����temp�Ự��ǵ�MBUF, ����Ϊ����*/
    SESSION_MBUF_SET_FLAG(pstMbuf, SESSION_MBUF_FIRSTPKT | SESSION_MBUF_PROCESSED);

    /* ����״̬������ */
    session_kLayer4StateNewExt(pstSession, (USHORT)uiL3Offset, uiL4Offset, pstMbuf, pstcskey->proto, pstSessionCtrl);

    /*ͳ�ƿ��ش򿪣��Ự����ͳ����Ϣ*/
    if (unlikely(BOOL_TRUE == pstSessionCtrl->bStatEnable))
    {
        /*��ʼ���Ự������ͳ����Ϣ*/
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

    /* ���÷Ƿ����ı�ǣ������Ļ������ڻỰ��ֻ����״̬���� */
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

    /* ���е����Ϸ��Լ�� */
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
        /* ���������ϻ��ಢ�����ϻ�ʱ�� */
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
            /*������״̬��pstClass*/
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

    /* ���������ϻ��ಢ�����ϻ�ʱ�� */
    if(!SESSION_MBUF_TEST_FLAG(pstMBuf, (USHORT)SESSION_MBUF_INVALID))
    {
        SESSION_KAgingRefresh(pstSession);
    }
    return;
}

/* ��ȡЭ����̬ */
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
        /* ���÷Ƿ����ı�ǣ������Ļ������ڻỰ��ֻ����״̬���� */
        SESSION_BAK_SetInvalidFlag(pstMBuf);
        SESSION_KStatFailInc(SESSION_STAT_FAIL_TOUCH_STATE, pstSessionCtrl);
    }

    ucNewState = pstSession->ucState;
    if (ucOldState != ucNewState)
    {
        /* ���������ϻ��ಢ�����ϻ�ʱ�� */
        SESSION_KAging_SetClassNew(pstSessionCtrl, pstSession);
    }
    else
    {
        /* ˢ���ϻ�ʱ�� */
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
 Description:�Ự4��Э��״̬����
       INPUT:IN csp_key_t        *pstcskey    ----��תKey
             IN UINT             uiL4_Offset  ----4��ͷƫ��λ��
             IN SESSION_S        *pstSession  ----���������Ự             
             IN MBUF_S           *pstMBuf     ----����
             IN SESSION_CTRL_S  *pstSessionCtrl      ----MDC
      Output:��
      Return:��
     Caution:Э��״̬������ֱ��������MBuf��
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

    /*��˲���ʱ��Ϊ��֤״̬�Ự������Aging_setClass��ȷ�������*/
    if(!SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_DELETING))
    {
        /*����״̬������*/
        session_kStateProc(pstL4Proto, usIPOffset, uiL4_Offset, pstSession, pstMBuf, pstSessionCtrl);
    }

    /*ˢ�¸��Ự���ϻ�ʱ��*/
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

    /*�������б��*/
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
        /*���ñ��Ĵ����־�ͷ����־*/
        SESSION_MBUF_SET_FLAG(pstMbuf, SESSION_MBUF_PROCESSED | enDir);
    }

    MBUF_SET_APP_ID(pstMbuf, SESSION_KGetAppID(hSession));

    /* ��ȡ4�㳤�� */
    uiIPLen = session_kGetL4Offset(pstMbuf, uiL3Offset, &uiL4OffSet);

    /* �ԷǷ�Ƭ���߷�Ƭ��Ƭ������״̬������ */
    if (!SESSION_IsIPv4LatterFrag(uiL3Offset, pstMbuf))
    {
        /* ����״̬������ */		
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
        /* ���»Ự������ͳ����Ϣ */
        SESSION_KAddTotalState((SESSION_L4_TYPE_E)pstSession->stSessionBase.ucSessionL4Type,
                               1, uiIPLen, pstSessionCtrl);  
    }

    return ;
}

/******************************************************************
   Func Name:session_kIsNeedProc
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�жϱ����Ƿ���Ҫ����
       INPUT:IN USHORT usIPOffset,    ----ƫ��
             IN MBUF_S *pstMBuf       ----����
             IN SESSION_S *pstSession ----�Ựָ��
      Output:��
      Return:BOOL_FALSE               ----����ת��
             BOOL_TRUE                ----��Ҫ��������
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
 Description:����Ƿ�ﵽ����������
       INPUT:IN SESSION_CTRL_S *pstSessionCtrl
      Output:��
      Return:BOOL_TRUE             ----�ﵽ��ֵ
             BOOL_FALSE            ----δ�ﵽ��ֵ
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
 Description:����Ƿ�ﵽ���������½���������
       INPUT:IN SESSION_CTRL_S *pstSessionCtrl
      Output:��
      Return:PKT_CONTINUE             ----����ת��
             PKT_DROPPED              ----ɾ��mbuf������
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
STATIC ULONG SESSION_KCapabitityTest(IN SESSION_CTRL_S *pstSessionCtrl, IN const MBUF_S *pstMBuf)
{
    ULONG ulErrCode = ERROR_FAILED;

    /* ���Ự�Ƿ�ﵽ���ֵ��δ�ﵽ�����������򴴽��Ự */
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
 Description:ɾ�����ӻỰ�ڴ�����ʱ�����е�non-persist������
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

    /* ��ȡ�����������key */
    pstcskey = GET_CSP_KEY((conn_sub_t *)pstSession->stSessionBase.pCache[SESSION_DIR_ORIGINAL]);

    //rte_spinlock_lock(&pstSession->stLock);
    /* �������Ự�Ĺ������� */
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
 Description:���½�����ʱ�Ự����Ự���У�����Ự���Ѿ�������������ʧ��.
             �����ӳɹ���֪ͨע��ģ��Ự�����¼�.
       INPUT:IN MBUF_S *pstMBuf            ----����       
             IN SESSION_CTRL_S *pstSessionCtrl    ----MDC
             IN USHORT usIPOffset          ----L3ƫ��
             INOUT SESSION_S *pstSession   ----�Ự
      Output:pstSession ---- ����ɹ�,�Ự������hash���У������뵽�ϻ�������
      Return:��
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

    /* ���Ӽ��� */
    SESSION_KAddStat(pstSessionCtrl, enSessType, pstSession->uiOriginalAppID);

	
    if(SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_DEL_NON_PERSIST_RELATION))
    {
        session_kDeleteNonPersistRelation(pstSession);
    }

    /* ���ͻỰ������־ */
    if(BOOL_TRUE == pstSessionCtrl->stSessionLogInfo.bLogSwitchEnable)
    {
        SESSION_KLOG_PROC_Create(pstMBuf, usIPOffset, pstSession, pstSessionCtrl);
    }

    /* ���ͻỰ�����¼� */
    SESSION_KNotify_TableCreate((SESSION_HANDLE)pstSession);

    /* �Ự�����ϻ����� */
    SESSION_KAging_Add(&(g_stSessionstAgingQueue), pstSession);

    return;
}

/******************************************************************
   Func Name:SESSION_KDeleteSession
Date Created:2021/04/25
      Author:wangxiaohua
 Description:ɾ���Ự,�Ự���SESSION_DELETING
       INPUT:IN SESSION_HANDLE hSession   ----�Ự���
      Output:��
      Return:��
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
 Description:ת�������л��ڻỰ������������
       INPUT:IN MBUF_S *pstMBuf         ----����
             IN USHORT usIPOffset       ----L3ƫ��
             IN SESSION_S *pstSession   ----�Ự
             IN SESSION_CTRL_S *pstSessionCtrl ----MDC
      Output:��
      Return:PKT_CONTINUE             ----����ת��
             PKT_DROPPED              ----ɾ��mbuf������
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

    /* �Ự�װ����Ự������1������ʱ�Ự����hash���У��Լ��ϻ������� */
    session_kFirstPktEnd(pstMBuf, pstSessionCtrl, usIPOffset, pstSession);
    /* �ỰALG���� */
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
 Description:ɾ��temp�Ự
       INPUT:IN SESSION_S *pstSession ----��ʱ�Ựָ��
             IN USHORT usIPOffset     ----L3ƫ��
             IN BOOL_T bNeedSendIcmp  ----�Ƿ���Ҫ���Ͳ����(NAT) 
             INOUT MBUF_S *pstMBuf    ----����
      Output:pstMBuf                  ----���Ŀ��ܱ��޸�
      Return:PKT_CONTINUE             ----����Χ�����߼�������
             PKT_DROPPED              ----�����Ѿ�������
     Caution:MBUF���ܻᱻ�޸�.
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

    /* ��ǰnat����SESSION_TEMP�ж��Ƿ��nat�Ựͳ�Ƽ���������ǰ�������temp��ǣ������ټ��� */
    SESSION_TABLE_SET_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP);

    /* ֪ͨɾ�� */
    /*local_bh_disable();*/
    SESSION_KNotify_TableDelete((SESSION_HANDLE)pstSession);
    /*local_bh_enable();*/

    /* ���MBUF�еĻỰָ���flagλ*/
    MBUF_CLEAR_CACHE(pstMBuf, MBUF_CACHE_SESSION);
    MBUF_SET_SESSION_FLAG(pstMBuf, 0);

    /* ���°汾cache�ɻỰ�ͷ�: old--�ͷŵ�ʱ�������Ҫ�ͷŻỰ��Cache�Ѿ��ͷ��� */
    SESSION_KPut(pstSession);

    return ulPktRet;
}
#endif

/******************************************************************
   Func Name:session_kAfterEnd
Date Created:2021/04/25
      Author:wangxiaohua
 Description:ת�������л��ڻỰ�����������㣬
             ��IPv4/IPv6�����е�session end����������
             ��������ỰΪ��ʱ�Ự�������Ự���С��������б��ģ�������ALG����
       INPUT:IN MBUF_S *pstMBuf       ----����
             IN USHORT usIPOffset     ----L3ƫ��
             IN SESSION_S *pstSession ----�Ựָ��
      Output:��
      Return:PKT_CONTINUE             ----����ת��
             PKT_DROPPED              ----ɾ��mbuf������
     Caution:MBUF���ܻᱻ�޸�.
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
        /* �ỰALG���� */
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
 Description:IPv4ת��������Session Endҵ���Ĵ�����
       INPUT:IN VOID *pCache          ----Cache
             INOUT MBUF_S *pstMBuf    ----����             
      Output:pstMBuf                  ----���Ŀ��ܱ��޸�
      Return:PKT_CONTINUE             ----����ת��
             PKT_DROPPED              ----ɾ��mbuf������
     Caution:MBUF���ܻᱻ�޸�.
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
	
    /* �ӱ��Ļ�ȡ�ỰpstSession */
    pstSession = GET_FWSESSION_FROM_LBUF(pstMBuf);
	
    pstSessionCtrl = SESSION_CtrlData_Get();

    if(NULL == pstSession)
    {
		/* ����Ự���Դ����ǽ����˱���򲻴�����ת�� */
	    /* �˴���Ҫ��flow��ͨ��flowĿǰ�߼��� �Ự����װ��ת��flow�϶����Լ���װ�ˣ� ���˴���ϣ��flow��װ */
       MBUF_SET_SESSION_FLAG(pstMBuf, 0);
       SESSION_KStatFailInc(SESSION_STAT_FAIL_TRY_FAIL_UNICAST, pstSessionCtrl);
       return PKT_CONTINUE;
    }

    /* ���ֱ��Ĳ�����:1.ICMP��� 2.������Ƭ����Ƭ���� */
    if (BOOL_TRUE != session_kIsNeedProc(usIPOffset, pstMBuf, pstSession))
    {
        SESSION_DBG_PACKETS_EVENT_SWITCH(pstMBuf, usIPOffset, DBG_ABNORM_PKT_ICMPERR_OR_LATTERFRAG);
        if (!SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP))
        {
            /* ��ʽ�Ự�����ͷŻỰ��Ϣ */
            MBUF_SET_SESSION_FLAG(pstMBuf, 0);
        }
                
        return PKT_CONTINUE;
    }

    /* SESSION��ʽ�� �϶�����ͨ�Ự */
    if(SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP))
    {
        ulPktRet = SESSION_KCapabitityTest(pstSessionCtrl, pstMBuf);
        if (PKT_DROPPED == ulPktRet)
        {
            SESSION_KStatFailInc(SESSION_STAT_FAIL_CAPABITITY_UNICAST, pstSessionCtrl);
            return PKT_DROPPED;
        }

        /* �������ü��� */
        rte_atomic32_set(&pstSession->stSessionBase.stRefCount.stCount, 1);

        /* �����ʱ�Ự��־λ */
        SESSION_TABLE_CLEAR_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP);

		fcp = GET_FC_FROM_LBUF(pstMBuf);
		flow_install_conn_no_refresh(fcp);
		ulPktRet = session_kFirstEnd(pstMBuf, usIPOffset, pstSession, pstSessionCtrl);
    }
    else
    {
        ulPktRet = session_kAfterEnd(pstMBuf, usIPOffset, pstSession); 
    }

    /*��ʽ���Ự���mbuf�ĻỰָ��*/
    if ((PKT_CONTINUE == ulPktRet) &&
        !SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP))
    {
        /* ���MBUF�еĻỰָ���flagλ */
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
 Description:��ת����״̬������
       INPUT:IN SESSION_S *pstSession,                ----�Ự
             IN SESSION_CTRL_S *pstSessionCtrl               ----MDC
             IN const IP_S *pstIP                     ----IPv4����ͷ
             IN FSBUF_PKTINFO_S *pstPktInfo           ----������Ϣ
             IN const FSBUF_BLOCKINFO_S *pstBlockInfo ----���ݿ���Ϣ
             IN UINT uiL3Offset                       ----����ƫ��
      Output:��
      Return:��
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
    else /* RAWIP �� UDP */
    {
        /* UDP��ԭʼ������״̬�����б任������ˢ���ϻ�ʱ��*/
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
        /* UDP������� */
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
        /* ���÷Ƿ����ı�ǣ������Ļ������ڻỰ��ֻ����״̬���� */
        SESSION_BAK_SetInvalidFlag(pstMbuf);
        SESSION_KStatFailInc(SESSION_STAT_FAIL_EXT_STATE, pstSessionCtrl);
    }

    ucNewState = pstSession->ucState;
    if (ucOldState != ucNewState)
    {
        /* ���������ϻ��ಢ�����ϻ�ʱ�� */
        SESSION_KAging_SetClassNew(pstSessionCtrl, pstSession);
    }
    else
    {
        /* ˢ���ϻ�ʱ�� */
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
    /* ��˲���ʱ��Ϊ��֤״̬�Ự�������Aging_setClass��ȷ������� */
    if (!SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_DELETING))
    {
        /* ����״̬������ */
        session_kExtStateProc(enDir, pstSession, pstMbuf, pstSessionCtrl, uiL3Offset, uiL4Offset);
    }

    /* ˢ�¸��Ự���ϻ�ʱ�� */
    SESSION_KRefreshParents(pstSession);

    return;
}

#if 0
/******************************************************************
   Func Name:SESSION_KExtStateProcess
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�Ự��ת����
       INPUT:IN SESSION_S *pstSession          ----�Ựָ��
             IN const VOID *pCache             ----��ת��
             IN SESSION_CTRL_S *pstSessionCtrlData    ----mdc���ƿ�
             IN IP_S *pstIP                    ----IPv4����ͷ
             IN FSBUF_PKTINFO_S *pstPktInfo    ----������Ϣ
             IN const FSBUF_BLOCKINFO_S *pstBlockInfo ----���ݿ���Ϣ
             IN UINT uiL3Offset                ----����ƫ��
      Output:��
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

    /* ���±��ķ��� */    
    SESSION_MBUF_SET_FLAG(pstMbuf, enDir);  

    if(!SESSION_IsIPv4LatterFrag(uiL3Offset, pstMbuf))
    {
        /* ����״̬������ */
        session_kExtLayer4State(enDir, pstSession, pstMbuf,pstSessionCtrl, uiL3Offset, uiL4Offset);
    }

    return;
}
#endif

/* ������������ */
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
        /* ����״̬������ */
        session_kExtLayer4State(enDir, pstSession, pstMbuf,pstSessionCtrl, uiL3Offset, uiL4Offset);
	}

    if((0 != pstSession->usAlgFlag) && 
       (!IN_MULTICAST(ntohl((*pstIP).daddr))))
    {
        /* �ỰALG���� ASPF */
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

	/* ASPF��ת */
	if (unlikely(SESSION_MBUF_TEST_FLAG(pstMbuf, SESSION_MBUF_INVALID)))
	{
    	if (SESSION_TABLE_IS_MODULEFLAG_SET(pstSession, SESSION_MODULE_ASPF))
    	{
    		ulRet = SESSION_Proc_Aspf(pstSession, pstMbuf);
    	}
	}

	/* ������־ */
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
    /* �������Ѿ�����FW��ת������ˣ���ת���账����ֱ�ӷ���continue���� */
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
	
    /* ��ȡ4�㳤�� */
    (VOID)session_kGetL4Offset(pstMbuf, uiL3Offset, &uiL4Offset);

	/* ȡ�����������IPͷ */
	pstIP = rte_pktmbuf_mtod_offset(pstRteMbuf, struct iphdr *, uiL3Offset);

    /* ��չ��ʽ�İ�ȫҵ��������� */
    ulRet = SESSION_KExtProc(pstSession, csp, pstIP, pstMbuf, pstSessionCtrl, uiL3Offset, uiL4Offset);
		
    if(unlikely(PKT_CONTINUE != ulRet))
    {
        /* �������� */
        return ulRet;
    }

	uiPreAppID = pstSession->uiAppID;

	/* �Ƿ���Ҫ��Ӧ��ʶ�� */		
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

    /* APPID�����������Ҫ������һ�鰲ȫ���� */ 
	if(uiPreAppID != pstSession->uiAppID)
	{
		ulRet = SESSION_FsSecpolicyMatch(pstSession);
		if(unlikely(PKT_CONTINUE != ulRet))
	    {
	        /* �������� */		
			SESSION_KDeleteSession((SESSION_HANDLE)pstSession);
	        return ulRet;
	    }
	}

    /* ����dpi���� */	
	stIpsPara.uiDirect = pstSession->uiDirect;
	IPS_Check(pstMbuf, &stIpsPara);
    ulRet = stIpsPara.uiAction;
	if(unlikely(PKT_CONTINUE != ulRet))
    {
        /* �������� */
        return ulRet;
    }

    if(unlikely(BOOL_TRUE == pstSessionCtrl->bStatEnable))
    {
        SESSION_FsAddStat(pstSession, pstMbuf, pstSessionCtrl, enPktDir);
    }

    /* ҵ���� */
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

	/* �Ự���� */
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
		/* �ỰALG���� ASPF */
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
	


	/*���㴦����������������תΪ�����򣬸���ҵ����ipͷ����Ϊ��������*/
	pstIP->usLen = ntohs(pstIP->usLen);
	pstIP->usOff = ntohs(pstIP->usOff);

	/* ��ǰֻ����ͨ��TCP/UDP/RAWIP������������ */
	if (likely((SESSION_TYPE_NORMAL == pstSession->stSessionBase.ucSessionType)
			   && (APP_ID_DNS != pstSession->uiAppID)
			   && (BOOL_TRUE != SESSION_IsIPv4LatterFrag(0, pstMBuf))))
	{
		/* ��������Ͱ��շ���������֣������������Э��Ĵ����ܹ����� */
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
		/* ��չ��ʽ�İ�ȫҵ��������� */
		ulRet = SESSION_KL2ExtProc(pstSession,pCache,&pstIP,pstMBuf,pstSessionCtrl,ucLinkLen);
		if (unlikely (PKT_CONTINUE != ulRet))
		{
			/* �������� */
			return ulRet;
		}
	}

	/* �û�̬dpi���ͱ��ĸ����� */
	UDPI_KCAP_Ipv4FsCapturePacket(enPktDir,ucLinkLen,pstMBuf);

	/* add dim fs proc*/
	if (unlikely(SESSION_TABLE_IS_MODULEFLAG_SET(pstSession, SESSION_MODULE_DIM) &&
				 SESSION_TABLE_IS_ATTACHFLAG_SET(pstSession, SESSION_MODULE_DIM)))
	{
		ulRet = DIM_KPKT_IPv4FastProc((SESSION_HANDLE)pstSession,enPktDir,ucLinkLen,
										&pstIP, pstMBuf);

		if (unlikely(PKT_CONTINUE != ulRet))
		{
			/* �������� */
			return ulRet;
		}
	}

	/*���ӻỰͳ����Ϣ*/
	if (unlikely(BOOL_TRUE == pstSessionCtrl->bStatEnable))
	{
		SESSION_FsAddStat(pstSession, pstMBuf, pstSessionCtrl, enPktDir, IPFS_GET_CACHE_MCTYPE(pCache));
	}

	/*ҵ����*/
	ulRet = SESSION_FsModuleProc(pstSession,pstSessionCtrl,pCache,pstMBuf);

	/*ת��������*/
	pstIP->usLen = htons(pstIP->usLen);
	pstIP->usOff = htons(pstIP->usOff);

	SESSION_IGNORE_CONST(pCache);

	return ulRet;
}
#endif

/* ���ݱ������Tuple��Ϣ */
ULONG SESSION_KGetTupleFromMbuf(IN MBUF_S *pstMBuf, IN UINT uiL3OffSet, INOUT SESSION_TUPLE_S *pstTuple)
{
    UINT uiL4OffSet;
    UCHAR ucL4Proto;
    UINT uiIPLen;
    SESSION_L3_PROTO_S *pstL3Proto;
    SESSION_L4_PROTO_S *pstL4Proto;
    ULONG ulRet;

    /* ��ȡ3�㡢4��Э�鴦��ģ�� */
    ulRet = session_kGetModule(pstMBuf, uiL3OffSet, &uiL4OffSet, &ucL4Proto, &uiIPLen, &pstL3Proto, &pstL4Proto);
    if(ERROR_SUCCESS != ulRet)
    {
        return ERROR_FAILED;
    }

    /* ��֤����Ҫ��ȡ��8�ֽڵĶ˿���Ϣ������ */
    ulRet = MBUF_PULLUP(pstMBuf, uiL4OffSet + 8);
    if(ERROR_SUCCESS != ulRet)
    {
        return ERROR_FAILED;
    }

    /* ��ȡ���ĵ�Tuple��Ϣ */
    session_kGetTuple(pstMBuf, uiL3OffSet, uiL4OffSet, ucL4Proto, pstL3Proto, pstL4Proto, pstTuple);

    return ERROR_SUCCESS;
}


