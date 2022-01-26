
#include "socket.h"
#include "session_ktable.h"
#include "session_kdebug.h"
#include "session_krelationhash.h"
#include "general_rcu.h"


/* �Ự�й�ģ����չ��Ϣ��Ϊ��̬���䣬���η���2��4��6��12��ָ�볤�� */
#define SESSION_ALLOC_SERVICE_NUM_2    2    /* ��һ�η���ָ�����Ϊ2 */
#define SESSION_ALLOC_SERVICE_NUM_4    4    /* �ڶ��η���ָ�����Ϊ4 */
#define SESSION_ALLOC_SERVICE_NUM_6    6    /* �����η���ָ�����Ϊ6 */
#define SESSION_ALLOC_SERVICE_NUM_12   12   /* ���Ĵη���ָ�����Ϊ12 */

/* ��¼��Э��ע����չ������Ϣ */
SESSION_EXT_REGINFO_S g_stSessionExtRegInfo;

UINT g_auiSessTotalLen[SESSION_TYPE_MAX];
rte_atomic32_t g_stSessionCount;

AGINGQUEUE_CHANGEABLE_S    g_stSessChangeableQueue;

#define SESSION_HASH_LEN2 (64 * 1024 * 1024UL)

/* �Ự�� */
struct rte_mempool *g_apstSessPool[SESSION_TYPE_MAX];


/* ҵ��ģ���Ƿ���Ự��������ALG������ */
BOOL_T SESSION_KIsAlgFlagSet(IN SESSION_HANDLE hSession, IN SESSION_MODULE_E enModule)
{
    return SESSION_TABLE_IS_ALGFLAG_SET((SESSION_S *)hSession, enModule);
}

/******************************************************************
   Func Name:SESSION_KFreeResetObject
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�ͷ�reset session�ڵ��ڴ�
       INPUT:IN AGINGQUEUE_RST_MSG_OBJECT_S *pstObject
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION_KFreeResetObject(IN AGINGQUEUE_RST_MSG_OBJECT_S *pstObject)
{
    SESSION_RESET_OBJ_S *pstSessionRstObj;

    pstSessionRstObj = container_of(pstObject, SESSION_RESET_OBJ_S, stRstObj);
    rte_free(pstSessionRstObj);
    return;
}

/******************************************************************
   Func Name:SESSION_KMallocResetObject
Date Created:2021/04/25
      Author:wangxiaohua
 Description:����reset session�ڵ��ڴ�
       INPUT:IN AGINGQUEUE_RST_MSG_OBJECT_S *pstObject
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
AGINGQUEUE_RST_MSG_OBJECT_S * SESSION_KMallocResetObject(IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstObject)
{
    SESSION_RESET_OBJ_S *pstSessionRstObj;
    SESSION_RESET_OBJ_S *pstSessionRstObjTmp;
    AGINGQUEUE_RST_MSG_OBJECT_S *pstObjectTmp;

    pstSessionRstObj = container_of(pstObject, SESSION_RESET_OBJ_S, stRstObj);
    pstSessionRstObjTmp = rte_zmalloc(NULL, sizeof(SESSION_RESET_OBJ_S), 0);
    if(NULL != pstSessionRstObjTmp)
    {
        *pstSessionRstObjTmp = *pstSessionRstObj;

        pstObjectTmp = &(pstSessionRstObjTmp->stRstObj);
        SL_NodeInit(&(pstObjectTmp->stNode));
    }
    return (AGINGQUEUE_RST_MSG_OBJECT_S *)pstSessionRstObjTmp;
}

/******************************************************************
   Func Name:IN6ADDR_Cmp
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�Ƚ�IPv6��ַ��С
       INPUT:pstAddr1:���Ƚϵ�ַ1
             pstAddr2:���Ƚϵ�ַ2
      Output:��
      Return:����0:��ַ1���ڵ�ַ2
             С��0:��ַ1С�ڵ�ַ2
             ����0:��ַ1���ڵ�ַ2
     Caution:IPV6��ַ������������
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline INT IN6ADDR_Cmp(IN const struct in6_addr *pstAddr1, IN const struct in6_addr *pstAddr2)
{
    UINT i;
    INT iRet;

    for(i=0; i < INET_ADDRSTRLEN; i++)
    {
        iRet = pstAddr1->s6_addr[i] - pstAddr2->s6_addr[i];
        if(0 != iRet)
        {
            break;
        }
    }

    return iRet;
}

/******************************************************************
   Func Name:_session_KIsSameSessionTuple
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�жϻỰ��Ԫ���Ƿ���ͬ
       INPUT:IN const SESSION_TUPLE_S *pstTupel1,
             IN const SESSION_TUPLE_S *pstTupel2
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline BOOL_T _session_KIsSameSessionTuple(IN const SESSION_TUPLE_S *pstTupel1,
                                                  IN const SESSION_TUPLE_S *pstTupel2)
{
    BOOL_T bRet = BOOL_FALSE;

    if((pstTupel1->ucL3Family == pstTupel2->ucL3Family)&&
       (pstTupel1->ucProtocol == pstTupel2->ucProtocol)&&
       (pstTupel1->ucType == pstTupel2->ucType)&&
       (pstTupel1->uiTunnelID == pstTupel2->uiTunnelID)&&
       (pstTupel1->vrfIndex == pstTupel2->vrfIndex)&&
       (pstTupel1->unL4Src.usAll == pstTupel2->unL4Src.usAll)&&
       (pstTupel1->unL4Dst.usAll == pstTupel2->unL4Dst.usAll))
    {
        if(AF_INET == pstTupel1->ucL3Family)
        {
            if((pstTupel1->unL3Src.uiIp == pstTupel2->unL3Src.uiIp) &&
               (pstTupel1->unL3Dst.uiIp == pstTupel2->unL3Dst.uiIp))
            {
                bRet = BOOL_TRUE;
            }
        }
        else if (AF_INET6 == pstTupel1->ucL3Family)
        {
            if((0 == IN6ADDR_Cmp(&pstTupel1->unL3Src.stin6, &pstTupel2->unL3Src.stin6)) &&
               (0 == IN6ADDR_Cmp(&pstTupel1->unL3Dst.stin6, &pstTupel2->unL3Dst.stin6)))
            {
                bRet = BOOL_TRUE;
            }
        }
        else if (AF_MAX == pstTupel1->ucL3Family)
        {
            bRet = BOOL_TRUE;
        }
    }
    return bRet;
}

/******************************************************************
   Func Name:_session_KIsSameSessionKey
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�ж�reset session �ؼ����Ƿ���ͬ
       INPUT:IN const SESSION_TABLE_KEY_S *pstKey1,
             IN const SESSION_TABLE_KEY_S *pstKey2
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline BOOL_T _session_KIsSameSessionKey(IN const SESSION_TABLE_KEY_S *pstKey1,
                                                 IN const SESSION_TABLE_KEY_S *pstKey2)
{
    BOOL_T bRet = BOOL_FALSE;

    if(((pstKey1->uiMask & ~SESSION_TABLE_BIT_STOP) == (pstKey2->uiMask & ~SESSION_TABLE_BIT_STOP))&&
       (pstKey1->uiModuleFlag == pstKey2->uiModuleFlag)&&
       (pstKey1->ucSessType == pstKey2->ucSessType))
    {
        bRet = _session_KIsSameSessionTuple(&pstKey1->stTuple, &pstKey2->stTuple);
    }

    return bRet;
}

/******************************************************************
   Func Name:SESSION_KIsSameResetMsg
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�ж�reset session�����Ƿ���ͬ
       INPUT:IN AGINGQUEUE_RST_MSG_OBJECT_S *pstObject
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
BOOL_T SESSION_KIsSameResetMsg(IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstObject1,
                               IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstObject2)
{
    SESSION_RESET_OBJ_S *pstSessionRstObj1;
    SESSION_RESET_OBJ_S *pstSessionRstObj2;
    BOOL_T bRet = BOOL_FALSE;

    pstSessionRstObj1 = container_of(pstObject1, SESSION_RESET_OBJ_S, stRstObj);    
    pstSessionRstObj2 = container_of(pstObject2, SESSION_RESET_OBJ_S, stRstObj);

    if(BOOL_TRUE == _session_KIsSameSessionKey(&pstSessionRstObj1->stKey, &pstSessionRstObj2->stKey))
    {
        bRet = BOOL_TRUE;
    }

    return bRet;
}

static inline BOOL_T SESSION_KIsTmpSession(IN SESSION_HANDLE hSession)
{
    SESSION_S *pstSession = (SESSION_S *)hSession;

    return SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP);
}

/******************************************************************
   Func Name:SESSION_KIsIPv6
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�жϻỰ�Ƿ���IPv6�Ự
       INPUT:SESSION_HANDEL hSession, �Ự
      Output:��
      Return:BOOL_TRUE, ��IPv6�Ự
             BOOL_FALSE,����IPv6�Ự
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline BOOL_T SESSION_KIsIPv6(IN SESSION_HANDLE hSession)
{
    SESSION_S *pstSession = (SESSION_S *)hSession;

    return SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_IPV6);
}

/******************************************************************
   Func Name:_session_KTable_ResetCheckIFVRF
Date Created:2021/04/25
      Author:wangxiaohua
 Description:reset�Ự�Ľӿ�VRF���
       INPUT:IN const SESSION_TABLE_KEY_S *pstKey,      �Ự����ϢKey
             IN const csp_key_t *pstcspkey,             ��ת����Ϣkey
             IN UINT uiMask,                            ���
      Output:��
      Return:BOOL_TRUE
             BOOL_FALSE
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static BOOL_T _session_KTable_ResetCheckIFVRF(IN const SESSION_TABLE_KEY_S *pstKey,
                                               IN const csp_key_t *pstcspkey,
                                               IN UINT uiMask)
{
    UINT uiToken;

    /* VRF��� */
    if(SESSION_KEY_IS_VPNIDSET(uiMask))
    {
        uiToken = pstcspkey->token;
        if(ntohl(uiToken) != pstKey->stTuple.vrfIndex)
        {
            return BOOL_FALSE;
        }
    }
#if 0
        if(0 == pstKey->stTuple.ucType)
        {
            if(BIT_TEST(pstcspkey->ucType, IPFS_CACHEKEYFLAG_MACFW|
                IPFS_CACHEKEYFLAG_BRIDGE|IPFS_CACHEKEYFLAG_INLINE))
            {
                return BOOL_FALSE;
            }
        }
        else if (0 == ((pstKey->stTuple.ucType) & (pstcspkey->ucType)))
        {
            return BOOL_FALSE;
        }
    }

    /* IFINDEX ��� */
    if(SESSION_KEY_IS_IFINDEX(uiMask))
    {
        if(pstcspkey->ifIndexRcv != pstKey->pstcspkey)
        {
            return BOOL_FALSE;
        }
    }
#endif

    return BOOL_TRUE;
}

/******************************************************************
   Func Name:_session6_KTable_ResetCheckSrcDes
Date Created:2021/04/25
      Author:wangxiaohua
 Description:reset�Ự��ԴĿ��IP�˿ڼ��
       INPUT:IN const SESSION_TABLE_KEY_S *pstKey,      �Ự����ϢKey
             IN const csp_key_t           *pstcspkey,   ��ת����Ϣkey
             IN UINT uiMask,                            ���
      Output:��
      Return:BOOL_TRUE
             BOOL_FALSE
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static BOOL_T _session6_KTable_ResetCheckSrcDes(IN const SESSION_TABLE_KEY_S *pstKey,
                                                IN const csp_key_t *pstcspkey,
                                                IN UINT uiMask)
{
    /* Դ��ַ��� */
    if(SESSION_KEY_IS_SRCIPSET(uiMask))
    {
        if(0 != memcmp(&pstcspkey->src_ip, &pstKey->stTuple.unL3Src.stin6, sizeof(struct in6_addr)))
        {
            return BOOL_FALSE;
        }
    }

    /* Ŀ�ĵ�ַ��� */
    if(SESSION_KEY_IS_DSTIPSET(uiMask))
    {
        if(0 != memcmp(&pstcspkey->dst_ip, &pstKey->stTuple.unL3Dst.stin6, sizeof(struct in6_addr)))
        {
            return BOOL_FALSE;
        }
    }

    /* Դ�˿ڼ�� */
    if(SESSION_KEY_IS_SRCPORTSET(uiMask))
    {
        if(ntohs(pstcspkey->src_port) != pstKey->stTuple.unL4Src.usAll)
        {
            return BOOL_FALSE;
        }
    }

    /* Ŀ�Ķ˿ڼ�� */
    if(SESSION_KEY_IS_DSTPORTSET(uiMask))
    {
        if(ntohs(pstcspkey->dst_port) != pstKey->stTuple.unL4Dst.usAll)
        {
            return BOOL_FALSE;
        }
    }

    return BOOL_TRUE;
}

/******************************************************************
   Func Name:_session6_KTable_ResetCheckAppStatePro
Date Created:2021/04/25
      Author:wangxiaohua
 Description:reset�Ự��Ӧ��Э��״̬���
       INPUT:IN const SESSION_S *pstSession             �Ự
             IN const SESSION_TABLE_KEY_S *pstKey,      �Ự����ϢKey
             IN UINT uiMask,                            ���
      Output:��
      Return:BOOL_TRUE
             BOOL_FALSE
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static BOOL_T _session6_KTable_ResetCheckAppStatePro(IN const SESSION_S *pstSession,
                                                     IN const SESSION_TABLE_KEY_S *pstKey,
                                                     IN UINT uiMask)
{
    /* APP ��� */
    if(SESSION_KEY_IS_APPSET(uiMask))
    {
        if(pstKey->uiAppID != pstSession->uiAppID)
        {
            return BOOL_FALSE;
        }
    }

    /* 4��Э���� */
    if(SESSION_KEY_IS_PROTSET(uiMask))
    {
        if(pstSession->stSessionBase.ucSessionL4Type != pstKey->ucSessType)
        {
            return BOOL_FALSE;
        }
    }

    /* ״̬��� */
    if(SESSION_KEY_IS_STATESET(uiMask))
    {
        if((pstKey->ucSessType != pstSession->stSessionBase.ucSessionL4Type) ||
           (pstKey->ucState != pstSession->ucState)) 
        {
            return BOOL_FALSE;
        }
    }

    return BOOL_TRUE;
}

/******************************************************************
   Func Name:_session6_KTable_ResetCheckZoneTimeID
Date Created:2021/04/25
      Author:wangxiaohua
 Description:reset�Ự����ʱ��ΰ�ȫ���Լ��
       INPUT:IN const SESSION_S *pstSession             �Ự
             IN const SESSION_TABLE_KEY_S *pstKey,      �Ự����ϢKey
             IN UINT uiMask,                            ���
      Output:��
      Return:BOOL_TRUE
             BOOL_FALSE
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static BOOL_T _session6_KTable_ResetCheckZoneTimeID(IN const SESSION_S *pstSession,
                                                     IN const SESSION_TABLE_KEY_S *pstKey,
                                                     IN UINT uiMask)
{
#if 0
    /* ����� */
    if(SESSION_KEY_IS_ZONESET(uiMask))
    {
        if(pstKey->zoneIDSrcID != pstSession->zoneIDSrcID)
        {
            return BOOL_FALSE;
        }
    }

    if(SESSION_KEY_IS_DSTZONESET(uiMask))
    {
        if(pstKey->zoneIDDestID != pstSession->zoneIDDestID)
        {
            return BOOL_FALSE;
        }
    }
#endif

    /* ʱ��μ�� */
    if(SESSION_KEY_IS_TIMERANGESET(uiMask))
    {
        if(pstKey->uiStartTime > (UINT)pstSession->stSessionBase.uiSessCreateTime ||
           pstKey->uiEndTime < (UINT)pstSession->stSessionBase.uiSessCreateTime)
        {
            return BOOL_FALSE;
        }
    }

#if 0
    /* ��ȫ���Լ�� */
    if(SESSION_KEY_IS_SECPNAME(uiMask))
    {
        if((pstKey->uiPolicyID != pstSession->uiPolicyID) ||
           (pstKey->uiRuleID != pstSession->uiRuleID)) 
        {
            return BOOL_FALSE;
        }
    }
#endif

    return BOOL_TRUE;
}


STATIC BOOL_T _session6_KTable_ResetCmp(IN SESSION_S *pstSession,
                                        IN const SESSION_TABLE_KEY_S *pstKey)
{
    UINT uiMask = pstKey->uiMask;
    csp_key_t *pstcspkey;
    BOOL_T bflag;

    /* ģ��ID��� */
    if(SESSION_KEY_IS_MODULESET(uiMask))
    {
        if(!SESSION_TABLE_IS_MODULEFLAG_SET(pstSession, pstKey->uiModuleFlag))
        {
            return BOOL_FALSE;
        }
    }
    if(SESSION_KEY_IS_RESPONDER(uiMask))
    {
        pstcspkey = SESSION_KGetIPfsKey((SESSION_HANDLE)pstSession, SESSION_DIR_REPLY);
    }
    else
    {
        pstcspkey = SESSION_KGetIPfsKey((SESSION_HANDLE)pstSession, SESSION_DIR_ORIGINAL);
    }

    /* �����ǵ��� */
    if(IN6ADDR_IsMulticast((struct in6_addr *)&pstcspkey->dst_ip))
    {
        return BOOL_FALSE;
    }

    bflag = _session6_KTable_ResetCheckSrcDes(pstKey, pstcspkey, uiMask);
    if(BOOL_FALSE == bflag)
    {
        return BOOL_FALSE;
    }

    bflag = _session_KTable_ResetCheckIFVRF(pstKey, pstcspkey, uiMask);
    if(BOOL_FALSE == bflag)
    {
        return BOOL_FALSE;
    }

    bflag = _session6_KTable_ResetCheckAppStatePro(pstSession, pstKey, uiMask);
    if(BOOL_FALSE == bflag)
    {
        return BOOL_FALSE;
    }

    bflag = _session6_KTable_ResetCheckZoneTimeID(pstSession, pstKey, uiMask);
    if(BOOL_FALSE == bflag)
    {
        return BOOL_FALSE;
    }

    return BOOL_TRUE;
}


/******************************************************************
   Func Name:_session_KTable_ResetCheckSrcDes
Date Created:2021/04/25
      Author:wangxiaohua
 Description:reset�Ự��ԴĿ��IP�˿ڼ��
       INPUT:IN const SESSION_TABLE_KEY_S *pstKey,      �Ự����ϢKey
             IN const csp_key_t *pstcspkey,             ��ת����Ϣkey
             IN UINT uiMask,                            ���
      Output:��
      Return:BOOL_TRUE
             BOOL_FALSE
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static BOOL_T _session_KTable_ResetCheckSrcDes(IN const SESSION_TABLE_KEY_S *pstKey,
                                               IN const csp_key_t *pstcspkey,
                                               IN UINT uiMask)
{
    /* Դ��ַ��� */
    if(SESSION_KEY_IS_SRCIPSET(uiMask))
    {
        if(pstcspkey->src_ip != pstKey->stTuple.unL3Src.uiIp)
        {
            return BOOL_FALSE;
        }
    }

    /* Ŀ�ĵ�ַ��� */
    if(SESSION_KEY_IS_DSTIPSET(uiMask))
    {
        if(pstcspkey->dst_ip != pstKey->stTuple.unL3Dst.uiIp)
        {
            return BOOL_FALSE;
        }
    }

    /* Դ�˿ڼ�� */
    if(SESSION_KEY_IS_SRCPORTSET(uiMask))
    {
        if(ntohs(pstcspkey->src_port) != pstKey->stTuple.unL4Src.usAll)
        {
            return BOOL_FALSE;
        }
    }

    /* Ŀ�Ķ˿ڼ�� */
    if(SESSION_KEY_IS_DSTPORTSET(uiMask))
    {
        if(ntohs(pstcspkey->dst_port) != pstKey->stTuple.unL4Dst.usAll)
        {
            return BOOL_FALSE;
        }
    }

    return BOOL_TRUE;
}

/******************************************************************
   Func Name:_session_KTable_ResetCheckAppStatePro
Date Created:2021/04/25
      Author:wangxiaohua
 Description:reset�Ự��Ӧ��Э��״̬���
       INPUT:IN const SESSION_S *pstSession             �Ự
             IN const SESSION_TABLE_KEY_S *pstKey,      �Ự����ϢKey
             IN UINT uiMask,                            ���
      Output:��
      Return:BOOL_TRUE
             BOOL_FALSE
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static BOOL_T _session_KTable_ResetCheckAppStatePro(IN const SESSION_S *pstSession,
                                                    IN const SESSION_TABLE_KEY_S *pstKey,
                                                    IN UINT uiMask)
{
    /* APP ��� */
    if(SESSION_KEY_IS_APPSET(uiMask))
    {
        if(pstKey->uiAppID != pstSession->uiAppID)
        {
            return BOOL_FALSE;
        }
    }

    /* 4��Э���� */
    if(SESSION_KEY_IS_PROTSET(uiMask))
    {
        if(pstSession->stSessionBase.ucSessionL4Type != pstKey->ucSessType)
        {
            return BOOL_FALSE;
        }
    }

    /* ״̬��� */
    if(SESSION_KEY_IS_STATESET(uiMask))
    {
        if((pstKey->ucSessType != pstSession->stSessionBase.ucSessionL4Type) ||
           (pstKey->ucState != pstSession->ucState)) 
        {
            return BOOL_FALSE;
        }
    }

    return BOOL_TRUE;
}

/******************************************************************
   Func Name:_session_KTable_ResetCheckZoneTimeID
Date Created:2021/04/25
      Author:wangxiaohua
 Description:reset�Ự����ʱ��ΰ�ȫ���Լ��
       INPUT:IN const SESSION_S *pstSession             �Ự
             IN const SESSION_TABLE_KEY_S *pstKey,      �Ự����ϢKey
             IN UINT uiMask,                            ���
      Output:��
      Return:BOOL_TRUE
             BOOL_FALSE
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static BOOL_T _session_KTable_ResetCheckZoneTimeID(IN const SESSION_S *pstSession,
                                                   IN const SESSION_TABLE_KEY_S *pstKey,
                                                   IN UINT uiMask)
{
#if 0
    /* ����� */
    if(SESSION_KEY_IS_ZONESET(uiMask))
    {
        if(pstKey->zoneIDSrcID != pstSession->zoneIDSrcID)
        {
            return BOOL_FALSE;
        }
    }

    if(SESSION_KEY_IS_DSTZONESET(uiMask))
    {
        if(pstKey->zoneIDDestID != pstSession->zoneIDDestID)
        {
            return BOOL_FALSE;
        }
    }
#endif
    /* ʱ��μ�� */
    if(SESSION_KEY_IS_TIMERANGESET(uiMask))
    {
        if(pstKey->uiStartTime > (UINT)pstSession->stSessionBase.uiSessCreateTime
          || pstKey->uiEndTime < (UINT)pstSession->stSessionBase.uiSessCreateTime)
        {
            return BOOL_FALSE;
        }
    }
#if 0
    /* ��ȫ���Լ�� */
    if(SESSION_KEY_IS_SECPNAME(uiMask))
    {
        if((pstKey->uiPolicyID != pstSession->uiPolicyID) ||
           (pstKey->uiRuleID != pstSession->uiRuleID)) 
        {
            return BOOL_FALSE;
        }
    }
#endif

    return BOOL_TRUE;
}


STATIC BOOL_T _session_KTable_ResetCmp(IN SESSION_S *pstSession,
                                       IN const SESSION_TABLE_KEY_S *pstKey)
{
    UINT uiMask = pstKey->uiMask;
	csp_key_t *pstcspkey;
    BOOL_T bflag;

    /* ģ��ID��� */
    if(SESSION_KEY_IS_MODULESET(uiMask))
    {
        if(!SESSION_TABLE_IS_MODULEFLAG_SET(pstSession, pstKey->uiModuleFlag))
        {
            return BOOL_FALSE;
        }
    }

    if(SESSION_KEY_IS_RESPONDER(uiMask))
    {
        pstcspkey = SESSION_KGetIPfsKey((SESSION_HANDLE)pstSession, SESSION_DIR_REPLY);
    }
    else
    {
        pstcspkey = SESSION_KGetIPfsKey((SESSION_HANDLE)pstSession, SESSION_DIR_ORIGINAL);
    }

    /* �����ǵ��� */
    if(IN_MULTICAST(ntohl(pstcspkey->dst_ip)))
    {
        return BOOL_FALSE;
    }

    bflag = _session_KTable_ResetCheckSrcDes(pstKey, pstcspkey, uiMask);
    if(BOOL_FALSE == bflag)
    {
        return BOOL_FALSE;
    }
    
    bflag = _session_KTable_ResetCheckIFVRF(pstKey, pstcspkey, uiMask);
    if(BOOL_FALSE == bflag)
    {
        return BOOL_FALSE;
    }

    bflag = _session_KTable_ResetCheckAppStatePro(pstSession, pstKey, uiMask);
    if(BOOL_FALSE == bflag)
    {
        return BOOL_FALSE;
    }

    bflag = _session_KTable_ResetCheckZoneTimeID(pstSession, pstKey, uiMask);
    if(BOOL_FALSE == bflag)
    {
        return BOOL_FALSE;
    }

    return BOOL_TRUE;
}

/******************************************************************
   Func Name:_session_KNeedResetProc
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�жϻỰ�Ƿ��reset
       INPUT:IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstResetObj,
             IN const AGINGQUEUE_UNSTABLE_OBJECT_S *pstAgingObject
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
BOOL_T _session_KNeedResetProc(IN const AGINGQUEUE_RST_MSG_OBJECT_S *pstResetObj,
                               IN const AGINGQUEUE_UNSTABLE_OBJECT_S *pstAgingObject)
{
    SESSION_TABLE_KEY_S *pstKey;
    SESSION_S *pstSession;
    SESSION_RESET_OBJ_S *pstSessionRstObj;
    BOOL_T bRet = BOOL_FALSE;

    pstSessionRstObj = container_of(pstResetObj, SESSION_RESET_OBJ_S, stRstObj);
    pstKey = (SESSION_TABLE_KEY_S *)&pstSessionRstObj->stKey;

    pstSession = container_of(pstAgingObject, SESSION_S, stSessionBase.unAgingRcuInfo.stAgingInfo);

    if(((INT)pstResetObj->uiResetTime - (INT)pstSession->stSessionBase.uiSessCreateTime) <= 1)
    {
        return BOOL_FALSE;
    }

    if((0 == pstKey->uiMask) &&
       (AF_MAX == pstKey->stTuple.ucL3Family))
    {
        /*ͨ�䣬ֱ�ӷ���true*/
        /*����ɾ����־����Ϊ����ɾ��*/
        /*ָ����ipv4��ipv6���������ɾ��*/
        SESSION_TABLE_SET_TABLEFLAG(&pstSession->stSessionBase,
                                    (USHORT)SESSION_DELTYPE_CFG);
        /*ͨ�����������������ɾ�����˴�����deleting���*/        
        SESSION_TABLE_SET_TABLEFLAG(&pstSession->stSessionBase, SESSION_DELETING);
        return BOOL_TRUE;
    }

    if(SESSION_KIsIPv6((SESSION_HANDLE)pstSession))
    {
        if((AF_MAX == pstKey->stTuple.ucL3Family) ||
           (AF_INET6 == pstKey->stTuple.ucL3Family))
        {
            bRet = _session6_KTable_ResetCmp(pstSession, pstKey);
        }
    }
    else
    {        
        if((AF_MAX == pstKey->stTuple.ucL3Family) ||
           (AF_INET == pstKey->stTuple.ucL3Family))
        {
            bRet = _session_KTable_ResetCmp(pstSession, pstKey);
        }
        
    }

    if(BOOL_TRUE == bRet)
    {
        /* ����ɾ����־����Ϊ����ɾ�� */            
        SESSION_TABLE_SET_TABLEFLAG(&pstSession->stSessionBase,
                                    (USHORT)SESSION_DELTYPE_CFG);

        SESSION_KDeleteSession((SESSION_HANDLE)pstSession);
    }
    return bRet;
}

VOID SESSION_KReset(IN const SESSION_TABLE_KEY_S *pstKey)
{
    SESSION_RESET_OBJ_S stSessionRstObj;
    AGINGQUEUE_RST_MSG_OBJECT_S *pstRstObj;
    UINT uiMDCLocalIndex = 0; //MDC_GetCurrentLocalIndex4FFW();

    memset(&stSessionRstObj, 0, sizeof(SESSION_RESET_OBJ_S));
    stSessionRstObj.stKey = *pstKey;

    pstRstObj = &(stSessionRstObj.stRstObj);
    pstRstObj->bNeedAdjCurson = BOOL_TRUE;
    pstRstObj->enRetsetType = AGINGQUE_RESET_TYPE_DEFAULT;
    pstRstObj->uiMDCLocalIndex = uiMDCLocalIndex;
    SL_NodeInit(&(pstRstObj->stNode));
    pstRstObj->pfFree = SESSION_KFreeResetObject;
    pstRstObj->pfMalloc = SESSION_KMallocResetObject;
    pstRstObj->pfIsSameMsg = SESSION_KIsSameResetMsg;
    pstRstObj->pfNeedResetProc = _session_KNeedResetProc;

    AGINGQUEUE_UnStable_AddResetObj(&(g_stSessionstAgingQueue), pstRstObj);
    return;
}

/******************************************************************
   Func Name:SESSION_KModuleExtDestroy
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�ͷ�ҵ��ģ����չ��Ϣ
       INPUT:IN SESSION_S *pstSession
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
STATIC VOID SESSION_KModuleExtDestroy(IN SESSION_S *pstSession)
{
    SESSION_EXT_DESTROY_CB_PF pfExtDestroy;
    VOID *pCb;

    if (0 == pstSession->usAttachFlag)
    {
        return;
    }

    /* ͨ��ҵ��ص��ͷ���չ��Ϣ */
    pCb = SESSION_KGetALGCb((SESSION_HANDLE)pstSession);
    if (pCb != NULL) 
    {
        pfExtDestroy = g_stSessionExtRegInfo.astCustomExtInfo[SESSION_MODULE_ALG].pfExtDestroy;
        pfExtDestroy((SESSION_HANDLE)pstSession, pCb);
    }
    
    return;
}

/******************************************************************
   Func Name:SESSION_KDestroy
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�ͷŻỰ�ڴ棬�ṩ��RCU�Ļص�����
       INPUT:RCU_REG_S *pstRcuHead, RCUͷ
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION_KDestroy(IN VOID *pSession)
{
    UCHAR ucSessionType;
	flow_connection_t *fcp;
	conn_sub_t *csp;
	SESSION_S *pstSession = (SESSION_S *)pSession;

    /* ���ÿ�תʧЧ */
    csp = pstSession->stSessionBase.pCache[SESSION_DIR_ORIGINAL];
	fcp = csp2base(csp);	
	set_fcp_invalid(fcp, FC_CLOSE_OTHER);

    ucSessionType = pstSession->stSessionBase.ucSessionType;
	
    /*�ͷ���չ��Ϣ*/
    SESSION_KModuleExtDestroy(pstSession);
    
    rte_mempool_put(g_apstSessPool[ucSessionType], pstSession);

    return;
}

/******************************************************************
   Func Name:SESSION_KNotify_TableCreate
Date Created:2021/04/25
      Author:wangxiaohua
 Description:���ø�ģ��ע��ĻỰ�����¼��ص�����.
       INPUT:SESSION_HANDLE hSession
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION_KNotify_TableCreate(IN SESSION_HANDLE hSession)
{
    SESSION_MODULE_E enModule;
    SESSION_KCREATE_CB_PF pfSessCreate;
    SESSION_S *pstSession = (SESSION_S *)hSession;

    if(0 == pstSession->usAttachFlag)
    {
        return;
    }

    for (enModule = (SESSION_MODULE_E)0; enModule < SESSION_MODULE_MAX; enModule++)
    {
        /* Ŀǰ��ģ���create��������ȥ��ȡ��չ��Ϣ����˿���ǰ�ж�
           �˻Ự��չ��ʶ��Ϣ���ж��Ƿ���Ҫ����create��������������չ��Ϣ֮��Ĵ���
           ������Ҫͬ���޸�
        */
        if(SESSION_TABLE_IS_ATTACHFLAG_SET((SESSION_S *)hSession, enModule))
        {
            pfSessCreate = g_astModuleRegInfo[enModule].pfSessCreate;
            if(NULL != pfSessCreate)
            {
                pfSessCreate(hSession);
            }
        }
    }
    
    return;
}

/******************************************************************
   Func Name:SESSION_KNotify_TableDelete
Date Created:2021/04/25
      Author:wangxiaohua
 Description:���ø�ģ��ע��ĻỰɾ���¼��ص�����
       INPUT:SESSION_HANDLE hSession, �Ự��
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION_KNotify_TableDelete(IN SESSION_HANDLE hSession)
{
    SESSION_MODULE_E enModule;
    UINT uiModule;
    SESSION_KDELETE_CB_PF pfSessDelete;
    SESSION_S *pstSession = (SESSION_S *)hSession;

    if(0 == pstSession->usAttachFlag)
    {
        return;
    }

    for(uiModule = 0; uiModule < SESSION_MODULE_MAX; uiModule++)
    {
        enModule = (SESSION_MODULE_E)uiModule;
        if (SESSION_TABLE_IS_ATTACHFLAG_SET((SESSION_S *)hSession, enModule))
        {
            pfSessDelete = g_astModuleRegInfo[enModule].pfSessDelete;
            if(NULL != pfSessDelete)
            {
                pfSessDelete(hSession);
            }
        }

        /* �Ự��Ҫ��RCU_CALL֮ǰ����չ��Ϣɾ����debug��Ϣ��ǰ��ӡ����Ϊ��RCU_CALLʱ���޷����ٻỰ��������VD�ˣ�
        ��debug��Ϣ��ʱ��ʵ������չ��Ϣ��û���ͷŵ������ǣ���ΪRCU_CALL֮���ڴ�ܿ�ͻ������ͷŵ� */
        if (SESSION_TABLE_IS_ATTACHFLAG_SET((SESSION_S *)hSession, enModule))
        {
            SESSION_DBG_EXT_EVENT_SWTICH((SESSION_S *)hSession, enModule, EVENT_DEL);
        }
    }

    return;
}


/* �Ự����չ��Ϣע�� */
STATIC VOID SESSION_KRegExtNum(IN USHORT usModule,
                               IN SESSION_EXT_DESTROY_CB_PF pfExtDestroy)
{
    g_stSessionExtRegInfo.astCustomExtInfo[usModule].pfExtDestroy = pfExtDestroy;

    return;
}


/******************************************************************
   Func Name:SESSION_KRegisterModule
Date Created:2021/04/25
      Author:wangxiaohua
 Description:���ڻỰ��ҵ����Ựģ��ע��
             ע������Ự��ģ�����ݵĴ�С���Լ��Ự���¼��Ļص�����.
             �ص�������ָ�������NULL.
       INPUT:enModule   ---- �Ựҵ��ģ��ID. ģ��ID�ɻỰģ��ͳһ�������
             pstRegInfo ---- ģ�����Ϣ�ṹ�������¼��ص��������Լ�ģ�����ݴ�С
      Output:��
      Return:ERROR_SUCCESS ---- ע��ɹ�
             ERROR_FAILED  ---- ����������Ϸ�
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
ULONG SESSION_KRegisterModule(IN SESSION_MODULE_E enModule, IN const SESSION_MODULE_REG_S *pstRegInfo)
{
    ULONG ulErrCode = ERROR_SUCCESS;

    if ((enModule >= SESSION_MODULE_MAX) || (NULL == pstRegInfo))
    {
        return ERROR_FAILED;
    }

    g_astModuleRegInfo [enModule] = *pstRegInfo;

    /* ע��ҵ��ģ�����չ���ݸ��� */
    SESSION_KRegExtNum ((USHORT)enModule, pstRegInfo->pfExtDestroy);

    return ulErrCode;
}

/******************************************************************
   Func Name:SESSION_KPut
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�����ü�����������0ʱ�����Ự�ڴ��ͷ�
       INPUT:IN SESSION_S *pstSession, �Ự
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION_KPut(IN SESSION_S *pstSession)
{
    if(rte_atomic32_dec_and_test(&pstSession->stSessionBase.stRefCount.stCount))
    {
        /* ɾ�����Ự�����ü��� */
        if (NULL != pstSession->pstParent)
        {
            SESSION_KPut(pstSession->pstParent);
        }

        /* �ָ����ͳ����ֵ */
        SESSION_InfoCountDec();

		general_rcu_qsbr_dq_enqueue((void *)pstSession, SESSION_KDestroy);
    }
    return;
}

STATIC inline VOID _session4_KMbufDestroy(IN SESSION_S *pstSession)
{
    /* �������ʱ�Ự��������֪ͨɾ�� */
    SESSION_KNotify_TableDelete((SESSION_HANDLE) pstSession);

    SESSION_DBG_SESSION_EVENT_SWITCH(pstSession, EVENT_DELETE);

    /* ɾ�����Ự�����ü��� */
    if(NULL!= pstSession->pstParent)
    {
        SESSION_KPut((SESSION_S *)(pstSession->pstParent));
        pstSession->pstParent = NULL;
    }

    /* ��ʱ�Ự�϶���û��ʹ�����ü��������ֱ��ɾ�� */
    SESSION_KDestroy(pstSession);

    return;
}

/******************************************************************
   Func Name:SESSION_KRelationListProc
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�Ự��ɾ��ʱ�Թ��ڻỰ�ϵĹ�������д���
       INPUT:DL_HEAD_S *pstRelationList, ����������
      Output:��
      Return:��
     Caution:���ڹ��ĸ��Ự�Ĺ�����:ժ������DELETING��־�����Ựָ���ÿ�
             ���ڲ����ĸ��Ự�Ĺ�����:�����κδ���
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
STATIC VOID SESSION_KRelationListProc(IN DL_HEAD_S *pstRelationList, IN SESSION_S *pstSession)
{
    RELATION_S *pstRelation;
    DL_NODE_S *pstCurNode;
    DL_NODE_S *pstNextNode;

    DL_FOREACH_SAFE(pstRelationList, pstCurNode, pstNextNode)
    {
        pstRelation = container_of(pstCurNode, RELATION_S, stNodeInSession);
        if(BOOL_TRUE == pstRelation->bCareParentFlag)
        {
            DL_Del(pstCurNode);
            RELATION_SET_DELETING(pstRelation);
            pstRelation->pstParent = NULL;
        }
    }

    if (BOOL_TRUE == DL_IsEmpty(pstRelationList))
    {
        DL_Init(pstRelationList);
    }

    return;
}

/******************************************************************
   Func Name:SESSION_Delete
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�Ự��ժHASH
       INPUT:IN SESSION_S *pstSession, �Ự
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
STATIC VOID SESSION_Delete(IN SESSION_S *pstSession)
{
    SESSION_CTRL_S *pstSessionMdc;

    pstSessionMdc = SESSION_CtrlData_Get();

    #if 0
    /* ������־ */
    if ( SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_LOG_ENABLE) &&
         (BOOL_TRUE == SESSION_IsOwner(pstSession)))
    {
        SESSION_LOG_PROC_Delete(pstSession, pstSessionMdc);
    }

    /* GDX ����ntop�ӿڷ��ͻỰ�������� */
    if (BOOL_TRUE == pstSessionMdc->bStatEnable)
    {
        NTOP_KSession_SendLog((SESSION_HANDLE)pstSession);
    }
    #endif

    /* ֪ͨɾ�� */
    SESSION_KNotify_TableDelete((SESSION_HANDLE)pstSession);

    /* ����ͳ����Ϣ */
    SESSION_KDecStat(pstSessionMdc, (SESSION_L4_TYPE_E)pstSession->stSessionBase.ucSessionL4Type,
                                            pstSession->uiOriginalAppID);


    //rte_spinlock_lock(&(pstSession->stLock));
    /* ɾ�����б��ữ�����Ĺ����� */
    SESSION_KRelationListProc(&(pstSession->stRelationList), pstSession);
    //rte_spinlock_unlock(&(pstSession->stLock));

    SESSION_KPut(pstSession);

    return;
}

/******************************************************************
   Func Name:SESSION_DisDelete
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�Ựɾ�����Ựͬ��ɾ�����ݵĻỰ
       INPUT:IN SESSION_S *pstSession, �Ự
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION_DisDelete(IN SESSION_S *pstSession)
{
    SESSION_Delete(pstSession);
}

/* �Ự��ɾ��ʱ�Թ��ڻỰ�ϵĹ�������д��� */
STATIC VOID SESSION6_KRelationListProc(IN DL_HEAD_S *pstRelationList, IN SESSION_S *pstSession)
{
    RELATION6_S *pstRelation;
    DL_NODE_S *pstCurNode;
    DL_NODE_S *pstNextNode;

    DL_FOREACH_SAFE(pstRelationList, pstCurNode, pstNextNode)
    {
        pstRelation = container_of(pstCurNode, RELATION6_S, stNodeInSession);
        if(BOOL_TRUE == pstRelation->bCareParentFlag)
        {
            DL_Del(pstCurNode);
            RELATION_SET_DELETING(pstRelation);
            pstRelation->pstParent = NULL;
        }
    }

    if (BOOL_TRUE == DL_IsEmpty(pstRelationList))
    {
        DL_Init(pstRelationList);
    }

    return;
}

/* �Ự��ժHASH */
VOID SESSION6_Delete(IN SESSION_S *pstSession)
{
    SESSION_CTRL_S *pstSessionMdc;

    /* ժhash���ɾ����ȷ������delete��ǵĻỰ�������ڱ���ƥ�� */
    if (!SESSION_TABLE_IS_TABLEFLAG(&(pstSession->stSessionBase), SESSION_CACHE_DELETED))
    {
        IP6FS_DeletePairFromHash(pstSession);
    }

    pstSessionMdc = SESSION_CtrlData_Get();

#if 0
    /* ������־ */
    if ( SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_LOG_ENABLE) &&
         (BOOL_TRUE == SESSION_IsOwner(pstSession)))
    {
        SESSION6_KLOG_PROC_Delete(pstSession, pstSessionMdc);
    }

    /* GDX ����ntop�ӿڷ��ͻỰ�������� */
    if (BOOL_TRUE == pstSessionMdc->bStatEnable)
    {
        NTOP_KSession6_SendLog((SESSION_HANDLE)pstSession);
    }
#endif

    /* ֪ͨɾ�� */
    SESSION_KNotify_TableDelete((SESSION_HANDLE)pstSession);

    /* ����ͳ����Ϣ */
    SESSION_KDecStat(pstSessionMdc, (SESSION_L4_TYPE_E)pstSession->stSessionBase.ucSessionL4Type,
                                            pstSession->uiOriginalAppID);


    //rte_spinlock_lock(&(pstSession->stLock));
    /* ɾ�����б��ữ�����Ĺ����� */
    SESSION6_KRelationListProc(&(pstSession->stRelationList), pstSession);
    //rte_spinlock_unlock(&(pstSession->stLock));

    SESSION6_KPut(pstSession);

    return;
}


/******************************************************************
   Func Name:SESSION6_KPut
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�����ü�����������0ʱ�����Ự�ڴ��ͷ�
       INPUT:IN SESSION_S *pstSession, �Ự
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
VOID SESSION6_KPut(IN SESSION_S *pstSession)
{
    if(rte_atomic32_dec_and_test(&pstSession->stSessionBase.stRefCount.stCount))
    {
        /* ɾ�����Ự�����ü��� */
        if (NULL != pstSession->pstParent)
        {
            SESSION6_KPut(pstSession->pstParent);
        }

        /* �ָ����ͳ����ֵ */
        SESSION_InfoCountDec();
		
		general_rcu_qsbr_dq_enqueue((void *)pstSession, SESSION_KDestroy);
    }
    return;
}

/* MBUF�ͷ�ʱ���MBuf�ԻỰ�����á�
   �ú���ͨ������MBUF_RegExtCacheFreeFunc����ע�ᣬ
   ��MBuf�ͷ�ʱ������øûص����������MBuf�лỰָ�벻Ϊ�գ�������ü�����
   ���ü�����Ϊ0ʱ���ͷŻỰ��
*/
STATIC inline VOID _session6_KMbufDestroy(IN SESSION_S *pstSession)
{
    /* �������ʱ�Ự��������֪ͨɾ�� */
    SESSION_KNotify_TableDelete((SESSION_HANDLE) pstSession);

    SESSION_DBG_SESSION_EVENT_SWITCH(pstSession, EVENT_DELETE);

    /* ɾ�����Ự�����ü��� */
    if (NULL!= pstSession->pstParent)
    {
        SESSION6_KPut((SESSION_S *)(pstSession->pstParent));
        pstSession->pstParent = NULL;
    }

    /* ��ʱ�Ự�϶���û��ʹ�����ü��������ֱ��ɾ�� */
    SESSION_KDestroy(pstSession);

    return;
}

/* MBUF�ͷ�ʱ���MBuf�ԻỰ�����á�
   �ú���ͨ������MBUF_RegExtCacheFreeFunc����ע�ᣬ
   ��MBuf�ͷ�ʱ������øú��������MBuf�лỰָ�벻Ϊ�գ�������ü�����
   ���ü�����Ϊ0ʱ���ͷŻỰ��
*/
ULONG SESSION_KMbufDestroy(IN MBUF_S *pstMbuf)
{
    SESSION_S *pstSession;
    flow_connection_t *fcp;
		      
    pstSession = (SESSION_S *)GET_FWSESSION_FROM_LBUF(pstMbuf);
    if(pstSession != NULL)
    {
        /*ֻ������ʱ�Ự��ɾ��*/
        if(SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_TEMP))
        {
            /* ipv4 �Ự */
            if(!SESSION_TABLE_IS_TABLEFLAG(&pstSession->stSessionBase, SESSION_IPV6))
            {
                _session4_KMbufDestroy(pstSession);
            }
            else
            {   
                _session6_KMbufDestroy(pstSession);
            }
        }

        /* ���Ự��־��0 */
        MBUF_SET_SESSION_FLAG(pstMbuf, 0);
    }
	else
	{		
		fcp = GET_FC_FROM_LBUF(pstMbuf);
		set_fcp_invalid(fcp, FC_CLOSE_OTHER); 
	}
	
    return ERROR_SUCCESS;
}

/* �Ự�������һ�׶γ�ʼ������ */
ULONG SESSION_KTableInit(VOID)
{
    ULONG ulErrCode;

    memset (&g_stSessionExtRegInfo, 0, sizeof(g_stSessionExtRegInfo));

    memset (&g_auiSessTotalLen, 0, sizeof(g_auiSessTotalLen));
    g_auiSessTotalLen[SESSION_TYPE_NORMAL] = SESS_MEMPOOL_ELT_SIZE_NORMAL;
    
    memset (&g_stSessChangeableQueue, 0, sizeof(g_stSessChangeableQueue));
    
    /* ��ǰֻ��alg����changeablequeue,�䲻������mdc */
    ulErrCode = AGINGQUEUE_Changeable_InitQueue(&g_stSessChangeableQueue);

	ulErrCode |= SESSION_RelationHash_Init();

    /* ��ʼ���Ự��mempool */
	/* create a mempool (with cache) for normal session */
	g_apstSessPool[SESSION_TYPE_NORMAL] = rte_mempool_create("normal_session", SESS_MEMPOOL_SIZE_NORMAL,
		SESS_MEMPOOL_ELT_SIZE_NORMAL,
		RTE_MEMPOOL_CACHE_MAX_SIZE, 0,
		NULL, NULL,
		NULL, NULL,
		SOCKET_ID_ANY, 0);

    /* ���ת���������ط��Ѿ�����������Ͳ��õ���;   
       ��Ҫ��ת��ģ��Ĵ�ѭ���е�rte_timer_manage()����֤timer����,
       ����ÿ10ms��1ms����һ��rte_timer_manage() */
    //��main�����е��� rte_timer_subsystem_init();

    return ulErrCode;
}


VOID SESSION_KTableFini(VOID)
{
    AGINGQUEUE_Changeable_DestroyQueue(&g_stSessChangeableQueue);

    /* �ͷŻỰ��mempool */
    rte_mempool_free(g_apstSessPool[SESSION_TYPE_NORMAL]);

    return;
}
							 
/*
��������:  ��ȡ�������Ự��չ��Ϣ�Ľӿ�, ͨ��������֧�ֲ��������չ��Ϣ
�������:  SESSION_HANDLE hSession,             �Ự
		 SESSION_MODULE_E enModule,         ҵ��ģ��
		 SESSION_ATTACH_CREATE_PF pfCreate, ��չ��Ϣ��������, ��pfGet��ȡΪ��ʱ����
		 ULONG ulPara,                      ���, �ɵ����߶���
ע���:     �˺����޸Ļ�Ӱ��ת������, �޸�ǰ��Ҫ�������ȷ��
***************************************************************************/
VOID *SESSION_KGetExtInfoSafe(IN SESSION_HANDLE hSession,
                              IN SESSION_MODULE_E enModule,
                              IN SESSION_ATTACH_CREATE_PF pfCreate,
                              IN ULONG ulPara)
{
	VOID *pExtInfo;

	/* Ԥȡ��չ��Ϣ������Ѿ�����չ��Ϣ��ֱ�ӷ��� 
	pExtInfo = SESSION_KGetStaticExtInfo(hSession, enModule);
	if(NULL != pExtInfo)
	{
		return pExtInfo;
	}*/

	/*spin_lock_bh(&pstSession->stLock);*/
	/* ���������»�ȡ��չ��Ϣ����ܲ��������ĳ��� */
	pExtInfo = SESSION_KGetStaticExtInfo(hSession, enModule);
	if(NULL == pExtInfo)
	{
		pExtInfo = pfCreate(hSession, ulPara);
	}
	/*spin_unlock_bh(&pstSession->stLock);*/

	return pExtInfo;
}

