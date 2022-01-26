#ifndef _SESSION_KCORE_H_
#define _SESSION_KCORE_H_

#include "tcp.h"
#include "session.h"
#include <rte_atomic.h>



/* �ỰALG������ */
typedef ULONG (*SESSION_ALG_PROC_PF)(IN MBUF_S *pstMbuf,
                                     IN UINT uiL3Offset,
                                     IN UINT uiL4Offset,
                                     IN SESSION_HANDLE hSession);
/* ALG��չ��Ϣ��Դ�ͷź��� */
typedef VOID (*SESSION_ALG_EXT_DESTROY_PF)(IN const VOID *pExt);

/* ALG��չ��Ϣ���ݻص����� */
typedef ULONG (*SESSION_ALG_EXTBACKUP_PF)(IN const VOID *pAlgCB, INOUT UCHAR *pucData);
/* ALG��չ��Ϣ���ݻص����� */
typedef ULONG (*SESSION_ALG_EXTRESTORE_PF)(IN const VOID *pAlgData,
                                           IN USHORT usDataLen,
                                           INOUT SESSION_HANDLE hSession);

typedef struct tagSessionALG
{
    SESSION_ALG_PROC_PF        pfAlgProc;       /* IPv4 ALG��ת������ */
    SESSION_ALG_PROC_PF        pfAlg6Proc;      /* IPv6 ALG��ת������ */
    SESSION_ALG_EXT_DESTROY_PF pfExtDestroy;    /* ALG��չ��Ϣ�ͷź��� */
    SESSION_ALG_EXTBACKUP_PF   pfExtBackup;     /* ALG��չ��Ϣ���ݺ��� */
    SESSION_ALG_EXTRESTORE_PF  pfExtRestore;    /* ALG��չ��Ϣ�ָ����� */
} SESSION_ALG_S;

/* ���ݹ��������Ựʱ, �ص������ù������ҵ��ģ�麯�� */
typedef ULONG (*SESSION_APP_CREATE_FROMRELATION_PF)(IN SESSION_S *pstNewSession, IN VOID *pAttachData);

/* ������ɾ��ʱ���ص������ù������ҵ��ģ�麯�� */
typedef ULONG (*SESSION_APP_DELETE_RELATION_PF)(IN VOID *pAttachData);

typedef enum enSessionTupleMask
{
    SESSION_TUPLE_MASK_IP = 0,
    SESSION_TUPLE_MASK_PORT,
    SESSION_TUPLE_MASK_MAX,
} SESSION_TUPLE_MASK_E;

typedef struct tagRelationTupleHashStruct
{
    DL_NODE_S       stNodeInHash;
    csp_key_t       stIpfsKey;
    UINT            uiMask;               /* ������TUPLE�Ƚϱ�ǣ�ֻ���Ŀ�ĵ�ַλ�Ƿ���� */
    USHORT          usLockIndex;          /* HASH������ */
    UCHAR           ucRsv1;
    UCHAR           ucRsv2;
} RELATION_TUPLE_HASH_S;


typedef struct tagRelation6TupleHashStruct
{
    DL_NODE_S       stNodeInHash;
    csp_key_t       stIp6fsKey;
    UINT            uiMask;               /* ������TUPLE�Ƚϱ�ǣ�ֻ���Ŀ�ĵ�ַλ�Ƿ���� */
    USHORT          usLockIndex;          /* HASH������ */
    UCHAR           ucRsv1;
    UCHAR           ucRsv2;
} RELATION6_TUPLE_HASH_S;

typedef struct tagRelationAttachHashStruct
{
    DL_NODE_S       stNodeInHash;
    USHORT          usLockIndex;
} RELATION_ATTATCH_HASH_S;

#define RELATION_TUPLEFLAG_IS_IPSET(_uiMask) SESSION_IS_PARABIT_SET(_uiMask, SESSION_TUPLE_MASK_IP)
#define RELATION_TUPLEFLAG_IS_PORTSET(_uiMask) SESSION_IS_PARABIT_SET(_uiMask, SESSION_TUPLE_MASK_PORT)

typedef enum tagRelationFlag
{
    RELATION_FLAG_DELETING,
    RELATION_FLAG_PERSIST,
    RELATION_FLAG_NEED_TO_REFRESH,
    RELATION_FLAG_CHANGEABLE_AGING_OBJ,
    RELATION_FLAG_GLOBAL_LIMIT,     /* ���ƹ�������ڱ���IPͷƥ��ʱֻ����globalƥ�� */     
    RELATION_FLAG_SELFAGED,         /* �������Ự��ͬʱ�Լ�Ҳ�ϻ� */
    RELATION_FLAG_ALGTEMP,
    RELATION_FLAG_ADD_LOCAL_HASH,
    RELATION_FLAG_IPV6,
    RELATION_FLAG_MAX,
} RELATION_FLAG_E;


#define RELATION_FLAG_BACKUPED 0x02
#define RELATION_FLAG_TEMP         0x04 
#define RELATION_FLAG_BROADCAST    0x08
#define RELATION_FLAG_CAST         0x10  /* ��ʶ�Ự�Ѿ��㲥���� */ 
#define RELATION_FLAG_VRRPBACKUPED 0x20
#define RELATION_FLAG_VRRPCAST     0x40  /* ��ʶVRRP�Ự�Ѿ��㲥���� */ 
#define RELATION_FLAG_AGENT        0x80 


#define RELATION_SET_TABLEFLAG(_pstRelation, usFlag) ((_pstRelation)->usBackupFlag |= usFlag)
#define RELATION_CLEAR_TABLEFLAG(_pstRelation, usFlag) ((_pstRelation)->usBackupFlag &= (USHORT)~usFlag)
#define RELATION_IS_TABLEFLAG(_pstRelation, usFlag) (0 != ((_pstRelation)->usBackupFlag) & (USHORT)usFlag)

typedef struct tagSessionRelationStruct
{
    //forcompile RCU_REG_S stRcu;
    union
    {
        AGINGQUEUE_UNSTABLE_OBJECT_S stUnstableAgingInfo;
        AGINGQUEUE_CHANGEABLE_OBJECT_S stChangeableAgingInfo;
    } unAgingObj;
    #define stUnstable         unAgingObj.stUnstableAgingInfo
    #define stChangeable       unAgingObj.stChangeableAgingInfo
    DL_NODE_S                  stNodeInSession; /* ͬһ���Ự�����й��������� */
    RELATION_TUPLE_HASH_S      stTupleHash;     /* ������HASH */
    RELATION_ATTATCH_HASH_S    stLocalHash;     /* ������LOCAL HASH, HASH KEYΪstAttachData */
    SESSION_S                  *pstParent;      /* ���Ựָ�� */
    SESSION_CHILD_DIR_E        enChildDir;      /* Ԥ���ӻỰ���� */
    RELATION_ATTACH_INFO_S     stAttachData;    /* ҵ��ģ�鸽�ӵ�������ĸ������� */ 
    NEW_SESSION_BY_RELATION_PF pfNewSession;    /* ҵ��ģ�鸽�ӵ�������ĸ������� */
    BOOL_T                     bSet;            /* ��¼��������չ��Ϣ�Ƿ��Ѿ������ù���ֻ��������һ�� */     
    USHORT                     usModuleFlag;
    UINT64                     uiUpdateTime;    /* ��λΪcycles */
    UINT                       uiClass;         /* Audio��Video��image��signalling */ 
    UINT                       uiAppID;         /* �ɴ˹����������ӻỰ��APPID */
    ULONG                      ulRelationFlag;  /* ������flag����RELATION_FLAG_E */
    ULONG                      ulDrvRetValue;   /* �·��������:δ�·����·��ɹ����·�ʧ�� */
    ULONG                      aulDrvContext[2];
    BOOL_T                     bCareParentFlag;
    USHORT                     usBackupFlag;
    UINT                       uiAgingType;
    ULONG                      ulID;
} RELATION_S;


typedef struct tagSessionRelation6Struct
{
    //forcompile RCU_REG_S stRcu;
    union
    {
        AGINGQUEUE_UNSTABLE_OBJECT_S stUnstableAgingInfo;
        AGINGQUEUE_CHANGEABLE_OBJECT_S stChangeableAgingInfo;
    } unAgingObj;                              /*�ϻ����� */
    #define stUnstable   unAgingObj.stUnstableAgingInfo
    #define stChangeable unAgingObj.stChangeableAgingInfo
    DL_NODE_S stNodeInSession;               /*ͬһ���Ự�����й���������*/
    RELATION6_TUPLE_HASH_S  stTupleHash;     /*������HASH */
    RELATION_ATTATCH_HASH_S stLocalHash;     /*������LOCAL HASH��HASH KEYΪstAttachData */
    SESSION_S *pstParent;                    /* ���Ựָ�� */
    SESSION_CHILD_DIR_E enChildDir;          /* Ԥ���ӻỰ���� */
    RELATION_ATTACH_INFO_S stAttachData;     /* ҵ��ģ�鸽�ӵ�������ĸ������� */
    NEW_SESSION_BY_RELATION_PF pfNewSession; /* ���ݹ��������Ự��ʱ���ص������ù������ҵ��ģ�麯�� */
    BOOL_T bSet;                             /* ��¼��������չ��Ϣ�Ƿ��Ѿ������ù���ֻ��������һ�� */
    UINT64 uiUpdateTime;
    UINT uiClass;                            /* Audio��Video��image��signalling */
    UINT uiAppID;                            /* �ɴ˹����������ӻỰ��APPID */
    ULONG ulRelationFlag;                    /* ������flag����RELATION_FLAG_E */
    ULONG ulDrvRetValue;                     /* �·��������: δ�·����·��ɹ����·�ʧ�� */
    ULONG aulDrvContext[2];
    BOOL_T bCareParentFlag;
    USHORT usBakupFlag;
    UINT uiAgingType;
    ULONG ulID;
    USHORT usModuleFlag;
} RELATION6_S;

typedef struct tagSessionKCapability
{
    UINT uiMaximum;
    UINT uiRate;
}SESSION_KCAPABILITY_S;

/* ������DELETING������ú��ж� */
#define RELATION_SET_DELETING(_Relation) BIT_SET((_Relation)->ulRelationFlag, RELATION_FLAG_DELETING)
#define RELATION_IS_DELETING(_Relation) \
    (0 != BIT_TEST((_Relation)->ulRelationFlag, RELATION_FLAG_DELETING))

/* ������PERSIST������ú��ж� */
#define RELATION_SET_PERSIST(_Relation) BIT_SET((_Relation)->ulRelationFlag, RELATION_FLAG_PERSIST)
#define RELATION_CLEAR_PERSIST(_Relation) BIT_CLEAR((_Relation)->ulRelationFlag, RELATION_FLAG_PERSIST)
#define RELATION_IS_PERSIST(_Relation) (0 != BIT_TEST((_Relation)->ulRelationFlag, RELATION_FLAG_PERSIST))

/* ����������Լ��ϻ� */
#define RELATION_SET_SELFAGED(_Relation) BIT_SET((_Relation)->ulRelationFlag, RELATION_FLAG_SELFAGED)
#define RELATION_CLEAR_SELFAGED(_Relation) BIT_CLEAR((_Relation)->ulRelationFlag, RELATION_FLAG_SELFAGED)
#define RELATION_IS_SELFAGED(_Relation) (0 != BIT_TEST((_Relation)->ulRelationFlag, RELATION_FLAG_SELFAGED))


#define RELATION_SET_TEMP(_Relation) BIT_SET((_Relation)->ulRelationFlag, RELATION_FLAG_ALGTEMP)
#define RELATION_CLEAR_TEMP(_Relation) BIT_CLEAR((_Relation)->ulRelationFlag, RELATION_FLAG_ALGTEMP)
#define RELATION_IS_TEMP(_Relation) (0 != BIT_TEST((_Relation)->ulRelationFlag, RELATION_FLAG_ALGTEMP))


#define RELATION_SET_IPV6(_Relation) BIT_SET((_Relation)->ulRelationFlag, RELATION_FLAG_IPV6)
#define RELATION_CLEAR_IPV6(_Relation) BIT_CLEAR((_Relation)->ulRelationFlag, RELATION_FLAG_IPV6)
#define RELATION_IS_IPV6(_Relation) (0 != BIT_TEST((_Relation)->ulRelationFlag, RELATION_FLAG_IPV6))


/* ��Э���Ӧ�ĻỰ���� */
extern SESSION_L4_TYPE_E g_aenSessionType[IPPROTO_MAX];
extern SESSION_CONF_S g_stSessionConfInfo; /* ��ʼ��һ��Ĭ��ֵ */
extern rte_atomic32_t g_stSessionCount;

/* ���ݻỰ��4��Э��Ż�ȡ�Ự������ */
static inline SESSION_L4_TYPE_E SESSION_KGetSessTypeByProto(IN UCHAR ucProto)
{
    return g_aenSessionType[ucProto];
}

/* ���ӻỰ���������ͳ�Ƽ��� */
static inline VOID SESSION_KAddOriginalFlowStat(IN const MBUF_S *pstMBuf, IN SESSION_S *pstSession)
{
    rte_atomic32_add(&(pstSession->_astBytes[SESSION_DIR_ORIGINAL]), (INT)MBUF_GET_TOTALDATASIZE(pstMBuf));
    
    rte_atomic32_add(&(pstSession->_astPackets[SESSION_DIR_ORIGINAL]), (INT)1);

    return;
}

/* ���»Ự��reply cache */
static inline VOID SESSION6_KUpdateReplyCache(IN VOID *pCache,
											  IN const MBUF_S *pstMBuf,
											  INOUT SESSION_S *pstSession)
{
	return;
}

static inline ULONG SESSION_KCheckTcpNew(IN const MBUF_S *pstMbuf,
                                         IN UINT uiL4OffSet,
                                         OUT UCHAR *pucNewState)
{
    TCPHDR_S *pstTcpHdr;
    ULONG ulRet = ERROR_SUCCESS;
    UCHAR ucFlags;

    pstTcpHdr = MBUF_BTOD_OFFSET(pstMbuf, uiL4OffSet, TCPHDR_S *);
    ucFlags = (pstTcpHdr->th_flags) & TCP_FLAGS_CARE_MASK & (~TH_URG);

    if(TH_SYN == ucFlags)
    {
        *pucNewState = TCP_ST_SYN_SENT;
    }
    else if (TH_ACK == ucFlags)
    {        
        *pucNewState = TCP_ST_ESTABLISHED;   
    }
    else
    {
        ulRet = ERROR_FAILED;
    }

    return ulRet;
}

/******************************************************************
   Func Name:SESSION_KCheckOtherNew
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�½��Ự���ĺϷ��Լ��
       INPUT:IN MBUF_S *pstMBuf    ----����
             IN UCAHR ucPro        ----Э��
             IN UCHAR ucKeyFlag    ----��ʶ������ת�����Ƕ���ת��
      Output:��
      Return:ERROR_SUCCESS         ----���ͨ��
             ERROR_FAILED          ----���ʧ��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline ULONG SESSION_KCheckOtherNew(IN MBUF_S *pstMbuf, 
                                           IN UINT uiL3_Offset, 
                                           IN UINT uiL4_Offset,
                                           IN UCHAR ucPro)
{
    SESSION_L4_PROTO_S *pstL4Proto;
    ULONG ulRet;

    pstL4Proto = SESSION_KGetL4Proto_Proc(ucPro);

    ulRet = pstL4Proto->pfPacketCheck(pstMbuf, uiL3_Offset, uiL4_Offset);
    if (ERROR_SUCCESS == ulRet) 
    {
        ulRet = pstL4Proto->pfNewSessCheck(pstMbuf, uiL3_Offset, uiL4_Offset);
    }
    
    return ulRet;
}

/******************************************************************
   Func Name:SESSION_KAddReplyFlowStat
Date Created:2021/04/25
      Author:wangxiaohua
 Description:���ӻỰ���������ͳ�Ƽ���
       INPUT:IN MBUF_S           *pstMBuf     ----����
             IN SESSION_S        *pstSession  ----���������Ự             
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline VOID SESSION_KAddReplyFlowStat(IN const MBUF_S *pstMBuf, IN SESSION_S*pstSession)
{
    rte_atomic32_add(&(pstSession->_astBytes[SESSION_DIR_REPLY]), (INT)MBUF_GET_TOTALDATASIZE(pstMBuf));
    
    rte_atomic32_add(&(pstSession->_astPackets[SESSION_DIR_REPLY]), (INT)1);

    return;
}

/******************************************************************
   Func Name:SESSION_Info_Specification
Date Created:2021/04/25
      Author:wangxiaohua
 Description:������
       INPUT:VOID
      Output:��
      Return:ULONG
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline ULONG SESSION_Info_Specification(VOID)
{
    ULONG ulErrCode;

    if (rte_atomic32_read(&g_stSessionCount) < (INT)g_stSessionConfInfo.uiMaxSessionEntries)
    {
        rte_atomic32_inc(&g_stSessionCount);
        ulErrCode = ERROR_SUCCESS;
    }
    else
    {
        ulErrCode = ERROR_FAILED;
    }
    
    return ulErrCode;
}

static inline BOOL_T SESSION6_KMatchACL(IN const SESSION_S *pstSession, IN UINT uiAclNum)
{
    BOOL_T bMatch;

    if(SESSION_CFG_ACLNUM_NONE == uiAclNum)
    {
        /* δʹ�ܹ��� */
        bMatch = BOOL_FALSE;
    }
    else if (SESSION_CFG_ACLNUM_ALL == uiAclNum)
    {
        /* δָ��ACL, ���ж�ƥ�� */
        bMatch = BOOL_TRUE;
    }
    else
    {
        bMatch = SESSION_MatchKeyIpv6AclRule(pstSession, uiAclNum);
    }

    return bMatch;
}

static inline BOOL_T SESSION_KMatchACL(IN const SESSION_S *pstSession, IN UINT uiAclNum)
{
    BOOL_T bMatch;

    if(SESSION_CFG_ACLNUM_NONE == uiAclNum)
    {
        /* δʹ�ܹ��� */
        bMatch = BOOL_FALSE;
    }
    else if (SESSION_CFG_ACLNUM_ALL == uiAclNum)
    {
        /* δָ��ACL, ���ж�ƥ�� */
        bMatch = BOOL_TRUE;
    }
    else
    {
        bMatch = SESSION_MatchKeyIpv4AclRule(pstSession, uiAclNum);
    }

    return bMatch;
}

ULONG SESSION_KGetNotZero(IN SESSION_S *pstSession);
VOID SESSION_BAK_SetInvalidFlag(IN MBUF_S *pstMBuf);
ULONG SESSION_KGetTupleFromMbuf(IN MBUF_S *pstMBuf, IN UINT uiL3OffSet, INOUT SESSION_TUPLE_S *pstTuple);
VOID SESSION_init_l4type_map(VOID);
VOID SESSION_KRefreshParents(IN const SESSION_S *pstSession);
VOID SESSION_KPut(IN SESSION_S *pstSession);
VOID RELATION6_BAK_SendDelete(SESSION_S *pstSession, RELATION6_S *pstRelation);

#endif
