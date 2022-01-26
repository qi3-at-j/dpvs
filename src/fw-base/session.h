#ifndef _SESSION_H_
#define _SESSION_H_

#include "flow.h"
#include "apr.h"
#include "ipfs.h"
#include "error.h"
#include "ipfw.h"
#include "ip6fw.h"
#include "hash.h"
#include "tcp.h"
#include <rte_atomic.h>
#include <rte_spinlock.h>
#include <rte_cycles.h>
//#include "in.h"
#include <netinet/in.h>

#include "agingqueue.h"
#include "session_mbuf.h"
#include "mbuf_ext.h"
#include "session_util.h"
#include "session_public.h"


typedef enum tagSESSION_STAT_FAIL_TYPE
{
    SESSION_STAT_FAIL_CREATE_CACHE_NULL,            /*�Ự����ʱcacheΪNULL*/
    SESSION_STAT_FAIL_GETL4OFFSET,                  /*��ȡ4��ͷƫ��ʧ��*/
    SESSION_STAT_FAIL_PKT_CHECK,                    /*���ļ��ʧ��*/
    SESSION_STAT_FAIL_ALLOC_CACHE,                  /*����cacheʧ��*/
    SESSION_STAT_FAIL_ALLOC_SESSION,                /*����Ựʧ��*/
    SESSION_STAT_FAIL_EXTNEW_STATE,                 /*��չ�Ự����ʱ״̬�쳣*/
    SESSION_STAT_FAIL_TRY_FAIL_UNICAST,             /*����session end���Դ���ʧ��*/
    SESSION_STAT_FAIL_CAPABITITY_UNICAST,           /*�����Ự��������*/
    SESSION_STAT_FAIL_FORMALIZE_UNICAST,            /*�����Ự��ʽ��ʧ��*/
//    SESSION_STAT_FAIL_TRY_FAIL_MULTICAST,           /*�鲥session end���Դ���ʧ��*/
//    SESSION_STAT_FAIL_CAPABITITY_MULTICAST,         /*�鲥�Ự��������*/
//    SESSION_STAT_FAIL_FORMALIZE_MULTICAST,          /*�鲥�Ự��ʽ��ʧ��*/
    SESSION_STAT_FAIL_TOUCH_CACHE_NULL,             /*ƥ��ỰʱcacheΪNULL*/
    SESSION_STAT_FAIL_TOUCH_STATE,                  /*ƥ��Ựʱ״̬�쳣*/
    SESSION_STAT_FAIL_EXT_STATE,                    /*��չ�Ự״̬�쳣*/
    SESSION_STAT_FAIL_TCP_STATE,                    /*TCP state �쳣*/
    SESSION_STAT_FAIL_FAST_TCP_STATE,               /*��תʱTCP state �쳣*/
//    SESSION_STAT_FAIL_NEED_RELAY,                   /*SYN-ACK������Ҫ͸��*/
    SESSION_STAT_FAIL_HOTBACKUP_DELETE_FAIL,        /*�ȱ�ǿ��ɾ�������Ựʧ��*/
    SESSION_STAT_FAIL_HOTBACKUP_HASHFAIL,           /*�ȱ��Ự���hash��ͻ*/
    SESSION_STAT_FAIL_RELATION_LOCAL_HASH,           
    SESSION_STAT_FAIL_RELATION_GLOBAL_HASH,      
//    SESSION_STAT_FAIL_MBUF_RELAY_OUTPUT,            /*��ת͸�����ճ�������*/
//    SESSION_STAT_FAIL_MBUF_RELAY_INPUT,             /*��ת͸�������봦����*/
    SESSION_STAT_FAIL_FIRST_PATH,                   /*��ת�ӿڷ���ֵ����FLOW_RET_OK*/
    SESSION_STAT_FAIL_FAST_PATH,                    /*��ת�ӿڷ���ֵ����FLOW_RET_OK*/
    SESSION_STAT_FAIL_TYPE_MAX
}SESSION_STAT_FAIL_TYPE_E;

typedef enum enSESSION_APP_STATIC_TYPE
{
    SESSION_APP_STATIC_DNS = 0,
    SESSION_APP_STATIC_FTP,
    SESSION_APP_STATIC_GTPC,
    SESSION_APP_STATIC_GTPU,
    SESSION_APP_STATIC_GPRSDATA,
    SESSION_APP_STATIC_GPRSSIG,
    SESSION_APP_STATIC_RAS,
    SESSION_APP_STATIC_H225,
    SESSION_APP_STATIC_H245,
    SESSION_APP_STATIC_HTTP,
    SESSION_APP_STATIC_ILS,
    SESSION_APP_STATIC_MGCPC,
    SESSION_APP_STATIC_MGCPG,
    SESSION_APP_STATIC_NETBIOSNS,
    SESSION_APP_STATIC_NETBIOSDGM,
    SESSION_APP_STATIC_NETBIOSSSN,
    SESSION_APP_STATIC_PPTP,
    SESSION_APP_STATIC_RSH,
    SESSION_APP_STATIC_RTSP,
    SESSION_APP_STATIC_SCCP,
    SESSION_APP_STATIC_SIP,
    SESSION_APP_STATIC_SMTP,
    SESSION_APP_STATIC_SQLNET,
    SESSION_APP_STATIC_SSH,
    SESSION_APP_STATIC_TELNET,
    SESSION_APP_STATIC_TFTP,
    SESSION_APP_STATIC_XDMCP,    
    SESSION_APP_STATIC_MAX
}SESSION_APP_STATIC_TYPE_E;

/* forcompile stub begin */
#define SESSION_MAX_APP_NUM 20
#define AGINGQUEUE_KSYSLOG printf
#define AGINGQUEUE_STABLE_LEVEL_NR  4
#define SESSION_APPID_MAX         1094
#define IPFS_AFT   0
#define IPFS_CACHEFLAG_MACFW     0x1
#define IPFS_CACHEFLAG_INLINE    0x2
#define SESSION_AGENT_DATA_MAX     2
#define SESSION_NUMRATE_TYPE_MAX   2
#define SESSION_DBG_SESSION_ERROR_SWTICH(x)
#define ERROR_SESSION_MEMORY_NOT_ENOUGH

typedef struct 
{
    ULONG ulExpires;
} ALG_SIP_EXT_S;
typedef struct {} SESSION_NUM_STATISTICS_S;
typedef ULONG (*SESSION_KALG_SEQ_CHECK_PF)(IN MBUF_S *pstMBuf, IN UINT uiL3Offset);
typedef ULONG (*SESSION_KALG_FS_SEQ_CHECK_PF)(IN MBUF_S *pstMBuf, IN UINT uiL3Offset);
typedef ULONG (*SESSION_KALG_SET_ACTION_PF)(IN MBUF_S *pstMBuf, IN UINT uiL3Offset);
typedef ULONG (*SESSION_KALG_PPTPGREDATA_PF)(IN MBUF_S *pstMBuf, IN UINT uiL3Offset);
typedef ULONG (*SESSION_KALG_SIPEST_PF)(IN MBUF_S *pstMBuf, IN UINT uiL3Offset);
typedef enum {DIRECTION_MAX} DIRECTION_E;
typedef enum {SESSION_LOG_FLOWMODE_MAX} SESSION_LOG_FLOWMODE_E;
typedef struct {} AGINGQUEUE_CHANGEABLE_CLASS_S;
typedef struct {BOOL_T bLogSwitchEnable;} SESSION_KLOG_GPARAM_S;
typedef struct {} SESSION_KTRAFFIC_LOG_S;

typedef struct tagSESSION_DBG
{
	UINT uiDbgSwitch;
	/*UINT auiDebugSwitch[SESSION_DEBUG_MAX];*/
	UINT uiAclNum_Event_Aging;
	UINT uiAclNum_Event_ExtInfo;
	UINT uiAclNum_Event_SessTable;
	UINT uiAclNum_Event_PkProc;
	UINT uiAclNum_ERROR_ExtInfo;
	UINT uiAclNum_Error_SessTable;
	UINT uiAclNum_Fsm_SessTable;
	UINT uiAclNum_Event_Alg;
	UINT uiAclNum_Error_Alg;
} SESSION_DEBUG_S;

typedef struct {} SESSION_TCP_DEBUG_S;
typedef struct {} SESSION_KALG_GPARAM_S;
typedef struct {} SESSION_SYNC_S;
typedef struct {} SESSION_CFG_DEBUG_S;
typedef struct {} SESSION_HOTBACKUP_DEBUG_S;
typedef struct {} AGINGQUEUE_CHANGEABLE_OBJECT_S;
#define local_bh_disable()
#define local_bh_enable()

typedef struct {} FIB6_FWDINFO_S;
typedef struct {} AGINGQUEUE_STABLE_ARRAY_S;
typedef struct {} AGINGQUEUE_CHANGEABLE_ARRAY_S;
typedef struct {} AGINGQUEUE_CHANGEABLE_S;
typedef struct {} FIB4_FWDINFO_S;

#define IP6FS_FreeCache_RCU IP6FS_FreeCache
#define RCU_Deref(x) (x)
#define SL_AddHead_Rcu SL_AddHead
#define SL_AddAfter_Rcu SL_AddAfter

typedef struct
{
    UINT auiStatFailCount[SESSION_STAT_FAIL_TYPE_MAX];
} SESSION_STAT_FAIL_S;

#define ERROR_MOR_SUCCESS 0
#define CLI_CMD_DO 0

#define SESSION_RATE_TIME 1    

typedef enum
{
    DBG_ABNORM_PKT_NOT_RESOLVE = 0,
    DBG_ABNORM_PKT_CHECK_FAIL,
    DBG_ABNORM_PKT_UNKNOWN_ICMP_ERROR_CTRL,
    DBG_ABNORM_PKT_FIRST_NOIPCACHE,
    DBG_ABNORM_PKT_FOLLOW_NOIPCACHE,
    DBG_ABNORM_PKT_ICMPERROR_OR_LATTERFRAG,
    DBG_ABNORM_PKT_INVALID,
    DBG_ABNORM_PKT_SESSION_PROCESSED_FAILED,
    DBG_ABNORM_PKT_MAX
} DBG_ABNORM_PKT_E;

#define SESSION_DEBUG_SWITCH_EVENT 0x1
#define SESSION_DEBUG_SWITCH_ERROR      ((UINT)(1<<1))
#define SESSION_DEBUG_SWITCH_FSM        ((UINT)(1<<2))
#define SESSION_DEBUG_SWITCH_STAT       ((UINT)(1<<3))
#define SESSION_DEBUG_ALG_ERROR         ((UINT)(1<<4))
#define SESSION_DEBUG_RELATION_EVENT    ((UINT)(1<<5))
#define SESSION_DEBUG_RELATION_ERROR    ((UINT)(1<<6))


#define DBG_AGING_L4AGING 0
#define ERROR_SESSION_CREATE_SESSION 0
#define SESSION_DBG_AGING_EVENT_SWITCH(pstSession, uiFlag)
#define SESSION_DBG_PACKETS_EVENT_SWITCH(pstMbuf, uiL3Offset, uiFlag)
#define SESSION_DBG_SESSION_ERROR_SWITCH(uiFlag)
#define SESSION_DBG_CONFIG_SWITCH(str)
#define SESSION_DBG_SESSION_PRINTF_SWITCH(pstSession, str)

#define SESSION_TIMER_INTERVAL  10
#define AGINGQUEUE_MODULE_SESSION 0
#define APR_MODULE_SESSION        1
#define AGINGQUEUE_MODULE_RELATION 0

#define SESSION_RELATION_HASH_LENGTH 100

extern SESSION_APP_STATIC_TYPE_E g_aenAppIndex[SESSION_APPID_MAX];
/* forcompile stub end */

#define SESSION_NAME      "session"

/*����ת�������Ự*/
#define SESSION_MACFW  0x1
#define SESSION_BRIDGE 0x2
#define SESSION_INLINE 0x4

/*�鲥�����Ự*/
#define SESSION_MCFS_IN  0x40
#define SESSION_MCFS_OUT 0x80

#define SESSION_SERVICE_INVALID_INDEX 0x0F    /*��Ч��������ʾģ��δ�����չ��Ϣ*/
#define SESSION_FIRST_SERVICE_INDEX   0x0E    /*ģ����չ��Ϣֱ�ӹ���session�е�pServiceCb*/

/*����const�����pclint�澯*/
#define SESSION_IGNORE_CONST(x) ((x) = (x))


#define SESSION_TABLE_SET_TABLEFLAG(_pSession, usFlag) \
    {(_pSession)->usTableFlag |= (USHORT)usFlag;}
#define SESSION_TABLE_CLEAR_TABLEFLAG(_pSession, usFlag) {(_pSession)->usTableFlag &= (USHORT)~usFlag;}

#define SESSION_TABLE_IS_TABLEFLAG(_pSession, usFlag) \
    (0 != ((_pSession)->usTableFlag & (USHORT)usFlag))

/* �Ự��ģ����չ�����Ƿ���ڱ�����ú��ж� */
#define SESSION_TABLE_SET_ATTACHFLAG(_pSession, _Module) {(_pSession)->usAttachFlag |= (USHORT)(1UL << (_Module));}
#define SESSION_TABLE_CLEAR_ATTACHFLAG(_pSession, _Module){(_pSession)->usAttachFlag &= (USHORT)~(1UL << (_Module));}
#define SESSION_TABLE_IS_ATTACHFLAG_SET(_pSession, _Module) \
    (0 != ((_pSession)->usAttachFlag & (USHORT)(1UL << (_Module))))

/* �Ự��ģ�鴦�������ú��ж�*/
#define SESSION_TABLE_SET_MODULEFLAG(_pSession, _Module) {(_pSession)->usModuleFlag |= (USHORT)(1UL << (_Module));}
#define SESSION_TABLE_IS_MODULEFLAG_SET(_pSession, _Module) \
    (0 != ((_pSession)->usModuleFlag & (USHORT)(1UL << (_Module))))
/* �Ự���ҵ��ģ�鿪��λ */
#define SESSION_TABLE_CLEAR_MODULELAG(_pSession, _Module) {(_pSession)->usModuleFlag &= (USHORT)~(1UL << _Module);}

/* �ỰALG�����Ǳ�����ú��ж� */
#define SESSION_TABLE_SET_ALGFLAG(_pSession, _Module) {(_pSession)->usAlgFlag |= (USHORT)(1UL << (_Module));}
#define SESSION_TABLE_IS_ALGFLAG_SET(_pSession, _Module)(0 != (((SESSION_S *)(_pSession))->usAlgFlag & (USHORT)(1UL << (_Module))))
#define SESSION_TABLE_UNSET_ALGFLAG(_pSession, _Module) {(_pSession)->usAlgFlag &= ((USHORT)(~(1UL << (_Module))));}

/* �Ự�� */
#define SESS_MAX_KEEP_NORMAL (4*1024)
#define SESS_MEMPOOL_SIZE_NORMAL    ((worker_thread_total()*(SESS_MAX_KEEP_NORMAL+RTE_MEMPOOL_CACHE_MAX_SIZE))-1)
#define SESS_MEMPOOL_ELT_SIZE_NORMAL    sizeof(SESSION_S)

typedef enum enSESSION_ALLSTAT_TYPE
{
    SESSION_ALLSTAT_TYPE_TCP   = 0, /*TCP*/        
    SESSION_ALLSTAT_TYPE_UDP,       /*UDP*/    
    SESSION_ALLSTAT_TYPE_RAWIP,     /*OTHER*/
    SESSION_ALLSTAT_TYPE_MAX
}SESSION_ALLSTAT_TYPE_E;

/*����alg�쳣ͳ����Ϣ���û�̬�·�����ALGϸ�����͵��ں�*/
typedef enum enSESSION_ALG_STAT_TYPE
{
    SESSION_ALG_STAT_TYPE_FTP = 0,
    SESSION_ALG_STAT_TYPE_RAS,
    SESSION_ALG_STAT_TYPE_H225,
    SESSION_ALG_STAT_TYPE_H245,
    SESSION_ALG_STAT_TYPE_SIP,
    SESSION_ALG_STAT_TYPE_TFTP,
    SESSION_ALG_STAT_TYPE_RTSP,
    SESSION_ALG_STAT_TYPE_GTP,
    SESSION_ALG_STAT_TYPE_PPTP,
    SESSION_ALG_STAT_TYPE_ILS,
    SESSION_ALG_STAT_TYPE_NBNS,
    SESSION_ALG_STAT_TYPE_NBDGM,
    SESSION_ALG_STAT_TYPE_NBSS,
    SESSION_ALG_STAT_TYPE_SCCP,
    SESSION_ALG_STAT_TYPE_SQLNET,
    SESSION_ALG_STAT_TYPE_XDMCP,
    SESSION_ALG_STAT_TYPE_MGCP,
    SESSION_ALG_STAT_TYPE_RSH,
    SESSION_ALG_STAT_TYPE_MAX   
}SESSION_ALG_STAT_TYPE_E;

/* session alg �쳣���� */
typedef enum tagSESSION_ALGFAIL_TYPE
{
	SESSION_ALG_FAIL_NOTSUPPORT_PROTOCOL = 0,
	SESSION_ALG_FAIL_GET_PAYLOAD_FAILED,
	SESSION_ALG_FAIL_DECODE_FAILED,
	SESSION_ALG_FAIL_ENCODE_FAILED,
	SESSION_ALG_FAIL_ALLOC_RELATION,
	SESSION_ALG_FAIL_ADD_RELATION_HASH,
	SESSION_ALG_FAIL_ADJUST_SEQUENCE,
	SESSION_ALG_FAIL_COPY_MBUF,
	SESSION_ALG_FAIL_TRANSLATE_PAYLOAD,
	SESSION_ALG_FAIL_FRAG_NOFIRST,
	SESSION_ALG_FAIL_DROPED_BY_ASPF,
	SESSION_ALG_FAIL_TYPE_MAX
}SESSION_ALGFAIL_TYPE_E;

/* ����Э������ */
typedef enum enSESSION_L3_TYPE
{
    SESSION_L3_TYPE_IPV4, /* IPv4Э�� */        
    SESSION_L3_TYPE_IPV6, /* IPv6Э�� */
    SESSION_L3_TYPE_MAX
}SESSION_L3_TYPE_E;

/* �Ĳ�Э������ */
typedef enum enSESSION_L4_TYPE
{
    SESSION_L4_TYPE_TCP = 0,  /* TCP */
    SESSION_L4_TYPE_UDP,      /* UDP */
    SESSION_L4_TYPE_ICMP,     /* ICMP */
    SESSION_L4_TYPE_ICMPV6,   /* ICMPv6 */
    SESSION_L4_TYPE_UDPLITE,  /* UDP-Lite */
    SESSION_L4_TYPE_SCTP,     /* SCTP */
    SESSION_L4_TYPE_DCCP,     /* DCCP */
    SESSION_L4_TYPE_RAWIP,    /* ���в����������Ĳ�Э���IP/IPv6���Ĺ�Ϊ���� */
    SESSION_L4_TYPE_MAX
}SESSION_L4_TYPE_E;

typedef enum enSESSION_ALG_ACTION_TYPE
{
    SESSION_ALG_ACTION_IF_IN = 0,
    SESSION_ALG_ACTION_IF_OUT,
    SESSION_ALG_ACTION_INTERZONE,
    SESSION_ALG_ACTION_MAX,
}SESSION_ALG_ACTION_TYPE_E;

UCHAR SESSION_K_ALG_GetActionInfo(IN SESSION_HANDLE hSession,
								  IN SESSION_ALG_ACTION_TYPE_E enActionType);

/* ��ȡ�Ự����ʱ�� */
#define SESSION_TABLE_GET_CREATE_TIME(_pSession, _uiCreateTime) \
	((_uiCreateTime) = (((SESSION_S *)(_pSession))->stSessionBase.uiSessCreateTime))

typedef union tagSessionAgingRcu
{
    AGINGQUEUE_UNSTABLE_OBJECT_S stAgingInfo;
}SESSION_AGING_RCU_U;

/* �Ự���ķ��� */
typedef enum SESSION_PKT_DIR
{	
    SESSION_DIR_ORIGINAL, /*����: ���ķ���Ϊ�ӷ��𷽵���Ӧ��*/        
    SESSION_DIR_REPLY,    /*����: ���ķ���Ϊ����Ӧ��������*/
    SESSION_DIR_BOTH
}SESSION_PKT_DIR_E;

/*DCCPЭ��״̬����*/
typedef enum tagDccp_state
{
    DCCP_ST_NONE,
    DCCP_ST_REQUEST,
    DCCP_ST_RESPOND,
    DCCP_ST_PARTOPEN,    
    DCCP_ST_OPEN,    
    DCCP_ST_CLOSEREQ,    
    DCCP_ST_CLOSING,    
    DCCP_ST_TIMEWAIT,    
    DCCP_ST_MAX,
    DCCP_ST_IGNORE
}DCCP_STATE_E;

/*ICMPЭ��״̬����*/
typedef enum tagIcmp_state
{
    ICMP_ST_NONE,
    ICMP_ST_REQUEST,
    ICMP_ST_REPLY,
    ICMP_ST_MAX
}ICMP_STATE_E;

/*RAWIPЭ��״̬����*/
typedef enum tagRawip_state
{
    RAWIP_ST_NONE,
    RAWIP_ST_OPEN,
    RAWIP_ST_READY,
    RAWIP_ST_MAX
}RAWIP_STATE_E;

/*SCTPЭ��״̬����*/
typedef enum tagSctp_state
{
    SCTP_ST_NONE,
    SCTP_ST_CLOSED,
    SCTP_ST_COOKIE_WAIT,
    SCTP_ST_COOKIE_ECHOED,   
    SCTP_ST_ESTABLISHED,
    SCTP_ST_SHUTDOWN_SENT,
    SCTP_ST_SHUTDOWN_RECD,
    SCTP_ST_SHUTDOWN_ACK_SENT,
    SCTP_ST_MAX
}SCTP_STATE_E;

/*TCPЭ��״̬����*/
typedef enum tagTcp_state
{
    TCP_ST_NONE,
    TCP_ST_SYN_SENT,
    TCP_ST_SYN_RECV,
    TCP_ST_ESTABLISHED,   
    TCP_ST_FIN_WAIT,
    TCP_ST_CLOSE_WAIT,
    TCP_ST_LAST_ACK,
    TCP_ST_TIME_WAIT,
    TCP_ST_CLOSE,
    TCP_ST_SYN_SENT2,    
    TCP_ST_MAX,
    TCP_ST_IGNORE
}TCP_STATE_E;

/*UDPЭ��״̬����*/
typedef enum tagUdp_state
{
    UDP_ST_NONE,
    UDP_ST_OPEN,
    UDP_ST_READY,
    UDP_ST_MAX
}UDP_STATE_E;

/*UDP-LiteЭ��״̬����*/
typedef enum tagUdplite_state
{
    UDPLITE_ST_NONE,
    UDPLITE_ST_OPEN,
    UDPLITE_ST_READY,        
    UDPLITE_ST_MAX,
}UDPLITE_STATE_E;

/*�Ĳ�Э��״̬�ϻ�ʱ�����ͣ������Ҫ����������ͣ�����ؼ������*/
typedef enum tagSESSION_PROT_AGING_Type
{
    SESSION_PROT_AGING_TCPSYN = 0,        
    SESSION_PROT_AGING_TCPEST,    
    SESSION_PROT_AGING_TCPFIN,
    SESSION_PROT_AGING_UDPOPEN,    
    SESSION_PROT_AGING_UDPREADY,    
    SESSION_PROT_AGING_ICMPREQUEST,    
    SESSION_PROT_AGING_ICMPREPLY,
    SESSION_PROT_AGING_RAWIPOPEN,    
    SESSION_PROT_AGING_RAWIPREADY,  
    SESSION_PROT_AGING_UDPLITEOPEN,    
    SESSION_PROT_AGING_UDPLITEREADY, 
    SESSION_PROT_AGING_DCCPREQUEST,    
    SESSION_PROT_AGING_DCCPEST,    
    SESSION_PROT_AGING_DCCPCLOSEREQ,
    SESSION_PROT_AGING_SCTPINIT,    
    SESSION_PROT_AGING_SCTPEST,    
    SESSION_PROT_AGING_SCTPSHUTDOWN,    
    SESSION_PROT_AGING_ICMPV6REQUEST,
    SESSION_PROT_AGING_ICMPV6REPLY,    
    SESSION_PROT_AGING_MAX  
}SESSION_PROT_AGING_TYPE_E;


typedef union tagSessionInetAddr
{
    UINT auiAll[4];
    UINT uiIp;         /* Ipv4��ַ */
    UINT auiIp6[4];    /* Ipv6��ַ */
    struct in_addr  stin;     /* Ipv4��ַ */
    struct in6_addr stin6;   /* Ipv6��ַ */
}SESSION_INET_ADDR_U;

typedef union tagSessionProtoSrc
{
    USHORT usAll;
    struct
    {
        USHORT usPort;         /* TCPЭ���Դ�˿� */
    }stTcp;
    struct
    {
        USHORT usPort;         /* UDPЭ���Դ�˿� */
    }stUdp;
    struct
    {
        USHORT usPort;         /* UDP-LiteЭ���Դ�˿� */
    }stUdpLite;
	struct
    {
        USHORT usSeq;          /* ICMPЭ���е�Seq�ֶ� */
    }stIcmp;
    struct
    {
        USHORT usId;           /* ICMPv6Э���е�ID�ֶ� */
    }stIcmpv6;
    struct
    {
        USHORT usPort;         /* DCCPЭ���Դ�˿� */
    }stDccp;
    struct
    {
        USHORT usPort;         /* SCTPЭ���Դ�˿� */
    }stSctp;
    struct
    {
        USHORT usKey;          /* GRE key is 32bit, PPtp only uses 16bit */         
    }stGre;
}SESSION_PROTO_SRC_U;

typedef union tagSessionProtoDst
{
    USHORT usAll;
    struct
    {
        USHORT usPort;         /* TCPЭ���Ŀ�Ķ˿� */
    }stTcp;
    struct
    {
        USHORT usPort;         /* UDPЭ���Ŀ�Ķ˿� */
    }stUdp;
    struct
    {
        USHORT usPort;         /* UDP-LiteЭ���Ŀ�Ķ˿� */
    }stUdpLite;
	struct
    {
        USHORT usId;           /* ICMPЭ���е�ID�ֶ� */
    }stIcmp;
    struct
    {
        UCHAR ucType;          /* ICMPv6Э���е�type�ֶ� */
        UCHAR ucCode;          /* ICMPv6Э���е�code�ֶ� */
    }stIcmpv6;
    struct
    {
        USHORT usPort;         /* DCCPЭ���Ŀ�Ķ˿� */
    }stDccp;
    struct
    {
        USHORT usPort;         /* SCTPЭ���Ŀ�Ķ˿� */
    }stSctp;
    struct
    {
        USHORT usKey;          /* GRE key is 32bit, PPtp only uses 16bit */         
    }stGre;
}SESSION_PROTO_DST_U;

/* �Ự����Ự����ỰKey */
typedef struct tagSessionTupleStruct
{
    UCHAR ucL3Family;               /* �Ự���ĵ�����Э�����ͣ��ο�SESSION_L3_TYPE_E */
    UCHAR ucProtocol;               /* �Ự���ĵ��Ĳ�Э�����ͣ��ο�SESSION_L4_TYPE_E */
    UCHAR ucType;                   /* �Ự���ͣ���ʶ�Ƿ��Ƕ���ת��(��Ӧcachekey�е�ucType����
                                       ������(��ӦstCacheRoute.ucMCType)*/
    UCHAR ucRsv2;                   /* ����ֶ�*/
    SESSION_INET_ADDR_U unL3Src;    /* ԴIP��ַ */    
    SESSION_INET_ADDR_U unL3Dst;    /* Ŀ��IP��ַ */
    SESSION_PROTO_SRC_U unL4Src;    /* Դ�˿� */
    SESSION_PROTO_DST_U unL4Dst;    /* Ŀ�Ķ˿� */
    UINT                uiTunnelID; /* Tunnel-ID */
    VRF_INDEX vrfIndex;             /* ������VPN VRF ID, 0��ʾ���� */
}SESSION_TUPLE_S;

typedef enum SESSION_APP_DIR
{
    DIR_IGNORE_PARENT = 0, /* �ӻỰ�ױ��ķ��𷽺���Ӧ���͸��Ựһ���ϵ��û�У�
                              һ����ԣ���Ӧ�����������ӻỰ���ڣ��ӹ�����Э�̽Ƕ���˵��
                              ����Ӧ���븸�Ự�ķ��𷽻���Ӧ���κ�һ������ϵ*/
    DIR_PARENT_SRC_2_DST,  /* �ӻỰ�ױ��ķ��𷢺���Ӧ���븸�Ự�ϸ���ͬ */
    DIR_PARENT_DST_2_SRC,  /* �ӻỰ�ױ��ķ��𷢺���Ӧ���븸�Ự�ϸ��෴ */
    DIR_PARENT_SRC_2_ANY,  /* �ӻỰ�ױ��ķ����븸�Ự�ױ��ķ�����ͬ��
                              ���ӻỰ�ױ�����Ӧ����ͬ�ڸ��Ự�ױ�����Ӧ�� */
    DIR_PARENT_ANY_2_SRC,  /* �ӻỰ�ױ�����Ӧ���븸�Ự�ױ��ķ�����ͬ��
                              ���ӻỰ�ױ��ķ��𷽲�ͬ�ڸ��Ự�ױ�����Ӧ�� */
    DIT_PARENT_MAX = 0x0F
}SESSION_CHILD_DIR_E;

/* �ϻ�ʱ����Чֵ */
#define SESSION_INVALID_VALUE       0
#define SESSION_CLEARALL_VALUE      100001

#define SESSION_TABLE_DEFAULT_TIMEOUT 2 /* �ỰĬ���ϻ�ʱ�䣬��λΪ�� */

/*�����ỰĬ���ϻ�ʱ��*/
#define SESSION_FASTDROP_DEFAULT_TIME  3
#define SESSION_FASTDROP_DEFAULT_RATIO 20

/* �����Ựʹ��BITλ�궨�� */
#define SESSION_FAST_DROP_BIT_INVLID            0x0000
#define SESSION_FAST_DROP_BIT_ASPF_ENABLE       0x0001
#define SESSION_FAST_DROP_BIT_CONNLIMIT_ENABLE  0x0002
#define SESSION_FAST_DROP_BIT_ALL_ENABLE        (SESSION_FAST_DROP_BIT_ASPF_ENABLE | \
                                                 SESSION_FAST_DROP_BIT_CONNLIMIT_ENABLE)

#define SESSION_CORE_NUM_INVALID  ((UINT)-1)
/* ACL�����ţ�����log��persistent */
#define SESSION_CFG_ACLNUM_NONE   0                          /* ������ */
#define SESSION_CFG_ACLNUM_ALL    0xFFFFFFFF                 /* ͨ�� */

/*���Ĳ�Э������״̬����*/
#define SESSION_PROTOCOL_STATE_MAX  10

/* ��ȡ�Ự����ʱ�� */
#define SESSION_TABLE_GET_CREATE_TIME(_pSession, _uiCreateTime) \
    ((_uiCreateTime) = (((SESSION_S *)(_pSession))->stSessionBase.uiSessCreateTime))
    
typedef enum tagDebugEventType
{
    EVENT_CREATE,         /* �����,*/
    EVENT_DELETE,
    EVENT_CLEAR,
    EVENT_UPDATE,
    EVENT_BACKUP,
    EVENT_RESTORE,
    EVENT_ADD,
    EVENT_DEL,
    EVENT_GET,
    EVENT_FORMATFAILED,
    EVENT,
    EVENT_DROPPKT,
    EVENT_MAX
}SESSION_DEBUG_EVENT_E;

typedef enum tagDebugOpReason
{
	DBG_REASON_MODCALL,
	DBG_REASON_TIMEOUT,
	DBG_REASON_CHILDFUL,
	DBG_REASON_MODCALLORCHILDFUL,
	DBG_REASON_WITH_SESSION,
	DBG_REASON_WITH_PARENTKEY,
	DBG_REASON_CREATE,
	DBG_REASON_ADDASSQUE,
	DBG_REASON_UPDATE,
	DBG_REASON_DELETE,
	DBG_REASON_FILLINFO,
	DBG_REASON_ADD_GLOBAL,
	DBG_REASON_ADD_LOCAL,
	DBG_REASON_MAX
}SESSION_REASON_OP_E;

/* IPv4��IPv6ʹ�õ�ͨ��IP��ַ�ṹ. ���еĵ�ַ����洢Ϊ������ */
typedef struct tagINET_ADDR
{
    uint16_t usFamily;             /* ��ַЭ����(AF_INET/AF_INET6) */
    uint16_t usReserved;           /* �����ֶ� */
    union
    {
        struct in6_addr stIP6Addr;
        struct in_addr  stIP4Addr;
    } un_addr;                   /* IP��ַ�ֶ� */

    #define uIP6_Addr    un_addr.stIP6Addr
    #define uIP4_Addr    un_addr.stIP4Addr
}INET_ADDR_S;

/* �������е�NAT��չ���� */
typedef struct tagRelationAttachInfo
{
    IF_INDEX ifIndex;        /* ALG �غɴ������ڽӿڣ���ת��ʹ�õ�NAT�������ڽӿڿ��ܲ�ͬ(hairpin��ʽ��)*/
    UINT uiNewTunnelID;      /* �ӻỰ�ױ���ת�����TUNNELID */
    INET_ADDR_S stNewDstIP;  /* �ӻỰ�ױ���ת�����Ŀ�ĵ�ַ */
    USHORT usNewDstPort;     /* �ӻỰ�ױ���ת�����Ŀ�Ķ˿� */
    USHORT usNewVpnID;       /* �ӻỰ�ױ���ת�����route vpn */
    USHORT usMdcId;
    UCHAR ucProtocol;        /* �Ĳ�Э������ */
    UCHAR ucArpPnpFlag;
    USHORT usCfgFlag;        /* NAT�������� */
}RELATION_ATTACH_INFO_S;

#define TCP_FLAGS_CARE_MASK (~(TH_PUSH|TH_ECE|TH_CWR))
#define TCP_PKT_BITTYPE_MAX ((TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG) + 1)

enum tagTcp_pkt_type {
    TCP_PKT_SYN,
    TCP_PKT_SYNACK,
    TCP_PKT_FIN,
    TCP_PKT_ACK,
    TCP_PKT_RST,
    TCP_PKT_NONE,
    TCP_PKT_MAX
};

#define sTCP_NO TCP_ST_NONE
#define sTCP_SS TCP_ST_SYN_SENT
#define sTCP_SR TCP_ST_SYN_RECV
#define sTCP_ES TCP_ST_ESTABLISHED
#define sTCP_FW TCP_ST_FIN_WAIT
#define sTCP_CW TCP_ST_CLOSE_WAIT
#define sTCP_LA TCP_ST_LAST_ACK
#define sTCP_TW TCP_ST_TIME_WAIT
#define sTCP_CL TCP_ST_CLOSE
#define sTCP_S2 TCP_ST_SYN_SENT2
#define sTCP_IV TCP_ST_MAX
#define sTCP_IG TCP_ST_IGNORE

extern UCHAR g_aucTcpPktType[];
extern UCHAR g_aucTcp_state_table[SESSION_DIR_BOTH][TCP_PKT_MAX][TCP_ST_MAX];


typedef struct tagSessionRefCount
{
    rte_atomic32_t stCount;
}SESSION_REF_COUNT_S;

/*�Ự�����ͳ����Ϣ*/
typedef struct tagSessionNativeStat
{
    rte_atomic32_t astPackets[SESSION_DIR_BOTH]; /*�Ự������ͳ����Ϣ*/
    rte_atomic32_t astBytes[SESSION_DIR_BOTH];   /*�Ự�ֽ���ͳ����Ϣ*/
}SESSION_NATIVE_STAT_S;

typedef struct tagSessionProto
{
    union
    {
        struct
        {
            UCHAR aucRole[SESSION_DIR_BOTH];
        } stDccp;
        struct
        {
            UINT auiVtag[SESSION_DIR_BOTH];
        } stSctp;
    }u;
}SESSION_PROTO_S;

/* ȫ��ͳ����Ϣ�ṹ���� */
typedef struct tagSessionRateStatistics
{
    UINT uiLastSecondRate;
    UINT uiCurrCount;
    ULONG ulLastJiffies;
}SESSION_RATE_STAT_S;

typedef struct tagSessionFlowStatitics
{
    UINT64 uiBytesCount;
    UINT64 uiPacketsCount;
}SESSION_FLOW_STAT_S;

typedef struct tagSessionStatVCPU
{
    SESSION_RATE_STAT_S astRateStat[SESSION_L4_TYPE_MAX]; /* ÿ��ÿL4Э��ĻỰ�½�����,��һ���ֵ */
    SESSION_FLOW_STAT_S astFlowStat[SESSION_L4_TYPE_MAX]; /* ÿ��ÿL4Э��İ��������ֽ�ͳ�� */
    SESSION_RATE_STAT_S stRelateTableRateStat;            /* ������������ͳ�� */
}SESSION_STAT_VCPU_S;

/* �Ự���м�¼��ҵ��ģ��ID */
typedef enum SESSION_Module
{
    SESSION_MODULE_NAT = 0,            /* NATģ�� */
    SESSION_MODULE_CONNLMT,            /* �Ự-����������ģ�� */
    SESSION_MODULE_LB,                 /* LBģ�� */
    SESSION_MODULE_ASPF,               /* ASPFģ�� */
    SESSION_MODULE_LOG,                /* �Ự����-LOG��ģ�� */
    SESSION_MODULE_ALG,                /* �Ự����ALGģ�� */
    SESSION_MODULE_DSLITE,             /* DS-Lite ģ�� */
    SESSION_MODULE_TCPMSS,             /* TCP MSS ģ�� */
    SESSION_MODULE_APPSTATICS,         /* Ӧ��ͳ�� */
    SESSION_MODULE_INTERZONE,          /* ���ҵ�� */
    SESSION_MODULE_WAAS,               /* WAASҵ�� */
    SESSION_MODULE_TCPCHECK,           /* TCP���кż����ģ�� */
    SESSION_MODULE_AFT,                /* AFTģ�� */
    SESSION_MODULE_DIM,                /* DIM���洦����ģ�� */
    SESSION_MODULE_TCPREASSEMBLE,      /* TCP�������洦��ģ�� */
    SESSION_MODULE_TRAFFICLOG,         /* �Ự������־ҵ�� */
    SESSION_MODULE_MAX
}SESSION_MODULE_E;

/* �Ựͳ����Ϣ */
typedef struct tagSessionStatistics
{
    UINT uiTotalSessNum;
    UINT uiTotalRelationNum;
    UINT auiProtoStateCount[SESSION_L4_TYPE_MAX][SESSION_PROTOCOL_STATE_MAX];
    UINT auiRateStat[SESSION_L4_TYPE_MAX];
    SESSION_FLOW_STAT_S astFlowStat[SESSION_L4_TYPE_MAX];
    UINT64 auiSessAllStatCount[SESSION_ALLSTAT_TYPE_MAX];
    UINT auiAgentCount[SESSION_AGENT_DATA_MAX];
    UINT auiAppStat[SESSION_APP_STATIC_MAX];
    UINT auiRelationRateStat;
    SESSION_NUM_STATISTICS_S astMaxSessNumStat[SESSION_NUMRATE_TYPE_MAX];  /*�����Ự���������ֵ*/
    SESSION_NUM_STATISTICS_S astMaxSessRateStat[SESSION_NUMRATE_TYPE_MAX]; /*�����Ự�½��������ֵ*/
}SESSION_STATISTICS_S;

typedef struct tagSessionKStatistics
{
    rte_atomic32_t stTotalSessNum;                                /* �Ự���� */
    rte_atomic32_t stTotalRelationNum;                            /* ���������� */
    rte_atomic32_t astProtoCount[SESSION_L4_TYPE_MAX];            /* ��L4Э���Ӧ�ĻỰ�� */
    rte_atomic64_t astSessAllStatCount[SESSION_ALLSTAT_TYPE_MAX]; /* ����ͳ�Ƽ��� */
    SESSION_STAT_VCPU_S *pstVcpuStat;
    rte_atomic32_t astAppCount[SESSION_APP_STATIC_MAX];
    ULONG ulLastJiffies;
}SESSION_K_STATISTICS_S;

/* alg �쳣ͳ����Ϣ */
typedef struct tagSessionPerCpuAlgFailCnt
{
    rte_atomic32_t astAlgFailCntGlobal4[SESSION_ALG_STAT_TYPE_MAX][SESSION_ALG_FAIL_TYPE_MAX];    
    rte_atomic32_t astAlgFailCntGlobal6[SESSION_ALG_FAIL_TYPE_MAX]; /*Ŀǰipv6ֻ֧��FTP*/    
    rte_atomic32_t astAlgFailCntAcl4[SESSION_ALG_STAT_TYPE_MAX][SESSION_ALG_FAIL_TYPE_MAX];      
    rte_atomic32_t astAlgFailCntAcl6[SESSION_ALG_FAIL_TYPE_MAX];    
}SESSION_ALGFAILCNT_VCPU_S;

typedef struct tagSessionAlgFailCnt
{
    SESSION_ALGFAILCNT_VCPU_S *pstVcpuAlgFailCnt;
}SESSION_ALGFAILCNT_S;

typedef struct tagSessionAlgStatSwitch
{
    UINT uiAclNum;
}SESSION_ALGSTAT_SWITCH_S;

typedef enum tagSessionTbaleBits
{
    SESSION_DELETING        = 0x01,
    SESSION_PERSIST         = 0x02,
    SESSION_TEMP            = 0x04,
    SESSION_LOG_NORMAL      = 0x08,    
    SESSION_LOG_TIME        = 0x10,
    SESSION_LOG_FLOW_BYTE   = 0x20,
    SESSION_LOG_FLOW_PACKET = 0x40,
    SESSION_DELTYPE_AGING   = 0x80,
    SESSION_DELTYPE_CFG     = 0x100,
    SESSION_DELTYPE_OTHER   = 0x200,
    SESSION_CACHE_DELETED   = 0x400,    
    SESSION_LOG_ENABLE      = 0x800,
    SESSION_FLT_FAST        = 0x1000,
    SESSION_IPV6            = 0x2000,
    SESSION_DEL_NON_PERSIST_RELATION = 0x4000,
    SESSION_NAT_CGN         = 0x8000,
}SESSION_TABLE_BITS_E;

/* ��Ҫ���Ựҵ����չָ��ӵ�session�ṹ��pServicCb�е�ҵ��ģ�� */
typedef enum SESSION_Service
{
    SESSION_SERVICE_NAT = 0,       /*uiServicePos��0-3λ��¼NAT��չ��Ϣ��pServiceCb��λ��*/
    SESSION_SERVICE_CONNLMT,       /*uiServicePos��4-7λ��¼CONNLMT��չ��Ϣ��pServiceCb��λ��*/
    SESSION_SERVICE_LB,            /*uiServicePos��8-11λ��¼LB��չ��Ϣ��pServiceCb��λ��*/
    SESSION_SERVICE_WAAS,          /*uiServicePos��12-15λ��¼WAAS��չ��Ϣ��pServiceCb��λ��*/
    SESSION_SERVICE_ALG,           /*uiServicePos��16-19λ��¼ALG��չ��Ϣ��pServiceCb��λ��*/
    SESSION_SERVICE_TCPCHECK,      /*uiServicePos��20-23λ��¼TCP check��չ��Ϣ��pServiceCb��λ��*/
    SESSION_SERVICE_AFT,           /*uiServicePos��24-27λ��¼AFT��չ��Ϣ��pServiceCb��λ��*/
    SESSION_SERVICE_DIM,           /*uiServicePos��28-31λ��¼DIM��չ��Ϣ��pServiceCb��λ��*/
    SESSION_SERVICE_TCPREASSEMBLE, /*uiServicePos��32-35λ��¼TCP������չ��Ϣ��pServiceCb��λ��*/
    SESSION_SERVICE_TRAFFICLOG,    /*uiServicePos��36-39λ��¼������־��չ��Ϣ��pServiceCb��λ��*/
    SESSION_SERVICE_MAX,
    SESSION_SERVICE_STATIC = (UCHAR)-1, /*��ָ̬�룬��ʶҵ��ģ���ԷǶ�̬��ʽ����չ��Ϣ*/
}SESSION_SERVICE_E;

/* �Ự����Ϣkey */
typedef struct tagSessionResetTableKey
{
    SESSION_TUPLE_S stTuple; /* �Ự��key��Ϣ */
    UINT uiModuleFlag;       /* �Ựģ��ID,�ο�SESSION_MODULE_E */
    UINT uiMask;             /* ʹ��SESSION_TABLE_BIT_E��ʶ��Щ������Ч*/
    UCHAR ucSessType;        /* �Ựת���˵�4��Э�����ͣ��ο�SESSION_L4_TYPE_E */
    UINT uiIdentityID;
    UINT uiStopSession;      /* ֹͣ�Ự�� */
    ZONE_ID zoneIDSrcID;
    ZONE_ID zoneIDDestID;
    UCHAR ucState;
    UINT uiAppID;  /* Ӧ��Э��ID */
    UINT uiStartTime;
    UINT uiEndTime;
    IF_INDEX ifIndex;
    UINT uiRuleID;
    UINT uiPolicyID;
}SESSION_TABLE_KEY_S;

/* ɾ���Ự�Ĳ�����Ϣ */
typedef struct tag_SessionResetMsgObjInfo
{
    AGINGQUEUE_RST_MSG_OBJECT_S stRstObj;
    SESSION_TABLE_KEY_S stKey;
}SESSION_RESET_OBJ_S;

/* �Ự����λ */
typedef enum tagSESSION_TABLE_BIT
{
    SESSION_TABLE_BIT_PROT = 0,         /*��ʶ�Ự��4��Э������*/
    SESSION_TABLE_BIT_SRCIP,            /*��ʶSESSION_TUPLE_S�е�ԴIP�ֶ�*/
    SESSION_TABLE_BIT_DSTIP,            /*��ʶSESSION_TUPLE_S�е�Ŀ��IP�ֶ�*/
    SESSION_TABLE_BIT_SRCPORT,          /*��ʶSESSION_TUPLE_S�е�Դ�˿��ֶ�*/
    SESSION_TABLE_BIT_DSTPORT,          /*��ʶSESSION_TUPLE_S�е�Ŀ�Ķ˿��ֶ�*/
    SESSION_TABLE_BIT_VPNID,            /*��ʶSESSION_TUPLE_S�е�VPN VRF ID�ֶ�*/
    SESSION_TABLE_BIT_MODULE,           /*��ʶ�Ựҵ��ģ��*/
    SESSION_TABLE_BIT_USERID,           /*��ʶ�Ự�û�ID*/
    SESSION_TABLE_BIT_USERGRPID,        /*��ʶ�Ự�û���ID*/
    SESSION_TABLE_BIT_RESPVPNID,        /*��ʶ�Ự��Ӧ��VPN*/
    SESSION_TABLE_BIT_LOCALCREATE,      /*��ʶ�Ự���*/
    SESSION_TABLE_BIT_RESPONDER,        /*��ʶ��Ӧ��*/
    SESSION_TABLE_BIT_STOP,             /*��ʶSESSION STOP��ʱ���*/
    SESSION_TABLE_BIT_APP,              /*��ʶӦ�ò�Э��*/
    SESSION_TABLE_BIT_ZONE,             /*��ʶԴ��*/
    SESSION_TABLE_BIT_STATE,            /*��ʶЭ��״̬*/
    SESSION_TABLE_BIT_IFINDEX,          /*��ʶ�Ự�ӿ�*/
    SESSION_TABLE_BIT_APPNAME,          /*��ʶӦ��application*/
    SESSION_TABLE_BIT_SECPNAME,         /*��ʶ��ȫ��������*/
    SESSION_TABLE_BIT_TIMERANGE,        /*��ʶʱ���*/
    SESSION_TABLE_BIT_DSTZONE,          /*��ʶĿ����*/
    SESSION_TABLE_BIT_DENYSESSION,      /*��ʶ�Ự����Ϊ�����Ự*/
}SESSION_TABLE_BIT_E;

#define SESSION_SET_PARABIT(_Flag, _Bit)  ((_Flag) |= ((UINT)1 << (_Bit)))
#define SESSION_CLEAR_PARABIT(_Flag,_Bit) ((_Flag) &= ~((UINT)1 << (_Bit)))
#define SESSION_IS_PARABIT_SET(_Flag, _Bit) (0 != ((_Flag) & ((UINT)1 << (_Bit))))

/*��ɾ���Ự������ú��ж�*/
#define SESSION_KEY_SET_PROT(_Mask)         SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_PROT)
#define SESSION_KEY_IS_PROTSET(_Mask)       SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_PROT)

#define SESSION_KEY_SET_SRCIP(_Mask)        SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_SRCIP)
#define SESSION_KEY_IS_SRCIPSET(_Mask)      SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_SRCIP)

#define SESSION_KEY_SET_DSTIP(_Mask)        SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_DSTIP)
#define SESSION_KEY_IS_DSTIPSET(_Mask)      SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_DSTIP)

#define SESSION_KEY_SET_SRCPORT(_Mask)      SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_SRCPORT)
#define SESSION_KEY_IS_SRCPORTSET(_Mask)    SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_SRCPORT)

#define SESSION_KEY_SET_DSTORT(_Mask)       SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_DSTPORT)
#define SESSION_KEY_IS_DSTPORTSET(_Mask)    SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_DSTPORT)

#define SESSION_KEY_SET_VPNID(_Mask)        SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_VPNID)
#define SESSION_KEY_IS_VPNIDSET(_Mask)      SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_VPNID)

#define SESSION_KEY_SET_MODULE(_Mask)       SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_MODULE)
#define SESSION_KEY_IS_MODULESET(_Mask)     SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_MODULE)

#define SESSION_KEY_SET_USERID(_Mask)       SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_USERID)
#define SESSION_KEY_IS_USERIDSET(_Mask)     SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_USERID)

#define SESSION_KEY_SET_USERGRPID(_Mask)    SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_USERGRPID)
#define SESSION_KEY_IS_USERGRPIDSET(_Mask)  SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_USERGRPID)

#define SESSION_KEY_SET_RESP_VPNID(_Mask)   SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_RESPVPNID)
#define SESSION_KEY_IS_RESP_VPNID(_Mask)    SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_RESPVPNID)

#define SESSION_KEY_SET_LOCALCREATE(_Mask)  SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_LOCALCREATE)
#define SESSION_KEY_IS_LOCALCREATESET(_Mask) SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_LOCALCREATE)

#define SESSION_KEY_SET_RESPONDER(_Mask)    SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_RESPONDER)
#define SESSION_KEY_IS_RESPONDER(_Mask)     SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_RESPONDER)

#define SESSION_KEY_SET_STOP(_Mask)         SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_STOP)
#define SESSION_KEY_IS_STOP(_Mask)          SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_STOP)

#define SESSION_KEY_SET_APP(_Mask)          SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_APP)
#define SESSION_KEY_IS_APPSET(_Mask)        SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_APP)

#define SESSION_KEY_SET_ZONE(_Mask)         SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_ZONE)
#define SESSION_KEY_IS_ZONESET(_Mask)       SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_ZONE)

#define SESSION_KEY_SET_DSTZONE(_Mask)      SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_DSTZONE)
#define SESSION_KEY_IS_DSTZONESET(_Mask)    SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_DSTZONE)

#define SESSION_KEY_SET_STATE(_Mask)        SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_STATE)
#define SESSION_KEY_IS_STATESET(_Mask)      SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_STATE)

#define SESSION_KEY_SET_IFINDEX(_Mask)      SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_IFINDEX)
#define SESSION_KEY_IS_IFINDEX(_Mask)       SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_IFINDEX)

#define SESSION_KEY_SET_APPNAME(_Mask)      SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_APPNAME)
#define SESSION_KEY_IS_APPNAMESET(_Mask)    SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_APPNAME)

#define SESSION_KEY_SET_SECPNAME(_Mask)     SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_SECPNAME)
#define SESSION_KEY_IS_SECPNAME(_Mask)      SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_SECPNAME)

#define SESSION_KEY_SET_TIMERANGE(_Mask)    SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_TIMERANGE)
#define SESSION_KEY_IS_TIMERANGESET(_Mask)  SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_TIMERANGE)

#define SESSION_KEY_SET_DENYSESSION(_Mask)  SESSION_SET_PARABIT(_Mask, SESSION_TABLE_BIT_DENYSESSION)
#define SESSION_KEY_IS_DENYSESSION(_Mask)   SESSION_IS_PARABIT_SET(_Mask, SESSION_TABLE_BIT_DENYSESSION)


/* ��¼��MBUF�еĻỰ���λ������ǰ�ĸ���Ƕ�����mbuf.h�У�SESSION������������ı�ǣ�
 * ��ע��Ự��Ҫ��mbuf.h�ж����λ�����塣
 */

/* Ӧ�ò�Э��������󳤶�*/
#define SESSION_APPNAME_MAX_LEN     63UL


/* ��Ʒ���ƻỰ��������� */
typedef struct tagSESSIONConf
{
    UINT uiMaxSessionEntries;
}SESSION_CONF_S;

typedef struct tagSessionALGPacket
{
    SESSION_KALG_SEQ_CHECK_PF    pfAlgSeqCheckProc;      /* ALG�����кŵ�����ת������ */
    SESSION_KALG_FS_SEQ_CHECK_PF pfAlgFsSeqCheckProc;    /* ALG�����кŵ�����ת������ */
    SESSION_KALG_SET_ACTION_PF   pfAlgSetAction;         /* ALG��Ӧ�ò�״̬���˴����� */
    SESSION_KALG_PPTPGREDATA_PF  pfAlgPptpGreData;       /* ALG��pptp gre data������  */
    SESSION_KALG_SIPEST_PF       pfAlgSipEstProc;        /* ALG��sip��̬������ */
}SESSION_KALG_PACKET_PROC_S;

typedef enum tagSessionAppType
{
    SESSION_APP_TYPE_SYSTEM,
	SESSION_APP_TYPE_USER,
	SESSION_APP_TYPE_MAX
}SESSION_APP_TYPE_E;

typedef struct tagSessionAppMsg
{
	UINT uiAppID;
	UINT uiTimeValue;
	SESSION_APP_TYPE_E enAppType;
	CHAR szAppName[SESSION_APPNAME_MAX_LEN + 1];
}SESSION_APP_S;

/* �Ĳ�Э���ϻ�ʱ�����ýṹ */
typedef struct tagSessionL4Aging
{
	SESSION_PROT_AGING_TYPE_E enL4Type;
	UINT                      uiTimeValue;
	UINT                      uiTimeWaitAging; /* time_wait״̬�ϻ�ʱ�䣬��λΪ�� */
	UINT                      uiCloseAging;    /* close״̬�ϻ�ʱ�䣬��λΪ�� */
}SESSION_L4AGING_S;

/* �����Ự���ý�� */
typedef struct tagSessionFDAging
{
	UINT uiTimeValue;
}SESSION_FASTDROP_AGING_S;

typedef struct tagSessionFDRatio
{
	UINT uiRatioValue;
}SESSION_FASTDROP_RATIO_S;

/* �Ự��־�������ýṹ */
typedef struct tagSESSION_CfgLogPolicy
{
	IF_INDEX          ifIndex;
	UINT              uiAcNum;
	SESSION_L3_TYPE_E enL3Type;
	DIRECTION_E       enDirection;
	BOOL_T            bIsEnable;
}SESSION_CFG_LOGPOLICY_S;

/* �Ự��־������ֵ���ýṹ */
typedef struct tagSESSION_LogFlow
{
	SESSION_LOG_FLOWMODE_E enMode;
	UINT                   uiValue;
}SESSION_LOG_FLOW_S;

/* ע�⣬�ýṹ���ֵ����comsh���ػ����̼䴫�ݣ�����issu������ؽ���ֵ
	��ӵ����*/
typedef enum tagSESSION_APP_AGING_TYPE
{
    SESSION_APP_AGING_DNS = 0,
    SESSION_APP_AGING_FTP,
    SESSION_APP_AGING_GTP,
    SESSION_APP_AGING_H225,
    SESSION_APP_AGING_H245,
    SESSION_APP_AGING_RAS,
    SESSION_APP_AGING_RTSP,
    SESSION_APP_AGING_SIP,
    SESSION_APP_AGING_TFTP,
    SESSION_APP_AGING_ILS,
    SESSION_APP_AGING_MGCP,
    SESSION_APP_AGING_NBT,
    SESSION_APP_AGING_PPTP,
    SESSION_APP_AGING_RSH,
    SESSION_APP_AGING_SCCP,
    SESSION_APP_AGING_SQLNET,
    SESSION_APP_AGING_XDMCP,
    SESSION_APP_AGING_MAX
}SESSION_APP_AGING_TYPE_E;

/* �Ĳ�Э��Ĭ���ϻ�ʱ�䣨��λΪ�룩 */
#define SESSION_TCP_SYN_OPEN_TIME     30    /* TCP�뿪�ỰĬ���ϻ�ʱ�� */
#define SESSION_TCP_FIN_CLOSE_TIME    30    /* TCP��ػỰĬ���ϻ�ʱ�� */
#define SESSION_TCP_ESTABILISHED_TIME 3600  /* TCP��̬�ỰĬ���ϻ�ʱ�� */

#define SESSION_UDP_OPEN_TIME  30  /* UDP�뿪�ỰĬ���ϻ�ʱ�� */
#define SESSION_UDP_READY_TIME 60  /* UDP��̬�ỰĬ���ϻ�ʱ�� */

#define SESSION_ICMP_REQUEST_TIME  10  /* ICMP����ỰĬ���ϻ�ʱ�� */
#define SESSION_ICMP_REPLY_TIME    2   /* ICMP˫��ỰĬ���ϻ�ʱ�� */

#define SESSION_RAWIP_OPEN_TIME    30  /* RAWIP�뿪�ỰĬ���ϻ�ʱ�� */
#define SESSION_RAWIP_READY_TIME   60  /* RAWIP��̬�ỰĬ���ϻ�ʱ�� */

#define SESSION_UDPLITE_OPEN_TIME  30  /* UDPLITE�뿪�ỰĬ���ϻ�ʱ�� */
#define SESSION_UDPLITE_READY_TIME 60  /* UDPLITE��̬�ỰĬ���ϻ�ʱ�� */

#define SESSION_DCCP_REQUEST_OPEN_TIME    30    /* DCCP�뿪�ỰĬ���ϻ�ʱ�� */
#define SESSION_DCCP_CLOSEREQ_CLOSE_TIME  30    /* DCCP��ػỰĬ���ϻ�ʱ�� */
#define SESSION_DCCP_ESTABILISHED_TIME    3600  /* DCCP��̬�ỰĬ���ϻ�ʱ�� */

#define SESSION_SCTP_INIT_OPEN_TIME       30    /* SCTP�뿪�ỰĬ���ϻ�ʱ�� */
#define SESSION_SCTP_SHUTDOWN_CLOSE_TIME  30    /* SCTP��ػỰĬ���ϻ�ʱ�� */
#define SESSION_SCTP_ESTABILISHED_TIME    3600  /* SCTP��̬�ỰĬ���ϻ�ʱ�� */

#define SESSION_ICMPV6_REQUEST_TIME   60    /* ICMPv6����ỰĬ���ϻ�ʱ�� */
#define SESSION_ICMPV6_REPLY_TIME     30    /* ICMPv6˫��ỰĬ���ϻ�ʱ�� */

/* Ӧ�ò�Э��Ĭ���ϻ�ʱ�䣨��λΪ�룩*/
#define SESSION_PRO_FTP_CTRL_TIME   SESSION_TCP_ESTABILISHED_TIME           /*FTP��������Ĭ���ϻ�ʱ��*/
#define SESSION_PRO_DNS_TIME       1       /*DNS�ỰĬ���ϻ�ʱ��*/
#define SESSION_PRO_SIP_TIME       300       /*SIP�ỰĬ���ϻ�ʱ��*/
#define SESSION_PRO_RAS_TIME       300       /*RAS�ỰĬ���ϻ�ʱ��*/
#define SESSION_PRO_H225_TIME      3600        /*H225�ỰĬ���ϻ�ʱ��*/
#define SESSION_PRO_H245_TIME      3600        /*H245�ỰĬ���ϻ�ʱ��*/
#define SESSION_PRO_TFTP_TIME      60        /*TFTP�ỰĬ���ϻ�ʱ��*/
#define SESSION_PRO_GTP_TIME       60       /*GTP�ỰĬ���ϻ�ʱ��*/
#define SESSION_PRO_RTSP_TIME      3600        /*RTSP�ỰĬ���ϻ�ʱ��*/
#define SESSION_PRO_PPTP_TIME      3600        /*PPTP�ỰĬ���ϻ�ʱ��*/
#define SESSION_PRO_ILS_TIME       3600       /*ILS�ỰĬ���ϻ�ʱ��*/
#define SESSION_PRO_NBT_TIME       3600       /*NBT�ỰĬ���ϻ�ʱ��*/
#define SESSION_PRO_SCCP_TIME      3600        /*SCCP�ỰĬ���ϻ�ʱ��*/
#define SESSION_PRO_SQLNET_TIME    600          /*SQLNET�ỰĬ���ϻ�ʱ��*/
#define SESSION_PRO_XDMCP_TIME     3600         /*XDMCP�ỰĬ���ϻ�ʱ��*/
#define SESSION_PRO_MGCP_TIME      60        /*MGCP�ỰĬ���ϻ�ʱ��*/
#define SESSION_PRO_RSH_TIME       60       /*RSH�ỰĬ���ϻ�ʱ��*/

/* Ӧ�ò�Э��Ĭ���ϻ�ʱ��(��λΪ��) */
#define SESSION_APP_DEFAULT_AGING   1200

/* ������Ĭ���ϻ�ʱ�� */
#define SESSION_PERSIST_DEFAULT_TIME  24

typedef enum tagSESSION_STAT_VERSION
{
    SESSION_STAT_IPV4,
    SESSION_STAT_IPV6,
    SESSION_STAT_NR
}SESSION_STAT_VERSION_E;

typedef struct tagSESSION_STAT_FAIL_KEY
{
    SESSION_STAT_VERSION_E enSessionVer;
}SESSION_STAT_FAIL_KEY_S;


/* �Ự���� */
typedef enum enSESSION_TYPE
{
    SESSION_TYPE_NORMAL = 0, /* ��ͨ */
    SESSION_TYPE_MAX
}SESSION_TYPE_E;

/* ȫ�ֻỰ���ƽṹ */
typedef struct tagSessionCtrlData
{
	AGINGQUEUE_UNSTABLE_S stAgingQueue; /* ���ȶ��ϻ�������� */
	SESSION_K_STATISTICS_S stSessStat;
	AGINGQUEUE_UNSTABLE_CLASS_S astTableAgingClass[SESSION_L3_TYPE_MAX][SESSION_L4_TYPE_MAX][SESSION_PROTOCOL_STATE_MAX];
    AGINGQUEUE_UNSTABLE_CLASS_S astAppAgingClass[SESSION_L3_TYPE_MAX][SESSION_APP_AGING_MAX];
    AGINGQUEUE_UNSTABLE_S       stRelationQueue;  /* ������Ĳ��ȶ��ϻ�������� */
    AGINGQUEUE_UNSTABLE_S       stRelationAssociateQueue;   /* ����������Ĳ��ȶ��ϻ�������� */
    AGINGQUEUE_CHANGEABLE_CLASS_S stIpv4RelationChangeClass;
    AGINGQUEUE_CHANGEABLE_CLASS_S stIpv6RelationChangeClass;
    SESSION_KLOG_GPARAM_S stSessionLogInfo;
    USHORT usCfgSeq;
    UINT uiSyncSeq;    /* ͬ��������ţ������ں�����ƽ�� */
    SESSION_DEBUG_S stDebug;
    UINT uiIFExtendEventHandle;
    BOOL_T bIsNewSessPermit; /* �Ƿ������¼�session */
    BOOL_T bIsDelSessPermit; /* �Ƿ�����ɾ��session */
    BOOL_T bIsDebugSwitch; /* debugȫ�ֿ��� */
    SESSION_SYNC_S stBackup; /* �Ự�ȱ����غͷǶԳ��������� */
    BOOL_T bStatEnable; /* ͳ�Ƶ�ȫ�ֿ��� */
    BOOL_T bSecEnable;  /* �Ƿ�����ȫ���� */
    rte_atomic32_t astStatFailCnt[SESSION_STAT_NR][SESSION_STAT_FAIL_TYPE_MAX];
    SESSION_ALGFAILCNT_S stAlgFail;
    SESSION_ALGSTAT_SWITCH_S stAlgStatSwitch;
    rte_spinlock_t stLogLock; /* �Ự�½���Ŀ/���ʸ澯��Ϣ������ */
    AGINGQUEUE_UNSTABLE_CLASS_S stAppDefaultClass;
    AGINGQUEUE_UNSTABLE_CLASS_S stApp6DefaultClass;
    UCHAR *pucTcpStateTable; /* TCP״̬��ָ�� */
} SESSION_CTRL_S;

typedef enum enSESSION_ALG_TYPE
{
    SESSION_ALG_TYPE_FTP,
    SESSION_ALG_TYPE_RAS, 
    SESSION_ALG_TYPE_H225,
    SESSION_ALG_TYPE_H245,  
    SESSION_ALG_TYPE_SIP,
    SESSION_ALG_TYPE_TFTP, 
    SESSION_ALG_TYPE_RTSP,
    SESSION_ALG_TYPE_GTPU, 
    SESSION_ALG_TYPE_GTPC,
    SESSION_ALG_TYPE_GTPVO_T, 
    SESSION_ALG_TYPE_GTPVO_U,
    SESSION_ALG_TYPE_PPTP, 
    SESSION_ALG_TYPE_ILS,
    SESSION_ALG_TYPE_NBNS, 
    SESSION_ALG_TYPE_NBDGM,
    SESSION_ALG_TYPE_NBSS, 
    SESSION_ALG_TYPE_SCCP,
    SESSION_ALG_TYPE_SQLNET, 
    SESSION_ALG_TYPE_XDMCP,
    SESSION_ALG_TYPE_MGCP_C, 
    SESSION_ALG_TYPE_MGCP_G,
    SESSION_ALG_TYPE_RSH, 
    SESSION_ALG_TYPE_HTTP,
    SESSION_ALG_TYPE_SMTP, 
    SESSION_ALG_TYPE_DNS,
    SESSION_ALG_TYPE_MAX, 
}SESSION_ALG_TYPE_E;


/* ������������ͨ�����ͣ���algtype���𣬺��߶�����ǵ�ǰͨ����alg���� */
typedef enum enRELATION_AGING_TYPE
{
	RELATION_AGING_TYPE_FTPDATA,
	RELATION_AGING_TYPE_RAS,
	RELATION_AGING_TYPE_RAS_H225, /* ��ͨ��ras������h225��ͨ�� */	
	RELATION_AGING_TYPE_H225,     /* ��ͨ��h225������h225��ͨ�� */
	RELATION_AGING_TYPE_H245,
	RELATION_AGING_TYPE_RTPRTCP, 
	RELATION_AGING_TYPE_T120, 
	RELATION_AGING_TYPE_SIP, 
	RELATION_AGING_TYPE_TFTP, 
	RELATION_AGING_TYPE_RTSP, 
	RELATION_AGING_TYPE_PPTP,
	RELATION_AGING_TYPE_ILS, 
	RELATION_AGING_TYPE_NBT, 
	RELATION_AGING_TYPE_SCCP, 
	RELATION_AGING_TYPE_SQLNET, 
	RELATION_AGING_TYPE_XDMCP, 
	RELATION_AGING_TYPE_MGCP,
	RELATION_AGING_TYPE_SDP, 
	RELATION_AGING_TYPE_RSH, 
	RELATION_AGING_TYPE_MAX  		
}RELATION_AGING_TYPE_E;

typedef VOID* SESSION_HASH_HANDLE;

typedef ULONG RELATION_HANDLE;

#define SESSION_INVALID_HANDLE  0UL /* ��Ч�ĻỰ��HANDLE */
#define RELATION_INVALID_HANDLE 0UL /* ��Ч�Ĺ�����HANDLE */

typedef struct tagSessionAging 
{ 
    UINT64  uiUpdateTime;                       /*����ʱ��*/
    UCHAR   ucSessionType;                      /*�Ự���� SESSION_TYPE_E*/
    UCHAR   ucSessionL4Type;                    /*�Ự4�����ͣ�ȡֵΪSESSION_L4_TYPE_E*/            
    USHORT  usTableFlag;                        /*�Ự������ ��SESSION_TABLE_BITS_E*/ 
    SESSION_AGING_RCU_U unAgingRcuInfo;         /*�����ϻ�����*/
    VOID *pCache[SESSION_DIR_BOTH];             /*��ʼ����ʱ����/����*/
    SESSION_REF_COUNT_S stRefCount;             /*���ü���*/
#define uiSessCreateTime unAgingRcuInfo.stAgingInfo.ulRcuReserve
}SESSION_BASE_S; 

typedef struct tagSession
{
    SESSION_BASE_S stSessionBase;     /*��ת�ϻ��Ự����*/
    SESSION_NATIVE_STAT_S stNativeStat; /*�Ựͳ��*/
    #define _astPackets stNativeStat.astPackets
    #define _astBytes   stNativeStat.astBytes
    UINT uiAppID;
    UINT uiTrustValue;       /*Ӧ��ʶ����Ŷ�*/
    USHORT usAttachFlag;
    USHORT usModuleFlag;    /*ҵ�����ǣ���SESSION_MODULE_E*/
    USHORT usCfgSeq;        /*�Ựȫ���������*/
    USHORT usAlgFlag;       /*ALG�����ǣ�ҵ��ģ���Ӧ��λ��λ��ʾ��ҵ����Ҫ����ALG����*/
    UCHAR ucState;                      /*״̬*/
    UINT uiOriginalAppID; /*��¼�Ự����ʱ��AppID,�������ᷢ���仯*/
	struct tagSession *pstParent; /*�����˻Ự�ĸ��Ựָ��*/
    DL_HEAD_S stRelationList;        /*����������*/
    VOID *pAlgCb;                    /*ALG��ָ��ռ�*/
    rte_spinlock_t stLock;
    USHORT usSessAlgType; /*��¼�Ự��Ӧ��ALG����*/
    UCHAR  ucDirAssociateWithParent;  /*ȡֵ��Χ:SESSION_CHILD_DIR_E,Ϊ�˽�ʡ�ռ����UCHAR*/
    UCHAR  ucAspfCfgSeq;              /*ASPF �������*/
    UINT   uiDiff;	
    UINT   uiDirect;
    ULONG  aulModuleData[0];          /*��ǰֻ��ALG�ã����ֶα�����ڻỰ�ṹ�����*/
}SESSION_S;

typedef struct SESSION_L3_PROTO
{
    /* ����IP��ַ�Ϸ��Լ�� */
    ULONG (*pfPktCheck)(IN const MBUF_S *pstMBuf, IN UINT uiL3OffSet);

    /* �ӱ��Ļ�ȡ3����Ϣ����ȡ�Ĳ�ͷλ�� */
    VOID (*pfPktToTuple)(IN const MBUF_S *pstMBuf,
                         IN UINT uiL3OffSet,
                         INOUT SESSION_TUPLE_S *pstTuple);

    /* ������Tuple��ȡ����Tuple��3����Ϣ */
    VOID (*pfGetInvertTuple)(IN const SESSION_TUPLE_S *pstOrigTuple,
                             INOUT SESSION_TUPLE_S *pstInverseTuple);

    /* ��ȡ�Ĳ�Э��ź��Ĳ�Э��ͷƫ��λ�� */
    ULONG (*pfGetL4Proto)(IN MBUF_S *pstMBuf,
                          IN UINT uiL3Offset,
                          OUT UINT *puiL4Offset,
                          OUT UCHAR *pucL4ProtoNum,
                          OUT UINT *puiIPLen);
} SESSION_L3_PROTO_S;

typedef struct tagSESSION_L4_PROTO
{
    VOID (*pfPktToTuple)(IN const MBUF_S *pstMBuf,
                         IN UINT uiL3OffSet,
                         IN UINT uiL4Offset,
                         INOUT SESSION_TUPLE_S *pstTuple); /*�ӱ��Ļ�ȡ4����Ϣ*/
    
    VOID (*pfGetInvertTuple)(IN SESSION_S *pstSession,
                             IN const SESSION_TUPLE_S *pstOrigTuple,
                             INOUT SESSION_TUPLE_S *pstInverseTuple); /*������Tuple��ȡ����Tuple��4����Ϣ*/

    ULONG (*pfPacketCheck)(IN MBUF_S *pstMBuf,
                           IN UINT uiL3Offset,
                           IN UINT uiL4Offset); /*���ĵ����Ϸ��Լ��*/

    ULONG (*pfNewSessCheck)(IN const MBUF_S *pstMBuf,
                            IN UINT uiL3OffSet,
                            IN UINT uiL4OffSet); /*�װ������Ự�Ϸ��Լ��*/

    ULONG (*pfFirstPacket)(IN const MBUF_S *pstMBuf,
                           IN UINT uiL4OffSet,
                           INOUT SESSION_S *pstSession); /*�Ự�װ�����*/
    
    ULONG (*pfState)(IN SESSION_S *pstSession,
                     IN MBUF_S *pstMBuf,
                     IN UINT uiL3OffSet,
                     IN UINT uiL4OffSet); /*Э��״̬������*/

    ULONG (*pfFastState)(IN SESSION_S *pstSession,
                         IN UINT uiL3OffSet,
                         IN UINT uiL4OffSet,
                         IN MBUF_S *pstMBuf,
                         IN SESSION_PKT_DIR_E enDir); /*Э��״̬������*/

    ULONG (*pfGetL4Payload)(IN MBUF_S *pstMBuf,
                            IN UINT uiL4OffSet,
                            OUT UINT *puiPayloadOff,
                            OUT UINT *puiPayloadLen); /*����Ĳ����ϵĸ���ƫ�ƺ͸��س���*/

    ULONG (*pfFsbufGetL4Payload)(IN const MBUF_S *pstMBuf,
                                 IN const struct iphdr *pstIP,
                                 IN UINT uiL4OffSet,
                                 OUT UINT *puiPayloadOff,
                                 OUT UINT *puiPayloadLen); /*����Ĳ����ϵĸ���ƫ�ƺ͸��س���*/

    ULONG (*pfFsbufIPv6GetL4Payload)(IN const MBUF_S *pstMBuf,
                                     IN const IP6_S *pstIP,
                                     IN UINT uiL4OffSet,
                                     OUT UINT *puiPayloadOff,
                                     OUT UINT *puiPayloadLen); /*����Ĳ����ϵĸ���ƫ�ƺ͸��س���*/

    UCHAR (*pfGetReadyState)(VOID);  
}SESSION_L4_PROTO_S;

/* �Ự�¼�����ص����� */
typedef VOID (*SESSION_KCREATE_CB_PF)(IN SESSION_HANDLE hSession);      /* �Ự�����ص����� */
typedef VOID (*SESSION_KDELETE_CB_PF)(IN SESSION_HANDLE hSession);      /* �Ự��ɾ���ص����� */
typedef VOID (*SESSION_KUPDATE_CB_PF)(IN SESSION_HANDLE hSession);      /* �Ự����»ص����� */
typedef VOID (*SESSION_KACTIVE_CB_PF)(IN SESSION_HANDLE hSession);      /* �Ự��Ծ�ص����� */
typedef ULONG (*SESSION_KEND_FAILED_CB_PF)(IN SESSION_HANDLE hSession,
                                           IN MBUF_S *pstMBuf,
                                           IN UINT uiL3Offset);         /* session-end����ʧ�ܻص����� */
typedef VOID (*SESSION_EXT_DESTROY_CB_PF)(IN SESSION_HANDLE hSession, VOID *pCb); /* ��չ��Ϣɾ���ص����� */
typedef VOID (*RELATION_KCREATE_CB_PF)(IN RELATION_HANDLE hRelation); /* ���������ص����� */
typedef VOID (*RELATION_KDELETE_CB_PF)(IN RELATION_HANDLE hRelation); /* ������ɾ���ص����� */
typedef BOOL_T (*SESSION_KAGING_CB_PF)(IN SESSION_HANDLE hSession);   /* �Ự���ϻ���ѯ�ص����� */
typedef ULONG (*SESSION_KQUERY_TRANS_CB_PF)(IN SESSION_HANDLE hSession,
                                            IN DIRECTION_E enDir,
                                            OUT BOOL_T *pbSrcTranslated,
                                            OUT BOOL_T *pbDstTranslated);
typedef VOID (*SESSION_KSENDLOG_CB_PF)(IN const SESSION_S *pstSession, IN CHAR *pcReason, IN CHAR *pcDomainName);

typedef VOID (*SESSION_RESTOREMODULE_PF)(IN SESSION_HANDLE hSession);

typedef ULONG (*NEW_SESSION_BY_RELATION_PF)(IN SESSION_HANDLE hSession,
                                            IN const RELATION_ATTACH_INFO_S *pstAttachInfo,
                                            IN const MBUF_S *pstMbuf);

/* ������ӻỰ��չ��Ϣ�ӿڣ�pfGet��ȡ��pfCreate��ӣ��ڲ�������֤���� */
typedef VOID*(*SESSION_ATTACH_CREATE_PF)(IN SESSION_HANDLE hSession, IN ULONG ulPara);

/* ҵ��ģ��ע��ṹ */
typedef struct tagSessionModuleReg
{
    SESSION_KCREATE_CB_PF pfSessCreate;     /* �Ự������¼�֪ͨ */    
    SESSION_KDELETE_CB_PF pfSessDelete;     /* �Ự����ɾ���¼�֪ͨ */
    SESSION_KUPDATE_CB_PF pfSessUpdate;     /* �Ự����״̬�����¼�֪ͨ */     
    SESSION_KACTIVE_CB_PF pfSessActive;     /* �Ự���ʱ�����¼�֪ͨ */     
    SESSION_EXT_DESTROY_CB_PF pfExtDestroy; /* �Ự�����ͷ��ڴ��¼�֪ͨ */ 
    SESSION_KEND_FAILED_CB_PF pfSessEndFailed; /* �Ự������ʽ��ʧ���¼�֪ͨ */
    RELATION_KCREATE_CB_PF pfRelationCreate; /* ����������¼�֪ͨ */
    RELATION_KDELETE_CB_PF pfRelationDelete; /* ��������ɾ���¼�֪ͨ */
    SESSION_KAGING_CB_PF pfSessAging; /* �Ự���ϻ���ѯ�ص����� */
    SESSION_KQUERY_TRANS_CB_PF pfSessQueryTrans; /* ��Ѱ�Ự��ַ�Ƿ�ת���ص����� */
    SESSION_KSENDLOG_CB_PF pfSessSendLog;
    USHORT usExtInfoNum;       /* ҵ����չ��Ϣʹ�õ�ULONG������Ext����Ӱ��Ự������ڴ�Ĵ�С */
}SESSION_MODULE_REG_S;

#define TUNNEL_INVALID_TUNNEL_ID 0
#define SESSION_GET_PERCPU_PTR(_pstBuf,_iCpuIndex) ((_pstBuf) + (_iCpuIndex))


extern SESSION_MODULE_REG_S g_astModuleRegInfo[SESSION_MODULE_MAX];
extern AGINGQUEUE_UNSTABLE_S g_stSessionstAgingQueue;
extern SESSION_CTRL_S g_stSessionCtrl;

VOID SESSION_KL4_Reg(IN const SESSION_L4_PROTO_S *pstRegInfo, IN UCHAR ucProto);
VOID SESSION_KL4_DeReg(IN UCHAR ucProto);
/* ��ȡ���Ĵ����õ�3�㣬4�㴦��ģ�� */
ULONG session_kGetModule(IN MBUF_S *pstMBuf,
                         IN UINT   uiL3Offset,
                         OUT UINT *puiL4Offset,
                         OUT UCHAR *pucL4ProtoNum,
                         OUT UINT *puiIPLen,
                         OUT SESSION_L3_PROTO_S **ppstL3Proto,
                         OUT SESSION_L4_PROTO_S **ppstL4Proto);
ULONG SESSION_IpfsEndProc(IN USHORT usIPOffset, INOUT MBUF_S *pstMBuf);
/* IPv6ת��������Session End ҵ���Ĵ����� */
ULONG SESSION6_IpfsEndProc(IN USHORT usIPOffset, INOUT MBUF_S *pstMBuf);
VOID SESSION6_KTouchProcess(INOUT MBUF_S *pstMbuf, IN SESSION_HANDLE hSession, IN UINT uiL3Offset);
SESSION_HANDLE SESSION6_KCreateProcess(INOUT MBUF_S *pstMbuf, IN UINT uiL3Offset);
/* �ӱ�������ȡtuple���� */
VOID session_kGetTuple(IN const MBUF_S *pstMBuf,
                       IN UINT uiL3Offset,
                       IN UINT uiL4Offset,
                       IN UCHAR ucL4ProtoNum,
                       IN const SESSION_L3_PROTO_S *pstL3Proto,
                       IN const SESSION_L4_PROTO_S *pstL4Proto,
                       INOUT SESSION_TUPLE_S *pstTuple);
VOID SESSION_DisDelete(IN SESSION_S *pstSession);
/* ���ݱ���ָ�룬��˫���ת���hash����ժ�������ͷſ�ת���ڴ� */
/* �Ự��ժHASH */
VOID SESSION6_Delete(IN SESSION_S *pstSession);
INT scnprintf(OUT CHAR *pcBuf, IN size_t ulSize, IN const CHAR *pcFmt,...);
VOID SESSION_KDestroy(IN VOID *pSession);
VOID SESSION_KDeleteSession(IN SESSION_HANDLE hSession);
VOID AGINGQUEUE_UnStable_AddResetObj(IN AGINGQUEUE_UNSTABLE_S *pstQueue,
                                     IN AGINGQUEUE_RST_MSG_OBJECT_S *pstResetObj);

VOID SESSION6_KPut(IN SESSION_S *pstSession);

/* L3Э��ע�ᴦ���� */
VOID SESSION_KL3_Reg(IN const SESSION_L3_PROTO_S *pstRegInfo, IN UCHAR ucFamily);
/* L3Э��ע�������� */
VOID SESSION_KL3_DeReg(IN UCHAR ucFamily);
ULONG SESSION6_McfsEndProc(IN VOID *pCache,IN USHORT usIPOffset, INOUT MBUF_S *pstMBuf);
ULONG SESSION_L2FsService(IN IF_INDEX ifIndex, IN VOID *pCache, INOUT MBUF_S *pstMBuf);
/* ��ȡ4��Э�鴦��ṹ */
SESSION_L4_PROTO_S *SESSION_KGetL4Proto_Proc(IN UCHAR ucProto);
/*** ��appid��ȡ�Ự��alg type ***/
USHORT SESSION_KGetSessionAlgType(IN UINT uiAppID);
/* �ȽϹ�����HASH�ڵ��Ƿ�ƥ�� */
BOOL_T SESSION6_Relation_IsTupleMatch(IN const csp_key_t *pstTupleFromHash,
                                      IN const csp_key_t *pstNewTuple,
                                      IN UINT uiCmpMask);
/* ���ڻỰ�İ�ȫҵ���ת��� */
ULONG SESSION6_FsService(struct rte_mbuf *pstRteMbuf);
/*****************************************************************************
��ת���ӻỰ����ͳ����Ϣ
*****************************************************************************/
VOID SESSION_FsAddStat(IN SESSION_S *pstSession,
					   IN const MBUF_S *pstMbuf,
					   IN SESSION_CTRL_S *pstSessionCtrl,
					   IN SESSION_PKT_DIR_E enPktDir);

/* ����Ĳ����ϵĸ��غ͸��س��� */
ULONG SESSION_Util_GetL4Payload_Default(IN MBUF_S *pstMBuf,
                                        IN UINT uiL4OffSet,
                                        IN UINT uiL4HdrLen,
                                        OUT UINT *puiPayloadOff,
                                        OUT UINT *puiPayloadLen);
/* ����Ĳ����ϵĸ��غ͸��س��� */
ULONG SESSION_Util_FsbufGetL4Payload_Default(IN const MBUF_S *pstMBuf,
                                             IN const struct iphdr *pstIP,
                                             IN UINT uiL4OffSet,
                                             IN UINT uiL4HdrLen,
                                             OUT UINT *puiPayloadOff,
                                             OUT UINT *puiPayloadLen);
/* ����Ĳ����ϵĸ��غ͸��س��� */
ULONG SESSION6_Util_FsbufGetL4Payload_Default(IN const MBUF_S *pstMBuf,
                                              IN const IP6_S *pstIP6,
                                              IN UINT uiL4OffSet,
                                              IN UINT uiL4HdrLen,
                                              OUT UINT *puiPayloadOff,
                                              OUT UINT *puiPayloadLen);
VOID SESSION_KReset(IN const SESSION_TABLE_KEY_S *pstKey);
/* ��ȡ������Ϣ */
SESSION_AGINGQUE_CONF_S* SESSION_GetAgingqueConfInfo(VOID);
/* ����3��Э�����ͻ�ȡ3��Э�鴦��ṹ */
SESSION_L3_PROTO_S *SESSION_KGetL3Proto_Proc(UCHAR ucFamily);

/* forcompile stub begin */
VOID _proc_SetMsgReply(INT iSocketFd, UINT uiVar, ULONG ulErrCode);
ULONG SESSION_KHash_Init(SESSION_HASH_HANDLE *phHash, UINT uiLen);
VOID session6_kdebugTableSetDelEvent(SESSION_S *pstSession, SESSION_MODULE_E enModule);
ULONG AGINGQUEUE_Changeable_InitQueue(AGINGQUEUE_CHANGEABLE_S *pstQue);
VOID AGINGQUEUE_Changeable_DestroyQueue(AGINGQUEUE_CHANGEABLE_S *pstQue);

VOID IP6FS_DeletePairFromHash(INOUT VOID *pSession);
VOID SESSION_DBG_SESSION_FSM_SWITCH(SESSION_S * pstSession, UINT uiVar, UINT uiVar2, 
    DIRECTION_E enDir, UCHAR ucOldState, UCHAR ucNewState);
VOID SESSION_FsTcpMssProc(SESSION_S *pstSession, UCHAR ucIndex, 
    MBUF_S *pstMBuf, TCPHDR_S *pstTcpHdr);
VOID RELATION_KAging_Init(VOID);
VOID RELATION6_KAging_Init(VOID);
ULONG SESSION_KALG_Init(VOID);
VOID SESSION_Packet_Module_Exit(VOID);
/* ALGЭ��ȥ��ʼ�� */
VOID SESSION_KALG_Fini(VOID);
/* ��������ģ��ȥ��ʼ�� */
VOID SESSION_KRelation_Exit(VOID);
VOID SESSION6_KRelation_Exit(VOID);
/* �������ϻ�ȥ��ʼ�� */
VOID RELATION_KAging_Fini(VOID);
VOID RELATION6_KAging_Fini(VOID);
VOID AGINGQUEUE_UnStable_Destroy(AGINGQUEUE_UNSTABLE_S *pstAgingQue);
/* ȥע��App Change�¼�*/
VOID APR_KAppChange_DeregFun(UINT uiModule);
/* ��ʼ���Ự����Ϣ */
ULONG SESSION_KTableRun(VOID);
/* ��ʼ����������Ϣ */
ULONG SESSION_KRelation_Run(VOID);
ULONG SESSION6_KRelation_Run(VOID);
VOID IP6FS_FreeCache(IN VOID *pCache);
BOOL_T APR_IfAppIdentified(UINT uiAppID);
VOID * IP6FS_AllocCache(IN UCHAR ucDir);
VOID SESSION6_KLOG_PROC_ActiveFlow(SESSION_S * pstSession, SESSION_CTRL_S *pstCtrl);
BOOL_T RBM_KCFG_IsBackupEnable(VOID);
VOID SESSION6_KLOG_PROC_Create(MBUF_S *pstMBuf, UINT uiIPOffset, 
    SESSION_S *pstSession, SESSION_CTRL_S *pstSessionCtrl);
ULONG session6_kEstablishFailedNotify(SESSION_S *pstSession, UINT uiIPOffset, MBUF_S *pstMBuf);
ULONG DIM_KPKT6_IPv6FastProc(SESSION_HANDLE hSession, SESSION_PKT_DIR_E enPktDir, 
    UINT uiVar, IP6_S **ppstIP6, MBUF_S *pstMBuf);
VOID SESSION_KStop(SESSION_TABLE_KEY_S *pstKey);
ULONG SESSION_DBM_SetL4Aging(const SESSION_L4AGING_S *pstAging);
VOID SESSION_SYNC_SetL4Aging(const SESSION_L4AGING_S *pstAging);
VOID SESSION_MSG_ErrorMsgReply(INT iSocketFd);
BOOL_T SESSION_MatchKeyIpv6AclRule(const SESSION_S *pstSession, UINT uiAclNum);
BOOL_T SESSION_MatchKeyIpv4AclRule(const SESSION_S *pstSession, UINT uiAclNum);
VOID SESSION_KLOG_PROC_Create(MBUF_S *pstMBuf, UINT uiIPOffset, 
    SESSION_S *pstSession, SESSION_CTRL_S *pstSessionCtrl);
VOID SESSION_KLOG_PROC_ActiveFlow(SESSION_S *pstSession, SESSION_CTRL_S *pstSessionCtrl);
SESSION_HANDLE SESSION_KCreateProcess(INOUT MBUF_S *pstMbuf, IN UINT uiL3Offset);
VOID SESSION_KTouchProcess(INOUT MBUF_S *pstMbuf, IN SESSION_HANDLE hSession, IN UINT uiL3Offset);
VOID SESSION_KGCFG_SetL4Aging(IN SESSION_CTRL_S *pstSessionCtrl, IN const SESSION_L4AGING_S *pstAging);
VOID SESSION_KStatFailInc(IN SESSION_STAT_FAIL_TYPE_E enStatFailType,
                          INOUT SESSION_CTRL_S *pstSessionCtrl);
VOID SESSION6_KStatFailInc(IN SESSION_STAT_FAIL_TYPE_E enStatFailType,
                          INOUT SESSION_CTRL_S *pstSessionCtrl);
UINT session_kIdentifyAppID(USHORT usDstPort, UCHAR ucL4Pro);

typedef struct
{
	UINT64 ulStartTime;
	SESSION_TUPLE_S astTuple[SESSION_DIR_BOTH];
	UINT auiPackets[SESSION_DIR_BOTH];
	UINT auiBytes[SESSION_DIR_BOTH];
	UINT uiAppID;
	UINT uiTTL;
	UINT uiRuleID;
	UCHAR ucState;
	UCHAR ucSessProto;
} SESSION_TABLE_INFO_S;

#define SESSION_TIME_NO_AGING 0xFFFFFFFF


/* forcompile stub end */

/* ע��!!! ֻ����worker thread���� */
static inline UINT32 index_from_lcore_id(VOID)
{
    return rte_lcore_id()-1;
}

/* core 0�ǿ��ƺ�, �����ų��� */
static inline UINT32 worker_thread_total(VOID)
{
    return rte_lcore_count()-1;
}

static inline VOID SESSION_KAddTotalState(IN SESSION_L4_TYPE_E enSessType,
                                          IN UINT              uiPackets,
                                          IN UINT              uiBytes,
                                          IN SESSION_CTRL_S   *pstSessionCtrl)
{
    SESSION_STAT_VCPU_S *pstPerCpuStat;
    SESSION_K_STATISTICS_S *pstKstatistics;
    SESSION_FLOW_STAT_S *pstFlowStat;

    pstKstatistics = &(pstSessionCtrl->stSessStat);

    pstPerCpuStat = SESSION_GET_PERCPU_PTR(pstKstatistics->pstVcpuStat, index_from_lcore_id());

    /* ����ָ�����ͻỰ��ȫ������ͳ�� */
    pstFlowStat = &pstPerCpuStat->astFlowStat[enSessType];
	
    pstFlowStat->uiBytesCount += uiBytes;
    pstFlowStat->uiPacketsCount += uiPackets;
    
    return;
}

/******************************************************************
   Func Name:SESSION_KGetAppID
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�ӻỰ���ȡAPPID
       INPUT:SESSION_HANDEL hSession, �Ự
      Output:��
      Return:APPID
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline UINT SESSION_KGetAppID(IN SESSION_HANDLE hSession)
{
    SESSION_S *pstSession = (SESSION_S *)hSession;

    return pstSession->uiAppID;
}

/* ���ݻỰһ�������tuple��÷������tuple */
static inline VOID session_invert_tuple(IN SESSION_S *pstSession,
                                        IN const SESSION_TUPLE_S *pstOrig,
                                        IN const SESSION_L3_PROTO_S *pstL3Proto,
                                        IN const SESSION_L4_PROTO_S *pstL4Proto,
                                        OUT SESSION_TUPLE_S *pstInverse)
{
    /* ���������г�ʼ��������������v4��v6��ַ��union, ƥ��Ựʱ���� */
    memset(pstInverse, 0, sizeof(SESSION_TUPLE_S));

    pstL3Proto->pfGetInvertTuple(pstOrig, pstInverse);
    pstL4Proto->pfGetInvertTuple(pstSession, pstOrig, pstInverse);

    return;
}

/******************************************************************
   Func Name:SESSION_IsIPv4LatterFrag
Date Created:2021/04/25
      Author:wangxiaohua
 Description:�ж�һ��IPv4�����Ƿ��Ǻ�����Ƭ����
       INPUT:IN UINT uiL3OffSet       ----����ƫ��
             IN MBUF_S *pstMBuf       ----����             
      Output:��
      Return:BOOL_TRUE                ----������Ƭ
             BOOL_FALSE               ----�Ǻ�����Ƭ
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline BOOL_T SESSION_IsIPv4LatterFrag(IN UINT uiL3OffSet, IN MBUF_S*pstMBuf)
{
    BOOL_T bIsLatterFrag;
    struct iphdr *pstIPHdr;
    USHORT usOff;
    ULONG ulRet;

    /* ��ǰsession_end����·�������ģ���·��ͷ�����ܺ�ipͷ������ */
    ulRet = MBUF_PULLUP(pstMBuf, (UINT)(uiL3OffSet + sizeof(struct iphdr)));
    if(unlikely(ERROR_SUCCESS != ulRet))
    {
        /* ���pullupʧ��������Ƭ������ǰ�Ὣcache�ͻỰɾ�� */
        return BOOL_TRUE;
    }

    pstIPHdr = MBUF_BTOD_OFFSET(pstMBuf, uiL3OffSet, struct iphdr*);
    usOff    = pstIPHdr->frag_off;
    usOff    = ntohs(usOff);

    if(0 != (usOff & IP_OFFMASK))
    {
        bIsLatterFrag = BOOL_TRUE;
    }
    else
    {
        bIsLatterFrag = BOOL_FALSE;
    }

    return bIsLatterFrag;
}

static inline SESSION_CTRL_S *SESSION_CtrlData_Get(VOID)
{
    return &g_stSessionCtrl;
}

/* �ж�SESSION��MBUF���Ƿ����õ���FLAGBIT�Ķ��� */
static inline BOOL_T SESSION_MBUF_TEST_FLAG(const IN MBUF_S *pstMBuf, IN USHORT usFlagBit)
{
    return (0 != ((UINT)pstMBuf->usSessionFlag & (UINT)usFlagBit));
}

/*** ҵ��ģ����Ự������ALG������ ***/
static inline VOID SESSION_KSetAlgFlag (IN SESSION_HANDLE hSession, IN SESSION_MODULE_E enModule)
{
	SESSION_S *pstSession = (SESSION_S *) hSession;

	SESSION_TABLE_SET_ALGFLAG(pstSession, enModule);

	return;
}

/* ��ȡ�෴�ı��ķ��� */
static inline SESSION_PKT_DIR_E SESSION_GetInvertDir(IN SESSION_PKT_DIR_E enDir)
{
    /*
        ORIGINAL  ->  REPLY
        REPLY     ->  ORIGINAL
    */

    return (SESSION_PKT_DIR_E)(1 ^ enDir);
}

/* ��ȡ���ķ��� */
static inline SESSION_PKT_DIR_E SESSION_GetDirFromMBuf(IN const MBUF_S *pstMBuf)
{
    return (MBUF_GET_SESSION_FLAG(pstMBuf) & SESSION_MBUF_REPLYPKT) ? SESSION_DIR_REPLY : SESSION_DIR_ORIGINAL;
}

/* ��SESSION_MODULE_E תΪSESSON_SERVICE_E */
static inline SESSION_SERVICE_E SESSION_KModuleToService(IN SESSION_MODULE_E enModule)
{
    SESSION_SERVICE_E enService;
    switch(enModule)
    {
        case SESSION_MODULE_NAT:
            enService = SESSION_SERVICE_NAT;
            break;
            
        case SESSION_MODULE_CONNLMT:
            enService = SESSION_SERVICE_CONNLMT;
            break;

        case SESSION_MODULE_LB:
                  enService = SESSION_SERVICE_LB;
                  break;

        case SESSION_MODULE_ALG:
            enService = SESSION_SERVICE_ALG;
            break;
            
        case SESSION_MODULE_WAAS:
            enService = SESSION_SERVICE_WAAS;
            break;
            
        case SESSION_MODULE_TCPCHECK:
            enService = SESSION_SERVICE_TCPCHECK;
            break;

        case SESSION_MODULE_AFT:
            enService = SESSION_SERVICE_AFT;
            break;
            
        case SESSION_MODULE_DIM:
            enService = SESSION_SERVICE_DIM;
            break;

        case SESSION_MODULE_TCPREASSEMBLE:
            enService = SESSION_SERVICE_TCPREASSEMBLE;
            break;
            
        case SESSION_MODULE_TRAFFICLOG:
            enService = SESSION_SERVICE_TRAFFICLOG;
            break;

        default:
            enService = SESSION_SERVICE_STATIC;
            break;
    }

    return enService;
}

static inline VOID* SESSION_KGetALGCb(IN SESSION_HANDLE hSession)
{
    return ((SESSION_S *)hSession)->pAlgCb;
}

static inline VOID SESSION_KSetALGCb(IN SESSION_HANDLE hSession, IN VOID *pExtInfo)
{
    ((SESSION_S *)hSession)->pAlgCb = pExtInfo;
    SESSION_TABLE_SET_ATTACHFLAG((SESSION_S *)hSession, SESSION_SERVICE_ALG);

    /* ���Debug��Ϣ 
    SESSION_DBG_EXT_EVENT_SWITCH((SESSION_S *)hSession, SESSION_MODULE_ALG, EVENT_ADD);*/

    return;
}

/* ��ȡָ���Ự��Ķ��㸸�Ự���ձ�ʾ�޸��Ự */
static inline SESSION_HANDLE SESSION_KGetParentSession(IN SESSION_HANDLE hSession)
{
    SESSION_S *pstParentSession = SESSION_INVALID_HANDLE;
    SESSION_S *pstSession = (SESSION_S *)hSession;
	
    while(NULL != pstSession->pstParent)
    {
        pstParentSession = pstSession->pstParent;
        pstSession = pstParentSession;
    }

    return (SESSION_HANDLE)pstParentSession;
}

#if 0
/* IPv6ת��������Session End ҵ���Ĵ����� */
static inline ULONG SESSION6_EndProc(IN VOID *pCache, IN USHORT usIPOffset, INOUT MBUF_S *pstMBuf)
{
	ULONG ulRet;
	UCHAR ucMCType = IP6FS_GET_CACHE_MCTYPE(pCache);

	if(likely(0 == ucMCType))
	{
		ulRet = SESSION6_IpfsEndProc(pCache, usIPOffset, pstMBuf);
	}
	else
	{
		DBGASSERT((IP6FS_MCTYPE_IN == ucMCType) || (IP6FS_MCTYPE_OUT == ucMCType));
		ulRet = SESSION6_McfsEndProc(pCache, usIPOffset, pstMBuf);
	}
	return ulRet;
}
#endif

static inline BOOL_T SESSION6_IsLatterFrag(IN const MBUF_S *pstMBuf)
{
    if(BOOL_TRUE != MBUF_IS_IP6_FRAGMENT(pstMBuf))
    {
        return BOOL_FALSE;
    }

    if(BOOL_TRUE == MBUF_IS_IP6_FIRSTFRAG(pstMBuf))
    {
        return BOOL_FALSE;
    }

    return BOOL_TRUE;
}


/* �ж�ģ�鴦���� */
static inline BOOL_T SESSION_KIsModuleFlagSet(IN SESSION_HANDLE hSession, IN SESSION_MODULE_E enModule)
{
    SESSION_S *pstSession = (SESSION_S *)hSession;
    
    return SESSION_TABLE_IS_MODULEFLAG_SET(pstSession, enModule);
}

/******************************************************************
   Func Name:SESSION_KAgingRefresh
Date Created:2021/04/25
      Author:wangxiaohua
 Description:ˢ�»Ự�ϻ�ʱ��
       INPUT:IN SESSION_S *pstSession,  �Ự
      Output:��
      Return:��
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline VOID SESSION_KAgingRefresh(IN SESSION_S *pstSession)
{
    pstSession->stSessionBase.uiUpdateTime = rte_get_timer_cycles();

    return;
}

/* ���ڻỰ�İ�ȫҵ���ת��� */ 
#if 0
static inline ULONG SESSION_L2FsServiceProc(IN IF_INDEX ifIndex,
											IN VOID *pCache,
											INOUT MBUF_S *pstMBuf)
{
	ULONG ulRet;

	DBGASSERT(NULL != pCache);

	ulRet = SESSION_L2FsService(ifIndex, pCache, pstMBuf);
	return ulRet;
}
#endif

static inline conn_sub_t *SESSION_KGetCsp(IN SESSION_HANDLE hSession, IN SESSION_PKT_DIR_E enDir)
{
    SESSION_S *pstSession = (SESSION_S *)hSession;	
	conn_sub_t *csp = (conn_sub_t *)pstSession->stSessionBase.pCache[enDir];

    return csp;
}

static inline csp_key_t *SESSION_KGetIPfsKey(IN SESSION_HANDLE hSession, IN SESSION_PKT_DIR_E enDir)
{
    SESSION_S *pstSession = (SESSION_S *)hSession;	

    return GET_CSP_KEY((conn_sub_t *)pstSession->stSessionBase.pCache[enDir]);
}

/* ����ģ�鴦���� */
static inline VOID SESSION_KSetModuleFlag(IN SESSION_HANDLE hSession, IN SESSION_MODULE_E enModule)
{
    SESSION_S *pstSession = (SESSION_S *)hSession;

    SESSION_TABLE_SET_MODULEFLAG(pstSession, enModule);

    return;
}

static inline SESSION_HANDLE SESSION_KGetSessionFromMbuf(INOUT MBUF_S *pstMbuf, IN UINT uiL3Offset)
{	
    SESSION_HANDLE hSession;

    /*
     *����Ự�Ѿ�������ñ��ģ��򲻱��ٴ���ֱ��ʹ��Mbuf�еĻỰָ�룬
     *���ⲻ�����κλỰ�ı��Ķ�δ���.
     */
      
    hSession = (SESSION_HANDLE)GET_FWSESSION_FROM_LBUF(pstMbuf);

    /* �������Ѿ�������� */
    if(SESSION_MBUF_TEST_FLAG(pstMbuf, SESSION_MBUF_PROCESSED))
    {
        return hSession;
    }

    /*�������Ѿ��лỰ��, ���ǿ����ǻ�Ӧ���Ļ���������ű���������´�����ת����*/
    if(SESSION_INVALID_HANDLE != hSession)
    {
        SESSION_KTouchProcess(pstMbuf, hSession, uiL3Offset);
        
        return hSession;
    }

    /* �޻Ự��Ҫ���� */
    return SESSION_KCreateProcess(pstMbuf, uiL3Offset);    
}

static inline SESSION_HANDLE SESSION6_KGetSessionFromMbuf(INOUT MBUF_S *pstMbuf, IN UINT uiL3Offset)
{	
    SESSION_HANDLE hSession;

    /*
     *����Ự�Ѿ�������ñ��ģ��򲻱��ٴ���ֱ��ʹ��Mbuf�еĻỰָ�룬
     *���ⲻ�����κλỰ�ı��Ķ�δ���.
     */
      
    hSession = (SESSION_HANDLE)GET_FWSESSION_FROM_LBUF(pstMbuf);

    /* �������Ѿ�������� */
    if(SESSION_MBUF_TEST_FLAG(pstMbuf, SESSION_MBUF_PROCESSED))
    {
        return hSession;
    }

    /*�������Ѿ��лỰ��, ���ǿ����ǻ�Ӧ���Ļ���������ű���������´�����ת����*/
    if(SESSION_INVALID_HANDLE != hSession)
    {
        SESSION6_KTouchProcess(pstMbuf, hSession, uiL3Offset);
        
        return hSession;
    }

    /* �޻Ự��Ҫ���� */
    return SESSION6_KCreateProcess(pstMbuf, uiL3Offset);    
}

static inline VOID SESSION_KAging_Add(IN AGINGQUEUE_UNSTABLE_S *pstAgingQueue, IN SESSION_S *pstSession)
{
    SESSION_KAgingRefresh(pstSession);
    AGINGQUEUE_UnStable_Add(pstAgingQueue, &pstSession->stSessionBase.unAgingRcuInfo.stAgingInfo);

    return;
}

/* ����IPv6��ַ */
static inline VOID IN6ADDR_Copy(OUT struct in6_addr *pstDestAddr, IN const struct in6_addr *pstSrcAddr)
{
	UINT *puiDestAddr;
	const UINT *puiSrcAddr;

	puiDestAddr = pstDestAddr->s6_addr32;
	puiSrcAddr  = pstSrcAddr->s6_addr32;

	puiDestAddr[0] = puiSrcAddr[0];
	puiDestAddr[1] = puiSrcAddr[1];
	puiDestAddr[2] = puiSrcAddr[2];
	puiDestAddr[3] = puiSrcAddr[3];

	return;
}

/* �ж�Ipv6��ַ�ǲ�����·���ص�ַ */
static inline BOOL_T IN6ADDR_IsLinkLocal(IN const struct in6_addr *pstAddr)
{
	const UCHAR *pucAddr;

	pucAddr = pstAddr->s6_addr;

	return ((pucAddr[0] == 0xfe) && ((pucAddr[1] & 0xc0) == 0x80));
}

/* �ж�Ipv6��ַ�ǲ���δָ����ַ(��ȫ0)*/
static inline BOOL_T IN6ADDR_IsUnspecified(IN const struct in6_addr *pstAddr)
{
    const UINT *puiAddr;

    puiAddr = pstAddr->s6_addr32;

    return ((puiAddr[0] == 0) && (puiAddr[1] == 0) && (puiAddr[2] == 0) && (puiAddr[3] == 0));
}

/******************************************************************
 Description:�ж�Ipv6��ַ�ǲ��Ƕಥ��ַ
       INPUT:pstAddr:���жϵ�IPv6��ַ
      Output:��
      Return:BOOL_TRUE: �Ƕಥ��ַ
             BOOL_FALSE:���Ƕಥ��ַ
     Caution:
---------------------------------------------------------------------
Modification History
DATE        NAME         DESCRIPTION
---------------------------------------------------------------------

*********************************************************************/
static inline BOOL_T IN6ADDR_IsMulticast(IN const struct in6_addr *pstAddr)
{
    return (pstAddr->s6_addr[0] == 0xff);
}

/**************************************************************************
Description�� �ж�Ipv6��ַ�ǲ��ǻ��ص�ַ(::1)
********************************************************************/
static inline BOOL_T IN6ADDR_IsLoopback(IN const struct in6_addr *pstAddr)
{
	const UINT *puiAddr;

	puiAddr = pstAddr->s6_addr32;

	return((puiAddr[0] == 0) && (puiAddr[1] == 0) &&
		   (puiAddr[2] == 0) && (puiAddr[3] == htonl(1)));
}


#endif
