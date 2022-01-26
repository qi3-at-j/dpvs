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
    SESSION_STAT_FAIL_CREATE_CACHE_NULL,            /*会话创建时cache为NULL*/
    SESSION_STAT_FAIL_GETL4OFFSET,                  /*获取4层头偏移失败*/
    SESSION_STAT_FAIL_PKT_CHECK,                    /*报文检查失败*/
    SESSION_STAT_FAIL_ALLOC_CACHE,                  /*分配cache失败*/
    SESSION_STAT_FAIL_ALLOC_SESSION,                /*分配会话失败*/
    SESSION_STAT_FAIL_EXTNEW_STATE,                 /*扩展会话创建时状态异常*/
    SESSION_STAT_FAIL_TRY_FAIL_UNICAST,             /*单播session end尝试处理失败*/
    SESSION_STAT_FAIL_CAPABITITY_UNICAST,           /*单播会话并发限制*/
    SESSION_STAT_FAIL_FORMALIZE_UNICAST,            /*单播会话正式化失败*/
//    SESSION_STAT_FAIL_TRY_FAIL_MULTICAST,           /*组播session end尝试处理失败*/
//    SESSION_STAT_FAIL_CAPABITITY_MULTICAST,         /*组播会话并发限制*/
//    SESSION_STAT_FAIL_FORMALIZE_MULTICAST,          /*组播会话正式化失败*/
    SESSION_STAT_FAIL_TOUCH_CACHE_NULL,             /*匹配会话时cache为NULL*/
    SESSION_STAT_FAIL_TOUCH_STATE,                  /*匹配会话时状态异常*/
    SESSION_STAT_FAIL_EXT_STATE,                    /*扩展会话状态异常*/
    SESSION_STAT_FAIL_TCP_STATE,                    /*TCP state 异常*/
    SESSION_STAT_FAIL_FAST_TCP_STATE,               /*快转时TCP state 异常*/
//    SESSION_STAT_FAIL_NEED_RELAY,                   /*SYN-ACK报文需要透传*/
    SESSION_STAT_FAIL_HOTBACKUP_DELETE_FAIL,        /*热备强制删除备机会话失败*/
    SESSION_STAT_FAIL_HOTBACKUP_HASHFAIL,           /*热备会话添加hash冲突*/
    SESSION_STAT_FAIL_RELATION_LOCAL_HASH,           
    SESSION_STAT_FAIL_RELATION_GLOBAL_HASH,      
//    SESSION_STAT_FAIL_MBUF_RELAY_OUTPUT,            /*慢转透传接收出处理函数*/
//    SESSION_STAT_FAIL_MBUF_RELAY_INPUT,             /*慢转透传接收入处理函数*/
    SESSION_STAT_FAIL_FIRST_PATH,                   /*慢转接口返回值不是FLOW_RET_OK*/
    SESSION_STAT_FAIL_FAST_PATH,                    /*快转接口返回值不是FLOW_RET_OK*/
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

/*二层转发所建会话*/
#define SESSION_MACFW  0x1
#define SESSION_BRIDGE 0x2
#define SESSION_INLINE 0x4

/*组播所建会话*/
#define SESSION_MCFS_IN  0x40
#define SESSION_MCFS_OUT 0x80

#define SESSION_SERVICE_INVALID_INDEX 0x0F    /*无效索引，表示模块未添加扩展信息*/
#define SESSION_FIRST_SERVICE_INDEX   0x0E    /*模块扩展信息直接挂在session中的pServiceCb*/

/*消除const引起的pclint告警*/
#define SESSION_IGNORE_CONST(x) ((x) = (x))


#define SESSION_TABLE_SET_TABLEFLAG(_pSession, usFlag) \
    {(_pSession)->usTableFlag |= (USHORT)usFlag;}
#define SESSION_TABLE_CLEAR_TABLEFLAG(_pSession, usFlag) {(_pSession)->usTableFlag &= (USHORT)~usFlag;}

#define SESSION_TABLE_IS_TABLEFLAG(_pSession, usFlag) \
    (0 != ((_pSession)->usTableFlag & (USHORT)usFlag))

/* 会话上模块扩展数据是否存在标记设置和判断 */
#define SESSION_TABLE_SET_ATTACHFLAG(_pSession, _Module) {(_pSession)->usAttachFlag |= (USHORT)(1UL << (_Module));}
#define SESSION_TABLE_CLEAR_ATTACHFLAG(_pSession, _Module){(_pSession)->usAttachFlag &= (USHORT)~(1UL << (_Module));}
#define SESSION_TABLE_IS_ATTACHFLAG_SET(_pSession, _Module) \
    (0 != ((_pSession)->usAttachFlag & (USHORT)(1UL << (_Module))))

/* 会话表模块处理标记设置和判断*/
#define SESSION_TABLE_SET_MODULEFLAG(_pSession, _Module) {(_pSession)->usModuleFlag |= (USHORT)(1UL << (_Module));}
#define SESSION_TABLE_IS_MODULEFLAG_SET(_pSession, _Module) \
    (0 != ((_pSession)->usModuleFlag & (USHORT)(1UL << (_Module))))
/* 会话清除业务模块开关位 */
#define SESSION_TABLE_CLEAR_MODULELAG(_pSession, _Module) {(_pSession)->usModuleFlag &= (USHORT)~(1UL << _Module);}

/* 会话ALG处理标记标记设置和判断 */
#define SESSION_TABLE_SET_ALGFLAG(_pSession, _Module) {(_pSession)->usAlgFlag |= (USHORT)(1UL << (_Module));}
#define SESSION_TABLE_IS_ALGFLAG_SET(_pSession, _Module)(0 != (((SESSION_S *)(_pSession))->usAlgFlag & (USHORT)(1UL << (_Module))))
#define SESSION_TABLE_UNSET_ALGFLAG(_pSession, _Module) {(_pSession)->usAlgFlag &= ((USHORT)(~(1UL << (_Module))));}

/* 会话池 */
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

/*用于alg异常统计信息中用户态下发各种ALG细分类型到内核*/
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

/* session alg 异常类型 */
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

/* 三层协议类型 */
typedef enum enSESSION_L3_TYPE
{
    SESSION_L3_TYPE_IPV4, /* IPv4协议 */        
    SESSION_L3_TYPE_IPV6, /* IPv6协议 */
    SESSION_L3_TYPE_MAX
}SESSION_L3_TYPE_E;

/* 四层协议类型 */
typedef enum enSESSION_L4_TYPE
{
    SESSION_L4_TYPE_TCP = 0,  /* TCP */
    SESSION_L4_TYPE_UDP,      /* UDP */
    SESSION_L4_TYPE_ICMP,     /* ICMP */
    SESSION_L4_TYPE_ICMPV6,   /* ICMPv6 */
    SESSION_L4_TYPE_UDPLITE,  /* UDP-Lite */
    SESSION_L4_TYPE_SCTP,     /* SCTP */
    SESSION_L4_TYPE_DCCP,     /* DCCP */
    SESSION_L4_TYPE_RAWIP,    /* 所有不属于以上四层协议的IP/IPv6报文归为此类 */
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

/* 获取会话表创建时间 */
#define SESSION_TABLE_GET_CREATE_TIME(_pSession, _uiCreateTime) \
	((_uiCreateTime) = (((SESSION_S *)(_pSession))->stSessionBase.uiSessCreateTime))

typedef union tagSessionAgingRcu
{
    AGINGQUEUE_UNSTABLE_OBJECT_S stAgingInfo;
}SESSION_AGING_RCU_U;

/* 会话报文方向 */
typedef enum SESSION_PKT_DIR
{	
    SESSION_DIR_ORIGINAL, /*正向: 报文方向为从发起方到响应方*/        
    SESSION_DIR_REPLY,    /*反向: 报文方向为从响应方到发起方*/
    SESSION_DIR_BOTH
}SESSION_PKT_DIR_E;

/*DCCP协议状态定义*/
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

/*ICMP协议状态定义*/
typedef enum tagIcmp_state
{
    ICMP_ST_NONE,
    ICMP_ST_REQUEST,
    ICMP_ST_REPLY,
    ICMP_ST_MAX
}ICMP_STATE_E;

/*RAWIP协议状态定义*/
typedef enum tagRawip_state
{
    RAWIP_ST_NONE,
    RAWIP_ST_OPEN,
    RAWIP_ST_READY,
    RAWIP_ST_MAX
}RAWIP_STATE_E;

/*SCTP协议状态定义*/
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

/*TCP协议状态定义*/
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

/*UDP协议状态定义*/
typedef enum tagUdp_state
{
    UDP_ST_NONE,
    UDP_ST_OPEN,
    UDP_ST_READY,
    UDP_ST_MAX
}UDP_STATE_E;

/*UDP-Lite协议状态定义*/
typedef enum tagUdplite_state
{
    UDPLITE_ST_NONE,
    UDPLITE_ST_OPEN,
    UDPLITE_ST_READY,        
    UDPLITE_ST_MAX,
}UDPLITE_STATE_E;

/*四层协议状态老化时间类型，如果需要添加其他类型，请务必加在最后*/
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
    UINT uiIp;         /* Ipv4地址 */
    UINT auiIp6[4];    /* Ipv6地址 */
    struct in_addr  stin;     /* Ipv4地址 */
    struct in6_addr stin6;   /* Ipv6地址 */
}SESSION_INET_ADDR_U;

typedef union tagSessionProtoSrc
{
    USHORT usAll;
    struct
    {
        USHORT usPort;         /* TCP协议的源端口 */
    }stTcp;
    struct
    {
        USHORT usPort;         /* UDP协议的源端口 */
    }stUdp;
    struct
    {
        USHORT usPort;         /* UDP-Lite协议的源端口 */
    }stUdpLite;
	struct
    {
        USHORT usSeq;          /* ICMP协议中的Seq字段 */
    }stIcmp;
    struct
    {
        USHORT usId;           /* ICMPv6协议中的ID字段 */
    }stIcmpv6;
    struct
    {
        USHORT usPort;         /* DCCP协议的源端口 */
    }stDccp;
    struct
    {
        USHORT usPort;         /* SCTP协议的源端口 */
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
        USHORT usPort;         /* TCP协议的目的端口 */
    }stTcp;
    struct
    {
        USHORT usPort;         /* UDP协议的目的端口 */
    }stUdp;
    struct
    {
        USHORT usPort;         /* UDP-Lite协议的目的端口 */
    }stUdpLite;
	struct
    {
        USHORT usId;           /* ICMP协议中的ID字段 */
    }stIcmp;
    struct
    {
        UCHAR ucType;          /* ICMPv6协议中的type字段 */
        UCHAR ucCode;          /* ICMPv6协议中的code字段 */
    }stIcmpv6;
    struct
    {
        USHORT usPort;         /* DCCP协议的目的端口 */
    }stDccp;
    struct
    {
        USHORT usPort;         /* SCTP协议的目的端口 */
    }stSctp;
    struct
    {
        USHORT usKey;          /* GRE key is 32bit, PPtp only uses 16bit */         
    }stGre;
}SESSION_PROTO_DST_U;

/* 会话管理会话表单向会话Key */
typedef struct tagSessionTupleStruct
{
    UCHAR ucL3Family;               /* 会话报文的三层协议类型，参考SESSION_L3_TYPE_E */
    UCHAR ucProtocol;               /* 会话报文的四层协议类型，参考SESSION_L4_TYPE_E */
    UCHAR ucType;                   /* 会话类型，标识是否是二层转发(对应cachekey中的ucType、组
                                       播类型(对应stCacheRoute.ucMCType)*/
    UCHAR ucRsv2;                   /* 填充字段*/
    SESSION_INET_ADDR_U unL3Src;    /* 源IP地址 */    
    SESSION_INET_ADDR_U unL3Dst;    /* 目的IP地址 */
    SESSION_PROTO_SRC_U unL4Src;    /* 源端口 */
    SESSION_PROTO_DST_U unL4Dst;    /* 目的端口 */
    UINT                uiTunnelID; /* Tunnel-ID */
    VRF_INDEX vrfIndex;             /* 所属的VPN VRF ID, 0表示公网 */
}SESSION_TUPLE_S;

typedef enum SESSION_APP_DIR
{
    DIR_IGNORE_PARENT = 0, /* 子会话首报文发起方和响应方和父会话一点关系都没有，
                              一般而言，不应该有这样的子会话存在，从关联表协商角度来说，
                              至少应该与父会话的发起方或响应方任何一方有联系*/
    DIR_PARENT_SRC_2_DST,  /* 子会话首报文发起发和响应方与父会话严格相同 */
    DIR_PARENT_DST_2_SRC,  /* 子会话首报文发起发和响应方与父会话严格相反 */
    DIR_PARENT_SRC_2_ANY,  /* 子会话首报文发起方与父会话首报文发起方相同，
                              但子会话首报文响应方不同于父会话首报文响应方 */
    DIR_PARENT_ANY_2_SRC,  /* 子会话首报文响应方与父会话首报文发起方相同，
                              但子会话首报文发起方不同于父会话首报文响应方 */
    DIT_PARENT_MAX = 0x0F
}SESSION_CHILD_DIR_E;

/* 老化时间无效值 */
#define SESSION_INVALID_VALUE       0
#define SESSION_CLEARALL_VALUE      100001

#define SESSION_TABLE_DEFAULT_TIMEOUT 2 /* 会话默认老化时间，单位为秒 */

/*丢包会话默认老化时间*/
#define SESSION_FASTDROP_DEFAULT_TIME  3
#define SESSION_FASTDROP_DEFAULT_RATIO 20

/* 丢包会话使能BIT位宏定义 */
#define SESSION_FAST_DROP_BIT_INVLID            0x0000
#define SESSION_FAST_DROP_BIT_ASPF_ENABLE       0x0001
#define SESSION_FAST_DROP_BIT_CONNLIMIT_ENABLE  0x0002
#define SESSION_FAST_DROP_BIT_ALL_ENABLE        (SESSION_FAST_DROP_BIT_ASPF_ENABLE | \
                                                 SESSION_FAST_DROP_BIT_CONNLIMIT_ENABLE)

#define SESSION_CORE_NUM_INVALID  ((UINT)-1)
/* ACL特殊编号，用于log和persistent */
#define SESSION_CFG_ACLNUM_NONE   0                          /* 无配置 */
#define SESSION_CFG_ACLNUM_ALL    0xFFFFFFFF                 /* 通配 */

/*各四层协议的最大状态个数*/
#define SESSION_PROTOCOL_STATE_MAX  10

/* 获取会话表创建时间 */
#define SESSION_TABLE_GET_CREATE_TIME(_pSession, _uiCreateTime) \
    ((_uiCreateTime) = (((SESSION_S *)(_pSession))->stSessionBase.uiSessCreateTime))
    
typedef enum tagDebugEventType
{
    EVENT_CREATE,         /* 表项创建,*/
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

/* IPv4和IPv6使用的通用IP地址结构. 其中的地址建议存储为网络序 */
typedef struct tagINET_ADDR
{
    uint16_t usFamily;             /* 地址协议族(AF_INET/AF_INET6) */
    uint16_t usReserved;           /* 保留字段 */
    union
    {
        struct in6_addr stIP6Addr;
        struct in_addr  stIP4Addr;
    } un_addr;                   /* IP地址字段 */

    #define uIP6_Addr    un_addr.stIP6Addr
    #define uIP4_Addr    un_addr.stIP4Addr
}INET_ADDR_S;

/* 关联表中的NAT扩展数据 */
typedef struct tagRelationAttachInfo
{
    IF_INDEX ifIndex;        /* ALG 载荷处理所在接口，跟转换使用的NAT配置所在接口可能不同(hairpin方式下)*/
    UINT uiNewTunnelID;      /* 子会话首报文转换后的TUNNELID */
    INET_ADDR_S stNewDstIP;  /* 子会话首报文转换后的目的地址 */
    USHORT usNewDstPort;     /* 子会话首报文转换后的目的端口 */
    USHORT usNewVpnID;       /* 子会话首报文转换后的route vpn */
    USHORT usMdcId;
    UCHAR ucProtocol;        /* 四层协议类型 */
    UCHAR ucArpPnpFlag;
    USHORT usCfgFlag;        /* NAT配置类型 */
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

/*会话表项的统计信息*/
typedef struct tagSessionNativeStat
{
    rte_atomic32_t astPackets[SESSION_DIR_BOTH]; /*会话报文数统计信息*/
    rte_atomic32_t astBytes[SESSION_DIR_BOTH];   /*会话字节数统计信息*/
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

/* 全局统计信息结构定义 */
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
    SESSION_RATE_STAT_S astRateStat[SESSION_L4_TYPE_MAX]; /* 每核每L4协议的会话新建速率,上一秒的值 */
    SESSION_FLOW_STAT_S astFlowStat[SESSION_L4_TYPE_MAX]; /* 每核每L4协议的包个数和字节统计 */
    SESSION_RATE_STAT_S stRelateTableRateStat;            /* 关联表创建速率统计 */
}SESSION_STAT_VCPU_S;

/* 会话表中记录的业务模块ID */
typedef enum SESSION_Module
{
    SESSION_MODULE_NAT = 0,            /* NAT模块 */
    SESSION_MODULE_CONNLMT,            /* 会话-连接数限制模块 */
    SESSION_MODULE_LB,                 /* LB模块 */
    SESSION_MODULE_ASPF,               /* ASPF模块 */
    SESSION_MODULE_LOG,                /* 会话管理-LOG子模块 */
    SESSION_MODULE_ALG,                /* 会话管理ALG模块 */
    SESSION_MODULE_DSLITE,             /* DS-Lite 模块 */
    SESSION_MODULE_TCPMSS,             /* TCP MSS 模块 */
    SESSION_MODULE_APPSTATICS,         /* 应用统计 */
    SESSION_MODULE_INTERZONE,          /* 域间业务 */
    SESSION_MODULE_WAAS,               /* WAAS业务 */
    SESSION_MODULE_TCPCHECK,           /* TCP序列号检查子模块 */
    SESSION_MODULE_AFT,                /* AFT模块 */
    SESSION_MODULE_DIM,                /* DIM引擎处理框架模块 */
    SESSION_MODULE_TCPREASSEMBLE,      /* TCP重组引擎处理模块 */
    SESSION_MODULE_TRAFFICLOG,         /* 会话流量日志业务 */
    SESSION_MODULE_MAX
}SESSION_MODULE_E;

/* 会话统计信息 */
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
    SESSION_NUM_STATISTICS_S astMaxSessNumStat[SESSION_NUMRATE_TYPE_MAX];  /*新增会话并发数最大值*/
    SESSION_NUM_STATISTICS_S astMaxSessRateStat[SESSION_NUMRATE_TYPE_MAX]; /*新增会话新建速率最大值*/
}SESSION_STATISTICS_S;

typedef struct tagSessionKStatistics
{
    rte_atomic32_t stTotalSessNum;                                /* 会话总数 */
    rte_atomic32_t stTotalRelationNum;                            /* 关联表总数 */
    rte_atomic32_t astProtoCount[SESSION_L4_TYPE_MAX];            /* 各L4协议对应的会话数 */
    rte_atomic64_t astSessAllStatCount[SESSION_ALLSTAT_TYPE_MAX]; /* 持续统计计数 */
    SESSION_STAT_VCPU_S *pstVcpuStat;
    rte_atomic32_t astAppCount[SESSION_APP_STATIC_MAX];
    ULONG ulLastJiffies;
}SESSION_K_STATISTICS_S;

/* alg 异常统计信息 */
typedef struct tagSessionPerCpuAlgFailCnt
{
    rte_atomic32_t astAlgFailCntGlobal4[SESSION_ALG_STAT_TYPE_MAX][SESSION_ALG_FAIL_TYPE_MAX];    
    rte_atomic32_t astAlgFailCntGlobal6[SESSION_ALG_FAIL_TYPE_MAX]; /*目前ipv6只支持FTP*/    
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

/* 需要将会话业务扩展指针加到session结构中pServicCb中的业务模块 */
typedef enum SESSION_Service
{
    SESSION_SERVICE_NAT = 0,       /*uiServicePos的0-3位记录NAT扩展信息在pServiceCb的位置*/
    SESSION_SERVICE_CONNLMT,       /*uiServicePos的4-7位记录CONNLMT扩展信息在pServiceCb的位置*/
    SESSION_SERVICE_LB,            /*uiServicePos的8-11位记录LB扩展信息在pServiceCb的位置*/
    SESSION_SERVICE_WAAS,          /*uiServicePos的12-15位记录WAAS扩展信息在pServiceCb的位置*/
    SESSION_SERVICE_ALG,           /*uiServicePos的16-19位记录ALG扩展信息在pServiceCb的位置*/
    SESSION_SERVICE_TCPCHECK,      /*uiServicePos的20-23位记录TCP check扩展信息在pServiceCb的位置*/
    SESSION_SERVICE_AFT,           /*uiServicePos的24-27位记录AFT扩展信息在pServiceCb的位置*/
    SESSION_SERVICE_DIM,           /*uiServicePos的28-31位记录DIM扩展信息在pServiceCb的位置*/
    SESSION_SERVICE_TCPREASSEMBLE, /*uiServicePos的32-35位记录TCP重组扩展信息在pServiceCb的位置*/
    SESSION_SERVICE_TRAFFICLOG,    /*uiServicePos的36-39位记录流量日志扩展信息在pServiceCb的位置*/
    SESSION_SERVICE_MAX,
    SESSION_SERVICE_STATIC = (UCHAR)-1, /*静态指针，标识业务模块以非动态方式加扩展信息*/
}SESSION_SERVICE_E;

/* 会话表信息key */
typedef struct tagSessionResetTableKey
{
    SESSION_TUPLE_S stTuple; /* 会话的key信息 */
    UINT uiModuleFlag;       /* 会话模块ID,参考SESSION_MODULE_E */
    UINT uiMask;             /* 使用SESSION_TABLE_BIT_E标识哪些参数有效*/
    UCHAR ucSessType;        /* 会话转义了的4层协议类型，参考SESSION_L4_TYPE_E */
    UINT uiIdentityID;
    UINT uiStopSession;      /* 停止会话流 */
    ZONE_ID zoneIDSrcID;
    ZONE_ID zoneIDDestID;
    UCHAR ucState;
    UINT uiAppID;  /* 应用协议ID */
    UINT uiStartTime;
    UINT uiEndTime;
    IF_INDEX ifIndex;
    UINT uiRuleID;
    UINT uiPolicyID;
}SESSION_TABLE_KEY_S;

/* 删除会话的参数信息 */
typedef struct tag_SessionResetMsgObjInfo
{
    AGINGQUEUE_RST_MSG_OBJECT_S stRstObj;
    SESSION_TABLE_KEY_S stKey;
}SESSION_RESET_OBJ_S;

/* 会话掩码位 */
typedef enum tagSESSION_TABLE_BIT
{
    SESSION_TABLE_BIT_PROT = 0,         /*标识会话的4层协议类型*/
    SESSION_TABLE_BIT_SRCIP,            /*标识SESSION_TUPLE_S中的源IP字段*/
    SESSION_TABLE_BIT_DSTIP,            /*标识SESSION_TUPLE_S中的目的IP字段*/
    SESSION_TABLE_BIT_SRCPORT,          /*标识SESSION_TUPLE_S中的源端口字段*/
    SESSION_TABLE_BIT_DSTPORT,          /*标识SESSION_TUPLE_S中的目的端口字段*/
    SESSION_TABLE_BIT_VPNID,            /*标识SESSION_TUPLE_S中的VPN VRF ID字段*/
    SESSION_TABLE_BIT_MODULE,           /*标识会话业务模块*/
    SESSION_TABLE_BIT_USERID,           /*标识会话用户ID*/
    SESSION_TABLE_BIT_USERGRPID,        /*标识会话用户组ID*/
    SESSION_TABLE_BIT_RESPVPNID,        /*标识会话响应方VPN*/
    SESSION_TABLE_BIT_LOCALCREATE,      /*标识会话板号*/
    SESSION_TABLE_BIT_RESPONDER,        /*标识响应方*/
    SESSION_TABLE_BIT_STOP,             /*标识SESSION STOP的时间段*/
    SESSION_TABLE_BIT_APP,              /*标识应用层协议*/
    SESSION_TABLE_BIT_ZONE,             /*标识源域*/
    SESSION_TABLE_BIT_STATE,            /*标识协议状态*/
    SESSION_TABLE_BIT_IFINDEX,          /*标识会话接口*/
    SESSION_TABLE_BIT_APPNAME,          /*标识应用application*/
    SESSION_TABLE_BIT_SECPNAME,         /*标识安全策略名称*/
    SESSION_TABLE_BIT_TIMERANGE,        /*标识时间段*/
    SESSION_TABLE_BIT_DSTZONE,          /*标识目的域*/
    SESSION_TABLE_BIT_DENYSESSION,      /*标识会话类型为丢包会话*/
}SESSION_TABLE_BIT_E;

#define SESSION_SET_PARABIT(_Flag, _Bit)  ((_Flag) |= ((UINT)1 << (_Bit)))
#define SESSION_CLEAR_PARABIT(_Flag,_Bit) ((_Flag) &= ~((UINT)1 << (_Bit)))
#define SESSION_IS_PARABIT_SET(_Flag, _Bit) (0 != ((_Flag) & ((UINT)1 << (_Bit))))

/*待删除会话标记设置和判断*/
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


/* 记录在MBUF中的会话标记位，以下前四个标记定义在mbuf.h中，SESSION继续定义其余的标记，
 * 请注意会话需要从mbuf.h中定义的位往后定义。
 */

/* 应用层协议名称最大长度*/
#define SESSION_APPNAME_MAX_LEN     63UL


/* 产品定制会话管理表项规格 */
typedef struct tagSESSIONConf
{
    UINT uiMaxSessionEntries;
}SESSION_CONF_S;

typedef struct tagSessionALGPacket
{
    SESSION_KALG_SEQ_CHECK_PF    pfAlgSeqCheckProc;      /* ALG的序列号调整慢转处理函数 */
    SESSION_KALG_FS_SEQ_CHECK_PF pfAlgFsSeqCheckProc;    /* ALG的序列号调整快转处理函数 */
    SESSION_KALG_SET_ACTION_PF   pfAlgSetAction;         /* ALG的应用层状态过滤处理函数 */
    SESSION_KALG_PPTPGREDATA_PF  pfAlgPptpGreData;       /* ALG的pptp gre data处理函数  */
    SESSION_KALG_SIPEST_PF       pfAlgSipEstProc;        /* ALG的sip稳态处理函数 */
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

/* 四层协议老化时间配置结构 */
typedef struct tagSessionL4Aging
{
	SESSION_PROT_AGING_TYPE_E enL4Type;
	UINT                      uiTimeValue;
	UINT                      uiTimeWaitAging; /* time_wait状态老化时间，单位为秒 */
	UINT                      uiCloseAging;    /* close状态老化时间，单位为秒 */
}SESSION_L4AGING_S;

/* 丢包会话配置结果 */
typedef struct tagSessionFDAging
{
	UINT uiTimeValue;
}SESSION_FASTDROP_AGING_S;

typedef struct tagSessionFDRatio
{
	UINT uiRatioValue;
}SESSION_FASTDROP_RATIO_S;

/* 会话日志策略配置结构 */
typedef struct tagSESSION_CfgLogPolicy
{
	IF_INDEX          ifIndex;
	UINT              uiAcNum;
	SESSION_L3_TYPE_E enL3Type;
	DIRECTION_E       enDirection;
	BOOL_T            bIsEnable;
}SESSION_CFG_LOGPOLICY_S;

/* 会话日志流量阈值配置结构 */
typedef struct tagSESSION_LogFlow
{
	SESSION_LOG_FLOWMODE_E enMode;
	UINT                   uiValue;
}SESSION_LOG_FLOW_S;

/* 注意，该结构体的值会在comsh与守护进程间传递，考虑issu，请务必将新值
	添加到最后*/
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

/* 四层协议默认老化时间（单位为秒） */
#define SESSION_TCP_SYN_OPEN_TIME     30    /* TCP半开会话默认老化时间 */
#define SESSION_TCP_FIN_CLOSE_TIME    30    /* TCP半关会话默认老化时间 */
#define SESSION_TCP_ESTABILISHED_TIME 3600  /* TCP稳态会话默认老化时间 */

#define SESSION_UDP_OPEN_TIME  30  /* UDP半开会话默认老化时间 */
#define SESSION_UDP_READY_TIME 60  /* UDP稳态会话默认老化时间 */

#define SESSION_ICMP_REQUEST_TIME  10  /* ICMP单向会话默认老化时间 */
#define SESSION_ICMP_REPLY_TIME    2   /* ICMP双向会话默认老化时间 */

#define SESSION_RAWIP_OPEN_TIME    30  /* RAWIP半开会话默认老化时间 */
#define SESSION_RAWIP_READY_TIME   60  /* RAWIP稳态会话默认老化时间 */

#define SESSION_UDPLITE_OPEN_TIME  30  /* UDPLITE半开会话默认老化时间 */
#define SESSION_UDPLITE_READY_TIME 60  /* UDPLITE稳态会话默认老化时间 */

#define SESSION_DCCP_REQUEST_OPEN_TIME    30    /* DCCP半开会话默认老化时间 */
#define SESSION_DCCP_CLOSEREQ_CLOSE_TIME  30    /* DCCP半关会话默认老化时间 */
#define SESSION_DCCP_ESTABILISHED_TIME    3600  /* DCCP稳态会话默认老化时间 */

#define SESSION_SCTP_INIT_OPEN_TIME       30    /* SCTP半开会话默认老化时间 */
#define SESSION_SCTP_SHUTDOWN_CLOSE_TIME  30    /* SCTP半关会话默认老化时间 */
#define SESSION_SCTP_ESTABILISHED_TIME    3600  /* SCTP稳态会话默认老化时间 */

#define SESSION_ICMPV6_REQUEST_TIME   60    /* ICMPv6单向会话默认老化时间 */
#define SESSION_ICMPV6_REPLY_TIME     30    /* ICMPv6双向会话默认老化时间 */

/* 应用层协议默认老化时间（单位为秒）*/
#define SESSION_PRO_FTP_CTRL_TIME   SESSION_TCP_ESTABILISHED_TIME           /*FTP控制连接默认老化时间*/
#define SESSION_PRO_DNS_TIME       1       /*DNS会话默认老化时间*/
#define SESSION_PRO_SIP_TIME       300       /*SIP会话默认老化时间*/
#define SESSION_PRO_RAS_TIME       300       /*RAS会话默认老化时间*/
#define SESSION_PRO_H225_TIME      3600        /*H225会话默认老化时间*/
#define SESSION_PRO_H245_TIME      3600        /*H245会话默认老化时间*/
#define SESSION_PRO_TFTP_TIME      60        /*TFTP会话默认老化时间*/
#define SESSION_PRO_GTP_TIME       60       /*GTP会话默认老化时间*/
#define SESSION_PRO_RTSP_TIME      3600        /*RTSP会话默认老化时间*/
#define SESSION_PRO_PPTP_TIME      3600        /*PPTP会话默认老化时间*/
#define SESSION_PRO_ILS_TIME       3600       /*ILS会话默认老化时间*/
#define SESSION_PRO_NBT_TIME       3600       /*NBT会话默认老化时间*/
#define SESSION_PRO_SCCP_TIME      3600        /*SCCP会话默认老化时间*/
#define SESSION_PRO_SQLNET_TIME    600          /*SQLNET会话默认老化时间*/
#define SESSION_PRO_XDMCP_TIME     3600         /*XDMCP会话默认老化时间*/
#define SESSION_PRO_MGCP_TIME      60        /*MGCP会话默认老化时间*/
#define SESSION_PRO_RSH_TIME       60       /*RSH会话默认老化时间*/

/* 应用层协议默认老化时间(单位为秒) */
#define SESSION_APP_DEFAULT_AGING   1200

/* 长连接默认老化时间 */
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


/* 会话类型 */
typedef enum enSESSION_TYPE
{
    SESSION_TYPE_NORMAL = 0, /* 普通 */
    SESSION_TYPE_MAX
}SESSION_TYPE_E;

/* 全局会话控制结构 */
typedef struct tagSessionCtrlData
{
	AGINGQUEUE_UNSTABLE_S stAgingQueue; /* 不稳定老化处理队列 */
	SESSION_K_STATISTICS_S stSessStat;
	AGINGQUEUE_UNSTABLE_CLASS_S astTableAgingClass[SESSION_L3_TYPE_MAX][SESSION_L4_TYPE_MAX][SESSION_PROTOCOL_STATE_MAX];
    AGINGQUEUE_UNSTABLE_CLASS_S astAppAgingClass[SESSION_L3_TYPE_MAX][SESSION_APP_AGING_MAX];
    AGINGQUEUE_UNSTABLE_S       stRelationQueue;  /* 关联表的不稳定老化处理队列 */
    AGINGQUEUE_UNSTABLE_S       stRelationAssociateQueue;   /* 关联表关联的不稳定老化处理队列 */
    AGINGQUEUE_CHANGEABLE_CLASS_S stIpv4RelationChangeClass;
    AGINGQUEUE_CHANGEABLE_CLASS_S stIpv6RelationChangeClass;
    SESSION_KLOG_GPARAM_S stSessionLogInfo;
    USHORT usCfgSeq;
    UINT uiSyncSeq;    /* 同步配置序号，用于内核配置平滑 */
    SESSION_DEBUG_S stDebug;
    UINT uiIFExtendEventHandle;
    BOOL_T bIsNewSessPermit; /* 是否允许新加session */
    BOOL_T bIsDelSessPermit; /* 是否允许删除session */
    BOOL_T bIsDebugSwitch; /* debug全局开关 */
    SESSION_SYNC_S stBackup; /* 会话热备开关和非对称流量开关 */
    BOOL_T bStatEnable; /* 统计的全局开关 */
    BOOL_T bSecEnable;  /* 是否开启安全功能 */
    rte_atomic32_t astStatFailCnt[SESSION_STAT_NR][SESSION_STAT_FAIL_TYPE_MAX];
    SESSION_ALGFAILCNT_S stAlgFail;
    SESSION_ALGSTAT_SWITCH_S stAlgStatSwitch;
    rte_spinlock_t stLogLock; /* 会话新建数目/速率告警信息发送锁 */
    AGINGQUEUE_UNSTABLE_CLASS_S stAppDefaultClass;
    AGINGQUEUE_UNSTABLE_CLASS_S stApp6DefaultClass;
    UCHAR *pucTcpStateTable; /* TCP状态机指针 */
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


/* 定义了所有子通道类型，与algtype区别，后者定义的是当前通道的alg类型 */
typedef enum enRELATION_AGING_TYPE
{
	RELATION_AGING_TYPE_FTPDATA,
	RELATION_AGING_TYPE_RAS,
	RELATION_AGING_TYPE_RAS_H225, /* 父通道ras创建的h225子通道 */	
	RELATION_AGING_TYPE_H225,     /* 父通道h225创建的h225子通道 */
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

#define SESSION_INVALID_HANDLE  0UL /* 无效的会话表HANDLE */
#define RELATION_INVALID_HANDLE 0UL /* 无效的关联表HANDLE */

typedef struct tagSessionAging 
{ 
    UINT64  uiUpdateTime;                       /*更新时间*/
    UCHAR   ucSessionType;                      /*会话类型 SESSION_TYPE_E*/
    UCHAR   ucSessionL4Type;                    /*会话4层类型，取值为SESSION_L4_TYPE_E*/            
    USHORT  usTableFlag;                        /*会话表项标记 见SESSION_TABLE_BITS_E*/ 
    SESSION_AGING_RCU_U unAgingRcuInfo;         /*锁及老化队列*/
    VOID *pCache[SESSION_DIR_BOTH];             /*初始建立时的入/出口*/
    SESSION_REF_COUNT_S stRefCount;             /*引用计数*/
#define uiSessCreateTime unAgingRcuInfo.stAgingInfo.ulRcuReserve
}SESSION_BASE_S; 

typedef struct tagSession
{
    SESSION_BASE_S stSessionBase;     /*快转老化会话数据*/
    SESSION_NATIVE_STAT_S stNativeStat; /*会话统计*/
    #define _astPackets stNativeStat.astPackets
    #define _astBytes   stNativeStat.astBytes
    UINT uiAppID;
    UINT uiTrustValue;       /*应用识别可信度*/
    USHORT usAttachFlag;
    USHORT usModuleFlag;    /*业务处理标记，见SESSION_MODULE_E*/
    USHORT usCfgSeq;        /*会话全局配置序号*/
    USHORT usAlgFlag;       /*ALG处理标记，业务模块对应的位置位表示该业务需要进行ALG处理*/
    UCHAR ucState;                      /*状态*/
    UINT uiOriginalAppID; /*记录会话创建时的AppID,后续不会发生变化*/
	struct tagSession *pstParent; /*派生此会话的父会话指针*/
    DL_HEAD_S stRelationList;        /*关联表链表*/
    VOID *pAlgCb;                    /*ALG的指针空间*/
    rte_spinlock_t stLock;
    USHORT usSessAlgType; /*记录会话对应的ALG类型*/
    UCHAR  ucDirAssociateWithParent;  /*取值范围:SESSION_CHILD_DIR_E,为了节省空间采用UCHAR*/
    UCHAR  ucAspfCfgSeq;              /*ASPF 配置序号*/
    UINT   uiDiff;	
    UINT   uiDirect;
    ULONG  aulModuleData[0];          /*当前只有ALG用，该字段必须放在会话结构体最后*/
}SESSION_S;

typedef struct SESSION_L3_PROTO
{
    /* 报文IP地址合法性检查 */
    ULONG (*pfPktCheck)(IN const MBUF_S *pstMBuf, IN UINT uiL3OffSet);

    /* 从报文获取3层信息，读取四层头位置 */
    VOID (*pfPktToTuple)(IN const MBUF_S *pstMBuf,
                         IN UINT uiL3OffSet,
                         INOUT SESSION_TUPLE_S *pstTuple);

    /* 从正向Tuple获取反向Tuple的3层信息 */
    VOID (*pfGetInvertTuple)(IN const SESSION_TUPLE_S *pstOrigTuple,
                             INOUT SESSION_TUPLE_S *pstInverseTuple);

    /* 获取四层协议号和四层协议头偏移位置 */
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
                         INOUT SESSION_TUPLE_S *pstTuple); /*从报文获取4层信息*/
    
    VOID (*pfGetInvertTuple)(IN SESSION_S *pstSession,
                             IN const SESSION_TUPLE_S *pstOrigTuple,
                             INOUT SESSION_TUPLE_S *pstInverseTuple); /*从正向Tuple获取反向Tuple的4层信息*/

    ULONG (*pfPacketCheck)(IN MBUF_S *pstMBuf,
                           IN UINT uiL3Offset,
                           IN UINT uiL4Offset); /*报文单包合法性检查*/

    ULONG (*pfNewSessCheck)(IN const MBUF_S *pstMBuf,
                            IN UINT uiL3OffSet,
                            IN UINT uiL4OffSet); /*首包创建会话合法性检查*/

    ULONG (*pfFirstPacket)(IN const MBUF_S *pstMBuf,
                           IN UINT uiL4OffSet,
                           INOUT SESSION_S *pstSession); /*会话首包处理*/
    
    ULONG (*pfState)(IN SESSION_S *pstSession,
                     IN MBUF_S *pstMBuf,
                     IN UINT uiL3OffSet,
                     IN UINT uiL4OffSet); /*协议状态机处理*/

    ULONG (*pfFastState)(IN SESSION_S *pstSession,
                         IN UINT uiL3OffSet,
                         IN UINT uiL4OffSet,
                         IN MBUF_S *pstMBuf,
                         IN SESSION_PKT_DIR_E enDir); /*协议状态机处理*/

    ULONG (*pfGetL4Payload)(IN MBUF_S *pstMBuf,
                            IN UINT uiL4OffSet,
                            OUT UINT *puiPayloadOff,
                            OUT UINT *puiPayloadLen); /*获得四层以上的负载偏移和负载长度*/

    ULONG (*pfFsbufGetL4Payload)(IN const MBUF_S *pstMBuf,
                                 IN const struct iphdr *pstIP,
                                 IN UINT uiL4OffSet,
                                 OUT UINT *puiPayloadOff,
                                 OUT UINT *puiPayloadLen); /*获得四层以上的负载偏移和负载长度*/

    ULONG (*pfFsbufIPv6GetL4Payload)(IN const MBUF_S *pstMBuf,
                                     IN const IP6_S *pstIP,
                                     IN UINT uiL4OffSet,
                                     OUT UINT *puiPayloadOff,
                                     OUT UINT *puiPayloadLen); /*获得四层以上的负载偏移和负载长度*/

    UCHAR (*pfGetReadyState)(VOID);  
}SESSION_L4_PROTO_S;

/* 会话事件处理回调函数 */
typedef VOID (*SESSION_KCREATE_CB_PF)(IN SESSION_HANDLE hSession);      /* 会话表创建回调函数 */
typedef VOID (*SESSION_KDELETE_CB_PF)(IN SESSION_HANDLE hSession);      /* 会话表删除回调函数 */
typedef VOID (*SESSION_KUPDATE_CB_PF)(IN SESSION_HANDLE hSession);      /* 会话表更新回调函数 */
typedef VOID (*SESSION_KACTIVE_CB_PF)(IN SESSION_HANDLE hSession);      /* 会话活跃回调函数 */
typedef ULONG (*SESSION_KEND_FAILED_CB_PF)(IN SESSION_HANDLE hSession,
                                           IN MBUF_S *pstMBuf,
                                           IN UINT uiL3Offset);         /* session-end流程失败回调函数 */
typedef VOID (*SESSION_EXT_DESTROY_CB_PF)(IN SESSION_HANDLE hSession, VOID *pCb); /* 扩展信息删除回调函数 */
typedef VOID (*RELATION_KCREATE_CB_PF)(IN RELATION_HANDLE hRelation); /* 关联表创建回调函数 */
typedef VOID (*RELATION_KDELETE_CB_PF)(IN RELATION_HANDLE hRelation); /* 关联表删除回调函数 */
typedef BOOL_T (*SESSION_KAGING_CB_PF)(IN SESSION_HANDLE hSession);   /* 会话表老化查询回调函数 */
typedef ULONG (*SESSION_KQUERY_TRANS_CB_PF)(IN SESSION_HANDLE hSession,
                                            IN DIRECTION_E enDir,
                                            OUT BOOL_T *pbSrcTranslated,
                                            OUT BOOL_T *pbDstTranslated);
typedef VOID (*SESSION_KSENDLOG_CB_PF)(IN const SESSION_S *pstSession, IN CHAR *pcReason, IN CHAR *pcDomainName);

typedef VOID (*SESSION_RESTOREMODULE_PF)(IN SESSION_HANDLE hSession);

typedef ULONG (*NEW_SESSION_BY_RELATION_PF)(IN SESSION_HANDLE hSession,
                                            IN const RELATION_ATTACH_INFO_S *pstAttachInfo,
                                            IN const MBUF_S *pstMbuf);

/* 并发添加会话扩展信息接口，pfGet获取，pfCreate添加，内部用锁保证互斥 */
typedef VOID*(*SESSION_ATTACH_CREATE_PF)(IN SESSION_HANDLE hSession, IN ULONG ulPara);

/* 业务模块注册结构 */
typedef struct tagSessionModuleReg
{
    SESSION_KCREATE_CB_PF pfSessCreate;     /* 会话表项创建事件通知 */    
    SESSION_KDELETE_CB_PF pfSessDelete;     /* 会话表项删除事件通知 */
    SESSION_KUPDATE_CB_PF pfSessUpdate;     /* 会话表项状态更新事件通知 */     
    SESSION_KACTIVE_CB_PF pfSessActive;     /* 会话表项定时遍历事件通知 */     
    SESSION_EXT_DESTROY_CB_PF pfExtDestroy; /* 会话表项释放内存事件通知 */ 
    SESSION_KEND_FAILED_CB_PF pfSessEndFailed; /* 会话表项正式化失败事件通知 */
    RELATION_KCREATE_CB_PF pfRelationCreate; /* 关联表项创建事件通知 */
    RELATION_KDELETE_CB_PF pfRelationDelete; /* 关联表项删除事件通知 */
    SESSION_KAGING_CB_PF pfSessAging; /* 会话表老化查询回调函数 */
    SESSION_KQUERY_TRANS_CB_PF pfSessQueryTrans; /* 查寻会话地址是否转换回调函数 */
    SESSION_KSENDLOG_CB_PF pfSessSendLog;
    USHORT usExtInfoNum;       /* 业务扩展信息使用的ULONG个数，Ext个数影响会话表分配内存的大小 */
}SESSION_MODULE_REG_S;

#define TUNNEL_INVALID_TUNNEL_ID 0
#define SESSION_GET_PERCPU_PTR(_pstBuf,_iCpuIndex) ((_pstBuf) + (_iCpuIndex))


extern SESSION_MODULE_REG_S g_astModuleRegInfo[SESSION_MODULE_MAX];
extern AGINGQUEUE_UNSTABLE_S g_stSessionstAgingQueue;
extern SESSION_CTRL_S g_stSessionCtrl;

VOID SESSION_KL4_Reg(IN const SESSION_L4_PROTO_S *pstRegInfo, IN UCHAR ucProto);
VOID SESSION_KL4_DeReg(IN UCHAR ucProto);
/* 获取报文处理用的3层，4层处理模块 */
ULONG session_kGetModule(IN MBUF_S *pstMBuf,
                         IN UINT   uiL3Offset,
                         OUT UINT *puiL4Offset,
                         OUT UCHAR *pucL4ProtoNum,
                         OUT UINT *puiIPLen,
                         OUT SESSION_L3_PROTO_S **ppstL3Proto,
                         OUT SESSION_L4_PROTO_S **ppstL4Proto);
ULONG SESSION_IpfsEndProc(IN USHORT usIPOffset, INOUT MBUF_S *pstMBuf);
/* IPv6转发流程中Session End 业务点的处理函数 */
ULONG SESSION6_IpfsEndProc(IN USHORT usIPOffset, INOUT MBUF_S *pstMBuf);
VOID SESSION6_KTouchProcess(INOUT MBUF_S *pstMbuf, IN SESSION_HANDLE hSession, IN UINT uiL3Offset);
SESSION_HANDLE SESSION6_KCreateProcess(INOUT MBUF_S *pstMbuf, IN UINT uiL3Offset);
/* 从报文中提取tuple参数 */
VOID session_kGetTuple(IN const MBUF_S *pstMBuf,
                       IN UINT uiL3Offset,
                       IN UINT uiL4Offset,
                       IN UCHAR ucL4ProtoNum,
                       IN const SESSION_L3_PROTO_S *pstL3Proto,
                       IN const SESSION_L4_PROTO_S *pstL4Proto,
                       INOUT SESSION_TUPLE_S *pstTuple);
VOID SESSION_DisDelete(IN SESSION_S *pstSession);
/* 根据表项指针，将双向快转表从hash表中摘除，不释放快转表内存 */
/* 会话表摘HASH */
VOID SESSION6_Delete(IN SESSION_S *pstSession);
INT scnprintf(OUT CHAR *pcBuf, IN size_t ulSize, IN const CHAR *pcFmt,...);
VOID SESSION_KDestroy(IN VOID *pSession);
VOID SESSION_KDeleteSession(IN SESSION_HANDLE hSession);
VOID AGINGQUEUE_UnStable_AddResetObj(IN AGINGQUEUE_UNSTABLE_S *pstQueue,
                                     IN AGINGQUEUE_RST_MSG_OBJECT_S *pstResetObj);

VOID SESSION6_KPut(IN SESSION_S *pstSession);

/* L3协议注册处理函数 */
VOID SESSION_KL3_Reg(IN const SESSION_L3_PROTO_S *pstRegInfo, IN UCHAR ucFamily);
/* L3协议注销处理函数 */
VOID SESSION_KL3_DeReg(IN UCHAR ucFamily);
ULONG SESSION6_McfsEndProc(IN VOID *pCache,IN USHORT usIPOffset, INOUT MBUF_S *pstMBuf);
ULONG SESSION_L2FsService(IN IF_INDEX ifIndex, IN VOID *pCache, INOUT MBUF_S *pstMBuf);
/* 获取4层协议处理结构 */
SESSION_L4_PROTO_S *SESSION_KGetL4Proto_Proc(IN UCHAR ucProto);
/*** 从appid获取会话的alg type ***/
USHORT SESSION_KGetSessionAlgType(IN UINT uiAppID);
/* 比较关联表HASH节点是否匹配 */
BOOL_T SESSION6_Relation_IsTupleMatch(IN const csp_key_t *pstTupleFromHash,
                                      IN const csp_key_t *pstNewTuple,
                                      IN UINT uiCmpMask);
/* 基于会话的安全业务快转入口 */
ULONG SESSION6_FsService(struct rte_mbuf *pstRteMbuf);
/*****************************************************************************
快转增加会话报文统计信息
*****************************************************************************/
VOID SESSION_FsAddStat(IN SESSION_S *pstSession,
					   IN const MBUF_S *pstMbuf,
					   IN SESSION_CTRL_S *pstSessionCtrl,
					   IN SESSION_PKT_DIR_E enPktDir);

/* 获得四层以上的负载和负载长度 */
ULONG SESSION_Util_GetL4Payload_Default(IN MBUF_S *pstMBuf,
                                        IN UINT uiL4OffSet,
                                        IN UINT uiL4HdrLen,
                                        OUT UINT *puiPayloadOff,
                                        OUT UINT *puiPayloadLen);
/* 获得四层以上的负载和负载长度 */
ULONG SESSION_Util_FsbufGetL4Payload_Default(IN const MBUF_S *pstMBuf,
                                             IN const struct iphdr *pstIP,
                                             IN UINT uiL4OffSet,
                                             IN UINT uiL4HdrLen,
                                             OUT UINT *puiPayloadOff,
                                             OUT UINT *puiPayloadLen);
/* 获得四层以上的负载和负载长度 */
ULONG SESSION6_Util_FsbufGetL4Payload_Default(IN const MBUF_S *pstMBuf,
                                              IN const IP6_S *pstIP6,
                                              IN UINT uiL4OffSet,
                                              IN UINT uiL4HdrLen,
                                              OUT UINT *puiPayloadOff,
                                              OUT UINT *puiPayloadLen);
VOID SESSION_KReset(IN const SESSION_TABLE_KEY_S *pstKey);
/* 获取定制信息 */
SESSION_AGINGQUE_CONF_S* SESSION_GetAgingqueConfInfo(VOID);
/* 根据3层协议类型获取3层协议处理结构 */
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
/* ALG协议去初始化 */
VOID SESSION_KALG_Fini(VOID);
/* 关联表子模块去初始化 */
VOID SESSION_KRelation_Exit(VOID);
VOID SESSION6_KRelation_Exit(VOID);
/* 关联表老化去初始化 */
VOID RELATION_KAging_Fini(VOID);
VOID RELATION6_KAging_Fini(VOID);
VOID AGINGQUEUE_UnStable_Destroy(AGINGQUEUE_UNSTABLE_S *pstAgingQue);
/* 去注册App Change事件*/
VOID APR_KAppChange_DeregFun(UINT uiModule);
/* 初始化会话表信息 */
ULONG SESSION_KTableRun(VOID);
/* 初始化关联表信息 */
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

/* 注意!!! 只能在worker thread调用 */
static inline UINT32 index_from_lcore_id(VOID)
{
    return rte_lcore_id()-1;
}

/* core 0是控制核, 所以排除掉 */
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

    /* 更新指定类型会话的全局流量统计 */
    pstFlowStat = &pstPerCpuStat->astFlowStat[enSessType];
	
    pstFlowStat->uiBytesCount += uiBytes;
    pstFlowStat->uiPacketsCount += uiPackets;
    
    return;
}

/******************************************************************
   Func Name:SESSION_KGetAppID
Date Created:2021/04/25
      Author:wangxiaohua
 Description:从会话表获取APPID
       INPUT:SESSION_HANDEL hSession, 会话
      Output:无
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

/* 根据会话一个方向的tuple获得反方向的tuple */
static inline VOID session_invert_tuple(IN SESSION_S *pstSession,
                                        IN const SESSION_TUPLE_S *pstOrig,
                                        IN const SESSION_L3_PROTO_S *pstL3Proto,
                                        IN const SESSION_L4_PROTO_S *pstL4Proto,
                                        OUT SESSION_TUPLE_S *pstInverse)
{
    /* 这里必须进行初始化，否则因其中v4和v6地址是union, 匹配会话时错误 */
    memset(pstInverse, 0, sizeof(SESSION_TUPLE_S));

    pstL3Proto->pfGetInvertTuple(pstOrig, pstInverse);
    pstL4Proto->pfGetInvertTuple(pstSession, pstOrig, pstInverse);

    return;
}

/******************************************************************
   Func Name:SESSION_IsIPv4LatterFrag
Date Created:2021/04/25
      Author:wangxiaohua
 Description:判断一个IPv4报文是否是后续分片报文
       INPUT:IN UINT uiL3OffSet       ----三层偏移
             IN MBUF_S *pstMBuf       ----报文             
      Output:无
      Return:BOOL_TRUE                ----后续分片
             BOOL_FALSE               ----非后续分片
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

    /* 当前session_end在链路层上下文，链路层头部可能和ip头不连续 */
    ulRet = MBUF_PULLUP(pstMBuf, (UINT)(uiL3OffSet + sizeof(struct iphdr)));
    if(unlikely(ERROR_SUCCESS != ulRet))
    {
        /* 如果pullup失败则当做分片处理，当前会将cache和会话删除 */
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

/* 判断SESSION向MBUF中是否设置单个FLAGBIT的动作 */
static inline BOOL_T SESSION_MBUF_TEST_FLAG(const IN MBUF_S *pstMBuf, IN USHORT usFlagBit)
{
    return (0 != ((UINT)pstMBuf->usSessionFlag & (UINT)usFlagBit));
}

/*** 业务模块向会话表设置ALG处理标记 ***/
static inline VOID SESSION_KSetAlgFlag (IN SESSION_HANDLE hSession, IN SESSION_MODULE_E enModule)
{
	SESSION_S *pstSession = (SESSION_S *) hSession;

	SESSION_TABLE_SET_ALGFLAG(pstSession, enModule);

	return;
}

/* 获取相反的报文方向 */
static inline SESSION_PKT_DIR_E SESSION_GetInvertDir(IN SESSION_PKT_DIR_E enDir)
{
    /*
        ORIGINAL  ->  REPLY
        REPLY     ->  ORIGINAL
    */

    return (SESSION_PKT_DIR_E)(1 ^ enDir);
}

/* 获取报文方向 */
static inline SESSION_PKT_DIR_E SESSION_GetDirFromMBuf(IN const MBUF_S *pstMBuf)
{
    return (MBUF_GET_SESSION_FLAG(pstMBuf) & SESSION_MBUF_REPLYPKT) ? SESSION_DIR_REPLY : SESSION_DIR_ORIGINAL;
}

/* 将SESSION_MODULE_E 转为SESSON_SERVICE_E */
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

    /* 输出Debug信息 
    SESSION_DBG_EXT_EVENT_SWITCH((SESSION_S *)hSession, SESSION_MODULE_ALG, EVENT_ADD);*/

    return;
}

/* 获取指定会话表的顶层父会话，空表示无父会话 */
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
/* IPv6转发流程中Session End 业务点的处理函数 */
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


/* 判断模块处理标记 */
static inline BOOL_T SESSION_KIsModuleFlagSet(IN SESSION_HANDLE hSession, IN SESSION_MODULE_E enModule)
{
    SESSION_S *pstSession = (SESSION_S *)hSession;
    
    return SESSION_TABLE_IS_MODULEFLAG_SET(pstSession, enModule);
}

/******************************************************************
   Func Name:SESSION_KAgingRefresh
Date Created:2021/04/25
      Author:wangxiaohua
 Description:刷新会话老化时间
       INPUT:IN SESSION_S *pstSession,  会话
      Output:无
      Return:无
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

/* 基于会话的安全业务快转入口 */ 
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

/* 设置模块处理标记 */
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
     *如果会话已经处理过该报文，则不必再处理，直接使用Mbuf中的会话指针，
     *避免不属于任何会话的报文多次处理.
     */
      
    hSession = (SESSION_HANDLE)GET_FWSESSION_FROM_LBUF(pstMbuf);

    /* 本报文已经处理过了 */
    if(SESSION_MBUF_TEST_FLAG(pstMbuf, SESSION_MBUF_PROCESSED))
    {
        return hSession;
    }

    /*本报文已经有会话表, 但是可能是回应报文或者配置序号变更导致重新触发慢转流程*/
    if(SESSION_INVALID_HANDLE != hSession)
    {
        SESSION_KTouchProcess(pstMbuf, hSession, uiL3Offset);
        
        return hSession;
    }

    /* 无会话需要创建 */
    return SESSION_KCreateProcess(pstMbuf, uiL3Offset);    
}

static inline SESSION_HANDLE SESSION6_KGetSessionFromMbuf(INOUT MBUF_S *pstMbuf, IN UINT uiL3Offset)
{	
    SESSION_HANDLE hSession;

    /*
     *如果会话已经处理过该报文，则不必再处理，直接使用Mbuf中的会话指针，
     *避免不属于任何会话的报文多次处理.
     */
      
    hSession = (SESSION_HANDLE)GET_FWSESSION_FROM_LBUF(pstMbuf);

    /* 本报文已经处理过了 */
    if(SESSION_MBUF_TEST_FLAG(pstMbuf, SESSION_MBUF_PROCESSED))
    {
        return hSession;
    }

    /*本报文已经有会话表, 但是可能是回应报文或者配置序号变更导致重新触发慢转流程*/
    if(SESSION_INVALID_HANDLE != hSession)
    {
        SESSION6_KTouchProcess(pstMbuf, hSession, uiL3Offset);
        
        return hSession;
    }

    /* 无会话需要创建 */
    return SESSION6_KCreateProcess(pstMbuf, uiL3Offset);    
}

static inline VOID SESSION_KAging_Add(IN AGINGQUEUE_UNSTABLE_S *pstAgingQueue, IN SESSION_S *pstSession)
{
    SESSION_KAgingRefresh(pstSession);
    AGINGQUEUE_UnStable_Add(pstAgingQueue, &pstSession->stSessionBase.unAgingRcuInfo.stAgingInfo);

    return;
}

/* 拷贝IPv6地址 */
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

/* 判断Ipv6地址是不是链路本地地址 */
static inline BOOL_T IN6ADDR_IsLinkLocal(IN const struct in6_addr *pstAddr)
{
	const UCHAR *pucAddr;

	pucAddr = pstAddr->s6_addr;

	return ((pucAddr[0] == 0xfe) && ((pucAddr[1] & 0xc0) == 0x80));
}

/* 判断Ipv6地址是不是未指定地址(即全0)*/
static inline BOOL_T IN6ADDR_IsUnspecified(IN const struct in6_addr *pstAddr)
{
    const UINT *puiAddr;

    puiAddr = pstAddr->s6_addr32;

    return ((puiAddr[0] == 0) && (puiAddr[1] == 0) && (puiAddr[2] == 0) && (puiAddr[3] == 0));
}

/******************************************************************
 Description:判断Ipv6地址是不是多播地址
       INPUT:pstAddr:待判断的IPv6地址
      Output:无
      Return:BOOL_TRUE: 是多播地址
             BOOL_FALSE:不是多播地址
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
Description∶ 判断Ipv6地址是不是环回地址(::1)
********************************************************************/
static inline BOOL_T IN6ADDR_IsLoopback(IN const struct in6_addr *pstAddr)
{
	const UINT *puiAddr;

	puiAddr = pstAddr->s6_addr32;

	return((puiAddr[0] == 0) && (puiAddr[1] == 0) &&
		   (puiAddr[2] == 0) && (puiAddr[3] == htonl(1)));
}


#endif
