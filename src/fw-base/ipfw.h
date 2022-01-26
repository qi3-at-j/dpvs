#ifndef _IPFW_H_
#define _IPFW_H_

//#include "in.h"

#include <netinet/in.h>

/*ip fragment flag*/
#define IP_DF         0x4000 /* dont fragment flag */
#define IP_MF         0x2000 /* more fragments flag */
#define IP_OFFMASK    0x1fff /* mask for fragment */

#if 0
/* IPv4 报文头数据结构定义 */
typedef struct tagIP
{
    #if defined(_LITTLE_ENDIAN_BITFIELD)
    UINT8    ucHLen:4;            /* header length */
    UINT8    ucVer:4;             /* version */
    #elif defined(_BIG_ENDIAN_BITFIELD)
    UINT8    ucVer:4;             /* version */
    UINT8    ucHLen:4;            /* header length */
    #else
    #error "Adjust your <asm/byteorder.h> defines"
    #endif
    UINT8    ucTOS;               /* type of service */
    UINT16   usLen;               /* total length */
    UINT16   usId;                /* identification */
    UINT16   usOff;               /* fragment offset field */
    UINT8    ucTTL;               /* time to live */
    UINT8    ucPr;                /* protocol */
    UINT16   usSum;               /* checksum */
    INADDR_S stIpSrc;             /* source address */
    INADDR_S stIpDst;             /* dest address */
}__attribute__((packed)) IP_S;
#endif

/* IP 转发业务阶段点定义 */
typedef enum tagIpfw_Phase
{
    IPFW_PRE_ALL,                  /* 接收报文入口阶段 */
    IPFW_PRE_ROUTING,              /* 接收报文预处理阶段 */
    IPFW_PRE_ROUTING2,             /* 接收报文预处理阶段2 */
    IPFW_POST_ROUTING,             /* 接收报文查询路由后处理阶段 */
    IPFW_LOCAL_IN_BEFOREDEFRAG,    /* 到本机报文重组前处理阶段 */
    IPFW_LOCAL_IN,                 /* 到本机报文处理阶段 */
    IPFW_LOCAL_OUT_PRE_ROUTING,    /* 本机发送报文查询路由前处理阶段 */    
    IPFW_LOCAL_OUT,                /* 本机发送报文处理阶段 */
    IPFW_LOCAL_OUT_POST_ROUTING,   /* 本机发送报文查询路由后处理阶段 */
    IPFW_POST_ROUTING_BEFOREFRAG,  /* 出接口发送分片前预处理阶段 */    
    IPFW_POST_ROUTING_BEFOREFRAG2, /* 出接口发送分片前预处理阶段2 */
    IPFW_PRE_RELAY,
    IPFW_RELAY_RECEIVE,
    IPFW_POST_ROUTING_AFTERFRAG,   /* IP_PACKET_TRACE 分片后报文的业务阶段，用于记录报文分片的操作 */
    IPFW_PHASE_BUTT
}IPFW_PHASE_E;

/* 接收报文入口处理阶段 */
typedef enum tagIpfw_PreAll
{
    IPFW_PRE_ALL_VYS,              /* 新增VSYS业务点，用于丢包模拟重启 */
    IPFW_PRE_ALL_PKTTRACE,         /* 报文示踪业务，务必放在需要示踪的业务点前 */
    IPFW_PRE_ALL_IPCAR,
    IPFW_PRE_ALL_AGENT,
    IPFW_PRE_ALL_ISG,
    IPFW_PRE_ALL_IPMAC,
    IPFW_PRE_ALL_ATKPROXY,
    IPFW_PRE_ALL_APPPROXY,
    IPFW_PRE_ALL_BUTT
}IPFW_PRE_ALL_SERVICEID_E;

/* 接收报文预处理阶段 */
typedef enum tagIpfw_PreRouting
{
    IPFW_PRE_ROUTING_DROP_PACKET,
    IPFW_PRE_ROUTING_BALANCE,
    IPFW_PRE_ROUTING_PKTTRACE,        /* 报文示踪业务，务必放在需要示踪的业务点前 */
    IPFW_PRE_ROUTING_IP_PTRACE,       /* IP_PACKET_TRACE, IP转发用于记录报文的轨迹信息 */
    IPFW_PRE_ROUTING_OFP,             /* OpenFlow业务，务必保证第一个业务 */
    IPFW_PRE_ROUTING_TCPREASSEMBLE,   /* TCP重组 */
    IPFW_PRE_ROUTING_NETSTREAM,       /* NETSTRAM业务 */
    IPFW_PRE_ROUTING_MGROUP,          /* Mirror Group处理 */
    IPFW_PRE_ROUTING_IPSEC,           /* IPsec 预处理 */
    IPFW_PRE_ROUTING_IPSECANTIATTACK, /* IPsec防攻击处理 */
    IPFW_PRE_ROUTING_FLOWMGR,
    IPFW_PRE_ROUTING_ATK,
    IPFW_PRE_ROUTING_SCD,             /* 异常外联防护项目 */
    IPFW_PRE_ROUTING_LBPRE,
    IPFW_PRE_ROUTING_IPOE,
    IPFW_PRE_ROUTING_WEBREDIRECT,
    IPFW_PRE_ROUTING_PORTAL,
    IPFW_PRE_ROUTING_TWAMP,           /* TWAMP业务 */
    IPFW_PRE_ROUTING_APR,             /* 协议识别 */
    IPFW_PRE_ROUTING_APPSTAT,         /* 流量统计 */
    IPFW_PRE_ROUTING_BPASTAT,         /* 基于BGP策略的流量统计 */
    IPFW_PRE_ROUTING_CONNLMT,         /* 连接数限制 */
    IPFW_PRE_ROUTING_AUTHORIZE,       /* 授权检查处理阶段 */
    IPFW_PRE_ROUTING_FILTER,          /* ASPF 和 PFLT 的共同处理阶段 */
    IPFW_PRE_ROUTING_MIP,             /* 移动 IP */
    IPFW_PRE_ROUTING_NAT,             /* NAT入接口业务处理 */
    IPFW_PRE_ROUTING_WLAN,            /* NAT转换后WLAN处理 */
    IPFW_PRE_ROUTING_LB,              /* LB负载均衡处理阶段 */
    IPFW_PRE_ROUTING_QPPB,            /* QPPB */
    IPFW_PRE_ROUTING_PRIMAP,
    IPFW_PRE_ROUTING_QOS,             /* Qos */
    IPFW_PRE_ROUTING_BUTT       
}IPFW_PRE_ROUING_SERVICEID_E;

/* 接收报文预处理阶段 */
typedef enum tagIpfw_PreRouting2
{
    IPFW_PRE_ROUTING2_TCPMSS,             /* TCP MSS */  
    IPFW_PRE_ROUTING2_DSLITE,             /* DS-Lite */
    IPFW_PRE_ROUTING2_AFT,                /* 地址转换 */
    IPFW_PRE_ROUTING2_KEEPLASTHOP,        /* 保持上一跳业务 */
    IPFW_PRE_ROUTING2_PPP,                /* PPP流量计费统计业务 */
    IPFW_PRE_ROUTING2_PMM,    
    IPFW_PRE_ROUTING2_WAAS_DECOMPRESS,    
    IPFW_PRE_ROUTING2_UCC,
    IPFW_PRE_ROUTING2_DNSSP,    
    IPFW_PRE_ROUTING2_BUTT
}IPFW_PRE_ROUTING2_SERVICEID_E;

/* 接收报文查询路由后处理阶段 */
typedef enum tagIpfw_PostRouting
{
    IPFW_POST_ROUTING_IP_PTRACE,      /* IP_PACKET_TRACE, IP转发用于记录报文的轨迹信息，注意移动业务枚举保证32bit */
    IPFW_POST_ROUTING_IPDFMODIFY,
    IPFW_POST_ROUTING_TNLSERVICECLASS,
    IPFW_POST_ROUTING_MFWSERVICECLASS,
    IPFW_POST_ROUTING_PBR,
    IPFW_POST_ROUTING_FSPC,
    IPFW_POST_ROUTING_RIR,    
    IPFW_POST_ROUTING_LB,    
    IPFW_POST_ROUTING_LISP,    
    IPFW_POST_ROUTING_OFP,
    IPFW_POST_ROUTING_NGX,    
    IPFW_POST_ROUTING_WAAS_COMPRESS,    
    IPFW_POST_ROUTING_WAAS,    
    IPFW_POST_ROUTING_NAT,  /* 腾讯VSG专线堆叠+NAT组网场景中，NAT业务配合快转处理存在问题 */ 
    IPFW_POST_ROUTING_IPSERVICE,    
    IPFW_POST_ROUTING_LICMGR,    
    IPFW_POST_ROUTING_BUTT
}IPFW_POST_ROUTING_SERVICEID_E;

/* IPv4处理上送本机重组前业务ID */
typedef enum tagIpfw_LocalInBeforeDefrag
{
    IPFW_LOCAL_IN_BEFOREDEFRAG_IP_PTRACE, /* IP_PACKET_TRACE, IP转发用于记录报文的轨迹信息，注意移动业务枚举保证32bit */
    IPFW_LOCAL_IN_INTERZONE,              /* 域间处理阶段 */     
    IPFW_LOCAL_IN_ATK,    
    IPFW_LOCAL_IN_CONNLMT,                /* 连接数限制 */    
    IPFW_LOCAL_IN_UDPI,                   /* 做用户态DPI业务，必须在DIM之前 */    
    IPFW_LOCAL_IN_APPL7,                  /* DIM的业务 */    
    IPFW_LOCAL_IN_NETSESSION,    
    IPFW_LOCAL_IN_BEFOREDEFRAG_BUTT
}IPFW_LOCAL_IN_BEFOREDEFRAG_SERVICEID_E;

/* 到本机报文处理阶段 */
typedef enum tagIpfw_LocalIn
{
    IPFW_LOCAL_IN_IP_PTRACE,  /* IP_PACKET_TRACE, IP转发用于记录报文的轨迹信息，注意移动业务枚举保证32bit */
    IPFW_LOCAL_IN_GTSM,
    IPFW_LOCAL_IN_BFD,
    IPFW_LOCAL_IN_UDPH,
    IPFW_LOCAL_IN_TCP_PROXY,
    IPFW_LOCAL_IN_LISP,
    IPFW_LOCAL_IN_WLAN,       /* 上送本机的WLAN处理 */
    IPFW_LOCAL_IN_BUTT
}IPFW_LOCAL_IN_SERVICEID_E;

/* 本机发送报文处理阶段 */
typedef enum tagIPfw_LocalOutPreRouting
{
    /*IPV4此阶段暂时无业务*/
    IPFW_LOCAL_OUT_PRE_ROUTING_BUTT
}IPFW_LOCAL_OUT_PRE_ROUTING_SERVICEID_E;

/* 本机发送报文处理阶段 */
typedef enum tagIPfw_LocalOut
{
    IPFW_LOCAL_OUT_VSYS,
    IPFW_LOCAL_OUT_BALANCE,
    IPFW_LOCAL_OUT_PKTTRACE,     /* 报文示踪业务，务必放在需要示踪的业务点前 */
    IPFW_LOCAL_OUT_IP_PTRACE,    /* IP_PACKET_TRACE, IP转发用于记录报文的轨迹信息，注意移动业务枚举保证32bit */
    IPFW_LOCAL_OUT_INTERZONE,    /* 域间处理阶段 */
    IPFW_LOCAL_OUT_DSLITE,       /* DS-LITE业务处理阶段 */
    IPFW_LOCAL_OUT_DHCPSP,       /* DHCP snooping处理 */
    IPFW_LOCAL_OUT_WAAS,
    IPFW_LOCAL_OUT_KEEPLASTHOP,  /* 保持上一跳业务 */
    IPFW_LOCAL_OUT_LB,           /* LB处理 */
    IPFW_LOCAL_OUT_BUTT
}IPFW_LOCAL_OUT_SERVICEID_E;

/* 本机发送报文查询路由后处理阶段 */
typedef enum tagIpfw_LocalOutPostRouting
{
    IPFW_LOCAL_OUT_POST_ROUTING_IP_PTRACE,    /* IP_PACKET_TRACE, IP转发用于记录报文的轨迹信息，注意移动业务枚举保证32bit */
    IPFW_LOCAL_OUT_POST_ROUTING_MFSERVICECLASS,
    IPFW_LOCAL_OUT_POST_ROUTING_PBR,
    IPFW_LOCAL_OUT_POST_ROUTING_LISP,
    IPFW_LOCAL_OUT_POST_ROUTING_OFP,
    IPFW_LOCAL_OUT_POST_ROUTING_OVERLAY,
    IPFW_LOCAL_OUT_POST_ROUTING_LICMGR,
    IPFW_LOCAL_OUT_POST_ROUTING_DNSSP,
    IPFW_LOCAL_OUT_POST_ROUTING_BUTT
}IPFW_LOCAL_OUT_POST_ROUTING_SERVICEID_E;

/* 出接口发送分片前预处理阶段 */
typedef enum tagIpfw_PostRoutingBeforeFrag
{
    IPFW_POST_ROUTING_BEFOREFRAG_IP_PTRACE,    /* IP_PACKET_TRACE, IP转发用于记录报文的轨迹信息，注意移动业务枚举保证32bit */
    IPFW_POST_ROUTING_BEFOREFRAG_FLOWMGR,      /* 二次引流业务阶段 */    
    IPFW_POST_ROUTING_BEFOREFRAG_FILLTAG,      /* 报文数据域填充 */    
    IPFW_POST_ROUTING_BEFOREFRAG_INTERZONE,    /* 域间处理阶段 */
    IPFW_POST_ROUTING_BEFOREFRAG_LB,           /* LB负载均衡处理阶段 */
    IPFW_POST_ROUTING_BEFOREFRAG_SSLVPN,
    IPFW_POST_ROUTING_BEFOREFRAG_WLAN,         /* NAT转换前WLAN处理 */
    IPFW_POST_ROUTING_BEFOREFRAG_NAT,          /* 出接口NAT业务处理 */
    IPFW_POST_ROUTING_BEFOREFRAG_FILTER,       /* ASPF和PFLT的共同处理阶段 */
    IPFW_POST_ROUTING_BEFOREFRAG_AUTHORIZE,    /* 授权检查处理阶段 */
    IPFW_POST_ROUTING_BEFOREFRAG_ATK,          /* ATK */
    IPFW_POST_ROUTING_BEFOREFRAG_MIP,          /* 移动 IP */
    IPFW_POST_ROUTING_BEFOREFRAG_CONNLMT,      /* 连接数限制 */    
    IPFW_POST_ROUTING_BEFOREFRAG_APR,          /* 协议识别 */    
    IPFW_POST_ROUTING_BEFOREFRAG_APPSTAT,      /* 流量统计 */
    IPFW_POST_ROUTING_BEFOREFRAG_BPASTAT,      /* 基于BGP策略的流量统计 */
    IPFW_POST_ROUTING_BEFOREFRAG_UDPI,         /* 做用户态DPI业务，必须在DIM之前 */
    IPFW_POST_ROUTING_BEFOREFRAG_APPL7,        /* DIM的业务 */
    IPFW_POST_ROUTING_BEFOREFRAG_APPPROXY,    
    IPFW_POST_ROUTING_BEFOREFRAG_NETSESSION,
    IPFW_POST_ROUTING_BEFOREFRAG_PORTAL,
    IPFW_POST_ROUTING_BEFOREFRAG_IPOE,
    IPFW_POST_ROUTING_BEFOREFRAG_ADVPN,    
    IPFW_POST_ROUTING_BEFOREFRAG_PREQOS,       /* Qos预处理 */    
    IPFW_POST_ROUTING_BEFOREFRAG_TCPMSS,
    IPFW_POST_ROUTING_BEFOREFRAG_TWAMP,    
    IPFW_POST_ROUTING_BEFOREFRAG_RAW_NETSTREAM,
    IPFW_POST_ROUTING_BEFOREFRAG_IPSEC,        /* IPsec 出方向报文处理 */    
    IPFW_POST_ROUTING_BEFOREFRAG_NETSTREAM,    
    IPFW_POST_ROUTING_BEFOREFRAG_MGROUP,       /* Mirror Group处理 */    
    IPFW_POST_ROUTING_BEFOREFRAG_NGINX,    
    IPFW_POST_ROUTING_BEFOREFRAG_BUTT
}IPFW_POST_ROUTING_BEFOREFRAG_SERVICEID_E;

/* 出接口发送分片前预处理阶段超过31个，故增加此阶段 */
typedef enum tagIpfw_PostRoutingBeforeFrag2
{
    IPFW_POST_ROUTING_BEFOREFRAG2_WAAS,
    IPFW_POST_ROUTING_BEFOREFRAG2_OFP,         /* 后Openflow处理 */
    IPFW_POST_ROUTING_BEFOREFRAG2_ALGFRAG,     /* ALG业务处理 */
    IPFW_POST_ROUTING_BEFOREFRAG2_UCC,
    IPFW_POST_ROUTING_BEFOREFRAG2_BUTT
}IPFW_POST_ROUTING_BEFOREFRAG2_SERVICEID_E;

/* 报文透传前阶段 */
typedef enum tagIpfw_PreRelay
{
    IPFW_PRE_RELAY_INTERZONE,     /* 域间处理阶段 */        
    IPFW_PRE_RELAY_CONNLMT,       /* 连接数限制 */
    IPFW_PRE_RELAY_APPL7,
    IPFW_PRE_RELAY_LICMGR,
    IPFW_PRE_RELAY_ALG,
    IPFW_PRE_RELAY_BUTT
}IPFW_PRE_RELAY_SERVICEID_E;

/* 报文透传接收阶段 */
typedef enum tagIpfw_RelayReceive
{
    IPFW_RELAY_RECEIVE_INTERZONE,   /* 域间处理阶段 */
    IPFW_RELAY_RECEIVE_DSLITE,      /* DS-Lite处理 */
    IPFW_RELAY_RECEIVE_BUTT
}IPFW_RELAY_RECEIVE_SERVICEID_E;

/* IP_PACKET_TRACE, IP转发用于记录报文的轨迹信息，注意移动业务枚举保证32bit */
/* 报文分片后发送阶段 */
typedef enum tagIpfw_PostRoutingAfterFrag
{
    IPFW_POST_ROUTING_AFTERFRAG_IP_PTRACE,
    IPFW_POST_ROUTING_AFTERFRAG_BUTT
}IPFW_POST_ROUTING_AFTERFRAG_SERVICEID_E;

/* IP 转发业务返回值定义 */
typedef enum tagIPFW_ServiceRet
{
    PKT_CONTINUE,     /* 由外围调用者继续处理 */
    PKT_DROPPED,      /* 报文已经被丢弃 */
    PKT_CONSUMED,     /* 报文已经被消费处理 */
    PKT_ENQUEUED,     /* 报文已经被放入队列 */
    PKT_RELAY         /* 报文要求进行透传 */
}IPFW_SERVICE_RET_E;

/* IP 转发提供给FIB的转发属性定义 */
typedef enum tagIpfw_FIB_FwdType
{
    IPFW_FIB_FORWARDING,  /* 单播转发 */        
    IPFW_FIB_LOOPBACK,    /* 上送本机 */    
    IPFW_FIB_BROADCAST,   /* 广播 */
    IPFW_FIB_MULTICAST,   /* 组播 */
    IPFW_FIB_LINKLOCAL,   /* 链路本地 */
    IPFW_FIB_LABLE,       /* MPLS标签 */
    IPFW_FIB_NHLFE,       /* MPLS NHLFE出 */
    IPFW_FIB_TRSEND,      /* 透传其它板 */
    IPFW_FIB_TRMASTER,    /* 透传主控板 */
    IPFW_FIB_BLACKHOLE,   /* 对应BLACKHOLE属性邻接表 */
    IPFW_FIB_REECT,       /* 对应REJECT属性邻接表 */ 
    IPFW_FIB_FWDTYPE_BUT
}IPFW_FIB_FWDTYPE_E;

#endif

