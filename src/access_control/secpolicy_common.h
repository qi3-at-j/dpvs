#ifndef _SECPOLICY_COMMON_H_
#define _SECPOLICY_COMMON_H_

#ifdef __cplusplus
extern "C"{
#endif

#include "basetype.h"
#include "extlist.h"
//#include "../fw-base/in.h"
#include <netinet/in.h>
#include <rte_rwlock.h>
#include <rte_atomic.h>

#define INVALID_TCPIP_PROTOCOL_ID 0xff

#define TENANT_ID_MAX  36
#define SECPOLICY_RULE_DECRIPTION_MAX 127
#define SECPOLICY_RULEID_SUM_MAX      1024

typedef enum enSecPolicy_Type
{
    SECPOLICY_TYPE_RESERVE,
    SECPOLICY_TYPE_EXTBODER, 
    SECPOLICY_TYPE_VPCBODER, 
    SECPOLICY_TYPE_MAX
}SECPOLICY_TYPE_E;

typedef struct tagIPAddr
{
    UINT uiIPType;  /* IPPROTO_IPV4  4; IPPROTO_IPV6   41; from in.h */
    union
    {
        struct in_addr  stIP4Addr;
        struct in6_addr stIP6Addr;
    }_ip_data;
    #define _ip4_addr   _ip_data.stIP4Addr.s_addr
    #define _ip6_addr   _ip_data.stIP6Addr.s6_addr
    #define _ip6_addr16 _ip_data.stIP6Addr.s6_addr16    
    #define _ip6_addr32 _ip_data.stIP6Addr.s6_addr32
}IP_ADDR_S;

typedef struct tagSecPolicyIPAddr_Node
{
    SL_NODE_S stNode;
    IP_ADDR_S stIPAddr;
}SECPOLICY_IPADDR_NODE_S;

typedef struct tagSecPolicy_ExtFlow_Node
{
    SL_NODE_S stNode;
    SL_HEAD_S stHead;  /* SECPOLICY_IPADDR_NODE_S */
    UCHAR szTenantID[TENANT_ID_MAX+1];
    rte_rwlock_t rwlock_ext_flow;
}SECPOLICY_EXT_FLOW_NODE_S;

typedef struct tagIPAddrMask
{
    IP_ADDR_S stIPAddr;
    UINT      uiIPMaskLen;
}IP_ADDR_MASK_S;

typedef struct tagSecPolicyIPAddrMask_Node
{
    SL_NODE_S stNode;
    IP_ADDR_MASK_S stIPAddrMask;
}SECPOLICY_IPADDR_MASK_NODE_S;

typedef struct tagSecPolicy_VPCFlow_Node
{
    SL_NODE_S stNode;
    SL_HEAD_S stHead;  /* SECPOLICY_IPADDR_MASK_NODE_S */
    UINT uiVxlanID;
    rte_rwlock_t rwlock_vpc_flow;
}SECPOLICY_VPC_FLOW_NODE_S;

typedef struct tagSecPolicy_Flow
{
    SL_HEAD_S stExtHead;    /* SECPOLICY_EXT_FLOW_NODE_S */
    SL_HEAD_S stVPCHead;    /* SECPOLICY_VPC_FLOW_NODE_S */
}SECPOLICY_FLOW_S;

typedef enum tagSecPolicy_MulTiIPType
{
    MULTITYPE_RESERVE,
    MULTITYPE_SINGLEIP,
    MULTITYPE_IPGROUP,
    MULTITYPE_MAX
}SECPOLICY_MULTIIP_TYPE_E;

typedef struct tagSecPolicy_MultiIP
{
    SECPOLICY_MULTIIP_TYPE_E enIPType;
    union{
        IP_ADDR_S stIPAddr;
        UINT      uiIPGroupID;
    }_multi_ip;
    UINT uiIPMaskLen;
    #define _multi_ip_type      _multi_ip.stIPAddr.uiIPType
    #define _multi_ip4_addr     _multi_ip.stIPAddr._ip4_addr
    #define _multi_ip6_addr     _multi_ip.stIPAddr._ip6_addr
    #define _multi_ip6_addr16   _multi_ip.stIPAddr._ip6_addr16
    #define _multi_ip6_addr32   _multi_ip.stIPAddr._ip6_addr32
}SECPOLICY_L3_MULTIIP_S;

/* icmp icmp6 */
typedef struct tagSecPolicyIcmp
{
    UCHAR ucType;
    UCHAR ucCode;
}SECPOLICY_ICMP_S;

/* port range */
typedef struct tagSecPolicyPortRange
{
    USHORT usSPort;
    USHORT usDPort;
}SECPOLICY_PORTRANGE_S;

typedef struct tagSecPolicyTcpUdpPortRange
{
    SECPOLICY_PORTRANGE_S stSRange;
    SECPOLICY_PORTRANGE_S stDRange;
}SECPOLICY_TCPUDP_PORTRANGE_S;

typedef struct tagSecPolicyL4ProtoPort
{
    UCHAR ucProtocol;  /* tcp udp icmp icmp6 any */
    SECPOLICY_TCPUDP_PORTRANGE_S stPortRange;
    SECPOLICY_ICMP_S stIcmp;
}SECPOLICY_L4_PROTO_PORT_S;

typedef enum tagSecPolicyAction
{
    SECPOLICY_ACTION_PERMIT = 1,
    SECPOLICY_ACTION_DENY,
    SECPOLICY_ACTION_MAX
}SECPOLICY_ACTION_E;



#define SECPOLICY_PACKET_MATCH_TYPE_ACTION         0x1
#define SECPOLICY_PACKET_MATCH_TYPE_SIP            0x2
#define SECPOLICY_PACKET_MATCH_TYPE_DIP            0x4
#define SECPOLICY_PACKET_MATCH_TYPE_SERVICE        0x8
#define SECPOLICY_PACKET_MATCH_TYPE_SPORT          0x10
#define SECPOLICY_PACKET_MATCH_TYPE_DPORT          0x20
#define SECPOLICY_PACKET_MATCH_TYPE_ICMP_TYPE      0x40
#define SECPOLICY_PACKET_MATCH_TYPE_ICMP_CODE      0x80
#define SECPOLICY_PACKET_MATCH_TYPE_STATUS         0x100
#define SECPOLICY_PACKET_MATCH_TYPE_STATISTICS     0x200
#define SECPOLICY_PACKET_MATCH_TYPE_APP            0x400
#define SECPOLICY_PACKET_MATCH_TYPE_DESC           0x800


#define SECPOLICY_APP_NUM_MAX    50
typedef struct tagSecPolicy_Conf_Rule_Node
{
    DTQ_NODE_S stNode;
    UINT uiRuleID;
    BOOL_T bIsEnable;
    BOOL_T bIsStatistics;
    SECPOLICY_L3_MULTIIP_S stSrc;
    SECPOLICY_L3_MULTIIP_S stDst;
    SECPOLICY_L4_PROTO_PORT_S stL4Info;
    SECPOLICY_ACTION_E enActionType;
    UINT uiKeyMask;
    USHORT szAppID[SECPOLICY_APP_NUM_MAX];
    UCHAR szDescInfo[SECPOLICY_RULE_DECRIPTION_MAX+1];
    UINT64 *puiCount;
}SECPOLICY_CONF_RULE_NODE_S;

typedef struct tagSecPolicy_Conf_Rule
{
    UINT uiSum;
    rte_atomic16_t stRuleCountOfRefApp;  /* Count of valid rules for reference applications */
    DTQ_HEAD_S stHead;
}SECPOLICY_CONF_RULE_S;

typedef struct tagSecPolicy_Conf_Node
{
    SL_NODE_S stNode;
    UINT uiVxlanID;
    UCHAR szTenantID[TENANT_ID_MAX+1];
    UINT uiDebug;
    SECPOLICY_CONF_RULE_S stHeadIn2Out;
    SECPOLICY_CONF_RULE_S stHeadOut2In;
    rte_rwlock_t rwlock_in2out;
    rte_rwlock_t rwlock_out2in;
}SECPOLICY_CONF_NODE_S;

typedef struct tagSecPolicy_Conf
{
    SL_HEAD_S stHeadIP4;
    SL_HEAD_S stHeadIP6;
}SECPOLICY_CONF_S;

typedef struct tagSecPolicy_All
{
    SECPOLICY_FLOW_S stSecFlow;
    SECPOLICY_CONF_S stSecConf;
}SECPOLICY_ALL_S;

typedef enum tagSecPolicyDirection
{
    SECPOLICY_DIRECTION_IN2OUT = 1,
    SECPOLICY_DIRECTION_OUT2IN,
    SECPOLICY_DIRECTION_MAX
}SECPOLICY_DIRECTION_E;

typedef struct tagSecPolicyRuleCfg
{
    SECPOLICY_TYPE_E enFwType;              /*  SECPOLICY_TYPE_EXTBODER      SECPOLICY_TYPE_VPCBODER */
    SECPOLICY_DIRECTION_E enFwDirect;       /*  SECPOLICY_DIRECTION_IN2OUT     SECPOLICY_DIRECTION_OUT2IN*/
    UINT   uiVxlanID;                         /*  SECPOLICY_TYPE_VPCBODER */
    UCHAR  szTenantID[TENANT_ID_MAX+1];     /*  SECPOLICY_TYPE_EXTBODER */
    UINT   uiRuleID;
    UINT   uiIPType;                        /* IPPROTO_IPV4 = 4   PPROTO_IPV6 = 41 */
    BOOL_T bIsEnable;
    BOOL_T bIsStatistics;
    UINT   uiKeyMask;
    SECPOLICY_L3_MULTIIP_S stSrc;
    SECPOLICY_L3_MULTIIP_S stDst;
    SECPOLICY_L4_PROTO_PORT_S stL4Info;
    SECPOLICY_ACTION_E enActionType;        /* SECPOLICY_ACTION_PERMIT      SECPOLICY_ACTION_DENY */
    USHORT szAppID[SECPOLICY_APP_NUM_MAX];
    UCHAR szDescInfo[SECPOLICY_RULE_DECRIPTION_MAX+1];
}SECPOLICY_RULE_CFG_S;

typedef enum tagSecPolicyMoveType
{
    SECPOLICY_MOVE_TYPE_HEAD = 1,
    SECPOLICY_MOVE_TYPE_TAIL,
    SECPOLICY_MOVE_TYPE_BEFORE,
    SECPOLICY_MOVE_TYPE_AFTER,
    SECPOLICY_MOVE_TYPE_MAX
}SECPOLICY_MOVE_TYPE_E;

typedef struct tagSecPolicyMoveRule
{
    SECPOLICY_TYPE_E enFwType;              /*  SECPOLICY_TYPE_EXTBODER      SECPOLICY_TYPE_VPCBODER */
    UINT uiVxlanID;                         /* SECPOLICY_TYPE_VPCBODER */
    UCHAR  szTenantID[TENANT_ID_MAX+1];     /* SECPOLICY_TYPE_EXTBODER */
    SECPOLICY_DIRECTION_E   enFwDirect;     /* 内到外 SECPOLICY_DIRECTION_IN2OUT     外到内 SECPOLICY_DIRECTION_OUT2IN*/
    UINT uiIPType;                        /* IPPROTO_IPV4 = 4   PPROTO_IPV6 = 41 */
    UINT uiRuleID;
    UINT uiTargetID;                      /* 移动到参考目标规则之前或者之后，若目标规则不存在，默认不移动 */
    SECPOLICY_MOVE_TYPE_E enMoveType;
}SECPOLICY_MOVE_RULE_S;

extern SL_HEAD_S * g_pstSecExtFlowHead;
extern SL_HEAD_S * g_pstSecVPCFlowHead;
extern SL_HEAD_S * g_pstExtSecConfHeadIP4;
extern SL_HEAD_S * g_pstExtSecConfHeadIP6;
extern SL_HEAD_S * g_pstVPCSecConfHeadIP4;
extern SL_HEAD_S * g_pstVPCSecConfHeadIP6;

/* debug option */
#define SECPOLICY_DEBUG_PACKET      0x1

extern BOOL_T g_bIsSecPolicyStatusOn;

#ifdef __cplusplus
}
#endif

#endif
