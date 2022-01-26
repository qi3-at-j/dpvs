#ifndef _ACL_H_
#define _ACL_H_

/* ACL无效索引 */
#define ACL_GROUP_INVALID_INDEX  ((uint32_t)-1)
#define ACL_RULE_INVALID_INDEX   ((uint32_t)0x0000FFFF)

/* ACL名称的最大长度 */
#define ACL_MAX_NAME_LEN   63UL

/* 规则属性掩码 */
#define ACL_RULE_PROPERTY_ACTIVE      	0x01           		/* 规则属性掩码 */
#define ACL_RULE_PROPERTY_LOG         	(0x01 << 1)    		/* 规则可用状态掩码 */
#define ACL_RULE_PROPERTY_COUNT       	(0x01 << 2)    		/* 配置统计属性掩码 */
#define ACL_RULE_PROPERTY_DISABLE     	(0x01 << 3)    		/* 规则禁止属性掩码 */
#define ACL_RULE_PROPERTY_PROFILE     	(0x01 << 4)    		/* Inspect Profile */
#define ACL_RULE_PROPERTY_TRACK 		(0x01 << 5) 		/* 规则Track属性掩码 */
#define ACL_RULE_PROPERTY_TRACKINACTIVE (0x01 << 6)  		/* 规则Track未激活属性掩码 */
#define ACL_RULE_PROPERTY_DYNAMIC 		(0x01 << 7) 		/* 动态规则属性掩码 */
#define ACL_RULE_PROPERTY_ACCELERATE 	((uint32_t)0x01 << 31)	/* 规则加速属性掩码 */

/* IPV4基本和高级ACL∶ */
#define ACL_KEY_SIP   	 0x01			/* 源IP地址 */
#define ACL_KEY_DIP   	 (0x01 << 1)	/* 目的IP地址 */
#define ACL_KEY_SPORT 	 (0x01 << 2)	/* 源端口号*/
#define ACL_KEY_DPORT 	 (0x01 << 3)	/* 目的端口号 */
#define ACL_KEY_ICMPTYPE (0x01 << 4) 	/* ICMP type */
#define ACL_KEY_ICMPCODE (0x01 << 5) 	/* ICMP code */
#define ACL_KEY_PID  	 (0x01 << 6)	/* 协议号 */
#define ACL_KEY_FRAG 	 (0x01 << 7)	/* 非首片分片标志 */
#define ACL_KEY_TCPFLAG  (0x01 << 8)	/* TCP连接标志 */
#define ACL_KEY_TOS  	 (0x01 << 9)	/* TOS */
#define ACL_KEY_L3VPN  	 (0x01 << 10)	/* L3VPN */

/* MAC ACL: */
#define ACL_KEY_SMAC      0x01  		/* 源MAC地址 */
#define ACL_KEY_DMAC      (0x01 << 1)   /* 目的MAC地址 */
#define ACL_KEY_COS       (0x01 << 2)   /* VLAN优先级 */
#define ACL_KEY_FRAMETYPE (0x01 << 3)   /* 以太网类型 */
#define ACL_KEY_FRAMELSAP (0x01 << 4)   /* LSAP */


/* IPV6基本和高级ACL∶*/
#define ACL6_KEY_SIP  		0x01           /* 源IP地址 */
#define ACL6_KEY_DIP       	(0x01 << 1)    /* 目的IP地址 */
#define ACL6_KEY_SPORT      (0x01 << 2)    /* 源端口号 */ 
#define ACL6_KEY_DPORT      (0x01 << 3)    /* 目的端口号 */  
#define ACL6_KEY_ICMPTYPE   (0x01 << 4)    /* ICMP type */    
#define ACL6_KEY_ICMPODE    (0x01 << 5)    /* ICMP code */   
#define ACL6_KEY_PID        (0x01 << 6)    /* 协议号 */
#define ACL6_KEY_FRAG   	(0x01 << 7)    /* 非首片分片标志 */
#define ACL6_KEY_TCPFLAG   	(0x01 << 8)    /* TCP连接标志 */
#define ACL6_KEY_DSCP   	(0x01 << 9)    /* DSCP */
#define ACL6_KEY_FLOWLABEL  (0x01 << 10)   /* 流标签 */
#define ACL6_KEY_L3VPN  	(0x01 << 11)   /* L3VPN */
#define ACL6_KEY_ROUTING 	(0x01 << 12)   /* 路由头选项 */
#define ACL6_KEY_HOP 		(0x01 << 13)   /* 逐跳头选项 */

/*域间策略规则标志位 */
#define ACLOBJ_KEY_SIP 		0x01	       /* 源IP地址对象组 */
#define ACLOBJ_KEY_DIP		(0x01 << 1)	   /* 目的IP地址对象组 */
#define ACLOBJ_KEY_SERVER 	(0x01 << 2)	   /* 服务对象组 */
#define ACLOBJ_KEY_L3VPN 	(0x01 << 3)	   /* VPN实例名 */
#define ACLOBJ_KEY_APPGRP 	(0x01 << 4)	   /* 应用组 */
#define ACLOBJ_KEY_APP 		(0x01 << 5)	   /* 应用 */

/* IPv6域间策略规则标志位 */
#define ACLOBJ6_KEY_SIP   0x01             /* 源IP地址对象组 */
#define ACLOBJ6_KEY_DIP   (0x01 << 1)      /* 目的IP地址对象组 */


typedef struct tagACL_MatchResult
{
	uint32_t uiRuleIndex;
	uint32_t uiRuleKeyMask;  /* 匹配到的规则中包含的Key掩码 */
	uint32_t uiPropertyMask; /* 匹配到的规则中包含的属性掩码 */
	uint32_t uiProfileID;    /* Inspect Profile ID */
}ACL_MATCH_RESULT_S;

/* 报文匹配信息全生效掩码值 */
#define ACL_KEY_MASK_ALL (uint32_t)-1)

/* 报文信息无效值 */
#define ACL_INVALID_PORT    ((uint32_t)-1)
#define ACL_INVALID_TCPFLAG ((uint8_t)-1)

/* 用于数据包匹配的IPv4分类匹配信息*/
typedef struct tagACL_MatchIPPktInfo
{
	struct in_addr stSIP;
	struct in_addr stDIP;
	uint32_t     uiFlag;  /* 生效比较位 */
	uint16_t     vrfIndex;
	uint32_t     uiSPort;
	uint32_t     uiDPort;
	uint16_t     bNIFrag; /* Non-initial fragments 标志 */
	uint8_t      ucProtocol;
	uint8_t      ucToS;
	uint8_t      ucTCPFlag;
}ACL_MATCH_IPPKTINFO_S;

#define ACL_HOPTYPE_MAXARRAY  32 /* 逐跳头类型为0-255，用32个字节来表示 */
#define ACL_SET_HOPTYPE(hopbitmap,hoptype) ((hopbitmap)[(hoptype) >> 3] |=(1 << ((hoptype) & 0x7)))

/* 用于数据包匹配的IPy6分类匹配信息 */
typedef struct tagACL_MatchIP6PktInfo
{
	struct in6_addr stSIP;
	struct in6_addr stDIP;
	uint32_t uiFlag;
	uint32_t uiFlowLabel;
	uint32_t uiSPort;
	uint32_t uiDPort;
	uint32_t uiAppId;
	uint16_t vrfIndex;
	uint16_t usRoutingType;
	uint16_t bNIFrag;
	uint8_t aucHopBitMap[ACL_HOPTYPE_MAXARRAY];
	uint8_t ucProtocol;
	uint8_t ucDSCP;
	uint8_t ucTCPFlag;
}ACL_MATCH_IP6PKTINFO_S;

typedef struct tagPfltMatchAclInfo
{
	void *pAclPktInfo;
	uint32_t uiObjFlag;
	uint32_t uiPfltFlag;
} PFLT_MATCH_ACL_INFO_S;

/* ACL的动作类型 */
typedef enum tagACL_Action
{
    ACL_DENY = 1,
    ACL_PERMIT
}ACL_ACTION_E;
	
typedef struct tagPfltAclIndexInfo
{
	ACL_ACTION_E enAction;
	uint32_t uiGroupIndex;
	uint32_t uiRuleIndex;
} PFLT_ACL_INDEX_INFO_S;


/* ACL版本号:IPv4、IPv6、MAC、USER、WLAN */
typedef enum tagACL_Version
{
    ACL_VERSION_ACL4 = 1,
    ACL_VERSION_ACL6,
    ACL_VERION_MAC,
    ACL_VERSION_USER,
    ACL_VERSION_WLAN,
    ACL_VERSION_MAX,
}ACL_VERSION_E;

#define INVALID_USERID 0

#define PFLT_OBJ_DROPNOTDELSESSION_KEY  (ACLOBJ_KEY_APPGRP | ACLOBJ_KEY_APP | SECPOBJ_KEY_URL)
#define PFLT_OBJ6_DROPNOTDELSESSION_KEY (ACLOBJ6_KEY_APPGRP | ACLOBJ6_KEY_APP | SECPOBJ6_KEY_URL)

#endif
