#ifndef _ACL_H_
#define _ACL_H_

/* ACL��Ч���� */
#define ACL_GROUP_INVALID_INDEX  ((uint32_t)-1)
#define ACL_RULE_INVALID_INDEX   ((uint32_t)0x0000FFFF)

/* ACL���Ƶ���󳤶� */
#define ACL_MAX_NAME_LEN   63UL

/* ������������ */
#define ACL_RULE_PROPERTY_ACTIVE      	0x01           		/* ������������ */
#define ACL_RULE_PROPERTY_LOG         	(0x01 << 1)    		/* �������״̬���� */
#define ACL_RULE_PROPERTY_COUNT       	(0x01 << 2)    		/* ����ͳ���������� */
#define ACL_RULE_PROPERTY_DISABLE     	(0x01 << 3)    		/* �����ֹ�������� */
#define ACL_RULE_PROPERTY_PROFILE     	(0x01 << 4)    		/* Inspect Profile */
#define ACL_RULE_PROPERTY_TRACK 		(0x01 << 5) 		/* ����Track�������� */
#define ACL_RULE_PROPERTY_TRACKINACTIVE (0x01 << 6)  		/* ����Trackδ������������ */
#define ACL_RULE_PROPERTY_DYNAMIC 		(0x01 << 7) 		/* ��̬������������ */
#define ACL_RULE_PROPERTY_ACCELERATE 	((uint32_t)0x01 << 31)	/* ��������������� */

/* IPV4�����͸߼�ACL�� */
#define ACL_KEY_SIP   	 0x01			/* ԴIP��ַ */
#define ACL_KEY_DIP   	 (0x01 << 1)	/* Ŀ��IP��ַ */
#define ACL_KEY_SPORT 	 (0x01 << 2)	/* Դ�˿ں�*/
#define ACL_KEY_DPORT 	 (0x01 << 3)	/* Ŀ�Ķ˿ں� */
#define ACL_KEY_ICMPTYPE (0x01 << 4) 	/* ICMP type */
#define ACL_KEY_ICMPCODE (0x01 << 5) 	/* ICMP code */
#define ACL_KEY_PID  	 (0x01 << 6)	/* Э��� */
#define ACL_KEY_FRAG 	 (0x01 << 7)	/* ����Ƭ��Ƭ��־ */
#define ACL_KEY_TCPFLAG  (0x01 << 8)	/* TCP���ӱ�־ */
#define ACL_KEY_TOS  	 (0x01 << 9)	/* TOS */
#define ACL_KEY_L3VPN  	 (0x01 << 10)	/* L3VPN */

/* MAC ACL: */
#define ACL_KEY_SMAC      0x01  		/* ԴMAC��ַ */
#define ACL_KEY_DMAC      (0x01 << 1)   /* Ŀ��MAC��ַ */
#define ACL_KEY_COS       (0x01 << 2)   /* VLAN���ȼ� */
#define ACL_KEY_FRAMETYPE (0x01 << 3)   /* ��̫������ */
#define ACL_KEY_FRAMELSAP (0x01 << 4)   /* LSAP */


/* IPV6�����͸߼�ACL��*/
#define ACL6_KEY_SIP  		0x01           /* ԴIP��ַ */
#define ACL6_KEY_DIP       	(0x01 << 1)    /* Ŀ��IP��ַ */
#define ACL6_KEY_SPORT      (0x01 << 2)    /* Դ�˿ں� */ 
#define ACL6_KEY_DPORT      (0x01 << 3)    /* Ŀ�Ķ˿ں� */  
#define ACL6_KEY_ICMPTYPE   (0x01 << 4)    /* ICMP type */    
#define ACL6_KEY_ICMPODE    (0x01 << 5)    /* ICMP code */   
#define ACL6_KEY_PID        (0x01 << 6)    /* Э��� */
#define ACL6_KEY_FRAG   	(0x01 << 7)    /* ����Ƭ��Ƭ��־ */
#define ACL6_KEY_TCPFLAG   	(0x01 << 8)    /* TCP���ӱ�־ */
#define ACL6_KEY_DSCP   	(0x01 << 9)    /* DSCP */
#define ACL6_KEY_FLOWLABEL  (0x01 << 10)   /* ����ǩ */
#define ACL6_KEY_L3VPN  	(0x01 << 11)   /* L3VPN */
#define ACL6_KEY_ROUTING 	(0x01 << 12)   /* ·��ͷѡ�� */
#define ACL6_KEY_HOP 		(0x01 << 13)   /* ����ͷѡ�� */

/*�����Թ����־λ */
#define ACLOBJ_KEY_SIP 		0x01	       /* ԴIP��ַ������ */
#define ACLOBJ_KEY_DIP		(0x01 << 1)	   /* Ŀ��IP��ַ������ */
#define ACLOBJ_KEY_SERVER 	(0x01 << 2)	   /* ��������� */
#define ACLOBJ_KEY_L3VPN 	(0x01 << 3)	   /* VPNʵ���� */
#define ACLOBJ_KEY_APPGRP 	(0x01 << 4)	   /* Ӧ���� */
#define ACLOBJ_KEY_APP 		(0x01 << 5)	   /* Ӧ�� */

/* IPv6�����Թ����־λ */
#define ACLOBJ6_KEY_SIP   0x01             /* ԴIP��ַ������ */
#define ACLOBJ6_KEY_DIP   (0x01 << 1)      /* Ŀ��IP��ַ������ */


typedef struct tagACL_MatchResult
{
	uint32_t uiRuleIndex;
	uint32_t uiRuleKeyMask;  /* ƥ�䵽�Ĺ����а�����Key���� */
	uint32_t uiPropertyMask; /* ƥ�䵽�Ĺ����а������������� */
	uint32_t uiProfileID;    /* Inspect Profile ID */
}ACL_MATCH_RESULT_S;

/* ����ƥ����Ϣȫ��Ч����ֵ */
#define ACL_KEY_MASK_ALL (uint32_t)-1)

/* ������Ϣ��Чֵ */
#define ACL_INVALID_PORT    ((uint32_t)-1)
#define ACL_INVALID_TCPFLAG ((uint8_t)-1)

/* �������ݰ�ƥ���IPv4����ƥ����Ϣ*/
typedef struct tagACL_MatchIPPktInfo
{
	struct in_addr stSIP;
	struct in_addr stDIP;
	uint32_t     uiFlag;  /* ��Ч�Ƚ�λ */
	uint16_t     vrfIndex;
	uint32_t     uiSPort;
	uint32_t     uiDPort;
	uint16_t     bNIFrag; /* Non-initial fragments ��־ */
	uint8_t      ucProtocol;
	uint8_t      ucToS;
	uint8_t      ucTCPFlag;
}ACL_MATCH_IPPKTINFO_S;

#define ACL_HOPTYPE_MAXARRAY  32 /* ����ͷ����Ϊ0-255����32���ֽ�����ʾ */
#define ACL_SET_HOPTYPE(hopbitmap,hoptype) ((hopbitmap)[(hoptype) >> 3] |=(1 << ((hoptype) & 0x7)))

/* �������ݰ�ƥ���IPy6����ƥ����Ϣ */
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

/* ACL�Ķ������� */
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


/* ACL�汾��:IPv4��IPv6��MAC��USER��WLAN */
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
