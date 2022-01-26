#ifndef _IPFW_H_
#define _IPFW_H_

//#include "in.h"

#include <netinet/in.h>

/*ip fragment flag*/
#define IP_DF         0x4000 /* dont fragment flag */
#define IP_MF         0x2000 /* more fragments flag */
#define IP_OFFMASK    0x1fff /* mask for fragment */

#if 0
/* IPv4 ����ͷ���ݽṹ���� */
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

/* IP ת��ҵ��׶ε㶨�� */
typedef enum tagIpfw_Phase
{
    IPFW_PRE_ALL,                  /* ���ձ�����ڽ׶� */
    IPFW_PRE_ROUTING,              /* ���ձ���Ԥ����׶� */
    IPFW_PRE_ROUTING2,             /* ���ձ���Ԥ����׶�2 */
    IPFW_POST_ROUTING,             /* ���ձ��Ĳ�ѯ·�ɺ���׶� */
    IPFW_LOCAL_IN_BEFOREDEFRAG,    /* ��������������ǰ����׶� */
    IPFW_LOCAL_IN,                 /* ���������Ĵ���׶� */
    IPFW_LOCAL_OUT_PRE_ROUTING,    /* �������ͱ��Ĳ�ѯ·��ǰ����׶� */    
    IPFW_LOCAL_OUT,                /* �������ͱ��Ĵ���׶� */
    IPFW_LOCAL_OUT_POST_ROUTING,   /* �������ͱ��Ĳ�ѯ·�ɺ���׶� */
    IPFW_POST_ROUTING_BEFOREFRAG,  /* ���ӿڷ��ͷ�ƬǰԤ����׶� */    
    IPFW_POST_ROUTING_BEFOREFRAG2, /* ���ӿڷ��ͷ�ƬǰԤ����׶�2 */
    IPFW_PRE_RELAY,
    IPFW_RELAY_RECEIVE,
    IPFW_POST_ROUTING_AFTERFRAG,   /* IP_PACKET_TRACE ��Ƭ���ĵ�ҵ��׶Σ����ڼ�¼���ķ�Ƭ�Ĳ��� */
    IPFW_PHASE_BUTT
}IPFW_PHASE_E;

/* ���ձ�����ڴ���׶� */
typedef enum tagIpfw_PreAll
{
    IPFW_PRE_ALL_VYS,              /* ����VSYSҵ��㣬���ڶ���ģ������ */
    IPFW_PRE_ALL_PKTTRACE,         /* ����ʾ��ҵ����ط�����Ҫʾ�ٵ�ҵ���ǰ */
    IPFW_PRE_ALL_IPCAR,
    IPFW_PRE_ALL_AGENT,
    IPFW_PRE_ALL_ISG,
    IPFW_PRE_ALL_IPMAC,
    IPFW_PRE_ALL_ATKPROXY,
    IPFW_PRE_ALL_APPPROXY,
    IPFW_PRE_ALL_BUTT
}IPFW_PRE_ALL_SERVICEID_E;

/* ���ձ���Ԥ����׶� */
typedef enum tagIpfw_PreRouting
{
    IPFW_PRE_ROUTING_DROP_PACKET,
    IPFW_PRE_ROUTING_BALANCE,
    IPFW_PRE_ROUTING_PKTTRACE,        /* ����ʾ��ҵ����ط�����Ҫʾ�ٵ�ҵ���ǰ */
    IPFW_PRE_ROUTING_IP_PTRACE,       /* IP_PACKET_TRACE, IPת�����ڼ�¼���ĵĹ켣��Ϣ */
    IPFW_PRE_ROUTING_OFP,             /* OpenFlowҵ����ر�֤��һ��ҵ�� */
    IPFW_PRE_ROUTING_TCPREASSEMBLE,   /* TCP���� */
    IPFW_PRE_ROUTING_NETSTREAM,       /* NETSTRAMҵ�� */
    IPFW_PRE_ROUTING_MGROUP,          /* Mirror Group���� */
    IPFW_PRE_ROUTING_IPSEC,           /* IPsec Ԥ���� */
    IPFW_PRE_ROUTING_IPSECANTIATTACK, /* IPsec���������� */
    IPFW_PRE_ROUTING_FLOWMGR,
    IPFW_PRE_ROUTING_ATK,
    IPFW_PRE_ROUTING_SCD,             /* �쳣����������Ŀ */
    IPFW_PRE_ROUTING_LBPRE,
    IPFW_PRE_ROUTING_IPOE,
    IPFW_PRE_ROUTING_WEBREDIRECT,
    IPFW_PRE_ROUTING_PORTAL,
    IPFW_PRE_ROUTING_TWAMP,           /* TWAMPҵ�� */
    IPFW_PRE_ROUTING_APR,             /* Э��ʶ�� */
    IPFW_PRE_ROUTING_APPSTAT,         /* ����ͳ�� */
    IPFW_PRE_ROUTING_BPASTAT,         /* ����BGP���Ե�����ͳ�� */
    IPFW_PRE_ROUTING_CONNLMT,         /* ���������� */
    IPFW_PRE_ROUTING_AUTHORIZE,       /* ��Ȩ��鴦��׶� */
    IPFW_PRE_ROUTING_FILTER,          /* ASPF �� PFLT �Ĺ�ͬ����׶� */
    IPFW_PRE_ROUTING_MIP,             /* �ƶ� IP */
    IPFW_PRE_ROUTING_NAT,             /* NAT��ӿ�ҵ���� */
    IPFW_PRE_ROUTING_WLAN,            /* NATת����WLAN���� */
    IPFW_PRE_ROUTING_LB,              /* LB���ؾ��⴦��׶� */
    IPFW_PRE_ROUTING_QPPB,            /* QPPB */
    IPFW_PRE_ROUTING_PRIMAP,
    IPFW_PRE_ROUTING_QOS,             /* Qos */
    IPFW_PRE_ROUTING_BUTT       
}IPFW_PRE_ROUING_SERVICEID_E;

/* ���ձ���Ԥ����׶� */
typedef enum tagIpfw_PreRouting2
{
    IPFW_PRE_ROUTING2_TCPMSS,             /* TCP MSS */  
    IPFW_PRE_ROUTING2_DSLITE,             /* DS-Lite */
    IPFW_PRE_ROUTING2_AFT,                /* ��ַת�� */
    IPFW_PRE_ROUTING2_KEEPLASTHOP,        /* ������һ��ҵ�� */
    IPFW_PRE_ROUTING2_PPP,                /* PPP�����Ʒ�ͳ��ҵ�� */
    IPFW_PRE_ROUTING2_PMM,    
    IPFW_PRE_ROUTING2_WAAS_DECOMPRESS,    
    IPFW_PRE_ROUTING2_UCC,
    IPFW_PRE_ROUTING2_DNSSP,    
    IPFW_PRE_ROUTING2_BUTT
}IPFW_PRE_ROUTING2_SERVICEID_E;

/* ���ձ��Ĳ�ѯ·�ɺ���׶� */
typedef enum tagIpfw_PostRouting
{
    IPFW_POST_ROUTING_IP_PTRACE,      /* IP_PACKET_TRACE, IPת�����ڼ�¼���ĵĹ켣��Ϣ��ע���ƶ�ҵ��ö�ٱ�֤32bit */
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
    IPFW_POST_ROUTING_NAT,  /* ��ѶVSGר�߶ѵ�+NAT���������У�NATҵ����Ͽ�ת����������� */ 
    IPFW_POST_ROUTING_IPSERVICE,    
    IPFW_POST_ROUTING_LICMGR,    
    IPFW_POST_ROUTING_BUTT
}IPFW_POST_ROUTING_SERVICEID_E;

/* IPv4�������ͱ�������ǰҵ��ID */
typedef enum tagIpfw_LocalInBeforeDefrag
{
    IPFW_LOCAL_IN_BEFOREDEFRAG_IP_PTRACE, /* IP_PACKET_TRACE, IPת�����ڼ�¼���ĵĹ켣��Ϣ��ע���ƶ�ҵ��ö�ٱ�֤32bit */
    IPFW_LOCAL_IN_INTERZONE,              /* ��䴦��׶� */     
    IPFW_LOCAL_IN_ATK,    
    IPFW_LOCAL_IN_CONNLMT,                /* ���������� */    
    IPFW_LOCAL_IN_UDPI,                   /* ���û�̬DPIҵ�񣬱�����DIM֮ǰ */    
    IPFW_LOCAL_IN_APPL7,                  /* DIM��ҵ�� */    
    IPFW_LOCAL_IN_NETSESSION,    
    IPFW_LOCAL_IN_BEFOREDEFRAG_BUTT
}IPFW_LOCAL_IN_BEFOREDEFRAG_SERVICEID_E;

/* ���������Ĵ���׶� */
typedef enum tagIpfw_LocalIn
{
    IPFW_LOCAL_IN_IP_PTRACE,  /* IP_PACKET_TRACE, IPת�����ڼ�¼���ĵĹ켣��Ϣ��ע���ƶ�ҵ��ö�ٱ�֤32bit */
    IPFW_LOCAL_IN_GTSM,
    IPFW_LOCAL_IN_BFD,
    IPFW_LOCAL_IN_UDPH,
    IPFW_LOCAL_IN_TCP_PROXY,
    IPFW_LOCAL_IN_LISP,
    IPFW_LOCAL_IN_WLAN,       /* ���ͱ�����WLAN���� */
    IPFW_LOCAL_IN_BUTT
}IPFW_LOCAL_IN_SERVICEID_E;

/* �������ͱ��Ĵ���׶� */
typedef enum tagIPfw_LocalOutPreRouting
{
    /*IPV4�˽׶���ʱ��ҵ��*/
    IPFW_LOCAL_OUT_PRE_ROUTING_BUTT
}IPFW_LOCAL_OUT_PRE_ROUTING_SERVICEID_E;

/* �������ͱ��Ĵ���׶� */
typedef enum tagIPfw_LocalOut
{
    IPFW_LOCAL_OUT_VSYS,
    IPFW_LOCAL_OUT_BALANCE,
    IPFW_LOCAL_OUT_PKTTRACE,     /* ����ʾ��ҵ����ط�����Ҫʾ�ٵ�ҵ���ǰ */
    IPFW_LOCAL_OUT_IP_PTRACE,    /* IP_PACKET_TRACE, IPת�����ڼ�¼���ĵĹ켣��Ϣ��ע���ƶ�ҵ��ö�ٱ�֤32bit */
    IPFW_LOCAL_OUT_INTERZONE,    /* ��䴦��׶� */
    IPFW_LOCAL_OUT_DSLITE,       /* DS-LITEҵ����׶� */
    IPFW_LOCAL_OUT_DHCPSP,       /* DHCP snooping���� */
    IPFW_LOCAL_OUT_WAAS,
    IPFW_LOCAL_OUT_KEEPLASTHOP,  /* ������һ��ҵ�� */
    IPFW_LOCAL_OUT_LB,           /* LB���� */
    IPFW_LOCAL_OUT_BUTT
}IPFW_LOCAL_OUT_SERVICEID_E;

/* �������ͱ��Ĳ�ѯ·�ɺ���׶� */
typedef enum tagIpfw_LocalOutPostRouting
{
    IPFW_LOCAL_OUT_POST_ROUTING_IP_PTRACE,    /* IP_PACKET_TRACE, IPת�����ڼ�¼���ĵĹ켣��Ϣ��ע���ƶ�ҵ��ö�ٱ�֤32bit */
    IPFW_LOCAL_OUT_POST_ROUTING_MFSERVICECLASS,
    IPFW_LOCAL_OUT_POST_ROUTING_PBR,
    IPFW_LOCAL_OUT_POST_ROUTING_LISP,
    IPFW_LOCAL_OUT_POST_ROUTING_OFP,
    IPFW_LOCAL_OUT_POST_ROUTING_OVERLAY,
    IPFW_LOCAL_OUT_POST_ROUTING_LICMGR,
    IPFW_LOCAL_OUT_POST_ROUTING_DNSSP,
    IPFW_LOCAL_OUT_POST_ROUTING_BUTT
}IPFW_LOCAL_OUT_POST_ROUTING_SERVICEID_E;

/* ���ӿڷ��ͷ�ƬǰԤ����׶� */
typedef enum tagIpfw_PostRoutingBeforeFrag
{
    IPFW_POST_ROUTING_BEFOREFRAG_IP_PTRACE,    /* IP_PACKET_TRACE, IPת�����ڼ�¼���ĵĹ켣��Ϣ��ע���ƶ�ҵ��ö�ٱ�֤32bit */
    IPFW_POST_ROUTING_BEFOREFRAG_FLOWMGR,      /* ��������ҵ��׶� */    
    IPFW_POST_ROUTING_BEFOREFRAG_FILLTAG,      /* ������������� */    
    IPFW_POST_ROUTING_BEFOREFRAG_INTERZONE,    /* ��䴦��׶� */
    IPFW_POST_ROUTING_BEFOREFRAG_LB,           /* LB���ؾ��⴦��׶� */
    IPFW_POST_ROUTING_BEFOREFRAG_SSLVPN,
    IPFW_POST_ROUTING_BEFOREFRAG_WLAN,         /* NATת��ǰWLAN���� */
    IPFW_POST_ROUTING_BEFOREFRAG_NAT,          /* ���ӿ�NATҵ���� */
    IPFW_POST_ROUTING_BEFOREFRAG_FILTER,       /* ASPF��PFLT�Ĺ�ͬ����׶� */
    IPFW_POST_ROUTING_BEFOREFRAG_AUTHORIZE,    /* ��Ȩ��鴦��׶� */
    IPFW_POST_ROUTING_BEFOREFRAG_ATK,          /* ATK */
    IPFW_POST_ROUTING_BEFOREFRAG_MIP,          /* �ƶ� IP */
    IPFW_POST_ROUTING_BEFOREFRAG_CONNLMT,      /* ���������� */    
    IPFW_POST_ROUTING_BEFOREFRAG_APR,          /* Э��ʶ�� */    
    IPFW_POST_ROUTING_BEFOREFRAG_APPSTAT,      /* ����ͳ�� */
    IPFW_POST_ROUTING_BEFOREFRAG_BPASTAT,      /* ����BGP���Ե�����ͳ�� */
    IPFW_POST_ROUTING_BEFOREFRAG_UDPI,         /* ���û�̬DPIҵ�񣬱�����DIM֮ǰ */
    IPFW_POST_ROUTING_BEFOREFRAG_APPL7,        /* DIM��ҵ�� */
    IPFW_POST_ROUTING_BEFOREFRAG_APPPROXY,    
    IPFW_POST_ROUTING_BEFOREFRAG_NETSESSION,
    IPFW_POST_ROUTING_BEFOREFRAG_PORTAL,
    IPFW_POST_ROUTING_BEFOREFRAG_IPOE,
    IPFW_POST_ROUTING_BEFOREFRAG_ADVPN,    
    IPFW_POST_ROUTING_BEFOREFRAG_PREQOS,       /* QosԤ���� */    
    IPFW_POST_ROUTING_BEFOREFRAG_TCPMSS,
    IPFW_POST_ROUTING_BEFOREFRAG_TWAMP,    
    IPFW_POST_ROUTING_BEFOREFRAG_RAW_NETSTREAM,
    IPFW_POST_ROUTING_BEFOREFRAG_IPSEC,        /* IPsec �������Ĵ��� */    
    IPFW_POST_ROUTING_BEFOREFRAG_NETSTREAM,    
    IPFW_POST_ROUTING_BEFOREFRAG_MGROUP,       /* Mirror Group���� */    
    IPFW_POST_ROUTING_BEFOREFRAG_NGINX,    
    IPFW_POST_ROUTING_BEFOREFRAG_BUTT
}IPFW_POST_ROUTING_BEFOREFRAG_SERVICEID_E;

/* ���ӿڷ��ͷ�ƬǰԤ����׶γ���31���������Ӵ˽׶� */
typedef enum tagIpfw_PostRoutingBeforeFrag2
{
    IPFW_POST_ROUTING_BEFOREFRAG2_WAAS,
    IPFW_POST_ROUTING_BEFOREFRAG2_OFP,         /* ��Openflow���� */
    IPFW_POST_ROUTING_BEFOREFRAG2_ALGFRAG,     /* ALGҵ���� */
    IPFW_POST_ROUTING_BEFOREFRAG2_UCC,
    IPFW_POST_ROUTING_BEFOREFRAG2_BUTT
}IPFW_POST_ROUTING_BEFOREFRAG2_SERVICEID_E;

/* ����͸��ǰ�׶� */
typedef enum tagIpfw_PreRelay
{
    IPFW_PRE_RELAY_INTERZONE,     /* ��䴦��׶� */        
    IPFW_PRE_RELAY_CONNLMT,       /* ���������� */
    IPFW_PRE_RELAY_APPL7,
    IPFW_PRE_RELAY_LICMGR,
    IPFW_PRE_RELAY_ALG,
    IPFW_PRE_RELAY_BUTT
}IPFW_PRE_RELAY_SERVICEID_E;

/* ����͸�����ս׶� */
typedef enum tagIpfw_RelayReceive
{
    IPFW_RELAY_RECEIVE_INTERZONE,   /* ��䴦��׶� */
    IPFW_RELAY_RECEIVE_DSLITE,      /* DS-Lite���� */
    IPFW_RELAY_RECEIVE_BUTT
}IPFW_RELAY_RECEIVE_SERVICEID_E;

/* IP_PACKET_TRACE, IPת�����ڼ�¼���ĵĹ켣��Ϣ��ע���ƶ�ҵ��ö�ٱ�֤32bit */
/* ���ķ�Ƭ���ͽ׶� */
typedef enum tagIpfw_PostRoutingAfterFrag
{
    IPFW_POST_ROUTING_AFTERFRAG_IP_PTRACE,
    IPFW_POST_ROUTING_AFTERFRAG_BUTT
}IPFW_POST_ROUTING_AFTERFRAG_SERVICEID_E;

/* IP ת��ҵ�񷵻�ֵ���� */
typedef enum tagIPFW_ServiceRet
{
    PKT_CONTINUE,     /* ����Χ�����߼������� */
    PKT_DROPPED,      /* �����Ѿ������� */
    PKT_CONSUMED,     /* �����Ѿ������Ѵ��� */
    PKT_ENQUEUED,     /* �����Ѿ���������� */
    PKT_RELAY         /* ����Ҫ�����͸�� */
}IPFW_SERVICE_RET_E;

/* IP ת���ṩ��FIB��ת�����Զ��� */
typedef enum tagIpfw_FIB_FwdType
{
    IPFW_FIB_FORWARDING,  /* ����ת�� */        
    IPFW_FIB_LOOPBACK,    /* ���ͱ��� */    
    IPFW_FIB_BROADCAST,   /* �㲥 */
    IPFW_FIB_MULTICAST,   /* �鲥 */
    IPFW_FIB_LINKLOCAL,   /* ��·���� */
    IPFW_FIB_LABLE,       /* MPLS��ǩ */
    IPFW_FIB_NHLFE,       /* MPLS NHLFE�� */
    IPFW_FIB_TRSEND,      /* ͸�������� */
    IPFW_FIB_TRMASTER,    /* ͸�����ذ� */
    IPFW_FIB_BLACKHOLE,   /* ��ӦBLACKHOLE�����ڽӱ� */
    IPFW_FIB_REECT,       /* ��ӦREJECT�����ڽӱ� */ 
    IPFW_FIB_FWDTYPE_BUT
}IPFW_FIB_FWDTYPE_E;

#endif

