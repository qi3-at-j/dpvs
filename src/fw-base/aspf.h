#ifndef _ASPF_H_
#define _ASPF_H_

/* ASPFģ�����Ʊ�ʶ */
#define ASPF_MODULE_NAME  "ASPF"

/* Bitset representing status of debug */
#define ASPF_DBG_BIT_EVENT     ((UINT)1 << 0)  /* event msg */
#define ASPF_DBG_BIT_PACKET    ((UINT)1 << 1)  /* packet msg */
#define ASPF_DBG_BIT_ALL       ((UINT)(~0))    /* all msg */


typedef enum tagASPF_ACT_TYPE
{
    ASPF_ACT_NOCARE = 0,
    ASPF_ACT_CARE,
} ASPF_ACT_TYPE_E;

typedef enum tagASPF_STAT_VERSION
{
    ASPF_STAT_IPV4,
    ASPF_STAT_IPV6,
    ASPF_STAT_NR
}ASPF_STAT_VERSION_E;

typedef enum tagASPF_DROP_TYPE
{
	ASPF_FTRST_SYN,                   /* �ױ���tcp syn��鶪�� */
    ASPF_CHILD_SYN,                   /* �ӻỰ�ױ���tcp syn��鶪�� */
    ASPF_NOSESSION_ICMPERR,           /* �޻Ựicmp error��鶪�� */
    ASPF_NOSESSION_SYN,               /* �޻Ựtcp syn��鶪�� */
    ASPF_NOSESSION_PFLT,              /* �޻Ựpflt���� */
    ASPF_FIRST_PFLT,                  /* �ױ���pflt���� */
    ASPF_NOFIRST_PFLT,                /* ��������pflt���� */
    ASPF_CHILDFIRST_PFLT,             /* �ӻỰ�ױ���pflt���� */
    ASPF_NOCHILDFIRST_PFLT,           /* �ӻỰ��������pflt���� */
    ASPF_NOFIRST_CFG_CHANGE,          /* �Ự�����������ñ������ */
    ASPF_NOFIRST_IV_STATUS,           /* ��������״̬��鶪�� */
    ASPF_CHILD_IV_STATUS,             /* �ӻỰ��������״̬��鶪�� */
    ASPF_FIRST_IV_STATUS,             /* �ױ���״̬��鶪�� */
    ASPF_PFLT_DIM,                    /* ���ʵ������DIMӦ��ʶ�𶪰� */
    ASPF_DROP_TYPE_MAX
} ASPF_DROP_TYPE_E;

/* aspf��debug��Ϣ */
typedef struct tagASPF_DBG_INFO
{
	UINT uiDbgSwitch;
	UINT uiAclNum;
} ASPF_DBG_INFO_S;

typedef struct tagAspfCtrlData
{
	UCHAR ucCfgSeq;
	ASPF_DBG_INFO_S stDbgInfo;
	UINT uiSyncSeq;
	BOOL_T bIcmpErrReply;
	rte_atomic32_t astDropCount[ASPF_STAT_NR][ASPF_DROP_TYPE_MAX];
} ASPF_CTRL_S;

extern ASPF_CTRL_S g_stAspfCtrl;

static inline ASPF_CTRL_S *ASPF_CtrlData_Get(VOID)
{
    return &g_stAspfCtrl;
}

#endif
