#ifndef _ASPF_H_
#define _ASPF_H_

/* ASPF模块名称标识 */
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
	ASPF_FTRST_SYN,                   /* 首报文tcp syn检查丢包 */
    ASPF_CHILD_SYN,                   /* 子会话首报文tcp syn检查丢包 */
    ASPF_NOSESSION_ICMPERR,           /* 无会话icmp error检查丢包 */
    ASPF_NOSESSION_SYN,               /* 无会话tcp syn检查丢包 */
    ASPF_NOSESSION_PFLT,              /* 无会话pflt丢包 */
    ASPF_FIRST_PFLT,                  /* 首报文pflt丢包 */
    ASPF_NOFIRST_PFLT,                /* 后续报文pflt丢包 */
    ASPF_CHILDFIRST_PFLT,             /* 子会话首报文pflt丢包 */
    ASPF_NOCHILDFIRST_PFLT,           /* 子会话后续报文pflt丢包 */
    ASPF_NOFIRST_CFG_CHANGE,          /* 会话后续报文配置变更丢包 */
    ASPF_NOFIRST_IV_STATUS,           /* 后续报文状态检查丢包 */
    ASPF_CHILD_IV_STATUS,             /* 子会话后续报文状态检查丢包 */
    ASPF_FIRST_IV_STATUS,             /* 首报文状态检查丢包 */
    ASPF_PFLT_DIM,                    /* 域间实例调用DIM应用识别丢包 */
    ASPF_DROP_TYPE_MAX
} ASPF_DROP_TYPE_E;

/* aspf的debug信息 */
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
