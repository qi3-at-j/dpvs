#ifndef _ASPF_KPOLICY_H_
#define _ASPF_KPOLICY_H_


#define ASPF_APPID_HASH_BITS 8U
#define ASPF_APPID_BUCKET_SIZE ((UINT)1 << ASPF_APPID_HASH_BITS)


/*** 结构体，枚举定义 ***/
typedef struct tagASPF_K_APPID_NODE
{
	DL_NODE_S stNode;
	RCU_REG_S stRcuInfo;
	UINT uiAppID;
	UINT uiSyncSeq;
} ASPF_K_APPID_NODE_S;

typedef struct tagASPF_K_POLICY
{
	RCU_REG_S stRcuInfo;
	BOOL_T bIcmpErrDrop;
	BOOL_T bTcpSynCheck;
	DL_HEAD_S astAppIDStatus[ASPF_APPID_BUCKET_SIZE];
	UINT uiSyncSeq;
	UCHAR aucProtoIDStatus[IPPROTO_MAX];
} ASPF_K_POLICY_S;

#endif