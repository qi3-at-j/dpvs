#ifdef BUILD_TODO

#define GOLDEN_RATIO_PRIME_32 0x9e370001UL


/* �ͷ�APP list */
STATIC VOID _kpolicy_applist_free(IN const DL_HEAD_S *pstList, IN UINT uiPolicyNum)
{
	ASPF_K_APPID_NODE_ S *pstAppIDNode;
	DL_NODE_S *pstNode;
	DL_NODE_S *pstNext;

	DL_FOREACH_SAFE(pstList, pstNode, pstNext)
	{
		pstAppIDNode = container_of(pstNode, ASPF_K_APPID_NODE_S, stNode);
		DL_Del(pstNode);
		RCU_BHCall(&(pstAppIDNode->stRcuInfo));
	}

	return;
}


BOOL_T ASPF_kutil_IsIcmpv6Relay(IN UCHAR ucType, IN UCHAR ucCode)
{
	return ((ucType == ICMP6_ECHO_REPLY) && (0 == ucCode));
}    

/* Description�ü��һ��Э��id�Ƿ�raw-protoco */
BOOL_T  ASPF_kutil_IsRawProto(IN UINT uiProtoID)
{
	BOOL_T bFlag;

	switch (uiProtoID)
	{
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_UDPLITE:
		case IPPROTO_ICMP
		case IPPROTO_ICMPV6:
		case IPPROTO_SCTP:
		case IPPROTO_DCCP:
		{
			bFlag = BOOL_FALSE;
			break;
		}
		default:
		{
			bFlag = BOOL_TRUE;
			break;
		}
	}

	return bFlag;
}

/* ��Ч��aspf-policy��� */
#define ASPF_INVALID_POLICY_NUM  ((UINT)(~0))

/* ͬ��aspf-policy���ں�̬ʱ��ÿ��aspf-policy֧��detect app������ */
#define ASPF_SYNC_APP_MAX_NUM   64U

/* ͬ��aspf-policy���ں�̬ʱ��ÿ��aspf-policy֧��detect protocol������ */
#define ASPF_SYNC_PROTO_MAX_NUM 8U


/*ASPF Ĭ�϶�������*/
typedef enum tagAspfDefaultAction
{
	ASPF_DEFAULT_ACTION_DENY,
	ASPF_DEFAULT_ACTION_PERMIT,
	ASPF_DEFAULT_ACTION_MAX
} ASPF_DEFAULT_ACTION_E;


static inline BOOL_T SESSION_FSBUF_TEST_FLAG(IN const FSBUF_PKTINFO_S *pstPktInfo, IN USHORT usFlagBit)
{
	return (0 != ((UINT)pstPktInfo->usSessionFlag & (UINT)usFlagBit));
}

#define SESSION_TABLE_CLEAR_LOGFLAG(_pSession) \
{(_pSession)->usTableFlag &= (USHORT)~((USHORT)SESSION_LOG_NORMAL | (USHORT)SESSION_LOG_TIME | \
							 (USHORT)SESSION_LOG_FLOW_BYTE | (USHORT)SESSION_LOG_FLOW_PACKET | \
							 (USHORT)SESSION_LOG_ENABLE);}

#endif
