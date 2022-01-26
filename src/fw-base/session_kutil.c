#include "session.h"
#include "session_kcore.h"
//#include "in.h"

#include <netinet/in.h>


/*****************************************************************************
快转增加会话报文统计信息
*****************************************************************************/
VOID SESSION_FsAddStat(IN SESSION_S *pstSession,
					   IN const MBUF_S *pstMbuf,
					   IN SESSION_CTRL_S *pstSessionCtrl,
					   IN SESSION_PKT_DIR_E enPktDir)
{
	if (SESSION_DIR_ORIGINAL == enPktDir)
	{
		/* 局部统计功能，ORIGINAL方向报文统计*/
		SESSION_KAddOriginalFlowStat(pstMbuf, pstSession);
	}
	else
	{
		/* 局部统计功能，REPLY方向报文统计 */
		SESSION_KAddReplyFlowStat(pstMbuf, pstSession);
	}

	/* 根据L4协议类型统计 */
	SESSION_KAddTotalState((SESSION_L4_TYPE_E)pstSession->stSessionBase.ucSessionL4Type,
							1, MBUF_GET_TOTALDATASIZE(pstMbuf), pstSessionCtrl);

	return;
}

