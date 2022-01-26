#include "session.h"
#include "session_kcore.h"
//#include "in.h"

#include <netinet/in.h>


/*****************************************************************************
��ת���ӻỰ����ͳ����Ϣ
*****************************************************************************/
VOID SESSION_FsAddStat(IN SESSION_S *pstSession,
					   IN const MBUF_S *pstMbuf,
					   IN SESSION_CTRL_S *pstSessionCtrl,
					   IN SESSION_PKT_DIR_E enPktDir)
{
	if (SESSION_DIR_ORIGINAL == enPktDir)
	{
		/* �ֲ�ͳ�ƹ��ܣ�ORIGINAL������ͳ��*/
		SESSION_KAddOriginalFlowStat(pstMbuf, pstSession);
	}
	else
	{
		/* �ֲ�ͳ�ƹ��ܣ�REPLY������ͳ�� */
		SESSION_KAddReplyFlowStat(pstMbuf, pstSession);
	}

	/* ����L4Э������ͳ�� */
	SESSION_KAddTotalState((SESSION_L4_TYPE_E)pstSession->stSessionBase.ucSessionL4Type,
							1, MBUF_GET_TOTALDATASIZE(pstMbuf), pstSessionCtrl);

	return;
}

