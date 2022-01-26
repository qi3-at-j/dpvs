
#include <ctype.h>

#include <rte_malloc.h>
#include <rte_memcpy.h>


#include "session.h"
#include "session_kcore.h"
#include "ac.h"
#include "session_kalg.h"
#include "session_kalg_ftp.h"
#include "session_kdebug.h"
#include "apr.h"



#define SESSION_TABLEHASH_LENGTH_MIN 1024  /* ��С�ĻỰHASH���� */

UINT g_uiSessTableHashLength;


#if 0
ULONG SESSION_Hash_Init(VOID)
{
	/*
	SESSION_CONF_S *pstConfInfo;
	UINT uiMaxEntry;
	UINT uiIndex = 0;
	*/
	ULONG ulRet;

    #if 0
	pstConfInfo = SESSION_GetConfInfo();
	uiMaxEntry = pstConfInfo->uiMaxSessionEntries;

	while(uiMaxEntry > 1)
	{
		uiMaxEntry = uiMaxEntry >> 1;
		uiIndex++;
	}
	g_uiSessTableHashLength = (UINT)1<<uiIndex;
	/* ��СHASH���ȱ��� */
	if(g_uiSessTableHashLength < SESSION_TABLEHASH_LENGTH_MIN)
	{
		g_uiSessTableHashLength = SESSION_TABLEHASH_LENGTH_MIN;
	}
    #endif
	
	g_uiSessTableHashLength = SESSION_TABLEHASH_LENGTH_MIN;
	
	/* ������HASH��ʼ�� */
	ulRet = SESSION_RelationHash_Init();

	return ulRet;
		
}
#endif
