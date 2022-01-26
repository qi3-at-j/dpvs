#ifdef BUILD_TODO

/*********************************************************************
Input:  VRF_INDEX vrfIndex��VPN ����
	    IN6ADDR S *pstDst��Ŀ�ĵ�ַ
	    UINT32 uiMode����ѯģʽ���ṩ���¼���ģʽ��FIB_QUERY_DEFAULT��FIB_QUERY_TURN
	    pstMbuf������ΪNULL
Output: FIB6_FWDINFO_S *pstFIB6Info��FIB6 ת����Ϣ
���жϻ��ں��߳��е���
Locking seq:rcu����
Description: ����˽��������Ŀ�ĵ�ַ�����ƥ���ѯ FIB6 ��ȡת����Ϣ
*****************************************************************************/
ULONG FIB6_SearchFWDInfo(IN VRF_INDEX vrfIndex,
						IN const IN6ADDR_S *pstDst,
						IN UINT32 uiMode,
						IN const MBUF_S *pstMbuf,
						OUT FIB6_FWDINFO_S *pstFIB6FWDInfo)
{
	FIB_MDC_S *pstFIBMDCData;
	FIB6 DB_FUNCSET_S *pstFIBFuncSet;
	FIB6_NODE_S *pstFIBNode;
	FIB6_BASE_S *pstPrefixBase = NULL;
	FIB6NDHOST_S *pstNDHostEntry;
	ULONG ulRet = ERROR_FATLED;

	/* ��ȡ��ǰMDC ���� */
	pstFIBMDCData = FIB_GetMdcData();
	if ((unlikely (NULL == pstFIBMDCData)) ||
		(BOOL_TRUE == pstFIBMDCData->bMDCDeleting) ||
		(unlikely(NULL == pstFIBMDCData->pstPrefix6StoreTable)))
	{
		return ERROR_FAILED;
	}

	/* �����Ϸ��Լ�� */ 
	if (unlikely((NULL == pstDst) ||
				(NULL = pstFIB6FWDInfo) ||
				(vrfIndex >pstFIBMDCData->vrfMaxIndex)))
	{
		rte_atomic32_inc(&(pstFIBMDCData->stPrefix6ErrStatistics.stFWDInvalid)); 
		return ERROR_FAILED;
	}

	pstFIBFuncSet = g_pstFIB6OpSet->pfGetZoneFunc(vrfIndex);
	DBGASSERT(NULL != pstFIBFuncSet);

	/* ���� VPN ID��Ŀ�ĵ�ַ���ƥ����� FIB6 �ڵ� */
	pstFIBNode= pstFIBFuncSet->pfSearchNodeByIP(pstFIBMDCData, vrfIndex, pstDst); 
	if ((NULL != pstFIBNode)&&
		(NULL != (pstPrefixBase = pstFIBNode->pstNodeBase)))
	{
		/* FIB ���� */
		if (NULL != pstPrefixBase->pstEntry)
		{
			ULONG ulEcmpNum;

			ulRet = VN_SearchFwdInfoByMode(pstPrefixBase-ulVnHandle,
											AF_INET6,
											uiMode,
											pstMbuf,
											&(pstFIB6FWDInfo->stVnFwdInfo),
											&ulEcmpNum,
											&pstFIB6FWDInfo->uiVNTimeStamp);
			if (ERROR_SUCCESS == ulRet)
			{
				/* ���ݲ��ҵ��ı����Լ� FIB6 �ڵ���Ϣ��� FIB6_FWDINFO_S �ṹ */
				ulRet = g_pstFIB6OpSet->pfFillFWDInfo(pstFIBNode,pstPrefixBase,ulEcmpNum,pstFIB6FWDInfo);
			}
		}
		else if (NULL != (pstNDHostEntry = pstPrefixBase->pstNDHostEntry)��
		{
			g_pstFIB6OpSet->pfNDFillFWDInfo(pstFIBNode,pstPrefixBase,pstNDHostEntry,pstFIB6FWDInfo);
			ulRet = ERROR_SUCCESS;
		}
	}
	else
	{
		rte_atomic32_inc(&(pstFIBMDCData->stPrefix6ErrStatistics.stFWDInvalid));
	}

	/* ����ת�����FIB+VN+ADJ����Ϣ��service-slot��Ϣ������������ */
	if (ERROR_SUCCESS == ulRet)
	{
		fib6_SetFWDInfo(pstFIB6FWDInfo);
	}

	return ulRet;
}

#endif
