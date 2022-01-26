#ifdef BUILD_TODO

/*********************************************************************
Input:  VRF_INDEX vrfIndex，VPN 索引
	    IN6ADDR S *pstDst，目的地址
	    UINT32 uiMode，查询模式，提供如下几种模式∶FIB_QUERY_DEFAULT，FIB_QUERY_TURN
	    pstMbuf，可以为NULL
Output: FIB6_FWDINFO_S *pstFIB6Info，FIB6 转发信息
软中断或内核线程中调用
Locking seq:rcu保护
Description: 根据私网索引和目的地址按照最长匹配查询 FIB6 获取转发信息
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

	/* 获取当前MDC 数据 */
	pstFIBMDCData = FIB_GetMdcData();
	if ((unlikely (NULL == pstFIBMDCData)) ||
		(BOOL_TRUE == pstFIBMDCData->bMDCDeleting) ||
		(unlikely(NULL == pstFIBMDCData->pstPrefix6StoreTable)))
	{
		return ERROR_FAILED;
	}

	/* 参数合法性检查 */ 
	if (unlikely((NULL == pstDst) ||
				(NULL = pstFIB6FWDInfo) ||
				(vrfIndex >pstFIBMDCData->vrfMaxIndex)))
	{
		rte_atomic32_inc(&(pstFIBMDCData->stPrefix6ErrStatistics.stFWDInvalid)); 
		return ERROR_FAILED;
	}

	pstFIBFuncSet = g_pstFIB6OpSet->pfGetZoneFunc(vrfIndex);
	DBGASSERT(NULL != pstFIBFuncSet);

	/* 根据 VPN ID、目的地址按最长匹配查找 FIB6 节点 */
	pstFIBNode= pstFIBFuncSet->pfSearchNodeByIP(pstFIBMDCData, vrfIndex, pstDst); 
	if ((NULL != pstFIBNode)&&
		(NULL != (pstPrefixBase = pstFIBNode->pstNodeBase)))
	{
		/* FIB 优先 */
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
				/* 根据查找到的表项以及 FIB6 节点信息填充 FIB6_FWDINFO_S 结构 */
				ulRet = g_pstFIB6OpSet->pfFillFWDInfo(pstFIBNode,pstPrefixBase,ulEcmpNum,pstFIB6FWDInfo);
			}
		}
		else if (NULL != (pstNDHostEntry = pstPrefixBase->pstNDHostEntry)）
		{
			g_pstFIB6OpSet->pfNDFillFWDInfo(pstFIBNode,pstPrefixBase,pstNDHostEntry,pstFIB6FWDInfo);
			ulRet = ERROR_SUCCESS;
		}
	}
	else
	{
		rte_atomic32_inc(&(pstFIBMDCData->stPrefix6ErrStatistics.stFWDInvalid));
	}

	/* 根据转发表项（FIB+VN+ADJ）信息、service-slot信息决定分流属性 */
	if (ERROR_SUCCESS == ulRet)
	{
		fib6_SetFWDInfo(pstFIB6FWDInfo);
	}

	return ulRet;
}

#endif
