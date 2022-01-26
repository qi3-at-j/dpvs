#if 0
/* 获取BLOCKBUF中数据总长度 */
static inline UINT FSBUF_GET_TOTALDATASIZE(IN const FSBUF_BLOCKINFO_S *pstBlockInfo)
{
	return pstBlockInfo->uiDataLen;
}

/* 获取BLOCKBUF中剩余可用长度 */
static inline UINT32 FSBUF_GET_LEFTLENGTH(IN const FSBUF_BLOCKINFO_S *pstBlockInfo)
{
	return pstBlockInfo->uiDataBlockLen - (pstBlockInfo->uiDataOffset + pstBlockInfo->uiDataLen);
}

/* 增加BLOCKBUF中数据长度 */
static inline ULONG FSBUF_ADD_DATALENGTH(IN UINT32 uiLength, INOUT FSBUF_BLOCKINFO_S *pstBlockInfo)
{
	if (uiLength > FSBUF_GET_LEFTLENGTH(pstBlockInfo))
	{
		return ERROR_FAILED;
	}

	pstBlockInfo->uiDataLen += uiLength;

	return ERROR_SUCCESS;
}

/* 网络层类型的Get和Set */
static inline VOID FSBUF_SET_L3TYPE(INOUT FSBUF_PKTINFO_S *pstPktInfo, IN UCHAR ucNetType)
{
	pstPktInfo->ucL3Type = ucNetType;
	return;
}

static inline UCHAR FSBUF_GET_L3TYPE(IN const FSBUF_PKTINFO_S *pstPktInfo)
{
	return (pstPktInfo->ucLType);
}

/* 设置为IP分片报文 */
static inline VOID FSBUF_SET_IP_FRAGMENT(INOUT FSBUF_PKINFO_S *pstPktInfo)
{
	pstPktInfo->ucIsFragment = BOOL_TRUE;
	return;
}

/* 判别MBuf是否为IP分片报文 */
static inline BOOL_T FSBUF_IS_IP_FRAGMENT(IN const FSBUF_PKTINFO_S *pstPktInfo) 
{
	return (BOOL_T)(pstPktInfo->ucIsFragment);
}

/* 设置为IP分片首片报文 */
static inline VOID FSBUF_SET_IP_FIRSTFRAG(INOUT FSBUF_PKTINFO_S *pstPktInfo)
{
	pstPktInfo->ucIsFirstFrag = BOOL_TRUE;
	return;
}

/* 判别是否为IP分片首片报文 */
static inline BOOL_T FSBUF_IS_IP_FIRSTFRAG(IN const FSBUF_PKTINFO_S *pstPktInfo)
{
	return (BOOL_T)(pstPktInfo->ucIsFirstFrag);
}

/* 报文下一跳地址的Get，Set */
static inline VOID FSBUF_SET_IP_NEXTHOP(INOUT FSBUF_PKTINFO_S *pstPktInfo, IN UINT32 uiAddr)
{
	pstPktInfo->uiNextHop = uiAddr;
	return;
}

/* 报文的链路层类型的Get和Set */
static inline VOID FSBUF_SET_LINKTYPE(INOUT FSBUF_PKTINFO_S *pstPktInfo,IN UCHAR ucLinkType)
{
	pstPktInfo->ucLinkType = ucLinkType;
	return; 
}

static inline UCHAR FSBUF_GET_LINKTYPE(IN const FSBUF_PKTINFO_S *pstPktInfo)
{
	return pstPktInfo->ucLinkType;
}

/* 报文的链路层头部长度的Set、Get和Inc */
static inline VOID FSBUF_SET_LINKHEADSIZE(INOUT FSBUF_PKTINFO_S *pstPktInfo, IN UCHAR ucLength)
{
	pstPktInfo->ucLinkLen = ucLength;
	return;
}

static inline VOID FSBUF_INCREASE_LINKHEADSIZE(INOUT FSBUF_PKTINFO_S *pstPktInfo, IN UCHAR ucLength)
{
	pstPktInfo->ucLinkLen += ucLength;
	return;
}

static inline UCHAR FSBUF_GET_LINKHEADSIZE(IN const FSBUF_PKTINFO_S *pstPktInfo)
{
	return (pstPktInfo->ucLinkLen);
}

/* 报文源MAC和目的MAC的Get和Set*/
static inline UCHAR *FSBUF_GET_SOURCEMAC(IN const FSBUF_PKTINFO_S *pstPktInfo)
{
	return (UCHAR*)(pstPktInfo->unL2Hdr.stEthHdr.aucHdrSrcMacAddr);
}

static inline UCHAR *FSBUF_GET_DESTMAC(IN const FSBUF_PKTINFO_S *pstPktInfo)
{
	return (UCHAR*)(pstPktInfo->unL2Hdr.stEthHdr.aucHdrDstMacAddr);
}
#endif

