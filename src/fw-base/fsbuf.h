#if 0
/* ��ȡBLOCKBUF�������ܳ��� */
static inline UINT FSBUF_GET_TOTALDATASIZE(IN const FSBUF_BLOCKINFO_S *pstBlockInfo)
{
	return pstBlockInfo->uiDataLen;
}

/* ��ȡBLOCKBUF��ʣ����ó��� */
static inline UINT32 FSBUF_GET_LEFTLENGTH(IN const FSBUF_BLOCKINFO_S *pstBlockInfo)
{
	return pstBlockInfo->uiDataBlockLen - (pstBlockInfo->uiDataOffset + pstBlockInfo->uiDataLen);
}

/* ����BLOCKBUF�����ݳ��� */
static inline ULONG FSBUF_ADD_DATALENGTH(IN UINT32 uiLength, INOUT FSBUF_BLOCKINFO_S *pstBlockInfo)
{
	if (uiLength > FSBUF_GET_LEFTLENGTH(pstBlockInfo))
	{
		return ERROR_FAILED;
	}

	pstBlockInfo->uiDataLen += uiLength;

	return ERROR_SUCCESS;
}

/* ��������͵�Get��Set */
static inline VOID FSBUF_SET_L3TYPE(INOUT FSBUF_PKTINFO_S *pstPktInfo, IN UCHAR ucNetType)
{
	pstPktInfo->ucL3Type = ucNetType;
	return;
}

static inline UCHAR FSBUF_GET_L3TYPE(IN const FSBUF_PKTINFO_S *pstPktInfo)
{
	return (pstPktInfo->ucLType);
}

/* ����ΪIP��Ƭ���� */
static inline VOID FSBUF_SET_IP_FRAGMENT(INOUT FSBUF_PKINFO_S *pstPktInfo)
{
	pstPktInfo->ucIsFragment = BOOL_TRUE;
	return;
}

/* �б�MBuf�Ƿ�ΪIP��Ƭ���� */
static inline BOOL_T FSBUF_IS_IP_FRAGMENT(IN const FSBUF_PKTINFO_S *pstPktInfo) 
{
	return (BOOL_T)(pstPktInfo->ucIsFragment);
}

/* ����ΪIP��Ƭ��Ƭ���� */
static inline VOID FSBUF_SET_IP_FIRSTFRAG(INOUT FSBUF_PKTINFO_S *pstPktInfo)
{
	pstPktInfo->ucIsFirstFrag = BOOL_TRUE;
	return;
}

/* �б��Ƿ�ΪIP��Ƭ��Ƭ���� */
static inline BOOL_T FSBUF_IS_IP_FIRSTFRAG(IN const FSBUF_PKTINFO_S *pstPktInfo)
{
	return (BOOL_T)(pstPktInfo->ucIsFirstFrag);
}

/* ������һ����ַ��Get��Set */
static inline VOID FSBUF_SET_IP_NEXTHOP(INOUT FSBUF_PKTINFO_S *pstPktInfo, IN UINT32 uiAddr)
{
	pstPktInfo->uiNextHop = uiAddr;
	return;
}

/* ���ĵ���·�����͵�Get��Set */
static inline VOID FSBUF_SET_LINKTYPE(INOUT FSBUF_PKTINFO_S *pstPktInfo,IN UCHAR ucLinkType)
{
	pstPktInfo->ucLinkType = ucLinkType;
	return; 
}

static inline UCHAR FSBUF_GET_LINKTYPE(IN const FSBUF_PKTINFO_S *pstPktInfo)
{
	return pstPktInfo->ucLinkType;
}

/* ���ĵ���·��ͷ�����ȵ�Set��Get��Inc */
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

/* ����ԴMAC��Ŀ��MAC��Get��Set*/
static inline UCHAR *FSBUF_GET_SOURCEMAC(IN const FSBUF_PKTINFO_S *pstPktInfo)
{
	return (UCHAR*)(pstPktInfo->unL2Hdr.stEthHdr.aucHdrSrcMacAddr);
}

static inline UCHAR *FSBUF_GET_DESTMAC(IN const FSBUF_PKTINFO_S *pstPktInfo)
{
	return (UCHAR*)(pstPktInfo->unL2Hdr.stEthHdr.aucHdrDstMacAddr);
}
#endif

