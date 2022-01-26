#ifndef _ASPF_KDBG_H_
#define _ASPF_KDBG_H_


VOID ASPF_kdbg_Zonepair_Output_Packet(IN CHAR *pcDbgDesc,
                                      IN ACL_VERSION_E enAclVer,
                                      IN MBUF_S *pstMBuf,
                                      IN USHORT usL3Offset,
                                      IN const ASPF_CTRL_S *pstAspfCtrl);

#define ASPF_DBG_ZONEPAIR_PACKETS_EVENT_SWITCH(pcDbgDesc, enAclVer, pstMBuf, usL3Offset, pstAspfCtrl)\
{\
    if(0 != (pstAspfCtrl->stDbgInfo.uiDbgSwitch & ASPF_DBG_BIT_PACKET)) \
    {\
        ASPF_kdbg_Zonepair_Output_Packet(pcDbgDesc, enAclVer, pstMBuf, usL3Offset, pstAspfCtrl);\
    }\
}





#endif
