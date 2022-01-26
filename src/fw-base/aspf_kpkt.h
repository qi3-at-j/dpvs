#ifdef BUILD_TODO


#ifndef _ASPF_KPKT_H_
#define _ASPF_KPKT_H_

#define ASPF_TCP_CARE_FLAGS   (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG)
#define ASPF_TCP_NOCARE_FLAGS (TH_PUSH | TH_ECE | TH_CWR)


#define SESSION_GetL4Type(hSession) \
	(((SESSION_S *)hSession)->stSessionBase.ucSessionL4Type)

#define PKT_INCOMPLETE  PKT_ENQUEUED

#endif
#endif

