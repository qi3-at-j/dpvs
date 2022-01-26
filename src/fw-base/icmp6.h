#ifndef _ICMP6_H_
#define _ICMP6_H_

#include "types.h"

#define ICMP6_DST_UNREACH        1      /* dest unreachable, codes defined below */
#define ICMP6_PACKET_TOO_BIG     2      /* packet too big */
#define ICMP6_TIME_EXCEEDED      3      /* time exceeded, code: */
#define ICMP6_PARAM_PROB         4      /* ip6 header bad */

#define ICMP6_ECHO_REQUEST       128    /* echo service */
#define ICMP6_ECHO_REPLY         129    /* echo reply */
#define MLD_LISTENER_QUERY       130    /* multicast listener query */
#define MLD_LISTENER_RPORT       131    /* multicast listener report */
#define MLD_LISTENER_DONE        132    /* multicast listener done */
#define MLD_LISTENER_REDUCTION   MLD_LISTENER_DONE    /* RFC3542 definition */

/* RFC2292 decls */
#define ICMP6_MEMBERSHIP_QUERY      130    /* group membership query */
#define ICMP6_MEMBERSHIP_REPORT     131    /* group membership report */
#define ICMP6_MEMBERSHIP_REDUCTION  132    /* group membership termination */

#define ND_ROUTER_SOLICIT           133    /* router solicitation */
#define ND_ROUTER_ADVERT            134    /* router advertisement */
#define ND_NEIGHBOR_SOLICIT         135    /* neighbor solicitation */
#define ND_NEIGHBOR_ADVERT          136    /* neighbor advertisement */
#define ND_REDIRECT                 137    /* redirect */

#define ICMP6_ROUTER_RENUMBERING    138    /* router renumbering */

#define ICMP6_WRUREQUEST            139    /* who are you request */
#define ICMP6_WRUREPLY              140    /* who are you reply */
#define ICMP6_FQDN_QUERY            139    /* FQDN query */
#define ICMP6_FQDN_REPLY            140    /* FQDN reply */
#define ICMP6_NI_QUERY              139    /* node information request */
#define ICMP6_NI_REPLY              140    /* node information reply */
#define MLDV2_LISTENER_REORT        143    /* RFC3810 listener report */

#define IND_SOLICIT                 141    /* IND Solicitations */
#define IND_ADVERT                  142    /* IND Advertisements */
#define ICMP6_DHAAD_REQUEST         144    /* DHAAD request */
#define ICMP6_DHAAD_REPLY           145    /* DHAAD reply */

/*The definitions below are experimental, TBA */
#define MLD_MTRACE_RESP             200    /* mtrace resp (to sender) */
#define MLD_MTRACE                  201    /* mtrace messages */

#define ICMP6_MAXTYPE               201


typedef struct icmp6_hdr {
    u_int8_t    icmp6_type;    /* type field */
    u_int8_t    icmp6_code;    /* code field */    
    u_int16_t   icmp6_cksum;   /* checksum field */
    union {
        u_int32_t    icmp6_un_data32[1];    /* type-specific field */        
        u_int16_t    icmp6_un_data16[2];    /* type-specific field */
        u_int8_t     icmp6_un_data8[4];     /* type-specific field */
    } icmp6_dataun;
} ICMP6HDR_S;

#define icmp6_data32     icmp6_dataun.icmp6_un_data32
#define icmp6_data16     icmp6_dataun.icmp6_un_data16
#define icmp6_data8      icmp6_dataun.icmp6_un_data8
#define icmp6_pptr       icmp6_data32[0]       /* parameter prob */
#define icmp6_mtu        icmp6_data32[0]       /* packet too big */
#define icmp6_id         icmp6_data16[0]       /* echo request/reply */
#define icmp6_seq        icmp6_data16[1]       /* echo request/reply */
#define icmp6_maxdelay   icmp6_data16[0]       /* mcast group membership */

#endif
