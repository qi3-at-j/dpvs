#ifndef _UDP_H_
#define _UDP_H_

#include "types.h"

/*
 * UDP protocol header.
 * Per RFC 768, September, 1981.
*/
typedef struct udphdr {
    u_short    uh_sport;    /* source port */
    u_short    uh_dport;    /* destination port */
    u_short    uh_ullen;    /* udp length */
    u_short    uh_sum;      /* udp checksum */
}UDPHDR_S;

#endif