#ifndef _TCP_H_
#define _TCP_H_

#include "types.h"

typedef u_int32_t tcp_seq;

#define tcp6_seq  tcp_seq  /* for KAME src sync over BSD*'s */
#define tcp6hdr   tcphdr   /* for KAME src sync over BSD*'s */

/*
 * TCP header.
 * Per RFC 793,September,1981.
 */
typedef struct tcphdr {
    u_short th_sport;      /* source port */    
    u_short th_dport;      /* destination port */
    tcp_seq th_seq;        /* sequence number */
    tcp_seq th_ack;        /* acknowledgement number */
#if defined(_LITTLE_ENDIAN_BITFIELD)
    u_char  th_x2:4,       /*(unused)*/
            th_off:4;      /* data offset */
#elif defined(_BIG_ENDIAN_BITFIELD)
    u_char  th_off:4,      /* data offset */
            th_x2:4;       /*(unused)*/
#else
    #error "Adjust your product defines"
#endif
    u_char  th_flags;
#define   TH_FIN  0x01
#define   TH_SYN  0x02
#define   TH_RST  0x04
#define   TH_PUSH 0x08
#define   TH_ACK  0x10
#define   TH_URG  0x20
#define   TH_ECE  0x40
#define   TH_CWR  0x80
#define   TH_FLAGS  (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short  th_win;    /* window */
    u_short  th_sum;    /* checksum */
    u_short  th_urp;    /* urgent pointer */
}TCPHDR_S;

#endif