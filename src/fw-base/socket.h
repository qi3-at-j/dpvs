#ifndef _SOCKET_H_
#define _SOCKET_H_

/*
 * Address families.
*/
#ifndef AF_INET
#define AF_INET          2    /* Internet IP Protocol */
#endif

#ifndef AF_INET6
#define AF_INET6         10   /* IP Version 6 */
#endif

#if 0
#define AF_UNSPEC        0
#define AF_UNIX          1    /* Unix domain sockets */
#define AF_LOCAL         1    /* POSIX name for AF_UNIX */
#define AF_INET          2    /* Internet IP Protocol */
#define AF_AX25          3    /* Amateur Radio AX.25 */
#define AF_IPX           4    /* Novell IPX */
#define AF_APPLETALK     5    /* AppleTalk DDP */
#define AF_NETOM         6    /* Amateur Radio NET/ROM */
#define AF_BRIDGE        7    /* Multiprotocol bridge */
#define AF_ATMPVC        8    /* ATM PVCs */
#define AF_X25           9    /* Reserved for X.25 project */
#define AF_INET6         10   /* IP Version 6 */
#define AF_ROSE          11   /* Amateur Radio X.25 PLP */
#define AF_DECnet        12   /* Reserved for DECnet project */
#define AF_NETBEUI       13   /* Reserver for 802.2LLC project */
#define AF_SECURITY      14   /* Security callback pseudo AF */
#define AF_KEY           15   /* PF_KEY key management API */
#define AF_NETLINK       16
#define AF_ROUTE AF_NETLINK   /* Alias to emulate 4.4BSD */
#define AF_PACKET        17   /* Packet family */
#define AF_ASH           18   /* Ash */
#define AF_ECONET        19   /* Acorn Econet */
#define AF_ATMSVC        20   /* ATM SVCs */
#define AF_SNA           22   /* Linux SNA Project (nutters!) */
#define AF_IRDA          23   /* IRDA sockets */
#define AF_PPPOX         24   /* PPPoX sockets */
#define AF_WANPIPE       25   /* Wanpipe API Sockets */
#define AF_LLC           26   /* Linux LLC */
#define AF_TIPC          30   /* TIPC sockets */
#define AF_BLUETOOTH     31   /* Bluetooth sockets */
#define AF_IUCV          32   /* IUCV sockets */
#define AF_RXRPC         33   /* RxRPC sockets */
#define AF_ARP           34   /* ARP */
#define AF_ARPREPLY      35   /* ARP Reply */
#define AF_MPLS          36   /* MPLS */
#define AF_LIPC          37   /* LIPC address family */
#define AF_MBUS          38   /* MBus address family */
#define AF_OSI           39   /* OSI Socket family */
#define AF_FC            40   /* FC family */
#define AF_LPS           41   /* Linux Packet family */
#define AF_NETLINK_CMW   42   /* Comware Netlink family */

#define AF_MAX           43   /* For now.. */
#endif
#endif