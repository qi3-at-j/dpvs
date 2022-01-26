#include <netinet/in.h>
#include "baseype.h"
#include "apr.h"

STATIC UINT GetAppIDForTCP(USHORT usDstPort)
{
    UINT uiAppID = APR_ID_INVALID;

    switch(usDstPort)
    {
        case 7:
            uiAppID = APP_ID_ECHO;
            break;

        case 11:
            uiAppID = APP_ID_SYSTEM_STATS;
            break;

        case 13:
            uiAppID = APP_ID_DAYTIME;
            break;

        case 19:
            uiAppID = APP_ID_CHARGEN;
            break;

        case 20:
            uiAppID = APP_ID_FTPDATA;
            break;

        case 21:
            uiAppID = APP_ID_FTP;
            break;

        case 22:
            uiAppID = APP_ID_SSH;
            break;

        case 23:
            uiAppID = APP_ID_TELNET;
            break;

        case 25:
            uiAppID = APP_ID_SMTP;
            break;

        case 37:
            uiAppID = APP_ID_TIME;
            break;

        case 43:
            uiAppID = APP_ID_NICNAME;
            break;

        case 49:
            uiAppID = APP_ID_TACACS;
            break;

        case 53:
            uiAppID = APP_ID_DNS;
            break;

        case 55:
            uiAppID = APP_ID_ISIGL;
            break;

        case 63:
            uiAppID = APP_ID_WHOISPP;
            break;

        case 65:
            uiAppID = APP_ID_TACACSDS;
            break;

        case 67:
            uiAppID = APP_ID_BOOTPS;
            break;

        case 68:
            uiAppID = APP_ID_BOOTPC;
            break;

        case 70:
            uiAppID = APP_ID_GOPHER;
            break;

        case 79:
            uiAppID = APP_ID_FINGER;
            break;

        case 80:
            uiAppID = APP_ID_HTTP;
            break;

        case 88:
            uiAppID = APP_ID_KERBEROS;
            break;

        case 92:
            uiAppID = APP_ID_NPP;
            break;

        case 107:
            uiAppID = APP_ID_RTELENT;
            break;

        case 110:
            uiAppID = APP_ID_POP3;
            break;

        case 111:
            uiAppID = APP_ID_SUNRPC;
            break;

        case 119:
            uiAppID = APP_ID_NNTP;
            break;

        case 123:
            uiAppID = APP_ID_NTP;
            break;

        case 135:
            uiAppID = APP_ID_MSRPC;
            break;

        case 137:
            uiAppID = APP_ID_NETBIOSNS;
            break;

        case 138:
            uiAppID = APP_ID_NETBIOSDGM;
            break;

        case 139:
            uiAppID = APP_ID_NETBIOSSSN;
            break;

        case 143:
            uiAppID = APP_ID_IMAP;
            break;

        case 161:
            uiAppID = APP_ID_SNMP;
            break;

        case 162:
            uiAppID = APP_ID_SNMPTRAP;
            break;

        case 177:
            uiAppID = APP_ID_XDMCP;
            break;

        case 179:
            uiAppID = APP_ID_BGP;
            break;

        case 194:
            uiAppID = APP_ID_IRC;
            break;

        case 213:
            uiAppID = APP_ID_IPX;
            break;

        case 217:
            uiAppID = APP_ID_DBASE;
            break;

        case 220:
            uiAppID = APP_ID_IMAP3;
            break;

        case 363:
            uiAppID = APP_ID_RSVP_TUNNEL;
            break;

        case 371:
            uiAppID = APP_ID_CLEARCASE;
            break;

        case 389:
            uiAppID = APP_ID_LDAP;
            break;

        case 443:
            uiAppID = APP_ID_HTTPS;
            break;

        case 445:
            uiAppID = APP_ID_SMB;
            break;

        case 458:
            uiAppID = APP_ID_APPLEQTC;
            break;

        case 465:
            uiAppID = APP_ID_SMTPS;
            break;

        case 469:
            uiAppID = APP_ID_RCP;
            break;

        case 500:
            uiAppID = APP_ID_ISAKMP;
            break;

        case 513:
            uiAppID = APP_ID_LOGIN;
            break;

        case 514:
            uiAppID = APP_ID_RSH;
            break;

        case 515:
            uiAppID = APP_ID_PRINTER;
            break;

        case 523:
            uiAppID = APP_ID_IBM_DB2;
            break;

        case 525:
            uiAppID = APP_ID_TIMED;
            break;

        case 529:
            uiAppID = APP_ID_IRC_SERV;
            break;

        case 543:
            uiAppID = APP_ID_KLOGIN;
            break;

        case 544:
            uiAppID = APP_ID_KSHELL;
            break;

        case 546:
            uiAppID = APP_ID_DHCP6_CLIENT;
            break;

        case 547:
            uiAppID = APP_ID_DHCP6_SERVER;
            break;

        case 554:
            uiAppID = APP_ID_RTSP;
            break;

        case 563:
            uiAppID = APP_ID_NNTPS;
            break;

        case 604:
            uiAppID = APP_ID_TUNNEL;
            break;

        case 636:
            uiAppID = APP_ID_LDAPS;
            break;

        case 666:
            uiAppID = APP_ID_DOOM;
            break;

        case 683:
            uiAppID = APP_ID_CORBA_IIOP;
            break;

        case 684:
            uiAppID = APP_ID_CORBA_IIOP_SSL;
            break;

        case 689:
            uiAppID = APP_ID_NMAP;
            break;

        case 749:
            uiAppID = APP_ID_KERBEROS_ADMIN;
            break;

        case 873:
            uiAppID = APP_ID_RSYNC;
            break;

        case 989:
            uiAppID = APP_ID_FTPS_DATA;
            break;

        case 990:
            uiAppID = APP_ID_FTPS;
            break;

        case 992:
            uiAppID = APP_ID_TELNETS;
            break;

        case 993:
            uiAppID = APP_ID_IMAPS;
            break;

        case 994:
            uiAppID = APP_ID_IRCS;
            break;

        case 995:
            uiAppID = APP_ID_POP3S;
            break;

        case 1002:
            uiAppID = APP_ID_ILS;
            break;

        case 1050:
            uiAppID = APP_ID_CORBA_MAN_AGENT;
            break;

        case 1080:
            uiAppID = APP_ID_SOCKS;
            break;

        case 1214:
            uiAppID = APP_ID_KAZAA;
            break;

        case 1300:
            uiAppID = APP_ID_H323_HOSTCALLSC;
            break;

        case 1352:
            uiAppID = APP_ID_NOTES;
            break;

        case 1433:
            uiAppID = APP_ID_MS_SQL_S;
            break;

        case 1434:
            uiAppID = APP_ID_MS_SQL_M;
            break;

        case 1494:
            uiAppID = APP_ID_CITRIX_ICA;
            break;

        case 1503:
            uiAppID = APP_ID_NETMEETING;
            break;

        case 1521:
            uiAppID = APP_ID_SQLNET;
            break;

        case 1525:
            uiAppID = APP_ID_ORASRV;
            break;

        case 1604:
            uiAppID = APP_ID_CITRIX_ICA_BRO;
            break;

        case 1698:
            uiAppID = APP_ID_RSVP_ENCAP_1;
            break;

        case 1699:
            uiAppID = APP_ID_RSVP_ENCAP_2;
            break;

        case 1701:
            uiAppID = APP_ID_L2TP;
            break;

        case 1718:
            uiAppID = APP_ID_H323_GATEDISC;
            break;

        case 1719:
            uiAppID = APP_ID_RAS;
            break;

        case 1720:
            uiAppID = APP_ID_H225;
            break;

        case 1723:
            uiAppID = APP_ID_PPTP;
            break;

        case 1731:
            uiAppID = APP_ID_NETMEETING;
            break;

        case 1755:
            uiAppID = APP_ID_MMS;
            break;

        case 1812:
            uiAppID = APP_ID_RADIUS;
            break;

        case 1813:
            uiAppID = APP_ID_RADIUS_ACCT;
            break;

        case 1863:
            uiAppID = APP_ID_MSN_MSGER;
            break;

        case 1935:
            uiAppID = APP_ID_RTMP;
            break;

        case 2000:
            uiAppID = APP_ID_SCCP;
            break;

        case 2009:
            uiAppID = APP_ID_NEWS;
            break;

        case 2049:
            uiAppID = APP_ID_NFS;
            break;

        case 2123:
            uiAppID = APP_ID_GTPC;
            break;

        case 2152:
            uiAppID = APP_ID_GTPU;
            break;

        case 2421:
            uiAppID = APP_ID_G_TALK;
            break;

        case 2427:
            uiAppID = APP_ID_MGCPG;
            break;

        case 2428:
            uiAppID = APP_ID_OTT;
            break;

        case 2512:
            uiAppID = APP_ID_CITRIX_IMA;
            break;

        case 2575:
            uiAppID = APP_ID_HL7;
            break;

        case 2598:
            uiAppID = APP_ID_CITRIX_MA_CLIENT;
            break;

        case 2727:
            uiAppID = APP_ID_MGCPC;
            break;

        case 2761:
            uiAppID = APP_ID_DICOM_ISCL;
            break;

        case 2762:
            uiAppID = APP_ID_DICOM_TLS;
            break;

        case 2809:
            uiAppID = APP_ID_CORBA_LOC;
            break;

        case 2979:
            uiAppID = APP_ID_H263_VIDEO;
            break;

        case 3386:
            uiAppID = APP_ID_GPRSDATA;
            break;

        case 3389:
            uiAppID = APP_ID_RDP;
            break;

        case 3460:
            uiAppID = APP_ID_EDM_MANAGER;
            break;

        case 3461:
            uiAppID = APP_ID_EDM_STAGER;
            break;

        case 3462:
            uiAppID = APP_ID_EDM_STD_NOTIFY;
            break;

        case 3463:
            uiAppID = APP_ID_EDM_ADM_NOTIFY;
            break;

        case 3464:
            uiAppID = APP_ID_EDM_MGR_SYNC;
            break;

        case 3465:
            uiAppID = APP_ID_EDM_MGR_CNTRL;
            break;

        case 3478:
            uiAppID = APP_ID_STUN;
            break;

        case 3690:
            uiAppID = APP_ID_SVN;
            break;

        case 3799:
            uiAppID = APP_ID_RADIUS_DYNAUTH;
            break;

        case 5050:
            uiAppID = APP_ID_MMCC;
            break;

        case 5060:
            uiAppID = APP_ID_SIP;
            break;

        case 5190:
        case 5191:
        case 5192:
        case 5193:
            uiAppID = APP_ID_AOL;
            break;

        case 5298:
            uiAppID = APP_ID_XMPP_LINKLOCAL;
            break;

        case 5349:
            uiAppID = APP_ID_STUNS;
            break;

        case 5352:
            uiAppID = APP_ID_DNS_LLQ;
            break;

        case 5353:
            uiAppID = APP_ID_MDNS;
            break;

        case 5354:
            uiAppID = APP_ID_MDNS_RESPONDER;
            break;

        case 5631:
            uiAppID = APP_ID_PCANYWHERE_DATA;
            break;

        case 5632:
            uiAppID = APP_ID_PCANYWHERE_STAT;
            break;

        case 5900:
            uiAppID = APP_ID_RFB;
            break;

        case 6346:
            uiAppID = APP_ID_GNUTELLA_SVC;
            break;

        case 6347:
            uiAppID = APP_ID_GNUTELLA_RTR;
            break;

        case 6620:
            uiAppID = APP_ID_KFTP_DATA;
            break;

        case 6621:
            uiAppID = APP_ID_KFTP;
            break;

        case 6623:
            uiAppID = APP_ID_KTELENT;
            break;

        case 7001:
            uiAppID = APP_ID_T3;
            break;

        case 7004:
            uiAppID = APP_ID_AFS3_KASERVER;
            break;

        case 7648:
            uiAppID = APP_ID_CUSEEME;
            break;

        case 9088:
            uiAppID = APP_ID_SQLEXEC;
            break;

        case 9089:
            uiAppID = APP_ID_SQLEXEC_SSL;
            break;

        case 11112:
            uiAppID = APP_ID_DICOM;
            break;

        case 11720:
            uiAppID = APP_ID_H323_CALLSIGALT;
            break;

        case 50000:
            uiAppID = APP_ID_IBM_DB2;
            break;

        default:
            break;
    }

    return uiAppID;
}


STATIC UINT GetAppIDForSCTP(USHORT usDstPort)
{
    UINT uiAppID = APR_ID_INVALID;

    switch(usDstPort)
    {
        case 21:
            uiAppID = APP_ID_FTP;
            break;

        case 22:
            uiAppID = APP_ID_SSH;
            break;

        case 179:
            uiAppID = APP_ID_BGP;
            break;

        case 443:
            uiAppID = APP_ID_HTTPS;
            break;

        case 2049:
            uiAppID = APP_ID_NFS;
            break;

        default:
            break;
    }

    return uiAppID;
}

STATIC UINT GetAppIDForUDP(USHORT usDstPort)
{
    UINT uiAppID = APR_ID_INVALID;

    switch(usDstPort)
    {
        case 7:
            uiAppID = APP_ID_ECHO;
            break;

        case 11:
            uiAppID = APP_ID_SYSTEM_STATS;
            break;

        case 13:
            uiAppID = APP_ID_DAYTIME;
            break;

        case 19:
            uiAppID = APP_ID_CHARGEN;
            break;

        case 21:
            uiAppID = APP_ID_FTP;
            break;

        case 22:
            uiAppID = APP_ID_SSH;
            break;

        case 23:
            uiAppID = APP_ID_TELNET;
            break;

        case 25:
            uiAppID = APP_ID_SMTP;
            break;

        case 37:
            uiAppID = APP_ID_TIME;
            break;

        case 43:
            uiAppID = APP_ID_NICNAME;
            break;

        case 49:
            uiAppID = APP_ID_TACACS;
            break;

        case 53:
            uiAppID = APP_ID_DNS;
            break;

        case 55:
            uiAppID = APP_ID_ISIGL;
            break;

        case 63:
            uiAppID = APP_ID_WHOISPP;
            break;

        case 65:
            uiAppID = APP_ID_TACACSDS;
            break;

        case 67:
            uiAppID = APP_ID_BOOTPS;
            break;

        case 68:
            uiAppID = APP_ID_BOOTPC;
            break;

        case 69:
            uiAppID = APP_ID_TFTP;
            break;

        case 70:
            uiAppID = APP_ID_GOPHER;
            break;

        case 79:
            uiAppID = APP_ID_FINGER;
            break;

        case 80:
            uiAppID = APP_ID_HTTP;
            break;

        case 88:
            uiAppID = APP_ID_KERBEROS;
            break;

        case 92:
            uiAppID = APP_ID_NPP;
            break;

        case 107:
            uiAppID = APP_ID_RTELENT;
            break;

        case 110:
            uiAppID = APP_ID_POP3;
            break;

        case 111:
            uiAppID = APP_ID_SUNRPC;
            break;

        case 119:
            uiAppID = APP_ID_NNTP;
            break;

        case 123:
            uiAppID = APP_ID_NTP;
            break;

        case 135:
            uiAppID = APP_ID_MSRPC;
            break;

        case 137:
            uiAppID = APP_ID_NETBIOSNS;
            break;

        case 138:
            uiAppID = APP_ID_NETBIOSDGM;
            break;

        case 139:
            uiAppID = APP_ID_NETBIOSSSN;
            break;

        case 143:
            uiAppID = APP_ID_IMAP;
            break;

        case 161:
            uiAppID = APP_ID_SNMP;
            break;

        case 162:
            uiAppID = APP_ID_SNMPTRAP;
            break;

        case 177:
            uiAppID = APP_ID_XDMCP;
            break;

        case 179:
            uiAppID = APP_ID_BGP;
            break;

        case 194:
            uiAppID = APP_ID_IRC;
            break;

        case 213:
            uiAppID = APP_ID_IPX;
            break;

        case 217:
            uiAppID = APP_ID_DBASE;
            break;

        case 220:
            uiAppID = APP_ID_IMAP3;
            break;

        case 363:
            uiAppID = APP_ID_RSVP_TUNNEL;
            break;

        case 371:
            uiAppID = APP_ID_CLEARCASE;
            break;

        case 389:
            uiAppID = APP_ID_LDAP;
            break;

        case 443:
            uiAppID = APP_ID_HTTPS;
            break;

        case 445:
            uiAppID = APP_ID_SMB;
            break;

        case 458:
            uiAppID = APP_ID_APPLEQTC;
            break;

        case 465:
            uiAppID = APP_ID_SMTPS;
            break;

        case 469:
            uiAppID = APP_ID_RCP;
            break;

        case 500:
            uiAppID = APP_ID_ISAKMP;
            break;

        case 513:
            uiAppID = APP_ID_WHO;
            break;

        case 514:
            uiAppID = APP_ID_SYSLOG;
            break;

        case 515:
            uiAppID = APP_ID_PRINTER;

        case 520:
            uiAppID = APP_ID_RIP;
            break;

        case 523:
            uiAppID = APP_ID_IBM_DB2;
            break;

        case 525:
            uiAppID = APP_ID_TIMED;
            break;

        case 529:
            uiAppID = APP_ID_IRC_SERV;
            break;

        case 543:
            uiAppID = APP_ID_KLOGIN;
            break;

        case 544:
            uiAppID = APP_ID_KSHELL;
            break;

        case 546:
            uiAppID = APP_ID_DHCP6_CLIENT;
            break;

        case 547:
            uiAppID = APP_ID_DHCP6_SERVER;
            break;

        case 554:
            uiAppID = APP_ID_RTSP;
            break;

        case 563:
            uiAppID = APP_ID_NNTPS;
            break;

        case 604:
            uiAppID = APP_ID_TUNNEL;
            break;

        case 636:
            uiAppID = APP_ID_LDAPS;
            break;

        case 666:
            uiAppID = APP_ID_DOOM;
            break;

        case 683:
            uiAppID = APP_ID_CORBA_IIOP;
            break;

        case 684:
            uiAppID = APP_ID_CORBA_IIOP_SSL;
            break;

        case 689:
            uiAppID = APP_ID_NMAP;
            break;

        case 749:
            uiAppID = APP_ID_KERBEROS_ADMIN;
            break;

        case 750:
            uiAppID = APP_ID_KERBEROS_IV;
            break;

        case 873:
            uiAppID = APP_ID_RSYNC;
            break;

        case 989:
            uiAppID = APP_ID_FTPS_DATA;
            break;

        case 990:
            uiAppID = APP_ID_FTPS;
            break;

        case 992:
            uiAppID = APP_ID_TELNETS;
            break;

        case 993:
            uiAppID = APP_ID_IMAPS;
            break;

        case 994:
            uiAppID = APP_ID_IRCS;
            break;

        case 995:
            uiAppID = APP_ID_POP3S;
            break;

        case 1050:
            uiAppID = APP_ID_CORBA_MAN_AGENT;
            break;

        case 1080:
            uiAppID = APP_ID_SOCKS;
            break;

        case 1214:
            uiAppID = APP_ID_KAZAA;
            break;

        case 1300:
            uiAppID = APP_ID_H323_HOSTCALLSC;
            break;

        case 1352:
            uiAppID = APP_ID_NOTES;
            break;

        case 1433:
            uiAppID = APP_ID_MS_SQL_S;
            break;

        case 1434:
            uiAppID = APP_ID_MS_SQL_M;
            break;

        case 1494:
            uiAppID = APP_ID_CITRIX_ICA;
            break;

        case 1503:
            uiAppID = APP_ID_NETMEETING;
            break;

        case 1521:
            uiAppID = APP_ID_SQLNET;
            break;

        case 1525:
            uiAppID = APP_ID_ORASRV;
            break;

        case 1604:
            uiAppID = APP_ID_CITRIX_ICA_BRO;
            break;

        case 1698:
            uiAppID = APP_ID_RSVP_ENCAP_1;
            break;

        case 1699:
            uiAppID = APP_ID_RSVP_ENCAP_2;
            break;

        case 1701:
            uiAppID = APP_ID_L2TP;
            break;

        case 1718:
            uiAppID = APP_ID_H323_GATEDISC;
            break;

        case 1719:
            uiAppID = APP_ID_RAS;
            break;

        case 1720:
            uiAppID = APP_ID_H225;
            break;

        case 1723:
            uiAppID = APP_ID_PPTP;
            break;

        case 1731:
            uiAppID = APP_ID_NETMEETING;
            break;

        case 1755:
            uiAppID = APP_ID_MMS;
            break;

        case 1812:
            uiAppID = APP_ID_RADIUS;
            break;

        case 1813:
            uiAppID = APP_ID_RADIUS_ACCT;
            break;

        case 1863:
            uiAppID = APP_ID_MSN_MSGER;
            break;

        case 1900:
            uiAppID = APP_ID_SSDP;
            break;

        case 2000:
            uiAppID = APP_ID_SCCP;
            break;

        case 2049:
            uiAppID = APP_ID_NFS;
            break;

        case 2123:
            uiAppID = APP_ID_GTPC;
            break;

        case 2152:
            uiAppID = APP_ID_GTPU;
            break;

        case 2421:
            uiAppID = APP_ID_G_TALK;
            break;

        case 2427:
            uiAppID = APP_ID_MGCPG;
            break;

        case 2428:
            uiAppID = APP_ID_OTT;
            break;

        case 2512:
            uiAppID = APP_ID_CITRIX_IMA;
            break;

        case 2575:
            uiAppID = APP_ID_HL7;
            break;

        case 2598:
            uiAppID = APP_ID_CITRIX_MA_CLIENT;
            break;

        case 2727:
            uiAppID = APP_ID_MGCPC;
            break;

        case 2761:
            uiAppID = APP_ID_DICOM_ISCL;
            break;

        case 2762:
            uiAppID = APP_ID_DICOM_TLS;
            break;

        case 2809:
            uiAppID = APP_ID_CORBA_LOC;
            break;

        case 2979:
            uiAppID = APP_ID_H263_VIDEO;
            break;

        case 3386:
            uiAppID = APP_ID_GPRSDATA;
            break;

        case 3460:
            uiAppID = APP_ID_EDM_MANAGER;
            break;

        case 3461:
            uiAppID = APP_ID_EDM_STAGER;
            break;

        case 3462:
            uiAppID = APP_ID_EDM_STD_NOTIFY;
            break;

        case 3463:
            uiAppID = APP_ID_EDM_ADM_NOTIFY;
            break;

        case 3464:
            uiAppID = APP_ID_EDM_MGR_SYNC;
            break;

        case 3465:
            uiAppID = APP_ID_EDM_MGR_CNTRL;
            break;

        case 3478:
            uiAppID = APP_ID_STUN;
            break;

        case 3690:
            uiAppID = APP_ID_SVN;
            break;

        case 3799:
            uiAppID = APP_ID_RADIUS_DYNAUTH;
            break;

        case 5050:
            uiAppID = APP_ID_MMCC;
            break;

        case 5060:
            uiAppID = APP_ID_SIP;
            break;

        case 5190:
        case 5191:
        case 5192:
        case 5193:
            uiAppID = APP_ID_AOL;
            break;

        case 5298:
            uiAppID = APP_ID_XMPP_LINKLOCAL;
            break;

        case 5349:
            uiAppID = APP_ID_STUNS;
            break;

        case 5352:
            uiAppID = APP_ID_DNS_LLQ;
            break;

        case 5353:
            uiAppID = APP_ID_MDNS;
            break;

        case 5354:
            uiAppID = APP_ID_MDNS_RESPONDER;
            break;

        case 5631:
            uiAppID = APP_ID_PCANYWHERE_DATA;
            break;

        case 5632:
            uiAppID = APP_ID_PCANYWHERE_STAT;
            break;

        case 5900:
            uiAppID = APP_ID_RFB;
            break;

        case 6346:
            uiAppID = APP_ID_GNUTELLA_SVC;
            break;

        case 6347:
            uiAppID = APP_ID_GNUTELLA_RTR;
            break;

        case 6620:
            uiAppID = APP_ID_KFTP_DATA;
            break;

        case 6621:
            uiAppID = APP_ID_KFTP;
            break;

        case 6623:
            uiAppID = APP_ID_KTELENT;
            break;

        case 7004:
            uiAppID = APP_ID_AFS3_KASERVER;
            break;

        case 7648:
            uiAppID = APP_ID_CUSEEME;
            break;

        case 8000:
            uiAppID = APP_ID_OICQ;
            break;

        case 9088:
            uiAppID = APP_ID_SQLEXEC;
            break;

        case 9089:
            uiAppID = APP_ID_SQLEXEC_SSL;
            break;

        case 11112:
            uiAppID = APP_ID_DICOM;
            break;

        case 11720:
            uiAppID = APP_ID_H323_CALLSIGALT;
            break;

        default:
            break;
    }

    return uiAppID;
}

UINT APR_GetAppByPort(USHORT usDstPort, UCHAR ucL4Pro)
{
    UINT uiAppID = APR_ID_INVALID;
	
    if (ucL4Pro == IPPROTO_TCP)
    {
        uiAppID = GetAppIDForTCP(usDstPort);
    }
    else if (ucL4Pro == IPPROTO_UDP)
    {
        uiAppID = GetAppIDForUDP(usDstPort);
    }
    else if (ucL4Pro == IPPROTO_SCTP)
    {
        uiAppID = GetAppIDForSCTP(usDstPort);
    }

    return uiAppID;
}

