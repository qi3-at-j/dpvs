#ifndef _APR_H_
#define _APR_H_


#define APR_NAME_INVALID        "invalid"
#define APR_NAME_OTHER          "other"
#define APR_NAME_GENERAL_TCP    "general_tcp"
#define APR_NAME_GENERAL_UDP    "general_udp"
#define APR_NAME_ICMP           "ICMP"

#define APR_ID_INVALID         0          /* not identify */
#define APR_ID_OTHER           (-1)       /* identify failed */
#define APR_ID_GENERAL_TCP     2086
#define APR_ID_GENERAL_UDP     2087
#define APR_ID_ICMP            22742

#define APR_ID_GENERAL_TCPOTHER      12288
#define APR_ID_GENERAL_UDPOTHER      12289
/***************************这几个宏涉及公共命令元素，禁止修改********************/
#define APR_NAME_MAX_LEN             63UL  /* 应用识别名称的最大长度 */
#define APR_PROTO_NAME_MAX_LEN       31UL  /* 协议名称的最大长度 */
#define APR_DESCRIPTION_MAX_LEN      127UL /* 描述信息最大长度 */
#define APR_BASEPROTOCOLINFO_MAX_LEN 127UL /* 应用依赖的基础协议最大长度 */

#define APR_RISK_DESCRIPTION_MAX_LEN 255UL /* 风险描述信息最大长度 */

/**********************************************************************************/

#define APR_MAX_SUB_APPGROUP    1024   /* 子组的最大个数 */
#define APR_MAX_SUB_APP         1023   /* 子应用的最大个数 */

#define APR_APPPROFILE_LEN      100UL  /* same as to APPPROFILE_MAX_NAME_LEN */

#define APR_APP_ID_USER_DEF_MASK 0x800000
/*定义最大检测长度*/
#define APR_DETECT_LEN_MAX (UINT)0XFFFFFFFF
/* APP ID DEFINE */
#define APP_ID_SYSTEM_MIN   0UL
#define APP_ID_USER_MIN     0x800000
#define APP_ID_NUM_SYSTEM   65536
#define APP_ID_NUM_MAX      1000

#define APP_ID_ECHO               2
#define APP_ID_SYSTEM_STATS       4
#define APP_ID_DAYTIME            5
#define APP_ID_CHARGEN            9
#define APP_ID_FTPDATA            10
#define APP_ID_FTP                11
#define APP_ID_SSH                13
#define APP_ID_TELNET             14
#define APP_ID_SMTP               15
#define APP_ID_TIME               16
#define APP_ID_TACACS             20
#define APP_ID_TACACSDS           24
#define APP_ID_BOOTPS             25
#define APP_ID_BOOTPC             26
#define APP_ID_TFTP               27
#define APP_ID_GOPHER             28
#define APP_ID_FINGER             30
#define APP_ID_HTTP               31
#define APP_ID_KERBEROS           33
#define APP_ID_RTELENT            39
#define APP_ID_POP3               41
#define APP_ID_SUNRPC             42
#define APP_ID_NNTP               46
#define APP_ID_NTP                47
#define APP_ID_NETBIOSNS          50
#define APP_ID_NETBIOSDGM         51
#define APP_ID_NETBIOSSSN         52
#define APP_ID_SNMP               54
#define APP_ID_XDMCP              59
#define APP_ID_BGP                61
#define APP_ID_IRC                63
#define APP_ID_IPX                71
#define APP_ID_IMAP3              72
#define APP_ID_CLEARCASE          78
#define APP_ID_LDAP               80
#define APP_ID_HTTPS              83
#define APP_ID_SMB                85
#define APP_ID_ISAKMP             88
#define APP_ID_RTSP               89
#define APP_ID_LOGIN              99
#define APP_ID_WHO                100
#define APP_ID_SYSLOG             102
#define APP_ID_PRINTER            103
#define APP_ID_TIMED              107
#define APP_ID_KLOGIN             115
#define APP_ID_KSHELL             116
#define APP_ID_DHCP6_CLIENT       117
#define APP_ID_DHCP6_SERVER       118
#define APP_ID_NNTPS              122
#define APP_ID_LDAPS              124
#define APP_ID_KERBEROS_ADMIN     127
#define APP_ID_RSYNC              129
#define APP_ID_FTPS_DATA          130
#define APP_ID_FTPS               131
#define APP_ID_TELNETS            132
#define APP_ID_IMAPS              133
#define APP_ID_IRCS               134
#define APP_ID_POP3S              135
#define APP_ID_SOCKS              136
#define APP_ID_KAZAA              141
#define APP_ID_MS_SQL_S           144
#define APP_ID_MS_SQL_M           145
#define APP_ID_RADIUS             153
#define APP_ID_RADIUS_ACCT        154
#define APP_ID_NFS                162
#define APP_ID_SVN                184
#define APP_ID_MMCC               195
#define APP_ID_SIP                196
#define APP_ID_AOL                198
#define APP_ID_MDNS               202
#define APP_ID_GNUTELLA_SVC       215
#define APP_ID_GNUTELLA_RTR       216
#define APP_ID_AFS3_KASERVER      224
#define APP_ID_RTMP               250
#define APP_ID_H245               557
#define APP_ID_RTCP               558
#define APP_ID_RTP                559
#define APP_ID_DNS                574
#define APP_ID_GPRSDATA           583
#define APP_ID_GPRSSIG            584
#define APP_ID_GTPC               586
#define APP_ID_GTPU               587
#define APP_ID_H225               588
#define APP_ID_ILS                597
#define APP_ID_IMAP               598
#define APP_ID_L2TP               605
#define APP_ID_MGCPC              607
#define APP_ID_MGCPG              608
#define APP_ID_PPTP               620
#define APP_ID_QQ                 622
#define APP_ID_RAS                624
#define APP_ID_RIP                627
#define APP_ID_RSH                628
#define APP_ID_SCCP               632
#define APP_ID_SNMPTRAP           633
#define APP_ID_SQLNET             636
#define APP_ID_STUN               637
#define APP_ID_XWINDOWS           913
#define APP_ID_TFTPDATA           1093
#define APP_ID_APPLEQTC           1300
#define APP_ID_CITRIX_ADMIN       1302
#define APP_ID_CITRIX_IMA         1303
#define APP_ID_CITRIX_MA_CLIENT   1304
#define APP_ID_CORBA_MAN_AGENT    1305
#define APP_ID_CORBA_IIOP         1306
#define APP_ID_CORBA_IIOP_SSL     1307
#define APP_ID_CORBA_LOC          1308
#define APP_ID_CUSEEME            1309
#define APP_ID_DBASE              1310
#define APP_ID_DICOM              1311
#define APP_ID_DICOM_ISCL         1312
#define APP_ID_DICOM_TLS          1313
#define APP_ID_DNS_LLQ            1314
#define APP_ID_DOOM               1315
#define APP_ID_EDM_ADM_NOTIFY     1316
#define APP_ID_EDM_MANAGER        1317
#define APP_ID_EDM_MGR_CNTRL      1318
#define APP_ID_EDM_MGR_SYNC       1319
#define APP_ID_EDM_STAGER         1320
#define APP_ID_EDM_STD_NOTIFY     1321
#define APP_ID_G_TALK             1323
#define APP_ID_H263_VIDEO         1324
#define APP_ID_H323_CALLSIGALT    1325
#define APP_ID_H323_GATEDISC      1326
#define APP_ID_H323_HOSTCALLSC    1327
#define APP_ID_HL7                1328
#define APP_ID_IBM_DB2            1329
#define APP_ID_CITRIX_ICA         1330
#define APP_ID_CITRIX_ICA_BRO     1331
#define APP_ID_IRC_SERV           1332
#define APP_ID_ISIGL              1333
#define APP_ID_KERBEROS_IV        1334
#define APP_ID_KFTP               1335
#define APP_ID_KFTP_DATA          1336
#define APP_ID_KTELENT            1337
#define APP_ID_MDNS_RESPONDER     1339
#define APP_ID_MSN_MSGER          1340
#define APP_ID_MSRPC              1341
#define APP_ID_NEWS               1342
#define APP_ID_NICNAME            1343
#define APP_ID_NMAP               1344
#define APP_ID_NOTES              1345
#define APP_ID_NPP                1346
#define APP_ID_ORASRV             1347
#define APP_ID_OTT                1348
#define APP_ID_PCANYWHERE_DATA    1349
#define APP_ID_PCANYWHERE_STAT    1350
#define APP_ID_XMPP_LINKLOCAL     1351
#define APP_ID_RADIUS_DYNAUTH     1353
#define APP_ID_RCP                1354
#define APP_ID_RFB                1355
#define APP_ID_RSVP_ENCAP_1       1357
#define APP_ID_RSVP_ENCAP_2       1358
#define APP_ID_RSVP_TUNNEL        1359
#define APP_ID_SQLEXEC            1362
#define APP_ID_SQLEXEC_SSL        1363
#define APP_ID_STUNS              1365
#define APP_ID_TUNNEL             1366
#define APP_ID_WHOISPP            1367
#define APP_ID_RDP                2973
#define APP_ID_SSDP               2974
#define APP_ID_OICQ               2975
#define APP_ID_NETMEETING         6565
#define APP_ID_T3                 6830
#define APP_ID_MMS                11553
#define APP_ID_SMTPS              12401

typedef enum tagAprDefineType {
    APR_DEFINE_TYPE_SYSTEM,
    APR_DEFINE_TYPE_USER,
    APR_DEFINE_TYPE_MAX
} APR_DEFINE_TYPE_E;

enum AprTrustEnum {
    APR_TRUST_INIT = 0,
    APR_TRUST_PORT,
    APR_TRUST_SIG_BASE,
    APR_TRUST_SIG_FINAL,
};

UINT APR_GetAppByPort(USHORT usDstPort, UCHAR ucL4Pro);

#endif
