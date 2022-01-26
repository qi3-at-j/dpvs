

#ifndef _SESSION_KALG_FTP_H_
#define _SESSION_KALG_FTP_H_

#define ALG_FTP_ASCII_ZERO 0x30     /* 0x30ÊÇ×Ö·û0 */

typedef enum entagALG_FTP_PATTERN
{
	ALG_FTP_USER_CMD = 0,
	ALG_FTP_PASS_CMD,
	ALG_FTP_PORT_CMD,
    ALG_FTP_EPRT_CMD,
	ALG_FTP_PASV_CMD,
	ALG_FTP_EPSV_CMD,
	ALG_FTP_TYPE_CMD,
    ALG_FTP_MODE_CMD,
	ALG_FTP_STRU_CMD,
	ALG_FTP_ACCT_CMD,
	ALG_FTP_ABOR_CMD,
    ALG_FTP_SYST_CMD,
	ALG_FTP_HELP_CMD,
	ALG_FTP_NOOP_CMD,
	ALG_FTP_QUIT_CMD,
    ALG_FTP_AUTH_CMD,
	ALG_FTP_ADAT_CMD,
	ALG_FTP_FEAT_CMD,
	ALG_FTP_SEVERREADY_CODE,
    ALG_FTP_USER_LOGGED_CODE,
	ALG_FTP_PASS_LOGGED_CODE,
	ALG_FTP_PORT_GOOD_CODE,
	ALG_FTP_PASV_GOOD_CODE,
    ALG_FTP_EPSV_GOOD_CODE,
	ALG_FTP_FEAT_END_CODE,	
	ALG_FTP_ERROR_RESP_TOK,
	ALG_FTP_FAIL_RESP_TOK,
	ALG_FTP_IGR_RESP,
}ALG_FTP_PATTERN_E;

typedef enum enSESSION_Alg_FTP_Status
{
	FTP_INIT = 0,
	FTP_READY,
	FTP_WAIT_USER_ACK,
	FTP_USER_LOGGED,
	FTP_WAIT_PASSWD_ACK,
	FTP_CONXN_UP,
	FTP_FEAT_REQUEST,
}SESSION_ALG_FTP_STATUS_E;

typedef enum enSESSION_ALG_FTP_TYPE
{
	SESSION_FTP_PORT,    /* PORT command from client */
	SESSION_FTP_PASV,    /* PORT response from server */
	SESSION_FTP_EPRT,    /* EPRT command from client */
	SESSION_FTP_EPSV,    /* EPSV response from server */
	SESSION_FTP_MAX
}SESSION_ALG_FTP_TYPE_E;

typedef struct tagALG_FTP_PATTERNS
{
	UCHAR *pucData;
	UINT uiDataLen;
	UINT uiPid;
}ALG_FTP_PATTERNS_S;

typedef struct tagFTPPayloadInfo
{
	SESSION_S *pstSession;
	MBUF_S        *pstMBuf;
	UINT          uiL3OffSet;
	UINT          uiL4OffSet;
	UINT          uiNumOff;
	UINT          uiNumLen;
	SESSION_ALG_FTP_TYPE_E enFtpType;
}SESSION_FTP_PAYLOAD_MBUF_S;

typedef struct tagAlgFtpExt
{
	rte_spinlock_t stLock;
#if 0
#if defined(_LITTLE_ENDIAN_BITFILELD)
    UCHAR ucOriginalSeg:1;
    UCHAR ucReplySeg:1;
	UCHAR ucOther:6;
#elif defined(_BIG_ENDIAN_BITFILELD)
    UCHAR ucOther:6;
    UCHAR ucReplySeg:1;
	UCHAR ucOriginalSeg:1;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
#endif
    UCHAR ucOriginalSeg:1;
    UCHAR ucReplySeg:1;
	UCHAR ucOther:6;
    SESSION_ALG_FTP_STATUS_E enStatus;
}ALG_FTP_EXT_S;

/* The manipulable part of the tuple. */
typedef struct tagSessionFtpAlgPayLoad
{
	SESSION_INET_ADDR_U unIp;
	SESSION_PROTO_SRC_U unPort;
	UCHAR               ucFamily;    /* Layer 3 protocol */
}SESSION_FTPALG_PAYLOAD_S;


extern ULONG SESSION_KFtpInit(VOID);
extern VOID *SESSION_ALG_FtpExtCreate(IN SESSION_HANDLE hSession, IN ULONG ulPara);


#endif
