


#ifndef _SYS_AC_H_
#define _SYS_AC_H_



typedef ULONG AC_HANDLE;

#define AC_HANDLE_INVALID   0  /* ��Ч��AC��, ������ac��anchorac */
#define AC_MAX_PATT_LEN     768  /*equal to AC_CASE_BITMAP_UNIT * AC_CASE_BITMAP_SIZE */
#define AC_MAX_OFFSET       65536 
#define AC_MAX_DEPTH        65536  /* ����ac���ƥ��1M���� */

#define AC_CASE_BITMAP_UNIT 8 
#define AC_BITMAP_SIZE      96 
#define AC_MAX_STATUS_65535 65535
#define AC_MAX_STATUS_32767 32767
#define AC_MAX_STATUS_127   127

#define AC_KHANDLE_INVALID 0 
#define AC_MAX_PATTERN_LEN 64
#define AC_GETID_NOFLAG(uiStateID)   ((uiStateID) & 0x7FFFFF)
#define AC_SET_HASPIDFLAG(uiStateID) ((uiStateID)|0x800000)
#define AC_IS_PIDFLAG_SET(uiStateID) (0 != ((uiStateID) & 0x800000)) 

/* ת����Сд */ 
#define AC_ASCII_NUM 256

typedef enum tagAC_TYPE
{
	AC_ANCHOR = 0, /* ê��ƥ��, ��ǰ׺ƥ�� */ 
	AC_FULL,       /* ȫ�ַ�ƥ��, ����ê��ƥ�������λ�õ��Ӵ�ƥ�� */
} AC_TYPE_E; 


typedef enum tagAC_CASE
{
    AC_CASE_SENSITIVE = 0,
    AC_CASE_INSENSITIVE,
    AC_CASE_MAX,
} AC_CASE_E;


typedef struct tagAC_KANCHOR_TRIE
{
	UINT (*puiStateArray)[256]; /* alloc sizeof(UINT) * 256 * StateNum */
	UINT *puiPidArray;          /* alloc sizeof(UINT) * StateNum */

	UINT uiStateNum;            /* Temporary using */
	UINT uiPidSum;              /* Temporary using */
	UINT uiPattLenSum;          /* ��Trie���ں���������ʱ, ��Ч, ��¼���е�pattern length �ܺ� */
	DTQ_HEAD_S stPattHead;
} AC_KANCHOR_TRIE_S;

typedef struct tagAC_KANCHOR_PATTERN
{
	DTQ_NODE_S stNode;
	UCHAR aucPattern[AC_MAX_PATTERN_LEN];
	UINT uiPatternLen; 
	UINT uiPid;
} AC_KANCHOR_PATTERN_S;


#endif

