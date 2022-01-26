#ifndef __DPVS_L2_DEBUG_H__
#define __DPVS_L2_DEBUG_H__
#include "conf/common.h"
#include "ipvs/kcompat.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "debug_flow.h"
#include "br_private.h"

inline int print_mbuf_head(struct rte_mbuf *mbuf, char *bufall);

void l2_debug_mbuf_trace(int node, int detail, struct rte_mbuf *mbuf, const char *fmt, ...);
#define DETAIL_ON 1
#define DETAIL_OFF 0

#define L2_DEBUG_BRIDGE   1
#define L2_DEBUG_L3_TEMP  2
#define L2_DEBUG_L2_XMIT  3
#define L2_DEBUG_ETH_INPUT  4

#define L2_DEBUG_BASIC  0x0001
#define L2_DEBUG_EVENT  0x0002
#define L2_DEBUG_PACKET 0x0004
#define L2_DEBUG_DETAIL 0x0008
#define L2_DEBUG_ALL (L2_DEBUG_BASIC | L2_DEBUG_EVENT | L2_DEBUG_PACKET)
#define L2_OLG_BUFFER_LEN 1024


extern uint32_t brctl_debug_flag;
extern uint32_t l2_xmit_debug_flag;
extern uint32_t l3_temp_debug_flag;
extern uint32_t eth_input_debug_flag;

#define debug_l2_packet_trace(node, mbuf, detail, fmt, arg...) \
    do { \
		switch(node){ \
			case L2_DEBUG_BRIDGE: \
			{ \
				if (brctl_debug_flag & L2_DEBUG_PACKET) \
            		l2_debug_mbuf_trace(node,detail, mbuf, fmt, ##arg); \
            	break; \
			} \
			case L2_DEBUG_L2_XMIT: \
			{ \
				if (l2_xmit_debug_flag & L2_DEBUG_PACKET) \
            		l2_debug_mbuf_trace(node, detail, mbuf, fmt, ##arg); \
            	break; \
			} \
			case L2_DEBUG_L3_TEMP: \
			{ \
				if (l3_temp_debug_flag & L2_DEBUG_PACKET) \
            		l2_debug_mbuf_trace(node, detail, mbuf, fmt, ##arg); \
            	break; \
			} \
			case L2_DEBUG_ETH_INPUT:\
			{\
				if(eth_input_debug_flag & L2_DEBUG_PACKET) \
					l2_debug_mbuf_trace(node, detail, mbuf, fmt, ##arg); \
				break;\
			}\
			default:\
			{\
				l2_debug_mbuf_trace(node, detail, mbuf, fmt, ##arg); \
			}\
		}\
    }while(0)

/**********************************************brctl debug相关*********************************************/


inline void __print_fdb_detail(struct net_bridge_fdb_entry *fdb_entry);
inline void print_fdb_detail(struct net_bridge_fdb_entry *fdb_entry);
int debug_brctl_cli(cmd_blk_t *cbt);

enum brctl_debug_event{
	BRCTL_EVENT_FDB_CREATE,
	BRCTL_EVENT_FDB_DELETE,
	BRCTL_EVENT_FDB_CLEANUP_SRART,
	BRCTL_EVENT_FDB_CLEANUP_END,
	BRCTL_EVENT_BRIDGE_IF_DEL_SYNC_WAIT,
	BRCTL_EVENT_BRIDGE_IF_DEL_SYNC_DONE,
	BRCTL_EVENT_BRIDGE_IF_DEL,
	BRCTL_EVENT_FDB_INVAILD
};

void brctl_debug_event_detail(enum brctl_debug_event event, void *param, const char *fmt, ...);


#define debug_brctl_event(event, param, fmt, arg...)    	\
	do{ 													\
		if(brctl_debug_flag & L2_DEBUG_EVENT) 			\
			brctl_debug_event_detail(event, param, fmt, ##arg);   \
	}while(0)

/********************************************************l2 xmit 相关********************************************************/
int debug_l2_xmit_cli(cmd_blk_t *cbt);
void l2xmit_debug_cli_init(void);

/********************************************************l3 temp 相关********************************************************/
int debug_l3_temp_cli(cmd_blk_t *cbt);

int
L2_debug_init(void);


#endif /* __DPVS_BR_H__ */


