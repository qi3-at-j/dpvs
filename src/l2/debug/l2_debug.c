/*
	bridge module init
 */
#include <assert.h>
#include "netif_addr.h"
#include "sys_time.h"
#include "../include/br_private.h"
#include "../include/l2_debug.h"
#include "../include/mac_filter.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"

uint32_t brctl_debug_flag;
uint32_t l2_xmit_debug_flag;
uint32_t l3_temp_debug_flag;
uint32_t eth_input_debug_flag;
uint32_t debug_l2_flag;

enum l2_debug_pos{
	L2_POS = 0,
	L2_SUB_POS = 1,
};

enum l2_debug_val{
	L2_BASIC   =  1,
	L2_EVENT  =  2,
	L2_PACKET =  3,
	L2_ALL    =  4,
};

enum brctl_val{
	BRCTL_BASIC  =  1,
	BRCTL_EVENT  =  2,
	BRCTL_PACKET =  3,
	BRCTL_ALL    =  4,
};

enum l2xmit_val{
	L2XMT_BASIC  =  1,
	L2XMT_EVENT  =  2,
	L2XMT_PACKET =  3,
	L2XMT_ALL    =  4,
};

enum l3temp_val{
	L3TEMP_BASIC  =  1,
	L3TEMP_EVENT  =  2,
	L3TEMP_PACKET =  3,
	L3TEMP_ALL    =  4,
};

enum ethin_val{
	ETHIN_BASIC  =  1,
	ETHIN_EVENT  =  2,
	ETHIN_PACKET =  3,
	ETHIN_ALL    =  4,
};


int 
debug_l2_cli(cmd_blk_t *cbt){	
	if (!cbt) {
		RTE_LOG(ERR, FLOW, "%s: the cbt is NULL!\n", __func__);
		return -1;
	}

	 switch (cbt->which[L2_POS]) {
        case L2_BASIC:
            if (cbt->mode & MODE_DO) {
                printf("l2 basic debug is enabled\n");
                brctl_debug_flag |= L2_DEBUG_BASIC;
			 	l2_xmit_debug_flag |= L2_DEBUG_BASIC;
			 	l3_temp_debug_flag |= L2_DEBUG_BASIC;
				eth_input_debug_flag |= L2_DEBUG_BASIC;
                debug_l2_flag |= L2_DEBUG_BASIC;
            } else if (cbt->mode & MODE_UNDO) {
                printf("l2 basic debug is disabled\n");
                brctl_debug_flag &= ~L2_DEBUG_BASIC; 
				l2_xmit_debug_flag &= ~L2_DEBUG_BASIC;
			    l3_temp_debug_flag &= ~L2_DEBUG_BASIC;
				eth_input_debug_flag &= ~L2_DEBUG_BASIC;
                debug_l2_flag &= ~L2_DEBUG_BASIC;
            }
            break;
        case L2_EVENT:
            if (cbt->mode & MODE_DO) {
                printf("l2 event debug is enabled\n");
                brctl_debug_flag |= L2_DEBUG_EVENT;
				l2_xmit_debug_flag |= L2_DEBUG_EVENT;
				l3_temp_debug_flag |= L2_DEBUG_EVENT;
				eth_input_debug_flag |= L2_DEBUG_EVENT;
                debug_l2_flag |= L2_DEBUG_EVENT;

            } else if (cbt->mode & MODE_UNDO) {
                printf("l2 event debug is disabled\n");
                brctl_debug_flag &= ~L2_DEBUG_EVENT;
				l2_xmit_debug_flag &= ~L2_DEBUG_EVENT;
				l3_temp_debug_flag &= ~L2_DEBUG_EVENT;
				eth_input_debug_flag &= ~L2_DEBUG_EVENT;
                debug_l2_flag &= ~L2_DEBUG_EVENT;
            }
            break;
        case L2_PACKET:
            if (cbt->mode & MODE_DO) {
                printf("l2 packet debug is enabled\n");
                brctl_debug_flag |= L2_DEBUG_PACKET; 
				l2_xmit_debug_flag |= L2_DEBUG_PACKET;
			 	l3_temp_debug_flag |= L2_DEBUG_PACKET;
				eth_input_debug_flag |= L2_DEBUG_PACKET;
                debug_l2_flag |= L2_DEBUG_PACKET;
                
            } else if (cbt->mode & MODE_UNDO) {
                printf("l2 packet debug is disabled\n");
                brctl_debug_flag &= ~L2_DEBUG_PACKET;
				l2_xmit_debug_flag &= ~L2_DEBUG_PACKET;
				l3_temp_debug_flag &= ~L2_DEBUG_PACKET;
				eth_input_debug_flag &= ~L2_DEBUG_PACKET;
                debug_l2_flag |= ~L2_DEBUG_PACKET;
            }
            break;
        case L2_ALL:
            if (cbt->mode & MODE_DO) {
                printf("l2 all debug is enabled\n");
                brctl_debug_flag |= L2_DEBUG_ALL; 
				l2_xmit_debug_flag |= L2_DEBUG_ALL;
			 	l3_temp_debug_flag |= L2_DEBUG_ALL;
				eth_input_debug_flag |= L2_DEBUG_ALL;
                debug_l2_flag |= L2_DEBUG_ALL;
                
            } else if (cbt->mode & MODE_UNDO) {
                printf("l2 all debug is disabled\n");
                brctl_debug_flag &= ~L2_DEBUG_ALL;
				l2_xmit_debug_flag &= ~L2_DEBUG_ALL;
				l3_temp_debug_flag &= ~L2_DEBUG_ALL;
				eth_input_debug_flag &= ~L2_DEBUG_ALL;
                debug_l2_flag &= ~L2_DEBUG_ALL;
            }
            break;
        default:
            break;
    }
    return 0;
}

int
debug_brctl_cli(cmd_blk_t *cbt)
{
    if (!cbt) {
        RTE_LOG(ERR, FLOW, "%s: the cbt is NULL!\n", __func__);
        return -1;
    }

    switch (cbt->which[L2_SUB_POS]) {
        case BRCTL_BASIC:
            if (cbt->mode & MODE_DO) {
                if (!(brctl_debug_flag & L2_DEBUG_BASIC)) {
                    printf("brctl basic debug is enabled\n");
                    brctl_debug_flag |= L2_DEBUG_BASIC;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (brctl_debug_flag & L2_DEBUG_BASIC) {
                    printf("brctl basic debug is disabled\n");
                    brctl_debug_flag &= ~L2_DEBUG_BASIC;
                }
            }
            break;
        case BRCTL_EVENT:
            if (cbt->mode & MODE_DO) {
                if (!(brctl_debug_flag & L2_DEBUG_EVENT)) {
                    printf("brctl event debug is enabled\n");
                    brctl_debug_flag |= L2_DEBUG_EVENT;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (brctl_debug_flag & L2_DEBUG_EVENT) {
                    printf("brctl event debug is disabled\n");
                    brctl_debug_flag &= ~L2_DEBUG_EVENT;
                }
            }
            break;
        case BRCTL_PACKET:
            if (cbt->mode & MODE_DO) {
                if (!(brctl_debug_flag & L2_DEBUG_PACKET)) {
                    printf("brctl packet debug is enabled\n");
                    brctl_debug_flag |= L2_DEBUG_PACKET;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (brctl_debug_flag & L2_DEBUG_PACKET) {
                    printf("brctl packet debug is disabled\n");
                    brctl_debug_flag &= ~L2_DEBUG_PACKET;
                }
            }
            break;
        case BRCTL_ALL:
            if (cbt->mode & MODE_DO) {
                if ((brctl_debug_flag & L2_DEBUG_ALL) != L2_DEBUG_ALL) {
                    printf("brctl all debug is enabled\n");
                    brctl_debug_flag |= L2_DEBUG_ALL;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (brctl_debug_flag & L2_DEBUG_ALL) {
                    printf("brctl all debug is disabled\n");
                    brctl_debug_flag &= ~L2_DEBUG_ALL;
                }
            }
            break;
        default:
            break;
    }
    return 0;
}

int
debug_l2_xmit_cli(cmd_blk_t *cbt)
{
    if (!cbt) {
        RTE_LOG(ERR, FLOW, "%s: the cbt is NULL!\n", __func__);
        return -1;
    }

    switch (cbt->which[L2_SUB_POS]) {
        case L2XMT_BASIC:
            if (cbt->mode & MODE_DO) {
                if (!(l2_xmit_debug_flag & L2_DEBUG_BASIC)) {
                    printf("l2 xmit basic debug is enabled\n");
                    l2_xmit_debug_flag |= L2_DEBUG_BASIC;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (l2_xmit_debug_flag & L2_DEBUG_BASIC) {
                    printf("l2 xmit basic debug is disabled\n");
                    l2_xmit_debug_flag &= ~L2_DEBUG_BASIC;
                }
            }
            break;
        case L2XMT_EVENT:
            if (cbt->mode & MODE_DO) {
                if (!(l2_xmit_debug_flag & L2_DEBUG_EVENT)) {
                    printf("l2 xmit event debug is enabled\n");
                    l2_xmit_debug_flag |= L2_DEBUG_EVENT;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (l2_xmit_debug_flag & L2_DEBUG_EVENT) {
                    printf("l2 xmit event debug is disabled\n");
                    l2_xmit_debug_flag &= ~L2_DEBUG_EVENT;
                }
            }
            break;
        case L2XMT_PACKET:
            if (cbt->mode & MODE_DO) {
                if (!(l2_xmit_debug_flag & L2_DEBUG_PACKET)) {
                    printf("l2 xmit packet debug is enabled\n");
                    l2_xmit_debug_flag |= L2_DEBUG_PACKET;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (l2_xmit_debug_flag & L2_DEBUG_PACKET) {
                    printf("l2 xmit packet debug is disabled\n");
                    l2_xmit_debug_flag &= ~L2_DEBUG_PACKET;
                }
            }
            break;
        case L2XMT_ALL:
            if (cbt->mode & MODE_DO) {
                if ((l2_xmit_debug_flag & L2_DEBUG_ALL) != L2_DEBUG_ALL) {
                    printf("l2 xmit all debug is enabled\n");
                    l2_xmit_debug_flag |= L2_DEBUG_ALL;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (l2_xmit_debug_flag & L2_DEBUG_ALL) {
                    printf("l2 xmit all debug is disabled\n");
                    l2_xmit_debug_flag &= ~L2_DEBUG_ALL;
                }
            }
            break;
        default:
            break;
    }
    return 0;
}

int
debug_l3_temp_cli(cmd_blk_t *cbt)
{
    if (!cbt) {
        RTE_LOG(ERR, FLOW, "%s: the cbt is NULL!\n", __func__);
        return -1;
    }

    switch (cbt->which[L2_SUB_POS]) {
        case L3TEMP_BASIC:
            if (cbt->mode & MODE_DO) {
                if (!(l3_temp_debug_flag & L2_DEBUG_BASIC)) {
                    printf("l3 xmit basic debug is enabled\n");
                    l3_temp_debug_flag |= L2_DEBUG_BASIC;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (l3_temp_debug_flag & L2_DEBUG_BASIC) {
                    printf("l3 xmit basic debug is disabled\n");
                    l3_temp_debug_flag &= ~L2_DEBUG_BASIC;
                }
            }
            break;
        case L3TEMP_EVENT:
            if (cbt->mode & MODE_DO) {
                if (!(l3_temp_debug_flag & L2_DEBUG_EVENT)) {
                    printf("l3 xmit event debug is enabled\n");
                    l3_temp_debug_flag |= L2_DEBUG_EVENT;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (l3_temp_debug_flag & L2_DEBUG_EVENT) {
                    printf("l3 xmit event debug is disabled\n");
                    l3_temp_debug_flag &= ~L2_DEBUG_EVENT;
                }
            }
            break;
        case L3TEMP_PACKET:
            if (cbt->mode & MODE_DO) {
                if (!(l3_temp_debug_flag & L2_DEBUG_PACKET)) {
                    printf("l3 xmit packet debug is enabled\n");
                    l3_temp_debug_flag |= L2_DEBUG_PACKET;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (l3_temp_debug_flag & L2_DEBUG_PACKET) {
                    printf("l3 xmit packet debug is disabled\n");
                    l3_temp_debug_flag &= ~L2_DEBUG_PACKET;
                }
            }
            break;
        case L3TEMP_ALL:
            if (cbt->mode & MODE_DO) {
                if ((l3_temp_debug_flag & L2_DEBUG_ALL) != L2_DEBUG_ALL) {
                    printf("l3 xmit all debug is enabled\n");
                    l3_temp_debug_flag |= L2_DEBUG_ALL;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (l3_temp_debug_flag & L2_DEBUG_ALL) {
                    printf("l3 xmit all debug is disabled\n");
                    l3_temp_debug_flag &= ~L2_DEBUG_ALL;
                }
            }
            break;
        default:
            break;
    }
    return 0;
}

int
debug_eth_in_cli(cmd_blk_t *cbt)
{
    if (!cbt) {
        RTE_LOG(ERR, FLOW, "%s: the cbt is NULL!\n", __func__);
        return -1;
    }

    switch (cbt->which[L2_SUB_POS]) {
        case ETHIN_BASIC:
            if (cbt->mode & MODE_DO) {
                if (!(eth_input_debug_flag & L2_DEBUG_BASIC)) {
                    printf("eth in basic debug is enabled\n");
                    eth_input_debug_flag |= L2_DEBUG_BASIC;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (eth_input_debug_flag & L2_DEBUG_BASIC) {
                    printf("eth in basic debug is disabled\n");
                    eth_input_debug_flag &= ~L2_DEBUG_BASIC;
                }
            }
            break;
        case ETHIN_EVENT:
            if (cbt->mode & MODE_DO) {
                if (!(eth_input_debug_flag & L2_DEBUG_EVENT)) {
                    printf("eth in event debug is enabled\n");
                    eth_input_debug_flag |= L2_DEBUG_EVENT;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (eth_input_debug_flag & L2_DEBUG_EVENT) {
                    printf("eth in event debug is disabled\n");
                    eth_input_debug_flag &= ~L2_DEBUG_EVENT;
                }
            }
            break;
        case ETHIN_PACKET:
            if (cbt->mode & MODE_DO) {
                if (!(eth_input_debug_flag & L2_DEBUG_PACKET)) {
                    printf("eth in packet debug is enabled\n");
                    eth_input_debug_flag |= L2_DEBUG_PACKET;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (eth_input_debug_flag & L2_DEBUG_PACKET) {
                    printf("eth in packet debug is disabled\n");
                    eth_input_debug_flag &= ~L2_DEBUG_PACKET;
                }
            }
            break;
        case ETHIN_ALL:
            if (cbt->mode & MODE_DO) {
                if ((eth_input_debug_flag & L2_DEBUG_ALL) != L2_DEBUG_ALL) {
                    printf("eth in all debug is enabled\n");
                    eth_input_debug_flag |= L2_DEBUG_ALL;
                }
            } else if (cbt->mode & MODE_UNDO) {
                if (eth_input_debug_flag & L2_DEBUG_ALL) {
                    printf("eth in all debug is disabled\n");
                    eth_input_debug_flag &= ~L2_DEBUG_ALL;
                }
            }
            break;
        default:
            break;
    }
    return 0;
}

#define L2_DEBUG_MAX_LINE_LEN     256
#define L2_DEBUG_MAX_LINE_CNT     8192
#define L2_DEBUG_MAX_BUF_LEN      (L2_DEBUG_MAX_LINE_LEN<<2)

rte_atomic32_t l2_debug_index;
char l2_debug_buffer[L2_DEBUG_MAX_LINE_CNT][L2_DEBUG_MAX_LINE_LEN];

static void
l2_debug_write_2_buffer(char *string)
{
    lcoreid_t cid;
    uint32_t sid;
    time_t tm;
    uint32_t hdr_len, body_len, n, start, i;
    char buf[L2_DEBUG_MAX_LINE_LEN] = {0};

    cid = rte_lcore_id();
    sid = rte_socket_id();
    tm  = sys_current_time();
    hdr_len = snprintf(buf, L2_DEBUG_MAX_LINE_LEN, "[T%d@%d] %d: ", cid, sid, (uint32_t)tm);
    body_len = strlen(string);
    n = 1;
    while ((body_len+hdr_len+n) >= n*L2_DEBUG_MAX_LINE_LEN)
        n++;

    start = rte_atomic32_add_return(&l2_debug_index, n) - n;
    i = snprintf(l2_debug_buffer[start], L2_DEBUG_MAX_LINE_LEN, "%s%s", buf, string);
    if (i >= L2_DEBUG_MAX_LINE_LEN) {
        char *bp = string+L2_DEBUG_MAX_LINE_LEN-1-hdr_len;
        while (--n && i >= L2_DEBUG_MAX_LINE_LEN && start<L2_DEBUG_MAX_LINE_CNT-1) {
            i = snprintf(l2_debug_buffer[++start], L2_DEBUG_MAX_LINE_LEN, "%s", bp);
        }
    }
}


inline int print_mbuf_head(struct rte_mbuf *mbuf, char *bufall){
	uint8_t *pkt;
	int len = 0;
	struct rte_ipv4_hdr *ip_header;
	rte_be16_t ptype;
	
	pkt = rte_pktmbuf_mtod(mbuf, uint8_t *);

	ptype = *(rte_be16_t *)(pkt + sizeof(struct rte_ether_hdr) - 2);
	len += snprintf(bufall + len, L2_OLG_BUFFER_LEN - len, "addr = %p, packt type:%02X%02X, ", mbuf, (uint8_t)ptype, (uint8_t)(ptype >> 8));

	len += snprintf(bufall + len, L2_OLG_BUFFER_LEN - len, "d_addr:%02X:%02X:%02X:%02X:%02X:%02X, ",
		   pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5]);
	len += snprintf(bufall + len, L2_OLG_BUFFER_LEN - len, "s_addr:%02X:%02X:%02X:%02X:%02X:%02X ",
		   pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11]);

	if (htons(ptype) == 0x0800) {
		struct in_addr in_ip;
		ip_header = (struct rte_ipv4_hdr *)(pkt + sizeof(struct rte_ether_hdr));
		in_ip.s_addr = ip_header->dst_addr;
		len += snprintf(bufall + len, L2_OLG_BUFFER_LEN - len, "d_ip:%s, ", inet_ntoa(in_ip));
		in_ip.s_addr = ip_header->src_addr;
		len += snprintf(bufall + len, L2_OLG_BUFFER_LEN - len, "s_ip:%s, ", inet_ntoa(in_ip));
	}

	len += snprintf(bufall + len, L2_OLG_BUFFER_LEN - len, "pkt len:%u\n", mbuf->pkt_len);
	len += snprintf(bufall + len, L2_OLG_BUFFER_LEN - len, "\t\t\t");
	return len;
}

int print_mbuf_pkt( struct rte_mbuf *mbuf, char *bufall){
	int i, seg_nb;
	uint8_t *pkt;
	int len = 0;
	seg_nb = 0;
	struct rte_mbuf * seg = mbuf;
	
	while (seg) {
		pkt = rte_pktmbuf_mtod(seg, uint8_t *);
		for (i = 0; i < seg->data_len; i++) {
			if(len >= L2_OLG_BUFFER_LEN)
				goto end;
			len += snprintf(bufall + len, L2_OLG_BUFFER_LEN - len, "%02hhX ", pkt[i]);
			if((i % 8) == 0){
				len += snprintf(bufall + len, L2_OLG_BUFFER_LEN - len, "\n\t\t\t");
			}
		}
		seg = seg->next;
		seg_nb++;
	}

	len += snprintf(bufall + len, L2_OLG_BUFFER_LEN - len, "\n\t\t\t");
	len += snprintf(bufall + len, L2_OLG_BUFFER_LEN - len, "seg num:%d\n", seg_nb);

end:
	return len;
}
void print_buf_force_end(char buf[]){
	buf[L2_OLG_BUFFER_LEN-4] = '.';
	buf[L2_OLG_BUFFER_LEN-3] = '.';
	buf[L2_OLG_BUFFER_LEN-2] = '.';
	buf[L2_OLG_BUFFER_LEN-1] = '\0';
}

void l2_debug_mbuf_trace(int node, int detail, struct rte_mbuf *mbuf, const char *fmt, ...){
	char buf[L2_OLG_BUFFER_LEN];
	int len = 0;
    int pass = 0;
    
	if(mbuf==NULL)
		return;

    if (rte_atomic32_read(&l2_debug_index) >= L2_DEBUG_MAX_LINE_CNT)
        return;

    pass = mac_match_filter(node, mbuf);
    if(!pass){
        return;
    }

	buf[0] = '\0';
	len = print_mbuf_head(mbuf, buf);
	if (unlikely(len == -1)) {
		printf("l2_debug_mbuf_trace failed, mbuf = %p\n", mbuf);
		return;
	}
    
	va_list args;
	va_start(args, fmt);
	len += vsnprintf(buf + len, L2_OLG_BUFFER_LEN - len , fmt, args);
	va_end(args);

	if (len >= L2_OLG_BUFFER_LEN) {
       print_buf_force_end(buf);
	   goto end;
    }

	if(detail == DETAIL_ON) {
		len += snprintf(buf + len, L2_OLG_BUFFER_LEN - len, "\t\t\t");
		len += print_mbuf_pkt(mbuf, buf);
		if (len >= L2_OLG_BUFFER_LEN) {
      	 	print_buf_force_end(buf);
	  		goto end;
    	}

        buf[len] = '\0';
	}

end:
	l2_debug_write_2_buffer(buf);
	return;
}

inline void print_fdb_detail(struct net_bridge_fdb_entry *fdb_entry){
	if(brctl_debug_flag & L2_DEBUG_EVENT)
		__print_fdb_detail(fdb_entry);
}

inline void __print_fdb_detail(struct net_bridge_fdb_entry *fdb_entry)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];

	if(!fdb_entry){
		return;
	}
	
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, &fdb_entry->addr);
	printf("\n");
	printf(" 	fdb *****start ****\n");
	printf("		addr : %s\n",buf);
	printf("		dst name : %s\n",fdb_entry->dst->dev->name);
	printf("		is-local : %d\n", fdb_entry->is_local);
	printf("		is-static : %d\n", fdb_entry->is_static);
	printf("	fdb *****end *****\n");
}

/*
static void brctl_proc_cleanup_end(){
	int i = 0;
	dpvs_timing_stop();
	i = dpvs_timing_get();

	
}
*/
static inline void brctl_print_event_detail(enum brctl_debug_event event, void *param){
	switch(event){
		case BRCTL_EVENT_FDB_CREATE:
		case BRCTL_EVENT_FDB_DELETE:
		{
			__print_fdb_detail((struct net_bridge_fdb_entry *)param);
			break;
		}
		case BRCTL_EVENT_FDB_CLEANUP_SRART:
			//dpvs_timing_start();
			break;
		case BRCTL_EVENT_FDB_CLEANUP_END:
		{
			break;
		}
		case BRCTL_EVENT_BRIDGE_IF_DEL_SYNC_DONE:
		case BRCTL_EVENT_BRIDGE_IF_DEL_SYNC_WAIT:
		case BRCTL_EVENT_BRIDGE_IF_DEL:
		{
			break;
		}
		default:
			printf("nuknow brctl event type = %d!\n", event);
	}
	
}
void brctl_debug_event_detail(enum brctl_debug_event event, void *param, const char *fmt, ...){
	char buf[L2_OLG_BUFFER_LEN];
	int len = 0;
	buf[0] = '\0';
	
	va_list args;
	va_start(args, fmt);
	len = vsnprintf(buf, L2_OLG_BUFFER_LEN, fmt, args);
	va_end(args);

	if (len >= L2_OLG_BUFFER_LEN) {
        buf[L2_OLG_BUFFER_LEN-4] = '.';
        buf[L2_OLG_BUFFER_LEN-3] = '.';
        buf[L2_OLG_BUFFER_LEN-2] = '.';
        buf[L2_OLG_BUFFER_LEN-1] = '\0';
    }
	/*print event head*/
	printf("%s\n", buf);

	/*print event detail*/
	brctl_print_event_detail(event, param);
	return;
}

static int
l2_show_debug_trace(cmd_blk_t *cbt)
{
    uint32_t i, j;

    j = rte_atomic32_read(&l2_debug_index);
    j = (j>=L2_DEBUG_MAX_LINE_CNT)?L2_DEBUG_MAX_LINE_CNT:j;
    for (i=0; i<j; i++) {
        tyflow_cmdline_printf(cbt->cl, "%4d %s", i, l2_debug_buffer[i]);
    }
    tyflow_cmdline_printf(cbt->cl, "total line %d\n", j);
    return 0;
}

EOL_NODE(l2_debug_trace_eol, l2_show_debug_trace);
KW_NODE(l2_debug_trace, l2_debug_trace_eol, none, "trace", "show debug trace");
KW_NODE(l2_get_debug, l2_debug_trace, none, "debug-l2", "show debug");

static int
l2_clear_debug_trace(cmd_blk_t *cbt)
{
    uint32_t j;

    j = rte_atomic32_read(&l2_debug_index);
    j = (j>=L2_DEBUG_MAX_LINE_CNT)?L2_DEBUG_MAX_LINE_CNT:j;
    rte_atomic32_set(&l2_debug_index, 0);
    tyflow_cmdline_printf(cbt->cl, "clear %d lines of trace\n", j);
    return 0;
}
EOL_NODE(l2_debug_trace2_eol, l2_clear_debug_trace);
KW_NODE(l2_debug_trace2, l2_debug_trace2_eol, none, "trace", "clear l2 debug trace");
KW_NODE(l2_clear_debug, l2_debug_trace2, none, "debug-l2", "clear l2 debug");

EOL_NODE(debug_ethin_eol, debug_eth_in_cli);
KW_NODE_WHICH(ethin_all, debug_ethin_eol, none, "all", "enable/disable ethin all debug", 2, 4);
KW_NODE_WHICH(ethin_packet, debug_ethin_eol, ethin_all, "packet", "enable/disable ethin packet debug", 2, 3);
KW_NODE_WHICH(ethin_event, debug_ethin_eol, ethin_packet, "event", "enable/disable ethin event debug", 2, 2);
KW_NODE_WHICH(ethin_basic, debug_ethin_eol, ethin_event, "basic", "enable/disable ethin basic debug", 2, 1);
KW_NODE_WHICH(ethin_debug, ethin_basic, none, "ethin", "enable/disable ethin app debug", 1, 8);

EOL_NODE(debug_l3temp_eol, debug_l3_temp_cli);
KW_NODE_WHICH(l3temp_all, debug_l3temp_eol, none, "all", "enable/disable l3temp all debug", 2, 4);
KW_NODE_WHICH(l3temp_packet, debug_l3temp_eol, l3temp_all, "packet", "enable/disable l3temp packet debug", 2, 3);
KW_NODE_WHICH(l3temp_event, debug_l3temp_eol, l3temp_packet, "event", "enable/disable l3temp event debug", 2, 2);
KW_NODE_WHICH(l3temp_basic, debug_l3temp_eol, l3temp_event, "basic", "enable/disable l3temp basic debug", 2, 1);
KW_NODE_WHICH(l3temp_debug, l3temp_basic, ethin_debug, "l3temp", "enable/disable l3temp app debug", 1, 7);


EOL_NODE(debug_l2xmit_eol, debug_l2_xmit_cli);
KW_NODE_WHICH(l2xmit_all, debug_l2xmit_eol, none, "all", "enable/disable l2xmit all debug", 2, 4);
KW_NODE_WHICH(l2xmit_packet, debug_l2xmit_eol, l2xmit_all, "packet", "enable/disable l2xmit packet debug", 2, 3);
KW_NODE_WHICH(l2xmit_event, debug_l2xmit_eol, l2xmit_packet, "event", "enable/disable l2xmit event debug", 2, 2);
KW_NODE_WHICH(l2xmit_basic, debug_l2xmit_eol, l2xmit_event, "basic", "enable/disable l2xmit basic debug", 2, 1);
KW_NODE_WHICH(l2xmit_debug, l2xmit_basic, l3temp_debug, "l2xmit", "enable/disable l2xmit app debug",1, 6);

EOL_NODE(debug_brctl_eol, debug_brctl_cli);
KW_NODE_WHICH(brctl_all, debug_brctl_eol, none, "all", "enable/disable brctl all debug", 2, 4);
KW_NODE_WHICH(brctl_packet, debug_brctl_eol, brctl_all, "packet", "enable/disable brctl packet debug", 2, 3);
KW_NODE_WHICH(brctl_event, debug_brctl_eol, brctl_packet, "event", "enable/disable brctl event debug", 2, 2);
KW_NODE_WHICH(brctl_basic, debug_brctl_eol, brctl_event, "basic", "enable/disable brctl basic debug", 2, 1);
KW_NODE_WHICH(brctl_debug, brctl_basic, l2xmit_debug, "brctl", "enable/disable br app debug",1, 5);

EOL_NODE(l2_debug_eol, debug_l2_cli);
KW_NODE_WHICH(l2_all, l2_debug_eol, brctl_debug, "all", "enable/disable l2 all debug", 1, 4);
KW_NODE_WHICH(l2_packet, l2_debug_eol, l2_all, "packet", "enable/disable l2 packet debug", 1, 3);
KW_NODE_WHICH(l2_event, l2_debug_eol, l2_packet, "event", "enable/disable l2 event debug", 1, 2);
KW_NODE_WHICH(l2_debug_basic, l2_debug_eol, l2_event, "basic", "enable/disable l2 basic debug", 1, 1);
KW_NODE(l2_set_debug, l2_debug_basic, none, "l2", "enable/disable l2 debug");

int 
L2_debug_init(void)
{
	add_debug_cmd(&cnode(l2_set_debug));
	add_get_cmd(&cnode(l2_get_debug));
    add_clear_cmd(&cnode(l2_clear_debug));
	rte_atomic32_set(&l2_debug_index, 0);
    mac_filter_init();
	return 0;
}


