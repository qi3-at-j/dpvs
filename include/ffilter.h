/*
 * Copyright (C) 2021 TYyun.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef	__FFILTER_H__
#define	__FFILTER_H__

#include <stdint.h>

#define MAX_FFILTER_NUM 8
typedef struct ffilter_ent_ {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t  proto;
	uint8_t  reserved1;
} ffilter_ent_t;

extern uint32_t total_ffilter;
extern ffilter_ent_t ffilter_ent[];

RTE_DECLARE_PER_LCORE(uint32_t, ffilter_show_this_pak);
#define this_ffilter_show_this_pak (RTE_PER_LCORE(ffilter_show_this_pak))

extern void flow_mark_pak_func(struct rte_ipv4_hdr  *iphdr, uint32_t *iptr);

/*
 * turn on debug for this packet if flow debug is on,
 * and packet matches filter conditions.
 */
#define flow_mark_pak(iphdr,iptr)      do { \
	ffilter_show_this_pak = 0; 					\
	if (flow_debug_flag) {                      \
		flow_mark_pak_func(iphdr,iptr);     \
	}\
}while (0)
#endif /* _FFILTER_H */
