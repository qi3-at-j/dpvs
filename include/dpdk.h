/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2021 iQIYI (www.iqiyi.com).
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
#ifndef __DPVS_DPDK_H__
#define __DPVS_DPDK_H__

#include "dpdk_version_adapter.h"
#include "mbuf.h"
#ifdef CONFIG_DPVS_PDUMP
#include <rte_pdump.h>
#endif

#ifdef RTE_LOG
extern int dpvs_log(uint32_t level, uint32_t logtype, const char *func, int line, const char *format, ...);
#undef RTE_LOG
#define RTE_LOG(l, t, ...)                  \
    dpvs_log(RTE_LOG_ ## l,                   \
        RTE_LOGTYPE_ ## t,  __func__, __LINE__, # t ": " __VA_ARGS__)
#endif

typedef uint8_t		u8;
typedef uint16_t	u16;
typedef uint32_t	u32;
typedef uint64_t	u64;

#ifndef __u8
typedef uint8_t     __u8;
#endif

#ifndef __u16
typedef uint16_t    __u16;
#endif

#ifndef __u32
typedef uint32_t    __u32;
#endif


#endif /* __DPVS_DPDK_H__ */
