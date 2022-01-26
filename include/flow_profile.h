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
 */

#ifndef __TYFLOW_FLOW_PROFILE_H__
#define __TYFLOW_FLOW_PROFILE_H__

#define FLOW_VECTOR_NAME_LEN 32
typedef struct {
    char name[FLOW_VECTOR_NAME_LEN];
    uint16_t id;
    uint16_t flag;
#define FLOW_PROF_REC_F_SUM   0x0001
#define FLOW_PROF_REC_F_FAST  0x0002
#define FLOW_PROF_REC_F_FIRST 0x0004
} flow_profile_item_t;

typedef struct {
    uint32_t count;
    uint64_t cycles;
} flow_profile_record_t;

enum {
    ID_flow_processing_paks = 0,
    ID_flow_parse_vector,
    ID_flow_filter_vector,
#ifdef TYFLOW_PER_THREAD
    ID_flow_fwd_vector,
#endif
    ID_flow_decap_vector,
    ID_flow_main_body_vector,
    ID_flow_fast_for_self,
    ID_flow_fast_check_routing,
    ID_flow_fast_reinject_out,
    ID_flow_fast_fw_entry,
#ifdef TYFLOW_LEGACY
    ID_flow_fast_send_out,
#endif
    ID_flow_first_sanity_check,
    ID_flow_first_hole_search,
    ID_flow_first_routing,
    ID_flow_first_for_self,
    ID_flow_first_alloc_connection,
    ID_flow_first_fw_entry,

    ID_flow_parse_vector_v6,
    ID_flow_filter_vector_v6,
    ID_flow_decap_vector_v6,
    ID_flow_fast_for_self_v6,
    ID_flow_fast_check_routing_v6,
    ID_flow_fast_reinject_out_v6,
#ifdef TYFLOW_LEGACY
    ID_flow_fast_send_out_v6,
#endif
    ID_flow_first_sanity_check_v6,
    ID_flow_first_hole_search_v6,
    ID_flow_first_routing_v6,
    ID_flow_first_for_self_v6,
    ID_flow_max
};

#define VECTOR_ENTRY(name, desc, flag) {desc, ID_##name, flag}
static flow_profile_item_t 
flow_prof_item_template[ID_flow_max] __rte_unused = {
    VECTOR_ENTRY(flow_processing_paks, "One pak proc", FLOW_PROF_REC_F_SUM),
    VECTOR_ENTRY(flow_parse_vector, "parse vector", FLOW_PROF_REC_F_FAST),
    VECTOR_ENTRY(flow_filter_vector, "filter vector", FLOW_PROF_REC_F_FAST),
#ifdef TYFLOW_PER_THREAD
    VECTOR_ENTRY(flow_fwd_vector, "fwd vector", FLOW_PROF_REC_F_FAST),
#endif
    VECTOR_ENTRY(flow_decap_vector, "decap vector", FLOW_PROF_REC_F_FAST),
    VECTOR_ENTRY(flow_main_body_vector, "main vector", FLOW_PROF_REC_F_FAST),
    VECTOR_ENTRY(flow_fast_for_self, "fast self", FLOW_PROF_REC_F_FAST),
    VECTOR_ENTRY(flow_fast_check_routing, "fast check route", FLOW_PROF_REC_F_FAST),
    VECTOR_ENTRY(flow_fast_reinject_out, "fast reinject", FLOW_PROF_REC_F_FAST),
    VECTOR_ENTRY(flow_fast_fw_entry, "fast fw", FLOW_PROF_REC_F_FAST),
#ifdef TYFLOW_LEGACY
    VECTOR_ENTRY(flow_fast_send_out, "fast send out", FLOW_PROF_REC_F_FAST),
#endif
    VECTOR_ENTRY(flow_first_sanity_check, "first sanity", FLOW_PROF_REC_F_FIRST),
    VECTOR_ENTRY(flow_first_hole_search, "first hole", FLOW_PROF_REC_F_FIRST),
    VECTOR_ENTRY(flow_first_routing, "first route", FLOW_PROF_REC_F_FIRST),
    VECTOR_ENTRY(flow_first_for_self, "first self", FLOW_PROF_REC_F_FIRST),
    VECTOR_ENTRY(flow_first_alloc_connection, "alloc fcp", FLOW_PROF_REC_F_FIRST),
    VECTOR_ENTRY(flow_first_fw_entry, "first fw", FLOW_PROF_REC_F_FIRST),
    VECTOR_ENTRY(flow_parse_vector_v6, "parse vector v6", FLOW_PROF_REC_F_FAST),
    VECTOR_ENTRY(flow_filter_vector_v6, "filter vector v6", FLOW_PROF_REC_F_FAST),
    VECTOR_ENTRY(flow_decap_vector_v6, "decap vector v6", FLOW_PROF_REC_F_FAST),
    VECTOR_ENTRY(flow_fast_for_self_v6, "fast self v6", FLOW_PROF_REC_F_FAST),
    VECTOR_ENTRY(flow_fast_check_routing_v6, "fast check route v6", FLOW_PROF_REC_F_FAST),
    VECTOR_ENTRY(flow_fast_reinject_out_v6, "fast reinject v6", FLOW_PROF_REC_F_FAST),
#ifdef TYFLOW_LEGACY
    VECTOR_ENTRY(flow_fast_send_out_v6, "fast send out v6", FLOW_PROF_REC_F_FAST),
#endif
    VECTOR_ENTRY(flow_first_sanity_check_v6, "first sanity v6", FLOW_PROF_REC_F_FIRST),
    VECTOR_ENTRY(flow_first_hole_search_v6, "first hole v6", FLOW_PROF_REC_F_FIRST),
    VECTOR_ENTRY(flow_first_routing_v6, "first route v6", FLOW_PROF_REC_F_FIRST),
    VECTOR_ENTRY(flow_first_for_self_v6, "first self v6", FLOW_PROF_REC_F_FIRST),
};

extern uint32_t flow_profile_flag;
#define FLOW_PROFILE_FLAG_VECTOR   0x00000001
#define FLOW_PROFILE_FLAG_SERVICE  0x00000002
#define FLOW_PROFILE_FLAG_TRAFFIC  0x00000004

typedef struct {
    uint32_t toggle;
    uint16_t prof_old_id;
    uint16_t resv;
    uint64_t prof_last_flow;
    uint64_t prof_old_time;
    flow_profile_item_t   item[ID_flow_max];
    flow_profile_record_t record[ID_flow_max];
} flow_profile_ctx_t;

/* per lcore flow profile context */
RTE_DECLARE_PER_LCORE(flow_profile_ctx_t, flow_prof);

#define this_flow_prof    (RTE_PER_LCORE(flow_prof))

#define is_flow_profile_vector_on()  \
    (flow_profile_flag & FLOW_PROFILE_FLAG_VECTOR)

extern void prof_vector(uint16_t id);
#define FLOW_PROFILE_VECTOR_START                                           \
    if (is_flow_profile_vector_on()) {                                      \
        if (!this_flow_prof.toggle) {                                       \
            memset(this_flow_prof.record, 0, sizeof(this_flow_prof.record));\
            this_flow_prof.toggle = 1;                                      \
        }                                                                   \
        this_flow_prof.prof_old_id = ID_flow_max;                           \
        this_flow_prof.prof_old_time = rte_get_tsc_cycles();                \
        this_flow_prof.prof_last_flow = this_flow_prof.prof_old_time;       \
    }

#define FLOW_PROFILE_VECTOR_END                                       \
    if (this_flow_prof.toggle) {                                      \
        prof_vector(ID_flow_max);                                     \
        this_flow_prof.prof_old_id = ID_flow_processing_paks;         \
        this_flow_prof.prof_old_time = this_flow_prof.prof_last_flow; \
        prof_vector(ID_flow_processing_paks);                         \
        if (!is_flow_profile_vector_on()) {                           \
            this_flow_prof.toggle = 0;                                \
        }                                                             \
    }

#define VECTOR_PROFILE(name)        \
do {                                \
    if (this_flow_prof.toggle) {    \
        prof_vector(ID_##name);     \
    }                               \
} while(0)

extern int
flow_profile_init(void);

#endif /* __TYFLOW_FLOW_PROFILE_H__ */
