#ifndef __NODE_SWITCH_CLI_PRIV_H__
#define __NODE_SWITCH_CLI_PRIV_H__

#include <rte_lcore.h>

#include "common_cli_priv.h"

RTE_DECLARE_PER_LCORE(struct common_cmd_switch, switch_lcore);
#define this_lcore_switch      (RTE_PER_LCORE(switch_lcore))
extern struct common_cmd_switch *g_sw_p[RTE_MAX_LCORE];

static inline uint8_t get_switch_nf(void)
{
    return this_lcore_switch.nf;
}

static inline uint8_t get_switch_fwd(void)
{
    return this_lcore_switch.fwd;
}

static inline uint8_t get_switch_arp(void)
{
    return this_lcore_switch.arp;
}

static inline int switch_init(void *arg)
{
    RTE_SET_USED(arg);
    this_lcore_switch.nf = 0;
    this_lcore_switch.fwd = 1;
    this_lcore_switch.arp = 1;
    g_sw_p[rte_lcore_id()] = &this_lcore_switch;
    return 0;
}

static inline int set_switch_nf(void *sw)
{
    if (unlikely(sw == NULL)) {
        return -EINVAL;
    }

    this_lcore_switch.nf = ((struct common_cmd_switch *)sw)->nf;

    return 0;
}

static inline int set_switch_fwd(void *sw)
{
    if (unlikely(sw == NULL)) {
        return -EINVAL;
    }

    this_lcore_switch.fwd = ((struct common_cmd_switch *)sw)->fwd;

    return 0;
}

static inline int set_switch_arp(void *sw)
{
    if (unlikely(sw == NULL)) {
        return -EINVAL;
    }

    this_lcore_switch.arp = ((struct common_cmd_switch *)sw)->arp;

    return 0;
}

void switch_cli_init(void);

#endif
