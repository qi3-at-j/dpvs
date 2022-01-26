#ifndef __IPS_POLICY_CLI_H__
#define __IPS_POLICY_CLI_H__

#define ACTION_ALERT        0x01
#define ACTION_DROP         0x02
#define ACTION_PASS         0x20

enum DpiMode {
    DPI_MODE_BLOCK,
    DPI_MODE_MONITOR,
};

enum VPatchSwitch {
    VPATCH_OFF,
    VPATCH_ON,
};

enum TraceSwitch {
    TRACE_OFF,
    TRACE_ON,
};

extern void ips_policy_cli_init(void);

#endif
