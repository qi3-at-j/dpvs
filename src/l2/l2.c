#include "dpdk.h"
#include "./include/l2_debug.h"
#include "./include/link_cmd.h"
#include "./include/device_id.h"
#include "./include/l2_meter.h"
int l2_init(void){
    int err = 0;
    err = L2_debug_init();
    err |= interface_cli_init();
    err |= l2_meter_init();
    return err;
}

