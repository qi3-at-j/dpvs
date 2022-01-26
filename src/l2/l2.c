
#include "./include/l2_debug.h"
#include "./include/link_cmd.h"
#include "./include/device_id.h"
int l2_init(void){
    int err = 0;
    err = L2_debug_init();
    err = interface_cli_init();

    return err;
}


