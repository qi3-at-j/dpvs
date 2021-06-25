/*
 br.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_ether.h>
#include "conf/common.h"
#include "dpip.h"
#include "utils.h"
#include "conf/br.h"
#include "sockopt.h"

/*
 * XXX: why "vlan" is first level of dpip object ?
 * We can implement vlan in dpip/link.c (or dpip/link_vlan.c) alternately.
 * But the "link" (even dpvs/netif) module need refactor to be more
 * abstractive and easier for extension. So that less effort is needed to
 * support different sort of devices (rte_eth, kni, bonding, vlan, etc).
 */

static void br_help(void)
{
    fprintf(stderr,
            "Usage:\n"
            "    dpip brctl add br { BR-NAME }\n"
            "    dpip brctl del br { BR-NAME }\n"
            "    dpip brctl add if { BR-NAME } {IF-NAME}\n"
            "    dpip brctl del if { BR-NAME } {TF-NAME}\n"
            "    dpip brctl show br { BR-NAME }\n"

            "Parameters:\n"
            "    BR-NAME       := DEV\n"
            "    IF-NAME       := DEV\n"
            "Examples:\n"
            "    \n"
            "    dpip brctl add br br0\n"
            "    dpip brctl del br br0\n"
            "    dpip brctl show br br0\n"
            "    dpip brctl add if br0  dpdk0\n"
            "    dpip brctl del if br0  dpdk0\n");
}


static int br_parse(struct dpip_obj *obj, struct dpip_conf *conf)
{
    struct br_param *param = obj->param;

    memset(param, 0, sizeof(*param));

    while (conf->argc > 0) {
		if(strcmp(conf->argv[0], "br") == 0){
			param->is_br = true;
			NEXTARG_CHECK(conf, conf->argv[0]);
			snprintf(param->brName, IFNAMSIZ, "%s", conf->argv[0]);
		}else if(strcmp(conf->argv[0], "if") == 0){
			param->is_br = false;
			NEXTARG_CHECK(conf, conf->argv[0]);
			snprintf(param->brName, IFNAMSIZ, "%s", conf->argv[0]);
			NEXTARG_CHECK(conf, conf->argv[0]);
			snprintf(param->ifName, IFNAMSIZ, "%s", conf->argv[0]);
		}else if(conf->cmd == DPIP_CMD_SHOW){
			snprintf(param->brName, IFNAMSIZ, "%s", conf->argv[0]);
		}else{
            fprintf(stderr, "too many arguments\n");
            return EDPVS_INVAL;
        }

        NEXTARG(conf);
    }

    return EDPVS_OK;
}

static int br_check(const struct dpip_obj *obj, dpip_cmd_t cmd)
{
    const struct br_param *param = obj->param;

    /* sanity check */
    switch (cmd) {
    case DPIP_CMD_DEL:
	case DPIP_CMD_ADD:
        if ((param->is_br == true)&&(strlen(param->brName) >= 0))
            return EDPVS_OK;
        if ((param->is_br == false) && (strlen(param->brName) >= 0) && ((strlen(param->ifName) >= 0)) )
            return EDPVS_OK;

    case DPIP_CMD_SHOW:
        /* either ifname or link device is set */
        if (strlen(param->brName) == 0) {
            fprintf(stderr, "missing bridge device name\n");
            return EDPVS_INVAL;
        }
        return EDPVS_OK;

    default:
        return EDPVS_NOTSUPP;
    }
}


static inline void br_param_dump(const struct br_param *param)
{
	int i=0;
	
	fprintf(stderr, "bridge name	bridge id		STP enabled		interfaces \n");
    fprintf(stderr, "%s\n",  param->brName);
	for(i=0; i<param->port_nb; i++){
		fprintf(stderr, "%70s\n",  param->br_port_infos[i].ifName);
	}
}

static int br_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd,
                       struct dpip_conf *conf)
{
    const struct br_param *param = obj->param;
    struct br_param_array *array;
    size_t size;
    int err, i;

    switch (cmd) {
    case DPIP_CMD_ADD:
        return dpvs_setsockopt(SOCKOPT_SET_BR_ADD, param, sizeof(*param));
    case DPIP_CMD_DEL:
        return dpvs_setsockopt(SOCKOPT_SET_BR_DEL, param, sizeof(*param));
    case DPIP_CMD_SHOW:
        err = dpvs_getsockopt(SOCKOPT_GET_BR_SHOW, param, sizeof(*param),
                              (void **)&array, &size);
        if (err != 0)
            return err;

        if (size < sizeof(*array)
                || size < sizeof(*array) + \
                           array->nparam * sizeof(struct br_param)) {
            fprintf(stderr, "corrupted response.\n");
            dpvs_sockopt_msg_free(array);
            return EDPVS_INVAL;
        }

        for (i = 0; i < array->nparam; i++)
            br_param_dump(&array->params[i]);

        dpvs_sockopt_msg_free(array);
        return EDPVS_OK;
    default:
        return EDPVS_NOTSUPP;
    }
}

static struct br_param br_param;

static struct dpip_obj dpip_br = {
    .name       = "brctl",
    .param      = &br_param,

    .help       = br_help,
    .parse      = br_parse,
    .check      = br_check,
    .do_cmd     = br_do_cmd,
};

static void __init br_init(void)
{
    dpip_register_obj(&dpip_br);
}

static void __exit br_exit(void)
{
    dpip_unregister_obj(&dpip_br);
}

