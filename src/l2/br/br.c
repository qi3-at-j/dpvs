/*
	bridge module init
 */
#include <assert.h>
#include <linux/if_ether.h>
#include "list.h"
#include "netif.h"
#include "netif_addr.h"
#include "kni.h"
#include "ctrl.h"
#include "../include/br_private.h"
#include "../include/l2_debug.h"
#include "parser/flow_cmdline_parse.h"
#include "parser/flow_cmdline.h"
#include "conf/br.h"
#include "l2.h"

static struct list_head g_br_list;
static uint16_t g_nbrs = 0;

static inline void bridge_global_list_init(void)
{
	INIT_LIST_HEAD(&g_br_list);
}

struct net_bridge* bridge_get_by_name(const char *name)
{
    struct net_bridge *br;

    if (!name || strlen(name) <= 0)
        return NULL;

    list_for_each_entry(br, &g_br_list, br_list) {
        if (!strcmp(br->dev->name, name)) {
            return br;
        }
    }

    return NULL;
}

int bridge_global_list_add(struct       net_bridge *br)
{
    struct net_bridge *cur;
    int err = EDPVS_OK;

    if (unlikely(NULL == br))
        return EDPVS_INVAL;

	list_for_each_entry(cur, &g_br_list, br_list) {
		if (!strcmp(br->dev->name, cur->dev->name)) {
		   	return EDPVS_EXIST;
		}
	 }


    list_add_tail(&br->br_list, &g_br_list);
    g_nbrs++;
	
    return err;

}

int bridge_global_list_del(struct net_bridge *br)
{
    struct net_bridge *cur, *next;
    int ret1;
    if (unlikely(NULL == br))
        return EDPVS_INVAL;

	ret1 = EDPVS_NOTEXIST;

    list_for_each_entry_safe(cur, next, &g_br_list, br_list) {
        if (strcmp(cur->dev->name, br->dev->name) == 0) {
            list_del_init(&cur->br_list);
            ret1 = EDPVS_OK;
            break;
        }
    }

    if (ret1 != EDPVS_OK)
        return EDPVS_NOTEXIST;

    g_nbrs--;
    return EDPVS_OK;
}

/**
 * control plane
 */
/* XXX: waiting netif to add control plane hooks for different virtual devices.
 * so that we do not need register sockopt by ourself. */

static int br_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
    const struct br_param *param = conf;
	struct netif_port *dev;
	struct netif_port *slave;
    if (!conf || size < sizeof(*param))
        return EDPVS_INVAL;

    if ((opt == SOCKOPT_SET_BR_ADD && !strlen(param->brName)) ||
        (opt == SOCKOPT_SET_BR_DEL && !strlen(param->brName))) {
		RTE_LOG(WARNING, BR, "%s:null name\n", __func__);
		return EDPVS_NODEV;
    }

    switch (opt) {
    case SOCKOPT_SET_BR_ADD:
        if ((param->is_br == true)&&(strlen(param->brName) > 0)) {
           	return br_add_bridge(param->brName);
        }else if((param->is_br == false)&&(strlen(param->brName) > 0)&&(strlen(param->ifName) > 0)){
			dev = netif_port_get_by_name(param->brName);
			if (!dev || dev->type != PORT_TYPE_BRIDGE)
				return EDPVS_NOTEXIST;

			slave = netif_port_get_by_name(param->ifName);
			if (!slave)
				return EDPVS_NOTEXIST;

			return dev->netif_ops->op_add_slave(dev, slave);
		}
		else{
			return EDPVS_INVAL;
		}
    case SOCKOPT_SET_BR_DEL:
        if ((param->is_br == true)&&(strlen(param->brName) > 0)) {
            return br_del_bridge(param->brName);
        }else if((param->is_br == false)&&(strlen(param->brName) > 0)&&(strlen(param->ifName) > 0)){
			dev = netif_port_get_by_name(param->brName);
			if (!dev || dev->type != PORT_TYPE_BRIDGE)
				return EDPVS_NOTEXIST;

			slave = netif_port_get_by_name(param->ifName);
			if (!slave)
				return EDPVS_NOTEXIST;

			return dev->netif_ops->op_del_slave(dev, slave);
        }else{
			return EDPVS_INVAL;
		}
    default:
        return EDPVS_NOTSUPP;
    }
}

/**
 * TODO: use msg to fetch per-lcore stats.
 */
static int br_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                            void **out, size_t *outsize)
{
    const struct br_param *param = conf;
    struct br_param_array *array;
    struct netif_port *dev;
	struct net_bridge_port *br_port;
	struct net_bridge *br; 
	struct list_head *pos;
	uint8_t port_nb = 0;
    int i = 0;

    if (!conf || size < sizeof(*param) || !out || !outsize)
        return EDPVS_INVAL;

    if (opt != SOCKOPT_GET_BR_SHOW)
        return EDPVS_NOTSUPP;

    if (strlen(param->brName) == 0){
		return EDPVS_INVAL;
	} 


    dev = netif_port_get_by_name(param->brName);
    if (!dev) {
        RTE_LOG(WARNING, BR, "%s: no such device\n", __func__);
        return EDPVS_NODEV;
    }

    if (dev->type != PORT_TYPE_BRIDGE) { /* good way ? */
        RTE_LOG(WARNING, BR, "%s: not br device\n", __func__);
        return EDPVS_INVAL;
    }

    br = netif_priv(dev);
	assert(NULL != br);
	
	list_for_each(pos, &br->port_list){
		port_nb++;
	}

    *outsize = sizeof(struct br_param_array) + sizeof(struct br_param) + sizeof(struct br_port_info)*port_nb;
    array = *out = rte_calloc(NULL, 1, *outsize, 0);
    if (!array)
        return EDPVS_NOMEM;
	array->nparam = 1;
	array->params[0].port_nb = port_nb;
	
	list_for_each_entry(br_port, &br->port_list, list) {
		strlcpy(array->params[0].br_port_infos[i].ifName , br_port->dev->name, 
				sizeof(array->params[0].br_port_infos[i].ifName));
		i++;
	}
   

    snprintf(array->params[0].brName, IFNAMSIZ, "%s", br->dev->name);
    return EDPVS_OK;

}

static struct dpvs_sockopts br_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_SET_BR_ADD,
    .set_opt_max    = SOCKOPT_SET_BR_DEL,
    .set            = br_sockopt_set,
    .get_opt_min    = SOCKOPT_GET_BR_SHOW,
    .get_opt_max    = SOCKOPT_GET_BR_SHOW,
    .get            = br_sockopt_get,
};

static int
br_detail_get_cli(cmd_blk_t *cbt)
{
	const char *brName = cbt->string[0];
    struct netif_port *dev;
	struct net_bridge_port *br_port;
	struct net_bridge *br; 

    if (strlen(brName) == 0){
		return EDPVS_INVAL;
	} 


	tyflow_cmdline_printf(cbt->cl, "\n");
    dev = netif_port_get_by_name(brName);
    if (!dev) {
		tyflow_cmdline_printf(cbt->cl, "%s: no such device\n", brName);
        return EDPVS_NODEV;
    }

    if (dev->type != PORT_TYPE_BRIDGE) { /* good way ? */
		tyflow_cmdline_printf(cbt->cl, "%s: not br device\n", brName);
        return EDPVS_INVAL;
    }

    br = netif_priv(dev);
	assert(NULL != br);

	
	tyflow_cmdline_printf(cbt->cl, "bridge name	bridge id		STP enabled		interfaces \n");
    tyflow_cmdline_printf(cbt->cl, "%s\n",  brName);

	list_for_each_entry(br_port, &br->port_list, list){
		tyflow_cmdline_printf(cbt->cl, "%70s\n",  br_port->dev->name);
	}
   
    return EDPVS_OK;
}

static int
br_stat_get_cli(cmd_blk_t *cbt)
{
	const char *brName = cbt->string[0];
    struct netif_port *dev;
	struct net_bridge *br; 
	struct rte_eth_stats  stats;
	int err = 0;
    if (strlen(brName) == 0){
		return EDPVS_INVAL;
	} 


	tyflow_cmdline_printf(cbt->cl, "\n");
    dev = netif_port_get_by_name(brName);
    if (!dev) {
		tyflow_cmdline_printf(cbt->cl, "%s: no such device\n", brName);
        return EDPVS_NODEV;
    }

    if (dev->type != PORT_TYPE_BRIDGE) { /* good way ? */
		tyflow_cmdline_printf(cbt->cl, "%s: not br device\n", brName);
        return EDPVS_INVAL;
    }

    br = netif_priv(dev);
	assert(NULL != br);

	memset(&stats, 0, sizeof(struct rte_eth_stats));
	err = br_get_stats(dev, &stats);
	if(err != EDPVS_OK){
		tyflow_cmdline_printf(cbt->cl, "get failed. err = %d\n", err);
		return err;
	}
	tyflow_cmdline_printf(cbt->cl, "***br %s pack statictis**** \n", br->dev->name);
   	tyflow_cmdline_printf(cbt->cl, "	ipackets : %lu\n", stats.ipackets);
	tyflow_cmdline_printf(cbt->cl, "	opackets : %lu\n", stats.opackets);
	tyflow_cmdline_printf(cbt->cl, "	ibytes   : %lu\n", stats.ibytes);
	tyflow_cmdline_printf(cbt->cl, "	obytes   : %lu\n", stats.obytes);
	tyflow_cmdline_printf(cbt->cl, "	imissed  : %lu\n", stats.imissed);
	tyflow_cmdline_printf(cbt->cl, "	ierrors  : %lu\n", stats.ierrors);
	tyflow_cmdline_printf(cbt->cl, "	oerrors  : %lu\n", stats.oerrors);
	tyflow_cmdline_printf(cbt->cl, "	rx_nombuf: %lu\n", stats.rx_nombuf);
	tyflow_cmdline_printf(cbt->cl, "\n");
    return EDPVS_OK;
}

static int
br_show_all_eol(cmd_blk_t *cbt){
	struct net_bridge_port *br_port;
	struct net_bridge *br;
	int err = 0;

	tyflow_cmdline_printf(cbt->cl, "\n");
	if(g_nbrs == 0)
	{
		tyflow_cmdline_printf(cbt->cl, "no bridges.\n");
		return 0;
	}
	tyflow_cmdline_printf(cbt->cl, "bridge name        bridge id        STP enabled        interfaces \n");
	list_for_each_entry(br, &g_br_list, br_list){
		tyflow_cmdline_printf(cbt->cl, "%s\n",  br->dev->name);
		list_for_each_entry(br_port, &br->port_list, list){
			//tyflow_cmdline_printf(cbt->cl, "%70s\n",  br_port->dev->name);
			tyflow_cmdline_printf(cbt->cl, "													   %s\n", br_port->dev->name);
		}
	}

	tyflow_cmdline_printf(cbt->cl, "\n");
	return err;
}

static int
set_br_cli(cmd_blk_t *param)
{

	int err = EDPVS_INVAL;
	const char *brName = param->string[0];
	const char *ifName = param->string[1];
 
	struct netif_port *dev;
	struct netif_port *slave;

	if (!strlen(brName)) {
		tyflow_cmdline_printf(param->cl,  "%s:null name\n", brName);
		return EDPVS_INVAL;
	}

	if (param->mode == MODE_DO){
		if (!strlen(ifName)){
			err = br_add_bridge(brName);
			if (err != EDPVS_OK){
				tyflow_cmdline_printf(param->cl, "create br failed, err: %d\n", err);
			}
		}
		else
		{
			dev = netif_port_get_by_name(brName);
			if (!dev || dev->type != PORT_TYPE_BRIDGE){
				tyflow_cmdline_printf(param->cl, "br is not exist: %s\n", brName);
				return EDPVS_NOTEXIST;
			}
			
			slave = netif_port_get_by_name(ifName);
			if (!slave){
				tyflow_cmdline_printf(param->cl, "port is not exist: %s\n", ifName);
				return EDPVS_NOTEXIST;
			}

			err = dev->netif_ops->op_add_slave(dev, slave);
			if (err != EDPVS_OK){
				tyflow_cmdline_printf(param->cl, "set port to br err: %d\n", err);
			}
		}
	}else{
		if (!strlen(ifName)){
			err = br_del_bridge(brName);
			if (err != EDPVS_OK){
				tyflow_cmdline_printf(param->cl, "delete br failed, err: %d\n", err);
			}
		}
		else
		{
			dev = netif_port_get_by_name(brName);
			if (!dev || dev->type != PORT_TYPE_BRIDGE){
				tyflow_cmdline_printf(param->cl, "br is not exist: %s\n", brName);
				return EDPVS_NOTEXIST;
			}
			
			slave = netif_port_get_by_name(ifName);
			if (!slave){
				tyflow_cmdline_printf(param->cl, "port is not exist: %s\n", ifName);
				return EDPVS_NOTEXIST;
			}

			err = dev->netif_ops->op_del_slave(dev, slave);
			if (err != EDPVS_OK){
				tyflow_cmdline_printf(param->cl, "del port to br err: %d\n", err);
			}
		}
	}
	
   	return err;
}

static int
show_fdb_entrys_cli(cmd_blk_t *cbt)
{
	int err = EDPVS_INVAL;
	struct netif_port *dev;
	struct net_bridge *br;
	struct rte_hash *hashs;
	const char *brName = cbt->string[0];
	dev = netif_port_get_by_name(brName);
	if (!dev || dev->type != PORT_TYPE_BRIDGE){
		tyflow_cmdline_printf(cbt->cl, "br is not exist: %s\n", brName);
		return EDPVS_NOTEXIST;
	}

	br = netif_priv(dev);
	assert(br);

	hashs = br->fdb.fdb_hash;
	assert(hashs);
	
	show_all_fdb_entrys(hashs);
    return err;
}


EOL_NODE_NEED_MAIN_EXEC(brctl_eol, set_br_cli);
VALUE_NODE(ifName, brctl_eol, none, "if-name", 2, STR);
KW_NODE(if, ifName, brctl_eol, "if", "the port of bridge");
VALUE_NODE(brName, if, none, "br-name", 1, STR);
KW_NODE(br, brName, none, "br", "the bridge ctl");
KW_NODE(brctl, br, none, "brctl", "the br apps");

EOL_NODE_NEED_MAIN_EXEC(br_show_fdb_eol, show_fdb_entrys_cli);
EOL_NODE_NEED_MAIN_EXEC(br_show_detail_eol, br_detail_get_cli);
EOL_NODE_NEED_MAIN_EXEC(br_show_stat_eol, br_stat_get_cli);
EOL_NODE_NEED_MAIN_EXEC(br_show_all, br_show_all_eol);
KW_NODE_WHICH(br_show_stat, br_show_stat_eol, none, "pack-statictis", "the bridge details as packets etc.", 1, 3);
KW_NODE_WHICH(br_show_detail, br_show_detail_eol, br_show_stat, "br-detail", "the bridge details as ports etc.", 1, 2);
KW_NODE_WHICH(br_show_fdb, br_show_fdb_eol, br_show_detail, "fdb-entrys", "the bridge fdb hash entrys", 1, 1);
VALUE_NODE(br_show_name, br_show_fdb, br_show_all, "br-name, or enter for show alls", 1, STR);
KW_NODE(br_show, br_show_name, none, "br", "the bridge ");
KW_NODE(fdb_show, br_show, none, "brctl", "the br apps");

static void
br_cli_init(void)
{
    add_set_cmd(&cnode(brctl));
	add_get_cmd(&cnode(fdb_show));
}

int br_init(void)
{
    int err;
	
    err = sockopt_register(&br_sockopts);
    if (err != EDPVS_OK)
        return err;

	br_cli_init();

	bridge_global_list_init();

	err = br_fdb_init();
	if (err)
		return err;

	err = register_netdevice_notifier(&br_device_notifier);
    if (err)
        return err;
	
    return EDPVS_OK;
}

