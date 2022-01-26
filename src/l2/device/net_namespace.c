
#include <stdio.h>
#include "list.h"
#include "netif.h"
#include "../include/net_namespace.h"
#include "../include/dev.h"


struct net init_net = {
	.dev_base_head = LIST_HEAD_INIT(init_net.dev_base_head),
};

struct list_head net_namespace_list = {
    .next = &net_namespace_list,
    .prev = &net_namespace_list,
};


void register_namespace_net(struct netif_port* dev){
    struct net *net = dev_net(dev);
    
    list_add_tail_rcu(&dev->dev_list, &net->dev_base_head);
}

void unregister_namespace_net(struct netif_port* dev){
    list_del_rcu(&dev->dev_list);
}

