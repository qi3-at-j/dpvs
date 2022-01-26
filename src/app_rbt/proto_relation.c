#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>   
#include <fcntl.h> 
#include <stdint.h>
#include <assert.h>

//#include "dpdk.h"
//#include <rte_mempool.h>

#include "cJSON.h"

#include "proto_relation.h"
#include "../ipvs/libconhash/util_rbtree.h"

#define PROTO_RELATION_MEMZONE_NAME  "apr-proto-relation-mz"
#define PROTO_RELATION_MEMPOOL_NAME  "apr-proto-relation-mp"
#define PROTO_RELATION_MEMPOOL_SIZE   4096

typedef struct _proto_relation_ctl {
    util_rbtree_t proto_rbtree;
    struct rte_mempool *mp;
    uint32_t already_init;
} proto_relation_ctl;

static proto_relation_ctl *proto_relation;
static char *proto_filename = "./etc/proto_relation";

static int add_to_tree(uint32_t app_id, uint32_t l5_id)
{
    util_rbtree_node_t *rbnode = NULL;

    if (unlikely(rte_mempool_get(proto_relation->mp, (void **)&rbnode) != 0)) {
        RTE_LOG(ERR, EAL, "%s proto relation mempool get failed.\n", __func__);
        return -1;
    }

    if (rbnode != NULL) {
        rbnode->key = (long)app_id;
        *(uint32_t *)&rbnode->data = l5_id;

        util_rbtree_node_t *node = util_rbtree_search(&proto_relation->proto_rbtree, app_id);
        if (!node) {
            util_rbtree_insert(&proto_relation->proto_rbtree, rbnode);
        } else {
            rte_mempool_put(proto_relation->mp, rbnode);
            //printf("app_id:%d l5_id:%d-%d already exist.\n", app_id, l5_id, *(uint32_t *)&node->data);
        }

        return 0;
    }

    RTE_LOG(ERR, EAL, "%s proto relation mempool get failed.\n", __func__);

    return -1;
}

static void proto_json_parse(cJSON *json)
{
    cJSON *object;
    cJSON *node;
    uint32_t app_id;
    uint32_t l5_id;

    while (json) {
        if (cJSON_Object == json->type) {
            if (0 == strcmp(json->string, "l4")) {
                printf("skip cJSON_Object name:%s\n", json->string);
                json = json->next;
                continue;
            }

            printf("proc cJSON_Object name:%s\n", json->string);

            object = json->child;
            while (object) {
                if (cJSON_Array == object->type) {
                    l5_id = atoi(object->string);
                    node = object->child;

                    while (node) {
                        assert(cJSON_Number == node->type);
                        app_id = node->valueint;

                        add_to_tree(app_id, l5_id);
                        node = node->next;
                    }
                }

                object = object->next;
            }
        }

        json = json->next;
    }

    return;
}

static void proto_file2json(char *text)
{
    cJSON *json;

    json = cJSON_Parse(text);
    if (!json) {
        printf("Error before file2json: [%s]\n", cJSON_GetErrorPtr());
    } else {
        assert(!json->next);
        assert(!json->prev);

        proto_json_parse(json->child);

        cJSON_Delete(json);
    }

    return;
}

uint32_t proto_relation_process(void)
{
    FILE *fd;
    long len;
    char *data;

    if (proto_relation->already_init) {
        printf("proto relation already inited.\n");
        printf("old proto relation avail_cnt: %u in_use:%u.\n",
                rte_mempool_avail_count(proto_relation->mp),
                rte_mempool_in_use_count(proto_relation->mp));
        return 0;
    }

    if (access(proto_filename, F_OK) < 0) {
        printf("file %s not found.\n", proto_filename);
        return -1;
    }

    fd = fopen(proto_filename, "r");
    if (!fd) {
        printf("Failed to open file %s.\n", proto_filename);
        return -1;
    }

    fseek(fd, 0, SEEK_END);
    len = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    data = malloc(len + 1);
    if (data) {
        fread(data, 1, len, fd);

        proto_file2json(data);

        free(data);
    }

    fclose(fd);

    printf("proto relation avail_cnt: %u in_use:%u.\n",
            rte_mempool_avail_count(proto_relation->mp),
            rte_mempool_in_use_count(proto_relation->mp));

    proto_relation->already_init = 1;

    return 0;
}

uint32_t proto_relation_get(uint32_t app_id)
{
    util_rbtree_node_t* rbnode;

    rbnode = util_rbtree_search(&proto_relation->proto_rbtree, app_id & 0xFFFF);
    if (rbnode) {
        return *(uint32_t *)&rbnode->data;
    }

    return 0;
}

void proto_relation_fini(void)
{
    util_rbtree_node_t *rbnode;

    while (!util_rbtree_isempty(&proto_relation->proto_rbtree)) {
        rbnode = proto_relation->proto_rbtree.root;
        util_rbtree_delete(&proto_relation->proto_rbtree, rbnode);

        rte_mempool_put(proto_relation->mp, rbnode);
    }

    return;
}

int32_t proto_relation_init(void)
{
    struct rte_mempool *mp;
    const struct rte_memzone *mz;

    mz = rte_memzone_lookup(PROTO_RELATION_MEMZONE_NAME);
    if (!mz) {
        mz = rte_memzone_reserve(PROTO_RELATION_MEMZONE_NAME, sizeof(proto_relation_ctl), SOCKET_ID_ANY, 0);
        if (!mz) {
            RTE_LOG(ERR, EAL, "%s reserve mem failed.\n", __func__);
            return -1;
        }
    }

    proto_relation = mz->addr;

    util_rbtree_init(&proto_relation->proto_rbtree);

    mp = rte_mempool_lookup(PROTO_RELATION_MEMPOOL_NAME);
    if (!mp) {
        mp = rte_mempool_create(PROTO_RELATION_MEMPOOL_NAME,
                PROTO_RELATION_MEMPOOL_SIZE, sizeof(util_rbtree_node_t),
                0, 0,
                NULL, NULL,
                NULL, NULL,
                SOCKET_ID_ANY, 0);
        if (!mp) {
            RTE_LOG(ERR, EAL, "%s create mempool failed.\n", __func__);
            return -1;
        }
    }

    proto_relation->mp = mp;

    return 0;
}

