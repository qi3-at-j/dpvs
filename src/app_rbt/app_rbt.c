#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>   
#include <fcntl.h> 
#include "cJSON.h"
#include "../ipvs/libconhash/util_rbtree.h"
#include "app_rbt.h"

static char *app_filename = "src/app_rbt/app_database";

#define APP_RBT_MEMZONE_NAME  "app-rbt-mz"
#define APP_RBT_MEMPOOL_NAME  "app-rbt-mp"
#define APP_RBT_MEMPOOL_SIZE   4096

typedef struct tagAppRbtNode
{
    util_rbtree_node_t stNode;
    unsigned int uiID;
}APP_RBT_NODE_S;

typedef struct tagAppRbtRoot
{
    util_rbtree_t stRoot;
    unsigned int uiCount;
    unsigned int already_init;
    struct rte_mempool *mp;
}APP_RBT_ROOT_S;

APP_RBT_ROOT_S *g_stAppRbtRoot;


static APP_RBT_NODE_S * _app_rbt_MallocNode(void)
{
    APP_RBT_NODE_S *pstAppRbtNode;

    if (likely(rte_mempool_get(g_stAppRbtRoot->mp, (void **)&pstAppRbtNode) == 0)) {
        return pstAppRbtNode;
    }

    return NULL;
}

static void App_Rbt_AddNode(unsigned int uiAppID, long lAppSubID)
{
    APP_RBT_NODE_S *pstAppRbtNode;
    if (NULL == util_rbtree_search(&g_stAppRbtRoot->stRoot, lAppSubID))
    {
        pstAppRbtNode =  _app_rbt_MallocNode();
        if (NULL != pstAppRbtNode)
        {
            pstAppRbtNode->uiID = uiAppID;
            pstAppRbtNode->stNode.key = lAppSubID;
            util_rbtree_insert(&g_stAppRbtRoot->stRoot, &pstAppRbtNode->stNode);
            g_stAppRbtRoot->uiCount++;
        }
        else
        {
            printf("Failed to get a APP_RBT_NODE_S.\n");
        }
    }
    else
    {
        printf("The same application SubID has different primary ids.\n");
    }

    return;
}
static void _app_rbt_cjsondata(cJSON *json)
{
    cJSON *pstHead, *SubID;
    unsigned int uiID = 0;
    bool bID = false;

    /* find "ID" */
    pstHead = json;
    while(pstHead)
    {
        if (pstHead->string && !strcasecmp(pstHead->string, "ID"))
        {
            //printf("\tID : %d\n", pstHead->valueint);
            uiID = pstHead->valueint;
            bID = true;
            break;
        }
        
        pstHead = pstHead->next;
    }

    /* if "ID" exist, then find "SubID" */
    if (true == bID)
    {
        pstHead = json;
        while(pstHead)
        {
            if (pstHead->string && !strcasecmp(pstHead->string, "SubID"))
            {
                //printf("\tSubID :");
                SubID = pstHead->child;
                while (SubID)
                {
                    //printf(" %d", SubID->valueint);
                    App_Rbt_AddNode(uiID, SubID->valueint);
                    SubID = SubID->next;
                }
                //printf("\n");
                break;
            }
            
            pstHead = pstHead->next;
        }
    }


    return;
}

static void _app_rbt_cjson(cJSON *json)
{
    while(json)
    {
        //printf("APP Name : %s\n", json->string);
        _app_rbt_cjsondata(json->child);
        json = json->next;
    }

    return;
}

static void _app_rbt_file2cjson(char *text)
{
    cJSON *json;
	
	json=cJSON_Parse(text);
	if (!json) 
    {
        printf("Error before file2json: [%s]\n",cJSON_GetErrorPtr());
    }
	else
	{
        _app_rbt_cjson(json->child);
		cJSON_Delete(json);
	}
}

/* Read a file, parse, render back, etc. */
static void _app_rbt_file(char *filename)
{
	FILE *file;
    long len;
    char *data;
	
	file=fopen(filename,"rb");
    if (file)
    {
        fseek(file,0,SEEK_END);
        len=ftell(file);
        fseek(file,0,SEEK_SET);
    }
    else
    {
        printf("Failed to open file %s.\n", filename);
        return;
    }
    
	data=(char*)malloc(len+1);
    if (data)
    {
        fread(data,1,len,file);
        _app_rbt_file2cjson(data);
	    free(data);
    }

    fclose(file);

	return;
}

void App_Rbt_Process(void)
{
    if (g_stAppRbtRoot->already_init) {
        printf("app rbt already inited.\n");
        printf("app rbt avail_cnt: %u in_use:%u.\n",
                rte_mempool_avail_count(g_stAppRbtRoot->mp),
                rte_mempool_in_use_count(g_stAppRbtRoot->mp));
        return;
    }

    if((access(app_filename,F_OK))!=-1)
    {
        _app_rbt_file(app_filename);
    }
    else
    {
        printf("%s file %s not found.\n", __func__, app_filename);
    }

    printf("app rbt avail_cnt: %u in_use:%u.\n",
            rte_mempool_avail_count(g_stAppRbtRoot->mp),
            rte_mempool_in_use_count(g_stAppRbtRoot->mp));

    g_stAppRbtRoot->already_init = 1;
	return;
}

void App_Rbt_Fini()
{
    APP_RBT_NODE_S *pstAppRbtNode;

    while(!util_rbtree_isempty(&g_stAppRbtRoot->stRoot))
    {
        util_rbtree_node_t *rbnode = g_stAppRbtRoot->stRoot.root;
        util_rbtree_delete(&g_stAppRbtRoot->stRoot, rbnode);
        pstAppRbtNode = container_of(rbnode, APP_RBT_NODE_S, stNode);
        rte_mempool_put(g_stAppRbtRoot->mp, pstAppRbtNode);
    }

    return;
}

/*
* return 0:Invalid values
*/
unsigned int App_Rbt_GetAppIDBySubID(unsigned int uiSubID)
{
    long lSubID = (long)uiSubID & 0xFFFF;
    util_rbtree_node_t* rbnode;
    APP_RBT_NODE_S *pstAppRbtNode = NULL;
    rbnode = util_rbtree_search(&g_stAppRbtRoot->stRoot, lSubID);
    if (rbnode)
    {
        pstAppRbtNode = container_of(rbnode, APP_RBT_NODE_S, stNode);
        return pstAppRbtNode->uiID;
    }
    else
    {
        return 0;
    }
}

int32_t App_Rbt_Init(void)
{
    struct rte_mempool *mp;
    const struct rte_memzone *mz;

    mz = rte_memzone_lookup(APP_RBT_MEMZONE_NAME);
    if (!mz) {
        mz = rte_memzone_reserve(APP_RBT_MEMZONE_NAME, sizeof(APP_RBT_ROOT_S), SOCKET_ID_ANY, 0);
        if (!mz) {
            RTE_LOG(ERR, EAL, "%s reserve mem failed.\n", __func__);
            return -1;
        }
    }

    g_stAppRbtRoot = mz->addr;

    util_rbtree_init(&g_stAppRbtRoot->stRoot);
    g_stAppRbtRoot->uiCount = 0;

    mp = rte_mempool_lookup(APP_RBT_MEMPOOL_NAME);
    if (!mp) {
        mp = rte_mempool_create(APP_RBT_MEMPOOL_NAME,
                APP_RBT_MEMPOOL_SIZE, sizeof(APP_RBT_NODE_S),
                0, 0,
                NULL, NULL,
                NULL, NULL,
                SOCKET_ID_ANY, 0);
        if (!mp) {
            RTE_LOG(ERR, EAL, "%s create mempool failed.\n", __func__);
            return -1;
        }
    }

    g_stAppRbtRoot->mp = mp;

    return 0;
}

