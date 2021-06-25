#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>


#include "dpdk.h"
#include "ctrl.h"
#include "scheduler.h"
#include "conf/common.h"
#include "general_rcu.h"

static struct rte_rcu_qsbr *g_general_rv = NULL;
static struct dpvs_general_rcu_config g_rcu_cfg = {0};
static struct rte_rcu_qsbr_dq *g_eneral_dq = NULL; /* RCU QSBR defer queue. */
static bool gener_rcu_switch = false;
/*********************************************数据申请与释放*********************************************************/

static void
general_rcu_qsbr_free_resource(void *p, void *element, unsigned int n)
{
	struct gener_rcu_defer_free_st *gener_elem = NULL; 

	RTE_SET_USED(n);
	RTE_SET_USED(p);//暂时是空，没用；
	
	gener_elem = (struct gener_rcu_defer_free_st *)element;

	gener_elem->fn(gener_elem->data);

	rte_free(element);
}

int 
general_rcu_qsbr_dq_enqueue(void *data, RCU_DEFER_FREE_FN fn)
{
	int err = 0;
	struct gener_rcu_defer_free_st *gener_elem = NULL; 
	
	assert(data);
	assert(fn);
	
	gener_elem = rte_malloc("gener_rcu_defer_free_struct", sizeof(*gener_elem), 0);
	if(gener_elem == NULL){
		RTE_LOG(ERR, RCU, "%s: fail to create  gener_rcu_defer_free_struct.\n", __func__);
		return EDPVS_NOMEM;
	}
	
	gener_elem->data = data;
	gener_elem->fn = fn;

	err = rte_rcu_qsbr_dq_enqueue(g_eneral_dq,  gener_elem);
	if(err != 0){
		RTE_LOG(ERR, RCU, "%s: fail to rte_rcu_qsbr_dq_enqueue.\n", __func__);
		return err;
	}
	
	printf("general_rcu_qsbr_dq_enqueue success!\n");
	return err;
}


inline void general_rcu_qsbr_synchronize(unsigned int thread_id){
	rte_rcu_qsbr_synchronize(g_general_rv, thread_id);
	return;
}
/*********************************************初始化相关*********************************************************/
static int general_rcu_msg_seq(void)
{
    static uint32_t seq = 0;

    return seq++;
}

static int slave_gener_rcu_reader_register_and_online(void){
	int err = 0;
	static bool on = false;

	lcoreid_t cid = rte_lcore_id();
	if(on == false){
		err = rte_rcu_qsbr_thread_register(g_general_rv, cid);
		if(err != 0)
			return err;
		
		rte_rcu_qsbr_thread_online(g_general_rv, cid);
		on = true;
		gener_rcu_switch = true;
	}

	return EDPVS_OK;
}

static int all_slave_reader_register_and_online(struct dpvs_msg *msg){
	int err = 0;
	static bool on = false;
	struct rcu_status *stats = NULL;
	assert(msg);

	lcoreid_t cid = rte_lcore_id();
	
	if(on == false){
		/*gener rcu注册*/
		err =slave_gener_rcu_reader_register_and_online();
		if(err != 0)
			goto done;
		
		/*fdb rcu 注册*/
		//err = slave_fdb_rcu_reader_register_and_online();
		if(err != 0)
			goto done;
	}

done:
    stats = msg_reply_alloc(sizeof(*stats));
    if (!stats)
        return EDPVS_NOMEM;

   	stats->errcode = err;
    msg->reply.len = sizeof(*stats);
    msg->reply.data = stats;
	return EDPVS_OK;
}

static inline void gener_rcu_report_quiescent(lcoreid_t cid){

	if (gener_rcu_switch == true){
		rte_rcu_qsbr_quiescent(g_general_rv, cid);
	}

	return;
}

/*周期性报告静默期的函数，此函数由从线程来执行。*/
static void all_rcu_report_quiescent(void *args){

	lcoreid_t cid = rte_lcore_id();

	/*报告gener qsbr状态*/
	gener_rcu_report_quiescent(cid);

	/*报告fdb qsbr状态*/
	//fdb_rcu_report_quiescent(cid);

	return;
}

static struct dpvs_msg_type general_rcu_stats_msg = {
    .type           = MSG_TYPE_GENER_RCU,
    .prio           = MSG_PRIO_LOW,
    .unicast_msg_cb = all_slave_reader_register_and_online,
};

static struct dpvs_lcore_job rcu_job = {
        .name = "rcu_report_quiescent",
        .type = LCORE_JOB_SLOW,
        .func = all_rcu_report_quiescent,
        .skip_loops = RCU_DELAY_LOOP_INTERVAL,
};

static int general_rcu_qsbr_add_dq(struct dpvs_general_rcu_config *cfg)
{
	int err = 0;
	struct rte_rcu_qsbr_dq_parameters params = {0};
	char rcu_dq_name[RTE_RCU_QSBR_DQ_NAMESIZE];
	void *temp = NULL;
	
	if (cfg == NULL) {
		return EDPVS_INVAL;
	}

	if (cfg->mode == RTE_GEN_QSBR_MODE_SYNC) {
		/* No other things to do. */
	} else if (cfg->mode == RTE_GEN_QSBR_MODE_DQ) {
		/* Init QSBR defer queue. */
		snprintf(rcu_dq_name, sizeof(rcu_dq_name), "dpvs_general_rcu");
		
		params.name = rcu_dq_name;
		params.size = cfg->dq_size;
		params.trigger_reclaim_limit = cfg->reclaim_thd;
		params.max_reclaim_size = cfg->reclaim_max;;
		params.esize = sizeof(struct gener_rcu_defer_free_st);
		params.free_fn = general_rcu_qsbr_free_resource;
		params.p = NULL;
		params.v = cfg->v;
		
		g_eneral_dq = rte_rcu_qsbr_dq_create(&params);
		if (g_eneral_dq == NULL) {
			RTE_LOG(ERR, RCU, "gener_RCU defer queue creation failed\n");
			return EDPVS_INVAL;
		}
	} else {
		return EDPVS_INVAL;
	}
	return 0;
}

int RCU_init(void){
	int err = 0;
	size_t sz;


	uint32_t nb_lcores = netif_get_all_enabled_cores_nb();

	//0.初始化一个qsbr
	sz = rte_rcu_qsbr_get_memsize(nb_lcores);
	g_general_rv = (struct rte_rcu_qsbr *)rte_zmalloc("g_general_rv", sz,
					RTE_CACHE_LINE_SIZE);
	rte_rcu_qsbr_init(g_general_rv, nb_lcores);

	//1.注册群发消息，用于slave执行注册和上线函数;
	err = msg_type_mc_register(&general_rcu_stats_msg);
    if (err != EDPVS_OK) {
         RTE_LOG(ERR, RCU, "%s: fail to register msg.\n", __func__);
         goto done;
    }

	//2.注册从线程的循环报告静默期函数;
	if ((err = dpvs_lcore_job_register(&rcu_job, LCORE_ROLE_FWD_WORKER)) != EDPVS_OK)
        goto done;

	//3.初始化qsbr 全局配置;
	g_rcu_cfg.v = g_general_rv;
	g_rcu_cfg.mode = RTE_GEN_QSBR_MODE_DQ;
	g_rcu_cfg.dq_size = DPVS_GENERAL_RCU_DQ_SIZE;
	g_rcu_cfg.reclaim_thd = DPVS_GENERAL_RCU_DQ_RECLAIM_THD;
	g_rcu_cfg.reclaim_max = DPVS_GENERAL_RCU_DQ_RECLAIM_MAX;

	//4.根据配置申请一个qsbr dq
	if (general_rcu_qsbr_add_dq(&g_rcu_cfg) != 0) {
		printf("variable assignment failed\n");
		err = EDPVS_INVAL;
		goto done;
	}

done:
	return err;
}


int RCU_start(void){
	int err = 0;
	int errcode = 0;
	struct dpvs_msg * msg = NULL;
	struct dpvs_msg * reply = NULL;
	struct dpvs_multicast_queue *replies = NULL;
	lcoreid_t cid;

	cid = rte_lcore_id();
	assert(cid == rte_get_master_lcore());

	//5.给从线程发消息，slave执行注册和上线函数；
	msg = msg_make(MSG_TYPE_GENER_RCU, general_rcu_msg_seq(), DPVS_MSG_MULTICAST, cid, 0, NULL);
	if (unlikely(msg == NULL)) {
		RTE_LOG(ERR, RCU, "%s: fail to make msg -- %s\n",
				__func__, dpvs_strerror(err));
		err = EDPVS_NOMEM;
		goto done;
	}

	err = multicast_msg_send(msg, 0, &replies);
	if (err != EDPVS_OK) {
		RTE_LOG(ERR, RCU, "%s: send msg: %s\n", __func__, dpvs_strerror(err));
		goto ret1;
	}

	//6.如果有一个执行得不成功全局rcu都算失败
	list_for_each_entry(reply, &replies->mq, mq_node) {
		struct rcu_status *stats = (struct rcu_status *)reply->data;
		if(stats->errcode != EDPVS_OK){
			err = stats->errcode;
			goto ret1;
		}

		printf("all replay is ok! \n");
	}

ret1:
	msg_destroy(&msg);
done:
	return err;
}


