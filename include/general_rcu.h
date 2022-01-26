
#ifndef __DPVS_GENERAL_RCU_H__
#define __DPVS_GENERAL_RCU_H__

#include<rte_atomic.h>
#define RTE_LOGTYPE_RCU RTE_LOGTYPE_USER1

#define DPVS_GENERAL_RCU_DQ_RECLAIM_THD	1//64
#define DPVS_GENERAL_RCU_DQ_RECLAIM_MAX	16
#define DPVS_GENERAL_RCU_DQ_SIZE		1024
#define RCU_DELAY_LOOP_INTERVAL 		1024
#define RCU_LCORE_JOB_MAX          		1

//目前还没找到实现这哥俩的方式，先空操作吧

#define __force 
#define __rcu

#define RCU_INIT_POINTER(p, v) \
	do { \
		p = (typeof(*v) __force __rcu *)(v); \
	} while (0)


#define __rcu_assign_pointer(p, v, space) \
		do { \
			rte_smp_wmb(); \
			(p) = (typeof(*v) __force space *)(v); \
		} while (0)

#define rcu_assign_pointer(p, v) \
	__rcu_assign_pointer((p), (v), __rcu)


#ifdef __CHECKER__
#define rcu_dereference_sparse(p, space) \
        ((void)(((typeof(*p) space *)p) == p))
#else /* #ifdef __CHECKER__ */
#define rcu_dereference_sparse(p, space)
#endif /* #else #ifdef __CHECKER__ */

#ifndef ACCESS_ONCE
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#endif

#define __rcu_access_pointer(p, space) \
	({ \
		typeof(*p) *_________p1 = (typeof(*p)*__force )ACCESS_ONCE(p); \
		rcu_dereference_sparse(p, space); \
		((typeof(*p) __force *)(_________p1)); \
	})

#define rcu_access_pointer(p) __rcu_access_pointer((p), __rcu)

#define rcu_dereference(p)   (p) //目前是空操作，待完善，因为除了alpha的架构，其他架构没有问题�?


#define smp_read_barrier_depends()	do {} while (0)
#define rcu_lockdep_assert(c, s) do { } while (0)
#define rcu_read_lock_held()  do { } while (0)

#define __rcu_dereference_check(p, c, space) \
        ({ \
            typeof(*p) *_________p1 = (typeof(*p)*__force )ACCESS_ONCE(p); \
            rcu_lockdep_assert(c, "suspicious rcu_dereference_check()" \
                          " usage"); \
            rcu_dereference_sparse(p, space); \
            smp_read_barrier_depends(); \
            ((typeof(*p) __force  *)(_________p1)); \
        })

#define rcu_dereference_check(p, c) \
	__rcu_dereference_check((p), rcu_read_lock_held() || (c), __rcu)

#define rcu_dereference_raw(p) rcu_dereference_check(p, 1) 

/** RCU reclamation modes */
enum dpvs_general_qsbr_mode {
	/** Create defer queue for reclaim. */
	RTE_GEN_QSBR_MODE_DQ = 0,
	/** Use blocking mode reclaim. No defer queue created. */
	RTE_GEN_QSBR_MODE_SYNC
};

struct dpvs_general_rcu_config {
	struct rte_rcu_qsbr *v;	/* RCU QSBR variable. */
	/* Mode of RCU QSBR. RTE_LPM_QSBR_MODE_xxx
	 * '0' for default: create defer queue for reclaim.
	 */
	enum dpvs_general_qsbr_mode mode;
	uint32_t dq_size;	/* RCU defer queue size.
				 * default: lpm->number_tbl8s.
				 */
	uint32_t reclaim_thd;	/* Threshold to trigger auto reclaim. */
	uint32_t reclaim_max;	/* Max entries to reclaim in one go.
				 * default: RTE_LPM_RCU_DQ_RECLAIM_MAX.
				 */
};

struct rcu_status{
	//目前就只有一个errcode
	int errcode;
};

typedef void (*RCU_DEFER_FREE_FN)(void *e);

struct gener_rcu_defer_free_st{
	RCU_DEFER_FREE_FN fn;
	void *data;
};

int RCU_init(void);
int RCU_start(void);
int general_rcu_qsbr_dq_enqueue(void *data, RCU_DEFER_FREE_FN fn);
inline void general_rcu_qsbr_synchronize(unsigned int thread_id);




#endif

