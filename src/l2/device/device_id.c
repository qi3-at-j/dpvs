
#include <stdio.h>
#include <string.h>
#include "dpdk.h"
#include <rte_bitmap.h>
#include "conf/common.h"
#include "../include/device_id.h"

static struct PID_Pool g_pid_pool = {
    .pid_cnt = PID_MAX,
};

/**
 * Bitmap memory  alloc
 *
 * @param phy_id
 *   Number of physics which shouldn't free,we mast alloc in init.
 * @return
 *   Bitmap memory footprint measured in bytes on success, 0 on error
 */
int
port_id_pool_init(int phy_nb)
{
	struct PID_Pool *pp = &g_pid_pool;
	uint32_t i, pid_bmp_size;

	rte_rwlock_init(&pp->stRWLock);
	pid_bmp_size = rte_bitmap_get_memory_footprint(pp->pid_cnt);
	pp->bitMapMem = rte_zmalloc("port_id_bitmap", pid_bmp_size,
				    RTE_CACHE_LINE_SIZE);
	if (pp->bitMapMem == NULL) {
		printf("[]failed to allocate bitmap size %u\n",
			     pid_bmp_size);
		return -1;
	}

    // Mark all pid as available.
	pp->bmp = rte_bitmap_init_with_all_set(pp->pid_cnt,
					pp->bitMapMem, pid_bmp_size);
	if (pp->bmp == NULL) {
		printf("failed to init pid bitmap\n");
		return -1;
	}

    for(i=0; i < phy_nb; i++){
         rte_bitmap_clear(pp->bmp, i);
    }
    //alloc delay buffer
    /*
    pp->puiDelayIDBuff = rte_zmalloc("port_id_delay_buff", PID_DELAY_BUFF_SIZE * sizeof(uint32_t),
				    RTE_CACHE_LINE_SIZE);
    if(pp->puiDelayIDBuff == NULL){
        printf("failed to alloc pid delay buffer\n");
        return -1;
    }*/

    
	return 0;
}

int
port_id_alloc(uint32_t *pid){
    int err = 0;
    uint32_t iidx = 0;
    uint64_t slab = 0;
    struct PID_Pool *pp = &g_pid_pool;

    rte_rwlock_write_lock(&pp->stRWLock);
    if (!rte_bitmap_scan(pp->bmp, &iidx, &slab)) {
		rte_rwlock_write_unlock(&pp->stRWLock);
		return EDPVS_FULL;
	}

    PID_ASSERT(slab);
	iidx += __builtin_ctzll(slab);
	PID_ASSERT(iidx != UINT32_MAX);

    rte_bitmap_clear(pp->bmp, iidx);

    rte_rwlock_write_unlock(&pp->stRWLock);
    *pid = iidx;
    return EDPVS_OK;
}

void 
port_id_free(uint32_t pid){
    struct PID_Pool *pp = &g_pid_pool;

    if (pid >= pp->pid_cnt) {
		printf("Invalid port id index %u", pid);
	} else {
		rte_rwlock_write_lock(&pp->stRWLock);
		rte_bitmap_set(pp->bmp, pid);
		rte_rwlock_write_unlock(&pp->stRWLock);
	}

    //delay xxx
}

void test_pid_func(void){
    int err = 0; 
    int i=0;
    uint32_t temp[PID_MAX];
    uint32_t pid = 0;

    printf("alloc %d times :\n", PID_MAX);
    for(i=0; i<PID_MAX; i++){
        err = port_id_alloc(&pid);
        if(0 != err){
            printf("alloc failed , err = %d\n", err);
        }
        printf("\t time %d is %d\n", i, pid);
        temp[i] = pid;
    }

    printf("free %d times :\n", PID_MAX);
    for(i=0; i<PID_MAX; i++){
        printf("\t free %d is %d\n", i, temp[i]);
        port_id_free(temp[i]);
    }

    printf("alloc %d times :\n", PID_MAX);
    for(i=0; i<PID_MAX; i++){
        err = port_id_alloc(&pid);
        if(0 != err){
            printf("alloc failed , err = %d\n", err);
        }
        printf("\t time %d is %d\n", i, pid);
        temp[i] = pid;
    }

   printf("free %d times :\n", PID_MAX);
    for(i=0; i<PID_MAX; i++){
        printf("\t free %d is %d\n", i, temp[i]);
        port_id_free(temp[i]);
    }

   printf("alloc-free %d times :\n", PID_MAX);
    for(i=0; i<PID_MAX; i++){
        err = port_id_alloc(&pid);
        printf("\t time %d is %d\n", i, pid);
        if(0 != err){
            printf("alloc failed , err = %d\n", err);
        }
        port_id_free(pid);
    }
}


