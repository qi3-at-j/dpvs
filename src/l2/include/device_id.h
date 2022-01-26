#ifndef    __DEVICE_ID_H__
#define    __DEVICE_ID_H__

#define PID_MAX 1024
#define PID_DELAY_BUFF_SIZE 8192
#define PID_ASSERT(exp) RTE_VERIFY(exp)

struct PID_Pool
{	
    struct rte_bitmap *bmp;
    void   *bitMapMem;
    uint32_t  pid_cnt;
    uint32_t *puiDelayIDBuff;//��������
    uint16_t usCurPos; //��������ǰλ�ã�
    rte_rwlock_t stRWLock;
};


#endif  /*__DEVICE_ID_H__*/

