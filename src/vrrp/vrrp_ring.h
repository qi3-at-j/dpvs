#ifndef _VRRP_RING_H_
#define _VRRP_RING_H_

#ifdef __cplusplus
extern "C"{
#endif

#include <rte_ring.h>
#include <rte_ring_elem.h>

extern struct rte_ring *g_stVrrpRingRP;
extern struct rte_ring *g_stVrrpRingSP;


#define VRRP_RING_SIZE   512    /* The total number of elements in the ring, it must be a power of two */
#define VRRP_RING_ESIZE  8       /* Each element in the ring takes up 8 bytes */

#define VRRP_RING_RP  "vrrp_ring_receive_packet"   /* receive vrrp packet ring queue */
#define VRRP_RING_SP  "vrrp_ring_send_packet"      /* send vrrp packet ring queue */

/*
*  @uiNum:     Expected number of enqueue elements
*  @pVrrpMbuf: Array of Pointers to VRRP packets
*  @return:    Actual number of enqueue, 0 indicates that no data enqueue
*/
extern unsigned int vrrp_ring_enqueue(unsigned int uiExpireNum, void *pVrrpMbuf[]);

/*
*  @uiNum:     Expected number of dequeue elements
*  @pVrrpMbuf: Array of Pointers to VRRP packets
*  @return:    Actual number of dequeue, 0 indicates that no data dequeue
*/

extern unsigned int vrrp_ring_dequeue(unsigned int uiExpireNum, void *pVrrpMbuf[]);

/*
*  @uiNum:     Expected number of enqueue elements
*  @pVrrpMbuf: Array of Pointers to VRRP packets
*  @return:    Actual number of enqueue, 0 indicates that no data enqueue
*/

extern unsigned int vrrp_ring_send(unsigned int uiExpireNum, void *pVrrpMbuf[]);

/*
*  @uiNum:     Expected number of dequeue elements
*  @pVrrpMbuf: Array of Pointers to VRRP packets
*  @return:    Actual number of dequeue, 0 indicates that no data dequeue
*/
extern unsigned int vrrp_ring_receive(unsigned int uiExpireNum, void *pVrrpMbuf[]);

extern int  vrrp_ring_init(void);
extern void vrrp_ring_destory(void);
extern void vrrp_ring_show(char *);

#ifdef __cplusplus
}
#endif

#endif

