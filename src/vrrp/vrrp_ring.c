
#include "vrrp_ring.h"

struct rte_ring *g_stVrrpRingRP = 0;
struct rte_ring *g_stVrrpRingSP = 0;

static unsigned int vrrp_ring_write(struct rte_ring *vrrp_ring, unsigned int uiExpireNum, void **pVrrpMbuf)
{
    unsigned int  uiNum = 0;

    if ((vrrp_ring == 0) || rte_ring_full(vrrp_ring))
    {
        return 0;
    }

    uiNum = rte_ring_mp_enqueue_burst_elem(vrrp_ring, pVrrpMbuf, VRRP_RING_ESIZE, uiExpireNum, 0);
    return uiNum;
}

static unsigned int vrrp_ring_read(struct rte_ring *vrrp_ring, unsigned int uiExpireNum, void **pVrrpMbuf)
{
    unsigned int  uiNum = 0;

    if ((vrrp_ring == 0) || rte_ring_empty(vrrp_ring))
    {
        return 0;
    }

    uiNum = rte_ring_mc_dequeue_burst_elem(vrrp_ring, pVrrpMbuf, VRRP_RING_ESIZE, uiExpireNum, 0);
    return uiNum;
}

/*
*  @uiNum:     Expected number of enqueue elements
*  @pVrrpMbuf: Array of Pointers to VRRP packets
*  @return:    Actual number of enqueue, 0 indicates that no data enqueue
*/
unsigned int vrrp_ring_enqueue(unsigned int uiExpireNum, void *pVrrpMbuf[])
{
    return vrrp_ring_write(g_stVrrpRingRP, uiExpireNum, pVrrpMbuf);
}

/*
*  @uiNum:     Expected number of dequeue elements
*  @pVrrpMbuf: Array of Pointers to VRRP packets
*  @return:    Actual number of dequeue, 0 indicates that no data dequeue
*/
unsigned int vrrp_ring_dequeue(unsigned int uiExpireNum, void *pVrrpMbuf[])
{
    return vrrp_ring_read(g_stVrrpRingSP, uiExpireNum, pVrrpMbuf);
}

/*
*  @uiNum:     Expected number of enqueue elements
*  @pVrrpMbuf: Array of Pointers to VRRP packets
*  @return:    Actual number of enqueue, 0 indicates that no data enqueue
*/
unsigned int vrrp_ring_send(unsigned int uiExpireNum, void *pVrrpMbuf[])
{
    return vrrp_ring_write(g_stVrrpRingSP, uiExpireNum, pVrrpMbuf);
}

/*
*  @uiNum:     Expected number of dequeue elements
*  @pVrrpMbuf: Array of Pointers to VRRP packets
*  @return:    Actual number of dequeue, 0 indicates that no data dequeue
*/
unsigned int vrrp_ring_receive(unsigned int uiExpireNum, void *pVrrpMbuf[])
{
    return vrrp_ring_read(g_stVrrpRingRP, uiExpireNum, pVrrpMbuf);
}


static int vrrp_ring_create(void)
{
    g_stVrrpRingRP = rte_ring_create_elem(VRRP_RING_RP, VRRP_RING_ESIZE, VRRP_RING_SIZE, SOCKET_ID_ANY, 0);
    g_stVrrpRingSP = rte_ring_create_elem(VRRP_RING_SP, VRRP_RING_ESIZE, VRRP_RING_SIZE, SOCKET_ID_ANY, 0);
    if ((g_stVrrpRingRP == NULL)  || (g_stVrrpRingSP == NULL))
    {
        if (g_stVrrpRingRP != NULL)
        {
            rte_ring_free(g_stVrrpRingRP);
        }

        if (g_stVrrpRingSP != NULL)
        {
            rte_ring_free(g_stVrrpRingSP);
        }

        return -1;
    }

    return 0;
    
}

int vrrp_ring_init(void)
{
	int32_t rc;

	rc = vrrp_ring_create();
    
	return rc;
}

void vrrp_ring_destory(void)
{
    struct rte_ring *ring;
    ring = rte_ring_lookup(VRRP_RING_RP);
    if (ring)
    {
        rte_ring_free(ring);
    }

    ring = rte_ring_lookup(VRRP_RING_SP);
    if (ring)
    {
        rte_ring_free(ring);
    }

    return;
}

void vrrp_ring_show(char *pstr)
{
    struct rte_ring *ring;

    if (pstr != NULL)
    {
        ring = rte_ring_lookup(pstr);
        if (ring)
        {
            rte_ring_dump(stdout, ring);
        }
        return;
    }

    ring = rte_ring_lookup(VRRP_RING_RP);
    if (ring)
    {
        rte_ring_dump(stdout, ring);
    }

    ring = rte_ring_lookup(VRRP_RING_SP);
    if (ring)
    {
        rte_ring_dump(stdout, ring);
    }
    return;
}
