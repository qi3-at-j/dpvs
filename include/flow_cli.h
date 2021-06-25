
#define number_2_mask(x) ((2<<(x)-1)<<(32-(x)))
/*** used for get or clear connections ***/
typedef struct connection_op_para_{

	/* serveral macro defined for mask */
#define CLR_GET_CONN_SRCIP          0x0001
#define CLR_GET_CONN_SRCIP_MASK     0x0002
#define CLR_GET_CONN_DESIP          0x0004
#define CLR_GET_CONN_DESIP_MASK     0x0008
#define CLR_GET_CONN_PROTOCOL_LOW   0x0010
#define CLR_GET_CONN_PROTOCOL_HIGH  0x0020
#define CLR_GET_CONN_SRCPORT_LOW    0x0040
#define CLR_GET_CONN_SRCPORT_HIGH   0x0080
#define CLR_GET_CONN_DESPORT_LOW    0x0100
#define CLR_GET_CONN_DESPORT_HIGH   0x0200
#define CLR_GET_CONN_VRF_ID         0x0400
#define CLR_GET_CONN_FCFLAG         0x0800
#define CLR_GET_CONN_FW_POLICY      0x1000
	uint32_t mask;		/* identify which fitler is set */

	/* if address netmask is provided the address is the */
	/* results applied by the netmask */
	uint32_t src_ip;	/* source ip address */
	uint32_t src_mask;	/* source ip netmask */
	uint32_t dst_ip;	/* destination ip address */
	uint32_t dst_mask;	/* destination ip netmask */

	/* if port low boundary is set the high boundary must be set */
    uint16_t srcport_low;	 /* source port low boundary */
    uint16_t srcport_high; /* source port high boundary */
    uint16_t dstport_low;	 /* destination port low boundary */
	uint16_t dstport_high; /* destination port high boundary */

	/* if low boundary is set the high boundary must be set */
	uint8_t  protocol_low;	 /* protocol low boundary */
	uint8_t  protocol_high; /* protocol high boundary */
	/* vrf/vni id */
	uint32_t vrf_id;

	/* show flow connection with specific flag */
	uint32_t fcflag;
	/* show flow connection with specific fw_policy */
	uint32_t policy_id;
} connection_op_para_t;

typedef void (* selected_connection_vector_t)(flow_connection_t *, void *);
