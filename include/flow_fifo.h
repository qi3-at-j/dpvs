#define BUF_SIZE 1024
#define BS_NUM   4
#define PID_FILE "/run/vty.pid"

/* named pipe(fifo) c2s even */
#define C2SFIFO_E "/tmp/flow_c2s_e"
/* named pipe(fifo) s2c even */
#define S2CFIFO_E "/tmp/flow_s2c_e"
/* named pipe(fifo) c2s odd */
#define C2SFIFO_O "/tmp/flow_c2s_o"
/* named pipe(fifo) s2c odd */
#define S2CFIFO_O "/tmp/flow_s2c_o"
#define EXIT_STR "exit"

#define PROMPT "tyflow > "

#define flow_vty_pick_fifo(seq, c2s, s2c) \
do {                                      \
    if (vty_seq++ & 1) {                  \
        c2sfifo = C2SFIFO_O;              \
        s2cfifo = S2CFIFO_O;              \
    } else {                              \
        c2sfifo = C2SFIFO_E;              \
        s2cfifo = S2CFIFO_E;              \
    }                                     \
} while(0)
