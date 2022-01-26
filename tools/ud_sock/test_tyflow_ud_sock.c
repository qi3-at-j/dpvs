
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define TYFLOW_UD_CMD_BATCH "/var/run/tyflow_cmd_batch"

#define RDLINE_BUF_SIZE 512
struct tyflow_cmd_batch_msg {
#define CMD_BATCH_MAGIC 0x434D4442
    int magic;
    char buf[RDLINE_BUF_SIZE];
};

int
main(int argc, char *argv[])
{
    int i, ret, len;
    struct sockaddr_un clt_addr;
    int clt_fd;
    struct tyflow_cmd_batch_msg msg = {0};

    for (i=0; i<argc; i++)
        printf("the %d arg: %s\n", i, argv[i]);

    memset(&clt_addr, 0, sizeof(struct sockaddr_un));
    clt_addr.sun_family = AF_UNIX;
    strncpy(clt_addr.sun_path, TYFLOW_UD_CMD_BATCH, sizeof(clt_addr.sun_path) - 1);

    clt_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (!clt_fd) {
        perror("socket");
        return -1;
    }
    ret = connect(clt_fd, (struct sockaddr*)&clt_addr, sizeof(clt_addr));
    if (-1 == ret) {
        perror("connect");
        return -1;
    }
    msg.magic = CMD_BATCH_MAGIC;
    len = snprintf(msg.buf, RDLINE_BUF_SIZE, "%s\n", argv[1]);
    ret = send(clt_fd, (const void *)&msg, len+sizeof(msg.magic), MSG_NOSIGNAL);
    if (ret != len) {
        perror("send");
        return -1;
    }
    printf("sent command (%s)\n", msg.buf);
    close(clt_fd);
    return 0;
}
