#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>

#include <pthread.h>

#include <termios.h>

#include "../../include/flow_fifo.h"

struct termios g_oldterm;
char buf[BUF_SIZE];

int c2s;
int s2c;

static int
exit_vty(char *reason)
{
    tcsetattr(fileno(stdin), TCSANOW, &g_oldterm);
    printf("%s\n", reason);
    if (c2s != -1)
        close(c2s);
    if (s2c != -1)
        close(s2c);
    exit(0);
}

static int pipe_error = 0;
static void
sig_handler(int sig)
{
    switch(sig) {
        case SIGINT:
            exit_vty("boorish close vty!");
            break;
        case SIGPIPE:
            if (!pipe_error) {
                printf("pipe error, try again!\n");
                pipe_error = 1;
            } else {
                printf("pipe error %d again!\n", SIGPIPE);
                assert(0);
            }
            break;
        default:
            printf("received unknown sig %d\n", sig);
            break;
    }
}

static int
pid_update(void)
{
    int fd, id = 0, ret = 0;
    FILE *fp, *temp;
    char pid[10] = {0};
    char tty[100];
    char buf[128] = {0};
    char *new_tty;

    fd = open(PID_FILE, O_CREAT|O_RDWR, 0644);
    if (fd < 0) {
        printf("failed to open %s\n", PID_FILE);
        return -1;
    }

    if (flock(fd, LOCK_EX|LOCK_NB) < 0) {
        printf("failed to lock %s\n", PID_FILE);
        close(fd);
        return -1;
    }

    fp = fdopen(fd, "w+");
    if (fgets(pid, sizeof(pid), fp) != NULL) {
        id = atol(pid);
        if (id) {
            snprintf(buf, sizeof(buf), "ps -p %d > /dev/null ; echo $?", id);
            temp = popen(buf, "r");
            if (temp != NULL) {
                ret = fgetc(temp);
                printf("pid %d, ret %d\n", id, ret);
                ret = (ret == (int)'0')?1:0;
                pclose(temp);
            } else {
                ret = 1;
            }
            if (ret) {
                if (fgets(tty, sizeof(tty), fp) != NULL) {
                    int try_again = 0;
                    snprintf(buf, sizeof(buf), "echo \" you are kicked off by %d\" >> %s", getpid(), tty);
                    system(buf);
                    do {
                        ret = 0;
                        snprintf(buf, sizeof(buf), "kill -%d %d", SIGINT, id);
                        system(buf);
                        snprintf(buf, sizeof(buf), "ps -p %d > /dev/null ; echo $?", id);
                        temp = popen(buf, "r");
                        if (temp != NULL) {
                            ret = fgetc(temp);
                            if (ret == (int)'0') {
                                pclose(temp);
                                try_again = 1;
                            }
                        }
                    } while(try_again);
                }
            }
        }
    }

    rewind(fp);
    ret = fprintf(fp, "%d\n", getpid());
    if (ret <= 0) {
        printf("failed to puts %d to %s\n", getpid(), PID_FILE);
        return -1;
    }
    new_tty = ttyname(0);
    ret = fprintf(fp, "%s\n", new_tty);
    if (ret <= 0) {
        printf("failed to puts %s to %s\n", new_tty, PID_FILE);
        return -1;
    }

    fclose(fp);
    return id;
}

#ifndef VTY_SYN
static void *
vty_a_c2s_routine(void *arg)
{
    int ret;
    char c;

    while(1) {
        ret = read(0, &c, 1);
        if (c != '\t' &&
            c != '\n' &&
            c != '\b' &&
            !(c >= 32 && c <= 126)) {
            continue;
        }

        ret = write(c2s, &c, 1);
        if (ret <= 0) {
            //goto new_login;
        }
    }
    return NULL;
}

static void *
vty_a_s2c_routine(void *arg)
{
    int ret;

    while(1) {
        ret = read(s2c, buf, BUF_SIZE);
        if (ret <= 0) {
            //goto new_login;
        }
        if (strcmp(buf+2, EXIT_STR) == 0 ||
            strcmp(buf+1, EXIT_STR) == 0 ||
            strcmp(buf+0, EXIT_STR) == 0) {
            write(1, buf, 2);
            exit_vty("bye.");
        } else {
            write(1, buf, ret);
        }
        memset(buf, 0, BUF_SIZE);
    }
    return NULL;
}
#endif

static int vty_seq;
int
main(void)
{
    int ret, len, reg_cmd;
    int newline = 0, flush_prompt = 0, swapout = 0;
    char *c2sfifo, *s2cfifo;
    char c;
    struct sigaction sa;

	struct termios term;

#ifndef VTY_SYN
    pthread_t c2s_thread, s2c_thread;
#endif

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = sig_handler;
    /* ^c */
    sigaction(SIGINT, &sa, NULL);

    /* SIGPIPE
     * we need to SIGPIPE to give it another chance to connect
     * to flow, if failed again, make it panic
     */
    sigaction(SIGINT, &sa, NULL);

	tcgetattr(0, &g_oldterm);
	memcpy(&term, &g_oldterm, sizeof(term));
	term.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(0, TCSANOW, &term);
	setbuf(stdin, NULL);

    newline = pid_update();
    reg_cmd = 0;
#ifdef VTY_SYN
new_login:
#endif
    if (c2s && c2s != -1) {
        close(c2s);
    }
    if (s2c && s2c != -1) {
        close(s2c);
    }
    flow_vty_pick_fifo(vty_seq, c2sfifo, s2cfifo);
    c2s = open(c2sfifo, O_WRONLY);
    if (c2s < 0) {
        perror("failed to open /dev/scull");
        goto out;
    }
    
    s2c = open(s2cfifo, O_RDONLY);
    if (s2c < 0) {
        perror("failed to open /dev/scull1");
        goto out;
    }
    if (swapout) {
        read(s2c, buf, BUF_SIZE);
        goto out;
    }
    
    bzero(buf, BUF_SIZE);
#ifndef VTY_SYN
    ret = pthread_create(&c2s_thread, NULL, vty_a_c2s_routine, NULL);
    if (ret) {
        perror("failed to create c2s thread");
        goto out;
    }
    ret = pthread_create(&s2c_thread, NULL, vty_a_s2c_routine, NULL);
    if (ret) {
        perror("failed to create s2c thread");
        goto out;
    }
    while(1) {
        sleep(1);
    }
    c = c;
    flush_prompt = flush_prompt;
    newline = newline;
    reg_cmd = reg_cmd;
    len = len;
#else
    while(1) {
        if (newline) {
            do {
                ret = read(s2c, buf, BUF_SIZE);
                if (ret <= 0) {
                    //snprintf(buf, sizeof(buf), "failed to read prompt %d", ret);
                    //perror(buf);
                    goto new_login;
                }
                if (!flush_prompt)
                    write(1, buf, ret);
                bzero(buf, BUF_SIZE);
            } while(ret < strlen(PROMPT));
            newline = 0;
        }
        ret = read(0, &c, 1);
        if (ret < 0) {
            goto new_login;
            //perror("failed to read 0");
        } else {
            if (c != '\t' &&
                c != '\n' &&
                !(c >= 32 && c <= 126)) {
                continue;
            }
        }
        ret = write(c2s, &c, 1);
        if (ret < 0) {
            goto new_login;
        }
        switch(c) {
            case '\t':
            case '?':
                do {
                    bzero(buf, BUF_SIZE);
                    len = 0;
                    ret = read(s2c, buf, BUF_SIZE);
                    if (ret < 0) {
                        perror("failed to read s2c");
                    } else if (ret == 0) {
                        //perror("peer close s2c");
                    } else {
                        len = strlen(buf);
                        write(1, buf, len);
                    }
                } while (ret != 0);
                newline = 1;
                flush_prompt = 1;
                goto new_login;
                break;
            case '\n':
                if (reg_cmd) {
                    do {
                        bzero(buf, BUF_SIZE);
                        len = 0;
                        ret = read(s2c, buf, BUF_SIZE);
                        if (ret < 0) {
                            perror("failed to read s2c");
                        } else if (ret == 0) {
                            //perror("peer close s2c");
                        } else {
                            len = strlen(buf);
                            write(1, buf, len);
                            if (strcmp(buf+2, EXIT_STR) == 0 ||
                                strcmp(buf+1, EXIT_STR) == 0 ||
                                strcmp(buf+0, EXIT_STR) == 0) {
                                swapout = 1;
                                goto new_login;
                            }
                        }
                    } while(ret != 0);
                    newline = 1;
                    reg_cmd = 0;
                    flush_prompt = 0;
                    goto new_login;
                } else {
                    bzero(buf, BUF_SIZE);
                    ret = read(s2c, buf, BUF_SIZE);
                    write(1, buf, ret);
                }
                break;
            default:
                ret = read(s2c, &c, 1);
                if (ret == 1) {
                    write(1, &c, 1);
                }
                if (c != ' ') {
                    reg_cmd = 1;
                }
                break;
        }
    }
#endif
out:
    return exit_vty("bye.");
}

