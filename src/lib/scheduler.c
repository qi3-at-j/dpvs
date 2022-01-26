/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Scheduling framework. This code is highly inspired from
 *              the thread management routine (thread.c) present in the
 *              very nice zebra project (http://www.zebra.org).
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include <errno.h>
#include <sys/wait.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <sys/signalfd.h>
#include <sys/utsname.h>
#include <linux/version.h>
#include <sched.h>

#include "scheduler.h"
#include "memory.h"
#include "rbtree.h"
#include "parser/utils.h"
#include "logger.h"
#include "bitops.h"
#include "timer.h"
#include "align.h"
#include "vrrp.h"
#include "vrrp_data.h"
#include "vrrp_parser.h"

int vrrp_eventfd = -1;

#ifdef THREAD_DUMP
typedef struct _func_det {
	const char *name;
	thread_func_t func;
	rb_node_t n;
} func_det_t;
#endif

/* global vars */
thread_master_t *master = NULL;
#ifndef _ONE_PROCESS_DEBUG_
prog_type_t prog_type;		/* Parent/VRRP/Checker process */
#endif
#ifdef _EPOLL_DEBUG_
bool do_epoll_debug;
#endif
#ifdef _EPOLL_THREAD_DUMP_
bool do_epoll_thread_dump;
#endif
extern vrrp_data_t *vrrp_data;

/* local variables */
static bool shutting_down;
static int sav_argc;
static char * const *sav_argv;
#ifdef THREAD_DUMP
static rb_root_t funcs = RB_ROOT;
#endif
#ifndef _ONE_PROCESS_DEBUG_
static void (*shutdown_function)(int);
#endif

/* Function that returns prog_name if pid is a known child */
static char const * (*child_finder_name)(pid_t);



#ifdef THREAD_DUMP
static const char *
get_thread_type_str(thread_type_t id)
{
	if (id == THREAD_READ) return "READ";
	if (id == THREAD_TIMER) return "TIMER";
	if (id == THREAD_EVENT) return "EVENT";
	if (id == THREAD_READY) return "READY";
	if (id == THREAD_UNUSED) return "UNUSED";
	if (id == THREAD_READ_TIMEOUT) return "READ_TIMEOUT";
	if (id == THREAD_READY_TIMER) return "READY_TIMER";
	if (id == THREAD_READY_READ_FD) return "READY_READ_FD";
	if (id == THREAD_READ_ERROR) return "READ_ERROR";

	return "unknown";
}

static inline int
function_cmp(const func_det_t *func1, const func_det_t *func2)
{
	if ((const void*)func1->func < (const void*)func2->func)
		return -1;
	if ((const void*)func1->func > (const void *)func2->func)
		return 1;
	return 0;
}

static const char *
get_function_name(thread_func_t func)
{
	func_det_t func_det = { .func = func };
	func_det_t *match;
	static char address[19];

	if (!RB_EMPTY_ROOT(&funcs)) {
		match = rb_search(&funcs, &func_det, n, function_cmp);
		if (match)
			return match->name;
	}

	snprintf(address, sizeof address, "%p", func);
	return address;
}

void
register_thread_address(const char *func_name, thread_func_t func)
{
	func_det_t *func_det;

	PMALLOC(func_det);
	if (!func_det)
		return;

	func_det->name = func_name;
	func_det->func = func;

	rb_insert_sort(&funcs, func_det, n, function_cmp);
}

void
deregister_thread_addresses(void)
{
	func_det_t *func_det, *func_det_tmp;

	if (RB_EMPTY_ROOT(&funcs))
		return;

	rb_for_each_entry_safe(func_det, func_det_tmp, &funcs, n) {
		rb_erase(&func_det->n, &funcs);
		FREE(func_det);
	}
}
#endif

/* The shutdown function is called if the scheduler gets repeated errors calling
 * epoll_wait() and so is unable to continue.
 * github issue 1809 reported the healthchecker process getting error EINVAL with
 * a particular configuration; this looks as though it was memory corruption but
 * we have no way of tracking down how that happened. This provides a way to escape
 * the error if it happens again, by the process terminating, and it will then be
 * restarted by the parent process. */
void
register_shutdown_function(void (*func)(int))
{
	/* The function passed here must not use the scheduler to shutdown */
	shutdown_function = func;
}

/* Move ready thread into ready queue */
static int
thread_move_ready(thread_master_t *m, rb_root_cached_t *root, thread_t *thread, int type)
{
	rb_erase_cached(&thread->n, root);
	INIT_LIST_HEAD(&thread->e_list);
	list_add_tail(&thread->e_list, &m->ready);
	thread->type = type;
	return 0;
}

/* Move ready thread into ready queue */
static void
thread_rb_move_ready(thread_master_t *m, rb_root_cached_t *root, int type)
{
	thread_t *thread, *thread_tmp;

	rb_for_each_entry_safe_cached(thread, thread_tmp, root, n) {
		if (thread->sands.tv_sec == TIMER_DISABLED || timercmp(&time_now, &thread->sands, <))
			break;

		if (type == THREAD_READ_TIMEOUT)
			thread->event->read = NULL;

		thread_move_ready(m, root, thread, type);
	}
}

/* Update timer value */
static void
thread_update_timer(rb_root_cached_t *root, timeval_t *timer_min)
{
	const thread_t *first;

	if (!root->rb_root.rb_node)
		return;

	first = rb_entry(rb_first_cached(root), thread_t, n);

	if (first->sands.tv_sec == TIMER_DISABLED)
		return;

	if (!timerisset(timer_min) ||
	    timercmp(&first->sands, timer_min, <=))
		*timer_min = first->sands;
}

/* Compute the wait timer. Take care of timeouted fd */
timeval_t
thread_set_timer(thread_master_t *m)
{
	timeval_t timer_wait, timer_wait_time;
	struct itimerspec its;

	/* Prepare timer */
	timerclear(&timer_wait_time);
	thread_update_timer(&m->timer, &timer_wait_time);
	thread_update_timer(&m->read, &timer_wait_time);

	if (timerisset(&timer_wait_time)) {
		/* Re-read the current time to get the maximum accuracy */
		set_time_now();

		/* Take care about monotonic clock */
		timersub(&timer_wait_time, &time_now, &timer_wait);

		if (timer_wait.tv_sec < 0) {
			/* This will disable the timerfd */
			timerclear(&timer_wait);
		}
	} else {
		/* set timer to a VERY long time */
		timer_wait.tv_sec = LONG_MAX;
		timer_wait.tv_usec = 0;
	}

	its.it_value.tv_sec = timer_wait.tv_sec;
	if (!timerisset(&timer_wait)) {
		/* We could try to avoid doing the epoll_wait since
		 * testing shows it takes about 4 microseconds
		 * for the timer to expire. */
		its.it_value.tv_nsec = 1;
	}
	else
		its.it_value.tv_nsec = timer_wait.tv_usec * 1000;

	/* We don't want periodic timer expiry */
	its.it_interval.tv_sec = its.it_interval.tv_nsec = 0;

	if (timerfd_settime(m->timer_fd, 0, &its, NULL))
		log_message(LOG_INFO, "Setting timer_fd returned errno %d - %m", errno);

#ifdef _EPOLL_DEBUG_
	if (do_epoll_debug)
		log_message(LOG_INFO, "Setting timer_fd %ld.%9.9ld", its.it_value.tv_sec, its.it_value.tv_nsec);
#endif

	return timer_wait_time;
}

static void
thread_timerfd_handler(thread_ref_t thread)
{
	thread_master_t *m = thread->master;
	uint64_t expired;
	ssize_t len;

	len = read(m->timer_fd, &expired, sizeof(expired));
	if (len < 0)
		log_message(LOG_ERR, "scheduler: Error reading on timerfd fd:%d (%m)", m->timer_fd);

	/* Read, Timer thread. */
	thread_rb_move_ready(m, &m->read, THREAD_READ_TIMEOUT);
	thread_rb_move_ready(m, &m->timer, THREAD_READY_TIMER);

	/* Register next timerfd thread */
	m->timer_thread = thread_add_read(m, thread_timerfd_handler, NULL, m->timer_fd, TIMER_NEVER, 0);
}

/* epoll related */
static int
thread_events_resize(thread_master_t *m, int delta)
{
	unsigned int new_size;

	m->epoll_count += delta;
	if (m->epoll_count < m->epoll_size)
		return 0;

	new_size = ((m->epoll_count / THREAD_EPOLL_REALLOC_THRESH) + 1);
	new_size *= THREAD_EPOLL_REALLOC_THRESH;

	if (m->epoll_events)
		FREE(m->epoll_events);
	m->epoll_events = MALLOC(new_size * sizeof(struct epoll_event));
	if (!m->epoll_events) {
		m->epoll_size = 0;
		return -1;
	}

	m->epoll_size = new_size;
	return 0;
}

static inline int
thread_event_cmp(const thread_event_t *event1, const thread_event_t *event2)
{
	if (event1->fd < event2->fd)
		return -1;
	if (event1->fd > event2->fd)
		return 1;
	return 0;
}

static thread_event_t *
thread_event_new(thread_master_t *m, int fd)
{
	thread_event_t *event;

	PMALLOC(event);
	if (!event)
		return NULL;

	if (thread_events_resize(m, 1) < 0) {
		FREE(event);
		return NULL;
	}

	event->fd = fd;

	rb_insert_sort(&m->io_events, event, n, thread_event_cmp);

	return event;
}

static thread_event_t * __attribute__ ((pure))
thread_event_get(thread_master_t *m, int fd)
{
	thread_event_t event = { .fd = fd };

	return rb_search(&m->io_events, &event, n, thread_event_cmp);
}

static int
thread_event_set(const thread_t *thread)
{
	thread_event_t *event = thread->event;
	thread_master_t *m = thread->master;
	struct epoll_event ev = { .events = 0, .data.ptr = event };
	int op;

	if (__test_bit(THREAD_FL_READ_BIT, &event->flags))
		ev.events |= EPOLLIN;

	if (__test_bit(THREAD_FL_EPOLL_BIT, &event->flags))
		op = EPOLL_CTL_MOD;
	else
		op = EPOLL_CTL_ADD;

	if (epoll_ctl(m->epoll_fd, op, event->fd, &ev) < 0) {
		log_message(LOG_INFO, "scheduler: Error %d performing control on EPOLL instance for fd %d (%m)", errno, event->fd);
		return -1;
	}

	__set_bit(THREAD_FL_EPOLL_BIT, &event->flags);
	return 0;
}

static int
thread_event_cancel(const thread_t *thread_cp)
{
	thread_t *thread = no_const(thread_t, thread_cp);
	thread_event_t *event = thread->event;
	thread_master_t *m = thread->master;

	if (!event) {
		log_message(LOG_INFO, "scheduler: Error performing epoll_ctl DEL op no event linked?!");
		return -1;
	}

	/* Ignore error if it was an SNMP fd, since we don't know
	 * if they have been closed */
	if (m->epoll_fd != -1 &&
	    epoll_ctl(m->epoll_fd, EPOLL_CTL_DEL, event->fd, NULL) < 0)
		log_message(LOG_INFO, "scheduler: Error performing epoll_ctl DEL op for fd:%d (%m)", event->fd);

	rb_erase(&event->n, &m->io_events);
	if (event == m->current_event)
		m->current_event = NULL;
	thread_events_resize(m, -1);
	FREE(thread->event);
	return 0;
}

static int
thread_event_del(const thread_t *thread_cp, unsigned flag)
{
	thread_t *thread = no_const(thread_t, thread_cp);
	thread_event_t *event = thread->event;

	if (!__test_bit(flag, &event->flags))
		return 0;

	if (flag == THREAD_FL_EPOLL_READ_BIT) {
		__clear_bit(THREAD_FL_READ_BIT, &event->flags);
		return thread_event_cancel(thread);
	}

	if (thread_event_set(thread) < 0)
		return -1;

	__clear_bit(flag, &event->flags);
	return 0;
}

extern unsigned int 
vrrp_ring_receive(unsigned int uiExpireNum, void *pVrrpMbuf[]);

extern int  
vrrp_ring_init(void);

extern void 
vrrp_dispatcher_read(void *pmbuf);

static void 
vrrp_eventfd_handler(thread_ref_t thread)
{
    int ret = 0;
    uint64_t ui64;
    void *ppmbuf[1] = {0};

    ret = read(vrrp_eventfd, &ui64, sizeof(ui64));
    if (ret < 0)
    {
        log_message(LOG_INFO,"vrrp_event: read failed from eventfd %d.", vrrp_eventfd);
        return;
    }

    do
    {
        ret = vrrp_ring_receive(1, ppmbuf);
        if (ret > 0)
        {
            vrrp_dispatcher_read(ppmbuf[0]);
        }
    }
    while (ret);

    return;    
}

extern int 
vrrp_eventfd_notify(unsigned int uiCount);
int 
vrrp_eventfd_notify(unsigned int uiCount)
{
    int ret = 0;
    uint64_t ui64 = uiCount;
    ret = write(vrrp_eventfd, &ui64, sizeof(ui64));
    if (ret < 0)
    {
        log_message(LOG_INFO,"vrrp_event: write failed to eventfd %d.", vrrp_eventfd);
        return -1;
    }

    return 0;
}

/* register vrrp eventfd */
static int 
vrrp_event_register(thread_master_t *new)
{
    int fd;
    thread_event_t * event;
    struct epoll_event ev ;

    fd = eventfd(0, 0);
    if (fd < 0)
    {
        log_message(LOG_INFO, "scheduler: vrrp_eventfd failed.\n");
        return -1;
    }

    vrrp_eventfd = fd;

    if (!(event = thread_event_new(new, vrrp_eventfd))) 
    {
        close(fd);
        log_message(LOG_INFO, "scheduler: Can not allocate vrrp event for fd [%d](%m)", vrrp_eventfd);
        return -1;
    }


	ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    ev.data.ptr = event;

	if (epoll_ctl(new->epoll_fd, EPOLL_CTL_ADD, event->fd, &ev) < 0) 
    {
        close(fd);
        FREE(event);
		log_message(LOG_INFO, "scheduler: Error %d performing control on EPOLL instance for fd %d (%m)", errno, event->fd);
		return -1;
	}

	__set_bit(THREAD_FL_EPOLL_BIT, &event->flags);

    return 0;
}

#ifdef ENABLE_LOG_TO_FILE

static void
thread_log2file_handler(thread_ref_t thread)
{
    char *log_file_full_name, *log_file_backup_full_name;
	thread_master_t *m = thread->master;
    int log_file_size = log_file_get_size();

    log_file_full_name        = make_file_name(log_file_name, "vrrp", NULL, NULL);
    log_file_backup_full_name = make_file_name(log_file_backup_name, "vrrp", NULL, NULL);
    if ((log_file_full_name == NULL) || (log_file_backup_full_name == NULL))
    {
        if (log_file_full_name != NULL)
        {
            FREE_CONST(log_file_full_name);
        }

        if (log_file_backup_full_name != NULL)
        {
            FREE_CONST(log_file_backup_full_name);
        }

        log_message(LOG_INFO, "%s : memory malloc failed.", __func__);
        return;
    }

    if (log_file_size >= (log_file_max_size * 1024))
    {
        if (access(log_file_backup_full_name, F_OK) == 0)
        {
            remove(log_file_backup_full_name);
            log_message(LOG_INFO, "%s : remove old %s", __func__, log_file_backup_full_name);
        }

        if (access(log_file_full_name, F_OK) == 0)
        {
            if (0 == rename(log_file_full_name, log_file_backup_full_name))
            {
                log_message(LOG_INFO, "%s : %s rename %s", __func__, log_file_full_name, log_file_backup_full_name);
            }

            close_log_file();
    	}

        if (log_file_name) 
        {
            open_log_file(log_file_name, "vrrp", NULL, NULL);
            set_flush_log_file();
            log_message(LOG_INFO, "%s : create new %s", __func__, log_file_full_name);
        }
    }

    if (log_file_full_name != NULL)
    {
        FREE_CONST(log_file_full_name);
    }

    if (log_file_backup_full_name != NULL)
    {
        FREE_CONST(log_file_backup_full_name);
    }

	/* Register next thread */
	thread_add_read(m, thread_log2file_handler, NULL, -1, (log_file_size_check_interval * TIMER_HZ), 0);
}

#endif


/* Make thread master. */
thread_master_t *
thread_make_master(void)
{
	thread_master_t *new;

	PMALLOC(new);

	new->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (new->epoll_fd < 0) {
		log_message(LOG_INFO, "scheduler: Error creating EPOLL instance (%m)");
		FREE(new);
		return NULL;
	}

	new->read = RB_ROOT_CACHED;
	new->timer = RB_ROOT_CACHED;
	new->io_events = RB_ROOT;
	INIT_LIST_HEAD(&new->event);
	INIT_LIST_HEAD(&new->ready);
	INIT_LIST_HEAD(&new->unuse);

	/* Register timerfd thread */
	new->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (new->timer_fd < 0) {
		log_message(LOG_ERR, "scheduler: Cant create timerfd (%m)");
		FREE(new);
		return NULL;
	}

	new->timer_thread = thread_add_read(new, thread_timerfd_handler, NULL, new->timer_fd, TIMER_NEVER, 0);

    /* Register vrrp eventfd */
    if (vrrp_event_register(new) < 0)
    {
        log_message(LOG_INFO, "scheduler: vrrp eventfd %d register failed.", vrrp_eventfd);
    }

#ifdef ENABLE_LOG_TO_FILE

    thread_add_read(new, thread_log2file_handler, NULL, -1, (log_file_size_check_interval * TIMER_HZ), 0);

#endif

	return new;
}

#ifdef THREAD_DUMP
static const char *
timer_delay(timeval_t sands)
{
	static char str[43];

	if (sands.tv_sec == TIMER_DISABLED)
		return "NEVER";
	if (sands.tv_sec == 0 && sands.tv_usec == 0)
		return "UNSET";

	if (timercmp(&sands, &time_now, >=)) {
		sands = timer_sub_now(sands);
		snprintf(str, sizeof str, "%ld.%6.6ld", sands.tv_sec, sands.tv_usec);
	} else {
		timersub(&time_now, &sands, &sands);
		snprintf(str, sizeof str, "-%ld.%6.6ld", sands.tv_sec, sands.tv_usec);
	}

	return str;
}

static void
thread_rb_dump(const rb_root_cached_t *root, const char *tree, FILE *fp)
{
	thread_t *thread;
	unsigned i = 1;

	conf_write(fp, "----[ Begin rb_dump %s ]----", tree);

	rb_for_each_entry_cached(thread, root, n)
		write_thread_entry(fp, i++, thread);

	conf_write(fp, "----[ End rb_dump ]----");
}

static void
thread_list_dump(const list_head_t *l, const char *list_type, FILE *fp)
{
	thread_t *thread;
	unsigned i = 1;

	conf_write(fp, "----[ Begin list_dump %s ]----", list_type);

	list_for_each_entry(thread, l, e_list)
		write_thread_entry(fp, i++, thread);

	conf_write(fp, "----[ End list_dump ]----");
}

static void
event_rb_dump(const rb_root_t *root, const char *tree, FILE *fp)
{
	thread_event_t *event;
	int i = 1;

	conf_write(fp, "----[ Begin rb_dump %s ]----", tree);
	rb_for_each_entry(event, root, n)
		conf_write(fp, "#%.2d event %p fd %d, flags: 0x%lx, read %p"
			     , i++, event, event->fd, event->flags
			     , event->read);
	conf_write(fp, "----[ End rb_dump ]----");
}

void
dump_thread_data(const thread_master_t *m, FILE *fp)
{
	thread_rb_dump(&m->read, "read", fp);
	thread_rb_dump(&m->timer, "timer", fp);
	thread_list_dump(&m->event, "event", fp);
	thread_list_dump(&m->ready, "ready", fp);
	thread_list_dump(&m->unuse, "unuse", fp);
	event_rb_dump(&m->io_events, "io_events", fp);
}
#endif

/* declare thread_timer_cmp() for rbtree compares */
RB_TIMER_CMP(thread);

/* Free all unused thread. */
static void
thread_clean_unuse(thread_master_t * m)
{
	thread_t *thread, *thread_tmp;
	list_head_t *l = &m->unuse;

	list_for_each_entry_safe(thread, thread_tmp, l, e_list) {
		list_del_init(&thread->e_list);

		/* free the thread */
		FREE(thread);
		m->alloc--;
	}

	INIT_LIST_HEAD(l);
}

/* Move thread to unuse list. */
static void
thread_add_unuse(thread_master_t *m, thread_t *thread)
{
	assert(m != NULL);

	thread->type = THREAD_UNUSED;
	thread->event = NULL;
	INIT_LIST_HEAD(&thread->e_list);
	list_add_tail(&thread->e_list, &m->unuse);
}

/* Move list element to unuse queue */
static void
thread_destroy_list(thread_master_t *m, list_head_t *l)
{
	thread_t *thread, *thread_tmp;

	list_for_each_entry_safe(thread, thread_tmp, l, e_list) {
		/* The following thread types are relevant for the ready list */
		if (thread->type == THREAD_READY_READ_FD ||
		    thread->type == THREAD_READ_TIMEOUT ||
		    thread->type == THREAD_READ_ERROR) {
			/* Do we have a thread_event, and does it need deleting? */
			if (thread->event) {
				thread_del_read(thread);
			}

			/* Do we have a file descriptor that needs closing ? */
			if (thread->u.f.flags & THREAD_DESTROY_CLOSE_FD)
				thread_close_fd(thread);

			/* Do we need to free arg? */
			if (thread->u.f.flags & THREAD_DESTROY_FREE_ARG)
				FREE(thread->arg);
		}

		list_del_init(&thread->e_list);
		thread_add_unuse(m, thread);
	}
}

static void
thread_destroy_rb(thread_master_t *m, rb_root_cached_t *root)
{
	thread_t *thread, *thread_tmp;

	rb_for_each_entry_safe_cached(thread, thread_tmp, root, n) {
		rb_erase_cached(&thread->n, root);

		/* The following are relevant for the read rb lists */
		if (thread->type == THREAD_READ) {
			/* Do we have a thread_event, and does it need deleting? */
			thread_del_read(thread);

			/* Do we have a file descriptor that needs closing ? */
			if (thread->u.f.flags & THREAD_DESTROY_CLOSE_FD)
				thread_close_fd(thread);

			/* Do we need to free arg? */
			if (thread->u.f.flags & THREAD_DESTROY_FREE_ARG)
				FREE(thread->arg);
		}

		thread_add_unuse(m, thread);
	}
}

/* Delete top of the list and return it. */
static thread_t *
thread_trim_head(list_head_t *l)
{
	thread_t *thread;

	if (list_empty(l))
		return NULL;

	thread = list_first_entry(l, thread_t, e_list);
	list_del_init(&thread->e_list);
	return thread;
}

/* Make unique thread id for non pthread version of thread manager. */
static inline unsigned long
thread_get_id(thread_master_t *m)
{
	return m->id++;
}

/* Make new thread. */
static thread_t *
thread_new(thread_master_t *m)
{
	thread_t *new;

	/* If one thread is already allocated return it */
	new = thread_trim_head(&m->unuse);
	if (!new) {
		PMALLOC(new);
		m->alloc++;
	}

	INIT_LIST_HEAD(&new->e_list);
	new->id = thread_get_id(m);
	return new;
}

/* Add new read thread. */
thread_ref_t
thread_add_read_sands(thread_master_t *m, thread_func_t func, void *arg, int fd, const timeval_t *sands, unsigned flags)
{
	thread_event_t *event;
	thread_t *thread;

	assert(m != NULL);

	/* I feel lucky ! :D */
	if (m->current_event && m->current_event->fd == fd)
		event = m->current_event;
	else
		event = thread_event_get(m, fd);

	if (!event) {
		if (!(event = thread_event_new(m, fd))) {
			log_message(LOG_INFO, "scheduler: Cant allocate read event for fd [%d](%m)", fd);
			return NULL;
		}
	}
	else if (__test_bit(THREAD_FL_READ_BIT, &event->flags) && event->read) {
		log_message(LOG_INFO, "scheduler: There is already read event %p (read %p) registered on fd [%d]", event, event->read, fd);
		return NULL;
	}

	thread = thread_new(m);
	thread->type = THREAD_READ;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.f.fd = fd;
	thread->u.f.flags = flags;
	thread->event = event;

    if (fd > 0)
    {
		/* Set & flag event */
		__set_bit(THREAD_FL_READ_BIT, &event->flags);
		event->read = thread;
		if (!__test_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags)) {
			if (thread_event_set(thread) < 0) {
				log_message(LOG_INFO, "scheduler: Cant register read event for fd [%d](%m)", fd);
				thread_add_unuse(m, thread);
				return NULL;
			}
			__set_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags);
		}
    }

	thread->sands = *sands;

	/* Sort the thread. */
	rb_insert_sort_cached(&m->read, thread, n, thread_timer_cmp);

	return thread;
}

thread_ref_t
thread_add_read(thread_master_t *m, thread_func_t func, void *arg, int fd, unsigned long timer, unsigned flags)
{
	timeval_t sands;

	/* Compute read timeout value */
	if (timer == TIMER_NEVER) {
		sands.tv_sec = TIMER_DISABLED;
		sands.tv_usec = 0;
	} else {
		set_time_now();
		sands = timer_add_long(time_now, timer);
	}

	return thread_add_read_sands(m, func, arg, fd, &sands, flags);
}

void
thread_del_read(thread_ref_t thread)
{
	if (!thread || !thread->event)
		return;

	thread_event_del(thread, THREAD_FL_EPOLL_READ_BIT);
}

void
thread_close_fd(thread_ref_t thread_cp)
{
	thread_t *thread = no_const(thread_t, thread_cp);

	if (thread->u.f.fd == -1)
		return;

	if (thread->event)
		thread_event_cancel(thread);

	close(thread->u.f.fd);
	thread->u.f.fd = -1;
}

/* Add timer event thread. */
thread_ref_t
thread_add_timer_uval(thread_master_t *m, thread_func_t func, void *arg, unsigned val, unsigned long timer)
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = THREAD_TIMER;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.uval = val;

	/* Do we need jitter here? */
	if (timer == TIMER_NEVER)
		thread->sands.tv_sec = TIMER_DISABLED;
	else {
		set_time_now();
		thread->sands = timer_add_long(time_now, timer);
	}

	/* Sort by timeval. */
	rb_insert_sort_cached(&m->timer, thread, n, thread_timer_cmp);

	return thread;
}

thread_ref_t
thread_add_timer(thread_master_t *m, thread_func_t func, void *arg, unsigned long timer)
{
	return thread_add_timer_uval(m, func, arg, 0, timer);
}

/* Add simple event thread. */
thread_ref_t
thread_add_event(thread_master_t * m, thread_func_t func, void *arg, int val)
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = THREAD_EVENT;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.val = val;
	INIT_LIST_HEAD(&thread->e_list);
	list_add_tail(&thread->e_list, &m->event);

	return thread;
}

/* Cancel thread from scheduler. */
void
thread_cancel(thread_ref_t thread_cp)
{
	thread_t *thread = no_const(thread_t, thread_cp);
	thread_master_t *m;

	if (!thread || thread->type == THREAD_UNUSED)
		return;

	m = thread->master;

	switch (thread->type) {
	case THREAD_READ:
		thread_event_del(thread, THREAD_FL_EPOLL_READ_BIT);
		rb_erase_cached(&thread->n, &m->read);
		break;
	case THREAD_TIMER:
		rb_erase_cached(&thread->n, &m->timer);
		break;
	case THREAD_READY_READ_FD:
	case THREAD_READ_TIMEOUT:
	case THREAD_READ_ERROR:
		if (thread->event)
			thread_event_del(thread, THREAD_FL_EPOLL_READ_BIT);
		list_del_init(&thread->e_list);
		break;
	case THREAD_EVENT:
	case THREAD_READY:
		list_del_init(&thread->e_list);
		break;
	default:
		break;
	}

	thread_add_unuse(m, thread);
}

/* Fetch next ready thread. */
static list_head_t *
thread_fetch_next_queue(thread_master_t *m)
{
	int last_epoll_errno = 0;
#ifndef _ONE_PROCESS_DEBUG_
	unsigned last_epoll_errno_count = 0;
#endif
	int ret;
	int i;

	assert(m != NULL);

	/* If there is event process it first. */
	if (!list_empty(&m->event))
		return &m->event;

	/* If there are ready threads process them */
	if (!list_empty(&m->ready))
		return &m->ready;

	do {
		/* Calculate and set wait timer. Take care of timeouted fd.  */
		thread_set_timer(m);

#ifdef _EPOLL_THREAD_DUMP_
		if (do_epoll_thread_dump)
			dump_thread_data(m, NULL);
#endif

#ifdef _EPOLL_DEBUG_
		if (do_epoll_debug)
			log_message(LOG_INFO, "calling epoll_wait");
#endif

		/* Call epoll function. */
		ret = epoll_wait(m->epoll_fd, m->epoll_events, m->epoll_count, -1);
        vrrp_sync_conf();
        if (!chk_min_cfg(&vrrp_data->vrrp)) {
            sleep(1);
            continue;
        }

#ifdef _EPOLL_DEBUG_
		if (do_epoll_debug) {
			int sav_errno = errno;

			if (ret == -1)
				log_message(LOG_INFO, "epoll_wait returned %d, errno %d", ret, sav_errno);
			else
				log_message(LOG_INFO, "epoll_wait returned %d fds", ret);

			errno = sav_errno;
		}
#endif

		if (ret < 0) {
			/* epoll_wait() will return EINTR if the process is sent SIGSTOP
			 * (see signal(7) man page for details.
			 * Although we don't except to receive SIGSTOP, it can happen if,
			 * for example, the system is hibernated. */
			if (errno == EINTR)
				continue;

			/* Real error. */
			if (errno != last_epoll_errno) {
				last_epoll_errno = errno;

				/* Log the error first time only */
				log_message(LOG_INFO, "scheduler: epoll_wait error: %d (%m)", errno);

#ifndef _ONE_PROCESS_DEBUG_
				last_epoll_errno_count = 1;
#endif
			}
#ifndef _ONE_PROCESS_DEBUG_
			else if (++last_epoll_errno_count == 5 && shutdown_function) {
				/* We aren't goint to be able to recover, so exit and let our parent restart us */
				log_message(LOG_INFO, "scheduler: epoll_wait has returned errno %d for 5 successive calls - terminating", last_epoll_errno);
				shutdown_function(KEEPALIVED_EXIT_PROGRAM_ERROR);
			}
#endif

			/* Make sure we don't sit it a tight loop */
			if (last_epoll_errno == EBADF || last_epoll_errno == EFAULT || last_epoll_errno == EINVAL)
				sleep(1);

			continue;
		} else
			last_epoll_errno = 0;

		/* Handle epoll events */
		for (i = 0; i < ret; i++) {
			struct epoll_event *ep_ev;
			thread_event_t *ev;

			ep_ev = &m->epoll_events[i];
			ev = ep_ev->data.ptr;

#ifdef _EPOLL_DEBUG_
			if (do_epoll_debug)
				log_message(LOG_INFO, "Handling event 0x%x for fd %d", ep_ev->events, ev->fd);
#endif

            /* Handle vrrp epoll events */
            if (ev->fd == vrrp_eventfd)
            {
                thread_t *thread;

                thread = thread_new(m);
                thread->type = THREAD_EVENT;
                thread->master = m;
                thread->func = vrrp_eventfd_handler;
                thread->u.f.fd = vrrp_eventfd;
                thread->u.f.flags = 0;
                thread->event = ev;
                INIT_LIST_HEAD(&thread->e_list);

                if (ep_ev->events & EPOLLIN)
                {
                    list_add_tail(&thread->e_list, &m->event);
                }
                else if (ep_ev->events & (EPOLLHUP | EPOLLERR))
                {
                    log_message(LOG_INFO, "Received vrrp eventfd EPOLLHUP | EPOLLERR for fd %d", ev->fd);
                    thread_close_fd(thread);
                    thread_add_unuse(m, thread);
                }

                continue;
            } else if (ev->fd == vrrp_data->fd_cfg_chg) {
                uint64_t u;
                ssize_t s;

                s = read(vrrp_data->fd_cfg_chg, &u, sizeof(uint64_t));
                if (s != sizeof(uint64_t))
                   log_message(LOG_ERR, "%s: failed to read from eventfd %d, res=%ld.", __func__, vrrp_data->fd_cfg_chg, s);

                continue;
            }

			/* Error */
			if (ep_ev->events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
				if (ev->read) {
					thread_move_ready(m, &m->read, ev->read, THREAD_READ_ERROR);
					ev->read = NULL;
				}

				if (ep_ev->events & EPOLLRDHUP)
					log_message(LOG_INFO, "Received EPOLLRDHUP for fd %d", ev->fd);

				continue;
			}

			/* READ */
			if (ep_ev->events & EPOLLIN) {
				if (!ev->read) {
					log_message(LOG_INFO, "scheduler: No read thread bound on fd:%d (fl:0x%.4X)"
						      , ev->fd, ep_ev->events);
					continue;
				}
				thread_move_ready(m, &m->read, ev->read, THREAD_READY_READ_FD);
				ev->read = NULL;
			}
		}

		/* Update current time */
		set_time_now();

        /* If there is event process it first. */
        if (!list_empty(&m->event))
		    return &m->event;

		/* If there is a ready thread, return it. */
		if (!list_empty(&m->ready))
			return &m->ready;
	} while (true);
}

/* Call thread ! */
static inline void
thread_call(thread_t * thread)
{
#ifdef _EPOLL_DEBUG_
	if (do_epoll_debug)
		log_message(LOG_INFO, "Calling thread function %s(), type %s, val/fd/pid %d, status %d id %lu", get_function_name(thread->func), get_thread_type_str(thread->type), thread->u.val, thread->u.c.status, thread->id);
#endif

	(*thread->func) (thread);
}

void
process_threads(thread_master_t *m)
{
	thread_t* thread;
	list_head_t *thread_list;
	int thread_type;

	/*
	 * Processing the master thread queues,
	 * return and execute one ready thread.
	 */
	while ((thread_list = thread_fetch_next_queue(m))) {
		/* If we are shutting down, only process relevant thread types.
		 * We only want timer and signal fd, and don't want inotify, vrrp socket,
		 * snmp_read, bfd_receiver, bfd pipe in vrrp/check, dbus pipe or netlink fds. */
		if (!(thread = thread_trim_head(thread_list)))
			continue;

		m->current_thread = thread;
		thread_type = thread->type;

		if (!shutting_down ||
		    ((thread->type == THREAD_READY_READ_FD ||
		      thread->type == THREAD_READ_ERROR) &&
		     thread->u.f.fd == m->timer_fd)) {
			if (thread->func)
				thread_call(thread);

			/* If m->current_thread has been cleared, the thread
			 * has been freed. This happens during a reload. */
			thread = m->current_thread;
		} else if (thread->type == THREAD_READY_READ_FD ||
    			   thread->type == THREAD_READ_TIMEOUT ||
    			   thread->type == THREAD_READ_ERROR) {
			thread_close_fd(thread);

			if (thread->u.f.flags & THREAD_DESTROY_FREE_ARG)
				FREE(thread->arg);
		}

		if (thread) {
			m->current_event = (thread_type == THREAD_READY_READ_FD) ? thread->event : NULL;
			thread_add_unuse(m, thread);
			m->current_thread = NULL;
		} else
			m->current_event = NULL;

		/* If daemon hanging event is received stop processing */
	}
}

/* Our infinite scheduling loop */
void
launch_thread_scheduler(thread_master_t *m)
{
	process_threads(m);
}

#ifdef THREAD_DUMP
void
register_scheduler_addresses(void)
{
	register_thread_address("thread_timerfd_handler", thread_timerfd_handler);
}
#endif
