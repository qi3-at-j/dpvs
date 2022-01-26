/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        General program utils.
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

/* System includes */
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/resource.h>

/* Local includes */
#include "utils.h"
#include "parser/utils.h"
#include "memory.h"
#include "utils.h"
#include "logger.h"
#include "align.h"


/* global vars */
unsigned long debug = 0;
mode_t umask_val = S_IXUSR | S_IRWXG | S_IRWXO;

const char *
make_file_name(const char *name, const char *prog, const char *namespace, const char *instance)
{
	const char *extn_start;
	const char *dir_end;
	size_t len;
	char *file_name;

	if (!name)
		return NULL;

	len = strlen(name);
	if (prog)
		len += strlen(prog) + 1;
	if (namespace)
		len += strlen(namespace) + 1;
	if (instance)
		len += strlen(instance) + 1;

	file_name = MALLOC(len + 1);
	dir_end = strrchr(name, '/');
	extn_start = strrchr(dir_end ? dir_end : name, '.');
	strncpy(file_name, name, extn_start ? (size_t)(extn_start - name) : len);

	if (prog) {
		strcat(file_name, "_");
		strcat(file_name, prog);
	}
	if (namespace) {
		strcat(file_name, "_");
		strcat(file_name, namespace);
	}
	if (instance) {
		strcat(file_name, "_");
		strcat(file_name, instance);
	}
	if (extn_start)
		strcat(file_name, extn_start);

	return file_name;
}

/* Compute a checksum */
uint16_t
in_csum(const uint16_t *addr, size_t len, uint32_t csum, uint32_t *acc)
{
	register size_t nleft = len;
	const uint16_t *w = addr;
	register uint16_t answer;
	register uint32_t sum = csum;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += htons(*PTR_CAST_CONST(u_char, w) << 8);

	if (acc)
		*acc = sum;

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = (~sum & 0xffff);		/* truncate to 16 bits */
	return (answer);
}

/* We need to use O_NOFOLLOW if opening a file for write, so that a non privileged user can't
 * create a symbolic link from the path to a system file and cause a system file to be overwritten. */
FILE * __attribute__((malloc))
fopen_safe(const char *path, const char *mode)
{
	int fd;
	FILE *file;
#ifdef ENABLE_LOG_FILE_APPEND
	int flags = O_NOFOLLOW | O_CREAT | O_CLOEXEC;
#endif
	int sav_errno;
	char file_tmp_name[PATH_MAX];

	if (mode[0] == 'r')
		return fopen(path, mode);

	if ((mode[0] != 'a' && mode[0] != 'w') ||
	    (mode[1] &&
	     (mode[1] != '+' || mode[2]))) {
		errno = EINVAL;
		return NULL;
	}

	if (mode[0] == 'w') {
		/* If we truncate an existing file, any non-privileged user who already has the file
		 * open would be able to read what we write, even though the file access mode is changed.
		 *
		 * If we unlink an existing file and the desired file is subsequently created via open,
		 * it leaves a window for someone else to create the same file between the unlink and the open.
		 *
		 * The solution is to create a temporary file that we will rename to the desired file name.
		 * Since the temporary file is created owned by root with the only file access permissions being
		 * owner read and write, no non root user will have access to the file. Further, the rename to
		 * the requested filename is atomic, and so there is no window when someone else could create
		 * another file of the same name.
		 */
		strcpy_safe(file_tmp_name, path);
		if (strlen(path) + 6 < sizeof(file_tmp_name))
			strcat(file_tmp_name, "XXXXXX");
		else
			strcpy(file_tmp_name + sizeof(file_tmp_name) - 6 - 1, "XXXXXX");
		fd = mkostemp(file_tmp_name, O_CLOEXEC);
	} else {
		/* Only allow append mode if debugging features requiring append are enabled. Since we
		 * can't unlink the file, there may be a non privileged user who already has the file open
		 * for read (e.g. tail -f). If these debug option aren't enabled, there is no potential
		 * security risk in that respect. */
#ifndef ENABLE_LOG_FILE_APPEND
		log_message(LOG_INFO, "BUG - shouldn't be opening file for append with current build options");
		errno = EINVAL;
		return NULL;
#else
		flags = O_NOFOLLOW | O_CREAT | O_CLOEXEC | O_APPEND;

		if (mode[1])
			flags |= O_RDWR;
		else
			flags |= O_WRONLY;

		fd = open(path, flags, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
#endif
	}

	if (fd == -1) {
		sav_errno = errno;
		log_message(LOG_INFO, "Unable to open '%s' - errno %d (%m)", path, errno);
		errno = sav_errno;
		return NULL;
	}

#ifndef ENABLE_LOG_FILE_APPEND
	/* Change file ownership to root */
	if (mode[0] == 'a' && fchown(fd, 0, 0)) {
		sav_errno = errno;
		log_message(LOG_INFO, "Unable to change file ownership of %s- errno %d (%m)", path, errno);
		close(fd);
		errno = sav_errno;
		return NULL;
	}
#endif

	/* Set file mode, default rw------- */
	if (fchmod(fd, (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) & ~umask_val)) {
		sav_errno = errno;
		log_message(LOG_INFO, "Unable to change file permission of %s - errno %d (%m)", path, errno);
		close(fd);
		errno = sav_errno;
		return NULL;
	}

	if (mode[0] == 'w') {
		/* Rename the temporary file to the one we want */
		if (rename(file_tmp_name, path)) {
			sav_errno = errno;
			log_message(LOG_INFO, "Failed to rename %s to %s - errno %d (%m)", file_tmp_name, path, errno);
			close(fd);
			errno = sav_errno;
			return NULL;
		}
	}

	file = fdopen (fd, "w");
	if (!file) {
		sav_errno = errno;
		log_message(LOG_INFO, "fdopen(\"%s\") failed - errno %d (%m)", path, errno);
		close(fd);
		errno = sav_errno;
		return NULL;
	}

	return file;
}

