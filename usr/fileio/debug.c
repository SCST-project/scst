/*
 *  debug.c
 *
 *  Copyright (C) 2004 - 2013 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
 *
 *  Contains helper functions for execution tracing and error reporting.
 *  Intended to be included in main .c file.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation, version 2
 *  of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "debug.h"

pid_t gettid (void)
{
	return syscall(__NR_gettid);
}

#if defined(DEBUG) || defined(TRACING)

#define TRACE_BUF_SIZE    512

static char trace_buf[TRACE_BUF_SIZE];
static pthread_spinlock_t trace_buf_lock;

int debug_print_prefix(unsigned long trace_flag, const char *prefix,
	const char *func, int line)
{
	int i = 0;

	pthread_spin_lock(&trace_buf_lock);

	if (trace_flag & TRACE_TIME) {
		struct tm t;
		time_t tt;
		time(&tt);
		localtime_r(&tt, &t);
		i += snprintf(&trace_buf[i], TRACE_BUF_SIZE, "%d:%d:%d ",
			t.tm_hour, t.tm_min, t.tm_sec);
	}
	if (trace_flag & TRACE_PID)
		i += snprintf(&trace_buf[i], TRACE_BUF_SIZE, "[%d]: ",
			      gettid());
	if (prefix != NULL)
		i += snprintf(&trace_buf[i], TRACE_BUF_SIZE - i, "%s:", prefix);
	if (trace_flag & TRACE_FUNCTION)
		i += snprintf(&trace_buf[i], TRACE_BUF_SIZE - i, "%s:", func);
	if (trace_flag & TRACE_LINE)
		i += snprintf(&trace_buf[i], TRACE_BUF_SIZE - i, "%i:", line);

	if (i > 0)
		PRINTN("%s", trace_buf);

	pthread_spin_unlock(&trace_buf_lock);

	return i;
}

void debug_print_buffer(const void *data, int len)
{
	int z, z1, i;
	const unsigned char *buf = (const unsigned char *) data;
	int f = 0;

	if (buf == NULL)
		return;

	pthread_spin_lock(&trace_buf_lock);

	PRINT(" (h)___0__1__2__3__4__5__6__7__8__9__A__B__C__D__E__F");
	for (z = 0, z1 = 0, i = 0; z < len; z++) {
		if (z % 16 == 0) {
			if (z != 0) {
				i += snprintf(&trace_buf[i], TRACE_BUF_SIZE - i,
					      " ");
				for (; (z1 < z) && (i < TRACE_BUF_SIZE - 1);
				     z1++) {
					if ((buf[z1] >= 0x20) &&
					    (buf[z1] < 0x80))
						trace_buf[i++] = buf[z1];
					else
						trace_buf[i++] = '.';
				}
				trace_buf[i] = '\0';
				PRINT("%s", trace_buf);
				i = 0;
				f = 1;
			}
			i += snprintf(&trace_buf[i], TRACE_BUF_SIZE - i,
				      "%4x: ", z);
		}
		i += snprintf(&trace_buf[i], TRACE_BUF_SIZE - i, "%02x ",
			      buf[z]);
	}
	i += snprintf(&trace_buf[i], TRACE_BUF_SIZE - i, "  ");
	for (; (z1 < z) && (i < TRACE_BUF_SIZE - 1); z1++) {
		if ((buf[z1] > 0x20) && (buf[z1] < 0x80))
			trace_buf[i++] = buf[z1];
		else
			trace_buf[i++] = '.';
	}
	trace_buf[i] = '\0';
	if (f) {
		PRINT("%s", trace_buf)
	} else {
		PRINT("%s", trace_buf);
	}

	pthread_spin_unlock(&trace_buf_lock);
	return;
}

int debug_init(void)
{
	int res;

	res = pthread_spin_init(&trace_buf_lock, PTHREAD_PROCESS_PRIVATE);
	if (res != 0) {
		res = errno;
		PRINT_ERROR("pthread_spin_init() failed: %s", strerror(res));
	}

	return res;
}

void debug_done(void)
{
	pthread_spin_destroy(&trace_buf_lock);
}

#endif /* DEBUG || TRACING */
