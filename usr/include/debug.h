/*
 *  debug.h
 *
 *  Copyright (C) 2004 - 2017 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 - 2017 SanDisk Corporation
 *
 *  Contains macroses for execution tracing and error reporting
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

#ifndef __DEBUG_H
#define __DEBUG_H

#include <sys/types.h>
#include <linux/unistd.h>
#include <errno.h>
#include <syslog.h>
#include <stdbool.h>

extern pid_t gettid(void);

#define sBUG() assert(0)
#define sBUG_ON(p) assert(!(p))

#ifdef EXTRACHECKS
#define EXTRACHECKS_BUG_ON(a)	sBUG_ON(a)
#else
#define EXTRACHECKS_BUG_ON(a)	do { } while (0)
#endif

#define TRACE_NULL           0x00000000
#define TRACE_DEBUG          0x00000001
#define TRACE_FUNCTION       0x00000002
#define TRACE_LINE           0x00000004
#define TRACE_PID            0x00000008
#define TRACE_ENTRYEXIT      0x00000010
#define TRACE_BUFF           0x00000020
#define TRACE_MEMORY         0x00000040
#define TRACE_SG             0x00000080
#define TRACE_OUT_OF_MEM     0x00000100
#define TRACE_MINOR          0x00000200 /* less important events */
#define TRACE_MGMT           0x00000400
#define TRACE_MGMT_DEBUG     0x00000800
#define TRACE_SCSI           0x00001000
#define TRACE_SPECIAL        0x00002000 /* filtering debug, etc */
#define TRACE_TIME           0x00004000
#define TRACE_ORDER          0x00008000
#define TRACE_ALL            0xffffffff

#define PRINT(priority, format, args...)			\
do {								\
	if (log_daemon)						\
		syslog(priority, format "\n", ## args);		\
	else							\
		fprintf(stdout, format "\n", ## args);		\
} while (0)

#define PRINTN(priority, format, args...)			\
do {								\
	if (log_daemon)						\
		syslog(priority, format, ## args);		\
	else							\
		fprintf(stdout, format, ## args);		\
} while (0)

extern char *app_name;
#define LOG_PREFIX	app_name

#ifdef LOG_PREFIX
#define __LOG_PREFIX	LOG_PREFIX
#else
#define __LOG_PREFIX	NULL
#endif

extern bool log_daemon;

#if defined(DEBUG) || defined(TRACING)

extern unsigned long trace_flag;

extern int debug_init(void);
extern void debug_done(void);

/*
 * We don't print prefix for debug traces to not put additional preasure
 * on the logging system in case of a lot of logging.
 */

extern int debug_print_prefix(unsigned long trace_flag, const char *prefix,
			      const char *func, int line);
extern void debug_print_buffer(const void *data, int len);

#define TRACE(trace, format, args...)				\
do {								\
	if (trace_flag & (trace)) {				\
		debug_print_prefix(trace_flag, __LOG_PREFIX,	\
			__func__, __LINE__);			\
		PRINT(LOG_DEBUG, format, args);			\
	}							\
} while (0)

#define PRINT_BUFFER(message, buff, len)			\
do {								\
	PRINT(LOG_INFO, "%s:", message);			\
	debug_print_buffer(buff, len);				\
} while (0)

#else  /* DEBUG || TRACING */

#define TRACE(trace, args...) do {} while (0)
#define PRINT_BUFFER(message, buff, len) do {} while (0)

static inline int debug_init(void) { return 0; }
static inline void debug_done(void) {}

#endif /* DEBUG || TRACING */

#ifdef DEBUG

#include <assert.h>

#define TRACE_MEM(format, args...)				\
do {								\
	if (trace_flag & TRACE_MEMORY) {			\
		debug_print_prefix(trace_flag, NULL,		\
				__func__, __LINE__);		\
		PRINT(LOG_DEBUG, format, args);			\
	}							\
} while (0)

#define TRACE_DBG(format, args...)				\
do {								\
	if (trace_flag & TRACE_DEBUG) {				\
		debug_print_prefix(trace_flag, NULL,		\
			__func__, __LINE__);			\
		PRINT(LOG_DEBUG, format, args);			\
	}							\
} while (0)

#define TRACE_DBG_SPECIAL(args...)	TRACE(TRACE_DEBUG|TRACE_SPECIAL, args)

#define TRACE_MGMT_DBG(format, args...)				\
do {								\
	if (trace_flag & TRACE_MGMT_DEBUG) {			\
		debug_print_prefix(trace_flag, NULL,		\
			__func__, __LINE__);			\
		PRINT(LOG_DEBUG, format, args);			\
	}							\
} while (0)

#define TRACE_BUFFER(message, buff, len)			\
do {								\
	if (trace_flag & TRACE_BUFF) {				\
		debug_print_prefix(trace_flag, NULL,		\
			__func__, __LINE__);			\
		PRINT(LOG_DEBUG, "%s:", message);		\
		debug_print_buffer(buff, len);			\
	}							\
} while (0)

#define TRACE_BUFF_FLAG(flag, message, buff, len)		\
do {								\
	if (trace_flag & (flag)) {				\
		debug_print_prefix(trace_flag, NULL,		\
			__func__, __LINE__);			\
		PRINT(LOG_DEBUG, "%s:", message);		\
		debug_print_buffer(buff, len);			\
	}							\
} while (0)

#define PRINT_INFO(format, args...)				\
do {								\
	debug_print_prefix(trace_flag, __LOG_PREFIX,		\
			__func__, __LINE__);			\
	PRINT(LOG_INFO, format, args);				\
} while (0)

#define PRINT_WARNING(format, args...)				\
do {								\
	debug_print_prefix(trace_flag, __LOG_PREFIX,		\
			__func__, __LINE__);			\
	PRINT(LOG_WARNING, "***WARNING*** " format, args);	\
} while (0)

#define PRINT_ERROR(format, args...)				\
do {								\
	debug_print_prefix(trace_flag, __LOG_PREFIX,		\
			__func__, __LINE__);			\
	PRINT(LOG_ERR, "***ERROR*** " format, args);		\
} while (0)

#define TRACE_ENTRY()						\
do {								\
	if (trace_flag & TRACE_ENTRYEXIT) {			\
		if (trace_flag & TRACE_PID) {			\
			PRINT(LOG_DEBUG, "[%d]: ENTRY %s",	\
				gettid(), __func__);		\
		} else {					\
			PRINT(LOG_DEBUG, "ENTRY %s",		\
				__func__);			\
		}						\
	}							\
} while (0)

#define TRACE_EXIT()						\
do {								\
	if (trace_flag & TRACE_ENTRYEXIT) {			\
		if (trace_flag & TRACE_PID) {			\
			PRINT(LOG_DEBUG, "[%d]: EXIT %s",	\
				gettid(), __func__);		\
		} else {					\
			PRINT(LOG_DEBUG, "EXIT %s", __func__);	\
		}						\
	}							\
} while (0)

#define TRACE_EXIT_RES(res)					\
do {								\
	if (trace_flag & TRACE_ENTRYEXIT) {			\
		if (trace_flag & TRACE_PID) {			\
			PRINT(LOG_DEBUG, "[%d]: EXIT %s: %ld",	\
				gettid(), __func__,		\
				(long)(res));			\
		} else {					\
			PRINT(LOG_DEBUG, "EXIT %s: %ld",	\
				__func__, (long)(res));		\
		}						\
	}							\
} while (0)

#define TRACE_EXIT_HRES(res)					\
do {								\
	if (trace_flag & TRACE_ENTRYEXIT) {			\
		if (trace_flag & TRACE_PID) {			\
			PRINT(LOG_DEBUG, "[%d]: EXIT %s: 0x%lx",\
				gettid(), __func__,		\
				(long)(res));			\
		} else {					\
			PRINT(LOG_DEBUG, "EXIT %s: %lx",	\
				__func__, (long)(res));		\
		}						\
	}							\
} while (0)

#else  /* DEBUG */

#define	NDEBUG
#include <assert.h>

#define TRACE_MEM(format, args...) do {} while (0)
#define TRACE_DBG(format, args...) do {} while (0)
#define TRACE_DBG_SPECIAL(args...) do {} while (0)
#define TRACE_MGMT_DBG(format, args...) do {} while (0)
#define TRACE_BUFFER(message, buff, len) do {} while (0)
#define TRACE_BUFF_FLAG(flag, message, buff, len) do {} while (0)
#define TRACE_ENTRY() do {} while (0)
#define TRACE_EXIT() do {} while (0)
#define TRACE_EXIT_RES(res) do {} while (0)
#define TRACE_EXIT_HRES(res) do {} while (0)

#ifdef LOG_PREFIX

#define PRINT_INFO(format, args...)				\
	PRINT(LOG_INFO, "%s: " format, LOG_PREFIX, args)	\

#define PRINT_WARNING(format, args...)				\
	PRINT(LOG_WARNING, "%s: ***WARNING*** "	format,		\
		LOG_PREFIX, args)				\

#define PRINT_ERROR(format, args...)				\
	PRINT(LOG_ERR, "%s: ***ERROR*** " format,		\
		LOG_PREFIX, args)				\

#else

#define PRINT_INFO(format, args...) PRINT(LOG_INFO, format, args)

#define PRINT_WARNING(format, args...)				\
	PRINT(LOG_WARNING, "***WARNING*** " format, args)	\

#define PRINT_ERROR(format, args...)				\
	PRINT(LOG_ERR, "***ERROR*** " format, args)		\

#endif /* LOG_PREFIX */

#endif /* DEBUG */

#endif /* __DEBUG_H */
