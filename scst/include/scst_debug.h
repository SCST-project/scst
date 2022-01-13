/*
 *  include/scst_debug.h
 *
 *  Copyright (C) 2004 - 2018 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 - 2018 Western Digital Corporation
 *
 *  Contains macros for execution tracing and error reporting
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

#ifndef __SCST_DEBUG_H
#define __SCST_DEBUG_H

#include <generated/autoconf.h>	/* for CONFIG_* */
#include <linux/bug.h>		/* for WARN_ON_ONCE */
#include <linux/ratelimit.h>

#ifdef INSIDE_KERNEL_TREE
#include <scst/backport.h>
#else
#include <build_mode.h>
#include <backport.h>
#endif

#if !defined(INSIDE_KERNEL_TREE)
#ifdef CONFIG_SCST_DEBUG

#ifdef __CHECKER__
/*
 * Avoid that the while (...) local_bh_enable() loop confuses the lock checking
 * code in smatch.
 */
#define sBUG()		BUG()
#define sBUG_ON(p)	BUG_ON((p))
#else
#define sBUG() do {						\
	pr_crit("BUG at %s:%d\n",  __FILE__, __LINE__);		\
	local_irq_enable();					\
	while (in_softirq())					\
		local_bh_enable();				\
	BUG();							\
} while (0)

#define sBUG_ON(p) do {						\
	if (unlikely(p)) {					\
		pr_crit("BUG at %s:%d (%s)\n",			\
			__FILE__, __LINE__, #p);		\
		local_irq_enable();				\
		while (in_softirq())				\
			local_bh_enable();			\
		BUG();						\
	}							\
} while (0)
#endif

#else

#define sBUG() BUG()
#define sBUG_ON(p) BUG_ON(p)

#endif
#endif

#if defined(CONFIG_SCST_EXTRACHECKS) || defined(__COVERITY__)
#define EXTRACHECKS_BUG()		sBUG()
#define EXTRACHECKS_BUG_ON(a)		sBUG_ON(a)
#define EXTRACHECKS_WARN_ON(a)		WARN_ON(a)
#define EXTRACHECKS_WARN_ON_ONCE(a)	WARN_ON_ONCE(a)
#else
#define EXTRACHECKS_BUG()		do { } while (0)
#define EXTRACHECKS_BUG_ON(a)		do { } while (0)
#define EXTRACHECKS_WARN_ON(a)		do { } while (0)
#define EXTRACHECKS_WARN_ON_ONCE(a)	do { } while (0)
#endif

#define TRACE_NULL           0x00000000
#define TRACE_DEBUG          0x00000001
#define TRACE_FUNCTION       0x00000002
#define TRACE_LINE           0x00000004
#define TRACE_PID            0x00000008
#ifndef GENERATING_UPSTREAM_PATCH
#define TRACE_ENTRYEXIT      0x00000010
#endif
#define TRACE_BUFF           0x00000020
#define TRACE_MEMORY         0x00000040
#define TRACE_SG_OP          0x00000080
#define TRACE_OUT_OF_MEM     0x00000100
#define TRACE_MINOR          0x00000200 /* less important events */
#define TRACE_MGMT           0x00000400
#define TRACE_MGMT_DEBUG     0x00000800
#define TRACE_SCSI           0x00001000
#define TRACE_SPECIAL        0x00002000 /* filtering debug, etc */
#define TRACE_FLOW_CONTROL   0x00004000 /* flow control in action */
#define TRACE_PRES           0x00008000
#define TRACE_BLOCKING       0x00010000
#define TRACE_ALL            0xffffffff
/* Flags 0xXXXXXXXXXX000000 are local for users */

#define TRACE_MINOR_AND_MGMT_DBG	(TRACE_MINOR|TRACE_MGMT_DEBUG)

/*
 * Note: in the next two printk() statements the KERN_CONT macro is only
 * present to suppress a checkpatch warning (KERN_CONT is defined as "").
 */
#define PRINT(log_flag, format, args...)  \
		printk(log_flag format "\n", ## args)
#define PRINTN(log_flag, format, args...) \
		printk(log_flag format, ## args)

#ifdef LOG_PREFIX
#define __LOG_PREFIX	LOG_PREFIX
#else
#define __LOG_PREFIX	NULL
#endif

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

#ifndef CONFIG_SCST_DEBUG
#define ___unlikely(a)		(a)
#else
#define ___unlikely(a)		unlikely(a)
#endif

int __printf(6, 7)
debug_print_with_prefix(unsigned long trace_flag,
	const char *severity, const char *prefix, const char *func, int line,
	const char *fmt, ...);
void debug_print_buffer(const void *data, int len);
const char *debug_transport_id_to_initiator_name(const uint8_t *transport_id);

#define TRACING_MINOR() (trace_flag & TRACE_MINOR)

#define TRACE(trace, format, args...)					\
do {									\
	if (___unlikely(trace_flag & (trace))) {			\
		debug_print_with_prefix(trace_flag, KERN_INFO,		\
			__LOG_PREFIX, __func__, __LINE__, format, ## args); \
	}								\
} while (0)

#define TRACE_PR(format, args...) TRACE(TRACE_PRES, format, ## args)

#ifdef CONFIG_SCST_DEBUG

#define PRINT_BUFFER(message, buff, len)                            \
do {                                                                \
	PRINT(KERN_INFO, "%s:%s:", __func__, message);		    \
	debug_print_buffer(buff, len);				    \
} while (0)

#else

#define PRINT_BUFFER(message, buff, len)                            \
do {                                                                \
	PRINT(KERN_INFO, "%s:", message);			    \
	debug_print_buffer(buff, len);				    \
} while (0)

#endif

#define PRINT_BUFF_FLAG(flag, message, buff, len)			\
do {									\
	if (___unlikely(trace_flag & (flag))) {				\
		debug_print_with_prefix(trace_flag, KERN_INFO, NULL,	\
			__func__, __LINE__, "%s:", message);		\
		debug_print_buffer(buff, len);				\
	}								\
} while (0)

#define PRINT_LOG_FLAG(log_flag, format, args...)			\
	debug_print_with_prefix(trace_flag, KERN_INFO, __LOG_PREFIX,	\
		__func__, __LINE__, format, ## args)

#define PRINT_WARNING(format, args...)					\
	debug_print_with_prefix(trace_flag, KERN_WARNING, __LOG_PREFIX,	\
		__func__, __LINE__, "***WARNING***: " format, ## args)

#define PRINT_ERROR(format, args...)					\
	debug_print_with_prefix(trace_flag, KERN_ERR, __LOG_PREFIX,	\
		__func__, __LINE__, "***ERROR***: " format, ## args)

#define PRINT_CRIT_ERROR(format, args...)				\
	debug_print_with_prefix(trace_flag, KERN_CRIT, __LOG_PREFIX,	\
		__func__, __LINE__, "***CRITICAL ERROR***: " format, ## args)

#define PRINT_INFO(format, args...)					\
	debug_print_with_prefix(trace_flag, KERN_INFO, __LOG_PREFIX,	\
		__func__, __LINE__, format, ## args)

#else  /* CONFIG_SCST_DEBUG || CONFIG_SCST_TRACING */

#define TRACING_MINOR() (false)

#define TRACE(trace, format, args...)			\
	do { (void)(trace); no_printk(format, ##args); } while (0)
#define PRINT_BUFFER(message, buff, len)		\
	((void)(message), (void)(buff), (void)(len))
#define PRINT_BUFF_FLAG(flag, message, buff, len)	\
	((void)(flag), (void)(message), (void)(buff), (void)(len))

/*
 * no_printk still calls its arguments, so we can not use it in perf build
 * for TRACE_PR or debug_transport_id_to_initiator_name() is not going to
 * be found.
 */
#define TRACE_PR(format, args...) do { } while (0)

#ifdef LOG_PREFIX

#define PRINT_INFO(format, args...)				\
	PRINT(KERN_INFO, "%s: " format, LOG_PREFIX, ## args)

#define PRINT_WARNING(format, args...)				\
	PRINT(KERN_WARNING, "%s: ***WARNING***: " format, LOG_PREFIX, ## args)

#define PRINT_ERROR(format, args...)				\
	PRINT(KERN_ERR, "%s: ***ERROR***: " format, LOG_PREFIX, ## args)

#define PRINT_CRIT_ERROR(format, args...)       \
	PRINT(KERN_CRIT, "%s: ***CRITICAL ERROR***: " \
		format, LOG_PREFIX, ## args)

#else /* LOG_PREFIX */

#define PRINT_INFO(format, args...)		\
	PRINT(KERN_INFO, format, ## args)

#define PRINT_WARNING(format, args...)          \
	PRINT(KERN_WARNING, "***WARNING***: " format, ## args)

#define PRINT_ERROR(format, args...)		\
	PRINT(KERN_ERR, "***ERROR***: " format, ## args)

#define PRINT_CRIT_ERROR(format, args...)	\
	PRINT(KERN_CRIT, "***CRITICAL ERROR***: " format, ## args)

#endif /* LOG_PREFIX */

#endif /* CONFIG_SCST_DEBUG || CONFIG_SCST_TRACING */

#define PRINT_ERROR_RATELIMITED(format, args...)	\
	do {						\
		static DEFINE_RATELIMIT_STATE(_rs,      \
			DEFAULT_RATELIMIT_INTERVAL,	\
			DEFAULT_RATELIMIT_BURST);	\
							\
		if (__ratelimit(&_rs))			\
			PRINT_ERROR(format, ##args);	\
	} while (0)

#ifdef CONFIG_SCST_DEBUG

#define TRACE_DBG_FLAG(trace, format, args...)				\
do {									\
	if (trace_flag & (trace)) {					\
		debug_print_with_prefix(trace_flag, KERN_INFO, NULL,	\
			__func__, __LINE__, format, ## args);		\
	}								\
} while (0)

#define TRACE_MEM(format, args...) \
		TRACE_DBG_FLAG(TRACE_MEMORY, format, ## args)
#define TRACE_SG(format, args...) \
		TRACE_DBG_FLAG(TRACE_SG_OP, format, ## args)
#define TRACE_DBG(format, args...) \
		TRACE_DBG_FLAG(TRACE_DEBUG, format, ## args)
#define TRACE_DBG_SPECIAL(format, args...) \
		TRACE_DBG_FLAG(TRACE_DEBUG|TRACE_SPECIAL, format, ## args)
#define TRACE_MGMT_DBG(format, args...) \
		TRACE_DBG_FLAG(TRACE_MGMT_DEBUG, format, ## args)
#define TRACE_MGMT_DBG_SPECIAL(args...)	\
		TRACE_DBG_FLAG(TRACE_MGMT_DEBUG|TRACE_SPECIAL, format, ## args)
#define TRACE_BLOCK(format, args...) \
		TRACE_DBG_FLAG(TRACE_BLOCKING, format, ## args)

#define TRACE_BUFFER(message, buff, len)				\
do {									\
	if (trace_flag & TRACE_BUFF) {					\
		debug_print_with_prefix(trace_flag, KERN_INFO, NULL,	\
			__func__, __LINE__, "%s:", message);		\
		debug_print_buffer(buff, len);				\
	}								\
} while (0)

#define TRACE_BUFF_FLAG(flag, message, buff, len)			\
do {									\
	if (trace_flag & (flag)) {					\
		debug_print_with_prefix(trace_flag, KERN_INFO, NULL,	\
			__func__, __LINE__, "%s:", message);		\
		debug_print_buffer(buff, len);				\
	}								\
} while (0)

#ifndef GENERATING_UPSTREAM_PATCH
#define TRACE_ENTRY()							\
do {									\
	if (trace_flag & TRACE_ENTRYEXIT) {				\
		if (trace_flag & TRACE_PID) {				\
			PRINT(KERN_INFO, "[%d]: ENTRY %s", current->pid, \
				__func__);				\
		}							\
		else {							\
			PRINT(KERN_INFO, "ENTRY %s", __func__);	\
		}							\
	}								\
} while (0)

#define TRACE_EXIT()							\
do {									\
	if (trace_flag & TRACE_ENTRYEXIT) {				\
		if (trace_flag & TRACE_PID) {				\
			PRINT(KERN_INFO, "[%d]: EXIT %s", current->pid,	\
				__func__);				\
		}							\
		else {							\
			PRINT(KERN_INFO, "EXIT %s", __func__);		\
		}							\
	}								\
} while (0)

#define TRACE_EXIT_RES(res)						\
do {									\
	unsigned long lres = res;					\
									\
	if (trace_flag & TRACE_ENTRYEXIT) {				\
		if (trace_flag & TRACE_PID) {				\
			PRINT(KERN_INFO, "[%d]: EXIT %s: %ld", current->pid, \
			      __func__, lres);				\
		} else {						\
			PRINT(KERN_INFO, "EXIT %s: %ld",		\
				__func__, lres);			\
		}							\
	}                                                               \
} while (0)

#define TRACE_EXIT_HRES(res)						\
do {									\
	unsigned long lres = (unsigned long)(res);			\
									\
	if (trace_flag & TRACE_ENTRYEXIT) {				\
		if (trace_flag & TRACE_PID) {				\
			PRINT(KERN_INFO, "[%d]: EXIT %s: 0x%lx", current->pid, \
			      __func__, lres);				\
		} else {						\
			PRINT(KERN_INFO, "EXIT %s: %lx",		\
					__func__, lres);		\
		}							\
	}                                                               \
} while (0)
#endif

#else  /* CONFIG_SCST_DEBUG */

#define TRACE_MEM(format, args...)	no_printk(format, ##args)
#define TRACE_SG(format, args...)	no_printk(format, ##args)
#define TRACE_DBG(format, args...)	no_printk(format, ##args)
#define TRACE_DBG_FLAG(flag, format, args...) \
	do { (void)(flag); no_printk(format, ##args); } while (0)
#define TRACE_DBG_SPECIAL(format, args...)	no_printk(format, ##args)
#define TRACE_MGMT_DBG(format, args...)	no_printk(format, ##args)
#define TRACE_MGMT_DBG_SPECIAL(format, args...)	no_printk(format, ##args)
#define TRACE_BLOCK(format, args...)	no_printk(format, ##args)
#define TRACE_BUFFER(message, buff, len) \
	((void)(message), (void)(buff), (void)(len))
#define TRACE_BUFF_FLAG(flag, message, buff, len) \
	((void)(flag), (void)(message), (void)(buff), (void)(len))

#ifndef GENERATING_UPSTREAM_PATCH
#define TRACE_ENTRY() do {} while (0)
#define TRACE_EXIT() do {} while (0)
#define TRACE_EXIT_RES(res) do {} while (0)
#define TRACE_EXIT_HRES(res) do {} while (0)
#endif

#endif /* CONFIG_SCST_DEBUG */

#if defined(CONFIG_SCST_DEBUG) && defined(CONFIG_DEBUG_SLAB)
#define SCST_SLAB_FLAGS (SLAB_RED_ZONE | SLAB_POISON)
#else
#define SCST_SLAB_FLAGS 0L
#endif

#define PRINT_WARNING_ONCE(format, args...)			\
do {								\
	static bool __warned;					\
	if (!__warned) {					\
		__warned = true;				\
		PRINT_WARNING(format, ## args);			\
	}							\
} while (0)

#endif /* __SCST_DEBUG_H */
