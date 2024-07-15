/* SPDX-License-Identifier: GPL-2.0 */
#if !defined(_TRACE_QLA_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_QLA_H_

#ifndef INSIDE_KERNEL_TREE
#include <linux/version.h>
#endif
#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM qla

#define QLA_MSG_MAX 256

#if __GNUC__ * 256 + __GNUC_MINOR__ >= 4 * 256 + 6
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsuggest-attribute=format"
#endif

DECLARE_EVENT_CLASS(qla_log_event,
	TP_PROTO(const char *buf,
		struct va_format *vaf),

	TP_ARGS(buf, vaf),

	TP_STRUCT__entry(
		__string(buf, buf)
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
		__dynamic_array(char, msg, QLA_MSG_MAX)
#else
		__vstring(msg, vaf->fmt, vaf->va)
#endif
	),
	TP_fast_assign(
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 10, 0)
		__assign_str(buf, buf);
#else
		__assign_str(buf);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
		vsnprintf(__get_str(msg), QLA_MSG_MAX, vaf->fmt, *vaf->va);
#else
		__assign_vstr(msg, vaf->fmt, vaf->va);
#endif
	),

	TP_printk("%s %s", __get_str(buf), __get_str(msg))
);

DEFINE_EVENT(qla_log_event, ql_dbg_log,
	TP_PROTO(const char *buf, struct va_format *vaf),
	TP_ARGS(buf, vaf)
);

#if __GNUC__ * 256 + __GNUC_MINOR__ >= 4 * 256 + 6
#pragma GCC diagnostic pop
#endif

#endif /* _TRACE_QLA_H */

#define TRACE_INCLUDE_FILE qla

#include <trace/define_trace.h>
