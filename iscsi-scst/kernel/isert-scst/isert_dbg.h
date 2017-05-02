/*
 *  Copyright (C) 2007 - 2014 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2014 Fusion-io, Inc.
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

#ifndef ISERT_DBG_H
#define ISERT_DBG_H

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif

#define LOG_PREFIX "isert" /* Prefix for SCST tracing macros. */

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst_debug.h>
#else
#include <linux/version.h>
#include <scst_debug.h>
#endif

#ifdef CONFIG_SCST_DEBUG
#define ISERT_DEFAULT_LOG_FLAGS (TRACE_FUNCTION | TRACE_LINE | TRACE_PID | \
	TRACE_OUT_OF_MEM | TRACE_MGMT | TRACE_MGMT_DEBUG | \
	TRACE_MINOR | TRACE_SPECIAL)
#else
#define ISERT_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MGMT | TRACE_PID | \
	TRACE_SPECIAL)
#endif

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
extern unsigned long isert_trace_flag;
#define trace_flag isert_trace_flag
#endif

#endif
