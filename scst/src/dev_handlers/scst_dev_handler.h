#ifndef __SCST_DEV_HANDLER_H
#define __SCST_DEV_HANDLER_H

#include <linux/module.h>
#include <scsi/scsi_eh.h>
#ifdef INSIDE_KERNEL_TREE
#include <scst/scst_debug.h>
#else
#include "scst_debug.h"
#endif

#define SCST_DEV_RETRIES_ON_UA 5
#define SCST_PASSTHROUGH_RETRIES	0

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

#ifdef CONFIG_SCST_DEBUG
#define SCST_DEFAULT_DEV_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_PID | \
	TRACE_LINE | TRACE_FUNCTION | TRACE_MGMT | TRACE_MINOR | \
	TRACE_MGMT_DEBUG | TRACE_SPECIAL)
#else
#define SCST_DEFAULT_DEV_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MGMT | TRACE_PID | \
	TRACE_SPECIAL)
#endif

static unsigned long dh_trace_flag = SCST_DEFAULT_DEV_LOG_FLAGS;
#define trace_flag dh_trace_flag

#endif /* defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING) */

#endif /* __SCST_DEV_HANDLER_H */
