/*
 *  scst_debug.c
 *  
 *  Copyright (C) 2004-2007 Vladislav Bolkhovitin <vst@vlnb.net>
 *                 and Leonid Stoljar
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

#include "scsi_tgt.h"
#include "scst_debug.h"

#if defined(DEBUG) || defined(TRACING)

#define TRACE_BUF_SIZE    512

static char trace_buf[TRACE_BUF_SIZE];
static spinlock_t trace_buf_lock = SPIN_LOCK_UNLOCKED;

int debug_print_prefix(unsigned long trace_flag, const char *func, 
			int line)
{
	int i = 0;
	unsigned long flags;

	spin_lock_irqsave(&trace_buf_lock, flags);

	if (trace_flag & TRACE_PID)
		i += snprintf(&trace_buf[i], TRACE_BUF_SIZE, "[%d]: ",
			      current->pid);
	if (trace_flag & TRACE_FUNCTION)
		i += snprintf(&trace_buf[i], TRACE_BUF_SIZE - i, "%s:", func);
	if (trace_flag & TRACE_LINE)
		i += snprintf(&trace_buf[i], TRACE_BUF_SIZE - i, "%i:", line);

	if (i > 0)
		PRINTN(LOG_FLAG, "%s", trace_buf);

	spin_unlock_irqrestore(&trace_buf_lock, flags);

	return i;
}

void debug_print_buffer(const void *data, int len)
{
	int z, z1, i;
	const unsigned char *buf = (const unsigned char *) data;
	int f = 0;
	unsigned long flags;

	if (buf == NULL)
		return;

	spin_lock_irqsave(&trace_buf_lock, flags);

	PRINT(NO_FLAG, " (h)___0__1__2__3__4__5__6__7__8__9__A__B__C__D__E__F");
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
				PRINT(NO_FLAG, "%s", trace_buf);
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
		PRINT(LOG_FLAG, "%s", trace_buf)
	} else {
		PRINT(NO_FLAG, "%s", trace_buf);
	}

	spin_unlock_irqrestore(&trace_buf_lock, flags);
	return;
}

EXPORT_SYMBOL(debug_print_prefix);
EXPORT_SYMBOL(debug_print_buffer);
#endif /* DEBUG || TRACING */
