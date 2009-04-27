/*
 *  Copyright (C) 2007 - 2009 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2009 ID7 Ltd.
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

#ifndef ISCSI_DBG_H
#define ISCSI_DBG_H

#define LOG_PREFIX "iscsi-scst"

#include <scst_debug.h>

#define TRACE_D_READ		0x80000000
#define TRACE_D_WRITE		0x40000000
#define TRACE_CONN_OC		0x20000000
#define TRACE_D_IOV		0x10000000
#define TRACE_D_DUMP_PDU	0x08000000
#define TRACE_NET_PG		0x04000000
#define TRACE_CONN_OC_DBG	0x02000000

#define TRACE_D_DATA		(TRACE_D_READ | TRACE_D_WRITE)

#define TRACE_ALL_NO_DATA 	\
	(TRACE_ALL & ~TRACE_D_IOV & ~TRACE_D_DUMP_PDU & ~TRACE_D_DATA)

#ifdef CONFIG_SCST_DEBUG
#define ISCSI_DEFAULT_LOG_FLAGS (TRACE_FUNCTION | TRACE_LINE | TRACE_PID | \
	TRACE_OUT_OF_MEM | TRACE_MGMT | TRACE_MGMT_MINOR | TRACE_MGMT_DEBUG | \
	TRACE_MINOR | TRACE_SPECIAL | TRACE_CONN_OC)
#else
#define ISCSI_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MGMT | \
	TRACE_MINOR | TRACE_SPECIAL)
#endif

#ifdef CONFIG_SCST_DEBUG
struct iscsi_pdu;
extern void iscsi_dump_pdu(struct iscsi_pdu *pdu);
#else
#define iscsi_dump_pdu(x) do {} while (0)
#endif

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
extern unsigned long iscsi_trace_flag;
#define trace_flag iscsi_trace_flag
#endif

#ifdef CONFIG_SCST_DEBUG

#define TRACE_CONN_CLOSE(args...)	TRACE(TRACE_CONN_OC, args)
#define TRACE_CONN_CLOSE_DBG(args...)	TRACE(TRACE_CONN_OC_DBG, args)
#define TRACE_NET_PAGE(args...)		TRACE(TRACE_NET_PG, args)
#define TRACE_WRITE(args...)		TRACE(TRACE_D_WRITE, args)
#define TRACE_READ(args...)		TRACE(TRACE_D_READ, args)

#else /* CONFIG_SCST_DEBUG */
#define TRACE_CONN_CLOSE(format, args...) {}
#define TRACE_CONN_CLOSE_DBG(format, args...) {}
#define TRACE_NET_PAGE(format, args...) {}
#define TRACE_WRITE(args...) {}
#define TRACE_READ(args...) {}
#endif

#endif
