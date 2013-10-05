/*
 *  Copyright (C) 2007 - 2013 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
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

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst_debug.h>
#else
#include <scst_debug.h>
#endif

#define TRACE_D_WRITE		0x80000000
#define TRACE_CONN_OC		0x40000000
#define TRACE_D_IOV		0x20000000
#define TRACE_D_DUMP_PDU	0x10000000
#define TRACE_NET_PG		0x08000000
#define TRACE_CONN_OC_DBG	0x04000000

#ifdef CONFIG_SCST_DEBUG
#define ISCSI_DEFAULT_LOG_FLAGS (TRACE_FUNCTION | TRACE_LINE | TRACE_PID | \
	TRACE_OUT_OF_MEM | TRACE_MGMT | TRACE_MGMT_DEBUG | \
	TRACE_MINOR | TRACE_SPECIAL | TRACE_CONN_OC)
#else
#define ISCSI_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MGMT | \
	TRACE_SPECIAL)
#endif

#ifdef CONFIG_SCST_DEBUG
struct iscsi_pdu;
struct iscsi_cmnd;
extern void iscsi_dump_pdu(struct iscsi_pdu *pdu);
extern unsigned long iscsi_get_flow_ctrl_or_mgmt_dbg_log_flag(
	struct iscsi_cmnd *cmnd);
#else
#define iscsi_dump_pdu(x) do {} while (0)
#define iscsi_get_flow_ctrl_or_mgmt_dbg_log_flag(x) do {} while (0)
#endif

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
extern unsigned long iscsi_trace_flag;
#define trace_flag iscsi_trace_flag
#endif

#define TRACE_CONN_CLOSE(args...)	TRACE_DBG_FLAG(TRACE_DEBUG|TRACE_CONN_OC, args)
#define TRACE_CONN_CLOSE_DBG(args...)	TRACE(TRACE_CONN_OC_DBG, args)
#define TRACE_NET_PAGE(args...)		TRACE_DBG_FLAG(TRACE_NET_PG, args)
#define TRACE_WRITE(args...)		TRACE_DBG_FLAG(TRACE_DEBUG|TRACE_D_WRITE, args)

#endif
