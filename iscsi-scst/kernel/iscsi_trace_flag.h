/*
 *  Copyright (C) 2007 - 2017 Vladislav Bolkhovitin
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

#ifndef ISCSI_TRACE_FLAG_H
#define ISCSI_TRACE_FLAG_H

/*
 * Only include this header file from iscsi-scst source files and not from
 * isert-scst source files.
 */

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
extern unsigned long iscsi_trace_flag;
#define trace_flag iscsi_trace_flag
#endif

#endif /* ISCSI_TRACE_FLAG_H */
