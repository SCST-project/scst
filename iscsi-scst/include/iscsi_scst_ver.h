/*
 *  Copyright (C) 2007 - 2010 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
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

/* #define CONFIG_SCST_PROC */

#ifdef CONFIG_SCST_PROC
#define ISCSI_VERSION_STRING_SUFFIX  "-procfs"
#else
#define ISCSI_VERSION_STRING_SUFFIX
#endif

#define ISCSI_VERSION_STRING	"2.0.0-rc3" ISCSI_VERSION_STRING_SUFFIX
