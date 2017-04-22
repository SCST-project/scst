/*
 *  Copyright (C) 2007 - 2017 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2017 SanDisk Corporation
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

#define ISCSI_VERSION_STRING	"3.3.0-pre1" ISCSI_VERSION_STRING_SUFFIX
