#
# Makefile for the kernel part of iSCSI-SCST.
#
# Copyright (C) 2007 - 2008 Vladislav Bolkhovitin
# Copyright (C) 2007 - 2008 CMS Distribution Limited
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation, version 2
# of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (not a .c file).
#
# Note 2! The CFLAGS definitions are now in the main makefile.

EXTRA_CFLAGS += -I$(src)/../include -I$(SCST_INC_DIR)
# -Wextra -Wno-unused-parameter

EXTRA_CFLAGS += -DCONFIG_SCST_EXTRACHECKS
#EXTRA_CFLAGS += -DCONFIG_SCST_TRACING
EXTRA_CFLAGS += -DCONFIG_SCST_DEBUG -g

#EXTRA_CFLAGS += -DCONFIG_SCST_ISCSI_DEBUG_DIGEST_FAILURES

obj-m		+= iscsi-scst.o
iscsi-scst-objs	:= iscsi.o nthread.o config.o digest.o \
	conn.o session.o target.o event.o param.o

