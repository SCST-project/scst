#
#  Makefile for the kernel part of iSCSI-SCST.
#
#  Copyright (C) 2007 - 2013 Vladislav Bolkhovitin
#  Copyright (C) 2007 - 2010 ID7 Ltd.
#  Copyright (C) 2010 - 2013 SCST Ltd.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation, version 2
#  of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.
#
#  Note! Dependencies are done automatically by 'make dep', which also
#  removes any old dependencies. DON'T put your own dependencies here
#  unless it's something special (not a .c file).
#
#  Note 2! The CFLAGS definitions are now in the main makefile.

cc-option = $(shell if $(CC) $(CFLAGS) $(1) -S -o /dev/null -xc /dev/null \
             > /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi ;)
enable-Wextra = $(shell uname_r="$$(uname -r)"; if [ "$${uname_r%.el5}" = "$${uname_r}" ]; then echo "$(1)"; fi)

EXTRA_CFLAGS += -I$(src)/../include -I$(SCST_INC_DIR)
EXTRA_CFLAGS += $(call enable-Wextra,-Wextra \
	$(call cc-option,-Wno-old-style-declaration) \
	-Wno-unused-parameter -Wno-missing-field-initializers)

EXTRA_CFLAGS += -DCONFIG_SCST_EXTRACHECKS
#EXTRA_CFLAGS += -DCONFIG_SCST_TRACING
EXTRA_CFLAGS += -DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions

#EXTRA_CFLAGS += -DCONFIG_SCST_ISCSI_DEBUG_DIGEST_FAILURES

obj-m		+= iscsi-scst.o
iscsi-scst-objs	:= iscsi.o nthread.o config.o digest.o \
	conn.o session.o target.o event.o param.o

