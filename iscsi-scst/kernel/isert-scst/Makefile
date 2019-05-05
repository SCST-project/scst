#
#  Makefile for the kernel part of iSER-SCST.
#
#  Copyright (C) 2007 - 2014 Vladislav Bolkhovitin
#  Copyright (C) 2007 - 2014 Fusion-io, Inc.
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

LINUXINCLUDE := $(PRE_CFLAGS) $(LINUXINCLUDE)
ccflags-y += -I$(src)/../../include -I$(KBUILD_EXTMOD)/../../../scst/include
ccflags-y += $(call cc-option,-Wextra) \
	$(call cc-option,-Wno-old-style-declaration) \
	-Wno-unused-parameter -Wno-missing-field-initializers

obj-m		+= isert-scst.o
isert-scst-objs	:= isert.o isert_login.o \
		iser_datamover.o iser_rdma.o iser_buf.o iser_pdu.o iser_global.o

