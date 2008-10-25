#
#  SCSI target mid-level dev handler's makefile
#  
#  Copyright (C) 2004 - 2008 Vladislav Bolkhovitin <vst@vlnb.net>
#  Copyright (C) 2004 - 2005 Leonid Stoljar
#  Copyright (C) 2007 - 2008 CMS Distribution Limited
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
#
# Main targets:
#    all (the default) : make all
#    clean             : clean files
#    extraclean        : clean + clean dependencies
#    install           : install 
#    uninstall         : uninstall 
#
# Notes :
#    - install and uninstall must be made as root
#

ifneq ($(KERNELRELEASE),)
SCST_INC_DIR := $(SUBDIRS)/../include

obj-m := scst_cdrom.o scst_changer.o scst_disk.o scst_modisk.o scst_tape.o \
	scst_vdisk.o scst_raid.o scst_processor.o scst_user.o

obj-$(CONFIG_SCST_DISK)		+= scst_disk.o
obj-$(CONFIG_SCST_TAPE)		+= scst_tape.o
obj-$(CONFIG_SCST_CDROM)	+= scst_cdrom.o
obj-$(CONFIG_SCST_MODISK)	+= scst_modisk.o
obj-$(CONFIG_SCST_CHANGER)	+= scst_changer.o
obj-$(CONFIG_SCST_RAID)		+= scst_raid.o
obj-$(CONFIG_SCST_PROCESSOR)	+= scst_processor.o
obj-$(CONFIG_SCST_VDISK)	+= scst_vdisk.o
obj-$(CONFIG_SCST_USER)		+= scst_user.o

else
ifeq ($(KDIR),)
  KVER = $(shell uname -r)
  KDIR := /lib/modules/$(KVER)/build
endif

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)

install: all
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) \
		modules_install
	-/sbin/depmod -a $(KVER)

uninstall:
	rm -f $(INSTALL_DIR)/scst_*.ko
endif

ifeq ($(KVER),)
INSTALL_DIR := /lib/modules/$(shell uname -r)/extra
else
INSTALL_DIR := /lib/modules/$(KVER)/extra
endif

EXTRA_CFLAGS += -I$(SUBDIRS) -I$(SCST_INC_DIR) -Wextra -Wno-unused-parameter \
		-Wno-missing-field-initializers

EXTRA_CFLAGS += -DCONFIG_SCST_EXTRACHECKS

#EXTRA_CFLAGS += -DCONFIG_SCST_TRACING
EXTRA_CFLAGS += -DCONFIG_SCST_DEBUG -g -W

clean:
	rm -f *.o *.ko .*.cmd *.mod.c .*.d .depend Modules.symvers \
		Module.symvers Module.markers modules.order
	rm -rf .tmp_versions

extraclean: clean

.PHONY: all install uninstall clean extraclean
