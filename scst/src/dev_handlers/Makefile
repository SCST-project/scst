#
#  SCSI target mid-level dev handler's makefile
#  
#  Copyright (C) 2004 Vladislav Bolkhovitin <vst@vlnb.net>
#                 and Leonid Stoljar
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
	scst_vdisk.o scst_raid.o scst_processor.o

obj-$(CONFIG_SCSI_TARGET_DISK)    += scst_disk.o
obj-$(CONFIG_SCSI_TARGET_TAPE)    += scst_tape.o
obj-$(CONFIG_SCSI_TARGET_CDROM)   += scst_cdrom.o
obj-$(CONFIG_SCSI_TARGET_MODISK)  += scst_modisk.o
obj-$(CONFIG_SCSI_TARGET_CHANGER) += scst_changer.o
obj-$(CONFIG_SCSI_TARGET_RAID)    += scst_raid.o
obj-$(CONFIG_SCSI_TARGET_PROCESSOR) += scst_processor.o
obj-$(CONFIG_SCSI_TARGET_VDISK)  += scst_vdisk.o

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
	-depmod -a $(KVER)

uninstall:
	rm -f $(INSTALL_DIR)/scst_*.ko
endif

INSTALL_DIR := /lib/modules/$(shell uname -r)/extra

EXTRA_CFLAGS += -I$(SUBDIRS) -I$(SCST_INC_DIR) -Wextra -Wno-unused-parameter

EXTRA_CFLAGS += -DEXTRACHECKS

#EXTRA_CFLAGS += -DTRACING
EXTRA_CFLAGS += -DDEBUG -g

clean:
	rm -f *.o *.ko .*.cmd *.mod.c .*.d .depend Modules.symvers Module.symvers
	rm -rf .tmp_versions

extraclean: clean

.PHONY: all install uninstall clean extraclean
