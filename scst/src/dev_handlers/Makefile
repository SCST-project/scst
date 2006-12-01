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
obj-m := scst_cdrom.o scst_changer.o scst_disk.o scst_modisk.o scst_tape.o \
	scst_fileio.o scst_raid.o scst_processor.o
else
ifeq ($(KDIR),)
  KDIR := /lib/modules/$(shell uname -r)/build
endif

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)

install: all
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) \
		modules_install
	-depmod -a

uninstall:
	rm -f $(INSTALL_DIR)/scst_*.ko
endif

INSTALL_DIR := /lib/modules/$(shell uname -r)/extra

EXTRA_CFLAGS += -I$(SUBDIRS) -I$(SUBDIRS)/../include
#EXTRA_CFLAGS += -I$(SUBDIRS) -I$(SUBDIRS)/../../include -I$(SUBDIRS)/..

EXTRA_CFLAGS += -DTRACING

#EXTRA_CFLAGS += -DDEBUG

clean:
	rm -f *.o *.ko .*.cmd *.mod.c .*.d .depend Modules.symvers Module.symvers
	rm -rf .tmp_versions

extraclean: clean

.PHONY: all install uninstall clean extraclean
