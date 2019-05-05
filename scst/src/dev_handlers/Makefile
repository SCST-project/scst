#
#  SCSI target mid-level dev handler's makefile
#
#  Copyright (C) 2015 - 2018 Vladislav Bolkhovitin <vst@vlnb.net>
#  Copyright (C) 2004 - 2005 Leonid Stoljar
#  Copyright (C) 2007 - 2018 Western Digital Corporation
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

SHELL=/bin/bash

ifneq ($(PATCHLEVEL),)
ccflags-y += -I$(KBUILD_EXTMOD)/../include				\
	$(call cc-option,-Wextra)					\
	-Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare
#ccflags-y += -DCONFIG_DEBUG_EXT_COPY_REMAP

obj-m := scst_cdrom.o scst_changer.o scst_disk.o scst_modisk.o scst_tape.o \
	scst_vdisk.o scst_raid.o scst_processor.o scst_user.o

else
######### BEGIN OUT-OF-TREE RULES #########

ifeq ($(KVER),)
  ifeq ($(KDIR),)
    KVER := $(shell uname -r)
    KDIR := /lib/modules/$(KVER)/build
  else
    KVER := $(strip $(shell						\
	cat $(KDIR)/include/config/kernel.release 2>/dev/null ||	\
	make -s -C $(KDIR) kernelversion))
  endif
else
  KDIR := /lib/modules/$(KVER)/build
endif

ifeq ($(INSTALL_MOD_PATH),)
  export INSTALL_MOD_PATH := $(DESTDIR)
endif

INSTALL_DIR := $(INSTALL_MOD_PATH)/lib/modules/$(KVER)/extra

all:
	$(MAKE) -C $(KDIR) M=$(shell pwd)

install: all
	mkdir -p $(DESTDIR)/var/lib/scst/vdev_mode_pages
	$(MAKE) -C $(KDIR) M=$(shell pwd) \
		$$([ -n "$(DESTDIR)$(INSTALL_MOD_PATH)" ] && echo DEPMOD=true) \
		modules_install

uninstall:
	rm -f $(INSTALL_DIR)/dev_handlers/scst_*.ko

########## END OUT-OF-TREE RULES ##########
endif

clean:
	rm -f *.o *.ko .*.cmd *.mod.c .*.d .depend Modules.symvers \
		Module.symvers Module.markers modules.order
	rm -rf .tmp_versions

extraclean: clean
	rm -f *.orig *.rej

.PHONY: all install uninstall clean extraclean
