#
#  SCSI target mid-level makefile
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

DEV_HANDLERS_DIR = dev_handlers

ifneq ($(KERNELRELEASE),)
SCST_INC_DIR := $(SUBDIRS)/../include

obj-m := scst.o
scst-objs := scst_main.o scst_targ.o scst_lib.o scst_mem.o scst_proc.o

scst-y        += scst_main.o
scst-y        += scst_targ.o
scst-y        += scst_lib.o
scst-y        += scst_proc.o
scst-y        += scst_mem.o
scst-y        += scst_debug.o
obj-$(CONFIG_SCSI_TARGET)   += scst.o dev_handlers/

obj-$(BUILD_DEV) += $(DEV_HANDLERS_DIR)/

else
ifeq ($(KVER),)
  ifeq ($(KDIR),)
    KVER = $(shell uname -r)
    KDIR := /lib/modules/$(KVER)/build
  endif
else
  KDIR := /lib/modules/$(KVER)/build
endif

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_DEV=m

scst:
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_DEV=n

MODS_VERS := $(shell ls Modules.symvers 2>/dev/null)
# It's renamed in 2.6.18
MOD_VERS := $(shell ls Module.symvers 2>/dev/null)

install: all
	-rm -f $(INSTALL_DIR)/scsi_tgt.ko
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_DEV=m \
		modules_install
	install -d $(INSTALL_DIR_H)
	install -m 644 ../include/scsi_tgt.h $(INSTALL_DIR_H)
	install -m 644 ../include/scst_debug.h $(INSTALL_DIR_H)
	install -m 644 ../include/scst_user.h $(INSTALL_DIR_H)
	install -m 644 ../include/scst_const.h $(INSTALL_DIR_H)
ifneq ($(MODS_VERS),)
	rm -f $(INSTALL_DIR_H)/Module.symvers
	install -m 644 Modules.symvers $(INSTALL_DIR_H)
endif
ifneq ($(MOD_VERS),)
	rm -f $(INSTALL_DIR_H)/Modules.symvers
	install -m 644 Module.symvers $(INSTALL_DIR_H)
endif
	-depmod -a $(KVER)
	@echo "****************************************************************"
	@echo "*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*"
	@echo "*!!                                                          !!*"
	@echo "*!!  Now don't forget to rebuild and reinstall all your      !!*"
	@echo "*!!  target drivers, custom dev handlers and necessary user  !!*"
	@echo "*!!  space applications. Otherwise, because of the versions  !!*"
	@echo "*!!  mismatch, you could have many problems and crashes.     !!*"
	@echo "*!!  See IMPORTANT note in the \"Installation\" section of     !!*"
	@echo "*!!  SCST's README file for more info.                       !!*"
	@echo "*!!                                                          !!*"
	@echo "*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*"
	@echo "****************************************************************"

uninstall:
	cd $(DEV_HANDLERS_DIR) && $(MAKE) $@
	rm -f $(INSTALL_DIR)/scst.ko
	-rmdir $(INSTALL_DIR) 2>/dev/null
	-/sbin/depmod -a $(KVER)
	rm -rf $(INSTALL_DIR_H)
endif

ifeq ($(KVER),)
INSTALL_DIR := /lib/modules/$(shell uname -r)/extra
else
INSTALL_DIR := /lib/modules/$(KVER)/extra
endif
INSTALL_DIR_H := /usr/local/include/scst

EXTRA_CFLAGS += -I$(SCST_INC_DIR) -Wextra -Wno-unused-parameter

#EXTRA_CFLAGS += -DSTRICT_SERIALIZING

EXTRA_CFLAGS += -DEXTRACHECKS

#EXTRA_CFLAGS += -fno-inline

#EXTRA_CFLAGS += -DTRACING

EXTRA_CFLAGS += -DDEBUG -g
#EXTRA_CFLAGS += -DDEBUG_TM -DTM_DBG_GO_OFFLINE=0
#EXTRA_CFLAGS += -DDEBUG_RETRY
#EXTRA_CFLAGS += -DDEBUG_OOM
#EXTRA_CFLAGS += -DDEBUG_SN

# If defined, makes SCST zero allocated data buffers. 
# Undefining it considerably improves performance and eases CPU load, 
# but could create a security hole (information leakage), so 
# enable it if you have strict security requirements.
#EXTRA_CFLAGS += -DSCST_STRICT_SECURITY

# If defined, allows SCST to use HIGHMEM. It's unclear, if it brings
# something valuable, except performance hit in some cases,
# so let it be off. Untested and unsupported.
#EXTRA_CFLAGS += -DSCST_HIGHMEM

clean:
	rm -f *.o *.ko .*.cmd *.mod.c .*.d .depend Modules.symvers Module.symvers
	rm -rf .tmp_versions
	cd $(DEV_HANDLERS_DIR) && $(MAKE) $@

extraclean: clean

.PHONY: all install uninstall clean extraclean
