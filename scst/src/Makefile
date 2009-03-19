#
#  SCSI target mid-level makefile
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
obj-$(CONFIG_SCST)   += scst.o dev_handlers/

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
	install -m 644 ../include/scst.h $(INSTALL_DIR_H)
	install -m 644 ../include/scst_sgv.h $(INSTALL_DIR_H)
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
	-/sbin/depmod -a $(KVER)
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
INSTALL_DIR := $(DISTDIR)/lib/modules/$(shell uname -r)/extra
else
INSTALL_DIR := $(DISTDIR)/lib/modules/$(KVER)/extra
endif
INSTALL_DIR_H := $(DISTDIR)/usr/local/include/scst

EXTRA_CFLAGS += -I$(SCST_INC_DIR) -Wextra -Wno-unused-parameter \
		-Wno-missing-field-initializers

#EXTRA_CFLAGS += -DCONFIG_SCST_STRICT_SERIALIZING

EXTRA_CFLAGS += -DCONFIG_SCST_EXTRACHECKS

#EXTRA_CFLAGS += -DCONFIG_SCST_USE_EXPECTED_VALUES
#EXTRA_CFLAGS += -DALLOW_PASSTHROUGH_IO_SUBMIT_IN_SIRQ
#EXTRA_CFLAGS += -DABORT_CONSIDER_FINISHED_TASKS_AS_NOT_EXISTING

#EXTRA_CFLAGS += -fno-inline

#EXTRA_CFLAGS += -DCONFIG_SCST_TRACING

EXTRA_CFLAGS += -DCONFIG_SCST_DEBUG -g
#EXTRA_CFLAGS += -DCONFIG_SCST_DEBUG_TM -DCONFIG_SCST_TM_DBG_GO_OFFLINE
#EXTRA_CFLAGS += -DCONFIG_SCST_DEBUG_RETRY
#EXTRA_CFLAGS += -DCONFIG_SCST_DEBUG_OOM
#EXTRA_CFLAGS += -DCONFIG_SCST_DEBUG_SN

#EXTRA_CFLAGS += -DCONFIG_SCST_MEASURE_LATENCY

# If defined, makes SCST zero allocated data buffers. 
# Undefining it considerably improves performance and eases CPU load, 
# but could create a security hole (information leakage), so 
# enable it if you have strict security requirements.
#EXTRA_CFLAGS += -DSCST_STRICT_SECURITY

clean:
	rm -f *.o *.ko .*.cmd *.mod.c .*.d .depend Modules.symvers \
		Module.symvers Module.markers modules.order
	rm -rf .tmp_versions
	cd $(DEV_HANDLERS_DIR) && $(MAKE) $@

extraclean: clean

.PHONY: all install uninstall clean extraclean
