#
#  Qlogic 2x00 SCSI target driver makefile
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

ifeq ($(KVER),)
  ifeq ($(KDIR),)
    KVER := $(shell uname -r)
    KDIR := /lib/modules/$(KVER)/build
  else
    ifeq ($(KERNELRELEASE),)
      KVER := $(strip $(shell						\
	cat $(KDIR)/include/config/kernel.release 2>/dev/null ||	\
	make -s -C $(KDIR) kernelversion))
    else
      KVER := $(KERNELRELEASE)
    endif
  endif
else
  KDIR := /lib/modules/$(KVER)/build
endif

ifeq ($(INSTALL_MOD_PATH),)
  export INSTALL_MOD_PATH := $(DESTDIR)
endif

ifeq ($(BUILD_2X_MODULE),)
QLA2XXX_INC_DIR := $(KDIR)/drivers/scsi/qla2xxx
else
QLA2XXX_INC_DIR := $(KBUILD_EXTMOD)/..
QLA2XXX_DIR := $(shell pwd)/..
QLA2XXX_SCST := qla2xxx_scst
endif

ifneq ($(PATCHLEVEL),)
ccflags-y += -I$(KBUILD_EXTMOD)/../../scst/include
ccflags-y += -W -Wno-unused-parameter -Wno-missing-field-initializers
#ccflags-y += -DCONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
#ccflags-y += -DCONFIG_QLA_TGT_DEBUG_SRR

ifneq ($(BUILD_2X_MODULE),)
ccflags-y += -DCONFIG_SCSI_QLA2XXX_TARGET=y
endif

ccflags-y += -I$(QLA2XXX_INC_DIR)

obj-m := qla2x00tgt.o
qla2x00tgt-objs := qla2x00t.o
else
######### BEGIN OUT-OF-TREE RULES #########

ifndef PREFIX
        PREFIX=/usr/local
endif

INSTALL_DIR := $(INSTALL_MOD_PATH)/lib/modules/$(KVER)/extra

SCST_DIR := $(shell echo "$$PWD/../../scst/src")

ifneq ($(BUILD_2X_MODULE),)
# We need to make qla2xxx_scst before Module.symvers
.NOTPARALLEL:
endif

# The file Modules.symvers has been renamed in the 2.6.18 kernel to
# Module.symvers. Find out which name to use by looking in $(KDIR).
MODULE_SYMVERS:=$(shell if [ -e "$(KDIR)/Modules.symvers" ]; then \
		       echo Modules.symvers; else echo Module.symvers; fi)

all: $(QLA2XXX_SCST) $(MODULE_SYMVERS)
	$(MAKE) -C $(KDIR) M=$(shell pwd) BUILD_INI=m

install: all
ifneq ($(BUILD_2X_MODULE),)
	$(MAKE) M=$(QLA2XXX_DIR) -C $(QLA2XXX_DIR) $@
endif
	$(MAKE) -C $(KDIR) M=$(shell pwd) BUILD_INI=m \
	  $$([ -n "$(DESTDIR)$(INSTALL_MOD_PATH)" ] && echo DEPMOD=true) \
	  modules_install

uninstall:
ifneq ($(BUILD_2X_MODULE),)
	$(MAKE) M=$(QLA2XXX_DIR) -C $(QLA2XXX_DIR) $@
endif
	rm -f $(INSTALL_DIR)/qla2[23x]00tgt.ko
	-/sbin/depmod -b $(INSTALL_MOD_PATH)/ -a $(KVER)

ifneq ($(BUILD_2X_MODULE),)
qla2xxx_scst:
	$(MAKE) BUILD_2X_MODULE=$(BUILD_2X_MODULE) CONFIG_SCSI_QLA2XXX_TARGET=y \
		M=$(QLA2XXX_DIR) -C $(QLA2XXX_DIR) all
endif

$(MODULE_SYMVERS): $(SCST_DIR)/$(MODULE_SYMVERS)
	cp $< .
ifneq ($(BUILD_2X_MODULE),)
	cat $(QLA2XXX_DIR)/$(MODULE_SYMVERS) >>$(MODULE_SYMVERS)
endif

########## END OUT-OF-TREE RULES ##########
endif

clean:
	rm -f *.o *.ko .*.cmd *.mod.c .*.d .depend *~ \
		$(MODULE_SYMVERS) Module.markers modules.order
	rm -rf .tmp_versions

extraclean: clean
	rm -f *.orig *.rej

.PHONY: all tgt install uninstall clean extraclean qla2xxx_scst
