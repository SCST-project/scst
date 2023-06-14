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
  ifeq ($(KDIR),)
    KDIR := /lib/modules/$(KVER)/build
  endif
endif

ifeq ($(INSTALL_MOD_PATH),)
  export INSTALL_MOD_PATH := $(DESTDIR)
endif

ifneq ($(BUILD_2X_MODULE),)
QLA2XXX_DIR := $(shell pwd)/..
QLA2XXX_SCST := qla2xxx_scst
endif

ifndef PREFIX
        PREFIX=/usr/local
endif

INSTALL_MOD_DIR=extra

INSTALL_DIR := $(INSTALL_MOD_PATH)/lib/modules/$(KVER)/$(INSTALL_MOD_DIR)

SCST_DIR := $(shell echo "$$PWD/../../scst/src")

all: $(QLA2XXX_SCST)
	$(MAKE) -C $(KDIR) M=$(shell pwd)				\
	  $(shell [ -n "$(PASS_CC_TO_MAKE)" ] && echo CC="$(CC)")

install: all
ifneq ($(BUILD_2X_MODULE),)
	$(MAKE) M=$(QLA2XXX_DIR) -C $(QLA2XXX_DIR) $@
endif
	KDIR=$(KDIR) ../../scripts/sign-modules
	$(MAKE) -C $(KDIR) M=$(shell pwd)				\
	  $(shell [ -n "$(PASS_CC_TO_MAKE)" ] && echo CC="$(CC)")	\
	  INSTALL_MOD_DIR=$(INSTALL_MOD_DIR)				\
	  $$([ -n "$(DEPMOD)" ] && echo "DEPMOD=$(DEPMOD)")		\
	  CONFIG_MODULE_SIG_ALL= modules_install

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

clean:
ifneq ($(BUILD_2X_MODULE),)
	$(MAKE) -C $(QLA2XXX_DIR) $@
endif
	$(MAKE) -C $(KDIR) M=$(shell pwd) $@

extraclean: clean
	rm -f *.orig *.rej

.PHONY: all install uninstall clean extraclean qla2xxx_scst
