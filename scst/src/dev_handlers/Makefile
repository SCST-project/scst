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
  ifeq ($(KDIR),)
    KDIR := /lib/modules/$(KVER)/build
  endif
endif

ifeq ($(INSTALL_MOD_PATH),)
  export INSTALL_MOD_PATH := $(DESTDIR)
endif

INSTALL_DIR := $(INSTALL_MOD_PATH)/lib/modules/$(KVER)/extra

all:
	$(MAKE) -C $(KDIR) M=$(shell pwd)				\
	  $(shell [ -n "$(PASS_CC_TO_MAKE)" ] && echo CC="$(CC)")

%.lst: %.c
	$(MAKE) -C $(KDIR) M=$(shell pwd) $@				\
	  $(shell [ -n "$(PASS_CC_TO_MAKE)" ] && echo CC="$(CC)")

install: all
	mkdir -p $(DESTDIR)/var/lib/scst/vdev_mode_pages
	KDIR=$(KDIR) ../../../scripts/sign-modules
	$(MAKE) -C $(KDIR) M=$(shell pwd)				\
	  $(shell [ -n "$(PASS_CC_TO_MAKE)" ] && echo CC="$(CC)")	\
	  $$([ -n "$(DEPMOD)" ] && echo "DEPMOD=$(DEPMOD)")		\
	  CONFIG_MODULE_SIG_ALL= modules_install

uninstall:
	rm -f $(INSTALL_DIR)/dev_handlers/scst_*.ko
	-rmdir $(INSTALL_DIR)/dev_handlers 2>/dev/null

clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) $@

extraclean: clean
	rm -f *.orig *.rej

.PHONY: all install uninstall clean extraclean
