#
#  FCST: libfc SCSI target makefile
#  Based on ../mvsas_tgt/Makefile
#
#  Copyright (C) 2006 - 2008 Jacky Feng <jfeng@marvell.com>
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

ifndef PREFIX
        PREFIX=/usr/local
endif

ifeq ($(KVER),)
  ifeq ($(KDIR),)
    KVER = $(shell uname -r)
    KDIR := /lib/modules/$(KVER)/build
  endif
else
  KDIR := /lib/modules/$(KVER)/build
endif

export PWD    := $(shell pwd)
export CONFIG_FCST   := m


# Set variable $(2) to value $(3) in file $(1).
set_var = $(shell { if [ -e "$(1)" ]; then grep -v '^$(2)=' "$(1)"; fi; echo "$(2)=$(3)"; } >/tmp/$(1)-$$$$.tmp && mv /tmp/$(1)-$$$$.tmp $(1))


FCSTFLAGS = -DDEBUG_WORK_IN_THREAD -DCONFIG_SCST_TRACING -DCONFIG_SCST_DEBUG \
	-DCONFIG_SCST_EXTRACHECKS -fno-inline -fno-inline-functions
FCSTFLAGSRELEASE = -DCONFIG_SCST_TRACING
FCSTFLAGSPERF =
EXTRA_CFLAGS += -I$(SCST_INC_DIR) $(FCSTFLAGS$(BUILDMODE))

MODULE_NAME = fcst

INSTALL_DIR := /lib/modules/$(KVER)/extra

ifneq ($(KERNELRELEASE),)
include $(SUBDIRS)/Makefile_in-tree
else
SCST_INC_DIR := $(shell if [ -e "$$PWD/../scst" ];			\
                  then echo "$$PWD/../scst/include";			\
                  else echo "$(PREFIX)/include/scst"; fi)
SCST_DIR := $(shell if [ -e "$$PWD/../scst" ]; then echo "$$PWD/../scst/src"; \
		else echo "$(PREFIX)/include/scst"; fi)

all: Modules.symvers Module.symvers
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=m \
	  SCST_INC_DIR=$(SCST_INC_DIR)

tgt: Modules.symvers Module.symvers
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=n \
	  SCST_INC_DIR=$(SCST_INC_DIR)

install: all
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=m \
	  SCST_INC_DIR=$(SCST_INC_DIR) modules_install
	-depmod -a $(KVER)

ins:
	./config
	insmod fcst.ko

SCST_MOD_VERS := $(shell ls $(SCST_DIR)/Modules.symvers 2>/dev/null)
ifneq ($(SCST_MOD_VERS),)
Modules.symvers: $(SCST_DIR)/Modules.symvers
	cp $(SCST_DIR)/Modules.symvers .
else
.PHONY: Modules.symvers
endif

# It's renamed in 2.6.18
SCST_MOD_VERS := $(shell ls $(SCST_DIR)/Module.symvers 2>/dev/null)
ifneq ($(SCST_MOD_VERS),)
Module.symvers: $(SCST_DIR)/Module.symvers
	cp $(SCST_DIR)/Module.symvers .
else
.PHONY: Module.symvers
endif

uninstall:
	rm -f $(INSTALL_DIR)/$(MODULE_NAME).ko
	-/sbin/depmod -a $(KVER)
endif

clean:
	rm -f *.o *.ko .*.cmd *.mod.c .*.d .depend *~ Modules.symvers \
		Module.symvers Module.markers modules.order
	rm -rf .tmp_versions

extraclean: clean
	rm -f *.orig *.rej

2debug:
	-$(MAKE) clean
	$(call set_var,build_mode,BUILDMODE,)

2release:
	-$(MAKE) clean
	$(call set_var,build_mode,BUILDMODE,RELEASE)

2perf:
	-$(MAKE) clean
	$(call set_var,build_mode,BUILDMODE,PERF)

.PHONY: all tgt install uninstall clean extraclean
