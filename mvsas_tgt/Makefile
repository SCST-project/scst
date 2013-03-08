#
#  Marvell SCSI target driver makefile
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
export LIBSAS := m

#SCST_INC_DIR := $(PREFIX)/include/scst
#SCST_DIR := $(SCST_INC_DIR)
SCST_INC_DIR := $(SUBDIRS)/../scst/include
SCST_DIR := $(shell pwd)/../scst/src

EXTRA_CFLAGS += -I$(SCST_INC_DIR)

EXTRA_CFLAGS +=  -DSUPPORT_TARGET
MODULE_NAME = mvsas_tgt

EXTRA_CFLAGS += -DMV_DEBUG

INSTALL_DIR := /lib/modules/$(shell uname -r)/extra

#EXTRA_CFLAGS += -DCONFIG_SCST_TRACING
#EXTRA_CFLAGS += -DDEBUG_WORK_IN_THREAD
#EXTRA_CFLAGS += -DCONFIG_SCST_DEBUG

ifneq ($(KERNELRELEASE),)
obj-m := mvsas.o
mvsas-y := mv_init.o  \
           mv_sas.o   \
           mv_tgt.o   \
           mv_64xx.o  \
           mv_94xx.o  \
           mv_spi.o
else
all: Modules.symvers Module.symvers
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=m

tgt: Modules.symvers Module.symvers
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=n

install: all
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=m \
		modules_install
	-depmod -a $(KVER)

ins:
	./config
	insmod mvsas.ko
	
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

.PHONY: all tgt install uninstall clean extraclean
