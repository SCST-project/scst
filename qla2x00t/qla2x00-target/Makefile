#
#  Qlogic 2x00 SCSI target driver makefile
#
#  Copyright (C) 2004 - 2013 Vladislav Bolkhovitin <vst@vlnb.net>
#  Copyright (C) 2004 - 2005 Leonid Stoljar
#  Copyright (C) 2006 - 2010 ID7 Ltd.
#  Copyright (C) 2010 - 2013 SCST Ltd.
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

SHELL=/bin/bash

EXTRA_CFLAGS += -I$(SCST_INC_DIR)

INSTALL_DIR := /lib/modules/$(shell uname -r)/extra

EXTRA_CFLAGS += -W -Wno-unused-parameter -Wno-missing-field-initializers

EXTRA_CFLAGS += -DCONFIG_SCST_EXTRACHECKS 
#EXTRA_CFLAGS += -DCONFIG_SCST_TRACING
EXTRA_CFLAGS += -DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions
#EXTRA_CFLAGS += -DCONFIG_QLA_TGT_DEBUG_WORK_IN_THREAD
#EXTRA_CFLAGS += -DCONFIG_QLA_TGT_DEBUG_SRR

ifeq ($(KVER),)
  ifeq ($(KDIR),)
    KVER = $(shell uname -r)
    KDIR := /lib/modules/$(KVER)/build
  endif
else
  KDIR := /lib/modules/$(KVER)/build
endif

ifeq ($(BUILD_2X_MODULE),)
QLA2XXX_INC_DIR := $(KDIR)/drivers/scsi/qla2xxx
else
QLA2XXX_INC_DIR := $(SUBDIRS)/..
QLA2XXX_DIR := $(shell pwd)/..
QLA2XXX_SCST := qla2xxx_scst
EXTRA_CFLAGS += -DCONFIG_SCSI_QLA2XXX_TARGET=y
endif

EXTRA_CFLAGS += -I$(QLA2XXX_INC_DIR)

ifneq ($(PATCHLEVEL),)
obj-m := qla2x00tgt.o
qla2x00tgt-objs := qla2x00t.o
else

SCST_INC_DIR := $(shell if [ -e "$$PWD/../../scst" ];			\
                  then echo "$$PWD/../../scst/include";			\
                  else echo "$(PREFIX)/include/scst"; fi)
SCST_DIR := $(shell if [ -e "$$PWD/../../scst" ];			\
		    then echo "$$PWD/../../scst/src";			\
		    else echo "$(PREFIX)/include/scst"; fi)

ifneq ($(BUILD_2X_MODULE),)
# We need to make qla2xxx_scst before Module.symvers
.NOTPARALLEL:
endif

all: $(QLA2XXX_SCST) Modules.symvers Module.symvers
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=m \
	  SCST_INC_DIR=$(SCST_INC_DIR)

install: all
ifneq ($(BUILD_2X_MODULE),)
	$(MAKE) SUBDIRS=$(QLA2XXX_DIR) -C $(QLA2XXX_DIR) $@ \
	  SCST_INC_DIR=$(SCST_INC_DIR)
endif
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=m \
	  SCST_INC_DIR=$(SCST_INC_DIR) modules_install
	-/sbin/depmod -a $(KVER)

uninstall:
ifneq ($(BUILD_2X_MODULE),)
	$(MAKE) SUBDIRS=$(QLA2XXX_DIR) -C $(QLA2XXX_DIR) $@
endif
	rm -f $(INSTALL_DIR)/qla2[23x]00tgt.ko
	-/sbin/depmod -a $(KVER)

ifneq ($(BUILD_2X_MODULE),)
qla2xxx_scst:
	$(MAKE) BUILD_2X_MODULE=$(BUILD_2X_MODULE) CONFIG_SCSI_QLA2XXX_TARGET=y \
		SUBDIRS=$(QLA2XXX_DIR) -C $(QLA2XXX_DIR) all
endif

SCST_MOD_VERS := $(shell ls $(SCST_DIR)/Modules.symvers 2>/dev/null)
ifneq ($(SCST_MOD_VERS),)
Modules.symvers: $(SCST_DIR)/Modules.symvers
	cp $(SCST_DIR)/Modules.symvers .
ifneq ($(BUILD_2X_MODULE),)
	cat $(QLA2XXX_DIR)/Modules.symvers >>Modules.symvers
endif
else
.PHONY: Modules.symvers
endif

# It's renamed in 2.6.18
SCST_MOD_VERS := $(shell ls $(SCST_DIR)/Module.symvers 2>/dev/null)
ifneq ($(SCST_MOD_VERS),)
Module.symvers: $(SCST_DIR)/Module.symvers
	cp $(SCST_DIR)/Module.symvers .
ifneq ($(BUILD_2X_MODULE),)
	cat $(QLA2XXX_DIR)/Module.symvers >>Module.symvers
endif
else
.PHONY: Module.symvers
endif

endif

clean:
	rm -f *.o *.ko .*.cmd *.mod.c .*.d .depend *~ Modules.symvers \
		Module.symvers Module.markers modules.order
	rm -rf .tmp_versions

extraclean: clean
	rm -f *.orig *.rej

2release:
	sed -i.aa s/"^E\?XTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/ Makefile
	grep "^#EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS" Makefile >/dev/null
	sed -i.aa s/"^#\?EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/"EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/ Makefile
	grep "^EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING" Makefile >/dev/null
	sed -i.aa s/"^E\?XTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/ Makefile
	grep "^#EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions" Makefile >/dev/null
	rm Makefile.aa

2debug:
	sed -i.aa s/"^#\?EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/"EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/ Makefile
	grep "^EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS" Makefile >/dev/null
	sed -i.aa s/"^E\?XTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/ Makefile
	grep "^#EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING" Makefile >/dev/null
	sed -i.aa s/"^#\?EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/"EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/ Makefile
	grep "^EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions" Makefile >/dev/null
	rm Makefile.aa

2perf:
	sed -i.aa s/"^E\?XTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/ Makefile
	grep "^#EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS" Makefile >/dev/null
	sed -i.aa s/"^E\?XTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/ Makefile
	grep "^#EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING" Makefile >/dev/null
	sed -i.aa s/"^E\?XTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/ Makefile
	grep "^#EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions" Makefile >/dev/null
	rm Makefile.aa

disable_proc:
	sed -i.aa s/"^#\?define CONFIG_SCST_PROC"/"\/* #define CONFIG_SCST_PROC *\/"/ ../qla_attr.c
	grep "^\/\* #define CONFIG_SCST_PROC \*\/" ../qla_attr.c >/dev/null
	rm ../qla_attr.c.aa

enable_proc:
	sed -i.aa s/"^\/\?\* #define CONFIG_SCST_PROC \*\/"/"#define CONFIG_SCST_PROC"/ ../qla_attr.c
	grep "^#define CONFIG_SCST_PROC" ../qla_attr.c >/dev/null
	rm ../qla_attr.c.aa

.PHONY: all tgt install uninstall clean extraclean 2perf 2release 2debug disable_proc enable_proc qla2xxx_scst
