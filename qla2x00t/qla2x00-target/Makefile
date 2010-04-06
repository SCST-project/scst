#
#  Qlogic 2x00 SCSI target driver makefile
#  
#  Copyright (C) 2004 - 2010 Vladislav Bolkhovitin <vst@vlnb.net>
#  Copyright (C) 2004 - 2010 Vladislav Bolkhovitin <vst@vlnb.net>
#  Copyright (C) 2004 - 2005 Leonid Stoljar
#  Copyright (C) 2006 - 2010 ID7 Ltd.
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

#SCST_INC_DIR := /usr/local/include/scst
#SCST_DIR := $(SCST_INC_DIR)
SCST_INC_DIR := $(SUBDIRS)/../../scst/include
SCST_DIR := $(shell pwd)/../../scst/src

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

QLA2XXX_INC_DIR := $(KDIR)/drivers/scsi/qla2xxx
EXTRA_CFLAGS += -I$(QLA2XXX_INC_DIR)

ifneq ($(PATCHLEVEL),)
obj-m := qla2x00tgt.o
qla2x00tgt-objs := qla2x00t.o

else

all: Modules.symvers Module.symvers
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=m

tgt: Modules.symvers Module.symvers
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=n

install: all
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=m \
		modules_install
	-/sbin/depmod -a $(KVER)

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
	rm -f $(INSTALL_DIR)/qla2[23x]00tgt.ko
	-/sbin/depmod -a $(KVER)
endif

clean:
	rm -f *.o *.ko .*.cmd *.mod.c .*.d .depend *~ Modules.symvers \
		Module.symvers Module.markers modules.order
	rm -rf .tmp_versions

extraclean: clean

debug2release:
	sed -i.aa s/"^EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/ Makefile
	@cmp Makefile Makefile.aa >/dev/null; if [[ $$? = 0 ]]; then rm Makefile.aa; echo "sed failed"; false; fi
	sed -i.aa s/"#EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/"EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/ Makefile
	@cmp Makefile Makefile.aa >/dev/null; if [[ $$? = 0 ]]; then rm Makefile.aa; echo "sed failed"; false; fi
	sed -i.aa s/"^EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/ Makefile
	@cmp Makefile Makefile.aa >/dev/null; if [[ $$? = 0 ]]; then rm Makefile.aa; echo "sed failed"; false; fi
	rm Makefile.aa

release2debug:
	sed -i.aa s/"#EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/"EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/ Makefile
	@cmp Makefile Makefile.aa >/dev/null; if [[ $$? = 0 ]]; then rm Makefile.aa; echo "sed failed"; false; fi
	sed -i.aa s/"^EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/ Makefile
	@cmp Makefile Makefile.aa >/dev/null; if [[ $$? = 0 ]]; then rm Makefile.aa; echo "sed failed"; false; fi
	sed -i.aa s/"#EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/"EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/ Makefile
	@cmp Makefile Makefile.aa >/dev/null; if [[ $$? = 0 ]]; then rm Makefile.aa; echo "sed failed"; false; fi
	rm Makefile.aa

debug2perf:
	sed -i.aa s/"^EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/ Makefile
	@cmp Makefile Makefile.aa >/dev/null; if [[ $$? = 0 ]]; then rm Makefile.aa; echo "sed failed"; false; fi
	sed -i.aa s/"^EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/ Makefile
	@cmp Makefile Makefile.aa >/dev/null; if [[ $$? = 0 ]]; then rm Makefile.aa; echo "sed failed"; false; fi
	rm Makefile.aa

perf2debug:
	sed -i.aa s/"#EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/"EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/ Makefile
	@cmp Makefile Makefile.aa >/dev/null; if [[ $$? = 0 ]]; then rm Makefile.aa; echo "sed failed"; false; fi
	sed -i.aa s/"#EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/"EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/ Makefile
	@cmp Makefile Makefile.aa >/dev/null; if [[ $$? = 0 ]]; then rm Makefile.aa; echo "sed failed"; false; fi
	rm Makefile.aa

disable_proc:
	sed -i.aa s/"^#define CONFIG_SCST_PROC"/"\/* #define CONFIG_SCST_PROC *\/"/ ../qla_attr.c
	@cmp ../qla_attr.c ../qla_attr.c.aa >/dev/null; if [[ $$? = 0 ]]; then rm ../qla_attr.c.aa; echo "sed failed"; false; fi
	rm ../qla_attr.c.aa

enable_proc:
	sed -i.aa s/"\/\* #define CONFIG_SCST_PROC \*\/"/"#define CONFIG_SCST_PROC"/ ../qla_attr.c
	@cmp ../qla_attr.c ../qla_attr.c.aa >/dev/null; if [[ $$? = 0 ]]; then rm ../qla_attr.c.aa; echo "sed failed"; false; fi
	rm ../qla_attr.c.aa

.PHONY: all tgt install uninstall clean extraclean debug2perf debug2release perf2debug release2debug disable_proc enable_proc
