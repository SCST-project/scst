#
#  FCST: libfc SCSI target makefile
#  Based on ../mvsas_tgt/Makefile
#
#  Copyright (C) 2006 - 2008 Jacky Feng <jfeng@marvell.com>
#  Copyright (C) 2011 - 2018 Bart Van Assche <bvanassche@acm.org>
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

export PWD    := $(shell pwd)
export CONFIG_FCST   := m

MODULE_NAME = fcst

ifneq ($(KERNELRELEASE),)
include $(KBUILD_EXTMOD)/Makefile_in-tree
else
######### BEGIN OUT-OF-TREE RULES #########

ifndef PREFIX
        PREFIX=/usr/local
endif

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

SCST_DIR := $(shell echo "$$PWD")/../scst/src

# The file Modules.symvers has been renamed in the 2.6.18 kernel to
# Module.symvers. Find out which name to use by looking in $(KDIR).
MODULE_SYMVERS:=$(shell if [ -e "$(KDIR)/Modules.symvers" ]; then \
		       echo Modules.symvers; else echo Module.symvers; fi)

all: $(MODULE_SYMVERS)
	$(MAKE) -C $(KDIR) M=$(shell pwd) BUILD_INI=m

tgt: $(MODULE_SYMVERS)
	$(MAKE) -C $(KDIR) M=$(shell pwd) BUILD_INI=n

install: all
	KDIR=$(KDIR) ../scripts/sign-modules
	$(MAKE) -C $(KDIR) M=$(shell pwd) BUILD_INI=m		\
	  $$([ -n "$(DEPMOD)" ] && echo "DEPMOD=$(DEPMOD)")	\
	  CONFIG_MODULE_SIG_ALL= modules_install

ins:
	./config
	insmod fcst.ko

$(MODULE_SYMVERS): $(SCST_DIR)/$(MODULE_SYMVERS)
	cp $< $@

uninstall:
	rm -f $(INSTALL_DIR)/$(MODULE_NAME).ko
	-/sbin/depmod -b $(INSTALL_MOD_PATH)/ -a $(KVER)

########## END OUT-OF-TREE RULES ##########
endif

clean:
	rm -f *.o *.ko .*.cmd *.mod.c .*.d .depend *~ \
		$(MODULE_SYMVERS) Module.markers modules.order
	rm -rf .tmp_versions

extraclean: clean
	rm -f *.orig *.rej

release-archive:
	../scripts/generate-release-archive fcst "$$(sed -n 's/^#define[[:blank:]]FT_VERSION[[:blank:]]*\"\([^\"]*\)\".*/\1/p' fcst.h)"

.PHONY: all tgt install uninstall clean extraclean release-archive
