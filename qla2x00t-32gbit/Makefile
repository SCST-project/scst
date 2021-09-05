# SPDX-License-Identifier: GPL-2.0

ifeq ($(BUILD_2X_MODULE),)

qla2xxx-y := qla_os.o qla_init.o qla_mbx.o qla_iocb.o qla_isr.o qla_gs.o \
		qla_dbg.o qla_sup.o qla_attr.o qla_mid.o qla_dfs.o qla_bsg.o \
		qla_nx.o qla_mr.o qla_nx2.o qla_target.o qla_tmpl.o qla_nvme.o \
		qla_edif.o

obj-$(CONFIG_SCSI_QLA_FC) += qla2xxx.o

clean:
	rm -f *.o *.ko .*.cmd *.mod.c .*.d .depend *~ \
		Module.symvers Module.markers modules.order
	rm -rf .tmp_versions

extraclean: clean
	rm -f *.orig *.rej

.PHONY: clean extraclean

else
######### BEGIN OUT-OF-TREE RULES #########

SHELL=/bin/bash

KMOD := $(shell pwd)/kernel

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
	  $(shell [ -n "$(PASS_CC_TO_MAKE)" ] && echo CC="$(CC)")	\
	  $(CONFIG_SCSI_QLA2XXX_TARGET)=CONFIG_SCSI_QLA2XXX_TARGET

install: all
	KDIR=$(KDIR) ../scripts/sign-modules
	$(MAKE) -C $(KDIR) M=$(shell pwd)				\
	  $(shell [ -n "$(PASS_CC_TO_MAKE)" ] && echo CC="$(CC)")	\
	  $$([ -n "$(DEPMOD)" ] && echo "DEPMOD=$(DEPMOD)")		\
	  CONFIG_MODULE_SIG_ALL= modules_install

uninstall:
	rm -f $(INSTALL_DIR)/qla2xxx_scst.ko
	-/sbin/depmod -b $(INSTALL_MOD_PATH)/ -a $(KVER)

########## END OUT-OF-TREE RULES ##########

clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) $@

extraclean: clean
	rm -f *.orig *.rej

.PHONY: all tgt install uninstall clean extraclean

endif

release-archive:
	../scripts/generate-release-archive qla2x00t-32gbit "$$(sed -n 's/^#define[[:blank:]]Q2T_VERSION_STRING[[:blank:]]*\"\([^\"]*\)\".*/\1/p' qla2x00-target/scst_qla2xxx.h)"
