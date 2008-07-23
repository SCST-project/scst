ifneq ($(KERNELRELEASE),)

qla2xxx-y := qla_os.o qla_init.o qla_mbx.o qla_iocb.o qla_isr.o qla_gs.o \
		qla_dbg.o qla_sup.o qla_attr.o qla_mid.o qla_dfs.o

obj-$(CONFIG_SCSI_QLA_FC) += qla2xxx.o

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
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)

install: all
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=m \
		modules_install

uninstall:
	rm -f $(INSTALL_DIR)/qla2[2-3]00.ko $(INSTALL_DIR)/qla2xxx.ko 
	-/sbin/depmod -a $(KVER)
endif

clean:
	rm -f *.o *.ko .*.cmd *.mod.c .*.d .depend *~ Modules.symvers \
		Module.symvers Module.markers modules.order
	rm -rf .tmp_versions

extraclean: clean

.PHONY: all install uninstall clean extraclean
