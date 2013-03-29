ifeq ($(BUILD_2X_MODULE),)

qla2xxx-y := qla_os.o qla_init.o qla_mbx.o qla_iocb.o qla_isr.o qla_gs.o \
		qla_dbg.o qla_sup.o qla_attr.o qla_mid.o qla_dfs.o

obj-$(CONFIG_SCSI_QLA_FC) += qla2xxx.o

clean:
	rm -f *.o *.ko .*.cmd *.mod.c .*.d .depend *~ Modules.symvers \
		Module.symvers Module.markers modules.order
	rm -rf .tmp_versions

extraclean: clean
	rm -f *.orig *.rej

.PHONY: clean extraclean

else

SHELL=/bin/bash

KMOD := $(shell pwd)/kernel

enable-Wextra = $(shell uname_r="$$(uname -r)"; if [ "$${uname_r%.el5}" = "$${uname_r}" ]; then echo "$(1)"; fi)

EXTRA_CFLAGS += $(call enable-Wextra,-Wextra -Wno-unused-parameter \
	-Wno-missing-field-initializers)

ifneq ($(CONFIG_SCSI_QLA2XXX_TARGET),)
EXTRA_CFLAGS += -DCONFIG_SCSI_QLA2XXX_TARGET=$(CONFIG_SCSI_QLA2XXX_TARGET)
endif

ifeq ($(KVER),)
  ifeq ($(KDIR),)
    KDIR := /lib/modules/$(shell uname -r)/build
  endif
else
  KDIR := /lib/modules/$(KVER)/build
endif

ifneq ($(PATCHLEVEL),)
obj-m := qla2xxx_scst.o
qla2xxx_scst-objs := qla_os.o qla_init.o qla_mbx.o qla_iocb.o qla_isr.o qla_gs.o \
		qla_dbg.o qla_sup.o qla_attr.o qla_mid.o qla_dfs.o
else

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=m

install: all
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=m \
		modules_install
	-/sbin/depmod -aq $(KVER)

uninstall:
	rm -f $(INSTALL_DIR)/qla2xxxt.ko
	-/sbin/depmod -a $(KVER)
endif

clean:
	@$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) clean
	@$(RM) tags Modules.symvers module.symvers Module.markers modules.order

extraclean: clean
	rm -f *.orig *.rej

.PHONY: all tgt install uninstall clean extraclean

endif

release-archive:
	../scripts/generate-release-archive qla2x00t "$$(sed -n 's/^#define[[:blank:]]Q2T_VERSION_STRING[[:blank:]]*\"\([^\"]*\)\".*/\1/p' qla2x00-target/qla2x00t.h)"
