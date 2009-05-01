#
# Makefile for the Linux kernel device drivers.
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (not a .c file).
#
# Note 2! The CFLAGS definitions are now in the main makefile.

SCST_DIR := $(shell pwd)/../scst/src
SUBDIRS := $(shell pwd)

ifeq ($(KVER),)
  ifeq ($(KDIR),)
    KVER = $(shell uname -r)
    KDIR ?= /lib/modules/$(KVER)/build
  else
    KVER = $$KERNELRELEASE
  endif
else
  KDIR ?= /lib/modules/$(KVER)/build
endif

# The file Modules.symvers has been renamed in the 2.6.18 kernel to
# Module.symvers. Find out which name to use by looking in $(KDIR).
MODULE_SYMVERS=$(shell if [ -e $(KDIR)/Module.symvers ]; then \
		       echo Module.symvers; else echo Modules.symvers; fi)

all: $(MODULE_SYMVERS)
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)/src modules

install: all src/ib_srpt.ko
	@eval `sed -n 's/#define UTS_RELEASE /KERNELRELEASE=/p' $(KDIR)/include/linux/version.h $(KDIR)/include/linux/utsrelease.h 2>/dev/null`; \
	install -vD -m 644 src/ib_srpt.ko \
	$(DESTDIR)$(INSTALL_MOD_PATH)/lib/modules/$(KVER)/extra/ib_srpt.ko
	-/sbin/depmod -aq $(KVER)

Module.symvers: src/Module.symvers

Modules.symvers: src/Modules.symvers

.PHONY: Module.symvers Modules.symvers

src/Module.symvers src/Modules.symvers: $(SCST_DIR)/$(MODULE_SYMVERS)
	if [ -e /lib/modules/$(KVER)/updates/kernel/drivers/infiniband ]; then\
	  if [ ! -e /usr/src/ofa_kernel/Module.symvers ]; then                \
	    echo "Error: the OFED package kernel-ib-devel has not yet been"   \
	         "installed.";                                                \
	    false;                                                            \
	  elif [ -e /lib/modules/$(KVER)/kernel/drivers/infiniband ]; then    \
	    echo "Error: OFED has not been installed correctly.";             \
	    false;                                                            \
	  else                                                                \
	    (                                                                 \
	      grep -v drivers/infiniband/ $<;                                 \
	      cat /usr/src/ofa_kernel/Module.symvers                          \
	    ) >$@;                                                            \
	  fi                                                                  \
	else                                                                  \
	  cp $< $@;                                                           \
	fi

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)/src clean
	rm -f src/Modules.symvers src/Module.symvers src/Module.markers \
		src/modules.order

extraclean: clean

.PHONY: all install clean extraclean
