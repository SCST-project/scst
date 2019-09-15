#
# Makefile for ibmvstgt.ko.
#

SCST_DIR := $(shell pwd)/../scst/src

ifeq ($(KVER),)
  ifeq ($(KDIR),)
    KVER := $(shell uname -r)
    KDIR := /lib/modules/$(KVER)/build
  else
    ifeq ($(KERNELRELEASE),)
      KVER := $(strip $(shell						\
	cat $(KDIR)/include/config/kernel.release 2>/dev/null ||	\
	make -s -C $(KDIR) kernelversion))
    else
      KVER := $(KERNELRELEASE)
    endif
  endif
else
  KDIR := /lib/modules/$(KVER)/build
endif

ifeq ($(INSTALL_MOD_PATH),)
  export INSTALL_MOD_PATH := $(DESTDIR)
endif

INSTALL_DIR := $(INSTALL_MOD_PATH)/lib/modules/$(KVER)/extra

# The file Modules.symvers has been renamed in the 2.6.18 kernel to
# Module.symvers. Find out which name to use by looking in $(KDIR).
MODULE_SYMVERS:=$(shell if [ -e $(KDIR)/Modules.symvers ]; then \
		       echo Modules.symvers; else echo Module.symvers; fi)


all: src/$(MODULE_SYMVERS)
	$(MAKE) -C $(KDIR) M=$(shell pwd)/src modules

install: all src/ibmvstgt.ko
	$(MAKE) -C $(KDIR) M=$(shell pwd)/src				\
		$$([ -n "$(DEPMOD)" ] && echo "DEPMOD=$(DEPMOD)")	\
		modules_install

uninstall:
	rm -f $(INSTALL_DIR)/libsrp.ko $(INSTALL_DIR)/ibmvstgt.ko
	-/sbin/depmod -b $(INSTALL_MOD_PATH)/ -a $(KVER)

src/Module.symvers src/Modules.symvers: $(SCST_DIR)/$(MODULE_SYMVERS)
	cp $< $@;

clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd)/src clean
	rm -f src/Modules.symvers src/Module.symvers src/Module.markers \
		src/modules.order

extraclean: clean
	rm -f *.orig *.rej

.PHONY: all install clean extraclean
