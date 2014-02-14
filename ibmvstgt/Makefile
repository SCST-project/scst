#
# Makefile for ibmvstgt.ko.
#

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
MODULE_SYMVERS:=$(shell if [ -e $(KDIR)/Module.symvers ]; then \
		       echo Module.symvers; else echo Modules.symvers; fi)


all: src/$(MODULE_SYMVERS)
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)/src modules

install: all src/ibmvstgt.ko
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)/src modules_install

src/Module.symvers src/Modules.symvers: $(SCST_DIR)/$(MODULE_SYMVERS)
	cp $< $@;

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)/src clean
	rm -f src/Modules.symvers src/Module.symvers src/Module.markers \
		src/modules.order

extraclean: clean
	rm -f *.orig *.rej

.PHONY: all install clean extraclean
