#
# A Makefile for the scst-local ...
#

SHELL=/bin/bash

KMOD 		:= $(shell pwd)/kernel

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
  ifeq ($(KDIR),)
    KDIR := /lib/modules/$(KVER)/build
  endif
endif

ifeq ($(INSTALL_MOD_PATH),)
  export INSTALL_MOD_PATH := $(DESTDIR)
endif

INSTALL_MOD_DIR=extra

INSTALL_DIR := $(INSTALL_MOD_PATH)/lib/modules/$(KVER)/$(INSTALL_MOD_DIR)

SCST_DIR := $(shell echo "$$PWD")/../scst/src

all:
	$(MAKE) -C $(KDIR) M=$(shell pwd)				\
	  $(shell [ -n "$(PASS_CC_TO_MAKE)" ] && echo CC="$(CC)")

install: all
	KDIR=$(KDIR) ../scripts/sign-modules
	$(MAKE) -C $(KDIR) M=$(shell pwd)				\
	  $(shell [ -n "$(PASS_CC_TO_MAKE)" ] && echo CC="$(CC)")	\
	  INSTALL_MOD_DIR=$(INSTALL_MOD_DIR)				\
	  $$([ -n "$(DEPMOD)" ] && echo "DEPMOD=$(DEPMOD)")		\
	  CONFIG_MODULE_SIG_ALL= modules_install

uninstall:
	rm -f $(INSTALL_DIR)/scst_local.ko
	-/sbin/depmod -b $(INSTALL_MOD_PATH)/ -a $(KVER)

clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) $@

extraclean: clean
	rm -f *.orig *.rej

release-archive:
	../scripts/generate-release-archive scst_local "$$(sed -n 's/^#define[[:blank:]]SCST_LOCAL_VERSION[[:blank:]]*\"\([^\"]*\)\".*/\1/p' scst_local.c)"

.PHONY: all install uninstall clean extraclean

