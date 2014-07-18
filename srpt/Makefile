#
# Makefile for ib_srpt.ko.
#
ifndef PREFIX
	PREFIX=/usr/local
endif

SCST_INC_DIR := $(shell if [ -e "$$PWD/../scst" ];			\
			then echo "$$PWD/../scst/include";		\
			else echo "$(DESTDIR)$(PREFIX)/include/scst"; fi)
SCST_SYMVERS_DIR := $(shell if [ -e $$PWD/../scst ]; then	\
                        echo $$PWD/../scst/src;			\
                      else echo $(DESTDIR)$(PREFIX)/include/scst; fi)

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

# Set variable $(2) to value $(3) in file $(1).
set_var = $(shell { if [ -e "$(1)" ]; then grep -v '^$(2)=' "$(1)"; fi; echo "$(2)=$(3)"; } >/tmp/$(1)-$$$$.tmp && mv /tmp/$(1)-$$$$.tmp $(1))


SRC_FILES=$(wildcard */*.[ch])

# The file Modules.symvers has been renamed in the 2.6.18 kernel to
# Module.symvers. Find out which name to use by looking in $(KDIR).
MODULE_SYMVERS:=$(shell if [ -e $(KDIR)/Module.symvers ]; then \
		       echo Module.symvers; else echo Modules.symvers; fi)

# Name of the OFED kernel RPM.
OFED_KERNEL_IB_RPM:=$(shell for r in mlnx-ofa_kernel compat-rdma kernel-ib; do rpm -q $$r 2>/dev/null | grep -q "^$$r" && echo $$r && break; done)

# Name of the OFED kernel development RPM.
OFED_KERNEL_IB_DEVEL_RPM:=$(shell for r in mlnx-ofa_kernel-devel compat-rdma-devel kernel-ib-devel; do rpm -q $$r 2>/dev/null | grep -q "^$$r" && echo $$r && break; done)

OFED_FLAVOR=$(shell /usr/bin/ofed_info 2>/dev/null | head -n1 | sed -n 's/^MLNX_OFED.*/MOFED/p;s/^OFED-.*/OFED/p')

ifneq ($(OFED_KERNEL_IB_RPM),)
ifeq ($(OFED_KERNEL_IB_RPM),compat-rdma)
# OFED 3.x
OFED_KERNEL_DIR:=/usr/src/compat-rdma
OFED_CFLAGS:=-I$(OFED_KERNEL_DIR)/include
else
ifeq ($(OFED_FLAVOR),MOFED)
# Mellanox OFED with or without kernel-ib RPM. Since several MOFED backport
# header files use the LINUX_BACKPORT() macro without including
# <linux/compat-2.6.h>, include that header file explicitly.
OFED_KERNEL_DIR:=/usr/src/ofa_kernel/default
OFED_CFLAGS:=-I$(OFED_KERNEL_DIR)/include -include linux/compat-2.6.h
else
# OFED 1.5
OFED_KERNEL_DIR:=/usr/src/ofa_kernel
include $(OFED_KERNEL_DIR)/config.mk
OFED_CFLAGS:=$(BACKPORT_INCLUDES) -I$(OFED_KERNEL_DIR)/include
endif
endif
# Any OFED version
OFED_MODULE_SYMVERS:=$(OFED_KERNEL_DIR)/$(MODULE_SYMVERS)
endif

HAVE_KCFLAGS    = $(shell $(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)/conftest/kcflags    KCFLAGS=-DKCFLAGS_MACRO=1       >/dev/null 2>&1 && echo true || echo false)
HAVE_PRE_CFLAGS = $(shell $(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)/conftest/pre_cflags PRE_CFLAGS=-DPRE_CFLAGS_MACRO=1 >/dev/null 2>&1 && echo true || echo false)
AUTOCONF_FLAGS  = $(shell $(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)/conftest/gid_change PRE_CFLAGS="$(OFED_CFLAGS)"     >/dev/null 2>&1 && echo -DHAVE_IB_EVENT_GID_CHANGE)


all: src/$(MODULE_SYMVERS)
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)/src \
	  PRE_CFLAGS="$(OFED_CFLAGS) $(AUTOCONF_FLAGS)" \
	  KCFLAGS="$(AUTOCONF_FLAGS)" SCST_INC_DIR=$(SCST_INC_DIR) modules

install: all src/ib_srpt.ko
	@[ -z "$(DESTDIR)$(INSTALL_MOD_PATH)" ] && \
	  find /lib/modules/$(KVER) -name ib_srpt.ko -exec rm {} \; ; \
	  true
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)/src		   \
	  PRE_CFLAGS="$(OFED_CFLAGS)" SCST_INC_DIR=$(SCST_INC_DIR) \
	  $$([ -n "$(DESTDIR)$(INSTALL_MOD_PATH)" ] && echo DEPMOD=true) \
	  modules_install

uninstall:
	rm -f $(INSTALL_DIR)/ib_srpt.ko
	-/sbin/depmod -b $(INSTALL_MOD_PATH)/ -a $(KVER)

src/$(MODULE_SYMVERS): $(SCST_SYMVERS_DIR)/$(MODULE_SYMVERS)	\
		       $(OFED_MODULE_SYMVERS)
	@if [ "$(HAVE_KCFLAGS)" = false -a "$(HAVE_PRE_CFLAGS)" = false -a  \
	      -n "$(AUTOCONF_FLAGS)" ]; then                                \
	    echo "Error: the kernel build system has not yet been patched.";\
	    false;                                                          \
	fi
	@if [ -n "$(OFED_KERNEL_IB_RPM)" ]; then                            \
	  if [ -z "$(OFED_KERNEL_IB_DEVEL_RPM)" ]; then                     \
	    echo "Error: the OFED package $(OFED_KERNEL_IB_RPM)-devel has"  \
	         "not yet been installed.";                                 \
	    false;                                                          \
	  elif [ "$(HAVE_PRE_CFLAGS)" = false ]; then                       \
	    echo "Error: the kernel build system has not yet been patched.";\
	    false;                                                          \
	  else                                                              \
	    echo "  Building against $(OFED_FLAVOR) $(OFED_KERNEL_IB_RPM)"  \
	         "InfiniBand kernel headers.";                              \
	    (                                                               \
	      cat  $(SCST_SYMVERS_DIR)/$(MODULE_SYMVERS) |                  \
	        grep -v 'drivers/infiniband/' |                             \
	        grep -v 'net/sunrpc/xprtrdma/' |                            \
	        grep -v 'net/rds/' |                                        \
	        grep -v 'extra/ib_srpt';                                    \
	      cat $(OFED_MODULE_SYMVERS)                                    \
	    ) >$@;                                                          \
	  fi                                                                \
	else                                                                \
	  if [ -n "$(OFED_KERNEL_IB_DEVEL_RPM)" ]; then                     \
	    echo "Error: the OFED kernel package has not yet been"          \
	         "installed.";                                              \
	    false;                                                          \
	  else                                                              \
	    echo "  Building against in-tree InfiniBand kernel headers.";   \
	    cp $< $@;                                                       \
	  fi;                                                               \
	fi

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)/src clean
	rm -f src/$(MODULE_SYMVERS) src/Module.markers src/modules.order

extraclean: clean
	rm -f *.orig *.rej

2debug:
	-$(MAKE) clean
	$(call set_var,build_mode,BUILDMODE,)

2release:
	-$(MAKE) clean
	$(call set_var,build_mode,BUILDMODE,RELEASE)

2perf:
	-$(MAKE) clean
	$(call set_var,build_mode,BUILDMODE,PERF)

release-archive:
	../scripts/generate-release-archive srpt "$$(sed -n 's/^#define[[:blank:]]DRV_VERSION[[:blank:]]*\"\([^\"]*\)\".*/\1/p' src/ib_srpt.c)"

kerneldoc.html: $(SRC_FILES)
	$(KDIR)/scripts/kernel-doc -html $(SRC_FILES) >$@

.PHONY: all install clean extraclean 2debug 2release 2perf
