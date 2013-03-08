#
# Makefile for ib_srpt.ko.
#
ifndef PREFIX
	PREFIX=/usr/local
endif

SCST_INC_DIR := $(shell if [ -e "$$PWD/../scst" ];			\
			then echo "$$PWD/../scst/include";		\
			else echo "$(PREFIX)/include/scst"; fi)
SCST_SYMVERS_DIR := $(shell if [ -e $$PWD/../scst ]; then	\
                        echo $$PWD/../scst/src;			\
                      else echo $(PREFIX)/include/scst; fi)
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

# Set variable $(2) to value $(3) in file $(1).
set_var = $(shell { if [ -e "$(1)" ]; then grep -v '^$(2)=' "$(1)"; fi; echo "$(2)=$(3)"; } >/tmp/$(1)-$$$$.tmp && mv /tmp/$(1)-$$$$.tmp $(1))


# The file Modules.symvers has been renamed in the 2.6.18 kernel to
# Module.symvers. Find out which name to use by looking in $(KDIR).
MODULE_SYMVERS:=$(shell if [ -e $(KDIR)/Module.symvers ]; then \
		       echo Module.symvers; else echo Modules.symvers; fi)

# Whether or not the OFED kernel modules have been installed.
OFED_KERNEL_IB_RPM_INSTALLED:=$(shell if rpm -q kernel-ib 2>/dev/null | grep -q $$(uname -r | sed 's/-/_/g'); then echo true; else echo false; fi)

# Whether or not the OFED kernel-ib-devel RPM has been installed.
OFED_KERNEL_IB_DEVEL_RPM_INSTALLED:=$(shell if rpm -q kernel-ib-devel 2>/dev/null | grep -q $$(uname -r | sed 's/-/_/g'); then echo true; else echo false; fi)

ifeq ($(OFED_KERNEL_IB_DEVEL_RPM_INSTALLED),true)
# Read OFED's config.mk, which contains the definition of the variable
# BACKPORT_INCLUDES.
include /usr/src/ofa_kernel/config.mk
endif

OFED_CFLAGS:=$(shell if $(OFED_KERNEL_IB_DEVEL_RPM_INSTALLED); then echo $(BACKPORT_INCLUDES) -I/usr/src/ofa_kernel/include; fi)

# Path of the OFED ib_srpt.ko kernel module.
OFED_SRPT_PATH:=/lib/modules/$(KVER)/updates/kernel/drivers/infiniband/ulp/srpt/ib_srpt.ko

# Whether or not the OFED ib_srpt.ko kernel module has been installed.
OFED_SRPT_INSTALLED:=$(shell if [ -e $(OFED_SRPT_PATH) ]; then echo true; else echo false; fi)


all: src/$(MODULE_SYMVERS)
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)/src \
	  PRE_CFLAGS="$(OFED_CFLAGS)" SCST_INC_DIR=$(SCST_INC_DIR) modules

install: all src/ib_srpt.ko
	@eval `sed -n 's/#define UTS_RELEASE /KERNELRELEASE=/p' $(KDIR)/include/linux/version.h $(KDIR)/include/linux/utsrelease.h 2>/dev/null`; \
	install -vD -m 644 src/ib_srpt.ko \
	$(DESTDIR)$(INSTALL_MOD_PATH)/lib/modules/$(KVER)/extra/ib_srpt.ko
	-/sbin/depmod -aq $(KVER)

src/Module.symvers src/Modules.symvers: $(SCST_SYMVERS_DIR)/$(MODULE_SYMVERS)
	@if $(OFED_KERNEL_IB_RPM_INSTALLED); then                           \
	  if ! $(OFED_KERNEL_IB_DEVEL_RPM_INSTALLED); then                  \
	    echo "Error: the OFED package kernel-ib-devel has not yet been" \
	         "installed.";                                              \
	    false;                                                          \
	  elif [ -e /lib/modules/$(KVER)/kernel/drivers/infiniband ]; then  \
	    echo "Error: the distro-provided InfiniBand kernel drivers"     \
	         "must be removed first.";                                  \
	    false;                                                          \
	  elif $(OFED_SRPT_INSTALLED); then                                 \
	    echo "Error: OFED has been built with srpt=y in ofed.conf.";    \
	    echo "Rebuild OFED with srpt=n.";                               \
	    false;                                                          \
	  elif [ -e $(KDIR)/scripts/Makefile.lib ]                          \
	       && ! grep -wq '^c_flags .*PRE_CFLAGS'                        \
                  $(KDIR)/scripts/Makefile.lib                              \
	       && ! grep -wq '^LINUXINCLUDE .*PRE_CFLAGS'                   \
                  $(KDIR)/Makefile; then                                    \
	    echo "Error: the kernel build system has not yet been patched.";\
	    false;                                                          \
	  else                                                              \
	    echo "  Building against OFED InfiniBand kernel headers.";      \
	    (                                                               \
	      grep -v drivers/infiniband/ $<;                               \
	      cat /usr/src/ofa_kernel/Module.symvers                        \
	    ) >$@;                                                          \
	  fi                                                                \
	else                                                                \
	  if $(OFED_KERNEL_IB_DEVEL_RPM_INSTALLED); then                    \
	    echo "Error: the OFED package kernel-ib has not yet been"       \
	         "installed.";                                              \
	    false;                                                          \
	  else                                                              \
	    echo "  Building against non-OFED InfiniBand kernel headers.";  \
	    cp $< $@;                                                       \
	  fi;                                                               \
	fi

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)/src clean
	rm -f src/Modules.symvers src/Module.symvers src/Module.markers \
		src/modules.order

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

.PHONY: all install clean extraclean 2debug 2release 2perf
