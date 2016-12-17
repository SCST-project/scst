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
MODULE_SYMVERS:=$(shell if [ -e "$(KDIR)/Module.symvers" ]; then \
		       echo Module.symvers; else echo Modules.symvers; fi)

# Name of the OFED kernel RPM.
OFED_KERNEL_IB_RPM:=$(shell for r in mlnx-ofa_kernel compat-rdma kernel-ib; do rpm -q $$r 2>/dev/null | grep -q "^$$r" && echo $$r && break; done)

# Name of the OFED kernel development RPM.
OFED_KERNEL_IB_DEVEL_RPM:=$(shell for r in mlnx-ofa_kernel-devel compat-rdma-devel kernel-ib-devel; do rpm -q $$r 2>/dev/null | grep -q "^$$r" && echo $$r && break; done)

OFED_FLAVOR=$(shell if [ -e /usr/bin/ofed_info ]; then /usr/bin/ofed_info 2>/dev/null | head -n1 | sed -n 's/^\(MLNX_OFED\|OFED-internal\).*/MOFED/p;s/^OFED-.*/OFED/p'; else echo in-tree; fi)

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
OFED_VERS=$(shell rpm -q --qf '%{version}\n' mlnx-ofa_kernel-devel 2>/dev/null)
CKVER:=$(shell echo "$(KVER)" | sed 's/^\(\(2\.6\|[3-9]\)\.[0-9]*\).*/\1/')
OFED_CFLAGS:=-I$(OFED_KERNEL_DIR)/include -include "linux/compat-2.6.h"
OFED_CFLAGS+=-DMOFED_MAJOR=$(shell echo $(OFED_VERS) | cut -f1 -d.)
OFED_CFLAGS+=-DMOFED_MINOR=$(shell echo $(OFED_VERS) | cut -f2 -d.)
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

GOALS:=$(if $(MAKECMDGOALS),$(MAKECMDGOALS),all)
OTHER_GOALS:=$(foreach goal,$(MAKECMDGOALS),$(subst all,,$(goal)))
# echo:=$(shell echo 'GOALS = $(GOALS)' >&2)
# echo:=$(shell echo 'OTHER_GOALS = $(OTHER_GOALS)' >&2)
ifneq ("$(GOALS)","$(OTHER_GOALS)")
run_conftest = $(shell if [ "0$(V)" -gt 0 ]; then output=/dev/stdout; else output=/dev/null; fi; if $(MAKE) -C $(KDIR) V=$(V) SUBDIRS="$(shell pwd)/conftest/$1" PRE_CFLAGS="-Werror $(OFED_CFLAGS)" 1>&2 2>$${output}; then echo "$2"; else echo "$3"; fi)
USE_PRE_440_WR_STRUCTURE    := $(call run_conftest,use_pre_440_wr_structure,-DUSE_PRE_440_WR_STRUCTURE)
CREATE_CQ_FLAG              := $(call run_conftest,create_cq,-DIB_CREATE_CQ_HAS_INIT_ATTR)
CREATE_SEND_MAD_AH_FLAG     := $(call run_conftest,create_send_mad_ah,-DCREATE_SEND_MAD_HAS_AH_ARG)
ifeq ($(CREATE_SEND_MAD_AH_FLAG),)
  CREATE_SEND_MAD_BASE_FLAG := $(call run_conftest,create_send_mad_base,-DCREATE_SEND_MAD_HAS_BASE_ARG)
endif
CLIENT_REMOVE		    := $(call run_conftest,ib_client_remove,-DIB_CLIENT_REMOVE_TAKES_TWO_ARGS)
CM_LISTEN		    := $(call run_conftest,cm_listen,-DIB_CM_LISTEN_TAKES_FOURTH_ARG)
MAD_HANDLER_TAKES_SEND_BUF  := $(call run_conftest,mad_handler_takes_send_buf,-DMAD_HANDLER_TAKES_SEND_BUF)
HAVE_IB_SET_CPI_RESP_TIME   := $(call run_conftest,ib_set_cpi_resp_time,-DHAVE_IB_SET_CPI_RESP_TIME)
GID_CHANGE_FLAG             := $(call run_conftest,gid_change,-DHAVE_IB_EVENT_GID_CHANGE)
RDMA_CREATE_ID              := $(call run_conftest,rdma_create_id_net,-DRDMA_CREATE_ID_TAKES_NET_ARG=1,-DRDMA_CREATE_ID_TAKES_NET_ARG=0)
REGISTER_MAD_AGENT_FLAG     := $(call run_conftest,register_mad_agent,-DREGISTER_MAD_AGENT_HAS_FLAGS_ARG)
QUERY_DEVICE                := $(call run_conftest,query_device,-DHAVE_IB_QUERY_DEVICE)
QUERY_DEVICE_HAS_ATTR_ARG   := $(call run_conftest,query_device_attr_arg,-DIB_QUERY_DEVICE_HAS_ATTR_ARG)
QUERY_GID_FLAG              := $(call run_conftest,query_gid,-DIB_QUERY_GID_HAS_ATTR_ARG)
PRE_CFLAGS=$(OFED_CFLAGS)			\
	$(USE_PRE_440_WR_STRUCTURE)		\
	$(CLIENT_REMOVE)			\
	$(CREATE_CQ_FLAG)			\
	$(CREATE_SEND_MAD_AH_FLAG)		\
	$(CREATE_SEND_MAD_BASE_FLAG)		\
	$(IB_CLIENT_REMOVE_TAKES_TWO_ARGS)	\
	$(CM_LISTEN)				\
	$(MAD_HANDLER_TAKES_SEND_BUF)		\
	$(HAVE_IB_SET_CPI_RESP_TIME)		\
	$(GID_CHANGE_FLAG)			\
	$(RDMA_CREATE_ID)			\
	$(REGISTER_MAD_AGENT_FLAG)		\
	$(QUERY_GID_FLAG)			\
	$(QUERY_DEVICE)				\
	$(QUERY_DEVICE_HAS_ATTR_ARG)		\
	-DOFED_FLAVOR=$(OFED_FLAVOR)
endif

all: src/$(MODULE_SYMVERS)
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)/src \
	  PRE_CFLAGS="$(PRE_CFLAGS)" SCST_INC_DIR=$(SCST_INC_DIR) modules

install: all
	@[ -z "$(DESTDIR)$(INSTALL_MOD_PATH)" ] && \
	  find /lib/modules/$(KVER) -name ib_srpt.ko -exec rm {} \; ; \
	  true
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)/src		   \
	  PRE_CFLAGS="$(PRE_CFLAGS)" SCST_INC_DIR=$(SCST_INC_DIR) \
	  $$([ -n "$(DESTDIR)$(INSTALL_MOD_PATH)" ] && echo DEPMOD=true) \
	  modules_install

uninstall:
	rm -f $(INSTALL_DIR)/ib_srpt.ko
	-/sbin/depmod -b $(INSTALL_MOD_PATH)/ -a $(KVER)

src/$(MODULE_SYMVERS): $(SCST_SYMVERS_DIR)/$(MODULE_SYMVERS)	\
		       $(OFED_MODULE_SYMVERS)
	@if [ -n "$(OFED_KERNEL_IB_RPM)" ]; then                            \
	  if [ -z "$(OFED_KERNEL_IB_DEVEL_RPM)" ]; then                     \
	    echo "Error: the OFED package $(OFED_KERNEL_IB_RPM)-devel has"  \
	         "not yet been installed.";                                 \
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
	rm -rf conftest/pre_cflags conftest/kcflags
	for d in conftest/* src; do					     \
	  [ -d "$$d" ] && $(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)/$$d clean; \
	done
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
