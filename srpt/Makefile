#
# Makefile for ib_srpt.ko.
#

ifndef PREFIX
	PREFIX=/usr/local
endif

SCST_INC_DIR := $(shell						\
	if [ -e "$$PWD/../scst" ]; then				\
		echo "$$PWD/../scst/include";			\
	else							\
		echo "$(DESTDIR)$(PREFIX)/include/scst";	\
	fi)
SCST_SYMVERS_DIR := $(shell					\
	if [ -e "$$PWD/../scst" ]; then				\
		echo "$$PWD/../scst/src";			\
	else							\
		echo "$(DESTDIR)$(PREFIX)/include/scst";	\
	fi)

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

run_conftest = $(shell if [ "0$(V)" -gt 0 ]; then output=/dev/stdout; else output=/dev/null; fi; if $(MAKE) -C $(KDIR) V=$(V) SUBDIRS="$(shell pwd)/conftest/$1" PRE_CFLAGS="-Werror $(OFED_CFLAGS)" 1>&2 2>$${output}; then echo "$(strip $2)"; else echo "$(strip $3)"; fi)
run_conftest_bool = $(call run_conftest,$1,-D$(strip $2)=1,-D$(strip $2)=0)

CONFTESTS = $(shell ls -d conftest/*)
CONFTEST_OUTPUTS = $(shell			\
	for t in $(CONFTESTS); do		\
		echo $$t/result-$(KVER).txt;	\
	done)

PRE_CFLAGS = $(OFED_CFLAGS)			\
	-DOFED_FLAVOR=$(OFED_FLAVOR)		\
	$(shell for t in $(CONFTESTS); do 	\
		cat $$t/result-$(KVER).txt 2>/dev/null; \
	done)

all: check src/$(MODULE_SYMVERS) $(CONFTEST_OUTPUTS)
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)/src \
	  PRE_CFLAGS="$(PRE_CFLAGS)" SCST_INC_DIR=$(SCST_INC_DIR) modules

src/$(MODULE_SYMVERS): $(SCST_SYMVERS_DIR)/$(MODULE_SYMVERS)	\
		       $(OFED_MODULE_SYMVERS)
	cat $^ |							\
	awk '{sym[$$2]=$$0} END {for (s in sym){print sym[s]}}' >"$@"

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

check:
	@if [ -n "$(OFED_KERNEL_IB_RPM)" ]; then                            \
	  if [ -z "$(OFED_KERNEL_IB_DEVEL_RPM)" ]; then                     \
	    echo "Error: the OFED package $(OFED_KERNEL_IB_RPM)-devel has"  \
	         "not yet been installed.";                                 \
	    false;                                                          \
	  else                                                              \
	    echo "  Building against $(OFED_FLAVOR) $(OFED_KERNEL_IB_RPM)"  \
	         "InfiniBand kernel headers.";                              \
	  fi                                                                \
	else                                                                \
	  if [ -n "$(OFED_KERNEL_IB_DEVEL_RPM)" ]; then                     \
	    echo "Error: the OFED kernel package has not yet been"          \
	         "installed.";                                              \
	    false;                                                          \
	  else                                                              \
	    echo "  Building against in-tree InfiniBand kernel headers.";   \
	  fi;                                                               \
	fi

clean:
	rm -rf conftest/pre_cflags conftest/kcflags
	for d in conftest/* src; do					     \
	  [ -d "$$d" ] && $(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd)/$$d clean; \
	  rm -f $$d/result*.txt;					     \
	done
	rm -f src/$(MODULE_SYMVERS) src/Module.markers src/modules.order

extraclean: clean
	rm -f *.orig *.rej

conftest/cm_listen/result-$(KVER).txt:					\
	conftest/cm_listen/cm_listen.c					\
	conftest/cm_listen/Makefile
	echo "$(call run_conftest,cm_listen,				\
		-DIB_CM_LISTEN_TAKES_FOURTH_ARG)" >"$@"

conftest/create_cq/result-$(KVER).txt:					\
	conftest/create_cq/create_cq.c					\
	conftest/create_cq/Makefile
	echo "$(call run_conftest,create_cq,				\
		-DIB_CREATE_CQ_HAS_INIT_ATTR)" >"$@"

conftest/create_send_mad_ah/result-$(KVER).txt:				\
	conftest/create_send_mad_ah/create_send_mad_ah.c		\
	conftest/create_send_mad_ah/Makefile
	echo "$(call run_conftest,create_send_mad_ah,			\
		-DCREATE_SEND_MAD_HAS_AH_ARG)" >"$@"

conftest/create_send_mad_base/result-$(KVER).txt:			\
	conftest/create_send_mad_base/create_send_mad_base.c		\
	conftest/create_send_mad_base/Makefile
	echo "$(call run_conftest,create_send_mad_base,			\
		-DCREATE_SEND_MAD_HAS_BASE_ARG)" >"$@"

conftest/gid_change/result-$(KVER).txt:					\
	conftest/gid_change/gid_change.c				\
	conftest/gid_change/Makefile
	echo "$(call run_conftest,gid_change,-DHAVE_IB_EVENT_GID_CHANGE)" >"$@"

conftest/ib_client_remove/result-$(KVER).txt:				\
	conftest/ib_client_remove/ib_client_remove.c			\
	conftest/ib_client_remove/Makefile
	echo "$(call run_conftest,ib_client_remove,			\
		-DIB_CLIENT_REMOVE_TAKES_TWO_ARGS)" >"$@"

conftest/ib_dma_map_ops/result-$(KVER).txt:				\
	conftest/ib_dma_map_ops/ib_dma_map_ops.c			\
	conftest/ib_dma_map_ops/Makefile
	echo "$(call run_conftest,ib_dma_map_ops,-DHAVE_IB_DMA_MAP_OPS)" >"$@"

conftest/ib_set_cpi_resp_time/result-$(KVER).txt:			\
	conftest/ib_set_cpi_resp_time/ib_set_cpi_resp_time.c		\
	conftest/ib_set_cpi_resp_time/Makefile
	echo "$(call run_conftest,ib_set_cpi_resp_time,			\
		-DHAVE_IB_SET_CPI_RESP_TIME)" >"$@"

conftest/mad_handler_takes_send_buf/result-$(KVER).txt:			\
	conftest/mad_handler_takes_send_buf/mad_handler_takes_send_buf.c\
	conftest/mad_handler_takes_send_buf/Makefile
	echo "$(call run_conftest,mad_handler_takes_send_buf,		\
		-DMAD_HANDLER_TAKES_SEND_BUF)" >"$@"

conftest/pd_has_local_dma_lkey/result-$(KVER).txt:			\
	conftest/pd_has_local_dma_lkey/pd_has_local_dma_lkey.c		\
	conftest/pd_has_local_dma_lkey/Makefile
	echo "$(call run_conftest,pd_has_local_dma_lkey,		\
		-DIB_PD_HAS_LOCAL_DMA_LKEY)" >"$@"

conftest/query_device/result-$(KVER).txt:				\
	conftest/query_device/query_device.c				\
	conftest/query_device/Makefile
	echo "$(call run_conftest,query_device,-DHAVE_IB_QUERY_DEVICE)" >"$@"

conftest/query_device_attr_arg/result-$(KVER).txt:			\
	conftest/query_device_attr_arg/query_device_attr_arg.c		\
	conftest/query_device_attr_arg/Makefile
	echo "$(call run_conftest,query_device_attr_arg,		\
		-DIB_QUERY_DEVICE_HAS_ATTR_ARG)" >"$@"

conftest/query_gid/result-$(KVER).txt:					\
	conftest/query_gid/query_gid.c					\
	conftest/query_gid/Makefile
	echo "$(call run_conftest,query_gid,-DIB_QUERY_GID_HAS_ATTR_ARG)" >"$@"

conftest/rdma_create_id_net/result-$(KVER).txt:				\
	conftest/rdma_create_id_net/rdma_create_id_net.c		\
	conftest/rdma_create_id_net/Makefile
	echo "$(call run_conftest_bool,rdma_create_id_net,		\
		RDMA_CREATE_ID_TAKES_NET_ARG)" >"$@"

conftest/register_mad_agent/result-$(KVER).txt:				\
	conftest/register_mad_agent/register_mad_agent.c		\
	conftest/register_mad_agent/Makefile
	echo "$(call run_conftest,register_mad_agent,			\
		-DREGISTER_MAD_AGENT_HAS_FLAGS_ARG)" >"$@"

conftest/use_pre_440_wr_structure/result-$(KVER).txt:			\
	conftest/use_pre_440_wr_structure/use_pre_440_wr_structure.c	\
	conftest/use_pre_440_wr_structure/Makefile
	echo "$(call run_conftest,use_pre_440_wr_structure,		\
		-DUSE_PRE_440_WR_STRUCTURE)" >"$@"

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
