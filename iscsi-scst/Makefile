#
# Makefile for iSCSI-SCST
#
# Note! Dependencies are done automatically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (not a .c file).

ifndef PREFIX
	PREFIX=/usr/local
endif

SHELL=/bin/bash

SUBDIRS := $(shell pwd)

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
SBINDIR := $(PREFIX)/sbin
INITDIR := /etc/init.d
RCDIR := /etc/rc.d
MANDIR ?= $(PREFIX)/man
KMOD := $(shell pwd)/kernel
INCDIR := $(shell pwd)/include
ISERTMOD := $(KMOD)/isert-scst

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
INFINIBAND_ENABLED = $(shell syms=$$(dirname "$(KDIR)")/modules.symbols; if [ -e "$$syms" ] && grep -wq 'ib_register_client' "$$syms" || grep -q "^CONFIG_INFINIBAND=[my]$$" "$(KDIR)/.config"; then echo true; else echo false; fi)

all: progs mods

ISER_SYMVERS:=$(KMOD)/Module.symvers
OFED_CFLAGS:=

OFED_FLAVOR=$(shell if [ -e /usr/bin/ofed_info ]; then /usr/bin/ofed_info 2>/dev/null | head -n1 | sed -n 's/^\(MLNX_OFED\|OFED-internal\).*/MOFED/p;s/^OFED-.*/OFED/p'; else echo in-tree; fi)

ifeq ($(OFED_FLAVOR),MOFED)
	# Whether MLNX_OFED for ubuntu has been installed
	MLNX_OFED_IB_UBUNTU_INSTALLED:=$(shell if dpkg -s mlnx-ofed-kernel-dkms >/dev/null 2>/dev/null; then echo true; else echo false; fi)

	# Whether MLNX_OFED for RedHat has been installed
	MLNX_OFED_IB_RH_INSTALLED:=$(shell if rpm -q mlnx-ofa_kernel-devel >&/dev/null; then echo true; else echo false; fi)

	# Check if we have custom compiled kernel modules
        ifeq ($(MLNX_OFED_IB_RH_INSTALLED),false)
	MLNX_OFED_IB_RH_INSTALLED:=$(shell if rpm -q kernel-ib-devel >&/dev/null; then echo true; else echo false; fi)
	endif

	ifeq ($(MLNX_OFED_IB_UBUNTU_INSTALLED),true)
	OFED_VERS=$(shell dpkg -s mlnx-ofed-kernel-dkms | awk -F\- '/Version/ {print $$1}' | awk '{print $$2}')
	OFED_CFLAGS:=-I/var/lib/dkms/mlnx-ofed-kernel/$(OFED_VERS)/build/include -include /var/lib/dkms/mlnx-ofed-kernel/$(OFED_VERS)/build/include/linux/compat-2.6.h
	ISER_SYMVERS:="$(ISER_SYMVERS) /var/lib/dkms/mlnx-ofed-kernel/$(OFED_VERS)/build/Module.symvers"
	endif

	ifeq ($(MLNX_OFED_IB_RH_INSTALLED),true)
	OFED_VERS=$(shell rpm -q --qf '%{version}\n' mlnx-ofa_kernel-devel \
			  2>/dev/null)
	OFED_CFLAGS:=-I/usr/src/ofa_kernel/default/include -include /usr/src/ofa_kernel/default/include/linux/compat-2.6.h
	ISER_SYMVERS:="$(ISER_SYMVERS) /usr/src/ofa_kernel/default/Module.symvers"
	endif

	# Make the version of the MOFED kernel package available to C source
	# files such that it can be used in #ifdef statements where MOFED
	# uses an older version of the RDMA API than the upstream kernel.
	OFED_CFLAGS+=-DMOFED_MAJOR=$(shell echo $(OFED_VERS) | cut -f1 -d.)
else
	# Whether or not the OFED kernel-ib-devel RPM has been installed.
	OFED_KERNEL_IB_DEVEL_RPM_INSTALLED:=$(shell if rpm -q kernel-ib-devel 2>/dev/null | grep -q $$(uname -r | sed 's/-/_/g'); then echo true; else echo false; fi)

	# Whether or not the OFED compat-rdma-devel RPM has been installed.
	OFED_COMPAT_RDMA_DEVEL_RPM_INSTALLED:=$(shell if rpm -q compat-rdma-devel 2>/dev/null | grep -q $$(uname -r | sed 's/-/_/g'); then echo true; else echo false; fi)

	ifeq ($(OFED_KERNEL_IB_DEVEL_RPM_INSTALLED),true)
	# Read OFED's config.mk, which contains the definition of the variable
	# BACKPORT_INCLUDES.
	include /usr/src/ofa_kernel/config.mk
	OFED_CFLAGS:=$(shell echo $(BACKPORT_INCLUDES) -I/usr/src/ofa_kernel/include)
	ISER_SYMVERS:="$(ISER_SYMVERS) /usr/src/ofa_kernel/Module.symvers"
	endif

	ifeq ($(OFED_COMPAT_RDMA_DEVEL_RPM_INSTALLED),true)
	OFED_CFLAGS:=-I/usr/src/compat-rdma/include -include /usr/src/compat-rdma/include/linux/compat-2.6.h
	ISER_SYMVERS:="$(ISER_SYMVERS) /usr/src/compat-rdma/Module.symvers"
	endif
endif

# Use make instead of $(MAKE) to get rid of command-line option -i
run_conftest = $(shell if [ "0$(V)" -gt 0 ]; then output=/dev/stdout; else output=/dev/null; fi; if MAKEFLAGS= make -C $(KDIR) V=$(V) SUBDIRS="$(shell pwd)/conftest/$1" PRE_CFLAGS="-Werror $(OFED_CFLAGS)" 1>&2 2>$${output}; then echo "$(strip $2)"; else echo "$(strip $3)"; fi)
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

mods: include/iscsi_scst_itf_ver.h Modules.symvers Module.symvers	\
	$(CONFTEST_OUTPUTS)
	$(MAKE) -C $(KDIR) SCST_INC_DIR=$(SCST_INC_DIR) SUBDIRS=$(KMOD) modules
	echo "$@:  INFINIBAND_ENABLED = $(INFINIBAND_ENABLED)"
	if $(INFINIBAND_ENABLED); then					       \
	  echo "  Building against $(OFED_FLAVOR) InfiniBand kernel headers."; \
	  $(MAKE) -C $(KDIR) SCST_INC_DIR=$(SCST_INC_DIR) SUBDIRS=$(ISERTMOD)  \
	  PRE_CFLAGS="$(PRE_CFLAGS)"	                                       \
	  KBUILD_EXTRA_SYMBOLS=$(ISER_SYMVERS) modules;			       \
	fi

progs: include/iscsi_scst_itf_ver.h
	$(MAKE) -C usr SCST_INC_DIR=$(SCST_INC_DIR)

include/iscsi_scst_itf_ver.h: include/iscsi_scst.h
	echo "/* Autogenerated, don't edit */" >include/iscsi_scst_itf_ver.h
	echo "" >>include/iscsi_scst_itf_ver.h
	echo -n "#define ISCSI_SCST_INTERFACE_VERSION " >>include/iscsi_scst_itf_ver.h
	echo -n "ISCSI_VERSION_STRING \"_" >>include/iscsi_scst_itf_ver.h
	echo "`sha1sum include/iscsi_scst.h|awk '{printf $$1}'`\"" >>include/iscsi_scst_itf_ver.h

install: all
	@install -vD -m 755 usr/iscsi-scstd $(DESTDIR)$(SBINDIR)/iscsi-scstd
	@install -vD -m 644 doc/manpages/iscsi-scstd.conf.5 $(DESTDIR)$(MANDIR)/man5/iscsi-scstd.conf.5
	@install -vD -m 644 doc/manpages/iscsi-scstd.8 $(DESTDIR)$(MANDIR)/man8/iscsi-scstd.8
	@install -vD -m 755 usr/iscsi-scst-adm $(DESTDIR)$(SBINDIR)/iscsi-scst-adm
	@install -vD -m 644 doc/manpages/iscsi-scst-adm.8 $(DESTDIR)$(MANDIR)/man8/iscsi-scst-adm.8
	$(MAKE) -C $(KDIR) SCST_INC_DIR=$(SCST_INC_DIR) SUBDIRS=$(KMOD) \
	  $$([ -n "$(DESTDIR)$(INSTALL_MOD_PATH)" ] && echo DEPMOD=true) \
	  modules_install
	echo "$@:  INFINIBAND_ENABLED = $(INFINIBAND_ENABLED)"
	if $(INFINIBAND_ENABLED); then					      \
	  $(MAKE) -C $(KDIR) SCST_INC_DIR=$(SCST_INC_DIR) SUBDIRS=$(ISERTMOD) \
	    $$([ -n "$(DESTDIR)$(INSTALL_MOD_PATH)" ] && echo DEPMOD=true)    \
	    modules_install;						      \
	fi

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/iscsi-scstd \
		$(DESTDIR)$(MANDIR)/man5/iscsi-scstd.conf.5 \
		$(DESTDIR)$(MANDIR)/man8/iscsi-scstd.8 \
		$(DESTDIR)$(SBINDIR)/iscsi-scst-adm \
		$(DESTDIR)$(MANDIR)/man8/iscsi-scst-adm.8 \
		$(INSTALL_DIR)/iscsi-scst.ko \
		$(INSTALL_DIR)/isert-scst.ko
	-/sbin/depmod -b $(INSTALL_MOD_PATH)/ -a $(KVER)

SCST_MOD_VERS := $(shell ls $(SCST_SYMVERS_DIR)/Modules.symvers 2>/dev/null)
ifneq ($(SCST_MOD_VERS),)
Modules.symvers: $(SCST_SYMVERS_DIR)/Modules.symvers
	echo $(SCST_MOD_VERS)
	cp $(SCST_SYMVERS_DIR)/Modules.symvers kernel/
	echo "$@:  INFINIBAND_ENABLED = $(INFINIBAND_ENABLED)"
	if $(INFINIBAND_ENABLED); then				    \
	  cp $(SCST_SYMVERS_DIR)/Modules.symvers kernel/isert-scst; \
	fi
else
.PHONY: Modules.symvers
endif

# It's renamed in 2.6.18
SCST_MOD_VERS := $(shell ls $(SCST_SYMVERS_DIR)/Module.symvers 2>/dev/null)
ifneq ($(SCST_MOD_VERS),)
Module.symvers: $(SCST_SYMVERS_DIR)/Module.symvers
	cp $(SCST_SYMVERS_DIR)/Module.symvers kernel/
	if $(INFINIBAND_ENABLED); then				   \
	  cp $(SCST_SYMVERS_DIR)/Module.symvers kernel/isert-scst; \
	fi
else
.PHONY: Module.symvers
endif

clean:
	$(MAKE) -C usr $@
	$(MAKE) -C $(KDIR) SUBDIRS=$(KMOD) $@
	$(MAKE) -C $(KDIR) SUBDIRS=$(ISERTMOD) $@
	rm -f kernel/Modules.symvers kernel/Module.symvers \
		kernel/Module.markers kernel/modules.order \
		kernel/isert-scst/Modules.symvers kernel/isert-scst/Module.symvers \
		kernel/isert-scst/Module.markers kernel/isert-scst/modules.order \
		include/iscsi_scst_itf_ver.h
	rm -rf conftest/*/*.ko conftest/*/*.mod.c conftest/*/Module.symvers conftest/*/*.o \
		conftest/*/*.o.cmd conftest/*/*.ko.cmd conftest/*/.*.o.cmd conftest/*/.*.ko.cmd \
		conftest/*/*.order conftest/*/.*.o.d conftest/*/.tmp_versions/ \
		conftest/*/result*.txt

extraclean: clean
	rm -f kernel/*.orig kernel/*.rej \
		kernel/isert-scst/*.orig kernel/isert-scst/*.rej
	rm -rf conftest/*/*.rej conftest/*/*.orig

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

2release:
	sed -i.aa s/"^E\?XTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/ $(KMOD)/Makefile
	grep "^#EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS" $(KMOD)/Makefile >/dev/null
	sed -i.aa s/"^#\?EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/"EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/ $(KMOD)/Makefile
	grep "^EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING" $(KMOD)/Makefile >/dev/null
	sed -i.aa s/"^E\?XTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/ $(KMOD)/Makefile
	grep "^#EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions" $(KMOD)/Makefile >/dev/null
	rm $(KMOD)/Makefile.aa
	sed -i.aa s/"^E\?XTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/ $(ISERTMOD)/Makefile
	grep "^#EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS" $(ISERTMOD)/Makefile >/dev/null
	sed -i.aa s/"^#\?EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/"EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/ $(ISERTMOD)/Makefile
	grep "^EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING" $(ISERTMOD)/Makefile >/dev/null
	sed -i.aa s/"^E\?XTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/ $(ISERTMOD)/Makefile
	grep "^#EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions" $(ISERTMOD)/Makefile >/dev/null
	rm $(ISERTMOD)/Makefile.aa

2debug:
	sed -i.aa s/"^#\?EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/"EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/ $(KMOD)/Makefile
	grep "^EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS" $(KMOD)/Makefile >/dev/null
	sed -i.aa s/"^E\?XTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/ $(KMOD)/Makefile
	grep "^#EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING" $(KMOD)/Makefile >/dev/null
	sed -i.aa s/"^#\?EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/"EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/ $(KMOD)/Makefile
	grep "^EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions" $(KMOD)/Makefile >/dev/null
	rm $(KMOD)/Makefile.aa
	sed -i.aa s/"^#\?EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/"EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/ $(ISERTMOD)/Makefile
	grep "^EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS" $(ISERTMOD)/Makefile >/dev/null
	sed -i.aa s/"^E\?XTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/ $(ISERTMOD)/Makefile
	grep "^#EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING" $(ISERTMOD)/Makefile >/dev/null
	sed -i.aa s/"^#\?EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/"EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/ $(ISERTMOD)/Makefile
	grep "^EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions" $(ISERTMOD)/Makefile >/dev/null
	rm $(ISERTMOD)/Makefile.aa

2perf:
	sed -i.aa s/"^E\?XTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/ $(KMOD)/Makefile
	grep "^#EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS" $(KMOD)/Makefile >/dev/null
	sed -i.aa s/"^E\?XTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/ $(KMOD)/Makefile
	grep "^#EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING" $(KMOD)/Makefile >/dev/null
	sed -i.aa s/"^E\?XTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/ $(KMOD)/Makefile
	grep "^#EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions" $(KMOD)/Makefile >/dev/null
	rm $(KMOD)/Makefile.aa
	sed -i.aa s/"^E\?XTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS"/ $(ISERTMOD)/Makefile
	grep "^#EXTRA_CFLAGS += \-DCONFIG_SCST_EXTRACHECKS" $(ISERTMOD)/Makefile >/dev/null
	sed -i.aa s/"^E\?XTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING"/ $(ISERTMOD)/Makefile
	grep "^#EXTRA_CFLAGS += \-DCONFIG_SCST_TRACING" $(ISERTMOD)/Makefile >/dev/null
	sed -i.aa s/"^E\?XTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/"#EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions"/ $(ISERTMOD)/Makefile
	grep "^#EXTRA_CFLAGS += \-DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions" $(ISERTMOD)/Makefile >/dev/null
	rm $(ISERTMOD)/Makefile.aa

disable_proc:
	sed -i.aa s/"^#\?define CONFIG_SCST_PROC"/"\/* #define CONFIG_SCST_PROC *\/"/ $(INCDIR)/iscsi_scst_ver.h
	grep "^\/\* #define CONFIG_SCST_PROC \*\/" $(INCDIR)/iscsi_scst_ver.h >/dev/null
	rm $(INCDIR)/iscsi_scst_ver.h.aa

enable_proc:
	sed -i.aa s/"^\/\?\* #define CONFIG_SCST_PROC \*\/"/"#define CONFIG_SCST_PROC"/ $(INCDIR)/iscsi_scst_ver.h
	grep "^#define CONFIG_SCST_PROC" $(INCDIR)/iscsi_scst_ver.h >/dev/null
	rm $(INCDIR)/iscsi_scst_ver.h.aa

release-archive:
	../scripts/generate-release-archive iscsi-scst "$$(sed -n 's/^#define[[:blank:]]ISCSI_VERSION_STRING[[:blank:]]*\"\([^\"]*\)\".*/\1/p' include/iscsi_scst_ver.h)"

.PHONY: all mods progs install clean extraclean 2release 2debug 2perf disable_proc enable_proc
