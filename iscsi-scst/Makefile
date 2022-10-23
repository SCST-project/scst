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

SCST_DIR := $(shell echo "$$PWD")/../scst/src
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
  ifeq ($(KDIR),)
    KDIR := /lib/modules/$(KVER)/build
  endif
endif

ifeq ($(INSTALL_MOD_PATH),)
  export INSTALL_MOD_PATH := $(DESTDIR)
endif

INSTALL_DIR := $(INSTALL_MOD_PATH)/lib/modules/$(KVER)/extra
INFINIBAND_ENABLED = $(shell syms=$$(dirname "$(KDIR)")/modules.symbols; if [ -e "$$syms" ] && grep -wq 'ib_register_client' "$$syms" || grep -q "^CONFIG_INFINIBAND=[my]$$" "$(KDIR)/.config"; then echo true; else echo false; fi)

all: progs mods

OFED_CFLAGS:=

OFED_FLAVOR=$(shell if [ -e /usr/bin/ofed_info ]; then /usr/bin/ofed_info 2>/dev/null | head -n1 | sed -n 's/^\(MLNX_OFED\|OFED-internal\).*/MOFED/p;s/^OFED-.*/OFED/p'; else echo in-tree; fi)

ifeq ($(OFED_FLAVOR),MOFED)
	ifeq ($(shell	if { dpkg -s mlnx-ofed-kernel-dkms || dpkg -s mlnx-ofed-kernel-modules; } >/dev/null 2>&1; then \
			  echo true;					       \
			else						       \
			  echo false;					       \
			fi),true)
	OFED_VERS=$(shell dpkg-query -W --showformat='$${Version}\n' mlnx-ofed-kernel-dkms mlnx-ofed-kernel-modules 2>/dev/null | head -n 1)
	else
	ifeq ($(shell	if { rpm -q mlnx-ofa_kernel-devel ||		 \
			     rpm -q kernel-ib-devel; } >&/dev/null; then \
			  echo true;					 \
			else						 \
			  echo false;					 \
			fi),true)
	OFED_VERS=$(shell rpm -q --qf '%{version}\n' mlnx-ofa_kernel-devel \
			  2>/dev/null)
	else
	echo := $(shell echo "Error: MLNX OFED has not been installed" >&2)
	endif
	endif

	echo := $(shell echo "OFED_VERS = $(OFED_VERS)" >&2)
	OFED_DIR:=/usr/src/ofa_kernel/default
	OFED_CFLAGS:=	-I$(OFED_DIR)/include				\
			-I$(OFED_DIR)/include/uapi			\
			-include $(OFED_DIR)/include/linux/compat-2.6.h \
			-DMOFED_MAJOR=$(shell echo $(OFED_VERS) | cut -f1 -d.)\
			-DMOFED_MINOR=$(shell echo $(OFED_VERS) | cut -f2 -d.)
	OFED_MODULE_SYMVERS:=$(OFED_DIR)/Module.symvers
	OFED_CONFIG:= CONFIG_DTRACE=
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
	endif

	ifeq ($(OFED_COMPAT_RDMA_DEVEL_RPM_INSTALLED),true)
	OFED_CFLAGS:=-I/usr/src/compat-rdma/include -include /usr/src/compat-rdma/include/linux/compat-2.6.h
	endif
endif

# Use make instead of $(MAKE) to get rid of command-line option -i. Enable
# -Wno-deprecated-declarations for the RHEL 7.x kernels.
run_conftest = $(shell							\
  export KCFLAGS="-Wno-deprecated-declarations";			\
  if [ "0$(V)" -gt 0 ]; then						\
    output=/dev/stdout;							\
  else									\
    output=conftest/$1/build-output-$(KVER).txt;			\
  fi;									\
  if MAKEFLAGS= make -C $(KDIR) V=$(V)					\
	$(shell [ -n "$(PASS_CC_TO_MAKE)" ] && echo CC="$(CC)")		\
	M="$(shell pwd)/conftest/$1"					\
	CONFTEST_CFLAGS="-Werror $(OFED_CFLAGS)" $(OFED_CONFIG)		\
	KBUILD_EXTRA_SYMBOLS="$(OFED_MODULE_SYMVERS)"			\
	1>&2 2>$${output}; then						\
    echo "$(strip $2)";							\
  else									\
    echo "$(strip $3)";							\
  fi)
run_conftest_bool = $(call run_conftest,$1,-D$(strip $2)=1,-D$(strip $2)=0)

CONFTESTS = $(shell ls -d conftest/*)
CONFTEST_OUTPUTS = $(shell			\
	for t in $(CONFTESTS); do		\
		echo $$t/result-$(KVER).txt;	\
	done)

CONFTEST_CFLAGS =					\
	$(shell for t in $(CONFTESTS); do 		\
		cat $$t/result-$(KVER).txt 2>/dev/null; \
	done)

ISER_CFLAGS = $(OFED_CFLAGS) -DOFED_FLAVOR=$(OFED_FLAVOR) $(CONFTEST_CFLAGS)

mods: include/iscsi_scst_itf_ver.h $(CONFTEST_OUTPUTS)
	$(MAKE) -C $(KDIR) M=$(KMOD) CONFTEST_CFLAGS="$(CONFTEST_CFLAGS)"\
	  $(shell [ -n "$(PASS_CC_TO_MAKE)" ] && echo CC="$(CC)")	\
	  modules
	echo "$@:  INFINIBAND_ENABLED = $(INFINIBAND_ENABLED)"
	if $(INFINIBAND_ENABLED); then					\
	  echo "  Building against $(OFED_FLAVOR) RDMA kernel headers.";\
	  $(MAKE) -C $(KDIR) M=$(ISERTMOD) ISER_CFLAGS="$(ISER_CFLAGS)"	\
	  $(shell [ -n "$(PASS_CC_TO_MAKE)" ] && echo CC="$(CC)")	\
	  $(OFED_CONFIG) modules;					\
	fi

progs: include/iscsi_scst_itf_ver.h
	$(MAKE) -C usr

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
	(cd $(KMOD) && KDIR=$(KDIR) ../../scripts/sign-modules)
	$(MAKE) -C $(KDIR) M=$(KMOD)					\
	  $(shell [ -n "$(PASS_CC_TO_MAKE)" ] && echo CC="$(CC)")	\
	  $$([ -n "$(DEPMOD)" ] && echo "DEPMOD=$(DEPMOD)")		\
	  CONFIG_MODULE_SIG_ALL= modules_install
	echo "$@:  INFINIBAND_ENABLED = $(INFINIBAND_ENABLED)"
	if $(INFINIBAND_ENABLED); then					\
	  (cd $(ISERTMOD) && KDIR=$(KDIR) ../../../scripts/sign-modules);\
	  $(MAKE) -C $(KDIR) M=$(ISERTMOD)				\
	    $(shell [ -n "$(PASS_CC_TO_MAKE)" ] && echo CC="$(CC)")	\
	    $$([ -n "$(DEPMOD)" ] && echo "DEPMOD=$(DEPMOD)")		\
	    CONFIG_MODULE_SIG_ALL= modules_install;			\
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

clean:
	rm -rf include/iscsi_scst_itf_ver.h
	rm -rf conftest/*/{build-output,result}*.txt
	for d in conftest/* kernel kernel/isert-scst; do		\
	  [ -d "$$d" ] && $(MAKE) -C $(KDIR) M=$(shell pwd)/$$d $@ &	\
	  rm -f $$d/result*.txt;					\
	done;								\
	wait
	$(MAKE) -C usr $@

extraclean: clean
	rm -f kernel/*.orig kernel/*.rej \
		kernel/isert-scst/*.orig kernel/isert-scst/*.rej
	rm -rf conftest/*/*.rej conftest/*/*.orig

conftest/bad_wr_mod/result-$(KVER).txt:					\
	conftest/bad_wr_mod/bad_wr_mod.c				\
	conftest/bad_wr_mod/Kbuild
	echo "$(call run_conftest,bad_wr_mod,				\
		-DBAD_WR_MODIFIER=const,-DBAD_WR_MODIFIER=)" >"$@"

conftest/cm_event_mod/result-$(KVER).txt:				\
	conftest/cm_event_mod/cm_event_mod.c				\
	conftest/cm_event_mod/Kbuild
	echo "$(call run_conftest,cm_event_mod,				\
		-DCM_HANDLER_EVENT_MODIFIER=const,-DCM_HANDLER_EVENT_MODIFIER=)" >"$@"

conftest/create_cq/result-$(KVER).txt:					\
	conftest/create_cq/create_cq.c					\
	conftest/create_cq/Kbuild
	echo "$(call run_conftest,create_cq,				\
		-DIB_CREATE_CQ_HAS_INIT_ATTR)" >"$@"

conftest/create_send_mad_ah/result-$(KVER).txt:				\
	conftest/create_send_mad_ah/create_send_mad_ah.c		\
	conftest/create_send_mad_ah/Kbuild
	echo "$(call run_conftest,create_send_mad_ah,			\
		-DCREATE_SEND_MAD_HAS_AH_ARG)" >"$@"

conftest/create_send_mad_base/result-$(KVER).txt:			\
	conftest/create_send_mad_base/create_send_mad_base.c		\
	conftest/create_send_mad_base/Kbuild
	echo "$(call run_conftest,create_send_mad_base,			\
		-DCREATE_SEND_MAD_HAS_BASE_ARG)" >"$@"

conftest/gid_change/result-$(KVER).txt:					\
	conftest/gid_change/gid_change.c				\
	conftest/gid_change/Kbuild
	echo "$(call run_conftest,gid_change,-DHAVE_IB_EVENT_GID_CHANGE)" >"$@"

conftest/ib_client_remove/result-$(KVER).txt:				\
	conftest/ib_client_remove/ib_client_remove.c			\
	conftest/ib_client_remove/Kbuild
	echo "$(call run_conftest,ib_client_remove,			\
		-DIB_CLIENT_REMOVE_TAKES_TWO_ARGS)" >"$@"

conftest/ib_dma_map_ops/result-$(KVER).txt:				\
	conftest/ib_dma_map_ops/ib_dma_map_ops.c			\
	conftest/ib_dma_map_ops/Kbuild
	echo "$(call run_conftest,ib_dma_map_ops,-DHAVE_IB_DMA_MAP_OPS)" >"$@"

conftest/ib_set_cpi_resp_time/result-$(KVER).txt:			\
	conftest/ib_set_cpi_resp_time/ib_set_cpi_resp_time.c		\
	conftest/ib_set_cpi_resp_time/Kbuild
	echo "$(call run_conftest,ib_set_cpi_resp_time,			\
		-DHAVE_IB_SET_CPI_RESP_TIME)" >"$@"

conftest/mad_handler_takes_send_buf/result-$(KVER).txt:			\
	conftest/mad_handler_takes_send_buf/mad_handler_takes_send_buf.c\
	conftest/mad_handler_takes_send_buf/Kbuild
	echo "$(call run_conftest,mad_handler_takes_send_buf,		\
		-DMAD_HANDLER_TAKES_SEND_BUF)" >"$@"

conftest/pd_has_local_dma_lkey/result-$(KVER).txt:			\
	conftest/pd_has_local_dma_lkey/pd_has_local_dma_lkey.c		\
	conftest/pd_has_local_dma_lkey/Kbuild
	echo "$(call run_conftest,pd_has_local_dma_lkey,		\
		-DIB_PD_HAS_LOCAL_DMA_LKEY)" >"$@"

conftest/query_device/result-$(KVER).txt:				\
	conftest/query_device/query_device.c				\
	conftest/query_device/Kbuild
	echo "$(call run_conftest,query_device,-DHAVE_IB_QUERY_DEVICE)" >"$@"

conftest/query_device_attr_arg/result-$(KVER).txt:			\
	conftest/query_device_attr_arg/query_device_attr_arg.c		\
	conftest/query_device_attr_arg/Kbuild
	echo "$(call run_conftest,query_device_attr_arg,		\
		-DIB_QUERY_DEVICE_HAS_ATTR_ARG)" >"$@"

conftest/dev_attr_max_recv_sge/result-$(KVER).txt:			\
	conftest/dev_attr_max_recv_sge/dev_attr_max_recv_sge.c	\
	conftest/dev_attr_max_recv_sge/Kbuild
	echo "$(call run_conftest,dev_attr_max_recv_sge,		\
		-DHAVE_DEV_ATTR_MAX_RECV_SGE)" >"$@"

conftest/query_gid/result-$(KVER).txt:					\
	conftest/query_gid/query_gid.c					\
	conftest/query_gid/Kbuild
	echo "$(call run_conftest,query_gid,-DIB_QUERY_GID_HAS_ATTR_ARG)" >"$@"

conftest/rdma_create_id_net/result-$(KVER).txt:				\
	conftest/rdma_create_id_net/rdma_create_id_net.c		\
	conftest/rdma_create_id_net/Kbuild
	echo "$(call run_conftest_bool,rdma_create_id_net,		\
		RDMA_CREATE_ID_TAKES_NET_ARG)" >"$@"

conftest/rdma_reject/result-$(KVER).txt:				\
	conftest/rdma_reject/rdma_reject.c				\
	conftest/rdma_reject/Kbuild
	echo "$(call run_conftest_bool,rdma_reject,			\
		RDMA_REJECT_HAS_FOUR_ARGS)" >"$@"

conftest/register_mad_agent/result-$(KVER).txt:				\
	conftest/register_mad_agent/register_mad_agent.c		\
	conftest/register_mad_agent/Kbuild
	echo "$(call run_conftest,register_mad_agent,			\
		-DREGISTER_MAD_AGENT_HAS_FLAGS_ARG)" >"$@"

conftest/sock_recvmsg/result-$(KVER).txt:				\
	conftest/sock_recvmsg/sock_recvmsg.c				\
	conftest/sock_recvmsg/Kbuild
	echo "$(call run_conftest_bool,sock_recvmsg,			\
		SOCK_RECVMSG_HAS_FOUR_ARGS)" >"$@"

conftest/use_pre_440_wr_structure/result-$(KVER).txt:			\
	conftest/use_pre_440_wr_structure/use_pre_440_wr_structure.c	\
	conftest/use_pre_440_wr_structure/Kbuild
	echo "$(call run_conftest,use_pre_440_wr_structure,		\
		-DUSE_PRE_440_WR_STRUCTURE)" >"$@"

release-archive:
	../scripts/generate-release-archive iscsi-scst "$$(sed -n 's/^#define[[:blank:]]ISCSI_VERSION_STRING[[:blank:]]*\"\([^\"]*\)\".*/\1/p' include/iscsi_scst_ver.h)"

.PHONY: all mods progs install clean extraclean
