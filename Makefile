#
#  Common makefile for SCSI target mid-level and its drivers
#
#  Copyright (C) 2015 - 2018 Vladislav Bolkhovitin <vst@vlnb.net>
#  Copyright (C) 2007 - 2018 Western Digital Corporation
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation, version 2
#  of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.
#
#

SHELL = /bin/bash

# Define the location to the kernel src. Can be defined here or on
# the command line during the build process. If KDIR is defined,
# we will determine an appropriate value for KVER from the kernel
# source tree. KVER can still be overridden by the user via the
# command line or by defining it in this Makefile. If KDIR and KVER
# are not defined by the user, the current running kernel version is
# used to define KVER.

#export KDIR=/usr/src/linux-2.6
#export KVER=2.6.x

ifdef KDIR
     ifndef KVER
          export KVER = $(strip $(shell					 \
		cat $(KDIR)/include/config/kernel.release 2>/dev/null || \
		make -s -C $(KDIR) kernelversion))
     endif
else
     ifndef KVER
	KVER=$(strip $(shell uname -r))
     endif
     KDIR=/lib/modules/$(KVER)/build
endif

PKG_BUILD_MODE ?= 2release

OLD_QLA_INI_DIR=qla2x00t
OLD_QLA_DIR=$(OLD_QLA_INI_DIR)/qla2x00-target

NEW_QLA_INI_DIR=qla2x00t-32gbit
NEW_QLA_DIR=$(NEW_QLA_INI_DIR)/qla2x00-target

ifeq ($(QLA_32GBIT),no)
    QLA_INI_DIR=$(OLD_QLA_INI_DIR)
    QLA_DIR=$(OLD_QLA_DIR)
else
    QLA_INI_DIR=$(NEW_QLA_INI_DIR)
    QLA_DIR=$(NEW_QLA_DIR)
endif


SCST_DIR=scst
DOC_DIR=doc
SCSTADM_DIR=scstadmin
USR_DIR=usr
SRP_DIR=srpt
SCST_LOCAL_DIR=scst_local
FCST_DIR=fcst
EMULEX_DIR=emulex

ISCSI_DIR=iscsi-scst

SCST_GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null)

REVISION ?= $(SCST_GIT_COMMIT)
export REVISION

VERSION_WITHOUT_REVISION := $(shell echo -n "$$(sed -n 's/^\#define[[:blank:]]SCST_VERSION_NAME[[:blank:]]*\"\([^-]*\).*\"/\1/p' scst/include/scst_const.h)")
ifneq (, $(REVISION))
VERSION := $(VERSION_WITHOUT_REVISION).$(REVISION)
else
VERSION := $(VERSION_WITHOUT_REVISION)
endif
DEBIAN_REVISION=1.1
RPMTOPDIR ?= $(shell if [ $$(id -u) = 0 ]; then echo /usr/src/packages;\
		else echo $$PWD/rpmbuilddir; fi)
SCST_SOURCE_FILES = $(shell if [ -e scripts/list-source-files ]; then	\
				scripts/list-source-files;		\
			else						\
				echo scripts-source-files-is-missing;	\
			fi)

help:
	@echo "		all               : make all"
	@echo "		clean             : clean files"
	@echo "		extraclean        : clean + clean dependencies"
	@echo "		install           : install"
	@echo "		uninstall         : uninstall"
	@echo ""
	@echo "		scst              : make scst only"
	@echo "		scst_clean        : scst: clean "
	@echo "		scst_extraclean   : scst: clean + clean dependencies"
	@echo "		scst_install      : scst: install"
	@echo "		scst_uninstall    : scst: uninstall"
	@echo ""
	@echo "		scstadm_install   : scstadmin: install"
	@echo "		scstadm_uninstall : scstadmin: uninstall"
	@echo ""
	@echo "		qla               : make QLA target driver"
	@echo "		qla_clean         : qla target: clean "
	@echo "		qla_extraclean    : qla target: clean + clean dependencies"
	@echo "		qla_install       : qla target: install"
	@echo "		qla_uninstall     : qla target: uninstall"
	@echo ""
	@echo "		iscsi             : make iSCSI target"
	@echo "		iscsi_clean       : ISCSI target: clean "
	@echo "		iscsi_extraclean  : ISCSI target: clean + clean dependencies"
	@echo "		iscsi_install     : ISCSI target: install"
	@echo "		iscsi_uninstall   : ISCSI target: uninstall"
	@echo ""
	@echo "		emulex             : make Emulex target"
	@echo "		emulex_clean       : Emulex target: clean "
	@echo "		emulex_extraclean  : Emulex target: clean + clean dependencies"
	@echo "		emulex_install     : Emulex target: install"
	@echo "		emulex_uninstall   : Emulex target: uninstall"
	@echo ""
	@echo "		srpt              : make SRP target"
	@echo "		srpt_clean        : srp target: clean "
	@echo "		srpt_extraclean   : srp target: clean + clean dependencies"
	@echo "		srpt_install      : srp target: install"
	@echo "		srpt_uninstall    : srp target: uninstall"
	@echo ""
	@echo "		fcst              : make FCoE target"
	@echo "		fcst_clean        : FCoE target: clean "
	@echo "		fcst_extraclean   : FCoE target: clean + clean dependencies"
	@echo "		fcst_install      : FCoE target: install"
	@echo "		fcst_uninstall    : FCoE target: uninstall"
	@echo ""
	@echo "		scst_local	  : make scst_local target"
	@echo "		scst_local_install : scst_local target: install"
	@echo "		scst_local_uninstall : scst_local target: uninstall"
	@echo ""
	@echo "		usr               : make user space targets"
	@echo "		usr_clean         : usr target: clean "
	@echo "		usr_extraclean    : usr target: clean + clean dependencies"
	@echo "		usr_install       : usr target: install"
	@echo "		usr_uninstall     : usr target: uninstall"
	@echo ""
	@echo "		2perf             : changes debug state to full performance"
	@echo "		2release          : changes debug state to release"
	@echo "		2debug            : changes debug state to full debug"
	@echo ""
	@echo "	Note:"
	@echo "		- install and uninstall may need root privileges"

all install uninstall clean extraclean:
	-if [ $@ = extraclean ]; then rm -f TAGS tags cscope.out; fi
	-for d in $(SCST_DIR) $(ISCSI_DIR) $(QLA_DIR) $(SRP_DIR)	    \
		$(SCST_LOCAL_DIR) $(FCST_DIR) $(USR_DIR) $(SCSTADM_DIR); do \
		$(MAKE) -j$$(nproc) -C "$$d" $@ || break;		    \
	done

tags:
	find . -type f -name "*.[ch]" | ctags --c-kinds=+p --fields=+iaS --extra=+q -e -L-

cov-build:
	-for d in $(SCST_DIR) $(ISCSI_DIR) $(OLD_QLA_DIR) $(NEW_QLA_DIR) $(SRP_DIR)  \
		$(SCST_LOCAL_DIR) $(FCST_DIR) $(USR_DIR) $(SCSTADM_DIR); do	     \
		if [[ $$d = $(OLD_QLA_DIR) || $$d = $(NEW_QLA_DIR) ]]; then	     \
			BUILD_2X_MODULE=y $(MAKE) -j$$(nproc) -C "$$d" all || break; \
		else								     \
			$(MAKE) -j$$(nproc) -C "$$d" all || break;		     \
		fi								     \
	done

scst:
	cd $(SCST_DIR) && $(MAKE) all

scst_install:
	cd $(SCST_DIR) && $(MAKE) install

scst_uninstall:
	cd $(SCST_DIR) && $(MAKE) uninstall

scst_clean:
	cd $(SCST_DIR) && $(MAKE) clean

scst_extraclean:
	cd $(SCST_DIR) && $(MAKE) extraclean

docs:
	cd $(DOC_DIR) && $(MAKE) all

docs_clean:
	cd $(DOC_DIR) && $(MAKE) clean

docs_extraclean:
	cd $(DOC_DIR) && $(MAKE) extraclean

scstadm:
	cd $(SCSTADM_DIR) && $(MAKE) all

scstadm_install:
	cd $(SCSTADM_DIR) && $(MAKE) install

scstadm_uninstall:
	cd $(SCSTADM_DIR) && $(MAKE) uninstall

scstadm_clean:
	cd $(SCSTADM_DIR) && $(MAKE) clean

scstadm_extraclean:
	cd $(SCSTADM_DIR) && $(MAKE) extraclean

qla:
	cd $(QLA_DIR) && $(MAKE) all

qla_install:
	cd $(QLA_DIR) && $(MAKE) install

qla_uninstall:
	cd $(QLA_DIR) && $(MAKE) uninstall

qla_clean:
	cd $(QLA_DIR) && $(MAKE) clean

qla_extraclean:
	cd $(QLA_DIR) && $(MAKE) extraclean

iscsi:
	cd $(ISCSI_DIR) && $(MAKE) all

iscsi_install:
	cd $(ISCSI_DIR) && $(MAKE) install

iscsi_uninstall:
	cd $(ISCSI_DIR) && $(MAKE) uninstall

iscsi_clean:
	cd $(ISCSI_DIR) && $(MAKE) clean

iscsi_extraclean:
	cd $(ISCSI_DIR) && $(MAKE) extraclean

emulex:
	cd $(EMULEX_DIR) && $(MAKE) all

emulex_install:
	cd $(EMULEX_DIR) && $(MAKE) install

emulex_uninstall:
	cd $(EMULEX_DIR) && $(MAKE) uninstall

emulex_clean:
	cd $(EMULEX_DIR) && $(MAKE) clean

emulex_extraclean:
	cd $(EMULEX_DIR) && $(MAKE) extraclean

srpt:
	cd $(SRP_DIR) && $(MAKE) all

srpt_install:
	cd $(SRP_DIR) && $(MAKE) install

srpt_uninstall:
	cd $(SRP_DIR) && $(MAKE) uninstall

srpt_clean:
	cd $(SRP_DIR) && $(MAKE) clean

srpt_extraclean:
	cd $(SRP_DIR) && $(MAKE) extraclean

scst_local:
	cd $(SCST_LOCAL_DIR) && $(MAKE) all

scst_local_install:
	cd $(SCST_LOCAL_DIR) && $(MAKE) install

scst_local_uninstall:
	cd $(SCST_LOCAL_DIR) && $(MAKE) uninstall

scst_local_clean:
	cd $(SCST_LOCAL_DIR) && $(MAKE) clean

scst_local_extraclean:
	cd $(SCST_LOCAL_DIR) && $(MAKE) extraclean

usr:
	cd $(USR_DIR) && $(MAKE)

usr_install:
	cd $(USR_DIR) && $(MAKE) install

usr_uninstall:
	cd $(USR_DIR) && $(MAKE) uninstall

usr_clean:
	cd $(USR_DIR) && $(MAKE) clean

usr_extraclean:
	cd $(USR_DIR) && $(MAKE) extraclean

fcst:
	cd $(FCST_DIR) && $(MAKE) all

fcst_install:
	cd $(FCST_DIR) && $(MAKE) install

fcst_uninstall:
	cd $(FCST_DIR) && $(MAKE) uninstall

fcst_clean:
	cd $(FCST_DIR) && $(MAKE) clean

fcst_extraclean:
	cd $(FCST_DIR) && $(MAKE) extraclean

# Make an SCST source code archive. $(1) is the tar compression option, $(2)
# is the tar filename compression suffix, $(3) is the version and $(4) is the
# source file filter.
make-scst-dist =							\
	[ -n "$(1)" ] && [ -n "$(2)" ] && [ -n "$(3)" ] &&		\
	[ -n "$(4)" ] &&						\
	name=scst &&							\
	mkdir "$${name}-$(3)" &&					\
	{								\
	  {								\
	    scripts/list-source-files | grep -v '/\.gitignore' &&	\
	    if [ -e debian/changelog ]; then echo debian/changelog; fi;	\
	    if [ -e debian/compat ]; then echo debian/compat; fi;	\
	  } |								\
	  $(4) |							\
	  tar -T- -cf- |						\
	  tar -C "$${name}-$(3)" -xf-;					\
	} &&								\
	rm -f "$${name}-$(3).tar.$(2)" &&				\
	tar -c$(1) -f "$${name}-$(3).tar.$(2)" "$${name}-$(3)" &&	\
	rm -rf "$${name}-$(3)"

scst-dist-gzip: scst-$(VERSION).tar.bz2

scst-$(VERSION).tar.bz2: $(SCST_SOURCE_FILES)
	$(call make-scst-dist,j,bz2,$(VERSION),grep -E '^debian/|^doc/|^fcst/|^iscsi-scst/|^Makefile|^qla2x00t(|-32gbit)/|^scripts/|^scst.spec|^scst/|^scst_local/|^srpt/|^usr/|^scstadmin/')

scst-rpm:
	name=scst &&							\
	rpmtopdir=$(RPMTOPDIR) &&					\
	$(MAKE) scst-dist-gzip &&					\
	for d in BUILD RPMS SOURCES SPECS SRPMS; do			\
	  mkdir -p $${rpmtopdir}/$$d;					\
	done &&								\
	cp scst-$(VERSION).tar.bz2 $${rpmtopdir}/SOURCES &&		\
	sed -e "s/@rpm_version@/$(VERSION)/g"				\
	    -e "s|@depmod@|$(shell which depmod)|g"			\
		<$${name}.spec.in >$${name}.spec &&			\
	MAKE="$(MAKE)" rpmbuild --define="%_topdir $${rpmtopdir}"	\
	    $(if $(KVER),--define="%kversion $(KVER)")			\
	    $(if $(KDIR),--define="%kdir $(KDIR)")			\
	    --define="%pkg_build_mode $(PKG_BUILD_MODE)"		\
	    -ba $${name}.spec &&					\
	rm -f scst-$(VERSION).tar.bz2

scst-dkms-rpm:
	name=scst-dkms &&						\
	rpmtopdir=$(RPMTOPDIR) &&					\
	$(MAKE) scst-dist-gzip &&					\
	for d in BUILD RPMS SOURCES SPECS SRPMS; do			\
	  mkdir -p $${rpmtopdir}/$$d;					\
	done &&								\
	cp scst-$(VERSION).tar.bz2 $${rpmtopdir}/SOURCES &&		\
	sed "s/@rpm_version@/$(VERSION)/g"				\
		<$${name}.spec.in >$${name}.spec &&			\
	MAKE="$(MAKE)" rpmbuild --define="%_topdir $${rpmtopdir}"	\
	    $(if $(KVER),--define="%kversion $(KVER)")			\
	    $(if $(KDIR),--define="%kdir $(KDIR)")			\
	    --define="%pkg_build_mode $(PKG_BUILD_MODE)"		\
	    -ba $${name}.spec &&					\
	rm -f scst-$(VERSION).tar.bz2

rpm:
	$(MAKE) scst-rpm
	$(MAKE) -C scstadmin rpm
	@if [ "$$(id -u)" != 0 ]; then			\
	    echo;					\
	    echo "The following RPMs have been built:";	\
	    find -name '*.rpm';				\
	fi

rpm-dkms:
	$(MAKE) scst-dkms-rpm
	$(MAKE) -C scstadmin rpm
	@if [ "$$(id -u)" != 0 ]; then			\
	    echo;					\
	    echo "The following RPMs have been built:";	\
	    find -name '*.rpm';				\
	fi

debian/changelog: debian/changelog.in
	sed 's/%{scst_version}/$(VERSION)-$(DEBIAN_REVISION)/'		\
	  <debian/changelog.in >debian/changelog

debian/compat:
	dpkg-query -W --showformat='$${Version}\n' debhelper 2>/dev/null | \
	sed 's/\..*//' >$@

../scst_$(VERSION).orig.tar.gz: debian/changelog debian/compat Makefile	\
		$(SCST_SOURCE_FILES)
	$(call make-scst-dist,z,gz,$(VERSION),cat) &&			\
	mv "scst-$(VERSION).tar.gz" "$@"

../scst_$(VERSION).orig.tar.xz: debian/changelog debian/compat Makefile	\
		$(SCST_SOURCE_FILES)
	$(call make-scst-dist,J,xz,$(VERSION),cat) &&			\
	mv "scst-$(VERSION).tar.xz" "$@"

dpkg: ../scst_$(VERSION).orig.tar.gz
	@[ -z "$$DEBEMAIL" ] || export DEBEMAIL=bvanassche@acm.org &&	\
	[ -z "$$DEBFULLNAME" ] || export DEBFULLNAME="Bart Van Assche" &&\
	echo "KDIR=$(KDIR)" &&						\
	echo "KVER=$(KVER)" &&						\
	sed 's/%{scst_version}/$(VERSION)/'				\
	  <debian/scst.dkms.in >debian/scst.dkms &&			\
	sed 's/%{KVER}/$(KVER)/'					\
	  <debian/scst.preinst.in >debian/scst.preinst &&		\
	sed 's/%{KVER}/$(KVER)/'					\
	  <debian/scst.postinst.in >debian/scst.postinst &&		\
	output_files=(							\
		../*_$(VERSION)-$(DEBIAN_REVISION)_*.deb		\
		../*_$(VERSION)-$(DEBIAN_REVISION)_*.ddeb		\
		../scst_$(VERSION)-$(DEBIAN_REVISION).debian.tar.[gx]z	\
		../scst_$(VERSION)-$(DEBIAN_REVISION).dsc		\
		../scst_$(VERSION)-$(DEBIAN_REVISION)_amd64.build	\
		../scst_$(VERSION)-$(DEBIAN_REVISION)_amd64.buildinfo	\
		../scst_$(VERSION)-$(DEBIAN_REVISION)_amd64.changes	\
	) &&								\
	rm -f "$${output_files[@]}" &&					\
	buildopts=(-uc -us) &&						\
	if dpkg-buildpackage --help 2>&1 | grep -q -- '-ui'; then	\
	  buildopts+=(-ui);						\
	fi &&								\
	if dpkg-buildpackage --help 2>&1 |				\
	   grep -q -- '--jobs\[=<number>|auto\]'; then			\
	  buildopts+=(-jauto);						\
	else								\
	  buildopts+=(-j4);						\
	fi &&								\
	DEB_CC_SET="$(CC)" DEB_KVER_SET=$(KVER) DEB_KDIR_SET=$(KDIR) DEB_QLA_DIR_SET=$(QLA_DIR) \
	   DEB_QLA_INI_DIR_SET=$(QLA_INI_DIR) DEB_PKG_BUILD_MODE=$(PKG_BUILD_MODE) \
	   debuild "$${buildopts[@]}" --lintian-opts --profile debian && \
	mkdir -p dpkg &&						\
	for f in "$${output_files[@]}" ../scst_$(VERSION).orig.tar.[gx]z; do\
		mv $$f dpkg || true;					\
	done &&								\
	echo "Output files:" &&						\
	ls -l dpkg

release-archive:
	$(MAKE) 2release
	scripts/generate-release-archive scst "$(VERSION_WITHOUT_REVISION)"
	md5sum ../scst-$(VERSION_WITHOUT_REVISION).tar.bz2	\
	  > ../scst-$(VERSION_WITHOUT_REVISION).tar.bz2.md5sum
	$(MAKE) 2debug

multiple-release-archives:
	$(MAKE) 2release
	for m in $$(find -name Makefile |			\
		    xargs grep -l '^release-archive:' |		\
		    grep -v '^\./Makefile');			\
	do							\
	    (cd $$(dirname $$m) && $(MAKE) release-archive)	\
	done
	$(MAKE) 2debug

2perf:
	cd $(SCST_DIR) && $(MAKE) $@

2release:
	cd $(SCST_DIR) && $(MAKE) $@

2debug:
	cd $(SCST_DIR) && $(MAKE) $@

.PHONY: all install uninstall clean extraclean tags help \
	qla qla_install qla_uninstall qla_clean qla_extraclean \
	iscsi iscsi_install iscsi_uninstall iscsi_clean iscsi_extraclean \
	emulex emulex_install emulex_uninstall emulex_clean emulex_extraclean \
	scst scst_install scst_uninstall scst_clean scst_extraclean \
	docs docs_clean docs_extraclean \
	scstadm scstadm_install scstadm_uninstall scstadm_clean scstadm_extraclean \
	srpt srpt_install srpt_uninstall srpt_clean srpt_extraclean \
	usr usr_install usr_uninstall usr_clean usr_extraclean \
	scst_local scst_local_install scst_local_uninstall scst_local_clean scst_local_extraclean \
	fcst fcst_install fcst_uninstall fcst_clean fcst_extraclean \
	scst-rpm scst-dkms-rpm dpkg \
	2perf 2release 2debug
