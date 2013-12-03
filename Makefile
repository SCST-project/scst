#
#  Common makefile for SCSI target mid-level and its drivers
#
#  Copyright (C) 2004 - 2013 Vladislav Bolkhovitin <vst@vlnb.net>
#  Copyright (C) 2007 - 2010 ID7 Ltd.
#  Copyright (C) 2010 - 2013 SCST Ltd.
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
# the command line during the build process.  If KDIR is defined,
# we will set an appropriate value for KVER by running "make
# kernelversion" in the kernel source tree.  KVER can still be
# overrode by the user via the command line or by defining it in
# this Makefile.  If KDIR and KVER are not defined by the user,
# the current running kernel version is used to define KVER.

#export KDIR=/usr/src/linux-2.6
#export KVER=2.6.x

ifdef KDIR
     ifndef KVER
          export KVER = $(strip $(shell make -s -C $(KDIR) kernelversion))
     endif
endif

SCST_DIR=scst
DOC_DIR=doc
SCSTADM_DIR=scstadmin
QLA_INI_DIR=qla2x00t
QLA_DIR=qla2x00t/qla2x00-target
QLA_ISP_DIR=qla_isp
LSI_DIR=mpt
USR_DIR=usr/fileio
SRP_DIR=srpt
SCST_LOCAL_DIR=scst_local
MVSAS_DIR=mvsas_tgt
FCST_DIR=fcst

ISCSI_DIR=iscsi-scst
#ISCSI_DESTDIR=../../../iscsi_scst_inst

VERSION = $(shell echo -n "$$(sed -n 's/^\#define[[:blank:]]SCST_VERSION_NAME[[:blank:]]*\"\([^-]*\).*\"/\1/p' scst/include/scst_const.h).";		\
		   if svn info >/dev/null 2>&1;				\
		   then svn info | sed -n 's/^Revision:[[:blank:]]*/r/p';\
		   else git show | sed -n 's/^commit[[:blank:]]*\(.......\).*/\1/p'; \
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
	@echo "		qla_clean         : 2.6 qla target: clean "
	@echo "		qla_extraclean    : 2.6 qla target: clean + clean dependencies"
	@echo "		qla_install       : 2.6 qla target: install"
	@echo "		qla_uninstall     : 2.6 qla target: uninstall"
	@echo ""
	@echo "		qla_isp           : make ISP Qlogic chipsets target driver"
	@echo "		qla_isp_clean     : qla ISP target: clean "
	@echo "		qla_isp_extraclean: qla ISP target: clean + clean dependencies"
	@echo "		qla_isp_install   : qla ISP target: install"
	@echo "		qla_isp_uninstall : qla ISP target: uninstall"
	@echo ""
	@echo "		iscsi             : make iSCSI target"
	@echo "		iscsi_clean       : ISCSI target: clean "
	@echo "		iscsi_extraclean  : ISCSI target: clean + clean dependencies"
	@echo "		iscsi_install     : ISCSI target: install"
	@echo "		iscsi_uninstall   : ISCSI target: uninstall"
	@echo ""
	@echo "		lsi               : make LSI MPT target"
	@echo "		lsi_clean         : lsi target: clean "
	@echo "		lsi_extraclean    : lsi target: clean + clean dependencies"
	@echo "		lsi_install       : lsi target: install"
	@echo "		lsi_uninstall     : lsi target: uninstall"
	@echo ""
	@echo "		srpt              : make SRP target"
	@echo "		srpt_clean        : srp target: clean "
	@echo "		srpt_extraclean   : srp target: clean + clean dependencies"
	@echo "		srpt_install      : srp target: install"
	@echo "		srpt_uninstall    : srp target: uninstall"
	@echo ""
	@echo "		mvsas             : make MVSAS target"
	@echo "		mvsas_clean       : mvsas target: clean "
	@echo "		mvsas_extraclean  : mvsas target: clean + clean dependencies"
	@echo "		mvsas_install     : mvsas target: install"
	@echo "		mvsas_uninstall   : mvsas target: uninstall"
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
	@echo "		usr               : make user space fileio_tgt target"
	@echo "		usr_clean         : usr target: clean "
	@echo "		usr_extraclean    : usr target: clean + clean dependencies"
	@echo "		usr_install       : usr target: install"
	@echo "		usr_uninstall     : usr target: uninstall"
	@echo ""
	@echo "		enable_proc       : switch to procfs interface"
	@echo "		disable_proc      : switch to sysfs interface (default)"
	@echo ""
	@echo "		2perf             : changes debug state to full performance"
	@echo "		2release          : changes debug state to release"
	@echo "		2debug            : changes debug state to full debug"
	@echo ""
	@echo "	Note:"
	@echo "		- install and uninstall may need root privileges"

all:
	cd $(SCST_DIR) && $(MAKE) $@
#	@if [ -d $(DOC_DIR) ]; then cd $(DOC_DIR) && $(MAKE) $@; fi
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi
#	@if [ -d $(QLA_ISP_DIR) ]; then cd $(QLA_ISP_DIR) && $(MAKE) $@; fi
#	@if [ -d $(LSI_DIR) ]; then cd $(LSI_DIR) && $(MAKE) $@; fi
#	@if [ -d $(SRP_DIR) ]; then cd $(SRP_DIR) && $(MAKE) $@; fi
	@if [ -d $(ISCSI_DIR) ]; then cd $(ISCSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(USR_DIR) ]; then cd $(USR_DIR) && $(MAKE) $@; fi
	@if [ -d $(SCST_LOCAL_DIR) ]; then cd $(SCST_LOCAL_DIR) && $(MAKE) $@; fi

install:
	cd $(SCST_DIR) && $(MAKE) $@
#	@if [ -d $(DOC_DIR) ]; then cd $(DOC_DIR) && $(MAKE) $@; fi
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi
#	@if [ -d $(QLA_ISP_DIR) ]; then cd $(QLA_ISP_DIR) && $(MAKE) $@; fi
#	@if [ -d $(LSI_DIR) ]; then cd $(LSI_DIR) && $(MAKE) $@; fi
#	@if [ -d $(SRP_DIR) ]; then cd $(SRP_DIR) && $(MAKE) $@; fi
	@if [ -d $(ISCSI_DIR) ]; then cd $(ISCSI_DIR) && $(MAKE) DESTDIR=$(ISCSI_DESTDIR) $@; fi
	@if [ -d $(USR_DIR) ]; then cd $(USR_DIR) && $(MAKE) $@; fi
	@if [ -d $(SCST_LOCAL_DIR) ]; then cd $(SCST_LOCAL_DIR) && $(MAKE) $@; fi

uninstall:
	cd $(SCST_DIR) && $(MAKE) $@
#	@if [ -d $(DOC_DIR) ]; then cd $(DOC_DIR) && $(MAKE) $@; fi
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi
#	@if [ -d $(QLA_ISP_DIR) ]; then cd $(QLA_ISP_DIR) && $(MAKE) $@; fi
#	@if [ -d $(LSI_DIR) ]; then cd $(LSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(SRP_DIR) ]; then cd $(SRP_DIR) && $(MAKE) $@; fi
	@if [ -d $(ISCSI_DIR) ]; then cd $(ISCSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(USR_DIR) ]; then cd $(USR_DIR) && $(MAKE) $@; fi
	@if [ -d $(SCST_LOCAL_DIR) ]; then cd $(SCST_LOCAL_DIR) && $(MAKE) $@; fi

clean:
	cd $(SCST_DIR) && $(MAKE) $@
	@if [ -d $(DOC_DIR) ]; then cd $(DOC_DIR) && $(MAKE) $@; fi
	@if [ -d $(QLA_INI_DIR) ]; then cd $(QLA_INI_DIR) && $(MAKE) $@; fi
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi
#	@if [ -d $(QLA_ISP_DIR) ]; then cd $(QLA_ISP_DIR) && $(MAKE) $@; fi
#	@if [ -d $(LSI_DIR) ]; then cd $(LSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(SRP_DIR) ]; then cd $(SRP_DIR) && $(MAKE) $@; fi
	@if [ -d $(ISCSI_DIR) ]; then cd $(ISCSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(USR_DIR) ]; then cd $(USR_DIR) && $(MAKE) $@; fi
	@if [ -d $(SCST_LOCAL_DIR) ]; then cd $(SCST_LOCAL_DIR) && $(MAKE) $@; fi

extraclean:
	-rm -f TAGS
	cd $(SCST_DIR) && $(MAKE) $@
	@if [ -d $(DOC_DIR) ]; then cd $(DOC_DIR) && $(MAKE) $@; fi
	@if [ -d $(QLA_INI_DIR) ]; then cd $(QLA_INI_DIR) && $(MAKE) $@; fi
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi
#	@if [ -d $(QLA_ISP_DIR) ]; then cd $(QLA_ISP_DIR) && $(MAKE) $@; fi
#	@if [ -d $(LSI_DIR) ]; then cd $(LSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(SRP_DIR) ]; then cd $(SRP_DIR) && $(MAKE) $@; fi
	@if [ -d $(ISCSI_DIR) ]; then cd $(ISCSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(USR_DIR) ]; then cd $(USR_DIR) && $(MAKE) $@; fi
	@if [ -d $(SCST_LOCAL_DIR) ]; then cd $(SCST_LOCAL_DIR) && $(MAKE) $@; fi

tags:
	find . -type f -name "*.[ch]" | ctags --c-kinds=+p --fields=+iaS --extra=+q -e -L-

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
	cd $(QLA_INI_DIR) && $(MAKE) clean
	cd $(QLA_DIR) && $(MAKE) clean

qla_extraclean:
	cd $(QLA_INI_DIR)/.. && $(MAKE) extraclean
	cd $(QLA_DIR) && $(MAKE) extraclean

qla_isp:
	cd $(QLA_ISP_DIR) && $(MAKE) all

qla_isp_install:
	cd $(QLA_ISP_DIR) && $(MAKE) install

qla_isp_uninstall:
	cd $(QLA_ISP_DIR) && $(MAKE) uninstall

qla_isp_clean:
	cd $(QLA_ISP_DIR) && $(MAKE) clean

qla_isp_extraclean:
	cd $(QLA_ISP_DIR) && $(MAKE) extraclean

iscsi:
	cd $(ISCSI_DIR) && $(MAKE) all

iscsi_install:
	cd $(ISCSI_DIR) && $(MAKE) DESTDIR=$(ISCSI_DESTDIR) install

iscsi_uninstall:
	cd $(ISCSI_DIR) && $(MAKE) uninstall

iscsi_clean: 
	cd $(ISCSI_DIR) && $(MAKE) clean

iscsi_extraclean:
	cd $(ISCSI_DIR) && $(MAKE) extraclean

lsi:
	cd $(LSI_DIR) && $(MAKE) all

lsi_install:
	cd $(LSI_DIR) && $(MAKE) install

lsi_uninstall:
	cd $(LSI_DIR) && $(MAKE) uninstall

lsi_clean: 
	cd $(LSI_DIR) && $(MAKE) clean

lsi_extraclean:
	cd $(LSI_DIR) && $(MAKE) extraclean

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

mvsas:
	cd $(MVSAS_DIR) && $(MAKE) all

mvsas_install:
	cd $(MVSAS_DIR) && $(MAKE) install

mvsas_uninstall:
	cd $(MVSAS_DIR) && $(MAKE) uninstall

mvsas_clean:
	cd $(MVSAS_DIR) && $(MAKE) clean

mvsas_extraclean:
	cd $(MVSAS_DIR) && $(MAKE) extraclean

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

scst-dist-gzip:
	name=scst &&							\
	mkdir $${name}-$(VERSION) &&					\
	{ scripts/list-source-files | \
	  grep -E '^doc/|^fcst/|^iscsi-scst/|^Makefile|^qla2x00t/|^scst.spec|^scst/|^scst_local/|^srpt/'|\
	  tar -T- -cf- |						\
	  tar -C $${name}-$(VERSION) -xf-; } &&				\
	rm -f $${name}-$(VERSION).tar.bz2 &&				\
	tar -cjf $${name}-$(VERSION).tar.bz2 $${name}-$(VERSION) &&	\
	rm -rf $${name}-$(VERSION)

scst-rpm:
	name=scst &&							\
	rpmtopdir="$$(if [ $$(id -u) = 0 ]; then echo /usr/src/packages;\
		    else echo $$PWD/rpmbuilddir; fi)" &&		\
	$(MAKE) scst-dist-gzip &&					\
	rm -rf $${rpmtopdir} &&						\
	for d in BUILD RPMS SOURCES SPECS SRPMS; do			\
	  mkdir -p $${rpmtopdir}/$$d;					\
	done &&								\
	cp $${name}-$(VERSION).tar.bz2 $${rpmtopdir}/SOURCES &&		\
	sed "s/@rpm_version@/$(VERSION)/g"				\
		<$${name}.spec.in >$${name}.spec;			\
	MAKE="$(MAKE)"							\
	rpmbuild --define="%_topdir $${rpmtopdir}" -ba $${name}.spec &&	\
	rm -f $${name}-$(VERSION).tar.bz2

rpm:
	$(MAKE) scst-rpm
	$(MAKE) -C scstadmin rpm
	@echo
	@echo "The following RPMs have been built:"
	@find -name '*.rpm'

2perf: extraclean
	cd $(SCST_DIR) && $(MAKE) $@
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi
#	patch -p0 <qla_isp-release.patch
#	@if [ -d $(LSI_DIR) ]; then cd $(LSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(SRP_DIR) ]; then cd $(SRP_DIR) && $(MAKE) $@; fi
	@if [ -d $(ISCSI_DIR) ]; then cd $(ISCSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(USR_DIR) ]; then cd $(USR_DIR) && $(MAKE) $@; fi
	@if [ -d $(SCST_LOCAL_DIR) ]; then cd $(SCST_LOCAL_DIR) && $(MAKE) $@; fi
	@if [ -d $(FCST_DIR) ]; then cd $(FCST_DIR) && $(MAKE) $@; fi

2release: extraclean
	cd $(SCST_DIR) && $(MAKE) $@
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi
#	patch -p0 <qla_isp-release.patch
#	@if [ -d $(LSI_DIR) ]; then cd $(LSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(SRP_DIR) ]; then cd $(SRP_DIR) && $(MAKE) $@; fi
	@if [ -d $(ISCSI_DIR) ]; then cd $(ISCSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(USR_DIR) ]; then cd $(USR_DIR) && $(MAKE) $@; fi
	@if [ -d $(SCST_LOCAL_DIR) ]; then cd $(SCST_LOCAL_DIR) && $(MAKE) $@; fi
	@if [ -d $(FCST_DIR) ]; then cd $(FCST_DIR) && $(MAKE) $@; fi

2debug: extraclean
	cd $(SCST_DIR) && $(MAKE) $@
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi
#	patch -p0 -R <qla_isp-release.patch
#	@if [ -d $(LSI_DIR) ]; then cd $(LSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(SRP_DIR) ]; then cd $(SRP_DIR) && $(MAKE) $@; fi
	@if [ -d $(ISCSI_DIR) ]; then cd $(ISCSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(USR_DIR) ]; then cd $(USR_DIR) && $(MAKE) $@; fi
	@if [ -d $(SCST_LOCAL_DIR) ]; then cd $(SCST_LOCAL_DIR) && $(MAKE) $@; fi
	@if [ -d $(FCST_DIR) ]; then cd $(FCST_DIR) && $(MAKE) $@; fi

enable_proc: extraclean
	cd $(SCST_DIR) && $(MAKE) $@
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi
#	patch -p0 -R <qla_isp-release.patch
#	@if [ -d $(LSI_DIR) ]; then cd $(LSI_DIR) && $(MAKE) $@; fi
#	@if [ -d $(SRP_DIR) ]; then cd $(SRP_DIR) && $(MAKE) $@; fi
	@if [ -d $(ISCSI_DIR) ]; then cd $(ISCSI_DIR) && $(MAKE) $@; fi
#	@if [ -d $(SCST_LOCAL_DIR) ]; then cd $(SCST_LOCAL_DIR) && $(MAKE) $@; fi
	@if [ -d $(SCSTADM_DIR) ]; then cd $(SCSTADM_DIR) && $(MAKE) $@; fi

disable_proc: extraclean
	cd $(SCST_DIR) && $(MAKE) $@
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi
#	patch -p0 -R <qla_isp-release.patch
#	@if [ -d $(LSI_DIR) ]; then cd $(LSI_DIR) && $(MAKE) $@; fi
#	@if [ -d $(SRP_DIR) ]; then cd $(SRP_DIR) && $(MAKE) $@; fi
	@if [ -d $(ISCSI_DIR) ]; then cd $(ISCSI_DIR) && $(MAKE) $@; fi
#	@if [ -d $(SCST_LOCAL_DIR) ]; then cd $(SCST_LOCAL_DIR) && $(MAKE) $@; fi
	@if [ -d $(SCSTADM_DIR) ]; then cd $(SCSTADM_DIR) && $(MAKE) $@; fi

.PHONY: all install uninstall clean extraclean tags help \
	qla qla_install qla_uninstall qla_clean qla_extraclean \
	qla_isp qla_isp_install qla_isp_uninstall qla_isp_clean qla_isp_extraclean \
	lsi lsi_install lsi_uninstall lsi_clean lsi_extraclean \
	iscsi iscsi_install iscsi_uninstall iscsi_clean iscsi_extraclean \
	scst scst_install scst_uninstall scst_clean scst_extraclean \
	docs docs_clean docs_extraclean \
	scstadm scstadm_install scstadm_uninstall scstadm_clean scstadm_extraclean \
	srpt srpt_install srpt_uninstall srpt_clean srpt_extraclean \
	usr usr_install usr_uninstall usr_clean usr_extraclean \
	scst_local scst_local_install scst_local_uninstall scst_local_clean scst_local_extraclean \
	mvsas mvsas_install mvsas_uninstall mvsas_clean mvsas_extraclean \
	fcst fcst_install fcst_uninstall fcst_clean fcst_extraclean \
	2perf 2release 2debug enable_proc disable_proc
