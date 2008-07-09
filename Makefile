#
#  Common makefile for SCSI target mid-level and its drivers
#  
#  Copyright (C) 2004 - 2008 Vladislav Bolkhovitin <vst@vlnb.net>
#  Copyright (C) 2007 - 2008 CMS Distribution Limited
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

# Decide to use which kernel src. If not specified, is current running kernel.
#export KDIR=/usr/src/linux-2.6

SCST_DIR=scst
SCSTADM_DIR=scstadmin
QLA_INI_DIR=qla2x00t
QLA_DIR=qla2x00t/qla2x00-target
QLA_ISP_DIR=qla_isp
LSI_DIR=mpt
USR_DIR=usr/fileio
SRP_DIR=srpt

ISCSI_DIR=iscsi-scst
#ISCSI_DISTDIR=../../../iscsi_scst_inst

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
	@echo "		usr               : make user space fileio_tgt target"
	@echo "		usr_clean         : usr target: clean "
	@echo "		usr_extraclean    : usr target: clean + clean dependencies"
	@echo "		usr_install       : usr target: install"
	@echo "		usr_uninstall     : usr target: uninstall"
	@echo ""
	@echo "		debug2perf        : changes debug state from full debug to full performance"
	@echo "		debug2release     : changes debug state from full debug to release"
	@echo "		perf2debug        : changes debug state from full performance to full debug"
	@echo "		release2debug     : changes debug state from release to full debug"
	@echo ""
	@echo "	Note:"
	@echo "		- install and uninstall may need root privileges"

all:
	cd $(SCST_DIR) && $(MAKE) $@
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi
#	@if [ -d $(QLA_ISP_DIR) ]; then cd $(QLA_ISP_DIR) && $(MAKE) $@; fi
#	@if [ -d $(LSI_DIR) ]; then cd $(LSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(SRP_DIR) ]; then cd $(SRP_DIR) && $(MAKE) $@; fi
	@if [ -d $(ISCSI_DIR) ]; then cd $(ISCSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(USR_DIR) ]; then cd $(USR_DIR) && $(MAKE) $@; fi

install: 
	cd $(SCST_DIR) && $(MAKE) $@
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi
#	@if [ -d $(QLA_ISP_DIR) ]; then cd $(QLA_ISP_DIR) && $(MAKE) $@; fi
#	@if [ -d $(LSI_DIR) ]; then cd $(LSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(SRP_DIR) ]; then cd $(SRP_DIR) && $(MAKE) $@; fi
	@if [ -d $(ISCSI_DIR) ]; then cd $(ISCSI_DIR) && $(MAKE) DISTDIR=$(ISCSI_DISTDIR) $@; fi
	@if [ -d $(USR_DIR) ]; then cd $(USR_DIR) && $(MAKE) $@; fi

uninstall: 
	cd $(SCST_DIR) && $(MAKE) $@
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi
#	@if [ -d $(QLA_ISP_DIR) ]; then cd $(QLA_ISP_DIR) && $(MAKE) $@; fi
#	@if [ -d $(LSI_DIR) ]; then cd $(LSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(SRP_DIR) ]; then cd $(SRP_DIR) && $(MAKE) $@; fi
	@if [ -d $(ISCSI_DIR) ]; then cd $(ISCSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(USR_DIR) ]; then cd $(USR_DIR) && $(MAKE) $@; fi

clean: 
	cd $(SCST_DIR) && $(MAKE) $@
	@if [ -d $(QLA_INI_DIR) ]; then cd $(QLA_INI_DIR) && $(MAKE) $@; fi
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi
#	@if [ -d $(QLA_ISP_DIR) ]; then cd $(QLA_ISP_DIR) && $(MAKE) $@; fi
#	@if [ -d $(LSI_DIR) ]; then cd $(LSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(SRP_DIR) ]; then cd $(SRP_DIR) && $(MAKE) $@; fi
	@if [ -d $(ISCSI_DIR) ]; then cd $(ISCSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(USR_DIR) ]; then cd $(USR_DIR) && $(MAKE) $@; fi

extraclean: 
	cd $(SCST_DIR) && $(MAKE) $@
	@if [ -d $(QLA_INI_DIR) ]; then cd $(QLA_INI_DIR) && $(MAKE) $@; fi
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi
#	@if [ -d $(QLA_ISP_DIR) ]; then cd $(QLA_ISP_DIR) && $(MAKE) $@; fi
#	@if [ -d $(LSI_DIR) ]; then cd $(LSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(SRP_DIR) ]; then cd $(SRP_DIR) && $(MAKE) $@; fi
	@if [ -d $(ISCSI_DIR) ]; then cd $(ISCSI_DIR) && $(MAKE) $@; fi
	@if [ -d $(USR_DIR) ]; then cd $(USR_DIR) && $(MAKE) $@; fi

scst: 
	cd $(SCST_DIR) && $(MAKE)

scst_install: 
	cd $(SCST_DIR) && $(MAKE) install

scst_uninstall: 
	cd $(SCST_DIR) && $(MAKE) uninstall

scst_clean: 
	cd $(SCST_DIR) && $(MAKE) clean

scst_extraclean: 
	cd $(SCST_DIR) && $(MAKE) extraclean

scstadm_install: 
	cd $(SCSTADM_DIR) && $(MAKE) install

scstadm_uninstall: 
	cd $(SCSTADM_DIR) && $(MAKE) uninstall

qla:
	cd $(QLA_DIR) && $(MAKE)

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
	cd $(QLA_ISP_DIR) && $(MAKE)

qla_isp_install:
	cd $(QLA_ISP_DIR) && $(MAKE) install

qla_isp_uninstall:
	cd $(QLA_ISP_DIR) && $(MAKE) uninstall

qla_isp_clean:
	cd $(QLA_ISP_DIR) && $(MAKE) clean

qla_isp_extraclean:
	cd $(QLA_ISP_DIR) && $(MAKE) extraclean

iscsi:
	cd $(ISCSI_DIR) && $(MAKE)

iscsi_install:
	cd $(ISCSI_DIR) && $(MAKE) DISTDIR=$(ISCSI_DISTDIR) install

iscsi_uninstall:
	cd $(ISCSI_DIR) && $(MAKE) uninstall

iscsi_clean: 
	cd $(ISCSI_DIR) && $(MAKE) clean

iscsi_extraclean:
	cd $(ISCSI_DIR) && $(MAKE) extraclean

lsi:
	cd $(LSI_DIR) && $(MAKE)

lsi_install:
	cd $(LSI_DIR) && $(MAKE) install

lsi_uninstall:
	cd $(LSI_DIR) && $(MAKE) uninstall

lsi_clean: 
	cd $(LSI_DIR) && $(MAKE) clean

lsi_extraclean:
	cd $(LSI_DIR) && $(MAKE) extraclean

srpt:
	cd $(SRP_DIR) && $(MAKE)

srpt_install:
	cd $(SRP_DIR) && $(MAKE) install

srpt_uninstall:
	cd $(SRP_DIR) && $(MAKE) uninstall

srpt_clean: 
	cd $(SRP_DIR) && $(MAKE) clean

srpt_extraclean:
	cd $(SRP_DIR) && $(MAKE) extraclean

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

debug2perf:
	echo "Changing current debug state from full debug to full performance"
	patch -p0 <scst-full_perf.patch
	patch -p0 <usr-full_perf.patch
	patch -p0 <qla2x00t-full_perf.patch
	patch -p0 <iscsi-full_perf.patch
	patch -p0 <qla_isp-release.patch

debug2release:
	echo "Changing current debug state from full debug to release"
	patch -p0 <scst-release.patch
	patch -p0 <usr-release.patch
	patch -p0 <qla2x00t-release.patch
	patch -p0 <iscsi-release.patch
	patch -p0 <qla_isp-release.patch

perf2debug:
	echo "Changing current debug state from full performance to full debug"
	patch -p0 -R <scst-full_perf.patch
	patch -p0 -R <usr-full_perf.patch
	patch -p0 -R <qla2x00t-full_perf.patch
	patch -p0 -R <iscsi-full_perf.patch
	patch -p0 -R <qla_isp-release.patch

release2debug:
	echo "Changing current debug state from release to full debug"
	patch -p0 -R <scst-release.patch
	patch -p0 -R <usr-release.patch
	patch -p0 -R <qla2x00t-release.patch
	patch -p0 -R <iscsi-release.patch
	patch -p0 -R <qla_isp-release.patch

.PHONY: all install uninstall clean extraclean help \
	qla qla_install qla_uninstall qla_clean qla_extraclean \
	qla_isp qla_isp_install qla_isp_uninstall qla_isp_clean qla_isp_extraclean \
	lsi lsi_install lsi_uninstall lsi_clean lsi_extraclean \
	iscsi iscsi_install iscsi_uninstall iscsi_clean iscsi_extraclean \
	scst scst_install scst_uninstall scst_clean scst_extraclean \
	scstadm_install scstadm_uninstall \
	usr usr_install usr_uninstall usr_clean usr_extraclean \
	debug2perf, debug2release, perf2debug, release2debug
