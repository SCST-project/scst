#
#  Common makefile for SCSI target mid-level and its drivers
#  
#  Copyright (C) 2006 Vladislav Bolkhovitin <vst@vlnb.net>
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
QLA_INI_DIR=qla2x00t
QLA_DIR=qla2x00t/qla2x00-target

all:
	cd $(SCST_DIR) && $(MAKE) $@
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi

install: 
	cd $(SCST_DIR) && $(MAKE) $@
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi

uninstall: 
	cd $(SCST_DIR) && $(MAKE) $@
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi

clean: 
	cd $(SCST_DIR) && $(MAKE) $@
	@if [ -d $(QLA_INI_DIR) ]; then cd $(QLA_INI_DIR) && $(MAKE) $@; fi
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi

extraclean: 
	cd $(SCST_DIR) && $(MAKE) $@
	@if [ -d $(QLA_INI_DIR) ]; then cd $(QLA_INI_DIR) && $(MAKE) $@; fi
	@if [ -d $(QLA_DIR) ]; then cd $(QLA_DIR) && $(MAKE) $@; fi

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

help:
	@echo "		all (the default) : make all"
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
	@echo "		qla             : make new qla target using 2.6.x kernel qla2xxx"
	@echo "		qla_clean       : 2.6 qla target: clean "
	@echo "		qla_extraclean  : 2.6 qla target: clean + clean dependencies"
	@echo "		qla_install     : 2.6 qla target: install"
	@echo "		qla_uninstall   : 2.6 qla target: uninstall"
	@echo "	Notes :"
	@echo "		- install and uninstall must be made as root"

.PHONY: all install uninstall clean extraclean help \
	qla qla_install qla_uninstall qla_clean qla_extraclean \
	scst scst_install scst_uninstall scst_clean scst_extraclean
