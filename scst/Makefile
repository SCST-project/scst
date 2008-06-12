#
#  Common makefile for SCSI target mid-level and its drivers
#  
#  Copyright (C) 2004 - 2008 Vladislav Bolkhovitin <vst@vlnb.net>
#  Copyright (C) 2004 - 2005 Leonid Stoljar
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

SCST_DIR=src

all: 
	cd $(SCST_DIR) && $(MAKE) $@

install: 
	cd $(SCST_DIR) && $(MAKE) $@

uninstall: 
	cd $(SCST_DIR) && $(MAKE) $@

clean: 
	cd $(SCST_DIR) && $(MAKE) $@

extraclean: 
	cd $(SCST_DIR) && $(MAKE) $@

help:
	@echo "		all (the default) : make all"
	@echo "		clean             : clean files"
	@echo "		extraclean        : clean + clean dependencies"
	@echo "		install           : install"
	@echo "		uninstall         : uninstall"
	@echo "	Notes :"
	@echo "		- install and uninstall must be made as root."
	@echo "         - be sure to compile qla against the correct initiator"
	@echo "           driver. Read its README for details."

.PHONY: all install uninstall clean extraclean help
