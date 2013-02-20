#
#  Common makefile for SCSI target mid-level and its drivers
#  
#  Copyright (C) 2004 - 2013 Vladislav Bolkhovitin <vst@vlnb.net>
#  Copyright (C) 2004 - 2005 Leonid Stoljar
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

SHELL=/bin/bash
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

2release:
	cd $(SCST_DIR) && $(MAKE) $@

2debug:
	cd $(SCST_DIR) && $(MAKE) $@

2perf:
	cd $(SCST_DIR) && $(MAKE) $@

disable_proc:
	cd $(SCST_DIR) && $(MAKE) $@

enable_proc:
	cd $(SCST_DIR) && $(MAKE) $@

release-archive:
	../scripts/generate-release-archive scst "$$(sed -n 's/^#define[[:blank:]]SCST_VERSION_NAME[[:blank:]]*\"\([^\"]*\)\".*/\1/p' include/scst_const.h)"

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

.PHONY: all install uninstall clean extraclean help 2release 2debug 2perf disable_proc enable_proc
