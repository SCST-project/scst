#
#  Common makefile for SCSI target mid-level and its drivers
#
#  Copyright (C) 2015 - 2017 Vladislav Bolkhovitin <vst@vlnb.net>
#  Copyright (C) 2004 - 2005 Leonid Stoljar
#  Copyright (C) 2007 - 2017 SanDisk Corporation
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

FILEIO_DIR=fileio
STPGD_DIR=stpgd
EVENTS_DIR=events

all:
	cd $(FILEIO_DIR) && $(MAKE) $@
	cd $(STPGD_DIR) && $(MAKE) $@
#	cd $(EVENTS_DIR) && $(MAKE) $@

install:
	cd $(FILEIO_DIR) && $(MAKE) $@
	cd $(STPGD_DIR) && $(MAKE) $@
#	cd $(EVENTS_DIR) && $(MAKE) $@

uninstall:
	cd $(FILEIO_DIR) && $(MAKE) $@
	cd $(STPGD_DIR) && $(MAKE) $@
	cd $(EVENTS_DIR) && $(MAKE) $@

clean:
	cd $(FILEIO_DIR) && $(MAKE) $@
	cd $(STPGD_DIR) && $(MAKE) $@
	cd $(EVENTS_DIR) && $(MAKE) $@

extraclean:
	cd $(FILEIO_DIR) && $(MAKE) $@
	cd $(STPGD_DIR) && $(MAKE) $@
	cd $(EVENTS_DIR) && $(MAKE) $@

2release:
	cd $(FILEIO_DIR) && $(MAKE) $@
	cd $(STPGD_DIR) && $(MAKE) $@
	cd $(EVENTS_DIR) && $(MAKE) $@

2debug:
	cd $(FILEIO_DIR) && $(MAKE) $@
	cd $(STPGD_DIR) && $(MAKE) $@
	cd $(EVENTS_DIR) && $(MAKE) $@

2perf:
	cd $(FILEIO_DIR) && $(MAKE) $@
	cd $(STPGD_DIR) && $(MAKE) $@
	cd $(EVENTS_DIR) && $(MAKE) $@

disable_proc:
	cd $(FILEIO_DIR) && $(MAKE) $@
	cd $(STPGD_DIR) && $(MAKE) $@
	cd $(EVENTS_DIR) && $(MAKE) $@

enable_proc:
	cd $(FILEIO_DIR) && $(MAKE) $@
	cd $(STPGD_DIR) && $(MAKE) $@
	cd $(EVENTS_DIR) && $(MAKE) $@

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
