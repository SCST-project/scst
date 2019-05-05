#
#  Common makefile for SCSI target mid-level and its drivers
#
#  Copyright (C) 2015 - 2018 Vladislav Bolkhovitin <vst@vlnb.net>
#  Copyright (C) 2004 - 2005 Leonid Stoljar
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

SHELL=/bin/bash
# Decide to use which kernel src. If not specified, is current running kernel.
#export KDIR=/usr/src/linux-2.6

SCST_DIR=src

# Set variable $(2) to value $(3) in file $(1) if $(2)=$(3) does not yet occur
# in file $(1).
set_var = $(shell if grep -q '^$(2)=' '$(1)' 2>/dev/null; then	\
		    grep -q '^$(2)=$(3)$$' '$(1)' ||		\
		      sed -i 's/^$(2)=.*/$(2)=$(3)/' '$(1)';	\
		  else						\
		    echo '$(2)=$(3)' >> '$(1)';			\
		  fi)

all: include/build_mode.h
	cd $(SCST_DIR) && $(MAKE) $@

install: include/build_mode.h
	cd $(SCST_DIR) && $(MAKE) $@

uninstall:
	cd $(SCST_DIR) && $(MAKE) $@

clean:
	cd $(SCST_DIR) && $(MAKE) $@

extraclean:
	cd $(SCST_DIR) && $(MAKE) $@

2debug:
	$(call set_var,build_mode,BUILD_MODE,)

2release:
	$(call set_var,build_mode,BUILD_MODE,RELEASE)

2perf:
	$(call set_var,build_mode,BUILD_MODE,PERF)

release-archive:
	../scripts/generate-release-archive scst \
	  "$$(sed -n 's/^#define[[:blank:]]SCST_VERSION_NAME[[:blank:]]*\"\([^\"]*\)\".*/\1/p' include/scst_const.h)" \

build_mode:
	$(call set_var,build_mode,BUILD_MODE,)

include/build_mode.h: build_mode
	@rm -f $@.tmp;							\
	touch $@.tmp;							\
	source build_mode;						\
	case "$${BUILD_MODE}" in					\
	"")      defines="CONFIG_SCST_TRACING CONFIG_SCST_DEBUG		\
			  CONFIG_SCST_EXTRACHECKS";;			\
	RELEASE) defines=CONFIG_SCST_TRACING;;				\
	PERF)    defines="";;						\
	*)	 echo "Error: unsupported build mode $$(<build_mode)";	\
		 exit 1;;						\
	esac;								\
	echo "defines=$$defines";					\
	for d in $$defines; do						\
		echo "#define $$d" >>$@.tmp;				\
	done;								\
	if [ ! -e $@ ] || ! diff -q $@.tmp $@ >&/dev/null; then		\
		mv $@.tmp $@;						\
	else								\
		rm -f $@.tmp;						\
	fi

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

.PHONY: all install uninstall clean extraclean help 2release 2debug 2perf
