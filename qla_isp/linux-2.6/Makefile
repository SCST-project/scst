# $Id: Makefile,v 1.11 2008/03/15 18:17:51 mjacob Exp $
#
# Makefile
#
# Copyright (c) 2006-2008 by Matthew Jacob
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of The Version 2 GNU General Public License as published
#  by the Free Software Foundation.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
#
# Matthew Jacob
# Feral Software
# 421 Laurel Avenue
# Menlo Park, CA 94025
# USA
#
# gpl at feral com
#
ifndef KDIR
LVERS	=	$(shell uname -r)
LINUX	?=	/lib/modules/${LVERS}/build
else
LINUX = ${KDIR}
endif

M			?=	$(CURDIR)
TDIR			=	$(M)/../
SCST_INC		=	${TDIR}/../scst/include
SCST_DIR		=	${TDIR}/../scst/src

all:	links
	@$(MAKE) -C ${LINUX} M=${CURDIR}/build

tgt:	links Modules.symvers Module.symvers
	@$(MAKE) -C ${LINUX} M=${CURDIR}/build SCST_INC=$(SCST_INC) ISP_TARGET_MODE=1

clean:
	@$(MAKE) -C ${LINUX} M=${CURDIR}/build clean
	@$(MAKE) -C build clean_links
	@$(RM) tags Modules.symvers Module.symvers

extraclean: clean
	rm -f *.orig *.rej

install:
	@$(MAKE) -C ${LINUX} M=${CURDIR}/build modules_install

install_host_progs:
	@$(MAKE) -C build $@

links:
	@$(MAKE) -C build make_links

tools:
	cd ../linux && $(MAKE) tools

tags:	FRC
	@ctags --recurse --append=no ../linux ../common ../../scst

FRC:

SCST_MOD_VERS := $(shell ls $(SCST_DIR)/Modules.symvers 2>/dev/null)
ifneq ($(SCST_MOD_VERS),)
Modules.symvers: $(SCST_DIR)/Modules.symvers
	cp $(SCST_DIR)/Modules.symvers ${CURDIR}/build
else
.PHONY: Modules.symvers
endif

# It's renamed in 2.6.18
SCST_MOD_VERS := $(shell ls $(SCST_DIR)/Module.symvers 2>/dev/null)
ifneq ($(SCST_MOD_VERS),)
Module.symvers: $(SCST_DIR)/Module.symvers
	cp $(SCST_DIR)/Module.symvers ${CURDIR}/build
else
.PHONY: Module.symvers
endif

KVER := $(shell cat ${LINUX}/.kernelrelease 2> /dev/null )
ifeq ($(KVER),)
KVER := $(shell cat ${LINUX}/include/config/kernel.release 2> /dev/null )
endif

uninstall:
	rm -f /lib/modules/${KVER}/extra/isp_mod.ko
	rm -f /lib/modules/${KVER}/extra/isp_scst.ko
	-/sbin/depmod -a ${KVER}


