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

all:	links
	@$(MAKE) -C ${LINUX} M=${CURDIR}/build

tgt:	links
	@$(MAKE) -C ${LINUX} M=${CURDIR}/build ISP_TARGET_MODE=1

clean:
	@$(MAKE) -C ${LINUX} M=${CURDIR}/build clean
	@$(MAKE) -C build clean_links
	@$(RM) tags

install:
	@$(MAKE) -C ${LINUX} M=${CURDIR}/build modules_install

install_host_progs:
	@$(MAKE) -C build $@

links:
	@$(MAKE) -C build make_links

tools:
	cd ../linux && $(MAKE) tools

tags:	FRC
	@ctags --recurse --append=no --exclude=linux-2.6 --exclude=Makefile --exclude=freebsd --exclude=solaris ../

FRC:

