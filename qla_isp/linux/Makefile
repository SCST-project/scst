# $Id: Makefile,v 1.27 2006/12/18 18:24:00 mjacob Exp $
#
# Qlogic ISP Host Adapter Build File
#
#  Copyright (c) 1997-2006 by Matthew Jacob
#  All rights reserved.
# 
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
# 
#   1. Redistributions of source code must retain the above copyright
#      notice, this list of conditions, and the following disclaimer,
#      without modification, immediately at the beginning of the file.
#   2. The name of the author may not be used to endorse or promote products
#      derived from this software without specific prior written permission.
# 
#   THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
#   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#   ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
#   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
#   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#   SUCH DAMAGE.
# 
#  Alternatively, this software may be distributed under the terms of the
#  the GNU Public License ("GPL") with platforms where the prevalant license
#  is the GNU Public License:
# 
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
# 
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#  
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
# 
# 
#  Matthew Jacob
# 
#  isplicense at feral com
#
#
LVERS	=	$(shell uname -r)
LINUX	?=	/lib/modules/${LVERS}/build
SERNO	=	$(shell hostid)
_SLIST	=	s/i.86/i386/ -e s/sun4u/sparc64/ -e s/sun4d/sparc/ \
		-e s/sun4m/sparc/ -e s/sun4c/sparc/ -e s/arm.*/arm/ \
		-e s/sa110/arm/
ARCH	:=	$(shell uname -m | sed -e $(_SLIST))
CC	=	cc
XFLAGS	=
MODV	=	-DMODVERSIONS
MODF	=	-DMODULE ${MODV}
DEFS	=	-D__KERNEL__ $(TMODE) $(MODF) ${XFLAGS} -DSERNO=\"$(SERNO)\"
KMOD	=	isp_mod.o
include	Makefile.${ARCH}
IFLAGS	=	-I. -I../common -I../firmware -I${LINUX}/drivers/scsi \
		-I${LINUX}/include
GKCFLAGS+=	$(DEFS) $(IFLAGS) -Werror -Wall -Wstrict-prototypes ${KCFLAGS}
COMD	=	../common
ALLSRC	=	isp_pci.c isp_linux.c isp_cb_ops.c \
		${COMD}/isp.c ${COMD}/isp_target.c ${COMD}/isp_library.c
COM_HDRS=	${COMD}/ispmbox.h ${COMD}/ispvar.h ${COMD}/ispreg.h \
		${COMD}/isp_library.h ${COMD}/isp_target.h \
		${COMD}/isp_tpublic.h ${COMD}/isp_stds.h
KOBJ	=	isp_pci.o isp_linux.o isp.o isp_cb_ops.o isp_target.o isp_library.o
TOOLS	=	isp_clrstats isp_debug isp_getrole isp_getstats isp_rescan \
		isp_lip isp_setrole isp_getpdb isp_gethba isp_struct
CFLAGS	=	-O -I. -I../common
LOC_HDRS=	isp_linux.h
ALL_HDRS=	${LOC_HDRS} ${COM_HDRS}

VPATH	=	. ../tools


all:	$(KMOD)

isp_mod.o: ${KOBJ}
	$(LD) -r -o $@ ${KOBJ}

isp_pci.o:	./isp_pci.c $(COM_HDRS) $(LOC_HDRS)
	$(CC) $(GKCFLAGS) -c -o isp_pci.o ./isp_pci.c

isp.o:	${COMD}/isp.c $(COM_HDRS) $(LOC_HDRS)
	$(CC) $(GKCFLAGS) -c -o $@ ${COMD}/isp.c

isp_target.o:	${COMD}/isp_target.c ${COMD}/isp_target.h $(ALL_HDRS)
	$(CC) $(GKCFLAGS) -c -o $@ ${COMD}/isp_target.c

isp_library.o:	${COMD}/isp_library.c ${COMD}/isp_library.h $(ALL_HDRS)
	$(CC) $(GKCFLAGS) -c -o $@ ${COMD}/isp_library.c


isp_linux.o:	isp_linux.c $(COM_HDRS) $(LOC_HDRS)
	$(CC) $(GKCFLAGS) -c -o $@ ./isp_linux.c

isp_cb_ops.o:	isp_cb_ops.c $(COM_HDRS) $(LOC_HDRS)
	$(CC) $(GKCFLAGS) -c -o $@ ./isp_cb_ops.c


scsi_tgt.o: scsi_target.c scsi_target.h ${ALL_HDRS}
	$(CC) $(GKCFLAGS) -c -o scsi_target.o scsi_target.c
	$(LD) -r -o $@ scsi_target.o

alltgt:
	$(MAKE) TMODE='-DISP_TARGET_MODE=1 -DISP_DEFAULT_ROLES=ISP_ROLE_NONE ' all

scsi_target_ctl:	scsi_target_ctl.o scsi_target.h
	$(CC) -o $@ scsi_target_ctl.c

tgt	:=	KMOD	+=	scsi_tgt.o
tgt:	scsi_target_ctl scsi_tgt.o alltgt

tools	:=	CFLAGS += -O -I.
tools:	${TOOLS}


tags:	FRC
	ctags *.[ch] ../common/*.[ch]

etags:	FRC
	etags --declarations --members *.[ch] ../common/*.[ch]

clean:
	@touch x.o
	$(RM) *.o scsi_target_ctl ${TOOLS}

clobber:	clean
	${RM} tags TAGS

FRC:

