# $Id: Makefile,v 1.13 2007/03/10 02:27:53 mjacob Exp $
#
# Copyright (c) 2006-2007 by Matthew Jacob
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

M			?=	$(CURDIR)
TDIR			=	$(M)/../../
COM_OBJ 		=	isp.o isp_library.o isp_target.o
LNX_OBJ 		=	isp_cb_ops.o isp_linux.o isp_pci.o
COM_DIR			=	${TDIR}/common
LNX_DIR			=	${TDIR}/linux

STG_SRC			=	isp_scst.c

#EXTRA_CFLAGS		+=	-Wall -Werror -Idrivers/scsi -I${COM_DIR} -I${LNX_DIR} -I${TDIR}/firmware -I${SCST_INC}
EXTRA_CFLAGS		+=	-Wall -Idrivers/scsi -I${COM_DIR} -I${LNX_DIR} -I${TDIR}/firmware -I${SCST_INC}

clean-files		:=	*.o scsi_target_ctl Module.symvers

ifdef ISP_TARGET_MODE

EXTRA_CFLAGS		+=	-DISP_TARGET_MODE=1 -DISP_DEFAULT_ROLES=ISP_ROLE_NONE

obj-m			:=	isp_mod.o isp_scst.o

else

obj-m			:=	isp_mod.o

endif

isp_mod-objs		:=	${COM_OBJ} ${LNX_OBJ}

clean_links:
	@${RM} $(COM_OBJ:.o=.c) $(LNX_OBJ:.o=.c) ${STG_SRC}

make_links: clean_links
	@for j in ${COM_OBJ:.o=.c}; do ln -s ${COM_DIR}/$$j;  done
	@for j in ${LNX_OBJ:.o=.c}; do ln -s ${LNX_DIR}/$$j;  done
	@for j in ${STG_SRC}; do ln -s ${LNX_DIR}/$$j;  done
