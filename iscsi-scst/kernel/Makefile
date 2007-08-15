#
# Makefile for the Linux kernel device drivers.
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (not a .c file).
#
# Note 2! The CFLAGS definitions are now in the main makefile.

#SCST_INC_DIR := /usr/local/include/scst
SCST_INC_DIR := $(SUBDIRS)/../../scst/include

EXTRA_CFLAGS += -I$(src)/../include -I$(SCST_INC_DIR)
# -Wextra -Wno-unused-parameter

EXTRA_CFLAGS += -DEXTRACHECKS
#EXTRA_CFLAGS += -DTRACING
EXTRA_CFLAGS += -DDEBUG -g

#EXTRA_CFLAGS += -DDEBUG_DIGEST_FAILURES

obj-m		+= iscsi-scst.o
iscsi-scst-objs	:= iscsi.o nthread.o config.o digest.o \
	conn.o session.o target.o event.o param.o

