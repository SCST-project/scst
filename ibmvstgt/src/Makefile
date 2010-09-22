EXTRA_CFLAGS += -I$(SUBDIRS)/../../scst/include
EXTRA_CFLAGS += -DCONFIG_SCST_TRACING
EXTRA_CFLAGS += -DCONFIG_SCST_DEBUG
#EXTRA_CFLAGS += -g -fno-inline -fno-inline-functions
EXTRA_CFLAGS += -DCONFIG_SCST_EXTRACHECKS
#EXTRA_CFLAGS += -Wextra -Wno-unused-parameter

obj-m		+= ibmvstgt.o
obj-m		+= libsrpnew.o

scsi_tgt-y	+= scsi_tgt_lib.o scsi_tgt_if.o
