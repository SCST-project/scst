SCST_INC_DIR := $(SUBDIRS)/../../scst/include/

EXTRA_CFLAGS +=  -I$(SCST_INC_DIR)
#EXTRA_CFLAGS += -DCONFIG_SCST_TRACING
#EXTRA_CFLAGS += -DCONFIG_SCST_DEBUG -g -fno-inline -fno-inline-functions
#EXTRA_CFLAGS += -DCONFIG_SCST_EXTRACHECKS
#EXTRA_CFLAGS += -Wextra -Wno-unused-parameter

obj-m		+= ib_srpt.o
