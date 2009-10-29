SCST_INC_DIR := $(SUBDIRS)/../../scst/include/

EXTRA_CFLAGS +=  -I$(SCST_INC_DIR)
#EXTRA_CFLAGS += -DCONFIG_SCST_TRACING
#EXTRA_CFLAGS += -DCONFIG_SCST_DEBUG -g
#EXTRA_CFLAGS += -Wextra -Wno-unused-parameter
#EXTRA_CFLAGS += -fno-inline -fno-inline-functions

obj-m		+= ib_srpt.o
