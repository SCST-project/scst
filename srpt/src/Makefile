SCST_INC_DIR := $(shell d="$(dir $(lastword $(MAKEFILE_LIST)))";	\
                  if [ -e "$$d../../scst" ];				\
                  then echo "$$d../../scst/include";			\
                  else echo "/usr/local/include/scst"; fi)
EXTRA_CFLAGS += -I$(SCST_INC_DIR)

-include $(SUBDIRS)/../build_mode

SRPTFLAGS = -DCONFIG_SCST_TRACING -DCONFIG_SCST_DEBUG \
	-DCONFIG_SCST_EXTRACHECKS -fno-inline -fno-inline-functions
SRPTFLAGSRELEASE = -DCONFIG_SCST_TRACING
SRPTFLAGSPERF =
EXTRA_CFLAGS += $(SRPTFLAGS$(BUILDMODE))

#EXTRA_CFLAGS += -Wextra -Wno-unused-parameter

obj-m		+= ib_srpt.o
