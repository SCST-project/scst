LINUXINCLUDE := $(PRE_CFLAGS) $(LINUXINCLUDE)
CPPFLAGS     := $(PRE_CFLAGS) $(CPPFLAGS)
ccflags-y    += -I$(KBUILD_EXTMOD)/../../scst/include

ifneq ($(and $(KBUILD_EXTMOD),$(if $(findstring $(abspath $(srctree)),$(abspath $(KBUILD_EXTMOD))),,true)),)
-include $(KBUILD_EXTMOD)/../../build_mode

echo := $(shell echo "srpt build mode: $(BUILD_MODE)" >& 2)

BUILD_MODE_CFLAGS_ = -DCONFIG_SCST_TRACING -DCONFIG_SCST_DEBUG \
	-DCONFIG_SCST_EXTRACHECKS -fno-inline -fno-inline-functions
BUILD_MODE_CFLAGS_RELEASE = -DCONFIG_SCST_TRACING
BUILD_MODE_CFLAGS_PERF =
ccflags-y += $(BUILD_MODE_CFLAGS_$(BUILD_MODE))
endif

#ccflags-y += -Wextra -Wno-unused-parameter

obj-m		+= ib_srpt.o
