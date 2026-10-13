# SPDX-License-Identifier: GPL-2.0-only
# Included by the owning module's Kbuild; object paths are relative to it.
include $(dir $(lastword $(MAKEFILE_LIST)))objects.mk

ifneq ($(filter-out y n,$(CONFIG_SCST_KUNIT_TEST)),)
$(error CONFIG_SCST_KUNIT_TEST must be y or n)
endif
ifneq ($(word 2,$(CONFIG_SCST_KUNIT_TEST)),)
$(error CONFIG_SCST_KUNIT_TEST must be y or n)
endif

ifeq ($(CONFIG_SCST_KUNIT_TEST),y)
# Kbuild also reads this file while cleaning, without loading kernel config.
ifeq ($(filter %/Makefile.clean,$(MAKEFILE_LIST)),)
ifeq ($(filter y m,$(CONFIG_KUNIT)),)
$(error SCST KUnit support requires a kernel built with CONFIG_KUNIT=y or m)
endif
endif
ccflags-y += -DSCST_KUNIT_ENABLED
ccflags-y += -DSCST_KUNIT_LOG_ENABLED=$(if $(filter y,$(CONFIG_SCST_KUNIT_LOG)),1,0)
$(scst-kunit-module)-y += $(scst-kunit-$(scst-kunit-module))
endif
