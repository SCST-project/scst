# SPDX-License-Identifier: GPL-2.0-only
scst-kunit-root := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../../..)
include $(scst-kunit-root)/scst/src/kunit/modules.mk

PYTHON ?= python3

ifneq ($(origin CONFIG_SCST_KUNIT_TEST),undefined)
ifneq ($(filter-out y n,$(CONFIG_SCST_KUNIT_TEST)),)
$(error CONFIG_SCST_KUNIT_TEST must be y or n)
endif
ifneq ($(words $(CONFIG_SCST_KUNIT_TEST)),1)
$(error CONFIG_SCST_KUNIT_TEST must be y or n)
endif
SCST_KUNIT_FLAGS := CONFIG_SCST_KUNIT_TEST=$(CONFIG_SCST_KUNIT_TEST)
endif

# Labels belong to suites, not the build inventory.
KUNIT_LABEL ?= ALL
scst-kunit-source-dirs = $(sort $(addsuffix kunit,$(dir $(SCST_KUNIT_MODULES))))

.PHONY: kunit-list
kunit-list:
	@$(PYTHON) "$(scst-kunit-root)/scripts/kunit/inventory.py" --labels "$(KUNIT_LABEL)" \
		$(foreach dir,$(scst-kunit-source-dirs),"$(scst-kunit-root)/$(dir)")
