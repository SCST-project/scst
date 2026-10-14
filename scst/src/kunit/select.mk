# SPDX-License-Identifier: GPL-2.0-only
scst-kunit-root := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../../..)
include $(scst-kunit-root)/scst/src/kunit/modules.mk

PYTHON ?= python3

ifneq ($(filter kunit-build kunit-list kunit-run kunit-test,$(MAKECMDGOALS)),)
scst-kunit-obsolete := $(foreach var,TEST TEST_LOG KUNIT_LABELS KUNIT_MODULE KUNIT_MODULES \
	KUNIT_CONFIG KUNIT_TIMEOUT KUNIT_OUTPUT KUNIT_VERBOSE,\
	$(if $(filter undefined,$(origin $(var))),,$(var)))
ifneq ($(strip $(scst-kunit-obsolete)),)
$(error Use KUNIT_LABEL and KUNIT_ARGS; unsupported variables: $(scst-kunit-obsolete))
endif
ifneq ($(strip $(STRESS) $(PERF)),)
$(error SCST KUnit supports KUNIT_LABEL labels only; STRESS and PERF are not implemented)
endif
endif

# Public Makefile options map to the private switches passed to Kbuild.
ifneq ($(filter kunit-build kunit-test,$(MAKECMDGOALS)),)
ifneq ($(filter-out y,$(KUNIT_TEST) $(CONFIG_SCST_KUNIT_TEST)),)
$(error kunit-build requires KUNIT_TEST=y)
endif
KUNIT_TEST := y
endif
KUNIT_TEST ?= $(if $(CONFIG_SCST_KUNIT_TEST),$(CONFIG_SCST_KUNIT_TEST),n)
KUNIT_LOG ?= $(if $(CONFIG_SCST_KUNIT_LOG),$(CONFIG_SCST_KUNIT_LOG),n)

ifneq ($(filter-out y n,$(KUNIT_TEST)),)
$(error KUNIT_TEST must be y or n)
endif
ifneq ($(words $(KUNIT_TEST)),1)
$(error KUNIT_TEST must be y or n)
endif
ifneq ($(filter-out y n,$(KUNIT_LOG)),)
$(error KUNIT_LOG must be y or n)
endif
ifneq ($(words $(KUNIT_LOG)),1)
$(error KUNIT_LOG must be y or n)
endif
SCST_KUNIT_FLAGS := CONFIG_SCST_KUNIT_TEST=$(KUNIT_TEST) CONFIG_SCST_KUNIT_LOG=$(KUNIT_LOG)

# Labels belong to suites, not the build inventory.
KUNIT_LABEL ?= ALL
scst-kunit-source-dirs = $(sort $(addsuffix kunit,$(dir $(SCST_KUNIT_MODULES))))

.PHONY: kunit-list
kunit-list:
	@$(PYTHON) "$(scst-kunit-root)/scripts/kunit/inventory.py" \
		$(foreach dir,$(scst-kunit-source-dirs),"$(scst-kunit-root)/$(dir)") $(KUNIT_ARGS)

# A component clean invalidates the recorded build as well as a top-level clean.
.PHONY: scst-kunit-clean-files
clean extraclean: scst-kunit-clean-files
scst-kunit-clean-files:
	@rm -f "$(scst-kunit-root)/.kunit-modules" "$(scst-kunit-root)/.kunit-modules.tmp"
	@if [ -d "$(scst-kunit-root)/scripts/kunit" ]; then \
		find "$(scst-kunit-root)/scripts/kunit" -type d -name __pycache__ -prune \
			-exec rm -rf {} +; \
	fi
