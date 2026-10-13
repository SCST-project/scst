# SPDX-License-Identifier: GPL-2.0-only
# Build components in dependency order and record their test modules.
SCST_KUNIT_COMPONENTS := scst

SCST_KUNIT_MODULES_scst := \
	scst/src/scst.ko \
	scst/src/dev_handlers/scst_vdisk.ko

SCST_KUNIT_MODULES = $(foreach component,$(SCST_KUNIT_COMPONENTS),$(SCST_KUNIT_MODULES_$(component)))
