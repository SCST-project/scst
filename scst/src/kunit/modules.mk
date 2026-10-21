# SPDX-License-Identifier: GPL-2.0-only
# Build components in dependency order and record their test modules.
SCST_KUNIT_COMPONENTS := scst iscsi-scst qla2x00t-32gbit/qla2x00-target

SCST_KUNIT_MODULES_scst := \
	scst/src/scst.ko \
	scst/src/dev_handlers/scst_vdisk.ko \
	scst/src/dev_handlers/scst_user.ko

SCST_KUNIT_MODULES_iscsi-scst := \
	iscsi-scst/kernel/iscsi-scst.ko \
	iscsi-scst/kernel/isert-scst/isert-scst.ko

SCST_KUNIT_MODULES_qla2x00t-32gbit/qla2x00-target := \
	qla2x00t-32gbit/qla2xxx_scst.ko \
	qla2x00t-32gbit/qla2x00-target/qla2x00tgt.ko

SCST_KUNIT_MODULES = $(foreach component,$(SCST_KUNIT_COMPONENTS),$(SCST_KUNIT_MODULES_$(component)))
