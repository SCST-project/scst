# SPDX-License-Identifier: GPL-2.0-only
# Test objects relative to each owning module; shared by both Kbuild modes.

scst-kunit-scst := \
	kunit/alua/suites/scst_kunit_alua.o \
	kunit/cdb/suites/scst_kunit_cdb.o \
	kunit/cm/suites/scst_kunit_cm.o \
	kunit/event/scst_event_fixture.o \
	kunit/event/suites/scst_kunit_event_import.o \
	kunit/event/suites/scst_kunit_event_delivery.o \
	kunit/lib/suites/scst_kunit_lib.o \
	kunit/lifecycle/suites/scst_kunit_lifecycle.o \
	kunit/lifecycle/suites/scst_kunit_blocking.o \
	kunit/order/suites/scst_kunit_order.o \
	kunit/tm/suites/scst_kunit_tm.o \
	kunit/unmap/suites/scst_kunit_unmap.o

scst-kunit-iscsi-scst := \
	kunit/suites/iscsi_tx_test.o

scst-kunit-scst_user := \
	kunit/user/suites/scst_user_cleanup_test.o

scst-kunit-scst_vdisk := \
	kunit/vdisk/scst_vdisk_fixture.o \
	kunit/vdisk/suites/scst_vdisk_capacity_test.o \
	kunit/vdisk/suites/scst_vdisk_io_test.o \
	kunit/vdisk/suites/scst_vdisk_protocol_test.o \
	kunit/vdisk/suites/scst_vdisk_sync_test.o \
	kunit/vdisk/suites/scst_vdisk_sysfs_test.o
