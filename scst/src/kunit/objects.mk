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
	kunit/order/suites/scst_kunit_order.o \
	kunit/unmap/suites/scst_kunit_unmap.o
