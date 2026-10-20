// SPDX-License-Identifier: GPL-2.0-only
#include "../../scst_kunit.h"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif

#include "../../../scst_lib_test.h"

struct scst_port_id_fixture {
	unsigned int free_id;
	unsigned int probes;
	bool invalid_id;
};

static bool scst_port_id_available(u16 id, const struct scst_tgt *t)
{
	struct kunit *test = kunit_get_current_test();
	struct scst_port_id_fixture *fixture = test->priv;

	fixture->probes++;
	fixture->invalid_id |= id < SCST_MIN_REL_TGT_ID;
	return id == fixture->free_id;
}

static void scst_port_id_boundaries(struct kunit *test)
{
	static const struct {
		unsigned int start;
		unsigned int free_id;
		unsigned int next;
		unsigned int probes;
		int status;
	} cases[] = {
		{ 1, 1, 2, 1, 0 },
		{ 1, 3, 4, 3, 0 },
		{ SCST_MAX_REL_TGT_ID, SCST_MAX_REL_TGT_ID, 1, 1, 0 },
		{ SCST_MAX_REL_TGT_ID, 1, 2, 2, 0 },
		{ 42, 0, 42, SCST_MAX_REL_TGT_ID, -EOVERFLOW },
	};
	struct scst_port_id_fixture fixture;
	unsigned int i;

	test->priv = &fixture;
	kunit_activate_static_stub(test, __scst_is_relative_target_port_id_unique,
				   scst_port_id_available);
	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		unsigned int next = cases[i].start;
		u16 id = 123;
		u16 expected_id = cases[i].free_id;

		if (cases[i].status)
			expected_id = id;

		memset(&fixture, 0, sizeof(fixture));
		fixture.free_id = cases[i].free_id;
		KUNIT_EXPECT_EQ(test, scst_alloc_relative_target_port_id(&id, &next),
				cases[i].status);
		KUNIT_EXPECT_EQ(test, next, cases[i].next);
		KUNIT_EXPECT_EQ(test, id, expected_id);
		KUNIT_EXPECT_EQ(test, fixture.probes, cases[i].probes);
		KUNIT_EXPECT_FALSE(test, fixture.invalid_id);
	}
	kunit_deactivate_static_stub(test, __scst_is_relative_target_port_id_unique);
	test->priv = NULL;
}

static void scst_lun_flat_encoding(struct kunit *test)
{
	/* Flat addressing: 01 in the top bits, followed by the 14-bit LUN. */
	__be64 wire_lun = cpu_to_be64(0x5234000000000000ULL);
	__be64 packed = scst_pack_lun(0x1234, SCST_LUN_ADDR_METHOD_FLAT);

	scst_kunit_log(test, "LUN 0x1234 encoded as 0x%016llx", be64_to_cpu(packed));
	KUNIT_EXPECT_EQ(test, be64_to_cpu(packed), 0x5234000000000000ULL);
	KUNIT_EXPECT_EQ(test, scst_unpack_lun((const u8 *)&wire_lun, sizeof(wire_lun)),
			(u64)0x1234);
}

static struct kunit_case scst_lib_cases[] = {
	KUNIT_CASE(scst_port_id_boundaries),
	KUNIT_CASE(scst_lun_flat_encoding),
	{}
};

scst_kunit_suite(scst_lib_suite, "LIB", "",
		 .test_cases = scst_lib_cases,
);
