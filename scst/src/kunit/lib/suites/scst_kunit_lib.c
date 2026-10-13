// SPDX-License-Identifier: GPL-2.0-only
#include "../../scst_kunit.h"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif

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
	KUNIT_CASE(scst_lun_flat_encoding),
	{}
};

scst_kunit_suite(scst_lib_suite, "LIB", "",
		 .test_cases = scst_lib_cases,
);
