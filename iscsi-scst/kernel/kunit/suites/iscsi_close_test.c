// SPDX-License-Identifier: GPL-2.0-only
#include <linux/jiffies.h>
#ifdef INSIDE_KERNEL_TREE
#include "../../../kunit/scst_kunit.h"
#else
#include "../../../../scst/src/kunit/scst_kunit.h"
#endif
#include "../../iscsi_trace_flag.h"
#include "../../iscsi.h"
#include "../../nthread_test.h"

static void iscsi_shutdown_grace_period(struct kunit *test)
{
	static const unsigned long starts[] = { 10000UL * HZ, ULONG_MAX - 5UL * HZ };
	unsigned int i, deleting;

	for (i = 0; i < ARRAY_SIZE(starts); i++) {
		for (deleting = 0; deleting <= 1; deleting++) {
			unsigned long grace = deleting ? 10UL * HZ : 125UL * HZ;
			unsigned long started = starts[i];
			bool expired;

			/* A close starts a relative deadline, independent of uptime. */
			expired = iscsi_shutdown_timed_out(deleting, started, started);
			KUNIT_EXPECT_FALSE(test, expired);
			expired = iscsi_shutdown_timed_out(deleting, started, started + grace - 1);
			KUNIT_EXPECT_FALSE(test, expired);
			expired = iscsi_shutdown_timed_out(deleting, started, started + grace);
			KUNIT_EXPECT_FALSE(test, expired);
			expired = iscsi_shutdown_timed_out(deleting, started, started + grace + 1);
			KUNIT_EXPECT_TRUE(test, expired);
		}
	}
}

static struct kunit_case iscsi_close_cases[] = {
	KUNIT_CASE(iscsi_shutdown_grace_period),
	{}
};

scst_kunit_suite(iscsi_close_suite, "ISCSI", "-close",
		 .test_cases = iscsi_close_cases,
);
