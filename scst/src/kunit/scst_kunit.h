/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_KUNIT_H
#define SCST_KUNIT_H

#include <kunit/test.h>
#include <kunit/static_stub.h>

/* One declaration supplies the native suite name and the runner's label metadata. */
#define scst_kunit_suite(suite, label, suffix, ...) \
	static struct kunit_suite suite = { \
		.name = "scst-" label suffix, \
		__VA_ARGS__ \
	}; \
	kunit_test_suite(suite); \
	MODULE_INFO(scst_kunit_suite, label ":scst-" label suffix)

/* Optional execution messages; assertion and retained-fixture errors are unconditional. */
#define scst_kunit_log(test, fmt, ...) \
	do { \
		if (SCST_KUNIT_LOG_ENABLED) \
			kunit_info(test, fmt, ##__VA_ARGS__); \
	} while (0)

/* Runner contract: unfinished work owns retained memory and a module reference. */
static inline void scst_kunit_retain(struct kunit *test, const char *reason)
{
	KUNIT_FAIL(test, "SCST_KUNIT_RETAINED: %s", reason);
}

#endif /* SCST_KUNIT_H */
