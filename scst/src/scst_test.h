/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_TEST_H
#define SCST_TEST_H

#ifdef SCST_KUNIT_ENABLED
#include <kunit/static_stub.h>
#include <kunit/visibility.h>

#define SCST_KUNIT_VISIBLE VISIBLE_IF_KUNIT
#define SCST_KUNIT_VISIBLE_INLINE VISIBLE_IF_KUNIT
#define SCST_KUNIT_REDIRECT(fn, ...) KUNIT_STATIC_STUB_REDIRECT(fn, ##__VA_ARGS__)
#else
#define SCST_KUNIT_VISIBLE static
#define SCST_KUNIT_VISIBLE_INLINE static inline
#define SCST_KUNIT_REDIRECT(...) do { } while (0)
#endif

#endif /* SCST_TEST_H */
