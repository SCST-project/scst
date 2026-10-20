/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_MEM_TEST_H
#define SCST_MEM_TEST_H

#include "scst_test.h"

#ifdef SCST_KUNIT_ENABLED
struct sgv_pool;

struct sgv_pool *sgv_pool_get_shared(struct sgv_pool *pool);
#endif

#endif /* SCST_MEM_TEST_H */
