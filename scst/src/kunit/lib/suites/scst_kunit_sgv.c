// SPDX-License-Identifier: GPL-2.0-only
#include "../../scst_kunit.h"
#include <linux/mm.h>
#include <linux/sched.h>
#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "../../../scst_mem.h"
#include "../../../scst_mem_test.h"

static void sgv_shared_rejects_other_mm(struct kunit *test)
{
	struct sgv_pool *pool = kunit_kzalloc(test, sizeof(*pool), GFP_KERNEL);
	struct mm_struct *other_mm = kunit_kzalloc(test, sizeof(*other_mm), GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, pool);
	KUNIT_ASSERT_NOT_NULL(test, other_mm);
	pool->owner_mm = other_mm;
	kref_init(&pool->sgv_pool_ref);

	/* A failed lookup must not return the original owner's reference. */
	KUNIT_EXPECT_PTR_EQ(test, sgv_pool_get_shared(pool), NULL);
	KUNIT_EXPECT_EQ(test, kref_read(&pool->sgv_pool_ref), 1);
}

static void sgv_shared_gets_same_mm(struct kunit *test)
{
	struct sgv_pool *pool = kunit_kzalloc(test, sizeof(*pool), GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, pool);
	pool->owner_mm = current->mm;
	kref_init(&pool->sgv_pool_ref);

	KUNIT_EXPECT_PTR_EQ(test, sgv_pool_get_shared(pool), pool);
	KUNIT_EXPECT_EQ(test, kref_read(&pool->sgv_pool_ref), 2);
}

/*
 * The registered callback retains the mutable parameter type required by its
 * interface.
 */
/* cppcheck-suppress constParameterCallback symbolName=ref */
static void sgv_defer_release(struct kref *ref)
{
	/* Keep the fixture alive to model a destructor waiting to unlink it. */
}

static void sgv_shared_rejects_destroying_pool(struct kunit *test)
{
	struct sgv_pool *pool = kunit_kzalloc(test, sizeof(*pool), GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, pool);
	pool->owner_mm = current->mm;
	/* Last put has reached zero; the destructor has not unlinked it yet. */
	kref_init(&pool->sgv_pool_ref);
	kref_put(&pool->sgv_pool_ref, sgv_defer_release);

	KUNIT_EXPECT_PTR_EQ(test, sgv_pool_get_shared(pool), NULL);
	KUNIT_EXPECT_EQ(test, kref_read(&pool->sgv_pool_ref), 0);
}

static struct kunit_case scst_sgv_cases[] = {
	KUNIT_CASE(sgv_shared_rejects_other_mm),
	KUNIT_CASE(sgv_shared_gets_same_mm),
	KUNIT_CASE(sgv_shared_rejects_destroying_pool),
	{}
};

scst_kunit_suite(scst_sgv_suite, "LIB", "-sgv",
		 .test_cases = scst_sgv_cases,
);
