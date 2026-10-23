// SPDX-License-Identifier: GPL-2.0-only
#include "../../../../scst/src/kunit/scst_kunit.h"
#include "scst.h"
#include "../../scst_qla2xxx.h"
#include "../../scst_qla2xxx_test.h"

struct qla_pool_fixture {
	struct scst_tgt target;
	struct scst_tgt_template tmplate;
	struct sqa_scst_tgt *allocated;
	unsigned long *bitmap;
	unsigned int maps_freed;
	unsigned int pools_freed;
	unsigned int registrations;
	bool fail_registration;
};

static void qla_pool_free_map(const void *map)
{
	struct kunit *test = kunit_get_current_test();
	struct qla_pool_fixture *f = test->priv;

	f->maps_freed++;
	KUNIT_EXPECT_NOT_NULL(test, map);
	kunit_deactivate_static_stub(test, sqa_free_cmd_map);
	sqa_free_cmd_map(map);
}

static void qla_pool_destroy(struct sqa_scst_tgt *sqa_tgt)
{
	struct kunit *test = kunit_get_current_test();
	struct qla_pool_fixture *f = test->priv;

	f->pools_freed++;
	kunit_deactivate_static_stub(test, sqa_destroy_tag_pool);
	sqa_destroy_tag_pool(sqa_tgt);
}

static struct scst_tgt *qla_pool_register(struct scst_tgt_template *tmplate,
					  const char *name)
{
	struct kunit *test = kunit_get_current_test();
	struct qla_pool_fixture *f = test->priv;

	f->registrations++;
	KUNIT_EXPECT_PTR_EQ(test, tmplate, &f->tmplate);
	KUNIT_EXPECT_STREQ(test, name, "qla-pool-test");
	return f->fail_registration ? NULL : &f->target;
}

static void *qla_pool_no_map(unsigned int tag_num, size_t tag_size)
{
	return NULL;
}

static int qla_pool_no_tags(struct sqa_scst_tgt *sqa_tgt, unsigned int tag_num)
{
	return -ENOMEM;
}

static int qla_pool_init(struct kunit *test)
{
	struct qla_pool_fixture *f;

	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;
	test->priv = f;
	kunit_activate_static_stub(test, sqa_free_cmd_map, qla_pool_free_map);
	kunit_activate_static_stub(test, sqa_destroy_tag_pool, qla_pool_destroy);
	kunit_activate_static_stub(test, sqa_register_target, qla_pool_register);
	return 0;
}

static void qla_pool_exit(struct kunit *test)
{
	struct qla_pool_fixture *f = test->priv;

	if (f->allocated)
		sqa_free_tgt(f->allocated);
	kfree(f->bitmap);
}

enum qla_pool_failure {
	QLA_POOL_SUCCESS,
	QLA_POOL_NO_MAP,
	QLA_POOL_NO_TAGS,
	QLA_POOL_NO_TARGET,
};

struct qla_pool_case {
	const char *name;
	enum qla_pool_failure failure;
	unsigned int maps_freed;
	unsigned int pools_freed;
	unsigned int registrations;
};

static const struct qla_pool_case qla_pool_cases[] = {
	{ "normal_release", QLA_POOL_SUCCESS, 1, 1, 1 },
	{ "map_allocation_failure", QLA_POOL_NO_MAP, 0, 0, 0 },
	{ "tag_pool_initialization_failure", QLA_POOL_NO_TAGS, 1, 0, 0 },
	{ "target_registration_failure", QLA_POOL_NO_TARGET, 1, 1, 1 },
};

static void qla_pool_desc(const struct qla_pool_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(qla_pool, qla_pool_cases, qla_pool_desc);

static void qla_pool_lifetime_test(struct kunit *test)
{
	const struct qla_pool_case *p = test->param_value;
	struct qla_pool_fixture *f = test->priv;
	struct sqa_scst_tgt *sqa_tgt;

	if (p->failure == QLA_POOL_NO_MAP)
		kunit_activate_static_stub(test, sqa_alloc_cmd_map, qla_pool_no_map);
	if (p->failure == QLA_POOL_NO_TAGS)
		kunit_activate_static_stub(test, sqa_init_tag_pool, qla_pool_no_tags);
	f->fail_registration = p->failure == QLA_POOL_NO_TARGET;

	sqa_tgt = sqa_alloc_tgt(&f->tmplate, "qla-pool-test", 32, 64);
	if (!IS_ERR_OR_NULL(sqa_tgt))
		f->allocated = sqa_tgt;
	if (p->failure == QLA_POOL_SUCCESS) {
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, sqa_tgt);
		KUNIT_EXPECT_PTR_EQ(test, sqa_tgt->scst_tgt, &f->target);
		KUNIT_EXPECT_NOT_NULL(test, sqa_tgt->tgt_cmd_map);
		KUNIT_EXPECT_EQ(test, f->maps_freed, 0U);
		KUNIT_EXPECT_EQ(test, f->pools_freed, 0U);
		sqa_free_tgt(sqa_tgt);
		f->allocated = NULL;
	} else {
		KUNIT_EXPECT_PTR_EQ(test, sqa_tgt, ERR_PTR(-ENOMEM));
	}
	KUNIT_EXPECT_EQ(test, f->maps_freed, p->maps_freed);
	KUNIT_EXPECT_EQ(test, f->pools_freed, p->pools_freed);
	KUNIT_EXPECT_EQ(test, f->registrations, p->registrations);
}

static const unsigned int qla_bitmap_sizes[] = {
	1, BITS_PER_LONG, BITS_PER_LONG + 1, SQA_DEFAULT_TAGS,
};

static void qla_bitmap_desc(const unsigned int *size, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%u_tags", *size);
}

KUNIT_ARRAY_PARAM(qla_bitmap, qla_bitmap_sizes, qla_bitmap_desc);

static void qla_bitmap_allocation_test(struct kunit *test)
{
	unsigned int tags = *(const unsigned int *)test->param_value;
	struct qla_pool_fixture *f = test->priv;
	size_t bytes = BITS_TO_LONGS(tags) * sizeof(*f->bitmap);
	unsigned int i;

	KUNIT_ASSERT_EQ(test, sqa_init_tag_bitmap(&f->bitmap, tags), 0);
	KUNIT_ASSERT_NOT_NULL(test, f->bitmap);
	/* Check the allocation before touching the high bits, even without KASAN. */
	KUNIT_ASSERT_GE(test, ksize(f->bitmap), bytes);
	for (i = 0; i < BITS_TO_LONGS(tags); i++)
		KUNIT_EXPECT_EQ(test, f->bitmap[i], 0UL);
	set_bit(tags - 1, f->bitmap);
	KUNIT_EXPECT_TRUE(test, test_bit(tags - 1, f->bitmap));
}

static unsigned long *qla_bitmap_no_memory(unsigned int tag_num)
{
	return NULL;
}

static void qla_bitmap_allocation_failure_test(struct kunit *test)
{
	struct qla_pool_fixture *f = test->priv;

	kunit_activate_static_stub(test, sqa_alloc_tag_bitmap, qla_bitmap_no_memory);
	KUNIT_EXPECT_EQ(test, sqa_init_tag_bitmap(&f->bitmap, SQA_DEFAULT_TAGS), -ENOMEM);
	KUNIT_EXPECT_PTR_EQ(test, f->bitmap, NULL);
}

static void qla_bitmap_exhaustion_test(struct kunit *test)
{
	unsigned int tags = *(const unsigned int *)test->param_value;
	unsigned int words = BITS_TO_LONGS(tags);
	unsigned long *bitmap;
	unsigned int i;

	/* A zero guard word makes an out-of-range claim observable without an OOB. */
	bitmap = kunit_kcalloc(test, words + 1, sizeof(*bitmap), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, bitmap);
	for (i = 0; i < tags; i++)
		KUNIT_EXPECT_EQ(test, sqa_get_tag_bitmap(bitmap, tags), (int)i);

	KUNIT_EXPECT_EQ(test, sqa_get_tag_bitmap(bitmap, tags), -ENOENT);
	KUNIT_EXPECT_EQ(test, bitmap[words], 0UL);
	if (tags % BITS_PER_LONG)
		KUNIT_EXPECT_EQ(test, bitmap[words - 1], BITMAP_LAST_WORD_MASK(tags));

	/* The last valid tag remains reusable after the pool was exhausted. */
	clear_bit(tags - 1, bitmap);
	KUNIT_EXPECT_EQ(test, sqa_get_tag_bitmap(bitmap, tags), (int)tags - 1);
	KUNIT_EXPECT_EQ(test, sqa_get_tag_bitmap(bitmap, tags), -ENOENT);
	KUNIT_EXPECT_EQ(test, bitmap[words], 0UL);
}

static void qla_bitmap_empty_pool_test(struct kunit *test)
{
	unsigned long guard = 0;

	KUNIT_EXPECT_EQ(test, sqa_get_tag_bitmap(&guard, 0), -ENOENT);
	KUNIT_EXPECT_EQ(test, guard, 0UL);
}

static struct kunit_case qla_pool_test_cases[] = {
	KUNIT_CASE_PARAM(qla_pool_lifetime_test, qla_pool_gen_params),
	KUNIT_CASE_PARAM(qla_bitmap_allocation_test, qla_bitmap_gen_params),
	KUNIT_CASE(qla_bitmap_allocation_failure_test),
	KUNIT_CASE_PARAM(qla_bitmap_exhaustion_test, qla_bitmap_gen_params),
	KUNIT_CASE(qla_bitmap_empty_pool_test),
	{}
};

scst_kunit_suite(qla_pool_suite, "QLA", "-pool",
		 .init = qla_pool_init,
		 .exit = qla_pool_exit,
		 .test_cases = qla_pool_test_cases,
);
