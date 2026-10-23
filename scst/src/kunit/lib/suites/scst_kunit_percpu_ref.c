// SPDX-License-Identifier: GPL-2.0-only
#include "../../scst_kunit.h"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif

struct percpu_ref_fixture {
	struct percpu_ref ref;
	atomic_t releases;
	atomic_t confirmations;
	unsigned int held;
	bool initialized;
	bool dead;
};

static void percpu_test_release(struct percpu_ref *ref)
{
	struct percpu_ref_fixture *f = container_of(ref, struct percpu_ref_fixture, ref);

	/* Like the SCST command counters, the fixture outlives zero references. */
	atomic_inc(&f->releases);
}

static void percpu_test_confirm(struct percpu_ref *ref)
{
	struct percpu_ref_fixture *f = container_of(ref, struct percpu_ref_fixture, ref);

	atomic_inc(&f->confirmations);
}

static int percpu_test_init(struct kunit *test)
{
	struct percpu_ref_fixture *f;

	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;
	atomic_set(&f->releases, 0);
	atomic_set(&f->confirmations, 0);
	test->priv = f;
	return 0;
}

static int percpu_test_start(const struct kunit *test, unsigned int flags)
{
	struct percpu_ref_fixture *f = test->priv;
	int ret;

	ret = percpu_ref_init(&f->ref, percpu_test_release,
			      flags | PERCPU_REF_ALLOW_REINIT, GFP_KERNEL);
	if (!ret)
		f->initialized = true;
	return ret;
}

static void percpu_test_get(struct percpu_ref_fixture *f)
{
	percpu_ref_get(&f->ref);
	f->held++;
}

static void percpu_test_put(struct percpu_ref_fixture *f)
{
	f->held--;
	percpu_ref_put(&f->ref);
}

static void percpu_test_kill(struct percpu_ref_fixture *f)
{
	f->dead = true;
	percpu_ref_kill_and_confirm(&f->ref, percpu_test_confirm);
}

static void percpu_test_resurrect(struct percpu_ref_fixture *f)
{
	/* Exercise the backport even when the running kernel has resurrect(). */
	scst_percpu_ref_resurrect_backport(&f->ref);
	f->dead = percpu_ref_is_dying(&f->ref);
}

/* The KUnit suite exit callback requires a mutable test parameter. */
/* cppcheck-suppress constParameterCallback symbolName=test */
static void percpu_test_exit(struct kunit *test)
{
	struct percpu_ref_fixture *f = test->priv;

	if (!f || !f->initialized)
		return;
	if (!f->dead)
		percpu_test_kill(f);
	/* KUnit runs on kernels using the unified RCU callback API. */
	rcu_barrier();
	while (f->held)
		percpu_test_put(f);
	percpu_ref_exit(&f->ref);
}

static void percpu_resurrect_preserves_active_refs(struct kunit *test)
{
	struct percpu_ref_fixture *f = test->priv;
	unsigned long allocation;
	bool acquired;

	KUNIT_ASSERT_EQ(test, percpu_test_start(test, 0), 0);
	allocation = f->ref.percpu_count_ptr & ~__PERCPU_REF_ATOMIC_DEAD;
	percpu_test_get(f);
	percpu_test_get(f);
	percpu_test_get(f);
	percpu_test_kill(f);
	acquired = percpu_ref_tryget_live(&f->ref);
	KUNIT_EXPECT_FALSE(test, acquired);
	if (acquired)
		percpu_ref_put(&f->ref);

	/* Do not drain RCU first: the backport must wait for a pending switch. */
	percpu_test_resurrect(f);
	KUNIT_ASSERT_FALSE(test, f->dead);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->confirmations), 1);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->releases), 0);
	KUNIT_EXPECT_EQ(test, f->ref.percpu_count_ptr, allocation);
	acquired = percpu_ref_tryget_live(&f->ref);
	KUNIT_EXPECT_TRUE(test, acquired);
	if (acquired)
		percpu_ref_put(&f->ref);

	/* Regather the counters to detect lost refs or stale per-CPU values. */
	percpu_test_kill(f);
	rcu_barrier();
	KUNIT_EXPECT_EQ(test, READ_REF_COUNT(&f->ref), 3L);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->releases), 0);
	while (f->held)
		percpu_test_put(f);
	KUNIT_EXPECT_TRUE(test, percpu_ref_is_zero(&f->ref));
	KUNIT_EXPECT_EQ(test, atomic_read(&f->releases), 1);
}

static void percpu_resurrect_after_drain(struct kunit *test)
{
	struct percpu_ref_fixture *f = test->priv;
	unsigned int cycle;

	KUNIT_ASSERT_EQ(test, percpu_test_start(test, 0), 0);
	for (cycle = 0; cycle < 3; cycle++) {
		percpu_test_kill(f);
		rcu_barrier();
		KUNIT_EXPECT_TRUE(test, percpu_ref_is_zero(&f->ref));
		KUNIT_EXPECT_EQ(test, atomic_read(&f->releases), (int)cycle + 1);
		percpu_test_resurrect(f);
		KUNIT_ASSERT_FALSE(test, f->dead);
		KUNIT_EXPECT_FALSE(test, percpu_ref_is_zero(&f->ref));
	}
}

static void percpu_resurrect_keeps_atomic_mode(struct kunit *test)
{
	struct percpu_ref_fixture *f = test->priv;

	KUNIT_ASSERT_EQ(test, percpu_test_start(test, PERCPU_REF_INIT_ATOMIC), 0);
	percpu_test_get(f);
	percpu_test_get(f);
	percpu_test_kill(f);
	percpu_test_resurrect(f);
	KUNIT_ASSERT_FALSE(test, f->dead);
	KUNIT_EXPECT_TRUE(test, f->ref.percpu_count_ptr & __PERCPU_REF_ATOMIC);
	KUNIT_EXPECT_EQ(test, READ_REF_COUNT(&f->ref), 3L);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->releases), 0);
	percpu_test_kill(f);
	rcu_barrier();
	KUNIT_EXPECT_EQ(test, READ_REF_COUNT(&f->ref), 2L);
	while (f->held)
		percpu_test_put(f);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->releases), 1);
}

static void percpu_resurrect_repeated_cancellations(struct kunit *test)
{
	struct percpu_ref_fixture *f = test->priv;
	unsigned int cycle;

	KUNIT_ASSERT_EQ(test, percpu_test_start(test, 0), 0);
	percpu_test_get(f);
	percpu_test_get(f);
	for (cycle = 0; cycle < 5; cycle++) {
		percpu_test_kill(f);
		rcu_barrier();
		KUNIT_EXPECT_EQ(test, READ_REF_COUNT(&f->ref), 2L);
		/* One command completes while suspended; the other survives resume. */
		percpu_test_put(f);
		percpu_test_resurrect(f);
		KUNIT_ASSERT_FALSE(test, f->dead);
		KUNIT_EXPECT_EQ(test, atomic_read(&f->releases), 0);
		percpu_test_get(f);
	}
	percpu_test_kill(f);
	rcu_barrier();
	KUNIT_EXPECT_EQ(test, READ_REF_COUNT(&f->ref), 2L);
	while (f->held)
		percpu_test_put(f);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->releases), 1);
}

static struct kunit_case percpu_ref_cases[] = {
	KUNIT_CASE(percpu_resurrect_preserves_active_refs),
	KUNIT_CASE(percpu_resurrect_after_drain),
	KUNIT_CASE(percpu_resurrect_keeps_atomic_mode),
	KUNIT_CASE(percpu_resurrect_repeated_cancellations),
	{}
};

scst_kunit_suite(percpu_ref_suite, "LIB", "-percpu-ref",
		 .init = percpu_test_init,
		 .exit = percpu_test_exit,
		 .test_cases = percpu_ref_cases,
);
