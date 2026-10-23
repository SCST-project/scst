// SPDX-License-Identifier: GPL-2.0-only
#include "../../../../kunit/scst_kunit.h"
#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#include <scst/scst_user.h>
#else
#include "scst.h"
#include "scst_user.h"
#endif
#include "../../../scst_user_priv.h"
#include "../../../scst_user_test.h"

struct user_cleanup_fixture {
	struct scst_user_dev devices[2];
	struct scst_user_cmd pending[2];
	struct completion reply;
	unsigned int pool_tokens[3];
	unsigned int flushes;
	bool return_on_second_flush;
	bool shared;
	bool guard_fired;
};

/*
 * The registered callback retains the mutable parameter type required by its
 * interface.
 */
/* cppcheck-suppress constParameterCallback symbolName=pool */
static void user_cleanup_flush(struct sgv_pool *pool)
{
	struct kunit *test = kunit_get_current_test();
	struct user_cleanup_fixture *f = test->priv;
	unsigned int i;

	KUNIT_EXPECT_TRUE(test, pool == f->devices[0].pool || pool == f->devices[1].pool ||
			  pool == f->devices[0].pool_clust);
	f->flushes++;
	/* A buggy inner retry must fail instead of hanging the KUnit executor. */
	if (f->flushes > 16) {
		KUNIT_FAIL(test, "cleanup did not yield to the other device");
		f->guard_fired = true;
		for (i = 0; i < 2; i++) {
			list_del_init(&f->pending[i].hash_list_entry);
			f->devices[i].cleanup_done = 1;
		}
	}
	/* Model the destructor releasing A's retained reference after B returns it. */
	if ((f->shared && completion_done(&f->reply)) ||
	    (f->return_on_second_flush && f->flushes == 3)) {
		for (i = 0; i < 2; i++)
			list_del_init(&f->pending[i].hash_list_entry);
	}
}

static int user_cleanup_init(struct kunit *test)
{
	struct user_cleanup_fixture *f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	unsigned int i, j;

	if (!f)
		return -ENOMEM;
	test->priv = f;
	init_completion(&f->reply);
	for (i = 0; i < 2; i++) {
		struct scst_user_dev *dev = &f->devices[i];
		struct scst_user_cmd *u = &f->pending[i];

		spin_lock_init(&dev->udev_cmd_threads.cmd_list_lock);
		/*
		 * This member belongs to the installed scst.h interface. Keep
		 * its source-compatible spelling; only private wait queue fields
		 * were renamed.
		 */
		/* checkpatch-suppress-symbol CAMELCASE symbolName=cmd_list_waitQ ; Public ABI. */
		init_waitqueue_head(&dev->udev_cmd_threads.cmd_list_waitQ);
		INIT_LIST_HEAD(&dev->udev_cmd_threads.active_cmd_list);
		INIT_LIST_HEAD(&dev->ready_cmd_list);
		init_completion(&dev->cleanup_cmpl);
		for (j = 0; j < ARRAY_SIZE(dev->ucmd_hash); j++)
			INIT_LIST_HEAD(&dev->ucmd_hash[j]);
		/* Opaque tokens consumed only by the task-scoped pool-flush stub. */
		dev->pool = (void *)&f->pool_tokens[i];
		dev->pool_clust = (void *)&f->pool_tokens[2];
		u->dev = dev;
		u->state = UCMD_STATE_ATTACH_SESS;
		u->cmpl = &f->reply;
		/* Fixture reference plus outstanding reply. */
		kref_init(&u->ucmd_ref);
		kref_get(&u->ucmd_ref);
		INIT_LIST_HEAD(&u->hash_list_entry);
		INIT_LIST_HEAD(&u->ready_cmd_list_entry);
	}
	kunit_activate_static_stub(test, dev_user_flush_pool, user_cleanup_flush);
	return 0;
}

struct user_cleanup_case {
	const char *name;
	bool done;
	bool pending;
	bool flush_return;
};

static const struct user_cleanup_case user_cleanup_cases[] = {
	{ "empty_waiting_for_core" },
	{ "empty_complete", .done = true },
	{ "pending_waiting_for_core", .pending = true },
	{ "pending_after_core_done", .done = true, .pending = true },
	{ "post_unjam_flush_releases_reference", .done = true, .pending = true,
	  .flush_return = true },
};

static void user_cleanup_desc(const struct user_cleanup_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(user_cleanup, user_cleanup_cases, user_cleanup_desc);

static void user_cleanup_test(struct kunit *test)
{
	const struct user_cleanup_case *p = test->param_value;
	struct user_cleanup_fixture *f = test->priv;
	struct scst_user_dev *dev = f->devices;
	bool complete = p->done && !p->pending;

	dev->cleanup_done = p->done;
	if (p->pending)
		list_add_tail(&f->pending[0].hash_list_entry, &dev->ucmd_hash[0]);
	f->return_on_second_flush = p->flush_return;
	KUNIT_EXPECT_EQ(test, dev_user_process_cleanup(dev), complete ? 0 : 1);
	KUNIT_EXPECT_EQ(test, completion_done(&dev->cleanup_cmpl), complete);
	KUNIT_EXPECT_EQ(test, f->flushes, 4U);
	KUNIT_EXPECT_FALSE(test, f->guard_fired);
	if (p->flush_return) {
		KUNIT_EXPECT_TRUE(test, list_empty(&dev->ucmd_hash[0]));
		KUNIT_EXPECT_EQ(test, dev_user_process_cleanup(dev), 0);
		KUNIT_EXPECT_TRUE(test, completion_done(&dev->cleanup_cmpl));
	}
}

static void user_cleanup_shared_test(struct kunit *test)
{
	struct user_cleanup_fixture *f = test->priv;
	unsigned int i;

	f->shared = true;
	for (i = 0; i < 2; i++) {
		f->devices[i].cleanup_done = 1;
		list_add_tail(&f->pending[i].hash_list_entry, &f->devices[i].ucmd_hash[0]);
	}
	f->pending[1].sent_to_user = 1;
	KUNIT_ASSERT_EQ(test, dev_user_process_cleanup(&f->devices[0]), 1);
	KUNIT_EXPECT_FALSE(test, completion_done(&f->devices[0].cleanup_cmpl));
	KUNIT_EXPECT_FALSE(test, completion_done(&f->reply));
	KUNIT_EXPECT_EQ(test, f->flushes, 4U);
	KUNIT_ASSERT_EQ(test, dev_user_process_cleanup(&f->devices[1]), 1);
	KUNIT_EXPECT_TRUE(test, completion_done(&f->reply));
	KUNIT_EXPECT_EQ(test, f->pending[1].result, -EFAULT);
	KUNIT_EXPECT_EQ(test, kref_read(&f->pending[1].ucmd_ref), 1);
	KUNIT_EXPECT_EQ(test, dev_user_process_cleanup(&f->devices[0]), 0);
	KUNIT_EXPECT_EQ(test, dev_user_process_cleanup(&f->devices[1]), 0);
	for (i = 0; i < 2; i++)
		KUNIT_EXPECT_TRUE(test, completion_done(&f->devices[i].cleanup_cmpl));
	KUNIT_EXPECT_FALSE(test, f->guard_fired);
}

struct user_reply_case {
	const char *name;
	bool detach;
	bool repeat;
	bool saved_flags;
	bool no_completion;
};

static const struct user_reply_case user_reply_cases[] = {
	{ "attach_failure" },
	{ "detach_failure", .detach = true },
	{ "attach_notified_once", .repeat = true },
	{ "detach_notified_once", .detach = true, .repeat = true },
	{ "attach_irqsave_caller", .saved_flags = true },
	{ "detach_irqsave_caller", .detach = true, .saved_flags = true },
	{ "attach_without_waiter", .no_completion = true },
	{ "detach_without_waiter", .detach = true, .no_completion = true },
};

static void user_reply_desc(const struct user_reply_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(user_reply, user_reply_cases, user_reply_desc);

static void user_reply_test(struct kunit *test)
{
	const struct user_reply_case *p = test->param_value;
	struct user_cleanup_fixture *f = test->priv;
	struct scst_user_cmd *u = f->pending;
	spinlock_t *lock = &f->devices[0].udev_cmd_threads.cmd_list_lock;
	unsigned long flags = 0;

	u->state = p->detach ? UCMD_STATE_DETACH_SESS : UCMD_STATE_ATTACH_SESS;
	u->sent_to_user = 1;
	if (p->no_completion)
		u->cmpl = NULL;
	if (p->saved_flags)
		spin_lock_irqsave(lock, flags);
	else
		spin_lock_irq(lock);
	dev_user_unjam_cmd(u, 0, p->saved_flags ? &flags : NULL);
	if (p->repeat)
		dev_user_unjam_cmd(u, 0, p->saved_flags ? &flags : NULL);
	if (p->saved_flags)
		spin_unlock_irqrestore(lock, flags);
	else
		spin_unlock_irq(lock);
	KUNIT_EXPECT_EQ(test, completion_done(&f->reply), !p->no_completion);
	KUNIT_EXPECT_EQ(test, u->result, p->detach ? 0 : -EFAULT);
	KUNIT_EXPECT_EQ(test, kref_read(&u->ucmd_ref), 1);
	KUNIT_EXPECT_TRUE(test, !!u->jammed);
	KUNIT_EXPECT_TRUE(test, !!u->this_state_unjammed);
	KUNIT_EXPECT_FALSE(test, !!u->sent_to_user);
}

/*
 * The registered callback retains the mutable parameter type required by its
 * interface.
 */
/* cppcheck-suppress constParameterCallback symbolName=ref */
static void user_defer_release(struct kref *ref)
{
	/* Model the destructor waiting for cmd_list_lock before hash removal. */
}

static void user_get_live_command(struct kunit *test)
{
	struct user_cleanup_fixture *f = test->priv;
	struct scst_user_cmd *u = f->pending;
	spinlock_t *lock = &f->devices[0].udev_cmd_threads.cmd_list_lock;
	unsigned long flags;
	bool skip;

	spin_lock_irqsave(lock, flags);
	skip = ucmd_get_check(u);
	spin_unlock_irqrestore(lock, flags);
	KUNIT_EXPECT_FALSE(test, skip);
	KUNIT_EXPECT_EQ(test, kref_read(&u->ucmd_ref), 3U);
}

static void user_get_destroying_command(struct kunit *test)
{
	struct user_cleanup_fixture *f = test->priv;
	struct scst_user_cmd *u = f->pending;
	spinlock_t *lock = &f->devices[0].udev_cmd_threads.cmd_list_lock;
	unsigned long flags;
	bool skip;

	kref_put(&u->ucmd_ref, user_defer_release);
	kref_put(&u->ucmd_ref, user_defer_release);
	spin_lock_irqsave(lock, flags);
	skip = ucmd_get_check(u);
	spin_unlock_irqrestore(lock, flags);
	KUNIT_EXPECT_TRUE(test, skip);
	KUNIT_EXPECT_EQ(test, kref_read(&u->ucmd_ref), 0U);
}

static struct kunit_case user_cleanup_cases_kunit[] = {
	KUNIT_CASE_PARAM(user_cleanup_test, user_cleanup_gen_params),
	KUNIT_CASE(user_cleanup_shared_test),
	KUNIT_CASE_PARAM(user_reply_test, user_reply_gen_params),
	KUNIT_CASE(user_get_live_command),
	KUNIT_CASE(user_get_destroying_command),
	{}
};

scst_kunit_suite(user_cleanup_suite, "USER", "-cleanup",
		 .init = user_cleanup_init,
		 .test_cases = user_cleanup_cases_kunit,
);
