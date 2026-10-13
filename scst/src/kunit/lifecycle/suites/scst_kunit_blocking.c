// SPDX-License-Identifier: GPL-2.0-only
#include "../../scst_kunit.h"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "../../../scst_priv.h"
#include "../../../scst_lib_test.h"

struct blocking_fixture {
	struct scst_device dev;
	wait_queue_entry_t waiter;
	wait_queue_head_t *queue;
	unsigned int waits;
	unsigned int wakes;
	unsigned int callbacks;
	int wait_result;
	u8 payload[4];
};

static int blocking_wait(struct scst_device *dev, wait_queue_head_t *w)
{
	struct kunit *test = kunit_get_current_test();
	struct blocking_fixture *f = test->priv;
	struct scst_ext_blocker *b;

	lockdep_assert_held(&dev->dev_lock);
	b = list_first_entry(&dev->ext_blockers_list, typeof(*b), ext_blockers_list_entry);
	KUNIT_EXPECT_PTR_EQ(test, w, (wait_queue_head_t *)b->ext_blocker_data);
	KUNIT_EXPECT_EQ(test, kref_read(&b->refcount), 2U);
	KUNIT_EXPECT_TRUE(test, !!dev->ext_blocking_pending);
	f->waits++;
	/* Return before the completion worker, as in the reported interleaving. */
	if (!f->wait_result)
		dev->on_dev_cmd_count = 0;
	return f->wait_result;
}

static int blocking_wake(wait_queue_entry_t *entry, unsigned int mode, int flags, void *key)
{
	struct blocking_fixture *f = container_of(entry, typeof(*f), waiter);

	f->wakes++;
	list_del_init(&entry->entry);
	f->queue = NULL;
	return 1;
}

static void blocking_callback(struct scst_device *dev, u8 *data, int len)
{
	struct kunit *test = kunit_get_current_test();
	struct blocking_fixture *f = test->priv;
	bool unlocked;

	KUNIT_EXPECT_PTR_EQ(test, dev, &f->dev);
	KUNIT_EXPECT_EQ(test, len, (int)sizeof(f->payload));
	KUNIT_EXPECT_PTR_NE(test, data, &f->payload[0]);
	KUNIT_EXPECT_EQ(test, memcmp(data, f->payload, sizeof(f->payload)), 0);
	unlocked = spin_trylock_bh(&dev->dev_lock);
	if (unlocked)
		spin_unlock_bh(&dev->dev_lock);
	KUNIT_EXPECT_TRUE(test, unlocked);
	f->callbacks++;
}

static int blocking_init(struct kunit *test)
{
	struct blocking_fixture *f;

	test->priv = NULL;
	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;
	test->priv = f;
	f->dev.virt_name = "kunit-private-blocking";
	spin_lock_init(&f->dev.dev_lock);
	INIT_LIST_HEAD(&f->dev.ext_blockers_list);
	INIT_LIST_HEAD(&f->dev.blocked_cmd_list);
	INIT_WORK(&f->dev.ext_blockers_work, scst_ext_blocking_done_fn);
	init_waitqueue_func_entry(&f->waiter, blocking_wake);
	memcpy(f->payload, "test", sizeof(f->payload));
	kunit_activate_static_stub(test, scst_wait_ext_block_dev, blocking_wait);
	return 0;
}

static void blocking_exit(struct kunit *test)
{
	struct blocking_fixture *f = test->priv;
	struct scst_ext_blocker *b, *tmp;

	if (!f)
		return;
	test->priv = NULL;
	if (f->queue)
		remove_wait_queue(f->queue, &f->waiter);
	list_for_each_entry_safe(b, tmp, &f->dev.ext_blockers_list, ext_blockers_list_entry) {
		list_del(&b->ext_blockers_list_entry);
		scst_ext_blocker_put(b);
	}
}

struct blocking_case {
	const char *name;
	bool active;
	bool interrupted;
	bool serialized;
	bool asynchronous;
	bool stpg;
};

static const struct blocking_case blocking_cases_data[] = {
	{ "sync-idle" },
	{ "sync-caller-returns-before-worker", true },
	{ "sync-interrupted-before-worker", true, true },
	{ "sync-reuses-serialization", false, false, true },
	{ "sync-interrupted-reuses-serialization", true, true, true },
	{ "async-immediate", false, false, false, true },
	{ "async-deferred", true, false, false, true },
	{ "async-stpg", true, false, false, true, true },
	{ "async-serialized", true, false, true, true },
};

static void blocking_desc(const struct blocking_case *p, char *desc)
{
	strscpy(desc, p->name, KUNIT_PARAM_DESC_SIZE);
}

KUNIT_ARRAY_PARAM(blocking, blocking_cases_data, blocking_desc);

static void blocking_test(struct kunit *test)
{
	const struct blocking_case *p = test->param_value;
	struct blocking_fixture *f = test->priv;
	struct scst_ext_blocker *b;
	int rc;

	f->dev.on_dev_cmd_count = p->active;
	f->dev.strictly_serialized_cmd_waiting = p->serialized;
	f->dev.block_count = p->serialized;
	f->wait_result = p->interrupted ? -ERESTARTSYS : 0;
	if (p->asynchronous)
		rc = scst_ext_block_dev(&f->dev, blocking_callback, f->payload,
					sizeof(f->payload), p->stpg);
	else
		rc = scst_sync_ext_block_dev(&f->dev);
	KUNIT_EXPECT_EQ(test, rc, p->interrupted ? -ERESTARTSYS : 0);
	KUNIT_EXPECT_EQ(test, f->dev.block_count, 1);
	KUNIT_EXPECT_EQ(test, f->dev.ext_blocks_cnt, 1);
	KUNIT_EXPECT_FALSE(test, !!f->dev.strictly_serialized_cmd_waiting);
	KUNIT_EXPECT_EQ(test, f->waits, (unsigned int)(p->active && !p->asynchronous));
	if (p->active) {
		KUNIT_ASSERT_FALSE(test, list_empty(&f->dev.ext_blockers_list));
		b = list_first_entry(&f->dev.ext_blockers_list, typeof(*b),
				     ext_blockers_list_entry);
		KUNIT_EXPECT_EQ(test, kref_read(&b->refcount), 1U);
		if (!p->asynchronous) {
			/* The caller's reference is gone; its heap wait queue must still live. */
			f->queue = (void *)b->ext_blocker_data;
			add_wait_queue(f->queue, &f->waiter);
		}
		f->dev.on_dev_cmd_count = 0;
		f->dev.ext_unblock_scheduled = 1;
		scst_ext_blocking_done_fn(&f->dev.ext_blockers_work);
	}
	KUNIT_EXPECT_EQ(test, f->wakes, (unsigned int)(p->active && !p->asynchronous));
	KUNIT_EXPECT_EQ(test, f->callbacks, (unsigned int)p->asynchronous);
	KUNIT_EXPECT_TRUE(test, list_empty(&f->dev.ext_blockers_list));
	KUNIT_EXPECT_FALSE(test, !!f->dev.ext_unblock_scheduled);
	KUNIT_EXPECT_FALSE(test, !!f->dev.ext_blocking_pending);
	if (p->stpg) {
		scst_ext_unblock_dev(&f->dev, false);
		KUNIT_EXPECT_EQ(test, f->dev.block_count, 1);
	}
	scst_ext_unblock_dev(&f->dev, p->stpg);
	KUNIT_EXPECT_EQ(test, f->dev.block_count, 0);
	KUNIT_EXPECT_EQ(test, f->dev.ext_blocks_cnt, 0);
	scst_ext_unblock_dev(&f->dev, false);
	KUNIT_EXPECT_EQ(test, f->dev.block_count, 0);
}

static struct kunit_case blocking_cases[] = {
	KUNIT_CASE_PARAM(blocking_test, blocking_gen_params),
	{}
};

scst_kunit_suite(blocking_suite, "LIFECYCLE", "-blocking",
		 .init = blocking_init,
		 .exit = blocking_exit,
		 .test_cases = blocking_cases,
);
