// SPDX-License-Identifier: GPL-2.0-only
#include "../scst_vdisk_fixture.h"

struct sync_device {
	struct scst_device dev;
	struct completion released;
};

struct sync_fixture {
	struct scst_device *dev;
	struct scst_sysfs_work_item *pending;
	int alloc_error;
	int suspend_error;
	int backend_result;
	unsigned int queues;
	unsigned int suspends;
	unsigned int resumes;
	unsigned int backends;
	bool delayed;
};

/* Release can run on another task with CONFIG_DEBUG_KOBJECT_RELEASE. */
static void sync_device_release(struct kobject *kobj)
{
	struct scst_device *dev = container_of(kobj, struct scst_device, dev_kobj);
	struct sync_device *d = container_of(dev, struct sync_device, dev);

	complete(&d->released);
}

static const struct kobj_type sync_device_type = {
	.release = sync_device_release,
};

static int sync_suspend(unsigned long timeout)
{
	struct kunit *test = kunit_get_current_test();
	struct sync_fixture *f = test->priv;

	KUNIT_EXPECT_EQ(test, timeout, (unsigned long)SCST_SUSPEND_TIMEOUT_USER);
	f->suspends++;
	return f->suspend_error;
}

static void sync_resume(void)
{
	struct kunit *test = kunit_get_current_test();
	struct sync_fixture *f = test->priv;
	bool unlocked = mutex_trylock(&scst_mutex);

	if (unlocked)
		mutex_unlock(&scst_mutex);
	KUNIT_EXPECT_TRUE(test, unlocked);
	f->resumes++;
}

static int sync_backend(struct scst_device *dev)
{
	struct kunit *test = kunit_get_current_test();
	struct sync_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, dev, f->dev);
	KUNIT_EXPECT_EQ(test, f->suspends, 1U);
	KUNIT_EXPECT_EQ(test, f->resumes, 0U);
	KUNIT_EXPECT_TRUE(test, mutex_is_locked(&scst_mutex));
	lockdep_assert_held(&scst_mutex);
	lockdep_assert_alua_lock_held();
	KUNIT_EXPECT_EQ(test, kref_read(&dev->dev_kobj.kref), 2U);
	f->backends++;
	/* Backend dispatch has a separate suite with real fake-file operations. */
	return f->backend_result;
}

static int sync_alloc(int (*fn)(struct scst_sysfs_work_item *), bool read_only,
		      struct scst_sysfs_work_item **work)
{
	struct kunit *test = kunit_get_current_test();
	struct sync_fixture *f = test->priv;
	int ret;

	KUNIT_EXPECT_FALSE(test, read_only);
	if (f->alloc_error)
		return f->alloc_error;
	kunit_deactivate_static_stub(test, scst_alloc_sysfs_work);
	ret = scst_alloc_sysfs_work(fn, read_only, work);
	kunit_activate_static_stub(test, scst_alloc_sysfs_work, sync_alloc);
	return ret;
}

static int sync_finish(struct sync_fixture *f)
{
	struct scst_sysfs_work_item *work = f->pending;
	int ret;

	f->pending = NULL;
	ret = work->sysfs_work_fn(work);
	scst_sysfs_work_put(work);
	return ret;
}

static int sync_queue(struct scst_sysfs_work_item *work)
{
	struct kunit *test = kunit_get_current_test();
	struct sync_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, work->dev, f->dev);
	KUNIT_EXPECT_EQ(test, kref_read(&f->dev->dev_kobj.kref), 2U);
	f->queues++;
	f->pending = work;
	/* Execute in this task so native static stubs never escape their owner. */
	return f->delayed ? -EAGAIN : sync_finish(f);
}

static int sync_init(struct kunit *test)
{
	struct sync_fixture *f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	struct sync_device *d;

	if (!f)
		return -ENOMEM;
	test->priv = f;
	d = kzalloc_obj(*d);
	if (!d)
		return -ENOMEM;
	f->dev = &d->dev;
	init_completion(&d->released);
	__module_get(THIS_MODULE);
	kobject_init(&f->dev->dev_kobj, &sync_device_type);
	f->dev->dh_priv = f;
	kunit_activate_static_stub(test, scst_suspend_activity, sync_suspend);
	kunit_activate_static_stub(test, scst_resume_activity, sync_resume);
	kunit_activate_static_stub(test, vdisk_flush_backend, sync_backend);
	kunit_activate_static_stub(test, scst_alloc_sysfs_work, sync_alloc);
	kunit_activate_static_stub(test, scst_sysfs_queue_wait_work, sync_queue);
	return 0;
}

static void sync_exit(struct kunit *test)
{
	struct sync_fixture *f = test->priv;
	struct sync_device *d;

	if (!f || !f->dev)
		return;
	if (f->pending)
		sync_finish(f);
	f->dev->dh_priv = NULL;
	if (kref_read(&f->dev->dev_kobj.kref) != 1) {
		scst_kunit_retain(test, "sync device reference leaked");
		return;
	}
	d = container_of(f->dev, struct sync_device, dev);
	kobject_put(&f->dev->dev_kobj);
	if (!wait_for_completion_timeout(&d->released, 10 * HZ)) {
		scst_kunit_retain(test, "sync device release did not finish");
		return;
	}
#ifdef CONFIG_DEBUG_KOBJECT_RELEASE
	/* Release has signalled; join its return before freeing the work storage. */
	flush_delayed_work(&f->dev->dev_kobj.release);
#endif
	kfree(d);
	module_put(THIS_MODULE);
}

struct sync_case {
	const char *name;
	int alloc_error;
	int suspend_error;
	int backend_error;
	bool delayed;
	bool detached;
};

static const struct sync_case sync_cases[] = {
	{ .name = "complete" },
	{ .name = "allocation_failed", .alloc_error = -ENOMEM },
	{ .name = "suspend_failed", .suspend_error = -EBUSY },
	{ .name = "backend_eio", .backend_error = -EIO },
	{ .name = "backend_enomem", .backend_error = -ENOMEM },
	{ .name = "delayed_completion", .delayed = true },
	{ .name = "delayed_error", .delayed = true, .backend_error = -EIO },
	{ .name = "handler_removed_before_execution", .delayed = true, .detached = true },
};

static void sync_desc(const struct sync_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(sync, sync_cases, sync_desc);

static void sync_test(struct kunit *test)
{
	const struct sync_case *p = test->param_value;
	struct sync_fixture *f = test->priv;
	int error = p->alloc_error ?: p->suspend_error ?: p->backend_error;
	ssize_t ret;

	f->alloc_error = p->alloc_error;
	f->suspend_error = p->suspend_error;
	f->backend_result = p->backend_error;
	f->delayed = p->delayed;
	ret = vdisk_sysfs_sync_store(&f->dev->dev_kobj, NULL, "1\n", 2);
	KUNIT_EXPECT_EQ(test, ret, p->delayed ? (ssize_t)-EAGAIN : error ?: (ssize_t)2);
	if (p->delayed) {
		KUNIT_EXPECT_EQ(test, f->suspends, 0U);
		KUNIT_EXPECT_EQ(test, kref_read(&f->dev->dev_kobj.kref), 2U);
		if (p->detached) {
			/* Model handler teardown while a timed-out store still owns work. */
			f->dev->dh_priv = NULL;
			kunit_deactivate_static_stub(test, vdisk_flush_backend);
			error = -ENODEV;
		}
		KUNIT_ASSERT_NOT_NULL(test, f->pending);
		KUNIT_EXPECT_EQ(test, sync_finish(f), error);
	}
	KUNIT_EXPECT_EQ(test, f->queues, p->alloc_error ? 0U : 1U);
	KUNIT_EXPECT_EQ(test, f->suspends, p->alloc_error ? 0U : 1U);
	KUNIT_EXPECT_EQ(test, f->resumes, p->alloc_error || p->suspend_error ? 0U : 1U);
	KUNIT_EXPECT_EQ(test, f->backends,
			p->alloc_error || p->suspend_error || p->detached ?
			0U : 1U);
	KUNIT_EXPECT_EQ(test, kref_read(&f->dev->dev_kobj.kref), 1U);
	KUNIT_EXPECT_PTR_EQ(test, f->pending, NULL);
}

static struct kunit_case sync_test_cases[] = {
	KUNIT_CASE_PARAM(sync_test, sync_gen_params),
	{}
};

scst_kunit_suite(vdisk_sysfs_suite, "VDISK", "-sysfs",
		 .init = sync_init,
		 .exit = sync_exit,
		 .test_cases = sync_test_cases,
);
