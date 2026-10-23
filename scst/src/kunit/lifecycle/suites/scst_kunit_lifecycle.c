// SPDX-License-Identifier: GPL-2.0-only
#include "../../scst_kunit.h"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "../../../scst_priv.h"
#include "../../../scst_lib_test.h"

#define LIFECYCLE_MAPPINGS 12

struct lifecycle_fixture {
	struct scst_device dev;
	struct scst_tgt tgt;
	struct scst_tgt_template tgtt;
	struct scst_acg acg;
	struct scst_session sessions[3];
	struct scst_tgt_dev mappings[LIFECYCLE_MAPPINGS];
	bool published[LIFECYCLE_MAPPINGS];
	bool removed[LIFECYCLE_MAPPINGS];
	bool freed[LIFECYCLE_MAPPINGS];
	unsigned int retired[LIFECYCLE_MAPPINGS];
	int alloc_results[3];
	unsigned int alloc_calls;
	unsigned int deletes;
	unsigned int frees;
	unsigned int grace_periods;
	unsigned int cm_adds;
	unsigned int cm_deletes;
	unsigned int sysfs_creates;
	unsigned int acg_frees;
	int cm_result;
	int sysfs_result;
	bool batch;
};

static void lifecycle_publish(struct lifecycle_fixture *f, unsigned int index,
			      struct scst_session *sess, u64 lun)
{
	struct scst_tgt_dev *td = &f->mappings[index];

	td->dev = &f->dev;
	td->sess = sess;
	td->tgtt = &f->tgtt;
	td->lun = lun;
	list_add_tail(&td->dev_tgt_dev_list_entry, &f->dev.dev_tgt_dev_list);
	list_add_tail_rcu(&td->sess_tgt_dev_list_entry,
			  &sess->sess_tgt_dev_list[SESS_TGT_DEV_LIST_HASH_FN(lun)]);
	f->published[index] = true;
}

static int lifecycle_alloc(struct scst_session *sess, struct scst_acg_dev *ad,
			   struct scst_tgt_dev **out)
{
	struct kunit *test = kunit_get_current_test();
	struct lifecycle_fixture *f = test->priv;
	unsigned int index = f->alloc_calls++;

	KUNIT_EXPECT_TRUE(test, mutex_is_locked(&scst_mutex));
	if (index >= ARRAY_SIZE(f->alloc_results))
		return -EOVERFLOW;
	if (f->alloc_results[index])
		return f->alloc_results[index];
	lifecycle_publish(f, index, sess, ad->lun);
	f->mappings[index].acg_dev = ad;
	*out = &f->mappings[index];
	return 0;
}

static void lifecycle_sysfs_remove(struct scst_tgt_dev *td)
{
	struct kunit *test = kunit_get_current_test();
	struct lifecycle_fixture *f = test->priv;
	unsigned int index = td - f->mappings;

	KUNIT_EXPECT_TRUE(test, mutex_is_locked(&scst_mutex));
	KUNIT_EXPECT_TRUE(test, mutex_is_locked(&td->sess->tgt_dev_list_mutex));
	rcu_read_lock();
	KUNIT_EXPECT_PTR_EQ(test, scst_lookup_tgt_dev(td->sess, td->lun), NULL);
	rcu_read_unlock();
	KUNIT_EXPECT_FALSE(test, f->removed[index]);
	f->removed[index] = true;
	f->deletes++;
}

static void lifecycle_grace_period(void)
{
	struct kunit *test = kunit_get_current_test();
	struct lifecycle_fixture *f = test->priv;
	unsigned int i;

	KUNIT_EXPECT_TRUE(test, mutex_is_locked(&scst_mutex));
	for (i = 0; i < ARRAY_SIZE(f->sessions); i++)
		KUNIT_EXPECT_FALSE(test, mutex_is_locked(&f->sessions[i].tgt_dev_list_mutex));
	f->grace_periods++;
	for (i = 0; i < ARRAY_SIZE(f->mappings); i++)
		if (f->removed[i])
			f->retired[i] = f->grace_periods;
}

static void lifecycle_free(struct scst_tgt_dev *td)
{
	struct kunit *test = kunit_get_current_test();
	struct lifecycle_fixture *f = test->priv;
	unsigned int index = td - f->mappings;

	KUNIT_EXPECT_TRUE(test, f->removed[index]);
	KUNIT_EXPECT_GT(test, f->retired[index], 0U);
	KUNIT_EXPECT_FALSE(test, f->freed[index]);
	KUNIT_EXPECT_FALSE(test, mutex_is_locked(&td->sess->tgt_dev_list_mutex));
	if (f->batch)
		KUNIT_EXPECT_TRUE(test, list_empty(&f->dev.dev_tgt_dev_list));
	f->freed[index] = true;
	f->frees++;
}

static int lifecycle_cm_add(struct scst_acg_dev *ad, u64 lun, unsigned int *flags)
{
	struct kunit *test = kunit_get_current_test();
	struct lifecycle_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, ad->acg, &f->acg);
	KUNIT_EXPECT_EQ(test, lun, ad->lun);
	KUNIT_EXPECT_EQ(test, (bool)ad->acg_dev_rd_only, !!(*flags & SCST_ADD_LUN_READ_ONLY));
	f->cm_adds++;
	return f->cm_result;
}

static void lifecycle_cm_del(const struct scst_acg_dev *ad)
{
	struct kunit *test = kunit_get_current_test();
	struct lifecycle_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, ad->dev, &f->dev);
	KUNIT_EXPECT_EQ(test, f->frees, 0U);
	f->cm_deletes++;
}

static int lifecycle_sysfs_create(struct scst_acg_dev *ad, struct kobject *parent)
{
	struct kunit *test = kunit_get_current_test();
	struct lifecycle_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, ad->dev, &f->dev);
	KUNIT_EXPECT_PTR_EQ(test, parent, &f->tgt.tgt_kobj);
	f->sysfs_creates++;
	return f->sysfs_result;
}

static void lifecycle_ref_release(struct percpu_ref *ref)
{
}

static int lifecycle_init(struct kunit *test)
{
	struct lifecycle_fixture *f;
	unsigned int i, j;
	int rc;

	test->priv = NULL;
	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;
	rc = percpu_ref_init(&f->dev.refcnt, lifecycle_ref_release,
			     PERCPU_REF_INIT_ATOMIC, GFP_KERNEL);
	if (rc)
		return rc;
	f->dev.virt_name = "kunit-private-device";
	spin_lock_init(&f->dev.dev_lock);
	INIT_LIST_HEAD(&f->dev.dev_tgt_dev_list);
	INIT_LIST_HEAD(&f->dev.dev_acg_dev_list);
	f->tgt.tgt_name = "kunit-private-target";
	f->tgt.tgtt = &f->tgtt;
	f->acg.tgt = &f->tgt;
	f->acg.acg_name = "kunit-private-group";
	INIT_LIST_HEAD(&f->acg.acg_dev_list);
	INIT_LIST_HEAD(&f->acg.acg_sess_list);
	for (i = 0; i < ARRAY_SIZE(f->sessions); i++) {
		f->sessions[i].tgt = &f->tgt;
		mutex_init(&f->sessions[i].tgt_dev_list_mutex);
		INIT_LIST_HEAD(&f->sessions[i].acg_sess_list_entry);
		for (j = 0; j < SESS_TGT_DEV_LIST_HASH_SIZE; j++)
			INIT_LIST_HEAD(&f->sessions[i].sess_tgt_dev_list[j]);
	}
	test->priv = f;
	kunit_activate_static_stub(test, scst_alloc_add_tgt_dev, lifecycle_alloc);
	kunit_activate_static_stub(test, scst_tgt_dev_sysfs_remove, lifecycle_sysfs_remove);
	kunit_activate_static_stub(test, scst_free_tgt_dev, lifecycle_free);
	kunit_activate_static_stub(test, scst_tgt_dev_grace_period, lifecycle_grace_period);
	kunit_activate_static_stub(test, scst_lun_cm_add, lifecycle_cm_add);
	kunit_activate_static_stub(test, scst_lun_cm_del, lifecycle_cm_del);
	kunit_activate_static_stub(test, scst_lun_sysfs_create, lifecycle_sysfs_create);
	return 0;
}

static void lifecycle_exit(struct kunit *test)
{
	struct lifecycle_fixture *f = test->priv;
	struct scst_acg_dev *ad, *tmp;
	unsigned int i;

	if (!f)
		return;
	/* Also reclaim an ACG allocation if an assertion interrupted a success case. */
	for (i = 0; i < ARRAY_SIZE(f->mappings); i++) {
		if (f->published[i] && !f->removed[i]) {
			list_del(&f->mappings[i].dev_tgt_dev_list_entry);
			list_del(&f->mappings[i].sess_tgt_dev_list_entry);
		}
	}
	mutex_lock(&scst_mutex);
	list_for_each_entry_safe(ad, tmp, &f->acg.acg_dev_list, acg_dev_list_entry)
		scst_del_free_acg_dev(ad, false);
	mutex_unlock(&scst_mutex);
	percpu_ref_exit(&f->dev.refcnt);
	test->priv = NULL;
}

struct lifecycle_lun_case {
	const char *name;
	unsigned int sessions;
	int alloc[3];
	int cm_error;
	int sysfs_error;
	unsigned int flags;
	int result;
	unsigned int mappings;
};

static const struct lifecycle_lun_case lifecycle_luns[] = {
	{ "empty-group", 0, {}, 0, 0, 0, 0, 0 },
	{ "three-sessions", 3, {}, 0, 0, 0, 0, 3 },
	{ "read-only", 3, {}, 0, 0, SCST_ADD_LUN_READ_ONLY, 0, 3 },
	{ "first-allocation-fails", 3, { -ENOMEM }, 0, 0, 0, -ENOMEM, 0 },
	{ "second-allocation-fails", 3, { 0, -ENOMEM }, 0, 0, 0, -ENOMEM, 1 },
	{ "third-allocation-fails", 3, { 0, 0, -EIO }, 0, 0, 0, -EIO, 2 },
	{ "skip-denied-session", 3, { 0, -EPERM }, 0, 0, 0, 0, 2 },
	{ "all-sessions-denied", 3, { -EPERM, -EPERM, -EPERM }, 0, 0, 0, 0, 0 },
	{ "cm-reject-empty", 0, {}, -EINVAL, 0, 0, -EINVAL, 0 },
	{ "cm-reject-one", 1, {}, -EINVAL, 0, SCST_ADD_LUN_READ_ONLY, -EINVAL, 1 },
	{ "cm-reject-three", 3, {}, -EINVAL, 0, SCST_ADD_LUN_READ_ONLY, -EINVAL, 3 },
	{ "sysfs-fails", 3, {}, 0, -ENOMEM, 0, -ENOMEM, 3 },
	{ "cm-origin-skips-cm", 3, {}, -EIO, 0, SCST_ADD_LUN_CM, 0, 3 },
	{ "cm-origin-sysfs-fails", 3, {}, 0, -EIO, SCST_ADD_LUN_CM, -EIO, 3 },
};

static void lifecycle_lun_desc(const struct lifecycle_lun_case *p, char *desc)
{
	strscpy(desc, p->name, KUNIT_PARAM_DESC_SIZE);
}

KUNIT_ARRAY_PARAM(lifecycle_lun, lifecycle_luns, lifecycle_lun_desc);

static void lifecycle_lun_test(struct kunit *test)
{
	const struct lifecycle_lun_case *p = test->param_value;
	struct lifecycle_fixture *f = test->priv;
	struct scst_acg_dev *out = NULL;
	unsigned int i;
	int rc;

	memcpy(f->alloc_results, p->alloc, sizeof(p->alloc));
	f->cm_result = p->cm_error;
	f->sysfs_result = p->sysfs_error;
	for (i = 0; i < p->sessions; i++)
		list_add_tail(&f->sessions[i].acg_sess_list_entry, &f->acg.acg_sess_list);
	mutex_lock(&scst_mutex);
	rc = scst_acg_add_lun(&f->acg, &f->tgt.tgt_kobj, &f->dev, 7, p->flags, &out);
	mutex_unlock(&scst_mutex);
	KUNIT_EXPECT_EQ(test, rc, p->result);
	KUNIT_EXPECT_EQ(test, f->cm_deletes,
			(unsigned int)(p->sysfs_error && !(p->flags & SCST_ADD_LUN_CM)));
	if (rc) {
		KUNIT_EXPECT_PTR_EQ(test, out, NULL);
		KUNIT_EXPECT_EQ(test, f->deletes, p->mappings);
		KUNIT_EXPECT_EQ(test, f->frees, p->mappings);
		KUNIT_EXPECT_EQ(test, f->grace_periods, p->mappings);
		KUNIT_EXPECT_TRUE(test, list_empty(&f->dev.dev_tgt_dev_list));
		KUNIT_EXPECT_TRUE(test, list_empty(&f->dev.dev_acg_dev_list));
		KUNIT_EXPECT_TRUE(test, list_empty(&f->acg.acg_dev_list));
	} else {
		KUNIT_ASSERT_NOT_NULL(test, out);
		KUNIT_EXPECT_EQ(test, out->lun, (u64)7);
		KUNIT_EXPECT_EQ(test, f->frees, 0U);
		KUNIT_EXPECT_EQ(test, f->sysfs_creates, 1U);
		KUNIT_EXPECT_EQ(test, f->cm_adds, (unsigned int)!(p->flags & SCST_ADD_LUN_CM));
	}
}

struct lifecycle_batch_case {
	const char *name;
	unsigned int count;
	unsigned int stride;
};

static const struct lifecycle_batch_case lifecycle_batches[] = {
	{ "empty", 0, 1 },
	{ "one", 1, 1 },
	{ "separate-buckets", 12, 1 },
	{ "same-bucket", 12, SESS_TGT_DEV_LIST_HASH_SIZE },
};

static void lifecycle_batch_desc(const struct lifecycle_batch_case *p, char *desc)
{
	strscpy(desc, p->name, KUNIT_PARAM_DESC_SIZE);
}

KUNIT_ARRAY_PARAM(lifecycle_batch, lifecycle_batches, lifecycle_batch_desc);

static void lifecycle_batch_test(struct kunit *test)
{
	const struct lifecycle_batch_case *p = test->param_value;
	struct lifecycle_fixture *f = test->priv;
	unsigned int i;

	f->batch = true;
	for (i = 0; i < p->count; i++)
		lifecycle_publish(f, i, &f->sessions[0], i * p->stride);
	mutex_lock(&scst_mutex);
	scst_sess_free_tgt_devs(&f->sessions[0]);
	mutex_unlock(&scst_mutex);
	KUNIT_EXPECT_EQ(test, f->grace_periods, 1U);
	KUNIT_EXPECT_EQ(test, f->deletes, p->count);
	KUNIT_EXPECT_EQ(test, f->frees, p->count);
	for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++)
		KUNIT_EXPECT_TRUE(test, list_empty(&f->sessions[0].sess_tgt_dev_list[i]));
}

static void lifecycle_free_acg(struct scst_acg *acg)
{
	struct kunit *test = kunit_get_current_test();
	struct lifecycle_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, acg, &f->acg);
	KUNIT_EXPECT_TRUE(test, mutex_is_locked(&scst_mutex));
	lockdep_assert_held(&scst_mutex);
	f->acg_frees++;
}

static void lifecycle_acg_worker_test(struct kunit *test)
{
	struct lifecycle_fixture *f = test->priv;
	struct scst_acg_release_work *work;

	/* Invoke the actual worker synchronously: static stubs are task-local. */
	work = kzalloc_obj(*work);
	KUNIT_ASSERT_NOT_NULL(test, work);
	work->acg = &f->acg;
	INIT_WORK(&work->work, scst_release_acg_work);
	kunit_activate_static_stub(test, scst_free_acg, lifecycle_free_acg);
	scst_release_acg_work(&work->work);
	KUNIT_EXPECT_EQ(test, f->acg_frees, 1U);
}

static struct kunit_case lifecycle_cases[] = {
	KUNIT_CASE_PARAM(lifecycle_lun_test, lifecycle_lun_gen_params),
	KUNIT_CASE_PARAM(lifecycle_batch_test, lifecycle_batch_gen_params),
	KUNIT_CASE(lifecycle_acg_worker_test),
	{}
};

scst_kunit_suite(lifecycle_suite, "LIFECYCLE", "",
		 .init = lifecycle_init,
		 .exit = lifecycle_exit,
		 .test_cases = lifecycle_cases,
);
