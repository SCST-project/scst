// SPDX-License-Identifier: GPL-2.0-only
#include "../../scst_kunit.h"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "../../../scst_priv.h"
#include "../../../scst_copy_mgr_test.h"

struct cm_fixture {
	struct scst_device dev;
	struct scst_acg acg;
	struct scst_acg other_acg;
	struct scst_acg_dev acg_dev;
	unsigned int registrations;
	int register_result;
	struct completion removing;
	unsigned int lun;
	unsigned int lookups;
	unsigned int designator_clears;
	unsigned int inquiries;
	int inquiry_result;
};

static unsigned int cm_lookup_stub(const struct scst_device *dev)
{
	struct kunit *test = kunit_get_current_test();
	struct cm_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, dev, &f->dev);
	KUNIT_EXPECT_TRUE(test, mutex_is_locked(&scst_mutex));
	lockdep_assert_held(&scst_mutex);
	f->lookups++;
	return f->lun;
}

static void cm_clear_stub(struct scst_device *dev)
{
	struct kunit *test = kunit_get_current_test();
	struct cm_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, dev, &f->dev);
	KUNIT_EXPECT_TRUE(test, mutex_is_locked(&scst_mutex));
	f->designator_clears++;
}

static int cm_inquiry_stub(struct scst_device *dev, unsigned int lun,
			   struct scst_cm_init_inq_priv *priv)
{
	struct kunit *test = kunit_get_current_test();
	struct cm_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, dev, &f->dev);
	KUNIT_EXPECT_PTR_EQ(test, priv, NULL);
	KUNIT_EXPECT_EQ(test, lun, f->lun);
	KUNIT_EXPECT_GT(test, dev->block_count, 0);
	KUNIT_EXPECT_TRUE(test, mutex_is_locked(&scst_mutex));
	KUNIT_EXPECT_EQ(test, f->designator_clears, f->inquiries + 1);
	f->inquiries++;
	return f->inquiry_result;
}

static int cm_test_init(struct kunit *test)
{
	struct cm_fixture *f;

	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;
	test->priv = f;
	f->dev.virt_name = "kunit-private-cm-device";
	spin_lock_init(&f->dev.dev_lock);
	INIT_LIST_HEAD(&f->dev.blocked_cmd_list);
	atomic_set(&f->dev.cm_update_req_cnt, 0);
	init_completion(&f->removing);
	f->lun = 9;
	kunit_activate_static_stub(test, scst_cm_get_lun, cm_lookup_stub);
	kunit_activate_static_stub(test, scst_cm_dev_free_designators, cm_clear_stub);
	kunit_activate_static_stub(test, scst_cm_send_init_inquiry, cm_inquiry_stub);
	return 0;
}

struct cm_update_case {
	const char *name;
	unsigned int pending;
	int error;
	bool removing;
	int initial_blocks;
};

static const struct cm_update_case cm_updates[] = {
	{ "single", 0 },
	{ "coalesce-two", 1 },
	{ "coalesce-many", 10 },
	{ "inquiry-enomem", 0, -ENOMEM },
	{ "inquiry-eio", 0, -EIO },
	{ "preserve-existing-block", 0, -ENOMEM, false, 1 },
	{ "unregistered-before-update", 0, 0, true },
	{ "unregistered-before-retry", 3, 0, true },
	{ "retry-enomem", 3, -ENOMEM },
	{ "retry-eio", 3, -EIO },
};

static void cm_update_desc(const struct cm_update_case *p, char *desc)
{
	strscpy(desc, p->name, KUNIT_PARAM_DESC_SIZE);
}

KUNIT_ARRAY_PARAM(cm_update, cm_updates, cm_update_desc);

static void cm_update_test(struct kunit *test)
{
	const struct cm_update_case *p = test->param_value;
	struct cm_fixture *f = test->priv;
	unsigned int i;

	f->dev.block_count = p->initial_blocks;
	if (!p->pending) {
		f->inquiry_result = p->error;
		if (p->removing) {
			f->lun = SCST_MAX_LUN;
			f->dev.remove_completion = &f->removing;
		}
	}
	scst_cm_update_dev_start(&f->dev);
	if (p->pending) {
		KUNIT_ASSERT_EQ(test, f->inquiries, 1U);
		for (i = 0; i < p->pending; i++)
			scst_cm_update_dev_start(&f->dev);
		KUNIT_EXPECT_EQ(test, f->inquiries, 1U);
		KUNIT_EXPECT_EQ(test, atomic_read(&f->dev.cm_update_req_cnt), (int)p->pending + 1);
		/* The real inquiry completion unblocks before calling update_fini. */
		spin_lock_bh(&f->dev.dev_lock);
		scst_unblock_dev(&f->dev);
		spin_unlock_bh(&f->dev.dev_lock);
		f->inquiry_result = p->error;
		if (p->removing) {
			f->lun = SCST_MAX_LUN;
			f->dev.remove_completion = &f->removing;
		}
		scst_cm_update_dev_fini(&f->dev);
	}
	KUNIT_EXPECT_EQ(test, f->lookups, p->pending ? 2U : 1U);
	KUNIT_EXPECT_EQ(test, f->inquiries,
			(unsigned int)!p->removing + (unsigned int)!!p->pending);
	if (p->error || p->removing) {
		KUNIT_EXPECT_EQ(test, f->dev.block_count, p->initial_blocks);
		KUNIT_EXPECT_EQ(test, atomic_read(&f->dev.cm_update_req_cnt), 0);
	} else {
		KUNIT_EXPECT_EQ(test, atomic_read(&f->dev.cm_update_req_cnt), 1);
		spin_lock_bh(&f->dev.dev_lock);
		scst_unblock_dev(&f->dev);
		spin_unlock_bh(&f->dev.dev_lock);
		scst_cm_update_dev_fini(&f->dev);
		KUNIT_EXPECT_EQ(test, atomic_read(&f->dev.cm_update_req_cnt), 0);
		KUNIT_EXPECT_EQ(test, f->dev.block_count, p->initial_blocks);
	}
	KUNIT_EXPECT_EQ(test, f->designator_clears, f->inquiries);
	KUNIT_EXPECT_FALSE(test, completion_done(&f->removing));
}

static struct scst_acg *cm_default_group(void)
{
	struct cm_fixture *f = kunit_get_current_test()->priv;

	return &f->acg;
}

static int cm_register_stub(struct scst_device *dev, uint64_t lun)
{
	struct kunit *test = kunit_get_current_test();
	struct cm_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, dev, &f->dev);
	KUNIT_EXPECT_EQ(test, lun, (u64)9);
	lockdep_assert_held(&scst_mutex);
	f->registrations++;
	return f->register_result;
}

struct cm_lun_case {
	const char *name;
	bool foreign;
	bool lun_readonly;
	bool dev_readonly;
	int register_error;
};

static const struct cm_lun_case cm_luns[] = {
	{ "foreign-writable", true },
	{ "foreign-readonly", true, true, true },
	{ "readonly-lun", false, true },
	{ "readonly-device", false, false, true },
	{ "readonly-both", false, true, true },
	{ "writable" },
	{ "register-enomem", false, false, false, -ENOMEM },
	{ "register-eio", false, false, false, -EIO },
};

static void cm_lun_desc(const struct cm_lun_case *p, char *desc)
{
	strscpy(desc, p->name, KUNIT_PARAM_DESC_SIZE);
}

KUNIT_ARRAY_PARAM(cm_lun, cm_luns, cm_lun_desc);

static void cm_lun_test(struct kunit *test)
{
	const struct cm_lun_case *p = test->param_value;
	struct cm_fixture *f = test->priv;
	unsigned int flags = SCST_ADD_LUN_GEN_UA | SCST_ADD_LUN_READ_ONLY;
	bool readonly = p->lun_readonly || p->dev_readonly;
	bool registered = !p->foreign && !readonly;
	int rc;

	f->acg_dev.acg = p->foreign ? &f->other_acg : &f->acg;
	f->acg_dev.dev = &f->dev;
	f->acg_dev.acg_dev_rd_only = p->lun_readonly;
	f->dev.dev_rd_only = p->dev_readonly;
	f->register_result = p->register_error;
	kunit_activate_static_stub(test, scst_cm_default_acg, cm_default_group);
	kunit_activate_static_stub(test, scst_cm_dev_register, cm_register_stub);
	mutex_lock(&scst_mutex);
	rc = scst_cm_on_add_lun(&f->acg_dev, 9, &flags);
	mutex_unlock(&scst_mutex);
	KUNIT_EXPECT_EQ(test, rc, p->foreign ? 0 : (readonly ? -EINVAL : p->register_error));
	KUNIT_EXPECT_EQ(test, f->registrations, (unsigned int)registered);
	KUNIT_EXPECT_EQ(test, !!(flags & SCST_ADD_LUN_GEN_UA), !registered);
	KUNIT_EXPECT_TRUE(test, !!(flags & SCST_ADD_LUN_READ_ONLY));
}

static struct kunit_case cm_cases[] = {
	KUNIT_CASE_PARAM(cm_update_test, cm_update_gen_params),
	KUNIT_CASE_PARAM(cm_lun_test, cm_lun_gen_params),
	{}
};

scst_kunit_suite(cm_suite, "CM", "",
		 .init = cm_test_init,
		 .test_cases = cm_cases,
);
