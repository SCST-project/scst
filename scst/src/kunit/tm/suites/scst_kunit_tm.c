// SPDX-License-Identifier: GPL-2.0-only
#include "../../scst_kunit.h"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "../../../scst_priv.h"
#include "../../../scst_lib_test.h"
#include "../../../scst_sysfs_test.h"
#include "../../../scst_targ_test.h"

struct tm_fixture {
	struct scst_tgt_template tgtt;
	struct scst_tgt tgt;
	struct scst_session sess;
	struct scst_acg old_acg;
	struct scst_acg new_acg;
	struct scst_acg_dev acg_dev;
	struct scst_device dev;
	unsigned int allocations;
	unsigned int links;
	unsigned int events;
	bool check_tm_during_reassign;
	bool expected_tm_dropped;
};

static void tm_check_teardown_commands(struct kunit *test, bool dropped);

static int tm_event_stub(struct scst_mgmt_cmd *mcmd)
{
	struct kunit *test = kunit_get_current_test();
	struct tm_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, mcmd->sess, &f->sess);
	KUNIT_EXPECT_EQ(test, mcmd->state, SCST_MCMD_STATE_EXEC);
	f->events++;
	return 0;
}

static int tm_luns_link_stub(struct scst_session *sess)
{
	struct kunit *test = kunit_get_current_test();
	struct tm_fixture *f = test->priv;

	lockdep_assert_held(&scst_mutex);
	KUNIT_EXPECT_PTR_EQ(test, sess, &f->sess);
	KUNIT_EXPECT_PTR_EQ(test, sess->acg, &f->new_acg);
	f->links++;
	return 0;
}

static int tm_alloc_tgt_dev_stub(struct scst_session *sess,
				 struct scst_acg_dev *acg_dev, struct scst_tgt_dev **out)
{
	struct kunit *test = kunit_get_current_test();
	struct tm_fixture *f = test->priv;

	lockdep_assert_held(&scst_mutex);
	KUNIT_EXPECT_PTR_EQ(test, sess, &f->sess);
	KUNIT_EXPECT_PTR_EQ(test, acg_dev, &f->acg_dev);
	f->allocations++;
	/* Exercise the reader before the real reassignment has completed. */
	if (f->check_tm_during_reassign) {
		KUNIT_EXPECT_PTR_EQ(test, sess->acg, NULL);
		tm_check_teardown_commands(test, f->expected_tm_dropped);
	}
	*out = NULL;
	return -EPERM;
}

static int tm_test_init(struct kunit *test)
{
	struct tm_fixture *f;
	int i;

	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;
	test->priv = f;
	f->tgt.tgtt = &f->tgtt;
	f->tgt.default_acg = &f->new_acg;
	INIT_LIST_HEAD(&f->tgt.tgt_acg_list);
	f->sess.tgt = &f->tgt;
	f->sess.initiator_name = "kunit-private-tm-initiator";
	f->sess.init_phase = SCST_SESS_IPH_READY;
	f->sess.shut_phase = SCST_SESS_SPH_READY;
	f->sess.acg = &f->old_acg;
	mutex_init(&f->sess.tgt_dev_list_mutex);
	for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++)
		INIT_LIST_HEAD(&f->sess.sess_tgt_dev_list[i]);
	f->old_acg.acg_name = "kunit-private-old-acg";
	f->new_acg.acg_name = "kunit-private-new-acg";
	INIT_LIST_HEAD(&f->old_acg.acg_sess_list);
	INIT_LIST_HEAD(&f->new_acg.acg_sess_list);
	INIT_LIST_HEAD(&f->old_acg.acg_dev_list);
	INIT_LIST_HEAD(&f->new_acg.acg_dev_list);
	kref_init(&f->old_acg.acg_kref);
	kref_init(&f->new_acg.acg_kref);
	/* Keep a fixture reference: reassignment must not schedule ACG release. */
	scst_get_acg(&f->old_acg);
	list_add_tail(&f->sess.acg_sess_list_entry, &f->old_acg.acg_sess_list);
	f->acg_dev.acg = &f->new_acg;
	f->acg_dev.dev = &f->dev;
	f->acg_dev.lun = 1;
	list_add_tail(&f->acg_dev.acg_dev_list_entry, &f->new_acg.acg_dev_list);
	kunit_activate_static_stub(test, scst_alloc_add_tgt_dev, tm_alloc_tgt_dev_stub);
	kunit_activate_static_stub(test, scst_recreate_sess_luns_link, tm_luns_link_stub);
	kunit_activate_static_stub(test, scst_event_queue_tm_fn_received, tm_event_stub);
	return 0;
}

static void tm_test_exit(struct kunit *test)
{
	struct tm_fixture *f = test->priv;

	list_del_init(&f->sess.acg_sess_list_entry);
	scst_put_acg(f->sess.acg);
	KUNIT_EXPECT_EQ(test, kref_read(&f->old_acg.acg_kref), 1U);
	KUNIT_EXPECT_EQ(test, kref_read(&f->new_acg.acg_kref), 1U);
	/* KUnit owns both ACG storage objects and their remaining references. */
}

struct tm_mode_case {
	const char *name;
	int mode;
	bool dropped;
};

static const struct tm_mode_case tm_modes[] = {
	{ "none", SCST_ACG_BLACK_HOLE_NONE, false },
	{ "commands", SCST_ACG_BLACK_HOLE_CMD, false },
	{ "all", SCST_ACG_BLACK_HOLE_ALL, true },
	{ "data_commands", SCST_ACG_BLACK_HOLE_DATA_CMD, false },
	{ "data_and_tm", SCST_ACG_BLACK_HOLE_DATA_MCMD, true },
};

static void tm_mode_desc(const struct tm_mode_case *p, char *desc)
{
	strscpy(desc, p->name, KUNIT_PARAM_DESC_SIZE);
}

KUNIT_ARRAY_PARAM(tm_mode, tm_modes, tm_mode_desc);

static void tm_check_teardown_commands(struct kunit *test, bool dropped)
{
	static const int functions[] = {
		SCST_NEXUS_LOSS_SESS, SCST_ABORT_ALL_TASKS_SESS,
		SCST_NEXUS_LOSS, SCST_ABORT_ALL_TASKS, SCST_UNREG_SESS_TM,
	};
	struct tm_fixture *f = test->priv;
	unsigned int events = f->events;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(functions); i++) {
		struct scst_mgmt_cmd mcmd = {
			.sess = &f->sess,
			.fn = functions[i],
			.state = SCST_MCMD_STATE_INIT,
		};

		KUNIT_EXPECT_EQ_MSG(test, scst_mgmt_cmd_init(&mcmd), 0,
				    "TM function %d", functions[i]);
		KUNIT_EXPECT_EQ(test, mcmd.state, SCST_MCMD_STATE_EXEC);
		KUNIT_EXPECT_EQ_MSG(test, (bool)mcmd.mcmd_dropped, dropped,
				    "TM function %d", functions[i]);
		KUNIT_EXPECT_PTR_EQ(test, mcmd.mcmd_tgt_dev, NULL);
		KUNIT_EXPECT_PTR_EQ(test, mcmd.cmd_to_abort, NULL);
	}
	KUNIT_EXPECT_EQ(test, f->events - events, (unsigned int)ARRAY_SIZE(functions));
}

static void tm_set_black_hole(struct kunit *test, struct scst_acg *acg, int mode)
{
	char buf[] = { '0' + mode, '\0' };

	KUNIT_EXPECT_EQ(test, __scst_acg_black_hole_store(acg, buf, 1), (ssize_t)0);
	KUNIT_EXPECT_EQ(test, acg->acg_black_hole_type, mode);
}

static void tm_black_hole_test(struct kunit *test)
{
	const struct tm_mode_case *p = test->param_value;
	struct tm_fixture *f = test->priv;

	tm_set_black_hole(test, &f->old_acg, p->mode);
	tm_check_teardown_commands(test, p->dropped);
}

static void tm_reassign(struct kunit *test)
{
	struct tm_fixture *f = test->priv;

	/* Only private objects are reachable; no live activity needs suspension. */
	mutex_lock(&scst_mutex);
	scst_check_reassign_sess(&f->sess);
	mutex_unlock(&scst_mutex);
}

static void tm_reassign_mode_test(struct kunit *test)
{
	const struct tm_mode_case *p = test->param_value;
	struct tm_fixture *f = test->priv;

	/* Cover both entering and leaving the modes which drop TM commands. */
	tm_set_black_hole(test, &f->old_acg, p->dropped ?
			  SCST_ACG_BLACK_HOLE_NONE : SCST_ACG_BLACK_HOLE_ALL);
	f->new_acg.acg_black_hole_type = p->mode;
	tm_check_teardown_commands(test, !p->dropped);
	/* Keep the old policy until the new ACG is installed. */
	f->expected_tm_dropped = !p->dropped;
	f->check_tm_during_reassign = true;
	tm_reassign(test);
	f->check_tm_during_reassign = false;
	KUNIT_ASSERT_PTR_EQ(test, f->sess.acg, &f->new_acg);
	KUNIT_EXPECT_EQ(test, f->allocations, 1U);
	KUNIT_EXPECT_EQ(test, f->links, 1U);
	KUNIT_EXPECT_TRUE(test, list_empty(&f->old_acg.acg_sess_list));
	KUNIT_EXPECT_TRUE(test, list_is_singular(&f->new_acg.acg_sess_list));
	KUNIT_EXPECT_EQ(test, kref_read(&f->old_acg.acg_kref), 1U);
	KUNIT_EXPECT_EQ(test, kref_read(&f->new_acg.acg_kref), 2U);
	tm_check_teardown_commands(test, p->dropped);
	/* Updating the former group must no longer affect this session. */
	tm_set_black_hole(test, &f->old_acg, p->mode);
	tm_set_black_hole(test, &f->old_acg, p->dropped ?
			  SCST_ACG_BLACK_HOLE_NONE : SCST_ACG_BLACK_HOLE_ALL);
	tm_check_teardown_commands(test, p->dropped);
}

static void tm_during_reassign_test(struct kunit *test)
{
	const struct tm_mode_case *p = test->param_value;
	struct tm_fixture *f = test->priv;

	/* The expected TM policy is unambiguous throughout this transition. */
	tm_set_black_hole(test, &f->old_acg, p->mode);
	f->new_acg.acg_black_hole_type = p->mode;
	f->expected_tm_dropped = p->dropped;
	f->check_tm_during_reassign = true;
	tm_reassign(test);
	f->check_tm_during_reassign = false;
	KUNIT_ASSERT_EQ(test, f->allocations, 1U);
	KUNIT_EXPECT_EQ(test, f->links, 1U);
	KUNIT_ASSERT_PTR_EQ(test, f->sess.acg, &f->new_acg);
	tm_check_teardown_commands(test, p->dropped);
}

static void tm_same_acg_test(struct kunit *test)
{
	struct tm_fixture *f = test->priv;

	f->tgt.default_acg = &f->old_acg;
	tm_set_black_hole(test, &f->old_acg, SCST_ACG_BLACK_HOLE_ALL);
	tm_reassign(test);
	KUNIT_EXPECT_PTR_EQ(test, f->sess.acg, &f->old_acg);
	KUNIT_EXPECT_EQ(test, f->allocations, 0U);
	KUNIT_EXPECT_EQ(test, f->links, 0U);
	KUNIT_EXPECT_TRUE(test, list_is_singular(&f->old_acg.acg_sess_list));
	KUNIT_EXPECT_TRUE(test, list_empty(&f->new_acg.acg_sess_list));
	tm_check_teardown_commands(test, true);
}

static void tm_sysfs_mode_test(struct kunit *test)
{
	const struct tm_mode_case *p = test->param_value;
	struct tm_fixture *f = test->priv;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(tm_modes); i++) {
		tm_set_black_hole(test, &f->old_acg, tm_modes[i].mode);
		tm_check_teardown_commands(test, tm_modes[i].dropped);
		tm_set_black_hole(test, &f->old_acg, p->mode);
		tm_check_teardown_commands(test, p->dropped);
		/* Repeating or rejecting a write must preserve the current mode. */
		tm_set_black_hole(test, &f->old_acg, p->mode);
		KUNIT_EXPECT_EQ(test, __scst_acg_black_hole_store(&f->old_acg, "x", 1),
				(ssize_t)-EINVAL);
		KUNIT_EXPECT_EQ(test, __scst_acg_black_hole_store(&f->old_acg, "0", 0),
				(ssize_t)0);
		KUNIT_EXPECT_EQ(test, __scst_acg_black_hole_store(&f->old_acg, NULL, 1),
				(ssize_t)0);
		tm_check_teardown_commands(test, p->dropped);
	}
}

static struct kunit_case tm_cases[] = {
	KUNIT_CASE_PARAM(tm_black_hole_test, tm_mode_gen_params),
	KUNIT_CASE_PARAM(tm_sysfs_mode_test, tm_mode_gen_params),
	KUNIT_CASE_PARAM(tm_reassign_mode_test, tm_mode_gen_params),
	KUNIT_CASE(tm_same_acg_test),
	KUNIT_CASE_PARAM(tm_during_reassign_test, tm_mode_gen_params),
	{}
};

scst_kunit_suite(scst_tm_suite, "TM", "-acg",
		 .init = tm_test_init,
		 .exit = tm_test_exit,
		 .test_cases = tm_cases,
);
