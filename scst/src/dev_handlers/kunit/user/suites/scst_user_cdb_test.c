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

static void user_cdb_tail(struct kunit *test)
{
	struct scst_cmd *cmd;
	u8 *long_cdb;
	unsigned int i;

	cmd = kunit_kzalloc(test, sizeof(*cmd), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, cmd);
	cmd->cdb = cmd->cdb_buf;
	for (i = 0; i <= SCST_MAX_CDB_SIZE; i++) {
		cmd->cdb_len = i;
		KUNIT_EXPECT_PTR_EQ(test, dev_user_ext_cdb(cmd), NULL);
	}

	long_cdb = kunit_kzalloc(test, 32, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, long_cdb);
	cmd->cdb = long_cdb;
	/* A valid external CDB must not trip the extra-check assertion. */
	for (i = SCST_MAX_CDB_SIZE + 1; i <= 32; i++) {
		cmd->cdb_len = i;
		KUNIT_EXPECT_PTR_EQ(test, dev_user_ext_cdb(cmd), long_cdb + SCST_MAX_CDB_SIZE);
	}
}

struct user_cdb_ref_case {
	const char *name;
	unsigned int state;
	bool sent;
	bool background;
	bool no_cmd;
	bool missing;
	bool dead;
	int error;
};

static const struct user_cdb_ref_case user_cdb_ref_cases[] = {
	{ .name = "sent", .state = UCMD_STATE_EXECING, .sent = true },
	{ .name = "background", .state = UCMD_STATE_EXECING, .background = true },
	{ .name = "parsing", .state = UCMD_STATE_PARSING, .sent = true },
	{ .name = "no_core_command", .state = UCMD_STATE_EXECING, .sent = true,
	  .no_cmd = true, .error = -EINVAL },
	{ .name = "not_published", .state = UCMD_STATE_EXECING, .error = -EINVAL },
	{ .name = "finished", .state = UCMD_STATE_EXECING + 1, .sent = true,
	  .error = -EINVAL },
	{ .name = "missing_handle", .missing = true, .error = -ESRCH },
	{ .name = "dying_command", .dead = true, .error = -ESRCH },
};

static void user_cdb_ref_desc(const struct user_cdb_ref_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(user_cdb_ref, user_cdb_ref_cases, user_cdb_ref_desc);

static void user_cdb_unexpected_release(struct kref *ref)
{
	KUNIT_FAIL(kunit_get_current_test(), "dropped the fixture's retained reference");
}

static void user_cdb_references(struct kunit *test)
{
	const struct user_cdb_ref_case *p = test->param_value;
	struct scst_user_dev *dev;
	struct scst_user_cmd *ucmd, *result;
	struct scst_cmd *cmd, *selected;
	unsigned int i;

	dev = kunit_kzalloc(test, sizeof(*dev), GFP_KERNEL);
	ucmd = kunit_kzalloc(test, sizeof(*ucmd), GFP_KERNEL);
	cmd = kunit_kzalloc(test, sizeof(*cmd), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, dev);
	KUNIT_ASSERT_NOT_NULL(test, ucmd);
	KUNIT_ASSERT_NOT_NULL(test, cmd);
	spin_lock_init(&dev->udev_cmd_threads.cmd_list_lock);
	for (i = 0; i < ARRAY_SIZE(dev->ucmd_hash); i++)
		INIT_LIST_HEAD(&dev->ucmd_hash[i]);
	ucmd->dev = dev;
	ucmd->cmd = p->no_cmd ? NULL : cmd;
	ucmd->h = 1;
	ucmd->state = p->state;
	ucmd->sent_to_user = p->sent;
	ucmd->background_exec = p->background;
	/* The fixture retains one reference; a dying hash entry has zero. */
	if (!p->dead)
		kref_init(&ucmd->ucmd_ref);
	kref_init(&cmd->cmd_ref);
	list_add_tail(&ucmd->hash_list_entry, &dev->ucmd_hash[ucmd->h]);

	selected = cmd;
	result = dev_user_ext_cdb_get(dev, p->missing ? 2 : ucmd->h, &selected);
	KUNIT_EXPECT_EQ(test, kref_read(&ucmd->ucmd_ref), p->dead ? 0 : (p->error ? 1 : 2));
	KUNIT_EXPECT_EQ(test, kref_read(&cmd->cmd_ref), p->error ? 1 : 2);
	if (p->error) {
		if (IS_ERR(result))
			KUNIT_EXPECT_EQ(test, PTR_ERR(result), (long)p->error);
		else
			KUNIT_FAIL(test, "invalid CDB lookup unexpectedly succeeded");
		KUNIT_EXPECT_PTR_EQ(test, selected, NULL);
	} else {
		KUNIT_ASSERT_FALSE(test, IS_ERR(result));
		KUNIT_EXPECT_PTR_EQ(test, result, ucmd);
		KUNIT_EXPECT_PTR_EQ(test, selected, cmd);
		kref_put(&cmd->cmd_ref, user_cdb_unexpected_release);
		kref_put(&ucmd->ucmd_ref, user_cdb_unexpected_release);
		KUNIT_EXPECT_EQ(test, kref_read(&cmd->cmd_ref), 1);
		KUNIT_EXPECT_EQ(test, kref_read(&ucmd->ucmd_ref), 1);
	}
	list_del_init(&ucmd->hash_list_entry);
}

static struct kunit_case user_cdb_cases[] = {
	KUNIT_CASE(user_cdb_tail),
	KUNIT_CASE_PARAM(user_cdb_references, user_cdb_ref_gen_params),
	{}
};

scst_kunit_suite(user_cdb_suite, "USER", "-cdb",
		 .test_cases = user_cdb_cases,
);
