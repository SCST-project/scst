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

static struct kunit_case user_cdb_cases[] = {
	KUNIT_CASE(user_cdb_tail),
	{}
};

scst_kunit_suite(user_cdb_suite, "USER", "-cdb",
		 .test_cases = user_cdb_cases,
);
