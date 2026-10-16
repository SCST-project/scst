// SPDX-License-Identifier: GPL-2.0-only
#include <linux/scatterlist.h>
#include "../../scst_kunit.h"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif

#define CAPACITY_OLD_SHIFT 12

struct capacity_shift_case {
	const char *name;
	int size;
	int shift;
};

static const struct capacity_shift_case capacity_shift_cases[] = {
	{ "zero_means_default", 0, 9 },
	{ "512", 512, 9 },
	{ "4096", 4096, 12 },
	{ "65536", 65536, 16 },
	{ "below_512", 4, -1 },
	{ "not_power_of_two", 768, -1 },
	{ "corrupt_0x30392b30", 809052976, -1 },
};

static void capacity_shift_desc(const struct capacity_shift_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(capacity_shift, capacity_shift_cases, capacity_shift_desc);

static void capacity_shift_test(struct kunit *test)
{
	const struct capacity_shift_case *p = test->param_value;

	KUNIT_EXPECT_EQ(test, scst_calc_block_shift(p->size), p->shift);
}

struct capacity_reply_case {
	const char *name;
	bool rc16;
	bool split;
	u32 block_size;
	/* Expected block shift, or -1 if the reply must be rejected. */
	int shift;
};

static const struct capacity_reply_case capacity_reply_cases[] = {
	{ "rc10_same", false, false, 4096, 12 },
	{ "rc10_change_to_512", false, false, 512, 9 },
	{ "rc10_split_same", false, true, 4096, 12 },
	{ "rc10_split_change_to_512", false, true, 512, 9 },
	{ "rc10_zero", false, false, 0, -1 },
	{ "rc10_invalid", false, false, 809052976, -1 },
	{ "rc10_split_zero", false, true, 0, -1 },
	{ "rc10_split_invalid", false, true, 809052976, -1 },
	{ "rc16_same", true, false, 4096, 12 },
	{ "rc16_change_to_512", true, false, 512, 9 },
	{ "rc16_split_same", true, true, 4096, 12 },
	{ "rc16_split_change_to_512", true, true, 512, 9 },
	{ "rc16_zero", true, false, 0, -1 },
	{ "rc16_invalid", true, false, 809052976, -1 },
	{ "rc16_split_zero", true, true, 0, -1 },
	{ "rc16_split_invalid", true, true, 809052976, -1 },
};

static void capacity_reply_desc(const struct capacity_reply_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(capacity_reply, capacity_reply_cases, capacity_reply_desc);

static void capacity_set_block_shift(struct scst_cmd *cmd, int shift)
{
	cmd->dev->block_shift = shift;
	cmd->dev->block_size = 1 << shift;
}

/*
 * Pass a backend READ CAPACITY reply through scst_block_generic_dev_done().
 * A split reply has its block length in the second SG entry.
 */
static void capacity_reply_test(struct kunit *test)
{
	const struct capacity_reply_case *p = test->param_value;
	unsigned int len = p->rc16 ? 32 : 8, off = p->rc16 ? 8 : 4;
	unsigned int first = p->split ? off : len;
	struct scst_device *dev;
	struct scst_cmd *cmd;
	struct scatterlist *sg;
	u8 *reply, *buf[2];
	u8 *sense;

	cmd = kunit_kzalloc(test, sizeof(*cmd), GFP_KERNEL);
	dev = kunit_kzalloc(test, sizeof(*dev), GFP_KERNEL);
	sg = kunit_kcalloc(test, 2, sizeof(*sg), GFP_KERNEL);
	reply = kunit_kzalloc(test, len, GFP_KERNEL);
	buf[0] = kunit_kzalloc(test, len, GFP_KERNEL);
	buf[1] = kunit_kzalloc(test, len, GFP_KERNEL);
	sense = kunit_kzalloc(test, SCST_SENSE_BUFFERSIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, cmd);
	KUNIT_ASSERT_NOT_NULL(test, dev);
	KUNIT_ASSERT_NOT_NULL(test, sg);
	KUNIT_ASSERT_NOT_NULL(test, reply);
	KUNIT_ASSERT_NOT_NULL(test, buf[0]);
	KUNIT_ASSERT_NOT_NULL(test, buf[1]);
	KUNIT_ASSERT_NOT_NULL(test, sense);

	reply[off - 1] = 0xff; /* Last LBA */
	put_unaligned_be32(p->block_size, &reply[off]);
	memcpy(buf[0], reply, first);
	memcpy(buf[1], reply + first, len - first);
	sg_init_table(sg, p->split ? 2 : 1);
	sg_set_buf(&sg[0], buf[0], first);
	if (p->split)
		sg_set_buf(&sg[1], buf[1], len - first);

	dev->virt_name = "kunit-capacity";
	dev->block_shift = CAPACITY_OLD_SHIFT;
	dev->block_size = 1 << CAPACITY_OLD_SHIFT;
	cmd->dev = dev;
	cmd->cdb = cmd->cdb_buf;
	cmd->cdb[0] = p->rc16 ? SERVICE_ACTION_IN_16 : READ_CAPACITY;
	cmd->cdb[1] = p->rc16 ? SAI_READ_CAPACITY_16 : 0;
	cmd->op_name = p->rc16 ? "READ CAPACITY(16)" : "READ CAPACITY";
	cmd->sense = sense;
	cmd->sense_buflen = SCST_SENSE_BUFFERSIZE;
	cmd->completed = 1;
	cmd->status = SAM_STAT_GOOD;
	cmd->data_direction = SCST_DATA_READ;
	cmd->bufflen = len;
	cmd->resp_data_len = len;
	cmd->sg = sg;
	cmd->sg_cnt = p->split ? 2 : 1;

	KUNIT_EXPECT_EQ(test, scst_block_generic_dev_done(cmd, capacity_set_block_shift),
			SCST_CMD_STATE_DEFAULT);
	scst_kunit_log(test, "%s: block length %u, status 0x%x, shift %d", p->name,
		       p->block_size, cmd->status, dev->block_shift);

	/* The reply must reach the initiator unchanged, if at all. */
	KUNIT_EXPECT_MEMEQ(test, buf[0], reply, first);
	KUNIT_EXPECT_MEMEQ(test, buf[1], reply + first, len - first);

	if (p->shift >= 0) {
		KUNIT_EXPECT_EQ(test, cmd->status, SAM_STAT_GOOD);
		KUNIT_EXPECT_EQ(test, cmd->resp_data_len, (int)len);
		KUNIT_EXPECT_EQ(test, cmd->data_direction, SCST_DATA_READ);
		KUNIT_EXPECT_EQ(test, dev->block_shift, p->shift);
		KUNIT_EXPECT_EQ(test, dev->block_size, 1 << p->shift);
		return;
	}

	/* An invalid block length leaves the geometry alone and fails the command. */
	KUNIT_EXPECT_EQ(test, dev->block_shift, CAPACITY_OLD_SHIFT);
	KUNIT_EXPECT_EQ(test, dev->block_size, 1 << CAPACITY_OLD_SHIFT);
	KUNIT_EXPECT_EQ(test, cmd->status, SAM_STAT_CHECK_CONDITION);
	KUNIT_EXPECT_EQ(test, cmd->resp_data_len, 0);
	KUNIT_EXPECT_EQ(test, cmd->data_direction, SCST_DATA_NONE);
	KUNIT_EXPECT_TRUE(test, !!cmd->is_send_status);
	KUNIT_EXPECT_TRUE(test, scst_analyze_sense(cmd->sense, cmd->sense_valid_len,
						   SCST_SENSE_ALL_VALID,
						   SCST_LOAD_SENSE(scst_sense_internal_failure)));
}

static struct kunit_case capacity_cases[] = {
	KUNIT_CASE_PARAM(capacity_shift_test, capacity_shift_gen_params),
	KUNIT_CASE_PARAM(capacity_reply_test, capacity_reply_gen_params),
	{}
};

scst_kunit_suite(capacity_suite, "LIB", "-capacity",
		 .test_cases = capacity_cases,
);
