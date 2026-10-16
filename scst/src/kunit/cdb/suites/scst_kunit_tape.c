// SPDX-License-Identifier: GPL-2.0-only
#include "../../scst_kunit.h"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "../../../scst_priv.h"
#include "../../../scst_targ_test.h"

struct tape_test_fixture {
	struct scst_cmd cmd;
	struct scst_device dev;
	u8 sense[SCST_SENSE_BUFFERSIZE];
};

static int tape_test_init(struct kunit *test)
{
	struct tape_test_fixture *f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);

	if (!f)
		return -ENOMEM;
	test->priv = f;
	f->dev.virt_name = "kunit-tape";
	f->dev.type = TYPE_TAPE;
	/* Tape devices do not use block_shift. */
	f->dev.block_shift = -1;
	f->cmd.dev = &f->dev;
	f->cmd.cdb = f->cmd.cdb_buf;
	f->cmd.sense = f->sense;
	f->cmd.sense_buflen = sizeof(f->sense);
	return 0;
}

/* Decode a tape READ(6) or WRITE(6) CDB and fill in the default lengths. */
static void tape_set_cdb(struct kunit *test, u8 opcode, bool fixed, u32 length)
{
	struct tape_test_fixture *f = test->priv;
	struct scst_cmd *cmd = &f->cmd;

	cmd->cdb[0] = opcode;
	cmd->cdb[1] = fixed;
	put_unaligned_be24(length, &cmd->cdb[2]);
	KUNIT_ASSERT_EQ(test, scst_get_cdb_info(cmd), 0);
	KUNIT_ASSERT_TRUE(test, !!(cmd->op_flags & SCST_TRANSFER_LEN_TYPE_FIXED));
	KUNIT_ASSERT_EQ(test, cmd->bufflen, (int)length);
}

struct tape_parse_case {
	const char *name;
	u8 opcode;
	u32 block_size;
	bool fixed;
	u32 length;
	/* Override the decoded lengths, if nonzero. */
	s64 data_len;
	int out_bufflen;
	bool rejected;
};

static const struct tape_parse_case tape_parse_cases[] = {
	{ "read_512", READ_6, 512, true, 3 },
	{ "read_1536", READ_6, 1536, true, 3 },
	{ "write_1536", WRITE_6, 1536, true, 3 },
	{ "read_80", READ_6, 80, true, 2 },
	{ "read_variable", READ_6, 512, false, 1000 },
	{ "write_variable_no_block_size", WRITE_6, 0, false, 1000 },
	{ "read_fixed_no_block_size", READ_6, 0, true, 2, .rejected = true },
	{ "read_bufflen_limit", READ_6, 1536, true, INT_MAX / 1536 },
	{ "read_bufflen_overflow", READ_6, 1536, true, INT_MAX / 1536 + 1,
	  .rejected = true },
	{ "read_data_len_limit", READ_6, 512, true, 1, LLONG_MAX / 512 },
	{ "read_data_len_overflow", READ_6, 512, true, 1, LLONG_MAX / 512 + 1,
	  .rejected = true },
	{ "out_bufflen_limit", READ_6, 512, true, 1, .out_bufflen = INT_MAX / 512 },
	{ "out_bufflen_overflow", READ_6, 512, true, 1, .out_bufflen = INT_MAX / 512 + 1,
	  .rejected = true },
};

static void tape_parse_desc(const struct tape_parse_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(tape_parse, tape_parse_cases, tape_parse_desc);

static void tape_parse_test(struct kunit *test)
{
	const struct tape_parse_case *p = test->param_value;
	struct tape_test_fixture *f = test->priv;
	struct scst_cmd *cmd = &f->cmd;
	u32 factor = p->fixed ? p->block_size : 1;
	s64 data_len;
	int bufflen, out_bufflen;

	f->dev.block_size = p->block_size;
	tape_set_cdb(test, p->opcode, p->fixed, p->length);
	if (p->data_len)
		cmd->data_len = p->data_len;
	if (p->out_bufflen)
		cmd->out_bufflen = p->out_bufflen;
	bufflen = cmd->bufflen;
	data_len = cmd->data_len;
	out_bufflen = cmd->out_bufflen;

	if (p->rejected) {
		bool sense_valid;

		KUNIT_EXPECT_EQ(test, scst_tape_generic_parse(cmd), -EINVAL);
		KUNIT_EXPECT_EQ(test, cmd->status, SAM_STAT_CHECK_CONDITION);
		sense_valid = scst_analyze_sense(cmd->sense, cmd->sense_valid_len,
						 SCST_SENSE_ALL_VALID,
						 SCST_LOAD_SENSE(scst_sense_block_out_range_error));
		KUNIT_EXPECT_TRUE(test, sense_valid);
		KUNIT_EXPECT_EQ(test, cmd->bufflen, bufflen);
		KUNIT_EXPECT_EQ(test, cmd->data_len, data_len);
		KUNIT_EXPECT_EQ(test, cmd->out_bufflen, out_bufflen);
		return;
	}

	KUNIT_EXPECT_EQ(test, scst_tape_generic_parse(cmd), 0);
	KUNIT_EXPECT_EQ(test, cmd->status, 0);
	KUNIT_EXPECT_EQ(test, cmd->bufflen, (int)(bufflen * factor));
	KUNIT_EXPECT_EQ(test, cmd->data_len, data_len * factor);
	KUNIT_EXPECT_EQ(test, cmd->out_bufflen, (int)(out_bufflen * factor));
}

struct tape_residual_case {
	const char *name;
	int type;
	u32 block_size;
	int block_shift;
	bool fixed;
	u32 length;
	int write_len;
	bool aligned;
};

static const struct tape_residual_case tape_residual_cases[] = {
	{ "tape_512_two_of_three_blocks", TYPE_TAPE, 512, -1, true, 3, 1024, true },
	{ "tape_512_partial_block", TYPE_TAPE, 512, -1, true, 3, 1000, false },
	{ "tape_1536_two_blocks", TYPE_TAPE, 1536, -1, true, 3, 3072, true },
	{ "tape_1536_partial_block", TYPE_TAPE, 1536, -1, true, 3, 2048, false },
	{ "tape_80_two_blocks", TYPE_TAPE, 80, -1, true, 3, 160, true },
	{ "tape_variable", TYPE_TAPE, 512, -1, false, 2000, 1000, true },
	{ "disk_512_two_blocks", TYPE_DISK, 512, 9, false, 3, 1024, true },
	{ "disk_512_partial_block", TYPE_DISK, 512, 9, false, 3, 1000, false },
	{ "disk_4096_partial_block", TYPE_DISK, 4096, 12, false, 3, 512, false },
};

static void tape_residual_desc(const struct tape_residual_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(tape_residual, tape_residual_cases, tape_residual_desc);

/* A short WRITE(6) must be judged by the block size, not by block_shift. */
static void tape_residual_test(struct kunit *test)
{
	const struct tape_residual_case *p = test->param_value;
	struct tape_test_fixture *f = test->priv;
	struct scst_cmd *cmd = &f->cmd;

	f->dev.type = p->type;
	f->dev.block_size = p->block_size;
	f->dev.block_shift = p->block_shift;
	if (p->type == TYPE_TAPE) {
		tape_set_cdb(test, WRITE_6, p->fixed, p->length);
	} else {
		cmd->cdb[0] = WRITE_6;
		cmd->cdb[4] = p->length;
		KUNIT_ASSERT_EQ(test, scst_get_cdb_info(cmd), 0);
	}
	cmd->write_len = p->write_len;
	KUNIT_EXPECT_EQ(test, scst_write_len_block_aligned(cmd), p->aligned);
}

static void tape_residual_no_block_size_test(struct kunit *test)
{
	struct tape_test_fixture *f = test->priv;
	struct scst_cmd *cmd = &f->cmd;

	tape_set_cdb(test, WRITE_6, true, 3);
	cmd->write_len = 1024;
	KUNIT_EXPECT_FALSE(test, scst_write_len_block_aligned(cmd));
}

static struct kunit_case tape_cases[] = {
	KUNIT_CASE_PARAM(tape_parse_test, tape_parse_gen_params),
	KUNIT_CASE_PARAM(tape_residual_test, tape_residual_gen_params),
	KUNIT_CASE(tape_residual_no_block_size_test),
	{}
};

scst_kunit_suite(tape_suite, "CDB", "-tape",
		 .init = tape_test_init,
		 .test_cases = tape_cases,
);
