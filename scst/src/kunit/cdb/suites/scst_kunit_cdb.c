// SPDX-License-Identifier: GPL-2.0-only
#include "../../scst_kunit.h"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "../../../scst_priv.h"
#include "../../../scst_targ_test.h"

struct cdb_test_fixture {
	struct scst_cmd cmd;
	struct scst_device dev;
	struct scst_session session;
	struct scst_tgt_dev tgt_dev;
	u8 sense[SCST_SENSE_BUFFERSIZE];
};

static int cdb_test_parse(struct scst_cmd *cmd)
{
	int ret = cmd->dev->type == TYPE_TAPE ? scst_tape_generic_parse(cmd) :
		  scst_sbc_generic_parse(cmd);

	return ret ? SCST_CMD_STATE_PRE_XMIT_RESP1 : SCST_CMD_STATE_DEFAULT;
}

static struct scst_dev_type cdb_test_handler = {
	.name = "kunit-cdb",
	.parse = cdb_test_parse,
};

static struct scst_tgt_template cdb_test_target = {
	.name = "kunit-cdb",
};

static int cdb_test_init(struct kunit *test)
{
	struct cdb_test_fixture *f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);

	if (!f)
		return -ENOMEM;
	test->priv = f;
	f->dev.virt_name = "kunit-cdb";
	f->dev.handler = &cdb_test_handler;
	f->dev.block_shift = 9;
	f->dev.block_size = 512;
	f->tgt_dev.dev = &f->dev;
	f->tgt_dev.tgtt = &cdb_test_target;
	f->tgt_dev.sess = &f->session;
	f->cmd.tgt_dev = &f->tgt_dev;
	f->cmd.dev = &f->dev;
	f->cmd.devt = &cdb_test_handler;
	f->cmd.tgtt = &cdb_test_target;
	f->cmd.sess = &f->session;
	f->cmd.cdb = f->cmd.cdb_buf;
	f->cmd.sense = f->sense;
	f->cmd.sense_buflen = sizeof(f->sense);
	f->cmd.state = SCST_CMD_STATE_PARSE;
	f->cmd.resp_data_len = -1;
	return 0;
}

struct cdb_decode_case {
	const char *name;
	u8 cdb[16];
	int type;
	int direction;
	unsigned int length;
	u64 lba;
	bool blocks;
	bool unknown;
	bool large_blocks;
};

static const struct cdb_decode_case cdb_decode_cases[] = {
	{ "rewind", { 0x01 }, TYPE_TAPE, SCST_DATA_NONE },
	{ "rewind_immediate", { 0x01, 0x01 }, TYPE_TAPE, SCST_DATA_NONE },
	{ "rewind_not_disk_opcode", { 0x01 }, TYPE_DISK, .unknown = true },
	{ "tape_space", { 0x11, 0, 0, 0, 3 }, TYPE_TAPE, SCST_DATA_NONE },
	{ "write_filemarks", { 0x10, 0, 0, 0, 1 }, TYPE_TAPE, SCST_DATA_NONE },
	{ "erase", { 0x19 }, TYPE_TAPE, SCST_DATA_NONE },
	{ "load_tape", { 0x1b, 0, 0, 0, 1 }, TYPE_TAPE, SCST_DATA_NONE },
	{ "test_unit_ready", { 0x00 }, TYPE_DISK, SCST_DATA_NONE },
	{ "prevent_removal", { 0x1e, 0, 0, 0, 1 }, TYPE_TAPE, SCST_DATA_NONE },
	{ "start_stop", { 0x1b, 0, 0, 0, 1 }, TYPE_DISK, SCST_DATA_NONE },
	{ "inquiry", { 0x12, 0, 0, 0, 36 }, TYPE_DISK, SCST_DATA_READ, 36 },
	{ "inquiry_zero_allocation", { 0x12 }, TYPE_DISK, SCST_DATA_READ },
	{ "request_sense", { 0x03, 0, 0, 0, 18 }, TYPE_DISK, SCST_DATA_READ, 18 },
	{ "mode_sense_6", { 0x1a, 0, 0, 0, 64 }, TYPE_DISK, SCST_DATA_READ, 64 },
	{ "mode_select_6", { 0x15, 0x10, 0, 0, 12 }, TYPE_DISK, SCST_DATA_WRITE, 12 },
	{ "read_6_zero_means_256", { 0x08 }, TYPE_DISK, SCST_DATA_READ, 256, .blocks = true },
	{ "read_6_lba", { 0x08, 0x1f, 0x23, 0x45, 2 }, TYPE_DISK, SCST_DATA_READ,
	  2, 0x1f2345, .blocks = true },
	{ "write_6", { 0x0a, 0, 0, 1, 3 }, TYPE_DISK, SCST_DATA_WRITE, 3, 1, .blocks = true },
	{ "read_10_zero", { 0x28 }, TYPE_DISK, SCST_DATA_READ, .blocks = true },
	{ "read_10", { 0x28, 0, 0x12, 0x34, 0x56, 0x78, 0, 0, 2 },
	  TYPE_DISK, SCST_DATA_READ, 2, 0x12345678, .blocks = true },
	{ "write_10_4k", { 0x2a, 0, 0, 0, 0, 1, 0, 0, 2 }, TYPE_DISK,
	  SCST_DATA_WRITE, 2, 1, .blocks = true, .large_blocks = true },
	{ "read_12", { 0xa8, 0, 0, 0, 0, 1, 0, 0, 0, 3 }, TYPE_DISK,
	  SCST_DATA_READ, 3, 1, .blocks = true },
	{ "read_16_large_lba", { 0x88, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1 },
	  TYPE_DISK, SCST_DATA_READ, 1, 0x100000002ULL, .blocks = true },
	{ "write_16_zero", { 0x8a }, TYPE_DISK, SCST_DATA_WRITE, .blocks = true },
};

static void cdb_decode_desc(const struct cdb_decode_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(cdb_decode, cdb_decode_cases, cdb_decode_desc);

static void cdb_decode_test(struct kunit *test)
{
	const struct cdb_decode_case *p = test->param_value;
	struct cdb_test_fixture *f = test->priv;
	struct scst_cmd *cmd = &f->cmd;
	unsigned int block_size = p->large_blocks ? 4096 : 512;
	int ret;

	memcpy(cmd->cdb, p->cdb, sizeof(p->cdb));
	f->dev.type = p->type;
	f->dev.block_size = block_size;
	f->dev.block_shift = p->large_blocks ? 12 : 9;
	ret = scst_get_cdb_info(cmd);
	if (p->unknown) {
		KUNIT_EXPECT_LT(test, ret, 0);
		KUNIT_EXPECT_FALSE(test, !!(cmd->op_flags & SCST_INFO_VALID));
		KUNIT_EXPECT_TRUE(test, !!(cmd->op_flags & SCST_LBA_NOT_VALID));
		return;
	}
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, !!(cmd->op_flags & SCST_INFO_VALID));
	KUNIT_EXPECT_EQ(test, cmd->data_direction, p->direction);
	KUNIT_EXPECT_EQ(test, cmd->bufflen, (int)p->length);
	if (p->blocks) {
		KUNIT_EXPECT_EQ(test, cmd->lba, p->lba);
		KUNIT_ASSERT_EQ(test, scst_sbc_generic_parse(cmd), 0);
		KUNIT_EXPECT_EQ(test, cmd->bufflen, (int)(p->length * block_size));
		KUNIT_EXPECT_EQ(test, cmd->data_len, (s64)p->length * block_size);
	}
	KUNIT_EXPECT_EQ(test, cmd->status, 0);
}

struct cdb_direction_case {
	const char *name;
	u8 opcode;
	int direction;
	unsigned int length;
	bool invalid;
};

static const struct cdb_direction_case cdb_direction_cases[] = {
	{ "rewind_without_data", 0x01, SCST_DATA_NONE },
	{ "rewind_read_flag", 0x01, SCST_DATA_READ, 0, true },
	{ "rewind_write_flag", 0x01, SCST_DATA_WRITE, 0, true },
	{ "rewind_unexpected_transfer", 0x01, SCST_DATA_READ, 512, true },
	{ "tur_read_exception", 0x00, SCST_DATA_READ },
	{ "tur_without_data", 0x00, SCST_DATA_NONE },
	{ "tur_write_rejected", 0x00, SCST_DATA_WRITE, 512, true },
	{ "zero_read_10_no_transfer", 0x28, SCST_DATA_NONE },
	{ "zero_read_10_read_flag", 0x28, SCST_DATA_READ },
	{ "zero_write_10_no_transfer", 0x2a, SCST_DATA_NONE },
};

static void cdb_direction_desc(const struct cdb_direction_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(cdb_direction, cdb_direction_cases, cdb_direction_desc);

static void cdb_direction_test(struct kunit *test)
{
	const struct cdb_direction_case *p = test->param_value;
	struct cdb_test_fixture *f = test->priv;
	struct scst_cmd *cmd = &f->cmd;
	bool invalid = p->invalid && !IS_ENABLED(CONFIG_SCST_USE_EXPECTED_VALUES);

	f->dev.type = p->opcode == 0x01 ? TYPE_TAPE : TYPE_DISK;
	cmd->cdb[0] = p->opcode;
	scst_cmd_set_expected(cmd, p->direction, p->length);
	KUNIT_ASSERT_EQ(test, scst_get_cdb_info(cmd), 0);
	scst_kunit_log(test, "%s: opcode=0x%02x direction=%d expected=%d length=%u",
		       p->name, p->opcode, cmd->data_direction, p->direction, p->length);
	scst_parse_cmd(cmd);
	KUNIT_EXPECT_EQ(test, cmd->status, invalid ? SAM_STAT_CHECK_CONDITION : 0);
	if (invalid) {
		bool sense_valid;

		KUNIT_EXPECT_TRUE(test, !!cmd->completed);
		sense_valid = scst_analyze_sense(cmd->sense, cmd->sense_valid_len,
						 SCST_SENSE_ALL_VALID,
						 SCST_LOAD_SENSE(scst_sense_invalid_message));
		KUNIT_EXPECT_TRUE(test, sense_valid);
	} else {
		KUNIT_EXPECT_EQ(test, cmd->state, SCST_CMD_STATE_PREPARE_SPACE);
		KUNIT_EXPECT_EQ(test, cmd->bufflen,
				IS_ENABLED(CONFIG_SCST_USE_EXPECTED_VALUES) ? (int)p->length : 0);
		if (!cmd->bufflen)
			KUNIT_EXPECT_EQ(test, cmd->data_direction, SCST_DATA_NONE);
	}
}

static struct kunit_case cdb_cases[] = {
	KUNIT_CASE_PARAM(cdb_decode_test, cdb_decode_gen_params),
	KUNIT_CASE_PARAM(cdb_direction_test, cdb_direction_gen_params),
	{}
};

scst_kunit_suite(cdb_suite, "CDB", "",
		 .init = cdb_test_init,
		 .test_cases = cdb_cases,
);
