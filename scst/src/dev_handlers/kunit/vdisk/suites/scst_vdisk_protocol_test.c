// SPDX-License-Identifier: GPL-2.0-only
#include "../scst_vdisk_fixture.h"

struct vdisk_cdb_case {
	const char *name;
	u8 opcode;
	u8 subcode;
	u8 shift;
	u64 lba;
	bool fua;
};

static const struct vdisk_cdb_case vdisk_cdb_cases[] = {
	{ "write10_fua", WRITE_10, 0, 9, 16, true },
	{ "write10_plain", WRITE_10, 0, 12, 16 },
	{ "write12_fua", WRITE_12, 0, 12, 16, true },
	{ "write12_plain", WRITE_12, 0, 9, 16 },
	{ "write16_fua_high_lba", WRITE_16, 0, 9, 0x100000001ULL, true },
	{ "write16_plain", WRITE_16, 0, 12, 16 },
	{ "write32_fua_high_lba", VARIABLE_LENGTH_CMD, SUBCODE_WRITE_32, 12,
	  0x100000001ULL, true },
	{ "write32_plain", VARIABLE_LENGTH_CMD, SUBCODE_WRITE_32, 9, 16 },
	{ "read16_fua_is_not_write_fua", READ_16, 0, 9, 16, true },
};

static void vdisk_cdb_desc(const struct vdisk_cdb_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(vdisk_cdb, vdisk_cdb_cases, vdisk_cdb_desc);

static void vdisk_cdb_test(struct kunit *test)
{
	const struct vdisk_cdb_case *p = test->param_value;
	struct vdisk_test_fixture *f = test->priv;
	u8 *cdb = f->cmd.cdb;
	loff_t offset = p->lba << p->shift;

	f->dev.block_shift = p->shift;
	f->dev.block_size = 1U << p->shift;
	f->vdev.file_size = offset + 2 * f->dev.block_size;
	cdb[0] = p->opcode;
	cdb[1] = p->fua ? 8 : 0;
	switch (p->opcode) {
	case WRITE_10:
		put_unaligned_be32(p->lba, &cdb[2]);
		put_unaligned_be16(2, &cdb[7]);
		break;
	case WRITE_12:
		put_unaligned_be32(p->lba, &cdb[2]);
		put_unaligned_be32(2, &cdb[6]);
		break;
	case VARIABLE_LENGTH_CMD:
		cdb[1] = 0;
		cdb[7] = 24;
		cdb[9] = p->subcode;
		cdb[10] = p->fua ? 8 : 0;
		put_unaligned_be64(p->lba, &cdb[12]);
		put_unaligned_be32(2, &cdb[28]);
		/* The core permits 32-byte read/write CDBs only for DIF type 2. */
		f->dev.dev_dif_type = 2;
		break;
	default:
		put_unaligned_be64(p->lba, &cdb[2]);
		put_unaligned_be32(2, &cdb[10]);
		break;
	}

	KUNIT_ASSERT_EQ(test, scst_get_cdb_info(&f->cmd), 0);
	KUNIT_ASSERT_EQ(test, scst_sbc_generic_parse(&f->cmd), 0);
	/* Poison the output so a parser that leaves it untouched cannot pass. */
	f->params.loff = -1;
	f->params.fua = !p->fua;
	KUNIT_ASSERT_TRUE(test, vdisk_parse_offset(&f->params, &f->cmd));
	KUNIT_EXPECT_EQ(test, f->params.loff, offset);
	KUNIT_EXPECT_EQ(test, !!f->params.fua, p->fua && p->opcode != READ_16);
	KUNIT_EXPECT_EQ(test, f->cmd.data_len, (s64)2 * f->dev.block_size);
	KUNIT_EXPECT_EQ(test, f->cmd.status, SAM_STAT_GOOD);
}

struct vdisk_cache_case {
	const char *name;
	bool sixteen;
	bool immed;
	bool direct;
	u8 shift;
	u32 blocks;
	int error;
};

static const struct vdisk_cache_case vdisk_cache_cases[] = {
	{ "cache10_range", .shift = 9, .blocks = 2 },
	{ "cache16_range_4k", .sixteen = true, .shift = 12, .blocks = 2 },
	{ "cache10_to_end", .shift = 9 },
	{ "cache16_to_end", .sixteen = true, .shift = 12 },
	{ "cache10_immed", .immed = true, .shift = 9, .blocks = 2 },
	{ "cache16_immed_direct", .sixteen = true, .immed = true,
	  .direct = true, .shift = 12 },
	{ "cache10_error", .shift = 9, .blocks = 2, .error = -EIO },
	{ "cache16_enomem", .sixteen = true, .shift = 9, .blocks = 2, .error = -ENOMEM },
	{ "immed_error_after_good", .sixteen = true, .immed = true,
	  .shift = 9, .blocks = 2, .error = -EIO },
};

static void vdisk_cache_desc(const struct vdisk_cache_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(vdisk_cache, vdisk_cache_cases, vdisk_cache_desc);

static void vdisk_cache_test(struct kunit *test)
{
	const struct vdisk_cache_case *p = test->param_value;
	struct vdisk_test_fixture *f = test->priv;
	u8 *cdb = f->cmd.cdb;
	loff_t start = 16LL << p->shift;
	loff_t end = (p->blocks ? 16LL + p->blocks : 32LL) << p->shift;

	f->dev.block_shift = p->shift;
	f->dev.block_size = 1U << p->shift;
	f->vdev.file_size = 32LL << p->shift;
	f->vdev.o_direct_flag = p->direct;
	f->data.sync_result = p->error;
	/* Cache commands have no data transfer, unlike the shared write fixture. */
	f->cmd.bufflen = 0;
	f->cmd.data_len = 0;
	f->cmd.resp_data_len = 0;
	f->cmd.sg = NULL;
	f->cmd.sg_cnt = 0;
	cdb[0] = p->sixteen ? SYNCHRONIZE_CACHE_16 : SYNCHRONIZE_CACHE;
	cdb[1] = p->immed ? 2 : 0;
	if (p->sixteen) {
		put_unaligned_be64(16, &cdb[2]);
		put_unaligned_be32(p->blocks, &cdb[10]);
	} else {
		put_unaligned_be32(16, &cdb[2]);
		put_unaligned_be16(p->blocks, &cdb[7]);
	}
	KUNIT_ASSERT_EQ(test, scst_get_cdb_info(&f->cmd), 0);
	KUNIT_ASSERT_EQ(test, scst_sbc_generic_parse(&f->cmd), 0);
	KUNIT_ASSERT_EQ(test, f->cmd.data_direction, SCST_DATA_NONE);
	KUNIT_ASSERT_EQ(test, f->cmd.bufflen, 0);
	KUNIT_ASSERT_TRUE(test, vdisk_parse_offset(&f->params, &f->cmd));
	KUNIT_ASSERT_EQ(test, vdisk_synchronize_cache(&f->params), RUNNING_ASYNC);
	KUNIT_ASSERT_EQ(test, f->flush_count, 1U);
	KUNIT_EXPECT_PTR_EQ(test, f->flushes[0].file, &f->data.file);
	KUNIT_EXPECT_EQ(test, f->flushes[0].start, start);
	/* The core's no-data parser leaves data_len zero, so vdisk flushes to EOF. */
	KUNIT_EXPECT_GE(test, f->flushes[0].end, end - 1);
	KUNIT_EXPECT_LE(test, f->flushes[0].end, f->vdev.file_size - 1);
	KUNIT_EXPECT_EQ(test, f->flushes[0].completions, p->immed ? 1U : 0U);
	KUNIT_EXPECT_EQ(test, f->flushes[0].cmd_refs, p->immed ? 2 : 1);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->cmd.cmd_ref), 1);
	KUNIT_EXPECT_EQ(test, f->completions, 1U);
	KUNIT_EXPECT_TRUE(test, f->completed_before_callback);
	KUNIT_EXPECT_EQ(test, f->completion_state, SCST_CMD_STATE_DEFAULT);
	KUNIT_EXPECT_EQ(test, f->cmd.status, p->immed || !p->error ? SAM_STAT_GOOD :
			p->error == -ENOMEM ? SAM_STAT_BUSY : SAM_STAT_CHECK_CONDITION);
}

static struct kunit_case vdisk_protocol_cases[] = {
	KUNIT_CASE_PARAM(vdisk_cdb_test, vdisk_cdb_gen_params),
	KUNIT_CASE_PARAM(vdisk_cache_test, vdisk_cache_gen_params),
	{}
};

scst_kunit_suite(vdisk_protocol_suite, "VDISK", "-protocol",
		 .init = vdisk_test_init,
		 .exit = vdisk_test_exit,
		 .test_cases = vdisk_protocol_cases,
);
