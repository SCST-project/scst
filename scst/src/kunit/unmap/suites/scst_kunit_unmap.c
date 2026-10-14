// SPDX-License-Identifier: GPL-2.0-only
#include "../../scst_kunit.h"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "../../../scst_priv.h"
#include "../../../scst_targ_test.h"

struct unmap_fixture {
	struct scst_cmd unmap;
	struct scst_cmd atomic;
	struct scst_device dev;
	struct scst_tgt_dev tgt_dev;
	struct scst_session sess;
	struct scatterlist sg[2];
	u8 sense[SCST_SENSE_BUFFERSIZE];
	u8 *wire;
};

static int unmap_init(struct kunit *test)
{
	struct unmap_fixture *f;

	test->priv = NULL;
	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);

	if (!f)
		return -ENOMEM;
	test->priv = f;
	f->dev.block_shift = 9;
	f->dev.block_size = 512;
	f->tgt_dev.dev = &f->dev;
	atomic_set(&f->sess.sess_cmd_count, 1);
	f->sess.init_phase = SCST_SESS_IPH_READY;
	f->sess.initiator_name = "kunit-unmap";
	f->unmap.dev = &f->dev;
	f->unmap.tgt_dev = &f->tgt_dev;
	f->unmap.sess = &f->sess;
	f->unmap.cmd_gfp_mask = GFP_KERNEL;
	f->unmap.state = SCST_CMD_STATE_EXEC_CHECK_SN;
	f->unmap.cdb = f->unmap.cdb_buf;
	f->unmap.cdb[0] = UNMAP;
	f->unmap.op_flags = SCST_DESCRIPTORS_BASED | SCST_LBA_NOT_VALID;
	f->unmap.data_direction = SCST_DATA_WRITE;
	f->unmap.sense = f->sense;
	f->unmap.sense_buflen = sizeof(f->sense);
	f->atomic.dev = &f->dev;
	f->atomic.cdb = f->atomic.cdb_buf;
	f->atomic.cdb[0] = COMPARE_AND_WRITE;
	f->atomic.op_flags = SCST_SCSI_ATOMIC;
	f->atomic.lba = 100;
	/* COMPARE AND WRITE keeps its range length in blocks. */
	f->atomic.data_len = 8;
	return 0;
}

static void unmap_exit(struct kunit *test)
{
	struct unmap_fixture *f = test->priv;

	test->priv = NULL;
	if (f)
		kfree(f->unmap.cmd_data_descriptors);
}

static void unmap_buffer(struct kunit *test, unsigned int length,
			 unsigned int cdb_length, unsigned int descriptor_length,
			 unsigned int split)
{
	struct unmap_fixture *f = test->priv;

	put_unaligned_be16(cdb_length, &f->unmap.cdb[7]);
	f->unmap.bufflen = cdb_length;
	if (!length)
		return;
	f->wire = kunit_kzalloc(test, length, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, f->wire);
	if (length >= 4) {
		put_unaligned_be16(length - 2, f->wire);
		put_unaligned_be16(descriptor_length, f->wire + 2);
	}
	if (split) {
		KUNIT_ASSERT_LT(test, split, length);
		sg_init_table(f->sg, 2);
		sg_set_buf(&f->sg[0], f->wire, split);
		sg_set_buf(&f->sg[1], f->wire + split, length - split);
		f->unmap.sg_cnt = 2;
	} else {
		sg_init_one(f->sg, f->wire, length);
		f->unmap.sg_cnt = 1;
	}
	f->unmap.sg = f->sg;
}

struct unmap_parse_case {
	const char *name;
	unsigned int length;
	unsigned int cdb_length;
	unsigned int descriptor_length;
	unsigned int split;
	int count;
	u8 asc;
};

static const struct unmap_parse_case unmap_parse_cases[] = {
	{ "zero_transfer", 0, 0, 0, 0, 0, 0 },
	{ "zero_cdb_ignores_sg", 24, 0, 16, 0, 0, 0 },
	{ "zero_cdb_ignores_short_sg", 1, 0, 0, 0, 0, 0 },
	{ "empty_list", 8, 8, 0, 0, 0, 0 },
	{ "one_descriptor", 24, 24, 16, 0, 1, 0 },
	{ "three_descriptors", 56, 56, 48, 0, 3, 0 },
	{ "header_across_sg", 24, 24, 16, 3, 1, 0 },
	{ "descriptor_across_sg", 56, 56, 48, 19, 3, 0 },
	{ "trailing_parameter_bytes", 32, 32, 16, 0, 1, 0 },
	{ "extra_sg_bytes", 32, 24, 16, 0, 1, 0 },
	{ "missing_transfer", 0, 24, 0, 0, 0, 0x1a },
	{ "one_byte_header", 1, 1, 0, 0, 0, 0x1a },
	{ "three_byte_header", 3, 3, 0, 0, 0, 0x1a },
	{ "seven_byte_header", 7, 7, 0, 0, 0, 0x1a },
	{ "short_cdb_length", 8, 7, 0, 0, 0, 0x1a },
	{ "short_cdb_with_descriptors", 24, 7, 16, 0, 0, 0x1a },
	{ "short_cdb_across_sg", 8, 7, 0, 3, 0, 0x1a },
	{ "truncated_header", 7, 8, 0, 0, 0, 0x1a },
	{ "truncated_sg_header", 7, 8, 0, 3, 0, 0x1a },
	{ "truncated_empty_list", 8, 24, 0, 0, 0, 0x1a },
	{ "truncated_descriptor", 23, 24, 16, 0, 0, 0x1a },
	{ "truncated_sg_descriptor", 23, 24, 16, 3, 0, 0x1a },
	/* SBC-3 5.26.2: ignore an incomplete final descriptor. */
	{ "descriptor_too_short", 24, 24, 15, 0, 0, 0 },
	{ "descriptor_not_aligned", 40, 40, 17, 0, 1, 0 },
	{ "partial_descriptor_in_transfer", 25, 25, 17, 0, 1, 0 },
	{ "partial_descriptor_across_sg", 25, 25, 17, 19, 1, 0 },
	{ "one_byte_descriptor", 9, 9, 1, 0, 0, 0 },
	/* The CDB length bounds the list; the first descriptor still fits. */
	{ "descriptor_exceeds_cdb", 40, 24, 32, 0, 1, 0 },
	{ "descriptor_exceeds_transfer", 24, 24, 32, 0, 1, 0 },
	{ "cdb_truncates_last_descriptor", 39, 39, 32, 0, 1, 0 },
	{ "cdb_truncates_first_descriptor", 23, 23, 16, 0, 0, 0 },
	{ "header_only_with_descriptors", 8, 8, 16, 0, 0, 0 },
	{ "maximum_descriptor_length", 24, 24, 0xffff, 0, 1, 0 },
};

static void unmap_parse_desc(const struct unmap_parse_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(unmap_parse, unmap_parse_cases, unmap_parse_desc);

static void unmap_parse(struct kunit *test)
{
	const struct unmap_parse_case *p = test->param_value;
	struct unmap_fixture *f = test->priv;
	struct scst_data_descriptor *descriptors;
	int i, rc;

	unmap_buffer(test, p->length, p->cdb_length, p->descriptor_length, p->split);
	/* Populate the input independently of the expected descriptor count. */
	for (i = 0; 8 + (i + 1) * 16 <= p->length; i++) {
		/* Exercise all bytes of the wire LBA and block count. */
		put_unaligned_be64(0x123456789abcdef0ULL + i, f->wire + 8 + i * 16);
		put_unaligned_be32(0x12345678 + i, f->wire + 16 + i * 16);
	}
	rc = scst_parse_descriptors(&f->unmap);
	KUNIT_EXPECT_FALSE(test, f->unmap.sg_buff_vmallocated);
	if (p->asc)
		KUNIT_ASSERT_LT(test, rc, 0);
	else
		KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, f->unmap.cmd_data_descriptors_cnt, p->count);
	if (p->asc) {
		KUNIT_EXPECT_PTR_EQ(test, f->unmap.cmd_data_descriptors, NULL);
		KUNIT_EXPECT_EQ(test, f->unmap.status, SAM_STAT_CHECK_CONDITION);
		KUNIT_EXPECT_EQ(test, f->unmap.state, SCST_CMD_STATE_PRE_DEV_DONE);
		KUNIT_EXPECT_EQ(test, f->sense[2], ILLEGAL_REQUEST);
		KUNIT_EXPECT_EQ(test, f->sense[12], p->asc);
		KUNIT_EXPECT_EQ(test, f->sense[13], 0);
		return;
	}
	KUNIT_EXPECT_EQ(test, f->unmap.status, SAM_STAT_GOOD);
	KUNIT_EXPECT_EQ(test, f->unmap.state, SCST_CMD_STATE_EXEC_CHECK_SN);
	if (!p->count) {
		KUNIT_EXPECT_PTR_EQ(test, f->unmap.cmd_data_descriptors, NULL);
		return;
	}
	descriptors = f->unmap.cmd_data_descriptors;
	KUNIT_ASSERT_NOT_NULL(test, descriptors);
	for (i = 0; i < p->count; i++) {
		KUNIT_EXPECT_EQ(test, (u64)descriptors[i].sdd_lba, 0x123456789abcdef0ULL + i);
		KUNIT_EXPECT_EQ(test, descriptors[i].sdd_blocks, (u64)0x12345678 + i);
		KUNIT_EXPECT_EQ(test, get_unaligned_be64(f->wire + 8 + i * 16),
				0x123456789abcdef0ULL + i);
	}
}

struct unmap_overlap_case {
	const char *name;
	unsigned int count;
	u64 lba[3];
	u32 blocks[3];
	bool overlap;
	bool guard_overlap;
};

static const struct unmap_overlap_case unmap_overlap_cases[] = {
	{ "empty", 0, {}, {}, false },
	{ "before", 1, { 90 }, { 2 }, false },
	{ "adjacent_left", 1, { 92 }, { 8 }, false },
	{ "adjacent_right", 1, { 108 }, { 1 }, false },
	{ "same_range", 1, { 100 }, { 8 }, true },
	{ "inside", 1, { 102 }, { 2 }, true },
	{ "contains", 1, { 99 }, { 10 }, true },
	{ "overlap_left", 1, { 99 }, { 2 }, true },
	{ "overlap_right", 1, { 107 }, { 2 }, true },
	{ "last_descriptor", 3, { 10, 30, 107 }, { 8, 8, 2 }, true },
	{ "no_sentinel", 3, { 0, 20, 110 }, { 8, 8, 8 }, false, true },
	{ "zero_first", 2, { 100, 102 }, { 0, 1 }, true },
	{ "zero_middle", 3, { 0, 100, 107 }, { 1, 0, 1 }, true },
	{ "zero_only", 1, { 100 }, { 0 }, false },
};

static void unmap_overlap_desc(const struct unmap_overlap_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(unmap_overlap, unmap_overlap_cases, unmap_overlap_desc);

static void unmap_overlap(struct kunit *test)
{
	const struct unmap_overlap_case *p = test->param_value;
	struct scst_data_descriptor *guarded;
	struct unmap_fixture *f = test->priv;
	unsigned int i;

	unmap_buffer(test, 8 + 16 * p->count, 8 + 16 * p->count, 16 * p->count, 0);
	for (i = 0; i < p->count; i++) {
		put_unaligned_be64(p->lba[i], f->wire + 8 + i * 16);
		put_unaligned_be32(p->blocks[i], f->wire + 16 + i * 16);
	}
	KUNIT_ASSERT_EQ(test, scst_parse_descriptors(&f->unmap), 0);
	KUNIT_ASSERT_EQ(test, f->unmap.cmd_data_descriptors_cnt, (int)p->count);
	if (p->count) {
		/* Bound the old sentinel walk without changing the published count. */
		guarded = kcalloc(p->count + 2, sizeof(*guarded), GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, guarded);
		memcpy(guarded, f->unmap.cmd_data_descriptors, p->count * sizeof(*guarded));
		if (p->guard_overlap) {
			/* Correct code ignores this allocated but unpublished descriptor. */
			guarded[p->count].sdd_lba = 100;
			guarded[p->count].sdd_blocks = 8;
		}
		kfree(f->unmap.cmd_data_descriptors);
		f->unmap.cmd_data_descriptors = guarded;
	}
	/* Both commands may be first in the blocked-command list. */
	KUNIT_EXPECT_EQ(test, scst_cmd_overlap(&f->atomic, &f->unmap), p->overlap);
	KUNIT_EXPECT_EQ(test, scst_cmd_overlap(&f->unmap, &f->atomic), p->overlap);
	f->dev.block_shift = 12;
	f->dev.block_size = 4096;
	KUNIT_EXPECT_EQ(test, scst_cmd_overlap(&f->atomic, &f->unmap), p->overlap);
}

static void unmap_descriptor_count_bounds_overlap(struct kunit *test)
{
	struct unmap_fixture *f = test->priv;

	unmap_buffer(test, 40, 40, 32, 0);
	put_unaligned_be64(10, f->wire + 8);
	put_unaligned_be32(1, f->wire + 16);
	put_unaligned_be64(100, f->wire + 24);
	put_unaligned_be32(8, f->wire + 32);
	KUNIT_ASSERT_EQ(test, scst_parse_descriptors(&f->unmap), 0);
	/* A second allocated descriptor must not extend the published list. */
	f->unmap.cmd_data_descriptors_cnt = 1;
	KUNIT_EXPECT_FALSE(test, scst_cmd_overlap(&f->atomic, &f->unmap));
	f->unmap.cmd_data_descriptors_cnt = 0;
	KUNIT_EXPECT_FALSE(test, scst_cmd_overlap(&f->atomic, &f->unmap));
}

static struct kunit_case scst_unmap_cases[] = {
	KUNIT_CASE_PARAM(unmap_parse, unmap_parse_gen_params),
	KUNIT_CASE_PARAM(unmap_overlap, unmap_overlap_gen_params),
	KUNIT_CASE(unmap_descriptor_count_bounds_overlap),
	{}
};

scst_kunit_suite(scst_unmap_suite, "UNMAP", "",
		 .init = unmap_init,
		 .exit = unmap_exit,
		 .test_cases = scst_unmap_cases,
);
