// SPDX-License-Identifier: GPL-2.0-only
#include "../../scst_kunit.h"

#include "scst.h"
#include "../../../scst_priv.h"
#include "../../../scst_lib_priv.h"
#include "../../../scst_lib_test.h"

struct write_same_fixture {
	struct scst_cmd cmd;
	struct scst_device dev;
	struct scst_session sess;
	struct scst_write_same_priv wsp;
	u8 cdb[32];
	u8 *data;
	size_t copied;
	unsigned int writes;
	unsigned int completions;
	bool replicated;
};

static int write_same_init(struct kunit *test)
{
	struct write_same_fixture *f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);

	if (!f)
		return -ENOMEM;
	test->priv = f;
	f->cmd.dev = &f->dev;
	f->cmd.sess = &f->sess;
	f->cmd.cdb = f->cdb;
	atomic_set(&f->sess.sess_cmd_count, 1);
	f->sess.initiator_name = "kunit-write-same";
	f->dev.dev_dif_type = 2;
	f->wsp.ws_orig_cmd = &f->cmd;
	f->wsp.dif_valid = 1;
	f->wsp.ref_tag = 0x10203040;
	return 0;
}

struct write_same_tag_case {
	const char *name;
	int cdb_len;
	u16 tag;
};

static const struct write_same_tag_case write_same_tag_cases[] = {
	{ "ws16_tag_1234", 16, 0x1234 },
	{ "ws16_tag_abcd", 16, 0xabcd },
	{ "ws16_tag_0001", 16, 0x0001 },
	{ "ws16_tag_ff00", 16, 0xff00 },
	{ "ws32_tag_1234", 32, 0x1234 },
	{ "ws32_tag_abcd", 32, 0xabcd },
	{ "ws32_tag_0001", 32, 0x0001 },
	{ "ws32_tag_ff00", 32, 0xff00 },
};

static void write_same_tag_desc(const struct write_same_tag_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(write_same_tag, write_same_tag_cases, write_same_tag_desc);

static void write_same_app_tag(struct kunit *test)
{
	const struct write_same_tag_case *p = test->param_value;
	struct write_same_fixture *f = test->priv;
	u8 buffer[34];
	u8 *cdb = &buffer[1];
	int len;

	f->cmd.cdb_len = p->cdb_len;
	f->cdb[0] = p->cdb_len == 16 ? WRITE_SAME_16 : VARIABLE_LENGTH_CMD;
	if (p->cdb_len == 32) {
		f->cdb[7] = 0x18;
		put_unaligned_be16(SUBCODE_WRITE_SAME_32, &f->cdb[8]);
		f->cdb[26] = 0x5a;
		f->cdb[27] = 0xc3;
	}
	f->wsp.app_tag = cpu_to_be16(p->tag);
	/* Poison both tag bytes: zero-filled fixtures can hide a short store. */
	memset(buffer, 0xa5, sizeof(buffer));
	len = scst_ws_build_write_cdb(&f->wsp, cdb, 0x1122334455667788LL, 0x01020304);

	KUNIT_ASSERT_EQ(test, len, 32);
	KUNIT_EXPECT_EQ(test, cdb[0], (u8)VARIABLE_LENGTH_CMD);
	KUNIT_EXPECT_EQ(test, get_unaligned_be16(&cdb[8]), (u16)SUBCODE_WRITE_32);
	KUNIT_EXPECT_EQ(test, cdb[24], (u8)(p->tag >> 8));
	KUNIT_EXPECT_EQ(test, cdb[25], (u8)p->tag);
	/* The wider store must preserve the adjacent reference tag and mask. */
	KUNIT_EXPECT_EQ(test, get_unaligned_be32(&cdb[20]), f->wsp.ref_tag);
	if (p->cdb_len == 32) {
		KUNIT_EXPECT_EQ(test, cdb[26], f->cdb[26]);
		KUNIT_EXPECT_EQ(test, cdb[27], f->cdb[27]);
	}
	KUNIT_EXPECT_EQ(test, buffer[0], (u8)0xa5);
	KUNIT_EXPECT_EQ(test, buffer[33], (u8)0xa5);
}

struct write_same_cdb_case {
	const char *name;
	int cdb_len;
	int dif_type;
	bool needs_dif;
};

static const struct write_same_cdb_case write_same_cdb_cases[] = {
	{ "no_dif", 16, 0, false },
	{ "type2_without_dif", 16, 2, false },
	{ "dif_type1", 16, 1, true },
	{ "dif_type3", 16, 3, true },
	{ "ws16_dif_type2", 16, 2, true },
	{ "ws32_dif_type2", 32, 2, true },
};

static void write_same_cdb_desc(const struct write_same_cdb_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(write_same_cdb, write_same_cdb_cases, write_same_cdb_desc);

static void write_same_cdb_image(struct kunit *test)
{
	static const u8 write16[32] = {
		0x8a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
		0x77, 0x88, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00,
	};
	static const u8 write32[32] = {
		0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18,
		0x00, 0x0b, 0x20, 0x00, 0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x77, 0x88, 0x10, 0x20, 0x30, 0x40,
		0x12, 0x34, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
	};
	static const u8 poisons[] = { 0xa5, 0x5a };
	const struct write_same_cdb_case *p = test->param_value;
	struct write_same_fixture *f = test->priv;
	bool long_write = p->dif_type == 2 && p->needs_dif;
	u8 buffer[34], expected[32];
	u8 *cdb = &buffer[1];
	int i;

	f->cmd.cdb_len = p->cdb_len;
	f->cdb[0] = p->cdb_len == 16 ? WRITE_SAME_16 : VARIABLE_LENGTH_CMD;
	f->dev.dev_dif_type = p->dif_type;
	f->wsp.dif_valid = p->needs_dif;
	f->wsp.app_tag = cpu_to_be16(0x1234);
	memcpy(expected, long_write ? write32 : write16, sizeof(expected));
	if (!long_write && p->needs_dif)
		expected[1] = 0x20;
	if (p->cdb_len == 32) {
		f->cdb[7] = 0x18;
		put_unaligned_be16(SUBCODE_WRITE_SAME_32, &f->cdb[8]);
		f->cdb[26] = 0x5a;
		f->cdb[27] = 0xc3;
		expected[26] = 0x5a;
		expected[27] = 0xc3;
	}

	for (i = 0; i < ARRAY_SIZE(poisons); i++) {
		int len;

		memset(buffer, poisons[i], sizeof(buffer));
		len = scst_ws_build_write_cdb(&f->wsp, cdb, 0x1122334455667788LL, 0x01020304);
		KUNIT_ASSERT_EQ(test, len, long_write ? 32 : 16);
		/* Check every byte, including control, group and reserved fields. */
		KUNIT_EXPECT_MEMEQ(test, cdb, expected, sizeof(expected));
		KUNIT_EXPECT_EQ(test, buffer[0], poisons[i]);
		KUNIT_EXPECT_EQ(test, buffer[33], poisons[i]);
	}
}

struct write_same_mask_case {
	const char *name;
	int cdb_len;
	bool check_app_tag;
	u16 mask;
};

static const struct write_same_mask_case write_same_mask_cases[] = {
	{ "ws16_no_app_check", 16, false, 0x0000 },
	{ "ws16_app_check", 16, true, 0xffff },
	{ "ws32_zero_mask", 32, true, 0x0000 },
	{ "ws32_full_mask", 32, false, 0xffff },
	{ "ws32_partial_mask_no_check", 32, false, 0x5ac3 },
	{ "ws32_partial_mask_check", 32, true, 0xa53c },
};

static void write_same_mask_desc(const struct write_same_mask_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(write_same_mask, write_same_mask_cases, write_same_mask_desc);

static void write_same_app_tag_mask(struct kunit *test)
{
	static const u8 poisons[] = { 0xa5, 0x5a };
	const struct write_same_mask_case *p = test->param_value;
	struct write_same_fixture *f = test->priv;
	u8 cdb[32];
	int i;

	f->cmd.cdb_len = p->cdb_len;
	f->cmd.cmd_dif_actions = p->check_app_tag ? SCST_DIF_CHECK_APP_TAG :
		SCST_DIF_ACTION_NONE;
	f->cdb[0] = p->cdb_len == 16 ? WRITE_SAME_16 : VARIABLE_LENGTH_CMD;
	if (p->cdb_len == 32) {
		f->cdb[7] = 0x18;
		put_unaligned_be16(SUBCODE_WRITE_SAME_32, &f->cdb[8]);
		put_unaligned_be16(p->mask, &f->cdb[26]);
	}

	for (i = 0; i < ARRAY_SIZE(poisons); i++) {
		int len;

		/* A short CDB has no mask: bytes beyond it must not affect output. */
		if (p->cdb_len == 16)
			memset(&f->cdb[16], poisons[i], 16);
		memset(cdb, poisons[i], sizeof(cdb));
		len = scst_ws_build_write_cdb(&f->wsp, cdb, 1, 1);
		KUNIT_ASSERT_EQ(test, len, 32);
		KUNIT_EXPECT_EQ(test, get_unaligned_be16(&cdb[26]), p->mask);
	}

	if (p->cdb_len == 16) {
		int len;

		/* Also exercise the actual 16-byte buffer used by scst_alloc_cmd(). */
		memcpy(f->cmd.cdb_buf, f->cdb, sizeof(f->cmd.cdb_buf));
		f->cmd.cdb = f->cmd.cdb_buf;
		len = scst_ws_build_write_cdb(&f->wsp, cdb, 1, 1);
		KUNIT_ASSERT_EQ(test, len, 32);
		KUNIT_EXPECT_EQ(test, get_unaligned_be16(&cdb[26]), p->mask);
	}
}

struct write_same_flags_case {
	const char *name;
	int cdb_len;
	bool needs_dif;
	u8 flags;
	u8 other_byte;
	u8 expected;
};

static const struct write_same_flags_case write_same_flags_cases[] = {
	{ "ws16_to_write32_default", 16, true, 0x00, 0xa5, 0x20 },
	{ "ws16_to_write32_protected", 16, true, 0x40, 0xa5, 0x40 },
	{ "ws32_to_write16", 32, false, 0x00, 0xa5, 0x00 },
	{ "ws16_to_write16", 16, false, 0x00, 0xa5, 0x00 },
	{ "ws32_to_write32", 32, true, 0x40, 0xa5, 0x40 },
};

static void write_same_flags_desc(const struct write_same_flags_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(write_same_flags, write_same_flags_cases, write_same_flags_desc);

static void write_same_flags(struct kunit *test)
{
	const struct write_same_flags_case *p = test->param_value;
	struct write_same_fixture *f = test->priv;
	u8 cdb[32];
	int len;

	f->cmd.cdb_len = p->cdb_len;
	f->cdb[0] = p->cdb_len == 16 ? WRITE_SAME_16 : VARIABLE_LENGTH_CMD;
	f->cdb[p->cdb_len == 32 ? 10 : 1] = p->flags;
	/* A short command's transfer length and a long one's control are not flags. */
	f->cdb[p->cdb_len == 32 ? 1 : 10] = p->other_byte;
	if (p->cdb_len == 32) {
		f->cdb[7] = 0x18;
		put_unaligned_be16(SUBCODE_WRITE_SAME_32, &f->cdb[8]);
	}
	f->wsp.dif_valid = p->needs_dif;

	len = scst_ws_build_write_cdb(&f->wsp, cdb, 1, 1);

	KUNIT_ASSERT_EQ(test, len, p->needs_dif ? 32 : 16);
	KUNIT_EXPECT_EQ(test, cdb[p->needs_dif ? 10 : 1], p->expected);
}

static int write_same_no_dif(struct scst_cmd *cmd)
{
	return 0;
}

static void write_same_done(struct scst_cmd *cmd, int next_state,
			    enum scst_exec_context context)
{
	struct write_same_fixture *f = container_of(cmd, struct write_same_fixture, cmd);

	f->completions++;
}

static int write_same_capture_write(struct scst_write_same_priv *wsp, s64 lba, int blocks)
{
	struct kunit *test = kunit_get_current_test();
	struct write_same_fixture *f = test->priv;
	struct scatterlist *sg;
	int sg_cnt;

	f->writes++;
	KUNIT_EXPECT_EQ(test, lba, f->cmd.lba);
	KUNIT_EXPECT_EQ(test, blocks, (int)(PAGE_SIZE >> f->dev.block_shift));
	if (blocks == wsp->ws_max_each) {
		sg = wsp->ws_sg_full;
		sg_cnt = wsp->ws_sg_full_cnt;
	} else {
		sg = wsp->ws_sg_tails[wsp->ws_cur_descr].sg;
		sg_cnt = wsp->ws_sg_tails[wsp->ws_cur_descr].sg_cnt;
	}
	KUNIT_EXPECT_EQ(test, sg_cnt, 1);
	if (sg && sg_cnt > 0) {
		f->replicated = sg_page(sg) != sg_page(f->cmd.sg);
		f->copied = sg_copy_to_buffer(sg, sg_cnt, f->data, PAGE_SIZE);
	}

	/* Stop before submitting I/O; the caller frees the prepared buffers. */
	return -EIO;
}

struct write_same_data_case {
	const char *name;
	unsigned int offset;
};

static const struct write_same_data_case write_same_data_cases[] = {
	{ "aligned_block", 0 },
	{ "offset_block", 512 },
	{ "page_crossing_block", PAGE_SIZE - 512 },
};

static void write_same_data_desc(const struct write_same_data_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(write_same_data, write_same_data_cases, write_same_data_desc);

/* CONFIG_DEBUG_KMAP_LOCAL_FORCE_MAP exposes reads past a single-page mapping. */
static void write_same_data(struct kunit *test)
{
	const struct write_same_data_case *p = test->param_value;
	struct write_same_fixture *f = test->priv;
	struct scatterlist sg;
	unsigned int i;
	u8 *source;

	source = kunit_kmalloc(test, 2 * PAGE_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, source);
	f->data = kunit_kmalloc(test, PAGE_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, f->data);
	/* Give the two halves of the crossing block different byte patterns. */
	for (i = 0; i < 2 * PAGE_SIZE; i++)
		source[i] = i ^ (i >> 8);
	memset(f->data, 0xa5, PAGE_SIZE);
	sg_init_one(&sg, source + p->offset, 1024);
	KUNIT_ASSERT_EQ(test, sg.offset, p->offset);
	f->cmd.sg = &sg;
	f->cmd.sg_cnt = 1;
	f->cmd.bufflen = 1024;
	f->cmd.data_len = PAGE_SIZE;
	f->cmd.lba = 123;
	f->cmd.cdb_len = 16;
	f->cdb[0] = WRITE_SAME_16;
	f->cmd.data_direction = SCST_DATA_WRITE;
	f->cmd.scst_cmd_done = write_same_done;
	f->dev.block_shift = 10;
	f->dev.block_size = 1024;
	f->dev.max_write_same_len = PAGE_SIZE;
	f->dev.dev_dif_fn = write_same_no_dif;

	kunit_activate_static_stub(test, scst_ws_push_single_write, write_same_capture_write);
	scst_write_same(&f->cmd, NULL);
	kunit_deactivate_static_stub(test, scst_ws_push_single_write);

	KUNIT_EXPECT_EQ(test, f->completions, 1U);
	KUNIT_EXPECT_TRUE(test, f->cmd.completed);
	KUNIT_ASSERT_EQ(test, f->writes, 1U);
	KUNIT_ASSERT_TRUE(test, f->replicated);
	KUNIT_ASSERT_EQ(test, f->copied, (size_t)PAGE_SIZE);
	for (i = 0; i < PAGE_SIZE; i += f->cmd.bufflen)
		KUNIT_EXPECT_MEMEQ(test, f->data + i, source + p->offset, f->cmd.bufflen);
}

static struct kunit_case write_same_cases[] = {
	KUNIT_CASE_PARAM(write_same_app_tag, write_same_tag_gen_params),
	KUNIT_CASE_PARAM(write_same_cdb_image, write_same_cdb_gen_params),
	KUNIT_CASE_PARAM(write_same_app_tag_mask, write_same_mask_gen_params),
	KUNIT_CASE_PARAM(write_same_flags, write_same_flags_gen_params),
	KUNIT_CASE_PARAM(write_same_data, write_same_data_gen_params),
	{}
};

scst_kunit_suite(write_same_suite, "LIB", "-write-same",
		 .init = write_same_init,
		 .test_cases = write_same_cases,
);
