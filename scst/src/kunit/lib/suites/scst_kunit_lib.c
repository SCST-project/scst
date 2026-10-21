// SPDX-License-Identifier: GPL-2.0-only
#include "../../scst_kunit.h"

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif

#include "../../../scst_lib_test.h"
#include "../../../scst_main_test.h"
#include "../../../scst_dlm.h"
#include "../../../scst_dlm_test.h"

struct scst_port_id_fixture {
	unsigned int free_id;
	unsigned int probes;
	bool invalid_id;
};

static bool scst_port_id_available(u16 id, const struct scst_tgt *t)
{
	struct kunit *test = kunit_get_current_test();
	struct scst_port_id_fixture *fixture = test->priv;

	fixture->probes++;
	fixture->invalid_id |= id < SCST_MIN_REL_TGT_ID;
	return id == fixture->free_id;
}

static void scst_port_id_boundaries(struct kunit *test)
{
	static const struct {
		unsigned int start;
		unsigned int free_id;
		unsigned int next;
		unsigned int probes;
		int status;
	} cases[] = {
		{ 1, 1, 2, 1, 0 },
		{ 1, 3, 4, 3, 0 },
		{ SCST_MAX_REL_TGT_ID, SCST_MAX_REL_TGT_ID, 1, 1, 0 },
		{ SCST_MAX_REL_TGT_ID, 1, 2, 2, 0 },
		{ 42, 0, 42, SCST_MAX_REL_TGT_ID, -EOVERFLOW },
	};
	struct scst_port_id_fixture fixture;
	unsigned int i;

	test->priv = &fixture;
	kunit_activate_static_stub(test, __scst_is_relative_target_port_id_unique,
				   scst_port_id_available);
	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		unsigned int next = cases[i].start;
		u16 id = 123;
		u16 expected_id = cases[i].free_id;

		if (cases[i].status)
			expected_id = id;

		memset(&fixture, 0, sizeof(fixture));
		fixture.free_id = cases[i].free_id;
		KUNIT_EXPECT_EQ(test, scst_alloc_relative_target_port_id(&id, &next),
				cases[i].status);
		KUNIT_EXPECT_EQ(test, next, cases[i].next);
		KUNIT_EXPECT_EQ(test, id, expected_id);
		KUNIT_EXPECT_EQ(test, fixture.probes, cases[i].probes);
		KUNIT_EXPECT_FALSE(test, fixture.invalid_id);
	}
	kunit_deactivate_static_stub(test, __scst_is_relative_target_port_id_unique);
	test->priv = NULL;
}

static void scst_lun_flat_encoding(struct kunit *test)
{
	/* Flat addressing: 01 in the top bits, followed by the 14-bit LUN. */
	__be64 wire_lun = cpu_to_be64(0x5234000000000000ULL);
	__be64 packed = scst_pack_lun(0x1234, SCST_LUN_ADDR_METHOD_FLAT);

	scst_kunit_log(test, "LUN 0x1234 encoded as 0x%016llx", be64_to_cpu(packed));
	KUNIT_EXPECT_EQ(test, be64_to_cpu(packed), 0x5234000000000000ULL);
	KUNIT_EXPECT_EQ(test, scst_unpack_lun((const u8 *)&wire_lun, sizeof(wire_lun)),
			(u64)0x1234);
}

static void scst_explicit_sg_buffers(struct kunit *test)
{
	struct scatterlist command_sg, selected_sg[2];
	struct scst_cmd *cmd;
	u8 *data, *buf;
	unsigned int i;

	cmd = kunit_kzalloc(test, sizeof(*cmd), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, cmd);
	data = kunit_kzalloc(test, 64, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, data);
	sg_init_one(&command_sg, data, 8);
	sg_init_table(selected_sg, ARRAY_SIZE(selected_sg));
	sg_set_buf(&selected_sg[0], data + 8, 16);
	sg_set_buf(&selected_sg[1], data + 24, 32);
	cmd->sg_cnt = 1;

	/* An explicit list works with either another command list or none. */
	for (i = 0; i < 2; i++) {
		cmd->sg = i ? NULL : &command_sg;
		cmd->may_need_dma_sync = 0;
		KUNIT_ASSERT_EQ(test, scst_get_sg_buf_first(cmd, &buf, selected_sg, 2), 16);
		KUNIT_ASSERT_PTR_EQ(test, buf, data + 8);
		KUNIT_EXPECT_EQ(test, cmd->get_sg_buf_entry_num, 1);
		KUNIT_EXPECT_TRUE(test, cmd->may_need_dma_sync);
		scst_put_sg_buf(cmd, buf, selected_sg, 2);

		KUNIT_ASSERT_EQ(test, scst_get_sg_buf_next(cmd, &buf, selected_sg, 2), 32);
		KUNIT_ASSERT_PTR_EQ(test, buf, data + 24);
		scst_put_sg_buf(cmd, buf, selected_sg, 2);
		KUNIT_EXPECT_EQ(test, scst_get_sg_buf_next(cmd, &buf, selected_sg, 2), 0);
		KUNIT_EXPECT_NULL(test, buf);
		KUNIT_EXPECT_EQ(test, cmd->get_sg_buf_entry_num, 2);
	}
}

static void scst_empty_explicit_sg_buffers(struct kunit *test)
{
	struct scatterlist sg;
	struct scst_cmd *cmd;
	u8 *data, *buf;

	cmd = kunit_kzalloc(test, sizeof(*cmd), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, cmd);
	data = kunit_kzalloc(test, 16, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, data);
	sg_init_one(&sg, data, 16);
	cmd->sg = &sg;
	cmd->sg_cnt = 1;

	buf = data;
	KUNIT_EXPECT_EQ(test, scst_get_sg_buf_first(cmd, &buf, NULL, 0), 0);
	KUNIT_EXPECT_NULL(test, buf);
	buf = data;
	KUNIT_EXPECT_EQ(test, scst_get_sg_buf_first(cmd, &buf, &sg, 0), 0);
	KUNIT_EXPECT_NULL(test, buf);
}

#if (defined(CONFIG_DLM) || defined(CONFIG_DLM_MODULE)) && !defined(CONFIG_SCST_NO_DLM)
static int scst_dlm_read_nodeids_error(char **entries)
{
	struct kunit *test = kunit_get_current_test();
	const int *error = test->priv;

	/* An empty partial result must not replace an established membership. */
	*entries = *error == -ENOMEM ? NULL : kzalloc(1, GFP_KERNEL);
	KUNIT_EXPECT_TRUE(test, *error == -ENOMEM || *entries);
	return *error;
}

static void scst_dlm_directory_error_preserves_membership(struct kunit *test)
{
	static const int errors[] = { -EIO, -EACCES, -ENOMEM };
	struct scst_pr_dlm_data *dlm;
	u32 *nodeids;
	unsigned int i;
	int error;

	dlm = kunit_kzalloc(test, sizeof(*dlm), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, dlm);
	mutex_init(&dlm->ls_mutex);
	kunit_activate_static_stub(test, scst_dlm_read_nodeids, scst_dlm_read_nodeids_error);
	for (i = 0; i < ARRAY_SIZE(errors); i++) {
		int ret;

		/* The production update owns and may reallocate this array. */
		nodeids = kmalloc_array(2, sizeof(*nodeids), GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, nodeids);
		nodeids[0] = 17;
		nodeids[1] = 23;
		dlm->nodeid = nodeids;
		dlm->participants = 2;
		dlm->local_nodeid = 17;
		error = errors[i];
		test->priv = &error;

		mutex_lock(&dlm->ls_mutex);
		ret = scst_dlm_update_nodeids(dlm);
		mutex_unlock(&dlm->ls_mutex);
		KUNIT_EXPECT_EQ(test, ret, errors[i]);
		KUNIT_EXPECT_PTR_EQ(test, dlm->nodeid, nodeids);
		KUNIT_EXPECT_EQ(test, dlm->participants, 2);
		KUNIT_EXPECT_EQ(test, dlm->local_nodeid, 17U);
		if (dlm->nodeid == nodeids) {
			KUNIT_EXPECT_EQ(test, nodeids[0], 17U);
			KUNIT_EXPECT_EQ(test, nodeids[1], 23U);
		}
		/* Also tolerate the old bug freeing/replacing nodeids. */
		kfree(dlm->nodeid);
		dlm->nodeid = NULL;
	}
	kunit_deactivate_static_stub(test, scst_dlm_read_nodeids);
	test->priv = NULL;
	mutex_destroy(&dlm->ls_mutex);
}
#endif

static void scst_cdb_trace_bounds(struct kunit *test)
{
	static const struct {
		unsigned int cdb_len;
		size_t capacity;
		const char *expected;
	} cases[] = {
		{ 0, 16, "" },
		{ 3, 16, "00 ab ff" },
		{ 3, 5, "00 a" },
		{ 3, 1, "" },
	};
	u8 cdb[] = { 0x00, 0xab, 0xff };
	struct scst_cmd *cmd;
	char buf[18];
	unsigned int i;

	cmd = kunit_kzalloc(test, sizeof(*cmd), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, cmd);
	cmd->cdb = cdb;
	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		memset(buf, 'x', sizeof(buf));
		cmd->cdb_len = cases[i].cdb_len;
		KUNIT_EXPECT_PTR_EQ(test, scst_dump_cdb(buf + 1, cases[i].capacity, cmd),
				    buf + 1);
		KUNIT_EXPECT_EQ(test, buf[0], 'x');
		KUNIT_EXPECT_EQ(test, buf[cases[i].capacity + 1], 'x');
		/* memcmp bounds the check even if the formatter misses the NUL. */
		KUNIT_EXPECT_EQ(test, memcmp(buf + 1, cases[i].expected,
					     strlen(cases[i].expected) + 1), 0);
	}

	memset(buf, 'x', sizeof(buf));
	KUNIT_EXPECT_PTR_EQ(test, scst_dump_cdb(buf + 1, 0, cmd), buf + 1);
	KUNIT_EXPECT_EQ(test, buf[1], 'x');
}

static void scst_lun_unaligned_encoding(struct kunit *test)
{
	u8 data[16] __aligned(8);
	unsigned int offset, len, tail;

	for (offset = 0; offset < 8; offset++) {
		for (len = 2; len <= 8; len += 2) {
			u8 *lun = data + offset;

			/* Nonzero bytes outside len must not affect decoding. */
			memset(data, 0x5a, sizeof(data));
			memset(lun, 0, len);
			lun[0] = 0x52;
			lun[1] = 0x34;
			KUNIT_EXPECT_EQ_MSG(test, scst_unpack_lun(lun, len), (u64)0x1234,
					    "offset=%u len=%u", offset, len);
			for (tail = 2; tail < len; tail++) {
				lun[tail] = 1;
				KUNIT_EXPECT_EQ_MSG(test, scst_unpack_lun(lun, len),
						    (u64)NO_SUCH_LUN, "offset=%u len=%u tail=%u",
						    offset, len, tail);
				lun[tail] = 0;
			}
		}
	}
}

/* Mapping-order diagnostics require CONFIG_DEBUG_KMAP_LOCAL_FORCE_MAP. */
static void scst_sg_copy_and_compare(struct kunit *test)
{
	static const struct {
		unsigned int offset;
		unsigned int length;
		int mismatch;
	} cases[] = {
		{ 0, PAGE_SIZE, -1 },
		{ 7, 32, -1 },
		{ 0, PAGE_SIZE, 0 },
		{ 0, PAGE_SIZE, 17 },
		{ 0, PAGE_SIZE, PAGE_SIZE - 1 },
		{ 7, 32, 0 },
		{ 7, 32, 31 },
	};
	u8 *source, *destination;
	unsigned int i;

	source = kunit_kmalloc(test, PAGE_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, source);
	destination = kunit_kmalloc(test, PAGE_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, destination);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct scatterlist src, dst, *cursor = &dst;
		size_t length, offset;
		int mismatch = -1;
		bool equal;

		memset(source, 0x5a, PAGE_SIZE);
		memset(destination, 0, PAGE_SIZE);
		sg_init_one(&src, source + cases[i].offset, cases[i].length);
		sg_init_one(&dst, destination + cases[i].offset, cases[i].length);
		length = dst.length;
		offset = dst.offset;
		KUNIT_EXPECT_EQ(test, sg_copy_elem(&cursor, &length, &offset, &src,
						   cases[i].length), (int)cases[i].length);
		KUNIT_EXPECT_EQ(test, memcmp(source + cases[i].offset,
					     destination + cases[i].offset, cases[i].length), 0);

		if (cases[i].mismatch >= 0)
			destination[cases[i].offset + cases[i].mismatch] ^= 1;
		cursor = &dst;
		length = dst.length;
		offset = dst.offset;
		sg_cmp_elem(&cursor, &length, &offset, &src, cases[i].length,
			    &mismatch, &equal);
		KUNIT_EXPECT_EQ(test, equal, cases[i].mismatch < 0);
		KUNIT_EXPECT_EQ(test, mismatch, cases[i].mismatch);
	}
}

static struct kunit_case scst_lib_cases[] = {
	KUNIT_CASE(scst_sg_copy_and_compare),
	KUNIT_CASE(scst_lun_unaligned_encoding),
	KUNIT_CASE(scst_cdb_trace_bounds),
#if (defined(CONFIG_DLM) || defined(CONFIG_DLM_MODULE)) && !defined(CONFIG_SCST_NO_DLM)
	KUNIT_CASE(scst_dlm_directory_error_preserves_membership),
#endif
	KUNIT_CASE(scst_port_id_boundaries),
	KUNIT_CASE(scst_lun_flat_encoding),
	KUNIT_CASE(scst_explicit_sg_buffers),
	KUNIT_CASE(scst_empty_explicit_sg_buffers),
	{}
};

scst_kunit_suite(scst_lib_suite, "LIB", "",
		 .test_cases = scst_lib_cases,
);
