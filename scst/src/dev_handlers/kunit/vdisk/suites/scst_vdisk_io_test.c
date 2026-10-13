// SPDX-License-Identifier: GPL-2.0-only
#include "../scst_vdisk_fixture.h"

struct vdisk_write_case {
	const char *name;
	loff_t start;
	ssize_t results[3];
	unsigned int result_count;
	unsigned int calls;
	size_t written;
	bool no_fua;
	bool direct;
	bool wt;
	bool nv_cache;
	bool thin;
	bool dif_fallback;
	int flush_error;
	u8 status;
};

static const struct vdisk_write_case vdisk_write_cases[] = {
	{ .name = "fua_at_zero", .calls = 1, .written = 1024 },
	{ .name = "fua_at_nonzero_offset", .start = 8192, .calls = 1, .written = 1024 },
	{ .name = "short_before_sg_boundary", .start = 8192, .results = { 256 },
	  .result_count = 1, .calls = 2, .written = 1024 },
	{ .name = "short_at_sg_boundary", .start = 8192, .results = { 512 },
	  .result_count = 1, .calls = 2, .written = 1024 },
	{ .name = "short_after_sg_boundary", .start = 8192, .results = { 768 },
	  .result_count = 1, .calls = 2, .written = 1024 },
	{ .name = "two_short_writes", .start = 8192, .results = { 128, 512 },
	  .result_count = 2, .calls = 3, .written = 1024 },
	{ .name = "write_eagain", .start = 8192, .results = { -EAGAIN },
	  .result_count = 1, .calls = 1, .status = SAM_STAT_BUSY },
	{ .name = "thin_out_of_space", .start = 8192, .results = { -ENOSPC },
	  .result_count = 1, .calls = 1, .thin = true, .status = SAM_STAT_CHECK_CONDITION },
	{ .name = "write_eio", .start = 8192, .results = { -EIO },
	  .result_count = 1, .calls = 1, .status = SAM_STAT_CHECK_CONDITION },
	{ .name = "eio_after_short_write", .start = 8192, .results = { 256, -EIO },
	  .result_count = 2, .calls = 2, .written = 256, .status = SAM_STAT_CHECK_CONDITION },
	{ .name = "ordinary_write", .start = 8192, .calls = 1, .written = 1024, .no_fua = true },
	{ .name = "flush_eio", .start = 8192, .calls = 1, .written = 1024,
	  .flush_error = -EIO, .status = SAM_STAT_CHECK_CONDITION },
	{ .name = "flush_enomem", .start = 8192, .calls = 1, .written = 1024,
	  .flush_error = -ENOMEM, .status = SAM_STAT_BUSY },
	{ .name = "direct_flag_still_flushes", .start = 8192, .calls = 1, .written = 1024,
	  .direct = true },
	{ .name = "write_through", .start = 8192, .calls = 1, .written = 1024, .wt = true },
	{ .name = "nonvolatile_cache", .start = 8192, .calls = 1, .written = 1024,
	  .nv_cache = true },
	{ .name = "direct_async_dif_fallback", .start = 8192, .calls = 1, .written = 1024,
	  .direct = true, .dif_fallback = true },
};

static void vdisk_write_desc(const struct vdisk_write_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(vdisk_write, vdisk_write_cases, vdisk_write_desc);

static void vdisk_write_test(struct kunit *test)
{
	const struct vdisk_write_case *p = test->param_value;
	struct vdisk_test_fixture *f = test->priv;
	loff_t offset = p->start;
	size_t remaining = 1024;
	unsigned int i;

	f->params.loff = p->start;
	f->params.fua = !p->no_fua;
	f->vdev.o_direct_flag = p->direct;
	f->vdev.wt_flag = p->wt;
	f->vdev.nv_cache = p->nv_cache;
	f->vdev.thin_provisioned = p->thin;
	f->vdev.async = p->dif_fallback;
	f->dev.dev_dif_mode = p->dif_fallback ? SCST_DIF_MODE_TGT : SCST_DIF_MODE_NONE;
	f->data.sync_result = p->flush_error;
	memcpy(f->results, p->results, sizeof(p->results));
	f->result_count = p->result_count;

	KUNIT_EXPECT_EQ(test, fileio_exec_write(&f->params), CMD_SUCCEEDED);
	KUNIT_EXPECT_EQ(test, f->cmd.status, p->status);
	KUNIT_EXPECT_EQ(test, f->completions, 0U);
	KUNIT_EXPECT_EQ(test, f->io_count, p->calls);
	KUNIT_EXPECT_EQ(test, f->written_len, p->written);
	for (i = 0; i < p->written; i++)
		KUNIT_EXPECT_EQ_MSG(test, f->written[i], f->input[i / 512][i % 512],
				    "payload byte %u", i);
	for (i = 0; i < p->calls; i++) {
		KUNIT_EXPECT_EQ(test, f->io_offset[i], offset);
		KUNIT_EXPECT_EQ(test, f->io_length[i], remaining);
		if (i < p->result_count && p->results[i] > 0) {
			offset += p->results[i];
			remaining -= p->results[i];
		}
	}
	if (p->no_fua || p->wt || p->nv_cache) {
		KUNIT_EXPECT_EQ(test, f->flush_count, 0U);
	} else if (p->written == sizeof(f->written)) {
		/* Failed writes above check status and progress, not FUA durability. */
		KUNIT_EXPECT_EQ(test, f->flush_count, 1U);
		vdisk_test_expect_flush(test, 0, &f->data.file, p->start, p->start + 1023);
	}
	KUNIT_EXPECT_EQ(test, f->block_flush_count, 0U);
}

struct vdisk_async_case {
	const char *name;
	bool read;
	bool no_fua;
	bool direct;
	bool wt;
	bool nv_cache;
	bool dsync;
	ssize_t result;
	unsigned int calls;
	u8 status;
};

static const struct vdisk_async_case vdisk_async_cases[] = {
	{ .name = "buffered_fua", .dsync = true, .calls = 1 },
	{ .name = "direct_fua", .direct = true, .dsync = true, .calls = 1 },
	{ .name = "ordinary_writeback", .no_fua = true, .calls = 1 },
	{ .name = "ordinary_direct_write", .no_fua = true, .direct = true, .calls = 1 },
	{ .name = "write_through", .no_fua = true, .wt = true, .dsync = true, .calls = 1 },
	{ .name = "fua_and_write_through", .wt = true, .dsync = true, .calls = 1 },
	{ .name = "fua_nonvolatile_cache", .nv_cache = true, .calls = 1 },
	{ .name = "write_through_nonvolatile_cache", .no_fua = true, .wt = true,
	  .nv_cache = true, .calls = 1 },
	{ .name = "read_ignores_fua", .read = true, .calls = 1 },
	{ .name = "direct_read_ignores_write_through", .read = true, .direct = true,
	  .wt = true, .calls = 1 },
	{ .name = "nowait_eagain_keeps_dsync", .direct = true, .dsync = true,
	  .result = -EAGAIN, .calls = 2 },
	{ .name = "nowait_eopnotsupp_keeps_dsync", .direct = true, .dsync = true,
	  .result = -EOPNOTSUPP, .calls = 2 },
	{ .name = "buffered_eagain_is_error", .dsync = true, .result = -EAGAIN,
	  .calls = 1, .status = SAM_STAT_CHECK_CONDITION },
	{ .name = "async_write_error", .dsync = true, .result = -EIO,
	  .calls = 1, .status = SAM_STAT_CHECK_CONDITION },
	{ .name = "async_read_error", .read = true, .result = -EIO,
	  .calls = 1, .status = SAM_STAT_CHECK_CONDITION },
	{ .name = "queued_fua_completion", .dsync = true, .result = -EIOCBQUEUED, .calls = 1 },
};

static void vdisk_async_desc(const struct vdisk_async_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(vdisk_async, vdisk_async_cases, vdisk_async_desc);

static void vdisk_async_test(struct kunit *test)
{
	const struct vdisk_async_case *p = test->param_value;
	struct vdisk_test_fixture *f = test->priv;
	unsigned int i;
	enum compl_status_e result;

	f->vdev.async = true;
	f->vdev.o_direct_flag = p->direct;
	f->vdev.wt_flag = p->wt;
	f->vdev.nv_cache = p->nv_cache;
	f->params.fua = !p->no_fua;
	f->cmd.data_direction = p->read ? SCST_DATA_READ : SCST_DATA_WRITE;
	if (p->result) {
		f->results[0] = p->result;
		f->result_count = 1;
	}

	result = p->read ? fileio_exec_read(&f->params) : fileio_exec_write(&f->params);
	KUNIT_EXPECT_EQ(test, result, RUNNING_ASYNC);
	KUNIT_EXPECT_EQ(test, f->io_count, p->calls);
	KUNIT_EXPECT_EQ(test, f->read_count, p->read ? p->calls : 0U);
	for (i = 0; i < p->calls; i++) {
		bool dsync = f->io_flags[i] & IOCB_DSYNC;
		bool direct = f->io_flags[i] & IOCB_DIRECT;
		bool nowait = f->io_flags[i] & IOCB_NOWAIT;

		KUNIT_EXPECT_EQ(test, f->io_offset[i], (loff_t)8192);
		KUNIT_EXPECT_EQ(test, f->io_length[i], (size_t)1024);
		KUNIT_EXPECT_EQ_MSG(test, dsync, p->dsync, "I/O %u: IOCB_DSYNC", i);
		KUNIT_EXPECT_EQ_MSG(test, direct, p->direct, "I/O %u: IOCB_DIRECT", i);
		KUNIT_EXPECT_EQ_MSG(test, nowait, p->direct && !i, "I/O %u: IOCB_NOWAIT", i);
	}
	if (p->result == -EIOCBQUEUED) {
		struct kiocb *pending = f->pending;

		KUNIT_EXPECT_EQ(test, f->completions, 0U);
		KUNIT_EXPECT_FALSE(test, f->cmd.completed);
		KUNIT_ASSERT_NOT_NULL(test, pending);
		f->pending = NULL;
		pending->ki_complete(pending, 1024);
	}
	KUNIT_EXPECT_EQ(test, f->completions, 1U);
	KUNIT_EXPECT_EQ(test, f->completion_state, SCST_CMD_STATE_DEFAULT);
	KUNIT_EXPECT_TRUE(test, f->completed_before_callback);
	KUNIT_EXPECT_TRUE(test, f->cmd.completed);
	KUNIT_EXPECT_EQ(test, f->cmd.status, p->status);
	KUNIT_EXPECT_EQ(test, f->flush_count, 0U);
	KUNIT_EXPECT_EQ(test, f->block_flush_count, 0U);
	if (!p->status && p->result != -EIOCBQUEUED) {
		if (!p->read)
			KUNIT_EXPECT_EQ(test, f->written_len, (size_t)1024);
		for (i = 0; i < ARRAY_SIZE(f->input); i++) {
			if (p->read)
				KUNIT_EXPECT_PTR_EQ(test, memchr_inv(f->input[i], 0, 512), NULL);
			else
				KUNIT_EXPECT_EQ(test,
						memcmp(f->written + i * 512, f->input[i], 512), 0);
		}
	}
}

static struct kunit_case vdisk_io_cases[] = {
	KUNIT_CASE_PARAM(vdisk_write_test, vdisk_write_gen_params),
	KUNIT_CASE_PARAM(vdisk_async_test, vdisk_async_gen_params),
	{}
};

scst_kunit_suite(vdisk_io_suite, "VDISK", "-io",
		 .init = vdisk_test_init,
		 .exit = vdisk_test_exit,
		 .test_cases = vdisk_io_cases,
);
