// SPDX-License-Identifier: GPL-2.0-only
#include "../scst_vdisk_fixture.h"

struct vdisk_range_case {
	const char *name;
	loff_t start;
	loff_t length;
	loff_t end;
	int error;
	bool no_cmd;
	u8 status;
};

static const struct vdisk_range_case vdisk_range_cases[] = {
	{ .name = "empty_at_zero" },
	{ .name = "empty_at_nonzero_offset", .start = 8192 },
	{ .name = "one_byte", .start = 8192, .length = 1, .end = 8192 },
	{ .name = "block_at_zero", .length = 512, .end = 511 },
	{ .name = "block_at_nonzero_offset", .start = 8192, .length = 512, .end = 8703 },
	{ .name = "cross_page", .start = 3584, .length = 1024, .end = 4607 },
	{ .name = "above_32_bits", .start = 1LL << 32, .length = 4096,
	  .end = (1LL << 32) + 4095 },
	{ .name = "last_representable_byte", .start = LLONG_MAX - 511, .length = 512,
	  .end = LLONG_MAX },
	{ .name = "write_error_sense", .start = 8192, .length = 512, .end = 8703,
	  .error = -EIO, .status = SAM_STAT_CHECK_CONDITION },
	{ .name = "memory_pressure_busy", .start = 8192, .length = 512, .end = 8703,
	  .error = -ENOMEM, .status = SAM_STAT_BUSY },
	{ .name = "commandless_write_error", .start = 8192, .length = 512, .end = 8703,
	  .error = -EIO, .no_cmd = true },
	{ .name = "commandless_memory_pressure", .start = 8192, .length = 512, .end = 8703,
	  .error = -ENOMEM, .no_cmd = true },
};

static void vdisk_range_desc(const struct vdisk_range_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(vdisk_range, vdisk_range_cases, vdisk_range_desc);

static void vdisk_range_test(struct kunit *test)
{
	const struct vdisk_range_case *p = test->param_value;
	struct vdisk_test_fixture *f = test->priv;
	int ret;

	f->data.sync_result = p->error;
	ret = __vdisk_fsync_fileio(p->start, p->length, &f->dev,
				   p->no_cmd ? NULL : &f->cmd, &f->data.file);
	KUNIT_EXPECT_EQ(test, ret, p->error);
	KUNIT_EXPECT_EQ(test, f->cmd.status, p->status);
	KUNIT_EXPECT_EQ(test, f->completions, 0U);
	/* An empty range may be a no-op or a harmless backend synchronization. */
	if (p->length) {
		KUNIT_EXPECT_EQ(test, f->flush_count, 1U);
		vdisk_test_expect_flush(test, 0, &f->data.file, p->start, p->end);
	}
	if (p->status == SAM_STAT_CHECK_CONDITION) {
		KUNIT_EXPECT_EQ(test, f->sense[2] & 0xf, MEDIUM_ERROR);
		KUNIT_EXPECT_EQ(test, f->sense[12], (u8)0x03);
	}
}

struct vdisk_flush_case {
	const char *name;
	bool async;
	bool no_cmd;
	bool wt;
	bool nv_cache;
	bool nullio;
	bool direct;
	bool blockio;
	unsigned int dif_shift;
	int data_error;
	int dif_error;
	unsigned int files;
	unsigned int blocks;
	int error;
};

static const struct vdisk_flush_case vdisk_flush_cases[] = {
	{ .name = "fileio", .files = 1 },
	{ .name = "async_fileio", .async = true, .files = 1 },
	{ .name = "commandless_async_fileio", .async = true, .no_cmd = true, .files = 1 },
	{ .name = "direct_fileio", .direct = true, .files = 1 },
	{ .name = "async_direct_fileio", .async = true, .direct = true, .files = 1 },
	{ .name = "async_fileio_error", .async = true, .data_error = -EIO,
	  .files = 1, .error = -EIO },
	{ .name = "async_write_through", .async = true, .wt = true },
	{ .name = "commandless_write_through", .async = true, .no_cmd = true, .wt = true },
	{ .name = "async_nonvolatile_cache", .async = true, .nv_cache = true },
	{ .name = "commandless_nonvolatile_cache", .async = true, .no_cmd = true,
	  .nv_cache = true },
	{ .name = "async_nullio", .async = true, .nullio = true },
	{ .name = "commandless_nullio", .async = true, .no_cmd = true, .nullio = true },
	{ .name = "fileio_dif_512", .dif_shift = 9, .files = 2 },
	{ .name = "fileio_dif_4096", .dif_shift = 12, .files = 2 },
	{ .name = "data_error_skips_dif", .dif_shift = 9, .data_error = -EIO,
	  .files = 1, .error = -EIO },
	{ .name = "dif_error_propagated", .dif_shift = 9, .dif_error = -EIO,
	  .files = 2, .error = -EIO },
	{ .name = "blockio", .blockio = true, .blocks = 1 },
	{ .name = "blockio_dif_512", .blockio = true, .dif_shift = 9, .files = 1, .blocks = 1 },
	{ .name = "blockio_dif_4096", .blockio = true, .dif_shift = 12, .files = 1,
	  .blocks = 1 },
	{ .name = "dif_error_skips_block_flush", .blockio = true, .dif_shift = 9,
	  .dif_error = -EIO, .files = 1, .error = -EIO },
};

static void vdisk_flush_desc(const struct vdisk_flush_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(vdisk_flush, vdisk_flush_cases, vdisk_flush_desc);

static void vdisk_flush_test(struct kunit *test)
{
	const struct vdisk_flush_case *p = test->param_value;
	struct vdisk_test_fixture *f = test->priv;
	int ret;

	/* The baseline bypass path dereferences cmd even when IMMED passed NULL. */
	if (p->async && p->no_cmd && (p->wt || p->nv_cache || p->nullio || p->direct)) {
		kunit_skip(test, "commandless cache bypass needs a separate NULL-command fix");
		return;
	}

	f->vdev.wt_flag = p->wt;
	f->vdev.nv_cache = p->nv_cache;
	f->vdev.nullio = p->nullio;
	f->vdev.o_direct_flag = p->direct;
	f->vdev.blockio = p->blockio;
	f->vdev.bdev_desc.bdev = p->blockio ? &f->bdev : NULL;
	f->data.sync_result = p->data_error;
	f->dif.sync_result = p->dif_error;
	if (p->dif_shift) {
		f->vdev.dif_fd = &f->dif.file;
		f->dev.block_shift = p->dif_shift;
		f->dev.block_size = 1U << p->dif_shift;
	}

	ret = vdisk_fsync(8192, 4096, &f->dev, GFP_KERNEL, p->no_cmd ? NULL : &f->cmd,
			  p->async);
	KUNIT_EXPECT_EQ(test, ret, p->error);
	KUNIT_EXPECT_EQ(test, f->flush_count, p->files);
	KUNIT_EXPECT_EQ(test, f->block_flush_count, p->blocks);
	KUNIT_EXPECT_EQ(test, f->completions, p->async && !p->no_cmd ? 1U : 0U);
	if (p->async && !p->no_cmd) {
		KUNIT_EXPECT_EQ(test, f->completion_state, SCST_CMD_STATE_DEFAULT);
		KUNIT_EXPECT_TRUE(test, f->completed_before_callback);
	}
	KUNIT_EXPECT_EQ(test, !!f->cmd.completed, (p->async || p->error) && !p->no_cmd);
	KUNIT_EXPECT_EQ(test, f->cmd.status,
			p->error && !p->no_cmd ? SAM_STAT_CHECK_CONDITION : SAM_STAT_GOOD);
	if (!p->blockio && p->files)
		vdisk_test_expect_flush(test, 0, &f->data.file, 8192, 12287);
	if (p->dif_shift && p->files > !p->blockio) {
		/* 8-byte tags: 16+8 blocks at 512 bytes, 2+1 at 4096 bytes. */
		vdisk_test_expect_flush(test, !p->blockio, &f->dif.file,
					p->dif_shift == 9 ? 128 : 16,
					p->dif_shift == 9 ? 191 : 23);
	}
}

struct vdisk_backend_case {
	const char *name;
	bool closed;
	bool inactive;
	bool nullio;
	bool blockio;
	bool empty;
	int error;
	int expected;
	unsigned int files;
	unsigned int blocks;
};

static const struct vdisk_backend_case vdisk_backend_cases[] = {
	{ .name = "inactive_fileio", .closed = true, .inactive = true, .expected = -ENOMEDIUM },
	{ .name = "unmapped_fileio", .closed = true, .expected = -ENOMEDIUM },
	{ .name = "inactive_blockio", .closed = true, .inactive = true, .blockio = true,
	  .expected = -ENOMEDIUM },
	{ .name = "unmapped_blockio", .closed = true, .blockio = true, .expected = -ENOMEDIUM },
	{ .name = "nullio_without_backend", .closed = true, .nullio = true },
	{ .name = "empty_file", .empty = true },
	{ .name = "open_file", .files = 1 },
	{ .name = "file_error", .error = -EIO, .files = 1, .expected = -EIO },
	{ .name = "file_memory_pressure", .error = -ENOMEM, .files = 1, .expected = -ENOMEM },
	{ .name = "open_block_device", .blockio = true, .blocks = 1 },
	{ .name = "block_error", .blockio = true, .error = -EIO, .blocks = 1, .expected = -EIO },
};

static void vdisk_backend_desc(const struct vdisk_backend_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(vdisk_backend, vdisk_backend_cases, vdisk_backend_desc);

static void vdisk_backend_test(struct kunit *test)
{
	const struct vdisk_backend_case *p = test->param_value;
	struct vdisk_test_fixture *f = test->priv;
	int ret;

	/* Avoid dereferencing a closed backend until its lifetime is fixed. */
	if (p->closed && !p->nullio) {
		kunit_skip(test, "closed-backend sync needs a separate lifetime fix");
		return;
	}

	f->vdev.dev_active = !p->inactive;
	f->vdev.nullio = p->nullio;
	f->vdev.blockio = p->blockio;
	f->vdev.fd = p->closed || p->blockio ? NULL : &f->data.file;
	f->vdev.bdev_desc.bdev = p->blockio && !p->closed ? &f->bdev : NULL;
	f->data.inode.i_size = p->empty ? 0 : 16384;
	f->data.sync_result = p->error;
	f->block_flush_result = p->error;
	f->sysfs_sync = true;

	/* Exercise the existing store callback with an unregistered private device. */
	ret = vdisk_sysfs_sync_store(&f->dev.dev_kobj, NULL, "1", 1);
	KUNIT_EXPECT_EQ(test, ret, p->expected ? p->expected : 1);
	/* Empty files may still need metadata synchronization. */
	if (!p->empty)
		KUNIT_EXPECT_EQ(test, f->flush_count, p->files);
	KUNIT_EXPECT_EQ(test, f->block_flush_count, p->blocks);
	KUNIT_EXPECT_EQ(test, f->completions, 0U);
	KUNIT_EXPECT_EQ(test, !!f->vdev.dev_active, !p->inactive);
	KUNIT_EXPECT_PTR_EQ(test, f->vdev.fd, p->closed || p->blockio ? NULL : &f->data.file);
	if (p->files)
		vdisk_test_expect_flush(test, 0, &f->data.file, 0, 16383);
}

static struct kunit_case vdisk_sync_cases[] = {
	KUNIT_CASE_PARAM(vdisk_range_test, vdisk_range_gen_params),
	KUNIT_CASE_PARAM(vdisk_flush_test, vdisk_flush_gen_params),
	KUNIT_CASE_PARAM(vdisk_backend_test, vdisk_backend_gen_params),
	{}
};

scst_kunit_suite(vdisk_sync_suite, "VDISK", "-sync",
		 .init = vdisk_test_init,
		 .exit = vdisk_test_exit,
		 .test_cases = vdisk_sync_cases,
);
