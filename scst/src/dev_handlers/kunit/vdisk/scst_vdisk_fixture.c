// SPDX-License-Identifier: GPL-2.0-only
#include "scst_vdisk_fixture.h"

static ssize_t vdisk_test_iter(struct kiocb *iocb, struct iov_iter *iter, bool write)
{
	struct vdisk_test_file *file = iocb->ki_filp->private_data;
	struct vdisk_test_fixture *f = file->fixture;
	struct kunit *test = kunit_get_current_test();
	unsigned int n = f->io_count++;
	size_t length = iov_iter_count(iter);
	ssize_t ret;

	/* Bound retries even if the production short-write loop regresses. */
	if (n >= ARRAY_SIZE(f->io_offset)) {
		KUNIT_FAIL(test, "unexpected backend retry");
		return -EIO;
	}
	f->io_offset[n] = iocb->ki_pos;
	f->io_length[n] = length;
	f->io_flags[n] = iocb->ki_flags;
	f->read_count += !write;
	ret = n < f->result_count ? f->results[n] : length;
	if (ret == -EIOCBQUEUED) {
		/* No work is scheduled: the test owns delivery of this completion. */
		f->pending = iocb;
		return ret;
	}
	if (ret < 0)
		return ret;
	if (ret > length || ret > sizeof(f->written) - f->written_len) {
		KUNIT_FAIL(test, "invalid fake I/O size");
		return -EIO;
	}
	if (write) {
		KUNIT_EXPECT_EQ(test, copy_from_iter(f->written + f->written_len, ret, iter),
				(size_t)ret);
		f->written_len += ret;
	} else {
		KUNIT_EXPECT_EQ(test, iov_iter_zero(ret, iter), (size_t)ret);
	}
	iocb->ki_pos += ret;
	return ret;
}

static ssize_t vdisk_test_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	return vdisk_test_iter(iocb, iter, true);
}

static ssize_t vdisk_test_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	return vdisk_test_iter(iocb, iter, false);
}

static int vdisk_test_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct vdisk_test_file *backend = file->private_data;
	struct vdisk_test_fixture *f = backend->fixture;
	unsigned int n = f->flush_count++;

	if (n >= ARRAY_SIZE(f->flushes)) {
		KUNIT_FAIL(kunit_get_current_test(), "unexpected extra flush");
		return -EIO;
	}
	f->flushes[n] = (struct vdisk_test_flush) {
		.file = file, .start = start, .end = end,
		.io_count = f->io_count, .written_len = f->written_len,
		.completions = f->completions,
		.cmd_refs = kref_read(&f->cmd.cmd_ref),
	};
	return backend->sync_result;
}

static const struct file_operations vdisk_test_fops = {
	.write_iter = vdisk_test_write_iter,
	.read_iter = vdisk_test_read_iter,
	.fsync = vdisk_test_fsync,
};

static void vdisk_test_file_init(struct vdisk_test_file *file, struct vdisk_test_fixture *f)
{
	file->fixture = f;
	file->file.f_op = &vdisk_test_fops;
	file->file.f_inode = &file->inode;
	file->file.f_mapping = &file->mapping;
	file->file.f_mode = FMODE_READ | FMODE_WRITE;
	file->file.private_data = file;
	file->mapping.host = &file->inode;
	/* A synthetic special inode avoids taking a real superblock freeze lock. */
	file->inode.i_mode = S_IFCHR;
	file->inode.i_size = 16384;
}

static int vdisk_test_block_flush(struct block_device *bdev, gfp_t gfp_mask, bool report_error,
				  struct scst_cmd *cmd, bool async)
{
	struct kunit *test = kunit_get_current_test();
	struct vdisk_test_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, bdev, &f->bdev);
	if (f->vdev.dif_fd) {
		KUNIT_EXPECT_EQ(test, f->flush_count, 1U);
		KUNIT_EXPECT_PTR_EQ(test, f->flushes[0].file, f->vdev.dif_fd);
	}
	if (f->sysfs_sync) {
		KUNIT_EXPECT_FALSE(test, report_error);
		KUNIT_EXPECT_FALSE(test, async);
		KUNIT_EXPECT_PTR_EQ(test, cmd, NULL);
	}
	f->block_flush_count++;
	return f->block_flush_result;
}

/*
 * The registered callback retains the mutable parameter type required by its
 * interface.
 */
/* cppcheck-suppress constParameterCallback symbolName=cmd */
static int vdisk_test_no_dif(struct scst_cmd *cmd)
{
	return 0;
}

static void vdisk_test_done(struct scst_cmd *cmd, int state, enum scst_exec_context context)
{
	struct vdisk_test_fixture *f = container_of(cmd, struct vdisk_test_fixture, cmd);

	f->completions++;
	f->completion_state = state;
	f->completed_before_callback = cmd->completed;
}

int vdisk_test_init(struct kunit *test)
{
	struct vdisk_test_fixture *f;
	unsigned int i, j;

	test->priv = NULL;
	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;
	test->priv = f;
	f->dev.dh_priv = &f->vdev;
	f->dev.block_size = 512;
	f->dev.block_shift = 9;
	f->dev.dev_dif_fn = vdisk_test_no_dif;
	f->vdev.dev = &f->dev;
	spin_lock_init(&f->vdev.flags_lock);
	f->vdev.dev_active = true;
	f->vdev.file_size = 16384;
	vdisk_test_file_init(&f->data, f);
	vdisk_test_file_init(&f->dif, f);
	f->vdev.fd = &f->data.file;
	f->cmd.cdb = f->cdb;
	kref_init(&f->cmd.cmd_ref);
	f->cmd.dev = &f->dev;
	f->cmd.sess = &f->sess;
	f->cmd.cmd_gfp_mask = GFP_KERNEL;
	f->cmd.data_direction = SCST_DATA_WRITE;
	f->cmd.data_len = sizeof(f->written);
	f->cmd.bufflen = sizeof(f->written);
	f->cmd.resp_data_len = sizeof(f->written);
	f->cmd.sense = f->sense;
	f->cmd.sense_buflen = sizeof(f->sense);
	f->cmd.scst_cmd_done = vdisk_test_done;
	f->params.cmd = &f->cmd;
	f->params.loff = 8192;
	f->params.fua = true;
	atomic_set(&f->sess.sess_cmd_count, 1);
	f->sess.initiator_name = "kunit";
	f->sess.init_phase = SCST_SESS_IPH_READY;
	sg_init_table(f->sg, ARRAY_SIZE(f->sg));
	for (i = 0; i < ARRAY_SIZE(f->sg); i++) {
		f->input[i] = kunit_kmalloc(test, 512, GFP_KERNEL);
		if (!f->input[i])
			return -ENOMEM;
		for (j = 0; j < 512; j++)
			f->input[i][j] = (j * 17 + i * 73) & 0xff;
		sg_set_buf(&f->sg[i], f->input[i], 512);
	}
	f->cmd.sg = f->sg;
	f->cmd.sg_cnt = ARRAY_SIZE(f->sg);
	kunit_activate_static_stub(test, vdisk_blockio_flush, vdisk_test_block_flush);
	return 0;
}

void vdisk_test_exit(struct kunit *test)
{
	struct vdisk_test_fixture *f = test->priv;

	if (!f)
		return;
	/* A failed assertion must not leave a synthetic completion outstanding. */
	if (f->pending)
		f->pending->ki_complete(f->pending, -EIO);
	vdisk_on_free_cmd_params(&f->params);
	test->priv = NULL;
}

void vdisk_test_expect_flush(struct kunit *test, unsigned int n, struct file *file,
			     loff_t start, loff_t end)
{
	struct vdisk_test_fixture *f = test->priv;

	KUNIT_ASSERT_LT(test, n, f->flush_count);
	KUNIT_ASSERT_LT(test, n, (unsigned int)ARRAY_SIZE(f->flushes));
	KUNIT_EXPECT_PTR_EQ(test, f->flushes[n].file, file);
	KUNIT_EXPECT_EQ(test, f->flushes[n].start, start);
	KUNIT_EXPECT_EQ(test, f->flushes[n].end, end);
}
