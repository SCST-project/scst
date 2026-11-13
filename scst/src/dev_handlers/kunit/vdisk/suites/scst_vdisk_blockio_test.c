// SPDX-License-Identifier: GPL-2.0-only
#include "../scst_vdisk_fixture.h"

#define BLOCKIO_TEST_DATA_LEN 1024

struct blockio_fixture {
	struct scst_cmd cmd;
	struct scst_device dev;
	struct scst_session sess;
	struct scst_vdisk_dev vdev;
	struct vdisk_cmd_params params;
	struct gendisk *disk;
	struct bio_set bioset;
	bool bioset_ready;
	struct scatterlist sg[2];
	u8 sense[SCST_SENSE_BUFFERSIZE];
	struct vdisk_test_response response;
	struct bio *pending[2];
	struct bio *held_bio;
	blk_status_t status[2];
	blk_opf_t flags[2];
	sector_t sector[2];
	unsigned int bytes[2];
	unsigned int allocations;
	unsigned int fail_alloc_at;
	unsigned int submissions;
	unsigned int completions;
	unsigned int flushes;
	unsigned int discards;
	int backend_error;
	ssize_t read_result;
	bool single_vec;
	bool inline_io;
};

static void blockio_done(struct scst_cmd *cmd, int state, enum scst_exec_context context)
{
	struct blockio_fixture *f = container_of(cmd, struct blockio_fixture, cmd);
	struct kunit *test = kunit_get_current_test();

	KUNIT_EXPECT_TRUE(test, cmd->completed);
	KUNIT_EXPECT_EQ(test, state, SCST_CMD_STATE_DEFAULT);
	if (!f->completions++)
		vdisk_test_save_response(&f->response, cmd);
}

static struct bio *blockio_alloc(int nr_vecs, gfp_t gfp_mask, struct bio_set *bs)
{
	struct kunit *test = kunit_get_current_test();
	struct blockio_fixture *f = test->priv;
	struct bio *bio;

	KUNIT_EXPECT_PTR_EQ(test, bs, &f->bioset);
	if (++f->allocations == f->fail_alloc_at)
		return NULL;
	/* Force one BIO per SG entry without relying on BIO_MAX_VECS or page size. */
	bio = bio_alloc_bioset(NULL, f->single_vec ? 1 : nr_vecs, 0, gfp_mask, bs);
	if (bio && f->fail_alloc_at && !f->held_bio) {
		/* Keep the first BIO alive to check its reference after allocation failure. */
		bio_get(bio);
		f->held_bio = bio;
	}
	return bio;
}

static void blockio_submit(struct bio *bio)
{
	struct kunit *test = kunit_get_current_test();
	struct blockio_fixture *f = test->priv;
	unsigned int n = f->submissions++;

	KUNIT_EXPECT_PTR_EQ(test, bio->bi_bdev, f->disk->part0);
	if (n >= ARRAY_SIZE(f->pending)) {
		KUNIT_FAIL(test, "unexpected extra BIO");
		bio->bi_status = BLK_STS_IOERR;
		bio_endio(bio);
		return;
	}
	f->flags[n] = bio->bi_opf;
	f->sector[n] = bio->bi_iter.bi_sector;
	f->bytes[n] = bio->bi_iter.bi_size;
	if (bio_op(bio) == REQ_OP_READ && bio->bi_iter.bi_size)
		zero_fill_bio(bio);
	if (f->inline_io) {
		/* The submitter reference must keep the command alive until it returns. */
		KUNIT_EXPECT_EQ(test, f->completions, 0U);
		bio->bi_status = f->status[n];
		bio_endio(bio);
	} else {
		f->pending[n] = bio;
	}
}

static void blockio_complete(struct kunit *test, unsigned int n, blk_status_t status)
{
	struct blockio_fixture *f = test->priv;
	struct bio *bio;

	KUNIT_ASSERT_LT(test, n, (unsigned int)ARRAY_SIZE(f->pending));
	bio = f->pending[n];
	KUNIT_ASSERT_NOT_NULL(test, bio);
	f->pending[n] = NULL;
	bio->bi_status = status;
	bio_endio(bio);
}

static int blockio_flush(struct block_device *bdev, gfp_t gfp_mask)
{
	struct kunit *test = kunit_get_current_test();
	struct blockio_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, bdev, f->disk->part0);
	f->flushes++;
	return f->backend_error;
}

static int blockio_discard(struct block_device *bdev, sector_t start, sector_t sectors,
			   gfp_t gfp_mask)
{
	struct kunit *test = kunit_get_current_test();
	struct blockio_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, bdev, f->disk->part0);
	KUNIT_EXPECT_EQ(test, start, (sector_t)8);
	KUNIT_EXPECT_EQ(test, sectors, (sector_t)2);
	f->discards++;
	return f->backend_error;
}

static ssize_t blockio_read_result(struct scst_vdisk_dev *vdev, void *buf, size_t len,
				   loff_t *loff)
{
	struct kunit *test = kunit_get_current_test();
	struct blockio_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, vdev, &f->vdev);
	KUNIT_EXPECT_EQ(test, len, (size_t)BLOCKIO_TEST_DATA_LEN);
	return f->read_result;
}

static int blockio_init(struct kunit *test)
{
	struct queue_limits limits = { .logical_block_size = 512 };
	struct blockio_fixture *f;
	unsigned int i;
	int ret;

	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;
	test->priv = f;
	sg_init_table(f->sg, ARRAY_SIZE(f->sg));
	for (i = 0; i < ARRAY_SIZE(f->sg); i++) {
		void *data = kunit_kzalloc(test, PAGE_SIZE, GFP_KERNEL);

		if (!data)
			return -ENOMEM;
		/* Distinct pages with short segments cannot merge into one bvec. */
		sg_set_buf(&f->sg[i], data, BLOCKIO_TEST_DATA_LEN / 2);
	}
	/* Private, unregistered disk: every backend entry point is stubbed below. */
	f->disk = blk_alloc_disk(&limits, NUMA_NO_NODE);
	if (IS_ERR(f->disk)) {
		ret = PTR_ERR(f->disk);
		f->disk = NULL;
		return ret;
	}
	ret = bioset_init(&f->bioset, 4, 0, BIOSET_NEED_BVECS);
	if (ret) {
		put_disk(f->disk);
		f->disk = NULL;
		return ret;
	}
	f->bioset_ready = true;
	f->vdev.bdev_desc.bdev = f->disk->part0;
	f->vdev.vdisk_bioset = &f->bioset;
	f->vdev.blockio = true;
	f->vdev.thin_provisioned = true;
	f->vdev.nblocks = 4096;
	f->vdev.file_size = f->vdev.nblocks << 9;
	f->vdev.dev = &f->dev;
	f->dev.dh_priv = &f->vdev;
	f->dev.block_size = 512;
	f->dev.block_shift = 9;
	f->cmd.dev = &f->dev;
	f->cmd.sess = &f->sess;
	f->cmd.cdb = f->cmd.cdb_buf;
	f->cmd.cmd_gfp_mask = GFP_KERNEL;
	f->cmd.lba = 8;
	f->cmd.data_len = BLOCKIO_TEST_DATA_LEN;
	f->cmd.bufflen = BLOCKIO_TEST_DATA_LEN;
	f->cmd.resp_data_len = BLOCKIO_TEST_DATA_LEN;
	f->cmd.sg = f->sg;
	f->cmd.sg_cnt = ARRAY_SIZE(f->sg);
	f->cmd.sense = f->sense;
	f->cmd.sense_buflen = sizeof(f->sense);
	f->cmd.scst_cmd_done = blockio_done;
	kref_init(&f->cmd.cmd_ref);
	f->sess.initiator_name = "kunit";
	f->sess.init_phase = SCST_SESS_IPH_READY;
	atomic_set(&f->sess.sess_cmd_count, 1);
	f->params.cmd = &f->cmd;
	f->params.loff = 8 << 9;
	kunit_activate_static_stub(test, vdisk_alloc_bio, blockio_alloc);
	kunit_activate_static_stub(test, vdisk_submit_bio, blockio_submit);
	kunit_activate_static_stub(test, vdisk_submit_flush_bio, blockio_submit);
	kunit_activate_static_stub(test, vdisk_issue_flush, blockio_flush);
	kunit_activate_static_stub(test, vdisk_issue_discard, blockio_discard);
	return 0;
}

/* KUnit's suite exit callback requires a mutable struct kunit pointer. */
/* cppcheck-suppress constParameterCallback symbolName=test */
static void blockio_exit(struct kunit *test)
{
	struct blockio_fixture *f = test->priv;
	unsigned int i;

	if (!f)
		return;
	/* Drain real end-I/O callbacks even after an assertion aborts the test. */
	for (i = 0; i < ARRAY_SIZE(f->pending); i++) {
		struct bio *bio = f->pending[i];

		if (!bio)
			continue;
		f->pending[i] = NULL;
		bio->bi_status = BLK_STS_IOERR;
		bio_endio(bio);
	}
	if (f->held_bio) {
		/* Recover a leaked production reference before dropping the test reference. */
		if (atomic_read(&f->held_bio->__bi_cnt) == 2)
			bio_put(f->held_bio);
		bio_put(f->held_bio);
	}
	if (f->bioset_ready)
		bioset_exit(&f->bioset);
	if (f->disk)
		put_disk(f->disk);
}

struct blockio_error_case {
	const char *name;
	blk_status_t status;
	int error;
	u8 read_key, read_asc;
	u8 write_key, write_asc, write_ascq;
	u8 other_key, other_asc;
};

/* Literal protocol expectations also pin the mappings outside ENOLINK. */
static const struct blockio_error_case blockio_errors[] = {
	{ "success", BLK_STS_OK, 0 },
	{ "transport", BLK_STS_TRANSPORT, -ENOLINK,
	  NOT_READY, 0x08, NOT_READY, 0x08, 0, NOT_READY, 0x08 },
	{ "io_error", BLK_STS_IOERR, -EIO,
	  MEDIUM_ERROR, 0x11, MEDIUM_ERROR, 0x03, 0, MEDIUM_ERROR, 0x03 },
	{ "offline", BLK_STS_OFFLINE, -ENODEV,
	  MEDIUM_ERROR, 0x11, MEDIUM_ERROR, 0x03, 0, MEDIUM_ERROR, 0x03 },
	{ "medium", BLK_STS_MEDIUM, -ENODATA,
	  MEDIUM_ERROR, 0x11, MEDIUM_ERROR, 0x03, 0, MEDIUM_ERROR, 0x03 },
	{ "protection", BLK_STS_PROTECTION, -EILSEQ,
	  MEDIUM_ERROR, 0x11, MEDIUM_ERROR, 0x03, 0, MEDIUM_ERROR, 0x03 },
	{ "space", BLK_STS_NOSPC, -ENOSPC,
	  MEDIUM_ERROR, 0x11, DATA_PROTECT, 0x27, 0x07, MEDIUM_ERROR, 0x03 },
	{ "target", BLK_STS_TARGET, -EREMOTEIO,
	  MEDIUM_ERROR, 0x11, MEDIUM_ERROR, 0x03, 0, MEDIUM_ERROR, 0x03 },
	{ "unsupported", BLK_STS_NOTSUPP, -EOPNOTSUPP,
	  MEDIUM_ERROR, 0x11, MEDIUM_ERROR, 0x03, 0, MEDIUM_ERROR, 0x03 },
	{ "resource", BLK_STS_RESOURCE, -ENOMEM,
	  MEDIUM_ERROR, 0x11, MEDIUM_ERROR, 0x03, 0, MEDIUM_ERROR, 0x03 },
	{ "again", BLK_STS_AGAIN, -EAGAIN,
	  MEDIUM_ERROR, 0x11, MEDIUM_ERROR, 0x03, 0, MEDIUM_ERROR, 0x03 },
};

static void blockio_error_desc(const struct blockio_error_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(blockio_error, blockio_errors, blockio_error_desc);

static void blockio_expect_result(struct kunit *test, int error, u8 key, u8 asc, u8 ascq,
				  int good_len)
{
	struct blockio_fixture *f = test->priv;
	struct vdisk_test_response response = {};

	vdisk_test_save_response(&response, &f->cmd);
	if (error) {
		vdisk_test_expect_sense(test, &response, key, asc, ascq);
		if (f->completions)
			vdisk_test_expect_sense(test, &f->response, key, asc, ascq);
	} else {
		vdisk_test_expect_response(test, &response, SAM_STAT_GOOD, good_len);
		if (f->completions)
			vdisk_test_expect_response(test, &f->response, SAM_STAT_GOOD, good_len);
	}
}

static void blockio_rw_test(struct kunit *test, bool write, bool inline_io)
{
	const struct blockio_error_case *p = test->param_value;
	struct blockio_fixture *f = test->priv;
	unsigned int i;

	f->single_vec = true;
	f->inline_io = inline_io;
	f->status[0] = p->status;
	f->cmd.data_direction = write ? SCST_DATA_WRITE : SCST_DATA_READ;
	blockio_exec_rw(&f->params, write, write);
	KUNIT_ASSERT_EQ(test, f->submissions, 2U);
	for (i = 0; i < 2; i++) {
		KUNIT_EXPECT_TRUE(test, (f->flags[i] & REQ_OP_MASK) ==
				  (write ? REQ_OP_WRITE : REQ_OP_READ));
		KUNIT_EXPECT_EQ(test, !!(f->flags[i] & REQ_FUA), write);
		KUNIT_EXPECT_EQ(test, f->sector[i], (sector_t)(8 + i));
		KUNIT_EXPECT_EQ(test, f->bytes[i], BLOCKIO_TEST_DATA_LEN / 2);
	}
	if (!inline_io) {
		KUNIT_EXPECT_EQ(test, f->completions, 0U);
		blockio_complete(test, 0, p->status);
		KUNIT_EXPECT_EQ(test, f->completions, 0U);
		blockio_complete(test, 1, BLK_STS_OK);
	}
	KUNIT_EXPECT_EQ(test, f->completions, 1U);
	blockio_expect_result(test, p->error, write ? p->write_key : p->read_key,
			      write ? p->write_asc : p->read_asc, write ? p->write_ascq : 0,
			      BLOCKIO_TEST_DATA_LEN);
	KUNIT_EXPECT_EQ(test, !!f->cmd.deferred_dif_read_check, !write && !p->error);
}

static void blockio_read_test(struct kunit *test)
{
	blockio_rw_test(test, false, false);
}

static void blockio_write_fua_test(struct kunit *test)
{
	blockio_rw_test(test, true, false);
}

static void blockio_inline_test(struct kunit *test)
{
	blockio_rw_test(test, true, true);
}

static void blockio_flush_sync_test(struct kunit *test)
{
	const struct blockio_error_case *p = test->param_value;
	struct blockio_fixture *f = test->priv;

	f->backend_error = p->error;
	f->cmd.resp_data_len = 0;
	KUNIT_EXPECT_EQ(test, vdisk_blockio_flush(f->disk->part0, GFP_KERNEL, false,
						  &f->cmd, false), p->error);
	KUNIT_EXPECT_EQ(test, f->flushes, 1U);
	KUNIT_EXPECT_EQ(test, f->submissions, 0U);
	KUNIT_EXPECT_EQ(test, f->completions, 0U);
	blockio_expect_result(test, p->error, p->other_key, p->other_asc, 0, 0);
}

static void blockio_flush_async_test(struct kunit *test)
{
	const struct blockio_error_case *p = test->param_value;
	struct blockio_fixture *f = test->priv;

	f->cmd.resp_data_len = 0;
	KUNIT_EXPECT_EQ(test, vdisk_synchronize_cache(&f->params), RUNNING_ASYNC);
	KUNIT_ASSERT_EQ(test, f->submissions, 1U);
	KUNIT_EXPECT_EQ(test, f->completions, 0U);
	blockio_complete(test, 0, p->status);
	KUNIT_EXPECT_EQ(test, f->completions, 1U);
	blockio_expect_result(test, p->error, p->other_key, p->other_asc, 0, 0);
}

static void blockio_flush_immed_test(struct kunit *test)
{
	const struct blockio_error_case *p = test->param_value;
	struct blockio_fixture *f = test->priv;

	f->cmd.cdb[1] = 2;
	f->cmd.resp_data_len = 0;
	KUNIT_EXPECT_EQ(test, vdisk_synchronize_cache(&f->params), RUNNING_ASYNC);
	KUNIT_ASSERT_EQ(test, f->submissions, 1U);
	KUNIT_EXPECT_EQ(test, f->completions, 1U);
	KUNIT_EXPECT_EQ(test, kref_read(&f->cmd.cmd_ref), 1U);
	KUNIT_ASSERT_NOT_NULL(test, f->pending[0]);
	KUNIT_EXPECT_PTR_EQ(test, f->pending[0]->bi_private, NULL);
	blockio_complete(test, 0, p->status);
	KUNIT_EXPECT_EQ(test, f->completions, 1U);
	blockio_expect_result(test, 0, 0, 0, 0, 0);
}

static void blockio_discard_test(struct kunit *test)
{
	const struct blockio_error_case *p = test->param_value;
	struct blockio_fixture *f = test->priv;

	f->backend_error = p->error;
	f->cmd.resp_data_len = 0;
	KUNIT_EXPECT_EQ(test, vdisk_unmap_range(&f->cmd, &f->vdev, 8, 2), p->error ? -EIO : 0);
	KUNIT_EXPECT_EQ(test, f->discards, 1U);
	KUNIT_EXPECT_EQ(test, f->completions, 0U);
	blockio_expect_result(test, p->error, p->other_key, p->other_asc, 0, 0);
}

static void blockio_flush_sync_prior_sense_test(struct kunit *test)
{
	struct blockio_fixture *f = test->priv;

	KUNIT_ASSERT_EQ(test, scst_set_cmd_error(&f->cmd, ABORTED_COMMAND, 0x10, 0x02), 0);
	f->backend_error = -ENOLINK;
	KUNIT_EXPECT_EQ(test, vdisk_blockio_flush(f->disk->part0, GFP_KERNEL, false,
						  &f->cmd, false), -ENOLINK);
	KUNIT_EXPECT_EQ(test, f->flushes, 1U);
	KUNIT_EXPECT_EQ(test, f->submissions, 0U);
	KUNIT_EXPECT_EQ(test, f->completions, 0U);
	blockio_expect_result(test, -ENOLINK, ABORTED_COMMAND, 0x10, 0x02, 0);
}

static void blockio_flush_async_prior_sense_test(struct kunit *test)
{
	struct blockio_fixture *f = test->priv;

	f->cmd.resp_data_len = 0;
	KUNIT_EXPECT_EQ(test, vdisk_synchronize_cache(&f->params), RUNNING_ASYNC);
	KUNIT_ASSERT_EQ(test, f->submissions, 1U);
	KUNIT_EXPECT_EQ(test, f->completions, 0U);
	KUNIT_ASSERT_EQ(test, scst_set_cmd_error(&f->cmd, ABORTED_COMMAND, 0x10, 0x02), 0);
	blockio_complete(test, 0, BLK_STS_TRANSPORT);
	KUNIT_EXPECT_EQ(test, f->completions, 1U);
	blockio_expect_result(test, -ENOLINK, ABORTED_COMMAND, 0x10, 0x02, 0);
}

static void blockio_discard_prior_sense_test(struct kunit *test)
{
	struct blockio_fixture *f = test->priv;

	KUNIT_ASSERT_EQ(test, scst_set_cmd_error(&f->cmd, ABORTED_COMMAND, 0x10, 0x02), 0);
	f->backend_error = -ENOLINK;
	KUNIT_EXPECT_EQ(test, vdisk_unmap_range(&f->cmd, &f->vdev, 8, 2), -EIO);
	KUNIT_EXPECT_EQ(test, f->discards, 1U);
	KUNIT_EXPECT_EQ(test, f->completions, 0U);
	blockio_expect_result(test, -ENOLINK, ABORTED_COMMAND, 0x10, 0x02, 0);
}

static void blockio_verify_test(struct kunit *test)
{
	const struct blockio_error_case *p = test->param_value;
	struct blockio_fixture *f = test->priv;

	f->inline_io = true;
	f->status[0] = p->status;
	f->cmd.data_direction = SCST_DATA_NONE;
	f->cmd.resp_data_len = 0;
	KUNIT_EXPECT_EQ(test, vdev_exec_verify(&f->params), CMD_SUCCEEDED);
	KUNIT_EXPECT_EQ(test, f->flushes, 1U);
	KUNIT_EXPECT_EQ(test, f->submissions, 1U);
	KUNIT_EXPECT_EQ(test, f->completions, 0U);
	KUNIT_EXPECT_TRUE(test, (f->flags[0] & REQ_OP_MASK) == REQ_OP_READ);
	KUNIT_EXPECT_TRUE(test, f->flags[0] & REQ_SYNC);
	if (p->error == -EAGAIN)
		KUNIT_EXPECT_EQ(test, f->cmd.status, (u8)SAM_STAT_BUSY);
	else
		blockio_expect_result(test, p->error, p->read_key, p->read_asc, 0, 0);
}

static void blockio_verify_flush_test(struct kunit *test)
{
	struct blockio_fixture *f = test->priv;

	/* A regression that continues into the read must fail without waiting. */
	f->inline_io = true;
	f->backend_error = -ENOLINK;
	f->cmd.data_direction = SCST_DATA_NONE;
	KUNIT_EXPECT_EQ(test, vdev_exec_verify(&f->params), CMD_SUCCEEDED);
	KUNIT_EXPECT_EQ(test, f->flushes, 1U);
	KUNIT_EXPECT_EQ(test, f->submissions, 0U);
	KUNIT_EXPECT_EQ(test, f->completions, 0U);
	blockio_expect_result(test, -ENOLINK, NOT_READY, 0x08, 0, 0);
}

struct blockio_verify_case {
	const char *name;
	bool fileio;
	ssize_t result;
};

static const struct blockio_verify_case blockio_verify_cases[] = {
	{ "fileio_enolink", true, -ENOLINK },
	{ "short_block_read", false, BLOCKIO_TEST_DATA_LEN - 1 },
	{ "zero_block_read", false, 0 },
};

static void blockio_verify_desc(const struct blockio_verify_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(blockio_verify, blockio_verify_cases, blockio_verify_desc);

static void blockio_verify_fallback_test(struct kunit *test)
{
	const struct blockio_verify_case *p = test->param_value;
	struct blockio_fixture *f = test->priv;

	f->vdev.blockio = !p->fileio;
	f->vdev.nv_cache = true;
	f->read_result = p->result;
	f->cmd.data_direction = SCST_DATA_NONE;
	kunit_activate_static_stub(test, vdev_read_sync, blockio_read_result);
	KUNIT_EXPECT_EQ(test, vdev_exec_verify(&f->params), CMD_SUCCEEDED);
	KUNIT_EXPECT_EQ(test, f->submissions, 0U);
	KUNIT_EXPECT_EQ(test, f->completions, 0U);
	blockio_expect_result(test, -EIO, MEDIUM_ERROR, 0x11, 0, 0);
}

struct blockio_compare_case {
	const char *name;
	blk_status_t status;
	bool mismatch;
	unsigned int reads;
	u8 key, asc;
};

static const struct blockio_compare_case blockio_compare_cases[] = {
	{ "matching_data", BLK_STS_OK, false, 2, 0, 0 },
	{ "miscompare", BLK_STS_OK, true, 1, MISCOMPARE, 0x1d },
	{ "transport_before_compare", BLK_STS_TRANSPORT, true, 1, NOT_READY, 0x08 },
	{ "medium_before_compare", BLK_STS_MEDIUM, true, 1, MEDIUM_ERROR, 0x11 },
};

static void blockio_compare_desc(const struct blockio_compare_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(blockio_compare, blockio_compare_cases, blockio_compare_desc);

static void blockio_compare_test(struct kunit *test)
{
	const struct blockio_compare_case *p = test->param_value;
	struct blockio_fixture *f = test->priv;

	f->inline_io = true;
	f->status[0] = p->status;
	f->cmd.data_direction = SCST_DATA_WRITE;
	f->cmd.resp_data_len = 0;
	if (p->mismatch)
		memset(sg_virt(f->sg), 0xa5, f->sg[0].length);
	KUNIT_EXPECT_EQ(test, vdev_exec_verify(&f->params), CMD_SUCCEEDED);
	KUNIT_EXPECT_EQ(test, f->flushes, 1U);
	KUNIT_EXPECT_EQ(test, f->submissions, p->reads);
	KUNIT_EXPECT_EQ(test, f->completions, 0U);
	blockio_expect_result(test, p->key ? -EIO : 0, p->key, p->asc, 0, 0);
}

struct blockio_order_case {
	const char *name;
	blk_status_t first, second;
	bool write;
	bool reverse;
	bool prior_dif;
	u8 key, asc, ascq;
};

static const struct blockio_order_case blockio_order_cases[] = {
	{ "success_then_transport", BLK_STS_OK, BLK_STS_TRANSPORT,
	  false, true, false, NOT_READY, 0x08, 0 },
	{ "transport_then_medium", BLK_STS_TRANSPORT, BLK_STS_MEDIUM,
	  false, false, false, NOT_READY, 0x08, 0 },
	{ "medium_then_transport", BLK_STS_MEDIUM, BLK_STS_TRANSPORT,
	  false, true, false, MEDIUM_ERROR, 0x11, 0 },
	{ "transport_then_nospc", BLK_STS_TRANSPORT, BLK_STS_NOSPC,
	  true, true, false, NOT_READY, 0x08, 0 },
	{ "nospc_then_transport", BLK_STS_NOSPC, BLK_STS_TRANSPORT,
	  true, false, false, DATA_PROTECT, 0x27, 0x07 },
	{ "prior_dif_error", BLK_STS_TRANSPORT, BLK_STS_TRANSPORT,
	  true, true, true, ABORTED_COMMAND, 0x10, 0x02 },
};

static void blockio_order_desc(const struct blockio_order_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(blockio_order, blockio_order_cases, blockio_order_desc);

static void blockio_order_test(struct kunit *test)
{
	const struct blockio_order_case *p = test->param_value;
	struct blockio_fixture *f = test->priv;

	f->single_vec = true;
	f->cmd.data_direction = p->write ? SCST_DATA_WRITE : SCST_DATA_READ;
	blockio_exec_rw(&f->params, p->write, false);
	KUNIT_ASSERT_EQ(test, f->submissions, 2U);
	KUNIT_EXPECT_EQ(test, f->completions, 0U);
	if (p->prior_dif)
		scst_set_cmd_error(&f->cmd,
				   SCST_LOAD_SENSE(scst_logical_block_app_tag_check_failed));
	blockio_complete(test, p->reverse ? 1 : 0, p->first);
	KUNIT_EXPECT_EQ(test, f->completions, 0U);
	blockio_complete(test, p->reverse ? 0 : 1, p->second);
	KUNIT_EXPECT_EQ(test, f->completions, 1U);
	blockio_expect_result(test, -EIO, p->key, p->asc, p->ascq, 0);
}

struct blockio_alloc_case {
	const char *name;
	unsigned int fail_at;
	unsigned int commands;
	u8 status;
};

static const struct blockio_alloc_case blockio_alloc_cases[] = {
	{ "first_bio_busy", 1, 1, SAM_STAT_BUSY },
	{ "second_bio_busy", 2, 1, SAM_STAT_BUSY },
	{ "second_bio_task_set_full", 2, 2, SAM_STAT_TASK_SET_FULL },
};

static void blockio_alloc_desc(const struct blockio_alloc_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(blockio_alloc, blockio_alloc_cases, blockio_alloc_desc);

static void blockio_alloc_test(struct kunit *test)
{
	const struct blockio_alloc_case *p = test->param_value;
	struct blockio_fixture *f = test->priv;

	f->single_vec = true;
	f->fail_alloc_at = p->fail_at;
	f->cmd.data_direction = SCST_DATA_READ;
	atomic_set(&f->sess.sess_cmd_count, p->commands);
	blockio_exec_rw(&f->params, false, false);
	KUNIT_EXPECT_EQ(test, f->allocations, p->fail_at);
	KUNIT_EXPECT_EQ(test, f->submissions, 0U);
	KUNIT_EXPECT_EQ(test, f->completions, 1U);
	vdisk_test_expect_response(test, &f->response, p->status, 0);
	if (p->fail_at > 1) {
		KUNIT_ASSERT_NOT_NULL(test, f->held_bio);
		/* Only our reference may remain after blockio_exec_rw() unwinds. */
		KUNIT_EXPECT_EQ(test, atomic_read(&f->held_bio->__bi_cnt), 1);
	} else {
		KUNIT_EXPECT_PTR_EQ(test, f->held_bio, NULL);
	}
}

static struct kunit_case blockio_cases[] = {
	KUNIT_CASE_PARAM(blockio_read_test, blockio_error_gen_params),
	KUNIT_CASE_PARAM(blockio_write_fua_test, blockio_error_gen_params),
	KUNIT_CASE_PARAM(blockio_inline_test, blockio_error_gen_params),
	KUNIT_CASE_PARAM(blockio_flush_sync_test, blockio_error_gen_params),
	KUNIT_CASE_PARAM(blockio_flush_async_test, blockio_error_gen_params),
	KUNIT_CASE_PARAM(blockio_flush_immed_test, blockio_error_gen_params),
	KUNIT_CASE_PARAM(blockio_discard_test, blockio_error_gen_params),
	KUNIT_CASE(blockio_flush_sync_prior_sense_test),
	KUNIT_CASE(blockio_flush_async_prior_sense_test),
	KUNIT_CASE(blockio_discard_prior_sense_test),
	KUNIT_CASE_PARAM(blockio_verify_test, blockio_error_gen_params),
	KUNIT_CASE(blockio_verify_flush_test),
	KUNIT_CASE_PARAM(blockio_verify_fallback_test, blockio_verify_gen_params),
	KUNIT_CASE_PARAM(blockio_compare_test, blockio_compare_gen_params),
	KUNIT_CASE_PARAM(blockio_order_test, blockio_order_gen_params),
	KUNIT_CASE_PARAM(blockio_alloc_test, blockio_alloc_gen_params),
	{}
};

scst_kunit_suite(blockio_suite, "VDISK", "-blockio",
		 .init = blockio_init,
		 .exit = blockio_exit,
		 .test_cases = blockio_cases,
);
