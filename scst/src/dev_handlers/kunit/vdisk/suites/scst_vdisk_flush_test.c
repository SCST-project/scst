// SPDX-License-Identifier: GPL-2.0-only
#include "../scst_vdisk_fixture.h"

/* Keep VERIFY within one read independently of the kernel's page size. */
#define FLUSH_TEST_DATA_LEN 4096

struct flush_fixture {
	struct scst_cmd cmd;
	struct scst_device dev;
	struct scst_session sess;
	struct scst_vdisk_dev vdev;
	struct vdisk_cmd_params params;
	struct gendisk *disk;
	u8 sense[SCST_SENSE_BUFFERSIZE];
	struct bio *pending;
	blk_status_t bio_status;
	unsigned int submissions;
	unsigned int completions;
	struct vdisk_test_response response;
	unsigned int sync_flushes;
	unsigned int reads;
	int sync_flush_error;
	bool defer;
};

static void flush_done(struct scst_cmd *cmd, int state, enum scst_exec_context context)
{
	struct flush_fixture *f = container_of(cmd, struct flush_fixture, cmd);
	struct kunit *test = kunit_get_current_test();

	KUNIT_EXPECT_TRUE(test, cmd->completed);
	KUNIT_EXPECT_EQ(test, state, SCST_CMD_STATE_DEFAULT);
	if (!f->completions++)
		vdisk_test_save_response(&f->response, cmd);
}

static void flush_submit(struct bio *bio)
{
	struct kunit *test = kunit_get_current_test();
	struct flush_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, bio->bi_bdev, f->disk->part0);
	if (f->submissions++) {
		KUNIT_FAIL(test, "unexpected extra flush BIO");
		bio->bi_status = BLK_STS_IOERR;
		bio_endio(bio);
		return;
	}
	/* Replace backend execution while retaining the actual end-I/O callback. */
	if (f->defer) {
		f->pending = bio;
		return;
	}
	bio->bi_status = f->bio_status;
	bio_endio(bio);
}

static int flush_issue(struct block_device *bdev, gfp_t gfp_mask)
{
	struct kunit *test = kunit_get_current_test();
	struct flush_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, bdev, f->disk->part0);
	f->sync_flushes++;
	return f->sync_flush_error;
}

static ssize_t flush_read(struct scst_vdisk_dev *vdev, void *buf, size_t len, loff_t *loff)
{
	struct kunit *test = kunit_get_current_test();
	struct flush_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, vdev, &f->vdev);
	KUNIT_EXPECT_EQ(test, f->sync_flushes, 1U);
	KUNIT_EXPECT_EQ(test, f->sync_flush_error, 0);
	KUNIT_EXPECT_EQ(test, len, (size_t)FLUSH_TEST_DATA_LEN);
	f->reads++;
	memset(buf, 0, len);
	*loff += len;
	return len;
}

static struct bio *flush_alloc_fail(gfp_t gfp_mask)
{
	return NULL;
}

static int flush_init(struct kunit *test)
{
	struct queue_limits limits = { .logical_block_size = 512 };
	struct flush_fixture *f;

	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;
	test->priv = f;
	/* Allocate private block-layer state without registering or opening a disk. */
	f->disk = blk_alloc_disk(&limits, NUMA_NO_NODE);
	if (IS_ERR(f->disk)) {
		int ret = PTR_ERR(f->disk);

		f->disk = NULL;
		return ret;
	}
	f->vdev.bdev_desc.bdev = f->disk->part0;
	f->vdev.blockio = true;
	f->vdev.file_size = 4096 << 9;
	f->vdev.dev = &f->dev;
	f->dev.dh_priv = &f->vdev;
	f->dev.block_size = 512;
	f->dev.block_shift = 9;
	f->cmd.dev = &f->dev;
	f->cmd.sess = &f->sess;
	f->cmd.cdb = f->cmd.cdb_buf;
	f->cmd.cmd_gfp_mask = GFP_KERNEL;
	f->cmd.data_len = FLUSH_TEST_DATA_LEN;
	f->cmd.resp_data_len = FLUSH_TEST_DATA_LEN;
	f->cmd.sense = f->sense;
	f->cmd.sense_buflen = sizeof(f->sense);
	f->cmd.scst_cmd_done = flush_done;
	kref_init(&f->cmd.cmd_ref);
	f->sess.initiator_name = "kunit";
	f->sess.init_phase = SCST_SESS_IPH_READY;
	atomic_set(&f->sess.sess_cmd_count, 1);
	f->params.cmd = &f->cmd;
	kunit_activate_static_stub(test, vdisk_submit_flush_bio, flush_submit);
	kunit_activate_static_stub(test, vdisk_issue_flush, flush_issue);
	kunit_activate_static_stub(test, vdev_read_sync, flush_read);
	return 0;
}

/* KUnit's suite exit callback requires a mutable struct kunit pointer. */
/* cppcheck-suppress constParameterCallback symbolName=test */
static void flush_exit(struct kunit *test)
{
	struct flush_fixture *f = test->priv;
	struct bio *bio;

	if (!f)
		return;
	/* A failed assertion must not leave a deferred flush BIO behind. */
	bio = f->pending;
	if (bio) {
		f->pending = NULL;
		bio->bi_status = BLK_STS_IOERR;
		bio_endio(bio);
	}
	if (f->disk)
		put_disk(f->disk);
}

struct flush_error_case {
	const char *name;
	blk_status_t status;
	int error;
};

static const struct flush_error_case flush_errors[] = {
	{ "success", BLK_STS_OK, 0 },
	{ "io_error", BLK_STS_IOERR, -EIO },
};

static void flush_error_desc(const struct flush_error_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(flush_error, flush_errors, flush_error_desc);

static void flush_expect_sense(struct kunit *test, u8 key, u8 asc, u8 ascq)
{
	struct flush_fixture *f = test->priv;

	KUNIT_EXPECT_EQ(test, f->cmd.status, (u8)SAM_STAT_CHECK_CONDITION);
	KUNIT_EXPECT_EQ(test, f->sense[2] & 0xf, key);
	KUNIT_EXPECT_EQ(test, f->sense[12], asc);
	KUNIT_EXPECT_EQ(test, f->sense[13], ascq);
	KUNIT_EXPECT_EQ(test, f->cmd.resp_data_len, 0);
	if (f->completions)
		vdisk_test_expect_sense(test, &f->response, key, asc, ascq);
}

static void flush_async_test(struct kunit *test)
{
	const struct flush_error_case *p = test->param_value;
	struct flush_fixture *f = test->priv;

	f->bio_status = p->status;
	KUNIT_EXPECT_EQ(test, vdisk_blockio_flush(f->disk->part0, GFP_KERNEL, true,
						  &f->cmd, true), 0);
	KUNIT_EXPECT_EQ(test, f->submissions, 1U);
	KUNIT_EXPECT_EQ(test, f->completions, 1U);
	if (p->error) {
		flush_expect_sense(test, MEDIUM_ERROR, 0x03, 0);
	} else {
		KUNIT_EXPECT_EQ(test, f->cmd.status, (u8)SAM_STAT_GOOD);
		vdisk_test_expect_response(test, &f->response, SAM_STAT_GOOD,
					   FLUSH_TEST_DATA_LEN);
	}
}

static void flush_sync_test(struct kunit *test)
{
	const struct flush_error_case *p = test->param_value;
	struct flush_fixture *f = test->priv;

	f->sync_flush_error = p->error;
	/* Disabling logging must not suppress the SCSI error. */
	KUNIT_EXPECT_EQ(test, vdisk_blockio_flush(f->disk->part0, GFP_KERNEL, false,
						  &f->cmd, false), p->error);
	KUNIT_EXPECT_EQ(test, f->sync_flushes, 1U);
	KUNIT_EXPECT_EQ(test, f->submissions, 0U);
	KUNIT_EXPECT_EQ(test, f->completions, 0U);
	if (p->error)
		flush_expect_sense(test, MEDIUM_ERROR, 0x03, 0);
	else
		KUNIT_EXPECT_EQ(test, f->cmd.status, (u8)SAM_STAT_GOOD);
}

static void flush_verify_test(struct kunit *test)
{
	const struct flush_error_case *p = test->param_value;
	struct flush_fixture *f = test->priv;

	f->sync_flush_error = p->error;
	f->cmd.data_direction = SCST_DATA_NONE;
	KUNIT_EXPECT_EQ(test, vdev_exec_verify(&f->params), CMD_SUCCEEDED);
	KUNIT_EXPECT_EQ(test, f->sync_flushes, 1U);
	KUNIT_EXPECT_EQ(test, f->reads, p->error ? 0U : 1U);
	KUNIT_EXPECT_EQ(test, f->submissions, 0U);
	KUNIT_EXPECT_EQ(test, f->completions, 0U);
	if (p->error)
		flush_expect_sense(test, MEDIUM_ERROR, 0x03, 0);
	else
		KUNIT_EXPECT_EQ(test, f->cmd.status, (u8)SAM_STAT_GOOD);
}

static void flush_start_stop_test(struct kunit *test)
{
	const struct flush_error_case *p = test->param_value;
	struct flush_fixture *f = test->priv;

	f->sync_flush_error = p->error;
	KUNIT_EXPECT_EQ(test, vdisk_exec_start_stop(&f->params), CMD_SUCCEEDED);
	KUNIT_EXPECT_EQ(test, f->sync_flushes, 1U);
	KUNIT_EXPECT_EQ(test, f->submissions, 0U);
	KUNIT_EXPECT_EQ(test, f->completions, 0U);
	if (p->error)
		flush_expect_sense(test, MEDIUM_ERROR, 0x03, 0);
	else
		KUNIT_EXPECT_EQ(test, f->cmd.status, (u8)SAM_STAT_GOOD);
}

static void flush_synchronize_test(struct kunit *test, bool immed)
{
	const struct flush_error_case *p = test->param_value;
	struct flush_fixture *f = test->priv;
	struct bio *bio;

	f->defer = true;
	f->cmd.cdb[1] = immed ? 2 : 0;
	f->cmd.resp_data_len = 0;
	KUNIT_EXPECT_EQ(test, vdisk_synchronize_cache(&f->params), RUNNING_ASYNC);
	KUNIT_EXPECT_EQ(test, f->completions, immed ? 1U : 0U);
	KUNIT_EXPECT_EQ(test, kref_read(&f->cmd.cmd_ref), 1U);
	KUNIT_ASSERT_EQ(test, f->submissions, 1U);
	bio = f->pending;
	KUNIT_ASSERT_NOT_NULL(test, bio);
	KUNIT_EXPECT_PTR_EQ(test, bio->bi_private, immed ? NULL : &f->cmd);
	f->pending = NULL;
	bio->bi_status = p->status;
	bio_endio(bio);
	KUNIT_EXPECT_EQ(test, f->completions, 1U);
	if (p->error && !immed) {
		flush_expect_sense(test, MEDIUM_ERROR, 0x03, 0);
	} else {
		KUNIT_EXPECT_EQ(test, f->cmd.status, (u8)SAM_STAT_GOOD);
		vdisk_test_expect_response(test, &f->response, SAM_STAT_GOOD, 0);
	}
}

static void flush_synchronize_wait_test(struct kunit *test)
{
	flush_synchronize_test(test, false);
}

static void flush_synchronize_immed_test(struct kunit *test)
{
	flush_synchronize_test(test, true);
}

struct flush_alloc_case {
	const char *name;
	unsigned int commands;
	bool no_cmd;
	bool prior_error;
	u8 status;
};

static const struct flush_alloc_case flush_alloc_cases[] = {
	{ "busy", 1, false, false, SAM_STAT_BUSY },
	{ "task_set_full", 2, false, false, SAM_STAT_TASK_SET_FULL },
	{ "commandless", 1, true, false, SAM_STAT_GOOD },
	{ "prior_dif_error", 1, false, true, SAM_STAT_CHECK_CONDITION },
};

static void flush_alloc_desc(const struct flush_alloc_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(flush_alloc, flush_alloc_cases, flush_alloc_desc);

static void flush_alloc_test(struct kunit *test)
{
	const struct flush_alloc_case *p = test->param_value;
	struct flush_fixture *f = test->priv;

	kunit_activate_static_stub(test, vdisk_alloc_flush_bio, flush_alloc_fail);
	atomic_set(&f->sess.sess_cmd_count, p->commands);
	if (p->prior_error)
		scst_set_cmd_error(&f->cmd,
				   SCST_LOAD_SENSE(scst_logical_block_app_tag_check_failed));
	KUNIT_EXPECT_EQ(test, vdisk_blockio_flush(f->disk->part0, GFP_KERNEL, true,
						  p->no_cmd ? NULL : &f->cmd, true), -ENOMEM);
	KUNIT_EXPECT_EQ(test, f->completions, p->no_cmd ? 0U : 1U);
	KUNIT_EXPECT_EQ(test, f->cmd.status, p->status);
	KUNIT_EXPECT_EQ(test, f->submissions, 0U);
	if (!p->no_cmd)
		vdisk_test_expect_response(test, &f->response, p->status, 0);
	if (p->prior_error)
		flush_expect_sense(test, ABORTED_COMMAND, 0x10, 0x02);
}

struct flush_synchronize_alloc_case {
	const char *name;
	unsigned int commands;
	bool immed;
	u8 status;
};

static const struct flush_synchronize_alloc_case flush_synchronize_alloc_cases[] = {
	{ "busy", 1, false, SAM_STAT_BUSY },
	{ "task_set_full", 2, false, SAM_STAT_TASK_SET_FULL },
	{ "immed", 1, true, SAM_STAT_GOOD },
};

static void flush_synchronize_alloc_desc(const struct flush_synchronize_alloc_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(flush_synchronize_alloc, flush_synchronize_alloc_cases,
		  flush_synchronize_alloc_desc);

static void flush_synchronize_alloc_test(struct kunit *test)
{
	const struct flush_synchronize_alloc_case *p = test->param_value;
	struct flush_fixture *f = test->priv;

	kunit_activate_static_stub(test, vdisk_alloc_flush_bio, flush_alloc_fail);
	atomic_set(&f->sess.sess_cmd_count, p->commands);
	f->cmd.cdb[1] = p->immed ? 2 : 0;
	f->cmd.resp_data_len = 0;
	KUNIT_EXPECT_EQ(test, vdisk_synchronize_cache(&f->params), RUNNING_ASYNC);
	KUNIT_EXPECT_EQ(test, f->completions, 1U);
	KUNIT_EXPECT_EQ(test, f->cmd.status, p->status);
	vdisk_test_expect_response(test, &f->response, p->status, 0);
	KUNIT_EXPECT_EQ(test, f->submissions, 0U);
	KUNIT_EXPECT_EQ(test, f->sync_flushes, 0U);
	KUNIT_EXPECT_PTR_EQ(test, f->pending, NULL);
	KUNIT_EXPECT_EQ(test, kref_read(&f->cmd.cmd_ref), 1U);
}

static struct kunit_case flush_cases[] = {
	KUNIT_CASE_PARAM(flush_async_test, flush_error_gen_params),
	KUNIT_CASE_PARAM(flush_sync_test, flush_error_gen_params),
	KUNIT_CASE_PARAM(flush_verify_test, flush_error_gen_params),
	KUNIT_CASE_PARAM(flush_start_stop_test, flush_error_gen_params),
	KUNIT_CASE_PARAM(flush_synchronize_wait_test, flush_error_gen_params),
	KUNIT_CASE_PARAM(flush_synchronize_immed_test, flush_error_gen_params),
	KUNIT_CASE_PARAM(flush_alloc_test, flush_alloc_gen_params),
	KUNIT_CASE_PARAM(flush_synchronize_alloc_test, flush_synchronize_alloc_gen_params),
	{}
};

scst_kunit_suite(flush_suite, "VDISK", "-flush",
		 .init = flush_init,
		 .exit = flush_exit,
		 .test_cases = flush_cases,
);
