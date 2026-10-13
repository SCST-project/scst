/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_VDISK_FIXTURE_H
#define SCST_VDISK_FIXTURE_H

#include "../../../kunit/scst_kunit.h"
#include "../../scst_vdisk_priv.h"
#include "../../scst_vdisk_test.h"

struct vdisk_test_fixture;

struct vdisk_test_file {
	struct file file;
	struct inode inode;
	struct address_space mapping;
	struct vdisk_test_fixture *fixture;
	int sync_result;
};

enum vdisk_test_sync_op {
	VDISK_TEST_WRITEBACK,
	VDISK_TEST_FSYNC,
};

struct vdisk_test_flush {
	struct file *file;
	loff_t start;
	loff_t end;
	enum vdisk_test_sync_op op;
};

struct vdisk_test_fixture {
	struct scst_cmd cmd;
	struct scst_device dev;
	struct scst_session sess;
	struct scst_vdisk_dev vdev;
	struct vdisk_cmd_params params;
	struct vdisk_test_file data;
	struct vdisk_test_file dif;
	struct block_device bdev;
	struct scatterlist sg[2];
	u8 sense[SCST_SENSE_BUFFERSIZE];
	u8 *input[2];
	u8 written[1024];
	size_t written_len;
	ssize_t results[4];
	unsigned int result_count;
	unsigned int io_count;
	loff_t io_offset[4];
	size_t io_length[4];
	unsigned int io_flags[4];
	unsigned int read_count;
	struct kiocb *pending;
	unsigned int completions;
	int completion_state;
	bool completed_before_callback;
	struct vdisk_test_flush flushes[2];
	unsigned int flush_count;
	unsigned int block_flush_count;
	int block_flush_result;
	bool sysfs_sync;
};

int vdisk_test_init(struct kunit *test);
void vdisk_test_exit(struct kunit *test);
void vdisk_test_expect_flush(struct kunit *test, unsigned int n, struct file *file,
			     loff_t start, loff_t end);

#endif /* SCST_VDISK_FIXTURE_H */
