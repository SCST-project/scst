/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_VDISK_TEST_H
#define SCST_VDISK_TEST_H

#include "../scst_test.h"

#ifdef SCST_KUNIT_ENABLED

struct vdisk_cmd_params;
struct scst_vdisk_dev;

struct bio *vdisk_alloc_bio(int nr_vecs, gfp_t gfp_mask, struct bio_set *bs);
void vdisk_submit_bio(struct bio *bio);
void blockio_exec_rw(struct vdisk_cmd_params *p, bool write, bool fua);
int vdisk_issue_discard(struct block_device *bdev, sector_t start, sector_t sectors,
			gfp_t gfp_mask);
int vdisk_unmap_range(struct scst_cmd *cmd, struct scst_vdisk_dev *virt_dev,
		      u64 start_lba, u64 blocks);
struct bio *vdisk_alloc_flush_bio(gfp_t gfp_mask);
void vdisk_submit_flush_bio(struct bio *bio);
int vdisk_issue_flush(struct block_device *bdev, gfp_t gfp_mask);
ssize_t vdev_read_sync(struct scst_vdisk_dev *virt_dev, void *buf, size_t len, loff_t *loff);
enum compl_status_e vdev_exec_verify(struct vdisk_cmd_params *p);
enum compl_status_e vdisk_exec_start_stop(struct vdisk_cmd_params *p);

int vdisk_blockio_flush(struct block_device *bdev, gfp_t gfp_mask, bool report_error,
			struct scst_cmd *cmd, bool async);
int __vdisk_fsync_fileio(loff_t loff, loff_t len, struct scst_device *dev,
			 struct scst_cmd *cmd, struct file *file);
int vdisk_fsync(loff_t loff, loff_t len, struct scst_device *dev, gfp_t gfp_flags,
		struct scst_cmd *cmd, bool async);
void vdisk_on_free_cmd_params(const struct vdisk_cmd_params *p);
enum compl_status_e vdisk_exec_sai_16(struct vdisk_cmd_params *p);
enum compl_status_e vdisk_exec_request_sense(struct vdisk_cmd_params *p);
enum compl_status_e fileio_exec_write(struct vdisk_cmd_params *p);
enum compl_status_e fileio_exec_read(struct vdisk_cmd_params *p);
enum compl_status_e nullio_exec_read(struct vdisk_cmd_params *p);
bool vdisk_parse_offset(struct vdisk_cmd_params *p, struct scst_cmd *cmd);
enum compl_status_e vdisk_synchronize_cache(struct vdisk_cmd_params *p);
ssize_t vdisk_sysfs_sync_store(struct kobject *kobj, struct kobj_attribute *attr,
			       const char *buf, size_t count);
int vdisk_flush_backend(struct scst_device *dev);

#endif /* SCST_KUNIT_ENABLED */
#endif /* SCST_VDISK_TEST_H */
