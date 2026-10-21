/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_VDISK_PRIV_H
#define SCST_VDISK_PRIV_H

#include <linux/bio.h>
#include <linux/fs.h>
#include <linux/uio.h>
#include <scsi/scsi.h>
#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#include <scst/scst_debug.h>
#else
#include "scst.h"
#include "scst_debug.h"
#endif

#define MAX_USN_LEN			(20 + 1) /* For '\0' */
#define MAX_INQ_VEND_SPECIFIC_LEN	(INQ_BUF_SZ - 96)
#define INQ_BUF_SZ			256

struct scst_vdisk_dev {
	uint64_t nblocks;
	unsigned int opt_trans_len;

	/*
	 * Not protected, because assignments to aligned 64-bit integers are
	 * atomic. At worst, accesses to it should be covered by READ_ONCE(),
	 * but not sure if that is really needed, so would prefer to keep it
	 * away from the fast path.
	 */
	loff_t file_size;	/* in bytes */

	/*
	 * This lock can be taken on both SIRQ and thread context, but in
	 * all cases for each particular instance it's taken consistently either
	 * on SIRQ or thread context. Mix of them is forbidden.
	 */
	spinlock_t flags_lock;

	/*
	 * Below flags are protected by flags_lock or suspended activity
	 * with scst_vdisk_mutex.
	 */
	unsigned int dev_active:1;
	unsigned int bind_alua_state:1;
	unsigned int rd_only:1;
	unsigned int wt_flag:1;
	unsigned int nv_cache:1;
	unsigned int o_direct_flag:1;
	unsigned int async:1;
	unsigned int media_changed:1;
	unsigned int prevent_allow_medium_removal:1;
	unsigned int nullio:1;
	unsigned int blockio:1;
	unsigned int blk_integrity:1;
	unsigned int cdrom_empty:1;
	unsigned int dummy:1;
	unsigned int read_zero:1;
	unsigned int removable:1;
	unsigned int thin_provisioned:1;
	unsigned int thin_provisioned_manually_set:1;
	unsigned int dev_thin_provisioned:1;
	unsigned int rotational:1;
	unsigned int wt_flag_saved:1;
	unsigned int tst:3;
	unsigned int format_active:1;
	unsigned int discard_zeroes_data:1;
	unsigned int reexam_pending:1;
	unsigned int size_key:1;
	unsigned int opt_trans_len_set:1;
	unsigned int lb_per_pb_exp:1;

	/*
	 * Thin provisioning (TP) state, protected by scst_alua_lock() after
	 * attach. Keep it separate from the command-side bitfields above.
	 */
	bool tp_recheck_pending;
	bool tp_ua_attr_created;
	bool thin_provisioned_requested;

	struct file *fd;
	struct file *dif_fd;
	struct scst_bdev_descriptor bdev_desc;
	struct bio_set *vdisk_bioset;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	struct bio_set vdisk_bioset_struct;
#endif

	/* Protected by flags_lock, together with format_active. */
	uint64_t format_progress_to_do, format_progress_done;

	int virt_id;
	/* Name of the virtual device, must be <= SCSI Model + 1 */
	char name[64 + 1];
	/* File name, protected by scst_mutex and suspended activities */
	char *filename;
	uint16_t command_set_version;

	unsigned int initial_cluster_mode:1;

	/* All 14 protected by vdisk_serial_rwlock */
	unsigned int t10_vend_id_set:1;   /* true if t10_vend_id manually set */
	/* true if vend_specific_id manually set */
	unsigned int vend_specific_id_set:1;
	unsigned int prod_id_set:1;          /* true if prod_id manually set */
	unsigned int prod_rev_lvl_set:1; /* true if prod_rev_lvl manually set */
	unsigned int scsi_device_name_set:1; /* true if scsi_device_name manually set */
	unsigned int t10_dev_id_set:1; /* true if t10_dev_id manually set */
	unsigned int usn_set:1; /* true if usn manually set */
	char t10_vend_id[8 + 1];
	char vend_specific_id[128 + 1];
	char prod_id[16 + 1];
	char prod_rev_lvl[4 + 1];
	char scsi_device_name[256 + 1];
	char t10_dev_id[16 + 8 + 2]; /* T10 device ID */
	int eui64_id_len;
	uint8_t eui64_id[16];
	int naa_id_len;
	uint8_t naa_id[16];
	char usn[MAX_USN_LEN];
	uint8_t inq_vend_specific[MAX_INQ_VEND_SPECIFIC_LEN];
	int inq_vend_specific_len;

	/* Unmap INQUIRY parameters */
	uint32_t unmap_opt_gran, unmap_align, unmap_max_lba_cnt;

	struct scst_device *dev;
	struct list_head vdev_list_entry;

	struct scst_dev_type *vdev_devt;

	int tgt_dev_cnt;

	char *dif_filename;

	struct work_struct vdev_inq_changed_work;

	/* Only to pass it to attach() callback. Don't use them anywhere else! */
	int blk_shift;
	int numa_node_id;
	enum scst_dif_mode dif_mode;
	int dif_type;
	__be64 dif_static_app_tag_combined;
};

struct vdisk_cmd_params {
	union {
		struct {
			struct kvec	*kvec;
			int		kvec_segs;
			struct kvec	small_kvec[4];
		} sync;
		struct {
			struct kiocb	iocb;
			struct bio_vec	*bvec;
			struct bio_vec	small_bvec[4];
		} async;
	};
	struct scst_cmd *cmd;
	loff_t loff;
	unsigned int fua:1;
	unsigned int execute_async:1;
};

enum compl_status_e {
#if defined(SCST_DEBUG)
	COMPL_STATUS_START_AT = 777,
#endif
	CMD_SUCCEEDED,
	CMD_FAILED,
	RUNNING_ASYNC,
	VDISK_INVALID_OPCODE,
};

#endif /* SCST_VDISK_PRIV_H */
