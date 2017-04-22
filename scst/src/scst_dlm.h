/*
 * Copyright (c) 2013 - 2014 Fusion-io, Inc. All rights reserved.
 * Copyright (C) 2014 - 2017 SanDisk Corporation.
 *
 * Synchronization of persistent registration data with DLM lock value blocks.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef __SCST_PRES_DLM_H
#define __SCST_PRES_DLM_H

#include <linux/dlm.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>

#define SCST_DLM_LOCKSPACE_PFX	"scst-"

/*
 * DLM lock names
 */
#define PR_LOCK			"pr"
#define PR_DATA_LOCK		"pr_data"
#define PR_PRE_JOIN_LOCK	"pr_pre_join_%d"
#define PR_POST_JOIN_LOCK	"pr_post_join_%d"
#define PR_PRE_UPDATE_LOCK	"pr_pre_%d"
#define PR_POST_UPDATE_LOCK	"pr_post_%d"
#define PR_REG_LOCK		"pr_reg_%02d"

/*
 * Data members needed for managing PR data via the DLM.
 *
 * Lock order when using the DLM (from outer to inner):
 * - scst_mutex;
 * - ls_cr_mutex;
 * - ls_mutex;
 * - PR_LOCK;
 * - PR_PRE_UPDATE_LOCK, PR_POST_UPDATE_LOCK, PR_PRE_JOIN_LOCK,
 *   PR_POST_JOIN_LOCK;
 * - PR_DATA_LOCK;
 * - PR_REG_LOCK;
 * - dev_pr_mutex / dev_lock.
 */
struct scst_pr_dlm_data {
	/* Backpointer to the SCST device. */
	struct scst_device *dev;

	/* Lockspace name suffix. */
	const char *cl_dev_id;

	/* Mutex that protects initialization of the lockspace pointer. */
	struct mutex ls_cr_mutex;

	/* Mutex that protects the lock status blocks. */
	struct mutex ls_mutex;

	/*
	 * Pointer to the DLM lockspace that contains the persistent
	 * reservation and SPC-2 reservation data for device @dev.
	 */
	dlm_lockspace_t *ls;

	/* Time of the latest lockspace creation attempt. */
	unsigned long latest_lscr_attempt;

	/* Corosync node ID of the local node. */
	uint32_t local_nodeid;

	/* Number of elements in the nodeid array. */
	int participants;

	/* Corosync cluster node ID's. Protected by ls_mutex. */
	uint32_t *nodeid;

	/* Workqueue for copy_from_dlm_work. */
	struct workqueue_struct *from_wq;
	/* Workqueue for copy_to_dlm_work. */
	struct workqueue_struct *to_wq;
	/* Workqueue for lvb_upd_work. */
	struct workqueue_struct *upd_wq;

	struct work_struct pre_join_work;
	struct work_struct pre_upd_work;
	struct work_struct copy_from_dlm_work;
	struct work_struct copy_to_dlm_work;
	struct work_struct lvb_upd_work;
	struct work_struct reread_lvb_work;

	/*
	 * DLM lock IDs of the locks used for persistent reservation data and
	 * the associated notification protocol.
	 */
	struct scst_lksb pre_join_lksb;
	struct scst_lksb post_join_lksb;
	struct scst_lksb data_lksb;
	struct scst_lksb pre_upd_lksb;
	struct scst_lksb post_upd_lksb;

	/* PR_DATA_LOCK LVB. */
	uint8_t  lvb[PR_DLM_LVB_LEN];

	/* SPC-2 reservation state information. */
	uint32_t reserved_by_nodeid;
};

/**
 * struct pr_lvb - PR_DATA_LOCK LVB data format
 * @nr_registrants: number of reservation keys that have been registered
 * @pr_generation:  persistent reservation generation
 * @version:	    version of this structure
 * @pr_is_set:	    whether the device has been reserved persistently
 * @pr_type:	    persistent reservation type
 * @pr_scope:	    persistent reservation scope
 * @pr_aptpl:	    persistent reservation APTPL
 * @reserved_by_nodeid: Corosync node ID of the node holding an SPC-2
 *                  reservation. Zero if no SPC-2 reservation is held.
 */
struct pr_lvb {
	__be32	nr_registrants;
	__be32	pr_generation;
	u8	version;
	u8	pr_is_set;
	u8	pr_type;
	u8	pr_scope;
	u8	pr_aptpl;
	u8      reserved[3];
	__be32  reserved_by_nodeid;
};

/**
 * struct pr_reg_lvb - PR_REG_LOCK LVB data format
 * @key:	reservation key
 * @rel_tgt_id:	relative target id
 * @version:	version of this structure
 * @is_holder:	whether or not holding the reservation
 * @tid:	transport ID - up to 228 bytes for iSCSI
 */
struct pr_reg_lvb {
	__be64	key;
	__be16	rel_tgt_id;
	u8	version;
	u8	is_holder;
	u8	tid[228];
};

#endif /* __SCST_PRES_DLM_H */
