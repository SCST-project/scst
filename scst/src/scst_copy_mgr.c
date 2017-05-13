/*
 *  Copyright (C) 2013 - 2017 SanDisk Corporation
 *
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <asm/unaligned.h>
#include <linux/delay.h>

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include "scst.h"
#endif
#include "scst_priv.h"
#include "scst_pres.h"

#ifdef CONFIG_SCST_PROC
#warning In the PROCFS build EXTENDED COPY not supported
#else

#define SCST_CM_NAME		"copy_manager"
#define SCST_CM_TGT_NAME	(SCST_CM_NAME "_tgt")
#define SCST_CM_SESS_NAME	(SCST_CM_NAME "_sess")

#define SCST_CM_TID_SIZE	24
#define SCST_CM_TID_ID		"COPY_MGR"

#define SCST_CM_RETRIES_WAIT	HZ
#define SCST_CM_MAX_RETRIES_TIME (30*HZ)
#define SCST_CM_ID_KEEP_TIME	(5*HZ)

#define SCST_CM_MAX_EACH_IO_SIZE (512*1024)

/* Too big value is not too good for the blocking machinery */
#define SCST_CM_MAX_TGT_DESCR_CNT 5

#define SCST_CM_MAX_SEG_DESCR_CNT					\
	(((PAGE_SIZE * 2) - sizeof(struct scst_cm_ec_cmd_priv)) /	\
	 sizeof(struct scst_ext_copy_seg_descr))

/* MAXIMUM DESCRIPTOR LIST LENGTH */
#define SCST_MAX_SEG_DESC_LEN 0xFFFF

static struct scst_tgt *scst_cm_tgt;
static struct scst_session *scst_cm_sess;

/* Protected by scst_mutex */
static unsigned int scst_cm_next_lun;

static DEFINE_MUTEX(scst_cm_mutex);

/* Protected by scst_cm_mutex */
static LIST_HEAD(scst_cm_desig_list);

struct scst_cm_desig {
	struct list_head cm_desig_list_entry;

	struct scst_tgt_dev *desig_tgt_dev;

	int desig_len;
	uint8_t desig[];
};

/* It's IRQ and inner for sess_list_lock */
static spinlock_t scst_cm_lock;

/* Necessary fields protected by scst_cm_lock */
struct scst_cm_list_id {
	struct list_head sess_cm_list_id_entry;

	int cm_lid;

#define SCST_CM_LIST_ID_STATE_ACTIVE		0
#define SCST_CM_LIST_ID_STATE_DONE		1
#define SCST_CM_LIST_ID_STATE_PENDING_FREE	2
	int cm_list_id_state;

	unsigned int cm_done:1;
	unsigned int cm_can_be_immed_free:1;

	int cm_segs_processed;
	int64_t cm_written_size; /* in bytes */

	unsigned long cm_time_to_free; /* in jiffies */

	int cm_status;
	unsigned short cm_sense_len;
	uint8_t cm_sense[SCST_SENSE_BUFFERSIZE];
};

struct scst_cm_internal_cmd_priv {
	/* Must be the first for scst_finish_internal_cmd()! */
	scst_i_finish_fn_t cm_finish_fn;

	/* Internal cmd itself. Needed for unified cleanups and aborts. */
	struct scst_cmd *cm_cmd;

	/* E.g. rcmd for WRITEs, ec_cmd for READs, etc. */
	struct scst_cmd *cm_orig_cmd;

	struct list_head cm_internal_cmd_list_entry;
};

struct scst_cm_dev_entry {
	struct list_head cm_sorted_devs_list_entry;
	struct scst_cmd *cm_fcmd; /* can point to the real EC cmd as well! */
};

/*
 * Most fields here not protected, since can be accessed only from a single
 * thread at time.
 */
struct scst_cm_ec_cmd_priv {
	struct scst_cm_list_id *cm_list_id;

	/*
	 * List of all devices involved in this EC cmd (structs
	 * scst_cm_dev_entry), sorted by their dev's address.
	 */
	struct list_head cm_sorted_devs_list;

	/*
	 * List of all generated internal commands. Where needed, protected
	 * by scst_cm_lock.
	 */
	struct list_head cm_internal_cmd_list;

#define SCST_CM_ERROR_NONE	0
#define SCST_CM_ERROR_READ	1
#define SCST_CM_ERROR_WRITE	2
	int cm_error;

	struct mutex cm_mutex;

	int cm_cur_in_flight; /* commands */

	/**
	 ** READ commands stuff
	 **/
	struct scst_tgt_dev *cm_read_tgt_dev;
	int64_t cm_start_read_lba; /* in blocks */
	int64_t cm_cur_read_lba; /* in blocks */
	int cm_left_to_read; /* in blocks */
	int cm_max_each_read;/* in blocks */

	/**
	 ** WRITE commands stuff
	 **/
	struct scst_tgt_dev *cm_write_tgt_dev;
	int64_t cm_start_write_lba; /* in blocks */
	int64_t cm_written; /* in bytes */

	/**
	 ** Current data descriptors and their count
	 **/
	const struct scst_ext_copy_data_descr *cm_data_descrs;
	int cm_data_descrs_cnt;
	int cm_cur_data_descr;

	int cm_cur_seg_descr;

	/**
	 ** Parsed descriptors. Number of them is in
	 ** cmd->cmd_data_descriptors_cnt
	 **/
	struct scst_ext_copy_seg_descr cm_seg_descrs[];
};

#define SCST_ALLOW_NOT_CONN_COPY_DEF	0
/* Not protected, because no need */
static bool scst_cm_allow_not_connected_copy = SCST_ALLOW_NOT_CONN_COPY_DEF;

#define SCST_CM_STATUS_CMD_SUCCEEDED	0
#define SCST_CM_STATUS_RETRY		1
#define SCST_CM_STATUS_CMD_FAILED	-1

typedef void (*scst_cm_retry_fn_t)(struct scst_cmd *cmd);

struct scst_cm_retry {
	struct scst_cmd *cm_retry_cmd;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct work_struct cm_retry_work;
#else
	struct delayed_work cm_retry_work;
#endif
	scst_cm_retry_fn_t cm_retry_fn;
};

static void scst_cm_retry_work_fn(struct work_struct *work)
{
	struct scst_cm_retry *retry = container_of(work, struct scst_cm_retry,
						   cm_retry_work.work);

	TRACE_ENTRY();

	TRACE_DBG("Retrying cmd %p", retry->cm_retry_cmd);

	retry->cm_retry_fn(retry->cm_retry_cmd);

	__scst_cmd_put(retry->cm_retry_cmd);

	kfree(retry);

	TRACE_EXIT();
	return;
}

/*
 * Checks if cmd finished successfully and performs/schedules retry, if necessary.
 * Returns one of SCST_CM_STATUS_* codes.
 */
static int scst_cm_err_check_retry(struct scst_cmd *cmd,
	unsigned long start_time, scst_cm_retry_fn_t retry_fn)
{
	int res = SCST_CM_STATUS_CMD_SUCCEEDED;
	unsigned long cur_time, max_retry_time, next_retry_time;
	struct scst_cm_retry *retry;
	bool imm_retry = false;

	TRACE_ENTRY();

	/* cmd->dev and tgt_dev can be NULL here! */

	TRACE_DBG("cmd %p, status %d, aborted %d", cmd, cmd->status,
		scst_cmd_aborted(cmd));

	if (likely((cmd->status == 0) && !scst_cmd_aborted(cmd)))
		goto out;

	cur_time = jiffies;
	max_retry_time = start_time + SCST_CM_MAX_RETRIES_TIME;

	mutex_lock(&scst_cm_mutex);

	if (test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)) {
		if (test_bit(SCST_CMD_ABORTED_OTHER, &cmd->cmd_flags)) {
			TRACE_MGMT_DBG("Cmd %p aborted by other initiator, "
				"retry possible", cmd);
			goto try_retry;
		} else {
			TRACE_MGMT_DBG("Cmd %p aborted, no retry ", cmd);
			goto out_err_unlock;
		}
	}

	if ((cmd->status == SAM_STAT_BUSY) ||
	    (cmd->status == SAM_STAT_TASK_SET_FULL) ||
	    (cmd->status == SAM_STAT_RESERVATION_CONFLICT) ||
	    (cmd->status == SAM_STAT_ACA_ACTIVE)) {
		TRACE_DBG("Cmd %p finished with status %d, retry possible",
			cmd, cmd->status);
		goto try_retry;
	}

	if ((cmd->status == SAM_STAT_CHECK_CONDITION) &&
	     scst_sense_valid(cmd->sense) &&
	     scst_analyze_sense(cmd->sense, cmd->sense_valid_len,
			SCST_SENSE_KEY_VALID, UNIT_ATTENTION, 0, 0)) {
		TRACE_DBG("Cmd %p finished with UA, immediate retry "
			"possible", cmd);
		imm_retry = true;
		goto try_retry;
	}

out_err_unlock:
	mutex_unlock(&scst_cm_mutex);

out_failed:
	res = SCST_CM_STATUS_CMD_FAILED;

out:
	TRACE_EXIT_RES(res);
	return res;

try_retry:
	if (time_after_eq(cur_time, max_retry_time))
		goto out_err_unlock;

	next_retry_time = cur_time + SCST_CM_RETRIES_WAIT;

	TRACE_DBG("Retrying cmd %p (imm_retry %d, next_retry_time %ld, "
		"cur_time %ld, start_time %ld, max_retry_time %ld): going "
		"to sleep", cmd, imm_retry, next_retry_time, cur_time,
		start_time, max_retry_time);

	mutex_unlock(&scst_cm_mutex);

	if (retry_fn == NULL)
		goto out_retry_done;

	/* Wait before retry */

	retry = kzalloc(sizeof(*retry), GFP_KERNEL);
	if (retry == NULL) {
		PRINT_ERROR("Unable to allocate retry struct");
		scst_set_busy(cmd);
		goto out_failed;
	}
	retry->cm_retry_cmd = cmd;
	__scst_cmd_get(cmd);
	INIT_DELAYED_WORK(&retry->cm_retry_work, scst_cm_retry_work_fn);
	retry->cm_retry_fn = retry_fn;

	if (imm_retry) {
		/* Let's use work to avoid possible recursion */
		TRACE_DBG("Immediate retry (cmd %p)", cmd);
		schedule_work(&retry->cm_retry_work.work);
	} else {
		TRACE_DBG("Scheduling cmd %p retry", cmd);
		schedule_delayed_work(&retry->cm_retry_work,
			next_retry_time - cur_time);
	}

out_retry_done:
	res = SCST_CM_STATUS_RETRY;
	goto out;
}

static bool scst_cm_is_ec_cmd_done(struct scst_cmd *ec_cmd)
{
	bool res;

	TRACE_ENTRY();

	if (unlikely(test_bit(SCST_CMD_ABORTED, &ec_cmd->cmd_flags))) {
		TRACE_MGMT_DBG("EC cmd %p aborted", ec_cmd);
		res = true;
	} else if (unlikely(ec_cmd->completed)) {
		TRACE_MGMT_DBG("EC cmd %p already completed with status (%d)",
			ec_cmd, ec_cmd->status);
		res = true;
	} else
		res = false;

	TRACE_EXIT_RES(res);
	return res;
}

/*
 * cm_mutex suppose to be locked or no activities on this ec_cmd's priv.
 *
 * Returns 0 on success or -ENOENT, if there's no more data descriptors in
 * ec_cmd, or other negative error code. For other error codes cmd status
 * and sense supposed to be set.
 */
static int scst_cm_setup_this_data_descr(struct scst_cmd *ec_cmd)
{
	int res;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;
	struct scst_ext_copy_seg_descr *sd;
	const struct scst_ext_copy_data_descr *dd;

	TRACE_ENTRY();

	TRACE_DBG("ec_cmd %p, cm_cur_data_descr %d", ec_cmd,
		priv->cm_cur_data_descr);

	EXTRACHECKS_BUG_ON(priv->cm_cur_data_descr > priv->cm_data_descrs_cnt);

	if (priv->cm_cur_data_descr == priv->cm_data_descrs_cnt) {
		TRACE_DBG("No more data descriptors for ec_cmd %p", ec_cmd);
		res = -ENOENT;
		goto out;
	}

	sd = &priv->cm_seg_descrs[priv->cm_cur_seg_descr];
	dd = &priv->cm_data_descrs[priv->cm_cur_data_descr];

	EXTRACHECKS_BUG_ON(dd->data_len == 0);

	priv->cm_read_tgt_dev = sd->src_tgt_dev;
	priv->cm_start_read_lba = dd->src_lba;
	priv->cm_cur_read_lba = dd->src_lba;
	priv->cm_left_to_read = dd->data_len >> sd->src_tgt_dev->dev->block_shift;
	priv->cm_max_each_read = SCST_CM_MAX_EACH_IO_SIZE >> sd->src_tgt_dev->dev->block_shift;

	priv->cm_write_tgt_dev = sd->dst_tgt_dev;
	priv->cm_start_write_lba = dd->dst_lba;

	TRACE_DBG("len %d, src_lba %lld, dst_lba %lld", dd->data_len,
		(long long)dd->src_lba, (long long)dd->dst_lba);

	if (unlikely((dd->data_len & (sd->src_tgt_dev->dev->block_size-1)) != 0) ||
	    unlikely((dd->data_len & (sd->dst_tgt_dev->dev->block_size-1)) != 0)) {
		PRINT_ERROR("Data len %d is not even for block size (src block "
			"size %d, dst block size %d)", dd->data_len,
			sd->src_tgt_dev->dev->block_size,
			sd->dst_tgt_dev->dev->block_size);
		scst_set_cmd_error(ec_cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
		res = -EINVAL;
		goto out;
	}

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/*
 * cm_mutex suppose to be locked or no activities on this ec_cmd's priv.
 *
 * Returns 0 on success or -ENOENT, if there's no more data descriptors in
 * ec_cmd, or other negative error code. For other error codes cmd status
 * and sense supposed to be set.
 */
static int scst_cm_setup_next_data_descr(struct scst_cmd *ec_cmd)
{
	int res;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;

	TRACE_ENTRY();

	TRACE_DBG("ec_cmd %p", ec_cmd);

	priv->cm_cur_data_descr++;

	res = scst_cm_setup_this_data_descr(ec_cmd);

	TRACE_EXIT_RES(res);
	return res;
}

/*
 * cm_mutex suppose to be locked or no activities on this ec_cmd's priv.
 *
 * Returns 0 on success or -ENOENT, if there are no data descriptors in
 * ec_cmd, or other negative error code. For other error codes cmd status
 * and sense supposed to be set.
 */
static int scst_cm_setup_first_data_descr(struct scst_cmd *ec_cmd)
{
	int res;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;

	TRACE_ENTRY();

	TRACE_DBG("ec_cmd %p", ec_cmd);

	priv->cm_cur_data_descr = 0;

	res = scst_cm_setup_this_data_descr(ec_cmd);

	TRACE_EXIT_RES(res);
	return res;
}

static void scst_cm_destroy_data_descrs(struct scst_cmd *ec_cmd)
{
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;

	TRACE_ENTRY();

	TRACE_DBG("ec_cmd %p, data_descrs %p, data_descrs_cnt %d ", ec_cmd,
		priv->cm_data_descrs, priv->cm_data_descrs_cnt);

	if (priv->cm_data_descrs != &priv->cm_seg_descrs[priv->cm_cur_seg_descr].data_descr) {
		TRACE_DBG_FLAG(TRACE_DEBUG|TRACE_MEMORY, "Freeing "
			"data_descrs %p", priv->cm_data_descrs);
		kfree(priv->cm_data_descrs);
	}

	priv->cm_data_descrs = NULL;
	priv->cm_data_descrs_cnt = 0;

	TRACE_EXIT();
	return;
}

/*
 * cm_mutex suppose to be locked or no activities on this ec_cmd's priv.
 *
 * Returns 0 on success or -ENOENT, if there are no data descriptors in
 * ec_cmd, or other negative error code. For other error codes cmd status
 * and sense supposed to be set.
 */
static int scst_cm_setup_data_descrs(struct scst_cmd *ec_cmd,
	const struct scst_ext_copy_data_descr *dds, int dds_cnt)
{
	int res;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;

	TRACE_ENTRY();

	TRACE_DBG("ec_cmd %p, dds %p, dds_cnt %d", ec_cmd, dds, dds_cnt);

	EXTRACHECKS_BUG_ON(dds_cnt == 0);

	priv->cm_data_descrs = dds;
	priv->cm_data_descrs_cnt = dds_cnt;

	res = scst_cm_setup_first_data_descr(ec_cmd);
	if (unlikely(res != 0))
		goto out_destr;

out:
	TRACE_EXIT_RES(res);
	return res;

out_destr:
	scst_cm_destroy_data_descrs(ec_cmd);
	goto out;
}

/*
 * cm_mutex suppose to be locked or no activities on this ec_cmd's priv.
 *
 * Returns 0 on success or -ENOENT, if there's no more seg descriptors in
 * ec_cmd, or other negative error code. For other error codes cmd status
 * and sense supposed to be set.
 */
static int scst_cm_setup_seg_descr(struct scst_cmd *ec_cmd)
{
	int res;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;
	struct scst_ext_copy_seg_descr *sd;

	TRACE_ENTRY();

	TRACE_DBG("ec_cmd %p, cm_cur_seg_descr %d", ec_cmd,
		priv->cm_cur_seg_descr);

	EXTRACHECKS_BUG_ON(priv->cm_cur_seg_descr > ec_cmd->cmd_data_descriptors_cnt);

	while (1) {
		if (priv->cm_cur_seg_descr == ec_cmd->cmd_data_descriptors_cnt)
			goto out_enoent;

		sd = &priv->cm_seg_descrs[priv->cm_cur_seg_descr];
		EXTRACHECKS_BUG_ON(sd->type != SCST_EXT_COPY_SEG_DATA);
		if (sd->data_descr.data_len != 0)
			break;

		priv->cm_cur_seg_descr++;
		TRACE_DBG("ec_cmd %p, cm_cur_seg_descr %d", ec_cmd,
			priv->cm_cur_seg_descr);
	}

	if (priv->cm_list_id != NULL) {
		/* SCSI: including the being processed one */
		priv->cm_list_id->cm_segs_processed = priv->cm_cur_seg_descr + 1;
	}

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;

out_enoent:
	TRACE_DBG("ec_cmd %p finished", ec_cmd);
	res = -ENOENT;
	goto out;
}

/* cm_mutex suppose to be locked or no activities on this ec_cmd's priv */
static void scst_cm_advance_seg_descr(struct scst_cmd *ec_cmd)
{
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;

	TRACE_ENTRY();

	TRACE_DBG("ec_cmd %p", ec_cmd);

	EXTRACHECKS_BUG_ON(priv->cm_cur_in_flight != 0);

	scst_cm_destroy_data_descrs(ec_cmd);

	priv->cm_cur_seg_descr++;

	TRACE_EXIT();
	return;
}

static void scst_cm_prepare_final_sense(struct scst_cmd *ec_cmd)
{
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;
	uint8_t *fsense = NULL;
	int d_sense = scst_get_cmd_dev_d_sense(ec_cmd);
	bool copy_sense = false;
	int sense_to_copy = ec_cmd->sense_valid_len;
	int sense_len = ec_cmd->sense_valid_len;

	TRACE_ENTRY();

	if (likely(priv->cm_error == SCST_CM_ERROR_NONE))
		goto out;

	TRACE_DBG("ec_cmd %p, cm_error %d, sense_to_copy %d", ec_cmd,
		priv->cm_error, sense_to_copy);

	if (sense_to_copy > (SCST_SENSE_BUFFERSIZE - 18)) {
		PRINT_WARNING("Too small sense buffer, %d bytes will be "
			"truncated (ec_cmd %p)",
			sense_to_copy - (SCST_SENSE_BUFFERSIZE-18), ec_cmd);
		sense_to_copy = SCST_SENSE_BUFFERSIZE - 18;
	}

	if ((priv->cm_error == SCST_CM_ERROR_WRITE) &&
	    (ec_cmd->status != SAM_STAT_CHECK_CONDITION)) {
		int rc;
		struct scst_ext_copy_seg_descr *sd = &priv->cm_seg_descrs[priv->cm_cur_seg_descr];

		/* THIRD PARTY DEVICE FAILURE */

		rc = scst_alloc_sense(ec_cmd, 0);
		if (rc != 0)
			goto out;

		TRACE_DBG("d_sense %d, cm_cur_seg_descr %d, cur_data_descr %d, "
			"tgt_descr_offs %d", d_sense, priv->cm_cur_seg_descr,
			priv->cm_cur_data_descr, sd->tgt_descr_offs);

		if (d_sense) {
			/* Descriptor format */
			ec_cmd->sense[0] = 0x72;
			ec_cmd->sense[1] = COPY_ABORTED;
			ec_cmd->sense[2] = 0xD; /* ASC */
			ec_cmd->sense[3] = 1; /* ASCQ */
			ec_cmd->sense[7] = 20; /* additional Sense Length */

			ec_cmd->sense[8] = 1; /* Command specific descriptor */
			ec_cmd->sense[9] = 0xA;
			put_unaligned_be16(priv->cm_cur_seg_descr, &ec_cmd->sense[14]);

			ec_cmd->sense[20] = 2; /* Sense key specific descriptor */
			ec_cmd->sense[21] = 6;
			ec_cmd->sense[24] = 0x80;
			put_unaligned_be16(sd->tgt_descr_offs, &ec_cmd->sense[25]);

			ec_cmd->sense_valid_len = 16;
		} else {
			/* Fixed format */
			ec_cmd->sense[0] = 0x70;
			ec_cmd->sense[2] = COPY_ABORTED;
			ec_cmd->sense[7] = 0x0a; /* additional Sense Length */
			ec_cmd->sense[12] = 0xD; /* ASC */
			ec_cmd->sense[13] = 1; /* ASCQ */

			put_unaligned_be16(priv->cm_cur_seg_descr, &ec_cmd->sense[10]);

			ec_cmd->sense[15] = 0x80;
			put_unaligned_be16(sd->tgt_descr_offs, &ec_cmd->sense[16]);

			ec_cmd->sense_valid_len = 18;
		}

		ec_cmd->status = SAM_STAT_CHECK_CONDITION;
		goto out;
	}

	fsense = mempool_alloc(scst_sense_mempool, GFP_KERNEL);
	if (fsense == NULL) {
		PRINT_ERROR("Allocation of the intermediate Extended Copy "
			"sense buffer failed. Reported sense data can be "
			"incorrect (ec_cmd %p)", ec_cmd);
		goto out;
	}
	memset(fsense, 0, SCST_SENSE_BUFFERSIZE);

	if (d_sense) {
		/* Descriptor format */
		fsense[0] = 0x72;
		fsense[1] = COPY_ABORTED;
		fsense[7] = 12; /* additional Sense Length */

		fsense[8] = 1; /* Command specific descriptor */
		fsense[9] = 0xA;
		put_unaligned_be16(priv->cm_cur_seg_descr, &fsense[14]);

		sense_len = 20;
	} else {
		/* Fixed format */
		fsense[0] = 0x70;
		fsense[2] = COPY_ABORTED;
		fsense[7] = 0x0a; /* additional Sense Length */

		put_unaligned_be16(priv->cm_cur_seg_descr, &fsense[10]);

		if (priv->cm_error == SCST_CM_ERROR_READ) {
			fsense[8] = 18;
			copy_sense = scst_sense_valid(ec_cmd->sense);
		} else if (priv->cm_error == SCST_CM_ERROR_WRITE) {
			fsense[9] = 18;
			copy_sense = scst_sense_valid(ec_cmd->sense);
		} else
			sBUG();

		if (copy_sense) {
			TRACE_DBG("Copying %db of old sense", sense_to_copy);
			fsense[7] += 1 + sense_to_copy;
			fsense[17] = ec_cmd->status;
			memcpy(&fsense[18], ec_cmd->sense, sense_to_copy);
		}

		sense_len = fsense[7] + 8;
		TRACE_DBG("New sense len %d", sense_len);
	}

	ec_cmd->status = SAM_STAT_CHECK_CONDITION;
	if (ec_cmd->sense != NULL) {
		memcpy(ec_cmd->sense, fsense, sense_len);
		ec_cmd->sense_valid_len = sense_len;
	} else
		scst_alloc_set_sense(ec_cmd, 0, fsense, sense_len);

	mempool_free(fsense, scst_sense_mempool);

out:
	TRACE_EXIT();
	return;
}

static void scst_cm_store_list_id_details(struct scst_cmd *ec_cmd)
{
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;
	struct scst_cm_list_id *l = priv->cm_list_id;

	TRACE_ENTRY();

	if (l != NULL) {
		TRACE_DBG("List id %p done (status %d, sense valid %d, sense "
			"len %d)", l, ec_cmd->status, scst_sense_valid(ec_cmd->sense),
			ec_cmd->sense_valid_len);
		spin_lock_irq(&scst_cm_lock);
		l->cm_list_id_state = SCST_CM_LIST_ID_STATE_DONE;
		if (ec_cmd->status != 0) {
			l->cm_status = ec_cmd->status;
			if (scst_sense_valid(ec_cmd->sense)) {
				int len = ec_cmd->sense_valid_len;

				if (len > sizeof(l->cm_sense)) {
					PRINT_WARNING("EC command's sense is "
						"too big (%d) with max allowed "
						"%d, truncating", len,
						(int)sizeof(l->cm_sense));
					len = sizeof(l->cm_sense);
				}
				l->cm_sense_len = ec_cmd->sense_valid_len;
				memcpy(l->cm_sense, ec_cmd->sense, len);
			}
		}
		spin_unlock_irq(&scst_cm_lock);
	}

	TRACE_EXIT();
	return;
}

static void scst_cm_ec_cmd_done(struct scst_cmd *ec_cmd)
{
#ifdef CONFIG_SCST_EXTRACHECKS
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;
#endif

	TRACE_ENTRY();

	TRACE_DBG("ec_cmd %p finished with status %d", ec_cmd, ec_cmd->status);

	EXTRACHECKS_BUG_ON(priv->cm_cur_in_flight != 0);
	EXTRACHECKS_BUG_ON(priv->cm_data_descrs != NULL);

	scst_cm_prepare_final_sense(ec_cmd);
	scst_cm_store_list_id_details(ec_cmd);

	ec_cmd->completed = 1; /* for success */
	ec_cmd->scst_cmd_done(ec_cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_THREAD);

	TRACE_EXIT();
	return;
}

static void scst_cm_ec_sched_next_seg(struct scst_cmd *ec_cmd)
{
	TRACE_ENTRY();

	/* No lock is needed, because it's all supposed to be calm */

	scst_cm_advance_seg_descr(ec_cmd);

	/*
	 * There's recursion possible here, if dev handlers call after
	 * remapping scst_ext_copy_remap_done() from the same thread context.
	 */
	scst_cm_ext_copy_exec(ec_cmd);

	TRACE_EXIT();
	return;
}

static void scst_cm_in_flight_cmd_finished(struct scst_cmd *ec_cmd)
{
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;
	int f;

	TRACE_ENTRY();

	mutex_lock(&priv->cm_mutex);

	priv->cm_cur_in_flight--;
	f = priv->cm_cur_in_flight;

	mutex_unlock(&priv->cm_mutex);

	TRACE_DBG("ec_cmd %p, priv->cm_cur_in_flight %d", ec_cmd, f);

	if (f > 0)
		goto out;

	if (priv->cm_list_id != NULL)
		priv->cm_list_id->cm_written_size += priv->cm_written;

	scst_cm_ec_sched_next_seg(ec_cmd);

out:
	TRACE_EXIT();
	return;
}

static int scst_cm_add_to_internal_cmd_list(struct scst_cmd *cmd,
	struct scst_cmd *ec_cmd, struct scst_cmd *orig_cmd,
	scst_i_finish_fn_t finish_fn)
{
	int res;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;
	struct scst_cm_internal_cmd_priv *p;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(ec_cmd == cmd);

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (p == NULL) {
		PRINT_ERROR("Unable to alloc scst_cm_internal_cmd_priv "
			"(size %d)", (int)sizeof(*p));
		goto out_enomem;
	}

	p->cm_finish_fn = finish_fn;
	p->cm_orig_cmd = orig_cmd;
	p->cm_cmd = cmd;

	TRACE_DBG("Adding internal cmd %p (priv %p, ec_cmd %p, orig_cmd %p)",
		cmd, p, ec_cmd, orig_cmd);
	spin_lock_irq(&scst_cm_lock);
	list_add_tail(&p->cm_internal_cmd_list_entry, &priv->cm_internal_cmd_list);
	spin_unlock_irq(&scst_cm_lock);

	cmd->tgt_i_priv = p;

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;

out_enomem:
	scst_set_busy(ec_cmd);
	res = -ENOMEM;
	goto out;
}

static void scst_cm_del_free_from_internal_cmd_list(struct scst_cmd *cmd,
	bool unblock_dev)
{
	struct scst_cm_internal_cmd_priv *p = cmd->tgt_i_priv;

	TRACE_ENTRY();

	TRACE_DBG("Deleting/freeing internal cmd %p (op %s, priv %p, "
		"orig_cmd %p)", cmd, scst_get_opcode_name(cmd), p,
		p->cm_orig_cmd);

	spin_lock_irq(&scst_cm_lock);
	list_del(&p->cm_internal_cmd_list_entry);
	spin_unlock_irq(&scst_cm_lock);

	if (unblock_dev) {
		TRACE_DBG("dev %p (internal cmd %p)", cmd->dev, cmd);
		scst_check_unblock_dev(cmd);
	}

	cmd->tgt_i_priv = NULL;

	kfree(p);

	TRACE_EXIT();
	return;
}

static void scst_cm_read_cmd_finished(struct scst_cmd *rcmd);

/* cm_mutex suppose to be locked */
static int __scst_cm_push_single_read(struct scst_cmd *ec_cmd,
	int64_t lba, int blocks)
{
	int res;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;
	uint8_t read_cdb[32];
	struct scst_device *rdev = priv->cm_read_tgt_dev->dev;
	int block_shift = rdev->block_shift;
	int len = blocks << block_shift;
	struct scst_cmd *rcmd;
	int cdb_len;
	bool check_dif = (rdev->dev_dif_mode & SCST_DIF_MODE_DEV);

	TRACE_ENTRY();

	if (unlikely(scst_cm_is_ec_cmd_done(ec_cmd))) {
		TRACE_MGMT_DBG("EC cmd %p done: aborting further read "
			"commands", ec_cmd);
		priv->cm_left_to_read = 0;
		res = -EPIPE;
		goto out;
	}

	memset(read_cdb, 0, sizeof(read_cdb));
	if (rdev->dev_dif_type != 2 || !check_dif) {
		read_cdb[0] = READ_16;
		if (check_dif)
			read_cdb[1] |= 0x20;
		put_unaligned_be64(lba, &read_cdb[2]);
		put_unaligned_be32(blocks, &read_cdb[10]);
		cdb_len = 16;
	} else {
		read_cdb[0] = VARIABLE_LENGTH_CMD;
		put_unaligned_be16(SUBCODE_READ_32, &read_cdb[8]);
		read_cdb[7] = 0x18;
		cdb_len = 32;
		read_cdb[10] = 0x20;
		put_unaligned_be64(lba, &read_cdb[12]);
		put_unaligned_be32(blocks, &read_cdb[28]);
		put_unaligned_be32(lba & 0xFFFF, &read_cdb[20]);
		/* No app tag check */
	}

	rcmd = __scst_create_prepare_internal_cmd(read_cdb,
		cdb_len, SCST_CMD_QUEUE_SIMPLE,
		priv->cm_read_tgt_dev, GFP_KERNEL, false);
	if (rcmd == NULL) {
		res = -ENOMEM;
		goto out_busy;
	}

	rcmd->internal_check_local_events = 1;

	rcmd->expected_data_direction = SCST_DATA_READ;
	rcmd->expected_transfer_len_full = len;
	if (check_dif != 0)
		rcmd->expected_transfer_len_full += len >> (block_shift - SCST_DIF_TAG_SHIFT);
	rcmd->expected_values_set = 1;

	res = scst_cm_add_to_internal_cmd_list(rcmd, ec_cmd, ec_cmd,
			scst_cm_read_cmd_finished);
	if (res != 0)
		goto out_free_rcmd;

	TRACE_DBG("Adding ec_cmd's (%p) READ rcmd %p (lba %lld, blocks %d, "
		"check_dif %d) to active cmd list", ec_cmd, rcmd,
		(long long)rcmd->lba, blocks, check_dif);
	spin_lock_irq(&rcmd->cmd_threads->cmd_list_lock);
	list_add_tail(&rcmd->cmd_list_entry, &rcmd->cmd_threads->active_cmd_list);
	spin_unlock_irq(&rcmd->cmd_threads->cmd_list_lock);

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;

out_busy:
	scst_set_busy(ec_cmd);
	goto out;

out_free_rcmd:
	__scst_cmd_put(rcmd);
	goto out;
}

static void scst_cm_read_retry_fn(struct scst_cmd *rcmd)
{
	struct scst_cm_internal_cmd_priv *p = rcmd->tgt_i_priv;
	struct scst_cmd *ec_cmd = p->cm_orig_cmd;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;
	int rc;

	TRACE_ENTRY();

	mutex_lock(&priv->cm_mutex);

	rc = __scst_cm_push_single_read(ec_cmd, rcmd->lba,
		rcmd->data_len >> priv->cm_read_tgt_dev->dev->block_shift);

	/* ec_cmd can get dead after we will drop cm_mutex! */
	scst_cm_del_free_from_internal_cmd_list(rcmd, false);

	mutex_unlock(&priv->cm_mutex);

	if (rc == 0)
		wake_up(&priv->cm_read_tgt_dev->active_cmd_threads->cmd_list_waitQ);
	else
		scst_cm_in_flight_cmd_finished(ec_cmd);

	TRACE_EXIT();
	return;
}

static int scst_cm_push_single_write(struct scst_cmd *ec_cmd,
	int64_t lba, int blocks, struct scst_cmd *rcmd);

static void scst_cm_write_retry_fn(struct scst_cmd *wcmd)
{
	struct scst_cm_internal_cmd_priv *p = wcmd->tgt_i_priv;
	struct scst_cmd *rcmd = p->cm_orig_cmd;
	struct scst_cm_internal_cmd_priv *rp = rcmd->tgt_i_priv;
	struct scst_cmd *ec_cmd = rp->cm_orig_cmd;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;
	int rc;

	TRACE_ENTRY();

	mutex_lock(&priv->cm_mutex);

	rc = scst_cm_push_single_write(ec_cmd, wcmd->lba,
		wcmd->data_len >> priv->cm_write_tgt_dev->dev->block_shift,
		rcmd);

	/* ec_cmd can get dead after we will drop cm_mutex! */
	scst_cm_del_free_from_internal_cmd_list(wcmd, false);

	mutex_unlock(&priv->cm_mutex);

	__scst_cmd_put(rcmd);

	if (rc != 0)
		scst_cm_in_flight_cmd_finished(ec_cmd);

	TRACE_EXIT();
	return;
}

static int scst_cm_push_single_read(struct scst_cmd *ec_cmd, int blocks,
	bool inc_cur_in_flight);

static void scst_cm_write_cmd_finished(struct scst_cmd *wcmd)
{
	struct scst_cm_internal_cmd_priv *p = wcmd->tgt_i_priv;
	struct scst_cmd *rcmd = p->cm_orig_cmd;
	struct scst_cm_internal_cmd_priv *rp = rcmd->tgt_i_priv;
	struct scst_cmd *ec_cmd = rp->cm_orig_cmd;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;
	int rc, blocks;

	TRACE_ENTRY();

	TRACE_DBG("Write cmd %p finished (ec_cmd %p, rcmd %p, cm_cur_in_flight %d)",
		wcmd, rcmd, ec_cmd, priv->cm_cur_in_flight);

	EXTRACHECKS_BUG_ON(wcmd->cdb[0] != WRITE_16);

	if (unlikely(scst_cm_is_ec_cmd_done(ec_cmd)))
		goto out_finished;

	rc = scst_cm_err_check_retry(wcmd, ec_cmd->start_time, scst_cm_write_retry_fn);
	if (likely(rc == SCST_CM_STATUS_CMD_SUCCEEDED))
		goto cont;
	else if (rc == SCST_CM_STATUS_RETRY)
		goto out;
	else {
		TRACE_DBG("Write cmd %p (ec_cmd %p) finished not successfully",
			wcmd, ec_cmd);
		if (wcmd->status == SAM_STAT_CHECK_CONDITION)
			rc = scst_set_cmd_error_sense(ec_cmd, wcmd->sense,
				wcmd->sense_valid_len);
		else {
			sBUG_ON(wcmd->sense != NULL);
			rc = scst_set_cmd_error_status(ec_cmd, wcmd->status);
		}
		if (rc != 0) {
			/*
			 * UAs should be retried unconditionally, but during
			 * limited time. If we are here, we need to requeue it.
			 */
			WARN_ON(scst_is_ua_sense(wcmd->sense, wcmd->sense_valid_len));
			sBUG_ON(priv->cm_error == SCST_CM_ERROR_NONE);
		} else
			priv->cm_error = SCST_CM_ERROR_WRITE;
		goto out_finished;
	}

cont:
	priv->cm_written += wcmd->data_len;
	TRACE_DBG("ec_cmd %p, cm_written %lld (data_len %lld)", ec_cmd,
		(long long)priv->cm_written, (long long)wcmd->data_len);

	wcmd->sg = NULL;
	wcmd->sg_cnt = 0;

	mutex_lock(&priv->cm_mutex);

	if (priv->cm_left_to_read == 0) {
		if (priv->cm_cur_data_descr >= priv->cm_data_descrs_cnt)
			goto out_unlock_finished;

		rc = scst_cm_setup_next_data_descr(ec_cmd);
		if (rc != 0)
			goto out_unlock_finished;
	}

	EXTRACHECKS_BUG_ON(priv->cm_left_to_read == 0);

	blocks = min_t(int, priv->cm_left_to_read, priv->cm_max_each_read);

	rc = scst_cm_push_single_read(ec_cmd, blocks, false);
	if (rc != 0)
		goto out_unlock_finished;

	scst_cm_del_free_from_internal_cmd_list(wcmd, false);
	scst_cm_del_free_from_internal_cmd_list(rcmd, false);

	mutex_unlock(&priv->cm_mutex);

	wake_up(&rcmd->cmd_threads->cmd_list_waitQ);

out_put:
	__scst_cmd_put(rcmd);

out:
	TRACE_EXIT();
	return;

out_unlock_finished:
	mutex_unlock(&priv->cm_mutex);

out_finished:
	scst_cm_del_free_from_internal_cmd_list(wcmd, false);
	scst_cm_del_free_from_internal_cmd_list(rcmd, false);

	scst_cm_in_flight_cmd_finished(ec_cmd);
	goto out_put;
}

static int scst_cm_push_single_write(struct scst_cmd *ec_cmd,
	int64_t lba, int blocks, struct scst_cmd *rcmd)
{
	int res;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;
	uint8_t write16_cdb[16];
	struct scst_cmd *wcmd;
	int len;

	TRACE_ENTRY();

	len = blocks << priv->cm_write_tgt_dev->dev->block_shift;

	/*
	 * ToDo: if rcmd is coming with tags SG, use it after updating ref and
	 * app tags instead of regenerating guard tags again with WRITE(16)
	 */

	memset(write16_cdb, 0, sizeof(write16_cdb));
	write16_cdb[0] = WRITE_16;
	put_unaligned_be64(lba, &write16_cdb[2]);
	put_unaligned_be32(blocks, &write16_cdb[10]);

	wcmd = __scst_create_prepare_internal_cmd(write16_cdb,
		sizeof(write16_cdb), SCST_CMD_QUEUE_SIMPLE,
		priv->cm_write_tgt_dev, GFP_KERNEL, false);
	if (wcmd == NULL) {
		res = -ENOMEM;
		goto out_busy;
	}

	wcmd->internal_check_local_events = 1;

	wcmd->expected_data_direction = SCST_DATA_WRITE;
	wcmd->expected_transfer_len_full = len;
	wcmd->expected_values_set = 1;

	res = scst_cm_add_to_internal_cmd_list(wcmd, ec_cmd, rcmd,
			scst_cm_write_cmd_finished);
	if (res != 0)
		goto out_free_wcmd;

	__scst_cmd_get(rcmd);

	wcmd->tgt_i_sg = rcmd->sg;
	wcmd->tgt_i_sg_cnt = rcmd->sg_cnt;
	wcmd->tgt_i_data_buf_alloced = 1;

	TRACE_DBG("Adding EC (%p) WRITE(16) cmd %p (lba %lld, blocks %d) to "
		"active cmd list", ec_cmd, wcmd, (long long)wcmd->lba, blocks);
	spin_lock_irq(&wcmd->cmd_threads->cmd_list_lock);
	list_add_tail(&wcmd->cmd_list_entry, &wcmd->cmd_threads->active_cmd_list);
	wake_up(&wcmd->cmd_threads->cmd_list_waitQ);
	spin_unlock_irq(&wcmd->cmd_threads->cmd_list_lock);

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;

out_busy:
	scst_set_busy(ec_cmd);
	goto out;

out_free_wcmd:
	__scst_cmd_put(wcmd);
	goto out;
}

static void scst_cm_read_cmd_finished(struct scst_cmd *rcmd)
{
	struct scst_cm_internal_cmd_priv *p = rcmd->tgt_i_priv;
	struct scst_cmd *ec_cmd = p->cm_orig_cmd;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;
	int64_t lba;
	int rc, len, blocks;

	TRACE_ENTRY();

	TRACE_DBG("READ cmd %p finished (ec_cmd %p, p %p)", rcmd, ec_cmd, p);

	if (unlikely(scst_cm_is_ec_cmd_done(ec_cmd)))
		goto out_finished;

	rc = scst_cm_err_check_retry(rcmd, ec_cmd->start_time, scst_cm_read_retry_fn);
	if (likely(rc == SCST_CM_STATUS_CMD_SUCCEEDED))
		goto cont;
	else if (rc == SCST_CM_STATUS_RETRY)
		goto out;
	else {
		TRACE_DBG("Read cmd %p (ec_cmd %p) finished not successfully",
			rcmd, ec_cmd);
		if (rcmd->status == SAM_STAT_CHECK_CONDITION)
			rc = scst_set_cmd_error_sense(ec_cmd, rcmd->sense,
				rcmd->sense_valid_len);
		else {
			sBUG_ON(rcmd->sense != NULL);
			rc = scst_set_cmd_error_status(ec_cmd, rcmd->status);
		}
		if (rc != 0) {
			/*
			 * UAs should be retried unconditionally, but during
			 * limited time. If we are here, we need to requeue it.
			 */
			WARN_ON(scst_is_ua_sense(rcmd->sense, rcmd->sense_valid_len));
			sBUG_ON(priv->cm_error == SCST_CM_ERROR_NONE);
		} else
			priv->cm_error = SCST_CM_ERROR_READ;
		goto out_finished;
	}

cont:
	lba = rcmd->lba - priv->cm_start_read_lba;
	lba <<= priv->cm_read_tgt_dev->dev->block_shift;
	lba >>= priv->cm_write_tgt_dev->dev->block_shift;
	lba += priv->cm_start_write_lba;

	len = rcmd->data_len;
	blocks = len >> priv->cm_write_tgt_dev->dev->block_shift;

	TRACE_DBG("rcmd->lba %lld, start_read_lba %lld, read shift %d, write "
		"shift %d, start_write_lba %lld, lba %lld, len %d, blocks %d",
		(long long)rcmd->lba, (long long)priv->cm_start_read_lba,
		priv->cm_read_tgt_dev->dev->block_shift,
		priv->cm_write_tgt_dev->dev->block_shift,
		(long long)priv->cm_start_write_lba, lba, len, blocks);

	rc = scst_cm_push_single_write(ec_cmd, lba, blocks, rcmd);
	if (rc != 0)
		goto out_finished;

out:
	TRACE_EXIT();
	return;

out_finished:
	scst_cm_del_free_from_internal_cmd_list(rcmd, false);

	scst_cm_in_flight_cmd_finished(ec_cmd);
	goto out;
}

/* cm_mutex suppose to be locked */
static int scst_cm_push_single_read(struct scst_cmd *ec_cmd, int blocks,
	bool inc_cur_in_flight)
{
	int res;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;

	TRACE_ENTRY();

	TRACE_DBG("ec_cmd %p, cm_cur_read_lba %lld, cm_left_to_read %d, "
		"blocks %d", ec_cmd, (long long)priv->cm_cur_read_lba,
		priv->cm_left_to_read, blocks);

	res = __scst_cm_push_single_read(ec_cmd, priv->cm_cur_read_lba, blocks);
	if (res != 0)
		goto out;

	priv->cm_cur_read_lba += blocks;
	priv->cm_left_to_read -= blocks;

	if (inc_cur_in_flight) {
		priv->cm_cur_in_flight++;
		TRACE_DBG("ec_cmd %p, new cm_cur_in_flight %d", ec_cmd,
			priv->cm_cur_in_flight);
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

/*
 * Generates original bunch of internal READ commands. In case of error
 * directly finishes ec_cmd, so it might be dead upon return!
 */
static void scst_cm_gen_reads(struct scst_cmd *ec_cmd)
{
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;
	int cnt = 0;

	TRACE_ENTRY();

	mutex_lock(&priv->cm_mutex);

	while (1) {
		int rc;

		while ((priv->cm_left_to_read > 0) &&
		       (priv->cm_cur_in_flight < SCST_MAX_IN_FLIGHT_INTERNAL_COMMANDS)) {
			int blocks;

			blocks = min_t(int, priv->cm_left_to_read, priv->cm_max_each_read);

			rc = scst_cm_push_single_read(ec_cmd, blocks, true);
			if (rc != 0)
				goto out_err;

			cnt++;
		}

		if (priv->cm_cur_in_flight == SCST_MAX_IN_FLIGHT_INTERNAL_COMMANDS)
			break;

		rc = scst_cm_setup_next_data_descr(ec_cmd);
		if (rc != 0)
			goto out_err;
	}

	EXTRACHECKS_BUG_ON(cnt == 0);

out_wake:
	if (cnt != 0)
		wake_up(&priv->cm_read_tgt_dev->active_cmd_threads->cmd_list_waitQ);

	mutex_unlock(&priv->cm_mutex);

out:
	TRACE_EXIT();
	return;

out_err:
	if (priv->cm_cur_in_flight != 0)
		goto out_wake;
	else {
		mutex_unlock(&priv->cm_mutex);
		scst_cm_ec_cmd_done(ec_cmd);
	}
	goto out;
}

/* cm_mutex suppose to be locked or no activities on this ec_cmd's priv */
static void scst_cm_process_data_descrs(struct scst_cmd *ec_cmd,
	const struct scst_ext_copy_data_descr *dds, int dds_cnt)
{
	int rc;

	TRACE_ENTRY();

	rc = scst_cm_setup_data_descrs(ec_cmd, dds, dds_cnt);
	if (rc != 0)
		goto out_done;

	scst_cm_gen_reads(ec_cmd);

	/* ec_cmd can be dead here! */

out:
	TRACE_EXIT();
	return;

out_done:
	scst_cm_ec_cmd_done(ec_cmd);
	goto out;
}

/**
 * scst_ext_copy_get_cur_seg_data_len() - return current segment data len
 * @ec_cmd:	EXTENDED COPY command
 */
int scst_ext_copy_get_cur_seg_data_len(struct scst_cmd *ec_cmd)
{
	int res;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;

	TRACE_ENTRY();

	res = priv->cm_seg_descrs[priv->cm_cur_seg_descr].data_descr.data_len;

	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL_GPL(scst_ext_copy_get_cur_seg_data_len);

/**
 * scst_ext_copy_remap_done() - dev handler done with remapping this segment
 * @ec_cmd:	EXTENDED COPY command
 * @dds:	Leftover data descriptors
 * @dds_cnt:	Count of the leftover data descriptors
 *
 * Called by dev handlers from inside ext_copy_remap() callback upon finish.
 * All not finished spaces should be k?alloc() as array of data descriptors
 * in dds argument with count dds_count. SCST core then will copy them using
 * internal copy machine and then kfree() dds.
 *
 * dds can point to &descr->data_descr, where descr is pointer supplied to
 * ext_copy_remap(). In this case SCST core will not kfree() it.
 *
 * If dds is NULL, then all data have been remapped, so SCST core will switch
 * to the next segment descriptor, if any.
 */
void scst_ext_copy_remap_done(struct scst_cmd *ec_cmd,
	struct scst_ext_copy_data_descr *dds, int dds_cnt)
{
	TRACE_ENTRY();

	scst_set_exec_time(ec_cmd);

	if (dds == NULL)
		scst_cm_ec_sched_next_seg(ec_cmd);
	else
		scst_cm_process_data_descrs(ec_cmd, dds, dds_cnt);

	/* ec_cmd can be dead here! */

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL_GPL(scst_ext_copy_remap_done);

static int scst_cm_try_to_remap(struct scst_cmd *ec_cmd);

static void scst_cm_remap_retry_fn(struct scst_cmd *cmd)
{
	struct scst_cmd *ec_cmd = cmd->tgt_i_priv;
	int rc;

	TRACE_ENTRY();

	rc = scst_cm_try_to_remap(ec_cmd);
	sBUG_ON(rc != 0);

	TRACE_EXIT();
	return;
}

/*
 * Tries to remap data before copying.
 *
 * Returns !=0 if remapping is not possible, or not 0 otherwise.
 */
static int scst_cm_try_to_remap(struct scst_cmd *ec_cmd)
{
	int res, rc;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;
	struct scst_ext_copy_seg_descr *sd = &priv->cm_seg_descrs[priv->cm_cur_seg_descr];
	struct scst_ext_copy_data_descr *dd = &sd->data_descr;
	struct scst_dev_type *handler = ec_cmd->dev->handler;
	uint8_t cdb[16];
	struct scst_cmd *cmd;

	TRACE_ENTRY();

	if (handler->ext_copy_remap == NULL) {
		res = 1;
		goto out;
	}

	res = 0;

	/* !! priv data descriptors fields are not setup yet !! */

	TRACE_DBG("Checking reservations on read dev %s (ec_cmd %p)",
		sd->src_tgt_dev->dev->virt_name, ec_cmd);

	memset(cdb, 0, sizeof(cdb));
	cdb[0] = READ_16;
	put_unaligned_be64(dd->src_lba, &cdb[2]);
	put_unaligned_be32(dd->data_len >> sd->src_tgt_dev->dev->block_shift, &cdb[10]);

	cmd = __scst_create_prepare_internal_cmd(cdb,
		sizeof(cdb), SCST_CMD_QUEUE_SIMPLE,
		sd->src_tgt_dev, GFP_KERNEL, true);
	if (cmd == NULL)
		goto out_busy;

	cmd->internal_check_local_events = 1;
	cmd->tgt_i_priv = ec_cmd; /* needed for retries */

	rc = __scst_check_local_events(cmd, false);
	if (unlikely(rc != 0))
		goto out_check_retry;

	__scst_cmd_put(cmd);

	TRACE_DBG("Checking reservations on write dev %s (ec_cmd %p)",
		sd->dst_tgt_dev->dev->virt_name, ec_cmd);

	memset(cdb, 0, sizeof(cdb));
	cdb[0] = WRITE_16;
	put_unaligned_be64(dd->dst_lba, &cdb[2]);
	put_unaligned_be32(dd->data_len >> sd->dst_tgt_dev->dev->block_shift, &cdb[10]);

	cmd = __scst_create_prepare_internal_cmd(cdb,
		sizeof(cdb), SCST_CMD_QUEUE_SIMPLE,
		sd->dst_tgt_dev, GFP_KERNEL, true);
	if (cmd == NULL)
		goto out_busy;

	cmd->internal_check_local_events = 1;
	cmd->tgt_i_priv = ec_cmd; /* needed for retries */

	rc = __scst_check_local_events(cmd, false);
	if (unlikely(rc != 0))
		goto out_check_retry;

	__scst_cmd_put(cmd);

	TRACE_DBG("Calling ext_copy_remap() for dev %s (ec_cmd %p)",
		sd->dst_tgt_dev->dev->virt_name, ec_cmd);

	scst_set_exec_start(ec_cmd);
	handler->ext_copy_remap(ec_cmd, sd);

out:
	TRACE_EXIT_RES(res);
	return res;

out_check_retry:
	rc = scst_cm_err_check_retry(cmd, ec_cmd->start_time, scst_cm_remap_retry_fn);
	sBUG_ON(rc == SCST_CM_STATUS_CMD_SUCCEEDED);
	if (rc == SCST_CM_STATUS_CMD_FAILED) {
		TRACE_DBG("Remap check cmd %p (ec_cmd %p, op %s) failed",
			cmd, ec_cmd, scst_get_opcode_name(cmd));
		if (cmd->status == SAM_STAT_CHECK_CONDITION)
			rc = scst_set_cmd_error_sense(ec_cmd, cmd->sense,
				cmd->sense_valid_len);
		else {
			sBUG_ON(cmd->sense != NULL);
			rc = scst_set_cmd_error_status(ec_cmd, cmd->status);
		}
		if (rc != 0) {
			/*
			 * UAs should be retried unconditionally, but during
			 * limited time. If we are here, we need to requeue it.
			 */
			WARN_ON(scst_is_ua_sense(cmd->sense, cmd->sense_valid_len));
		} else {
			if (cmd->cdb[0] == READ_16)
				priv->cm_error = SCST_CM_ERROR_READ;
			else {
				EXTRACHECKS_BUG_ON(cmd->cdb[0] != WRITE_16);
				priv->cm_error = SCST_CM_ERROR_WRITE;
			}
		}
		__scst_cmd_put(cmd);
		goto out_done;
	}
	__scst_cmd_put(cmd);
	goto out;

out_busy:
	res = -ENOMEM;
	scst_set_busy(ec_cmd);

out_done:
	scst_cm_ec_cmd_done(ec_cmd);
	goto out;
}

static void scst_cm_process_cur_seg_descr(struct scst_cmd *ec_cmd)
{
	int rc;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;

	TRACE_ENTRY();

	rc = scst_cm_try_to_remap(ec_cmd);
	if (rc == 0)
		goto out;

	/* No remapping supported */

	scst_ext_copy_remap_done(ec_cmd,
		&priv->cm_seg_descrs[priv->cm_cur_seg_descr].data_descr, 1);

out:
	TRACE_EXIT();
	return;
}

int scst_cm_ext_copy_exec(struct scst_cmd *ec_cmd)
{
	int res = SCST_EXEC_COMPLETED, rc;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;

	TRACE_ENTRY();

	if (unlikely(priv == NULL))
		goto out_local_done;

	if (unlikely(scst_cm_is_ec_cmd_done(ec_cmd))) {
		TRACE_DBG("ec_cmd %p done", ec_cmd);
		goto out_done;
	}

	rc = scst_cm_setup_seg_descr(ec_cmd);
	if (rc != 0)
		goto out_err_done;

	scst_cm_process_cur_seg_descr(ec_cmd);

out:
	TRACE_EXIT();
	return res;

out_local_done:
	ec_cmd->completed = 1; /* for success */
	ec_cmd->scst_cmd_done(ec_cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_THREAD);
	goto out;

out_err_done:
	sBUG_ON((rc != -ENOENT) && !ec_cmd->completed);

out_done:
	scst_cm_ec_cmd_done(ec_cmd);
	goto out;
}

bool scst_cm_ec_cmd_overlap(struct scst_cmd *ec_cmd, struct scst_cmd *cmd)
{
	bool res = false;
	int i;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;

	TRACE_ENTRY();

	TRACE_DBG("ec_cmd %p, cmd %p", ec_cmd, cmd);

	EXTRACHECKS_BUG_ON(ec_cmd->cdb[0] != EXTENDED_COPY);

	if ((cmd->op_flags & SCST_LBA_NOT_VALID) != 0)
		goto out;

	for (i = 0; i < ec_cmd->cmd_data_descriptors_cnt; i++) {
		struct scst_ext_copy_seg_descr *sd = &priv->cm_seg_descrs[i];

		TRACE_DBG("type %d, dst_dev %p, dev %p", sd->type,
			sd->dst_tgt_dev->dev, cmd->dev);

		if (sd->type != SCST_EXT_COPY_SEG_DATA)
			continue;
		if (sd->dst_tgt_dev->dev != cmd->dev)
			continue;

		res = scst_lba1_inside_lba2(sd->data_descr.dst_lba, cmd->lba,
			cmd->data_len >> cmd->dev->block_shift);
		if (res)
			goto out;
		res = scst_lba1_inside_lba2(cmd->lba, sd->data_descr.dst_lba,
			sd->data_descr.data_len >> sd->dst_tgt_dev->dev->block_shift);
		if (res)
			goto out;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

/*
 * No locks. Returns true if cmd should be blocked.
 */
bool scst_cm_check_block_all_devs(struct scst_cmd *cmd)
{
	bool res = false;
	struct scst_cmd *ec_cmd;
	struct scst_cm_ec_cmd_priv *d;
	struct scst_cm_dev_entry *e;

	TRACE_ENTRY();

	/*
	 * EXTENDED COPY command creates a new challenge: it can operate on
	 * several devices at the same time. Hence, it opens a wide possibility
	 * of deadlocks like the following.
	 *
	 * Device A received EXTENDED COPY command EC1 to copy data from device
	 * A to device B. It started doing the job by generating SCSI READ and
	 * WRITE commands to devices A and B. In the middle of the work device B
	 * received its EXTENDED COPY command EC2 to copy data from device B
	 * to device A. It also started doing its work in parallel with EC1.
	 * Then, device A received a serialized or SCSI atomic command, which
	 * can not proceed until EC1 finished and don't let EC2 generated
	 * commands to proceed ahead of it. Then, if device B received similar
	 * serialized or SCSI atomic command, blocking EC2 generated commands,
	 * we would have a deadlock.
	 *
	 * So, we can not allow EXTENDED COPY generated SCSI commands be
	 * blocked. From other side, we have to honor serialized and SCSI atomic
	 * commands as well as all other devices blocking events.
	 *
	 * To handle it, we, from one side, generate all EXTENDED COPY read and
	 * writes commands as internal commands, so they bypass blocking
	 * checking, and from another side, create "fantom" EXTENDED COPY
	 * commands on all participating devices, then pass "check blocking" on
	 * all them at once. If any device blocked its command, then undo check
	 * blocking on all previously processed devices. After the blocked
	 * command resumed, we retry again. For SCSI atomic commands we check
	 * each if any of the (fantom) EXTENDED COPY commands conflict with
	 * existing SCSI atomic commands. If yes, then restart on the conflicting
	 * (fantom) EXTENDED COPY resume as described above. Then we check all
	 * newly coming SCSI atomic commands if they conflict with existing
	 * (fantom) EXTENDED COPY commands.
	 */

	if (cmd->internal) {
		struct scst_cm_internal_cmd_priv *p = cmd->tgt_i_priv;

		/* cmd is a resumed phantom EXTENDED COPY command */

		ec_cmd = p->cm_orig_cmd;

		TRACE_BLOCK("Rewaking blocked EC cmd %p (fcmd %p)",
			ec_cmd, cmd);

		scst_check_unblock_dev(cmd);

		spin_lock_irq(&ec_cmd->cmd_threads->cmd_list_lock);
		list_add_tail(&ec_cmd->cmd_list_entry,
			&ec_cmd->cmd_threads->active_cmd_list);
		wake_up(&ec_cmd->cmd_threads->cmd_list_waitQ);
		spin_unlock_irq(&ec_cmd->cmd_threads->cmd_list_lock);

		res = true;
		goto out;
	}

	/* cmd is a real ready for exec EXTENDED COPY command */

	ec_cmd = cmd;
	/*
	 * This could be restart of previously blocked ec_cmd, so
	 * check unblock it.
	 */
	TRACE_DBG("Check unblocking ec_cmd %p", ec_cmd);
	scst_check_unblock_dev(ec_cmd);

	d = ec_cmd->cmd_data_descriptors;
	if (d == NULL) {
		spin_lock_bh(&ec_cmd->dev->dev_lock);
		res = scst_do_check_blocked_dev(ec_cmd);
		spin_unlock_bh(&ec_cmd->dev->dev_lock);
		goto out;
	}

	local_bh_disable();

#if !defined(__CHECKER__)
	list_for_each_entry(e, &d->cm_sorted_devs_list, cm_sorted_devs_list_entry) {
		spin_lock_nolockdep(&e->cm_fcmd->dev->dev_lock);
	}
#endif

	list_for_each_entry(e, &d->cm_sorted_devs_list, cm_sorted_devs_list_entry) {
		TRACE_DBG("dev %p (fcmd %p)", e->cm_fcmd->dev, e->cm_fcmd);
		res = scst_do_check_blocked_dev(e->cm_fcmd);
		if (unlikely(res)) {
			TRACE_BLOCK("fcmd %p (ec_cmd %p) blocked, undo "
				"check blocking devices", e->cm_fcmd, ec_cmd);
			break;
		}
	}

	if (unlikely(res)) {
		struct scst_cmd *blocked_cmd = e->cm_fcmd;

		list_for_each_entry(e, &d->cm_sorted_devs_list,
					cm_sorted_devs_list_entry) {
			if (e->cm_fcmd == blocked_cmd)
				break;
			__scst_check_unblock_dev(e->cm_fcmd);
			e->cm_fcmd->state = SCST_CMD_STATE_EXEC_CHECK_BLOCKING;
		}
	}

#if !defined(__CHECKER__)
	list_for_each_entry_reverse(e, &d->cm_sorted_devs_list,
					cm_sorted_devs_list_entry) {
		spin_unlock_nolockdep(&e->cm_fcmd->dev->dev_lock);
	}
#endif

	local_bh_enable();

out:
	TRACE_EXIT_RES(res);
	return res;
}

void scst_cm_abort_ec_cmd(struct scst_cmd *ec_cmd)
{
	struct scst_cm_ec_cmd_priv *p = ec_cmd->cmd_data_descriptors;
	struct scst_cm_internal_cmd_priv *ip;
	unsigned long flags;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(ec_cmd->cdb[0] != EXTENDED_COPY);

	spin_lock_irqsave(&scst_cm_lock, flags);

	if (p == NULL)
		goto out_unlock;

	TRACE_MGMT_DBG("Aborting fantom and internal commands of ec_cmd %p",
		ec_cmd);

	list_for_each_entry(ip, &p->cm_internal_cmd_list,
					cm_internal_cmd_list_entry) {
		struct scst_cmd *c = ip->cm_cmd;

		TRACE_MGMT_DBG("Aborting (f)cmd %p", c);
		set_bit(SCST_CMD_ABORTED, &c->cmd_flags);
	}

out_unlock:
	spin_unlock_irqrestore(&scst_cm_lock, flags);

	TRACE_EXIT();
	return;
}

static void scst_cm_del_free_list_id(struct scst_cm_list_id *l, bool locked)
{
	unsigned long flags = 0;

	TRACE_ENTRY();

	TRACE_DBG("Freeing list id %p", l);

#if !defined(__CHECKER__)
	if (!locked)
		spin_lock_irqsave(&scst_cm_lock, flags);
#endif

#ifdef CONFIG_SMP
	EXTRACHECKS_BUG_ON(!spin_is_locked(&scst_cm_lock));
#endif

	list_del(&l->sess_cm_list_id_entry);

#if !defined(__CHECKER__)
	if (!locked)
		spin_unlock_irqrestore(&scst_cm_lock, flags);
#endif

	kfree(l);

	TRACE_EXIT();
	return;
}

static void scst_cm_sched_del_list_id(struct scst_cmd *ec_cmd)
{
	struct scst_session *sess = ec_cmd->sess;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;
	struct scst_cm_list_id *l = priv->cm_list_id;
	unsigned long flags;

	TRACE_ENTRY();

	spin_lock_irqsave(&scst_cm_lock, flags);

	if (l->cm_list_id_state != SCST_CM_LIST_ID_STATE_DONE) {
		/*
		 * It can happen for preliminary EC command finish, e.g.,
		 * because of local event like UA.
		 */
		l->cm_can_be_immed_free = 1;
	}

	l->cm_done = 1;

	/*
	 * Barrier to sync with scst_abort_cmd() and
	 * scst_mgmt_affected_cmds_done() calling scst_cm_free_pending_list_ids().
	 * It has nothing common with cm_done set above. Just in case, actually.
	 */
	smp_rmb();
	if (test_bit(SCST_CMD_ABORTED, &ec_cmd->cmd_flags) ||
	    l->cm_can_be_immed_free) {
		TRACE_DBG("List id %p can be immed freed", l);
		scst_cm_del_free_list_id(l, true);
		spin_unlock_irqrestore(&scst_cm_lock, flags);
		goto out;
	}

	l->cm_list_id_state = SCST_CM_LIST_ID_STATE_PENDING_FREE;
	l->cm_time_to_free = jiffies + SCST_CM_ID_KEEP_TIME;

	spin_unlock_irqrestore(&scst_cm_lock, flags);

	TRACE_DBG("Schedule pending free list id %p", l);

	schedule_delayed_work(&sess->sess_cm_list_id_cleanup_work,
				SCST_CM_ID_KEEP_TIME);

out:
	TRACE_EXIT();
	return;
}

static struct scst_cm_list_id *scst_cm_add_list_id(struct scst_cmd *cmd,
	int list_id)
{
	struct scst_cm_list_id *res;
	struct scst_session *sess = cmd->sess;
	struct scst_cm_list_id *l;

	TRACE_ENTRY();

	res = kzalloc(sizeof(*res), GFP_KERNEL);
	if (res == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "Unable to allocate list_id");
		scst_set_busy(cmd);
		goto out;
	}

	res->cm_lid = list_id;
	res->cm_list_id_state = SCST_CM_LIST_ID_STATE_ACTIVE;

	spin_lock_irq(&scst_cm_lock);

	list_for_each_entry(l, &sess->sess_cm_list_id_list, sess_cm_list_id_entry) {
		if (l->cm_lid == list_id) {
			if (l->cm_list_id_state == SCST_CM_LIST_ID_STATE_PENDING_FREE) {
				scst_cm_del_free_list_id(l, true);
				break;
			} else {
				TRACE_DBG("List id %d already exists", list_id);
				scst_set_cmd_error(cmd,
					SCST_LOAD_SENSE(scst_sense_operation_in_progress));
				goto out_unlock_free;
			}
		}
	}

	TRACE_DBG("Adding list id %p (id %d)", res, list_id);
	list_add_tail(&res->sess_cm_list_id_entry, &sess->sess_cm_list_id_list);

	spin_unlock_irq(&scst_cm_lock);

out:
	TRACE_EXIT();
	return res;

out_unlock_free:
	spin_unlock_irq(&scst_cm_lock);
	kfree(res);
	res = NULL;
	goto out;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
void sess_cm_list_id_cleanup_work_fn(void *p)
{
	struct scst_session *sess = p;
#else
void sess_cm_list_id_cleanup_work_fn(struct work_struct *work)
{
	struct scst_session *sess = container_of(work,
			struct scst_session, sess_cm_list_id_cleanup_work.work);
#endif
	struct scst_cm_list_id *l, *t;
	unsigned long cur_time = jiffies;
	unsigned long flags;

	TRACE_ENTRY();

	/*
	 * We assume that EC commands finish _more or less_ in order, so
	 * there's no need to scan the whole list each time.
	 */

	spin_lock_irqsave(&scst_cm_lock, flags);
	list_for_each_entry_safe(l, t, &sess->sess_cm_list_id_list, sess_cm_list_id_entry) {
		if (l->cm_list_id_state != SCST_CM_LIST_ID_STATE_PENDING_FREE)
			break;
		if (time_after_eq(cur_time, l->cm_time_to_free))
			scst_cm_del_free_list_id(l, true);
		else {
			TRACE_DBG("Reschedule pending free list ids cleanup");
			schedule_delayed_work(&sess->sess_cm_list_id_cleanup_work,
				l->cm_time_to_free - cur_time);
		}
	}
	spin_unlock_irqrestore(&scst_cm_lock, flags);

	TRACE_EXIT();
	return;
}

void scst_cm_free_pending_list_ids(struct scst_session *sess)
{
	struct scst_cm_list_id *l, *t;

	TRACE_ENTRY();

	cancel_delayed_work_sync(&sess->sess_cm_list_id_cleanup_work);

	spin_lock_irq(&scst_cm_lock);
	list_for_each_entry_safe(l, t, &sess->sess_cm_list_id_list, sess_cm_list_id_entry) {
		TRACE_DBG("List id %p, state %d", l, l->cm_list_id_state);
		if (l->cm_list_id_state == SCST_CM_LIST_ID_STATE_PENDING_FREE)
			scst_cm_del_free_list_id(l, true);
	}
	spin_unlock_irq(&scst_cm_lock);

	TRACE_EXIT();
	return;
}

static void scst_cm_copy_status(struct scst_cmd *cmd)
{
	ssize_t length = 0;
	uint8_t *buf, tbuf[12];
	int list_id;
	struct scst_cm_list_id *l;
	struct scst_session *sess = cmd->sess;
	bool found = false;

	TRACE_ENTRY();

	list_id = cmd->cdb[2];

	spin_lock_irq(&scst_cm_lock);
	list_for_each_entry(l, &sess->sess_cm_list_id_list, sess_cm_list_id_entry) {
		if (l->cm_lid == list_id) {
			TRACE_DBG("list id %p found (id %d)", l, list_id);
			found = true;
			break;
		}
	}
	if (found) {
		l->cm_can_be_immed_free = 1;

		memset(tbuf, 0, sizeof(tbuf));
		put_unaligned_be32(8, &tbuf[0]);
		if (l->cm_list_id_state == SCST_CM_LIST_ID_STATE_ACTIVE)
			tbuf[4] = 0; /* in progress */
		else if (l->cm_status == 0)
			tbuf[4] = 1; /* finished, no errors */
		else
			tbuf[4] = 2; /* finished with errors */
		put_unaligned_be16(l->cm_segs_processed, &tbuf[5]);
		tbuf[7] = 1; /* KBs */
		put_unaligned_be32(l->cm_written_size >> 10, &tbuf[8]);

		if (l->cm_done)
			scst_cm_del_free_list_id(l, true);
	}

	l = NULL; /* after unlock it can be immediately get dead */

	spin_unlock_irq(&scst_cm_lock);

	if (!found)
		goto out_list_id_not_found;

	length = scst_get_buf_full_sense(cmd, &buf);
	if (unlikely(length <= 0))
		goto out;

	length = min_t(int, (int)sizeof(tbuf), length);

	memcpy(buf, tbuf, length);
	scst_set_resp_data_len(cmd, length);

	scst_put_buf_full(cmd, buf);

out:
	TRACE_EXIT();
	return;

out_list_id_not_found:
	TRACE_DBG("list_id %d not found", list_id);
	scst_set_invalid_field_in_cdb(cmd, 2, 0);
	goto out;
}

static void scst_cm_failed_seg_details(struct scst_cmd *cmd)
{
	ssize_t length = 0;
	uint8_t *buf, *tbuf;
	int list_id, size;
	struct scst_cm_list_id *l;
	struct scst_session *sess = cmd->sess;
	bool found = false;

	TRACE_ENTRY();

	list_id = cmd->cdb[2];

	size = 60 + SCST_SENSE_BUFFERSIZE;

	tbuf = kzalloc(size, GFP_KERNEL);
	if (tbuf == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "Unable to allocate FAILED SEGMENTS "
			"DETAILS buffer (size %d)", size);
		goto out_busy;
	}

	spin_lock_irq(&scst_cm_lock);
	list_for_each_entry(l, &sess->sess_cm_list_id_list, sess_cm_list_id_entry) {
		if (l->cm_lid == list_id) {
			TRACE_DBG("list id %p found (id %d)", l, list_id);
			found = true;
			break;
		}
	}
	if (found) {
		if (l->cm_list_id_state == SCST_CM_LIST_ID_STATE_ACTIVE) {
			found = false;
			goto skip;
		}

		if ((cmd->bufflen == 0) ||
		    ((l->cm_status == 0) && (cmd->bufflen >= 60)) ||
		    ((l->cm_status != 0) && (cmd->bufflen >= 60 + SCST_SENSE_BUFFERSIZE)))
			l->cm_can_be_immed_free = 1;

		if (l->cm_status == 0)
			size = 60;
		else
			size = 60 + l->cm_sense_len;

		TRACE_DBG("l %p, status %d, sense_len %d, size %d", l,
			l->cm_status, l->cm_sense_len, size);

		put_unaligned_be32(size-3, &tbuf[0]);
		tbuf[56] = l->cm_status;
		EXTRACHECKS_BUG_ON(l->cm_sense_len > SCST_SENSE_BUFFERSIZE);
		BUILD_BUG_ON(sizeof(l->cm_sense) != SCST_SENSE_BUFFERSIZE);
		put_unaligned_be16(l->cm_sense_len, &tbuf[58]);
		if (l->cm_sense_len > 0)
			memcpy(&tbuf[60], l->cm_sense, l->cm_sense_len);

		if (l->cm_can_be_immed_free && l->cm_done)
			scst_cm_del_free_list_id(l, true);
	}

skip:
	l = NULL; /* after unlock it can be immediately get dead */

	spin_unlock_irq(&scst_cm_lock);

	if (!found)
		goto out_list_id_not_found;

	length = scst_get_buf_full_sense(cmd, &buf);
	if (unlikely(length <= 0))
		goto out_free;

	length = min_t(int, size, length);

	memcpy(buf, tbuf, length);
	scst_set_resp_data_len(cmd, length);

	scst_put_buf_full(cmd, buf);

out_free:
	kfree(tbuf);

	TRACE_EXIT();
	return;

out_list_id_not_found:
	TRACE_DBG("list_id %d not found", list_id);
	scst_set_invalid_field_in_cdb(cmd, 2, 0);
	goto out_free;

out_busy:
	scst_set_busy(cmd);
	goto out_free;
}

static void scst_cm_oper_parameters(struct scst_cmd *cmd)
{
	ssize_t length = 0;
	uint8_t *buf, tbuf[44+2] /* 2 descriptors implemented */;

	TRACE_ENTRY();

	memset(tbuf, 0, sizeof(tbuf));

	/* AVAILABLE DATA */
	put_unaligned_be32(sizeof(tbuf) - 4, &tbuf[0]);

	/* SNLID */
	tbuf[4] = 1;

	/* MAXIMUM TARGET DESCRIPTOR COUNT */
	put_unaligned_be16(SCST_CM_MAX_TGT_DESCR_CNT, &tbuf[8]);

	/* MAXIMUM SEGMENT DESCRIPTOR COUNT */
	put_unaligned_be16(SCST_CM_MAX_SEG_DESCR_CNT, &tbuf[10]);

	/* MAXIMUM DESCRIPTOR LIST LENGTH */
	put_unaligned_be32(SCST_MAX_SEG_DESC_LEN, &tbuf[12]);

	/* MAXIMUM SEGMENT LENGTH: 256MB */
	put_unaligned_be32(256*1024*1024, &tbuf[16]);

	/* No inline and held data. No stream device max data size. */

	/* TOTAL CONCURRENT COPIES */
	put_unaligned_be16(0xFFFF, &tbuf[34]);

	/* MAXIMUM CONCURRENT COPIES */
	tbuf[36] = 0xFF;

	/* DATA SEGMENT GRANULARITY */
	tbuf[37] = 16; /* 64K */

	/* 2 descriptor codes implemented */
	tbuf[43] = 2;

	/* Implemented descriptor codes */
	tbuf[44] = 2;
	tbuf[45] = 0xE4;

	length = scst_get_buf_full_sense(cmd, &buf);
	if (unlikely(length <= 0))
		goto out;

	length = min_t(int, (int)sizeof(tbuf), length);

	memcpy(buf, tbuf, length);
	scst_set_resp_data_len(cmd, length);

	scst_put_buf_full(cmd, buf);

out:
	TRACE_EXIT();
	return;
}

int scst_cm_rcv_copy_res_exec(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_COMPLETED, action;

	TRACE_ENTRY();

	action = cmd->cdb[1] & 0x1F;

	switch (action) {
	case 0: /* copy status */
		scst_cm_copy_status(cmd);
		break;
	case 3: /* operational parameters */
		scst_cm_oper_parameters(cmd);
		break;
	case 4: /* failed segment details */
		scst_cm_failed_seg_details(cmd);
		break;
	default:
		TRACE(TRACE_MINOR, "%s: action %d not supported", cmd->op_name,
			action);
		scst_set_invalid_field_in_cdb(cmd, 1,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
		break;
	}

	cmd->completed = 1; /* for success */
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_THREAD);

	TRACE_EXIT_RES(res);
	return res;
}

struct scst_cm_init_inq_priv {
	/* Must be the first for scst_finish_internal_cmd()! */
	scst_i_finish_fn_t cm_init_inq_finish_fn;

	struct scst_device *dev;
};

static int scst_cm_send_init_inquiry(struct scst_device *dev,
	unsigned int unpacked_lun, struct scst_cm_init_inq_priv *priv);

static void scst_cm_inq_retry_fn(struct scst_cmd *cmd)
{
	struct scst_cm_init_inq_priv *priv = cmd->tgt_i_priv;

	TRACE_ENTRY();

	/* cmd->dev can be NULL here! */

	scst_cm_send_init_inquiry(priv->dev, cmd->lun, priv);

	TRACE_EXIT();
	return;
}

static void scst_cm_init_inq_finish(struct scst_cmd *cmd)
{
	int length, page_len, off, rc;
	uint8_t *buf;
	struct scst_cm_init_inq_priv *priv = cmd->tgt_i_priv;
	struct scst_device *dev = priv->dev;

	TRACE_ENTRY();

	/* cmd->dev can be NULL here! */

	rc = scst_cm_err_check_retry(cmd, cmd->start_time, scst_cm_inq_retry_fn);
	if (rc == SCST_CM_STATUS_RETRY || !cmd->dev || !cmd->tgt_dev)
		goto out;

	spin_lock_bh(&dev->dev_lock);
	scst_unblock_dev(dev);
	spin_unlock_bh(&dev->dev_lock);

	kfree(priv);
	priv = NULL;
	cmd->tgt_i_priv = NULL;

	if (rc != SCST_CM_STATUS_CMD_SUCCEEDED) {
		PRINT_CRIT_ERROR("Unable to perform initial INQUIRY for device "
			"%s. Copy manager for this device will be disabled",
			dev->virt_name);
		goto out;
	}

	length = scst_get_buf_full(cmd, &buf);
	TRACE_DBG("length %d", length);
	if (unlikely(length <= 0)) {
		if (length < 0)
			PRINT_ERROR("scst_get_buf_full() failed: %d", length);
		goto out;
	}

	TRACE_BUFF_FLAG(TRACE_DEBUG, "buf", buf, length);

	if (buf[0] != 0) {
		TRACE(TRACE_MINOR, "Not supported dev type %x, ignoring", buf[0]);
		goto out_put;
	}

	if (buf[1] != 0x83) {
		PRINT_WARNING("Incorrect page code %x, ignoring", buf[1]);
		goto out_put;
	}

	page_len = get_unaligned_be16(&buf[2]);
	if (page_len+3 > cmd->resp_data_len) {
		PRINT_WARNING("Page len (%d) doesn't match resp len (%d), ignoring",
			page_len+3, cmd->resp_data_len);
		goto out_put;
	}

	off = 4;
	while (off < page_len) {
		int des_len, des_alloc_len;
		struct scst_cm_desig *des;

		if (off + 3 >= page_len) {
			PRINT_WARNING("Too small page len %d, (off %d), ignoring",
				page_len, off);
			goto out_put;
		}

		des_len = buf[off + 3];
		if ((off + des_len) > page_len) {
			PRINT_WARNING("Too small buf len %d (off %d, des_len %d), "
				"ignoring", page_len, off, des_len);
			goto out_put;
		}

		des_len += 4;

		if (((buf[off] & 0xF0) != 0) || ((buf[off+1] & 0xF0) != 0)) {
			TRACE_DBG("Unsupported designator (%x, %x), "
				"ignoring", buf[off] & 0xF0, buf[off+1] & 0xF0);
			goto next;
		}

		des_alloc_len = sizeof(*des) + des_len;
		des = kzalloc(des_alloc_len, GFP_KERNEL);
		if (des == NULL) {
			PRINT_CRIT_ERROR("Unable to allocate designator (len %d, "
				"type %x), ignoring it", des_alloc_len,
				buf[off+1] & 0xF);
			goto out_put;
		}

		des->desig_tgt_dev = cmd->tgt_dev;

		des->desig_len = des_len;
		memcpy(des->desig, &buf[off], des_len);

		TRACE_DBG("des %p, len %d", des, des->desig_len);
		TRACE_BUFF_FLAG(TRACE_DEBUG, "des", des->desig, des->desig_len);

		mutex_lock(&scst_cm_mutex);
		list_add_tail(&des->cm_desig_list_entry, &scst_cm_desig_list);
		mutex_unlock(&scst_cm_mutex);
next:
		off += des_len;
		TRACE_DBG("off %d", off);
	}

out_put:
	scst_put_buf_full(cmd, buf);

out:
	TRACE_EXIT();
	return;
}

static int scst_cm_send_init_inquiry(struct scst_device *dev,
	unsigned int unpacked_lun, struct scst_cm_init_inq_priv *priv)
{
	int res;
	static const uint8_t inq_cdb[6] = { INQUIRY, 1, 0x83, 0x10, 0, 0 };
	__be64 lun;
	struct scst_cmd *cmd;

	TRACE_ENTRY();

	if (priv == NULL) {
		priv = kzalloc(sizeof(*priv), GFP_KERNEL);
		if (priv == NULL) {
			PRINT_ERROR("Unable to alloc priv");
			res = -ENOMEM;
			goto out;
		}
		priv->cm_init_inq_finish_fn = scst_cm_init_inq_finish;
		priv->dev = dev;
	}

	lun = scst_pack_lun(unpacked_lun, scst_cm_sess->acg->addr_method);

	cmd = scst_rx_cmd(scst_cm_sess, (const uint8_t *)&lun,
			       sizeof(lun), inq_cdb, sizeof(inq_cdb), false);
	if (cmd == NULL) {
		res = -ENOMEM;
		goto out_free;
	}

	scst_cmd_set_expected(cmd, SCST_DATA_READ, 4096);
	scst_cmd_set_queue_type(cmd, SCST_CMD_QUEUE_HEAD_OF_QUEUE);
	scst_cmd_set_tgt_priv(cmd, priv);

	cmd->bypass_blocking = 1;

	scst_cmd_init_done(cmd, SCST_CONTEXT_THREAD);

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	kfree(priv);
	goto out;
}

static bool scst_cm_is_lun_free(unsigned int lun)
{
	bool res = true;
	struct list_head *head = &scst_cm_sess->sess_tgt_dev_list[SESS_TGT_DEV_LIST_HASH_FN(lun)];
	struct scst_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	scst_assert_activity_suspended();
	lockdep_assert_held(&scst_mutex);

	list_for_each_entry(tgt_dev, head, sess_tgt_dev_list_entry) {
		if (tgt_dev->lun == lun) {
			res = false;
			break;
		}
	}

	TRACE_EXIT_RES(res);
	return res;
}

static unsigned int scst_cm_get_lun(const struct scst_device *dev)
{
	unsigned int res = SCST_MAX_LUN;
	int i;

	TRACE_ENTRY();

	scst_assert_activity_suspended();
	lockdep_assert_held(&scst_mutex);

	for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
		struct list_head *head = &scst_cm_sess->sess_tgt_dev_list[i];
		struct scst_tgt_dev *tgt_dev;

		list_for_each_entry(tgt_dev, head, sess_tgt_dev_list_entry) {
			if (tgt_dev->dev == dev) {
				res = tgt_dev->lun;
				TRACE_DBG("LUN %d found (full LUN %lld)",
					res, tgt_dev->lun);
				goto out;
			}
		}
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_cm_dev_register(struct scst_device *dev, uint64_t lun)
{
	int res, i;
	struct scst_acg_dev *acg_dev;
	bool add_lun;

	TRACE_ENTRY();

	scst_assert_activity_suspended();
	lockdep_assert_held(&scst_mutex);

	TRACE_DBG("dev %s, LUN %ld", dev->virt_name, (unsigned long)lun);

	for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
		struct scst_tgt_dev *tgt_dev;
		struct list_head *head = &scst_cm_sess->sess_tgt_dev_list[i];

		list_for_each_entry(tgt_dev, head, sess_tgt_dev_list_entry) {
			if (tgt_dev->dev == dev) {
				/*
				 * It's OK, because the copy manager could
				 * auto register some devices
				 */
				TRACE_DBG("Copy Manager already registered "
					"device %s", dev->virt_name);
				res = 0;
				goto out;
			}
		}
	}

	if (lun == SCST_MAX_LUN) {
		add_lun = true;
		while (1) {
			lun = scst_cm_next_lun++;
			if (lun == SCST_MAX_LUN)
				continue;
			if (scst_cm_is_lun_free(lun))
				break;
		}
	} else
		add_lun = false;

	if (add_lun) {
		res = scst_acg_add_lun(scst_cm_tgt->default_acg,
			scst_cm_tgt->tgt_luns_kobj, dev, lun, SCST_ADD_LUN_CM,
			&acg_dev);
		if (res != 0)
			goto out_err;
	}

	spin_lock_bh(&dev->dev_lock);
	scst_block_dev(dev);
	spin_unlock_bh(&dev->dev_lock);

	res = scst_cm_send_init_inquiry(dev, lun, NULL);
	if (res != 0)
		goto out_unblock;

out:
	TRACE_EXIT_RES(res);
	return res;

out_unblock:
	spin_lock_bh(&dev->dev_lock);
	scst_unblock_dev(dev);
	spin_unlock_bh(&dev->dev_lock);

	scst_acg_del_lun(scst_cm_tgt->default_acg, lun, false);

out_err:
	scst_cm_next_lun--;
	goto out;
}

static void scst_cm_dev_unregister(struct scst_device *dev, bool del_lun)
{
	int i;
	struct scst_cm_desig *des, *t;

	TRACE_ENTRY();

	scst_assert_activity_suspended();
	lockdep_assert_held(&scst_mutex);

	TRACE_DBG("dev %s, del_lun %d", dev->virt_name, del_lun);

	list_for_each_entry_safe(des, t, &scst_cm_desig_list, cm_desig_list_entry) {
		if (des->desig_tgt_dev->dev == dev) {
			TRACE_DBG("Deleting des %p", des);
			list_del(&des->cm_desig_list_entry);
			kfree(des);
		}
	}

	if (!del_lun)
		goto out;

	for (i = 0; i < SESS_TGT_DEV_LIST_HASH_SIZE; i++) {
		struct scst_tgt_dev *tgt_dev;
		struct list_head *head = &scst_cm_sess->sess_tgt_dev_list[i];

		list_for_each_entry(tgt_dev, head, sess_tgt_dev_list_entry) {
			if (tgt_dev->dev == dev) {
				scst_acg_del_lun(scst_cm_tgt->default_acg,
					tgt_dev->lun, false);
				break;
			}
		}
	}

out:
	TRACE_EXIT();
	return;
}

void scst_cm_update_dev(struct scst_device *dev)
{
	int rc;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("copy manager: updating device %s", dev->virt_name);

	scst_suspend_activity(SCST_SUSPEND_TIMEOUT_UNLIMITED);
	mutex_lock(&scst_mutex);

	scst_cm_dev_unregister(dev, false);

	spin_lock_bh(&dev->dev_lock);
	scst_block_dev(dev);
	spin_unlock_bh(&dev->dev_lock);

	rc = scst_cm_send_init_inquiry(dev, scst_cm_get_lun(dev), NULL);
	if (rc != 0)
		goto out_unblock;

out_resume:
	mutex_unlock(&scst_mutex);
	scst_resume_activity();

	TRACE_EXIT();
	return;

out_unblock:
	spin_lock_bh(&dev->dev_lock);
	scst_unblock_dev(dev);
	spin_unlock_bh(&dev->dev_lock);
	goto out_resume;
}

int scst_cm_on_dev_register(struct scst_device *dev)
{
	int res = 0;

	TRACE_ENTRY();

	scst_assert_activity_suspended();
	lockdep_assert_held(&scst_mutex);

	if (!scst_auto_cm_assignment || !dev->handler->auto_cm_assignment_possible)
		goto out;

	res = scst_cm_dev_register(dev, SCST_MAX_LUN);

out:
	TRACE_EXIT_RES(res);
	return res;
}

void scst_cm_on_dev_unregister(struct scst_device *dev)
{
	TRACE_ENTRY();

	scst_assert_activity_suspended();
	lockdep_assert_held(&scst_mutex);

	scst_cm_dev_unregister(dev, true);

	TRACE_EXIT();
	return;
}

int scst_cm_on_add_acg(struct scst_acg *acg)
{
	int res = 0;

	TRACE_ENTRY();

	lockdep_assert_held(&scst_mutex);

	if (scst_cm_tgt == NULL)
		goto out;

	if (acg->tgt != scst_cm_tgt)
		goto out;

	if (acg != scst_cm_tgt->default_acg) {
		PRINT_ERROR("Copy Manager does not support security groups");
		res = -EINVAL;
		goto out;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

void scst_cm_on_del_acg(struct scst_acg *acg)
{
	scst_assert_activity_suspended();
	lockdep_assert_held(&scst_mutex);
	/* Nothing to do */
}

int scst_cm_on_add_lun(struct scst_acg_dev *acg_dev, uint64_t lun,
	unsigned int *flags)
{
	int res = 0;

	TRACE_ENTRY();

	lockdep_assert_held(&scst_mutex);

	if (acg_dev->acg != scst_cm_tgt->default_acg)
		goto out;

	if (acg_dev->acg_dev_rd_only || acg_dev->dev->dev_rd_only) {
		PRINT_ERROR("Copy Manager does not support read only devices");
		res = -EINVAL;
		goto out;
	}

	*flags &= ~SCST_ADD_LUN_GEN_UA;

	res = scst_cm_dev_register(acg_dev->dev, lun);

out:
	TRACE_EXIT_RES(res);
	return res;
}

bool scst_cm_on_del_lun(struct scst_acg_dev *acg_dev, bool gen_report_luns_changed)
{
	bool res = gen_report_luns_changed;

	TRACE_ENTRY();

	scst_assert_activity_suspended();
	lockdep_assert_held(&scst_mutex);

	if (acg_dev->acg != scst_cm_tgt->default_acg)
		goto out;

	scst_cm_dev_unregister(acg_dev->dev, false);

	res = false;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static bool scst_cm_check_access_acg(const char *initiator_name,
	const struct scst_device *dev, const struct scst_acg *acg,
	bool default_acg)
{
	bool res = true;
	struct scst_acg_dev *acg_dev;

	TRACE_ENTRY();

	lockdep_assert_held(&scst_mutex2);

	list_for_each_entry(acg_dev, &acg->acg_dev_list, acg_dev_list_entry) {
		if (acg_dev->dev == dev) {
			struct scst_acn *acn;

			if (default_acg)
				goto found;
			list_for_each_entry(acn, &acg->acn_list, acn_list_entry) {
				if (strcmp(acn->name, initiator_name) == 0)
					goto found;
			}
		}
	}

	res = false;

found:
	TRACE_EXIT_RES(res);
	return res;
}

static bool scst_cm_check_access(const char *initiator_name,
	const struct scst_device *dev, bool *read_only)
{
	bool res = true;
	struct scst_tgt_template *tgtt;

	TRACE_ENTRY();

	if (scst_cm_allow_not_connected_copy)
		goto out_rd_only;

	/* ToDo: make it hash based */

	/*
	 * We can't use scst_mutex on commands processing path, because
	 * otherwise we can fall in a deadlock with kthread_stop() in
	 * scst_del_threads() waiting for this command to finish.
	 */
	mutex_lock(&scst_mutex2);

	list_for_each_entry(tgtt, &scst_template_list, scst_template_list_entry) {
		struct scst_tgt *tgt;

		list_for_each_entry(tgt, &tgtt->tgt_list, tgt_list_entry) {
			struct scst_acg *acg;

			if (tgt == scst_cm_tgt)
				continue;

			TRACE_DBG("Checking tgt %s", tgt->tgt_name);

			if (scst_cm_check_access_acg(initiator_name, dev, tgt->default_acg, true))
				goto out_unlock_rd_only;

			list_for_each_entry(acg, &tgt->tgt_acg_list, acg_list_entry) {
				if (scst_cm_check_access_acg(initiator_name, dev, acg, false))
					goto out_unlock_rd_only;
			}
		}
	}

	res = false;
	PRINT_WARNING("Initiator %s not allowed to use device %s in EXTENDED "
		"COPY command", initiator_name, dev->virt_name);

out_unlock_rd_only:
	mutex_unlock(&scst_mutex2);

out_rd_only:
	*read_only = dev->dev_rd_only || dev->swp;

	TRACE_EXIT_RES(res);
	return res;
}

struct scst_cm_tgt_descr {
	struct scst_tgt_dev *tgt_dev;
	unsigned int read_only:1;
	int param_offs;
};

static int scst_cm_parse_id_tgt_descr(struct scst_cmd *cmd, const uint8_t *seg,
	int offs, struct scst_cm_tgt_descr *tgt_descr)
{
	int res = 32;
	struct scst_cm_desig *des;
	int block;
	bool read_only = false;

	TRACE_ENTRY();

	TRACE_BUFF_FLAG(TRACE_DEBUG, "seg", seg, 32);

	EXTRACHECKS_BUG_ON(seg[0] != 0xE4);

	if ((seg[1] & 0xC0) != 0) {
		PRINT_WARNING("LU ID %x not supported", seg[1] & 0xC0);
		scst_set_invalid_field_in_parm_list(cmd, offs+1,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 6);
		goto out_err;
	}

	if ((seg[1] & 0x20) != 0) {
		TRACE_DBG("NULL tgt descriptor");
		tgt_descr->tgt_dev = NULL;
		goto out;
	}

	if ((seg[1] & 0xF) != 0) {
		PRINT_WARNING("PERIPHERAL DEVICE TYPE %d not supported",
			seg[1] & 0xF);
		scst_set_invalid_field_in_parm_list(cmd, offs+1,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 0);
		goto out_err;
	}

	block = get_unaligned_be24(&seg[29]);

	mutex_lock(&scst_cm_mutex);

	/* ToDo: make it hash based */

	list_for_each_entry(des, &scst_cm_desig_list, cm_desig_list_entry) {
		TRACE_DBG("des %p (tgt_dev %p, lun %lld)", des, des->desig_tgt_dev,
			(unsigned long long)des->desig_tgt_dev->lun);
		if (seg[4] != des->desig[0])
			continue;
		if (seg[5] != des->desig[1])
			continue;
		if (seg[7] > des->desig[3])
			continue;
		if (memcmp(&des->desig[4], &seg[8], min_t(int, seg[7], des->desig[3])) == 0) {
			TRACE_DBG("Tgt_dev %p (lun %lld) found",
				des->desig_tgt_dev,
				(unsigned long long)des->desig_tgt_dev->lun);

			mutex_unlock(&scst_cm_mutex);

			if (block != des->desig_tgt_dev->dev->block_size) {
				PRINT_WARNING("Block size %d doesn't match %d", block,
					des->desig_tgt_dev->dev->block_size);
				scst_set_invalid_field_in_parm_list(cmd, offs+29, 0);
				goto out_err;
			}

			if (!scst_cm_check_access(cmd->sess->initiator_name,
					des->desig_tgt_dev->dev, &read_only))
				goto out_not_found;

			tgt_descr->tgt_dev = des->desig_tgt_dev;
			tgt_descr->read_only = read_only;
			TRACE_DBG("Found des %p (tgt_dev %p, read_only %d)",
				des, tgt_descr->tgt_dev, tgt_descr->read_only);
			goto out;
		}
	}

	mutex_unlock(&scst_cm_mutex);

	TRACE(TRACE_MINOR|TRACE_SCSI, "Target descriptor designator not found "
		"(initiator %s, offs %d)", cmd->sess->initiator_name, offs);
	TRACE_BUFF_FLAG(TRACE_MINOR|TRACE_SCSI, "Designator", seg, 32);

out_not_found:
	scst_set_invalid_field_in_parm_list(cmd, offs, 0);

out_err:
	res = -1;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_cm_set_seg_err_sense(struct scst_cmd *cmd, int asc, int ascq,
	int seg_num, int offs)
{
	int res, d_sense = scst_get_cmd_dev_d_sense(cmd);

	TRACE_ENTRY();

	TRACE_DBG("cmd %p, seg %d, offs %d (d_sense %d)", cmd, seg_num, offs,
		d_sense);

	res = scst_set_cmd_error_status(cmd, SAM_STAT_CHECK_CONDITION);
	if (res != 0)
		goto out;

	res = scst_alloc_sense(cmd, 1);
	if (res != 0) {
		PRINT_ERROR("Lost COPY ABORTED sense data");
		goto out;
	}

	sBUG_ON(cmd->sense_buflen < 18);
	BUILD_BUG_ON(SCST_SENSE_BUFFERSIZE < 18);

	if (d_sense) {
		/* Descriptor format */
		cmd->sense[0] = 0x72;
		cmd->sense[1] = COPY_ABORTED;
		cmd->sense[2] = asc;
		cmd->sense[3] = ascq;
		cmd->sense[7] = 20; /* additional Sense Length */

		cmd->sense[8] = 1; /* Command specific descriptor */
		cmd->sense[9] = 0x0A;
		put_unaligned_be16(seg_num, &cmd->sense[14]);

		cmd->sense[20] = 2; /* Sense key specific descriptor */
		cmd->sense[21] = 6;
		cmd->sense[24] = 0xA0;
		put_unaligned_be16(offs, &cmd->sense[25]);

		cmd->sense_valid_len = 28;
	} else {
		/* Fixed format */
		cmd->sense[0] = 0x70;
		cmd->sense[2] = COPY_ABORTED;
		cmd->sense[7] = 0x0a; /* additional Sense Length */
		cmd->sense[12] = asc;
		cmd->sense[13] = ascq;

		put_unaligned_be16(seg_num, &cmd->sense[10]);

		cmd->sense[15] = 0xA0;
		put_unaligned_be16(offs, &cmd->sense[16]);

		cmd->sense_valid_len = 18;
	}

	TRACE_BUFFER("Sense set", cmd->sense, cmd->sense_valid_len);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void scst_cm_fantom_cmd_finished(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	TRACE_DBG("Fantom cmd %p", cmd);

	EXTRACHECKS_BUG_ON(!cmd->internal);

	/* Nothing to do */

	TRACE_EXIT();
	return;
}

static int scst_cm_add_to_descr_list(struct scst_cmd *ec_cmd,
	struct scst_tgt_dev *tgt_dev)
{
	int res;
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;
	struct scst_cm_dev_entry *e, *t;
	struct scst_cmd *fcmd;
	bool added;

	TRACE_ENTRY();

	/* Check if we already have this device in the list */
	list_for_each_entry(e, &priv->cm_sorted_devs_list, cm_sorted_devs_list_entry) {
		if (e->cm_fcmd->dev == tgt_dev->dev) {
			TRACE_DBG("Dev %p is already in cm_sorted_devs_list",
				tgt_dev->dev);
			goto out_success;
		}
	}

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (e == NULL) {
		PRINT_ERROR("Unable to allocate scst_cm_dev_entry (size %d)",
			(int)sizeof(*e));
		goto out_enomem;
	}

	if (ec_cmd->dev == tgt_dev->dev) {
		fcmd = ec_cmd;
		goto skip_fcmd_create;
	}

	fcmd = __scst_create_prepare_internal_cmd(ec_cmd->cdb,
		ec_cmd->cdb_len, SCST_CMD_QUEUE_SIMPLE, tgt_dev,
		GFP_KERNEL, true);
	if (fcmd == NULL)
		goto out_enomem_free_e;

	fcmd->expected_data_direction = ec_cmd->expected_data_direction;
	fcmd->expected_transfer_len_full = ec_cmd->expected_transfer_len_full;
	fcmd->expected_values_set = 1;

	fcmd->cmd_data_descriptors = ec_cmd->cmd_data_descriptors;
	fcmd->cmd_data_descriptors_cnt = ec_cmd->cmd_data_descriptors_cnt;

	fcmd->state = SCST_CMD_STATE_EXEC_CHECK_BLOCKING;

	res = scst_cm_add_to_internal_cmd_list(fcmd, ec_cmd, ec_cmd,
			scst_cm_fantom_cmd_finished);
	if (res != 0)
		goto out_free_cmd;

skip_fcmd_create:
	TRACE_DBG("ec_cmd %p, e %p, fcmd %p, tgt_dev %p (dev %p)", ec_cmd, e, fcmd,
		tgt_dev, tgt_dev->dev);

	e->cm_fcmd = fcmd;

	added = false;
	list_for_each_entry_reverse(t, &priv->cm_sorted_devs_list, cm_sorted_devs_list_entry) {
		EXTRACHECKS_BUG_ON(t->cm_fcmd->dev == tgt_dev->dev);
		if (((unsigned long)e->cm_fcmd->dev) > ((unsigned long)t->cm_fcmd->dev)) {
			__list_add(&e->cm_sorted_devs_list_entry,
				&t->cm_sorted_devs_list_entry,
				t->cm_sorted_devs_list_entry.next);
			added = true;
			break;
		}
	}
	if (!added)
		list_add(&e->cm_sorted_devs_list_entry,
			&priv->cm_sorted_devs_list);

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_EXTRACHECKS)
	{
		struct scst_cm_dev_entry *tp = NULL;

		list_for_each_entry(t, &priv->cm_sorted_devs_list, cm_sorted_devs_list_entry) {
			TRACE_DBG("t %p, cm dev %p", t, t->cm_fcmd->dev);
			if (tp != NULL) {
				if (((unsigned long)t->cm_fcmd->dev) <= ((unsigned long)tp->cm_fcmd->dev)) {
					list_for_each_entry(t, &priv->cm_sorted_devs_list, cm_sorted_devs_list_entry) {
						pr_emerg("%s: t %p, cm dev %p\n",
							 __func__, t,
							 t->cm_fcmd->dev);
					}
					sBUG();
					break;
				}
				tp = t;
			}
			tp = t;
		}
	}
#endif

out_success:
	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free_cmd:
	__scst_cmd_put(fcmd);

out_enomem_free_e:
	kfree(e);

out_enomem:
	scst_set_busy(ec_cmd);
	res = -ENOMEM;
	goto out;
}

static int scst_cm_parse_b2b_seg_descr(struct scst_cmd *ec_cmd,
	const uint8_t *seg, const struct scst_cm_tgt_descr *tgt_descrs,
	int tgt_descrs_cnt, int seg_num)
{
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;
	struct scst_ext_copy_seg_descr *d = &priv->cm_seg_descrs[seg_num];
	int res = 28, rc, len, src_des_idx, tgt_des_idx, blocks, dc;
	const struct scst_cm_tgt_descr *src_des, *tgt_des;

	TRACE_ENTRY();

	TRACE_BUFF_FLAG(TRACE_DEBUG, "seg", seg, 28);

	EXTRACHECKS_BUG_ON(seg[0] != 2);

	len = get_unaligned_be16(&seg[2]);
	if (len != 0x18) {
		PRINT_WARNING("Incorrect B2B segment descriptor len %d", len);
		scst_cm_set_seg_err_sense(ec_cmd, 0, 0, seg_num, 2);
		goto out_err;
	}

	src_des_idx = get_unaligned_be16(&seg[4]);
	if (src_des_idx >= tgt_descrs_cnt) {
		PRINT_WARNING("Invalid src descriptor index %d", src_des_idx);
		scst_cm_set_seg_err_sense(ec_cmd, 0, 0, seg_num, 4);
		goto out_err;
	}

	src_des = &tgt_descrs[src_des_idx];
	if (src_des->tgt_dev == NULL) {
		PRINT_WARNING("Segment with NULL src tgt device");
		/* COPY TARGET DEVICE NOT REACHABLE */
		scst_cm_set_seg_err_sense(ec_cmd, 0xD, 2, seg_num, 4);
		goto out_err;
	}

	tgt_des_idx = get_unaligned_be16(&seg[6]);
	if (tgt_des_idx >= tgt_descrs_cnt) {
		PRINT_WARNING("Invalid tgt descriptor index %d", tgt_des_idx);
		scst_cm_set_seg_err_sense(ec_cmd, 0, 0, seg_num, 6);
		goto out_err;
	}

	tgt_des = &tgt_descrs[tgt_des_idx];
	if (tgt_des->tgt_dev == NULL) {
		PRINT_WARNING("Segment with NULL tgt device");
		/* COPY TARGET DEVICE NOT REACHABLE */
		scst_cm_set_seg_err_sense(ec_cmd, 0xD, 2, seg_num, 6);
		goto out_err;
	}
	if (tgt_des->read_only) {
		PRINT_WARNING("Target descriptor refers to read-only device");
		scst_cm_set_seg_err_sense(ec_cmd, 0, 0, seg_num, 6);
		goto out_err;
	}

	dc = (seg[1] >> 1) & 1;
	blocks = get_unaligned_be16(&seg[10]);
	if (dc)
		len = blocks << tgt_des->tgt_dev->dev->block_shift;
	else
		len = blocks << src_des->tgt_dev->dev->block_shift;

	if (unlikely((len & (src_des->tgt_dev->dev->block_size-1)) != 0) ||
	    unlikely((len & (tgt_des->tgt_dev->dev->block_size-1)) != 0)) {
		PRINT_WARNING("Data len %d is not even for block size (src block "
			"size %d, dst block size %d)", len,
			src_des->tgt_dev->dev->block_size,
			tgt_des->tgt_dev->dev->block_size);
		scst_cm_set_seg_err_sense(ec_cmd, 0, 0, seg_num, 10);
		goto out_err;
	}

	d->type = SCST_EXT_COPY_SEG_DATA;
	d->data_descr.data_len = len;
	d->src_tgt_dev = src_des->tgt_dev;
	d->data_descr.src_lba = get_unaligned_be64(&seg[12]);
	d->dst_tgt_dev = tgt_des->tgt_dev;
	d->data_descr.dst_lba = get_unaligned_be64(&seg[20]);
	d->tgt_descr_offs = tgt_des->param_offs;

	TRACE(TRACE_DEBUG|TRACE_SCSI, "ec_cmd %p, src dev %s, dst dev %s, "
		"len %d, src_lba %lld, dst_lba %lld", ec_cmd,
		d->src_tgt_dev->dev->virt_name, d->dst_tgt_dev->dev->virt_name,
		len, (long long)d->data_descr.src_lba,
		(long long)d->data_descr.dst_lba);

	TRACE_DBG("src tgt_dev %p, dst tgt_dev %p, tgt_descr_offs %d",
		d->src_tgt_dev, d->dst_tgt_dev, d->tgt_descr_offs);

	rc = scst_cm_add_to_descr_list(ec_cmd, src_des->tgt_dev);
	if (rc != 0) {
		res = rc;
		goto out;
	}

	rc = scst_cm_add_to_descr_list(ec_cmd, tgt_des->tgt_dev);
	if (rc != 0) {
		res = rc;
		goto out;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_err:
	res = -1;
	goto out;
}

static void scst_cm_free_ec_priv(struct scst_cmd *ec_cmd, bool unblock_dev)
{
	struct scst_cm_ec_cmd_priv *p = ec_cmd->cmd_data_descriptors;
	struct scst_cm_dev_entry *e, *t;
	struct scst_cm_internal_cmd_priv *ip, *it;
	unsigned long flags;

	TRACE_ENTRY();

	list_for_each_entry_safe(e, t, &p->cm_sorted_devs_list,
				cm_sorted_devs_list_entry) {
		TRACE_DBG("Deleting e %p", e);
		list_del(&e->cm_sorted_devs_list_entry);
		kfree(e);
	}

	list_for_each_entry_safe(ip, it, &p->cm_internal_cmd_list,
				cm_internal_cmd_list_entry) {
		struct scst_cmd *c = ip->cm_cmd;

		scst_cm_del_free_from_internal_cmd_list(c, unblock_dev);
		__scst_cmd_put(c);
	}

	/* Lock to sync with scst_cm_abort_ec_cmd() */
	spin_lock_irqsave(&scst_cm_lock, flags);
	ec_cmd->cmd_data_descriptors = NULL;
	ec_cmd->cmd_data_descriptors_cnt = 0;
	spin_unlock_irqrestore(&scst_cm_lock, flags);

	kfree(p);

	TRACE_EXIT();
	return;
}

int scst_cm_parse_descriptors(struct scst_cmd *ec_cmd)
{
	int res = 0, rc;
	struct scst_cm_list_id *plist_id = NULL;
	ssize_t length = 0;
	uint8_t *buf;
	int list_id, list_id_usage, len, tgt_len, seg_len;
	struct scst_cm_ec_cmd_priv *p;
	int tgt_cnt, seg_cnt, i, offs, t;
	struct scst_cm_tgt_descr *tgt_descrs;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(ec_cmd->cmd_data_descriptors != NULL);

	length = scst_get_buf_full_sense(ec_cmd, &buf);
	if (unlikely(length <= 0)) {
		if (length == 0)
			goto out_put;
		else
			goto out_abn;
	}

	if (length < 16) {
		PRINT_WARNING("Too small EXTENDED COPY data len %d", (int)length);
		scst_set_invalid_field_in_cdb(ec_cmd, 10, 0);
		goto out_abn_put;
	}

	list_id = buf[0];
	list_id_usage = (buf[1] & 0x18) >> 3;

	TRACE_BUFF_FLAG(TRACE_DEBUG, "buf", buf, length);

	TRACE_DBG("list_id %d, list_id_usage %d", list_id, list_id_usage);

	switch (list_id_usage) {
	case 0:
	case 2:
		plist_id = scst_cm_add_list_id(ec_cmd, list_id);
		if (plist_id == NULL)
			goto out_abn_put;
		break;
	case 3:
		if (list_id != 0) {
			PRINT_WARNING("Invalid list ID %d with list ID usage %d",
				list_id, list_id_usage);
			scst_set_invalid_field_in_parm_list(ec_cmd, 0, 0);
			goto out_abn_put;
		}
		break;
	default:
		PRINT_WARNING("Invalid list ID usage %d, rejecting", list_id_usage);
		scst_set_invalid_field_in_parm_list(ec_cmd, 1,
			SCST_INVAL_FIELD_BIT_OFFS_VALID | 3);
		goto out_abn_put;
	}

	len = get_unaligned_be32(&buf[12]);
	if (len != 0) {
		PRINT_WARNING("Inline data not supported (len %d)", len);
		scst_set_cmd_error(ec_cmd, SCST_LOAD_SENSE(scst_sense_inline_data_length_exceeded));
		goto out_del_abn_put;
	}

	tgt_len = get_unaligned_be16(&buf[2]);
	seg_len = get_unaligned_be32(&buf[8]);

	if (tgt_len == 0) {
		if (seg_len == 0)
			goto out_del_put;
		else {
			PRINT_WARNING("Zero target descriptors with non-zero "
				"segments len (%d)", seg_len);
			scst_set_invalid_field_in_parm_list(ec_cmd, 2, 0);
			goto out_del_abn_put;
		}
	}

	if ((tgt_len + seg_len + 16) > length) {
		PRINT_WARNING("Parameters truncation");
		scst_set_cmd_error(ec_cmd,
			SCST_LOAD_SENSE(scst_sense_parameter_list_length_invalid));
		goto out_del_abn_put;
	}

	if ((tgt_len + seg_len + 16) != length) {
		PRINT_WARNING("Unexpected inline data");
		scst_set_cmd_error(ec_cmd,
			SCST_LOAD_SENSE(scst_sense_inline_data_length_exceeded));
		goto out_del_abn_put;
	}

	if ((tgt_len % 32) != 0) {
		PRINT_WARNING("Invalid tgt len %d", tgt_len);
		scst_set_invalid_field_in_parm_list(ec_cmd, 2, 0);
		goto out_del_abn_put;
	}

	tgt_cnt = tgt_len/32;
	if (tgt_cnt > SCST_CM_MAX_TGT_DESCR_CNT) {
		PRINT_WARNING("Too many target descriptors %d", tgt_cnt);
		scst_set_cmd_error(ec_cmd,
			SCST_LOAD_SENSE(scst_sense_too_many_target_descriptors));
		goto out_del_abn_put;
	}

	TRACE_DBG("tgt_cnt %d", tgt_cnt);

	tgt_descrs = kcalloc(tgt_cnt, sizeof(*tgt_descrs), GFP_KERNEL);
	if (tgt_descrs == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "Unable to allocate tgt_descrs "
			"(count %d, size %zd)", tgt_cnt,
			sizeof(*tgt_descrs) * tgt_cnt);
		scst_set_busy(ec_cmd);
		goto out_del_abn_put;
	}

	offs = 16;
	for (i = 0; i < tgt_cnt; i++) {
		TRACE_DBG("offs %d", offs);
		switch (buf[offs]) {
		case 0xE4: /* identification descriptor target descriptor format */
			rc = scst_cm_parse_id_tgt_descr(ec_cmd, &buf[offs], offs,
				&tgt_descrs[i]);
			if (rc <= 0)
				goto out_free_tgt_descr;
			break;
		default:
			PRINT_WARNING("Not supported target descriptor %x", buf[offs]);
			scst_set_cmd_error(ec_cmd, SCST_LOAD_SENSE(scst_sense_unsupported_tgt_descr_type));
			goto out_free_tgt_descr;
		}
		tgt_descrs[i].param_offs = offs;
		offs += rc;
	}

	WARN_ON(offs != tgt_len + 16);

	t = offs;
	seg_cnt = 0;
	while (offs < length) {
		if (seg_cnt == SCST_CM_MAX_SEG_DESCR_CNT) {
			PRINT_WARNING("Too many segment descriptors");
			scst_set_cmd_error(ec_cmd,
				SCST_LOAD_SENSE(
				    scst_sense_too_many_segment_descriptors));
			goto out_free_tgt_descr;
		}
		switch (buf[offs]) {
		case 2: /* block device to block device segment descriptor */
			offs += 28;
			break;
		default:
			PRINT_WARNING("Not supported segment descriptor %x", buf[offs]);
			scst_set_cmd_error(ec_cmd,
				SCST_LOAD_SENSE(scst_sense_unsupported_seg_descr_type));
			goto out_free_tgt_descr;
		}
		seg_cnt++;
	}
	offs = t;

	TRACE_DBG("seg_cnt %d", seg_cnt);

	p = kzalloc(sizeof(*p) + seg_cnt * sizeof(struct scst_ext_copy_seg_descr), GFP_KERNEL);
	if (p == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "Unable to allocate Extended Copy "
			"descriptors (seg_cnt %d)", seg_cnt);
		scst_set_busy(ec_cmd);
		goto out_free_tgt_descr;
	}

	p->cm_list_id = plist_id;
	plist_id = NULL;
	INIT_LIST_HEAD(&p->cm_sorted_devs_list);
	INIT_LIST_HEAD(&p->cm_internal_cmd_list);
	p->cm_error = SCST_CM_ERROR_NONE;
	mutex_init(&p->cm_mutex);

	ec_cmd->cmd_data_descriptors = p;
	ec_cmd->cmd_data_descriptors_cnt = seg_cnt;

	res = scst_cm_add_to_descr_list(ec_cmd, ec_cmd->tgt_dev);
	if (res != 0)
		goto out_free_p;

	for (i = 0; i < seg_cnt; i++) {
		TRACE_DBG("offs %d", offs);
		switch (buf[offs]) {
		case 2: /* block device to block device segment descriptor */
			rc = scst_cm_parse_b2b_seg_descr(ec_cmd, &buf[offs],
				tgt_descrs, tgt_cnt, i);
			if (rc <= 0) {
				if (rc == -ENOMEM)
					goto out_free_p;
				else {
					/*
					 * We may need to keep list_id for a
					 * while for further FAILED SEGMENT
					 * DETAILS of RECEIVE COPY RESULTS
					 */
					scst_cm_store_list_id_details(ec_cmd);
					goto out_free_tgt_descr;
				}
			}
			EXTRACHECKS_BUG_ON(rc != 28);
			break;
		default:
			sBUG();
		}
		offs += rc;
	}

	kfree(tgt_descrs);

out_del_put:
	if (plist_id != NULL)
		scst_cm_del_free_list_id(plist_id, false);

out_put:
	scst_put_buf_full(ec_cmd, buf);

out:
	TRACE_EXIT_RES(res);
	return res;

out_free_p:
	scst_cm_free_ec_priv(ec_cmd, false);

out_free_tgt_descr:
	kfree(tgt_descrs);

out_del_abn_put:
	if (plist_id != NULL)
		scst_cm_del_free_list_id(plist_id, false);

out_abn_put:
	scst_put_buf_full(ec_cmd, buf);

out_abn:
	scst_set_cmd_abnormal_done_state(ec_cmd);
	res = -1;
	goto out;
}

void scst_cm_free_descriptors(struct scst_cmd *ec_cmd)
{
	struct scst_cm_ec_cmd_priv *priv = ec_cmd->cmd_data_descriptors;

	TRACE_ENTRY();

	TRACE_DBG("cmd %p (internal %d)", ec_cmd, ec_cmd->internal);

	if (priv == NULL) {
		/* It can be for early errors */
		goto out;
	}

	if (ec_cmd->internal)
		goto out;

	if (priv->cm_list_id != NULL)
		scst_cm_sched_del_list_id(ec_cmd);

	scst_cm_free_ec_priv(ec_cmd, true);

out:
	TRACE_EXIT();
	return;
}

#ifndef CONFIG_SCST_PROC

static ssize_t scst_cm_allow_not_conn_copy_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	ssize_t res;

	TRACE_ENTRY();

	res = sprintf(buf, "%d\n%s", scst_cm_allow_not_connected_copy,
		(scst_cm_allow_not_connected_copy == SCST_ALLOW_NOT_CONN_COPY_DEF) ?
			"" : SCST_SYSFS_KEY_MARK "\n");

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t scst_cm_allow_not_conn_copy_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buffer, size_t size)
{
	ssize_t res;
	unsigned long val;

	TRACE_ENTRY();

	res = kstrtoul(buffer, 0, &val);
	if (res != 0) {
		PRINT_ERROR("strtoul() for %s failed: %zd", buffer, res);
		goto out;
	}

	scst_cm_allow_not_connected_copy = val;

	res = size;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute scst_cm_allow_not_conn_copy_attr =
	__ATTR(allow_not_connected_copy, S_IRUGO|S_IWUSR,
		scst_cm_allow_not_conn_copy_show,
		scst_cm_allow_not_conn_copy_store);

static const struct attribute *scst_cm_tgtt_attrs[] = {
	&scst_cm_allow_not_conn_copy_attr.attr,
	NULL,
};

#endif /* #ifndef CONFIG_SCST_PROC */

static int scst_cm_get_initiator_port_transport_id(struct scst_tgt *tgt,
	struct scst_session *scst_sess, uint8_t **transport_id)
{
	int res = 0;
	uint8_t *tid = NULL;

	TRACE_ENTRY();

	BUILD_BUG_ON((sizeof(SCST_CM_TID_ID)+3) > SCST_CM_TID_SIZE);
	BUILD_BUG_ON(TID_COMMON_SIZE != SCST_CM_TID_SIZE);

	if (scst_sess == NULL) {
		res = SCST_TRANSPORTID_PROTOCOLID_COPY_MGR;
		goto out;
	}

	tid = kzalloc(SCST_CM_TID_SIZE, GFP_KERNEL);
	if (tid == NULL) {
		PRINT_ERROR("Allocation of TransportID (size %d) failed",
			SCST_CM_TID_SIZE);
		res = -ENOMEM;
		goto out;
	}

	tid[0] = SCST_TRANSPORTID_PROTOCOLID_COPY_MGR;
	memcpy(&tid[2], SCST_CM_TID_ID, sizeof(SCST_CM_TID_ID));

	*transport_id = tid;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_cm_release(struct scst_tgt *tgt)
{
	TRACE_ENTRY();
	TRACE_EXIT();
	return 0;
}

static int scst_cm_xmit_response(struct scst_cmd *cmd)
{
	int res = SCST_TGT_RES_SUCCESS;
	scst_i_finish_fn_t f = (void *) *((unsigned long long **)cmd->tgt_i_priv);

	TRACE_ENTRY();

	/*
	 * Used for CM-only generated commands, i.e. commands generated without
	 * any external command, like INQUIRY.
	 */

	f(cmd);
	scst_tgt_cmd_done(cmd, SCST_CONTEXT_SAME);

	TRACE_EXIT_RES(res);
	return res;
}

static void scst_cm_task_mgmt_fn_done(struct scst_mgmt_cmd *scst_mcmd)
{
	/* Nothing to do */
	return;
}

static int scst_cm_report_aen(struct scst_aen *aen)
{
	/* Nothing to do */
	scst_aen_done(aen);
	return SCST_AEN_RES_SUCCESS;
}

static struct scst_tgt_template scst_cm_tgtt = {
	.name			= SCST_CM_NAME,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	.sg_tablesize		= SG_MAX_SINGLE_ALLOC,
#else
	.sg_tablesize		= 0xffff,
#endif
#ifndef CONFIG_SCST_PROC
	.enabled_attr_not_needed = 1,
#endif
	.dif_supported		= 1,
	.hw_dif_type1_supported = 1,
	.hw_dif_type2_supported = 1,
	.hw_dif_type3_supported = 1,
	.release		= scst_cm_release,
	.xmit_response		= scst_cm_xmit_response,
	.task_mgmt_fn_done	= scst_cm_task_mgmt_fn_done,
	.report_aen             = scst_cm_report_aen,
	.get_initiator_port_transport_id = scst_cm_get_initiator_port_transport_id,
#ifndef CONFIG_SCST_PROC
	.tgtt_attrs = scst_cm_tgtt_attrs,
#endif
};

int __init scst_cm_init(void)
{
	int res = 0;

	TRACE_ENTRY();

	spin_lock_init(&scst_cm_lock);

	res = scst_register_target_template(&scst_cm_tgtt);
	if (res != 0) {
		PRINT_ERROR("Unable to register copy manager template: %d", res);
		goto out;
	}

	scst_cm_tgt = scst_register_target(&scst_cm_tgtt, SCST_CM_TGT_NAME);
	if (scst_cm_tgt == NULL) {
		PRINT_ERROR("%s", "scst_register_target() failed");
		res = -EFAULT;
		goto out_unreg_tgtt;
	}

	scst_cm_sess = scst_register_session(scst_cm_tgt, false,
				SCST_CM_SESS_NAME, NULL, NULL, NULL);
	if (scst_cm_sess == NULL) {
		PRINT_ERROR("%s", "scst_register_session() failed");
		res = -EFAULT;
		goto out_unreg_tgt;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_unreg_tgt:
	scst_unregister_target(scst_cm_tgt);

out_unreg_tgtt:
	scst_unregister_target_template(&scst_cm_tgtt);
	goto out;
}

void __exit scst_cm_exit(void)
{
	TRACE_ENTRY();

	scst_unregister_session(scst_cm_sess, true, NULL);
	scst_unregister_target(scst_cm_tgt);
	scst_unregister_target_template(&scst_cm_tgtt);

	TRACE_EXIT();
	return;
}

#endif /* #ifndef CONFIG_SCST_PROC */
