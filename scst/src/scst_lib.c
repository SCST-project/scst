/*
 *  scst_lib.c
 *
 *  Copyright (C) 2004 - 2009 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 - 2009 ID7 Ltd.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation, version 2
 *  of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/cdrom.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <asm/kmap_types.h>

#include "scst.h"
#include "scst_priv.h"
#include "scst_mem.h"

#include "scst_cdbprobe.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
struct scsi_io_context {
	unsigned int full_cdb_used:1;
	void *data;
	void (*done)(void *data, char *sense, int result, int resid);
	char sense[SCST_SENSE_BUFFERSIZE];
	unsigned char full_cdb[0];
};
static struct kmem_cache *scsi_io_context_cache;
#endif

static void scst_free_tgt_dev(struct scst_tgt_dev *tgt_dev);
static void scst_check_internal_sense(struct scst_device *dev, int result,
	uint8_t *sense, int sense_len);
static void scst_queue_report_luns_changed_UA(struct scst_session *sess,
	int flags);
static void __scst_check_set_UA(struct scst_tgt_dev *tgt_dev,
	const uint8_t *sense, int sense_len, int flags);
static void scst_alloc_set_UA(struct scst_tgt_dev *tgt_dev,
	const uint8_t *sense, int sense_len, int flags);
static void scst_free_all_UA(struct scst_tgt_dev *tgt_dev);
static void scst_release_space(struct scst_cmd *cmd);
static void scst_sess_free_tgt_devs(struct scst_session *sess);
static void scst_unblock_cmds(struct scst_device *dev);
static void scst_clear_reservation(struct scst_tgt_dev *tgt_dev);
static struct scst_tgt_dev *scst_alloc_add_tgt_dev(struct scst_session *sess,
	struct scst_acg_dev *acg_dev);

#ifdef CONFIG_SCST_DEBUG_TM
static void tm_dbg_init_tgt_dev(struct scst_tgt_dev *tgt_dev,
	struct scst_acg_dev *acg_dev);
static void tm_dbg_deinit_tgt_dev(struct scst_tgt_dev *tgt_dev);
#else
static inline void tm_dbg_init_tgt_dev(struct scst_tgt_dev *tgt_dev,
	struct scst_acg_dev *acg_dev) {}
static inline void tm_dbg_deinit_tgt_dev(struct scst_tgt_dev *tgt_dev) {}
#endif /* CONFIG_SCST_DEBUG_TM */

int scst_alloc_sense(struct scst_cmd *cmd, int atomic)
{
	int res = 0;
	gfp_t gfp_mask = atomic ? GFP_ATOMIC : (GFP_KERNEL|__GFP_NOFAIL);

	TRACE_ENTRY();

	if (cmd->sense != NULL)
		goto memzero;

	cmd->sense = mempool_alloc(scst_sense_mempool, gfp_mask);
	if (cmd->sense == NULL) {
		PRINT_CRIT_ERROR("Sense memory allocation failed (op %x). "
			"The sense data will be lost!!", cmd->cdb[0]);
		res = -ENOMEM;
		goto out;
	}

memzero:
	cmd->sense_bufflen = SCST_SENSE_BUFFERSIZE;
	memset(cmd->sense, 0, SCST_SENSE_BUFFERSIZE);

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_alloc_sense);

int scst_alloc_set_sense(struct scst_cmd *cmd, int atomic,
	const uint8_t *sense, unsigned int len)
{
	int res;

	TRACE_ENTRY();

	res = scst_alloc_sense(cmd, atomic);
	if (res != 0) {
		PRINT_BUFFER("Lost sense", sense, len);
		goto out;
	}

	memcpy(cmd->sense, sense, min((int)len, (int)cmd->sense_bufflen));
	TRACE_BUFFER("Sense set", cmd->sense, cmd->sense_bufflen);

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_alloc_set_sense);

void scst_set_cmd_error_status(struct scst_cmd *cmd, int status)
{
	TRACE_ENTRY();

	cmd->status = status;
	cmd->host_status = DID_OK;

	cmd->dbl_ua_orig_resp_data_len = cmd->resp_data_len;
	cmd->dbl_ua_orig_data_direction = cmd->data_direction;

	cmd->data_direction = SCST_DATA_NONE;
	cmd->resp_data_len = 0;
	cmd->is_send_status = 1;

	cmd->completed = 1;

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_set_cmd_error_status);

void scst_set_cmd_error(struct scst_cmd *cmd, int key, int asc, int ascq)
{
	int rc;

	TRACE_ENTRY();

	scst_set_cmd_error_status(cmd, SAM_STAT_CHECK_CONDITION);

	rc = scst_alloc_sense(cmd, 1);
	if (rc != 0) {
		PRINT_ERROR("Lost sense data (key %x, asc %x, ascq %x)",
			key, asc, ascq);
		goto out;
	}

	scst_set_sense(cmd->sense, cmd->sense_bufflen,
		scst_get_cmd_dev_d_sense(cmd), key, asc, ascq);
	TRACE_BUFFER("Sense set", cmd->sense, cmd->sense_bufflen);

out:
	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_set_cmd_error);

void scst_set_sense(uint8_t *buffer, int len, bool d_sense,
	int key, int asc, int ascq)
{
	sBUG_ON(len == 0);

	memset(buffer, 0, len);

	if (d_sense) {
		/* Descriptor format */
		if (len < 4) {
			PRINT_ERROR("Length %d of sense buffer too small to "
				"fit sense %x:%x:%x", len, key, asc, ascq);
		}

		buffer[0] = 0x72;		/* Response Code	*/
		if (len > 1)
			buffer[1] = key;	/* Sense Key		*/
		if (len > 2)
			buffer[2] = asc;	/* ASC			*/
		if (len > 3)
			buffer[3] = ascq;	/* ASCQ			*/
	} else {
		/* Fixed format */
		if (len < 14) {
			PRINT_ERROR("Length %d of sense buffer too small to "
				"fit sense %x:%x:%x", len, key, asc, ascq);
		}

		buffer[0] = 0x70;		/* Response Code	*/
		if (len > 2)
			buffer[2] = key;	/* Sense Key		*/
		if (len > 7)
			buffer[7] = 0x0a;	/* Additional Sense Length */
		if (len > 12)
			buffer[12] = asc;	/* ASC			*/
		if (len > 13)
			buffer[13] = ascq;	/* ASCQ			*/
	}

	TRACE_BUFFER("Sense set", buffer, len);
	return;
}
EXPORT_SYMBOL(scst_set_sense);

bool scst_analyze_sense(const uint8_t *sense, int len, unsigned int valid_mask,
	int key, int asc, int ascq)
{
	bool res = false;

	/* Response Code */
	if ((sense[0] == 0x70) || (sense[0] == 0x71)) {
		/* Fixed format */

		if (len < 14) {
			PRINT_ERROR("Sense too small to analyze (%d, "
				"type fixed)", len);
			goto out;
		}

		/* Sense Key */
		if ((valid_mask & SCST_SENSE_KEY_VALID) && (sense[2] != key))
			goto out;

		/* ASC */
		if ((valid_mask & SCST_SENSE_ASC_VALID) && (sense[12] != asc))
			goto out;

		/* ASCQ */
		if ((valid_mask & SCST_SENSE_ASCQ_VALID) && (sense[13] != ascq))
			goto out;
	} else if ((sense[0] == 0x72) || (sense[0] == 0x73)) {
		/* Descriptor format */

		if (len < 4) {
			PRINT_ERROR("Sense too small to analyze (%d, "
				"type descriptor)", len);
			goto out;
		}

		/* Sense Key */
		if ((valid_mask & SCST_SENSE_KEY_VALID) && (sense[1] != key))
			goto out;

		/* ASC */
		if ((valid_mask & SCST_SENSE_ASC_VALID) && (sense[2] != asc))
			goto out;

		/* ASCQ */
		if ((valid_mask & SCST_SENSE_ASCQ_VALID) && (sense[3] != ascq))
			goto out;
	} else
		goto out;

	res = true;

out:
	TRACE_EXIT_RES((int)res);
	return res;
}
EXPORT_SYMBOL(scst_analyze_sense);

bool scst_is_ua_sense(const uint8_t *sense, int len)
{
	if (SCST_SENSE_VALID(sense))
		return scst_analyze_sense(sense, len,
			SCST_SENSE_KEY_VALID, UNIT_ATTENTION, 0, 0);
	else
		return false;
}
EXPORT_SYMBOL(scst_is_ua_sense);

bool scst_is_ua_global(const uint8_t *sense, int len)
{
	bool res;

	/* Changing it don't forget to change scst_requeue_ua() as well!! */

	if (scst_analyze_sense(sense, len, SCST_SENSE_ALL_VALID,
			SCST_LOAD_SENSE(scst_sense_reported_luns_data_changed)))
		res = true;
	else
		res = false;

	return res;
}

void scst_check_convert_sense(struct scst_cmd *cmd)
{
	bool d_sense;

	TRACE_ENTRY();

	if ((cmd->sense == NULL) || (cmd->status != SAM_STAT_CHECK_CONDITION))
		goto out;

	d_sense = scst_get_cmd_dev_d_sense(cmd);
	if (d_sense && ((cmd->sense[0] == 0x70) || (cmd->sense[0] == 0x71))) {
		TRACE_MGMT_DBG("Converting fixed sense to descriptor (cmd %p)",
			cmd);
		if (cmd->sense_bufflen < 14) {
			PRINT_ERROR("Sense too small to convert (%d, "
				"type fixed)", cmd->sense_bufflen);
			goto out;
		}
		scst_set_sense(cmd->sense, cmd->sense_bufflen, d_sense,
			cmd->sense[2], cmd->sense[12], cmd->sense[13]);
	} else if (!d_sense && ((cmd->sense[0] == 0x72) ||
				(cmd->sense[0] == 0x73))) {
		TRACE_MGMT_DBG("Converting descriptor sense to fixed (cmd %p)",
			cmd);
		if (cmd->sense_bufflen < 4) {
			PRINT_ERROR("Sense too small to convert (%d, "
				"type descryptor)", cmd->sense_bufflen);
			goto out;
		}
		scst_set_sense(cmd->sense, cmd->sense_bufflen, d_sense,
			cmd->sense[1], cmd->sense[2], cmd->sense[3]);
	}

out:
	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_check_convert_sense);

static void scst_set_cmd_error_sense(struct scst_cmd *cmd, uint8_t *sense,
	unsigned int len)
{
	TRACE_ENTRY();

	scst_set_cmd_error_status(cmd, SAM_STAT_CHECK_CONDITION);
	scst_alloc_set_sense(cmd, 1, sense, len);

	TRACE_EXIT();
	return;
}

void scst_set_busy(struct scst_cmd *cmd)
{
	int c = atomic_read(&cmd->sess->sess_cmd_count);

	TRACE_ENTRY();

	if ((c <= 1) || (cmd->sess->init_phase != SCST_SESS_IPH_READY))	{
		scst_set_cmd_error_status(cmd, SAM_STAT_BUSY);
		TRACE(TRACE_MGMT_MINOR, "Sending BUSY status to initiator %s "
			"(cmds count %d, queue_type %x, sess->init_phase %d)",
			cmd->sess->initiator_name, c,
			cmd->queue_type, cmd->sess->init_phase);
	} else {
		scst_set_cmd_error_status(cmd, SAM_STAT_TASK_SET_FULL);
		TRACE(TRACE_MGMT_MINOR, "Sending QUEUE_FULL status to "
			"initiator %s (cmds count %d, queue_type %x, "
			"sess->init_phase %d)", cmd->sess->initiator_name, c,
			cmd->queue_type, cmd->sess->init_phase);
	}

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_set_busy);

void scst_set_initial_UA(struct scst_session *sess, int key, int asc, int ascq)
{
	int i;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Setting for sess %p initial UA %x/%x/%x", sess, key,
		asc, ascq);

	/* Protect sess_tgt_dev_list_hash */
	mutex_lock(&scst_mutex);

	for (i = 0; i < TGT_DEV_HASH_SIZE; i++) {
		struct list_head *sess_tgt_dev_list_head =
			&sess->sess_tgt_dev_list_hash[i];
		struct scst_tgt_dev *tgt_dev;

		list_for_each_entry(tgt_dev, sess_tgt_dev_list_head,
				sess_tgt_dev_list_entry) {
			spin_lock_bh(&tgt_dev->tgt_dev_lock);
			if (!list_empty(&tgt_dev->UA_list)) {
				struct scst_tgt_dev_UA *ua;

				ua = list_entry(tgt_dev->UA_list.next,
					typeof(*ua), UA_list_entry);
				if (scst_analyze_sense(ua->UA_sense_buffer,
						sizeof(ua->UA_sense_buffer),
						SCST_SENSE_ALL_VALID,
						SCST_LOAD_SENSE(scst_sense_reset_UA))) {
					scst_set_sense(ua->UA_sense_buffer,
						sizeof(ua->UA_sense_buffer),
						tgt_dev->dev->d_sense,
						key, asc, ascq);
				} else
					PRINT_ERROR("%s",
						"The first UA isn't RESET UA");
			} else
				PRINT_ERROR("%s", "There's no RESET UA to "
					"replace");
			spin_unlock_bh(&tgt_dev->tgt_dev_lock);
		}
	}

	mutex_unlock(&scst_mutex);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_set_initial_UA);

static struct scst_aen *scst_alloc_aen(struct scst_session *sess,
	uint64_t unpacked_lun)
{
	struct scst_aen *aen;

	TRACE_ENTRY();

	aen = mempool_alloc(scst_aen_mempool, GFP_KERNEL);
	if (aen == NULL) {
		PRINT_ERROR("AEN memory allocation failed. Corresponding "
			"event notification will not be performed (initiator "
			"%s)", sess->initiator_name);
		goto out;
	}
	memset(aen, 0, sizeof(*aen));

	aen->sess = sess;
	scst_sess_get(sess);

	aen->lun = scst_pack_lun(unpacked_lun);

out:
	TRACE_EXIT_HRES((unsigned long)aen);
	return aen;
};

static void scst_free_aen(struct scst_aen *aen)
{
	TRACE_ENTRY();

	scst_sess_put(aen->sess);
	mempool_free(aen, scst_aen_mempool);

	TRACE_EXIT();
	return;
};

/* Must be called unded scst_mutex */
void scst_gen_aen_or_ua(struct scst_tgt_dev *tgt_dev,
	int key, int asc, int ascq)
{
	struct scst_tgt_template *tgtt = tgt_dev->sess->tgt->tgtt;
	uint8_t sense_buffer[SCST_STANDARD_SENSE_LEN];

	TRACE_ENTRY();

	if (tgtt->report_aen != NULL) {
		struct scst_aen *aen;
		int rc;

		aen = scst_alloc_aen(tgt_dev->sess, tgt_dev->lun);
		if (aen == NULL)
			goto queue_ua;

		aen->event_fn = SCST_AEN_SCSI;
		aen->aen_sense_len = SCST_STANDARD_SENSE_LEN;
		scst_set_sense(aen->aen_sense, aen->aen_sense_len,
			tgt_dev->dev->d_sense, key, asc, ascq);

		TRACE_DBG("Calling target's %s report_aen(%p)",
			tgtt->name, aen);
		rc = tgtt->report_aen(aen);
		TRACE_DBG("Target's %s report_aen(%p) returned %d",
			tgtt->name, aen, rc);
		if (rc == SCST_AEN_RES_SUCCESS)
			goto out;

		scst_free_aen(aen);
	}

queue_ua:
	TRACE_MGMT_DBG("AEN not supported, queuing plain UA (tgt_dev %p)",
		tgt_dev);
	scst_set_sense(sense_buffer, sizeof(sense_buffer),
		tgt_dev->dev->d_sense, key, asc, ascq);
	scst_check_set_UA(tgt_dev, sense_buffer, sizeof(sense_buffer), 0);

out:
	TRACE_EXIT();
	return;
}

/* No locks */
void scst_capacity_data_changed(struct scst_device *dev)
{
	struct scst_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	if (dev->type != TYPE_DISK) {
		TRACE_MGMT_DBG("Device type %d isn't for CAPACITY DATA "
			"CHANGED UA", dev->type);
		goto out;
	}

	TRACE_MGMT_DBG("CAPACITY DATA CHANGED (dev %p)", dev);

	mutex_lock(&scst_mutex);

	list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
			    dev_tgt_dev_list_entry) {
		scst_gen_aen_or_ua(tgt_dev,
			SCST_LOAD_SENSE(scst_sense_capacity_data_changed));
	}

	mutex_unlock(&scst_mutex);

out:
	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_capacity_data_changed);

static inline bool scst_is_report_luns_changed_type(int type)
{
	switch (type) {
	case TYPE_DISK:
	case TYPE_TAPE:
	case TYPE_PRINTER:
	case TYPE_PROCESSOR:
	case TYPE_WORM:
	case TYPE_ROM:
	case TYPE_SCANNER:
	case TYPE_MOD:
	case TYPE_MEDIUM_CHANGER:
	case TYPE_RAID:
	case TYPE_ENCLOSURE:
		return true;
	default:
		return false;
	}
}

/* scst_mutex supposed to be held */
static void scst_queue_report_luns_changed_UA(struct scst_session *sess,
					      int flags)
{
	uint8_t sense_buffer[SCST_STANDARD_SENSE_LEN];
	struct list_head *shead;
	struct scst_tgt_dev *tgt_dev;
	int i;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Queuing REPORTED LUNS DATA CHANGED UA "
		"(sess %p)", sess);

	local_bh_disable();

	for (i = 0; i < TGT_DEV_HASH_SIZE; i++) {
		shead = &sess->sess_tgt_dev_list_hash[i];

		list_for_each_entry(tgt_dev, shead,
				sess_tgt_dev_list_entry) {
			/* Lockdep triggers here a false positive.. */
			spin_lock(&tgt_dev->tgt_dev_lock);
		}
	}

	for (i = 0; i < TGT_DEV_HASH_SIZE; i++) {
		shead = &sess->sess_tgt_dev_list_hash[i];

		list_for_each_entry(tgt_dev, shead,
				sess_tgt_dev_list_entry) {
			if (!scst_is_report_luns_changed_type(
					tgt_dev->dev->type))
				continue;

			scst_set_sense(sense_buffer, sizeof(sense_buffer),
				tgt_dev->dev->d_sense,
				SCST_LOAD_SENSE(scst_sense_reported_luns_data_changed));

			__scst_check_set_UA(tgt_dev, sense_buffer,
				sizeof(sense_buffer),
				flags | SCST_SET_UA_FLAG_GLOBAL);
		}
	}

	for (i = TGT_DEV_HASH_SIZE-1; i >= 0; i--) {
		shead = &sess->sess_tgt_dev_list_hash[i];

		list_for_each_entry_reverse(tgt_dev,
				shead, sess_tgt_dev_list_entry) {
			spin_unlock(&tgt_dev->tgt_dev_lock);
		}
	}

	local_bh_enable();

	TRACE_EXIT();
	return;
}

/* The activity supposed to be suspended and scst_mutex held */
static void scst_report_luns_changed_sess(struct scst_session *sess)
{
	int i;
	struct scst_tgt_template *tgtt = sess->tgt->tgtt;
	int d_sense = 0;
	uint64_t lun = 0;

	TRACE_ENTRY();

	TRACE_DBG("REPORTED LUNS DATA CHANGED (sess %p)", sess);

	for (i = 0; i < TGT_DEV_HASH_SIZE; i++) {
		struct list_head *shead;
		struct scst_tgt_dev *tgt_dev;

		shead = &sess->sess_tgt_dev_list_hash[i];

		list_for_each_entry(tgt_dev, shead,
				sess_tgt_dev_list_entry) {
			if (scst_is_report_luns_changed_type(
					tgt_dev->dev->type)) {
				lun = tgt_dev->lun;
				d_sense = tgt_dev->dev->d_sense;
				goto found;
			}
		}
	}

found:
	if (tgtt->report_aen != NULL) {
		struct scst_aen *aen;
		int rc;

		aen = scst_alloc_aen(sess, lun);
		if (aen == NULL)
			goto queue_ua;

		aen->event_fn = SCST_AEN_SCSI;
		aen->aen_sense_len = SCST_STANDARD_SENSE_LEN;
		scst_set_sense(aen->aen_sense, aen->aen_sense_len, d_sense,
			SCST_LOAD_SENSE(scst_sense_reported_luns_data_changed));

		TRACE_DBG("Calling target's %s report_aen(%p)",
			tgtt->name, aen);
		rc = tgtt->report_aen(aen);
		TRACE_DBG("Target's %s report_aen(%p) returned %d",
			tgtt->name, aen, rc);
		if (rc == SCST_AEN_RES_SUCCESS)
			goto out;

		scst_free_aen(aen);
	}

queue_ua:
	scst_queue_report_luns_changed_UA(sess, 0);

out:
	TRACE_EXIT();
	return;
}

/* The activity supposed to be suspended and scst_mutex held */
void scst_report_luns_changed(struct scst_acg *acg)
{
	struct scst_session *sess;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("REPORTED LUNS DATA CHANGED (acg %s)", acg->acg_name);

	list_for_each_entry(sess, &acg->acg_sess_list, acg_sess_list_entry) {
		scst_report_luns_changed_sess(sess);
	}

	TRACE_EXIT();
	return;
}

void scst_aen_done(struct scst_aen *aen)
{
	TRACE_ENTRY();

	TRACE_MGMT_DBG("AEN %p (fn %d) done (initiator %s)", aen,
		aen->event_fn, aen->sess->initiator_name);

	if (aen->delivery_status == SCST_AEN_RES_SUCCESS)
		goto out_free;

	if (aen->event_fn != SCST_AEN_SCSI)
		goto out_free;

	TRACE_MGMT_DBG("Delivery of SCSI AEN failed (initiator %s)",
		aen->sess->initiator_name);

	if (scst_analyze_sense(aen->aen_sense, aen->aen_sense_len,
			SCST_SENSE_ALL_VALID, SCST_LOAD_SENSE(
				scst_sense_reported_luns_data_changed))) {
		mutex_lock(&scst_mutex);
		scst_queue_report_luns_changed_UA(aen->sess,
			SCST_SET_UA_FLAG_AT_HEAD);
		mutex_unlock(&scst_mutex);
	} else {
		struct list_head *shead;
		struct scst_tgt_dev *tgt_dev;
		uint64_t lun;

		lun = scst_unpack_lun((uint8_t *)&aen->lun, sizeof(aen->lun));

		mutex_lock(&scst_mutex);

		/* tgt_dev might get dead, so we need to reseek it */
		shead = &aen->sess->sess_tgt_dev_list_hash[HASH_VAL(lun)];
		list_for_each_entry(tgt_dev, shead,
				sess_tgt_dev_list_entry) {
			if (tgt_dev->lun == lun) {
				TRACE_MGMT_DBG("Requeuing failed AEN UA for "
					"tgt_dev %p", tgt_dev);
				scst_check_set_UA(tgt_dev, aen->aen_sense,
					aen->aen_sense_len,
					SCST_SET_UA_FLAG_AT_HEAD);
				break;
			}
		}

		mutex_unlock(&scst_mutex);
	}

out_free:
	scst_free_aen(aen);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_aen_done);

void scst_requeue_ua(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	if (scst_analyze_sense(cmd->sense, cmd->sense_bufflen,
			SCST_SENSE_ALL_VALID,
			SCST_LOAD_SENSE(scst_sense_reported_luns_data_changed))) {
		TRACE_MGMT_DBG("Requeuing REPORTED LUNS DATA CHANGED UA "
			"for delivery failed cmd %p", cmd);
		mutex_lock(&scst_mutex);
		scst_queue_report_luns_changed_UA(cmd->sess,
			SCST_SET_UA_FLAG_AT_HEAD);
		mutex_unlock(&scst_mutex);
	} else {
		TRACE_MGMT_DBG("Requeuing UA for delivery failed cmd %p", cmd);
		scst_check_set_UA(cmd->tgt_dev, cmd->sense,
			cmd->sense_bufflen, SCST_SET_UA_FLAG_AT_HEAD);
	}

	TRACE_EXIT();
	return;
}

/* The activity supposed to be suspended and scst_mutex held */
static void scst_check_reassign_sess(struct scst_session *sess)
{
	struct scst_acg *acg, *old_acg;
	struct scst_acg_dev *acg_dev;
	int i;
	struct list_head *shead;
	struct scst_tgt_dev *tgt_dev;
	bool luns_changed = false;
	bool add_failed, something_freed, not_needed_freed = false;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Checking reassignment for sess %p (initiator %s)",
		sess, sess->initiator_name);

	acg = scst_find_acg(sess);
	if (acg == sess->acg) {
		TRACE_MGMT_DBG("No reassignment for sess %p", sess);
		goto out;
	}

	TRACE_MGMT_DBG("sess %p will be reassigned from acg %s to acg %s",
		sess, sess->acg->acg_name, acg->acg_name);

	old_acg = sess->acg;
	sess->acg = NULL; /* to catch implicit dependencies earlier */

retry_add:
	add_failed = false;
	list_for_each_entry(acg_dev, &acg->acg_dev_list, acg_dev_list_entry) {
		unsigned int inq_changed_ua_needed = 0;

		for (i = 0; i < TGT_DEV_HASH_SIZE; i++) {
			shead = &sess->sess_tgt_dev_list_hash[i];

			list_for_each_entry(tgt_dev, shead,
					sess_tgt_dev_list_entry) {
				if ((tgt_dev->dev == acg_dev->dev) &&
				    (tgt_dev->lun == acg_dev->lun) &&
				    (tgt_dev->acg_dev->rd_only == acg_dev->rd_only)) {
					TRACE_MGMT_DBG("sess %p: tgt_dev %p for "
						"LUN %lld stays the same",
						sess, tgt_dev,
						(unsigned long long)tgt_dev->lun);
					tgt_dev->acg_dev = acg_dev;
					goto next;
				} else if (tgt_dev->lun == acg_dev->lun)
					inq_changed_ua_needed = 1;
			}
		}

		luns_changed = true;

		TRACE_MGMT_DBG("sess %p: Allocing new tgt_dev for LUN %lld",
			sess, (unsigned long long)acg_dev->lun);

		tgt_dev = scst_alloc_add_tgt_dev(sess, acg_dev);
		if (tgt_dev == NULL) {
			add_failed = true;
			break;
		}

		tgt_dev->inq_changed_ua_needed = inq_changed_ua_needed ||
						 not_needed_freed;
next:
		continue;
	}

	something_freed = false;
	not_needed_freed = true;
	for (i = 0; i < TGT_DEV_HASH_SIZE; i++) {
		struct scst_tgt_dev *t;
		shead = &sess->sess_tgt_dev_list_hash[i];

		list_for_each_entry_safe(tgt_dev, t, shead,
					sess_tgt_dev_list_entry) {
			if (tgt_dev->acg_dev->acg != acg) {
				TRACE_MGMT_DBG("sess %p: Deleting not used "
					"tgt_dev %p for LUN %lld",
					sess, tgt_dev,
					(unsigned long long)tgt_dev->lun);
				luns_changed = true;
				something_freed = true;
				scst_free_tgt_dev(tgt_dev);
			}
		}
	}

	if (add_failed && something_freed) {
		TRACE_MGMT_DBG("sess %p: Retrying adding new tgt_devs", sess);
		goto retry_add;
	}

	sess->acg = acg;

	TRACE_DBG("Moving sess %p from acg %s to acg %s", sess,
		old_acg->acg_name, acg->acg_name);
	list_move_tail(&sess->acg_sess_list_entry, &acg->acg_sess_list);

	if (luns_changed) {
		scst_report_luns_changed_sess(sess);

		for (i = 0; i < TGT_DEV_HASH_SIZE; i++) {
			shead = &sess->sess_tgt_dev_list_hash[i];

			list_for_each_entry(tgt_dev, shead,
					sess_tgt_dev_list_entry) {
				if (tgt_dev->inq_changed_ua_needed) {
					TRACE_MGMT_DBG("sess %p: Setting "
						"INQUIRY DATA HAS CHANGED UA "
						"(tgt_dev %p)", sess, tgt_dev);

					tgt_dev->inq_changed_ua_needed = 0;

					scst_gen_aen_or_ua(tgt_dev,
						SCST_LOAD_SENSE(scst_sense_inquery_data_changed));
				}
			}
		}
	}

out:
	TRACE_EXIT();
	return;
}

/* The activity supposed to be suspended and scst_mutex held */
void scst_check_reassign_sessions(void)
{
	struct scst_tgt_template *tgtt;

	TRACE_ENTRY();

	list_for_each_entry(tgtt, &scst_template_list, scst_template_list_entry) {
		struct scst_tgt *tgt;
		list_for_each_entry(tgt, &tgtt->tgt_list, tgt_list_entry) {
			struct scst_session *sess;
			list_for_each_entry(sess, &tgt->sess_list,
						sess_list_entry) {
				scst_check_reassign_sess(sess);
			}
		}
	}

	TRACE_EXIT();
	return;
}

int scst_get_cmd_abnormal_done_state(const struct scst_cmd *cmd)
{
	int res;

	TRACE_ENTRY();

	switch (cmd->state) {
	case SCST_CMD_STATE_INIT_WAIT:
	case SCST_CMD_STATE_INIT:
	case SCST_CMD_STATE_PRE_PARSE:
	case SCST_CMD_STATE_DEV_PARSE:
	case SCST_CMD_STATE_DEV_DONE:
		if (cmd->internal)
			res = SCST_CMD_STATE_FINISHED_INTERNAL;
		else
			res = SCST_CMD_STATE_PRE_XMIT_RESP;
		break;

	case SCST_CMD_STATE_PRE_DEV_DONE:
	case SCST_CMD_STATE_MODE_SELECT_CHECKS:
		res = SCST_CMD_STATE_DEV_DONE;
		break;

	case SCST_CMD_STATE_PRE_XMIT_RESP:
		res = SCST_CMD_STATE_XMIT_RESP;
		break;

	case SCST_CMD_STATE_PREPROCESS_DONE:
	case SCST_CMD_STATE_PREPARE_SPACE:
	case SCST_CMD_STATE_RDY_TO_XFER:
	case SCST_CMD_STATE_DATA_WAIT:
	case SCST_CMD_STATE_TGT_PRE_EXEC:
	case SCST_CMD_STATE_SEND_FOR_EXEC:
	case SCST_CMD_STATE_LOCAL_EXEC:
	case SCST_CMD_STATE_REAL_EXEC:
	case SCST_CMD_STATE_REAL_EXECUTING:
		res = SCST_CMD_STATE_PRE_DEV_DONE;
		break;

	default:
		PRINT_CRIT_ERROR("Wrong cmd state %d (cmd %p, op %x)",
			cmd->state, cmd, cmd->cdb[0]);
		sBUG();
		/* Invalid state to supress compiler's warning */
		res = SCST_CMD_STATE_LAST_ACTIVE;
	}

	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_get_cmd_abnormal_done_state);

void scst_set_cmd_abnormal_done_state(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

#ifdef CONFIG_SCST_EXTRACHECKS
	switch (cmd->state) {
	case SCST_CMD_STATE_XMIT_RESP:
	case SCST_CMD_STATE_FINISHED:
	case SCST_CMD_STATE_FINISHED_INTERNAL:
	case SCST_CMD_STATE_XMIT_WAIT:
		PRINT_CRIT_ERROR("Wrong cmd state %d (cmd %p, op %x)",
			cmd->state, cmd, cmd->cdb[0]);
		sBUG();
	}
#endif

	cmd->state = scst_get_cmd_abnormal_done_state(cmd);

#ifdef CONFIG_SCST_EXTRACHECKS
	if ((cmd->state != SCST_CMD_STATE_PRE_XMIT_RESP) &&
		   (cmd->tgt_dev == NULL) && !cmd->internal) {
		PRINT_CRIT_ERROR("Wrong not inited cmd state %d (cmd %p, "
			"op %x)", cmd->state, cmd, cmd->cdb[0]);
		sBUG();
	}
#endif

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_set_cmd_abnormal_done_state);

void scst_set_resp_data_len(struct scst_cmd *cmd, int resp_data_len)
{
	int i, l;

	TRACE_ENTRY();

	scst_check_restore_sg_buff(cmd);
	cmd->resp_data_len = resp_data_len;

	if (resp_data_len == cmd->bufflen)
		goto out;

	l = 0;
	for (i = 0; i < cmd->sg_cnt; i++) {
		l += cmd->sg[i].length;
		if (l >= resp_data_len) {
			int left = resp_data_len - (l - cmd->sg[i].length);
#ifdef CONFIG_SCST_DEBUG
			TRACE(TRACE_SG_OP|TRACE_MEMORY, "cmd %p (tag %llu), "
				"resp_data_len %d, i %d, cmd->sg[i].length %d, "
				"left %d",
				cmd, (long long unsigned int)cmd->tag,
				resp_data_len, i,
				cmd->sg[i].length, left);
#endif
			cmd->orig_sg_cnt = cmd->sg_cnt;
			cmd->orig_sg_entry = i;
			cmd->orig_entry_len = cmd->sg[i].length;
			cmd->sg_cnt = (left > 0) ? i+1 : i;
			cmd->sg[i].length = left;
			cmd->sg_buff_modified = 1;
			break;
		}
	}

out:
	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_set_resp_data_len);

/* No locks */
int scst_queue_retry_cmd(struct scst_cmd *cmd, int finished_cmds)
{
	struct scst_tgt *tgt = cmd->tgt;
	int res = 0;
	unsigned long flags;

	TRACE_ENTRY();

	spin_lock_irqsave(&tgt->tgt_lock, flags);
	tgt->retry_cmds++;
	/*
	 * Memory barrier is needed here, because we need the exact order
	 * between the read and write between retry_cmds and finished_cmds to
	 * not miss the case when a command finished while we queuing it for
	 * retry after the finished_cmds check.
	 */
	smp_mb();
	TRACE_RETRY("TGT QUEUE FULL: incrementing retry_cmds %d",
	      tgt->retry_cmds);
	if (finished_cmds != atomic_read(&tgt->finished_cmds)) {
		/* At least one cmd finished, so try again */
		tgt->retry_cmds--;
		TRACE_RETRY("Some command(s) finished, direct retry "
		      "(finished_cmds=%d, tgt->finished_cmds=%d, "
		      "retry_cmds=%d)", finished_cmds,
		      atomic_read(&tgt->finished_cmds), tgt->retry_cmds);
		res = -1;
		goto out_unlock_tgt;
	}

	TRACE_RETRY("Adding cmd %p to retry cmd list", cmd);
	list_add_tail(&cmd->cmd_list_entry, &tgt->retry_cmd_list);

	if (!tgt->retry_timer_active) {
		tgt->retry_timer.expires = jiffies + SCST_TGT_RETRY_TIMEOUT;
		add_timer(&tgt->retry_timer);
		tgt->retry_timer_active = 1;
	}

out_unlock_tgt:
	spin_unlock_irqrestore(&tgt->tgt_lock, flags);

	TRACE_EXIT_RES(res);
	return res;
}

/* Returns 0 to continue, >0 to restart, <0 to break */
static int scst_check_hw_pending_cmd(struct scst_cmd *cmd,
	unsigned long cur_time, unsigned long max_time,
	struct scst_session *sess, unsigned long *flags,
	struct scst_tgt_template *tgtt)
{
	int res = -1; /* break */

	TRACE_DBG("cmd %p, hw_pending %d, proc time %ld, "
		"pending time %ld", cmd, cmd->cmd_hw_pending,
		(long)(cur_time - cmd->start_time) / HZ,
		(long)(cur_time - cmd->hw_pending_start) / HZ);

	if (time_before_eq(cur_time, cmd->start_time + max_time)) {
		/* Cmds are ordered, so no need to check more */
		goto out;
	}

	if (!cmd->cmd_hw_pending) {
		res = 0; /* continue */
		goto out;
	}

	if (time_before(cur_time, cmd->hw_pending_start + max_time)) {
		/* Cmds are ordered, so no need to check more */
		goto out;
	}

	TRACE_MGMT_DBG("Cmd %p HW pending for too long %ld (state %x)",
		cmd, (cur_time - cmd->hw_pending_start) / HZ,
		cmd->state);

	cmd->cmd_hw_pending = 0;

	spin_unlock_irqrestore(&sess->sess_list_lock, *flags);
	tgtt->on_hw_pending_cmd_timeout(cmd);
	spin_lock_irqsave(&sess->sess_list_lock, *flags);

	res = 1; /* restart */

out:
	TRACE_EXIT_RES(res);
	return res;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void scst_hw_pending_work_fn(void *p)
#else
static void scst_hw_pending_work_fn(struct delayed_work *work)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct scst_session *sess = (struct scst_session *)p;
#else
	struct scst_session *sess = container_of(work, struct scst_session,
					hw_pending_work);
#endif
	struct scst_tgt_template *tgtt = sess->tgt->tgtt;
	struct scst_cmd *cmd;
	unsigned long cur_time = jiffies;
	unsigned long flags;
	unsigned long max_time = tgtt->max_hw_pending_time * HZ;

	TRACE_ENTRY();

	TRACE_DBG("HW pending work (sess %p, max time %ld)", sess, max_time/HZ);

	clear_bit(SCST_SESS_HW_PENDING_WORK_SCHEDULED, &sess->sess_aflags);

	spin_lock_irqsave(&sess->sess_list_lock, flags);

restart:
	list_for_each_entry(cmd, &sess->search_cmd_list,
				sess_cmd_list_entry) {
		int rc;

		rc = scst_check_hw_pending_cmd(cmd, cur_time, max_time, sess,
					&flags, tgtt);
		if (rc < 0)
			break;
		else if (rc == 0)
			continue;
		else
			goto restart;
	}

restart1:
	list_for_each_entry(cmd, &sess->after_pre_xmit_cmd_list,
				sess_cmd_list_entry) {
		int rc;

		rc = scst_check_hw_pending_cmd(cmd, cur_time, max_time, sess,
					&flags, tgtt);
		if (rc < 0)
			break;
		else if (rc == 0)
			continue;
		else
			goto restart1;
	}

	if (!list_empty(&sess->search_cmd_list) ||
	    !list_empty(&sess->after_pre_xmit_cmd_list)) {
		/*
		 * For stuck cmds if there is no activity we might need to have
		 * one more run to release them, so reschedule once again.
		 */
		TRACE_DBG("Sched HW pending work for sess %p (max time %d)",
			sess, tgtt->max_hw_pending_time);
		set_bit(SCST_SESS_HW_PENDING_WORK_SCHEDULED, &sess->sess_aflags);
		schedule_delayed_work(&sess->hw_pending_work,
				tgtt->max_hw_pending_time * HZ);
	}

	spin_unlock_irqrestore(&sess->sess_list_lock, flags);

	TRACE_EXIT();
	return;
}

/* Called under scst_mutex and suspended activity */
int scst_alloc_device(gfp_t gfp_mask, struct scst_device **out_dev)
{
	struct scst_device *dev;
	int res = 0;
	static int dev_num; /* protected by scst_mutex */

	TRACE_ENTRY();

	dev = kzalloc(sizeof(*dev), gfp_mask);
	if (dev == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s",
			"Allocation of scst_device failed");
		res = -ENOMEM;
		goto out;
	}

	dev->handler = &scst_null_devtype;
	dev->p_cmd_lists = &scst_main_cmd_lists;
	atomic_set(&dev->dev_cmd_count, 0);
	atomic_set(&dev->write_cmd_count, 0);
	scst_init_mem_lim(&dev->dev_mem_lim);
	spin_lock_init(&dev->dev_lock);
	atomic_set(&dev->on_dev_count, 0);
	INIT_LIST_HEAD(&dev->blocked_cmd_list);
	INIT_LIST_HEAD(&dev->dev_tgt_dev_list);
	INIT_LIST_HEAD(&dev->dev_acg_dev_list);
	INIT_LIST_HEAD(&dev->threads_list);
	init_waitqueue_head(&dev->on_dev_waitQ);
	dev->dev_double_ua_possible = 1;
	dev->queue_alg = SCST_CONTR_MODE_QUEUE_ALG_UNRESTRICTED_REORDER;
	dev->dev_num = dev_num++;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25) && defined(SCST_IO_CONTEXT)
#if defined(CONFIG_BLOCK)
	dev->dev_io_ctx = alloc_io_context(GFP_KERNEL, -1);
	if (dev->dev_io_ctx == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Failed to alloc dev IO context");
		res = -ENOMEM;
		kfree(dev);
		goto out;
	}
#endif
#endif

	*out_dev = dev;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* Called under scst_mutex and suspended activity */
void scst_free_device(struct scst_device *dev)
{
	TRACE_ENTRY();

#ifdef CONFIG_SCST_EXTRACHECKS
	if (!list_empty(&dev->dev_tgt_dev_list) ||
	    !list_empty(&dev->dev_acg_dev_list)) {
		PRINT_CRIT_ERROR("%s: dev_tgt_dev_list or dev_acg_dev_list "
			"is not empty!", __func__);
		sBUG();
	}
#endif

	__exit_io_context(dev->dev_io_ctx);

	kfree(dev);

	TRACE_EXIT();
	return;
}

void scst_init_mem_lim(struct scst_mem_lim *mem_lim)
{
	atomic_set(&mem_lim->alloced_pages, 0);
	mem_lim->max_allowed_pages =
		((uint64_t)scst_max_dev_cmd_mem << 10) >> (PAGE_SHIFT - 10);
}
EXPORT_SYMBOL(scst_init_mem_lim);

static struct scst_acg_dev *scst_alloc_acg_dev(struct scst_acg *acg,
					struct scst_device *dev, uint64_t lun)
{
	struct scst_acg_dev *res;

	TRACE_ENTRY();

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 17)
	res = kmem_cache_alloc(scst_acgd_cachep, GFP_KERNEL);
#else
	res = kmem_cache_zalloc(scst_acgd_cachep, GFP_KERNEL);
#endif
	if (res == NULL) {
		TRACE(TRACE_OUT_OF_MEM,
		      "%s", "Allocation of scst_acg_dev failed");
		goto out;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 17)
	memset(res, 0, sizeof(*res));
#endif

	res->dev = dev;
	res->acg = acg;
	res->lun = lun;

out:
	TRACE_EXIT_HRES(res);
	return res;
}

/* The activity supposed to be suspended and scst_mutex held */
static void scst_free_acg_dev(struct scst_acg_dev *acg_dev)
{
	TRACE_ENTRY();

	TRACE_DBG("Removing acg_dev %p from acg_dev_list and dev_acg_dev_list",
		acg_dev);
	list_del(&acg_dev->acg_dev_list_entry);
	list_del(&acg_dev->dev_acg_dev_list_entry);

	kmem_cache_free(scst_acgd_cachep, acg_dev);

	TRACE_EXIT();
	return;
}

/* The activity supposed to be suspended and scst_mutex held */
struct scst_acg *scst_alloc_add_acg(const char *acg_name)
{
	struct scst_acg *acg;

	TRACE_ENTRY();

	acg = kzalloc(sizeof(*acg), GFP_KERNEL);
	if (acg == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of acg failed");
		goto out;
	}

	INIT_LIST_HEAD(&acg->acg_dev_list);
	INIT_LIST_HEAD(&acg->acg_sess_list);
	INIT_LIST_HEAD(&acg->acn_list);
	acg->acg_name = acg_name;

	TRACE_DBG("Adding acg %s to scst_acg_list", acg_name);
	list_add_tail(&acg->scst_acg_list_entry, &scst_acg_list);

	scst_check_reassign_sessions();

out:
	TRACE_EXIT_HRES(acg);
	return acg;
}

/* The activity supposed to be suspended and scst_mutex held */
int scst_destroy_acg(struct scst_acg *acg)
{
	struct scst_acn *n, *nn;
	struct scst_acg_dev *acg_dev, *acg_dev_tmp;
	int res = 0;

	TRACE_ENTRY();

	if (!list_empty(&acg->acg_sess_list)) {
		PRINT_ERROR("%s: acg_sess_list is not empty!", __func__);
		res = -EBUSY;
		goto out;
	}

	TRACE_DBG("Removing acg %s from scst_acg_list", acg->acg_name);
	list_del(&acg->scst_acg_list_entry);

	/* Freeing acg_devs */
	list_for_each_entry_safe(acg_dev, acg_dev_tmp, &acg->acg_dev_list,
			acg_dev_list_entry) {
		struct scst_tgt_dev *tgt_dev, *tt;
		list_for_each_entry_safe(tgt_dev, tt,
				 &acg_dev->dev->dev_tgt_dev_list,
				 dev_tgt_dev_list_entry) {
			if (tgt_dev->acg_dev == acg_dev)
				scst_free_tgt_dev(tgt_dev);
		}
		scst_free_acg_dev(acg_dev);
	}

	/* Freeing names */
	list_for_each_entry_safe(n, nn, &acg->acn_list,
			acn_list_entry) {
		list_del(&n->acn_list_entry);
		kfree(n->name);
		kfree(n);
	}
	INIT_LIST_HEAD(&acg->acn_list);

	kfree(acg);
out:
	TRACE_EXIT_RES(res);
	return res;
}

/*
 * scst_mutex supposed to be held, there must not be parallel activity in this
 * session.
 */
static struct scst_tgt_dev *scst_alloc_add_tgt_dev(struct scst_session *sess,
	struct scst_acg_dev *acg_dev)
{
	int ini_sg, ini_unchecked_isa_dma, ini_use_clustering;
	struct scst_tgt_dev *tgt_dev, *t = NULL;
	struct scst_device *dev = acg_dev->dev;
	struct list_head *sess_tgt_dev_list_head;
	struct scst_tgt_template *vtt = sess->tgt->tgtt;
	int rc, i;
	bool share_io_ctx = false;
	uint8_t sense_buffer[SCST_STANDARD_SENSE_LEN];

	TRACE_ENTRY();

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 17)
	tgt_dev = kmem_cache_alloc(scst_tgtd_cachep, GFP_KERNEL);
#else
	tgt_dev = kmem_cache_zalloc(scst_tgtd_cachep, GFP_KERNEL);
#endif
	if (tgt_dev == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s",
		      "Allocation of scst_tgt_dev failed");
		goto out;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 17)
	memset(tgt_dev, 0, sizeof(*tgt_dev));
#endif

	tgt_dev->dev = dev;
	tgt_dev->lun = acg_dev->lun;
	tgt_dev->acg_dev = acg_dev;
	tgt_dev->sess = sess;
	atomic_set(&tgt_dev->tgt_dev_cmd_count, 0);

	scst_sgv_pool_use_norm(tgt_dev);

	if (dev->scsi_dev != NULL) {
		ini_sg = dev->scsi_dev->host->sg_tablesize;
		ini_unchecked_isa_dma = dev->scsi_dev->host->unchecked_isa_dma;
		ini_use_clustering = (dev->scsi_dev->host->use_clustering ==
				ENABLE_CLUSTERING);
	} else {
		ini_sg = (1 << 15) /* infinite */;
		ini_unchecked_isa_dma = 0;
		ini_use_clustering = 0;
	}
	tgt_dev->max_sg_cnt = min(ini_sg, sess->tgt->sg_tablesize);

	if ((sess->tgt->tgtt->use_clustering || ini_use_clustering) &&
	    !sess->tgt->tgtt->no_clustering)
		scst_sgv_pool_use_norm_clust(tgt_dev);

	if (sess->tgt->tgtt->unchecked_isa_dma || ini_unchecked_isa_dma)
		scst_sgv_pool_use_dma(tgt_dev);

	if (dev->scsi_dev != NULL) {
		TRACE_MGMT_DBG("host=%d, channel=%d, id=%d, lun=%d, "
		      "SCST lun=%lld", dev->scsi_dev->host->host_no,
		      dev->scsi_dev->channel, dev->scsi_dev->id,
		      dev->scsi_dev->lun,
		      (long long unsigned int)tgt_dev->lun);
	} else {
		TRACE_MGMT_DBG("Virtual device %s on SCST lun=%lld",
		       dev->virt_name, (long long unsigned int)tgt_dev->lun);
	}

	spin_lock_init(&tgt_dev->tgt_dev_lock);
	INIT_LIST_HEAD(&tgt_dev->UA_list);
	spin_lock_init(&tgt_dev->thr_data_lock);
	INIT_LIST_HEAD(&tgt_dev->thr_data_list);
	spin_lock_init(&tgt_dev->sn_lock);
	INIT_LIST_HEAD(&tgt_dev->deferred_cmd_list);
	INIT_LIST_HEAD(&tgt_dev->skipped_sn_list);
	tgt_dev->expected_sn = 1;
	tgt_dev->num_free_sn_slots = ARRAY_SIZE(tgt_dev->sn_slots)-1;
	tgt_dev->cur_sn_slot = &tgt_dev->sn_slots[0];
	for (i = 0; i < (int)ARRAY_SIZE(tgt_dev->sn_slots); i++)
		atomic_set(&tgt_dev->sn_slots[i], 0);

	if (dev->handler->parse_atomic &&
	    (sess->tgt->tgtt->preprocessing_done == NULL)) {
		if (sess->tgt->tgtt->rdy_to_xfer_atomic)
			__set_bit(SCST_TGT_DEV_AFTER_INIT_WR_ATOMIC,
				&tgt_dev->tgt_dev_flags);
		if (dev->handler->exec_atomic)
			__set_bit(SCST_TGT_DEV_AFTER_INIT_OTH_ATOMIC,
				&tgt_dev->tgt_dev_flags);
	}
	if (dev->handler->exec_atomic) {
		if (sess->tgt->tgtt->rdy_to_xfer_atomic)
			__set_bit(SCST_TGT_DEV_AFTER_RESTART_WR_ATOMIC,
				&tgt_dev->tgt_dev_flags);
		__set_bit(SCST_TGT_DEV_AFTER_RESTART_OTH_ATOMIC,
				&tgt_dev->tgt_dev_flags);
		__set_bit(SCST_TGT_DEV_AFTER_RX_DATA_ATOMIC,
			&tgt_dev->tgt_dev_flags);
	}
	if (dev->handler->dev_done_atomic &&
	    sess->tgt->tgtt->xmit_response_atomic) {
		__set_bit(SCST_TGT_DEV_AFTER_EXEC_ATOMIC,
			&tgt_dev->tgt_dev_flags);
	}

	scst_set_sense(sense_buffer, sizeof(sense_buffer),
		dev->d_sense, SCST_LOAD_SENSE(scst_sense_reset_UA));
	scst_alloc_set_UA(tgt_dev, sense_buffer, sizeof(sense_buffer), 0);

	tm_dbg_init_tgt_dev(tgt_dev, acg_dev);

	if (tgt_dev->sess->initiator_name != NULL) {
		spin_lock_bh(&dev->dev_lock);
		list_for_each_entry(t, &dev->dev_tgt_dev_list,
				dev_tgt_dev_list_entry) {
			TRACE_DBG("t name %s (tgt_dev name %s)",
				t->sess->initiator_name,
				tgt_dev->sess->initiator_name);
			if (t->sess->initiator_name == NULL)
				continue;
			if (strcmp(t->sess->initiator_name,
					tgt_dev->sess->initiator_name) == 0) {
				share_io_ctx = true;
				break;
			}
		}
		spin_unlock_bh(&dev->dev_lock);
	}

	if (share_io_ctx) {
		TRACE_MGMT_DBG("Sharing IO context %p (tgt_dev %p, ini %s)",
			t->tgt_dev_io_ctx, tgt_dev,
			tgt_dev->sess->initiator_name);
		tgt_dev->tgt_dev_io_ctx = ioc_task_link(t->tgt_dev_io_ctx);
	} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25) && defined(SCST_IO_CONTEXT)
#if defined(CONFIG_BLOCK)
		tgt_dev->tgt_dev_io_ctx = alloc_io_context(GFP_KERNEL, -1);
		if (tgt_dev->tgt_dev_io_ctx == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "Failed to alloc tgt_dev IO "
				"context for dev %s (initiator %s)",
				dev->virt_name, sess->initiator_name);
			goto out_free;
		}
#endif
#endif
	}

	if (vtt->threads_num > 0) {
		rc = 0;
		if (dev->handler->threads_num > 0)
			rc = scst_add_dev_threads(dev, vtt->threads_num);
		else if (dev->handler->threads_num == 0)
			rc = scst_add_global_threads(vtt->threads_num);
		if (rc != 0)
			goto out_free;
	}

	if (dev->handler && dev->handler->attach_tgt) {
		TRACE_DBG("Calling dev handler's attach_tgt(%p)",
		      tgt_dev);
		rc = dev->handler->attach_tgt(tgt_dev);
		TRACE_DBG("%s", "Dev handler's attach_tgt() returned");
		if (rc != 0) {
			PRINT_ERROR("Device handler's %s attach_tgt() "
			    "failed: %d", dev->handler->name, rc);
			goto out_thr_free;
		}
	}

	spin_lock_bh(&dev->dev_lock);
	list_add_tail(&tgt_dev->dev_tgt_dev_list_entry, &dev->dev_tgt_dev_list);
	if (dev->dev_reserved)
		__set_bit(SCST_TGT_DEV_RESERVED, &tgt_dev->tgt_dev_flags);
	spin_unlock_bh(&dev->dev_lock);

	sess_tgt_dev_list_head =
		&sess->sess_tgt_dev_list_hash[HASH_VAL(tgt_dev->lun)];
	list_add_tail(&tgt_dev->sess_tgt_dev_list_entry,
		      sess_tgt_dev_list_head);

out:
	TRACE_EXIT();
	return tgt_dev;

out_thr_free:
	if (vtt->threads_num > 0) {
		if (dev->handler->threads_num > 0)
			scst_del_dev_threads(dev, vtt->threads_num);
		else if (dev->handler->threads_num == 0)
			scst_del_global_threads(vtt->threads_num);
	}

out_free:
	scst_free_all_UA(tgt_dev);
	__exit_io_context(tgt_dev->tgt_dev_io_ctx);

	kmem_cache_free(scst_tgtd_cachep, tgt_dev);
	tgt_dev = NULL;
	goto out;
}

/* No locks supposed to be held, scst_mutex - held */
void scst_nexus_loss(struct scst_tgt_dev *tgt_dev, bool queue_UA)
{
	TRACE_ENTRY();

	scst_clear_reservation(tgt_dev);

	/* With activity suspended the lock isn't needed, but let's be safe */
	spin_lock_bh(&tgt_dev->tgt_dev_lock);
	scst_free_all_UA(tgt_dev);
	memset(tgt_dev->tgt_dev_sense, 0, sizeof(tgt_dev->tgt_dev_sense));
	spin_unlock_bh(&tgt_dev->tgt_dev_lock);

	if (queue_UA) {
		uint8_t sense_buffer[SCST_STANDARD_SENSE_LEN];
		scst_set_sense(sense_buffer, sizeof(sense_buffer),
			tgt_dev->dev->d_sense,
			SCST_LOAD_SENSE(scst_sense_nexus_loss_UA));
		scst_check_set_UA(tgt_dev, sense_buffer,
			sizeof(sense_buffer), 0);
	}

	TRACE_EXIT();
	return;
}

/*
 * scst_mutex supposed to be held, there must not be parallel activity in this
 * session.
 */
static void scst_free_tgt_dev(struct scst_tgt_dev *tgt_dev)
{
	struct scst_device *dev = tgt_dev->dev;
	struct scst_tgt_template *vtt = tgt_dev->sess->tgt->tgtt;

	TRACE_ENTRY();

	tm_dbg_deinit_tgt_dev(tgt_dev);

	spin_lock_bh(&dev->dev_lock);
	list_del(&tgt_dev->dev_tgt_dev_list_entry);
	spin_unlock_bh(&dev->dev_lock);

	list_del(&tgt_dev->sess_tgt_dev_list_entry);

	scst_clear_reservation(tgt_dev);
	scst_free_all_UA(tgt_dev);

	if (dev->handler && dev->handler->detach_tgt) {
		TRACE_DBG("Calling dev handler's detach_tgt(%p)",
		      tgt_dev);
		dev->handler->detach_tgt(tgt_dev);
		TRACE_DBG("%s", "Dev handler's detach_tgt() returned");
	}

	if (vtt->threads_num > 0) {
		if (dev->handler->threads_num > 0)
			scst_del_dev_threads(dev, vtt->threads_num);
		else if (dev->handler->threads_num == 0)
			scst_del_global_threads(vtt->threads_num);
	}

	__exit_io_context(tgt_dev->tgt_dev_io_ctx);

	kmem_cache_free(scst_tgtd_cachep, tgt_dev);

	TRACE_EXIT();
	return;
}

/* scst_mutex supposed to be held */
int scst_sess_alloc_tgt_devs(struct scst_session *sess)
{
	int res = 0;
	struct scst_acg_dev *acg_dev;
	struct scst_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	list_for_each_entry(acg_dev, &sess->acg->acg_dev_list,
			acg_dev_list_entry) {
		tgt_dev = scst_alloc_add_tgt_dev(sess, acg_dev);
		if (tgt_dev == NULL) {
			res = -ENOMEM;
			goto out_free;
		}
	}

out:
	TRACE_EXIT();
	return res;

out_free:
	scst_sess_free_tgt_devs(sess);
	goto out;
}

/*
 * scst_mutex supposed to be held, there must not be parallel activity in this
 * session.
 */
static void scst_sess_free_tgt_devs(struct scst_session *sess)
{
	int i;
	struct scst_tgt_dev *tgt_dev, *t;

	TRACE_ENTRY();

	/* The session is going down, no users, so no locks */
	for (i = 0; i < TGT_DEV_HASH_SIZE; i++) {
		struct list_head *sess_tgt_dev_list_head =
			&sess->sess_tgt_dev_list_hash[i];
		list_for_each_entry_safe(tgt_dev, t, sess_tgt_dev_list_head,
				sess_tgt_dev_list_entry) {
			scst_free_tgt_dev(tgt_dev);
		}
		INIT_LIST_HEAD(sess_tgt_dev_list_head);
	}

	TRACE_EXIT();
	return;
}

/* The activity supposed to be suspended and scst_mutex held */
int scst_acg_add_dev(struct scst_acg *acg, struct scst_device *dev,
	uint64_t lun, int read_only, bool gen_scst_report_luns_changed)
{
	int res = 0;
	struct scst_acg_dev *acg_dev;
	struct scst_tgt_dev *tgt_dev;
	struct scst_session *sess;
	LIST_HEAD(tmp_tgt_dev_list);

	TRACE_ENTRY();

	INIT_LIST_HEAD(&tmp_tgt_dev_list);

	acg_dev = scst_alloc_acg_dev(acg, dev, lun);
	if (acg_dev == NULL) {
		res = -ENOMEM;
		goto out;
	}
	acg_dev->rd_only = read_only;

	TRACE_DBG("Adding acg_dev %p to acg_dev_list and dev_acg_dev_list",
		acg_dev);
	list_add_tail(&acg_dev->acg_dev_list_entry, &acg->acg_dev_list);
	list_add_tail(&acg_dev->dev_acg_dev_list_entry, &dev->dev_acg_dev_list);

	list_for_each_entry(sess, &acg->acg_sess_list, acg_sess_list_entry) {
		tgt_dev = scst_alloc_add_tgt_dev(sess, acg_dev);
		if (tgt_dev == NULL) {
			res = -ENOMEM;
			goto out_free;
		}
		list_add_tail(&tgt_dev->extra_tgt_dev_list_entry,
			      &tmp_tgt_dev_list);
	}

	if (gen_scst_report_luns_changed)
		scst_report_luns_changed(acg);

	if (dev->virt_name != NULL) {
		PRINT_INFO("Added device %s to group %s (LUN %lld, "
			"rd_only %d)", dev->virt_name, acg->acg_name,
			(long long unsigned int)lun,
			read_only);
	} else {
		PRINT_INFO("Added device %d:%d:%d:%d to group %s (LUN "
			"%lld, rd_only %d)",
			dev->scsi_dev->host->host_no,
			dev->scsi_dev->channel,	dev->scsi_dev->id,
			dev->scsi_dev->lun, acg->acg_name,
			(long long unsigned int)lun,
			read_only);
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	list_for_each_entry(tgt_dev, &tmp_tgt_dev_list,
			 extra_tgt_dev_list_entry) {
		scst_free_tgt_dev(tgt_dev);
	}
	scst_free_acg_dev(acg_dev);
	goto out;
}

/* The activity supposed to be suspended and scst_mutex held */
int scst_acg_remove_dev(struct scst_acg *acg, struct scst_device *dev,
	bool gen_scst_report_luns_changed)
{
	int res = 0;
	struct scst_acg_dev *acg_dev = NULL, *a;
	struct scst_tgt_dev *tgt_dev, *tt;

	TRACE_ENTRY();

	list_for_each_entry(a, &acg->acg_dev_list, acg_dev_list_entry) {
		if (a->dev == dev) {
			acg_dev = a;
			break;
		}
	}

	if (acg_dev == NULL) {
		PRINT_ERROR("Device is not found in group %s", acg->acg_name);
		res = -EINVAL;
		goto out;
	}

	list_for_each_entry_safe(tgt_dev, tt, &dev->dev_tgt_dev_list,
			 dev_tgt_dev_list_entry) {
		if (tgt_dev->acg_dev == acg_dev)
			scst_free_tgt_dev(tgt_dev);
	}
	scst_free_acg_dev(acg_dev);

	if (gen_scst_report_luns_changed)
		scst_report_luns_changed(acg);

	if (dev->virt_name != NULL) {
		PRINT_INFO("Removed device %s from group %s",
			dev->virt_name, acg->acg_name);
	} else {
		PRINT_INFO("Removed device %d:%d:%d:%d from group %s",
			dev->scsi_dev->host->host_no,
			dev->scsi_dev->channel,	dev->scsi_dev->id,
			dev->scsi_dev->lun, acg->acg_name);
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* The activity supposed to be suspended and scst_mutex held */
int scst_acg_add_name(struct scst_acg *acg, const char *name)
{
	int res = 0;
	struct scst_acn *n;
	int len;
	char *nm;

	TRACE_ENTRY();

	list_for_each_entry(n, &acg->acn_list, acn_list_entry) {
		if (strcmp(n->name, name) == 0) {
			PRINT_ERROR("Name %s already exists in group %s",
				name, acg->acg_name);
			res = -EINVAL;
			goto out;
		}
	}

	n = kmalloc(sizeof(*n), GFP_KERNEL);
	if (n == NULL) {
		PRINT_ERROR("%s", "Unable to allocate scst_acn");
		res = -ENOMEM;
		goto out;
	}

	len = strlen(name);
	nm = kmalloc(len + 1, GFP_KERNEL);
	if (nm == NULL) {
		PRINT_ERROR("%s", "Unable to allocate scst_acn->name");
		res = -ENOMEM;
		goto out_free;
	}

	strcpy(nm, name);
	n->name = nm;

	list_add_tail(&n->acn_list_entry, &acg->acn_list);

out:
	if (res == 0) {
		PRINT_INFO("Added name %s to group %s", name, acg->acg_name);
		scst_check_reassign_sessions();
	}

	TRACE_EXIT_RES(res);
	return res;

out_free:
	kfree(n);
	goto out;
}

/* scst_mutex supposed to be held */
void __scst_acg_remove_acn(struct scst_acn *n)
{
	TRACE_ENTRY();

	list_del(&n->acn_list_entry);
	kfree(n->name);
	kfree(n);

	TRACE_EXIT();
	return;
}

/* The activity supposed to be suspended and scst_mutex held */
int scst_acg_remove_name(struct scst_acg *acg, const char *name, bool reassign)
{
	int res = -EINVAL;
	struct scst_acn *n;

	TRACE_ENTRY();

	list_for_each_entry(n, &acg->acn_list, acn_list_entry) {
		if (strcmp(n->name, name) == 0) {
			__scst_acg_remove_acn(n);
			res = 0;
			break;
		}
	}

	if (res == 0) {
		PRINT_INFO("Removed name %s from group %s", name,
			acg->acg_name);
		if (reassign)
			scst_check_reassign_sessions();
	} else
		PRINT_ERROR("Unable to find name %s in group %s", name,
			acg->acg_name);

	TRACE_EXIT_RES(res);
	return res;
}

static struct scst_cmd *scst_create_prepare_internal_cmd(
	struct scst_cmd *orig_cmd, int bufsize)
{
	struct scst_cmd *res;
	gfp_t gfp_mask = scst_cmd_atomic(orig_cmd) ? GFP_ATOMIC : GFP_KERNEL;

	TRACE_ENTRY();

	res = scst_alloc_cmd(gfp_mask);
	if (res == NULL)
		goto out;

	res->cmd_lists = orig_cmd->cmd_lists;
	res->sess = orig_cmd->sess;
	res->atomic = scst_cmd_atomic(orig_cmd);
	res->internal = 1;
	res->tgtt = orig_cmd->tgtt;
	res->tgt = orig_cmd->tgt;
	res->dev = orig_cmd->dev;
	res->tgt_dev = orig_cmd->tgt_dev;
	res->lun = orig_cmd->lun;
	res->queue_type = SCST_CMD_QUEUE_HEAD_OF_QUEUE;
	res->data_direction = SCST_DATA_UNKNOWN;
	res->orig_cmd = orig_cmd;
	res->bufflen = bufsize;

	scst_sess_get(res->sess);
	if (res->tgt_dev != NULL)
		__scst_get(0);

	res->state = SCST_CMD_STATE_PRE_PARSE;

out:
	TRACE_EXIT_HRES((unsigned long)res);
	return res;
}

int scst_prepare_request_sense(struct scst_cmd *orig_cmd)
{
	int res = 0;
	static const uint8_t request_sense[6] =
	    { REQUEST_SENSE, 0, 0, 0, SCST_SENSE_BUFFERSIZE, 0 };
	struct scst_cmd *rs_cmd;

	TRACE_ENTRY();

	if (orig_cmd->sense != NULL) {
		TRACE_MEM("Releasing sense %p (orig_cmd %p)",
			orig_cmd->sense, orig_cmd);
		mempool_free(orig_cmd->sense, scst_sense_mempool);
		orig_cmd->sense = NULL;
	}

	rs_cmd = scst_create_prepare_internal_cmd(orig_cmd,
			SCST_SENSE_BUFFERSIZE);
	if (rs_cmd == NULL)
		goto out_error;

	memcpy(rs_cmd->cdb, request_sense, sizeof(request_sense));
	rs_cmd->cdb[1] |= scst_get_cmd_dev_d_sense(orig_cmd);
	rs_cmd->cdb_len = sizeof(request_sense);
	rs_cmd->data_direction = SCST_DATA_READ;
	rs_cmd->expected_data_direction = rs_cmd->data_direction;
	rs_cmd->expected_transfer_len = SCST_SENSE_BUFFERSIZE;
	rs_cmd->expected_values_set = 1;

	TRACE(TRACE_MGMT_MINOR, "Adding REQUEST SENSE cmd %p to head of active "
		"cmd list", rs_cmd);
	spin_lock_irq(&rs_cmd->cmd_lists->cmd_list_lock);
	list_add(&rs_cmd->cmd_list_entry, &rs_cmd->cmd_lists->active_cmd_list);
	wake_up(&rs_cmd->cmd_lists->cmd_list_waitQ);
	spin_unlock_irq(&rs_cmd->cmd_lists->cmd_list_lock);

out:
	TRACE_EXIT_RES(res);
	return res;

out_error:
	res = -1;
	goto out;
}

static void scst_complete_request_sense(struct scst_cmd *req_cmd)
{
	struct scst_cmd *orig_cmd = req_cmd->orig_cmd;
	uint8_t *buf;
	int len;

	TRACE_ENTRY();

	sBUG_ON(orig_cmd == NULL);

	len = scst_get_buf_first(req_cmd, &buf);

	if (scsi_status_is_good(req_cmd->status) && (len > 0) &&
	    SCST_SENSE_VALID(buf) && (!SCST_NO_SENSE(buf))) {
		PRINT_BUFF_FLAG(TRACE_SCSI, "REQUEST SENSE returned",
			buf, len);
		scst_alloc_set_sense(orig_cmd, scst_cmd_atomic(req_cmd), buf,
			len);
	} else {
		PRINT_ERROR("%s", "Unable to get the sense via "
			"REQUEST SENSE, returning HARDWARE ERROR");
		scst_set_cmd_error(orig_cmd,
			SCST_LOAD_SENSE(scst_sense_hardw_error));
	}

	if (len > 0)
		scst_put_buf(req_cmd, buf);

	TRACE(TRACE_MGMT_MINOR, "Adding orig cmd %p to head of active "
		"cmd list", orig_cmd);
	spin_lock_irq(&orig_cmd->cmd_lists->cmd_list_lock);
	list_add(&orig_cmd->cmd_list_entry, &orig_cmd->cmd_lists->active_cmd_list);
	wake_up(&orig_cmd->cmd_lists->cmd_list_waitQ);
	spin_unlock_irq(&orig_cmd->cmd_lists->cmd_list_lock);

	TRACE_EXIT();
	return;
}

int scst_finish_internal_cmd(struct scst_cmd *cmd)
{
	int res;

	TRACE_ENTRY();

	sBUG_ON(!cmd->internal);

	if (cmd->cdb[0] == REQUEST_SENSE)
		scst_complete_request_sense(cmd);

	__scst_cmd_put(cmd);

	res = SCST_CMD_STATE_RES_CONT_NEXT;

	TRACE_EXIT_HRES(res);
	return res;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
static void scst_req_done(struct scsi_cmnd *scsi_cmd)
{
	struct scsi_request *req;

	TRACE_ENTRY();

	if (scsi_cmd && (req = scsi_cmd->sc_request)) {
		if (req) {
			if (req->sr_bufflen)
				kfree(req->sr_buffer);
			scsi_release_request(req);
		}
	}

	TRACE_EXIT();
	return;
}

static void scst_send_release(struct scst_device *dev)
{
	struct scsi_request *req;
	struct scsi_device *scsi_dev;
	uint8_t cdb[6];

	TRACE_ENTRY();

	if (dev->scsi_dev == NULL)
		goto out;

	scsi_dev = dev->scsi_dev;

	req = scsi_allocate_request(scsi_dev, GFP_KERNEL);
	if (req == NULL) {
		PRINT_ERROR("Allocation of scsi_request failed: unable "
			    "to RELEASE device %d:%d:%d:%d",
			    scsi_dev->host->host_no, scsi_dev->channel,
			    scsi_dev->id, scsi_dev->lun);
		goto out;
	}

	memset(cdb, 0, sizeof(cdb));
	cdb[0] = RELEASE;
	cdb[1] = (scsi_dev->scsi_level <= SCSI_2) ?
	    ((scsi_dev->lun << 5) & 0xe0) : 0;
	memcpy(req->sr_cmnd, cdb, sizeof(cdb));
	req->sr_cmd_len = sizeof(cdb);
	req->sr_data_direction = SCST_DATA_NONE;
	req->sr_use_sg = 0;
	req->sr_bufflen = 0;
	req->sr_buffer = NULL;
	req->sr_request->rq_disk = dev->rq_disk;
	req->sr_sense_buffer[0] = 0;

	TRACE(TRACE_DEBUG | TRACE_SCSI, "Sending RELEASE req %p to SCSI "
		"mid-level", req);
	scst_do_req(req, req->sr_cmnd, (void *)req->sr_buffer, req->sr_bufflen,
		    scst_req_done, 15, 3);

out:
	TRACE_EXIT();
	return;
}
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18) */
static void scst_send_release(struct scst_device *dev)
{
	struct scsi_device *scsi_dev;
	unsigned char cdb[6];
	uint8_t sense[SCSI_SENSE_BUFFERSIZE];
	int rc, i;

	TRACE_ENTRY();

	if (dev->scsi_dev == NULL)
		goto out;

	scsi_dev = dev->scsi_dev;

	for (i = 0; i < 5; i++) {
		memset(cdb, 0, sizeof(cdb));
		cdb[0] = RELEASE;
		cdb[1] = (scsi_dev->scsi_level <= SCSI_2) ?
		    ((scsi_dev->lun << 5) & 0xe0) : 0;

		memset(sense, 0, sizeof(sense));

		TRACE(TRACE_DEBUG | TRACE_SCSI, "%s", "Sending RELEASE req to "
			"SCSI mid-level");
		rc = scsi_execute(scsi_dev, cdb, SCST_DATA_NONE, NULL, 0,
				sense, 15, 0, 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
				, NULL
#endif
				);
		TRACE_DBG("MODE_SENSE done: %x", rc);

		if (scsi_status_is_good(rc)) {
			break;
		} else {
			PRINT_ERROR("RELEASE failed: %d", rc);
			PRINT_BUFFER("RELEASE sense", sense, sizeof(sense));
			scst_check_internal_sense(dev, rc, sense,
				sizeof(sense));
		}
	}

out:
	TRACE_EXIT();
	return;
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18) */

/* scst_mutex supposed to be held */
static void scst_clear_reservation(struct scst_tgt_dev *tgt_dev)
{
	struct scst_device *dev = tgt_dev->dev;
	int release = 0;

	TRACE_ENTRY();

	spin_lock_bh(&dev->dev_lock);
	if (dev->dev_reserved &&
	    !test_bit(SCST_TGT_DEV_RESERVED, &tgt_dev->tgt_dev_flags)) {
		/* This is one who holds the reservation */
		struct scst_tgt_dev *tgt_dev_tmp;
		list_for_each_entry(tgt_dev_tmp, &dev->dev_tgt_dev_list,
				    dev_tgt_dev_list_entry) {
			clear_bit(SCST_TGT_DEV_RESERVED,
				    &tgt_dev_tmp->tgt_dev_flags);
		}
		dev->dev_reserved = 0;
		release = 1;
	}
	spin_unlock_bh(&dev->dev_lock);

	if (release)
		scst_send_release(dev);

	TRACE_EXIT();
	return;
}

struct scst_session *scst_alloc_session(struct scst_tgt *tgt, gfp_t gfp_mask,
	const char *initiator_name)
{
	struct scst_session *sess;
	int i;
	int len;
	char *nm;

	TRACE_ENTRY();

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 17)
	sess = kmem_cache_alloc(scst_sess_cachep, gfp_mask);
#else
	sess = kmem_cache_zalloc(scst_sess_cachep, gfp_mask);
#endif
	if (sess == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s",
		      "Allocation of scst_session failed");
		goto out;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 17)
	memset(sess, 0, sizeof(*sess));
#endif

	sess->init_phase = SCST_SESS_IPH_INITING;
	sess->shut_phase = SCST_SESS_SPH_READY;
	atomic_set(&sess->refcnt, 0);
	for (i = 0; i < TGT_DEV_HASH_SIZE; i++) {
		struct list_head *sess_tgt_dev_list_head =
			 &sess->sess_tgt_dev_list_hash[i];
		INIT_LIST_HEAD(sess_tgt_dev_list_head);
	}
	spin_lock_init(&sess->sess_list_lock);
	INIT_LIST_HEAD(&sess->search_cmd_list);
	INIT_LIST_HEAD(&sess->after_pre_xmit_cmd_list);
	sess->tgt = tgt;
	INIT_LIST_HEAD(&sess->init_deferred_cmd_list);
	INIT_LIST_HEAD(&sess->init_deferred_mcmd_list);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20))
	INIT_DELAYED_WORK(&sess->hw_pending_work,
		(void (*)(struct work_struct *))scst_hw_pending_work_fn);
#else
	INIT_WORK(&sess->hw_pending_work, scst_hw_pending_work_fn, sess);
#endif

#ifdef CONFIG_SCST_MEASURE_LATENCY
	spin_lock_init(&sess->meas_lock);
#endif

	len = strlen(initiator_name);
	nm = kmalloc(len + 1, gfp_mask);
	if (nm == NULL) {
		PRINT_ERROR("%s", "Unable to allocate sess->initiator_name");
		goto out_free;
	}

	strcpy(nm, initiator_name);
	sess->initiator_name = nm;

out:
	TRACE_EXIT();
	return sess;

out_free:
	kmem_cache_free(scst_sess_cachep, sess);
	sess = NULL;
	goto out;
}

void scst_free_session(struct scst_session *sess)
{
	TRACE_ENTRY();

	mutex_lock(&scst_mutex);

	TRACE_DBG("Removing sess %p from the list", sess);
	list_del(&sess->sess_list_entry);
	TRACE_DBG("Removing session %p from acg %s", sess, sess->acg->acg_name);
	list_del(&sess->acg_sess_list_entry);

	scst_sess_free_tgt_devs(sess);

	wake_up_all(&sess->tgt->unreg_waitQ);

	mutex_unlock(&scst_mutex);

	kfree(sess->initiator_name);
	kmem_cache_free(scst_sess_cachep, sess);

	TRACE_EXIT();
	return;
}

void scst_free_session_callback(struct scst_session *sess)
{
	struct completion *c;

	TRACE_ENTRY();

	TRACE_DBG("Freeing session %p", sess);

	cancel_delayed_work_sync(&sess->hw_pending_work);

	c = sess->shutdown_compl;

	if (sess->unreg_done_fn) {
		TRACE_DBG("Calling unreg_done_fn(%p)", sess);
		sess->unreg_done_fn(sess);
		TRACE_DBG("%s", "unreg_done_fn() returned");
	}
	scst_free_session(sess);

	if (c)
		complete_all(c);

	TRACE_EXIT();
	return;
}

void scst_sched_session_free(struct scst_session *sess)
{
	unsigned long flags;

	TRACE_ENTRY();

	if (sess->shut_phase != SCST_SESS_SPH_SHUTDOWN) {
		PRINT_CRIT_ERROR("session %p is going to shutdown with unknown "
			"shut phase %lx", sess, sess->shut_phase);
		sBUG();
	}

	spin_lock_irqsave(&scst_mgmt_lock, flags);
	TRACE_DBG("Adding sess %p to scst_sess_shut_list", sess);
	list_add_tail(&sess->sess_shut_list_entry, &scst_sess_shut_list);
	spin_unlock_irqrestore(&scst_mgmt_lock, flags);

	wake_up(&scst_mgmt_waitQ);

	TRACE_EXIT();
	return;
}

void scst_cmd_get(struct scst_cmd *cmd)
{
	__scst_cmd_get(cmd);
}
EXPORT_SYMBOL(scst_cmd_get);

void scst_cmd_put(struct scst_cmd *cmd)
{
	__scst_cmd_put(cmd);
}
EXPORT_SYMBOL(scst_cmd_put);

struct scst_cmd *scst_alloc_cmd(gfp_t gfp_mask)
{
	struct scst_cmd *cmd;

	TRACE_ENTRY();

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 17)
	cmd = kmem_cache_alloc(scst_cmd_cachep, gfp_mask);
#else
	cmd = kmem_cache_zalloc(scst_cmd_cachep, gfp_mask);
#endif
	if (cmd == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of scst_cmd failed");
		goto out;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 17)
	memset(cmd, 0, sizeof(*cmd));
#endif

	cmd->state = SCST_CMD_STATE_INIT_WAIT;
	cmd->start_time = jiffies;
	atomic_set(&cmd->cmd_ref, 1);
	cmd->cmd_lists = &scst_main_cmd_lists;
	INIT_LIST_HEAD(&cmd->mgmt_cmd_list);
	cmd->queue_type = SCST_CMD_QUEUE_SIMPLE;
	cmd->timeout = SCST_DEFAULT_TIMEOUT;
	cmd->retries = 0;
	cmd->data_len = -1;
	cmd->is_send_status = 1;
	cmd->resp_data_len = -1;

	cmd->dbl_ua_orig_data_direction = SCST_DATA_UNKNOWN;
	cmd->dbl_ua_orig_resp_data_len = -1;

out:
	TRACE_EXIT();
	return cmd;
}

static void scst_destroy_put_cmd(struct scst_cmd *cmd)
{
	scst_sess_put(cmd->sess);

	/*
	 * At this point tgt_dev can be dead, but the pointer remains non-NULL
	 */
	if (likely(cmd->tgt_dev != NULL))
		__scst_put();

	scst_destroy_cmd(cmd);
	return;
}

/* No locks supposed to be held */
void scst_free_cmd(struct scst_cmd *cmd)
{
	int destroy = 1;

	TRACE_ENTRY();

	TRACE_DBG("Freeing cmd %p (tag %llu)",
		  cmd, (long long unsigned int)cmd->tag);

	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))) {
		TRACE_MGMT_DBG("Freeing aborted cmd %p (scst_cmd_count %d)",
			cmd, atomic_read(&scst_cmd_count));
	}

	sBUG_ON(cmd->inc_blocking || cmd->needs_unblocking ||
		cmd->dec_on_dev_needed);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
#if defined(CONFIG_SCST_EXTRACHECKS)
	if (cmd->scsi_req) {
		PRINT_ERROR("%s: %s", __func__, "Cmd with unfreed "
			"scsi_req!");
		scst_release_request(cmd);
	}
#endif
#endif

	/*
	 * Target driver can already free sg buffer before calling
	 * scst_tgt_cmd_done(). E.g., scst_local has to do that.
	 */
	if (!cmd->tgt_data_buf_alloced)
		scst_check_restore_sg_buff(cmd);

	if (cmd->tgtt->on_free_cmd != NULL) {
		TRACE_DBG("Calling target's on_free_cmd(%p)", cmd);
		cmd->tgtt->on_free_cmd(cmd);
		TRACE_DBG("%s", "Target's on_free_cmd() returned");
	}

	if (likely(cmd->dev != NULL)) {
		struct scst_dev_type *handler = cmd->dev->handler;
		if (handler->on_free_cmd != NULL) {
			TRACE_DBG("Calling dev handler %s on_free_cmd(%p)",
			      handler->name, cmd);
			handler->on_free_cmd(cmd);
			TRACE_DBG("Dev handler %s on_free_cmd() returned",
				handler->name);
		}
	}

	scst_release_space(cmd);

	if (unlikely(cmd->sense != NULL)) {
		TRACE_MEM("Releasing sense %p (cmd %p)", cmd->sense, cmd);
		mempool_free(cmd->sense, scst_sense_mempool);
		cmd->sense = NULL;
	}

	if (likely(cmd->tgt_dev != NULL)) {
#ifdef CONFIG_SCST_EXTRACHECKS
		if (unlikely(!cmd->sent_for_exec) && !cmd->internal) {
			PRINT_ERROR("Finishing not executed cmd %p (opcode "
			    "%d, target %s, LUN %lld, sn %ld, expected_sn %ld)",
			    cmd, cmd->cdb[0], cmd->tgtt->name,
			    (long long unsigned int)cmd->lun,
			    cmd->sn, cmd->tgt_dev->expected_sn);
			scst_unblock_deferred(cmd->tgt_dev, cmd);
		}
#endif

		if (unlikely(cmd->out_of_sn)) {
			TRACE_SN("Out of SN cmd %p (tag %llu, sn %ld), "
				"destroy=%d", cmd,
				(long long unsigned int)cmd->tag,
				cmd->sn, destroy);
			destroy = test_and_set_bit(SCST_CMD_CAN_BE_DESTROYED,
					&cmd->cmd_flags);
		}
	}

	if (likely(destroy))
		scst_destroy_put_cmd(cmd);

	TRACE_EXIT();
	return;
}

/* No locks supposed to be held. */
void scst_check_retries(struct scst_tgt *tgt)
{
	int need_wake_up = 0;

	TRACE_ENTRY();

	/*
	 * We don't worry about overflow of finished_cmds, because we check
	 * only for its change.
	 */
	atomic_inc(&tgt->finished_cmds);
	/* See comment in scst_queue_retry_cmd() */
	smp_mb__after_atomic_inc();
	if (unlikely(tgt->retry_cmds > 0)) {
		struct scst_cmd *c, *tc;
		unsigned long flags;

		TRACE_RETRY("Checking retry cmd list (retry_cmds %d)",
		      tgt->retry_cmds);

		spin_lock_irqsave(&tgt->tgt_lock, flags);
		list_for_each_entry_safe(c, tc, &tgt->retry_cmd_list,
				cmd_list_entry) {
			tgt->retry_cmds--;

			TRACE_RETRY("Moving retry cmd %p to head of active "
				"cmd list (retry_cmds left %d)",
				c, tgt->retry_cmds);
			spin_lock(&c->cmd_lists->cmd_list_lock);
			list_move(&c->cmd_list_entry,
				  &c->cmd_lists->active_cmd_list);
			wake_up(&c->cmd_lists->cmd_list_waitQ);
			spin_unlock(&c->cmd_lists->cmd_list_lock);

			need_wake_up++;
			if (need_wake_up >= 2) /* "slow start" */
				break;
		}
		spin_unlock_irqrestore(&tgt->tgt_lock, flags);
	}

	TRACE_EXIT();
	return;
}

void scst_tgt_retry_timer_fn(unsigned long arg)
{
	struct scst_tgt *tgt = (struct scst_tgt *)arg;
	unsigned long flags;

	TRACE_RETRY("Retry timer expired (retry_cmds %d)", tgt->retry_cmds);

	spin_lock_irqsave(&tgt->tgt_lock, flags);
	tgt->retry_timer_active = 0;
	spin_unlock_irqrestore(&tgt->tgt_lock, flags);

	scst_check_retries(tgt);

	TRACE_EXIT();
	return;
}

struct scst_mgmt_cmd *scst_alloc_mgmt_cmd(gfp_t gfp_mask)
{
	struct scst_mgmt_cmd *mcmd;

	TRACE_ENTRY();

	mcmd = mempool_alloc(scst_mgmt_mempool, gfp_mask);
	if (mcmd == NULL) {
		PRINT_CRIT_ERROR("%s", "Allocation of management command "
			"failed, some commands and their data could leak");
		goto out;
	}
	memset(mcmd, 0, sizeof(*mcmd));

out:
	TRACE_EXIT();
	return mcmd;
}

void scst_free_mgmt_cmd(struct scst_mgmt_cmd *mcmd)
{
	unsigned long flags;

	TRACE_ENTRY();

	spin_lock_irqsave(&mcmd->sess->sess_list_lock, flags);
	atomic_dec(&mcmd->sess->sess_cmd_count);
	spin_unlock_irqrestore(&mcmd->sess->sess_list_lock, flags);

	scst_sess_put(mcmd->sess);

	if (mcmd->mcmd_tgt_dev != NULL)
		__scst_put();

	mempool_free(mcmd, scst_mgmt_mempool);

	TRACE_EXIT();
	return;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
int scst_alloc_request(struct scst_cmd *cmd)
{
	int res = 0;
	struct scsi_request *req;
	int gm = scst_cmd_atomic(cmd) ? GFP_ATOMIC : GFP_KERNEL;

	TRACE_ENTRY();

	/* cmd->dev->scsi_dev must be non-NULL here */
	req = scsi_allocate_request(cmd->dev->scsi_dev, gm);
	if (req == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s",
		      "Allocation of scsi_request failed");
		res = -ENOMEM;
		goto out;
	}

	cmd->scsi_req = req;

	memcpy(req->sr_cmnd, cmd->cdb, cmd->cdb_len);
	req->sr_cmd_len = cmd->cdb_len;
	req->sr_data_direction = cmd->data_direction;
	req->sr_use_sg = cmd->sg_cnt;
	req->sr_bufflen = cmd->bufflen;
	req->sr_buffer = cmd->sg;
	req->sr_request->rq_disk = cmd->dev->rq_disk;
	req->sr_sense_buffer[0] = 0;

	cmd->scsi_req->upper_private_data = cmd;

out:
	TRACE_EXIT();
	return res;
}

void scst_release_request(struct scst_cmd *cmd)
{
	scsi_release_request(cmd->scsi_req);
	cmd->scsi_req = NULL;
}
#endif

static bool is_report_sg_limitation(void)
{
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	return (trace_flag & TRACE_OUT_OF_MEM) != 0;
#else
	return false;
#endif
}

int scst_alloc_space(struct scst_cmd *cmd)
{
	gfp_t gfp_mask;
	int res = -ENOMEM;
	int atomic = scst_cmd_atomic(cmd);
	int flags;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	static int ll;

	TRACE_ENTRY();

	gfp_mask = tgt_dev->gfp_mask | (atomic ? GFP_ATOMIC : GFP_KERNEL);

	flags = atomic ? SGV_POOL_NO_ALLOC_ON_CACHE_MISS : 0;
	if (cmd->no_sgv)
		flags |= SGV_POOL_ALLOC_NO_CACHED;

	cmd->sg = sgv_pool_alloc(tgt_dev->pool, cmd->bufflen, gfp_mask, flags,
			&cmd->sg_cnt, &cmd->sgv, &cmd->dev->dev_mem_lim, NULL);
	if (cmd->sg == NULL)
		goto out;

	if (unlikely(cmd->sg_cnt > tgt_dev->max_sg_cnt)) {
		if ((ll < 10) || is_report_sg_limitation()) {
			PRINT_INFO("Unable to complete command due to "
				"SG IO count limitation (requested %d, "
				"available %d, tgt lim %d)", cmd->sg_cnt,
				tgt_dev->max_sg_cnt, cmd->tgt->sg_tablesize);
			ll++;
		}
		goto out_sg_free;
	}

	if (cmd->data_direction != SCST_DATA_BIDI)
		goto success;

	cmd->in_sg = sgv_pool_alloc(tgt_dev->pool, cmd->in_bufflen, gfp_mask,
			 flags, &cmd->in_sg_cnt, &cmd->in_sgv,
			 &cmd->dev->dev_mem_lim, NULL);
	if (cmd->in_sg == NULL)
		goto out_sg_free;

	if (unlikely(cmd->in_sg_cnt > tgt_dev->max_sg_cnt)) {
		if ((ll < 10)  || is_report_sg_limitation()) {
			PRINT_INFO("Unable to complete command due to "
				"SG IO count limitation (IN buffer, requested "
				"%d, available %d, tgt lim %d)", cmd->in_sg_cnt,
				tgt_dev->max_sg_cnt, cmd->tgt->sg_tablesize);
			ll++;
		}
		goto out_in_sg_free;
	}

success:
	res = 0;

out:
	TRACE_EXIT();
	return res;

out_in_sg_free:
	sgv_pool_free(cmd->in_sgv, &cmd->dev->dev_mem_lim);
	cmd->in_sgv = NULL;
	cmd->in_sg = NULL;
	cmd->in_sg_cnt = 0;

out_sg_free:
	sgv_pool_free(cmd->sgv, &cmd->dev->dev_mem_lim);
	cmd->sgv = NULL;
	cmd->sg = NULL;
	cmd->sg_cnt = 0;
	goto out;
}

static void scst_release_space(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	if (cmd->sgv == NULL)
		goto out;

	if (cmd->tgt_data_buf_alloced || cmd->dh_data_buf_alloced) {
		TRACE_MEM("%s", "*data_buf_alloced set, returning");
		goto out;
	}

	sgv_pool_free(cmd->sgv, &cmd->dev->dev_mem_lim);
	cmd->sgv = NULL;
	cmd->sg_cnt = 0;
	cmd->sg = NULL;
	cmd->bufflen = 0;
	cmd->data_len = 0;

	if (cmd->in_sgv != NULL) {
		sgv_pool_free(cmd->in_sgv, &cmd->dev->dev_mem_lim);
		cmd->in_sgv = NULL;
		cmd->in_sg_cnt = 0;
		cmd->in_sg = NULL;
		cmd->in_bufflen = 0;
	}

out:
	TRACE_EXIT();
	return;
}

#if !((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)) && defined(SCSI_EXEC_REQ_FIFO_DEFINED))

/*
 * Can switch to the next dst_sg element, so, to copy to strictly only
 * one dst_sg element, it must be either last in the chain, or
 * copy_len == dst_sg->length.
 */
static int sg_copy_elem(struct scatterlist **pdst_sg, size_t *pdst_len,
			size_t *pdst_offs, struct scatterlist *src_sg,
			size_t copy_len,
			enum km_type d_km_type, enum km_type s_km_type)
{
	int res = 0;
	struct scatterlist *dst_sg;
	size_t src_len, dst_len, src_offs, dst_offs;
	struct page *src_page, *dst_page;

	dst_sg = *pdst_sg;
	dst_len = *pdst_len;
	dst_offs = *pdst_offs;
	dst_page = sg_page(dst_sg);

	src_page = sg_page(src_sg);
	src_len = src_sg->length;
	src_offs = src_sg->offset;

	do {
		void *saddr, *daddr;
		size_t n;

		saddr = kmap_atomic(src_page +
					 (src_offs >> PAGE_SHIFT), s_km_type) +
				    (src_offs & ~PAGE_MASK);
		daddr = kmap_atomic(dst_page +
					(dst_offs >> PAGE_SHIFT), d_km_type) +
				    (dst_offs & ~PAGE_MASK);

		if (((src_offs & ~PAGE_MASK) == 0) &&
		    ((dst_offs & ~PAGE_MASK) == 0) &&
		    (src_len >= PAGE_SIZE) && (dst_len >= PAGE_SIZE) &&
		    (copy_len >= PAGE_SIZE)) {
			copy_page(daddr, saddr);
			n = PAGE_SIZE;
		} else {
			n = min_t(size_t, PAGE_SIZE - (dst_offs & ~PAGE_MASK),
					  PAGE_SIZE - (src_offs & ~PAGE_MASK));
			n = min(n, src_len);
			n = min(n, dst_len);
			n = min_t(size_t, n, copy_len);
			memcpy(daddr, saddr, n);
		}
		dst_offs += n;
		src_offs += n;

		kunmap_atomic(saddr, s_km_type);
		kunmap_atomic(daddr, d_km_type);

		res += n;
		copy_len -= n;
		if (copy_len == 0)
			goto out;

		src_len -= n;
		dst_len -= n;
		if (dst_len == 0) {
			dst_sg = sg_next(dst_sg);
			if (dst_sg == NULL)
				goto out;
			dst_page = sg_page(dst_sg);
			dst_len = dst_sg->length;
			dst_offs = dst_sg->offset;
		}
	} while (src_len > 0);

out:
	*pdst_sg = dst_sg;
	*pdst_len = dst_len;
	*pdst_offs = dst_offs;
	return res;
}

/**
 * sg_copy - copy one SG vector to another
 * @dst_sg:	destination SG
 * @src_sg:	source SG
 * @nents_to_copy: maximum number of entries to copy
 * @copy_len:	maximum amount of data to copy. If 0, then copy all.
 * @d_km_type:	kmap_atomic type for the destination SG
 * @s_km_type:	kmap_atomic type for the source SG
 *
 * Description:
 *    Data from the source SG vector will be copied to the destination SG
 *    vector. End of the vectors will be determined by sg_next() returning
 *    NULL. Returns number of bytes copied.
 */
static int sg_copy(struct scatterlist *dst_sg, struct scatterlist *src_sg,
	    int nents_to_copy, size_t copy_len,
	    enum km_type d_km_type, enum km_type s_km_type)
{
	int res = 0;
	size_t dst_len, dst_offs;

	if (copy_len == 0)
		copy_len = 0x7FFFFFFF; /* copy all */

	if (nents_to_copy == 0)
		nents_to_copy = 0x7FFFFFFF; /* copy all */

	dst_len = dst_sg->length;
	dst_offs = dst_sg->offset;

	do {
		int copied = sg_copy_elem(&dst_sg, &dst_len, &dst_offs,
				src_sg, copy_len, d_km_type, s_km_type);
		copy_len -= copied;
		res += copied;
		if ((copy_len == 0) || (dst_sg == NULL))
			goto out;

		nents_to_copy--;
		if (nents_to_copy == 0)
			goto out;

		src_sg = sg_next(src_sg);
	} while (src_sg != NULL);

out:
	return res;
}

#endif /* !((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)) && defined(SCSI_EXEC_REQ_FIFO_DEFINED)) */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26) && !((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)) && defined(SCSI_EXEC_REQ_FIFO_DEFINED))

#include <linux/pfn.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
static inline int object_is_on_stack(void *obj)
{
	void *stack = task_stack_page(current);

	return (obj >= stack) && (obj < (stack + THREAD_SIZE));
}
#endif

struct blk_kern_sg_work {
	atomic_t bios_inflight;
	struct sg_table sg_table;
	struct scatterlist *src_sgl;
};

static void blk_rq_unmap_kern_sg(struct request *rq, int err);

static void blk_free_kern_sg_work(struct blk_kern_sg_work *bw)
{
	TRACE_DBG("Freeing bw %p", bw);
	sg_free_table(&bw->sg_table);
	kfree(bw);
	return;
}

static void blk_bio_map_kern_endio(struct bio *bio, int err)
{
	struct blk_kern_sg_work *bw = bio->bi_private;

	TRACE_DBG("bio %p finished", bio);

	if (bw != NULL) {
		/* Decrement the bios in processing and, if zero, free */
		BUG_ON(atomic_read(&bw->bios_inflight) <= 0);
		if (atomic_dec_and_test(&bw->bios_inflight)) {
			TRACE_DBG("sgl %p, new_sgl %p, new_sgl_nents %d",
				bw->src_sgl, bw->sg_table.sgl,
				bw->sg_table.nents);
			if ((bio_data_dir(bio) == READ) && (err == 0)) {
				unsigned long flags;

				TRACE_DBG("Copying sgl %p (nents %d) to "
					"orig_sgl %p", bw->sg_table.sgl,
					bw->sg_table.nents, bw->src_sgl);

				local_irq_save(flags);	/* to protect KMs */
				sg_copy(bw->src_sgl, bw->sg_table.sgl, 0, 0,
					KM_BIO_DST_IRQ, KM_BIO_SRC_IRQ);
				local_irq_restore(flags);
			}
			blk_free_kern_sg_work(bw);
		}
	}

	bio_put(bio);
	return;
}

static int blk_rq_copy_kern_sg(struct request *rq, struct scatterlist *sgl,
			       int nents, struct blk_kern_sg_work **pbw,
			       gfp_t gfp, gfp_t page_gfp)
{
	int res = 0, i;
	struct scatterlist *sg;
	struct scatterlist *new_sgl;
	int new_sgl_nents;
	size_t len = 0, to_copy;
	struct blk_kern_sg_work *bw;

	bw = kzalloc(sizeof(*bw), gfp);
	if (bw == NULL) {
		PRINT_ERROR("%s", "Unable to alloc blk_kern_sg_work");
		goto out;
	}

	bw->src_sgl = sgl;

	for_each_sg(sgl, sg, nents, i)
		len += sg->length;
	to_copy = len;

	new_sgl_nents = PFN_UP(len);

	res = sg_alloc_table(&bw->sg_table, new_sgl_nents, gfp);
	if (res != 0) {
		PRINT_ERROR("Unable to alloc copy sg table (nents %d)",
			new_sgl_nents);
		goto out_free_bw;
	}

	new_sgl = bw->sg_table.sgl;

	TRACE_DBG("sgl %p, nents %d, to_copy %lld, new_sgl %p, new_sgl_nents %d",
		sgl, nents, (long long)to_copy, new_sgl, new_sgl_nents);

	for_each_sg(new_sgl, sg, new_sgl_nents, i) {
		struct page *pg;

		pg = alloc_page(page_gfp);
		if (pg == NULL) {
			PRINT_ERROR("Unable to alloc copy page (left %lld)",
				(long long)len);
			goto err_free_new_sgl;
		}

		sg_assign_page(sg, pg);
		sg->length = min_t(size_t, PAGE_SIZE, len);

		len -= PAGE_SIZE;
	}

	if (rq_data_dir(rq) == WRITE) {
		/*
		 * We need to limit amount of copied data to to_copy, because
		 * sgl might have the last element in sgl not marked as last in
		 * SG chaining.
		 */
		TRACE_DBG("Copying sgl %p (nents %d) to new_sgl %p "
			"(new_sgl_nents %d), to_copy %lld", sgl, nents,
			new_sgl, new_sgl_nents, (long long)to_copy);
		sg_copy(new_sgl, sgl, 0, to_copy,
			KM_USER0, KM_USER1);
	}

	*pbw = bw;
	/*
	 * REQ_COPY_USER name is misleading. It should be something like
	 * REQ_HAS_TAIL_SPACE_FOR_PADDING.
	 */
	rq->cmd_flags |= REQ_COPY_USER;

out:
	return res;

err_free_new_sgl:
	for_each_sg(new_sgl, sg, new_sgl_nents, i) {
		struct page *pg = sg_page(sg);
		if (pg == NULL)
			break;
		__free_page(pg);
	}
	sg_free_table(&bw->sg_table);

out_free_bw:
	kfree(bw);
	res = -ENOMEM;
	goto out;
}

static int __blk_rq_map_kern_sg(struct request *rq, struct scatterlist *sgl,
	int nents, struct blk_kern_sg_work *bw, gfp_t gfp)
{
	int res = 0;
	struct request_queue *q = rq->q;
	int rw = rq_data_dir(rq);
	int max_nr_vecs, i;
	size_t tot_len;
	bool need_new_bio;
	struct scatterlist *sg, *prev_sg = NULL;
	struct bio *bio = NULL, *hbio = NULL, *tbio = NULL;
	int bios;

	if (unlikely((sgl == NULL) || (sgl->length == 0) || (nents <= 0))) {
		WARN_ON(1);
		res = -EINVAL;
		goto out;
	}

	/*
	 * Let's keep each bio allocation inside a single page to decrease
	 * probability of failure.
	 */
	max_nr_vecs =  min_t(size_t,
		((PAGE_SIZE - sizeof(struct bio)) / sizeof(struct bio_vec)),
		BIO_MAX_PAGES);

	TRACE_DBG("sgl %p, nents %d, bw %p, max_nr_vecs %d", sgl, nents, bw,
		max_nr_vecs);

	need_new_bio = true;
	tot_len = 0;
	bios = 0;
	for_each_sg(sgl, sg, nents, i) {
		struct page *page = sg_page(sg);
		void *page_addr = page_address(page);
		size_t len = sg->length, l;
		size_t offset = sg->offset;

		tot_len += len;
		prev_sg = sg;

		/*
		 * Each segment must be aligned on DMA boundary and
		 * not on stack. The last one may have unaligned
		 * length as long as the total length is aligned to
		 * DMA padding alignment.
		 */
		if (i == nents - 1)
			l = 0;
		else
			l = len;
		if (((sg->offset | l) & queue_dma_alignment(q)) ||
		    (page_addr && object_is_on_stack(page_addr + sg->offset))) {
			TRACE_DBG("%s", "DMA alignment or offset don't match");
			res = -EINVAL;
			goto out_free_bios;
		}

		while (len > 0) {
			size_t bytes;
			int rc;

			if (need_new_bio) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
				bio = bio_kmalloc(gfp, max_nr_vecs);
#else
				bio = bio_alloc(gfp, max_nr_vecs);
#endif
				if (bio == NULL) {
					PRINT_ERROR("%s", "Can't to alloc bio");
					res = -ENOMEM;
					goto out_free_bios;
				}

				TRACE_DBG("bio %p alloced", bio);

				if (rw == WRITE)
					bio->bi_rw |= 1 << BIO_RW;

				bios++;
				bio->bi_private = bw;
				bio->bi_end_io = blk_bio_map_kern_endio;

				if (hbio == NULL)
					hbio = tbio = bio;
				else
					tbio = tbio->bi_next = bio;
			}

			bytes = min_t(size_t, len, PAGE_SIZE - offset);

			rc = bio_add_pc_page(q, bio, page, bytes, offset);
			if (rc < bytes) {
				if (unlikely(need_new_bio || (rc < 0))) {
					if (rc < 0)
						res = rc;
					else
						res = -EIO;
					PRINT_ERROR("bio_add_pc_page() failed: "
						"%d", rc);
					goto out_free_bios;
				} else {
					need_new_bio = true;
					len -= rc;
					offset += rc;
					continue;
				}
			}

			need_new_bio = false;
			offset = 0;
			len -= bytes;
			page = nth_page(page, 1);
		}
	}

	if (hbio == NULL) {
		res = -EINVAL;
		goto out_free_bios;
	}

	/* Total length must be aligned on DMA padding alignment */
	if ((tot_len & q->dma_pad_mask) &&
	    !(rq->cmd_flags & REQ_COPY_USER)) {
		TRACE_DBG("Total len %lld doesn't match DMA pad mask %x",
			(long long)tot_len, q->dma_pad_mask);
		res = -EINVAL;
		goto out_free_bios;
	}

	if (bw != NULL)
		atomic_set(&bw->bios_inflight, bios);

	while (hbio != NULL) {
		bio = hbio;
		hbio = hbio->bi_next;
		bio->bi_next = NULL;

		blk_queue_bounce(q, &bio);

		res = blk_rq_append_bio(q, rq, bio);
		if (unlikely(res != 0)) {
			PRINT_ERROR("blk_rq_append_bio() failed: %d", res);
			bio->bi_next = hbio;
			hbio = bio;
			/* We can have one or more bios bounced */
			goto out_unmap_bios;
		}
	}

	rq->buffer = rq->data = NULL;
out:
	return res;

out_free_bios:
	while (hbio != NULL) {
		bio = hbio;
		hbio = hbio->bi_next;
		bio_put(bio);
	}
	goto out;

out_unmap_bios:
	blk_rq_unmap_kern_sg(rq, res);
	goto out;
}

/**
 * blk_rq_map_kern_sg - map kernel data to a request, for REQ_TYPE_BLOCK_PC
 * @rq:		request to fill
 * @sgl:	area to map
 * @nents:	number of elements in @sgl
 * @gfp:	memory allocation flags
 *
 * Description:
 *    Data will be mapped directly if possible. Otherwise a bounce
 *    buffer will be used.
 */
static int blk_rq_map_kern_sg(struct request *rq, struct scatterlist *sgl,
		       int nents, gfp_t gfp)
{
	int res;

	res = __blk_rq_map_kern_sg(rq, sgl, nents, NULL, gfp);
	if (unlikely(res != 0)) {
		struct blk_kern_sg_work *bw = NULL;

		TRACE_DBG("__blk_rq_map_kern_sg() failed: %d", res);

		res = blk_rq_copy_kern_sg(rq, sgl, nents, &bw,
				gfp, rq->q->bounce_gfp | gfp);
		if (unlikely(res != 0))
			goto out;

		res = __blk_rq_map_kern_sg(rq, bw->sg_table.sgl,
				bw->sg_table.nents, bw, gfp);
		if (res != 0) {
			TRACE_DBG("Copied __blk_rq_map_kern_sg() failed: %d",
				res);
			blk_free_kern_sg_work(bw);
			goto out;
		}
	}

	rq->buffer = rq->data = NULL;

out:
	return res;
}

/**
 * blk_rq_unmap_kern_sg - unmap a request with kernel sg
 * @rq:		request to unmap
 * @err:	non-zero error code
 *
 * Description:
 *    Unmap a rq previously mapped by blk_rq_map_kern_sg(). Must be called
 *    only in case of an error!
 */
static void blk_rq_unmap_kern_sg(struct request *rq, int err)
{
	struct bio *bio = rq->bio;

	while (bio) {
		struct bio *b = bio;
		bio = bio->bi_next;
		b->bi_end_io(b, err);
	}
	rq->bio = NULL;

	return;
}

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26) && !(LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30) && defined(SCSI_EXEC_REQ_FIFO_DEFINED)) */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)

static void scsi_end_async(struct request *req, int error)
{
	struct scsi_io_context *sioc = req->end_io_data;

	TRACE_DBG("sioc %p, cmd %p", sioc, sioc->data);

	if (sioc->done)
		sioc->done(sioc->data, sioc->sense, req->errors, req->data_len);

	if (!sioc->full_cdb_used)
		kmem_cache_free(scsi_io_context_cache, sioc);
	else
		kfree(sioc);

	__blk_put_request(req->q, req);
	return;
}

/**
 * scst_scsi_exec_async - executes a SCSI command in pass-through mode
 * @cmd:	scst command
 * @done:	callback function when done
 */
int scst_scsi_exec_async(struct scst_cmd *cmd,
		       void (*done)(void *, char *, int, int))
{
	int res = 0;
	struct request_queue *q = cmd->dev->scsi_dev->request_queue;
	struct request *rq;
	struct scsi_io_context *sioc;
	int write = (cmd->data_direction & SCST_DATA_WRITE) ? WRITE : READ;
	gfp_t gfp = scst_cmd_atomic(cmd) ? GFP_ATOMIC : GFP_KERNEL;
	int cmd_len = cmd->cdb_len;

	if (cmd->ext_cdb_len == 0) {
		TRACE_DBG("Simple CDB (cmd_len %d)", cmd_len);
		sioc = kmem_cache_zalloc(scsi_io_context_cache, gfp);
		if (sioc == NULL) {
			res = -ENOMEM;
			goto out;
		}
	} else {
		cmd_len += cmd->ext_cdb_len;

		TRACE_DBG("Extended CDB (cmd_len %d)", cmd_len);

		sioc = kzalloc(sizeof(*sioc) + cmd_len, gfp);
		if (sioc == NULL) {
			res = -ENOMEM;
			goto out;
		}

		sioc->full_cdb_used = 1;

		memcpy(sioc->full_cdb, cmd->cdb, cmd->cdb_len);
		memcpy(&sioc->full_cdb[cmd->cdb_len], cmd->ext_cdb,
			cmd->ext_cdb_len);
	}

	rq = blk_get_request(q, write, gfp);
	if (rq == NULL) {
		res = -ENOMEM;
		goto out_free_sioc;
	}

	rq->cmd_type = REQ_TYPE_BLOCK_PC;
	rq->cmd_flags |= REQ_QUIET;

	if (cmd->sg != NULL) {
		res = blk_rq_map_kern_sg(rq, cmd->sg, cmd->sg_cnt, gfp);
		if (res) {
			TRACE_DBG("blk_rq_map_kern_sg() failed: %d", res);
			goto out_free_rq;
		}
	}

	if (cmd->data_direction  == SCST_DATA_BIDI) {
		struct request *next_rq;

		if (!test_bit(QUEUE_FLAG_BIDI, &q->queue_flags)) {
			res = -EOPNOTSUPP;
			goto out_free_unmap;
		}

		next_rq = blk_get_request(q, READ, gfp);
		if (next_rq == NULL) {
			res = -ENOMEM;
			goto out_free_unmap;
		}
		rq->next_rq = next_rq;
		next_rq->cmd_type = rq->cmd_type;

		res = blk_rq_map_kern_sg(next_rq, cmd->in_sg,
			cmd->in_sg_cnt, gfp);
		if (res != 0)
			goto out_free_unmap;
	}

	TRACE_DBG("sioc %p, cmd %p", sioc, cmd);

	sioc->data = cmd;
	sioc->done = done;

	rq->cmd_len = cmd_len;
	if (cmd->ext_cdb_len == 0) {
		memset(rq->cmd, 0, BLK_MAX_CDB); /* ATAPI hates garbage after CDB */
		memcpy(rq->cmd, cmd->cdb, cmd->cdb_len);
	} else
		rq->cmd = sioc->full_cdb;

	rq->sense = sioc->sense;
	rq->sense_len = sizeof(sioc->sense);
	rq->timeout = cmd->timeout;
	rq->retries = cmd->retries;
	rq->end_io_data = sioc;

	blk_execute_rq_nowait(rq->q, NULL, rq,
		(cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE), scsi_end_async);
out:
	return res;

out_free_unmap:
	if (rq->next_rq != NULL) {
		blk_put_request(rq->next_rq);
		rq->next_rq = NULL;
	}
	blk_rq_unmap_kern_sg(rq, res);

out_free_rq:
	blk_put_request(rq);

out_free_sioc:
	if (!sioc->full_cdb_used)
		kmem_cache_free(scsi_io_context_cache, sioc);
	else
		kfree(sioc);
	goto out;
}

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26) */

void scst_copy_sg(struct scst_cmd *cmd, enum scst_sg_copy_dir copy_dir)
{
	struct scatterlist *src_sg, *dst_sg;
	unsigned int to_copy;
	int atomic = scst_cmd_atomic(cmd);

	TRACE_ENTRY();

	if (copy_dir == SCST_SG_COPY_FROM_TARGET) {
		if (cmd->data_direction != SCST_DATA_BIDI) {
			src_sg = cmd->tgt_sg;
			dst_sg = cmd->sg;
			to_copy = cmd->bufflen;
		} else {
			TRACE_MEM("BIDI cmd %p", cmd);
			src_sg = cmd->tgt_in_sg;
			dst_sg = cmd->in_sg;
			to_copy = cmd->in_bufflen;
		}
	} else {
		src_sg = cmd->sg;
		dst_sg = cmd->tgt_sg;
		to_copy = cmd->resp_data_len;
	}

	TRACE_MEM("cmd %p, copy_dir %d, src_sg %p, dst_sg %p, to_copy %lld",
		cmd, copy_dir, src_sg, dst_sg, (long long)to_copy);

	if (unlikely(src_sg == NULL) || unlikely(dst_sg == NULL)) {
		/*
		 * It can happened, e.g., with scst_user for cmd with delay
		 * alloc, which failed with Check Condition.
		 */
		goto out;
	}

	sg_copy(dst_sg, src_sg, 0, to_copy,
		atomic ? KM_SOFTIRQ0 : KM_USER0,
		atomic ? KM_SOFTIRQ1 : KM_USER1);

out:
	TRACE_EXIT();
	return;
}

static const int SCST_CDB_LENGTH[8] = { 6, 10, 10, -1, 16, 12, -1, -1 };

#define SCST_CDB_GROUP(opcode)   ((opcode >> 5) & 0x7)
#define SCST_GET_CDB_LEN(opcode) SCST_CDB_LENGTH[SCST_CDB_GROUP(opcode)]

int scst_get_cdb_len(const uint8_t *cdb)
{
	return SCST_GET_CDB_LEN(cdb[0]);
}

/* get_trans_len_x extract x bytes from cdb as length starting from off */

static int get_trans_cdb_len_10(struct scst_cmd *cmd, uint8_t off)
{
	cmd->cdb_len = 10;
	cmd->bufflen = 0;
	return 0;
}

static int get_trans_len_block_limit(struct scst_cmd *cmd, uint8_t off)
{
	cmd->bufflen = 6;
	return 0;
}

static int get_trans_len_read_capacity(struct scst_cmd *cmd, uint8_t off)
{
	cmd->bufflen = READ_CAP_LEN;
	return 0;
}

static int get_trans_len_serv_act_in(struct scst_cmd *cmd, uint8_t off)
{
	int res = 0;

	TRACE_ENTRY();

	if ((cmd->cdb[1] & 0x1f) == SAI_READ_CAPACITY_16) {
		cmd->op_name = "READ CAPACITY(16)";
		cmd->bufflen = READ_CAP16_LEN;
		cmd->op_flags |= SCST_IMPLICIT_HQ;
	} else
		cmd->op_flags |= SCST_UNKNOWN_LENGTH;

	TRACE_EXIT_RES(res);
	return res;
}

static int get_trans_len_single(struct scst_cmd *cmd, uint8_t off)
{
	cmd->bufflen = 1;
	return 0;
}

static int get_trans_len_read_pos(struct scst_cmd *cmd, uint8_t off)
{
	uint8_t *p = (uint8_t *)cmd->cdb + off;
	int res = 0;

	cmd->bufflen = 0;
	cmd->bufflen |= ((u32)p[0]) << 8;
	cmd->bufflen |= ((u32)p[1]);

	switch (cmd->cdb[1] & 0x1f) {
	case 0:
	case 1:
	case 6:
		if (cmd->bufflen != 0) {
			PRINT_ERROR("READ POSITION: Invalid non-zero (%d) "
				"allocation length for service action %x",
				cmd->bufflen, cmd->cdb[1] & 0x1f);
			goto out_inval;
		}
		break;
	}

	switch (cmd->cdb[1] & 0x1f) {
	case 0:
	case 1:
		cmd->bufflen = 20;
		break;
	case 6:
		cmd->bufflen = 32;
		break;
	case 8:
		cmd->bufflen = max(28, cmd->bufflen);
		break;
	default:
		PRINT_ERROR("READ POSITION: Invalid service action %x",
			cmd->cdb[1] & 0x1f);
		goto out_inval;
	}

out:
	return res;

out_inval:
	scst_set_cmd_error(cmd,
		SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
	res = 1;
	goto out;
}

static int get_trans_len_1(struct scst_cmd *cmd, uint8_t off)
{
	cmd->bufflen = (u32)cmd->cdb[off];
	return 0;
}

static int get_trans_len_1_256(struct scst_cmd *cmd, uint8_t off)
{
	cmd->bufflen = (u32)cmd->cdb[off];
	if (cmd->bufflen == 0)
		cmd->bufflen = 256;
	return 0;
}

static int get_trans_len_2(struct scst_cmd *cmd, uint8_t off)
{
	const uint8_t *p = cmd->cdb + off;

	cmd->bufflen = 0;
	cmd->bufflen |= ((u32)p[0]) << 8;
	cmd->bufflen |= ((u32)p[1]);

	return 0;
}

static int get_trans_len_3(struct scst_cmd *cmd, uint8_t off)
{
	const uint8_t *p = cmd->cdb + off;

	cmd->bufflen = 0;
	cmd->bufflen |= ((u32)p[0]) << 16;
	cmd->bufflen |= ((u32)p[1]) << 8;
	cmd->bufflen |= ((u32)p[2]);

	return 0;
}

static int get_trans_len_4(struct scst_cmd *cmd, uint8_t off)
{
	const uint8_t *p = cmd->cdb + off;

	cmd->bufflen = 0;
	cmd->bufflen |= ((u32)p[0]) << 24;
	cmd->bufflen |= ((u32)p[1]) << 16;
	cmd->bufflen |= ((u32)p[2]) << 8;
	cmd->bufflen |= ((u32)p[3]);

	return 0;
}

static int get_trans_len_none(struct scst_cmd *cmd, uint8_t off)
{
	cmd->bufflen = 0;
	return 0;
}

int scst_get_cdb_info(struct scst_cmd *cmd)
{
	int dev_type = cmd->dev->type;
	int i, res = 0;
	uint8_t op;
	const struct scst_sdbops *ptr = NULL;

	TRACE_ENTRY();

	op = cmd->cdb[0];	/* get clear opcode */

	TRACE_DBG("opcode=%02x, cdblen=%d bytes, tblsize=%d, "
		"dev_type=%d", op, SCST_GET_CDB_LEN(op), SCST_CDB_TBL_SIZE,
		dev_type);

	i = scst_scsi_op_list[op];
	while (i < SCST_CDB_TBL_SIZE && scst_scsi_op_table[i].ops == op) {
		if (scst_scsi_op_table[i].devkey[dev_type] != SCST_CDB_NOTSUPP) {
			ptr = &scst_scsi_op_table[i];
			TRACE_DBG("op = 0x%02x+'%c%c%c%c%c%c%c%c%c%c'+<%s>",
			      ptr->ops, ptr->devkey[0],	/* disk     */
			      ptr->devkey[1],	/* tape     */
			      ptr->devkey[2],	/* printer */
			      ptr->devkey[3],	/* cpu      */
			      ptr->devkey[4],	/* cdr      */
			      ptr->devkey[5],	/* cdrom    */
			      ptr->devkey[6],	/* scanner */
			      ptr->devkey[7],	/* worm     */
			      ptr->devkey[8],	/* changer */
			      ptr->devkey[9],	/* commdev */
			      ptr->op_name);
			TRACE_DBG("direction=%d flags=%d off=%d",
			      ptr->direction,
			      ptr->flags,
			      ptr->off);
			break;
		}
		i++;
	}

	if (unlikely(ptr == NULL)) {
		/* opcode not found or now not used !!! */
		TRACE(TRACE_SCSI, "Unknown opcode 0x%x for type %d", op,
		      dev_type);
		res = -1;
		cmd->op_flags = SCST_INFO_NOT_FOUND;
		goto out;
	}

	cmd->cdb_len = SCST_GET_CDB_LEN(op);
	cmd->op_name = ptr->op_name;
	cmd->data_direction = ptr->direction;
	cmd->op_flags = ptr->flags;
	res = (*ptr->get_trans_len)(cmd, ptr->off);

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_get_cdb_info);

/* Packs SCST LUN back to SCSI form using peripheral device addressing method */
uint64_t scst_pack_lun(const uint64_t lun)
{
	uint64_t res;
	uint16_t *p = (uint16_t *)&res;

	res = lun;
	*p = cpu_to_be16(*p);

	TRACE_EXIT_HRES((unsigned long)res);
	return res;
}

/*
 * Routine to extract a lun number from an 8-byte LUN structure
 * in network byte order (BE).
 * (see SAM-2, Section 4.12.3 page 40)
 * Supports 2 types of lun unpacking: peripheral and logical unit.
 */
uint64_t scst_unpack_lun(const uint8_t *lun, int len)
{
	uint64_t res = NO_SUCH_LUN;
	int address_method;

	TRACE_ENTRY();

	TRACE_BUFF_FLAG(TRACE_DEBUG, "Raw LUN", lun, len);

	if (unlikely(len < 2)) {
		PRINT_ERROR("Illegal lun length %d, expected 2 bytes or "
			"more", len);
		goto out;
	}

	if (len > 2) {
		switch (len) {
		case 8:
			if ((*((uint64_t *)lun) &
			  __constant_cpu_to_be64(0x0000FFFFFFFFFFFFLL)) != 0)
				goto out_err;
			break;
		case 4:
			if (*((uint16_t *)&lun[2]) != 0)
				goto out_err;
			break;
		case 6:
			if (*((uint32_t *)&lun[2]) != 0)
				goto out_err;
			break;
		default:
			goto out_err;
		}
	}

	address_method = (*lun) >> 6;	/* high 2 bits of byte 0 */
	switch (address_method) {
	case 0:	/* peripheral device addressing method */
#if 0
		if (*lun) {
			PRINT_ERROR("Illegal BUS INDENTIFIER in LUN "
			     "peripheral device addressing method 0x%02x, "
			     "expected 0", *lun);
			break;
		}
		res = *(lun + 1);
		break;
#else
		/*
		 * Looks like it's legal to use it as flat space addressing
		 * method as well
		 */

		/* go through */
#endif

	case 1:	/* flat space addressing method */
		res = *(lun + 1) | (((*lun) & 0x3f) << 8);
		break;

	case 2:	/* logical unit addressing method */
		if (*lun & 0x3f) {
			PRINT_ERROR("Illegal BUS NUMBER in LUN logical unit "
				    "addressing method 0x%02x, expected 0",
				    *lun & 0x3f);
			break;
		}
		if (*(lun + 1) & 0xe0) {
			PRINT_ERROR("Illegal TARGET in LUN logical unit "
				    "addressing method 0x%02x, expected 0",
				    (*(lun + 1) & 0xf8) >> 5);
			break;
		}
		res = *(lun + 1) & 0x1f;
		break;

	case 3:	/* extended logical unit addressing method */
	default:
		PRINT_ERROR("Unimplemented LUN addressing method %u",
			    address_method);
		break;
	}

out:
	TRACE_EXIT_RES((int)res);
	return res;

out_err:
	PRINT_ERROR("%s", "Multi-level LUN unimplemented");
	goto out;
}

int scst_calc_block_shift(int sector_size)
{
	int block_shift = 0;
	int t;

	if (sector_size == 0)
		sector_size = 512;

	t = sector_size;
	while (1) {
		if ((t & 1) != 0)
			break;
		t >>= 1;
		block_shift++;
	}
	if (block_shift < 9) {
		PRINT_ERROR("Wrong sector size %d", sector_size);
		block_shift = -1;
	}

	TRACE_EXIT_RES(block_shift);
	return block_shift;
}
EXPORT_SYMBOL(scst_calc_block_shift);

int scst_sbc_generic_parse(struct scst_cmd *cmd,
	int (*get_block_shift)(struct scst_cmd *cmd))
{
	int res = 0;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->data_direction and cmd->bufflen,
	 * therefore change them only if necessary
	 */

	TRACE_DBG("op_name <%s> direct %d flags %d transfer_len %d",
	      cmd->op_name, cmd->data_direction, cmd->op_flags, cmd->bufflen);

	switch (cmd->cdb[0]) {
	case VERIFY_6:
	case VERIFY:
	case VERIFY_12:
	case VERIFY_16:
		if ((cmd->cdb[1] & BYTCHK) == 0) {
			cmd->data_len = cmd->bufflen << get_block_shift(cmd);
			cmd->bufflen = 0;
			goto set_timeout;
		} else
			cmd->data_len = 0;
		break;
	default:
		/* It's all good */
		break;
	}

	if (cmd->op_flags & SCST_TRANSFER_LEN_TYPE_FIXED) {
		/*
		 * No need for locks here, since *_detach() can not be
		 * called, when there are existing commands.
		 */
		cmd->bufflen = cmd->bufflen << get_block_shift(cmd);
	}

set_timeout:
	if ((cmd->op_flags & (SCST_SMALL_TIMEOUT | SCST_LONG_TIMEOUT)) == 0)
		cmd->timeout = SCST_GENERIC_DISK_REG_TIMEOUT;
	else if (cmd->op_flags & SCST_SMALL_TIMEOUT)
		cmd->timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT;
	else if (cmd->op_flags & SCST_LONG_TIMEOUT)
		cmd->timeout = SCST_GENERIC_DISK_LONG_TIMEOUT;

	TRACE_DBG("res %d, bufflen %d, data_len %d, direct %d",
	      res, cmd->bufflen, cmd->data_len, cmd->data_direction);

	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_sbc_generic_parse);

int scst_cdrom_generic_parse(struct scst_cmd *cmd,
	int (*get_block_shift)(struct scst_cmd *cmd))
{
	int res = 0;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->data_direction and cmd->bufflen,
	 * therefore change them only if necessary
	 */

	TRACE_DBG("op_name <%s> direct %d flags %d transfer_len %d",
	      cmd->op_name, cmd->data_direction, cmd->op_flags, cmd->bufflen);

	cmd->cdb[1] &= 0x1f;

	switch (cmd->cdb[0]) {
	case VERIFY_6:
	case VERIFY:
	case VERIFY_12:
	case VERIFY_16:
		if ((cmd->cdb[1] & BYTCHK) == 0) {
			cmd->data_len = cmd->bufflen << get_block_shift(cmd);
			cmd->bufflen = 0;
			goto set_timeout;
		}
		break;
	default:
		/* It's all good */
		break;
	}

	if (cmd->op_flags & SCST_TRANSFER_LEN_TYPE_FIXED)
		cmd->bufflen = cmd->bufflen << get_block_shift(cmd);

set_timeout:
	if ((cmd->op_flags & (SCST_SMALL_TIMEOUT | SCST_LONG_TIMEOUT)) == 0)
		cmd->timeout = SCST_GENERIC_CDROM_REG_TIMEOUT;
	else if (cmd->op_flags & SCST_SMALL_TIMEOUT)
		cmd->timeout = SCST_GENERIC_CDROM_SMALL_TIMEOUT;
	else if (cmd->op_flags & SCST_LONG_TIMEOUT)
		cmd->timeout = SCST_GENERIC_CDROM_LONG_TIMEOUT;

	TRACE_DBG("res=%d, bufflen=%d, direct=%d", res, cmd->bufflen,
		cmd->data_direction);

	TRACE_EXIT();
	return res;
}
EXPORT_SYMBOL(scst_cdrom_generic_parse);

int scst_modisk_generic_parse(struct scst_cmd *cmd,
	int (*get_block_shift)(struct scst_cmd *cmd))
{
	int res = 0;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->data_direction and cmd->bufflen,
	 * therefore change them only if necessary
	 */

	TRACE_DBG("op_name <%s> direct %d flags %d transfer_len %d",
	      cmd->op_name, cmd->data_direction, cmd->op_flags, cmd->bufflen);

	cmd->cdb[1] &= 0x1f;

	switch (cmd->cdb[0]) {
	case VERIFY_6:
	case VERIFY:
	case VERIFY_12:
	case VERIFY_16:
		if ((cmd->cdb[1] & BYTCHK) == 0) {
			cmd->data_len = cmd->bufflen << get_block_shift(cmd);
			cmd->bufflen = 0;
			goto set_timeout;
		}
		break;
	default:
		/* It's all good */
		break;
	}

	if (cmd->op_flags & SCST_TRANSFER_LEN_TYPE_FIXED)
		cmd->bufflen = cmd->bufflen << get_block_shift(cmd);

set_timeout:
	if ((cmd->op_flags & (SCST_SMALL_TIMEOUT | SCST_LONG_TIMEOUT)) == 0)
		cmd->timeout = SCST_GENERIC_MODISK_REG_TIMEOUT;
	else if (cmd->op_flags & SCST_SMALL_TIMEOUT)
		cmd->timeout = SCST_GENERIC_MODISK_SMALL_TIMEOUT;
	else if (cmd->op_flags & SCST_LONG_TIMEOUT)
		cmd->timeout = SCST_GENERIC_MODISK_LONG_TIMEOUT;

	TRACE_DBG("res=%d, bufflen=%d, direct=%d", res, cmd->bufflen,
		cmd->data_direction);

	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_modisk_generic_parse);

int scst_tape_generic_parse(struct scst_cmd *cmd,
	int (*get_block_size)(struct scst_cmd *cmd))
{
	int res = 0;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->data_direction and cmd->bufflen,
	 * therefore change them only if necessary
	 */

	TRACE_DBG("op_name <%s> direct %d flags %d transfer_len %d",
	      cmd->op_name, cmd->data_direction, cmd->op_flags, cmd->bufflen);

	if (cmd->cdb[0] == READ_POSITION) {
		int tclp = cmd->cdb[1] & 4;
		int long_bit = cmd->cdb[1] & 2;
		int bt = cmd->cdb[1] & 1;

		if ((tclp == long_bit) && (!bt || !long_bit)) {
			cmd->bufflen =
			    tclp ? POSITION_LEN_LONG : POSITION_LEN_SHORT;
			cmd->data_direction = SCST_DATA_READ;
		} else {
			cmd->bufflen = 0;
			cmd->data_direction = SCST_DATA_NONE;
		}
	}

	if (cmd->op_flags & SCST_TRANSFER_LEN_TYPE_FIXED & cmd->cdb[1])
		cmd->bufflen = cmd->bufflen * get_block_size(cmd);

	if ((cmd->op_flags & (SCST_SMALL_TIMEOUT | SCST_LONG_TIMEOUT)) == 0)
		cmd->timeout = SCST_GENERIC_TAPE_REG_TIMEOUT;
	else if (cmd->op_flags & SCST_SMALL_TIMEOUT)
		cmd->timeout = SCST_GENERIC_TAPE_SMALL_TIMEOUT;
	else if (cmd->op_flags & SCST_LONG_TIMEOUT)
		cmd->timeout = SCST_GENERIC_TAPE_LONG_TIMEOUT;

	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_tape_generic_parse);

static int scst_null_parse(struct scst_cmd *cmd)
{
	int res = 0;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->data_direction and cmd->bufflen,
	 * therefore change them only if necessary
	 */

	TRACE_DBG("op_name <%s> direct %d flags %d transfer_len %d",
	      cmd->op_name, cmd->data_direction, cmd->op_flags, cmd->bufflen);
#if 0
	switch (cmd->cdb[0]) {
	default:
		/* It's all good */
		break;
	}
#endif
	TRACE_DBG("res %d bufflen %d direct %d",
	      res, cmd->bufflen, cmd->data_direction);

	TRACE_EXIT();
	return res;
}

int scst_changer_generic_parse(struct scst_cmd *cmd,
	int (*nothing)(struct scst_cmd *cmd))
{
	int res = scst_null_parse(cmd);

	if (cmd->op_flags & SCST_LONG_TIMEOUT)
		cmd->timeout = SCST_GENERIC_CHANGER_LONG_TIMEOUT;
	else
		cmd->timeout = SCST_GENERIC_CHANGER_TIMEOUT;

	return res;
}
EXPORT_SYMBOL(scst_changer_generic_parse);

int scst_processor_generic_parse(struct scst_cmd *cmd,
	int (*nothing)(struct scst_cmd *cmd))
{
	int res = scst_null_parse(cmd);

	if (cmd->op_flags & SCST_LONG_TIMEOUT)
		cmd->timeout = SCST_GENERIC_PROCESSOR_LONG_TIMEOUT;
	else
		cmd->timeout = SCST_GENERIC_PROCESSOR_TIMEOUT;

	return res;
}
EXPORT_SYMBOL(scst_processor_generic_parse);

int scst_raid_generic_parse(struct scst_cmd *cmd,
	int (*nothing)(struct scst_cmd *cmd))
{
	int res = scst_null_parse(cmd);

	if (cmd->op_flags & SCST_LONG_TIMEOUT)
		cmd->timeout = SCST_GENERIC_RAID_LONG_TIMEOUT;
	else
		cmd->timeout = SCST_GENERIC_RAID_TIMEOUT;

	return res;
}
EXPORT_SYMBOL(scst_raid_generic_parse);

int scst_block_generic_dev_done(struct scst_cmd *cmd,
	void (*set_block_shift)(struct scst_cmd *cmd, int block_shift))
{
	int opcode = cmd->cdb[0];
	int status = cmd->status;
	int res = SCST_CMD_STATE_DEFAULT;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->is_send_status and
	 * cmd->resp_data_len based on cmd->status and cmd->data_direction,
	 * therefore change them only if necessary
	 */

	if ((status == SAM_STAT_GOOD) || (status == SAM_STAT_CONDITION_MET)) {
		switch (opcode) {
		case READ_CAPACITY:
		{
			/* Always keep track of disk capacity */
			int buffer_size, sector_size, sh;
			uint8_t *buffer;

			buffer_size = scst_get_buf_first(cmd, &buffer);
			if (unlikely(buffer_size <= 0)) {
				if (buffer_size < 0) {
					PRINT_ERROR("%s: Unable to get the"
					" buffer (%d)",	__func__, buffer_size);
				}
				goto out;
			}

			sector_size =
			    ((buffer[4] << 24) | (buffer[5] << 16) |
			     (buffer[6] << 8) | (buffer[7] << 0));
			scst_put_buf(cmd, buffer);
			if (sector_size != 0)
				sh = scst_calc_block_shift(sector_size);
			else
				sh = 0;
			set_block_shift(cmd, sh);
			TRACE_DBG("block_shift %d", sh);
			break;
		}
		default:
			/* It's all good */
			break;
		}
	}

	TRACE_DBG("cmd->is_send_status=%x, cmd->resp_data_len=%d, "
	      "res=%d", cmd->is_send_status, cmd->resp_data_len, res);

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_block_generic_dev_done);

int scst_tape_generic_dev_done(struct scst_cmd *cmd,
	void (*set_block_size)(struct scst_cmd *cmd, int block_shift))
{
	int opcode = cmd->cdb[0];
	int res = SCST_CMD_STATE_DEFAULT;
	int buffer_size, bs;
	uint8_t *buffer = NULL;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->is_send_status and
	 * cmd->resp_data_len based on cmd->status and cmd->data_direction,
	 * therefore change them only if necessary
	 */

	switch (opcode) {
	case MODE_SENSE:
	case MODE_SELECT:
		buffer_size = scst_get_buf_first(cmd, &buffer);
		if (unlikely(buffer_size <= 0)) {
			if (buffer_size < 0) {
				PRINT_ERROR("%s: Unable to get the buffer (%d)",
					__func__, buffer_size);
			}
			goto out;
		}
		break;
	}

	switch (opcode) {
	case MODE_SENSE:
		TRACE_DBG("%s", "MODE_SENSE");
		if ((cmd->cdb[2] & 0xC0) == 0) {
			if (buffer[3] == 8) {
				bs = (buffer[9] << 16) |
				    (buffer[10] << 8) | buffer[11];
				set_block_size(cmd, bs);
			}
		}
		break;
	case MODE_SELECT:
		TRACE_DBG("%s", "MODE_SELECT");
		if (buffer[3] == 8) {
			bs = (buffer[9] << 16) | (buffer[10] << 8) |
			    (buffer[11]);
			set_block_size(cmd, bs);
		}
		break;
	default:
		/* It's all good */
		break;
	}

	switch (opcode) {
	case MODE_SENSE:
	case MODE_SELECT:
		scst_put_buf(cmd, buffer);
		break;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_tape_generic_dev_done);

static void scst_check_internal_sense(struct scst_device *dev, int result,
	uint8_t *sense, int sense_len)
{
	TRACE_ENTRY();

	if (host_byte(result) == DID_RESET) {
		TRACE(TRACE_MGMT_MINOR, "%s", "DID_RESET received, triggering "
			"reset UA");
		scst_set_sense(sense, sense_len, dev->d_sense,
			SCST_LOAD_SENSE(scst_sense_reset_UA));
		scst_dev_check_set_UA(dev, NULL, sense, sense_len);
	} else if ((status_byte(result) == CHECK_CONDITION) &&
		   scst_is_ua_sense(sense, sense_len))
		scst_dev_check_set_UA(dev, NULL, sense, sense_len);

	TRACE_EXIT();
	return;
}

enum dma_data_direction scst_to_dma_dir(int scst_dir)
{
	static const enum dma_data_direction tr_tbl[] = { DMA_NONE,
		DMA_TO_DEVICE, DMA_FROM_DEVICE, DMA_BIDIRECTIONAL, DMA_NONE };

	return tr_tbl[scst_dir];
}
EXPORT_SYMBOL(scst_to_dma_dir);

enum dma_data_direction scst_to_tgt_dma_dir(int scst_dir)
{
	static const enum dma_data_direction tr_tbl[] = { DMA_NONE,
		DMA_FROM_DEVICE, DMA_TO_DEVICE, DMA_BIDIRECTIONAL, DMA_NONE };

	return tr_tbl[scst_dir];
}
EXPORT_SYMBOL(scst_to_tgt_dma_dir);

int scst_obtain_device_parameters(struct scst_device *dev)
{
	int res = 0, i;
	uint8_t cmd[16];
	uint8_t buffer[4+0x0A];
	uint8_t sense_buffer[SCSI_SENSE_BUFFERSIZE];

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(dev->scsi_dev == NULL);

	for (i = 0; i < 5; i++) {
		/* Get control mode page */
		memset(cmd, 0, sizeof(cmd));
#if 0
		cmd[0] = MODE_SENSE_10;
		cmd[1] = 0;
		cmd[2] = 0x0A;
		cmd[8] = sizeof(buffer); /* it's < 256 */
#else
		cmd[0] = MODE_SENSE;
		cmd[1] = 8; /* DBD */
		cmd[2] = 0x0A;
		cmd[4] = sizeof(buffer);
#endif

		memset(buffer, 0, sizeof(buffer));
		memset(sense_buffer, 0, sizeof(sense_buffer));

		TRACE(TRACE_SCSI, "%s", "Doing internal MODE_SENSE");
		res = scsi_execute(dev->scsi_dev, cmd, SCST_DATA_READ, buffer,
				sizeof(buffer), sense_buffer, 15, 0, 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
				, NULL
#endif
				);

		TRACE_DBG("MODE_SENSE done: %x", res);

		if (scsi_status_is_good(res)) {
			int q;

			PRINT_BUFF_FLAG(TRACE_SCSI,
				"Returned control mode page data",
				buffer,	sizeof(buffer));

			dev->tst = buffer[4+2] >> 5;
			q = buffer[4+3] >> 4;
			if (q > SCST_CONTR_MODE_QUEUE_ALG_UNRESTRICTED_REORDER) {
				PRINT_ERROR("Too big QUEUE ALG %x, dev "
					"%d:%d:%d:%d", dev->queue_alg,
					dev->scsi_dev->host->host_no,
					dev->scsi_dev->channel,
					dev->scsi_dev->id, dev->scsi_dev->lun);
			}
			dev->queue_alg = q;
			dev->swp = (buffer[4+4] & 0x8) >> 3;
			dev->tas = (buffer[4+5] & 0x40) >> 6;
			dev->d_sense = (buffer[4+2] & 0x4) >> 2;

			/*
			 * Unfortunately, SCSI ML doesn't provide a way to
			 * specify commands task attribute, so we can rely on
			 * device's restricted reordering only.
			 */
			dev->has_own_order_mgmt = !dev->queue_alg;

			TRACE(TRACE_SCSI|TRACE_MGMT_MINOR,
				"Device %d:%d:%d:%d: TST %x, "
				"QUEUE ALG %x, SWP %x, TAS %x, D_SENSE %d"
				"has_own_order_mgmt %d",
				dev->scsi_dev->host->host_no,
				dev->scsi_dev->channel,	dev->scsi_dev->id,
				dev->scsi_dev->lun, dev->tst, dev->queue_alg,
				dev->swp, dev->tas, dev->d_sense,
				dev->has_own_order_mgmt);

			goto out;
		} else {
#if 0
			if ((status_byte(res) == CHECK_CONDITION) &&
			    SCST_SENSE_VALID(sense_buffer)) {
#else
			/*
			 * 3ware controller is buggy and returns CONDITION_GOOD
			 * instead of CHECK_CONDITION
			 */
			if (SCST_SENSE_VALID(sense_buffer)) {
#endif
				if (scst_analyze_sense(sense_buffer,
						sizeof(sense_buffer),
						SCST_SENSE_KEY_VALID,
						ILLEGAL_REQUEST, 0, 0)) {
					TRACE(TRACE_SCSI|TRACE_MGMT_MINOR,
						"Device %d:%d:%d:%d doesn't "
						"support control mode page, "
						"using defaults: TST %x, "
						"QUEUE ALG %x, SWP %x, "
						"TAS %x, D_SENSE %d, "
						"has_own_order_mgmt %d ",
						dev->scsi_dev->host->host_no,
						dev->scsi_dev->channel,
						dev->scsi_dev->id,
						dev->scsi_dev->lun,
						dev->tst, dev->queue_alg,
						dev->swp, dev->tas,
						dev->d_sense,
						dev->has_own_order_mgmt);
					res = 0;
					goto out;
				} else if (scst_analyze_sense(sense_buffer,
						sizeof(sense_buffer),
						SCST_SENSE_KEY_VALID,
						NOT_READY, 0, 0)) {
					TRACE(TRACE_SCSI,
						"Device %d:%d:%d:%d not ready",
						dev->scsi_dev->host->host_no,
						dev->scsi_dev->channel,
						dev->scsi_dev->id,
						dev->scsi_dev->lun);
					res = 0;
					goto out;
				}
			} else {
				TRACE(TRACE_SCSI|TRACE_MGMT_MINOR,
					"Internal MODE SENSE to "
					"device %d:%d:%d:%d failed: %x",
					dev->scsi_dev->host->host_no,
					dev->scsi_dev->channel,
					dev->scsi_dev->id,
					dev->scsi_dev->lun, res);
				PRINT_BUFF_FLAG(TRACE_SCSI|TRACE_MGMT_MINOR,
					"MODE SENSE sense",
					sense_buffer, sizeof(sense_buffer));
			}
			scst_check_internal_sense(dev, res, sense_buffer,
					sizeof(sense_buffer));
		}
	}
	res = -ENODEV;

out:
	TRACE_EXIT_RES(res);
	return res;
}
EXPORT_SYMBOL(scst_obtain_device_parameters);

/* Called under dev_lock and BH off */
void scst_process_reset(struct scst_device *dev,
	struct scst_session *originator, struct scst_cmd *exclude_cmd,
	struct scst_mgmt_cmd *mcmd, bool setUA)
{
	struct scst_tgt_dev *tgt_dev;
	struct scst_cmd *cmd, *tcmd;

	TRACE_ENTRY();

	/* Clear RESERVE'ation, if necessary */
	if (dev->dev_reserved) {
		list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
				    dev_tgt_dev_list_entry) {
			TRACE(TRACE_MGMT_MINOR, "Clearing RESERVE'ation for "
				"tgt_dev LUN %lld",
				(long long unsigned int)tgt_dev->lun);
			clear_bit(SCST_TGT_DEV_RESERVED,
				  &tgt_dev->tgt_dev_flags);
		}
		dev->dev_reserved = 0;
		/*
		 * There is no need to send RELEASE, since the device is going
		 * to be resetted. Actually, since we can be in RESET TM
		 * function, it might be dangerous.
		 */
	}

	dev->dev_double_ua_possible = 1;

	list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
		dev_tgt_dev_list_entry) {
		struct scst_session *sess = tgt_dev->sess;

		spin_lock_bh(&tgt_dev->tgt_dev_lock);

		scst_free_all_UA(tgt_dev);

		memset(tgt_dev->tgt_dev_sense, 0,
			sizeof(tgt_dev->tgt_dev_sense));

		spin_unlock_bh(&tgt_dev->tgt_dev_lock);

		spin_lock_irq(&sess->sess_list_lock);

		TRACE_DBG("Searching in search cmd list (sess=%p)", sess);
		list_for_each_entry(cmd, &sess->search_cmd_list,
				sess_cmd_list_entry) {
			if (cmd == exclude_cmd)
				continue;
			if ((cmd->tgt_dev == tgt_dev) ||
			    ((cmd->tgt_dev == NULL) &&
			     (cmd->lun == tgt_dev->lun))) {
				scst_abort_cmd(cmd, mcmd,
					(tgt_dev->sess != originator), 0);
			}
		}
		spin_unlock_irq(&sess->sess_list_lock);
	}

	list_for_each_entry_safe(cmd, tcmd, &dev->blocked_cmd_list,
				blocked_cmd_list_entry) {
		if (test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)) {
			list_del(&cmd->blocked_cmd_list_entry);
			TRACE_MGMT_DBG("Adding aborted blocked cmd %p "
				"to active cmd list", cmd);
			spin_lock_irq(&cmd->cmd_lists->cmd_list_lock);
			list_add_tail(&cmd->cmd_list_entry,
				&cmd->cmd_lists->active_cmd_list);
			wake_up(&cmd->cmd_lists->cmd_list_waitQ);
			spin_unlock_irq(&cmd->cmd_lists->cmd_list_lock);
		}
	}

	if (setUA) {
		uint8_t sense_buffer[SCST_STANDARD_SENSE_LEN];
		scst_set_sense(sense_buffer, sizeof(sense_buffer),
			dev->d_sense, SCST_LOAD_SENSE(scst_sense_reset_UA));
		scst_dev_check_set_local_UA(dev, exclude_cmd, sense_buffer,
			sizeof(sense_buffer));
	}

	TRACE_EXIT();
	return;
}

/* No locks, no IRQ or IRQ-disabled context allowed */
int scst_set_pending_UA(struct scst_cmd *cmd)
{
	int res = 0, i;
	struct scst_tgt_dev_UA *UA_entry;
	bool first = true, global_unlock = false;
	struct scst_session *sess = cmd->sess;

	TRACE_ENTRY();

	TRACE(TRACE_MGMT_MINOR, "Setting pending UA cmd %p", cmd);

	spin_lock_bh(&cmd->tgt_dev->tgt_dev_lock);

again:
	/* UA list could be cleared behind us, so retest */
	if (list_empty(&cmd->tgt_dev->UA_list)) {
		TRACE_DBG("%s",
		      "SCST_TGT_DEV_UA_PENDING set, but UA_list empty");
		res = -1;
		goto out_unlock;
	}

	UA_entry = list_entry(cmd->tgt_dev->UA_list.next, typeof(*UA_entry),
			      UA_list_entry);

	TRACE_DBG("next %p UA_entry %p",
	      cmd->tgt_dev->UA_list.next, UA_entry);

	if (UA_entry->global_UA && first) {
		TRACE_MGMT_DBG("Global UA %p detected", UA_entry);

		spin_unlock_bh(&cmd->tgt_dev->tgt_dev_lock);

		/*
		 * cmd won't allow to suspend activities, so we can access
		 * sess->sess_tgt_dev_list_hash without any additional
		 * protection.
		 */

		local_bh_disable();

		for (i = 0; i < TGT_DEV_HASH_SIZE; i++) {
			struct list_head *sess_tgt_dev_list_head =
				&sess->sess_tgt_dev_list_hash[i];
			struct scst_tgt_dev *tgt_dev;
			list_for_each_entry(tgt_dev, sess_tgt_dev_list_head,
					sess_tgt_dev_list_entry) {
				/* Lockdep triggers here a false positive.. */
				spin_lock(&tgt_dev->tgt_dev_lock);
			}
		}

		first = false;
		global_unlock = true;
		goto again;
	}

	scst_set_cmd_error_sense(cmd, UA_entry->UA_sense_buffer,
		sizeof(UA_entry->UA_sense_buffer));

	cmd->ua_ignore = 1;

	list_del(&UA_entry->UA_list_entry);

	if (UA_entry->global_UA) {
		for (i = 0; i < TGT_DEV_HASH_SIZE; i++) {
			struct list_head *sess_tgt_dev_list_head =
				&sess->sess_tgt_dev_list_hash[i];
			struct scst_tgt_dev *tgt_dev;

			list_for_each_entry(tgt_dev, sess_tgt_dev_list_head,
					sess_tgt_dev_list_entry) {
				struct scst_tgt_dev_UA *ua;
				list_for_each_entry(ua, &tgt_dev->UA_list,
							UA_list_entry) {
					if (ua->global_UA &&
					    memcmp(ua->UA_sense_buffer,
						UA_entry->UA_sense_buffer,
					     sizeof(ua->UA_sense_buffer)) == 0) {
						TRACE_MGMT_DBG("Freeing not "
							"needed global UA %p",
							ua);
						list_del(&ua->UA_list_entry);
						mempool_free(ua, scst_ua_mempool);
						break;
					}
				}
			}
		}
	}

	mempool_free(UA_entry, scst_ua_mempool);

	if (list_empty(&cmd->tgt_dev->UA_list)) {
		clear_bit(SCST_TGT_DEV_UA_PENDING,
			  &cmd->tgt_dev->tgt_dev_flags);
	}

out_unlock:
	if (global_unlock) {
		for (i = TGT_DEV_HASH_SIZE-1; i >= 0; i--) {
			struct list_head *sess_tgt_dev_list_head =
				&sess->sess_tgt_dev_list_hash[i];
			struct scst_tgt_dev *tgt_dev;
			list_for_each_entry_reverse(tgt_dev, sess_tgt_dev_list_head,
					sess_tgt_dev_list_entry) {
				spin_unlock(&tgt_dev->tgt_dev_lock);
			}
		}

		local_bh_enable();
		spin_lock_bh(&cmd->tgt_dev->tgt_dev_lock);
	}

	spin_unlock_bh(&cmd->tgt_dev->tgt_dev_lock);

	TRACE_EXIT_RES(res);
	return res;
}

/* Called under tgt_dev_lock and BH off */
static void scst_alloc_set_UA(struct scst_tgt_dev *tgt_dev,
	const uint8_t *sense, int sense_len, int flags)
{
	struct scst_tgt_dev_UA *UA_entry = NULL;

	TRACE_ENTRY();

	UA_entry = mempool_alloc(scst_ua_mempool, GFP_ATOMIC);
	if (UA_entry == NULL) {
		PRINT_CRIT_ERROR("%s", "UNIT ATTENTION memory "
		     "allocation failed. The UNIT ATTENTION "
		     "on some sessions will be missed");
		PRINT_BUFFER("Lost UA", sense, sense_len);
		goto out;
	}
	memset(UA_entry, 0, sizeof(*UA_entry));

	UA_entry->global_UA = (flags & SCST_SET_UA_FLAG_GLOBAL) != 0;
	if (UA_entry->global_UA)
		TRACE_MGMT_DBG("Queuing global UA %p", UA_entry);

	if (sense_len > (int)sizeof(UA_entry->UA_sense_buffer))
		sense_len = sizeof(UA_entry->UA_sense_buffer);
	memcpy(UA_entry->UA_sense_buffer, sense, sense_len);

	set_bit(SCST_TGT_DEV_UA_PENDING, &tgt_dev->tgt_dev_flags);

	TRACE_MGMT_DBG("Adding new UA to tgt_dev %p", tgt_dev);

	if (flags & SCST_SET_UA_FLAG_AT_HEAD)
		list_add(&UA_entry->UA_list_entry, &tgt_dev->UA_list);
	else
		list_add_tail(&UA_entry->UA_list_entry, &tgt_dev->UA_list);

out:
	TRACE_EXIT();
	return;
}

/* tgt_dev_lock supposed to be held and BH off */
static void __scst_check_set_UA(struct scst_tgt_dev *tgt_dev,
	const uint8_t *sense, int sense_len, int flags)
{
	int skip_UA = 0;
	struct scst_tgt_dev_UA *UA_entry_tmp;
	int len = min((int)sizeof(UA_entry_tmp->UA_sense_buffer), sense_len);

	TRACE_ENTRY();

	list_for_each_entry(UA_entry_tmp, &tgt_dev->UA_list,
			    UA_list_entry) {
		if (memcmp(sense, UA_entry_tmp->UA_sense_buffer, len) == 0) {
			TRACE_MGMT_DBG("%s", "UA already exists");
			skip_UA = 1;
			break;
		}
	}

	if (skip_UA == 0)
		scst_alloc_set_UA(tgt_dev, sense, len, flags);

	TRACE_EXIT();
	return;
}

void scst_check_set_UA(struct scst_tgt_dev *tgt_dev,
	const uint8_t *sense, int sense_len, int flags)
{
	TRACE_ENTRY();

	spin_lock_bh(&tgt_dev->tgt_dev_lock);
	__scst_check_set_UA(tgt_dev, sense, sense_len, flags);
	spin_unlock_bh(&tgt_dev->tgt_dev_lock);

	TRACE_EXIT();
	return;
}

/* Called under dev_lock and BH off */
void scst_dev_check_set_local_UA(struct scst_device *dev,
	struct scst_cmd *exclude, const uint8_t *sense, int sense_len)
{
	struct scst_tgt_dev *tgt_dev, *exclude_tgt_dev = NULL;

	TRACE_ENTRY();

	if (exclude != NULL)
		exclude_tgt_dev = exclude->tgt_dev;

	list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
			dev_tgt_dev_list_entry) {
		if (tgt_dev != exclude_tgt_dev)
			scst_check_set_UA(tgt_dev, sense, sense_len, 0);
	}

	TRACE_EXIT();
	return;
}

/* Called under dev_lock and BH off */
void __scst_dev_check_set_UA(struct scst_device *dev,
	struct scst_cmd *exclude, const uint8_t *sense, int sense_len)
{
	TRACE_ENTRY();

	TRACE(TRACE_MGMT_MINOR, "Processing UA dev %p", dev);

	/* Check for reset UA */
	if (scst_analyze_sense(sense, sense_len, SCST_SENSE_ASC_VALID,
				0, SCST_SENSE_ASC_UA_RESET, 0))
		scst_process_reset(dev,
				   (exclude != NULL) ? exclude->sess : NULL,
				   exclude, NULL, false);

	scst_dev_check_set_local_UA(dev, exclude, sense, sense_len);

	TRACE_EXIT();
	return;
}

/* Called under tgt_dev_lock or when tgt_dev is unused */
static void scst_free_all_UA(struct scst_tgt_dev *tgt_dev)
{
	struct scst_tgt_dev_UA *UA_entry, *t;

	TRACE_ENTRY();

	list_for_each_entry_safe(UA_entry, t,
				 &tgt_dev->UA_list, UA_list_entry) {
		TRACE_MGMT_DBG("Clearing UA for tgt_dev LUN %lld",
			       (long long unsigned int)tgt_dev->lun);
		list_del(&UA_entry->UA_list_entry);
		mempool_free(UA_entry, scst_ua_mempool);
	}
	INIT_LIST_HEAD(&tgt_dev->UA_list);
	clear_bit(SCST_TGT_DEV_UA_PENDING, &tgt_dev->tgt_dev_flags);

	TRACE_EXIT();
	return;
}

/* No locks */
struct scst_cmd *__scst_check_deferred_commands(struct scst_tgt_dev *tgt_dev)
{
	struct scst_cmd *res = NULL, *cmd, *t;
	typeof(tgt_dev->expected_sn) expected_sn = tgt_dev->expected_sn;

	spin_lock_irq(&tgt_dev->sn_lock);

	if (unlikely(tgt_dev->hq_cmd_count != 0))
		goto out_unlock;

restart:
	list_for_each_entry_safe(cmd, t, &tgt_dev->deferred_cmd_list,
				sn_cmd_list_entry) {
		EXTRACHECKS_BUG_ON(cmd->queue_type ==
			SCST_CMD_QUEUE_HEAD_OF_QUEUE);
		if (cmd->sn == expected_sn) {
			TRACE_SN("Deferred command %p (sn %ld, set %d) found",
				cmd, cmd->sn, cmd->sn_set);
			tgt_dev->def_cmd_count--;
			list_del(&cmd->sn_cmd_list_entry);
			if (res == NULL)
				res = cmd;
			else {
				spin_lock(&cmd->cmd_lists->cmd_list_lock);
				TRACE_SN("Adding cmd %p to active cmd list",
					cmd);
				list_add_tail(&cmd->cmd_list_entry,
					&cmd->cmd_lists->active_cmd_list);
				wake_up(&cmd->cmd_lists->cmd_list_waitQ);
				spin_unlock(&cmd->cmd_lists->cmd_list_lock);
			}
		}
	}
	if (res != NULL)
		goto out_unlock;

	list_for_each_entry(cmd, &tgt_dev->skipped_sn_list,
				sn_cmd_list_entry) {
		EXTRACHECKS_BUG_ON(cmd->queue_type ==
			SCST_CMD_QUEUE_HEAD_OF_QUEUE);
		if (cmd->sn == expected_sn) {
			atomic_t *slot = cmd->sn_slot;
			/*
			 * !! At this point any pointer in cmd, except !!
			 * !! sn_slot and sn_cmd_list_entry, could be	!!
			 * !! already destroyed				!!
			 */
			TRACE_SN("cmd %p (tag %llu) with skipped sn %ld found",
				 cmd,
				 (long long unsigned int)cmd->tag,
				 cmd->sn);
			tgt_dev->def_cmd_count--;
			list_del(&cmd->sn_cmd_list_entry);
			spin_unlock_irq(&tgt_dev->sn_lock);
			if (test_and_set_bit(SCST_CMD_CAN_BE_DESTROYED,
					     &cmd->cmd_flags))
				scst_destroy_put_cmd(cmd);
			scst_inc_expected_sn(tgt_dev, slot);
			expected_sn = tgt_dev->expected_sn;
			spin_lock_irq(&tgt_dev->sn_lock);
			goto restart;
		}
	}

out_unlock:
	spin_unlock_irq(&tgt_dev->sn_lock);
	return res;
}

void scst_add_thr_data(struct scst_tgt_dev *tgt_dev,
	struct scst_thr_data_hdr *data,
	void (*free_fn) (struct scst_thr_data_hdr *data))
{
	data->owner_thr = current;
	atomic_set(&data->ref, 1);
	EXTRACHECKS_BUG_ON(free_fn == NULL);
	data->free_fn = free_fn;
	spin_lock(&tgt_dev->thr_data_lock);
	list_add_tail(&data->thr_data_list_entry, &tgt_dev->thr_data_list);
	spin_unlock(&tgt_dev->thr_data_lock);
}
EXPORT_SYMBOL(scst_add_thr_data);

void scst_del_all_thr_data(struct scst_tgt_dev *tgt_dev)
{
	spin_lock(&tgt_dev->thr_data_lock);
	while (!list_empty(&tgt_dev->thr_data_list)) {
		struct scst_thr_data_hdr *d = list_entry(
				tgt_dev->thr_data_list.next, typeof(*d),
				thr_data_list_entry);
		list_del(&d->thr_data_list_entry);
		spin_unlock(&tgt_dev->thr_data_lock);
		scst_thr_data_put(d);
		spin_lock(&tgt_dev->thr_data_lock);
	}
	spin_unlock(&tgt_dev->thr_data_lock);
	return;
}
EXPORT_SYMBOL(scst_del_all_thr_data);

void scst_dev_del_all_thr_data(struct scst_device *dev)
{
	struct scst_tgt_dev *tgt_dev;

	TRACE_ENTRY();

	mutex_lock(&scst_mutex);

	list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
				dev_tgt_dev_list_entry) {
		scst_del_all_thr_data(tgt_dev);
	}

	mutex_unlock(&scst_mutex);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(scst_dev_del_all_thr_data);

struct scst_thr_data_hdr *__scst_find_thr_data(struct scst_tgt_dev *tgt_dev,
	struct task_struct *tsk)
{
	struct scst_thr_data_hdr *res = NULL, *d;

	spin_lock(&tgt_dev->thr_data_lock);
	list_for_each_entry(d, &tgt_dev->thr_data_list, thr_data_list_entry) {
		if (d->owner_thr == tsk) {
			res = d;
			scst_thr_data_get(res);
			break;
		}
	}
	spin_unlock(&tgt_dev->thr_data_lock);
	return res;
}
EXPORT_SYMBOL(__scst_find_thr_data);

/* dev_lock supposed to be held and BH disabled */
void __scst_block_dev(struct scst_device *dev)
{
	dev->block_count++;
	TRACE_MGMT_DBG("Device BLOCK(new %d), dev %p", dev->block_count, dev);
}

/* No locks */
static void scst_block_dev(struct scst_device *dev, int outstanding)
{
	spin_lock_bh(&dev->dev_lock);
	__scst_block_dev(dev);
	spin_unlock_bh(&dev->dev_lock);

	/*
	 * Memory barrier is necessary here, because we need to read
	 * on_dev_count in wait_event() below after we increased block_count.
	 * Otherwise, we can miss wake up in scst_dec_on_dev_cmd().
	 * We use the explicit barrier, because spin_unlock_bh() doesn't
	 * provide the necessary memory barrier functionality.
	 */
	smp_mb();

	TRACE_MGMT_DBG("Waiting during blocking outstanding %d (on_dev_count "
		"%d)", outstanding, atomic_read(&dev->on_dev_count));
	wait_event(dev->on_dev_waitQ,
		atomic_read(&dev->on_dev_count) <= outstanding);
	TRACE_MGMT_DBG("%s", "wait_event() returned");
}

/* No locks */
void scst_block_dev_cmd(struct scst_cmd *cmd, int outstanding)
{
	sBUG_ON(cmd->needs_unblocking);

	cmd->needs_unblocking = 1;
	TRACE_MGMT_DBG("Needs unblocking cmd %p (tag %llu)",
		       cmd, (long long unsigned int)cmd->tag);

	scst_block_dev(cmd->dev, outstanding);
}

/* No locks */
void scst_unblock_dev(struct scst_device *dev)
{
	spin_lock_bh(&dev->dev_lock);
	TRACE_MGMT_DBG("Device UNBLOCK(new %d), dev %p",
		dev->block_count-1, dev);
	if (--dev->block_count == 0)
		scst_unblock_cmds(dev);
	spin_unlock_bh(&dev->dev_lock);
	sBUG_ON(dev->block_count < 0);
}

/* No locks */
void scst_unblock_dev_cmd(struct scst_cmd *cmd)
{
	scst_unblock_dev(cmd->dev);
	cmd->needs_unblocking = 0;
}

/* No locks */
int scst_inc_on_dev_cmd(struct scst_cmd *cmd)
{
	int res = 0;
	struct scst_device *dev = cmd->dev;

	TRACE_ENTRY();

	sBUG_ON(cmd->inc_blocking || cmd->dec_on_dev_needed);

	atomic_inc(&dev->on_dev_count);
	cmd->dec_on_dev_needed = 1;
	TRACE_DBG("New on_dev_count %d", atomic_read(&dev->on_dev_count));

	if (unlikely(cmd->internal) && (cmd->cdb[0] == REQUEST_SENSE)) {
		/*
		 * The original command can already block the device, so
		 * REQUEST SENSE command should always pass.
		 */
		goto out;
	}

#ifdef CONFIG_SCST_STRICT_SERIALIZING
	spin_lock_bh(&dev->dev_lock);
	if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)))
		goto out_unlock;
	if (dev->block_count > 0) {
		scst_dec_on_dev_cmd(cmd);
		TRACE_MGMT_DBG("Delaying cmd %p due to blocking or strict "
			"serializing (tag %llu, dev %p)", cmd, cmd->tag, dev);
		list_add_tail(&cmd->blocked_cmd_list_entry,
			      &dev->blocked_cmd_list);
		res = 1;
	} else {
		__scst_block_dev(dev);
		cmd->inc_blocking = 1;
	}
	spin_unlock_bh(&dev->dev_lock);
	goto out;
#else
repeat:
	if (unlikely(dev->block_count > 0)) {
		spin_lock_bh(&dev->dev_lock);
		if (unlikely(test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)))
			goto out_unlock;
		if (dev->block_count > 0) {
			scst_dec_on_dev_cmd(cmd);
			TRACE_MGMT_DBG("Delaying cmd %p due to blocking "
				"(tag %llu, dev %p)", cmd,
				(long long unsigned int)cmd->tag, dev);
			list_add_tail(&cmd->blocked_cmd_list_entry,
				      &dev->blocked_cmd_list);
			res = 1;
			spin_unlock_bh(&dev->dev_lock);
			goto out;
		} else {
			TRACE_MGMT_DBG("%s", "Somebody unblocked the device, "
				"continuing");
		}
		spin_unlock_bh(&dev->dev_lock);
	}
	if (unlikely(dev->dev_double_ua_possible)) {
		spin_lock_bh(&dev->dev_lock);
		if (dev->block_count == 0) {
			TRACE_MGMT_DBG("cmd %p (tag %llu), blocking further "
				"cmds due to possible double reset UA (dev %p)",
				cmd, (long long unsigned int)cmd->tag, dev);
			__scst_block_dev(dev);
			cmd->inc_blocking = 1;
		} else {
			spin_unlock_bh(&dev->dev_lock);
			TRACE_MGMT_DBG("Somebody blocked the device, "
				"repeating (count %d)", dev->block_count);
			goto repeat;
		}
		spin_unlock_bh(&dev->dev_lock);
	}
#endif

out:
	TRACE_EXIT_RES(res);
	return res;

out_unlock:
	spin_unlock_bh(&dev->dev_lock);
	goto out;
}

/* Called under dev_lock */
static void scst_unblock_cmds(struct scst_device *dev)
{
#ifdef CONFIG_SCST_STRICT_SERIALIZING
	struct scst_cmd *cmd, *t;
	unsigned long flags;

	TRACE_ENTRY();

	local_irq_save(flags);
	list_for_each_entry_safe(cmd, t, &dev->blocked_cmd_list,
				 blocked_cmd_list_entry) {
		int brk = 0;
		/*
		 * Since only one cmd per time is being executed, expected_sn
		 * can't change behind us, if the corresponding cmd is in
		 * blocked_cmd_list, but we could be called before
		 * scst_inc_expected_sn().
		 *
		 * For HQ commands SN is not set.
		 */
		if (likely(!cmd->internal && cmd->sn_set)) {
			typeof(cmd->tgt_dev->expected_sn) expected_sn;
			if (cmd->tgt_dev == NULL)
				sBUG();
			expected_sn = cmd->tgt_dev->expected_sn;
			if (cmd->sn == expected_sn)
				brk = 1;
			else if (cmd->sn != (expected_sn+1))
				continue;
		}

		list_del(&cmd->blocked_cmd_list_entry);
		TRACE_MGMT_DBG("Adding cmd %p to head of active cmd list", cmd);
		spin_lock(&cmd->cmd_lists->cmd_list_lock);
		list_add(&cmd->cmd_list_entry,
			 &cmd->cmd_lists->active_cmd_list);
		wake_up(&cmd->cmd_lists->cmd_list_waitQ);
		spin_unlock(&cmd->cmd_lists->cmd_list_lock);
		if (brk)
			break;
	}
	local_irq_restore(flags);
#else /* CONFIG_SCST_STRICT_SERIALIZING */
	struct scst_cmd *cmd, *tcmd;
	unsigned long flags;

	TRACE_ENTRY();

	local_irq_save(flags);
	list_for_each_entry_safe(cmd, tcmd, &dev->blocked_cmd_list,
				 blocked_cmd_list_entry) {
		list_del(&cmd->blocked_cmd_list_entry);
		TRACE_MGMT_DBG("Adding blocked cmd %p to active cmd list", cmd);
		spin_lock(&cmd->cmd_lists->cmd_list_lock);
		if (unlikely(cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE))
			list_add(&cmd->cmd_list_entry,
				&cmd->cmd_lists->active_cmd_list);
		else
			list_add_tail(&cmd->cmd_list_entry,
				&cmd->cmd_lists->active_cmd_list);
		wake_up(&cmd->cmd_lists->cmd_list_waitQ);
		spin_unlock(&cmd->cmd_lists->cmd_list_lock);
	}
	local_irq_restore(flags);
#endif /* CONFIG_SCST_STRICT_SERIALIZING */

	TRACE_EXIT();
	return;
}

static void __scst_unblock_deferred(struct scst_tgt_dev *tgt_dev,
	struct scst_cmd *out_of_sn_cmd)
{
	EXTRACHECKS_BUG_ON(!out_of_sn_cmd->sn_set);

	if (out_of_sn_cmd->sn == tgt_dev->expected_sn) {
		scst_inc_expected_sn(tgt_dev, out_of_sn_cmd->sn_slot);
		scst_make_deferred_commands_active(tgt_dev);
	} else {
		out_of_sn_cmd->out_of_sn = 1;
		spin_lock_irq(&tgt_dev->sn_lock);
		tgt_dev->def_cmd_count++;
		list_add_tail(&out_of_sn_cmd->sn_cmd_list_entry,
			      &tgt_dev->skipped_sn_list);
		TRACE_SN("out_of_sn_cmd %p with sn %ld added to skipped_sn_list"
			" (expected_sn %ld)", out_of_sn_cmd, out_of_sn_cmd->sn,
			tgt_dev->expected_sn);
		spin_unlock_irq(&tgt_dev->sn_lock);
	}

	return;
}

void scst_unblock_deferred(struct scst_tgt_dev *tgt_dev,
	struct scst_cmd *out_of_sn_cmd)
{
	TRACE_ENTRY();

	if (!out_of_sn_cmd->sn_set) {
		TRACE_SN("cmd %p without sn", out_of_sn_cmd);
		goto out;
	}

	__scst_unblock_deferred(tgt_dev, out_of_sn_cmd);

out:
	TRACE_EXIT();
	return;
}

void scst_on_hq_cmd_response(struct scst_cmd *cmd)
{
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;

	TRACE_ENTRY();

	if (!cmd->hq_cmd_inced)
		goto out;

	spin_lock_irq(&tgt_dev->sn_lock);
	tgt_dev->hq_cmd_count--;
	spin_unlock_irq(&tgt_dev->sn_lock);

	EXTRACHECKS_BUG_ON(tgt_dev->hq_cmd_count < 0);

	/*
	 * There is no problem in checking hq_cmd_count in the
	 * non-locked state. In the worst case we will only have
	 * unneeded run of the deferred commands.
	 */
	if (tgt_dev->hq_cmd_count == 0)
		scst_make_deferred_commands_active(tgt_dev);

out:
	TRACE_EXIT();
	return;
}

void scst_store_sense(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	if (SCST_SENSE_VALID(cmd->sense) &&
	    !test_bit(SCST_CMD_NO_RESP, &cmd->cmd_flags) &&
	    (cmd->tgt_dev != NULL)) {
		struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;

		TRACE_DBG("Storing sense (cmd %p)", cmd);

		spin_lock_bh(&tgt_dev->tgt_dev_lock);

		if (cmd->sense_bufflen <= sizeof(tgt_dev->tgt_dev_sense))
			tgt_dev->tgt_dev_valid_sense_len = cmd->sense_bufflen;
		else {
			tgt_dev->tgt_dev_valid_sense_len = sizeof(tgt_dev->tgt_dev_sense);
			PRINT_ERROR("Stored sense truncated to size %d "
				"(needed %d)", tgt_dev->tgt_dev_valid_sense_len,
				cmd->sense_bufflen);
		}
		memcpy(tgt_dev->tgt_dev_sense, cmd->sense,
			tgt_dev->tgt_dev_valid_sense_len);

		spin_unlock_bh(&tgt_dev->tgt_dev_lock);
	}

	TRACE_EXIT();
	return;
}

void scst_xmit_process_aborted_cmd(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	TRACE_MGMT_DBG("Aborted cmd %p done (cmd_ref %d, "
		"scst_cmd_count %d)", cmd, atomic_read(&cmd->cmd_ref),
		atomic_read(&scst_cmd_count));

	scst_done_cmd_mgmt(cmd);

	if (test_bit(SCST_CMD_ABORTED_OTHER, &cmd->cmd_flags)) {
		if (cmd->completed) {
			/* It's completed and it's OK to return its result */
			goto out;
		}

		if (cmd->dev->tas) {
			TRACE_MGMT_DBG("Flag ABORTED OTHER set for cmd %p "
				"(tag %llu), returning TASK ABORTED ", cmd,
				(long long unsigned int)cmd->tag);
			scst_set_cmd_error_status(cmd, SAM_STAT_TASK_ABORTED);
		} else {
			TRACE_MGMT_DBG("Flag ABORTED OTHER set for cmd %p "
				"(tag %llu), aborting without delivery or "
				"notification",
				cmd, (long long unsigned int)cmd->tag);
			/*
			 * There is no need to check/requeue possible UA,
			 * because, if it exists, it will be delivered
			 * by the "completed" branch above.
			 */
			clear_bit(SCST_CMD_ABORTED_OTHER, &cmd->cmd_flags);
		}
	}

out:
	TRACE_EXIT();
	return;
}

static void __init scst_scsi_op_list_init(void)
{
	int i;
	uint8_t op = 0xff;

	TRACE_ENTRY();

	for (i = 0; i < 256; i++)
		scst_scsi_op_list[i] = SCST_CDB_TBL_SIZE;

	for (i = 0; i < SCST_CDB_TBL_SIZE; i++) {
		if (scst_scsi_op_table[i].ops != op) {
			op = scst_scsi_op_table[i].ops;
			scst_scsi_op_list[op] = i;
		}
	}

	TRACE_EXIT();
	return;
}

int __init scst_lib_init(void)
{
	int res = 0;

	scst_scsi_op_list_init();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
	scsi_io_context_cache = kmem_cache_create("scst_scsi_io_context",
					sizeof(struct scsi_io_context),
					0, 0, NULL);
	if (!scsi_io_context_cache) {
		PRINT_ERROR("%s", "Can't init scsi io context cache");
		res = -ENOMEM;
		goto out;
	}

out:
#endif
	TRACE_EXIT_RES(res);
	return res;
}

void scst_lib_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
	BUILD_BUG_ON(SCST_MAX_CDB_SIZE != BLK_MAX_CDB);
	BUILD_BUG_ON(SCST_SENSE_BUFFERSIZE < SCSI_SENSE_BUFFERSIZE);

	kmem_cache_destroy(scsi_io_context_cache);
#endif
}

#ifdef CONFIG_SCST_DEBUG
/* Original taken from the XFS code */
unsigned long scst_random(void)
{
	static int Inited;
	static unsigned long RandomValue;
	static DEFINE_SPINLOCK(lock);
	/* cycles pseudo-randomly through all values between 1 and 2^31 - 2 */
	register long rv;
	register long lo;
	register long hi;
	unsigned long flags;

	spin_lock_irqsave(&lock, flags);
	if (!Inited) {
		RandomValue = jiffies;
		Inited = 1;
	}
	rv = RandomValue;
	hi = rv / 127773;
	lo = rv % 127773;
	rv = 16807 * lo - 2836 * hi;
	if (rv <= 0)
		rv += 2147483647;
	RandomValue = rv;
	spin_unlock_irqrestore(&lock, flags);
	return rv;
}
EXPORT_SYMBOL(scst_random);
#endif

#ifdef CONFIG_SCST_DEBUG_TM

#define TM_DBG_STATE_ABORT		0
#define TM_DBG_STATE_RESET		1
#define TM_DBG_STATE_OFFLINE		2

#define INIT_TM_DBG_STATE		TM_DBG_STATE_ABORT

static void tm_dbg_timer_fn(unsigned long arg);

static DEFINE_SPINLOCK(scst_tm_dbg_lock);
/* All serialized by scst_tm_dbg_lock */
static struct {
	unsigned int tm_dbg_release:1;
	unsigned int tm_dbg_blocked:1;
} tm_dbg_flags;
static LIST_HEAD(tm_dbg_delayed_cmd_list);
static int tm_dbg_delayed_cmds_count;
static int tm_dbg_passed_cmds_count;
static int tm_dbg_state;
static int tm_dbg_on_state_passes;
static DEFINE_TIMER(tm_dbg_timer, tm_dbg_timer_fn, 0, 0);
static struct scst_tgt_dev *tm_dbg_tgt_dev;

static const int tm_dbg_on_state_num_passes[] = { 5, 1, 0x7ffffff };

static void tm_dbg_init_tgt_dev(struct scst_tgt_dev *tgt_dev,
	struct scst_acg_dev *acg_dev)
{
	if ((acg_dev->acg == scst_default_acg) && (acg_dev->lun == 0)) {
		unsigned long flags;

		if (tm_dbg_tgt_dev != NULL)
			tm_dbg_deinit_tgt_dev(tm_dbg_tgt_dev);

		/* Do TM debugging only for LUN 0 */
		spin_lock_irqsave(&scst_tm_dbg_lock, flags);
		tm_dbg_state = INIT_TM_DBG_STATE;
		tm_dbg_on_state_passes =
			tm_dbg_on_state_num_passes[tm_dbg_state];
		tm_dbg_tgt_dev = tgt_dev;
		PRINT_INFO("LUN 0 connected from initiator %s is under "
			"TM debugging (tgt_dev %p)",
			tgt_dev->sess->initiator_name, tgt_dev);
		spin_unlock_irqrestore(&scst_tm_dbg_lock, flags);
	}
	return;
}

static void tm_dbg_deinit_tgt_dev(struct scst_tgt_dev *tgt_dev)
{
	if (tm_dbg_tgt_dev == tgt_dev) {
		unsigned long flags;
		TRACE_MGMT_DBG("Deinit TM debugging tgt_dev %p", tgt_dev);
		del_timer_sync(&tm_dbg_timer);
		spin_lock_irqsave(&scst_tm_dbg_lock, flags);
		tm_dbg_tgt_dev = NULL;
		spin_unlock_irqrestore(&scst_tm_dbg_lock, flags);
	}
	return;
}

static void tm_dbg_timer_fn(unsigned long arg)
{
	TRACE_MGMT_DBG("%s", "delayed cmd timer expired");
	tm_dbg_flags.tm_dbg_release = 1;
	/* Used to make sure that all woken up threads see the new value */
	smp_wmb();
	wake_up_all(&tm_dbg_tgt_dev->dev->p_cmd_lists->cmd_list_waitQ);
	return;
}

/* Called under scst_tm_dbg_lock and IRQs off */
static void tm_dbg_delay_cmd(struct scst_cmd *cmd)
{
	switch (tm_dbg_state) {
	case TM_DBG_STATE_ABORT:
		if (tm_dbg_delayed_cmds_count == 0) {
			unsigned long d = 58*HZ + (scst_random() % (4*HZ));
			TRACE_MGMT_DBG("STATE ABORT: delaying cmd %p (tag %llu)"
				" for %ld.%ld seconds (%ld HZ), "
				"tm_dbg_on_state_passes=%d", cmd, cmd->tag,
				d/HZ, (d%HZ)*100/HZ, d,	tm_dbg_on_state_passes);
			mod_timer(&tm_dbg_timer, jiffies + d);
#if 0
			tm_dbg_flags.tm_dbg_blocked = 1;
#endif
		} else {
			TRACE_MGMT_DBG("Delaying another timed cmd %p "
				"(tag %llu), delayed_cmds_count=%d, "
				"tm_dbg_on_state_passes=%d", cmd, cmd->tag,
				tm_dbg_delayed_cmds_count,
				tm_dbg_on_state_passes);
			if (tm_dbg_delayed_cmds_count == 2)
				tm_dbg_flags.tm_dbg_blocked = 0;
		}
		break;

	case TM_DBG_STATE_RESET:
	case TM_DBG_STATE_OFFLINE:
		TRACE_MGMT_DBG("STATE RESET/OFFLINE: delaying cmd %p "
			"(tag %llu), delayed_cmds_count=%d, "
			"tm_dbg_on_state_passes=%d", cmd, cmd->tag,
			tm_dbg_delayed_cmds_count, tm_dbg_on_state_passes);
		tm_dbg_flags.tm_dbg_blocked = 1;
		break;

	default:
		sBUG();
	}
	/* IRQs already off */
	spin_lock(&cmd->cmd_lists->cmd_list_lock);
	list_add_tail(&cmd->cmd_list_entry, &tm_dbg_delayed_cmd_list);
	spin_unlock(&cmd->cmd_lists->cmd_list_lock);
	cmd->tm_dbg_delayed = 1;
	tm_dbg_delayed_cmds_count++;
	return;
}

/* No locks */
void tm_dbg_check_released_cmds(void)
{
	if (tm_dbg_flags.tm_dbg_release) {
		struct scst_cmd *cmd, *tc;
		spin_lock_irq(&scst_tm_dbg_lock);
		list_for_each_entry_safe_reverse(cmd, tc,
				&tm_dbg_delayed_cmd_list, cmd_list_entry) {
			TRACE_MGMT_DBG("Releasing timed cmd %p (tag %llu), "
				"delayed_cmds_count=%d", cmd, cmd->tag,
				tm_dbg_delayed_cmds_count);
			spin_lock(&cmd->cmd_lists->cmd_list_lock);
			list_move(&cmd->cmd_list_entry,
				&cmd->cmd_lists->active_cmd_list);
			spin_unlock(&cmd->cmd_lists->cmd_list_lock);
		}
		tm_dbg_flags.tm_dbg_release = 0;
		spin_unlock_irq(&scst_tm_dbg_lock);
	}
}

/* Called under scst_tm_dbg_lock */
static void tm_dbg_change_state(void)
{
	tm_dbg_flags.tm_dbg_blocked = 0;
	if (--tm_dbg_on_state_passes == 0) {
		switch (tm_dbg_state) {
		case TM_DBG_STATE_ABORT:
			TRACE_MGMT_DBG("%s", "Changing "
			    "tm_dbg_state to RESET");
			tm_dbg_state = TM_DBG_STATE_RESET;
			tm_dbg_flags.tm_dbg_blocked = 0;
			break;
		case TM_DBG_STATE_RESET:
		case TM_DBG_STATE_OFFLINE:
#ifdef CONFIG_SCST_TM_DBG_GO_OFFLINE
			    TRACE_MGMT_DBG("%s", "Changing "
				    "tm_dbg_state to OFFLINE");
			    tm_dbg_state = TM_DBG_STATE_OFFLINE;
#else
			    TRACE_MGMT_DBG("%s", "Changing "
				    "tm_dbg_state to ABORT");
			    tm_dbg_state = TM_DBG_STATE_ABORT;
#endif
			break;
		default:
			sBUG();
		}
		tm_dbg_on_state_passes =
		    tm_dbg_on_state_num_passes[tm_dbg_state];
	}

	TRACE_MGMT_DBG("%s", "Deleting timer");
	del_timer_sync(&tm_dbg_timer);
	return;
}

/* No locks */
int tm_dbg_check_cmd(struct scst_cmd *cmd)
{
	int res = 0;
	unsigned long flags;

	if (cmd->tm_dbg_immut)
		goto out;

	if (cmd->tm_dbg_delayed) {
		spin_lock_irqsave(&scst_tm_dbg_lock, flags);
		TRACE_MGMT_DBG("Processing delayed cmd %p (tag %llu), "
			"delayed_cmds_count=%d", cmd, cmd->tag,
			tm_dbg_delayed_cmds_count);

		cmd->tm_dbg_immut = 1;
		tm_dbg_delayed_cmds_count--;
		if ((tm_dbg_delayed_cmds_count == 0) &&
		    (tm_dbg_state == TM_DBG_STATE_ABORT))
			tm_dbg_change_state();
		spin_unlock_irqrestore(&scst_tm_dbg_lock, flags);
	} else if (cmd->tgt_dev && (tm_dbg_tgt_dev == cmd->tgt_dev)) {
		/* Delay 50th command */
		spin_lock_irqsave(&scst_tm_dbg_lock, flags);
		if (tm_dbg_flags.tm_dbg_blocked ||
		    (++tm_dbg_passed_cmds_count % 50) == 0) {
			tm_dbg_delay_cmd(cmd);
			res = 1;
		} else
			cmd->tm_dbg_immut = 1;
		spin_unlock_irqrestore(&scst_tm_dbg_lock, flags);
	}

out:
	return res;
}

/* No locks */
void tm_dbg_release_cmd(struct scst_cmd *cmd)
{
	struct scst_cmd *c;
	unsigned long flags;

	spin_lock_irqsave(&scst_tm_dbg_lock, flags);
	list_for_each_entry(c, &tm_dbg_delayed_cmd_list,
				cmd_list_entry) {
		if (c == cmd) {
			TRACE_MGMT_DBG("Abort request for "
				"delayed cmd %p (tag=%llu), moving it to "
				"active cmd list (delayed_cmds_count=%d)",
				c, c->tag, tm_dbg_delayed_cmds_count);

			if (!test_bit(SCST_CMD_ABORTED_OTHER,
					    &cmd->cmd_flags)) {
				/* Test how completed commands handled */
				if (((scst_random() % 10) == 5)) {
					scst_set_cmd_error(cmd,
						SCST_LOAD_SENSE(
						scst_sense_hardw_error));
					/* It's completed now */
				}
			}

			spin_lock(&cmd->cmd_lists->cmd_list_lock);
			list_move(&c->cmd_list_entry,
				&c->cmd_lists->active_cmd_list);
			wake_up(&c->cmd_lists->cmd_list_waitQ);
			spin_unlock(&cmd->cmd_lists->cmd_list_lock);
			break;
		}
	}
	spin_unlock_irqrestore(&scst_tm_dbg_lock, flags);
	return;
}

/* Might be called under scst_mutex */
void tm_dbg_task_mgmt(struct scst_device *dev, const char *fn, int force)
{
	unsigned long flags;

	if (dev != NULL) {
		if (tm_dbg_tgt_dev == NULL)
			goto out;

		if (tm_dbg_tgt_dev->dev != dev)
			goto out;
	}

	spin_lock_irqsave(&scst_tm_dbg_lock, flags);
	if ((tm_dbg_state != TM_DBG_STATE_OFFLINE) || force) {
		TRACE_MGMT_DBG("%s: freeing %d delayed cmds", fn,
			tm_dbg_delayed_cmds_count);
		tm_dbg_change_state();
		tm_dbg_flags.tm_dbg_release = 1;
		/*
		 * Used to make sure that all woken up threads see the new
		 * value.
		 */
		smp_wmb();
		if (tm_dbg_tgt_dev != NULL)
			wake_up_all(&tm_dbg_tgt_dev->dev->p_cmd_lists->cmd_list_waitQ);
	} else {
		TRACE_MGMT_DBG("%s: while OFFLINE state, doing nothing", fn);
	}
	spin_unlock_irqrestore(&scst_tm_dbg_lock, flags);

out:
	return;
}

int tm_dbg_is_release(void)
{
	return tm_dbg_flags.tm_dbg_release;
}
#endif /* CONFIG_SCST_DEBUG_TM */

#ifdef CONFIG_SCST_DEBUG_SN
void scst_check_debug_sn(struct scst_cmd *cmd)
{
	static DEFINE_SPINLOCK(lock);
	static int type;
	static int cnt;
	unsigned long flags;
	int old = cmd->queue_type;

	spin_lock_irqsave(&lock, flags);

	if (cnt == 0) {
		if ((scst_random() % 1000) == 500) {
			if ((scst_random() % 3) == 1)
				type = SCST_CMD_QUEUE_HEAD_OF_QUEUE;
			else
				type = SCST_CMD_QUEUE_ORDERED;
			do {
				cnt = scst_random() % 10;
			} while (cnt == 0);
		} else
			goto out_unlock;
	}

	cmd->queue_type = type;
	cnt--;

	if (((scst_random() % 1000) == 750))
		cmd->queue_type = SCST_CMD_QUEUE_ORDERED;
	else if (((scst_random() % 1000) == 751))
		cmd->queue_type = SCST_CMD_QUEUE_HEAD_OF_QUEUE;
	else if (((scst_random() % 1000) == 752))
		cmd->queue_type = SCST_CMD_QUEUE_SIMPLE;

	TRACE_SN("DbgSN changed cmd %p: %d/%d (cnt %d)", cmd, old,
		cmd->queue_type, cnt);

out_unlock:
	spin_unlock_irqrestore(&lock, flags);
	return;
}
#endif /* CONFIG_SCST_DEBUG_SN */
