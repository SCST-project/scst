/*
 *  scst_lib.c
 *  
 *  Copyright (C) 2004-2006 Vladislav Bolkhovitin <vst@vlnb.net>
 *                 and Leonid Stoljar
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
#include <asm/unistd.h>
#include <asm/string.h>

#ifdef SCST_HIGHMEM
#include <linux/highmem.h>
#endif

#include "scst_debug.h"
#include "scsi_tgt.h"
#include "scst_priv.h"
#include "scst_mem.h"

#include "scst_cdbprobe.h"

static void scst_free_tgt_dev(struct scst_tgt_dev *tgt_dev);

void scst_set_cmd_error_status(struct scst_cmd *cmd, int status)
{
	TRACE_ENTRY();

	cmd->status = status;
	cmd->masked_status = status >> 1;
	cmd->host_status = DID_OK;

	cmd->data_direction = SCST_DATA_NONE;
	cmd->tgt_resp_flags = SCST_TSC_FLAG_STATUS;
	cmd->resp_data_len = 0;

	TRACE_EXIT();
	return;
}

void scst_set_cmd_error(struct scst_cmd *cmd, int key, int asc, int ascq)
{
	TRACE_ENTRY();

	scst_set_cmd_error_status(cmd, SAM_STAT_CHECK_CONDITION);
	scst_set_sense(cmd->sense_buffer, sizeof(cmd->sense_buffer),
		key, asc, ascq);
	TRACE_BUFFER("Sense set", cmd->sense_buffer, sizeof(cmd->sense_buffer));

	TRACE_EXIT();
	return;
}

void scst_set_cmd_error_sense(struct scst_cmd *cmd, uint8_t *sense, 
	unsigned int len)
{
	TRACE_ENTRY();

	scst_set_cmd_error_status(cmd, SAM_STAT_CHECK_CONDITION);

	memset(cmd->sense_buffer, 0, sizeof(cmd->sense_buffer));
	memcpy(cmd->sense_buffer, sense, min((unsigned long)len, 
		(unsigned long)sizeof(cmd->sense_buffer)));
	TRACE_BUFFER("Sense set", cmd->sense_buffer, sizeof(cmd->sense_buffer));

	TRACE_EXIT();
	return;
}

void scst_set_busy(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	if ((cmd->sess->sess_cmd_count <= 1) || 
	    (cmd->sess->init_phase != SCST_SESS_IPH_READY))
	{
		scst_set_cmd_error_status(cmd, SAM_STAT_BUSY);
		TRACE_MGMT_DBG("Sending BUSY status to initiator %s "
			"(cmds count %d, queue_type %x, sess->init_phase %d)",
			cmd->sess->initiator_name, cmd->sess->sess_cmd_count,
			cmd->queue_type, cmd->sess->init_phase);
	} else {
		scst_set_cmd_error_status(cmd, SAM_STAT_TASK_SET_FULL);
		TRACE_MGMT_DBG("Sending QUEUE_FULL status to initiator %s "
			"(cmds count %d, queue_type %x, sess->init_phase %d)",
			cmd->sess->initiator_name, cmd->sess->sess_cmd_count,
			cmd->queue_type, cmd->sess->init_phase);
	}

	TRACE_EXIT();
	return;
}

void scst_set_resp_data_len(struct scst_cmd *cmd, int resp_data_len)
{
	int i, l;

	TRACE_ENTRY();

	scst_check_restore_sg_buff(cmd);
	cmd->resp_data_len = resp_data_len;

	if (resp_data_len == cmd->bufflen)
		goto out;

	l = 0;
	for(i = 0; i < cmd->sg_cnt; i++) {
		l += cmd->sg[i].length;
		if (l >= resp_data_len) {
			int left = resp_data_len - (l - cmd->sg[i].length);
			TRACE(TRACE_SG, "cmd %p (tag %d), "
				"resp_data_len %d, i %d, cmd->sg[i].length %d, "
				"left %d", cmd, cmd->tag, resp_data_len, i,
				cmd->sg[i].length, left);
			cmd->orig_sg_cnt = cmd->sg_cnt;
			cmd->orig_sg_entry = i;
			cmd->orig_entry_len = cmd->sg[i].length;
			cmd->sg_cnt = i+1;
			cmd->sg[i].length = left;
			cmd->sg_buff_modified = 1;
			break;
		}
	}

out:
	TRACE_EXIT();
	return;
}

struct scst_device *scst_alloc_device(int gfp_mask)
{
	struct scst_device *dev;

	TRACE_ENTRY();

	dev = kzalloc(sizeof(*dev), gfp_mask);
	TRACE_MEM("kzalloc() for dev (%zd): %p", sizeof(*dev), dev);
	if (dev == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s",
		      "Allocation of scst_device failed");
		goto out;
	}

	spin_lock_init(&dev->dev_lock);
	atomic_set(&dev->on_dev_count, 0);
	INIT_LIST_HEAD(&dev->blocked_cmd_list);
	INIT_LIST_HEAD(&dev->dev_tgt_dev_list);
	INIT_LIST_HEAD(&dev->dev_acg_dev_list);
	init_waitqueue_head(&dev->on_dev_waitQ);
	dev->dev_double_ua_possible = 1;
	dev->dev_serialized = 1;

out:
	TRACE_EXIT_HRES(dev);
	return dev;
}

void scst_free_device(struct scst_device *dev)
{
	TRACE_ENTRY();

#ifdef EXTRACHECKS
	if (!list_empty(&dev->dev_tgt_dev_list) || 
	    !list_empty(&dev->dev_acg_dev_list))
	{
		PRINT_ERROR_PR("%s: dev_tgt_dev_list or dev_acg_dev_list "
			"is not empty!", __FUNCTION__);
		BUG();
	}
#endif

	TRACE_MEM("kfree for dev: %p", dev);
	kfree(dev);

	TRACE_EXIT();
	return;
}

struct scst_acg_dev *scst_alloc_acg_dev(struct scst_acg *acg,
	struct scst_device *dev, lun_t lun)
{
	struct scst_acg_dev *res;

	TRACE_ENTRY();
	
	res = kmem_cache_alloc(scst_acgd_cachep, GFP_KERNEL);
	TRACE_MEM("kmem_cache_alloc() for acg_dev (%zd): %p", sizeof(*res), res);
	if (res == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of scst_acg_dev failed");
		goto out;
	}
	memset(res, 0, sizeof(*res));
	
	res->dev = dev;
	res->acg = acg;
	res->lun = lun;
	
out:
	TRACE_EXIT_HRES(res);
	return res;
}

/* scst_mutex supposed to be held */
void scst_free_acg_dev(struct scst_acg_dev *acg_dev)
{
	TRACE_ENTRY();
	
	TRACE_DBG("Removing acg_dev %p from acg_dev_list and dev_acg_dev_list", 
		acg_dev);
	list_del(&acg_dev->acg_dev_list_entry);
	list_del(&acg_dev->dev_acg_dev_list_entry);
	
	TRACE_MEM("kfree for acg_dev: %p", acg_dev);
	kmem_cache_free(scst_acgd_cachep, acg_dev);
	
	TRACE_EXIT();
	return;
}

/* scst_mutex supposed to be held */
struct scst_acg *scst_alloc_add_acg(const char *acg_name)
{
	struct scst_acg *acg;

	TRACE_ENTRY();

	acg = kzalloc(sizeof(*acg), GFP_KERNEL);
	TRACE_MEM("kzalloc() for acg (%zd): %p", sizeof(*acg), acg);
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
	
out:
	TRACE_EXIT_HRES(acg);
	return acg;
}

/* scst_mutex supposed to be held */
int scst_destroy_acg(struct scst_acg *acg)
{
	struct scst_acn *n, *nn;
	struct scst_acg_dev *acg_dev, *acg_dev_tmp;
	int res = 0;

	TRACE_ENTRY();

	if (!list_empty(&acg->acg_sess_list)) {
		PRINT_ERROR_PR("%s: acg_sess_list is not empty!", __FUNCTION__);
		res = -EBUSY;
		goto out;
	}

	__scst_suspend_activity();

	TRACE_DBG("Removing acg %s from scst_acg_list", acg->acg_name);
	list_del(&acg->scst_acg_list_entry);
	
	/* Freeing acg_devs */
	list_for_each_entry_safe(acg_dev, acg_dev_tmp, &acg->acg_dev_list, 
		acg_dev_list_entry)
	{
		struct scst_tgt_dev *tgt_dev, *tt;
		list_for_each_entry_safe(tgt_dev, tt,
			 &acg_dev->dev->dev_tgt_dev_list,
			 dev_tgt_dev_list_entry)
		{
			if (tgt_dev->acg_dev == acg_dev)
				scst_free_tgt_dev(tgt_dev);
		}
		scst_free_acg_dev(acg_dev);
	}

	__scst_resume_activity();

	/* Freeing names */
	list_for_each_entry_safe(n, nn, &acg->acn_list, 
		acn_list_entry)
	{
		list_del(&n->acn_list_entry);
		TRACE_MEM("kfree() for scst_acn->name: %p", n->name);
		kfree(n->name);
		TRACE_MEM("kfree() for scst_acn: %p", n);
		kfree(n);
	}
	INIT_LIST_HEAD(&acg->acn_list);

	TRACE_MEM("kfree for acg: %p", acg);
	kfree(acg);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/*
 * No spin locks supposed to be held, scst_mutex - held.
 * The activity is suspended.
 */
static struct scst_tgt_dev *scst_alloc_add_tgt_dev(struct scst_session *sess,
	struct scst_acg_dev *acg_dev)
{
	struct scst_tgt_dev *tgt_dev;
	struct scst_device *dev = acg_dev->dev;
	int res;

	TRACE_ENTRY();

	tgt_dev = kmem_cache_alloc(scst_tgtd_cachep, GFP_KERNEL);
	TRACE_MEM("kmem_cache_alloc(GFP_KERNEL) for tgt_dev (%zd): %p",
	      sizeof(*tgt_dev), tgt_dev);
	if (tgt_dev != NULL)
		memset(tgt_dev, 0, sizeof(*tgt_dev));
	else {
		TRACE(TRACE_OUT_OF_MEM, "%s",
		      "Allocation of scst_tgt_dev failed");
		goto out;
	}

	tgt_dev->acg_dev = acg_dev;
	tgt_dev->sess = sess;
	tgt_dev->cmd_count = 0;

	if (dev->scsi_dev != NULL) {
		TRACE(TRACE_DEBUG, "host=%d, channel=%d, id=%d, lun=%d, "
		      "SCST lun=%Ld", dev->scsi_dev->host->host_no, 
		      dev->scsi_dev->channel, dev->scsi_dev->id, 
		      dev->scsi_dev->lun, (uint64_t)tgt_dev->acg_dev->lun);
	}
	else {
		TRACE(TRACE_MINOR, "Virtual device SCST lun=%Ld", 
		      (uint64_t)tgt_dev->acg_dev->lun);
	}

	spin_lock_init(&tgt_dev->tgt_dev_lock);
	INIT_LIST_HEAD(&tgt_dev->UA_list);
	spin_lock_init(&tgt_dev->sn_lock);
	INIT_LIST_HEAD(&tgt_dev->deferred_cmd_list);
	INIT_LIST_HEAD(&tgt_dev->skipped_sn_list);

	spin_lock_bh(&scst_temp_UA_lock);
	scst_set_sense(scst_temp_UA, sizeof(scst_temp_UA),
		SCST_LOAD_SENSE(scst_sense_reset_UA));
	scst_alloc_set_UA(tgt_dev, scst_temp_UA, sizeof(scst_temp_UA));
	spin_unlock_bh(&scst_temp_UA_lock);

	tm_dbg_init_tgt_dev(tgt_dev, acg_dev);

	if (dev->handler && dev->handler->attach_tgt) {
		TRACE_DBG("Calling dev handler's attach_tgt(%p)",
		      tgt_dev);
		res = dev->handler->attach_tgt(tgt_dev);
		TRACE_DBG("%s", "Dev handler's attach_tgt() returned");
		if (res != 0) {
			PRINT_ERROR_PR("Device handler's %s attach_tgt() "
			    "failed: %d", dev->handler->name, res);
			goto out_free;
		}
	}
	
	list_add_tail(&tgt_dev->dev_tgt_dev_list_entry, &dev->dev_tgt_dev_list);
	if (dev->dev_reserved)
		__set_bit(SCST_TGT_DEV_RESERVED, &tgt_dev->tgt_dev_flags);

	list_add_tail(&tgt_dev->sess_tgt_dev_list_entry,
		&sess->sess_tgt_dev_list);

out:
	TRACE_EXIT();
	return tgt_dev;

out_free:
	TRACE_MEM("kfree for tgt_dev: %p", tgt_dev);
	kmem_cache_free(scst_tgtd_cachep, tgt_dev);
	tgt_dev = NULL;
	goto out;
}

static void scst_send_release(struct scst_tgt_dev *tgt_dev);

/* 
 * No locks supposed to be held, scst_mutex - held.
 * The activity is suspended.
 */
void scst_reset_tgt_dev(struct scst_tgt_dev *tgt_dev, int nexus_loss)
{
	struct scst_device *dev = tgt_dev->acg_dev->dev;

	if (dev->dev_reserved &&
	    !test_bit(SCST_TGT_DEV_RESERVED, &tgt_dev->tgt_dev_flags)) 
	{
		/* This is one who holds the reservation */
		struct scst_tgt_dev *tgt_dev_tmp;
		list_for_each_entry(tgt_dev_tmp, &dev->dev_tgt_dev_list,
				    dev_tgt_dev_list_entry) 
		{
			clear_bit(SCST_TGT_DEV_RESERVED,
				    &tgt_dev_tmp->tgt_dev_flags);
		}
		dev->dev_reserved = 0;

		scst_send_release(tgt_dev);
	}

	spin_lock_bh(&scst_temp_UA_lock);
	if (nexus_loss) {
		scst_set_sense(scst_temp_UA, sizeof(scst_temp_UA),
			SCST_LOAD_SENSE(scst_sense_nexus_loss_UA));
	} else {
		scst_set_sense(scst_temp_UA, sizeof(scst_temp_UA),
			SCST_LOAD_SENSE(scst_sense_reset_UA));
	}
	scst_check_set_UA(tgt_dev, scst_temp_UA, sizeof(scst_temp_UA));
	spin_unlock_bh(&scst_temp_UA_lock);
}

/* 
 * No locks supposed to be held, scst_mutex - held.
 * The activity is suspended.
 */
static void scst_free_tgt_dev(struct scst_tgt_dev *tgt_dev)
{
	struct scst_device *dev = tgt_dev->acg_dev->dev;

	TRACE_ENTRY();

	tm_dbg_deinit_tgt_dev(tgt_dev);

	list_del(&tgt_dev->dev_tgt_dev_list_entry);
	list_del(&tgt_dev->sess_tgt_dev_list_entry);

	scst_reset_tgt_dev(tgt_dev, 0);
	scst_free_all_UA(tgt_dev);

	if (dev->handler && dev->handler->detach_tgt) {
		TRACE_DBG("Calling dev handler's detach_tgt(%p)",
		      tgt_dev);
		dev->handler->detach_tgt(tgt_dev);
		TRACE_DBG("%s", "Dev handler's detach_tgt() returned");
	}

	TRACE_MEM("kfree for tgt_dev: %p", tgt_dev);
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

	__scst_suspend_activity();

	INIT_LIST_HEAD(&sess->sess_tgt_dev_list);
	list_for_each_entry(acg_dev, &sess->acg->acg_dev_list, 
		acg_dev_list_entry)
	{
		tgt_dev = scst_alloc_add_tgt_dev(sess, acg_dev);
		if (tgt_dev == NULL) {
			res = -ENOMEM;
			goto out_free;
		}
	}

out_resume:
	__scst_resume_activity();

	TRACE_EXIT();
	return res;

out_free:
	scst_sess_free_tgt_devs(sess);
	goto out_resume;
}

/* scst_mutex supposed to be held and activity suspended */
void scst_sess_free_tgt_devs(struct scst_session *sess)
{
	struct scst_tgt_dev *tgt_dev, *t;

	TRACE_ENTRY();
	
	/* The session is going down, no users, so no locks */
	list_for_each_entry_safe(tgt_dev, t, &sess->sess_tgt_dev_list,
				 sess_tgt_dev_list_entry) 
	{
		scst_free_tgt_dev(tgt_dev);
	}
	INIT_LIST_HEAD(&sess->sess_tgt_dev_list);

	TRACE_EXIT();
	return;
}

/* scst_mutex supposed to be held */
int scst_acg_add_dev(struct scst_acg *acg, struct scst_device *dev, lun_t lun,
	int read_only)
{
	int res = 0;
	struct scst_acg_dev *acg_dev;
	struct scst_tgt_dev *tgt_dev;
	struct scst_session *sess;
	LIST_HEAD(tmp_tgt_dev_list);
	
	TRACE_ENTRY();
	
	INIT_LIST_HEAD(&tmp_tgt_dev_list);
	
#ifdef EXTRACHECKS
	list_for_each_entry(acg_dev, &acg->acg_dev_list, acg_dev_list_entry) {
		if (acg_dev->dev == dev) {
			PRINT_ERROR_PR("Device is already in group %s", 
				acg->acg_name);
			res = -EINVAL;
			goto out;
		}
	}
#endif
	
	acg_dev = scst_alloc_acg_dev(acg, dev, lun);
	if (acg_dev == NULL) {
		res = -ENOMEM;
		goto out;
	}
	acg_dev->rd_only_flag = read_only;

	__scst_suspend_activity();

	TRACE_DBG("Adding acg_dev %p to acg_dev_list and dev_acg_dev_list", 
		acg_dev);
	list_add_tail(&acg_dev->acg_dev_list_entry, &acg->acg_dev_list);
	list_add_tail(&acg_dev->dev_acg_dev_list_entry, &dev->dev_acg_dev_list);
	
	list_for_each_entry(sess, &acg->acg_sess_list, acg_sess_list_entry) 
	{
		tgt_dev = scst_alloc_add_tgt_dev(sess, acg_dev);
		if (tgt_dev == NULL) {
			res = -ENOMEM;
			goto out_free;
		}
		list_add_tail(&tgt_dev->extra_tgt_dev_list_entry,
			      &tmp_tgt_dev_list);
	}

out_resume:
	__scst_resume_activity();

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	list_for_each_entry(tgt_dev, &tmp_tgt_dev_list,
			 extra_tgt_dev_list_entry) 
	{
		scst_free_tgt_dev(tgt_dev);
	}
	scst_free_acg_dev(acg_dev);
	goto out_resume;
}

/* scst_mutex supposed to be held */
int scst_acg_remove_dev(struct scst_acg *acg, struct scst_device *dev)
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
		PRINT_ERROR_PR("Device is not found in group %s", acg->acg_name);
		res = -EINVAL;
		goto out;
	}

	__scst_suspend_activity();

	list_for_each_entry_safe(tgt_dev, tt, &dev->dev_tgt_dev_list,
		 dev_tgt_dev_list_entry) 
	{
		if (tgt_dev->acg_dev == acg_dev)
			scst_free_tgt_dev(tgt_dev);
	}
	scst_free_acg_dev(acg_dev);

	__scst_resume_activity();

out:	
	TRACE_EXIT_RES(res);
	return res;
}

/* scst_mutex supposed to be held */
int scst_acg_add_name(struct scst_acg *acg, const char *name)
{
	int res = 0;
	struct scst_acn *n;
	int len;
	char *nm;
	
	TRACE_ENTRY();

	list_for_each_entry(n, &acg->acn_list, acn_list_entry) 
	{
		if (strcmp(n->name, name) == 0) {
			PRINT_ERROR_PR("Name %s already exists in access "
				"control group %s", name, acg->acg_name);
			res = -EINVAL;
			goto out;
		}
	}
	
	n = kmalloc(sizeof(*n), GFP_KERNEL);
	TRACE_MEM("kmalloc(GFP_KERNEL) for scst_acn (%zd): %p", sizeof(*n), n);
	if (n == NULL) {
		PRINT_ERROR_PR("%s", "Unable to allocate scst_acn");
		res = -ENOMEM;
		goto out;
	}
	
	len = strlen(name);
	nm = kmalloc(len + 1, GFP_KERNEL);
	TRACE_MEM("kmalloc(GFP_KERNEL) for scst_acn->name (%d): %p",
		  len + 1, nm);
	if (nm == NULL) {
		PRINT_ERROR_PR("%s", "Unable to allocate scst_acn->name");
		res = -ENOMEM;
		goto out_free;
	}
	
	strcpy(nm, name);
	n->name = nm;
	
	list_add_tail(&n->acn_list_entry, &acg->acn_list);

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	TRACE_MEM("kfree() for scst_acn: %p", n);
	kfree(n);
	goto out;
}

/* scst_mutex supposed to be held */
int scst_acg_remove_name(struct scst_acg *acg, const char *name)
{
	int res = -EINVAL;
	struct scst_acn *n;
	
	TRACE_ENTRY();
	
	list_for_each_entry(n, &acg->acn_list, acn_list_entry)
	{
		if (strcmp(n->name, name) == 0) {
			list_del(&n->acn_list_entry);
			TRACE_MEM("kfree() for scst_acn->name: %p", n->name);
		        kfree(n->name);
			TRACE_MEM("kfree() for scst_acn: %p", n);
		        kfree(n);
			res = 0;
			break;
		}
	}
	
	if (res != 0) {
		PRINT_ERROR_PR("Unable to find name %s in access control "
			"group %s", name, acg->acg_name);
	}

	TRACE_EXIT_RES(res);
	return res;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
static void scst_req_done(struct scsi_cmnd *scsi_cmd)
{
	struct scsi_request *req;

	TRACE_ENTRY();

	if (scsi_cmd && (req = scsi_cmd->sc_request)) {
		if (req) {
			if (req->sr_bufflen) {
				TRACE_MEM("kfree for req->sr_buffer: %p",
				      req->sr_buffer);
				kfree(req->sr_buffer);
			}
			scsi_release_request(req);
		}
	}

	TRACE_EXIT();
	return;
}

static void scst_send_release(struct scst_tgt_dev *tgt_dev)
{
	struct scsi_request *req;
	struct scsi_device *scsi_dev;
	uint8_t cdb[6];

	TRACE_ENTRY();
	
	if (tgt_dev->acg_dev->dev->scsi_dev == NULL)
		goto out;

	scsi_dev = tgt_dev->acg_dev->dev->scsi_dev;

	req = scsi_allocate_request(scsi_dev, GFP_KERNEL);
	if (req == NULL) {
		PRINT_ERROR_PR("Allocation of scsi_request failed: unable "
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
	req->sr_request->rq_disk = tgt_dev->acg_dev->dev->rq_disk;
	req->sr_sense_buffer[0] = 0;

	TRACE(TRACE_DEBUG | TRACE_SCSI, "Sending RELEASE req %p to SCSI "
		"mid-level", req);
	scst_do_req(req, req->sr_cmnd, (void *)req->sr_buffer, req->sr_bufflen,
		    scst_req_done, SCST_DEFAULT_TIMEOUT, 3);

out:
	TRACE_EXIT();
	return;
}
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18) */
static void scst_send_release(struct scst_tgt_dev *tgt_dev)
{
	struct scsi_device *scsi_dev;
	unsigned char cdb[6];
	unsigned char sense[SCSI_SENSE_BUFFERSIZE];
	int rc;

	TRACE_ENTRY();
	
	if (tgt_dev->acg_dev->dev->scsi_dev == NULL)
		goto out;

	scsi_dev = tgt_dev->acg_dev->dev->scsi_dev;

	memset(cdb, 0, sizeof(cdb));
	cdb[0] = RELEASE;
	cdb[1] = (scsi_dev->scsi_level <= SCSI_2) ?
	    ((scsi_dev->lun << 5) & 0xe0) : 0;

	TRACE(TRACE_DEBUG | TRACE_SCSI, "%s", "Sending RELEASE req to SCSI "
		"mid-level");
	rc = scsi_execute(scsi_dev, cdb, SCST_DATA_NONE, NULL, 0,
			sense, SCST_DEFAULT_TIMEOUT,
			3, GFP_KERNEL);
	if (rc) {
		PRINT_INFO_PR("scsi_execute() failed: %d", rc);
		goto out;
	}

out:
	TRACE_EXIT();
	return;
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18) */

struct scst_session *scst_alloc_session(struct scst_tgt *tgt, int gfp_mask,
	const char *initiator_name)
{
	struct scst_session *sess;
	int len;
	char *nm;

	TRACE_ENTRY();

	sess = kmem_cache_alloc(scst_sess_cachep, gfp_mask);
	TRACE_MEM("kmem_cache_alloc() for sess (%zd): %p", sizeof(*sess), sess);
	if (sess != NULL)
		memset(sess, 0, sizeof(*sess));
	else {
		TRACE(TRACE_OUT_OF_MEM, "%s",
		      "Allocation of scst_session failed");
		goto out;
	}

	sess->init_phase = SCST_SESS_IPH_INITING;
	atomic_set(&sess->refcnt, 0);
	INIT_LIST_HEAD(&sess->sess_tgt_dev_list);
	INIT_LIST_HEAD(&sess->search_cmd_list);
	sess->tgt = tgt;
	INIT_LIST_HEAD(&sess->init_deferred_cmd_list);
	INIT_LIST_HEAD(&sess->init_deferred_mcmd_list);
	
	len = strlen(initiator_name);
	nm = kmalloc(len + 1, gfp_mask);
	TRACE_MEM("kmalloc(GFP_KERNEL) for sess->initiator_name (%d): %p",
		  len + 1, nm);
	if (nm == NULL) {
		PRINT_ERROR_PR("%s", "Unable to allocate sess->initiator_name");
		goto out_free;
	}
	
	strcpy(nm, initiator_name);
	sess->initiator_name = nm;
	
out:
	TRACE_EXIT();
	return sess;

out_free:
	TRACE_MEM("kfree() for sess: %p", sess);
	kmem_cache_free(scst_sess_cachep, sess);
	sess = NULL;
	goto out;
}

void scst_free_session(struct scst_session *sess)
{
	TRACE_ENTRY();

	down(&scst_mutex);
	TRACE_DBG("Removing sess %p from the list", sess);
	list_del(&sess->sess_list_entry);
	TRACE_DBG("Removing session %p from acg %s", sess, sess->acg->acg_name);
	list_del(&sess->acg_sess_list_entry);
	
	__scst_suspend_activity();
	scst_sess_free_tgt_devs(sess);
	__scst_resume_activity();

	wake_up_all(&sess->tgt->unreg_waitQ);

	up(&scst_mutex);

	TRACE_MEM("kfree for sess->initiator_name: %p", sess->initiator_name);
	kfree(sess->initiator_name);

	TRACE_MEM("kfree for sess: %p", sess);
	kmem_cache_free(scst_sess_cachep, sess);

	TRACE_EXIT();
	return;
}

void scst_free_session_callback(struct scst_session *sess)
{
	struct semaphore *shm;

	TRACE_ENTRY();

	TRACE_DBG("Freeing session %p", sess);

	shm = sess->shutdown_mutex;

	if (sess->unreg_done_fn) {
		TRACE_DBG("Calling unreg_done_fn(%p)", sess);
		sess->unreg_done_fn(sess);
		TRACE_DBG("%s", "unreg_done_fn() returned");
	}
	scst_free_session(sess);

	if (shm)
		up(shm);

	TRACE_EXIT();
	return;
}

void scst_sched_session_free(struct scst_session *sess)
{
	unsigned long flags;

	TRACE_ENTRY();

	spin_lock_irqsave(&scst_mgmt_lock, flags);
	TRACE_DBG("Adding sess %p to scst_sess_mgmt_list", sess);
	list_add_tail(&sess->sess_mgmt_list_entry, &scst_sess_mgmt_list);
	spin_unlock_irqrestore(&scst_mgmt_lock, flags);
	
	wake_up(&scst_mgmt_waitQ);

	TRACE_EXIT();
	return;
}

struct scst_cmd *scst_alloc_cmd(int gfp_mask)
{
	struct scst_cmd *cmd;

	TRACE_ENTRY();

	cmd = kmem_cache_alloc(scst_cmd_cachep, gfp_mask);
	TRACE_MEM("kmem_cache_alloc() for cmd (%zd): %p", sizeof(*cmd), cmd);
	if (cmd != NULL)
		memset(cmd, 0, sizeof(*cmd));
	else {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of scst_cmd failed");
		goto out;
	}

	cmd->queue_type = SCST_CMD_QUEUE_UNTAGGED;
	cmd->timeout = SCST_DEFAULT_TIMEOUT;
	cmd->retries = SCST_DEFAULT_RETRIES;
	cmd->data_len = -1;
	cmd->tgt_resp_flags = SCST_TSC_FLAG_STATUS;
	cmd->resp_data_len = -1;

out:
	TRACE_EXIT();
	return cmd;
}

static void scst_destroy_put_cmd(struct scst_cmd *cmd)
{
	scst_sess_put(cmd->sess);

	/* At this point tgt_dev can be dead, but the pointer remains not-NULL */
	if (likely(cmd->tgt_dev != NULL))
		scst_dec_cmd_count();

	scst_destroy_cmd(cmd);
	return;
}

/* No locks supposed to be held. Must be called only from scst_finish_cmd()! */
void scst_free_cmd(struct scst_cmd *cmd)
{
	int destroy = 1;

	TRACE_ENTRY();

	BUG_ON(cmd->blocking);

#if defined(EXTRACHECKS) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18))
	if (cmd->scsi_req) {
		PRINT_ERROR_PR("%s: %s", __FUNCTION__, "Cmd with unfreed "
			"scsi_req!");
		scst_release_request(cmd);
	}
#endif

	TRACE_DBG("Calling target's on_free_cmd(%p)", cmd);
	cmd->tgtt->on_free_cmd(cmd);
	TRACE_DBG("%s", "Target's on_free_cmd() returned");

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

	if (likely(cmd->tgt_dev != NULL)) {
#ifdef EXTRACHECKS
		if (cmd->sent_to_midlev == 0) {
			PRINT_ERROR_PR("Finishing not executed cmd (opcode %d, "
			     "target %s, lun %Ld, sn %d, expected_sn %d)", 
			     cmd->cdb[0], cmd->tgtt->name, (uint64_t)cmd->lun, 
			     cmd->sn, cmd->tgt_dev->expected_sn);
			scst_inc_expected_sn_unblock(cmd->tgt_dev, cmd, 0);
		}
#endif
		if (unlikely(test_bit(SCST_CMD_OUT_OF_SN, 
				&cmd->cmd_flags)))
		{
			spin_lock_bh(&cmd->tgt_dev->sn_lock);
			set_bit(SCST_CMD_CAN_BE_DESTROYED, 
				&cmd->cmd_flags);
			barrier(); /* to reread SCST_CMD_OUT_OF_SN */
			destroy = !test_bit(SCST_CMD_OUT_OF_SN, 
					&cmd->cmd_flags);
			TRACE(TRACE_SCSI_SERIALIZING, "Out of SN "
				"cmd %p (tag %d, sn %d), destroy=%d", cmd,
				cmd->tag, cmd->sn, destroy);
			spin_unlock_bh(&cmd->tgt_dev->sn_lock);
		}
	}

	if (likely(destroy))
		scst_destroy_put_cmd(cmd);

	TRACE_EXIT();
	return;
}

/* No locks supposed to be held. */
void scst_check_retries(struct scst_tgt *tgt, int processible_env)
{
	int need_wake_up = 0;

	TRACE_ENTRY();

	/* 
	 * We don't worry about overflow of finished_cmds, because we check 
	 * only for its change 
	 */
	atomic_inc(&tgt->finished_cmds);
	smp_mb__after_atomic_inc();
	if (unlikely(tgt->retry_cmds > 0)) 
	{
		struct scst_cmd *c, *tc;
		unsigned long flags;

		TRACE(TRACE_RETRY, "Checking retry cmd list (retry_cmds %d)",
		      tgt->retry_cmds);

		spin_lock_irqsave(&tgt->tgt_lock, flags);
		spin_lock(&scst_list_lock);

		list_for_each_entry_safe(c, tc, &tgt->retry_cmd_list,
				cmd_list_entry)
		{
			tgt->retry_cmds--;

			TRACE(TRACE_RETRY, "Moving retry cmd %p to active cmd "
			    "list (retry_cmds left %d)", c, tgt->retry_cmds);
			list_move(&c->cmd_list_entry, &scst_active_cmd_list);

			need_wake_up++;
			if (need_wake_up >= 2) /* "slow start" */
				break; 
		}

		spin_unlock(&scst_list_lock);
		spin_unlock_irqrestore(&tgt->tgt_lock, flags);
	}

	if (need_wake_up && !processible_env)
		wake_up(&scst_list_waitQ);

	TRACE_EXIT();
	return;
}

void scst_tgt_retry_timer_fn(unsigned long arg)
{
	struct scst_tgt *tgt = (struct scst_tgt*)arg;
	unsigned long flags;

	TRACE(TRACE_RETRY, "Retry timer expired (retry_cmds %d)",
		tgt->retry_cmds);

	spin_lock_irqsave(&tgt->tgt_lock, flags);
	tgt->retry_timer_active = 0;
	spin_unlock_irqrestore(&tgt->tgt_lock, flags);

	scst_check_retries(tgt, 0);

	TRACE_EXIT();
	return;
}

struct scst_mgmt_cmd *scst_alloc_mgmt_cmd(int gfp_mask)
{
	struct scst_mgmt_cmd *mcmd;

	TRACE_ENTRY();

	mcmd = mempool_alloc(scst_mgmt_mempool, gfp_mask);
	TRACE_MEM("mempool_alloc() for mgmt cmd (%zd): %p", sizeof(*mcmd),
		mcmd);
	if (mcmd == NULL) {
		PRINT_ERROR("%s", "Allocation of management command "
			"failed, some commands and their data could leak");
		goto out;
	}
	memset(mcmd, 0, sizeof(*mcmd));

out:
	TRACE_EXIT();
	return mcmd;
}

void scst_free_mgmt_cmd(struct scst_mgmt_cmd *mcmd, int del)
{
	unsigned long flags;

	TRACE_ENTRY();

	spin_lock_irqsave(&scst_list_lock, flags);
	if (del)
		list_del(&mcmd->mgmt_cmd_list_entry);
	mcmd->sess->sess_cmd_count--;
	spin_unlock_irqrestore(&scst_list_lock, flags);

	scst_sess_put(mcmd->sess);

	if (mcmd->mcmd_tgt_dev != NULL)
		scst_dec_cmd_count();

	TRACE_MEM("mempool_free for mgmt cmd: %p", mcmd);
	mempool_free(mcmd, scst_mgmt_mempool);

	TRACE_EXIT();
	return;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
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

int scst_alloc_space(struct scst_cmd *cmd)
{
	int tgt_sg = cmd->tgt->sg_tablesize;
	int ini_sg;
	int gfp_mask;
	int res = -ENOMEM;
	int ini_unchecked_isa_dma, ini_use_clustering;
	struct sgv_pool *pool;
	struct sgv_pool_obj *sgv;

	TRACE_ENTRY();

	if (cmd->data_buf_alloced) {
		TRACE_MEM("%s", "data_buf_alloced set, returning");
		BUG_ON(cmd->sg == NULL);
		res = 0;
		goto out;
	}

	gfp_mask = __GFP_NOWARN;
	gfp_mask |= (scst_cmd_atomic(cmd) ? GFP_ATOMIC : GFP_KERNEL);
	pool = &scst_sgv.norm;

	if (cmd->dev->scsi_dev != NULL) {
		ini_sg = cmd->dev->scsi_dev->host->sg_tablesize;
		ini_unchecked_isa_dma = 
			cmd->dev->scsi_dev->host->unchecked_isa_dma;
		ini_use_clustering = 
			(cmd->dev->scsi_dev->host->use_clustering == 
				ENABLE_CLUSTERING);
	}
	else {
		ini_sg = (1 << 15) /* infinite */;
		ini_unchecked_isa_dma = 0;
		ini_use_clustering = 0;
	}

	if (cmd->tgtt->use_clustering || ini_use_clustering)
	{
		TRACE_MEM("%s", "Use clustering");
		pool = &scst_sgv.norm_clust;
	}

	if (cmd->tgtt->unchecked_isa_dma || ini_unchecked_isa_dma) {
		TRACE_MEM("%s", "Use ISA DMA memory");
		gfp_mask |= GFP_DMA;
		pool = &scst_sgv.dma;
	} else {
#ifdef SCST_HIGHMEM
		gfp_mask |= __GFP_HIGHMEM;
		pool = &scst_sgv.highmem;
#endif
	}

	sgv = sgv_pool_alloc(pool, cmd->bufflen, gfp_mask, &cmd->sg_cnt);
	if (sgv == NULL)
		goto out;

	if (unlikely(cmd->sg_cnt > ini_sg)) {
		static int ll;
		if (ll < 10) {
			PRINT_INFO("Unable to complete command due to "
				"underlying device SG IO count limitation "
				"(requested %d, available %d)", cmd->sg_cnt,
				ini_sg);
			ll++;
		}
		goto out_sgv_free;
	}

	if (unlikely(cmd->sg_cnt > tgt_sg)) {
		static int ll;
		if (ll < 10) {
			PRINT_INFO("Unable to complete command due to "
				"target device %s SG IO count limitation "
				"(requested %d, available %d)", cmd->tgtt->name,
				cmd->sg_cnt, tgt_sg);
			ll++;
		}
		goto out_sgv_free;
	}

	cmd->sgv = sgv;
	cmd->sg = sgv_pool_sg(sgv);
	
	res = 0;

out:
	TRACE_EXIT();
	return res;

out_sgv_free:
	sgv_pool_free(sgv);
	cmd->sg_cnt = 0;
	goto out;
}

void scst_release_space(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	if (cmd->data_buf_alloced) {
		TRACE_MEM("%s", "data_buf_alloced set, returning");
		goto out;
	}

	if (cmd->sgv) {
		scst_check_restore_sg_buff(cmd);
		sgv_pool_free(cmd->sgv);
	}

	cmd->sgv = NULL;
	cmd->sg_cnt = 0;
	cmd->sg = NULL;
	cmd->bufflen = 0;
	cmd->data_len = 0;

out:
	TRACE_EXIT();
	return;
}

int __scst_get_buf(struct scst_cmd *cmd, uint8_t **buf)
{
	int res = 0;
	struct scatterlist *sg = cmd->sg;
	int i = cmd->get_sg_buf_entry_num;
	
	TRACE_ENTRY();
	
	*buf = NULL;
	
	if (i >= cmd->sg_cnt)
		goto out;
#ifdef SCST_HIGHMEM
	/* 
	 * HIGHMEM pages not merged (clustered), so if it's 
	 * not HIGHMEM page, kmap() is the same as page_address()
	 */
	if (scst_cmd_atomic(cmd)) {
		enum km_type km;
		if (in_softirq())
			km = KM_SOFTIRQ0;
		else
			km = KM_USER0;
		*buf = kmap_atomic(sg[i].page, km);
	} else
		*buf = kmap(sg[i].page);
#else
	*buf = page_address(sg[i].page);
#endif
	res = sg[i].length;
	cmd->get_sg_buf_entry_num++;
	
out:
	TRACE_EXIT_RES(res);
	return res;
}

static const int SCST_CDB_LENGTH[8] = { 6, 10, 10, -1, 16, 12, -1, -1 };

#define SCST_CDB_GROUP(opcode)   ((opcode >> 5) & 0x7)
#define SCST_GET_CDB_LEN(opcode) SCST_CDB_LENGTH[SCST_CDB_GROUP(opcode)]

int scst_get_cdb_len(const uint8_t *cdb)
{
	return SCST_GET_CDB_LEN(cdb[0]);
}

int scst_get_cdb_info(const uint8_t *cdb_p, int dev_type,
		      struct scst_info_cdb *info_p)
{
	int i, res = 0;
	uint8_t op;
	const struct scst_sdbops *ptr = NULL;

	TRACE_ENTRY();

	memset(info_p, 0, sizeof(*info_p));
	info_p->direction = SCST_DATA_NONE;
	info_p->op_name = "NOOP";
	op = *cdb_p;	/* get clear opcode */

	TRACE(TRACE_SCSI, "opcode=%02x, cdblen=%d bytes, tblsize=%zd, "
		"dev_type=%d", op, SCST_GET_CDB_LEN(op), SCST_CDB_TBL_SIZE,
		dev_type);

	i = scst_scsi_op_list[op];
	while (i < SCST_CDB_TBL_SIZE && scst_scsi_op_table[i].ops == op) {
		if (scst_scsi_op_table[i].devkey[dev_type] != SCST_CDB_NOTSUPP) {
			ptr = &scst_scsi_op_table[i];
#if 0
			TRACE(TRACE_SCSI, "op = 0x%02x+'%c%c%c%c%c%c%c%c%c%c'+<%s>", 
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

			TRACE(TRACE_SCSI,
			      "direction=%d size_field_len=%d fixed=%d flag1=%d flag2=%d",
			      ptr->direction,
			      ptr->size_field_len,
			      ptr->fixed, ptr->flag1, ptr->flag2);
#endif
			break;
		}
		i++;
	}

	if (ptr == NULL) {
		/* opcode not found or now not used !!! */
		TRACE(TRACE_SCSI, "Unknown opcode 0x%x for type %d", op,
		      dev_type);
		res = -1;
		goto out;
	}

	info_p->cdb_len = SCST_GET_CDB_LEN(op);
	info_p->op_name = ptr->op_name;
	/* 1. direction */
	info_p->direction = ptr->direction;
	if (info_p->direction == SCST_DATA_NONE)
		goto out;

	/* 2. flags */
	info_p->flags = ptr->fixed;

	/*
	 * CDB length needed, because we must know offsets:
	 * 1) for  6-bytes CDB len = 1 byte or 3 bytes(if real transfer exist)
	 * 2) for 10-bytes CDB len = 1 byte or 2 bytes(0x24,0x25 = 3)
	 * 3) for 12-bytes CDB len = 1 byte or 4 bytes
	 */

	/* 3. transfer_len */
	if (SCST_GET_CDB_LEN(op) == 6) {
		if (ptr->size_field_len == 3) {
			/* length = 3 bytes */
			info_p->transfer_len = (((*(cdb_p + 2)) & 0xff) << 16) +
			    (((*(cdb_p + 3)) & 0xff) << 8) +
			    ((*(cdb_p + 4)) & 0xff);
			info_p->transfer_len &= 0xffffff;
		} else if (ptr->size_field_len == 1) {
			/* 
			 * Warning!!! CDB 'READ BLOCK LIMITS'
			 * always returns 6-byte block with limits
			 * info_p->transfer_len = (int)(*(cdb_p + 4));
			 */
			info_p->transfer_len = ((op == READ_BLOCK_LIMITS) ?
						SCST_BLOCK_LIMIT_LEN : 
						*(cdb_p + 4)) & 0xff;
		}
	} else if (SCST_GET_CDB_LEN(op) == 10) {
		if (ptr->size_field_len == 3)
			/* 
			 * SET window usees 3 bytes length SET/GET WINDOW
			 * if ((uint8_t)ptr->ops == 0x24 || 0x25)
			 */
		{
			info_p->transfer_len = (((*(cdb_p + 6)) & 0xff) << 16) +
			    (((*(cdb_p + 7)) & 0xff) << 8) +
			    ((*(cdb_p + 8)) & 0xff);
			info_p->transfer_len &= 0xffffff;
		} else if (ptr->size_field_len == 2) {
			info_p->transfer_len = (((*(cdb_p + 7)) & 0xff) << 8) +
			    ((*(cdb_p + 8)) & 0xff);
			info_p->transfer_len &= 0xffff;
		} else if (ptr->size_field_len == 1) {
			info_p->transfer_len = (*(cdb_p + 8));

			/* opcode = READ-WRITE UPDATED BLOCK */
			if ((ptr->ops == 0x5d) ||
			    (ptr->ops == UPDATE_BLOCK) ||
			    (ptr->ops == WRITE_SAME)) {
				/* the opcode always returns 1 block */
				info_p->flags |= SCST_TRANSFER_LEN_TYPE_FIXED;
				info_p->transfer_len = 1;
			}

			if ((ptr->ops == COMPARE) || (ptr->ops == COPY_VERIFY)) {
				/* ese other place in CDB [3,4],5 */
				info_p->transfer_len = (*(cdb_p + 5));
			}

			info_p->transfer_len &= 0xff;
		}
	} else if (SCST_GET_CDB_LEN(op) == 12) {
		if (ptr->size_field_len == 4) {
			info_p->transfer_len = (((*(cdb_p + 6)) & 0xff) << 24) +
			    (((*(cdb_p + 7)) & 0xff) << 16) +
			    (((*(cdb_p + 8)) & 0xff) << 8) +
			    ((*(cdb_p + 9)) & 0xff);
			info_p->transfer_len &= 0xffffffff;
		} else if (ptr->size_field_len == 3) {
			info_p->transfer_len = (((*(cdb_p + 7)) & 0xff) << 16) +
			    (((*(cdb_p + 8)) & 0xff) << 8) +
			    ((*(cdb_p + 9)) & 0xff);
			info_p->transfer_len &= 0xffffff;
		} else if (ptr->size_field_len == 2) {
			info_p->transfer_len = (((*(cdb_p + 8)) & 0xff) << 8) +
			    ((*(cdb_p + 9)) & 0xff);
			info_p->transfer_len &= 0xffff;
		} else {
			if (ptr->size_field_len == 1) {
				info_p->transfer_len = (*(cdb_p + 9));
				info_p->transfer_len &= 0xff;
			}
		}
	} else if (SCST_GET_CDB_LEN(op) == 16) {
		if (ptr->size_field_len == 4) {
			info_p->transfer_len =
			    (((*(cdb_p + 10)) & 0xff) << 24) +
			    (((*(cdb_p + 11)) & 0xff) << 16) +
			    (((*(cdb_p + 12)) & 0xff) << 8) +
			    ((*(cdb_p + 13)) & 0xff);
		}
	}
	if (!info_p->transfer_len) {
		TRACE(TRACE_SCSI,
		      "Warning! transfer_len 0, direction %d change on " "%d",
		      info_p->direction, SCST_DATA_NONE);
		info_p->direction = SCST_DATA_NONE;
	}

out:
	TRACE_EXIT();
	return res;
}

void scst_scsi_op_list_init(void)
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

/*
 * Routine to extract a lun number from an 8-byte LUN structure
 * in network byte order (BE).
 * (see SAM-2, Section 4.12.3 page 40)
 * Supports 2 types of lun unpacking: peripheral and logical unit.
 */
lun_t scst_unpack_lun(const uint8_t *lun, int len)
{
	lun_t res = (lun_t)-1;
	int address_method;

	TRACE_ENTRY();

	TRACE_BUFF_FLAG(TRACE_DEBUG, "Raw LUN", lun, len);

	if (len < 2) {
		PRINT_ERROR_PR("Illegal lun length %d, expected 2 bytes or "
			"more", len);
		goto out;
	}

	if (len > 2) {
		switch(len) {
		case 8:
		{
			if ((*((uint64_t*)lun) & 
			  __constant_cpu_to_be64(0x0000FFFFFFFFFFFFLL)) != 0)
				goto out_err;
			break;
		}
		case 4:
			if (*((uint16_t*)&lun[2]) != 0)
				goto out_err;
			break;
		case 6:
			if (*((uint32_t*)&lun[2]) != 0)
				goto out_err;
			break;
		default:
			goto out_err;
		}
	}

	address_method = (*lun) >> 6;	/* high 2 bits of byte 0 */
	switch (address_method) {
	case 0:	/* peripheral device addressing method */
		if (*lun) {
			PRINT_ERROR_PR("Illegal BUS INDENTIFIER in LUN "
			     "peripheral device addressing method 0x%02x, "
			     "expected 0", *lun);
			break;
		}
		res = *(lun + 1);
		break;

	case 1:	/* flat space addressing method */
		res = *(lun + 1) | (((*lun) & 0x3f) << 8);
		break;

	case 2:	/* logical unit addressing method */
		if (*lun & 0x3f) {
			PRINT_ERROR_PR("Illegal BUS NUMBER in LUN logical unit "
				    "addressing method 0x%02x, expected 0",
				    *lun & 0x3f);
			break;
		}
		if (*(lun + 1) & 0xe0) {
			PRINT_ERROR_PR("Illegal TARGET in LUN logical unit "
				    "addressing method 0x%02x, expected 0",
				    (*(lun + 1) & 0xf8) >> 5);
			break;
		}
		res = *(lun + 1) & 0x1f;
		break;

	case 3:	/* extended logical unit addressing method */
	default:
		PRINT_ERROR_PR("Unimplemented LUN addressing method %u",
			    address_method);
		break;
	}

out:
	TRACE_EXIT_RES((int)res);
	return res;

out_err:
	PRINT_ERROR_PR("%s", "Multi-level LUN unimplemented");
	goto out;
}

/* Called under dev_lock and BH off */
void scst_process_reset(struct scst_device *dev,
	struct scst_session *originator, struct scst_cmd *exclude_cmd,
	struct scst_mgmt_cmd *mcmd)
{
	struct scst_tgt_dev *tgt_dev;
	struct scst_cmd *cmd, *tcmd;
	int wake = 0;

	TRACE_ENTRY();

	/* Clear RESERVE'ation, if necessary */
	if (dev->dev_reserved) {
		list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
				    dev_tgt_dev_list_entry) 
		{
			TRACE(TRACE_MGMT, "Clearing RESERVE'ation for tgt_dev "
				"lun %d", tgt_dev->acg_dev->lun);
			clear_bit(SCST_TGT_DEV_RESERVED,
				  &tgt_dev->tgt_dev_flags);
		}
		dev->dev_reserved = 0;
		/*
		 * There is no need to send RELEASE, since the device is going
		 * to be resetted
		 */
	}

	dev->dev_double_ua_possible = 1;
	dev->dev_serialized = 1;

	/* BH already off */
	spin_lock(&scst_temp_UA_lock);
	scst_set_sense(scst_temp_UA, sizeof(scst_temp_UA),
		SCST_LOAD_SENSE(scst_sense_reset_UA));
	__scst_process_UA(dev, exclude_cmd, scst_temp_UA, sizeof(scst_temp_UA),
		1);
	spin_unlock(&scst_temp_UA_lock);

	list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list, 
		dev_tgt_dev_list_entry) 
	{
		struct scst_session *sess = tgt_dev->sess;

		spin_lock_irq(&scst_list_lock);

		TRACE_DBG("Searching in search cmd list (sess=%p)", sess);
		list_for_each_entry(cmd, &sess->search_cmd_list, 
				search_cmd_list_entry) {
			if (cmd == exclude_cmd)
				continue;
			if ((cmd->tgt_dev == tgt_dev) ||
			    ((cmd->tgt_dev == NULL) && 
			     (cmd->lun == tgt_dev->acg_dev->lun))) {
			        scst_abort_cmd(cmd, mcmd, 
			        	(tgt_dev->sess != originator), 0);
			}
		}
		spin_unlock_irq(&scst_list_lock);
	}

	list_for_each_entry_safe(cmd, tcmd, &dev->blocked_cmd_list,
				blocked_cmd_list_entry) {
		if (test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags)) {
			list_del(&cmd->blocked_cmd_list_entry);
			TRACE_MGMT_DBG("Moving aborted blocked cmd %p "
				"to active cmd list", cmd);
			spin_lock_irq(&scst_list_lock);
			list_move_tail(&cmd->cmd_list_entry,
				&scst_active_cmd_list);
			spin_unlock_irq(&scst_list_lock);
			wake = 1;
		}
	}

	if (wake)
		wake_up(&scst_list_waitQ);

	TRACE_EXIT();
	return;
}

int scst_set_pending_UA(struct scst_cmd *cmd)
{
	int res = 0;
	struct scst_tgt_dev_UA *UA_entry;

	TRACE_ENTRY();

	TRACE(TRACE_MGMT, "Setting pending UA cmd %p", cmd);

	spin_lock_bh(&cmd->tgt_dev->tgt_dev_lock);

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

	scst_set_cmd_error_sense(cmd, UA_entry->UA_sense_buffer,
		sizeof(UA_entry->UA_sense_buffer));

	cmd->ua_ignore = 1;

	list_del(&UA_entry->UA_list_entry);


	TRACE_MEM("mempool_free for UA_entry: %p", UA_entry);
	mempool_free(UA_entry, scst_ua_mempool);

	if (list_empty(&cmd->tgt_dev->UA_list)) {
		clear_bit(SCST_TGT_DEV_UA_PENDING,
			  &cmd->tgt_dev->tgt_dev_flags);
	}

	spin_unlock_bh(&cmd->tgt_dev->tgt_dev_lock);

out:
	TRACE_EXIT_RES(res);
	return res;

out_unlock:
	spin_unlock_bh(&cmd->tgt_dev->tgt_dev_lock);
	goto out;
}

/* Called under dev_lock, tgt_dev_lock and BH off */
void scst_alloc_set_UA(struct scst_tgt_dev *tgt_dev,
	const uint8_t *sense, int sense_len)
{
	struct scst_tgt_dev_UA *UA_entry = NULL;

	TRACE_ENTRY();

	UA_entry = mempool_alloc(scst_ua_mempool, GFP_ATOMIC);
	TRACE_MEM("mempool_alloc(GFP_ATOMIC) for UA_entry (%zd): %p",
		sizeof(*UA_entry), UA_entry);
	if (UA_entry == NULL) {
		PRINT_ERROR_PR("%s", "UNIT ATTENTION memory "
		     "allocation failed. The UNIT ATTENTION "
		     "on some sessions will be missed");
		goto out;
	}
	memset(UA_entry, 0, sizeof(*UA_entry));

	if (sense_len > sizeof(UA_entry->UA_sense_buffer))
		sense_len = sizeof(UA_entry->UA_sense_buffer);
	memcpy(UA_entry->UA_sense_buffer, sense, sense_len);
	set_bit(SCST_TGT_DEV_UA_PENDING, &tgt_dev->tgt_dev_flags);
	smp_mb__after_set_bit();
	list_add_tail(&UA_entry->UA_list_entry, &tgt_dev->UA_list);

out:
	TRACE_EXIT();
	return;
}

/* Called under dev_lock and BH off */
void scst_check_set_UA(struct scst_tgt_dev *tgt_dev,
	const uint8_t *sense, int sense_len)
{
	int skip_UA = 0;
	struct scst_tgt_dev_UA *UA_entry_tmp;

	TRACE_ENTRY();

	spin_lock(&tgt_dev->tgt_dev_lock);

	list_for_each_entry(UA_entry_tmp, &tgt_dev->UA_list,
			    UA_list_entry) 
	{
		if (sense[12] == UA_entry_tmp->UA_sense_buffer[12]) {
			skip_UA = 1;
			break;
		}
	}

	if (skip_UA == 0)
		scst_alloc_set_UA(tgt_dev, sense, sense_len);

	spin_unlock(&tgt_dev->tgt_dev_lock);

	TRACE_EXIT();
	return;
}

/* Called under dev_lock and BH off */
void __scst_process_UA(struct scst_device *dev,
	struct scst_cmd *exclude, const uint8_t *sense, int sense_len,
	int internal)
{
	struct scst_tgt_dev *tgt_dev, *exclude_tgt_dev = NULL;

	TRACE_ENTRY();

	TRACE(TRACE_MGMT, "Processing UA dev %p", dev);

	if (exclude != NULL)
		exclude_tgt_dev = exclude->tgt_dev;

	/* Check for reset UA */
	if (!internal && (sense[12] == SCST_SENSE_ASC_UA_RESET)) {
		scst_process_reset(dev, (exclude != NULL) ? exclude->sess : NULL,
			exclude, NULL);
	}

	list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list, 
				dev_tgt_dev_list_entry) {
		if (tgt_dev != exclude_tgt_dev)
			scst_check_set_UA(tgt_dev, sense, sense_len);
	}

	TRACE_EXIT();
	return;
}

/* Called under tgt_dev_lock or when tgt_dev is unused */
void scst_free_all_UA(struct scst_tgt_dev *tgt_dev)
{
	struct scst_tgt_dev_UA *UA_entry, *t;

	TRACE_ENTRY();

	list_for_each_entry_safe(UA_entry, t, &tgt_dev->UA_list, UA_list_entry) {
		TRACE_MGMT_DBG("Clearing UA for tgt_dev lun %d", 
			tgt_dev->acg_dev->lun);
		list_del(&UA_entry->UA_list_entry);
		TRACE_MEM("kfree for UA_entry: %p", UA_entry);
		kfree(UA_entry);
	}
	INIT_LIST_HEAD(&tgt_dev->UA_list);
	clear_bit(SCST_TGT_DEV_UA_PENDING, &tgt_dev->tgt_dev_flags);

	TRACE_EXIT();
	return;
}

struct scst_cmd *__scst_check_deferred_commands(struct scst_tgt_dev *tgt_dev,
	int expected_sn)
{
	struct scst_cmd *cmd = NULL, *tcmd;

	if (tgt_dev->def_cmd_count == 0)
		goto out;

	spin_lock_bh(&tgt_dev->sn_lock);

restart:
	list_for_each_entry(tcmd, &tgt_dev->deferred_cmd_list,
				sn_cmd_list_entry) {
		if (tcmd->sn == expected_sn) {
			TRACE(TRACE_SCSI_SERIALIZING,
			      "Deferred command sn %d found", tcmd->sn);
			tgt_dev->def_cmd_count--;
			list_del(&tcmd->sn_cmd_list_entry);
			cmd = tcmd;
			goto out_unlock;
		}
	}

	list_for_each_entry(tcmd, &tgt_dev->skipped_sn_list,
				sn_cmd_list_entry) {
		if (tcmd->sn == expected_sn) {
			/* 
			 * !! At this point any pointer in tcmd, except      !!
			 * !! sn_cmd_list_entry, could be already destroyed  !!
			 */
			TRACE(TRACE_SCSI_SERIALIZING,
			      "cmd %p (tag %d) with skipped sn %d found", tcmd,
			      tcmd->tag, tcmd->sn);
			tgt_dev->def_cmd_count--;
			list_del(&tcmd->sn_cmd_list_entry);
			if (test_bit(SCST_CMD_CAN_BE_DESTROYED, 
					&tcmd->cmd_flags)) {
				scst_destroy_put_cmd(tcmd);
			} else {
				smp_mb__before_clear_bit();
				clear_bit(SCST_CMD_OUT_OF_SN, &tcmd->cmd_flags);
			}
			expected_sn = __scst_inc_expected_sn(tgt_dev);
			goto restart;
		}
	}

out_unlock:
	spin_unlock_bh(&tgt_dev->sn_lock);

out:
	return cmd;
}

/* No locks */
int scst_inc_on_dev_cmd(struct scst_cmd *cmd)
{
	int res = 0;
	struct scst_device *dev = cmd->dev;

	BUG_ON(cmd->blocking);

	atomic_inc(&dev->on_dev_count);

#ifdef STRICT_SERIALIZING
	spin_lock_bh(&dev->dev_lock);
	if (test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))
		goto out_unlock;
	if (dev->block_count > 0) {
		scst_dec_on_dev_cmd(cmd);
		TRACE_MGMT_DBG("Delaying cmd %p due to blocking or serializing"
		      "(tag %d, dev %p)", cmd, cmd->tag, dev);
		list_add_tail(&cmd->blocked_cmd_list_entry,
			      &dev->blocked_cmd_list);
		res = 1;
	} else {
		__scst_block_dev(cmd->dev);
		cmd->blocking = 1;
	}
	spin_unlock_bh(&dev->dev_lock);
	goto out;
#else
repeat:
	if (unlikely(dev->block_count > 0)) {
		spin_lock_bh(&dev->dev_lock);
		if (test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags))
			goto out_unlock;
		barrier(); /* to reread block_count */
		if (dev->block_count > 0) {
			scst_dec_on_dev_cmd(cmd);
			TRACE_MGMT_DBG("Delaying cmd %p due to blocking or "
				"serializing (tag %d, dev %p)", cmd,
				cmd->tag, dev);
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
	if (unlikely(cmd->dev->dev_serialized)) {
		spin_lock_bh(&dev->dev_lock);
		barrier(); /* to reread block_count */
		if (cmd->dev->block_count == 0) {
			TRACE_MGMT_DBG("cmd %p (tag %d), blocking further "
				"cmds due to serializing (dev %p)", cmd,
				cmd->tag, dev);
			__scst_block_dev(cmd->dev);
			cmd->blocking = 1;
		} else {
			spin_unlock_bh(&dev->dev_lock);
			goto repeat;
		}
		spin_unlock_bh(&dev->dev_lock);
	}
#endif

out:
	return res;

out_unlock:
	spin_unlock_bh(&dev->dev_lock);
	goto out;
}

/* Called under dev_lock */
void scst_unblock_cmds(struct scst_device *dev)
{
#ifdef STRICT_SERIALIZING
	struct scst_cmd *cmd;
	int found = 0;

	TRACE_ENTRY();

	list_for_each_entry(cmd, &dev->blocked_cmd_list,
				 blocked_cmd_list_entry) {
		/* 
		 * Since only one cmd per time is being executed, expected_sn
		 * can't change behind us, if the corresponding cmd is in
		 * blocked_cmd_list
		 */
		if ((cmd->tgt_dev && (cmd->sn == cmd->tgt_dev->expected_sn)) ||
		    (unlikely(cmd->internal) || unlikely(cmd->retry))) {
		    	unsigned long flags;
			list_del(&cmd->blocked_cmd_list_entry);
			TRACE_MGMT_DBG("Moving cmd %p to active cmd list", cmd);
			spin_lock_irqsave(&scst_list_lock, flags);
			list_move(&cmd->cmd_list_entry, &scst_active_cmd_list);
			spin_unlock_irqrestore(&scst_list_lock, flags);
			wake_up(&scst_list_waitQ);
			found = 1;
			break;
		}
	}
#ifdef EXTRACHECKS
	if (!found && !list_empty(&dev->blocked_cmd_list)) {
		TRACE(TRACE_MINOR, "%s", "No commands unblocked when "
			"blocked cmd list is not empty");
	}
#endif
#else /* STRICT_SERIALIZING */
	struct scst_cmd *cmd, *tcmd;
	unsigned long flags;

	TRACE_ENTRY();

	spin_lock_irqsave(&scst_list_lock, flags);
	list_for_each_entry_safe(cmd, tcmd, &dev->blocked_cmd_list,
				 blocked_cmd_list_entry) {
		list_del(&cmd->blocked_cmd_list_entry);
		TRACE_MGMT_DBG("Moving blocked cmd %p to active cmd list", cmd);
		list_move_tail(&cmd->cmd_list_entry, &scst_active_cmd_list);
		wake_up(&scst_list_waitQ);
	}
	spin_unlock_irqrestore(&scst_list_lock, flags);
#endif /* STRICT_SERIALIZING */

	TRACE_EXIT();
	return;
}

static struct scst_cmd *scst_inc_expected_sn(
	struct scst_tgt_dev *tgt_dev, struct scst_cmd *out_of_sn_cmd)
{
	struct scst_cmd *res = NULL;

	if (out_of_sn_cmd->sn == tgt_dev->expected_sn) {
		__scst_inc_expected_sn(tgt_dev);
	} else {
		spin_lock_bh(&tgt_dev->sn_lock);
		tgt_dev->def_cmd_count++;
		set_bit(SCST_CMD_OUT_OF_SN, &out_of_sn_cmd->cmd_flags);
		list_add_tail(&out_of_sn_cmd->sn_cmd_list_entry,
			      &tgt_dev->skipped_sn_list);
		TRACE(TRACE_SCSI_SERIALIZING, "out_of_sn_cmd %p with sn %d "
			"added to skipped_sn_list (expected_sn %d)",
			out_of_sn_cmd, out_of_sn_cmd->sn, tgt_dev->expected_sn);
		spin_unlock_bh(&tgt_dev->sn_lock);
		smp_mb(); /* just in case, we need new value of tgt_dev->expected_sn */
	}
	res = scst_check_deferred_commands(tgt_dev, tgt_dev->expected_sn);
	return res;
}

void scst_inc_expected_sn_unblock(struct scst_tgt_dev *tgt_dev,
	struct scst_cmd *cmd_sn, int locked)
{
	struct scst_cmd *cmd;

	TRACE_ENTRY();

	cmd = scst_inc_expected_sn(tgt_dev, cmd_sn);
	if (cmd != NULL) {
		unsigned long flags = 0;
		if (!locked)
			spin_lock_irqsave(&scst_list_lock, flags);
		TRACE(TRACE_SCSI_SERIALIZING, "cmd %p with sn %d "
			"moved to active cmd list", cmd, cmd->sn);
		list_move(&cmd->cmd_list_entry, &scst_active_cmd_list);
		if (!locked)
			spin_unlock_irqrestore(&scst_list_lock, flags);
		if (!cmd_sn->processible_env)
			wake_up(&scst_list_waitQ);
	}

	TRACE_EXIT();
	return;
}

#ifdef DEBUG
/* Original taken from the XFS code */
unsigned long scst_random(void)
{
	static int Inited;
	static unsigned long RandomValue;
	static spinlock_t lock = SPIN_LOCK_UNLOCKED;
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
	if (rv <= 0) rv += 2147483647;
	RandomValue = rv;
	spin_unlock_irqrestore(&lock, flags);
	return rv;
}
#endif

#ifdef DEBUG_TM

#define TM_DBG_STATE_ABORT		0
#define TM_DBG_STATE_RESET		1
#define TM_DBG_STATE_OFFLINE		2

#define INIT_TM_DBG_STATE		TM_DBG_STATE_ABORT

static void tm_dbg_timer_fn(unsigned long arg);

/* All serialized by scst_list_lock */
static int tm_dbg_release;
static int tm_dbg_blocked;
static LIST_HEAD(tm_dbg_delayed_cmd_list);
static int tm_dbg_delayed_cmds_count;
static int tm_dbg_passed_cmds_count;
static int tm_dbg_state;
static int tm_dbg_on_state_passes;
static DEFINE_TIMER(tm_dbg_timer, tm_dbg_timer_fn, 0, 0);

static const int tm_dbg_on_state_num_passes[] = { 10, 1, 0x7ffffff };

void tm_dbg_init_tgt_dev(struct scst_tgt_dev *tgt_dev,
	struct scst_acg_dev *acg_dev)
{
	if ((acg_dev->acg == scst_default_acg) && (acg_dev->lun == 0)) {
		/* Do TM debugging only for LUN 0 */
		tm_dbg_state = INIT_TM_DBG_STATE;
		tm_dbg_on_state_passes =
			tm_dbg_on_state_num_passes[tm_dbg_state];
		__set_bit(SCST_TGT_DEV_UNDER_TM_DBG, &tgt_dev->tgt_dev_flags);
		PRINT_INFO("LUN 0 connected from initiator %s is under "
			"TM debugging", tgt_dev->sess->tgt->tgtt->name);
	}
}

void tm_dbg_deinit_tgt_dev(struct scst_tgt_dev *tgt_dev)
{
	if (test_bit(SCST_TGT_DEV_UNDER_TM_DBG, &tgt_dev->tgt_dev_flags))
		del_timer_sync(&tm_dbg_timer);
}

static void tm_dbg_timer_fn(unsigned long arg)
{
	TRACE_MGMT_DBG("%s: delayed cmd timer expired", __func__);
	tm_dbg_release = 1;
	smp_mb();
	wake_up_all(&scst_list_waitQ);
}

/* Called under scst_list_lock */
static void tm_dbg_delay_cmd(struct scst_cmd *cmd)
{
	switch(tm_dbg_state) {
	case TM_DBG_STATE_ABORT:
		if (tm_dbg_delayed_cmds_count == 0) {
			unsigned long d = 58*HZ + (scst_random() % (4*HZ));
			TRACE_MGMT_DBG("%s: delaying timed cmd %p (tag %d) "
				"for %ld.%ld seconds (%ld HZ)", __func__, cmd, cmd->tag,
				d/HZ, (d%HZ)*100/HZ, d);
			mod_timer(&tm_dbg_timer, jiffies + d);
#if 0
			tm_dbg_blocked = 1;
#endif
		} else {
			TRACE_MGMT_DBG("%s: delaying another timed cmd %p "
				"(tag %d), delayed_cmds_count=%d", __func__, cmd,
				cmd->tag, tm_dbg_delayed_cmds_count);
			if (tm_dbg_delayed_cmds_count == 2)
				tm_dbg_blocked = 0;
		}
		break;

	case TM_DBG_STATE_RESET:
	case TM_DBG_STATE_OFFLINE:
		TRACE_MGMT_DBG("%s: delaying cmd %p "
			"(tag %d), delayed_cmds_count=%d", __func__, cmd,
			cmd->tag, tm_dbg_delayed_cmds_count);
		tm_dbg_blocked = 1;
		break;

	default:
		BUG();
	}
	list_move_tail(&cmd->cmd_list_entry, &tm_dbg_delayed_cmd_list);
	cmd->tm_dbg_delayed = 1;
	tm_dbg_delayed_cmds_count++;
	return;
}

/* Called under scst_list_lock */
void tm_dbg_check_released_cmds(void)
{
	if (tm_dbg_release) {
		struct scst_cmd *cmd, *tc;
		list_for_each_entry_safe_reverse(cmd, tc, 
				&tm_dbg_delayed_cmd_list, cmd_list_entry) {
			TRACE_MGMT_DBG("%s: Releasing timed cmd %p "
				"(tag %d), delayed_cmds_count=%d", __func__,
				cmd, cmd->tag, tm_dbg_delayed_cmds_count);
			list_move(&cmd->cmd_list_entry, &scst_active_cmd_list);
		}
		tm_dbg_release = 0;
	}
}

static void tm_dbg_change_state(void)
{
	tm_dbg_blocked = 0;
	if (--tm_dbg_on_state_passes == 0) {
		switch(tm_dbg_state) {
		case TM_DBG_STATE_ABORT:
			TRACE_MGMT_DBG("%s", "Changing "
			    "tm_dbg_state to RESET");
			tm_dbg_state =
				TM_DBG_STATE_RESET;
			tm_dbg_blocked = 0;
			break;
		case TM_DBG_STATE_RESET:
		case TM_DBG_STATE_OFFLINE:
			if (TM_DBG_GO_OFFLINE) {
			    TRACE_MGMT_DBG("%s", "Changing "
				    "tm_dbg_state to OFFLINE");
			    tm_dbg_state =
				TM_DBG_STATE_OFFLINE;
			} else {
			    TRACE_MGMT_DBG("%s", "Changing "
				    "tm_dbg_state to ABORT");
			    tm_dbg_state =
				TM_DBG_STATE_ABORT;
			}
			break;
		default:
			BUG();
		}
		tm_dbg_on_state_passes =
		    tm_dbg_on_state_num_passes[tm_dbg_state];
	}
		
	TRACE_MGMT_DBG("%s", "Deleting timer");
	del_timer(&tm_dbg_timer);
}

/* Called under scst_list_lock */
int tm_dbg_check_cmd(struct scst_cmd *cmd)
{
	int res = 0;

	if (cmd->tm_dbg_immut)
		goto out;

	if (cmd->tm_dbg_delayed) {
		TRACE_MGMT_DBG("Processing delayed cmd %p (tag %d), "
			"delayed_cmds_count=%d", cmd, cmd->tag,
			tm_dbg_delayed_cmds_count);

		cmd->tm_dbg_immut = 1;
		tm_dbg_delayed_cmds_count--;
		if ((tm_dbg_delayed_cmds_count == 0) &&
		    (tm_dbg_state == TM_DBG_STATE_ABORT))
			tm_dbg_change_state();

	} else if (cmd->tgt_dev && test_bit(SCST_TGT_DEV_UNDER_TM_DBG,
					&cmd->tgt_dev->tgt_dev_flags)) {
		/* Delay 50th command */
		if (tm_dbg_blocked || (++tm_dbg_passed_cmds_count % 50) == 0) {
			tm_dbg_delay_cmd(cmd);
			res = 1;
		} else
			cmd->tm_dbg_immut = 1;
	}

out:
	return res;
}

/* Called under scst_list_lock */
void tm_dbg_release_cmd(struct scst_cmd *cmd)
{
	struct scst_cmd *c;
	list_for_each_entry(c, &tm_dbg_delayed_cmd_list,
				cmd_list_entry) {
		if (c == cmd) {
			TRACE_MGMT_DBG("Abort request for "
				"delayed cmd %p (tag=%d), moving it to "
				"active cmd list (delayed_cmds_count=%d)",
				c, c->tag, tm_dbg_delayed_cmds_count);
			list_move(&c->cmd_list_entry, &scst_active_cmd_list);
			wake_up_all(&scst_list_waitQ);
			break;
		}
	}
}

/* Called under scst_list_lock */
void tm_dbg_task_mgmt(const char *fn)
{
	if (tm_dbg_state != TM_DBG_STATE_OFFLINE) {
		TRACE_MGMT_DBG("%s: freeing %d delayed cmds", fn,
			tm_dbg_delayed_cmds_count);
		tm_dbg_change_state();
		tm_dbg_release = 1;
		smp_mb();
		wake_up_all(&scst_list_waitQ);
	} else {
		TRACE_MGMT_DBG("%s: while OFFLINE state, doing nothing", fn);
	}
}

int tm_dbg_is_release(void)
{
	return tm_dbg_release;
}
#endif /* DEBUG_TM */
