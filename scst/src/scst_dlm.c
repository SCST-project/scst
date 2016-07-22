/*
 * Copyright (c) 2013 - 2014 Fusion-io, Inc. All rights reserved.
 * Copyright (C) 2014 - 2016 SanDisk Corporation.
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

#include <linux/types.h>
#include <linux/dlm.h>
#include <linux/kmod.h>
#include <linux/vmalloc.h>
#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#include <scst/scst_const.h>
#else
#include "scst.h"
#include "scst_const.h"
#endif
#include "scst_priv.h"
#include "scst_pres.h"
#include "scst_dlm.h"

#if (defined(CONFIG_DLM) || defined(CONFIG_DLM_MODULE)) && \
	!defined(CONFIG_SCST_NO_DLM)

static void scst_pr_dlm_cleanup(struct scst_device *dev);
static void scst_dlm_pre_bast(void *bastarg, int mode);
static void scst_dlm_post_bast(void *bastarg, int mode);
static void scst_dlm_post_ast(void *astarg);

static inline void compile_time_size_checks(void)
{
	BUILD_BUG_ON(sizeof(struct pr_lvb) > PR_DLM_LVB_LEN);
	BUILD_BUG_ON(sizeof(struct pr_lvb) != 20);
	BUILD_BUG_ON(sizeof(struct pr_reg_lvb) > PR_DLM_LVB_LEN);
	BUILD_BUG_ON(sizeof(struct pr_reg_lvb) != 240);
}

static void scst_dlm_ast(void *astarg)
{
	struct scst_lksb *scst_lksb = astarg;

	complete(&scst_lksb->compl);
}

/**
 * scst_dlm_cancel - Synchronously cancel a pending dlm_lock() operation
 */
static int scst_dlm_cancel(dlm_lockspace_t *ls, struct scst_lksb *lksb,
			   int flags, const char *name)
{
	int res;

	res = dlm_unlock(ls, lksb->lksb.sb_lkid,
			      DLM_LKF_CANCEL | (flags & DLM_LKF_VALBLK),
			      &lksb->lksb, lksb);
	if (res < 0)
		goto out;
	res = wait_for_completion_timeout(&lksb->compl, 10 * HZ);

out:
	return res;
}

/**
 * scst_dlm_lock_wait - Wait until a DLM lock has been granted
 * @ls:     DLM lock space.
 * @mode:   DLM lock mode.
 * @lksb:   DLM lock status block.
 * @flags:  DLM flags.
 * @name:   DLM lock name. Only required for non-conversion requests.
 * @bast:   AST to be invoked in case this lock blocks another one.
 */
static int scst_dlm_lock_wait(dlm_lockspace_t *ls, int mode,
			      struct scst_lksb *lksb, int flags,
			      const char *name, void (*bast)(void *, int))
{
	int res;

	init_completion(&lksb->compl);
	res = dlm_lock(ls, mode, &lksb->lksb, flags,
			    (void *)name, name ? strlen(name) : 0, 0,
			    scst_dlm_ast, lksb, bast);
	if (res < 0)
		goto out;
	res = wait_for_completion_timeout(&lksb->compl, 60 * HZ);
	if (res > 0)
		res = lksb->lksb.sb_status;
	else if (res == 0)
		res = -ETIMEDOUT;
	if (res < 0) {
		int res2 = scst_dlm_cancel(ls, lksb, flags, name);

		WARN(res2 < 0, "canceling lock %s / %08x failed: %d\n",
		     name ? : "?", lksb->lksb.sb_lkid, res2);
	}

out:
	return res;
}

/**
 * scst_dlm_unlock_wait - Discard a DLM lock
 */
static int scst_dlm_unlock_wait(dlm_lockspace_t *ls, struct scst_lksb *lksb)
{
	int res;

	sBUG_ON(!ls);

	init_completion(&lksb->compl);
	res = dlm_unlock(ls, lksb->lksb.sb_lkid, 0, &lksb->lksb, lksb);
	if (res < 0)
		goto out;
	res = wait_for_completion_timeout(&lksb->compl, 60 * HZ);
	if (res > 0) {
		res = lksb->lksb.sb_status;
		if (res == -DLM_EUNLOCK || res == -DLM_ECANCEL)
			res = 0;
	} else if (res == 0) {
		res = -ETIMEDOUT;
	}

out:
	return res;
}

/* Number of persistent reservation registrants. */
static uint32_t scst_pr_num_regs(struct scst_device *dev)
{
	struct scst_dev_registrant *reg;
	uint32_t num_regs = 0;

	lockdep_assert_pr_read_lock_held(dev);

	list_for_each_entry(reg, &dev->dev_registrants_list,
			    dev_registrants_list_entry)
		num_regs++;

	return num_regs;
}

/* DLM-specific registrant initialization. */
static void scst_dlm_pr_init_reg(struct scst_device *dev,
				 struct scst_dev_registrant *reg)
{
	reg->lksb.lksb.sb_lvbptr = (void *)reg->lvb;
	reg->lksb.lksb.sb_lkid = 0;
	reg->dlm_idx = -1;
}

static void scst_dlm_pr_rm_reg_ls(dlm_lockspace_t *ls,
				  struct scst_dev_registrant *reg)
{
	int res;

	if (!reg->lksb.lksb.sb_lkid)
		return;
	res = scst_dlm_unlock_wait(ls, &reg->lksb);
	WARN(res < 0, "scst_dlm_unlock_wait(%08x) failed (%d)",
	     reg->lksb.lksb.sb_lkid, res);
	reg->lksb.lksb.sb_lkid = 0;
	reg->dlm_idx = -1;
}

/* DLM-specific registrant cleanup. */
static void scst_dlm_pr_rm_reg(struct scst_device *dev,
			       struct scst_dev_registrant *reg)
{
	lockdep_assert_pr_write_lock_held(dev);
	scst_dlm_pr_rm_reg_ls(dev->pr_dlm->ls, reg);
}

/* Copy SPC-2 reservation state from the DLM LVB into @dev. */
static bool scst_copy_res_from_dlm(struct scst_device *dev, struct pr_lvb *lvb)
{
	struct scst_pr_dlm_data *const pr_dlm = dev->pr_dlm;
	struct scst_session *dropped_res = NULL;
	bool modified_lvb = false;

	spin_lock_bh(&dev->dev_lock);
	pr_dlm->reserved_by_nodeid = be32_to_cpu(lvb->reserved_by_nodeid);
	if (dev->reserved_by &&
	    pr_dlm->reserved_by_nodeid != pr_dlm->local_nodeid) {
		PRINT_WARNING("%s: dropping SPC-2 reservation for %s (due to"
			      " split-brain ?) because node %d holds a"
			      " reservation", dev->virt_name,
			      dev->reserved_by->initiator_name,
			      pr_dlm->reserved_by_nodeid);
		swap(dev->reserved_by, dropped_res);
	}
	if (!dev->reserved_by &&
	    pr_dlm->reserved_by_nodeid == pr_dlm->local_nodeid) {
		PRINT_WARNING("%s: dropping SPC-2 reservation (due to restart"
			      " or split-brain ?) and triggering LVB update"
			      " because of inconstency (holder %d / not rsrvd)",
			      dev->virt_name, pr_dlm->reserved_by_nodeid);
		pr_dlm->reserved_by_nodeid = 0;
		lvb->reserved_by_nodeid = 0;
		modified_lvb = true;
	}
	if (dev->reserved_by)
		EXTRACHECKS_BUG_ON(pr_dlm->reserved_by_nodeid !=
				   pr_dlm->local_nodeid);
	else
		EXTRACHECKS_BUG_ON(pr_dlm->reserved_by_nodeid ==
				   pr_dlm->local_nodeid);
	if (dropped_res)
		scst_sess_get(dropped_res);
	spin_unlock_bh(&dev->dev_lock);

	if (dropped_res) {
		/*
		 * To do: something like
		 * scst_do_nexus_loss_sess(dropped_res, true);
		 */
		scst_sess_put(dropped_res);
	}

	return modified_lvb;
}

/*
 * Update local PR and registrant information from the content of the DLM LVB's.
 * Caller must hold PR_DATA_LOCK in PW mode.
 *
 * Returns -EINVAL if and only if an invalid lock value block has been
 * encountered.
 */
static int scst_copy_from_dlm(struct scst_device *dev, dlm_lockspace_t *ls,
			      bool *modified_lvb)
{
	struct scst_pr_dlm_data *const pr_dlm = dev->pr_dlm;
	struct pr_lvb *lvb = (void *)pr_dlm->lvb;
	struct scst_lksb *reg_lksb = NULL;
	struct scst_dev_registrant *reg, *tmp_reg;
	int i, res = -ENOMEM;
	uint32_t nr_registrants;
	void *reg_lvb_content = NULL;

	lockdep_assert_held(&pr_dlm->ls_mutex);

	nr_registrants = be32_to_cpu(lvb->nr_registrants);
	if (nr_registrants) {
		reg_lksb = vzalloc((sizeof(*reg_lksb) + PR_DLM_LVB_LEN) *
				   nr_registrants);
		if (!reg_lksb) {
			PRINT_ERROR("%s: failed to allocate %d * %zd bytes of"
				    " memory", __func__, nr_registrants,
				    sizeof(*reg_lksb) + PR_DLM_LVB_LEN);
			goto out;
		}
		reg_lvb_content = (void *)reg_lksb +
			nr_registrants * sizeof(*reg_lksb);
	}

	for (i = 0; i < nr_registrants; i++) {
		char reg_name[32];
		struct pr_reg_lvb *reg_lvb;

		snprintf(reg_name, sizeof(reg_name), PR_REG_LOCK, i);
		reg_lvb = reg_lvb_content + i * PR_DLM_LVB_LEN;
		reg_lksb[i].lksb.sb_lvbptr = (void *)reg_lvb;
		res = scst_dlm_lock_wait(ls, DLM_LOCK_PW, &reg_lksb[i],
					 DLM_LKF_VALBLK, reg_name, NULL);
		if (res < 0) {
			res = -EFAULT;
			PRINT_ERROR("locking %s.%s failed", dev->virt_name,
				    reg_name);
			goto cancel;
		} else if (reg_lksb[i].lksb.sb_flags & DLM_SBF_VALNOTVALID) {
			res = -EINVAL;
			PRINT_WARNING("%s.%s has an invalid lock value block",
				      dev->virt_name, reg_name);
			goto cancel;
		} else if (reg_lvb->version != 1) {
			res = -EPROTONOSUPPORT;
			PRINT_ERROR("%s.%s.version = %d instead of 1",
				    dev->virt_name, reg_name,
				    reg_lvb->version);
			goto cancel;
		}
	}

	*modified_lvb = scst_copy_res_from_dlm(dev, lvb);

	scst_pr_write_lock(dev);

	dev->pr_aptpl = lvb->pr_aptpl;
	dev->pr_generation = be32_to_cpu(lvb->pr_generation);
	dev->pr_is_set = lvb->pr_is_set;
	dev->pr_type = lvb->pr_type;
	dev->pr_scope = lvb->pr_scope;
	dev->pr_holder = NULL;

	list_for_each_entry(reg, &dev->dev_registrants_list,
			    dev_registrants_list_entry)
		scst_dlm_pr_rm_reg_ls(ls, reg);

	for (i = 0; i < nr_registrants; i++) {
		struct pr_reg_lvb *reg_lvb;
		uint16_t rel_tgt_id;

		reg_lvb = (struct pr_reg_lvb *)reg_lksb[i].lksb.sb_lvbptr;
		rel_tgt_id = be16_to_cpu(reg_lvb->rel_tgt_id);
#if 0
		PRINT_INFO("Transport ID in %s." PR_REG_LOCK " (len %d):",
			   dev->virt_name, i, scst_tid_size(reg_lvb->tid));
		print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_OFFSET, 16, 1,
			       reg_lvb->tid, scst_tid_size(reg_lvb->tid), 1);
#endif
		reg = scst_pr_find_reg(dev, reg_lvb->tid, rel_tgt_id);
		if (reg && reg->key != reg_lvb->key) {
			scst_pr_remove_registrant(dev, reg);
			reg = NULL;
		}
		if (!reg)
			reg = scst_pr_add_registrant(dev, reg_lvb->tid,
						     rel_tgt_id, reg_lvb->key,
						     false);
		if (reg) {
			scst_dlm_pr_rm_reg_ls(ls, reg);
			reg->lksb.lksb.sb_lkid = reg_lksb[i].lksb.sb_lkid;
			reg->dlm_idx = i;
			memcpy(reg->lvb, reg_lvb_content, sizeof(reg->lvb));
			if (reg_lvb->is_holder) {
				if (dev->pr_is_set)
					scst_pr_clear_holder(dev);
				scst_pr_set_holder(dev, reg, lvb->pr_scope,
						   lvb->pr_type);
			}
		} else {
			PRINT_ERROR("pr_add_registrant %s." PR_REG_LOCK
				    " failed\n", dev->virt_name, i);
			scst_dlm_unlock_wait(ls, &reg_lksb[i]);
			continue;
		}
		scst_dlm_lock_wait(ls, DLM_LOCK_CR, &reg->lksb,
				   DLM_LKF_CONVERT | DLM_LKF_VALBLK, NULL,
				   NULL);
	}

	/* Remove all registrants not found in any DLM LVB */
	list_for_each_entry_safe(reg, tmp_reg, &dev->dev_registrants_list,
				 dev_registrants_list_entry)
		if (reg->lksb.lksb.sb_lkid == 0)
			scst_pr_remove_registrant(dev, reg);

#ifndef CONFIG_SCST_PROC
	scst_pr_sync_device_file(dev);
#endif

	scst_pr_write_unlock(dev);

	res = 0;

out:
	vfree(reg_lksb);
	return res;

cancel:
	for (i = 0; i < nr_registrants; i++)
		if (reg_lksb[i].lksb.sb_lkid)
			scst_dlm_unlock_wait(ls, &reg_lksb[i]);

	goto out;
}

static struct scst_dev_registrant*
scst_get_reg_by_dlm_idx(struct scst_device *dev, int i)
{
	struct scst_dev_registrant *reg;

	lockdep_assert_pr_read_lock_held(dev);

	list_for_each_entry(reg, &dev->dev_registrants_list,
			    dev_registrants_list_entry)
		if (reg->dlm_idx == i)
			return reg;

	return NULL;
}

static int scst_get_available_dlm_idx(struct scst_device *dev)
{
	int i = 0;

	lockdep_assert_pr_read_lock_held(dev);

	while (scst_get_reg_by_dlm_idx(dev, i))
		i++;

	return i;
}

/* Copy SPC-2 reservation state for @dev into the DLM LVB @lvb. */
static void scst_copy_res_to_dlm(struct scst_device *dev, struct pr_lvb *lvb)
{
	struct scst_pr_dlm_data *const pr_dlm = dev->pr_dlm;

	spin_lock_bh(&dev->dev_lock);
	lvb->reserved_by_nodeid = cpu_to_be32(pr_dlm->reserved_by_nodeid);
	spin_unlock_bh(&dev->dev_lock);
}

/*
 * Update PR and registrant information in the DLM LVB's. Caller must hold
 * PR_DATA_LOCK in PW mode.
 */
static void scst_copy_to_dlm(struct scst_device *dev, dlm_lockspace_t *ls)
{
	struct scst_pr_dlm_data *const pr_dlm = dev->pr_dlm;
	struct pr_lvb *lvb = (void *)pr_dlm->lvb;
	struct pr_reg_lvb *reg_lvb;
	struct scst_dev_registrant *reg;
	int i, tid_size;
	char reg_name[32];
	uint32_t nr_registrants;

	lockdep_assert_held(&pr_dlm->ls_mutex);

	scst_copy_res_to_dlm(dev, lvb);

	scst_pr_write_lock(dev);

	nr_registrants = scst_pr_num_regs(dev);
	lvb->version = 1;
	lvb->pr_is_set = dev->pr_is_set;
	lvb->pr_type = dev->pr_type;
	lvb->pr_scope = dev->pr_scope;
	lvb->pr_aptpl = dev->pr_aptpl;
	lvb->nr_registrants = cpu_to_be32(nr_registrants);
	lvb->pr_generation = cpu_to_be32(dev->pr_generation);

	list_for_each_entry(reg, &dev->dev_registrants_list,
			    dev_registrants_list_entry) {
		if (reg->dlm_idx >= nr_registrants)
			scst_dlm_pr_rm_reg_ls(ls, reg);
		if (reg->dlm_idx < 0) {
			i = scst_get_available_dlm_idx(dev);
			snprintf(reg_name, sizeof(reg_name), PR_REG_LOCK, i);
			if (scst_dlm_lock_wait(ls, DLM_LOCK_NL,
					       &reg->lksb, 0, reg_name, NULL)
			    >= 0)
				reg->dlm_idx = i;
		}
	}

	list_for_each_entry(reg, &dev->dev_registrants_list,
			    dev_registrants_list_entry) {
		if (WARN_ON(!reg->lksb.lksb.sb_lkid))
			continue;
		snprintf(reg_name, sizeof(reg_name), PR_REG_LOCK, reg->dlm_idx);
		if (scst_dlm_lock_wait(ls, DLM_LOCK_PW, &reg->lksb,
				       DLM_LKF_VALBLK | DLM_LKF_CONVERT,
				       reg_name, NULL) >= 0) {
			reg_lvb = (void *)reg->lksb.lksb.sb_lvbptr;
			memset(reg->lvb, 0, sizeof(reg->lvb));
			reg_lvb->key = reg->key;
			reg_lvb->rel_tgt_id = cpu_to_be16(reg->rel_tgt_id);
			reg_lvb->version = 1;
			reg_lvb->is_holder = dev->pr_holder == reg;
			tid_size = scst_tid_size(reg->transport_id);
#if 0
			PRINT_INFO("Copying transport ID into %s." PR_REG_LOCK
				   " (len %d)", dev->virt_name, reg->dlm_idx,
				   tid_size);
			print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_OFFSET, 16,
				       1, reg->transport_id, tid_size, 1);
#endif
			if (WARN(tid_size > sizeof(reg_lvb->tid),
				 "tid_size %d > %zd\n", tid_size,
				 sizeof(reg_lvb->tid)))
				tid_size = sizeof(reg_lvb->tid);
			memcpy(reg_lvb->tid, reg->transport_id, tid_size);
			scst_dlm_lock_wait(ls, DLM_LOCK_CR, &reg->lksb,
					   DLM_LKF_CONVERT | DLM_LKF_VALBLK,
					   reg_name, NULL);
		} else {
			PRINT_ERROR("Failed to lock %s.%s", dev->virt_name,
				    reg_name);
		}
	}

	scst_pr_write_unlock(dev);
}

/*
 * Read the contents of a file, copy it into a buffer and terminate the buffer
 * with '\0'.
 */
static int scst_read_file(const char *path, char *buf, int buf_len)
{
	struct file *f;
	loff_t pos;
	int ret;

	f = filp_open(path, 0, 0400);
	if (IS_ERR(f)) {
		ret = PTR_ERR(f);
		goto out;
	}
	pos = 0;
	ret = vfs_read(f, (char __force __user *)buf, buf_len, &pos);
	if (ret >= 0)
		buf[min(ret, buf_len - 1)] = '\0';
	filp_close(f, NULL);
out:
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
struct scst_dlm_readdir_context {
	struct dir_context ctx;
	char *entries;
};
#endif

/* Append the name of each directory entry to the buffer @arg points to. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
static int scst_dlm_filldir(void *arg, const char *name_arg, int name_len,
			    loff_t curr_pos, u64 inode, unsigned int dtype)
#else
static int scst_dlm_filldir(struct dir_context *arg, const char *name_arg,
			    int name_len, loff_t curr_pos, u64 inode,
			    unsigned int dtype)
#endif
{
	char *p, *q, name[64];
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
	char **entries = arg;
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	struct scst_dlm_readdir_context *ctx =
		container_of((struct dir_context *)arg, typeof(*ctx), ctx);
#else
	struct scst_dlm_readdir_context *ctx =
		container_of(arg, typeof(*ctx), ctx);
#endif
	char **entries = &ctx->entries;
#endif
	int i;

	snprintf(name, sizeof(name), "%.*s", name_len, name_arg);
	if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0 || !*entries)
		goto out;
	for (p = *entries; *p; p += strlen(p) + 1)
		;
	i = p - *entries;
	q = *entries;
	*entries = krealloc(q, i + strlen(name) + 2, GFP_KERNEL);
	if (!*entries) {
		kfree(q);
		goto out;
	}
	strcpy(*entries + i, name);
	i += strlen(name);
	(*entries)[i + 1] = '\0';

out:
	return *entries ? 0 : -ENOMEM;
}

/**
 * scst_dlm_update_nodeids - Update the Corosync node ID array pr_dlm->nodeid[]
 */
static int scst_dlm_update_nodeids(struct scst_pr_dlm_data *pr_dlm)
{
	static const char comms_dir[] = "/sys/kernel/config/dlm/cluster/comms";
	struct file *comms;
	char *p, *entries = kzalloc(1, GFP_KERNEL);
	unsigned long nodeid;
	uint32_t *new;
	int i, ret, num_nodes;
	char path[256], buf[64];

	lockdep_assert_held(&pr_dlm->ls_mutex);

	num_nodes = 0;

	comms = filp_open(comms_dir, 0, 0400);
	if (IS_ERR(comms)) {
		ret = PTR_ERR(comms);
		goto out;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
	ret = vfs_readdir(comms, scst_dlm_filldir, &entries);
#else
	{
		struct scst_dlm_readdir_context ctx = {
			.ctx = {
				.actor = scst_dlm_filldir,
			},
			.entries = entries,
		};
		ret = iterate_dir(comms, &ctx.ctx);
		entries = ctx.entries;
	}
#endif
	filp_close(comms, NULL);
	ret = -ENOMEM;
	if (!entries)
		goto out;
	for (p = entries; *p; p += strlen(p) + 1)
		num_nodes++;
	new = krealloc(pr_dlm->nodeid, sizeof(*pr_dlm->nodeid) * num_nodes,
		       GFP_KERNEL);
	if (!new)
		goto out;
	pr_dlm->nodeid = new;
	pr_dlm->participants = num_nodes;
	for (i = 0, p = entries; *p; i++, p += strlen(p) + 1) {
		ret = kstrtoul(p, 0, &nodeid);
		if (WARN_ON_ONCE(ret < 0))
			continue;
		snprintf(path, sizeof(path), "%s/%s/local", comms_dir, p);
		if (scst_read_file(path, buf, sizeof(buf)) >= 0 &&
		    strcmp(buf, "1\n") == 0)
			pr_dlm->local_nodeid = nodeid;
		pr_dlm->nodeid[i] = nodeid;
	}
	ret = 0;

out:
	kfree(entries);
	return ret;
}

/*
 * Toggle all non-local DLM locks with name format @fmt from NL to PR and back
 * to NL.
 */
static void scst_pr_toggle_lock(struct scst_pr_dlm_data *pr_dlm,
				dlm_lockspace_t *ls, const char *fmt)
{
	struct scst_lksb lksb;
	int i, res;
	char lock_name[32];

	memset(&lksb, 0, sizeof(lksb));
	for (i = 0; i < pr_dlm->participants; i++) {
		if (pr_dlm->nodeid[i] == pr_dlm->local_nodeid)
			continue;
		snprintf(lock_name, sizeof(lock_name), fmt, pr_dlm->nodeid[i]);
		lksb.lksb.sb_lkid = 0;
		res = scst_dlm_lock_wait(ls, DLM_LOCK_PR, &lksb, 0,
					 lock_name, NULL);
		if (res < 0)
			PRINT_WARNING("Locking %s.%s failed (%d)",
				      pr_dlm->dev->virt_name, lock_name, res);
		if (!lksb.lksb.sb_lkid)
			continue;
		scst_dlm_lock_wait(ls, DLM_LOCK_NL, &lksb,
				   DLM_LKF_CONVERT, lock_name, NULL);
		scst_dlm_unlock_wait(ls, &lksb);
	}
}

/* Remove a lock from the local DLM lockspace instance. */
static void scst_dlm_remove_lock(dlm_lockspace_t *ls, struct scst_lksb *lksb,
				 const char *name)
{
	if (!lksb->lksb.sb_lkid)
		return;
	scst_dlm_lock_wait(ls, DLM_LOCK_NL, lksb, DLM_LKF_CONVERT, name,
			   NULL);
	scst_dlm_unlock_wait(ls, lksb);
	lksb->lksb.sb_lkid = 0;
}

static void scst_dlm_remove_locks(struct scst_pr_dlm_data *pr_dlm,
				  dlm_lockspace_t *ls)
{
	struct scst_device *dev = pr_dlm->dev;
	struct scst_dev_registrant *reg;

	lockdep_assert_held(&pr_dlm->ls_mutex);

	scst_pr_write_lock(dev);
	list_for_each_entry(reg, &dev->dev_registrants_list,
			    dev_registrants_list_entry)
		scst_dlm_pr_rm_reg_ls(ls, reg);
	scst_pr_write_unlock(dev);

	scst_dlm_remove_lock(ls, &pr_dlm->pre_join_lksb, NULL);
	scst_dlm_remove_lock(ls, &pr_dlm->post_join_lksb, NULL);
	scst_dlm_remove_lock(ls, &pr_dlm->pre_upd_lksb, NULL);
	scst_dlm_remove_lock(ls, &pr_dlm->post_upd_lksb, NULL);
	scst_dlm_remove_lock(ls, &pr_dlm->data_lksb, PR_DATA_LOCK);
}

/*
 * If two or more nodes are present in the cluster, tell each other node to
 * update the local state information from the DLM lock value blocks. The
 * caller must hold PR_LOCK in EX mode.
 */
static void scst_trigger_reread_lvb(struct scst_pr_dlm_data *const pr_dlm,
				    dlm_lockspace_t *ls)
{
	scst_pr_toggle_lock(pr_dlm, ls, PR_POST_UPDATE_LOCK);
	scst_pr_toggle_lock(pr_dlm, ls, PR_PRE_UPDATE_LOCK);
	scst_pr_toggle_lock(pr_dlm, ls, PR_POST_UPDATE_LOCK);
}

/*
 * If two or more nodes are present in the cluster, tell each other node to
 * refresh the DLM lock value blocks. The caller must hold PR_LOCK in EX mode.
 */
static void scst_trigger_lvb_update(struct scst_pr_dlm_data *const pr_dlm,
				    dlm_lockspace_t *ls)
{
	PRINT_INFO("%s: about to trigger an LVB update",
		   pr_dlm->dev->virt_name);
	scst_pr_toggle_lock(pr_dlm, ls, PR_POST_JOIN_LOCK);
	scst_pr_toggle_lock(pr_dlm, ls, PR_PRE_JOIN_LOCK);
	scst_pr_toggle_lock(pr_dlm, ls, PR_POST_JOIN_LOCK);
	PRINT_INFO("%s: finished triggering an LVB update",
		   pr_dlm->dev->virt_name);
}

static void dump_lockspace(const char *cl_dev_id)
{
	char *argv0 = kstrdup("/bin/bash", GFP_KERNEL);
	char *argv1 = kstrdup("-c", GFP_KERNEL);
	char *argv2 = kasprintf(GFP_KERNEL,
				"{ echo lockspace-dump-start;"
				" grep -aH '' /sys/kernel/debug/dlm/%s%s*;"
				" echo lockspace-dump-end; } 2>&1 |"
				" while read line; do logger \"$line\"; done",
				SCST_DLM_LOCKSPACE_PFX, cl_dev_id);
	char *argv[] = { argv0, argv1, argv2, NULL };
	char *envp[] = {
		kstrdup("PATH=/usr/bin:/bin:/usr/sbin:/sbin", GFP_KERNEL),
		NULL
	};


	if (!argv[0] || !argv[1] || !argv[2] || !envp[0]) {
		PRINT_ERROR("%s: out of memory", __func__);
		goto out;
	}

	PRINT_INFO("Invoking %s", argv2);

	call_usermodehelper(argv0, argv, envp, UMH_WAIT_PROC);

out:
	kfree(envp[0]);
	kfree(argv[2]);
	kfree(argv[1]);
	kfree(argv[0]);
}

static void release_lockspace(dlm_lockspace_t *ls, const char *cl_dev_id)
{
	int res;

	res = dlm_release_lockspace(ls, 1);
	if (res) {
		PRINT_ERROR("releasing lockspace for %s failed: %d",
			    cl_dev_id, res);
		dump_lockspace(cl_dev_id);
	}
	if (res == -EBUSY) {
		/*
		 * Releasing a lockspace fails if one or more local instances
		 * of DLM locks still exist in the lockspace. If that
		 * happens try to release the lockspace forcibly.
		 */
		res = dlm_release_lockspace(ls, 2);
		if (res)
			PRINT_ERROR("forcibly releasing lockspace for %s"
				    " failed: %d", cl_dev_id, res);
	}
	if (res == 0)
		PRINT_INFO("released lockspace for %s", cl_dev_id);
}

/* Initialize DLM lockspace. */
static dlm_lockspace_t *get_lockspace(struct scst_device *dev)
{
	struct scst_pr_dlm_data *const pr_dlm = dev->pr_dlm;
	dlm_lockspace_t *ls;
	struct scst_lksb pr_lksb;
	struct pr_lvb *lvb = (void *)pr_dlm->lvb;
	char lsp_name[32], lock_name[32];
	int res;
	bool modified_lvb = false;

	if (pr_dlm->ls || !pr_dlm->cl_dev_id || in_interrupt() ||
	    time_is_after_jiffies(pr_dlm->latest_lscr_attempt + 1 * HZ))
		goto out;

	mutex_lock(&pr_dlm->ls_cr_mutex);
	if (pr_dlm->ls)
		goto out_unlock_ls_cr;

	pr_dlm->latest_lscr_attempt = jiffies;

	mutex_lock(&pr_dlm->ls_mutex);

	res = scst_dlm_update_nodeids(pr_dlm);
	if (res < 0) {
		PRINT_ERROR("scst_dlm_update_nodeids(%s) failed: %d",
			    dev->virt_name, res);
		goto out_unlock_ls;
	}
	if (pr_dlm->participants == 0)
		goto out_unlock_ls;

	snprintf(lsp_name, sizeof(lsp_name), "%s%s", SCST_DLM_LOCKSPACE_PFX,
		 pr_dlm->cl_dev_id);
	res = scst_dlm_new_lockspace(lsp_name, strlen(lsp_name), &ls,
				     DLM_LSFL_NEWEXCL | DLM_LSFL_FS,
				     PR_DLM_LVB_LEN);
	if (res) {
		PRINT_ERROR("Creating DLM lockspace %s failed: %d", lsp_name,
			    res);
		goto out_unlock_ls;
	}

	PRINT_INFO("Created DLM lockspace %s for %s", lsp_name, dev->virt_name);

	memset(&pr_lksb, 0, sizeof(pr_lksb));
	res = scst_dlm_lock_wait(ls, DLM_LOCK_EX, &pr_lksb, 0, PR_LOCK,
				 NULL);
	if (res < 0)
		goto unlock_dlm_pr;

	snprintf(lock_name, sizeof(lock_name), PR_POST_JOIN_LOCK,
		 pr_dlm->local_nodeid);
	pr_dlm->post_join_lksb.pr_dlm = pr_dlm;
	res = scst_dlm_lock_wait(ls, DLM_LOCK_NL,
				 &pr_dlm->post_join_lksb, 0, lock_name,
				 scst_dlm_post_bast);
	if (res < 0)
		goto release_lockspace;

	snprintf(lock_name, sizeof(lock_name), PR_PRE_JOIN_LOCK,
		 pr_dlm->local_nodeid);
	pr_dlm->pre_join_lksb.pr_dlm = pr_dlm;
	res = scst_dlm_lock_wait(ls, DLM_LOCK_EX,
				 &pr_dlm->pre_join_lksb, 0, lock_name,
				 scst_dlm_pre_bast);
	if (res < 0)
		goto release_lockspace;

	res = scst_dlm_lock_wait(ls, DLM_LOCK_PW, &pr_dlm->data_lksb,
				 DLM_LKF_VALBLK, PR_DATA_LOCK, NULL);
	if (res < 0)
		goto release_lockspace;

	if (pr_dlm->data_lksb.lksb.sb_status & DLM_SBF_VALNOTVALID) {
		PRINT_ERROR("%s.%s lock value block not valid", dev->virt_name,
			    PR_DATA_LOCK);
		memset(pr_dlm->lvb, 0, sizeof(pr_dlm->lvb));
	}

	snprintf(lock_name, sizeof(lock_name), PR_POST_UPDATE_LOCK,
		 pr_dlm->local_nodeid);
	pr_dlm->post_upd_lksb.pr_dlm = pr_dlm;
	res = scst_dlm_lock_wait(ls, DLM_LOCK_NL,
				 &pr_dlm->post_upd_lksb, 0, lock_name,
				 scst_dlm_post_bast);
	if (res < 0)
		goto release_lockspace;

	snprintf(lock_name, sizeof(lock_name), PR_PRE_UPDATE_LOCK,
		 pr_dlm->local_nodeid);
	pr_dlm->pre_upd_lksb.pr_dlm = pr_dlm;
	res = scst_dlm_lock_wait(ls, DLM_LOCK_EX, &pr_dlm->pre_upd_lksb,
				 0, lock_name, scst_dlm_pre_bast);
	if (res < 0)
		goto release_lockspace;

	switch (lvb->version) {
	case 0:
		scst_copy_to_dlm(dev, ls);
		break;
	case 1:
		res = scst_copy_from_dlm(dev, ls, &modified_lvb);
		break;
	default:
		PRINT_ERROR("%s: Wrong PR LVB version %d", dev->virt_name,
			    lvb->version);
		goto release_lockspace;
	}

	scst_dlm_lock_wait(ls, DLM_LOCK_CR, &pr_dlm->data_lksb,
			   DLM_LKF_CONVERT | DLM_LKF_VALBLK, PR_DATA_LOCK,
			   NULL);

	if (res == -EINVAL)
		scst_trigger_lvb_update(pr_dlm, ls);
	else if (modified_lvb)
		scst_trigger_reread_lvb(pr_dlm, ls);

	scst_dlm_unlock_wait(ls, &pr_lksb);

	/*
	 * Only store the lockspace pointer in pr_dlm->ls after the lockspace
	 * has been fully initialized. Storing it earlier would create a risk
	 * that a concurrent get_lockspace() call returns a pointer to the
	 * lockspace that is under creation.
	 */
	pr_dlm->ls = ls;

out_unlock_ls:
	mutex_unlock(&pr_dlm->ls_mutex);

out_unlock_ls_cr:
	mutex_unlock(&pr_dlm->ls_cr_mutex);

out:
	return pr_dlm->ls;

release_lockspace:
	scst_dlm_remove_locks(pr_dlm, ls);
unlock_dlm_pr:
	scst_dlm_remove_lock(ls, &pr_lksb, PR_LOCK);
	mutex_unlock(&pr_dlm->ls_mutex);

	cancel_work_sync(&pr_dlm->copy_from_dlm_work);
	cancel_work_sync(&pr_dlm->copy_to_dlm_work);
	cancel_work_sync(&pr_dlm->lvb_upd_work);
	cancel_work_sync(&pr_dlm->reread_lvb_work);

	release_lockspace(ls, pr_dlm->cl_dev_id);
	goto out_unlock_ls_cr;
}

static bool scst_dlm_pr_is_set(struct scst_device *dev)
{
	get_lockspace(dev);
	return dev->pr_is_set;
}

static void scst_dlm_pr_write_lock(struct scst_device *dev,
				   struct scst_lksb *pr_lksb)
{
	struct scst_pr_dlm_data *const pr_dlm = dev->pr_dlm;
	dlm_lockspace_t *ls;

	memset(pr_lksb, 0, sizeof(*pr_lksb));

	ls = get_lockspace(dev);
	if (!ls)
		goto out;

	scst_dlm_lock_wait(ls, DLM_LOCK_EX, pr_lksb, 0, PR_LOCK, NULL);
	if (pr_lksb->lksb.sb_lkid) {
		scst_pr_toggle_lock(pr_dlm, ls, PR_POST_UPDATE_LOCK);
		scst_pr_toggle_lock(pr_dlm, ls, PR_PRE_UPDATE_LOCK);
		scst_dlm_lock_wait(ls, DLM_LOCK_PW,
				   &pr_dlm->data_lksb,
				   DLM_LKF_CONVERT | DLM_LKF_VALBLK,
				   PR_DATA_LOCK, NULL);
	}

out:
	/*
	 * Note: invoking scst_copy_from_dlm(dev) here is not necessary
	 * because that function is already invoked after joining the
	 * lockspace and from inside post_bast().
	 */
	scst_pr_write_lock(dev);
}

static void scst_dlm_pr_write_unlock(struct scst_device *dev,
				     struct scst_lksb *pr_lksb)
{
	struct scst_pr_dlm_data *const pr_dlm = dev->pr_dlm;
	dlm_lockspace_t *ls = pr_dlm->ls;

	scst_pr_write_unlock(dev);

	if (!pr_lksb->lksb.sb_lkid)
		return;

	scst_copy_to_dlm(dev, ls);
	scst_dlm_lock_wait(ls, DLM_LOCK_CR, &pr_dlm->data_lksb,
			   DLM_LKF_CONVERT | DLM_LKF_VALBLK, PR_DATA_LOCK,
			   NULL);
	scst_pr_toggle_lock(pr_dlm, ls, PR_POST_UPDATE_LOCK);
	scst_dlm_unlock_wait(ls, pr_lksb);
}

static bool scst_dlm_reserved(struct scst_device *dev)
{
	EXTRACHECKS_BUG_ON(in_irq() || irqs_disabled());

	get_lockspace(dev);
	return dev->reserved_by || dev->pr_dlm->reserved_by_nodeid;
}

static void scst_dlm_res_lock(struct scst_device *dev,
			      struct scst_lksb *pr_lksb)
	__acquires(&dev->dev_lock)
{
	struct scst_pr_dlm_data *const pr_dlm = dev->pr_dlm;
	dlm_lockspace_t *ls;

	EXTRACHECKS_BUG_ON(in_irq() || irqs_disabled());
	memset(pr_lksb, 0, sizeof(*pr_lksb));
	ls = get_lockspace(dev);
	if (!ls)
		goto out;

	scst_dlm_lock_wait(ls, DLM_LOCK_EX, pr_lksb, 0, PR_LOCK, NULL);
	if (pr_lksb->lksb.sb_lkid) {
		scst_dlm_lock_wait(ls, DLM_LOCK_PW, &pr_dlm->data_lksb,
				   DLM_LKF_CONVERT | DLM_LKF_VALBLK,
				   PR_DATA_LOCK, NULL);
	}

out:
	spin_lock_bh(&dev->dev_lock);
}

static void scst_dlm_res_unlock(struct scst_device *dev,
				struct scst_lksb *pr_lksb)
	__releases(&dev->dev_lock)
{
	struct scst_pr_dlm_data *const pr_dlm = dev->pr_dlm;
	dlm_lockspace_t *ls = pr_dlm->ls;
	struct pr_lvb *lvb = (void *)pr_dlm->lvb;
	bool update_lvb;

	spin_unlock_bh(&dev->dev_lock);

	if (!pr_lksb->lksb.sb_lkid)
		return;

	update_lvb = (be32_to_cpu(lvb->reserved_by_nodeid) !=
		      pr_dlm->reserved_by_nodeid);

	if (update_lvb)
		scst_copy_to_dlm(dev, ls);
	scst_dlm_lock_wait(ls, DLM_LOCK_CR, &pr_dlm->data_lksb,
			   DLM_LKF_CONVERT | DLM_LKF_VALBLK, PR_DATA_LOCK,
			   NULL);
	if (update_lvb) {
		scst_pr_toggle_lock(pr_dlm, ls, PR_PRE_UPDATE_LOCK);
		scst_pr_toggle_lock(pr_dlm, ls, PR_POST_UPDATE_LOCK);
	}
	scst_dlm_unlock_wait(ls, pr_lksb);
}

static bool scst_dlm_is_rsv_holder(struct scst_device *dev,
				   struct scst_session *sess)
{
	return dev->reserved_by == sess;
}

static bool scst_dlm_is_not_rsv_holder(struct scst_device *dev,
				       struct scst_session *sess)
{
	return dev->pr_dlm->reserved_by_nodeid && dev->reserved_by != sess;
}

static void scst_dlm_reserve(struct scst_device *dev, struct scst_session *sess)
{
	dev->reserved_by = sess;
	dev->pr_dlm->reserved_by_nodeid = sess ? dev->pr_dlm->local_nodeid : 0;
}

static void scst_dlm_pre_bast(void *bastarg, int mode)
{
	struct scst_lksb *pre_lksb = bastarg;
	struct scst_pr_dlm_data *pr_dlm = pre_lksb->pr_dlm;
	const bool join = pre_lksb == &pr_dlm->pre_join_lksb;

	/* An AST must not block, so execute further work asynchronously. */
	if (join)
		queue_work(pr_dlm->to_wq, &pr_dlm->pre_join_work);
	else
		queue_work(pr_dlm->from_wq, &pr_dlm->pre_upd_work);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void scst_pre_join_work(void *p)
{
	struct scst_pr_dlm_data *pr_dlm = p;
#else
static void scst_pre_join_work(struct work_struct *work)
{
	struct scst_pr_dlm_data *pr_dlm = container_of(work,
				struct scst_pr_dlm_data, pre_join_work);
#endif
	dlm_lockspace_t *ls;

	mutex_lock(&pr_dlm->ls_mutex);
	ls = pr_dlm->ls;
	if (ls) {
		scst_dlm_lock_wait(ls, DLM_LOCK_EX, &pr_dlm->post_join_lksb,
				   DLM_LKF_CONVERT, NULL, scst_dlm_post_bast);
		scst_dlm_lock_wait(ls, DLM_LOCK_NL, &pr_dlm->pre_join_lksb,
				   DLM_LKF_CONVERT, NULL, scst_dlm_pre_bast);
	}
	mutex_unlock(&pr_dlm->ls_mutex);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void scst_pre_upd_work(void *p)
{
	struct scst_pr_dlm_data *pr_dlm = p;
#else
static void scst_pre_upd_work(struct work_struct *work)
{
	struct scst_pr_dlm_data *pr_dlm = container_of(work,
				struct scst_pr_dlm_data, pre_upd_work);
#endif
	dlm_lockspace_t *ls;

	mutex_lock(&pr_dlm->ls_mutex);
	ls = pr_dlm->ls;
	if (ls) {
		scst_dlm_lock_wait(ls, DLM_LOCK_EX, &pr_dlm->post_upd_lksb,
				   DLM_LKF_CONVERT, NULL, scst_dlm_post_bast);
		scst_dlm_lock_wait(ls, DLM_LOCK_NL, &pr_dlm->pre_upd_lksb,
				   DLM_LKF_CONVERT, NULL, scst_dlm_pre_bast);
	}
	mutex_unlock(&pr_dlm->ls_mutex);
}

static void scst_dlm_post_bast(void *bastarg, int mode)
{
	struct scst_lksb *post_lksb = bastarg;
	struct scst_pr_dlm_data *pr_dlm = post_lksb->pr_dlm;
	const bool join = post_lksb == &pr_dlm->post_join_lksb;

	/* An AST must not block, so execute further work asynchronously. */
	if (join)
		queue_work(pr_dlm->to_wq, &pr_dlm->copy_to_dlm_work);
	else
		queue_work(pr_dlm->from_wq, &pr_dlm->copy_from_dlm_work);
}

/*
 * Note: the node that has invoked scst_trigger_lvb_update() holds PR_LOCK
 * in EX mode and waits until this function has finished.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void scst_copy_to_dlm_work(void *p)
{
	struct scst_pr_dlm_data *pr_dlm = p;
#else
static void scst_copy_to_dlm_work(struct work_struct *work)
{
	struct scst_pr_dlm_data *pr_dlm = container_of(work,
				struct scst_pr_dlm_data, copy_to_dlm_work);
#endif
	struct scst_device *dev = pr_dlm->dev;
	dlm_lockspace_t *ls;
	int res;

	PRINT_INFO("Copying PR state to the DLM");

	mutex_lock(&pr_dlm->ls_mutex);
	ls = pr_dlm->ls;
	if (!ls)
		goto unlock_ls;
	scst_dlm_lock_wait(ls, DLM_LOCK_EX, &pr_dlm->pre_join_lksb,
			   DLM_LKF_CONVERT, NULL, scst_dlm_pre_bast);
	res = scst_dlm_lock_wait(ls, DLM_LOCK_PW, &pr_dlm->data_lksb,
				 DLM_LKF_CONVERT | DLM_LKF_VALBLK, PR_DATA_LOCK,
				 NULL);
	if (res < 0) {
		PRINT_WARNING("dlm_lock(%s.%s) returned %d", dev->virt_name,
			      PR_DATA_LOCK, res);
		goto unlock_pr;
	}

	/*
	 * Note: whether or not the PR_DATA_LOCK LVB is valid does not matter
	 * here since we are going to overwrite it anyway.
	 */
	if (pr_dlm->data_lksb.lksb.sb_flags & DLM_SBF_VALNOTVALID)
		PRINT_INFO("%s.%s LVB not valid\n", dev->virt_name,
			   PR_DATA_LOCK);

	scst_copy_to_dlm(dev, ls);
	scst_dlm_lock_wait(ls, DLM_LOCK_CR, &pr_dlm->data_lksb,
			   DLM_LKF_CONVERT | DLM_LKF_VALBLK, PR_DATA_LOCK,
			   NULL);

unlock_pr:
	dlm_lock(ls, DLM_LOCK_NL, &pr_dlm->post_join_lksb.lksb,
		      DLM_LKF_CONVERT, NULL, 0, 0, scst_dlm_post_ast,
		      &pr_dlm->post_join_lksb, scst_dlm_post_bast);

	PRINT_INFO("Finished copying PR state to the DLM");

	scst_dlm_update_nodeids(pr_dlm);

	scst_pr_toggle_lock(pr_dlm, ls, PR_POST_UPDATE_LOCK);
	scst_pr_toggle_lock(pr_dlm, ls, PR_PRE_UPDATE_LOCK);
	scst_pr_toggle_lock(pr_dlm, ls, PR_POST_UPDATE_LOCK);

unlock_ls:
	mutex_unlock(&pr_dlm->ls_mutex);

	PRINT_INFO("Finished notifying other nodes about the new PR state");
}

/*
 * Note: the scst_copy_from_dlm() call below runs outside command context. It
 * is protected against device removal because scst_pr_dlm_cleanup() is
 * invoked before a device is removed and that last function waits until this
 * function has finished and additionally prevents new invocations of this
 * function. The scst_copy_from_dlm() call below is protected against tgt_dev
 * addition or removal (e.g. due to a cable pull) because
 * scst_pr_init_tgt_dev() and scst_pr_clear_tgt_dev() in scst_pres.c protect
 * these manipulations by locking the PR data structures for writing.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void scst_copy_from_dlm_work(void *p)
{
	struct scst_pr_dlm_data *pr_dlm = p;
#else
static void scst_copy_from_dlm_work(struct work_struct *work)
{
	struct scst_pr_dlm_data *pr_dlm = container_of(work,
				struct scst_pr_dlm_data, copy_from_dlm_work);
#endif
	struct scst_device *dev = pr_dlm->dev;
	dlm_lockspace_t *ls;
	int res = -ENOENT;
	bool modified_lvb = false;

	mutex_lock(&pr_dlm->ls_mutex);
	ls = pr_dlm->ls;
	if (!ls)
		goto unlock_ls;
	scst_dlm_lock_wait(ls, DLM_LOCK_EX, &pr_dlm->pre_upd_lksb,
			   DLM_LKF_CONVERT, NULL, scst_dlm_pre_bast);
	res = scst_dlm_lock_wait(ls, DLM_LOCK_PW, &pr_dlm->data_lksb,
				 DLM_LKF_CONVERT | DLM_LKF_VALBLK, PR_DATA_LOCK,
				 NULL);
	if (res < 0) {
		PRINT_WARNING("dlm_lock(%s.%s) returned %d", dev->virt_name,
			      PR_DATA_LOCK, res);
		goto unlock_pr;
	}
	if (pr_dlm->data_lksb.lksb.sb_flags & DLM_SBF_VALNOTVALID) {
		PRINT_WARNING("%s.%s has an invalid lock value block",
			      dev->virt_name, PR_DATA_LOCK);
		res = -EINVAL;
		goto unlock_pr;
	}
	res = scst_copy_from_dlm(dev, ls, &modified_lvb);
	scst_dlm_lock_wait(ls, DLM_LOCK_CR, &pr_dlm->data_lksb,
			   DLM_LKF_CONVERT | DLM_LKF_VALBLK, PR_DATA_LOCK,
			   NULL);

unlock_pr:
	dlm_lock(ls, DLM_LOCK_NL, &pr_dlm->post_upd_lksb.lksb,
		      DLM_LKF_CONVERT, NULL, 0, 0, scst_dlm_post_ast,
		      &pr_dlm->post_upd_lksb, scst_dlm_post_bast);

	scst_dlm_update_nodeids(pr_dlm);

unlock_ls:
	mutex_unlock(&pr_dlm->ls_mutex);

	if (res == -EINVAL)
		queue_work(pr_dlm->upd_wq, &pr_dlm->lvb_upd_work);
	else if (modified_lvb)
		queue_work(pr_dlm->upd_wq, &pr_dlm->reread_lvb_work);
}

static void scst_dlm_post_ast(void *astarg)
{
}

/* Tell other nodes to refresh their local state from the lock value blocks. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void scst_reread_lvb_work(void *p)
{
	struct scst_pr_dlm_data *pr_dlm = p;
#else
static void scst_reread_lvb_work(struct work_struct *work)
{
	struct scst_pr_dlm_data *pr_dlm = container_of(work,
				struct scst_pr_dlm_data, reread_lvb_work);
#endif
	dlm_lockspace_t *ls;
	struct scst_lksb pr_lksb;
	int res;

	mutex_lock(&pr_dlm->ls_mutex);
	ls = pr_dlm->ls;
	if (!ls)
		goto unlock_ls;
	memset(&pr_lksb, 0, sizeof(pr_lksb));
	res = scst_dlm_lock_wait(ls, DLM_LOCK_EX, &pr_lksb, 0, PR_LOCK,
				 NULL);
	if (res >= 0)
		scst_trigger_reread_lvb(pr_dlm, ls);
	if (pr_lksb.lksb.sb_lkid)
		scst_dlm_unlock_wait(ls, &pr_lksb);

unlock_ls:
	mutex_unlock(&pr_dlm->ls_mutex);
}

/* Tell other nodes to update the DLM lock value blocks. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void scst_lvb_upd_work(void *p)
{
	struct scst_pr_dlm_data *pr_dlm = p;
#else
static void scst_lvb_upd_work(struct work_struct *work)
{
	struct scst_pr_dlm_data *pr_dlm = container_of(work,
				struct scst_pr_dlm_data, lvb_upd_work);
#endif
	dlm_lockspace_t *ls;
	struct scst_lksb lksb;
	int res;

	mutex_lock(&pr_dlm->ls_mutex);
	ls = pr_dlm->ls;
	if (!ls)
		goto unlock_ls;
	memset(&lksb, 0, sizeof(lksb));
	res = scst_dlm_lock_wait(ls, DLM_LOCK_EX, &lksb, 0, PR_LOCK, NULL);
	if (res >= 0)
		scst_trigger_lvb_update(pr_dlm, ls);
	if (lksb.lksb.sb_lkid)
		scst_dlm_unlock_wait(ls, &lksb);

unlock_ls:
	mutex_unlock(&pr_dlm->ls_mutex);
}

static struct workqueue_struct *__printf(1, 2)
create_st_wq(const char *fmt, ...)
{
	struct workqueue_struct *wq = NULL;
	va_list ap;
	char *name;

	va_start(ap, fmt);
	name = kvasprintf(GFP_KERNEL, fmt, ap);
	va_end(ap);
	if (name)
		wq = create_singlethread_workqueue(name);
	kfree(name);
	return wq;
}

/*
 * Caller must ensure that no commands are being executed for device @dev,
 * e.g. by suspending commands before calling this function.
 */
static int scst_pr_dlm_init(struct scst_device *dev, const char *cl_dev_id)
{
	struct scst_pr_dlm_data *pr_dlm;
	struct scst_dev_registrant *reg;
	int res = -ENOMEM;

	compile_time_size_checks();

	list_for_each_entry(reg, &dev->dev_registrants_list,
			    dev_registrants_list_entry)
		scst_dlm_pr_init_reg(dev, reg);

	pr_dlm = kzalloc(sizeof(*dev->pr_dlm), GFP_KERNEL);
	if (!pr_dlm)
		goto out;
	dev->pr_dlm = pr_dlm;
	pr_dlm->dev = dev;
	mutex_init(&pr_dlm->ls_cr_mutex);
	mutex_init(&pr_dlm->ls_mutex);
	pr_dlm->data_lksb.lksb.sb_lvbptr = pr_dlm->lvb;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	INIT_WORK(&pr_dlm->pre_join_work, scst_pre_join_work, pr_dlm);
	INIT_WORK(&pr_dlm->pre_upd_work, scst_pre_upd_work, pr_dlm);
	INIT_WORK(&pr_dlm->copy_from_dlm_work, scst_copy_from_dlm_work, pr_dlm);
	INIT_WORK(&pr_dlm->copy_to_dlm_work, scst_copy_to_dlm_work, pr_dlm);
	INIT_WORK(&pr_dlm->lvb_upd_work, scst_lvb_upd_work, pr_dlm);
	INIT_WORK(&pr_dlm->reread_lvb_work, scst_reread_lvb_work, pr_dlm);
#else
	INIT_WORK(&pr_dlm->pre_join_work, scst_pre_join_work);
	INIT_WORK(&pr_dlm->pre_upd_work, scst_pre_upd_work);
	INIT_WORK(&pr_dlm->copy_from_dlm_work, scst_copy_from_dlm_work);
	INIT_WORK(&pr_dlm->copy_to_dlm_work, scst_copy_to_dlm_work);
	INIT_WORK(&pr_dlm->lvb_upd_work, scst_lvb_upd_work);
	INIT_WORK(&pr_dlm->reread_lvb_work, scst_reread_lvb_work);
#endif
	pr_dlm->latest_lscr_attempt = jiffies - 100 * HZ;

	res = -ENOMEM;
	pr_dlm->cl_dev_id = kstrdup(cl_dev_id, GFP_KERNEL);
	if (!pr_dlm->cl_dev_id)
		goto err_free;

	pr_dlm->from_wq = create_st_wq("%s_from_dlm", dev->virt_name);
	if (IS_ERR(pr_dlm->from_wq)) {
		res = PTR_ERR(pr_dlm->from_wq);
		pr_dlm->from_wq = NULL;
		goto err_free;
	}

	pr_dlm->to_wq = create_st_wq("%s_to_dlm", dev->virt_name);
	if (IS_ERR(pr_dlm->to_wq)) {
		res = PTR_ERR(pr_dlm->to_wq);
		pr_dlm->to_wq = NULL;
		goto err_free;
	}

	pr_dlm->upd_wq = create_st_wq("%s_upd_dlm", dev->virt_name);
	if (IS_ERR(pr_dlm->upd_wq)) {
		res = PTR_ERR(pr_dlm->upd_wq);
		pr_dlm->upd_wq = NULL;
		goto err_free;
	}

	res = 0;

out:
	return res;

err_free:
	scst_pr_dlm_cleanup(dev);
	goto out;
}

/*
 * Note: The caller must ensure that get_lockspace() is not invoked
 * concurrently with scst_pr_dlm_cleanup(). This can be realized by suspending
 * command execution and by holding scst_mutex. The get_lockspace() callers are:
 * - scst_dlm_pr_is_set();
 * - scst_dlm_pr_write_lock();
 * - scst_dlm_reserved();
 * - scst_dlm_res_lock().
 * The first three functions are invoked from command context only. The last
 * function is either invoked from command context or is invoked with
 * scst_mutex held (from scst_clear_reservation(),
 * scst_reassign_persistent_sess_states() and scst_obtain_device_parameters()).
 */
static void scst_pr_dlm_cleanup(struct scst_device *dev)
{
	struct scst_pr_dlm_data *const pr_dlm = dev->pr_dlm;
	dlm_lockspace_t *ls;
	struct scst_lksb pr_lksb;

	if (!pr_dlm)
		return;
	ls = pr_dlm->ls;
	if (ls) {
		memset(&pr_lksb, 0, sizeof(pr_lksb));

		mutex_lock(&pr_dlm->ls_mutex);
		scst_dlm_lock_wait(ls, DLM_LOCK_EX, &pr_lksb, 0, PR_LOCK, NULL);
		scst_dlm_remove_locks(pr_dlm, ls);
		scst_dlm_unlock_wait(ls, &pr_lksb);
		pr_dlm->ls = NULL;
		mutex_unlock(&pr_dlm->ls_mutex);

		if (pr_dlm->from_wq)
			cancel_work_sync(&pr_dlm->copy_from_dlm_work);
		if (pr_dlm->to_wq)
			cancel_work_sync(&pr_dlm->copy_to_dlm_work);
		if (pr_dlm->upd_wq) {
			cancel_work_sync(&pr_dlm->lvb_upd_work);
			cancel_work_sync(&pr_dlm->reread_lvb_work);
		}
		release_lockspace(ls, pr_dlm->cl_dev_id);
	}
	if (pr_dlm->upd_wq)
		destroy_workqueue(pr_dlm->upd_wq);
	if (pr_dlm->to_wq)
		destroy_workqueue(pr_dlm->to_wq);
	if (pr_dlm->from_wq)
		destroy_workqueue(pr_dlm->from_wq);
	kfree(pr_dlm->nodeid);
	kfree(pr_dlm->cl_dev_id);
	kfree(pr_dlm);
	dev->pr_dlm = NULL;
}

const struct scst_cl_ops scst_dlm_cl_ops = {
	.pr_init		= scst_pr_dlm_init,
	.pr_cleanup		= scst_pr_dlm_cleanup,
	.pr_is_set		= scst_dlm_pr_is_set,
	.pr_init_reg		= scst_dlm_pr_init_reg,
	.pr_rm_reg		= scst_dlm_pr_rm_reg,
	.pr_write_lock		= scst_dlm_pr_write_lock,
	.pr_write_unlock	= scst_dlm_pr_write_unlock,
	.reserved		= scst_dlm_reserved,
	.res_lock		= scst_dlm_res_lock,
	.res_unlock		= scst_dlm_res_unlock,
	.is_rsv_holder		= scst_dlm_is_rsv_holder,
	.is_not_rsv_holder	= scst_dlm_is_not_rsv_holder,
	.reserve		= scst_dlm_reserve,
};

#endif
