/*
 *  scst_user.c
 *
 *  Copyright (C) 2007 - 2018 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2007 - 2018 Western Digital Corporation
 *
 *  SCSI virtual user space device handler
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

#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/poll.h>
#include <linux/eventpoll.h>
#include <linux/stddef.h>
#include <linux/slab.h>

#define LOG_PREFIX		DEV_USER_NAME

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#include <scst/scst_user.h>
#else
#include <linux/version.h>
#include "scst.h"
#include "scst_user.h"
#endif
#include "scst_dev_handler.h"

#ifndef INSIDE_KERNEL_TREE
#if defined(CONFIG_HIGHMEM4G) || defined(CONFIG_HIGHMEM64G)
#warning HIGHMEM kernel configurations are not supported by this module, \
because nowadays it is not worth the effort. Consider changing \
VMSPLIT option or use a 64-bit configuration instead. See README file \
for details.
#endif
#endif

#define DEV_USER_CMD_HASH_ORDER		6
#define DEV_USER_ATTACH_TIMEOUT		(5 * HZ)

struct scst_user_dev {
	/*
	 * Must be kept here, because it's needed on the cleanup time,
	 * when corresponding scst_dev is already dead.
	 */
	struct scst_cmd_threads udev_cmd_threads;

	/* Protected by udev_cmd_threads.cmd_list_lock */
	struct list_head ready_cmd_list;

	/*
	 * Don't need any protection or assignment in SCST_USER_SET_OPTIONS
	 * supposed to be serialized by the caller
	 */
	unsigned int blocking:1;
	unsigned int cleanup_done:1;
	unsigned int tst:3;
	unsigned int tmf_only:1;
	unsigned int queue_alg:4;
	unsigned int qerr:2;
	unsigned int tas:1;
	unsigned int swp:1;
	unsigned int d_sense:1;
	unsigned int has_own_order_mgmt:1;
	unsigned int ext_copy_remap_supported:1;

	int (*generic_parse)(struct scst_cmd *cmd);

	int def_block_size;

	struct scst_mem_lim udev_mem_lim;
	struct sgv_pool *pool;
	struct sgv_pool *pool_clust;

	uint8_t parse_type;
	uint8_t on_free_cmd_type;
	uint8_t memory_reuse_type;
	uint8_t partial_transfers_type;
	uint32_t partial_len;

	struct scst_dev_type devtype;

	/* Both protected by udev_cmd_threads.cmd_list_lock */
	unsigned int handle_counter;
	struct list_head ucmd_hash[1 << DEV_USER_CMD_HASH_ORDER];

	struct scst_device *sdev;

	int virt_id;
	struct list_head dev_list_entry;
	char name[SCST_MAX_NAME];

	struct list_head cleanup_list_entry;
	struct completion cleanup_cmpl;
};

/* Most fields are unprotected, since only one thread at time can access them */
struct scst_user_cmd {
	struct scst_cmd *cmd;
	struct scst_user_dev *dev;

	/*
	 * Note, gcc reported to have a long standing bug, when it uses 64-bit
	 * memory accesses for int bit fields, so, if any neighbor int field
	 * modified intependently to those bit fields, it must be 64-bit
	 * aligned to workaround this gcc bug!
	 */
	unsigned int buff_cached:1;
	unsigned int buf_dirty:1;
	unsigned int background_exec:1;
	unsigned int aborted:1;

	struct scst_user_cmd *buf_ucmd;

	atomic_t ucmd_ref;

	int cur_data_page;
	int num_data_pages;
	int first_page_offset;
	unsigned long ubuff;
	struct page **data_pages;
	struct sgv_pool_obj *sgv;

	/*
	 * Special flags, which can be accessed asynchronously (hence "long").
	 * Protected by udev_cmd_threads.cmd_list_lock.
	 */
	unsigned long sent_to_user:1;
	unsigned long jammed:1;
	unsigned long this_state_unjammed:1;
	unsigned long seen_by_user:1; /* here only as a small optimization */

	unsigned int state;

	struct list_head ready_cmd_list_entry;

	unsigned int h;
	struct list_head hash_list_entry;

	int user_cmd_payload_len;
	struct scst_user_get_cmd user_cmd;

	/* cmpl used only by ATTACH_SESS, mcmd used only by TM */
	union {
		struct completion *cmpl;
		struct scst_mgmt_cmd *mcmd;
	};
	int result;
};

static void dev_user_free_ucmd(struct scst_user_cmd *ucmd);

static struct page *dev_user_alloc_pages(struct scatterlist *sg, gfp_t gfp_mask, void *priv);
static void dev_user_free_sg_entries(struct scatterlist *sg, int sg_count,
				     void *priv);

static void dev_user_add_to_ready(struct scst_user_cmd *ucmd);

static void dev_user_unjam_cmd(struct scst_user_cmd *ucmd, int busy, unsigned long *flags);

static int dev_user_process_reply_on_free(struct scst_user_cmd *ucmd);
static int dev_user_process_reply_tm_exec(struct scst_user_cmd *ucmd, int status);
static int dev_user_process_reply_sess(struct scst_user_cmd *ucmd, int status);
static int dev_user_register_dev(struct file *file, const struct scst_user_dev_desc *dev_desc);
static int dev_user_unregister_dev(struct file *file);
static int dev_user_flush_cache(struct file *file);
static int dev_user_capacity_changed(struct file *file);
static int dev_user_prealloc_buffer(struct file *file, void __user *arg);
static int __dev_user_set_opt(struct scst_user_dev *dev, const struct scst_user_opt *opt);
static int dev_user_set_opt(struct file *file, const struct scst_user_opt *opt);
static int dev_user_get_opt(struct file *file, void __user *arg);

static __poll_t dev_user_poll(struct file *filp, poll_table *wait);
static long dev_user_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static int dev_user_release(struct inode *inode, struct file *file);
static int dev_user_exit_dev(struct scst_user_dev *dev);

static ssize_t dev_user_sysfs_commands_show(struct kobject *kobj, struct kobj_attribute *attr,
					    char *buf);

static struct kobj_attribute dev_user_commands_attr =
	__ATTR(commands, 0444, dev_user_sysfs_commands_show, NULL);

static const struct attribute *dev_user_dev_attrs[] = {
	&dev_user_commands_attr.attr,
	NULL,
};

static int dev_usr_parse(struct scst_cmd *cmd);

/** Data **/

static struct kmem_cache *user_dev_cachep;

static struct kmem_cache *user_cmd_cachep;

static const struct file_operations dev_user_fops = {
	.poll		= dev_user_poll,
	.unlocked_ioctl	= dev_user_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= dev_user_ioctl,
#endif
	.release	= dev_user_release,
};

static struct scst_dev_type dev_user_devtype = {
	.no_mgmt =	1,
	.name =		DEV_USER_NAME,
	.type =		-1,
	.parse =	dev_usr_parse,
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags = SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags = &trace_flag,
#endif
};

static int dev_user_major;

static struct class *dev_user_sysfs_class;

static DEFINE_SPINLOCK(dev_list_lock);
static LIST_HEAD(dev_list);

static DEFINE_SPINLOCK(cleanup_lock);
static LIST_HEAD(cleanup_list);
static DECLARE_WAIT_QUEUE_HEAD(cleanup_list_waitQ);
static struct task_struct *cleanup_thread;

/*
 * Skip this command if result is not 0. Must be called under
 * udev_cmd_threads.cmd_list_lock and IRQ off.
 */
static inline bool ucmd_get_check(struct scst_user_cmd *ucmd)
{
	int r = atomic_inc_return(&ucmd->ucmd_ref);
	int res;

	if (unlikely(r == 1)) {
		TRACE_DBG("ucmd %p is being destroyed", ucmd);
		atomic_dec(&ucmd->ucmd_ref);
		res = true;
		/*
		 * Necessary code is serialized by cmd_list_lock in
		 * cmd_remove_hash()
		 */
	} else {
		TRACE_DBG("ucmd %p, new ref_cnt %d", ucmd,
			  atomic_read(&ucmd->ucmd_ref));
		res = false;
	}
	return res;
}

static inline void ucmd_get(struct scst_user_cmd *ucmd)
{
	TRACE_DBG("ucmd %p, ucmd_ref %d", ucmd, atomic_read(&ucmd->ucmd_ref));
	atomic_inc(&ucmd->ucmd_ref);
	/*
	 * For the same reason as in kref_get(). Let's be safe and
	 * always do it.
	 */
	smp_mb__after_atomic_inc();
}

/* Must not be called under cmd_list_lock!! */
static inline void ucmd_put(struct scst_user_cmd *ucmd)
{
	TRACE_DBG("ucmd %p, ucmd_ref %d", ucmd, atomic_read(&ucmd->ucmd_ref));

	EXTRACHECKS_BUG_ON(atomic_read(&ucmd->ucmd_ref) == 0);

	if (atomic_dec_and_test(&ucmd->ucmd_ref))
		dev_user_free_ucmd(ucmd);
}

static inline int calc_num_pg(unsigned long buf, int len)
{
	len += buf & ~PAGE_MASK;
	return (len >> PAGE_SHIFT) + ((len & ~PAGE_MASK) != 0);
}

static void __dev_user_not_reg(void)
{
	TRACE_MGMT_DBG("Device not registered");
}

static inline int dev_user_check_reg(struct scst_user_dev *dev)
{
	if (!dev) {
		__dev_user_not_reg();
		return -ENODEV;
	}
	return 0;
}

static inline int scst_user_cmd_hashfn(int h)
{
	return h & ((1 << DEV_USER_CMD_HASH_ORDER) - 1);
}

static inline struct scst_user_cmd *__ucmd_find_hash(struct scst_user_dev *dev, unsigned int h)
{
	struct list_head *head;
	struct scst_user_cmd *ucmd;

	head = &dev->ucmd_hash[scst_user_cmd_hashfn(h)];
	list_for_each_entry(ucmd, head, hash_list_entry) {
		if (ucmd->h == h) {
			TRACE_DBG("Found ucmd %p", ucmd);
			return ucmd;
		}
	}
	return NULL;
}

static void cmd_insert_hash(struct scst_user_cmd *ucmd)
{
	struct list_head *head;
	struct scst_user_dev *dev = ucmd->dev;
	struct scst_user_cmd *u;
	unsigned long flags;

	spin_lock_irqsave(&dev->udev_cmd_threads.cmd_list_lock, flags);

	do {
		ucmd->h = dev->handle_counter++;
		u = __ucmd_find_hash(dev, ucmd->h);
	} while (u);

	head = &dev->ucmd_hash[scst_user_cmd_hashfn(ucmd->h)];
	list_add_tail(&ucmd->hash_list_entry, head);
	spin_unlock_irqrestore(&dev->udev_cmd_threads.cmd_list_lock, flags);

	TRACE_DBG("Inserted ucmd %p, h=%d (dev %s)", ucmd, ucmd->h, dev->name);
}

static inline void cmd_remove_hash(struct scst_user_cmd *ucmd)
{
	unsigned long flags;

	spin_lock_irqsave(&ucmd->dev->udev_cmd_threads.cmd_list_lock, flags);
	list_del(&ucmd->hash_list_entry);
	spin_unlock_irqrestore(&ucmd->dev->udev_cmd_threads.cmd_list_lock, flags);

	TRACE_DBG("Removed ucmd %p, h=%d", ucmd, ucmd->h);
}

static void dev_user_free_ucmd(struct scst_user_cmd *ucmd)
{
	TRACE_ENTRY();

	TRACE_MEM("Freeing ucmd %p", ucmd);

	cmd_remove_hash(ucmd);
	EXTRACHECKS_BUG_ON(ucmd->cmd);

	kmem_cache_free(user_cmd_cachep, ucmd);

	TRACE_EXIT();
}

static struct page *dev_user_alloc_pages(struct scatterlist *sg, gfp_t gfp_mask, void *priv)
{
	struct scst_user_cmd *ucmd = priv;
	int offset = 0;

	TRACE_ENTRY();

	/* *sg supposed to be zeroed */

	TRACE_MEM("ucmd %p, ubuff %lx, ucmd->cur_data_page %d",
		  ucmd, ucmd->ubuff, ucmd->cur_data_page);

	if (ucmd->cur_data_page == 0) {
		TRACE_MEM("ucmd->first_page_offset %d",
			  ucmd->first_page_offset);
		offset = ucmd->first_page_offset;
		ucmd_get(ucmd);
	}

	if (ucmd->cur_data_page >= ucmd->num_data_pages)
		goto out;

	sg_set_page(sg, ucmd->data_pages[ucmd->cur_data_page], PAGE_SIZE - offset, offset);
	ucmd->cur_data_page++;

	TRACE_MEM("page=%p, length=%d, offset=%d",
		  sg_page(sg), sg->length, sg->offset);
	TRACE_BUFFER("Page data", sg_virt(sg), sg->length);

out:
	TRACE_EXIT();
	return sg_page(sg);
}

static void dev_user_on_cached_mem_free(struct scst_user_cmd *ucmd)
{
	TRACE_ENTRY();

	TRACE_MEM("Preparing ON_CACHED_MEM_FREE (ucmd %p, h %d, ubuff %lx)",
		  ucmd, ucmd->h, ucmd->ubuff);

	ucmd->user_cmd_payload_len =
		offsetof(struct scst_user_get_cmd, on_cached_mem_free) +
		sizeof(ucmd->user_cmd.on_cached_mem_free);
	ucmd->user_cmd.cmd_h = ucmd->h;
	ucmd->user_cmd.subcode = SCST_USER_ON_CACHED_MEM_FREE;
	ucmd->user_cmd.on_cached_mem_free.pbuf = ucmd->ubuff;

	ucmd->state = UCMD_STATE_ON_CACHE_FREEING;

	dev_user_add_to_ready(ucmd);

	TRACE_EXIT();
}

static void dev_user_unmap_buf(struct scst_user_cmd *ucmd)
{
	int i;

	TRACE_ENTRY();

	TRACE_MEM("Unmapping data pages (ucmd %p, ubuff %lx, num %d)",
		  ucmd, ucmd->ubuff, ucmd->num_data_pages);

	for (i = 0; i < ucmd->num_data_pages; i++) {
		struct page *page = ucmd->data_pages[i];

		if (ucmd->buf_dirty)
			SetPageDirty(page);

		put_page(page);
	}

	kfree(ucmd->data_pages);
	ucmd->data_pages = NULL;

	TRACE_EXIT();
}

static void __dev_user_free_sg_entries(struct scst_user_cmd *ucmd)
{
	TRACE_ENTRY();

	sBUG_ON(!ucmd->data_pages);

	TRACE_MEM("Freeing data pages (ucmd=%p, ubuff=%lx, buff_cached=%d)",
		  ucmd, ucmd->ubuff, ucmd->buff_cached);

	dev_user_unmap_buf(ucmd);

	if (ucmd->buff_cached)
		dev_user_on_cached_mem_free(ucmd);
	else
		ucmd_put(ucmd);

	TRACE_EXIT();
}

static void dev_user_free_sg_entries(struct scatterlist *sg, int sg_count, void *priv)
{
	struct scst_user_cmd *ucmd = priv;

	TRACE_MEM("Freeing data pages (sg=%p, sg_count=%d, priv %p)",
		  sg, sg_count, ucmd);

	__dev_user_free_sg_entries(ucmd);
}

static inline int is_buff_cached(struct scst_user_cmd *ucmd)
{
	int mem_reuse_type = ucmd->dev->memory_reuse_type;

	if (mem_reuse_type == SCST_USER_MEM_REUSE_ALL ||
	    (ucmd->cmd->data_direction == SCST_DATA_READ &&
	     mem_reuse_type == SCST_USER_MEM_REUSE_READ) ||
	    (ucmd->cmd->data_direction == SCST_DATA_WRITE &&
	     mem_reuse_type == SCST_USER_MEM_REUSE_WRITE))
		return 1;
	else
		return 0;
}

static inline int is_need_offs_page(unsigned long buf, int len)
{
	return ((buf & ~PAGE_MASK) != 0) &&
		((buf & PAGE_MASK) != ((buf + len - 1) & PAGE_MASK));
}

/*
 * Returns 0 for success, <0 for fatal failure, >0 - need pages.
 * Unmaps the buffer, if needed in case of error
 */
static int dev_user_alloc_sg(struct scst_user_cmd *ucmd, int cached_buff)
{
	int res = 0;
	struct scst_cmd *cmd = ucmd->cmd;
	struct scst_user_dev *dev = ucmd->dev;
	struct sgv_pool *pool;
	gfp_t gfp_mask;
	int flags = 0;
	int bufflen, orig_bufflen;
	int last_len = 0;
	int out_sg_pages = 0;

	TRACE_ENTRY();

	gfp_mask = __GFP_NOWARN;
	gfp_mask |= (scst_cmd_atomic(cmd) ? GFP_ATOMIC : GFP_KERNEL);

	if (cmd->data_direction != SCST_DATA_BIDI) {
		orig_bufflen = cmd->bufflen;
		pool = cmd->tgt_dev->dh_priv;
	} else {
		/* Make out_sg->offset 0 */
		int len = cmd->bufflen + ucmd->first_page_offset;

		out_sg_pages = (len >> PAGE_SHIFT) + ((len & ~PAGE_MASK) != 0);
		orig_bufflen = (out_sg_pages << PAGE_SHIFT) + cmd->out_bufflen;
		pool = dev->pool;
	}
	bufflen = orig_bufflen;

	EXTRACHECKS_BUG_ON(bufflen == 0);

	if (cached_buff) {
		flags |= SGV_POOL_RETURN_OBJ_ON_ALLOC_FAIL;
		if (ucmd->ubuff == 0)
			flags |= SGV_POOL_NO_ALLOC_ON_CACHE_MISS;
	} else {
		TRACE_MEM("Not cached buff");
		flags |= SGV_POOL_ALLOC_NO_CACHED;
		if (ucmd->ubuff == 0) {
			res = 1;
			goto out;
		}
		bufflen += ucmd->first_page_offset;
		if (is_need_offs_page(ucmd->ubuff, orig_bufflen))
			last_len = bufflen & ~PAGE_MASK;
		else
			last_len = orig_bufflen & ~PAGE_MASK;
	}
	ucmd->buff_cached = cached_buff;

	cmd->sg = sgv_pool_alloc(pool, bufflen, gfp_mask, flags, &cmd->sg_cnt, &ucmd->sgv,
				 &dev->udev_mem_lim, ucmd);
	if (cmd->sg) {
		struct scst_user_cmd *buf_ucmd = sgv_get_priv(ucmd->sgv);

		TRACE_MEM("Buf ucmd %p (cmd->sg_cnt %d, last seg len %d, last_len %d, bufflen %d)",
			  buf_ucmd, cmd->sg_cnt, cmd->sg[cmd->sg_cnt - 1].length,
			  last_len, bufflen);

		ucmd->ubuff = buf_ucmd->ubuff;
		ucmd->buf_ucmd = buf_ucmd;

		EXTRACHECKS_BUG_ON(ucmd->data_pages && ucmd != buf_ucmd);

		if (last_len != 0) {
			cmd->sg[cmd->sg_cnt - 1].length &= PAGE_MASK;
			cmd->sg[cmd->sg_cnt - 1].length += last_len;
		}

		TRACE_MEM("Buf alloced (ucmd %p, cached_buff %d, ubuff %lx, last seg len %d)",
			  ucmd, cached_buff, ucmd->ubuff, cmd->sg[cmd->sg_cnt - 1].length);

		if (cmd->data_direction == SCST_DATA_BIDI) {
			cmd->out_sg = &cmd->sg[out_sg_pages];
			cmd->out_sg_cnt = cmd->sg_cnt - out_sg_pages;
			cmd->sg_cnt = out_sg_pages;
			TRACE_MEM("cmd %p, out_sg %p, out_sg_cnt %d, sg_cnt %d",
				  cmd, cmd->out_sg, cmd->out_sg_cnt, cmd->sg_cnt);
		}

		if (unlikely(cmd->sg_cnt > cmd->tgt_dev->max_sg_cnt)) {
			static int ll;

			if (ll < 10 || TRACING_MINOR()) {
				PRINT_INFO("Unable to complete command due to SG IO count limitation (requested %d, available %d, tgt lim %d)",
					   cmd->sg_cnt, cmd->tgt_dev->max_sg_cnt,
					   cmd->tgt->sg_tablesize);
				ll++;
			}
			cmd->sg = NULL;
			/* sgv will be freed in dev_user_free_sgv() */
			res = -1;
		}
	} else {
		TRACE_MEM("Buf not alloced (ucmd %p, h %d, buff_cached, %d, sg_cnt %d, ubuff %lx, sgv %p",
			  ucmd, ucmd->h, ucmd->buff_cached, cmd->sg_cnt, ucmd->ubuff, ucmd->sgv);
		if (unlikely(cmd->sg_cnt == 0)) {
			TRACE_MEM("Refused allocation (ucmd %p)", ucmd);
			sBUG_ON(ucmd->sgv);
			res = -1;
		} else {
			switch (ucmd->state) {
			case UCMD_STATE_BUF_ALLOCING:
				res = 1;
				break;
			case UCMD_STATE_EXECING:
				res = -1;
				break;
			default:
				sBUG();
				break;
			}
		}
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_alloc_space(struct scst_user_cmd *ucmd)
{
	int rc, res = SCST_CMD_STATE_DEFAULT;
	struct scst_cmd *cmd = ucmd->cmd;

	TRACE_ENTRY();

	ucmd->state = UCMD_STATE_BUF_ALLOCING;
	scst_cmd_set_dh_data_buff_alloced(cmd);

	rc = dev_user_alloc_sg(ucmd, is_buff_cached(ucmd));
	if (rc == 0)
		goto out;

	if (rc < 0) {
		scst_set_busy(cmd);
		res = scst_get_cmd_abnormal_done_state(cmd);
		goto out;
	}

	if (!(cmd->data_direction & SCST_DATA_WRITE) &&
	    ((cmd->op_flags & SCST_LOCAL_CMD) == 0)) {
		TRACE_DBG("Delayed alloc, ucmd %p", ucmd);
		goto out;
	}

	ucmd->user_cmd_payload_len =
		offsetof(struct scst_user_get_cmd, alloc_cmd) +
		sizeof(ucmd->user_cmd.alloc_cmd);
	ucmd->user_cmd.cmd_h = ucmd->h;
	ucmd->user_cmd.subcode = SCST_USER_ALLOC_MEM;
	ucmd->user_cmd.alloc_cmd.sess_h = (unsigned long)cmd->tgt_dev;
	memcpy(ucmd->user_cmd.alloc_cmd.cdb, cmd->cdb,
	       min_t(int, SCST_MAX_CDB_SIZE, cmd->cdb_len));
	ucmd->user_cmd.alloc_cmd.cdb_len = cmd->cdb_len;
	ucmd->user_cmd.alloc_cmd.alloc_len = ucmd->buff_cached ?
		(cmd->sg_cnt << PAGE_SHIFT) : cmd->bufflen;
	ucmd->user_cmd.alloc_cmd.queue_type = cmd->queue_type;
	ucmd->user_cmd.alloc_cmd.data_direction = cmd->data_direction;
	ucmd->user_cmd.alloc_cmd.sn = cmd->tgt_sn;

	TRACE_DBG("Preparing ALLOC_MEM for user space (ucmd=%p, h=%d, alloc_len %d)",
		  ucmd, ucmd->h, ucmd->user_cmd.alloc_cmd.alloc_len);

	dev_user_add_to_ready(ucmd);

	res = SCST_CMD_STATE_STOP;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct scst_user_cmd *dev_user_alloc_ucmd(struct scst_user_dev *dev, gfp_t gfp_mask)
{
	struct scst_user_cmd *ucmd = NULL;

	TRACE_ENTRY();

	ucmd = kmem_cache_zalloc(user_cmd_cachep, gfp_mask);
	if (unlikely(!ucmd)) {
		TRACE(TRACE_OUT_OF_MEM, "Unable to allocate user cmd (gfp_mask %x)",
		      gfp_mask);
		goto out;
	}
	ucmd->dev = dev;
	atomic_set(&ucmd->ucmd_ref, 1);

	cmd_insert_hash(ucmd);

	TRACE_MEM("ucmd %p allocated", ucmd);

out:
	TRACE_EXIT_HRES(ucmd);
	return ucmd;
}

static int dev_user_parse(struct scst_cmd *cmd)
{
	int rc, res = SCST_CMD_STATE_DEFAULT;
	struct scst_user_cmd *ucmd;
	int atomic = scst_cmd_atomic(cmd);
	struct scst_user_dev *dev = cmd->dev->dh_priv;
	gfp_t gfp_mask = atomic ? GFP_ATOMIC : GFP_KERNEL;

	TRACE_ENTRY();

	if (!cmd->dh_priv) {
		ucmd = dev_user_alloc_ucmd(dev, gfp_mask);
		if (unlikely(!ucmd)) {
			if (atomic) {
				res = SCST_CMD_STATE_NEED_THREAD_CTX;
				goto out;
			} else {
				scst_set_busy(cmd);
				goto out_error;
			}
		}
		ucmd->cmd = cmd;
		cmd->dh_priv = ucmd;
	} else {
		ucmd = cmd->dh_priv;
		TRACE_DBG("Used ucmd %p, state %x", ucmd, ucmd->state);
	}

	TRACE_DBG("ucmd %p, cmd %p, state %x", ucmd, cmd, ucmd->state);

	if (ucmd->state == UCMD_STATE_PARSING) {
		/* We've already done */
		goto done;
	}

	EXTRACHECKS_BUG_ON(ucmd->state != UCMD_STATE_NEW);

	switch (dev->parse_type) {
	case SCST_USER_PARSE_STANDARD:
		TRACE_DBG("PARSE STANDARD: ucmd %p", ucmd);
		rc = dev->generic_parse(cmd);
		if (rc != 0) {
			PRINT_ERROR("PARSE failed (ucmd %p, rc %d)", ucmd, rc);
			goto out_error;
		}
		break;

	case SCST_USER_PARSE_EXCEPTION:
		TRACE_DBG("PARSE EXCEPTION: ucmd %p", ucmd);
		rc = dev->generic_parse(cmd);
		if (rc == 0 && (cmd->op_flags & SCST_INFO_VALID))
			break;
		if (rc == SCST_CMD_STATE_NEED_THREAD_CTX) {
			TRACE_MEM("Restarting PARSE to thread context (ucmd %p)",
				  ucmd);
			res = SCST_CMD_STATE_NEED_THREAD_CTX;
			goto out;
		}
		fallthrough;

	case SCST_USER_PARSE_CALL:
		TRACE_DBG("Preparing PARSE for user space (ucmd=%p, h=%d, bufflen %d)",
			  ucmd, ucmd->h, cmd->bufflen);
		ucmd->user_cmd_payload_len =
			offsetof(struct scst_user_get_cmd, parse_cmd) +
			sizeof(ucmd->user_cmd.parse_cmd);
		ucmd->user_cmd.cmd_h = ucmd->h;
		ucmd->user_cmd.subcode = SCST_USER_PARSE;
		ucmd->user_cmd.parse_cmd.sess_h = (unsigned long)cmd->tgt_dev;
		memcpy(ucmd->user_cmd.parse_cmd.cdb, cmd->cdb,
		       min_t(int, SCST_MAX_CDB_SIZE, cmd->cdb_len));
		ucmd->user_cmd.parse_cmd.cdb_len = cmd->cdb_len;
		ucmd->user_cmd.parse_cmd.timeout = cmd->timeout / HZ;
		ucmd->user_cmd.parse_cmd.lba = cmd->lba;
		ucmd->user_cmd.parse_cmd.bufflen = cmd->bufflen;
		ucmd->user_cmd.parse_cmd.data_len = cmd->data_len;
		ucmd->user_cmd.parse_cmd.out_bufflen = cmd->out_bufflen;
		ucmd->user_cmd.parse_cmd.queue_type = cmd->queue_type;
		ucmd->user_cmd.parse_cmd.data_direction = cmd->data_direction;
		ucmd->user_cmd.parse_cmd.expected_values_set =
					cmd->expected_values_set;
		ucmd->user_cmd.parse_cmd.expected_data_direction =
					cmd->expected_data_direction;
		ucmd->user_cmd.parse_cmd.expected_transfer_len =
					cmd->expected_transfer_len_full;
		ucmd->user_cmd.parse_cmd.expected_out_transfer_len =
					cmd->expected_out_transfer_len;
		ucmd->user_cmd.parse_cmd.sn = cmd->tgt_sn;
		ucmd->user_cmd.parse_cmd.op_flags = cmd->op_flags;
		ucmd->state = UCMD_STATE_PARSING;
		dev_user_add_to_ready(ucmd);
		res = SCST_CMD_STATE_STOP;
		goto out;

	default:
		sBUG();
	}

done:
	if (cmd->bufflen == 0) {
		/*
		 * According to SPC bufflen 0 for data transfer commands isn't
		 * an error, so we need to fix the transfer direction.
		 */
		cmd->data_direction = SCST_DATA_NONE;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_error:
	res = scst_get_cmd_abnormal_done_state(cmd);
	goto out;
}

static int dev_user_alloc_data_buf(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_DEFAULT;
	struct scst_user_cmd *ucmd = cmd->dh_priv;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON((ucmd->state != UCMD_STATE_NEW) &&
			   (ucmd->state != UCMD_STATE_PARSING) &&
			   (ucmd->state != UCMD_STATE_BUF_ALLOCING));

	res = dev_user_alloc_space(ucmd);

	TRACE_EXIT_RES(res);
	return res;
}

static void dev_user_flush_dcache(struct scst_user_cmd *ucmd)
{
	struct scst_user_cmd *buf_ucmd = ucmd->buf_ucmd;
	unsigned long start = buf_ucmd->ubuff;
	int i, bufflen = ucmd->cmd->bufflen;

	TRACE_ENTRY();

	if (start == 0)
		goto out;

	/*
	 * Possibly, flushing of all the pages from ucmd->cmd->sg can be
	 * faster, since it should be cache hot, while ucmd->buf_ucmd and
	 * buf_ucmd->data_pages are cache cold. But, from other side,
	 * sizeof(buf_ucmd->data_pages[0]) is considerably smaller, than
	 * sizeof(ucmd->cmd->sg[0]), so on big buffers going over
	 * data_pages array can lead to less cache misses. So, real numbers are
	 * needed. ToDo.
	 */

	for (i = 0; (bufflen > 0) && (i < buf_ucmd->num_data_pages); i++) {
		struct page *page __attribute__((unused));

		page = buf_ucmd->data_pages[i];
#ifdef ARCH_HAS_FLUSH_ANON_PAGE
		{
			struct vm_area_struct *vma;

			vma = find_vma(current->mm, start);
			if (vma)
				flush_anon_page(vma, page, start);
		}
#endif
		flush_dcache_page(page);
		start += PAGE_SIZE;
		bufflen -= PAGE_SIZE;
	}

out:
	TRACE_EXIT();
}

static enum scst_exec_res dev_user_exec(struct scst_cmd *cmd)
{
	struct scst_user_cmd *ucmd = cmd->dh_priv;
	enum scst_exec_res res = SCST_EXEC_COMPLETED;

	TRACE_ENTRY();

	TRACE_DBG("Preparing EXEC for user space (ucmd=%p, h=%d, lba %lld, bufflen %d, data_len %lld, ubuff %lx)",
		  ucmd, ucmd->h, (long long)cmd->lba, cmd->bufflen, (long long)cmd->data_len,
		  ucmd->ubuff);

	if (cmd->data_direction & SCST_DATA_WRITE)
		dev_user_flush_dcache(ucmd);

	ucmd->user_cmd_payload_len =
		offsetof(struct scst_user_get_cmd, exec_cmd) +
		sizeof(ucmd->user_cmd.exec_cmd);
	ucmd->user_cmd.cmd_h = ucmd->h;
	ucmd->user_cmd.subcode = SCST_USER_EXEC;
	ucmd->user_cmd.exec_cmd.sess_h = (unsigned long)cmd->tgt_dev;
	memcpy(ucmd->user_cmd.exec_cmd.cdb, cmd->cdb,
	       min_t(int, SCST_MAX_CDB_SIZE, cmd->cdb_len));
	ucmd->user_cmd.exec_cmd.cdb_len = cmd->cdb_len;
	ucmd->user_cmd.exec_cmd.lba = cmd->lba;
	ucmd->user_cmd.exec_cmd.bufflen = cmd->bufflen;
	ucmd->user_cmd.exec_cmd.data_len = cmd->data_len;
	ucmd->user_cmd.exec_cmd.pbuf = ucmd->ubuff;
	if (ucmd->ubuff == 0 && cmd->data_direction != SCST_DATA_NONE) {
		ucmd->user_cmd.exec_cmd.alloc_len = ucmd->buff_cached ?
			(cmd->sg_cnt << PAGE_SHIFT) : cmd->bufflen;
	}
	ucmd->user_cmd.exec_cmd.queue_type = cmd->queue_type;
	ucmd->user_cmd.exec_cmd.data_direction = cmd->data_direction;
	ucmd->user_cmd.exec_cmd.partial = 0;
	ucmd->user_cmd.exec_cmd.timeout = cmd->timeout / HZ;
	ucmd->user_cmd.exec_cmd.p_out_buf = ucmd->ubuff +
						(cmd->sg_cnt << PAGE_SHIFT);
	ucmd->user_cmd.exec_cmd.out_bufflen = cmd->out_bufflen;
	ucmd->user_cmd.exec_cmd.sn = cmd->tgt_sn;

	ucmd->state = UCMD_STATE_EXECING;

	dev_user_add_to_ready(ucmd);

	TRACE_EXIT_RES(res);
	return res;
}

static void dev_user_ext_copy_remap(struct scst_cmd *cmd, struct scst_ext_copy_seg_descr *seg)
{
	struct scst_user_cmd *ucmd = cmd->dh_priv;

	TRACE_ENTRY();

	TRACE_DBG("Preparing EXT_COPY_REMAP for user space (ucmd=%p, h=%d, seg %p)",
		  ucmd, ucmd->h, seg);

	ucmd->user_cmd_payload_len =
		offsetof(struct scst_user_get_cmd, remap_cmd) +
		sizeof(ucmd->user_cmd.remap_cmd);
	ucmd->user_cmd.cmd_h = ucmd->h;
	ucmd->user_cmd.subcode = SCST_USER_EXT_COPY_REMAP;
	ucmd->user_cmd.remap_cmd.sess_h = (unsigned long)cmd->tgt_dev;

	ucmd->user_cmd.remap_cmd.src_sess_h = (unsigned long)seg->src_tgt_dev;
	ucmd->user_cmd.remap_cmd.dst_sess_h = (unsigned long)seg->dst_tgt_dev;
	ucmd->user_cmd.remap_cmd.data_descr.src_lba = seg->data_descr.src_lba;
	ucmd->user_cmd.remap_cmd.data_descr.dst_lba = seg->data_descr.dst_lba;
	ucmd->user_cmd.remap_cmd.data_descr.data_len = seg->data_descr.data_len;

	ucmd->state = UCMD_STATE_EXT_COPY_REMAPPING;

	dev_user_add_to_ready(ucmd);

	TRACE_EXIT();
}

static void dev_user_free_sgv(struct scst_user_cmd *ucmd)
{
	if (ucmd->sgv) {
		sgv_pool_free(ucmd->sgv, &ucmd->dev->udev_mem_lim);
		ucmd->sgv = NULL;
	} else if (ucmd->data_pages) {
		/* We mapped pages, but for some reason didn't allocate them */
		ucmd_get(ucmd);
		__dev_user_free_sg_entries(ucmd);
	}
}

static void dev_user_on_free_cmd(struct scst_cmd *cmd)
{
	struct scst_user_cmd *ucmd = cmd->dh_priv;

	TRACE_ENTRY();

	if (unlikely(!ucmd))
		goto out;

	TRACE_MEM("ucmd %p, cmd %p, buff_cached %d, ubuff %lx",
		  ucmd, ucmd->cmd, ucmd->buff_cached, ucmd->ubuff);

	ucmd->cmd = NULL;
	if ((cmd->data_direction & SCST_DATA_WRITE) && ucmd->buf_ucmd)
		ucmd->buf_ucmd->buf_dirty = 1;

	if (ucmd->dev->on_free_cmd_type == SCST_USER_ON_FREE_CMD_IGNORE) {
		ucmd->state = UCMD_STATE_ON_FREE_SKIPPED;
		/* The state assignment must be before freeing sgv! */
		goto out_reply;
	}

	if (unlikely(!ucmd->seen_by_user)) {
		TRACE_MGMT_DBG("Not seen by user ucmd %p", ucmd);
		goto out_reply;
	}

	TRACE_DBG("Preparing ON_FREE_CMD (pbuff 0x%lx)", ucmd->ubuff);
	ucmd->user_cmd_payload_len =
		offsetof(struct scst_user_get_cmd, on_free_cmd) +
		sizeof(ucmd->user_cmd.on_free_cmd);
	ucmd->user_cmd.cmd_h = ucmd->h;
	ucmd->user_cmd.subcode = SCST_USER_ON_FREE_CMD;
	ucmd->user_cmd.on_free_cmd.pbuf = ucmd->ubuff;
	ucmd->user_cmd.on_free_cmd.resp_data_len = cmd->resp_data_len;
	ucmd->user_cmd.on_free_cmd.buffer_cached = ucmd->buff_cached;
	ucmd->user_cmd.on_free_cmd.aborted = ucmd->aborted;
	ucmd->user_cmd.on_free_cmd.status = cmd->status;
	ucmd->user_cmd.on_free_cmd.delivery_status = cmd->delivery_status;

	ucmd->state = UCMD_STATE_ON_FREEING;

	dev_user_add_to_ready(ucmd);

out:
	TRACE_EXIT();
	return;

out_reply:
	dev_user_process_reply_on_free(ucmd);
	goto out;
}

static void dev_user_set_block_shift(struct scst_cmd *cmd, int block_shift)
{
	struct scst_device *dev = cmd->dev;
	struct scst_user_dev *udev = cmd->dev->dh_priv;
	int new_block_shift;

	TRACE_ENTRY();

	/*
	 * No need for locks here, since *_detach() can not be
	 * called, when there are existing commands.
	 */
	new_block_shift = block_shift ? :
		scst_calc_block_shift(udev->def_block_size);
	if (new_block_shift < 9) {
		PRINT_ERROR("Invalid block shift %d", new_block_shift);
	} else if (dev->block_shift != new_block_shift) {
		PRINT_INFO("%s: Changed block shift from %d into %d / %d",
			   dev->virt_name, dev->block_shift, block_shift,
			   new_block_shift);
		dev->block_shift = new_block_shift;
		dev->block_size = 1 << dev->block_shift;
	}

	TRACE_EXIT();
}

static void dev_user_set_block_size(struct scst_cmd *cmd, int block_size)
{
	struct scst_device *dev = cmd->dev;

	TRACE_ENTRY();

	/*
	 * No need for locks here, since *_detach() can not be
	 * called, when there are existing commands.
	 */
	TRACE_DBG("dev %p, new block size %d", dev, block_size);
	if (block_size != 0) {
		dev->block_size = block_size;
	} else {
		struct scst_user_dev *udev = cmd->dev->dh_priv;

		dev->block_size = udev->def_block_size;
	}
	dev->block_shift = -1; /* not used */

	TRACE_EXIT();
}

static int dev_user_disk_done(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_DEFAULT;

	TRACE_ENTRY();

	res = scst_block_generic_dev_done(cmd, dev_user_set_block_shift);

	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_tape_done(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_DEFAULT;

	TRACE_ENTRY();

	res = scst_tape_generic_dev_done(cmd, dev_user_set_block_size);

	TRACE_EXIT_RES(res);
	return res;
}

static inline bool dev_user_mgmt_ucmd(struct scst_user_cmd *ucmd)
{
	return (ucmd->state == UCMD_STATE_TM_RECEIVED_EXECING) ||
	       (ucmd->state == UCMD_STATE_TM_DONE_EXECING) ||
	       (ucmd->state == UCMD_STATE_ATTACH_SESS) ||
	       (ucmd->state == UCMD_STATE_DETACH_SESS);
}

/* Supposed to be called under cmd_list_lock */
static inline void dev_user_add_to_ready_head(struct scst_user_cmd *ucmd)
{
	struct scst_user_dev *dev = ucmd->dev;
	struct list_head *entry;

	TRACE_ENTRY();

	__list_for_each(entry, &dev->ready_cmd_list) {
		struct scst_user_cmd *u = list_entry(entry,
			struct scst_user_cmd, ready_cmd_list_entry);
		/*
		 * Skip other queued mgmt commands to not reverse order
		 * of them and prevent conditions, where DETACH_SESS or a SCSI
		 * command comes before ATTACH_SESS for the same session.
		 */
		if (unlikely(dev_user_mgmt_ucmd(u)))
			continue;
		TRACE_DBG("Adding ucmd %p (state %d) after mgmt ucmd %p (state %d)",
			  ucmd, ucmd->state, u, u->state);
		list_add_tail(&ucmd->ready_cmd_list_entry, &u->ready_cmd_list_entry);
		goto out;
	}

	TRACE_DBG("Adding ucmd %p (state %d) to tail of mgmt ready cmd list",
		  ucmd, ucmd->state);
	list_add_tail(&ucmd->ready_cmd_list_entry, &dev->ready_cmd_list);

out:
	TRACE_EXIT();
}

static void dev_user_add_to_ready(struct scst_user_cmd *ucmd)
{
	struct scst_user_dev *dev = ucmd->dev;
	unsigned long flags;
	/*
	 * Note, a separate softIRQ check is required for real-time kernels
	 * (CONFIG_PREEMPT_RT_FULL=y) since on such kernels softIRQ's are
	 * served in thread context. See also http://lwn.net/Articles/302043/.
	 */
	int do_wake = in_interrupt() || in_serving_softirq();

	TRACE_ENTRY();

	if (ucmd->cmd)
		do_wake |= ucmd->cmd->preprocessing_only;

	spin_lock_irqsave(&dev->udev_cmd_threads.cmd_list_lock, flags);

	ucmd->this_state_unjammed = 0;

	if (ucmd->state == UCMD_STATE_PARSING || ucmd->state == UCMD_STATE_BUF_ALLOCING) {
		/*
		 * If we don't put such commands in the queue head, then under
		 * high load we might delay threads, waiting for memory
		 * allocations, for too long and start losing NOPs, which
		 * would lead to consider us by remote initiators as
		 * unresponsive and stuck => broken connections, etc. If none
		 * of our commands completed in NOP timeout to allow the head
		 * commands to go, then we are really overloaded and/or stuck.
		 */
		dev_user_add_to_ready_head(ucmd);
	} else if (unlikely(dev_user_mgmt_ucmd(ucmd))) {
		dev_user_add_to_ready_head(ucmd);
		do_wake = 1;
	} else {
		if (ucmd->cmd &&
		    unlikely(ucmd->cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE)) {
			TRACE_DBG("Adding HQ ucmd %p to head of ready cmd list",
				  ucmd);
			dev_user_add_to_ready_head(ucmd);
		} else {
			TRACE_DBG("Adding ucmd %p to ready cmd list", ucmd);
			list_add_tail(&ucmd->ready_cmd_list_entry,
				      &dev->ready_cmd_list);
		}
		do_wake |= ((ucmd->state == UCMD_STATE_ON_CACHE_FREEING) ||
			    (ucmd->state == UCMD_STATE_ON_FREEING) ||
			    (ucmd->state == UCMD_STATE_EXT_COPY_REMAPPING));
	}

	if (do_wake) {
		TRACE_DBG("Waking up dev %p", dev);
		wake_up(&dev->udev_cmd_threads.cmd_list_waitQ);
	}

	spin_unlock_irqrestore(&dev->udev_cmd_threads.cmd_list_lock, flags);

	TRACE_EXIT();
}

static int dev_user_map_buf(struct scst_user_cmd *ucmd, unsigned long ubuff, int num_pg)
{
	int res = 0, rc;
	int i;
	struct task_struct *tsk = current;

	TRACE_ENTRY();

	if (unlikely(ubuff == 0))
		goto out_nomem;

	sBUG_ON(ucmd->data_pages);

	ucmd->num_data_pages = num_pg;

	ucmd->data_pages = kmalloc_array(ucmd->num_data_pages,
					 sizeof(*ucmd->data_pages),
					 GFP_KERNEL);
	if (!ucmd->data_pages) {
		TRACE(TRACE_OUT_OF_MEM, "Unable to allocate data_pages array (num_data_pages=%d)",
		      ucmd->num_data_pages);
		res = -ENOMEM;
		goto out_nomem;
	}

	TRACE_MEM("Mapping buffer (ucmd %p, ubuff %lx, ucmd->num_data_pages %d, first_page_offset %d, len %d)",
		  ucmd, ubuff, ucmd->num_data_pages, (int)(ubuff & ~PAGE_MASK),
		  ucmd->cmd ? ucmd->cmd->bufflen : -1);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
	down_read(&tsk->mm->mmap_sem);
	rc = get_user_pages(ubuff, ucmd->num_data_pages, FOLL_WRITE,
			    ucmd->data_pages);
	up_read(&tsk->mm->mmap_sem);
#else
	mmap_read_lock(tsk->mm);
	rc = get_user_pages(ubuff, ucmd->num_data_pages, FOLL_WRITE,
			    ucmd->data_pages);
	mmap_read_unlock(tsk->mm);
#endif

	/* get_user_pages() flushes dcache */

	if (rc < ucmd->num_data_pages)
		goto out_unmap;

	ucmd->ubuff = ubuff;
	ucmd->first_page_offset = (ubuff & ~PAGE_MASK);

out:
	TRACE_EXIT_RES(res);
	return res;

out_nomem:
	if (ucmd->cmd)
		scst_set_busy(ucmd->cmd);
	/* fall through */

out_err:
	if (ucmd->cmd)
		scst_set_cmd_abnormal_done_state(ucmd->cmd);
	goto out;

out_unmap:
	PRINT_ERROR("Failed to get %d user pages (rc %d)",
		    ucmd->num_data_pages, rc);
	if (rc > 0) {
		for (i = 0; i < rc; i++)
			put_page(ucmd->data_pages[i]);
	}
	kfree(ucmd->data_pages);
	ucmd->data_pages = NULL;
	res = -EFAULT;
	if (ucmd->cmd)
		scst_set_cmd_error(ucmd->cmd, SCST_LOAD_SENSE(scst_sense_internal_failure));
	goto out_err;
}

static int dev_user_process_reply_alloc(struct scst_user_cmd *ucmd,
					struct scst_user_reply_cmd *reply)
{
	int res = 0;
	struct scst_cmd *cmd = ucmd->cmd;

	TRACE_ENTRY();

	TRACE_DBG("ucmd %p, pbuf %llx", ucmd, reply->alloc_reply.pbuf);

	if (likely(reply->alloc_reply.pbuf != 0)) {
		int pages;

		if (ucmd->buff_cached) {
			if (unlikely((reply->alloc_reply.pbuf & ~PAGE_MASK) != 0)) {
				PRINT_ERROR("Supplied pbuf %llx isn't page aligned",
					    reply->alloc_reply.pbuf);
				goto out_hwerr;
			}
			pages = cmd->sg_cnt;
		} else {
			pages = calc_num_pg(reply->alloc_reply.pbuf, cmd->bufflen);
		}
		res = dev_user_map_buf(ucmd, reply->alloc_reply.pbuf, pages);
	} else {
		scst_set_busy(ucmd->cmd);
		scst_set_cmd_abnormal_done_state(ucmd->cmd);
	}

out_process:
	scst_process_active_cmd(cmd, false);

	TRACE_DBG("ALLOC_MEM finished");
	TRACE_EXIT_RES(res);
	return res;

out_hwerr:
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	scst_set_cmd_abnormal_done_state(ucmd->cmd);
	res = -EINVAL;
	goto out_process;
}

static int dev_user_process_reply_parse(struct scst_user_cmd *ucmd,
					struct scst_user_reply_cmd *reply)
{
	int res = 0, rc;
	struct scst_user_scsi_cmd_reply_parse *preply = &reply->parse_reply;
	struct scst_cmd *cmd = ucmd->cmd;

	TRACE_ENTRY();

	if (preply->status != 0)
		goto out_status;

	if (unlikely(preply->queue_type > SCST_CMD_QUEUE_ACA))
		goto out_inval;

	if (unlikely(preply->data_direction != SCST_DATA_WRITE &&
		     preply->data_direction != SCST_DATA_READ &&
		     preply->data_direction != SCST_DATA_BIDI &&
		     preply->data_direction != SCST_DATA_NONE))
		goto out_inval;

	if (unlikely(preply->data_direction != SCST_DATA_NONE &&
		     preply->bufflen == 0))
		goto out_inval;

	if (unlikely(preply->bufflen < 0 || preply->out_bufflen < 0 ||
		     preply->data_len < 0 || preply->lba < 0))
		goto out_inval;

	if (unlikely(preply->cdb_len > cmd->cdb_len))
		goto out_inval;

	if (!(preply->op_flags & SCST_INFO_VALID))
		goto out_inval;

	TRACE_DBG("ucmd %p, queue_type %x, data_direction, %x, lba %lld, bufflen %d, data_len %lld, pbuf %llx, cdb_len %d, op_flags %x",
		  ucmd, preply->queue_type, preply->data_direction,
		  (long long)preply->lba, preply->bufflen, (long long)preply->data_len,
		  reply->alloc_reply.pbuf, preply->cdb_len, preply->op_flags);

	cmd->queue_type = preply->queue_type;
	cmd->data_direction = preply->data_direction;
	cmd->lba = preply->lba;
	cmd->bufflen = preply->bufflen;
	cmd->out_bufflen = preply->out_bufflen;
	cmd->data_len = preply->data_len;
	if (preply->cdb_len > 0)
		cmd->cdb_len = preply->cdb_len;
	cmd->op_flags = preply->op_flags;

out_process:
	TRACE_DBG("PARSE finished");

	scst_process_active_cmd(cmd, false);

	TRACE_EXIT_RES(res);
	return res;

out_inval:
	PRINT_ERROR("Invalid parse_reply parameters (LUN %lld, op %s, cmd %p)",
		    (unsigned long long)cmd->lun, scst_get_opcode_name(cmd), cmd);
	PRINT_BUFFER("Invalid parse_reply", reply, sizeof(*reply));
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	res = -EINVAL;
	goto out_abnormal;

out_intern_fail_res_set:
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_internal_failure));

out_abnormal:
	scst_set_cmd_abnormal_done_state(cmd);
	goto out_process;

out_status:
	TRACE_DBG("ucmd %p returned with error from user status %x",
		  ucmd, preply->status);

	if (preply->sense_len != 0) {
		int sense_len;

		res = scst_alloc_sense(cmd, 0);
		if (res != 0)
			goto out_intern_fail_res_set;

		sense_len = min_t(int, cmd->sense_buflen, preply->sense_len);

		rc = copy_from_user(cmd->sense,
				    (void __user *)(unsigned long)preply->psense_buffer,
				    sense_len);
		if (rc != 0) {
			PRINT_ERROR("Failed to copy %d sense's bytes", rc);
			res = -EFAULT;
			goto out_intern_fail_res_set;
		}
		cmd->sense_valid_len = sense_len;
	}
	scst_set_cmd_error_status(cmd, preply->status);
	goto out_abnormal;
}

static int dev_user_process_reply_on_free(struct scst_user_cmd *ucmd)
{
	int res = 0;

	TRACE_ENTRY();

	TRACE_DBG("ON FREE ucmd %p", ucmd);

	dev_user_free_sgv(ucmd);
	ucmd_put(ucmd);

	TRACE_DBG("ON_FREE_CMD finished");
	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_process_reply_on_cache_free(struct scst_user_cmd *ucmd)
{
	int res = 0;

	TRACE_ENTRY();

	TRACE_DBG("ON CACHE FREE ucmd %p", ucmd);

	ucmd_put(ucmd);

	TRACE_MEM("ON_CACHED_MEM_FREE finished");
	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_process_reply_ext_copy_remap(struct scst_user_cmd *ucmd,
						 struct scst_user_reply_cmd *reply)
{
	int res = 0, rc, count = 0, i, len;
	struct scst_user_ext_copy_reply_remap *rreply = &reply->remap_reply;
	struct scst_cmd *cmd = ucmd->cmd;
	uint8_t *buf;
	struct scst_user_ext_copy_data_descr *uleft;
	struct scst_ext_copy_data_descr *left = NULL;

	TRACE_ENTRY();

	if (unlikely(rreply->status != 0 || rreply->sense_len != 0))
		goto out_status;

	if (rreply->remap_descriptors_len == 0) {
		TRACE_DBG("No remap leftovers (ucmd %p, cmd %p)", ucmd, cmd);
		goto out_done;
	}

	if (unlikely(rreply->remap_descriptors_len > PAGE_SIZE)) {
		PRINT_ERROR("Too many leftover REMAP descriptors (len %d, ucmd %p, cmd %p)",
			    rreply->remap_descriptors_len, ucmd, cmd);
		res = -EOVERFLOW;
		goto out_hw_err;
	}

	buf = kzalloc(rreply->remap_descriptors_len, GFP_KERNEL);
	if (unlikely(!buf)) {
		PRINT_ERROR("Unable to alloc leftover remap descriptors buf (size %d)",
			    rreply->remap_descriptors_len);
		goto out_busy;
	}

	rc = copy_from_user(buf, (void __user *)(unsigned long)rreply->remap_descriptors,
			    rreply->remap_descriptors_len);
	if (unlikely(rc != 0)) {
		PRINT_ERROR("Failed to copy %d leftover remap descriptors bytes", rc);
		res = -EFAULT;
		goto out_free_buf;
	}

	uleft = (struct scst_user_ext_copy_data_descr *)buf;
	count = rreply->remap_descriptors_len / sizeof(*uleft);
	if (unlikely((rreply->remap_descriptors_len % sizeof(*uleft)) != 0)) {
		PRINT_ERROR("Invalid leftover remap descriptors (ucmd %p, cmd %p, count %d)",
			    ucmd, cmd, count);
		res = -EINVAL;
		goto out_hw_err_free_buf;
	}

	left = kmalloc_array(count, sizeof(*left), GFP_KERNEL);
	if (unlikely(!left)) {
		PRINT_ERROR("Unable to alloc leftover remap descriptors (size %zd, count %d)",
			    sizeof(*left) * count, count);
		goto out_busy_free_buf;
	}

	TRACE_DBG("count %d", count);

	len = 0;
	for (i = 0; i < count; i++) {
		TRACE_DBG("src_lba %lld, dst_lba %lld, data_len %d (len %d)",
			  (long long)uleft[i].src_lba, (long long)uleft[i].dst_lba,
			  uleft[i].data_len, len);
		if (unlikely(uleft[i].data_len == 0)) {
			PRINT_ERROR("Invalid data descr %d len %d (cmd %p)",
				    i, uleft[i].data_len, cmd);
			res = -EINVAL;
			goto out_hw_err_free_buf;
		}
		left[i].src_lba = uleft[i].src_lba;
		left[i].dst_lba = uleft[i].dst_lba;
		left[i].data_len = uleft[i].data_len;
		len += uleft[i].data_len;
	}

	if (unlikely(len > scst_ext_copy_get_cur_seg_data_len(cmd))) {
		PRINT_ERROR("Invalid data descr len %d (cmd %p, seg descr len %d)",
			    len, cmd, scst_ext_copy_get_cur_seg_data_len(cmd));
		res = -EINVAL;
		goto out_hw_err_free_buf;
	}

out_free_buf:
	kfree(buf);

out_done:
	if (unlikely(res != 0)) {
		kfree(left);
		left = NULL;
		count = 0;
	}

	scst_ext_copy_remap_done(cmd, left, count);

	TRACE_EXIT_RES(res);
	return res;

out_hw_err:
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	goto out_done;

out_hw_err_free_buf:
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	goto out_free_buf;

out_busy_free_buf:
	scst_set_busy(cmd);
	goto out_free_buf;

out_busy:
	scst_set_busy(cmd);
	goto out_done;

out_status:
	TRACE_DBG("Remap finished with status %d (ucmd %p, cmd %p)",
		  rreply->status, ucmd, cmd);

	if (rreply->sense_len != 0) {
		int sense_len;

		res = scst_alloc_sense(cmd, 0);
		if (res != 0)
			goto out_hw_err;

		sense_len = min_t(int, cmd->sense_buflen, rreply->sense_len);

		rc = copy_from_user(cmd->sense,
				    (void __user *)(unsigned long)rreply->psense_buffer,
				    sense_len);
		if (rc != 0) {
			PRINT_ERROR("Failed to copy %d sense's bytes", rc);
			res = -EFAULT;
			goto out_hw_err;
		}
		cmd->sense_valid_len = sense_len;
	}
	scst_set_cmd_error_status(cmd, rreply->status);
	goto out_done;
}

static int dev_user_process_ws_reply(struct scst_user_cmd *ucmd,
				     struct scst_user_scsi_cmd_reply_exec *ereply)
{
	int res = 0, rc, count, i;
	struct scst_cmd *cmd = ucmd->cmd;
	uint8_t *buf;
	struct scst_user_data_descriptor *uwhere;
	struct scst_data_descriptor *where;

	TRACE_ENTRY();

	if (unlikely(cmd->cdb[0] != WRITE_SAME) &&
	    unlikely(cmd->cdb[0] != WRITE_SAME_16)) {
		PRINT_ERROR("Request to process WRITE SAME for not WRITE SAME CDB (ucmd %p, cmd %p, op %s)",
			    ucmd, cmd, scst_get_opcode_name(cmd));
		res = -EINVAL;
		goto out_hw_err;
	}

	if (unlikely(ereply->status != 0)) {
		PRINT_ERROR("Request to process WRITE SAME with not 0 status (ucmd %p, cmd %p, status %d)",
			    ucmd, cmd, ereply->status);
		res = -EINVAL;
		goto out_hw_err;
	}

	if (ereply->ws_descriptors_len == 0) {
		scst_write_same(cmd, NULL);
		goto out;
	}

	if (unlikely(ereply->ws_descriptors_len > PAGE_SIZE)) {
		PRINT_ERROR("Too many WRITE SAME descriptors (len %d, ucmd %p, cmd %p)",
			    ereply->ws_descriptors_len, ucmd, cmd);
		res = -EOVERFLOW;
		goto out_hw_err;
	}

	buf = kzalloc(ereply->ws_descriptors_len, GFP_KERNEL);
	if (unlikely(!buf)) {
		PRINT_ERROR("Unable to alloc WS descriptors buf (size %d)",
			    ereply->ws_descriptors_len);
		goto out_busy;
	}

	rc = copy_from_user(buf, (void __user *)(unsigned long)ereply->ws_descriptors,
			    ereply->ws_descriptors_len);
	if (unlikely(rc != 0)) {
		PRINT_ERROR("Failed to copy %d WS descriptors' bytes", rc);
		res = -EFAULT;
		goto out_free_buf;
	}

	uwhere = (struct scst_user_data_descriptor *)buf;
	count = ereply->ws_descriptors_len / sizeof(*uwhere);
	if (unlikely((ereply->ws_descriptors_len % sizeof(*uwhere)) != 0) ||
	    unlikely(uwhere[count - 1].usdd_blocks != 0)) {
		PRINT_ERROR("Invalid WS descriptors (ucmd %p, cmd %p)",
			    ucmd, cmd);
		res = -EINVAL;
		goto out_free_buf;
	}

	where = kmalloc_array(count, sizeof(*where), GFP_KERNEL);
	if (unlikely(!where)) {
		PRINT_ERROR("Unable to alloc WS descriptors where (size %zd)",
			    sizeof(*where) * count);
		goto out_busy_free_buf;
	}

	for (i = 0; i < count; i++) {
		where[i].sdd_lba = uwhere[i].usdd_lba;
		where[i].sdd_blocks = uwhere[i].usdd_blocks;
	}
	kfree(buf);

	scst_write_same(cmd, where);

out:
	TRACE_EXIT_RES(res);
	return res;

out_free_buf:
	kfree(buf);

out_hw_err:
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));

out_compl:
	cmd->completed = 1;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_DIRECT);
	/* !! At this point cmd can be already freed !! */
	goto out;

out_busy_free_buf:
	kfree(buf);

out_busy:
	scst_set_busy(cmd);
	goto out_compl;
}

static int dev_user_process_reply_exec(struct scst_user_cmd *ucmd,
				       struct scst_user_reply_cmd *reply)
{
	int res = 0;
	struct scst_user_scsi_cmd_reply_exec *ereply =
		&reply->exec_reply;
	struct scst_cmd *cmd = ucmd->cmd;

	TRACE_ENTRY();

	if (ereply->reply_type == SCST_EXEC_REPLY_COMPLETED) {
		if (ucmd->background_exec) {
			TRACE_DBG("Background ucmd %p finished", ucmd);
			ucmd_put(ucmd);
			goto out;
		}
		if (unlikely(ereply->resp_data_len > cmd->bufflen))
			goto out_inval;
		if (unlikely(cmd->data_direction != SCST_DATA_READ && ereply->resp_data_len != 0))
			goto out_inval;
	} else if (ereply->reply_type == SCST_EXEC_REPLY_BACKGROUND) {
		if (unlikely(ucmd->background_exec))
			goto out_inval;
		if (unlikely((cmd->data_direction & SCST_DATA_READ) || cmd->resp_data_len != 0))
			goto out_inval;
		/*
		 * background_exec assignment must be after ucmd get.
		 * Otherwise, due to reorder, in dev_user_process_reply()
		 * it is possible that ucmd is destroyed before it "got" here.
		 */
		ucmd_get(ucmd);
		ucmd->background_exec = 1;
		TRACE_DBG("Background ucmd %p", ucmd);
		goto out_compl;
	} else if (ereply->reply_type == SCST_EXEC_REPLY_DO_WRITE_SAME) {
		res = dev_user_process_ws_reply(ucmd, ereply);
		goto out;
	} else {
		goto out_inval;
	}

	TRACE_DBG("ucmd %p, status %d, resp_data_len %d",
		  ucmd, ereply->status, ereply->resp_data_len);

	cmd->atomic = 0;

	if (ereply->resp_data_len != 0) {
		if (ucmd->ubuff == 0) {
			int pages, rc;

			if (unlikely(ereply->pbuf == 0))
				goto out_busy;
			if (ucmd->buff_cached) {
				if (unlikely((ereply->pbuf & ~PAGE_MASK) != 0)) {
					PRINT_ERROR("Supplied pbuf %llx isn't page aligned",
						    ereply->pbuf);
					goto out_intern_fail;
				}
				pages = cmd->sg_cnt;
			} else {
				pages = calc_num_pg(ereply->pbuf, cmd->bufflen);
			}
			rc = dev_user_map_buf(ucmd, ereply->pbuf, pages);
			if (rc != 0 || ucmd->ubuff == 0)
				goto out_compl;

			rc = dev_user_alloc_sg(ucmd, ucmd->buff_cached);
			if (unlikely(rc != 0))
				goto out_busy;
		} else {
			dev_user_flush_dcache(ucmd);
		}
		cmd->may_need_dma_sync = 1;
		scst_set_resp_data_len(cmd, ereply->resp_data_len);
	} else if (cmd->resp_data_len != ereply->resp_data_len) {
		if (ucmd->ubuff == 0) {
			/*
			 * We have an empty SG, so can't call
			 * scst_set_resp_data_len()
			 */
			WARN_ON(ereply->resp_data_len != 0);
			cmd->resp_data_len = 0;
			cmd->resid_possible = 1;
		} else {
			scst_set_resp_data_len(cmd, ereply->resp_data_len);
		}
	}

#ifdef CONFIG_SCST_EXTRACHECKS
	if (unlikely(ereply->resp_data_len == 0 && ereply->pbuf != 0)) {
		PRINT_WARNING("Supplied pbuf 0x%llx ignored, because resp_data_len is 0. Memory leak? (op %s)",
			      (unsigned long long)ereply->pbuf, scst_get_opcode_name(cmd));
	}
#endif

	cmd->status = ereply->status;
	if (ereply->sense_len != 0) {
		int sense_len, rc;

		res = scst_alloc_sense(cmd, 0);
		if (res != 0)
			goto out_compl;

		sense_len = min_t(int, cmd->sense_buflen, ereply->sense_len);

		rc = copy_from_user(cmd->sense,
				    (void __user *)(unsigned long)ereply->psense_buffer,
				    sense_len);
		if (rc != 0) {
			PRINT_ERROR("Failed to copy %d sense's bytes", rc);
			res = -EFAULT;
			goto out_intern_fail_res_set;
		}
		cmd->sense_valid_len = sense_len;
	}

out_compl:
	cmd->completed = 1;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_DIRECT);
	/* !! At this point cmd can be already freed !! */

out:
	TRACE_DBG("EXEC finished");
	TRACE_EXIT_RES(res);
	return res;

out_inval:
	PRINT_ERROR("Invalid exec_reply parameters (LUN %lld, op %s, cmd %p)",
		    (unsigned long long)cmd->lun, scst_get_opcode_name(cmd), cmd);
	PRINT_BUFFER("Invalid exec_reply", reply, sizeof(*reply));

out_intern_fail:
	res = -EINVAL;

out_intern_fail_res_set:
	if (ucmd->background_exec) {
		ucmd_put(ucmd);
		goto out;
	} else {
		scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_internal_failure));
		goto out_compl;
	}

out_busy:
	scst_set_busy(cmd);
	goto out_compl;
}

static int dev_user_process_reply(struct scst_user_dev *dev, struct scst_user_reply_cmd *reply)
{
	int res = 0;
	struct scst_user_cmd *ucmd;
	int state;

	TRACE_ENTRY();

	spin_lock_irq(&dev->udev_cmd_threads.cmd_list_lock);

	ucmd = __ucmd_find_hash(dev, reply->cmd_h);
	if (unlikely(!ucmd)) {
		TRACE_MGMT_DBG("cmd_h %d not found", reply->cmd_h);
		res = -ESRCH;
		goto out_unlock;
	}

	if (unlikely(ucmd_get_check(ucmd))) {
		TRACE_MGMT_DBG("Found being destroyed cmd_h %d", reply->cmd_h);
		res = -ESRCH;
		goto out_unlock;
	}

	/* To sync. with dev_user_process_reply_exec(). See comment there. */
	smp_mb();
	if (ucmd->background_exec) {
		state = UCMD_STATE_EXECING;
		goto unlock_process;
	}

	if (unlikely(ucmd->this_state_unjammed)) {
		TRACE_MGMT_DBG("Reply on unjammed ucmd %p, ignoring",
			       ucmd);
		goto out_unlock_put;
	}

	if (unlikely(!ucmd->sent_to_user)) {
		TRACE_MGMT_DBG("Ucmd %p isn't in the sent to user state %x",
			       ucmd, ucmd->state);
		res = -EINVAL;
		goto out_unlock_put;
	}

	if (unlikely(reply->subcode != ucmd->user_cmd.subcode))
		goto out_wrong_state;

	if (unlikely(_IOC_NR(reply->subcode) != ucmd->state))
		goto out_wrong_state;

	state = ucmd->state;
	ucmd->sent_to_user = 0;

unlock_process:
	spin_unlock_irq(&dev->udev_cmd_threads.cmd_list_lock);

	switch (state) {
	case UCMD_STATE_PARSING:
		res = dev_user_process_reply_parse(ucmd, reply);
		break;

	case UCMD_STATE_BUF_ALLOCING:
		res = dev_user_process_reply_alloc(ucmd, reply);
		break;

	case UCMD_STATE_EXECING:
		res = dev_user_process_reply_exec(ucmd, reply);
		break;

	case UCMD_STATE_ON_FREEING:
		res = dev_user_process_reply_on_free(ucmd);
		break;

	case UCMD_STATE_ON_CACHE_FREEING:
		res = dev_user_process_reply_on_cache_free(ucmd);
		break;

	case UCMD_STATE_EXT_COPY_REMAPPING:
		res = dev_user_process_reply_ext_copy_remap(ucmd, reply);
		break;

	case UCMD_STATE_TM_RECEIVED_EXECING:
	case UCMD_STATE_TM_DONE_EXECING:
		res = dev_user_process_reply_tm_exec(ucmd,
						     state == UCMD_STATE_TM_RECEIVED_EXECING ?
						     SCST_MGMT_STATUS_RECEIVED_STAGE_COMPLETED :
						     reply->result);
		break;

	case UCMD_STATE_ATTACH_SESS:
	case UCMD_STATE_DETACH_SESS:
		res = dev_user_process_reply_sess(ucmd, reply->result);
		break;

	default:
		sBUG();
		break;
	}

out_put:
	ucmd_put(ucmd);

out:
	TRACE_EXIT_RES(res);
	return res;

out_wrong_state:
	PRINT_ERROR("Command's %p subcode %x doesn't match internal command's state %x or reply->subcode (%x) != ucmd->subcode (%x)",
		    ucmd, _IOC_NR(reply->subcode), ucmd->state,
		    reply->subcode, ucmd->user_cmd.subcode);
	res = -EINVAL;
	dev_user_unjam_cmd(ucmd, 0, NULL);

out_unlock_put:
	spin_unlock_irq(&dev->udev_cmd_threads.cmd_list_lock);
	goto out_put;

out_unlock:
	spin_unlock_irq(&dev->udev_cmd_threads.cmd_list_lock);
	goto out;
}

static int dev_user_reply_cmd(struct file *file, void __user *arg)
{
	int res = 0, rc;
	struct scst_user_dev *dev;
	struct scst_user_reply_cmd reply;

	TRACE_ENTRY();

	dev = file->private_data;
	res = dev_user_check_reg(dev);
	if (unlikely(res != 0))
		goto out;

	rc = copy_from_user(&reply, arg, sizeof(reply));
	if (unlikely(rc != 0)) {
		PRINT_ERROR("Failed to copy %d user's bytes", rc);
		res = -EFAULT;
		goto out;
	}

	TRACE_DBG("Reply for dev %s", dev->name);

	TRACE_BUFFER("Reply", &reply, sizeof(reply));

	res = dev_user_process_reply(dev, &reply);
	if (unlikely(res < 0))
		goto out;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_get_ext_cdb(struct file *file, void __user *arg)
{
	int res = 0, rc;
	struct scst_user_dev *dev;
	struct scst_user_cmd *ucmd;
	struct scst_cmd *cmd = NULL;
	struct scst_user_get_ext_cdb get;

	TRACE_ENTRY();

	dev = file->private_data;
	res = dev_user_check_reg(dev);
	if (unlikely(res != 0))
		goto out;

	rc = copy_from_user(&get, arg, sizeof(get));
	if (unlikely(rc != 0)) {
		PRINT_ERROR("Failed to copy %d user's bytes", rc);
		res = -EFAULT;
		goto out;
	}

	TRACE_MGMT_DBG("Get ext cdb for dev %s", dev->name);

	TRACE_BUFFER("Get ext cdb", &get, sizeof(get));

	spin_lock_irq(&dev->udev_cmd_threads.cmd_list_lock);

	ucmd = __ucmd_find_hash(dev, get.cmd_h);
	if (unlikely(!ucmd)) {
		TRACE_MGMT_DBG("cmd_h %d not found", get.cmd_h);
		res = -ESRCH;
		goto out_unlock;
	}

	if (unlikely(ucmd_get_check(ucmd))) {
		TRACE_MGMT_DBG("Found being destroyed cmd_h %d", get.cmd_h);
		res = -ESRCH;
		goto out_unlock;
	}

	if (ucmd->cmd && ucmd->state <= UCMD_STATE_EXECING &&
	    (ucmd->sent_to_user || ucmd->background_exec)) {
		cmd = ucmd->cmd;
		scst_cmd_get(cmd);
	} else {
		TRACE_MGMT_DBG("Invalid ucmd state %d for cmd_h %d",
			       ucmd->state, get.cmd_h);
		res = -EINVAL;
		goto out_unlock;
	}

	spin_unlock_irq(&dev->udev_cmd_threads.cmd_list_lock);

	if (!cmd)
		goto out_put;

	BUILD_BUG_ON(sizeof(cmd->cdb_buf) != SCST_MAX_CDB_SIZE);

	if (cmd->cdb_len <= SCST_MAX_CDB_SIZE)
		goto out_cmd_put;

	EXTRACHECKS_BUG_ON(cmd->cdb_buf == cmd->cdb_buf);

	TRACE_BUFFER("EXT CDB", &cmd->cdb[sizeof(cmd->cdb_buf)],
		     cmd->cdb_len - sizeof(cmd->cdb_buf));
	rc = copy_to_user((void __user *)(unsigned long)get.ext_cdb_buffer,
			  &cmd->cdb[sizeof(cmd->cdb_buf)],
			  cmd->cdb_len - sizeof(cmd->cdb_buf));
	if (unlikely(rc != 0)) {
		PRINT_ERROR("Failed to copy to user %d bytes", rc);
		res = -EFAULT;
		goto out_cmd_put;
	}

out_cmd_put:
	scst_cmd_put(cmd);

out_put:
	ucmd_put(ucmd);

out:
	TRACE_EXIT_RES(res);
	return res;

out_unlock:
	spin_unlock_irq(&dev->udev_cmd_threads.cmd_list_lock);
	goto out;
}

static int dev_user_process_scst_commands(struct scst_user_dev *dev)
	__releases(&dev->udev_cmd_threads.cmd_list_lock)
	__acquires(&dev->udev_cmd_threads.cmd_list_lock)
{
	int res = 0;

	TRACE_ENTRY();

	while (!list_empty(&dev->udev_cmd_threads.active_cmd_list)) {
		struct scst_cmd *cmd = list_entry(dev->udev_cmd_threads.active_cmd_list.next,
						  typeof(*cmd), cmd_list_entry);
		TRACE_DBG("Deleting cmd %p from active cmd list", cmd);
		list_del(&cmd->cmd_list_entry);
		spin_unlock_irq(&dev->udev_cmd_threads.cmd_list_lock);
		scst_process_active_cmd(cmd, false);
		spin_lock_irq(&dev->udev_cmd_threads.cmd_list_lock);
		res++;
	}

	TRACE_EXIT_RES(res);
	return res;
}

/* Called under udev_cmd_threads.cmd_list_lock and IRQ off */
static struct scst_user_cmd *__dev_user_get_next_cmd(struct list_head *cmd_list)
	__releases(&dev->udev_cmd_threads.cmd_list_lock)
	__acquires(&dev->udev_cmd_threads.cmd_list_lock)
{
	struct scst_user_cmd *u;

again:
	u = NULL;
	if (!list_empty(cmd_list)) {
		u = list_first_entry(cmd_list, typeof(*u), ready_cmd_list_entry);

		TRACE_DBG("Found ready ucmd %p", u);
		list_del(&u->ready_cmd_list_entry);

		EXTRACHECKS_BUG_ON(u->this_state_unjammed);

		if (u->cmd) {
			if (u->state == UCMD_STATE_EXECING) {
				struct scst_user_dev *dev = u->dev;
				int rc;

				EXTRACHECKS_BUG_ON(u->jammed);

				spin_unlock_irq(&dev->udev_cmd_threads.cmd_list_lock);

				rc = scst_check_local_events(u->cmd);
				if (unlikely(rc != 0)) {
					u->cmd->scst_cmd_done(u->cmd,
						SCST_CMD_STATE_DEFAULT,
						SCST_CONTEXT_DIRECT);
					/*
					 * !! At this point cmd & u can be !!
					 * !! already freed		   !!
					 */
					spin_lock_irq(&dev->udev_cmd_threads.cmd_list_lock);
					goto again;
				}

				spin_lock_irq(&dev->udev_cmd_threads.cmd_list_lock);
			} else if (unlikely(test_bit(SCST_CMD_ABORTED,
					&u->cmd->cmd_flags))) {
				switch (u->state) {
				case UCMD_STATE_PARSING:
				case UCMD_STATE_BUF_ALLOCING:
					TRACE_MGMT_DBG("Aborting ucmd %p", u);
					dev_user_unjam_cmd(u, 0, NULL);
					goto again;
				case UCMD_STATE_EXECING:
					EXTRACHECKS_BUG();
				}
			}
		}
		u->sent_to_user = 1;
		u->seen_by_user = 1;
	}
	return u;
}

static inline int test_cmd_threads(struct scst_user_dev *dev, bool can_block)
{
	int res = !list_empty(&dev->udev_cmd_threads.active_cmd_list) ||
		  !list_empty(&dev->ready_cmd_list) ||
		  !can_block || !dev->blocking || dev->cleanup_done;
	return res;
}

/* Called under udev_cmd_threads.cmd_list_lock and IRQ off */
static int dev_user_get_next_cmd(struct scst_user_dev *dev, struct scst_user_cmd **ucmd,
				 bool can_block)
{
	int res = 0;

	TRACE_ENTRY();

	while (1) {
		res = scst_wait_event_interruptible_lock_irq(dev->udev_cmd_threads.cmd_list_waitQ,
							     test_cmd_threads(dev, can_block),
							     dev->udev_cmd_threads.cmd_list_lock);
		if (res)
			break;

		dev_user_process_scst_commands(dev);

		*ucmd = __dev_user_get_next_cmd(&dev->ready_cmd_list);
		if (*ucmd)
			break;

		if (!can_block || !dev->blocking || dev->cleanup_done) {
			res = -EAGAIN;
			TRACE_DBG("No ready commands, returning %d", res);
			break;
		}
	}

	TRACE_EXIT_RES(res);
	return res;
}

/* No locks */
static int dev_user_get_cmd_to_user(struct scst_user_dev *dev, void __user *where, bool can_block)
{
	int res;
	struct scst_user_cmd *ucmd;

	TRACE_ENTRY();

	spin_lock_irq(&dev->udev_cmd_threads.cmd_list_lock);
again:
	res = dev_user_get_next_cmd(dev, &ucmd, can_block);
	if (res == 0) {
		int len, rc;
		/*
		 * A misbehaving user space handler can make ucmd to get dead
		 * immediately after we released the lock, which can lead to
		 * copy of dead data to the user space, which can lead to a
		 * leak of sensitive information.
		 */
		if (unlikely(ucmd_get_check(ucmd))) {
			/* Oops, this ucmd is already being destroyed. Retry. */
			goto again;
		}
		spin_unlock_irq(&dev->udev_cmd_threads.cmd_list_lock);

		EXTRACHECKS_BUG_ON(ucmd->user_cmd_payload_len == 0);

		len = ucmd->user_cmd_payload_len;
		TRACE_DBG("ucmd %p (user_cmd %p), payload_len %d (len %d)",
			  ucmd, &ucmd->user_cmd, ucmd->user_cmd_payload_len, len);
		TRACE_BUFFER("UCMD", &ucmd->user_cmd, len);
		rc = copy_to_user(where, &ucmd->user_cmd, len);
		if (unlikely(rc != 0)) {
			PRINT_ERROR("Copy to user failed (%d), requeuing ucmd %p back to head of ready cmd list",
				    res, ucmd);
			res = -EFAULT;
			/* Requeue ucmd back */
			spin_lock_irq(&dev->udev_cmd_threads.cmd_list_lock);
			list_add(&ucmd->ready_cmd_list_entry, &dev->ready_cmd_list);
			spin_unlock_irq(&dev->udev_cmd_threads.cmd_list_lock);
		}
#ifdef CONFIG_SCST_EXTRACHECKS
		else
			ucmd->user_cmd_payload_len = 0;
#endif
		ucmd_put(ucmd);
	} else {
		spin_unlock_irq(&dev->udev_cmd_threads.cmd_list_lock);
	}

	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_reply_get_cmd(struct file *file,
				  struct scst_user_get_cmd __user *get_cmd)
{
	int res = 0, rc;
	struct scst_user_dev *dev;
	struct scst_user_reply_cmd reply;
	uintptr_t ureply;

	TRACE_ENTRY();

	dev = file->private_data;
	res = dev_user_check_reg(dev);
	if (unlikely(res != 0))
		goto out;

	/* get_user() can't be used with 64-bit values on x86_32 */
	rc = copy_from_user(&ureply, &get_cmd->preply, sizeof(ureply));
	if (unlikely(rc != 0)) {
		PRINT_ERROR("Failed to copy %d user's bytes", rc);
		res = -EFAULT;
		goto out;
	}

	TRACE_DBG("ureply %lld (dev %s)", (unsigned long long)ureply,
		  dev->name);

	if (ureply != 0) {
		void __user *u = (void __user *)ureply;

		rc = copy_from_user(&reply, u, sizeof(reply));
		if (unlikely(rc != 0)) {
			PRINT_ERROR("Failed to copy %d user's bytes", rc);
			res = -EFAULT;
			goto out;
		}

		TRACE_BUFFER("Reply", &reply, sizeof(reply));

		res = dev_user_process_reply(dev, &reply);
		if (unlikely(res < 0))
			goto out;
	}

	res = dev_user_get_cmd_to_user(dev, get_cmd, true);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_reply_get_multi(struct file *file,
				    struct scst_user_get_multi __user *gm)
{
	int res = 0, rc;
	struct scst_user_dev *dev = file->private_data;
	struct scst_user_reply_cmd __user *replies;
	int16_t i, replies_cnt, replies_done = 0, cmds_cnt = 0;

	TRACE_ENTRY();

	res = dev_user_check_reg(dev);
	if (unlikely(res != 0))
		goto out;

	res = get_user(replies_cnt, &gm->replies_cnt);
	if (unlikely(res < 0)) {
		PRINT_ERROR("Unable to get replies_cnt");
		goto out;
	}

	res = get_user(cmds_cnt, &gm->cmds_cnt);
	if (unlikely(res < 0)) {
		PRINT_ERROR("Unable to get cmds_cnt");
		goto out;
	}

	TRACE_DBG("replies %d, space %d (dev %s)",
		  replies_cnt, cmds_cnt, dev->name);

	if (replies_cnt == 0)
		goto get_cmds;

	/* get_user() can't be used with 64-bit values on x86_32 */
	rc = copy_from_user(&replies, &gm->preplies, sizeof(replies));
	if (unlikely(rc != 0)) {
		PRINT_ERROR("Unable to get preply");
		res = -EFAULT;
		goto out;
	}

	for (i = 0; i < replies_cnt; i++) {
		struct scst_user_reply_cmd reply;

		rc = copy_from_user(&reply, &replies[i], sizeof(reply));
		if (unlikely(rc != 0)) {
			PRINT_ERROR("Unable to get reply %d", i);
			res = -EFAULT;
			goto out_part_replies_done;
		}

		TRACE_BUFFER("Reply", &reply, sizeof(reply));

		res = dev_user_process_reply(dev, &reply);
		if (unlikely(res < 0))
			goto out_part_replies_done;

		replies_done++;
	}

get_cmds:
	TRACE_DBG("Returning %d replies_done", replies_done);
	res = put_user(replies_done, &gm->replies_done);
	if (unlikely(res < 0))
		goto out;

	for (i = 0; i < cmds_cnt; i++) {
		res = dev_user_get_cmd_to_user(dev, &gm->cmds[i], i == 0);
		if (res != 0) {
			if ((res == -EAGAIN) && i > 0)
				res = 0;
			break;
		}
	}

	TRACE_DBG("Returning %d cmds_ret", i);
	rc = put_user(i, &gm->cmds_cnt);
	if (unlikely(rc < 0)) {
		res = rc; /* this error is more important */
		goto out;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_part_replies_done:
	TRACE_DBG("Partial returning %d replies_done", replies_done);
	rc = put_user(replies_done, &gm->replies_done);
	if (unlikely(rc < 0))
		res = rc;
	rc = put_user(0, &gm->cmds_cnt);
	if (unlikely(rc < 0))
		res = rc;
	goto out;
}

static long dev_user_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long res, rc;

	TRACE_ENTRY();

	switch (cmd) {
	case SCST_USER_REPLY_AND_GET_CMD:
		TRACE_DBG("REPLY_AND_GET_CMD");
		res = dev_user_reply_get_cmd(file, (void __user *)arg);
		break;

	case SCST_USER_REPLY_CMD:
		TRACE_DBG("REPLY_CMD");
		res = dev_user_reply_cmd(file, (void __user *)arg);
		break;

	case SCST_USER_REPLY_AND_GET_MULTI:
		TRACE_DBG("REPLY_AND_GET_MULTI");
		res = dev_user_reply_get_multi(file, (void __user *)arg);
		break;

	case SCST_USER_GET_EXTENDED_CDB:
		TRACE_DBG("GET_EXTENDED_CDB");
		res = dev_user_get_ext_cdb(file, (void __user *)arg);
		break;

	case SCST_USER_REGISTER_DEVICE:
	{
		struct scst_user_dev_desc *dev_desc;

		TRACE_DBG("REGISTER_DEVICE");
		dev_desc = kmalloc(sizeof(*dev_desc), GFP_KERNEL);
		if (!dev_desc) {
			res = -ENOMEM;
			goto out;
		}
		rc = copy_from_user(dev_desc, (void __user *)arg, sizeof(*dev_desc));
		if (rc != 0) {
			PRINT_ERROR("Failed to copy %ld user's bytes", rc);
			res = -EFAULT;
			kfree(dev_desc);
			goto out;
		}
		TRACE_BUFFER("dev_desc", dev_desc, sizeof(*dev_desc));
		dev_desc->name[sizeof(dev_desc->name) - 1] = '\0';
		dev_desc->sgv_name[sizeof(dev_desc->sgv_name) - 1] = '\0';
		res = dev_user_register_dev(file, dev_desc);
		kfree(dev_desc);
		break;
	}

	case SCST_USER_UNREGISTER_DEVICE:
		TRACE_DBG("UNREGISTER_DEVICE");
		res = dev_user_unregister_dev(file);
		break;

	case SCST_USER_FLUSH_CACHE:
		TRACE_DBG("FLUSH_CACHE");
		res = dev_user_flush_cache(file);
		break;

	case SCST_USER_SET_OPTIONS:
	{
		struct scst_user_opt opt;

		TRACE_DBG("SET_OPTIONS");
		rc = copy_from_user(&opt, (void __user *)arg, sizeof(opt));
		if (rc != 0) {
			PRINT_ERROR("Failed to copy %ld user's bytes", rc);
			res = -EFAULT;
			goto out;
		}
		TRACE_BUFFER("opt", &opt, sizeof(opt));
		res = dev_user_set_opt(file, &opt);
		break;
	}

	case SCST_USER_GET_OPTIONS:
		TRACE_DBG("GET_OPTIONS");
		res = dev_user_get_opt(file, (void __user *)arg);
		break;

	case SCST_USER_DEVICE_CAPACITY_CHANGED:
		TRACE_DBG("CAPACITY_CHANGED");
		res = dev_user_capacity_changed(file);
		break;

	case SCST_USER_PREALLOC_BUFFER:
		TRACE_DBG("PREALLOC_BUFFER");
		res = dev_user_prealloc_buffer(file, (void __user *)arg);
		break;

	default:
		PRINT_ERROR("Invalid ioctl cmd %x", cmd);
		res = -EINVAL;
		goto out;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static __poll_t dev_user_poll(struct file *file, poll_table *wait)
{
	__poll_t res;
	struct scst_user_dev *dev;

	TRACE_ENTRY();

	res = EPOLLNVAL;
	dev = file->private_data;
	if (unlikely(dev_user_check_reg(dev) != 0))
		goto out;

	spin_lock_irq(&dev->udev_cmd_threads.cmd_list_lock);

	if (!list_empty(&dev->ready_cmd_list) ||
	    !list_empty(&dev->udev_cmd_threads.active_cmd_list)) {
		res = EPOLLIN | EPOLLRDNORM;
		goto out_unlock;
	}

	spin_unlock_irq(&dev->udev_cmd_threads.cmd_list_lock);

	TRACE_DBG("Before poll_wait() (dev %s)", dev->name);
	poll_wait(file, &dev->udev_cmd_threads.cmd_list_waitQ, wait);
	TRACE_DBG("After poll_wait() (dev %s)", dev->name);

	spin_lock_irq(&dev->udev_cmd_threads.cmd_list_lock);

	if (!list_empty(&dev->ready_cmd_list) ||
	    !list_empty(&dev->udev_cmd_threads.active_cmd_list)) {
		res = EPOLLIN | EPOLLRDNORM;
		goto out_unlock;
	}

out_unlock:
	spin_unlock_irq(&dev->udev_cmd_threads.cmd_list_lock);

out:
	TRACE_EXIT_HRES(res);
	return res;
}

/*
 * Called under udev_cmd_threads.cmd_list_lock, but can drop it inside,
 * then reacquire.
 */
static void dev_user_unjam_cmd(struct scst_user_cmd *ucmd, int busy, unsigned long *flags)
	__releases(&dev->udev_cmd_threads.cmd_list_lock)
	__acquires(&dev->udev_cmd_threads.cmd_list_lock)
{
	int state = ucmd->state;
	struct scst_user_dev *dev = ucmd->dev;

	TRACE_ENTRY();

	if (ucmd->this_state_unjammed)
		goto out;

	TRACE_MGMT_DBG("Unjamming ucmd %p (busy %d, state %x)",
		       ucmd, busy, state);

	ucmd->jammed = 1;
	ucmd->this_state_unjammed = 1;
	ucmd->sent_to_user = 0;

	switch (state) {
	case UCMD_STATE_PARSING:
	case UCMD_STATE_BUF_ALLOCING:
		if (test_bit(SCST_CMD_ABORTED, &ucmd->cmd->cmd_flags)) {
			ucmd->aborted = 1;
		} else {
			if (busy)
				scst_set_busy(ucmd->cmd);
			else
				scst_set_cmd_error(ucmd->cmd,
						   SCST_LOAD_SENSE(scst_sense_lun_not_supported));
		}
		scst_set_cmd_abnormal_done_state(ucmd->cmd);

		TRACE_MGMT_DBG("Adding ucmd %p to active list", ucmd);
		list_add(&ucmd->cmd->cmd_list_entry, &ucmd->cmd->cmd_threads->active_cmd_list);
		wake_up(&ucmd->cmd->cmd_threads->cmd_list_waitQ);
		break;

	case UCMD_STATE_EXECING:
	case UCMD_STATE_EXT_COPY_REMAPPING:
		if (flags)
			spin_unlock_irqrestore(&dev->udev_cmd_threads.cmd_list_lock,
					       *flags);
		else
			spin_unlock_irq(&dev->udev_cmd_threads.cmd_list_lock);

		TRACE_MGMT_DBG("EXEC: unjamming ucmd %p", ucmd);

		if (test_bit(SCST_CMD_ABORTED, &ucmd->cmd->cmd_flags)) {
			ucmd->aborted = 1;
		} else {
			if (busy)
				scst_set_busy(ucmd->cmd);
			else
				scst_set_cmd_error(ucmd->cmd,
						   SCST_LOAD_SENSE(scst_sense_lun_not_supported));
		}

		if (state == UCMD_STATE_EXECING) {
			ucmd->cmd->scst_cmd_done(ucmd->cmd, SCST_CMD_STATE_DEFAULT,
						 SCST_CONTEXT_THREAD);
		} else {
			sBUG_ON(state != UCMD_STATE_EXT_COPY_REMAPPING);
			scst_ext_copy_remap_done(ucmd->cmd, NULL, 0);
		}
		/* !! At this point cmd and ucmd can be already freed !! */

		if (flags)
			spin_lock_irqsave(&dev->udev_cmd_threads.cmd_list_lock,
					  *flags);
		else
			spin_lock_irq(&dev->udev_cmd_threads.cmd_list_lock);
		break;

	case UCMD_STATE_ON_FREEING:
	case UCMD_STATE_ON_CACHE_FREEING:
	case UCMD_STATE_TM_RECEIVED_EXECING:
	case UCMD_STATE_TM_DONE_EXECING:
	case UCMD_STATE_ATTACH_SESS:
	case UCMD_STATE_DETACH_SESS:
		if (flags)
			spin_unlock_irqrestore(&dev->udev_cmd_threads.cmd_list_lock,
					       *flags);
		else
			spin_unlock_irq(&dev->udev_cmd_threads.cmd_list_lock);

		switch (state) {
		case UCMD_STATE_ON_FREEING:
			dev_user_process_reply_on_free(ucmd);
			break;

		case UCMD_STATE_ON_CACHE_FREEING:
			dev_user_process_reply_on_cache_free(ucmd);
			break;

		case UCMD_STATE_TM_RECEIVED_EXECING:
		case UCMD_STATE_TM_DONE_EXECING:
			dev_user_process_reply_tm_exec(ucmd,
						       state == UCMD_STATE_TM_RECEIVED_EXECING ?
						       SCST_MGMT_STATUS_RECEIVED_STAGE_COMPLETED :
						       SCST_MGMT_STATUS_FAILED);
			break;

		case UCMD_STATE_ATTACH_SESS:
		case UCMD_STATE_DETACH_SESS:
			dev_user_process_reply_sess(ucmd, -EFAULT);
			break;
		}

		if (flags)
			spin_lock_irqsave(&dev->udev_cmd_threads.cmd_list_lock, *flags);
		else
			spin_lock_irq(&dev->udev_cmd_threads.cmd_list_lock);
		break;

	default:
		PRINT_CRIT_ERROR("Wrong ucmd state %x", state);
		sBUG();
		break;
	}

out:
	TRACE_EXIT();
}

static int dev_user_unjam_dev(struct scst_user_dev *dev)
	__releases(&dev->udev_cmd_threads.cmd_list_lock)
	__acquires(&dev->udev_cmd_threads.cmd_list_lock)
{
	int i, res = 0;
	struct scst_user_cmd *ucmd;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Unjamming dev %p", dev);

	sgv_pool_flush(dev->pool);
	sgv_pool_flush(dev->pool_clust);

	spin_lock_irq(&dev->udev_cmd_threads.cmd_list_lock);

repeat:
	for (i = 0; i < ARRAY_SIZE(dev->ucmd_hash); i++) {
		struct list_head *head = &dev->ucmd_hash[i];

		list_for_each_entry(ucmd, head, hash_list_entry) {
			res++;

			if (!ucmd->sent_to_user)
				continue;

			if (ucmd_get_check(ucmd))
				continue;

			TRACE_MGMT_DBG("ucmd %p, state %x, scst_cmd %p",
				       ucmd, ucmd->state, ucmd->cmd);

			dev_user_unjam_cmd(ucmd, 0, NULL);

			spin_unlock_irq(&dev->udev_cmd_threads.cmd_list_lock);
			ucmd_put(ucmd);
			spin_lock_irq(&dev->udev_cmd_threads.cmd_list_lock);

			goto repeat;
		}
	}

	if (dev_user_process_scst_commands(dev) != 0)
		goto repeat;

	spin_unlock_irq(&dev->udev_cmd_threads.cmd_list_lock);

	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_process_reply_tm_exec(struct scst_user_cmd *ucmd, int status)
{
	int res = 0;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("TM reply (ucmd %p, fn %d, status %d)",
		       ucmd, ucmd->user_cmd.tm_cmd.fn, status);

	if (status == SCST_MGMT_STATUS_TASK_NOT_EXIST) {
		/*
		 * It is possible that user space seen TM cmd before cmd
		 * to abort or will never see it at all, because it was
		 * aborted on the way there. So, it is safe to return
		 * success instead, because, if there is the TM cmd at this
		 * point, then the cmd to abort apparrently does exist.
		 */
		status = SCST_MGMT_STATUS_SUCCESS;
	}

	scst_async_mcmd_completed(ucmd->mcmd, status);

	ucmd_put(ucmd);

	TRACE_EXIT_RES(res);
	return res;
}

static void dev_user_abort_ready_commands(struct scst_user_dev *dev)
{
	struct scst_user_cmd *ucmd;
	unsigned long flags;

	TRACE_ENTRY();

	spin_lock_irqsave(&dev->udev_cmd_threads.cmd_list_lock, flags);
again:
	list_for_each_entry(ucmd, &dev->ready_cmd_list, ready_cmd_list_entry) {
		if (ucmd->cmd && !ucmd->seen_by_user &&
		    test_bit(SCST_CMD_ABORTED, &ucmd->cmd->cmd_flags)) {
			switch (ucmd->state) {
			case UCMD_STATE_PARSING:
			case UCMD_STATE_BUF_ALLOCING:
			case UCMD_STATE_EXECING:
				TRACE_MGMT_DBG("Aborting ready ucmd %p", ucmd);
				list_del(&ucmd->ready_cmd_list_entry);
				dev_user_unjam_cmd(ucmd, 0, &flags);
				goto again;
			}
		}
	}

	spin_unlock_irqrestore(&dev->udev_cmd_threads.cmd_list_lock, flags);

	TRACE_EXIT();
}

/* Can be called under some spinlock and IRQs off */
static void __dev_user_task_mgmt_fn(struct scst_mgmt_cmd *mcmd, struct scst_tgt_dev *tgt_dev,
				    bool done)
{
	struct scst_user_cmd *ucmd;
	struct scst_user_dev *dev = tgt_dev->dev->dh_priv;
	struct scst_user_cmd *ucmd_to_abort = NULL;

	TRACE_ENTRY();

	/*
	 * In the used approach we don't do anything with hung devices, which
	 * stopped responding and/or have stuck commands. We forcedly abort such
	 * commands only if they not yet sent to the user space or if the device
	 * is getting unloaded, e.g. if its handler program gets killed. This is
	 * because it's pretty hard to distinguish between stuck and temporary
	 * overloaded states of the device. There are several reasons for that:
	 *
	 * 1. Some commands need a lot of time to complete (several hours),
	 *    so for an impatient user such command(s) will always look as
	 *    stuck.
	 *
	 * 2. If we forcedly abort, i.e. abort before it's actually completed
	 *    in the user space, just one command, we will have to put the whole
	 *    device offline until we are sure that no more previously aborted
	 *    commands will get executed. Otherwise, we might have a possibility
	 *    for data corruption, when aborted and reported as completed
	 *    command actually gets executed *after* new commands sent
	 *    after the force abort was done. Many journaling file systems and
	 *    databases use "provide required commands order via queue draining"
	 *    approach and not putting the whole device offline after the forced
	 *    abort will break it. This makes our decision, if a command stuck
	 *    or not, cost a lot.
	 *
	 * So, we leave policy definition if a device stuck or not to
	 * the user space and simply let all commands live until they are
	 * completed or their devices get closed/killed. This approach is very
	 * much OK, but can affect management commands, which need activity
	 * suspending via scst_suspend_activity() function such as devices or
	 * targets registration/removal. But during normal life such commands
	 * should be rare. Plus, when possible, scst_suspend_activity() will
	 * return after timeout EBUSY status to allow caller to not stuck
	 * forever as well.
	 *
	 * But, anyway, ToDo, we should reimplement that in the SCST core, so
	 * stuck commands would affect only related devices.
	 */

	if (!done)
		dev_user_abort_ready_commands(dev);

	/* We can't afford missing TM command due to memory shortage */
	ucmd = dev_user_alloc_ucmd(dev, GFP_ATOMIC | __GFP_NOFAIL);
	if (!ucmd) {
		PRINT_CRIT_ERROR("Unable to allocate TM %d message (dev %s)",
				 mcmd->fn, dev->name);
		goto out;
	}

	ucmd->user_cmd_payload_len =
		offsetof(struct scst_user_get_cmd, tm_cmd) +
		sizeof(ucmd->user_cmd.tm_cmd);
	ucmd->user_cmd.cmd_h = ucmd->h;
	if (done)
		ucmd->user_cmd.subcode = SCST_USER_TASK_MGMT_DONE;
	else
		ucmd->user_cmd.subcode = SCST_USER_TASK_MGMT_RECEIVED;
	ucmd->user_cmd.tm_cmd.sess_h = (unsigned long)tgt_dev;
	ucmd->user_cmd.tm_cmd.fn = mcmd->fn;
	ucmd->user_cmd.tm_cmd.cmd_sn = mcmd->cmd_sn;
	ucmd->user_cmd.tm_cmd.cmd_sn_set = mcmd->cmd_sn_set;

	if (mcmd->cmd_to_abort) {
		ucmd_to_abort = mcmd->cmd_to_abort->dh_priv;
		if (ucmd_to_abort)
			ucmd->user_cmd.tm_cmd.cmd_h_to_abort = ucmd_to_abort->h;
	}

	TRACE_MGMT_DBG("Preparing TM ucmd %p (h %d, fn %d, cmd_to_abort %p, ucmd_to_abort %p, cmd_h_to_abort %d, mcmd %p)",
		       ucmd, ucmd->h, mcmd->fn, mcmd->cmd_to_abort, ucmd_to_abort,
		       ucmd->user_cmd.tm_cmd.cmd_h_to_abort, mcmd);

	ucmd->mcmd = mcmd;
	if (done)
		ucmd->state = UCMD_STATE_TM_DONE_EXECING;
	else
		ucmd->state = UCMD_STATE_TM_RECEIVED_EXECING;

	scst_prepare_async_mcmd(mcmd);

	dev_user_add_to_ready(ucmd);

out:
	TRACE_EXIT();
}

static void dev_user_task_mgmt_fn_received(struct scst_mgmt_cmd *mcmd,
					   struct scst_tgt_dev *tgt_dev)
{
	TRACE_ENTRY();
	__dev_user_task_mgmt_fn(mcmd, tgt_dev, false);
	TRACE_EXIT();
}

static void dev_user_task_mgmt_fn_done(struct scst_mgmt_cmd *mcmd, struct scst_tgt_dev *tgt_dev)
{
	TRACE_ENTRY();
	__dev_user_task_mgmt_fn(mcmd, tgt_dev, true);
	TRACE_EXIT();
}

static int dev_user_attach(struct scst_device *sdev)
{
	int res = 0;
	struct scst_user_dev *dev = NULL, *d;

	TRACE_ENTRY();

	spin_lock(&dev_list_lock);
	list_for_each_entry(d, &dev_list, dev_list_entry) {
		if (strcmp(d->name, sdev->virt_name) == 0) {
			dev = d;
			break;
		}
	}
	spin_unlock(&dev_list_lock);
	if (!dev) {
		PRINT_ERROR("Device %s not found", sdev->virt_name);
		res = -EINVAL;
		goto out;
	}

	sdev->block_size = dev->def_block_size;
	switch (sdev->type) {
	case TYPE_DISK:
	case TYPE_ROM:
	case TYPE_MOD:
		sdev->block_shift = scst_calc_block_shift(sdev->block_size);
		if (sdev->block_shift < 9) {
			PRINT_ERROR("Invalid block size %d", sdev->block_size);
			res = -EINVAL;
			goto out;
		}
		break;
	default:
		sdev->block_shift = -1; /* not used */
		break;
	}

	sdev->dh_priv = dev;
	sdev->tst = dev->tst;
	sdev->tmf_only = dev->tmf_only;
	sdev->tmf_only_saved = dev->tmf_only;
	sdev->tmf_only_default = dev->tmf_only;
	sdev->queue_alg = dev->queue_alg;
	sdev->qerr = dev->qerr;
	sdev->qerr_saved = dev->qerr;
	sdev->qerr_default = dev->qerr;
	sdev->swp = dev->swp;
	sdev->swp_saved = dev->swp;
	sdev->swp_default = dev->swp;
	sdev->tas = dev->tas;
	sdev->tas_saved = dev->tas;
	sdev->tas_default = dev->tas;
	sdev->d_sense = dev->d_sense;
	sdev->d_sense_saved = dev->d_sense;
	sdev->d_sense_default = dev->d_sense;
	sdev->has_own_order_mgmt = dev->has_own_order_mgmt;

	dev->sdev = sdev;

	PRINT_INFO("Attached user space virtual device \"%s\"",
		   dev->name);

out:
	TRACE_EXIT();
	return res;
}

static void dev_user_detach(struct scst_device *sdev)
{
	struct scst_user_dev *dev = sdev->dh_priv;

	TRACE_ENTRY();

	TRACE_DBG("virt_id %d", sdev->virt_id);

	PRINT_INFO("Detached user space virtual device \"%s\"",
		   dev->name);

	/* dev will be freed by the caller */
	sdev->dh_priv = NULL;
	dev->sdev = NULL;

	TRACE_EXIT();
}

static int dev_user_process_reply_sess(struct scst_user_cmd *ucmd, int status)
{
	int res = 0;
	unsigned long flags;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("ucmd %p, cmpl %p, status %d", ucmd, ucmd->cmpl, status);

	spin_lock_irqsave(&ucmd->dev->udev_cmd_threads.cmd_list_lock, flags);

	if (ucmd->state == UCMD_STATE_ATTACH_SESS) {
		TRACE_MGMT_DBG("ATTACH_SESS finished");
		ucmd->result = status;
	} else if (ucmd->state == UCMD_STATE_DETACH_SESS) {
		TRACE_MGMT_DBG("DETACH_SESS finished");
	} else {
		sBUG();
	}

	if (ucmd->cmpl)
		complete_all(ucmd->cmpl);

	spin_unlock_irqrestore(&ucmd->dev->udev_cmd_threads.cmd_list_lock, flags);

	ucmd_put(ucmd);

	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_attach_tgt(struct scst_tgt_dev *tgt_dev)
{
	struct scst_user_dev *dev = tgt_dev->dev->dh_priv;
	int res = 0, rc;
	struct scst_user_cmd *ucmd;
	DECLARE_COMPLETION_ONSTACK(cmpl);
	struct scst_tgt_template *tgtt = tgt_dev->tgtt;
	struct scst_tgt *tgt = tgt_dev->sess->tgt;

	TRACE_ENTRY();

	tgt_dev->active_cmd_threads = &dev->udev_cmd_threads;

	/*
	 * We can't replace tgt_dev->pool, because it can be used to allocate
	 * memory for SCST local commands, like REPORT LUNS, where there is no
	 * corresponding ucmd. Otherwise we will crash in dev_user_alloc_sg().
	 */
	if (tgt_dev->tgt_dev_clust_pool)
		tgt_dev->dh_priv = dev->pool_clust;
	else
		tgt_dev->dh_priv = dev->pool;

	ucmd = dev_user_alloc_ucmd(dev, GFP_KERNEL);
	if (!ucmd)
		goto out_nomem;

	ucmd->cmpl = &cmpl;

	ucmd->user_cmd_payload_len = offsetof(struct scst_user_get_cmd, sess) +
		sizeof(ucmd->user_cmd.sess);
	ucmd->user_cmd.cmd_h = ucmd->h;
	ucmd->user_cmd.subcode = SCST_USER_ATTACH_SESS;
	ucmd->user_cmd.sess.sess_h = (unsigned long)tgt_dev;
	ucmd->user_cmd.sess.lun = (uint64_t)tgt_dev->lun;
	ucmd->user_cmd.sess.threads_num = tgt_dev->tgtt->threads_num;
	ucmd->user_cmd.sess.rd_only = tgt_dev->tgt_dev_rd_only;
	if (tgtt->get_phys_transport_version)
		ucmd->user_cmd.sess.phys_transport_version =
			tgtt->get_phys_transport_version(tgt);
	if (tgtt->get_scsi_transport_version)
		ucmd->user_cmd.sess.scsi_transport_version =
			tgtt->get_scsi_transport_version(tgt);
	strscpy(ucmd->user_cmd.sess.initiator_name,
		tgt_dev->sess->initiator_name,
		sizeof(ucmd->user_cmd.sess.initiator_name) - 1);
	strscpy(ucmd->user_cmd.sess.target_name,
		tgt_dev->sess->tgt->tgt_name,
		sizeof(ucmd->user_cmd.sess.target_name) - 1);

	TRACE_MGMT_DBG("Preparing ATTACH_SESS %p (h %d, sess_h %llx, LUN %llx, threads_num %d, rd_only %d, initiator %s, target %s)",
		       ucmd, ucmd->h, ucmd->user_cmd.sess.sess_h,
		       ucmd->user_cmd.sess.lun, ucmd->user_cmd.sess.threads_num,
		       ucmd->user_cmd.sess.rd_only, ucmd->user_cmd.sess.initiator_name,
		       ucmd->user_cmd.sess.target_name);

	ucmd->state = UCMD_STATE_ATTACH_SESS;

	ucmd_get(ucmd);

	dev_user_add_to_ready(ucmd);

	rc = wait_for_completion_timeout(ucmd->cmpl, DEV_USER_ATTACH_TIMEOUT);
	if (rc > 0) {
		res = ucmd->result;
	} else {
		PRINT_ERROR("ATTACH_SESS command timeout");
		res = -EFAULT;
	}

	sBUG_ON(irqs_disabled());

	spin_lock_irq(&dev->udev_cmd_threads.cmd_list_lock);
	ucmd->cmpl = NULL;
	spin_unlock_irq(&dev->udev_cmd_threads.cmd_list_lock);

	ucmd_put(ucmd);

out:
	TRACE_EXIT_RES(res);
	return res;

out_nomem:
	res = -ENOMEM;
	goto out;
}

static void dev_user_detach_tgt(struct scst_tgt_dev *tgt_dev)
{
	struct scst_user_dev *dev = tgt_dev->dev->dh_priv;
	struct scst_user_cmd *ucmd;

	TRACE_ENTRY();

	/*
	 * We can't miss detach command due to memory shortage, because it might
	 * lead to a memory leak in the user space handler.
	 */
	ucmd = dev_user_alloc_ucmd(dev, GFP_KERNEL | __GFP_NOFAIL);
	if (!ucmd) {
		PRINT_CRIT_ERROR("Unable to allocate DETACH_SESS message (dev %s)",
				 dev->name);
		goto out;
	}

	TRACE_MGMT_DBG("Preparing DETACH_SESS %p (h %d, sess_h %llx)",
		       ucmd, ucmd->h, ucmd->user_cmd.sess.sess_h);

	ucmd->user_cmd_payload_len = offsetof(struct scst_user_get_cmd, sess) +
		sizeof(ucmd->user_cmd.sess);
	ucmd->user_cmd.cmd_h = ucmd->h;
	ucmd->user_cmd.subcode = SCST_USER_DETACH_SESS;
	ucmd->user_cmd.sess.sess_h = (unsigned long)tgt_dev;

	ucmd->state = UCMD_STATE_DETACH_SESS;

	dev_user_add_to_ready(ucmd);

out:
	TRACE_EXIT();
}

/* No locks are needed, but the activity must be suspended */
static void dev_user_setup_functions(struct scst_user_dev *dev)
{
	TRACE_ENTRY();

	dev->devtype.parse = dev_user_parse;
	dev->devtype.dev_alloc_data_buf = dev_user_alloc_data_buf;
	dev->devtype.dev_done = NULL;

	dev->devtype.ext_copy_remap = NULL;
	if (dev->ext_copy_remap_supported)
		dev->devtype.ext_copy_remap = dev_user_ext_copy_remap;

	if (dev->parse_type != SCST_USER_PARSE_CALL) {
		switch (dev->devtype.type) {
		case TYPE_DISK:
			dev->generic_parse = scst_sbc_generic_parse;
			dev->devtype.dev_done = dev_user_disk_done;
			break;

		case TYPE_TAPE:
			dev->generic_parse = scst_tape_generic_parse;
			dev->devtype.dev_done = dev_user_tape_done;
			break;

		case TYPE_MOD:
			dev->generic_parse = scst_modisk_generic_parse;
			dev->devtype.dev_done = dev_user_disk_done;
			break;

		case TYPE_ROM:
			dev->generic_parse = scst_cdrom_generic_parse;
			dev->devtype.dev_done = dev_user_disk_done;
			break;

		case TYPE_MEDIUM_CHANGER:
			dev->generic_parse = scst_changer_generic_parse;
			break;

		case TYPE_PROCESSOR:
			dev->generic_parse = scst_processor_generic_parse;
			break;

		case TYPE_RAID:
			dev->generic_parse = scst_raid_generic_parse;
			break;

		default:
			PRINT_INFO("Unknown SCSI type %x, using PARSE_CALL for it",
				   dev->devtype.type);
			dev->parse_type = SCST_USER_PARSE_CALL;
			break;
		}
	} else {
		dev->generic_parse = NULL;
		dev->devtype.dev_done = NULL;
	}

	TRACE_EXIT();
}

static int dev_user_check_version(const struct scst_user_dev_desc *dev_desc)
{
	char str[sizeof(DEV_USER_VERSION) > 20 ? sizeof(DEV_USER_VERSION) : 20];
	int res = 0, rc;

	rc = copy_from_user(str, (void __user *)(unsigned long)dev_desc->license_str, sizeof(str));
	if (rc != 0) {
		PRINT_ERROR("Unable to get license string");
		res = -EFAULT;
		goto out;
	}
	str[sizeof(str) - 1] = '\0';

	if ((strcmp(str, "GPL") != 0) &&
	    (strcmp(str, "GPL v2") != 0) &&
	    (strcmp(str, "Dual BSD/GPL") != 0) &&
	    (strcmp(str, "Dual MIT/GPL") != 0) &&
	    (strcmp(str, "Dual MPL/GPL") != 0)) {
		/* ->name already 0-terminated in dev_user_ioctl() */
		PRINT_ERROR("Unsupported license of user device %s (%s). Ask license@scst-tgt.com for more info.",
			    dev_desc->name, str);
		res = -EPERM;
		goto out;
	}

	rc = copy_from_user(str, (void __user *)(unsigned long)dev_desc->version_str,
			    sizeof(str));
	if (rc != 0) {
		PRINT_ERROR("Unable to get version string");
		res = -EFAULT;
		goto out;
	}
	str[sizeof(str) - 1] = '\0';

	if (strcmp(str, DEV_USER_VERSION) != 0) {
		/* ->name already 0-terminated in dev_user_ioctl() */
		PRINT_ERROR("Incorrect version of user device %s (%s). Expected: %s",
			    dev_desc->name, str, DEV_USER_VERSION);
		res = -EINVAL;
		goto out;
	}

out:
	return res;
}

static int dev_user_register_dev(struct file *file, const struct scst_user_dev_desc *dev_desc)
{
	int res, i;
	struct scst_user_dev *dev, *d;
	int block_size;

	TRACE_ENTRY();

	res = dev_user_check_version(dev_desc);
	if (res != 0)
		goto out;

	switch (dev_desc->type) {
	case TYPE_DISK:
	case TYPE_ROM:
	case TYPE_MOD:
		if (dev_desc->block_size == 0) {
			PRINT_ERROR("Wrong block size %d", dev_desc->block_size);
			res = -EINVAL;
			goto out;
		}
		block_size = dev_desc->block_size;
		if (scst_calc_block_shift(block_size) == -1) {
			res = -EINVAL;
			goto out;
		}
		break;
	default:
		block_size = dev_desc->block_size;
		break;
	}

	if (!try_module_get(THIS_MODULE)) {
		PRINT_ERROR("Fail to get module");
		res = -ETXTBSY;
		goto out;
	}

	dev = kmem_cache_zalloc(user_dev_cachep, GFP_KERNEL);
	if (!dev) {
		res = -ENOMEM;
		goto out_put;
	}

	INIT_LIST_HEAD(&dev->ready_cmd_list);
	if (file->f_flags & O_NONBLOCK) {
		TRACE_DBG("Non-blocking operations");
		dev->blocking = 0;
	} else {
		dev->blocking = 1;
	}
	for (i = 0; i < ARRAY_SIZE(dev->ucmd_hash); i++)
		INIT_LIST_HEAD(&dev->ucmd_hash[i]);

	scst_init_threads(&dev->udev_cmd_threads);

	strscpy(dev->name, dev_desc->name, sizeof(dev->name) - 1);

	scst_init_mem_lim(&dev->udev_mem_lim);

	scnprintf(dev->devtype.name, sizeof(dev->devtype.name), "%s",
		  dev_desc->sgv_name[0] == '\0' ? dev->name : dev_desc->sgv_name);
	dev->pool = sgv_pool_create(dev->devtype.name, sgv_no_clustering,
				    dev_desc->sgv_single_alloc_pages,
				    dev_desc->sgv_shared,
				    dev_desc->sgv_purge_interval * HZ);
	if (!dev->pool) {
		res = -ENOMEM;
		goto out_deinit_threads;
	}
	sgv_pool_set_allocator(dev->pool, dev_user_alloc_pages, dev_user_free_sg_entries);

	if (!dev_desc->sgv_disable_clustered_pool) {
		scnprintf(dev->devtype.name, sizeof(dev->devtype.name),
			  "%s-clust",
			  dev_desc->sgv_name[0] == '\0' ? dev->name : dev_desc->sgv_name);
		dev->pool_clust = sgv_pool_create(dev->devtype.name,
						  sgv_tail_clustering,
						  dev_desc->sgv_single_alloc_pages,
						  dev_desc->sgv_shared,
						  dev_desc->sgv_purge_interval * HZ);
		if (!dev->pool_clust) {
			res = -ENOMEM;
			goto out_free0;
		}
		sgv_pool_set_allocator(dev->pool_clust, dev_user_alloc_pages,
				       dev_user_free_sg_entries);
	} else {
		dev->pool_clust = dev->pool;
		sgv_pool_get(dev->pool_clust);
	}

	scnprintf(dev->devtype.name, sizeof(dev->devtype.name), "%s", dev->name);
	dev->devtype.type = dev_desc->type;
	dev->devtype.threads_num = -1;
	dev->devtype.parse_atomic = 1;
	dev->devtype.dev_alloc_data_buf_atomic = 1;
	dev->devtype.dev_done_atomic = 1;
	dev->devtype.dev_attrs = dev_user_dev_attrs;
	dev->devtype.attach = dev_user_attach;
	dev->devtype.detach = dev_user_detach;
	dev->devtype.attach_tgt = dev_user_attach_tgt;
	dev->devtype.detach_tgt = dev_user_detach_tgt;
	dev->devtype.exec = dev_user_exec;
	dev->devtype.on_free_cmd = dev_user_on_free_cmd;
	dev->devtype.task_mgmt_fn_received = dev_user_task_mgmt_fn_received;
	dev->devtype.task_mgmt_fn_done = dev_user_task_mgmt_fn_done;
	if (dev_desc->enable_pr_cmds_notifications)
		dev->devtype.pr_cmds_notifications = 1;

	init_completion(&dev->cleanup_cmpl);
	dev->def_block_size = block_size;

	res = __dev_user_set_opt(dev, &dev_desc->opt);
	if (res != 0)
		goto out_free;

	TRACE_MEM("dev %p, name %s", dev, dev->name);

	spin_lock(&dev_list_lock);

	list_for_each_entry(d, &dev_list, dev_list_entry) {
		if (strcmp(d->name, dev->name) == 0) {
			PRINT_ERROR("Device %s already exist",
				    dev->name);
			res = -EEXIST;
			spin_unlock(&dev_list_lock);
			goto out_free;
		}
	}

	list_add_tail(&dev->dev_list_entry, &dev_list);

	spin_unlock(&dev_list_lock);

	res = scst_register_virtual_dev_driver(&dev->devtype);
	if (res < 0)
		goto out_del_free;

	dev->virt_id = scst_register_virtual_device(&dev->devtype, dev->name);
	if (dev->virt_id < 0) {
		res = dev->virt_id;
		goto out_unreg_handler;
	}

	spin_lock(&dev_list_lock);
	if (file->private_data) {
		spin_unlock(&dev_list_lock);
		PRINT_ERROR("Device already registered");
		res = -EINVAL;
		goto out_unreg_drv;
	}
	/*
	 * Assumption here is that the private_data reading is atomic,
	 * hence could be lockless and without READ_ONCE().
	 */
	file->private_data = dev;
	spin_unlock(&dev_list_lock);

out:
	TRACE_EXIT_RES(res);
	return res;

out_unreg_drv:
	scst_unregister_virtual_device(dev->virt_id, NULL, NULL);

out_unreg_handler:
	scst_unregister_virtual_dev_driver(&dev->devtype);

out_del_free:
	spin_lock(&dev_list_lock);
	list_del(&dev->dev_list_entry);
	spin_unlock(&dev_list_lock);

out_free:
	sgv_pool_del(dev->pool_clust);

out_free0:
	sgv_pool_del(dev->pool);

out_deinit_threads:
	scst_deinit_threads(&dev->udev_cmd_threads);

	kmem_cache_free(user_dev_cachep, dev);

out_put:
	module_put(THIS_MODULE);
	goto out;
}

static int dev_user_unregister_dev(struct file *file)
{
	struct scst_user_dev *dev;
	int res;

	dev = file->private_data;
	res = dev_user_check_reg(dev);
	if (unlikely(res != 0))
		goto out;

	PRINT_WARNING("SCST_USER_UNREGISTER_DEVICE is obsolete and NOOP. Closing fd should be used instead.");

	/* For backward compatibility unblock possibly blocked sync threads */
	dev->blocking = 0;
	wake_up_all(&dev->udev_cmd_threads.cmd_list_waitQ);

out:
	return res;
}

static int dev_user_flush_cache(struct file *file)
{
	int res;
	struct scst_user_dev *dev;

	TRACE_ENTRY();

	dev = file->private_data;
	res = dev_user_check_reg(dev);
	if (unlikely(res != 0))
		goto out;

	res = scst_suspend_activity(SCST_SUSPEND_TIMEOUT_USER);
	if (res != 0)
		goto out;

	sgv_pool_flush(dev->pool);
	sgv_pool_flush(dev->pool_clust);

	scst_resume_activity();

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_capacity_changed(struct file *file)
{
	int res;
	struct scst_user_dev *dev;

	TRACE_ENTRY();

	dev = file->private_data;
	res = dev_user_check_reg(dev);
	if (unlikely(res != 0))
		goto out;

	scst_capacity_data_changed(dev->sdev);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_prealloc_buffer(struct file *file, void __user *arg)
{
	int res = 0, rc;
	struct scst_user_dev *dev;
	union scst_user_prealloc_buffer pre;
	aligned_u64 pbuf;
	uint32_t bufflen;
	struct scst_user_cmd *ucmd;
	int pages, sg_cnt;
	struct sgv_pool *pool;
	struct scatterlist *sg;

	TRACE_ENTRY();

	dev = file->private_data;
	res = dev_user_check_reg(dev);
	if (unlikely(res != 0))
		goto out;

	rc = copy_from_user(&pre.in, arg, sizeof(pre.in));
	if (unlikely(rc != 0)) {
		PRINT_ERROR("Failed to copy %d user's bytes", rc);
		res = -EFAULT;
		goto out;
	}

	TRACE_MEM("Prealloc buffer with size %dKB for dev %s",
		  pre.in.bufflen / 1024, dev->name);
	TRACE_BUFFER("Input param", &pre.in, sizeof(pre.in));

	pbuf = pre.in.pbuf;
	bufflen = pre.in.bufflen;

	ucmd = dev_user_alloc_ucmd(dev, GFP_KERNEL);
	if (!ucmd) {
		res = -ENOMEM;
		goto out;
	}

	ucmd->buff_cached = 1;

	TRACE_MEM("ucmd %p, pbuf %llx", ucmd, pbuf);

	if (unlikely((pbuf & ~PAGE_MASK) != 0)) {
		PRINT_ERROR("Supplied pbuf %llx isn't page aligned", pbuf);
		res = -EINVAL;
		goto out_put;
	}

	pages = calc_num_pg(pbuf, bufflen);
	res = dev_user_map_buf(ucmd, pbuf, pages);
	if (res != 0)
		goto out_put;

	if (pre.in.for_clust_pool)
		pool = dev->pool_clust;
	else
		pool = dev->pool;

	sg = sgv_pool_alloc(pool, bufflen, GFP_KERNEL, SGV_POOL_ALLOC_GET_NEW,
			    &sg_cnt, &ucmd->sgv, &dev->udev_mem_lim, ucmd);
	if (sg) {
		struct scst_user_cmd *buf_ucmd = sgv_get_priv(ucmd->sgv);

		TRACE_MEM("Buf ucmd %p (sg_cnt %d, last seg len %d, bufflen %d)",
			  buf_ucmd, sg_cnt, sg[sg_cnt - 1].length, bufflen);

		EXTRACHECKS_BUG_ON(ucmd != buf_ucmd);

		ucmd->buf_ucmd = buf_ucmd;
	} else {
		res = -ENOMEM;
		goto out_put;
	}

	dev_user_free_sgv(ucmd);

	pre.out.cmd_h = ucmd->h;
	rc = copy_to_user(arg, &pre.out, sizeof(pre.out));
	if (unlikely(rc != 0)) {
		PRINT_ERROR("Failed to copy to user %d bytes", rc);
		res = -EFAULT;
		goto out_put;
	}

out_put:
	ucmd_put(ucmd);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int __dev_user_set_opt(struct scst_user_dev *dev, const struct scst_user_opt *opt)
{
	int res = 0;

	TRACE_ENTRY();

	TRACE_DBG("dev %s, parse_type %x, on_free_cmd_type %x, memory_reuse_type %x, partial_transfers_type %x, partial_len %d, opt->ext_copy_remap_supported %d",
		  dev->name, opt->parse_type, opt->on_free_cmd_type,
		  opt->memory_reuse_type, opt->partial_transfers_type,
		  opt->partial_len, opt->ext_copy_remap_supported);

	if (opt->parse_type > SCST_USER_MAX_PARSE_OPT ||
	    opt->on_free_cmd_type > SCST_USER_MAX_ON_FREE_CMD_OPT ||
	    opt->memory_reuse_type > SCST_USER_MAX_MEM_REUSE_OPT ||
	    opt->partial_transfers_type > SCST_USER_MAX_PARTIAL_TRANSFERS_OPT) {
		PRINT_ERROR("Invalid option");
		res = -EINVAL;
		goto out;
	}

	if ((opt->tst != SCST_TST_0_SINGLE_TASK_SET && opt->tst != SCST_TST_1_SEP_TASK_SETS) ||
	    opt->tmf_only > 1 ||
	    (opt->queue_alg != SCST_QUEUE_ALG_0_RESTRICTED_REORDER &&
	     opt->queue_alg != SCST_QUEUE_ALG_1_UNRESTRICTED_REORDER) ||
	    (opt->qerr == SCST_QERR_2_RESERVED || opt->qerr > SCST_QERR_3_ABORT_THIS_NEXUS_ONLY) ||
	    opt->swp > 1 || opt->tas > 1 || opt->has_own_order_mgmt > 1 || opt->d_sense > 1 ||
	    opt->ext_copy_remap_supported > 1) {
		PRINT_ERROR("Invalid SCSI option (tst %x, tmf_only %x, queue_alg %x, qerr %x, swp %x, tas %x, d_sense %d, has_own_order_mgmt %x, ext_copy_remap_supported %d)",
			    opt->tst, opt->tmf_only, opt->queue_alg, opt->qerr,
			    opt->swp, opt->tas, opt->d_sense, opt->has_own_order_mgmt,
			    opt->ext_copy_remap_supported);
		res = -EINVAL;
		goto out;
	}

#if 1
	if (dev->tst != opt->tst && dev->sdev && !list_empty(&dev->sdev->dev_tgt_dev_list)) {
		PRINT_ERROR("On the fly setting of TST not supported. See comment in struct scst_device.");
		res = -EINVAL;
		goto out;
	}
#endif

	dev->parse_type = opt->parse_type;
	dev->on_free_cmd_type = opt->on_free_cmd_type;
	dev->memory_reuse_type = opt->memory_reuse_type;
	dev->partial_transfers_type = opt->partial_transfers_type;
	dev->partial_len = opt->partial_len;

	dev->tst = opt->tst;
	dev->tmf_only = opt->tmf_only;
	dev->queue_alg = opt->queue_alg;
	dev->qerr = opt->qerr;
	dev->swp = opt->swp;
	dev->tas = opt->tas;
	dev->d_sense = opt->d_sense;
	dev->has_own_order_mgmt = opt->has_own_order_mgmt;
	dev->ext_copy_remap_supported = opt->ext_copy_remap_supported;

	if (dev->sdev) {
		dev->sdev->tst = opt->tst;
		dev->sdev->tmf_only = opt->tmf_only;
		dev->sdev->queue_alg = opt->queue_alg;
		dev->sdev->qerr = opt->qerr;
		dev->sdev->swp = opt->swp;
		dev->sdev->tas = opt->tas;
		dev->sdev->d_sense = opt->d_sense;
		dev->sdev->has_own_order_mgmt = opt->has_own_order_mgmt;
	}

	dev_user_setup_functions(dev);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_set_opt(struct file *file, const struct scst_user_opt *opt)
{
	int res;
	struct scst_user_dev *dev;

	TRACE_ENTRY();

	dev = file->private_data;
	res = dev_user_check_reg(dev);
	if (unlikely(res != 0))
		goto out;

	res = scst_suspend_activity(SCST_SUSPEND_TIMEOUT_USER);
	if (res != 0)
		goto out;

	res = __dev_user_set_opt(dev, opt);

	scst_resume_activity();

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_get_opt(struct file *file, void __user *arg)
{
	int res, rc;
	struct scst_user_dev *dev;
	struct scst_user_opt opt;

	TRACE_ENTRY();

	dev = file->private_data;
	res = dev_user_check_reg(dev);
	if (unlikely(res != 0))
		goto out;

	memset(&opt, 0, sizeof(opt));
	opt.parse_type = dev->parse_type;
	opt.on_free_cmd_type = dev->on_free_cmd_type;
	opt.memory_reuse_type = dev->memory_reuse_type;
	opt.partial_transfers_type = dev->partial_transfers_type;
	opt.partial_len = dev->partial_len;
	opt.tst = dev->tst;
	opt.tmf_only = dev->tmf_only;
	opt.queue_alg = dev->queue_alg;
	opt.qerr = dev->qerr;
	opt.tas = dev->tas;
	opt.swp = dev->swp;
	opt.d_sense = dev->d_sense;
	opt.has_own_order_mgmt = dev->has_own_order_mgmt;
	opt.ext_copy_remap_supported = dev->ext_copy_remap_supported;

	TRACE_DBG("dev %s, parse_type %x, on_free_cmd_type %x, memory_reuse_type %x, partial_transfers_type %x, partial_len %d, ext_copy_remap_supported %d",
		  dev->name, opt.parse_type, opt.on_free_cmd_type, opt.memory_reuse_type,
		  opt.partial_transfers_type, opt.partial_len,
		  opt.ext_copy_remap_supported);

	rc = copy_to_user(arg, &opt, sizeof(opt));
	if (unlikely(rc != 0)) {
		PRINT_ERROR("Failed to copy to user %d bytes", rc);
		res = -EFAULT;
		goto out;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int dev_usr_parse(struct scst_cmd *cmd)
{
	sBUG();
	return SCST_CMD_STATE_DEFAULT;
}

static int dev_user_exit_dev(struct scst_user_dev *dev)
{
	TRACE_ENTRY();

	TRACE(TRACE_MGMT, "Releasing dev %s", dev->name);

	spin_lock(&dev_list_lock);
	list_del(&dev->dev_list_entry);
	spin_unlock(&dev_list_lock);

	dev->blocking = 0;
	wake_up_all(&dev->udev_cmd_threads.cmd_list_waitQ);

	spin_lock(&cleanup_lock);
	list_add_tail(&dev->cleanup_list_entry, &cleanup_list);
	spin_unlock(&cleanup_lock);

	wake_up(&cleanup_list_waitQ);

	scst_unregister_virtual_device(dev->virt_id, NULL, NULL);
	scst_unregister_virtual_dev_driver(&dev->devtype);

	sgv_pool_flush(dev->pool_clust);
	sgv_pool_flush(dev->pool);

	TRACE_MGMT_DBG("Unregistering finished (dev %p)", dev);

	dev->cleanup_done = 1;

	wake_up(&cleanup_list_waitQ);
	wake_up(&dev->udev_cmd_threads.cmd_list_waitQ);

	wait_for_completion(&dev->cleanup_cmpl);

	sgv_pool_del(dev->pool_clust);
	sgv_pool_del(dev->pool);

	scst_deinit_threads(&dev->udev_cmd_threads);

	TRACE_MGMT_DBG("Releasing completed (dev %p)", dev);

	module_put(THIS_MODULE);

	TRACE_EXIT();
	return 0;
}

static int __dev_user_release(void *arg)
{
	struct scst_user_dev *dev = arg;

	dev_user_exit_dev(dev);
	kmem_cache_free(user_dev_cachep, dev);
	return 0;
}

static int dev_user_release(struct inode *inode, struct file *file)
{
	struct scst_user_dev *dev;
	struct task_struct *t;

	TRACE_ENTRY();

	dev = file->private_data;
	if (!dev)
		goto out;
	file->private_data = NULL;

	TRACE_MGMT_DBG("Going to release dev %s", dev->name);

	t = kthread_run(__dev_user_release, dev, "scst_usr_released");
	if (IS_ERR(t)) {
		PRINT_CRIT_ERROR("kthread_run() failed (%ld), releasing device %p directly. If you have several devices under load it might deadlock!",
				 PTR_ERR(t), dev);
		__dev_user_release(dev);
	}

out:
	TRACE_EXIT();
	return 0;
}

#ifdef CONFIG_SCST_EXTRACHECKS
static void dev_user_check_lost_ucmds(struct scst_user_dev *dev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dev->ucmd_hash); i++) {
		struct list_head *head = &dev->ucmd_hash[i];
		struct scst_user_cmd *ucmd2, *tmp;

		list_for_each_entry_safe(ucmd2, tmp, head, hash_list_entry) {
			PRINT_ERROR("Lost ucmd %p (state %x, ref %d)",
				    ucmd2, ucmd2->state, atomic_read(&ucmd2->ucmd_ref));
			ucmd_put(ucmd2);
		}
	}
}
#else
static void dev_user_check_lost_ucmds(struct scst_user_dev *dev)
{
}
#endif

static int dev_user_process_cleanup(struct scst_user_dev *dev)
{
	struct scst_user_cmd *ucmd;
	int rc = 0, res = 1;

	TRACE_ENTRY();

	sBUG_ON(dev->blocking);
	wake_up_all(&dev->udev_cmd_threads.cmd_list_waitQ); /* just in case */

	while (1) {
		int rc1;

		TRACE_DBG("Cleanuping dev %p", dev);

		rc1 = dev_user_unjam_dev(dev);
		if (rc1 == 0 && rc == -EAGAIN && dev->cleanup_done)
			break;

		spin_lock_irq(&dev->udev_cmd_threads.cmd_list_lock);

		rc = dev_user_get_next_cmd(dev, &ucmd, false);
		if (rc == 0)
			dev_user_unjam_cmd(ucmd, 1, NULL);

		spin_unlock_irq(&dev->udev_cmd_threads.cmd_list_lock);

		if (rc == -EAGAIN) {
			if (!dev->cleanup_done) {
				TRACE_DBG("No more commands (dev %p)", dev);
				goto out;
			}
		}
	}

	dev_user_check_lost_ucmds(dev);

	TRACE_DBG("Cleanuping done (dev %p)", dev);
	complete_all(&dev->cleanup_cmpl);
	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t dev_user_sysfs_commands_show(struct kobject *kobj, struct kobj_attribute *attr,
					    char *buf)
{
	struct scst_device *dev;
	struct scst_user_dev *udev;
	unsigned long flags;
	int i, ret = 0, pos;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	udev = dev->dh_priv;

	spin_lock_irqsave(&udev->udev_cmd_threads.cmd_list_lock, flags);
	for (i = 0; i < ARRAY_SIZE(udev->ucmd_hash); i++) {
		struct list_head *head = &udev->ucmd_hash[i];
		struct scst_user_cmd *ucmd;

		list_for_each_entry(ucmd, head, hash_list_entry) {
			pos = ret;
			ret += sysfs_emit_at(buf, ret,
					     "ucmd %p (state %x, ref %d), sent_to_user %d, seen_by_user %d, aborted %d, jammed %d, scst_cmd %p\n",
					     ucmd, ucmd->state,
					     atomic_read(&ucmd->ucmd_ref),
					     ucmd->sent_to_user, ucmd->seen_by_user,
					     ucmd->aborted, ucmd->jammed, ucmd->cmd);
			if (ret >= SCST_SYSFS_BLOCK_SIZE - 1) {
				pos += sysfs_emit_at(buf, pos, "...\n");
				ret = pos;
				break;
			}
		}
	}
	spin_unlock_irqrestore(&udev->udev_cmd_threads.cmd_list_lock, flags);

	TRACE_EXIT_RES(ret);
	return ret;
}

static inline int test_cleanup_list(void)
{
	int res = !list_empty(&cleanup_list) || unlikely(kthread_should_stop());
	return res;
}

static int dev_user_cleanup_thread(void *arg)
{
	TRACE_ENTRY();

	PRINT_INFO("Cleanup thread started");

	current->flags |= PF_NOFREEZE;

	spin_lock(&cleanup_lock);
	while (!kthread_should_stop()) {
		scst_wait_event_interruptible_lock(cleanup_list_waitQ, test_cleanup_list(),
						   cleanup_lock);

		/*
		 * We have to poll devices, because commands can go from SCST
		 * core on cmd_list_waitQ and we have no practical way to
		 * detect them.
		 */

		while (1) {
			struct scst_user_dev *dev;
			LIST_HEAD(cl_devs);

			while (!list_empty(&cleanup_list)) {
				int rc;

				dev = list_first_entry(&cleanup_list, typeof(*dev),
						       cleanup_list_entry);
				list_del(&dev->cleanup_list_entry);

				spin_unlock(&cleanup_lock);
				rc = dev_user_process_cleanup(dev);
				spin_lock(&cleanup_lock);

				if (rc != 0)
					list_add_tail(&dev->cleanup_list_entry, &cl_devs);
			}

			if (list_empty(&cl_devs))
				break;

			spin_unlock(&cleanup_lock);
			msleep(100);
			spin_lock(&cleanup_lock);

			while (!list_empty(&cl_devs)) {
				dev = list_first_entry(&cl_devs, typeof(*dev), cleanup_list_entry);
				list_move_tail(&dev->cleanup_list_entry, &cleanup_list);
			}
		}
	}
	spin_unlock(&cleanup_lock);

	/*
	 * If kthread_should_stop() is true, we are guaranteed to be
	 * on the module unload, so cleanup_list must be empty.
	 */
	sBUG_ON(!list_empty(&cleanup_list));

	PRINT_INFO("Cleanup thread finished");

	TRACE_EXIT();
	return 0;
}

static int __init init_scst_user(void)
{
	int res = 0;
	struct max_get_reply {
		union {
			struct scst_user_get_cmd g;
			struct scst_user_reply_cmd r;
		};
	};
	struct device *dev;

	TRACE_ENTRY();

#ifndef INSIDE_KERNEL_TREE
#if defined(CONFIG_HIGHMEM4G) || defined(CONFIG_HIGHMEM64G)
	PRINT_ERROR("HIGHMEM kernel configurations are not supported. Consider changing VMSPLIT option or use a 64-bit configuration instead. See README file for details.");
	res = -EINVAL;
	goto out;
#endif
#endif

	user_dev_cachep = KMEM_CACHE(scst_user_dev, SCST_SLAB_FLAGS | SLAB_HWCACHE_ALIGN);
	if (!user_dev_cachep) {
		res = -ENOMEM;
		goto out;
	}

	user_cmd_cachep = KMEM_CACHE_USERCOPY(scst_user_cmd, SCST_SLAB_FLAGS | SLAB_HWCACHE_ALIGN,
					      user_cmd);
	if (!user_cmd_cachep) {
		res = -ENOMEM;
		goto out_dev_cache;
	}

	dev_user_devtype.module = THIS_MODULE;

	res = scst_register_virtual_dev_driver(&dev_user_devtype);
	if (res < 0)
		goto out_cache;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0) &&		\
	(!defined(RHEL_RELEASE_CODE) ||				\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(9, 4))
	dev_user_sysfs_class = class_create(THIS_MODULE, DEV_USER_NAME);
#else
	dev_user_sysfs_class = class_create(DEV_USER_NAME);
#endif
	if (IS_ERR(dev_user_sysfs_class)) {
		PRINT_ERROR("Unable create sysfs class for SCST user space handler");
		res = PTR_ERR(dev_user_sysfs_class);
		goto out_unreg;
	}

	dev_user_major = register_chrdev(0, DEV_USER_NAME, &dev_user_fops);
	if (dev_user_major < 0) {
		PRINT_ERROR("register_chrdev() failed: %d", res);
		res = dev_user_major;
		goto out_class;
	}

	dev = device_create(dev_user_sysfs_class, NULL, MKDEV(dev_user_major, 0), NULL,
			    DEV_USER_NAME);
	if (IS_ERR(dev)) {
		res = PTR_ERR(dev);
		goto out_chrdev;
	}

	cleanup_thread = kthread_run(dev_user_cleanup_thread, NULL, "scst_usr_cleanupd");
	if (IS_ERR(cleanup_thread)) {
		res = PTR_ERR(cleanup_thread);
		PRINT_ERROR("kthread_create() failed: %d", res);
		goto out_dev;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_dev:
	device_destroy(dev_user_sysfs_class, MKDEV(dev_user_major, 0));

out_chrdev:
	unregister_chrdev(dev_user_major, DEV_USER_NAME);

out_class:
	class_destroy(dev_user_sysfs_class);

out_unreg:
	scst_unregister_dev_driver(&dev_user_devtype);

out_cache:
	kmem_cache_destroy(user_cmd_cachep);

out_dev_cache:
	kmem_cache_destroy(user_dev_cachep);
	goto out;
}

static void __exit exit_scst_user(void)
{
	int rc;

	TRACE_ENTRY();

	rc = kthread_stop(cleanup_thread);
	if (rc < 0)
		TRACE_MGMT_DBG("kthread_stop() failed: %d", rc);

	unregister_chrdev(dev_user_major, DEV_USER_NAME);
	device_destroy(dev_user_sysfs_class, MKDEV(dev_user_major, 0));
	class_destroy(dev_user_sysfs_class);

	scst_unregister_virtual_dev_driver(&dev_user_devtype);

	kmem_cache_destroy(user_cmd_cachep);
	kmem_cache_destroy(user_dev_cachep);

	TRACE_EXIT();
}

module_init(init_scst_user);
module_exit(exit_scst_user);

MODULE_AUTHOR("Vladislav Bolkhovitin");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("User space device handler for SCST");
MODULE_VERSION(SCST_VERSION_STRING);
MODULE_IMPORT_NS(SCST_NAMESPACE);
