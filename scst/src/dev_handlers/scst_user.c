/*
 *  scst_user.c
 *
 *  Copyright (C) 2007 Vladislav Bolkhovitin <vst@vlnb.net>
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

#define LOG_PREFIX		DEV_USER_NAME

#include "scst.h"
#include "scst_user.h"
#include "scst_dev_handler.h"

#if defined(CONFIG_HIGHMEM4G) || defined(CONFIG_HIGHMEM64G)
#warning "HIGHMEM kernel configurations are not supported by this module, \
	because nowadays it doesn't worth the effort. Consider change \
	VMSPLIT option or use 64-bit configuration instead. See README file \
	for details."
#endif

#define DEV_USER_MAJOR			237
#define DEV_USER_CMD_HASH_ORDER		6
#define DEV_USER_TM_TIMEOUT		(10*HZ)
#define DEV_USER_ATTACH_TIMEOUT		(5*HZ)
#define DEV_USER_DETACH_TIMEOUT		(5*HZ)
#define DEV_USER_PRE_UNREG_POLL_TIME	(HZ/10)

struct scst_user_dev {
	struct rw_semaphore dev_rwsem;

	struct scst_cmd_lists cmd_lists;
	/* All 3 protected by cmd_lists.cmd_list_lock */
	struct list_head ready_cmd_list;
	struct list_head prio_ready_cmd_list;
	wait_queue_head_t prio_cmd_list_waitQ;

	/* All, including detach_cmd_count, protected by cmd_lists.cmd_list_lock */
	unsigned short blocking:1;
	unsigned short cleaning:1;
	unsigned short cleanup_done:1;
	unsigned short attach_cmd_active:1;
	unsigned short tm_cmd_active:1;
	unsigned short internal_reset_active:1;
	unsigned short pre_unreg_sess_active:1; /* just a small optimization */

	unsigned short tst:3;
	unsigned short queue_alg:4;
	unsigned short tas:1;
	unsigned short swp:1;
	unsigned short has_own_order_mgmt:1;

	unsigned short detach_cmd_count;

	int (*generic_parse)(struct scst_cmd *cmd,
		int (*get_block)(struct scst_cmd *cmd));

	int block;
	int def_block;

	struct sgv_pool *pool;

	uint8_t parse_type;
	uint8_t on_free_cmd_type;
	uint8_t memory_reuse_type;
	uint8_t prio_queue_type;
	uint8_t partial_transfers_type;
	uint32_t partial_len;

	struct scst_dev_type devtype;

	/* Both protected by cmd_lists.cmd_list_lock */
	unsigned int handle_counter;
	struct list_head ucmd_hash[1<<DEV_USER_CMD_HASH_ORDER];

	struct scst_device *sdev;

	int virt_id;
	struct list_head dev_list_entry;
	char name[SCST_MAX_NAME];

	/* Protected by cmd_lists.cmd_list_lock */
	struct list_head pre_unreg_sess_list;

	struct list_head cleanup_list_entry;
	struct completion cleanup_cmpl;
};

struct scst_user_pre_unreg_sess_obj {
	struct scst_tgt_dev *tgt_dev;
	unsigned int active:1;
	unsigned int exit:1;
	struct list_head pre_unreg_sess_list_entry;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct work_struct pre_unreg_sess_work;
#else
	struct delayed_work pre_unreg_sess_work;
#endif
};

/* Most fields are unprotected, since only one thread at time can access them */
struct scst_user_cmd {
	struct scst_cmd *cmd;
	struct scst_user_dev *dev;

	atomic_t ucmd_ref;

	unsigned int buff_cached:1;
	unsigned int buf_dirty:1;
	unsigned int background_exec:1;
	unsigned int internal_reset_tm:1;
	unsigned int aborted:1;

	struct scst_user_cmd *buf_ucmd;

	int cur_data_page;
	int num_data_pages;
	int first_page_offset;
	unsigned long ubuff;
	struct page **data_pages;
	struct sgv_pool_obj *sgv;

	unsigned int state;

	struct list_head ready_cmd_list_entry;

	unsigned int h;
	struct list_head hash_list_entry;

	struct scst_user_get_cmd user_cmd;

	struct completion *cmpl;
	int result;
};

static struct scst_user_cmd *dev_user_alloc_ucmd(struct scst_user_dev *dev,
	int gfp_mask);
static void dev_user_free_ucmd(struct scst_user_cmd *ucmd);

static int dev_user_parse(struct scst_cmd *cmd);
static int dev_user_exec(struct scst_cmd *cmd);
static void dev_user_on_free_cmd(struct scst_cmd *cmd);
static int dev_user_task_mgmt_fn(struct scst_mgmt_cmd *mcmd,
	struct scst_tgt_dev *tgt_dev);

static int dev_user_disk_done(struct scst_cmd *cmd);
static int dev_user_tape_done(struct scst_cmd *cmd);

static struct page *dev_user_alloc_pages(struct scatterlist *sg,
	gfp_t gfp_mask, void *priv);
static void dev_user_free_sg_entries(struct scatterlist *sg, int sg_count,
				     void *priv);

static void dev_user_add_to_ready(struct scst_user_cmd *ucmd);

static void dev_user_unjam_cmd(struct scst_user_cmd *ucmd, int busy,
	unsigned long *flags);
static void dev_user_unjam_dev(struct scst_user_dev *dev, int tm,
	struct scst_tgt_dev *tgt_dev);

static int dev_user_process_reply_tm_exec(struct scst_user_cmd *ucmd,
	int status);
static int dev_user_process_reply_sess(struct scst_user_cmd *ucmd, int status);
static int dev_user_register_dev(struct file *file,
	const struct scst_user_dev_desc *dev_desc);
static int __dev_user_set_opt(struct scst_user_dev *dev,
	const struct scst_user_opt *opt);
static int dev_user_set_opt(struct file *file, const struct scst_user_opt *opt);
static int dev_user_get_opt(struct file *file, void *arg);

static unsigned int dev_user_poll(struct file *filp, poll_table *wait);
static long dev_user_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg);
static int dev_user_release(struct inode *inode, struct file *file);

/** Data **/

static struct kmem_cache *user_cmd_cachep;

static DEFINE_MUTEX(dev_priv_mutex);

static struct file_operations dev_user_fops = {
	.poll		= dev_user_poll,
	.unlocked_ioctl	= dev_user_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= dev_user_ioctl,
#endif
	.release	= dev_user_release,
};

static struct class *dev_user_sysfs_class;

static spinlock_t dev_list_lock = SPIN_LOCK_UNLOCKED;
static LIST_HEAD(dev_list);

static spinlock_t cleanup_lock = SPIN_LOCK_UNLOCKED;
static LIST_HEAD(cleanup_list);
static DECLARE_WAIT_QUEUE_HEAD(cleanup_list_waitQ);
static struct task_struct *cleanup_thread;

static inline void ucmd_get(struct scst_user_cmd *ucmd, int barrier)
{
	TRACE_DBG("ucmd %p, ucmd_ref %d", ucmd, atomic_read(&ucmd->ucmd_ref));
	atomic_inc(&ucmd->ucmd_ref);
	if (barrier)
		smp_mb__after_atomic_inc();
}

static inline void ucmd_put(struct scst_user_cmd *ucmd)
{
	TRACE_DBG("ucmd %p, ucmd_ref %d", ucmd, atomic_read(&ucmd->ucmd_ref));
	if (atomic_dec_and_test(&ucmd->ucmd_ref))
		dev_user_free_ucmd(ucmd);
}

static inline int calc_num_pg(unsigned long buf, int len)
{
	len += buf & ~PAGE_MASK;
	return (len >> PAGE_SHIFT) + ((len & ~PAGE_MASK) != 0);
}

static inline int is_need_offs_page(unsigned long buf, int len)
{
	return ((buf & ~PAGE_MASK) != 0) &&
		((buf & PAGE_MASK) != ((buf+len-1) & PAGE_MASK));
}

static void __dev_user_not_reg(void)
{
	PRINT_ERROR("%s", "Device not registered");
	return;
}

static inline int dev_user_check_reg(struct scst_user_dev *dev)
{
	if (dev == NULL) {
		__dev_user_not_reg();
		return -EINVAL;
	}
	return 0;
}

static inline int scst_user_cmd_hashfn(int h)
{
	return h & ((1 << DEV_USER_CMD_HASH_ORDER) - 1);
}

static inline struct scst_user_cmd *__ucmd_find_hash(struct scst_user_dev *dev,
	unsigned int h)
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

	spin_lock_irqsave(&dev->cmd_lists.cmd_list_lock, flags);
	do {
		ucmd->h = dev->handle_counter++;
		u = __ucmd_find_hash(dev, ucmd->h);
	} while (u != NULL);
	head = &dev->ucmd_hash[scst_user_cmd_hashfn(ucmd->h)];
	list_add_tail(&ucmd->hash_list_entry, head);
	spin_unlock_irqrestore(&dev->cmd_lists.cmd_list_lock, flags);

	TRACE_DBG("Inserted ucmd %p, h=%d", ucmd, ucmd->h);
	return;
}

static inline void cmd_remove_hash(struct scst_user_cmd *ucmd)
{
	unsigned long flags;
	spin_lock_irqsave(&ucmd->dev->cmd_lists.cmd_list_lock, flags);
	list_del(&ucmd->hash_list_entry);
	spin_unlock_irqrestore(&ucmd->dev->cmd_lists.cmd_list_lock, flags);

	TRACE_DBG("Removed ucmd %p, h=%d", ucmd, ucmd->h);
	return;
}

static void dev_user_free_ucmd(struct scst_user_cmd *ucmd)
{
	TRACE_ENTRY();

	TRACE_MEM("Freeing ucmd %p", ucmd);

	cmd_remove_hash(ucmd);
	EXTRACHECKS_BUG_ON(ucmd->cmd != NULL);

	kmem_cache_free(user_cmd_cachep, ucmd);

	TRACE_EXIT();
	return;
}

static struct page *dev_user_alloc_pages(struct scatterlist *sg,
	gfp_t gfp_mask, void *priv)
{
	struct scst_user_cmd *ucmd = (struct scst_user_cmd *)priv;
	int offset = 0;

	TRACE_ENTRY();

	/* *sg supposed to be zeroed */

	TRACE_MEM("ucmd %p, ubuff %lx, ucmd->cur_data_page %d", ucmd,
		ucmd->ubuff, ucmd->cur_data_page);

	if (ucmd->cur_data_page == 0) {
		TRACE_MEM("ucmd->first_page_offset %d",
			ucmd->first_page_offset);
		offset = ucmd->first_page_offset;
		ucmd_get(ucmd, 0);
	}

	if (ucmd->cur_data_page >= ucmd->num_data_pages)
		goto out;

	sg_set_page(sg, ucmd->data_pages[ucmd->cur_data_page],
		PAGE_SIZE - offset, offset);
	ucmd->cur_data_page++;

	TRACE_MEM("page=%p, length=%d, offset=%d", sg_page(sg), sg->length,
		sg->offset);
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

	ucmd->user_cmd.cmd_h = ucmd->h;
	ucmd->user_cmd.subcode = SCST_USER_ON_CACHED_MEM_FREE;
	ucmd->user_cmd.on_cached_mem_free.pbuf = ucmd->ubuff;

	ucmd->state = UCMD_STATE_ON_CACHE_FREEING;

	dev_user_add_to_ready(ucmd);

	TRACE_EXIT();
	return;
}

static void dev_user_unmap_buf(struct scst_user_cmd *ucmd)
{
	int i;

	TRACE_ENTRY();

	TRACE_MEM("Unmapping data pages (ucmd %p, ubuff %lx, num %d)", ucmd,
		ucmd->ubuff, ucmd->num_data_pages);

	for (i = 0; i < ucmd->num_data_pages; i++) {
		struct page *page = ucmd->data_pages[i];

		if (ucmd->buf_dirty)
			SetPageDirty(page);

		page_cache_release(page);
	}
	kfree(ucmd->data_pages);
	ucmd->data_pages = NULL;

	TRACE_EXIT();
	return;
}

static void __dev_user_free_sg_entries(struct scst_user_cmd *ucmd)
{
	TRACE_ENTRY();

	sBUG_ON(ucmd->data_pages == NULL);

	TRACE_MEM("Freeing data pages (ucmd=%p, ubuff=%lx, buff_cached=%d)",
		ucmd, ucmd->ubuff, ucmd->buff_cached);

	dev_user_unmap_buf(ucmd);

	if (ucmd->buff_cached)
		dev_user_on_cached_mem_free(ucmd);
	else
		ucmd_put(ucmd);

	TRACE_EXIT();
	return;
}

static void dev_user_free_sg_entries(struct scatterlist *sg, int sg_count,
	void *priv)
{
	struct scst_user_cmd *ucmd = (struct scst_user_cmd *)priv;

	TRACE_MEM("Freeing data pages (sg=%p, sg_count=%d, priv %p)", sg,
		sg_count, ucmd);

	__dev_user_free_sg_entries(ucmd);

	return;
}

static inline int is_buff_cached(struct scst_user_cmd *ucmd)
{
	int mem_reuse_type = ucmd->dev->memory_reuse_type;

	if ((mem_reuse_type == SCST_USER_MEM_REUSE_ALL) ||
	    ((ucmd->cmd->data_direction == SCST_DATA_READ) &&
	     (mem_reuse_type == SCST_USER_MEM_REUSE_READ)) ||
	    ((ucmd->cmd->data_direction == SCST_DATA_WRITE) &&
	     (mem_reuse_type == SCST_USER_MEM_REUSE_WRITE)))
		return 1;
	else
		return 0;
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
	int gfp_mask, flags = 0;
	int bufflen = cmd->bufflen;
	int last_len = 0;

	TRACE_ENTRY();

	gfp_mask = __GFP_NOWARN;
	gfp_mask |= (scst_cmd_atomic(cmd) ? GFP_ATOMIC : GFP_KERNEL);

	if (cached_buff) {
		flags |= SCST_POOL_RETURN_OBJ_ON_ALLOC_FAIL;
		if (ucmd->ubuff == 0)
			flags |= SCST_POOL_NO_ALLOC_ON_CACHE_MISS;
	} else {
		TRACE_MEM("%s", "Not cached buff");
		flags |= SCST_POOL_ALLOC_NO_CACHED;
		if (ucmd->ubuff == 0) {
			res = 1;
			goto out;
		}
		bufflen += ucmd->first_page_offset;
		if (is_need_offs_page(ucmd->ubuff, cmd->bufflen))
			last_len = bufflen & ~PAGE_MASK;
		else
			last_len = cmd->bufflen & ~PAGE_MASK;
		if (last_len == 0)
			last_len = PAGE_SIZE;
	}
	ucmd->buff_cached = cached_buff;

	cmd->sg = sgv_pool_alloc(dev->pool, bufflen, gfp_mask, flags,
			&cmd->sg_cnt, &ucmd->sgv, ucmd);
	if (cmd->sg != NULL) {
		struct scst_user_cmd *buf_ucmd =
			(struct scst_user_cmd *)sgv_get_priv(ucmd->sgv);

		TRACE_MEM("Buf ucmd %p", buf_ucmd);

		ucmd->ubuff = buf_ucmd->ubuff;
		ucmd->buf_ucmd = buf_ucmd;

		EXTRACHECKS_BUG_ON((ucmd->data_pages != NULL) &&
				   (ucmd != buf_ucmd));

		if (last_len != 0) {
			/* We don't use clustering, so the assignment is safe */
			cmd->sg[cmd->sg_cnt-1].length = last_len;
		}

		TRACE_MEM("Buf alloced (ucmd %p, cached_buff %d, ubuff %lx, "
			"last_len %d, l %d)", ucmd, cached_buff, ucmd->ubuff,
			last_len, cmd->sg[cmd->sg_cnt-1].length);

		if (unlikely(cmd->sg_cnt > cmd->tgt_dev->max_sg_cnt)) {
			static int ll;
			if (ll < 10) {
				PRINT_INFO("Unable to complete command due to "
					"SG IO count limitation (requested %d, "
					"available %d, tgt lim %d)", cmd->sg_cnt,
					cmd->tgt_dev->max_sg_cnt,
					cmd->tgt->sg_tablesize);
				ll++;
			}
			cmd->sg = NULL;
			/* sgv will be freed in dev_user_free_sgv() */
			res = -1;
		}
	} else {
		TRACE_MEM("Buf not alloced (ucmd %p, h %d, buff_cached, %d, "
			"sg_cnt %d, ubuff %lx, sgv %p", ucmd, ucmd->h,
			ucmd->buff_cached, cmd->sg_cnt,	ucmd->ubuff, ucmd->sgv);
		if (unlikely(cmd->sg_cnt == 0)) {
			TRACE_MEM("Refused allocation (ucmd %p)", ucmd);
			sBUG_ON(ucmd->sgv != NULL);
			res = -1;
		} else {
			switch (ucmd->state & ~UCMD_STATE_MASK) {
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

	if (unlikely(ucmd->cmd->data_buf_tgt_alloc)) {
		PRINT_ERROR("Target driver %s requested own memory "
			"allocation", ucmd->cmd->tgtt->name);
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
		res = SCST_CMD_STATE_PRE_XMIT_RESP;
		goto out;
	}

	ucmd->state = UCMD_STATE_BUF_ALLOCING;
	cmd->data_buf_alloced = 1;

	rc = dev_user_alloc_sg(ucmd, is_buff_cached(ucmd));
	if (rc == 0)
		goto out;
	else if (rc < 0) {
		scst_set_busy(cmd);
		res = SCST_CMD_STATE_PRE_XMIT_RESP;
		goto out;
	}

	if ((cmd->data_direction != SCST_DATA_WRITE) &&
	    !scst_is_cmd_local(cmd)) {
		TRACE_DBG("Delayed alloc, ucmd %p", ucmd);
		goto out;
	}

	ucmd->user_cmd.cmd_h = ucmd->h;
	ucmd->user_cmd.subcode = SCST_USER_ALLOC_MEM;
	ucmd->user_cmd.alloc_cmd.sess_h = (unsigned long)cmd->tgt_dev;
	memcpy(ucmd->user_cmd.alloc_cmd.cdb, cmd->cdb,
		min(sizeof(ucmd->user_cmd.alloc_cmd.cdb), sizeof(cmd->cdb)));
	ucmd->user_cmd.alloc_cmd.cdb_len = cmd->cdb_len;
	ucmd->user_cmd.alloc_cmd.alloc_len = ucmd->buff_cached ?
		(cmd->sg_cnt << PAGE_SHIFT) : cmd->bufflen;
	ucmd->user_cmd.alloc_cmd.queue_type = cmd->queue_type;
	ucmd->user_cmd.alloc_cmd.data_direction = cmd->data_direction;
	ucmd->user_cmd.alloc_cmd.sn = cmd->tgt_sn;

	dev_user_add_to_ready(ucmd);

	res = SCST_CMD_STATE_STOP;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct scst_user_cmd *dev_user_alloc_ucmd(struct scst_user_dev *dev,
	int gfp_mask)
{
	struct scst_user_cmd *ucmd = NULL;

	TRACE_ENTRY();

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 17)
	ucmd = kmem_cache_alloc(user_cmd_cachep, gfp_mask);
	if (ucmd != NULL)
		memset(ucmd, 0, sizeof(*ucmd));
#else
	ucmd = kmem_cache_zalloc(user_cmd_cachep, gfp_mask);
#endif
	if (unlikely(ucmd == NULL)) {
		TRACE(TRACE_OUT_OF_MEM, "Unable to allocate "
			"user cmd (gfp_mask %x)", gfp_mask);
		goto out;
	}
	ucmd->dev = dev;
	atomic_set(&ucmd->ucmd_ref, 1);

	cmd_insert_hash(ucmd);

	TRACE_MEM("ucmd %p allocated", ucmd);

out:
	TRACE_EXIT_HRES((unsigned long)ucmd);
	return ucmd;
}

static int dev_user_get_block(struct scst_cmd *cmd)
{
	struct scst_user_dev *dev = (struct scst_user_dev *)cmd->dev->dh_priv;
	/*
	 * No need for locks here, since *_detach() can not be
	 * called, when there are existing commands.
	 */
	TRACE_EXIT_RES(dev->block);
	return dev->block;
}

static int dev_user_parse(struct scst_cmd *cmd)
{
	int rc, res = SCST_CMD_STATE_DEFAULT;
	struct scst_user_cmd *ucmd;
	int atomic = scst_cmd_atomic(cmd);
	struct scst_user_dev *dev = (struct scst_user_dev *)cmd->dev->dh_priv;
	int gfp_mask = atomic ? GFP_ATOMIC : GFP_KERNEL;

	TRACE_ENTRY();

	if (cmd->dh_priv == NULL) {
		ucmd = dev_user_alloc_ucmd(dev, gfp_mask);
		if (unlikely(ucmd == NULL)) {
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
		ucmd = (struct scst_user_cmd *)cmd->dh_priv;
		TRACE_DBG("Used ucmd %p, state %x", ucmd, ucmd->state);
	}

	TRACE_DBG("ucmd %p, cmd %p, state %x", ucmd, cmd, ucmd->state);

	if (ucmd->state != UCMD_STATE_NEW)
		goto alloc;

	switch (dev->parse_type) {
	case SCST_USER_PARSE_STANDARD:
		TRACE_DBG("PARSE STANDARD: ucmd %p", ucmd);
		rc = dev->generic_parse(cmd, dev_user_get_block);
		if ((rc != 0) || (cmd->op_flags & SCST_INFO_INVALID))
			goto out_invalid;
		break;

	case SCST_USER_PARSE_EXCEPTION:
		TRACE_DBG("PARSE EXCEPTION: ucmd %p", ucmd);
		rc = dev->generic_parse(cmd, dev_user_get_block);
		if ((rc == 0) && (!(cmd->op_flags & SCST_INFO_INVALID)))
			break;
		else if (rc == SCST_CMD_STATE_NEED_THREAD_CTX) {
			TRACE_MEM("Restarting PARSE to thread context "
				"(ucmd %p)", ucmd);
			res = SCST_CMD_STATE_NEED_THREAD_CTX;
			goto out;
		}
		/* else go through */

	case SCST_USER_PARSE_CALL:
		TRACE_DBG("Preparing PARSE for user space (ucmd=%p, h=%d, "
			"bufflen %d)", ucmd, ucmd->h, cmd->bufflen);
		ucmd->user_cmd.cmd_h = ucmd->h;
		ucmd->user_cmd.subcode = SCST_USER_PARSE;
		ucmd->user_cmd.parse_cmd.sess_h = (unsigned long)cmd->tgt_dev;
		memcpy(ucmd->user_cmd.parse_cmd.cdb, cmd->cdb,
			min(sizeof(ucmd->user_cmd.parse_cmd.cdb),
			    sizeof(cmd->cdb)));
		ucmd->user_cmd.parse_cmd.cdb_len = cmd->cdb_len;
		ucmd->user_cmd.parse_cmd.timeout = cmd->timeout;
		ucmd->user_cmd.parse_cmd.bufflen = cmd->bufflen;
		ucmd->user_cmd.parse_cmd.queue_type = cmd->queue_type;
		ucmd->user_cmd.parse_cmd.data_direction = cmd->data_direction;
		ucmd->user_cmd.parse_cmd.expected_values_set =
					cmd->expected_values_set;
		ucmd->user_cmd.parse_cmd.expected_data_direction =
					cmd->expected_data_direction;
		ucmd->user_cmd.parse_cmd.expected_transfer_len =
					cmd->expected_transfer_len;
		ucmd->user_cmd.parse_cmd.sn = cmd->tgt_sn;
		ucmd->state = UCMD_STATE_PARSING;
		dev_user_add_to_ready(ucmd);
		res = SCST_CMD_STATE_STOP;
		goto out;

	default:
		sBUG();
		goto out;
	}

alloc:
	if (cmd->data_direction != SCST_DATA_NONE)
		res = dev_user_alloc_space(ucmd);

out:
	TRACE_EXIT_RES(res);
	return res;

out_invalid:
	PRINT_ERROR("PARSE failed (ucmd %p, rc %d, invalid %d)", ucmd, rc,
		cmd->op_flags & SCST_INFO_INVALID);
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_invalid_opcode));

out_error:
	res = SCST_CMD_STATE_PRE_XMIT_RESP;
	goto out;
}

static void dev_user_flush_dcache(struct scst_user_cmd *ucmd)
{
	struct scst_user_cmd *buf_ucmd = ucmd->buf_ucmd;
	unsigned long start = buf_ucmd->ubuff;
	int i;

	TRACE_ENTRY();

	if (start == 0)
		goto out;

	for (i = 0; i < buf_ucmd->num_data_pages; i++) {
		struct page *page;
		page = buf_ucmd->data_pages[i];
#ifdef ARCH_HAS_FLUSH_ANON_PAGE
		struct vm_area_struct *vma = find_vma(current->mm, start);
		if (vma != NULL)
			flush_anon_page(vma, page, start);
#endif
		flush_dcache_page(page);
		start += PAGE_SIZE;
	}

out:
	TRACE_EXIT();
	return;
}

static int dev_user_exec(struct scst_cmd *cmd)
{
	struct scst_user_cmd *ucmd = (struct scst_user_cmd *)cmd->dh_priv;
	int res = SCST_EXEC_COMPLETED;

	TRACE_ENTRY();

#if 0 /* We set exec_atomic in 0 to let SCST core know that we need a thread
       * context to complete the necessary actions, but all we are going to
       * do in this function is, in fact, atomic, so let's skip this check.
       */
	if (scst_cmd_atomic(cmd)) {
		TRACE_DBG("%s", "User exec() can not be called in atomic "
			"context, rescheduling to the thread");
		res = SCST_EXEC_NEED_THREAD;
		goto out;
	}
#endif

	TRACE_DBG("Preparing EXEC for user space (ucmd=%p, h=%d, "
		"bufflen %d, data_len %d, ubuff %lx)", ucmd, ucmd->h,
		cmd->bufflen, cmd->data_len, ucmd->ubuff);

	if (cmd->data_direction == SCST_DATA_WRITE)
		dev_user_flush_dcache(ucmd);

	ucmd->user_cmd.cmd_h = ucmd->h;
	ucmd->user_cmd.subcode = SCST_USER_EXEC;
	ucmd->user_cmd.exec_cmd.sess_h = (unsigned long)cmd->tgt_dev;
	memcpy(ucmd->user_cmd.exec_cmd.cdb, cmd->cdb,
		min(sizeof(ucmd->user_cmd.exec_cmd.cdb),
		    sizeof(cmd->cdb)));
	ucmd->user_cmd.exec_cmd.cdb_len = cmd->cdb_len;
	ucmd->user_cmd.exec_cmd.bufflen = cmd->bufflen;
	ucmd->user_cmd.exec_cmd.data_len = cmd->data_len;
	ucmd->user_cmd.exec_cmd.pbuf = ucmd->ubuff;
	if ((ucmd->ubuff == 0) && (cmd->data_direction != SCST_DATA_NONE)) {
		ucmd->user_cmd.exec_cmd.alloc_len = ucmd->buff_cached ?
			(cmd->sg_cnt << PAGE_SHIFT) : cmd->bufflen;
	}
	ucmd->user_cmd.exec_cmd.queue_type = cmd->queue_type;
	ucmd->user_cmd.exec_cmd.data_direction = cmd->data_direction;
	ucmd->user_cmd.exec_cmd.partial = 0;
	ucmd->user_cmd.exec_cmd.timeout = cmd->timeout;
	ucmd->user_cmd.exec_cmd.sn = cmd->tgt_sn;

	ucmd->state = UCMD_STATE_EXECING;

	dev_user_add_to_ready(ucmd);

	TRACE_EXIT_RES(res);
	return res;
}

static void dev_user_free_sgv(struct scst_user_cmd *ucmd)
{
	if (ucmd->sgv != NULL) {
		sgv_pool_free(ucmd->sgv);
		ucmd->sgv = NULL;
	} else if (ucmd->data_pages != NULL) {
		/* We mapped pages, but for some reason didn't allocate them */
		ucmd_get(ucmd, 0);
		__dev_user_free_sg_entries(ucmd);
	}
	return;
}

static void dev_user_on_free_cmd(struct scst_cmd *cmd)
{
	struct scst_user_cmd *ucmd = (struct scst_user_cmd *)cmd->dh_priv;

	TRACE_ENTRY();

	if (unlikely(ucmd == NULL))
		goto out;

	TRACE_MEM("ucmd %p, cmd %p, buff_cached %d, ubuff %lx", ucmd, ucmd->cmd,
		ucmd->buff_cached, ucmd->ubuff);

	ucmd->cmd = NULL;
	if ((cmd->data_direction == SCST_DATA_WRITE) && (ucmd->buf_ucmd != NULL))
		ucmd->buf_ucmd->buf_dirty = 1;

	if (ucmd->dev->on_free_cmd_type == SCST_USER_ON_FREE_CMD_IGNORE) {
		ucmd->state = UCMD_STATE_ON_FREE_SKIPPED;
		/* The state assignment must be before freeing sgv! */
		dev_user_free_sgv(ucmd);
		ucmd_put(ucmd);
		goto out;
	}

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
}

static void dev_user_set_block(struct scst_cmd *cmd, int block)
{
	struct scst_user_dev *dev = (struct scst_user_dev *)cmd->dev->dh_priv;
	/*
	 * No need for locks here, since *_detach() can not be
	 * called, when there are existing commands.
	 */
	TRACE_DBG("dev %p, new block %d", dev, block);
	if (block != 0)
		dev->block = block;
	else
		dev->block = dev->def_block;
	return;
}

static int dev_user_disk_done(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_DEFAULT;

	TRACE_ENTRY();

	res = scst_block_generic_dev_done(cmd, dev_user_set_block);

	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_tape_done(struct scst_cmd *cmd)
{
	int res = SCST_CMD_STATE_DEFAULT;

	TRACE_ENTRY();

	res = scst_tape_generic_dev_done(cmd, dev_user_set_block);

	TRACE_EXIT_RES(res);
	return res;
}

static void dev_user_add_to_ready(struct scst_user_cmd *ucmd)
{
	struct scst_user_dev *dev = ucmd->dev;
	unsigned long flags;
	int do_wake;

	TRACE_ENTRY();

	do_wake = (in_interrupt() ||
		   (ucmd->state == UCMD_STATE_ON_CACHE_FREEING));
	if (ucmd->cmd)
		do_wake |= ucmd->cmd->preprocessing_only;

	EXTRACHECKS_BUG_ON(ucmd->state & UCMD_STATE_JAMMED_MASK);

	spin_lock_irqsave(&dev->cmd_lists.cmd_list_lock, flags);

	/* Hopefully, compiler will make it as a single test/jmp */
	if (unlikely(dev->attach_cmd_active || dev->tm_cmd_active ||
		     dev->internal_reset_active || dev->pre_unreg_sess_active ||
		     (dev->detach_cmd_count != 0))) {
		switch (ucmd->state) {
		case UCMD_STATE_PARSING:
		case UCMD_STATE_BUF_ALLOCING:
		case UCMD_STATE_EXECING:
			if (dev->pre_unreg_sess_active &&
			    !(dev->attach_cmd_active || dev->tm_cmd_active ||
			      dev->internal_reset_active ||
			      (dev->detach_cmd_count != 0))) {
				struct scst_user_pre_unreg_sess_obj *p, *found = NULL;
				list_for_each_entry(p, &dev->pre_unreg_sess_list,
					pre_unreg_sess_list_entry) {
					if (p->tgt_dev == ucmd->cmd->tgt_dev) {
						if (p->active)
							found = p;
						break;
					}
				}
				if (found == NULL) {
					TRACE_MGMT_DBG("No pre unreg sess "
						"active (ucmd %p)", ucmd);
					break;
				} else {
					TRACE_MGMT_DBG("Pre unreg sess %p "
						"active (ucmd %p)", found, ucmd);
				}
			}
			TRACE(TRACE_MGMT, "Mgmt cmd active, returning BUSY for "
				"ucmd %p", ucmd);
			dev_user_unjam_cmd(ucmd, 1, &flags);
			spin_unlock_irqrestore(&dev->cmd_lists.cmd_list_lock, flags);
			goto out;
		}
	}

	if (unlikely(ucmd->state == UCMD_STATE_TM_EXECING) ||
	    unlikely(ucmd->state == UCMD_STATE_ATTACH_SESS) ||
	    unlikely(ucmd->state == UCMD_STATE_DETACH_SESS)) {
		if (dev->prio_queue_type == SCST_USER_PRIO_QUEUE_SEPARATE) {
			TRACE_MGMT_DBG("Adding mgmt ucmd %p to prio ready cmd "
				       "list", ucmd);
			list_add_tail(&ucmd->ready_cmd_list_entry,
				&dev->prio_ready_cmd_list);
			wake_up(&dev->prio_cmd_list_waitQ);
			do_wake = 0;
		} else {
			TRACE_MGMT_DBG("Adding mgmt ucmd %p to ready cmd "
				"list", ucmd);
			list_add_tail(&ucmd->ready_cmd_list_entry,
				&dev->ready_cmd_list);
			do_wake = 1;
		}
	} else if ((ucmd->cmd != NULL) &&
	    unlikely((ucmd->cmd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE))) {
		TRACE_DBG("Adding ucmd %p to head ready cmd list", ucmd);
		list_add(&ucmd->ready_cmd_list_entry, &dev->ready_cmd_list);
	} else {
		TRACE_DBG("Adding ucmd %p to ready cmd list", ucmd);
		list_add_tail(&ucmd->ready_cmd_list_entry, &dev->ready_cmd_list);
	}

	if (do_wake) {
		TRACE_DBG("Waking up dev %p", dev);
		wake_up(&dev->cmd_lists.cmd_list_waitQ);
	}

	spin_unlock_irqrestore(&dev->cmd_lists.cmd_list_lock, flags);

out:
	TRACE_EXIT();
	return;
}

static int dev_user_map_buf(struct scst_user_cmd *ucmd, unsigned long ubuff,
	int num_pg)
{
	int res = 0, rc;
	int i;

	TRACE_ENTRY();

	if (unlikely(ubuff == 0))
		goto out_nomem;

	sBUG_ON(ucmd->data_pages != NULL);

	ucmd->num_data_pages = num_pg;

	ucmd->data_pages = kzalloc(sizeof(*ucmd->data_pages)*ucmd->num_data_pages,
		GFP_KERNEL);
	if (ucmd->data_pages == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "Unable to allocate data_pages array "
			"(num_data_pages=%d)", ucmd->num_data_pages);
		res = -ENOMEM;
		goto out_nomem;
	}

	TRACE_MEM("Mapping buffer (ucmd %p, ubuff %lx, ucmd->num_data_pages %d, "
		"first_page_offset %d, len %d)", ucmd, ubuff,
		ucmd->num_data_pages, (int)(ubuff & ~PAGE_MASK),
		ucmd->cmd->bufflen);

	down_read(&current->mm->mmap_sem);
	rc = get_user_pages(current, current->mm, ubuff, ucmd->num_data_pages,
		1/*writable*/, 0/*don't force*/, ucmd->data_pages, NULL);
	up_read(&current->mm->mmap_sem);

	/* get_user_pages() flushes dcache */

	if (rc < ucmd->num_data_pages)
		goto out_unmap;

	ucmd->ubuff = ubuff;
	ucmd->first_page_offset = (ubuff & ~PAGE_MASK);

out:
	TRACE_EXIT_RES(res);
	return res;

out_nomem:
	scst_set_busy(ucmd->cmd);
	/* go through */

out_err:
	ucmd->cmd->state = SCST_CMD_STATE_PRE_XMIT_RESP;
	goto out;

out_unmap:
	PRINT_ERROR("Failed to get %d user pages (rc %d)",
		ucmd->num_data_pages, rc);
	if (rc > 0) {
		for (i = 0; i < rc; i++)
			page_cache_release(ucmd->data_pages[i]);
	}
	kfree(ucmd->data_pages);
	ucmd->data_pages = NULL;
	res = -EFAULT;
	scst_set_cmd_error(ucmd->cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	goto out_err;
}

static int dev_user_process_reply_alloc(struct scst_user_cmd *ucmd,
	struct scst_user_reply_cmd *reply)
{
	int res = 0;
	struct scst_cmd *cmd = ucmd->cmd;

	TRACE_ENTRY();

	TRACE_DBG("ucmd %p, pbuf %Lx", ucmd, reply->alloc_reply.pbuf);

	if (likely(reply->alloc_reply.pbuf != 0)) {
		int pages;
		if (ucmd->buff_cached) {
			if (unlikely((reply->alloc_reply.pbuf & ~PAGE_MASK) != 0)) {
				PRINT_ERROR("Supplied pbuf %Lx isn't "
					"page aligned", reply->alloc_reply.pbuf);
				goto out_hwerr;
			}
			pages = cmd->sg_cnt;
		} else
			pages = calc_num_pg(reply->alloc_reply.pbuf, cmd->bufflen);
		res = dev_user_map_buf(ucmd, reply->alloc_reply.pbuf, pages);
	} else {
		scst_set_busy(ucmd->cmd);
		ucmd->cmd->state = SCST_CMD_STATE_PRE_XMIT_RESP;
	}

out_process:
	scst_process_active_cmd(cmd, SCST_CONTEXT_DIRECT);

	TRACE_EXIT_RES(res);
	return res;

out_hwerr:
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	res = -EINVAL;
	goto out_process;
}

static int dev_user_process_reply_parse(struct scst_user_cmd *ucmd,
	struct scst_user_reply_cmd *reply)
{
	int res = 0;
	struct scst_user_scsi_cmd_reply_parse *preply =
		&reply->parse_reply;
	struct scst_cmd *cmd = ucmd->cmd;

	TRACE_ENTRY();

	if (unlikely(preply->queue_type > SCST_CMD_QUEUE_ACA))
		goto out_inval;

	if (unlikely((preply->data_direction != SCST_DATA_WRITE) &&
		     (preply->data_direction != SCST_DATA_READ) &&
		     (preply->data_direction != SCST_DATA_NONE)))
		goto out_inval;

	if (unlikely((preply->data_direction != SCST_DATA_NONE) &&
		     (preply->bufflen == 0)))
		goto out_inval;

	if (unlikely((preply->bufflen < 0) || (preply->data_len < 0)))
		goto out_inval;

	TRACE_DBG("ucmd %p, queue_type %x, data_direction, %x, bufflen %d, "
		"data_len %d, pbuf %Lx", ucmd, preply->queue_type,
		preply->data_direction, preply->bufflen, preply->data_len,
		reply->alloc_reply.pbuf);

	cmd->queue_type = preply->queue_type;
	cmd->data_direction = preply->data_direction;
	cmd->bufflen = preply->bufflen;
	cmd->data_len = preply->data_len;

out_process:
	scst_process_active_cmd(cmd, SCST_CONTEXT_DIRECT);

	TRACE_EXIT_RES(res);
	return res;

out_inval:
	PRINT_ERROR("%s", "Invalid parse_reply parameter(s)");
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	res = -EINVAL;
	goto out_process;
}

static int dev_user_process_reply_on_free(struct scst_user_cmd *ucmd)
{
	int res = 0;

	TRACE_ENTRY();

	TRACE_DBG("ON FREE ucmd %p", ucmd);

	dev_user_free_sgv(ucmd);
	ucmd_put(ucmd);

	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_process_reply_on_cache_free(struct scst_user_cmd *ucmd)
{
	int res = 0;

	TRACE_ENTRY();

	TRACE_DBG("ON CACHE FREE ucmd %p", ucmd);

	ucmd_put(ucmd);

	TRACE_EXIT_RES(res);
	return res;
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
		if (unlikely((cmd->data_direction != SCST_DATA_READ) &&
			     (ereply->resp_data_len != 0)))
			goto out_inval;
	} else if (ereply->reply_type == SCST_EXEC_REPLY_BACKGROUND) {
		if (unlikely(ucmd->background_exec))
			goto out_inval;
		if (unlikely((cmd->data_direction == SCST_DATA_READ) ||
			     (cmd->resp_data_len != 0)))
			goto out_inval;
		ucmd_get(ucmd, 1);
		ucmd->background_exec = 1;
		TRACE_DBG("Background ucmd %p", ucmd);
		goto out_compl;
	} else
		goto out_inval;

	TRACE_DBG("ucmd %p, status %d, resp_data_len %d", ucmd,
		ereply->status, ereply->resp_data_len);

	 if (ereply->resp_data_len != 0) {
		if (ucmd->ubuff == 0) {
			int pages, rc;
			if (unlikely(ereply->pbuf == 0))
				goto out_busy;
			if (ucmd->buff_cached) {
				if (unlikely((ereply->pbuf & ~PAGE_MASK) != 0)) {
					PRINT_ERROR("Supplied pbuf %Lx isn't "
						"page aligned", ereply->pbuf);
					goto out_hwerr;
				}
				pages = cmd->sg_cnt;
			} else
				pages = calc_num_pg(ereply->pbuf, cmd->bufflen);
			rc = dev_user_map_buf(ucmd, ereply->pbuf, pages);
			if ((rc != 0) || (ucmd->ubuff == 0))
				goto out_compl;

			rc = dev_user_alloc_sg(ucmd, ucmd->buff_cached);
			if (unlikely(rc != 0))
				goto out_busy;
		} else
			dev_user_flush_dcache(ucmd);
		cmd->may_need_dma_sync = 1;
		scst_set_resp_data_len(cmd, ereply->resp_data_len);
	} else if (cmd->resp_data_len != ereply->resp_data_len) {
		if (ucmd->ubuff == 0)
			cmd->resp_data_len = ereply->resp_data_len;
		else
			scst_set_resp_data_len(cmd, ereply->resp_data_len);
	}

	cmd->status = ereply->status;
	if (ereply->sense_len != 0) {
		res = scst_alloc_sense(cmd, 0);
		if (res != 0)
			goto out_compl;
		res = copy_from_user(cmd->sense,
			(void *)(unsigned long)ereply->psense_buffer,
			min((unsigned int)SCST_SENSE_BUFFERSIZE,
				(unsigned int)ereply->sense_len));
		if (res < 0) {
			PRINT_ERROR("%s", "Unable to get sense data");
			goto out_hwerr_res_set;
		}
	}

out_compl:
	cmd->completed = 1;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT);
	/* !! At this point cmd can be already freed !! */

out:
	TRACE_EXIT_RES(res);
	return res;

out_inval:
	PRINT_ERROR("%s", "Invalid exec_reply parameter(s)");

out_hwerr:
	res = -EINVAL;

out_hwerr_res_set:
	if (ucmd->background_exec) {
		ucmd_put(ucmd);
		goto out;
	} else {
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out_compl;
	}

out_busy:
	scst_set_busy(cmd);
	goto out_compl;
}

static int dev_user_process_reply(struct scst_user_dev *dev,
	struct scst_user_reply_cmd *reply)
{
	int res = 0;
	struct scst_user_cmd *ucmd;
	int state;

	TRACE_ENTRY();

	spin_lock_irq(&dev->cmd_lists.cmd_list_lock);

	ucmd = __ucmd_find_hash(dev, reply->cmd_h);
	if (ucmd == NULL) {
		TRACE_MGMT_DBG("cmd_h %d not found", reply->cmd_h);
		res = -ESRCH;
		goto out_unlock;
	}

	if (ucmd->background_exec) {
		state = UCMD_STATE_EXECING;
		goto unlock_process;
	}

	if (unlikely(!(ucmd->state & UCMD_STATE_SENT_MASK))) {
		if (ucmd->state & UCMD_STATE_JAMMED_MASK) {
			TRACE_MGMT_DBG("Reply on jammed ucmd %p, ignoring",
				ucmd);
		} else {
			TRACE_MGMT_DBG("Ucmd %p isn't in the sent to user "
				"state %x", ucmd, ucmd->state);
			res = -EBUSY;
		}
		goto out_unlock;
	}

	if (unlikely(reply->subcode != ucmd->user_cmd.subcode))
		goto out_wrong_state;

	if (unlikely(_IOC_NR(reply->subcode) !=
			(ucmd->state & ~UCMD_STATE_SENT_MASK)))
		goto out_wrong_state;

	ucmd->state &= ~UCMD_STATE_SENT_MASK;
	state = ucmd->state;
	ucmd->state |= UCMD_STATE_RECV_MASK;

unlock_process:
	spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);

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

	case UCMD_STATE_TM_EXECING:
		res = dev_user_process_reply_tm_exec(ucmd, reply->result);
		break;

	case UCMD_STATE_ATTACH_SESS:
	case UCMD_STATE_DETACH_SESS:
		res = dev_user_process_reply_sess(ucmd, reply->result);
		break;

	default:
		sBUG();
		break;
	}
out:
	TRACE_EXIT_RES(res);
	return res;

out_wrong_state:
	PRINT_ERROR("Command's %p subcode %x doesn't match internal "
		"command's state %x or reply->subcode (%x) != ucmd->subcode "
		"(%x)", ucmd, _IOC_NR(reply->subcode), ucmd->state,
		reply->subcode, ucmd->user_cmd.subcode);
	res = -EINVAL;
	dev_user_unjam_cmd(ucmd, 0, NULL);

out_unlock:
	spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);
	goto out;
}

static int dev_user_reply_cmd(struct file *file, unsigned long arg)
{
	int res = 0;
	struct scst_user_dev *dev;
	struct scst_user_reply_cmd *reply;

	TRACE_ENTRY();

	mutex_lock(&dev_priv_mutex);
	dev = (struct scst_user_dev *)file->private_data;
	res = dev_user_check_reg(dev);
	if (res != 0) {
		mutex_unlock(&dev_priv_mutex);
		goto out;
	}
	down_read(&dev->dev_rwsem);
	mutex_unlock(&dev_priv_mutex);

	reply = kzalloc(sizeof(*reply), GFP_KERNEL);
	if (reply == NULL) {
		res = -ENOMEM;
		goto out_up;
	}

	res = copy_from_user(reply, (void *)arg, sizeof(*reply));
	if (res < 0)
		goto out_free;

	TRACE_BUFFER("Reply", reply, sizeof(*reply));

	res = dev_user_process_reply(dev, reply);
	if (res < 0)
		goto out_free;

out_free:
	kfree(reply);

out_up:
	up_read(&dev->dev_rwsem);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_process_scst_commands(struct scst_user_dev *dev)
{
	int res = 0;

	TRACE_ENTRY();

	while (!list_empty(&dev->cmd_lists.active_cmd_list)) {
		struct scst_cmd *cmd = list_entry(
			dev->cmd_lists.active_cmd_list.next, typeof(*cmd),
			cmd_list_entry);
		TRACE_DBG("Deleting cmd %p from active cmd list", cmd);
		list_del(&cmd->cmd_list_entry);
		spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);
		scst_process_active_cmd(cmd, SCST_CONTEXT_DIRECT |
						 SCST_CONTEXT_PROCESSABLE);
		spin_lock_irq(&dev->cmd_lists.cmd_list_lock);
		res++;
	}

	TRACE_EXIT_RES(res);
	return res;
}

/* Called under cmd_lists.cmd_list_lock and IRQ off */
struct scst_user_cmd *__dev_user_get_next_cmd(struct list_head *cmd_list)
{
	struct scst_user_cmd *u;

again:
	u = NULL;
	if (!list_empty(cmd_list)) {
		u = list_entry(cmd_list->next, typeof(*u), ready_cmd_list_entry);

		TRACE_DBG("Found ready ucmd %p", u);
		list_del(&u->ready_cmd_list_entry);

		EXTRACHECKS_BUG_ON(u->state & UCMD_STATE_JAMMED_MASK);

		if (u->cmd != NULL) {
			if (u->state == UCMD_STATE_EXECING) {
				struct scst_user_dev *dev = u->dev;
				int rc;
				spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);
				rc = scst_check_local_events(u->cmd);
				if (unlikely(rc != 0)) {
					u->cmd->scst_cmd_done(u->cmd,
						SCST_CMD_STATE_DEFAULT);
					/*
					 * !! At this point cmd & u can be !!
					 * !! already freed		   !!
					 */
					spin_lock_irq(
						&dev->cmd_lists.cmd_list_lock);
					goto again;
				}
				/*
				 * There is no real need to lock again here, but
				 * let's do it for simplicity.
				 */
				spin_lock_irq(&dev->cmd_lists.cmd_list_lock);
			} else if (unlikely(test_bit(SCST_CMD_ABORTED,
					&u->cmd->cmd_flags))) {
				switch (u->state) {
				case UCMD_STATE_PARSING:
				case UCMD_STATE_BUF_ALLOCING:
					TRACE_MGMT_DBG("Aborting ucmd %p", u);
					dev_user_unjam_cmd(u, 0, NULL);
					goto again;
				case UCMD_STATE_EXECING:
					EXTRACHECKS_BUG_ON(1);
				}
			}
		}
		u->state |= UCMD_STATE_SENT_MASK;
	}
	return u;
}

static inline int test_cmd_lists(struct scst_user_dev *dev)
{
	int res = !list_empty(&dev->cmd_lists.active_cmd_list) ||
		  !list_empty(&dev->ready_cmd_list) ||
		  !dev->blocking || dev->cleanup_done ||
		  signal_pending(current);
	return res;
}

/* Called under cmd_lists.cmd_list_lock and IRQ off */
static int dev_user_get_next_cmd(struct scst_user_dev *dev,
	struct scst_user_cmd **ucmd)
{
	int res = 0;
	wait_queue_t wait;

	TRACE_ENTRY();

	init_waitqueue_entry(&wait, current);

	while (1) {
		if (!test_cmd_lists(dev)) {
			add_wait_queue_exclusive(&dev->cmd_lists.cmd_list_waitQ,
				&wait);
			for (;;) {
				set_current_state(TASK_INTERRUPTIBLE);
				if (test_cmd_lists(dev))
					break;
				spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);
				schedule();
				spin_lock_irq(&dev->cmd_lists.cmd_list_lock);
			}
			set_current_state(TASK_RUNNING);
			remove_wait_queue(&dev->cmd_lists.cmd_list_waitQ,
				&wait);
		}

		dev_user_process_scst_commands(dev);

		*ucmd = __dev_user_get_next_cmd(&dev->ready_cmd_list);
		if (*ucmd != NULL)
			break;

		if (!dev->blocking || dev->cleanup_done) {
			res = -EAGAIN;
			TRACE_DBG("No ready commands, returning %d", res);
			break;
		}

		if (signal_pending(current)) {
			res = -EINTR;
			TRACE_DBG("Signal pending, returning %d", res);
			break;
		}
	}

	TRACE_EXIT_RES(res);
	return res;
}

static inline int test_prio_cmd_list(struct scst_user_dev *dev)
{
	/*
	 * Prio queue is always blocking, because poll() seems doesn't
	 * support, when different threads wait with different events
	 * mask. Only one thread is woken up on each event and if it
	 * isn't interested in such events, another (interested) one
	 * will not be woken up. Does't know if it's a bug or feature.
	 */
	int res = !list_empty(&dev->prio_ready_cmd_list) ||
		  dev->cleaning || dev->cleanup_done ||
		  signal_pending(current);
	return res;
}

/* Called under cmd_lists.cmd_list_lock and IRQ off */
static int dev_user_get_next_prio_cmd(struct scst_user_dev *dev,
	struct scst_user_cmd **ucmd)
{
	int res = 0;
	wait_queue_t wait;

	TRACE_ENTRY();

	init_waitqueue_entry(&wait, current);

	while (1) {
		if (!test_prio_cmd_list(dev)) {
			add_wait_queue_exclusive(&dev->prio_cmd_list_waitQ,
				&wait);
			for (;;) {
				set_current_state(TASK_INTERRUPTIBLE);
				if (test_prio_cmd_list(dev))
					break;
				spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);
				schedule();
				spin_lock_irq(&dev->cmd_lists.cmd_list_lock);
			}
			set_current_state(TASK_RUNNING);
			remove_wait_queue(&dev->prio_cmd_list_waitQ, &wait);
		}

		*ucmd = __dev_user_get_next_cmd(&dev->prio_ready_cmd_list);
		if (*ucmd != NULL)
			break;

		if (dev->cleaning || dev->cleanup_done) {
			res = -EAGAIN;
			TRACE_DBG("No ready commands, returning %d", res);
			break;
		}

		if (signal_pending(current)) {
			res = -EINTR;
			TRACE_DBG("Signal pending, returning %d", res);
			break;
		}
	}

	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_reply_get_cmd(struct file *file, unsigned long arg,
	int prio)
{
	int res = 0;
	struct scst_user_dev *dev;
	struct scst_user_get_cmd *cmd;
	struct scst_user_reply_cmd *reply;
	struct scst_user_cmd *ucmd;
	uint64_t ureply;

	TRACE_ENTRY();

	mutex_lock(&dev_priv_mutex);
	dev = (struct scst_user_dev *)file->private_data;
	res = dev_user_check_reg(dev);
	if (res != 0) {
		mutex_unlock(&dev_priv_mutex);
		goto out;
	}
	down_read(&dev->dev_rwsem);
	mutex_unlock(&dev_priv_mutex);

	res = copy_from_user(&ureply, (void *)arg, sizeof(ureply));
	if (res < 0)
		goto out_up;

	TRACE_DBG("ureply %Ld", ureply);

	cmd = kzalloc(max(sizeof(*cmd), sizeof(*reply)), GFP_KERNEL);
	if (cmd == NULL) {
		res = -ENOMEM;
		goto out_up;
	}

	if (ureply != 0) {
		unsigned long u = (unsigned long)ureply;
		reply = (struct scst_user_reply_cmd *)cmd;
		res = copy_from_user(reply, (void *)u, sizeof(*reply));
		if (res < 0)
			goto out_free;

		TRACE_BUFFER("Reply", reply, sizeof(*reply));

		res = dev_user_process_reply(dev, reply);
		if (res < 0)
			goto out_free;
	}

	spin_lock_irq(&dev->cmd_lists.cmd_list_lock);
	if (prio && (dev->prio_queue_type == SCST_USER_PRIO_QUEUE_SEPARATE))
		res = dev_user_get_next_prio_cmd(dev, &ucmd);
	else
		res = dev_user_get_next_cmd(dev, &ucmd);
	if (res == 0) {
		*cmd = ucmd->user_cmd;
		spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);
		TRACE_BUFFER("UCMD", cmd, sizeof(*cmd));
		res = copy_to_user((void *)arg, cmd, sizeof(*cmd));
	} else
		spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);

out_free:
	kfree(cmd);

out_up:
	up_read(&dev->dev_rwsem);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static long dev_user_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg)
{
	long res;

	TRACE_ENTRY();

	switch (cmd) {
	case SCST_USER_REPLY_AND_GET_CMD:
		TRACE_DBG("%s", "REPLY_AND_GET_CMD");
		res = dev_user_reply_get_cmd(file, arg, 0);
		break;

	case SCST_USER_REPLY_CMD:
		TRACE_DBG("%s", "REPLY_CMD");
		res = dev_user_reply_cmd(file, arg);
		break;

	case SCST_USER_REPLY_AND_GET_PRIO_CMD:
		TRACE_DBG("%s", "REPLY_AND_GET_PRIO_CMD");
		res = dev_user_reply_get_cmd(file, arg, 1);
		break;

	case SCST_USER_REGISTER_DEVICE:
	{
		struct scst_user_dev_desc *dev_desc;
		TRACE_DBG("%s", "REGISTER_DEVICE");
		dev_desc = kmalloc(sizeof(*dev_desc), GFP_KERNEL);
		if (dev_desc == NULL) {
			res = -ENOMEM;
			goto out;
		}
		res = copy_from_user(dev_desc, (void *)arg, sizeof(*dev_desc));
		if (res < 0) {
			kfree(dev_desc);
			goto out;
		}
		TRACE_BUFFER("dev_desc", dev_desc, sizeof(*dev_desc));
		dev_desc->name[sizeof(dev_desc->name)-1] = '\0';
		res = dev_user_register_dev(file, dev_desc);
		kfree(dev_desc);
		break;
	}

	case SCST_USER_SET_OPTIONS:
	{
		struct scst_user_opt opt;
		TRACE_DBG("%s", "SET_OPTIONS");
		res = copy_from_user(&opt, (void *)arg, sizeof(opt));
		if (res < 0)
			goto out;
		TRACE_BUFFER("opt", &opt, sizeof(opt));
		res = dev_user_set_opt(file, &opt);
		break;
	}

	case SCST_USER_GET_OPTIONS:
		TRACE_DBG("%s", "GET_OPTIONS");
		res = dev_user_get_opt(file, (void *)arg);
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

static unsigned int dev_user_poll(struct file *file, poll_table *wait)
{
	int res = 0;
	struct scst_user_dev *dev;

	TRACE_ENTRY();

	mutex_lock(&dev_priv_mutex);
	dev = (struct scst_user_dev *)file->private_data;
	res = dev_user_check_reg(dev);
	if (res != 0) {
		mutex_unlock(&dev_priv_mutex);
		goto out;
	}
	down_read(&dev->dev_rwsem);
	mutex_unlock(&dev_priv_mutex);

	spin_lock_irq(&dev->cmd_lists.cmd_list_lock);

	if (!list_empty(&dev->ready_cmd_list) ||
	    !list_empty(&dev->cmd_lists.active_cmd_list)) {
		res |= POLLIN | POLLRDNORM;
		goto out_unlock;
	}

	spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);

	TRACE_DBG("Before poll_wait() (dev %p)", dev);
	poll_wait(file, &dev->cmd_lists.cmd_list_waitQ, wait);
	TRACE_DBG("After poll_wait() (dev %p)", dev);

	spin_lock_irq(&dev->cmd_lists.cmd_list_lock);

	if (!list_empty(&dev->ready_cmd_list) ||
	    !list_empty(&dev->cmd_lists.active_cmd_list)) {
		res |= POLLIN | POLLRDNORM;
		goto out_unlock;
	}

out_unlock:
	spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);

	up_read(&dev->dev_rwsem);

out:
	TRACE_EXIT_HRES(res);
	return res;
}

/*
 * Called under cmd_lists.cmd_list_lock, but can drop it inside, then reaquire.
 */
static void dev_user_unjam_cmd(struct scst_user_cmd *ucmd, int busy,
	unsigned long *flags)
{
	int state = ucmd->state & ~UCMD_STATE_MASK;
	struct scst_user_dev *dev = ucmd->dev;

	TRACE_ENTRY();

	if (ucmd->state & UCMD_STATE_JAMMED_MASK)
		goto out;

	TRACE_MGMT_DBG("Unjamming ucmd %p (busy %d, state %x)", ucmd, busy,
		ucmd->state);

	ucmd->state = state | UCMD_STATE_JAMMED_MASK;

	switch (state) {
	case UCMD_STATE_PARSING:
	case UCMD_STATE_BUF_ALLOCING:
		if (test_bit(SCST_CMD_ABORTED, &ucmd->cmd->cmd_flags))
			ucmd->aborted = 1;
		else {
			if (busy)
				scst_set_busy(ucmd->cmd);
			else
				scst_set_cmd_error(ucmd->cmd,
					SCST_LOAD_SENSE(scst_sense_hardw_error));
		}
		TRACE_MGMT_DBG("Adding ucmd %p to active list", ucmd);
		list_add(&ucmd->cmd->cmd_list_entry,
			&ucmd->cmd->cmd_lists->active_cmd_list);
		wake_up(&ucmd->dev->cmd_lists.cmd_list_waitQ);
		break;

	case UCMD_STATE_EXECING:
		if (flags != NULL)
			spin_unlock_irqrestore(&dev->cmd_lists.cmd_list_lock, *flags);
		else
			spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);

		TRACE_MGMT_DBG("EXEC: unjamming ucmd %p", ucmd);

		if (test_bit(SCST_CMD_ABORTED,	&ucmd->cmd->cmd_flags))
			ucmd->aborted = 1;
		else {
			if (busy)
				scst_set_busy(ucmd->cmd);
			else
				scst_set_cmd_error(ucmd->cmd,
					SCST_LOAD_SENSE(scst_sense_hardw_error));
		}

		ucmd->cmd->scst_cmd_done(ucmd->cmd, SCST_CMD_STATE_DEFAULT);
		/* !! At this point cmd ans ucmd can be already freed !! */

		if (flags != NULL)
			spin_lock_irqsave(&dev->cmd_lists.cmd_list_lock, *flags);
		else
			spin_lock_irq(&dev->cmd_lists.cmd_list_lock);
		break;

	case UCMD_STATE_ON_FREEING:
	case UCMD_STATE_ON_CACHE_FREEING:
	case UCMD_STATE_TM_EXECING:
	case UCMD_STATE_ATTACH_SESS:
	case UCMD_STATE_DETACH_SESS:
	{
		if (flags != NULL)
			spin_unlock_irqrestore(&dev->cmd_lists.cmd_list_lock, *flags);
		else
			spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);

		switch (state) {
		case UCMD_STATE_ON_FREEING:
			dev_user_process_reply_on_free(ucmd);
			break;

		case UCMD_STATE_ON_CACHE_FREEING:
			dev_user_process_reply_on_cache_free(ucmd);
			break;

		case UCMD_STATE_TM_EXECING:
			dev_user_process_reply_tm_exec(ucmd, SCST_MGMT_STATUS_FAILED);
			break;

		case UCMD_STATE_ATTACH_SESS:
		case UCMD_STATE_DETACH_SESS:
			dev_user_process_reply_sess(ucmd, -EFAULT);
			break;
		}

		if (flags != NULL)
			spin_lock_irqsave(&dev->cmd_lists.cmd_list_lock, *flags);
		else
			spin_lock_irq(&dev->cmd_lists.cmd_list_lock);
		break;
	}

	default:
		PRINT_CRIT_ERROR("Wrong ucmd state %x", state);
		sBUG();
		break;
	}

out:
	TRACE_EXIT();
	return;
}

static int __unjam_check_tgt_dev(struct scst_user_cmd *ucmd, int state,
	struct scst_tgt_dev *tgt_dev)
{
	int res = 0;

	if (ucmd->cmd == NULL)
		goto out;

	if (ucmd->cmd->tgt_dev != tgt_dev)
		goto out;

	switch (state & ~UCMD_STATE_MASK) {
	case UCMD_STATE_PARSING:
	case UCMD_STATE_BUF_ALLOCING:
	case UCMD_STATE_EXECING:
		break;
	default:
		goto out;
	}

	res = 1;
out:
	return res;
}

static int __unjam_check_tm(struct scst_user_cmd *ucmd, int state)
{
	int res = 0;

	switch (state & ~UCMD_STATE_MASK) {
	case UCMD_STATE_PARSING:
	case UCMD_STATE_BUF_ALLOCING:
	case UCMD_STATE_EXECING:
		if ((ucmd->cmd != NULL) &&
		    (!test_bit(SCST_CMD_ABORTED,
				&ucmd->cmd->cmd_flags)))
			goto out;
		break;
	default:
		goto out;
	}

	res = 1;
out:
	return res;
}

static void dev_user_unjam_dev(struct scst_user_dev *dev, int tm,
	struct scst_tgt_dev *tgt_dev)
{
	int i;
	unsigned long flags;
	struct scst_user_cmd *ucmd;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Unjamming dev %p", dev);

	spin_lock_irqsave(&dev->cmd_lists.cmd_list_lock, flags);

repeat:
	for (i = 0; i < (int)ARRAY_SIZE(dev->ucmd_hash); i++) {
		struct list_head *head = &dev->ucmd_hash[i];
		list_for_each_entry(ucmd, head, hash_list_entry) {
			TRACE_DBG("ALL: ucmd %p, state %x, scst_cmd %p",
				ucmd, ucmd->state, ucmd->cmd);
			if (ucmd->state & UCMD_STATE_SENT_MASK) {
				int st = ucmd->state & ~UCMD_STATE_SENT_MASK;
				if (tgt_dev != NULL) {
					if (__unjam_check_tgt_dev(ucmd, st,
							tgt_dev) == 0)
						continue;
				} else if (tm) {
					if (__unjam_check_tm(ucmd, st) == 0)
						continue;
				}
				dev_user_unjam_cmd(ucmd, 0, &flags);
				goto repeat;
			}
		}
	}

	if ((tgt_dev != NULL) || tm) {
		list_for_each_entry(ucmd, &dev->ready_cmd_list,
				ready_cmd_list_entry) {
			TRACE_DBG("READY: ucmd %p, state %x, scst_cmd %p",
				ucmd, ucmd->state, ucmd->cmd);
			if (tgt_dev != NULL) {
				if (__unjam_check_tgt_dev(ucmd, ucmd->state,
						tgt_dev) == 0)
					continue;
			} else if (tm) {
				if (__unjam_check_tm(ucmd, ucmd->state) == 0)
					continue;
			}
			list_del(&ucmd->ready_cmd_list_entry);
			dev_user_unjam_cmd(ucmd, 0, &flags);
			goto repeat;
		}
	}

	if (dev_user_process_scst_commands(dev) != 0)
		goto repeat;

	spin_unlock_irqrestore(&dev->cmd_lists.cmd_list_lock, flags);

	TRACE_EXIT();
	return;
}

/**
 ** In order to deal with user space handler hangups we rely on remote
 ** initiators, which in case if a command doesn't respond for too long
 ** supposed to issue a task management command, so on that event we can
 ** "unjam" the command. In order to prevent TM command from stalling, we
 ** use a timer. In order to prevent too many queued TM commands, we
 ** enqueue only 2 of them, the first one with the requested TM function,
 ** the second - with TARGET_RESET as the most comprehensive function.
 **
 ** The only exception here is DETACH_SESS subcode, where there are no TM
 ** commands could be expected, so we need manually after a timeout "unjam"
 ** all the commands on the device.
 **
 ** We also don't queue >1 ATTACH_SESS commands and after timeout fail it.
 **/

static int dev_user_process_reply_tm_exec(struct scst_user_cmd *ucmd,
	int status)
{
	int res = 0;
	unsigned long flags;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("TM reply (ucmd %p, fn %d, status %d)", ucmd,
		ucmd->user_cmd.tm_cmd.fn, status);

	ucmd->result = status;

	spin_lock_irqsave(&ucmd->dev->cmd_lists.cmd_list_lock, flags);

	if (ucmd->internal_reset_tm) {
		TRACE_MGMT_DBG("Internal TM ucmd %p finished", ucmd);
		ucmd->dev->internal_reset_active = 0;
	} else {
		TRACE_MGMT_DBG("TM ucmd %p finished", ucmd);
		ucmd->dev->tm_cmd_active = 0;
	}

	if (ucmd->cmpl != NULL)
		complete_all(ucmd->cmpl);

	spin_unlock_irqrestore(&ucmd->dev->cmd_lists.cmd_list_lock, flags);

	ucmd_put(ucmd);

	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_task_mgmt_fn(struct scst_mgmt_cmd *mcmd,
	struct scst_tgt_dev *tgt_dev)
{
	int res, rc;
	struct scst_user_cmd *ucmd;
	struct scst_user_dev *dev = (struct scst_user_dev *)tgt_dev->dev->dh_priv;
	struct scst_user_cmd *ucmd_to_abort = NULL;

	TRACE_ENTRY();

	/* We can't afford missing TM command due to memory shortage */
	ucmd = dev_user_alloc_ucmd(dev, GFP_KERNEL|__GFP_NOFAIL);
	ucmd->cmpl = kmalloc(sizeof(*ucmd->cmpl), GFP_KERNEL|__GFP_NOFAIL);

	init_completion(ucmd->cmpl);

	ucmd->user_cmd.cmd_h = ucmd->h;
	ucmd->user_cmd.subcode = SCST_USER_TASK_MGMT;
	ucmd->user_cmd.tm_cmd.sess_h = (unsigned long)tgt_dev;
	ucmd->user_cmd.tm_cmd.fn = mcmd->fn;
	ucmd->user_cmd.tm_cmd.cmd_sn = mcmd->cmd_sn;
	ucmd->user_cmd.tm_cmd.cmd_sn_set = mcmd->cmd_sn_set;

	if (mcmd->cmd_to_abort != NULL) {
		ucmd_to_abort = (struct scst_user_cmd *)mcmd->cmd_to_abort->dh_priv;
		if (ucmd_to_abort != NULL)
			ucmd->user_cmd.tm_cmd.cmd_h_to_abort = ucmd_to_abort->h;
	}

	TRACE_MGMT_DBG("Preparing TM ucmd %p (h %d, fn %d, cmd_to_abort %p, "
		"ucmd_to_abort %p, cmd_h_to_abort %d)", ucmd, ucmd->h,
		mcmd->fn, mcmd->cmd_to_abort, ucmd_to_abort,
		ucmd->user_cmd.tm_cmd.cmd_h_to_abort);

	ucmd->state = UCMD_STATE_TM_EXECING;

	spin_lock_irq(&dev->cmd_lists.cmd_list_lock);
	if (dev->internal_reset_active) {
		PRINT_ERROR("Loosing TM cmd %d, because there are other "
			"unprocessed TM commands", mcmd->fn);
		res = SCST_MGMT_STATUS_FAILED;
		goto out_locked_free;
	} else if (dev->tm_cmd_active) {
		/*
		 * We are going to miss some TM commands, so replace it
		 * by the hardest one.
		 */
		PRINT_ERROR("Replacing TM cmd %d by TARGET_RESET, because "
			"there is another unprocessed TM command", mcmd->fn);
		ucmd->user_cmd.tm_cmd.fn = SCST_TARGET_RESET;
		ucmd->internal_reset_tm = 1;
		dev->internal_reset_active = 1;
	} else
		dev->tm_cmd_active = 1;
	spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);

	ucmd_get(ucmd, 0);
	dev_user_add_to_ready(ucmd);

	/*
	 * Since the user space handler should not wait for affecting tasks to
	 * complete it shall complete the TM request ASAP, otherwise the device
	 * will be considered stalled.
	 */
	rc = wait_for_completion_timeout(ucmd->cmpl, DEV_USER_TM_TIMEOUT);
	if (rc > 0)
		res = ucmd->result;
	else {
		PRINT_ERROR("Task management command %p timeout", ucmd);
		res = SCST_MGMT_STATUS_FAILED;
	}

	sBUG_ON(irqs_disabled());

	spin_lock_irq(&dev->cmd_lists.cmd_list_lock);

out_locked_free:
	kfree(ucmd->cmpl);
	ucmd->cmpl = NULL;
	spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);

	dev_user_unjam_dev(ucmd->dev, 1, NULL);

	ucmd_put(ucmd);

	TRACE_EXIT();
	return res;
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
	if (dev == NULL) {
		PRINT_ERROR("Device %s not found", sdev->virt_name);
		res = -EINVAL;
		goto out;
	}

	sdev->p_cmd_lists = &dev->cmd_lists;
	sdev->dh_priv = dev;
	sdev->tst = dev->tst;
	sdev->queue_alg = dev->queue_alg;
	sdev->swp = dev->swp;
	sdev->tas = dev->tas;
	sdev->has_own_order_mgmt = dev->has_own_order_mgmt;

	dev->sdev = sdev;

	PRINT_INFO("Attached user space SCSI target virtual device \"%s\"",
		dev->name);

out:
	TRACE_EXIT();
	return res;
}

static void dev_user_detach(struct scst_device *sdev)
{
	struct scst_user_dev *dev = (struct scst_user_dev *)sdev->dh_priv;

	TRACE_ENTRY();

	TRACE_DBG("virt_id %d", sdev->virt_id);

	PRINT_INFO("Detached user space SCSI target virtual device \"%s\"",
		dev->name);

	/* dev will be freed by the caller */
	sdev->dh_priv = NULL;
	dev->sdev = NULL;

	TRACE_EXIT();
	return;
}

static int dev_user_process_reply_sess(struct scst_user_cmd *ucmd, int status)
{
	int res = 0;
	unsigned long flags;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("ucmd %p, cmpl %p, status %d", ucmd, ucmd->cmpl, status);

	spin_lock_irqsave(&ucmd->dev->cmd_lists.cmd_list_lock, flags);

	if ((ucmd->state & ~UCMD_STATE_MASK) ==
			UCMD_STATE_ATTACH_SESS) {
		TRACE_MGMT_DBG("%s", "ATTACH_SESS finished");
		ucmd->result = status;
		ucmd->dev->attach_cmd_active = 0;
	} else if ((ucmd->state & ~UCMD_STATE_MASK) ==
			UCMD_STATE_DETACH_SESS) {
		TRACE_MGMT_DBG("%s", "DETACH_SESS finished");
		ucmd->dev->detach_cmd_count--;
	} else
		sBUG();

	if (ucmd->cmpl != NULL)
		complete_all(ucmd->cmpl);

	spin_unlock_irqrestore(&ucmd->dev->cmd_lists.cmd_list_lock, flags);

	ucmd_put(ucmd);

	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_attach_tgt(struct scst_tgt_dev *tgt_dev)
{
	struct scst_user_dev *dev =
		(struct scst_user_dev *)tgt_dev->dev->dh_priv;
	int res = 0, rc;
	struct scst_user_cmd *ucmd;

	TRACE_ENTRY();

	ucmd = dev_user_alloc_ucmd(dev, GFP_KERNEL);
	if (ucmd == NULL)
		goto out_nomem;

	ucmd->cmpl = kmalloc(sizeof(*ucmd->cmpl), GFP_KERNEL);
	if (ucmd->cmpl == NULL)
		goto out_put_nomem;

	init_completion(ucmd->cmpl);

	ucmd->user_cmd.cmd_h = ucmd->h;
	ucmd->user_cmd.subcode = SCST_USER_ATTACH_SESS;
	ucmd->user_cmd.sess.sess_h = (unsigned long)tgt_dev;
	ucmd->user_cmd.sess.lun = (uint64_t)tgt_dev->lun;
	ucmd->user_cmd.sess.threads_num = tgt_dev->sess->tgt->tgtt->threads_num;
	ucmd->user_cmd.sess.rd_only = tgt_dev->acg_dev->rd_only_flag;
	strncpy(ucmd->user_cmd.sess.initiator_name,
		tgt_dev->sess->initiator_name,
		sizeof(ucmd->user_cmd.sess.initiator_name)-1);
	ucmd->user_cmd.sess.initiator_name[
		sizeof(ucmd->user_cmd.sess.initiator_name)-1] = '\0';

	TRACE_MGMT_DBG("Preparing ATTACH_SESS %p (h %d, sess_h %Lx, LUN %Lx, "
		"threads_num %d, rd_only_flag %d, initiator %s)", ucmd, ucmd->h,
		ucmd->user_cmd.sess.sess_h, ucmd->user_cmd.sess.lun,
		ucmd->user_cmd.sess.threads_num, ucmd->user_cmd.sess.rd_only,
		ucmd->user_cmd.sess.initiator_name);

	ucmd->state = UCMD_STATE_ATTACH_SESS;

	spin_lock_irq(&dev->cmd_lists.cmd_list_lock);
	if (dev->attach_cmd_active) {
		PRINT_ERROR("%s", "ATTACH_SESS command failed, because "
			"there is another unprocessed ATTACH_SESS command");
		res = -EBUSY;
		goto out_locked_free;
	}
	dev->attach_cmd_active = 1;
	spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);

	ucmd_get(ucmd, 0);
	dev_user_add_to_ready(ucmd);

	rc = wait_for_completion_timeout(ucmd->cmpl, DEV_USER_ATTACH_TIMEOUT);
	if (rc > 0)
		res = ucmd->result;
	else {
		PRINT_ERROR("%s", "ATTACH_SESS command timeout");
		res = -EFAULT;
	}

	sBUG_ON(irqs_disabled());

	spin_lock_irq(&dev->cmd_lists.cmd_list_lock);
out_locked_free:
	kfree(ucmd->cmpl);
	ucmd->cmpl = NULL;
	spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);

	ucmd_put(ucmd);

out:
	TRACE_EXIT_RES(res);
	return res;

out_put_nomem:
	ucmd_put(ucmd);

out_nomem:
	res = -ENOMEM;
	goto out;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void dev_user_pre_unreg_sess_work_fn(void *p)
#else
static void dev_user_pre_unreg_sess_work_fn(struct work_struct *work)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct scst_user_pre_unreg_sess_obj *pd = (struct scst_user_pre_unreg_sess_obj *)p;
#else
	struct scst_user_pre_unreg_sess_obj *pd = container_of(
		(struct delayed_work *)work, struct scst_user_pre_unreg_sess_obj,
		pre_unreg_sess_work);
#endif
	struct scst_user_dev *dev =
		(struct scst_user_dev *)pd->tgt_dev->dev->dh_priv;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Unreg sess: unjaming dev %p (tgt_dev %p)", dev,
		pd->tgt_dev);

	pd->active = 1;

	dev_user_unjam_dev(dev, 0, pd->tgt_dev);

	if (!pd->exit) {
		TRACE_MGMT_DBG("Rescheduling pre_unreg_sess work %p (dev %p, "
			"tgt_dev %p)", pd, dev, pd->tgt_dev);
		schedule_delayed_work(&pd->pre_unreg_sess_work,
			DEV_USER_PRE_UNREG_POLL_TIME);
	}

	TRACE_EXIT();
	return;
}

static void dev_user_pre_unreg_sess(struct scst_tgt_dev *tgt_dev)
{
	struct scst_user_dev *dev =
		(struct scst_user_dev *)tgt_dev->dev->dh_priv;
	struct scst_user_pre_unreg_sess_obj *pd;

	TRACE_ENTRY();

	/* We can't afford missing DETACH command due to memory shortage */
	pd = kzalloc(sizeof(*pd), GFP_KERNEL|__GFP_NOFAIL);

	pd->tgt_dev = tgt_dev;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	INIT_WORK(&pd->pre_unreg_sess_work, dev_user_pre_unreg_sess_work_fn, pd);
#else
	INIT_DELAYED_WORK(&pd->pre_unreg_sess_work, dev_user_pre_unreg_sess_work_fn);
#endif

	spin_lock_irq(&dev->cmd_lists.cmd_list_lock);
	dev->pre_unreg_sess_active = 1;
	list_add_tail(&pd->pre_unreg_sess_list_entry, &dev->pre_unreg_sess_list);
	spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);

	TRACE_MGMT_DBG("Scheduling pre_unreg_sess work %p (dev %p, tgt_dev %p)",
		pd, dev, pd->tgt_dev);

	schedule_delayed_work(&pd->pre_unreg_sess_work, DEV_USER_DETACH_TIMEOUT);

	TRACE_EXIT();
	return;
}

static void dev_user_detach_tgt(struct scst_tgt_dev *tgt_dev)
{
	struct scst_user_dev *dev =
		(struct scst_user_dev *)tgt_dev->dev->dh_priv;
	struct scst_user_cmd *ucmd;
	struct scst_user_pre_unreg_sess_obj *pd = NULL, *p;

	TRACE_ENTRY();

	spin_lock_irq(&dev->cmd_lists.cmd_list_lock);
	list_for_each_entry(p, &dev->pre_unreg_sess_list,
			pre_unreg_sess_list_entry) {
		if (p->tgt_dev == tgt_dev) {
			list_del(&p->pre_unreg_sess_list_entry);
			if (list_empty(&dev->pre_unreg_sess_list))
				dev->pre_unreg_sess_active = 0;
			pd = p;
			break;
		}
	}
	spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);

	if (pd != NULL) {
		pd->exit = 1;
		TRACE_MGMT_DBG("Canceling pre unreg work %p", pd);
		cancel_delayed_work(&pd->pre_unreg_sess_work);
		flush_scheduled_work();
		kfree(pd);
	}

	ucmd = dev_user_alloc_ucmd(dev, GFP_KERNEL);
	if (ucmd == NULL)
		goto out;

	TRACE_MGMT_DBG("Preparing DETACH_SESS %p (h %d, sess_h %Lx)", ucmd,
		ucmd->h, ucmd->user_cmd.sess.sess_h);

	ucmd->user_cmd.cmd_h = ucmd->h;
	ucmd->user_cmd.subcode = SCST_USER_DETACH_SESS;
	ucmd->user_cmd.sess.sess_h = (unsigned long)tgt_dev;

	spin_lock_irq(&dev->cmd_lists.cmd_list_lock);
	dev->detach_cmd_count++;
	spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);

	ucmd->state = UCMD_STATE_DETACH_SESS;

	dev_user_add_to_ready(ucmd);

out:
	TRACE_EXIT();
	return;
}

/* No locks are needed, but the activity must be suspended */
static void dev_user_setup_functions(struct scst_user_dev *dev)
{
	TRACE_ENTRY();

	dev->devtype.parse = dev_user_parse;
	dev->devtype.dev_done = NULL;

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
			PRINT_INFO("Unknown SCSI type %x, using PARSE_CALL "
				"for it", dev->devtype.type);
			dev->parse_type = SCST_USER_PARSE_CALL;
			break;
		}
	} else {
		dev->generic_parse = NULL;
		dev->devtype.dev_done = NULL;
	}

	TRACE_EXIT();
	return;
}

static int dev_user_check_version(const struct scst_user_dev_desc *dev_desc)
{
	char ver[sizeof(DEV_USER_VERSION)+1];
	int res;

	res = copy_from_user(ver, (void *)(unsigned long)dev_desc->version_str,
				sizeof(ver));
	if (res < 0) {
		PRINT_ERROR("%s", "Unable to get version string");
		goto out;
	}
	ver[sizeof(ver)-1] = '\0';

	if (strcmp(ver, DEV_USER_VERSION) != 0) {
		/* ->name already 0-terminated in dev_user_ioctl() */
		PRINT_ERROR("Incorrect version of user device %s (%s)",
			dev_desc->name, ver);
		res = -EINVAL;
		goto out;
	}

out:
	return res;
}

static int dev_user_register_dev(struct file *file,
	const struct scst_user_dev_desc *dev_desc)
{
	int res = -ENOMEM, i;
	struct scst_user_dev *dev, *d;
	int block;

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
		block = scst_calc_block_shift(dev_desc->block_size);
		if (block == -1) {
			res = -EINVAL;
			goto out;
		}
		break;
	default:
		block = dev_desc->block_size;
		break;
	}

	if (!try_module_get(THIS_MODULE)) {
		PRINT_ERROR("%s", "Fail to get module");
		goto out;
	}

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (dev == NULL)
		goto out_put;

	init_rwsem(&dev->dev_rwsem);
	spin_lock_init(&dev->cmd_lists.cmd_list_lock);
	INIT_LIST_HEAD(&dev->cmd_lists.active_cmd_list);
	init_waitqueue_head(&dev->cmd_lists.cmd_list_waitQ);
	INIT_LIST_HEAD(&dev->ready_cmd_list);
	INIT_LIST_HEAD(&dev->prio_ready_cmd_list);
	init_waitqueue_head(&dev->prio_cmd_list_waitQ);
	if (file->f_flags & O_NONBLOCK) {
		TRACE_DBG("%s", "Non-blocking operations");
		dev->blocking = 0;
	} else
		dev->blocking = 1;
	for (i = 0; i < (int)ARRAY_SIZE(dev->ucmd_hash); i++)
		INIT_LIST_HEAD(&dev->ucmd_hash[i]);
	INIT_LIST_HEAD(&dev->pre_unreg_sess_list);

	strncpy(dev->name, dev_desc->name, sizeof(dev->name)-1);
	dev->name[sizeof(dev->name)-1] = '\0';

	/*
	 * We don't use clustered pool, since it implies pages reordering,
	 * which isn't possible with user space supplied buffers. Although
	 * it's still possible to cluster pages by the tail of each other,
	 * seems it doesn't worth the effort.
	 */
	dev->pool = sgv_pool_create(dev->name, 0);
	if (dev->pool == NULL)
		goto out_put;
	sgv_pool_set_allocator(dev->pool, dev_user_alloc_pages,
		dev_user_free_sg_entries);

	scnprintf(dev->devtype.name, sizeof(dev->devtype.name), "dh-%s",
		dev->name);
	dev->devtype.type = dev_desc->type;
	dev->devtype.threads_num = -1;
	dev->devtype.parse_atomic = 1;
	dev->devtype.exec_atomic = 0; /* no point to make it 1 */
	dev->devtype.dev_done_atomic = 1;
	dev->devtype.no_proc = 1;
	dev->devtype.attach = dev_user_attach;
	dev->devtype.detach = dev_user_detach;
	dev->devtype.attach_tgt = dev_user_attach_tgt;
	dev->devtype.pre_unreg_sess = dev_user_pre_unreg_sess;
	dev->devtype.detach_tgt = dev_user_detach_tgt;
	dev->devtype.exec = dev_user_exec;
	dev->devtype.on_free_cmd = dev_user_on_free_cmd;
	dev->devtype.task_mgmt_fn = dev_user_task_mgmt_fn;

	init_completion(&dev->cleanup_cmpl);
	dev->block = block;
	dev->def_block = dev->block;

	res = __dev_user_set_opt(dev, &dev_desc->opt);

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

	if (res != 0)
		goto out_del_free;

	res = scst_register_virtual_dev_driver(&dev->devtype);
	if (res < 0)
		goto out_del_free;

	dev->virt_id = scst_register_virtual_device(&dev->devtype, dev->name);
	if (dev->virt_id < 0) {
		res = dev->virt_id;
		goto out_unreg_handler;
	}

	mutex_lock(&dev_priv_mutex);
	if (file->private_data != NULL) {
		mutex_unlock(&dev_priv_mutex);
		PRINT_ERROR("%s", "Device already registered");
		res = -EINVAL;
		goto out_unreg_drv;
	}
	file->private_data = dev;
	mutex_unlock(&dev_priv_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;

out_unreg_drv:
	scst_unregister_virtual_device(dev->virt_id);

out_unreg_handler:
	scst_unregister_virtual_dev_driver(&dev->devtype);

out_del_free:
	spin_lock(&dev_list_lock);
	list_del(&dev->dev_list_entry);
	spin_unlock(&dev_list_lock);

out_free:
	sgv_pool_destroy(dev->pool);
	kfree(dev);
	goto out_put;

out_put:
	module_put(THIS_MODULE);
	goto out;
}

static int __dev_user_set_opt(struct scst_user_dev *dev,
	const struct scst_user_opt *opt)
{
	int res = 0;

	TRACE_ENTRY();

	TRACE_DBG("parse_type %x, on_free_cmd_type %x, memory_reuse_type %x, "
		"partial_transfers_type %x, partial_len %d", opt->parse_type,
		opt->on_free_cmd_type, opt->memory_reuse_type,
		opt->partial_transfers_type, opt->partial_len);

	if ((opt->parse_type > SCST_USER_MAX_PARSE_OPT) ||
	    (opt->on_free_cmd_type > SCST_USER_MAX_ON_FREE_CMD_OPT) ||
	    (opt->memory_reuse_type > SCST_USER_MAX_MEM_REUSE_OPT) ||
	    (opt->prio_queue_type > SCST_USER_MAX_PRIO_QUEUE_OPT) ||
	    (opt->partial_transfers_type > SCST_USER_MAX_PARTIAL_TRANSFERS_OPT)) {
		PRINT_ERROR("%s", "Invalid option");
		res = -EINVAL;
		goto out;
	}

	if (((opt->tst != SCST_CONTR_MODE_ONE_TASK_SET) &&
	     (opt->tst != SCST_CONTR_MODE_SEP_TASK_SETS)) ||
	    ((opt->queue_alg != SCST_CONTR_MODE_QUEUE_ALG_RESTRICTED_REORDER) &&
	     (opt->queue_alg != SCST_CONTR_MODE_QUEUE_ALG_UNRESTRICTED_REORDER)) ||
	    (opt->swp > 1) || (opt->tas > 1) || (opt->has_own_order_mgmt > 1)) {
		PRINT_ERROR("Invalid SCSI option (tst %x, queue_alg %x, swp %x, "
			"tas %x, has_own_order_mgmt %x)", opt->tst,
			opt->queue_alg, opt->swp, opt->tas, opt->has_own_order_mgmt);
		res = -EINVAL;
		goto out;
	}

	if ((dev->prio_queue_type != opt->prio_queue_type) &&
	    (opt->prio_queue_type == SCST_USER_PRIO_QUEUE_SINGLE)) {
		struct scst_user_cmd *u, *t;
		/* No need for lock, the activity is suspended */
		list_for_each_entry_safe(u, t, &dev->prio_ready_cmd_list,
				ready_cmd_list_entry) {
			list_move_tail(&u->ready_cmd_list_entry,
				&dev->ready_cmd_list);
		}
	}

	dev->prio_queue_type = opt->prio_queue_type;
	dev->parse_type = opt->parse_type;
	dev->on_free_cmd_type = opt->on_free_cmd_type;
	dev->memory_reuse_type = opt->memory_reuse_type;
	dev->partial_transfers_type = opt->partial_transfers_type;
	dev->partial_len = opt->partial_len;

	dev->tst = opt->tst;
	dev->queue_alg = opt->queue_alg;
	dev->swp = opt->swp;
	dev->tas = opt->tas;
	dev->has_own_order_mgmt = opt->has_own_order_mgmt;
	if (dev->sdev != NULL) {
		dev->sdev->tst = opt->tst;
		dev->sdev->queue_alg = opt->queue_alg;
		dev->sdev->swp = opt->swp;
		dev->sdev->tas = opt->tas;
		dev->sdev->has_own_order_mgmt = opt->has_own_order_mgmt;
	}

	dev_user_setup_functions(dev);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_set_opt(struct file *file, const struct scst_user_opt *opt)
{
	int res = 0;
	struct scst_user_dev *dev;

	TRACE_ENTRY();

	mutex_lock(&dev_priv_mutex);
	dev = (struct scst_user_dev *)file->private_data;
	res = dev_user_check_reg(dev);
	if (res != 0) {
		mutex_unlock(&dev_priv_mutex);
		goto out;
	}
	down_read(&dev->dev_rwsem);
	mutex_unlock(&dev_priv_mutex);

	scst_suspend_activity();
	res = __dev_user_set_opt(dev, opt);
	scst_resume_activity();

	up_read(&dev->dev_rwsem);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int dev_user_get_opt(struct file *file, void *arg)
{
	int res = 0;
	struct scst_user_dev *dev;
	struct scst_user_opt opt;

	TRACE_ENTRY();

	mutex_lock(&dev_priv_mutex);
	dev = (struct scst_user_dev *)file->private_data;
	res = dev_user_check_reg(dev);
	if (res != 0) {
		mutex_unlock(&dev_priv_mutex);
		goto out;
	}
	down_read(&dev->dev_rwsem);
	mutex_unlock(&dev_priv_mutex);

	opt.parse_type = dev->parse_type;
	opt.on_free_cmd_type = dev->on_free_cmd_type;
	opt.memory_reuse_type = dev->memory_reuse_type;
	opt.prio_queue_type = dev->prio_queue_type;
	opt.partial_transfers_type = dev->partial_transfers_type;
	opt.partial_len = dev->partial_len;
	opt.tst = dev->tst;
	opt.queue_alg = dev->queue_alg;
	opt.tas = dev->tas;
	opt.swp = dev->swp;
	opt.has_own_order_mgmt = dev->has_own_order_mgmt;

	TRACE_DBG("parse_type %x, on_free_cmd_type %x, memory_reuse_type %x, "
		"partial_transfers_type %x, partial_len %d", opt.parse_type,
		opt.on_free_cmd_type, opt.memory_reuse_type,
		opt.partial_transfers_type, opt.partial_len);

	res = copy_to_user(arg, &opt, sizeof(opt));

	up_read(&dev->dev_rwsem);
out:
	TRACE_EXIT_RES(res);
	return res;
}

static int dev_usr_parse(struct scst_cmd *cmd)
{
	sBUG();
	return SCST_CMD_STATE_DEFAULT;
}

/* Needed only for /proc support */
#define USR_TYPE {			\
	.name =		DEV_USER_NAME,	\
	.type =		-1,		\
	.parse =	dev_usr_parse,	\
}

static struct scst_dev_type dev_user_devtype = USR_TYPE;

static int dev_user_release(struct inode *inode, struct file *file)
{
	int res = 0;
	struct scst_user_dev *dev;

	TRACE_ENTRY();

	mutex_lock(&dev_priv_mutex);
	dev = (struct scst_user_dev *)file->private_data;
	if (dev == NULL) {
		mutex_unlock(&dev_priv_mutex);
		goto out;
	}
	file->private_data = NULL;

	TRACE(TRACE_MGMT, "Releasing dev %s", dev->name);

	spin_lock(&dev_list_lock);
	list_del(&dev->dev_list_entry);
	spin_unlock(&dev_list_lock);

	mutex_unlock(&dev_priv_mutex);

	down_write(&dev->dev_rwsem);

	spin_lock(&cleanup_lock);
	list_add_tail(&dev->cleanup_list_entry, &cleanup_list);
	spin_unlock(&cleanup_lock);

	wake_up(&cleanup_list_waitQ);
	wake_up(&dev->prio_cmd_list_waitQ);
	wake_up(&dev->cmd_lists.cmd_list_waitQ);

	scst_unregister_virtual_device(dev->virt_id);
	scst_unregister_virtual_dev_driver(&dev->devtype);

	sgv_pool_destroy(dev->pool);

	TRACE_DBG("Unregistering finished (dev %p)", dev);

	dev->cleanup_done = 1;
	wake_up(&cleanup_list_waitQ);
	wake_up(&dev->prio_cmd_list_waitQ);
	wake_up(&dev->cmd_lists.cmd_list_waitQ);
	wait_for_completion(&dev->cleanup_cmpl);

	up_write(&dev->dev_rwsem); /* to make the debug check happy */

	TRACE_DBG("Releasing completed (dev %p)", dev);

	kfree(dev);

	module_put(THIS_MODULE);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void dev_user_process_cleanup(struct scst_user_dev *dev)
{
	struct scst_user_cmd *ucmd;
	int rc;

	TRACE_ENTRY();

	dev->prio_queue_type = SCST_USER_PRIO_QUEUE_SINGLE;
	dev->cleaning = 1;
	dev->blocking = 1;

	while (1) {
		TRACE_DBG("Cleanuping dev %p", dev);

		dev_user_unjam_dev(dev, 0, NULL);

		spin_lock_irq(&dev->cmd_lists.cmd_list_lock);
		rc = dev_user_get_next_prio_cmd(dev, &ucmd);
		if (rc != 0)
			rc = dev_user_get_next_cmd(dev, &ucmd);
		if (rc == 0)
			dev_user_unjam_cmd(ucmd, 1, NULL);
		spin_unlock_irq(&dev->cmd_lists.cmd_list_lock);
		if ((rc == -EAGAIN) && dev->cleanup_done)
			break;
	}

#ifdef EXTRACHECKS
{
	int i;
	for (i = 0; i < (int)ARRAY_SIZE(dev->ucmd_hash); i++) {
		struct list_head *head = &dev->ucmd_hash[i];
		struct scst_user_cmd *ucmd, *t;
		list_for_each_entry_safe(ucmd, t, head, hash_list_entry) {
			PRINT_ERROR("Lost ucmd %p (state %x, ref %d)", ucmd,
				ucmd->state, atomic_read(&ucmd->ucmd_ref));
			ucmd_put(ucmd);
		}
	}
}
#endif

	TRACE_DBG("Cleanuping done (dev %p)", dev);
	complete_all(&dev->cleanup_cmpl);

	TRACE_EXIT();
	return;
}

static inline int test_cleanup_list(void)
{
	int res = !list_empty(&cleanup_list) ||
		  unlikely(kthread_should_stop());
	return res;
}

static int dev_user_cleanup_thread(void *arg)
{
	struct scst_user_dev *dev;

	TRACE_ENTRY();

	PRINT_INFO("Cleanup thread started, PID %d", current->pid);

	current->flags |= PF_NOFREEZE;

	spin_lock(&cleanup_lock);
	while (!kthread_should_stop()) {
		wait_queue_t wait;
		init_waitqueue_entry(&wait, current);

		if (!test_cleanup_list()) {
			add_wait_queue_exclusive(&cleanup_list_waitQ, &wait);
			for (;;) {
				set_current_state(TASK_INTERRUPTIBLE);
				if (test_cleanup_list())
					break;
				spin_unlock(&cleanup_lock);
				schedule();
				spin_lock(&cleanup_lock);
			}
			set_current_state(TASK_RUNNING);
			remove_wait_queue(&cleanup_list_waitQ, &wait);
		}
restart:
		list_for_each_entry(dev, &cleanup_list, cleanup_list_entry) {
			list_del(&dev->cleanup_list_entry);
			spin_unlock(&cleanup_lock);
			dev_user_process_cleanup(dev);
			spin_lock(&cleanup_lock);
			goto restart;
		}
	}
	spin_unlock(&cleanup_lock);

	/*
	 * If kthread_should_stop() is true, we are guaranteed to be
	 * on the module unload, so cleanup_list must be empty.
	 */
	sBUG_ON(!list_empty(&cleanup_list));

	PRINT_INFO("Cleanup thread PID %d finished", current->pid);

	TRACE_EXIT();
	return 0;
}

static int __init init_scst_user(void)
{
	int res = 0;
	struct class_device *class_member;

	TRACE_ENTRY();

#if defined(CONFIG_HIGHMEM4G) || defined(CONFIG_HIGHMEM64G)
	PRINT_ERROR("%s", "HIGHMEM kernel configurations are not supported. "
		"Consider change VMSPLIT option or use 64-bit "
		"configuration instead. See README file for details.");
	res = -EINVAL;
	goto out;
#endif

	user_cmd_cachep = KMEM_CACHE(scst_user_cmd, SCST_SLAB_FLAGS);
	if (user_cmd_cachep == NULL) {
		res = -ENOMEM;
		goto out;
	}

	dev_user_devtype.module = THIS_MODULE;

	res = scst_register_virtual_dev_driver(&dev_user_devtype);
	if (res < 0)
		goto out_cache;

	res = scst_dev_handler_build_std_proc(&dev_user_devtype);
	if (res != 0)
		goto out_unreg;

	dev_user_sysfs_class = class_create(THIS_MODULE, DEV_USER_NAME);
	if (IS_ERR(dev_user_sysfs_class)) {
		PRINT_ERROR("%s", "Unable create sysfs class for SCST user "
			"space handler");
		res = PTR_ERR(dev_user_sysfs_class);
		goto out_proc;
	}

	res = register_chrdev(DEV_USER_MAJOR, DEV_USER_NAME, &dev_user_fops);
	if (res) {
		PRINT_ERROR("Unable to get major %d for SCSI tapes", DEV_USER_MAJOR);
		goto out_class;
	}

	class_member = class_device_create(dev_user_sysfs_class, NULL,
		MKDEV(DEV_USER_MAJOR, 0), NULL, DEV_USER_NAME);
	if (IS_ERR(class_member)) {
		res = PTR_ERR(class_member);
		goto out_chrdev;
	}

	cleanup_thread = kthread_run(dev_user_cleanup_thread, NULL,
		"scst_usr_cleanupd");
	if (IS_ERR(cleanup_thread)) {
		res = PTR_ERR(cleanup_thread);
		PRINT_ERROR("kthread_create() failed: %d", res);
		goto out_dev;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_dev:
	class_device_destroy(dev_user_sysfs_class, MKDEV(DEV_USER_MAJOR, 0));

out_chrdev:
	unregister_chrdev(DEV_USER_MAJOR, DEV_USER_NAME);

out_class:
	class_destroy(dev_user_sysfs_class);

out_proc:
	scst_dev_handler_destroy_std_proc(&dev_user_devtype);

out_unreg:
	scst_unregister_dev_driver(&dev_user_devtype);

out_cache:
	kmem_cache_destroy(user_cmd_cachep);
	goto out;
}

static void __exit exit_scst_user(void)
{
	int rc;

	TRACE_ENTRY();

	rc = kthread_stop(cleanup_thread);
	if (rc < 0)
		TRACE_MGMT_DBG("kthread_stop() failed: %d", rc);

	unregister_chrdev(DEV_USER_MAJOR, DEV_USER_NAME);
	class_device_destroy(dev_user_sysfs_class, MKDEV(DEV_USER_MAJOR, 0));
	class_destroy(dev_user_sysfs_class);

	scst_dev_handler_destroy_std_proc(&dev_user_devtype);
	scst_unregister_virtual_dev_driver(&dev_user_devtype);

	kmem_cache_destroy(user_cmd_cachep);

	TRACE_EXIT();
	return;
}

module_init(init_scst_user);
module_exit(exit_scst_user);

MODULE_AUTHOR("Vladislav Bolkhovitin");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Virtual user space device handler for SCST");
MODULE_VERSION(SCST_VERSION_STRING);
MODULE_ALIAS_CHARDEV_MAJOR(DEV_USER_MAJOR);
