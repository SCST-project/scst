/*
 *  scst_mem.h
 *
 *  Copyright (C) 2006 - 2013 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
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

#include <linux/scatterlist.h>
#include <linux/workqueue.h>

#define SGV_POOL_ELEMENTS	11

/*
 * sg_num is indexed by the page number, pg_count is indexed by the sg number.
 * Made in one entry to simplify the code (eg all sizeof(*) parts) and save
 * some CPU cache for non-clustered case.
 */
struct trans_tbl_ent {
	unsigned short sg_num;
	unsigned short pg_count;
};

/*
 * SGV pool object
 */
struct sgv_pool_obj {
	int cache_num;
	int pages;

	/* jiffies, protected by sgv_pool_lock */
	unsigned long time_stamp;

	struct list_head recycling_list_entry;
	struct list_head sorted_recycling_list_entry;

	struct sgv_pool *owner_pool;
	int orig_sg;
	int orig_length;
	int sg_count;
	void *allocator_priv;
	struct trans_tbl_ent *trans_tbl;
	struct scatterlist *sg_entries;
	struct scatterlist sg_entries_data[0];
};

/*
 * SGV pool statistics accounting structure
 */
struct sgv_pool_cache_acc {
	atomic_t total_alloc, hit_alloc;
	atomic_t merged;
};

/*
 * SGV pool allocation functions
 */
struct sgv_pool_alloc_fns {
	struct page *(*alloc_pages_fn)(struct scatterlist *sg, gfp_t gfp_mask,
		void *priv);
	void (*free_pages_fn)(struct scatterlist *sg, int sg_count,
		void *priv);
}
#ifdef CONSTIFY_PLUGIN
/* Avoid that the Grsecurity gcc constify_plugin constifies this structure. */
__attribute__((no_const))
#endif
;

/*
 * SGV pool
 */
struct sgv_pool {
	enum sgv_clustering_types clustering_type;
	int single_alloc_pages;
	int max_cached_pages;

	struct sgv_pool_alloc_fns alloc_fns;

	/* <=4K, <=8, <=16, <=32, <=64, <=128, <=256, <=512, <=1024, <=2048 */
	struct kmem_cache *caches[SGV_POOL_ELEMENTS];

	spinlock_t sgv_pool_lock; /* outer lock for sgv_pools_lock! */

	int purge_interval;

	/* Protected by sgv_pool_lock, if necessary */
	unsigned int purge_work_scheduled:1;

	/* Protected by sgv_pool_lock */
	struct list_head sorted_recycling_list;

	int inactive_cached_pages; /* protected by sgv_pool_lock */

	/* Protected by sgv_pool_lock */
	struct list_head recycling_lists[SGV_POOL_ELEMENTS];

	int cached_pages, cached_entries; /* protected by sgv_pool_lock */

	struct sgv_pool_cache_acc cache_acc[SGV_POOL_ELEMENTS];

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20))
	struct delayed_work sgv_purge_work;
#else
	struct work_struct sgv_purge_work;
#endif

	struct list_head sgv_active_pools_list_entry;

	atomic_t big_alloc, big_pages, big_merged;
	atomic_t other_alloc, other_pages, other_merged;

	atomic_t sgv_pool_ref;

	int max_caches;

	/* SCST_MAX_NAME + few more bytes to match scst_user expectations */
	char cache_names[SGV_POOL_ELEMENTS][SCST_MAX_NAME + 10];
	char name[SCST_MAX_NAME + 10];

	struct mm_struct *owner_mm;

	struct list_head sgv_pools_list_entry;

	struct kobject sgv_kobj;

	/* sysfs release completion */
	struct completion *sgv_kobj_release_cmpl;
};

static inline struct scatterlist *sgv_pool_sg(struct sgv_pool_obj *obj)
{
	return obj->sg_entries;
}

int scst_sgv_pools_init(unsigned long mem_hwmark, unsigned long mem_lwmark);
void scst_sgv_pools_deinit(void);

#ifdef CONFIG_SCST_PROC
int sgv_procinfo_show(struct seq_file *seq, void *v);
#endif

void scst_sgv_pool_use_norm(struct scst_tgt_dev *tgt_dev);
void scst_sgv_pool_use_norm_clust(struct scst_tgt_dev *tgt_dev);
void scst_sgv_pool_use_dma(struct scst_tgt_dev *tgt_dev);
