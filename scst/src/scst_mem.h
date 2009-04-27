/*
 *  scst_mem.h
 *
 *  Copyright (C) 2006 - 2009 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2007 Krzysztof Blaszkowski <kb@sysmikro.com.pl>
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

#include <linux/scatterlist.h>
#include <linux/workqueue.h>
#include <linux/seq_file.h>

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

struct sgv_pool_obj {
	/* if <0 - pages, >0 - order */
	int order_or_pages;

	struct {
		/* jiffies, protected by pool_mgr_lock */
		unsigned long time_stamp;
		struct list_head recycling_list_entry;
		struct list_head sorted_recycling_list_entry;
	} recycle_entry;

	struct sgv_pool *owner_pool;
	int orig_sg;
	int orig_length;
	int sg_count;
	void *allocator_priv;
	struct trans_tbl_ent *trans_tbl;
	struct scatterlist *sg_entries;
	struct scatterlist sg_entries_data[0];
};

struct sgv_pool_acc {
	u32 cached_pages, cached_entries;
	atomic_t big_alloc, other_alloc;
	atomic_t big_pages, other_pages;
	atomic_t big_merged, other_merged;
};

struct sgv_pool_cache_acc {
	atomic_t total_alloc, hit_alloc;
	atomic_t merged;
};

struct sgv_pool_alloc_fns {
	struct page *(*alloc_pages_fn)(struct scatterlist *sg, gfp_t gfp_mask,
		void *priv);
	void (*free_pages_fn)(struct scatterlist *sg, int sg_count,
		void *priv);
};

struct sgv_pool {
	enum sgv_clustering_types clustering_type;
	struct sgv_pool_alloc_fns alloc_fns;
	/* 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048 */
	struct kmem_cache *caches[SGV_POOL_ELEMENTS];

	/* protected by pool_mgr_lock */
	struct list_head recycling_lists[SGV_POOL_ELEMENTS];

	struct sgv_pool_acc acc;
	struct sgv_pool_cache_acc cache_acc[SGV_POOL_ELEMENTS];

	/* SCST_MAX_NAME + few more bytes to match scst_user expectations */
	char cache_names[SGV_POOL_ELEMENTS][SCST_MAX_NAME + 10];
	char name[SCST_MAX_NAME + 10];
	struct list_head sgv_pool_list_entry;
};

struct scst_sgv_pools_manager {
	struct {
		struct sgv_pool norm_clust, norm;
		struct sgv_pool dma;
	} default_set;

	struct sgv_pool_mgr {
		spinlock_t pool_mgr_lock;
		/* protected by pool_mgr_lock */
		struct list_head sorted_recycling_list;
		/* protected by pool_mgr_lock */
		unsigned pitbool_running:1;

		struct sgv_mem_throttling {
			u32 inactive_pages_total;
			u32 active_pages_total;

			/*
			 * compared against inactive_pages_total +
			 *		    active_pages_total
			 */
			u32 hi_wmk;
			/* compared against inactive_pages_total only */
			u32 lo_wmk;

			u32 releases_on_hiwmk;
			u32 releases_failed;
		} throttle; /* protected by pool_mgr_lock */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23))
		struct shrinker *sgv_shrinker;
#else
		struct shrinker sgv_shrinker;
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20))
		struct delayed_work apit_pool;
#else
		struct work_struct apit_pool;
#endif
	} mgr;

	int sgv_max_local_order, sgv_max_trans_order;

	atomic_t sgv_other_total_alloc;
	struct mutex scst_sgv_pool_mutex;
	struct list_head scst_sgv_pool_list;
};

int sgv_pool_init(struct sgv_pool *pool, const char *name,
	enum sgv_clustering_types clustering_type);
void sgv_pool_deinit(struct sgv_pool *pool);

static inline struct scatterlist *sgv_pool_sg(struct sgv_pool_obj *obj)
{
	return obj->sg_entries;
}

extern int scst_sgv_pools_init(unsigned long mem_hwmark,
			       unsigned long mem_lwmark);
extern void scst_sgv_pools_deinit(void);
extern int sgv_pool_procinfo_show(struct seq_file *seq, void *v);

void scst_sgv_pool_use_norm(struct scst_tgt_dev *tgt_dev);
void scst_sgv_pool_use_norm_clust(struct scst_tgt_dev *tgt_dev);
void scst_sgv_pool_use_dma(struct scst_tgt_dev *tgt_dev);
