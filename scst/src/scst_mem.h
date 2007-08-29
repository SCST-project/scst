/*
 *  scst_mem.h
 *  
 *  Copyright (C) 2006-2007 Vladislav Bolkhovitin <vst@vlnb.net>
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

#include <asm/scatterlist.h>

#define SGV_POOL_ELEMENTS	11

#if defined(DEBUG) && defined(CONFIG_DEBUG_SLAB)
#define SCST_SLAB_FLAGS ( SLAB_RED_ZONE | SLAB_POISON )
#else
#define SCST_SLAB_FLAGS 0L
#endif

/* 
 * sg_num is indexed by the page number, pg_count is indexed by the sg number.
 * Made in one entry to simplify the code (eg all sizeof(*) parts) and save
 * some CPU cache for non-clustered case.
 */
struct trans_tbl_ent {
	unsigned short sg_num;
	unsigned short pg_count;
};

struct sgv_pool_obj
{
	struct kmem_cache *owner_cache;
	struct sgv_pool *owner_pool;
	int orig_sg;
	int orig_length;
	int sg_count;
	void *allocator_priv;
	struct trans_tbl_ent *trans_tbl;
	struct scatterlist *sg_entries;
	struct scatterlist sg_entries_data[0];
};

struct sgv_pool_acc
{
	atomic_t total_alloc, hit_alloc;
};

struct sgv_pool_alloc_fns
{
	struct page *(*alloc_pages_fn)(struct scatterlist *sg, gfp_t gfp_mask,
		void *priv);
	void (*free_pages_fn)(struct scatterlist *sg, int sg_count,
		void *priv);
};

struct sgv_pool
{
	unsigned int clustered;
	struct sgv_pool_alloc_fns alloc_fns;
	/* 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048 */
	struct kmem_cache *caches[SGV_POOL_ELEMENTS];

	atomic_t big_alloc, other_alloc;
	struct sgv_pool_acc acc;
	struct sgv_pool_acc cache_acc[SGV_POOL_ELEMENTS];

	char cache_names[SGV_POOL_ELEMENTS][25];
	char name[25];
	struct list_head sgv_pool_list_entry;
};

struct scst_sgv_pools
{
	struct sgv_pool norm_clust, norm;
	struct sgv_pool dma;
#ifdef SCST_HIGHMEM
	struct sgv_pool highmem;
#endif
};

extern atomic_t sgv_other_total_alloc;
extern struct mutex scst_sgv_pool_mutex;
extern struct list_head scst_sgv_pool_list; 

int sgv_pool_init(struct sgv_pool *pool, const char *name, 
	int clustered);
void sgv_pool_deinit(struct sgv_pool *pool);

static inline struct scatterlist *sgv_pool_sg(struct sgv_pool_obj *obj)
{
	return obj->sg_entries;
}

extern int scst_sgv_pools_init(struct scst_sgv_pools *pools);
extern void scst_sgv_pools_deinit(struct scst_sgv_pools *pools);
