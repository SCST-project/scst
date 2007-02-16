/*
 *  scst_sgv_pool.h
 *  
 *  Copyright (C) 2006 Vladislav Bolkhovitin <vst@vlnb.net>
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
 * the CPU cache for non-clustered case.
 */
struct trans_tbl_ent {
	unsigned short sg_num;
	unsigned short pg_count;
};

struct sgv_pool_obj
{
	struct kmem_cache *owner_cache;
	int eorder;
	int orig_sg;
	int orig_length;
	int sg_count;
	struct scatterlist *entries;
	struct trans_tbl_ent trans_tbl[0];
};

struct sgv_pool_acc
{
	atomic_t total_alloc, hit_alloc;
};

struct sgv_pool
{
	struct sgv_pool_acc acc;
	struct sgv_pool_acc cache_acc[SGV_POOL_ELEMENTS];
	unsigned int clustered:1;
	/* 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048 */
	struct kmem_cache *caches[SGV_POOL_ELEMENTS];
	char cache_names[SGV_POOL_ELEMENTS][25];
};

struct scst_sgv_pools
{
	struct sgv_pool norm_clust, norm;
	struct sgv_pool dma;
#ifdef SCST_HIGHMEM
	struct sgv_pool highmem;
#endif
};

extern atomic_t sgv_big_total_alloc;
extern atomic_t sgv_other_total_alloc;

extern struct sgv_pool *sgv_pool_create(const char *name, int clustered);
extern void sgv_pool_destroy(struct sgv_pool *pool);

extern int sgv_pool_init(struct sgv_pool *pool, const char *name, 
	int clustered);
extern void sgv_pool_deinit(struct sgv_pool *pool);

extern struct scatterlist *sgv_pool_alloc(struct sgv_pool *pool, int size,
	unsigned long gfp_mask, int atomic, int *count,
	struct sgv_pool_obj **sgv);
static inline void sgv_pool_free(struct sgv_pool_obj *sgv)
{
	TRACE_MEM("Freeing sgv_obj %p", sgv);
	sgv->entries[sgv->orig_sg].length = sgv->orig_length;
	kmem_cache_free(sgv->owner_cache, sgv);
}

static inline struct scatterlist *sgv_pool_sg(struct sgv_pool_obj *obj)
{
	return obj->entries;
}

extern int scst_sgv_pools_init(struct scst_sgv_pools *pools);
extern void scst_sgv_pools_deinit(struct scst_sgv_pools *pools);
