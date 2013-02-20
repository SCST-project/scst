/*
 *  include/scst_sgv.h
 *
 *  Copyright (C) 2004 - 2013 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
 *
 *  Include file for SCST SGV cache.
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
#ifndef __SCST_SGV_H
#define __SCST_SGV_H

/** SGV pool routines and flag bits **/

/* Set if the allocated object must be not from the cache */
#define SGV_POOL_ALLOC_NO_CACHED		1

/* Set if there should not be any memory allocations on a cache miss */
#define SGV_POOL_NO_ALLOC_ON_CACHE_MISS		2

/* Set an object should be returned even if it doesn't have SG vector built */
#define SGV_POOL_RETURN_OBJ_ON_ALLOC_FAIL	4

/*
 * Set if the allocated object must be a new one, i.e. from the cache,
 * but not cached
 */
#define SGV_POOL_ALLOC_GET_NEW			8

struct sgv_pool_obj;
struct sgv_pool;

/*
 * Structure to keep a memory limit for an SCST object
 */
struct scst_mem_lim {
	/* How much memory allocated under this object */
	atomic_t alloced_pages;

	/*
	 * How much memory allowed to allocated under this object. Put here
	 * mostly to save a possible cache miss accessing scst_max_dev_cmd_mem.
	 */
	int max_allowed_pages;
};

/* Types of clustering */
enum sgv_clustering_types {
	/* No clustering performed */
	sgv_no_clustering = 0,

	/*
	 * A page will only be merged with the latest previously allocated
	 * page, so the order of pages in the SG will be preserved.
	 */
	sgv_tail_clustering,

	/*
	 * Free merging of pages at any place in the SG is allowed. This mode
	 * usually provides the best merging rate.
	 */
	sgv_full_clustering,
};

struct sgv_pool *sgv_pool_create(const char *name,
	enum sgv_clustering_types clustered, int single_alloc_pages,
	bool shared, int purge_interval);
void sgv_pool_del(struct sgv_pool *pool);

void sgv_pool_get(struct sgv_pool *pool);
void sgv_pool_put(struct sgv_pool *pool);

void sgv_pool_flush(struct sgv_pool *pool);

void sgv_pool_set_allocator(struct sgv_pool *pool,
	struct page *(*alloc_pages_fn)(struct scatterlist *, gfp_t, void *),
	void (*free_pages_fn)(struct scatterlist *, int, void *));

struct scatterlist *sgv_pool_alloc(struct sgv_pool *pool, unsigned int size,
	gfp_t gfp_mask, int flags, int *count,
	struct sgv_pool_obj **sgv, struct scst_mem_lim *mem_lim, void *priv);
void sgv_pool_free(struct sgv_pool_obj *sgv, struct scst_mem_lim *mem_lim);

void *sgv_get_priv(struct sgv_pool_obj *sgv);

void scst_init_mem_lim(struct scst_mem_lim *mem_lim);

#endif /* __SCST_SGV_H */
