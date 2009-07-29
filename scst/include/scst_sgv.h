/*
 *  include/scst_sgv.h
 *
 *  Copyright (C) 2004 - 2009 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2007 - 2009 ID7 Ltd.
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

struct sgv_pool_obj;
struct sgv_pool;

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

/**
 * sgv_pool_create - creates and initializes an SGV cache
 * @name:	the name of the SGV cache
 * @clustered:	sets type of the pages clustering.
 * @single_alloc_pages:	if 0, then the SGV cache will work in the set of
 *		power 2 size buffers mode. If >0, then the SGV cache will
 *		work in the fixed size buffers mode. In this case
 *		single_alloc_pages sets the size of each buffer in pages.
 * @shared:	sets if the SGV cache can be shared between devices or not.
 *		The cache sharing allowed only between devices created inside
 *		the same address space. If an SGV cache is shared, each
 *		subsequent call of sgv_pool_create() with the same cache name
 *		will not create a new cache, but instead return a reference
 *		to it.
 * @purge_interval	sets the cache purging interval. I.e., an SG buffer
 *		will be freed if it's unused for time t
 *		purge_interval <= t < 2*purge_interval. If purge_interval
 *		is 0, then the default interval will be used (60 seconds).
 *		If purge_interval <0, then the automatic purging will be
 *		disabled.
 *
 * Description:
 *    Returns the resulting SGV cache or NULL in case of any error.
 */
struct sgv_pool *sgv_pool_create(const char *name,
	enum sgv_clustering_types clustered, int single_alloc_pages,
	bool shared, int purge_interval);

/**
 * sgv_pool_del - deletes the corresponding SGV cache
 * @:pool	the cache to delete.
 *
 * Description:
 *    If the cache is shared, it will decrease its reference counter.
 *    If the reference counter reaches 0, the cache will be destroyed.
 */
void sgv_pool_del(struct sgv_pool *pool);

/**
 * sgv_pool_flush - flushes the SGV cache
 * @:pool	the cache to flush
 *
 * Description:
 *    Flushes, i.e. frees, all the cached entries in the SGV cache.
 */
void sgv_pool_flush(struct sgv_pool *pool);

/**
 * sgv_pool_set_allocator - allows to set a custom pages allocator
 * @:pool	the cache
 * @:alloc_pages_fn	pages allocation function
 * @:free_pages_fn	pages freeing function
 *
 * Description:
 *    See the SGV cache documentation for more details.
 */
void sgv_pool_set_allocator(struct sgv_pool *pool,
	struct page *(*alloc_pages_fn)(struct scatterlist *, gfp_t, void *),
	void (*free_pages_fn)(struct scatterlist *, int, void *));

/**
 * sgv_pool_alloc - allocates an SG vector from the SGV cache
 * @:pool	the cache to alloc from
 * @:size	size of the resulting SG vector in bytes
 * @:gfp_mask	the allocation mask
 * @:flags	the allocation flags
 * @:count	the resulting count of SG entries in the resulting SG vector
 * @:sgv	the resulting SGV object
 * @:mem_lim	memory limits
 * @:priv	pointer to private for this allocation data
 *
 * Description:
 *    Returns pointer to the resulting SG vector or NULL in case
 *    of any error. See the SGV cache documentation for more details.
 */
struct scatterlist *sgv_pool_alloc(struct sgv_pool *pool, unsigned int size,
	gfp_t gfp_mask, int flags, int *count,
	struct sgv_pool_obj **sgv, struct scst_mem_lim *mem_lim, void *priv);

/**
 * sgv_pool_free - frees previously allocated SG vector
 * @:sgv	the SGV object to free
 * @:mem_lim	memory limits
 *
 * Description:
 *    Frees previously allocated SG vector, referenced by SGV cache object sgv
 */
void sgv_pool_free(struct sgv_pool_obj *sgv, struct scst_mem_lim *mem_lim);

/**
 * sgv_get_priv - returns the private allocation data
 * @:sgv        the SGV object
 *
 * Description:
 *     Allows to get the allocation private data for this SGV
 *     cache object sgv. The private data are set by sgv_pool_alloc().
 */
void *sgv_get_priv(struct sgv_pool_obj *sgv);

/**
 * scst_init_mem_lim - initializes memory limits
 * @:mem_lim	memory limits
 *
 * Description:
 *    Initializes memory limits structure mem_lim according to
 *    the current system configuration. This structure should be latter used
 *    to track and limit allocated by one or more SGV caches memory.
 */
void scst_init_mem_lim(struct scst_mem_lim *mem_lim);

#endif /* __SCST_SGV_H */
