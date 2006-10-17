/*
 *  scst_sgv_pool.c
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

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <asm/unistd.h>
#include <asm/string.h>

#ifdef SCST_HIGHMEM
#include <linux/highmem.h>
#endif

#include "scsi_tgt.h"
#include "scst_debug.h"
#include "scst_priv.h"
#include "scst_mem.h"

/*
 * This implementation of sgv_pool is not the best, because the SLABs could get
 * fragmented and too much undesirable memory could be kept, plus
 * under memory pressure the cached objects could be purged too quickly.
 * From other side it's simple, works well, and doesn't require any modifications
 * of the existing SLAB code.
 */

atomic_t sgv_big_total_alloc;

static int scst_check_clustering(struct scatterlist *sg, int cur, int hint)
{
	int res = -1;
	int i = hint;
	unsigned long pfn_cur = page_to_pfn(sg[cur].page);
	int len_cur = sg[cur].length;
	unsigned long pfn_cur_next = pfn_cur + (len_cur >> PAGE_SHIFT);
	int full_page_cur = (len_cur & (PAGE_SIZE - 1)) == 0;
	unsigned long pfn, pfn_next, full_page;

#ifdef SCST_HIGHMEM
	if (page >= highmem_start_page) {
		TRACE_MEM("%s", "HIGHMEM page allocated, no clustering")
		goto out;
	}
#endif

#if 0
	TRACE_MEM("pfn_cur %ld, pfn_cur_next %ld, len_cur %d, full_page_cur %d",
		pfn_cur, pfn_cur_next, len_cur, full_page_cur);
#endif

	/* check the hint first */
	if (i >= 0) {
		pfn = page_to_pfn(sg[i].page);
		pfn_next = pfn + (sg[i].length >> PAGE_SHIFT);
		full_page = (sg[i].length & (PAGE_SIZE - 1)) == 0;
		
		if ((pfn == pfn_cur_next) && full_page_cur)
			goto out_head;

		if ((pfn_next == pfn_cur) && full_page)
			goto out_tail;
	}

	/* ToDo: implement more intelligent search */
	for (i = cur - 1; i >= 0; i--) {
		pfn = page_to_pfn(sg[i].page);
		pfn_next = pfn + (sg[i].length >> PAGE_SHIFT);
		full_page = (sg[i].length & (PAGE_SIZE - 1)) == 0;
		
		if ((pfn == pfn_cur_next) && full_page_cur)
			goto out_head;

		if ((pfn_next == pfn_cur) && full_page)
			goto out_tail;
	}

out:
	return res;

out_tail:
	TRACE_MEM("SG segment %d will be tail merged with segment %d", cur, i);
	sg[i].length += len_cur;
	memset(&sg[cur], 0, sizeof(sg[cur]));
	res = i;
	goto out;

out_head:
	TRACE_MEM("SG segment %d will be head merged with segment %d", cur, i);
	sg[i].page = sg[cur].page;
	sg[i].length += len_cur;
	memset(&sg[cur], 0, sizeof(sg[cur]));
	res = i;
	goto out;
}

static void sgv_free_sg(struct sgv_pool_obj *obj)
{
	int i;

	TRACE_MEM("obj=%p, sg_count=%d", obj, obj->sg_count);

	for (i = 0; i < obj->sg_count; i++) {
		struct page *p = obj->entries[i].page;
		int len = obj->entries[i].length;
		int pages =
			(len >> PAGE_SHIFT) + ((len & ~PAGE_MASK) != 0);

		TRACE_MEM("page %lx, len %d, pages %d", 
			(unsigned long)p, len, pages);

		while (pages > 0) {
			int order = 0;

/* 
 * __free_pages() doesn't like freeing pages with not that order with
 * which they were allocated, so disable this small optimization.
 */
#if 0
			if (len > 0) {
				while(((1 << order) << PAGE_SHIFT) < len)
					order++;
				len = 0;
			}
#endif
			TRACE_MEM("free_pages(): order %d, page %lx",
				order, (unsigned long)p);

			__free_pages(p, order);

			pages -= 1 << order;
			p += 1 << order;
		}
	}
	obj->sg_count = 0;
}

static int sgv_alloc_sg(struct sgv_pool_obj *obj, int pages,
	unsigned long mask, int clustered)
{
	int res = 0;
	int pg, i, j;
	int merged = -1;

	TRACE_MEM("pages=%d, clustered=%d", pages, clustered);

#if 0
	mask |= __GFP_COLD;
#endif
#ifdef SCST_STRICT_SECURITY
	mask |= __GFP_ZERO;
#endif

	obj->sg_count = 0;
	for (pg = 0; pg < pages; pg++) {
#ifdef DEBUG_OOM
		if ((scst_random() % 10000) == 55)
			obj->entries[obj->sg_count].page = NULL;
		else
#endif
			obj->entries[obj->sg_count].page = alloc_pages(mask, 0);
		if (obj->entries[obj->sg_count].page == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of "
				"sgv_pool_obj page failed");
			res = -ENOMEM;
			goto out_free;
		}
		obj->entries[obj->sg_count].length = PAGE_SIZE;
		if (clustered) {
			merged = scst_check_clustering(obj->entries, 
				obj->sg_count, merged);
			if (merged == -1)
				obj->sg_count++;
		} else
			obj->sg_count++;
		TRACE_MEM("pg=%d, merged=%d, sg_count=%d", pg, merged,
			obj->sg_count);
	}

	if (clustered) {
		pg = 0;
		for (i = 0; i < pages; i++) {
			int n = obj->entries[i].length >> PAGE_SHIFT;
			obj->trans_tbl[i].pg_count = pg;
			for (j = 0; j < n; j++)
				obj->trans_tbl[pg++].sg_num = i+1;
		}
	}

out:
	TRACE_MEM("res=%d, sg_count=%d", res, obj->sg_count);
	return res;

out_free:
	sgv_free_sg(obj);
	goto out;
}

struct sgv_pool_obj *sgv_pool_alloc_big(int size, int pages,
	unsigned long mask, int *count, int clustered)
{
	struct sgv_pool_obj *obj;
	int elen, cnt = 0;

	elen = sizeof(*obj) + pages * (sizeof(obj->entries[0]) +
		clustered ? sizeof(obj->trans_tbl[0]) : 0);
	obj = kzalloc(elen, mask & ~(__GFP_HIGHMEM|GFP_DMA));
	if (obj == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "Allocation big of sgv_pool_obj "
				"failed (elen=%d, size=%d)", elen, size);
		goto out;
	}
	obj->entries = (struct scatterlist*)&obj->trans_tbl[pages];

	atomic_inc(&sgv_big_total_alloc);

	if (sgv_alloc_sg(obj, pages, mask, clustered) != 0)
		goto out_free;
	cnt = obj->sg_count;
	if (size & ~PAGE_MASK) {
		obj->entries[cnt-1].length -= 
			PAGE_SIZE - (size & ~PAGE_MASK);
	}
	*count = cnt;

out:
	TRACE_MEM("obj=%p (count=%d)", obj, cnt);
	return obj;

out_free:
	kfree(obj);
	obj = NULL;
	goto out;
}

void __sgv_pool_free_big(struct sgv_pool_obj *obj)
{
	TRACE_MEM("obj=%p", obj);
	sgv_free_sg(obj);
	kfree(obj);
}

struct sgv_pool_obj *sgv_pool_alloc(struct sgv_pool *pool, int size,
	unsigned long mask, int *count)
{
	struct sgv_pool_obj *obj;
	int order, pages, cnt, sg;

	if (unlikely(size == 0))
		return NULL;

	pages = (size >> PAGE_SHIFT) + ((size & ~PAGE_MASK) != 0);
	order = get_order(size);

	TRACE_MEM("size=%d, pages=%d, order=%d", size, pages, order);

	if (order >= SGV_POOL_ELEMENTS) {
		obj = NULL;
		if (mask & GFP_ATOMIC)
			goto out;
		obj = sgv_pool_alloc_big(size, pages, mask, count,
				pool->clustered);
		goto out;
	}

	obj = kmem_cache_alloc(pool->caches[order], 
			mask & ~(__GFP_HIGHMEM|GFP_DMA));
	if (obj == NULL) {
		if (!(mask & GFP_ATOMIC)) {
			TRACE(TRACE_OUT_OF_MEM, "Allocation of sgv_pool_obj "
				"failed (size %d)", size);
		}
		goto out;
	}

	if (obj->owner_cache != pool->caches[order]) {
		int esz, epg, eorder;

		if (mask & GFP_ATOMIC)
			goto out_free;

		esz = (1 << order) * sizeof(obj->entries[0]);
		epg = (esz >> PAGE_SHIFT) + ((esz & ~PAGE_MASK) != 0);
		eorder = get_order(esz);
		TRACE_MEM("Brand new sgv_obj %p (esz=%d, epg=%d, eorder=%d)",
			obj, esz, epg, eorder);

		obj->eorder = eorder;
		obj->entries = (struct scatterlist*)__get_free_pages(
					mask|__GFP_ZERO, eorder);
		if (obj->entries == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "Allocation of sgv_pool_obj "
				"SG vector order %d failed", eorder);
			goto out_free;
		}

		if (sgv_alloc_sg(obj, (1 << order), mask, 
					pool->clustered) != 0)
			goto out_free_entries;

		obj->owner_cache = pool->caches[order];
	} else {
		TRACE_MEM("Cached sgv_obj %p", obj);
		atomic_inc(&pool->acc.hit_alloc);
		atomic_inc(&pool->cache_acc[order].hit_alloc);
	}
	atomic_inc(&pool->acc.total_alloc);
	atomic_inc(&pool->cache_acc[order].total_alloc);
	if (pool->clustered)
		cnt = obj->trans_tbl[pages-1].sg_num;
	else
		cnt = pages;
	sg = cnt-1;
	obj->orig_sg = sg;
	obj->orig_length = obj->entries[sg].length;
	if (pool->clustered) {
		obj->entries[sg].length = 
			(pages - obj->trans_tbl[sg].pg_count) << PAGE_SHIFT;
	}
	if (size & ~PAGE_MASK) {
		obj->entries[sg].length -= PAGE_SIZE - (size & ~PAGE_MASK);
	}
	*count = cnt;

	TRACE_MEM("sgv_obj=%p (size=%d, pages=%d, "
		"sg_count=%d, count=%d, last_len=%d)", obj, size, pages, 
		obj->sg_count, *count, obj->entries[obj->orig_sg].length);

out:
	return obj;

out_free_entries:
	free_pages((unsigned long)obj->entries, obj->eorder);
	obj->entries = NULL;

out_free:
	kmem_cache_free(pool->caches[order], obj);
	obj = NULL;
	goto out;
}

static void sgv_ctor(void *data,  kmem_cache_t *c, unsigned long flags)
{
	struct sgv_pool_obj *obj = data;

	if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) !=
	     SLAB_CTOR_CONSTRUCTOR)
		return;

	TRACE_MEM("Constructor for sgv_obj %p", obj);
	memset(obj, 0, sizeof(*obj));
}

static void __sgv_dtor(void *data, int pages)
{
	struct sgv_pool_obj *obj = data;
	TRACE_MEM("Destructor for sgv_obj %p", obj);
	if (obj->entries) {
		sgv_free_sg(obj);
		free_pages((unsigned long)obj->entries, obj->eorder);
	}
}

#define SGV_DTOR_NAME(order) sgv_dtor##order
#define SGV_DTOR(order) static void sgv_dtor##order(void *d, kmem_cache_t *k, \
		unsigned long f) { __sgv_dtor(d, 1 << order); }

SGV_DTOR(0);
SGV_DTOR(1);
SGV_DTOR(2);
SGV_DTOR(3);
SGV_DTOR(4);
SGV_DTOR(5);
SGV_DTOR(6);
SGV_DTOR(7);
SGV_DTOR(8);
SGV_DTOR(9);
SGV_DTOR(10);

typedef void (*dtor_t)(void *, kmem_cache_t *, unsigned long);

dtor_t cache_dtors[SGV_POOL_ELEMENTS] =
	{ SGV_DTOR_NAME(0), SGV_DTOR_NAME(1), SGV_DTOR_NAME(2), SGV_DTOR_NAME(3),
	  SGV_DTOR_NAME(4), SGV_DTOR_NAME(5), SGV_DTOR_NAME(6), SGV_DTOR_NAME(7), 
	  SGV_DTOR_NAME(8), SGV_DTOR_NAME(9), SGV_DTOR_NAME(10) }; 

int sgv_pool_init(struct sgv_pool *pool, const char *name, int clustered)
{
	int res = -ENOMEM;
	int i;
	struct sgv_pool_obj *obj;

	TRACE_ENTRY();

	memset(pool, 0, sizeof(*pool));
	pool->clustered = clustered;

	TRACE_MEM("sizeof(*obj)=%d, clustered=%d, sizeof(obj->trans_tbl[0])=%d",
		sizeof(*obj), clustered, sizeof(obj->trans_tbl[0]));

	for(i = 0; i < SGV_POOL_ELEMENTS; i++) {
		int size, pages;

		atomic_set(&pool->cache_acc[i].total_alloc, 0);
		atomic_set(&pool->cache_acc[i].hit_alloc, 0);

		pages = 1 << i;
		size = sizeof(*obj) + pages *
			(clustered ? sizeof(obj->trans_tbl[0]) : 0);
		TRACE_MEM("pages=%d, size=%d", pages, size);

		scnprintf(pool->cache_names[i], sizeof(pool->cache_names[i]),
			"%s-%luK", name, (PAGE_SIZE >> 10) << i);
		pool->caches[i] = kmem_cache_create(pool->cache_names[i], 
			size, 0, SCST_SLAB_FLAGS, sgv_ctor, cache_dtors[i]);
		if (pool->caches[i] == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "Allocation of sgv_pool cache "
				"%s(%d) failed", name, i);
			goto out_free;
		}
	}

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	for(i = 0; i < SGV_POOL_ELEMENTS; i++) {
		if (pool->caches[i]) {
			kmem_cache_destroy(pool->caches[i]);
			pool->caches[i] = NULL;
		} else
			break;
	}
	goto out;
}

void sgv_pool_deinit(struct sgv_pool *pool)
{
	int i;

	TRACE_ENTRY();

	for(i = 0; i < SGV_POOL_ELEMENTS; i++) {
		if (pool->caches[i])
			kmem_cache_destroy(pool->caches[i]);
		pool->caches[i] = NULL;
	}

	TRACE_EXIT();
}

struct sgv_pool *sgv_pool_create(const char *name, int clustered)
{
	struct sgv_pool *pool;
	int rc;

	TRACE_ENTRY();

	pool = kmalloc(sizeof(*pool), GFP_KERNEL);
	if (pool == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of sgv_pool failed");
		goto out;
	}

	rc = sgv_pool_init(pool, name, clustered);
	if (rc != 0)
		goto out_free;

out:
	TRACE_EXIT_RES(pool != NULL);
	return pool;

out_free:
	kfree(pool);
	pool = NULL;
	goto out;
}

void sgv_pool_destroy(struct sgv_pool *pool)
{
	TRACE_ENTRY();

	sgv_pool_deinit(pool);
	kfree(pool);

	TRACE_EXIT();
}

int scst_sgv_pools_init(struct scst_sgv_pools *pools)
{
	int res;

	TRACE_ENTRY();

	atomic_set(&sgv_big_total_alloc, 0);

	res = sgv_pool_init(&pools->norm, "sgv", 0);
	if (res != 0)
		goto out_free_clust;

	res = sgv_pool_init(&pools->norm_clust, "sgv-clust", 1);
	if (res != 0)
		goto out;

	res = sgv_pool_init(&pools->dma, "sgv-dma", 0);
	if (res != 0)
		goto out_free_norm;

#ifdef SCST_HIGHMEM
	res = sgv_pool_init(&pools->highmem, "sgv-high", 0);
	if (res != 0)
		goto out_free_dma;
#endif

out:
	TRACE_EXIT_RES(res);
	return res;

#ifdef SCST_HIGHMEM
out_free_dma:
	sgv_pool_deinit(&pools->dma);
#endif

out_free_norm:
	sgv_pool_deinit(&pools->norm);

out_free_clust:
	sgv_pool_deinit(&pools->norm_clust);
	goto out;
}

void scst_sgv_pools_deinit(struct scst_sgv_pools *pools)
{
	TRACE_ENTRY();

#ifdef SCST_HIGHMEM
	sgv_pool_deinit(&pools->highmem);
#endif
	sgv_pool_deinit(&pools->dma);
	sgv_pool_deinit(&pools->norm);
	sgv_pool_deinit(&pools->norm_clust);

	TRACE_EXIT();
	return;
}
