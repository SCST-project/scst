/*
 *  scst_sgv_pool.c
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
#include "scst_priv.h"
#include "scst_mem.h"

/*
 * This implementation of sgv_pool is not the best, because the SLABs could get
 * fragmented and too much undesirable memory could be kept, plus
 * under memory pressure the cached objects could be purged too quickly.
 * From other side it's simple, works well, and doesn't require any modifications
 * of the existing SLAB code.
 */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22))
#error 2.6.22+ kernels are not supported yet, because some oversmart nerd \
has deleted support for destructors from SLABs in those kernels and was \
unresponsible enough to made that without even set it in the deprecated \
status for some time to allow depending on it projects fix it without \
disturbing their users. Blame him for that! So, now to be usable on \
2.6.22+ kernels SCST requires a complete rewrite of one of its major low \
level parts: all kmem_cache_*() functions in this file should be replaced \
with new ones with similar functionality. I'm not sure I will have time for \
that in the near future, therefore you are welcome to implement that. \
Don't hesitate to ask me how to do it most effectively. VLNB.
#endif

/* Chosen to have one page per slab for all orders */
#ifdef CONFIG_DEBUG_SLAB
#define SGV_MAX_LOCAL_SLAB_ORDER	4
#else
#define SGV_MAX_LOCAL_SLAB_ORDER	5
#endif

static int sgv_max_local_order, sgv_max_trans_order;

atomic_t sgv_other_total_alloc;

DEFINE_MUTEX(scst_sgv_pool_mutex);
LIST_HEAD(scst_sgv_pool_list);

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

static void scst_free_sys_sg_entries(struct scatterlist *sg, int sg_count,
	void *priv)
{
	int i;

	TRACE_MEM("sg=%p, sg_count=%d", sg, sg_count);

	for (i = 0; i < sg_count; i++) {
		struct page *p = sg[i].page;
		int len = sg[i].length;
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
}

static struct page *scst_alloc_sys_pages(struct scatterlist *sg,
	gfp_t gfp_mask, void *priv)
{
	sg->page = alloc_pages(gfp_mask, 0);
	sg->offset = 0;
	sg->length = PAGE_SIZE;
	TRACE_MEM("page=%p, sg=%p, priv=%p", sg->page, sg, priv);
	if (sg->page == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of "
			"sg page failed");
	}
	return sg->page;
}

static int scst_alloc_sg_entries(struct scatterlist *sg, int pages,
	gfp_t gfp_mask, int clustered, struct trans_tbl_ent *trans_tbl,
	const struct sgv_pool_alloc_fns *alloc_fns, void *priv)
{
	int sg_count = 0;
	int pg, i, j;
	int merged = -1;

	TRACE_MEM("pages=%d, clustered=%d", pages, clustered);

#if 0
	gfp_mask |= __GFP_COLD;
#endif
#ifdef SCST_STRICT_SECURITY
	gfp_mask |= __GFP_ZERO;
#endif

	for (pg = 0; pg < pages; pg++) {
		void *rc;
#ifdef DEBUG_OOM
		if (((gfp_mask & __GFP_NOFAIL) == 0) &&
		    ((scst_random() % 10000) == 55))
			rc = NULL;
		else
#endif
			rc = alloc_fns->alloc_pages_fn(&sg[sg_count], gfp_mask,
				priv);
		if (rc == NULL)
			goto out_no_mem;
		if (clustered) {
			merged = scst_check_clustering(sg, sg_count, merged);
			if (merged == -1)
				sg_count++;
		} else
			sg_count++;
		TRACE_MEM("pg=%d, merged=%d, sg_count=%d", pg, merged,
			sg_count);
	}

	if (clustered && (trans_tbl != NULL)) {
		pg = 0;
		for (i = 0; i < pages; i++) {
			int n = (sg[i].length >> PAGE_SHIFT) +
				((sg[i].length & ~PAGE_MASK) != 0);
			trans_tbl[i].pg_count = pg;
			for (j = 0; j < n; j++)
				trans_tbl[pg++].sg_num = i+1;
			TRACE_MEM("i=%d, n=%d, pg_count=%d", i, n,
				trans_tbl[i].pg_count);
		}
	}

out:
	TRACE_MEM("sg_count=%d", sg_count);
	return sg_count;

out_no_mem:
	alloc_fns->free_pages_fn(sg, sg_count, priv);
	sg_count = 0;
	goto out;
}

static int sgv_alloc_sg_entries(struct sgv_pool_obj *obj,
	int pages_to_alloc, int order, unsigned long gfp_mask)
{
	int sz, tsz = 0;
	int res = 0;

	TRACE_ENTRY();

	sz = pages_to_alloc * sizeof(obj->sg_entries[0]);

	obj->sg_entries = (struct scatterlist*)kzalloc(sz, gfp_mask);
 	if (unlikely(obj->sg_entries == NULL)) {
		TRACE(TRACE_OUT_OF_MEM, "Allocation of sgv_pool_obj "
			"SG vector failed (size %d)", sz);
		res = -ENOMEM;
		goto out;
 	}

	if (obj->owner_pool->clustered) {
		if (order <= sgv_max_trans_order) {
			obj->trans_tbl = (struct trans_tbl_ent*)obj->sg_entries_data;
			/*
			 * No need to clear trans_tbl, if needed, it will be
			 * fully rewritten in scst_alloc_sg_entries()
			 */
		} else {
			tsz = pages_to_alloc * sizeof(obj->trans_tbl[0]);
			obj->trans_tbl = (struct trans_tbl_ent*)kzalloc(tsz, gfp_mask);
		 	if (unlikely(obj->trans_tbl == NULL)) {
				TRACE(TRACE_OUT_OF_MEM, "Allocation of trans_tbl "
					"failed (size %d)", tsz);
				res = -ENOMEM;
				goto out_free;
 			}
		}
	}

	TRACE_MEM("pages_to_alloc %d, order %d, sz %d, tsz %d, obj %p, "
		"sg_entries %p, trans_tbl %p", pages_to_alloc, order,
		sz, tsz, obj, obj->sg_entries, obj->trans_tbl);

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	kfree(obj->sg_entries);
	obj->sg_entries = NULL;
	goto out;
}

struct scatterlist *sgv_pool_alloc(struct sgv_pool *pool, unsigned int size,
	unsigned long gfp_mask, int flags, int *count,
	struct sgv_pool_obj **sgv, void *priv)
{
	struct sgv_pool_obj *obj;
	int order, pages, cnt;
	struct scatterlist *res;
	int pages_to_alloc;
	struct kmem_cache *cache;
	int no_cached = flags & SCST_POOL_ALLOC_NO_CACHED;

	sBUG_ON(size == 0);

	pages = (size >> PAGE_SHIFT) + ((size & ~PAGE_MASK) != 0);
	order = get_order(size);

	TRACE_MEM("size=%d, pages=%d, order=%d, flags=%x, *sgv %p", size, pages,
		order, flags, *sgv);

	if (*sgv != NULL) {
		obj = *sgv;
		TRACE_MEM("Supplied sgv_obj %p", obj);
		pages_to_alloc = (1 << order);
		cache = obj->owner_cache;
		EXTRACHECKS_BUG_ON(cache != pool->caches[order]);
		EXTRACHECKS_BUG_ON(obj->sg_count != 0);
		goto alloc;
	}

	if ((order < SGV_POOL_ELEMENTS) && !no_cached) {
		cache = pool->caches[order];
		obj = kmem_cache_alloc(cache,
				gfp_mask & ~(__GFP_HIGHMEM|GFP_DMA));
		if (unlikely(obj == NULL)) {
			TRACE(TRACE_OUT_OF_MEM, "Allocation of "
				"sgv_pool_obj failed (size %d)", size);
			goto out_fail;
		}
		if (obj->sg_count != 0) {
			TRACE_MEM("Cached sgv_obj %p", obj);
			EXTRACHECKS_BUG_ON(obj->owner_cache != cache);
			atomic_inc(&pool->acc.hit_alloc);
			atomic_inc(&pool->cache_acc[order].hit_alloc);
			goto success;
		}
		pages_to_alloc = (1 << order);
		if (flags & SCST_POOL_NO_ALLOC_ON_CACHE_MISS) {
			if (!(flags & SCST_POOL_RETURN_OBJ_ON_ALLOC_FAIL))
				goto out_fail_free;
		}
		TRACE_MEM("Brand new sgv_obj %p", obj);
		obj->owner_cache = cache;
		obj->owner_pool = pool;
		if (order <= sgv_max_local_order) {
			obj->sg_entries = obj->sg_entries_data;
			TRACE_MEM("sg_entries %p", obj->sg_entries);
			memset(obj->sg_entries, 0,
				pages_to_alloc*sizeof(obj->sg_entries[0]));
			if (pool->clustered) {
				obj->trans_tbl = (struct trans_tbl_ent*)
					(obj->sg_entries + pages_to_alloc);
				TRACE_MEM("trans_tbl %p", obj->trans_tbl);
				/* We want to have all the data on the same page */
				EXTRACHECKS_WARN_ON_ONCE(((unsigned long)obj->sg_entries & PAGE_MASK) !=
					((unsigned long)&obj->trans_tbl[pages_to_alloc-1] & PAGE_MASK));
				/*
				 * No need to clear trans_tbl, if needed, it will
				 * be fully rewritten in scst_alloc_sg_entries()
				 */
			} else {
				/* We want to have all the data on the same page */
				EXTRACHECKS_WARN_ON_ONCE(((unsigned long)obj->sg_entries & PAGE_MASK) !=
					((unsigned long)&obj->sg_entries[pages_to_alloc-1] & PAGE_MASK));
			}
		} else {
			if (unlikely(sgv_alloc_sg_entries(obj, pages_to_alloc,
					order, gfp_mask) != 0))
				goto out_fail_free;
		}
		
		if ((flags & SCST_POOL_NO_ALLOC_ON_CACHE_MISS) && 
		    (flags & SCST_POOL_RETURN_OBJ_ON_ALLOC_FAIL))
			goto out_return;
	} else {
		int sz;
		pages_to_alloc = pages;
		if (flags & SCST_POOL_NO_ALLOC_ON_CACHE_MISS)
			goto out_return2;
		cache = NULL;
		sz = sizeof(*obj) + pages*sizeof(obj->sg_entries[0]);
		obj = kzalloc(sz, gfp_mask);
		if (unlikely(obj == NULL)) {
			TRACE(TRACE_OUT_OF_MEM, "Allocation of "
				"sgv_pool_obj failed (size %d)", size);
			goto out_fail;
		}
		obj->owner_pool = pool;
		obj->sg_entries = obj->sg_entries_data;
		TRACE_MEM("Big or no_cached sgv_obj %p (size %d)", obj,	sz);
	}

	obj->allocator_priv = priv;

alloc:
	obj->sg_count = scst_alloc_sg_entries(obj->sg_entries,
		pages_to_alloc, gfp_mask, pool->clustered, obj->trans_tbl,
		&pool->alloc_fns, priv);
	if (unlikely(obj->sg_count <= 0)) {
		obj->sg_count = 0;
		if ((flags & SCST_POOL_RETURN_OBJ_ON_ALLOC_FAIL) && cache)
			goto out_return1;
		else
			goto out_fail_free_sg_entries;
	}

success:
	atomic_inc(&pool->acc.total_alloc);
	if (cache) {
		int sg;
		atomic_inc(&pool->cache_acc[order].total_alloc);
		if (pool->clustered)
			cnt = obj->trans_tbl[pages-1].sg_num;
		else
			cnt = pages;
		sg = cnt-1;
		obj->orig_sg = sg;
		obj->orig_length = obj->sg_entries[sg].length;
		if (pool->clustered) {
			obj->sg_entries[sg].length = 
				(pages - obj->trans_tbl[sg].pg_count) << PAGE_SHIFT;
		}
	} else {
		cnt = obj->sg_count;
		if (no_cached)
			atomic_inc(&pool->other_alloc);
		else
			atomic_inc(&pool->big_alloc);
	}

	*count = cnt;
	res = obj->sg_entries;
	*sgv = obj;

	if (size & ~PAGE_MASK)
		obj->sg_entries[cnt-1].length -= PAGE_SIZE - (size & ~PAGE_MASK);

	TRACE_MEM("sgv_obj=%p, sg_entries %p (size=%d, pages=%d, sg_count=%d, "
		"count=%d, last_len=%d)", obj, obj->sg_entries, size, pages,
		obj->sg_count, *count, obj->sg_entries[obj->orig_sg].length);

out:
	return res;

out_return:
	obj->allocator_priv = priv;
	obj->owner_pool = pool;

out_return1:
	*sgv = obj;
	TRACE_MEM("Returning failed sgv_obj %p (count %d)", obj, *count);

out_return2:
	*count = pages_to_alloc;
	res = NULL;
	goto out;

out_fail_free_sg_entries:
	if (obj->sg_entries != obj->sg_entries_data) {
		if (obj->trans_tbl != (struct trans_tbl_ent*)obj->sg_entries_data) {
			/* kfree() handles NULL parameter */
			kfree(obj->trans_tbl);
			obj->trans_tbl = NULL;
		}
		kfree(obj->sg_entries);
		obj->sg_entries = NULL;
	}

out_fail_free:
	if (cache)
		kmem_cache_free(pool->caches[order], obj);
	else
		kfree(obj);

out_fail:
	res = NULL;
	*count = 0;
	*sgv = NULL;
	TRACE_MEM("%s", "Allocation failed");
	goto out;
}

void *sgv_get_priv(struct sgv_pool_obj *sgv)
{
	return sgv->allocator_priv;
}

void sgv_pool_free(struct sgv_pool_obj *sgv)
{
	TRACE_MEM("Freeing sgv_obj %p, owner_cache %p, sg_entries %p, "
		"sg_count %d, allocator_priv %p", sgv, sgv->owner_cache,
		sgv->sg_entries, sgv->sg_count, sgv->allocator_priv);
	if (sgv->owner_cache != NULL) {
		sgv->sg_entries[sgv->orig_sg].length = sgv->orig_length;
		kmem_cache_free(sgv->owner_cache, sgv);
	} else {
		sgv->owner_pool->alloc_fns.free_pages_fn(sgv->sg_entries,
			sgv->sg_count, sgv->allocator_priv);
		kfree(sgv);
	}
	return;
}

static void sgv_ctor(void *data, struct kmem_cache *c, unsigned long flags)
{
	struct sgv_pool_obj *obj = data;

#ifdef SLAB_CTOR_VERIFY
	if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) !=
	     SLAB_CTOR_CONSTRUCTOR)
		return;
#endif

	TRACE_MEM("Constructor for sgv_obj %p", obj);
	memset(obj, 0, sizeof(*obj));
	return;
}

static void sgv_dtor(void *data, struct kmem_cache *k, unsigned long f)
{
	struct sgv_pool_obj *obj = data;
	if (obj->sg_count != 0) {
		obj->owner_pool->alloc_fns.free_pages_fn(obj->sg_entries,
			obj->sg_count, obj->allocator_priv);
	}
	if (obj->sg_entries != obj->sg_entries_data) {
		if (obj->trans_tbl != (struct trans_tbl_ent*)obj->sg_entries_data) {
			/* kfree() handles NULL parameter */
			kfree(obj->trans_tbl);
			obj->trans_tbl = NULL;
		}
		kfree(obj->sg_entries);
	}
	return;
}

struct scatterlist *scst_alloc(int size, unsigned long gfp_mask,
	int use_clustering, int *count)
{
	struct scatterlist *res;
	int pages = (size >> PAGE_SHIFT) + ((size & ~PAGE_MASK) != 0);
	struct sgv_pool_alloc_fns sys_alloc_fns = {
		scst_alloc_sys_pages, scst_free_sys_sg_entries };

	TRACE_ENTRY();

	atomic_inc(&sgv_other_total_alloc);

	res = kzalloc(pages*sizeof(*res), gfp_mask);
	if (res == NULL)
		goto out;

	*count = scst_alloc_sg_entries(res, pages, gfp_mask, use_clustering,
		NULL, &sys_alloc_fns, NULL);
	if (*count <= 0)
		goto out_free;

out:
	TRACE_MEM("Alloced sg %p (count %d)", res, *count);

	TRACE_EXIT_HRES(res);
	return res;

out_free:
	kfree(res);
	res = NULL;
	goto out;
}

void scst_free(struct scatterlist *sg, int count)
{
	TRACE_MEM("Freeing sg=%p", sg);
	scst_free_sys_sg_entries(sg, count, NULL);
	kfree(sg);
}

int sgv_pool_init(struct sgv_pool *pool, const char *name, int clustered)
{
	int res = -ENOMEM;
	int i;
	struct sgv_pool_obj *obj;

	TRACE_ENTRY();

	memset(pool, 0, sizeof(*pool));

	atomic_set(&pool->other_alloc, 0);
	atomic_set(&pool->big_alloc, 0);
	atomic_set(&pool->acc.total_alloc, 0);
	atomic_set(&pool->acc.hit_alloc, 0);

	pool->clustered = clustered;
	pool->alloc_fns.alloc_pages_fn = scst_alloc_sys_pages;
	pool->alloc_fns.free_pages_fn = scst_free_sys_sg_entries;

	TRACE_MEM("name %s, sizeof(*obj)=%zd, clustered=%d", name, sizeof(*obj),
		clustered);

	strncpy(pool->name, name, sizeof(pool->name)-1);
	pool->name[sizeof(pool->name)-1] = '\0';

	for(i = 0; i < SGV_POOL_ELEMENTS; i++) {
		int size;

		atomic_set(&pool->cache_acc[i].total_alloc, 0);
		atomic_set(&pool->cache_acc[i].hit_alloc, 0);

		/*
		 * We need one page per SLAB. That's hackish, but is there
		 * any other choice?
		 */
		if (i <= SGV_MAX_LOCAL_SLAB_ORDER) {
			int pages = 1 << i;
			size = sizeof(*obj) + pages * 
				(sizeof(obj->sg_entries[0]) +
				 (clustered ? sizeof(obj->trans_tbl[0]) : 0));
		} else
			size = PAGE_SIZE - 96;

		TRACE_MEM("pages=%d, size=%d", 1 << i, size);

		scnprintf(pool->cache_names[i], sizeof(pool->cache_names[i]),
			"%s-%luK", name, (PAGE_SIZE >> 10) << i);
		pool->caches[i] = kmem_cache_create(pool->cache_names[i], 
			size, 0, SCST_SLAB_FLAGS, sgv_ctor, sgv_dtor);
		if (pool->caches[i] == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "Allocation of sgv_pool cache "
				"%s(%d) failed", name, i);
			goto out_free;
		}
	}

	mutex_lock(&scst_sgv_pool_mutex);
	list_add_tail(&pool->sgv_pool_list_entry, &scst_sgv_pool_list);
	mutex_unlock(&scst_sgv_pool_mutex);

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

	mutex_lock(&scst_sgv_pool_mutex);
	list_del(&pool->sgv_pool_list_entry);
	mutex_unlock(&scst_sgv_pool_mutex);

	TRACE_EXIT();
}

void sgv_pool_set_allocator(struct sgv_pool *pool,
	struct page *(*alloc_pages_fn)(struct scatterlist *, gfp_t, void *),
	void (*free_pages_fn)(struct scatterlist *, int, void *))
{
	pool->alloc_fns.alloc_pages_fn = alloc_pages_fn;
	pool->alloc_fns.free_pages_fn = free_pages_fn;
	return;
}

struct sgv_pool *sgv_pool_create(const char *name, int clustered)
{
	struct sgv_pool *pool;
	int rc;

	TRACE_ENTRY();

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
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

	sgv_max_local_order = get_order(
		((((PAGE_SIZE - sizeof(struct sgv_pool_obj)) /
		  (sizeof(struct trans_tbl_ent) + sizeof(struct scatterlist))) *
			PAGE_SIZE) & PAGE_MASK)) - 1;

	sgv_max_trans_order = get_order(
		((((PAGE_SIZE - sizeof(struct sgv_pool_obj)) /
		  (sizeof(struct trans_tbl_ent))) * PAGE_SIZE) & PAGE_MASK)) - 1;

	TRACE_MEM("sgv_max_local_order %d, sgv_max_trans_order %d",
		sgv_max_local_order, sgv_max_trans_order);

	atomic_set(&sgv_other_total_alloc, 0);

	res = sgv_pool_init(&pools->norm, "sgv", 0);
	if (res != 0)
		goto out;

	res = sgv_pool_init(&pools->norm_clust, "sgv-clust", 1);
	if (res != 0)
		goto out_free_clust;

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
