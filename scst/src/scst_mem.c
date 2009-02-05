/*
 *  scst_mem.c
 *
 *  Copyright (C) 2006 - 2008 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2007 Krzysztof Blaszkowski <kb@sysmikro.com.pl>
 *  Copyright (C) 2007 - 2008 CMS Distribution Limited
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
#include <linux/unistd.h>
#include <linux/string.h>

#include "scst.h"
#include "scst_priv.h"
#include "scst_mem.h"

#define PURGE_INTERVAL		(60 * HZ)
#define PURGE_TIME_AFTER	PURGE_INTERVAL
#define SHRINK_TIME_AFTER	(1 * HZ)

static struct scst_sgv_pools_manager sgv_pools_mgr;

static inline bool sgv_pool_clustered(const struct sgv_pool *pool)
{
	return (pool->clustering_type != sgv_no_clustering);
}

void scst_sgv_pool_use_norm(struct scst_tgt_dev *tgt_dev)
{
	tgt_dev->gfp_mask = __GFP_NOWARN;
	tgt_dev->pool = &sgv_pools_mgr.default_set.norm;
	clear_bit(SCST_TGT_DEV_CLUST_POOL, &tgt_dev->tgt_dev_flags);
}

void scst_sgv_pool_use_norm_clust(struct scst_tgt_dev *tgt_dev)
{
	TRACE_MEM("%s", "Use clustering");
	tgt_dev->gfp_mask = __GFP_NOWARN;
	tgt_dev->pool = &sgv_pools_mgr.default_set.norm_clust;
	set_bit(SCST_TGT_DEV_CLUST_POOL, &tgt_dev->tgt_dev_flags);
}

void scst_sgv_pool_use_dma(struct scst_tgt_dev *tgt_dev)
{
	TRACE_MEM("%s", "Use ISA DMA memory");
	tgt_dev->gfp_mask = __GFP_NOWARN | GFP_DMA;
	tgt_dev->pool = &sgv_pools_mgr.default_set.dma;
	clear_bit(SCST_TGT_DEV_CLUST_POOL, &tgt_dev->tgt_dev_flags);
}

static int sgv_check_full_clustering(struct scatterlist *sg, int cur, int hint)
{
	int res = -1;
	int i = hint;
	unsigned long pfn_cur = page_to_pfn(sg_page(&sg[cur]));
	int len_cur = sg[cur].length;
	unsigned long pfn_cur_next = pfn_cur + (len_cur >> PAGE_SHIFT);
	int full_page_cur = (len_cur & (PAGE_SIZE - 1)) == 0;
	unsigned long pfn, pfn_next;
	bool full_page;

#if 0
	TRACE_MEM("pfn_cur %ld, pfn_cur_next %ld, len_cur %d, full_page_cur %d",
		pfn_cur, pfn_cur_next, len_cur, full_page_cur);
#endif

	/* check the hint first */
	if (i >= 0) {
		pfn = page_to_pfn(sg_page(&sg[i]));
		pfn_next = pfn + (sg[i].length >> PAGE_SHIFT);
		full_page = (sg[i].length & (PAGE_SIZE - 1)) == 0;

		if ((pfn == pfn_cur_next) && full_page_cur)
			goto out_head;

		if ((pfn_next == pfn_cur) && full_page)
			goto out_tail;
	}

	/* ToDo: implement more intelligent search */
	for (i = cur - 1; i >= 0; i--) {
		pfn = page_to_pfn(sg_page(&sg[i]));
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
	sg_clear(&sg[cur]);
	res = i;
	goto out;

out_head:
	TRACE_MEM("SG segment %d will be head merged with segment %d", cur, i);
	sg_assign_page(&sg[i], sg_page(&sg[cur]));
	sg[i].length += len_cur;
	sg_clear(&sg[cur]);
	res = i;
	goto out;
}

static int sgv_check_tail_clustering(struct scatterlist *sg, int cur, int hint)
{
	int res = -1;
	unsigned long pfn_cur = page_to_pfn(sg_page(&sg[cur]));
	int len_cur = sg[cur].length;
	int prev;
	unsigned long pfn_prev;
	bool full_page;

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

	if (cur == 0)
		goto out;

	prev = cur - 1;
	pfn_prev = page_to_pfn(sg_page(&sg[prev])) +
			(sg[prev].length >> PAGE_SHIFT);
	full_page = (sg[prev].length & (PAGE_SIZE - 1)) == 0;

	if ((pfn_prev == pfn_cur) && full_page) {
		TRACE_MEM("SG segment %d will be tail merged with segment %d",
			cur, prev);
		sg[prev].length += len_cur;
		sg_clear(&sg[cur]);
		res = prev;
	}

out:
	return res;
}

static void scst_free_sys_sg_entries(struct scatterlist *sg, int sg_count,
	void *priv)
{
	int i;

	TRACE_MEM("sg=%p, sg_count=%d", sg, sg_count);

	for (i = 0; i < sg_count; i++) {
		struct page *p = sg_page(&sg[i]);
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
				while (((1 << order) << PAGE_SHIFT) < len)
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
	struct page *page = alloc_pages(gfp_mask, 0);

	sg_set_page(sg, page, PAGE_SIZE, 0);
	TRACE_MEM("page=%p, sg=%p, priv=%p", page, sg, priv);
	if (page == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of "
			"sg page failed");
	}
	return page;
}

static int scst_alloc_sg_entries(struct scatterlist *sg, int pages,
	gfp_t gfp_mask, enum sgv_clustering_types clustering_type,
	struct trans_tbl_ent *trans_tbl,
	const struct sgv_pool_alloc_fns *alloc_fns, void *priv)
{
	int sg_count = 0;
	int pg, i, j;
	int merged = -1;

	TRACE_MEM("pages=%d, clustering_type=%d", pages, clustering_type);

#if 0
	gfp_mask |= __GFP_COLD;
#endif
#ifdef CONFIG_SCST_STRICT_SECURITY
	gfp_mask |= __GFP_ZERO;
#endif

	for (pg = 0; pg < pages; pg++) {
		void *rc;
#ifdef CONFIG_SCST_DEBUG_OOM
		if (((gfp_mask & __GFP_NOFAIL) != __GFP_NOFAIL) &&
		    ((scst_random() % 10000) == 55))
			rc = NULL;
		else
#endif
			rc = alloc_fns->alloc_pages_fn(&sg[sg_count], gfp_mask,
				priv);
		if (rc == NULL)
			goto out_no_mem;

		if (clustering_type == sgv_full_clustering)
			merged = sgv_check_full_clustering(sg, sg_count, merged);
		else if (clustering_type == sgv_tail_clustering)
			merged = sgv_check_tail_clustering(sg, sg_count, merged);
		else
			merged = -1;

		if (merged == -1)
			sg_count++;

		TRACE_MEM("pg=%d, merged=%d, sg_count=%d", pg, merged,
			sg_count);
	}

	if ((clustering_type != sgv_no_clustering) && (trans_tbl != NULL)) {
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

static int sgv_alloc_arrays(struct sgv_pool_obj *obj,
	int pages_to_alloc, int order, gfp_t gfp_mask)
{
	int sz, tsz = 0;
	int res = 0;

	TRACE_ENTRY();

	sz = pages_to_alloc * sizeof(obj->sg_entries[0]);

	obj->sg_entries = kmalloc(sz, gfp_mask);
	if (unlikely(obj->sg_entries == NULL)) {
		TRACE(TRACE_OUT_OF_MEM, "Allocation of sgv_pool_obj "
			"SG vector failed (size %d)", sz);
		res = -ENOMEM;
		goto out;
	}

	sg_init_table(obj->sg_entries, pages_to_alloc);

	if (sgv_pool_clustered(obj->owner_pool)) {
		if (order <= sgv_pools_mgr.sgv_max_trans_order) {
			obj->trans_tbl =
				(struct trans_tbl_ent *)obj->sg_entries_data;
			/*
			 * No need to clear trans_tbl, if needed, it will be
			 * fully rewritten in scst_alloc_sg_entries()
			 */
		} else {
			tsz = pages_to_alloc * sizeof(obj->trans_tbl[0]);
			obj->trans_tbl = kzalloc(tsz, gfp_mask);
			if (unlikely(obj->trans_tbl == NULL)) {
				TRACE(TRACE_OUT_OF_MEM, "Allocation of "
					"trans_tbl failed (size %d)", tsz);
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

static void sgv_dtor_and_free(struct sgv_pool_obj *obj)
{
	if (obj->sg_count != 0) {
		obj->owner_pool->alloc_fns.free_pages_fn(obj->sg_entries,
			obj->sg_count, obj->allocator_priv);
	}
	if (obj->sg_entries != obj->sg_entries_data) {
		if (obj->trans_tbl !=
		    (struct trans_tbl_ent *)obj->sg_entries_data) {
			/* kfree() handles NULL parameter */
			kfree(obj->trans_tbl);
			obj->trans_tbl = NULL;
		}
		kfree(obj->sg_entries);
	}

	kmem_cache_free(obj->owner_pool->caches[obj->order_or_pages], obj);
	return;
}

static struct sgv_pool_obj *sgv_pool_cached_get(struct sgv_pool *pool,
	int order, gfp_t gfp_mask)
{
	struct sgv_pool_obj *obj;
	int pages = 1 << order;

	spin_lock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);
	if (likely(!list_empty(&pool->recycling_lists[order]))) {
		obj = list_entry(pool->recycling_lists[order].next,
			 struct sgv_pool_obj,
			recycle_entry.recycling_list_entry);

		list_del(&obj->recycle_entry.sorted_recycling_list_entry);
		list_del(&obj->recycle_entry.recycling_list_entry);

		sgv_pools_mgr.mgr.throttle.inactive_pages_total -= pages;
		sgv_pools_mgr.mgr.throttle.active_pages_total += pages;

		spin_unlock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);

		EXTRACHECKS_BUG_ON(obj->order_or_pages != order);
		goto out;
	}

	pool->acc.cached_entries++;
	pool->acc.cached_pages += pages;

	spin_unlock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);

	obj = kmem_cache_alloc(pool->caches[order],
		gfp_mask & ~(__GFP_HIGHMEM|GFP_DMA));
	if (likely(obj)) {
		memset(obj, 0, sizeof(*obj));
		obj->order_or_pages = order;
		obj->owner_pool = pool;
	} else {
		spin_lock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);
		pool->acc.cached_entries--;
		pool->acc.cached_pages -= pages;
		spin_unlock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);
	}

out:
	return obj;
}

static void sgv_pool_cached_put(struct sgv_pool_obj *sgv)
{
	struct sgv_pool *owner = sgv->owner_pool;
	struct list_head *entry;
	struct list_head *list = &owner->recycling_lists[sgv->order_or_pages];
	int sched = 0;
	int pages = 1 << sgv->order_or_pages;

	EXTRACHECKS_BUG_ON(sgv->order_or_pages < 0);

	spin_lock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);

	TRACE_MEM("sgv %p, order %d, sg_count %d", sgv, sgv->order_or_pages,
		sgv->sg_count);

	if (sgv_pool_clustered(owner)) {
		/* Make objects with less entries more preferred */
		__list_for_each(entry, list) {
			struct sgv_pool_obj *tmp = list_entry(entry,
				struct sgv_pool_obj,
				recycle_entry.recycling_list_entry);
			TRACE_DBG("tmp %p, order %d, sg_count %d", tmp,
				tmp->order_or_pages, tmp->sg_count);
			if (sgv->sg_count <= tmp->sg_count)
				break;
		}
		entry = entry->prev;
	} else
		entry = list;

	TRACE_DBG("Adding in %p (list %p)", entry, list);
	list_add(&sgv->recycle_entry.recycling_list_entry, entry);

	list_add_tail(&sgv->recycle_entry.sorted_recycling_list_entry,
		&sgv_pools_mgr.mgr.sorted_recycling_list);

	sgv->recycle_entry.time_stamp = jiffies;

	sgv_pools_mgr.mgr.throttle.inactive_pages_total += pages;
	sgv_pools_mgr.mgr.throttle.active_pages_total -= pages;

	if (!sgv_pools_mgr.mgr.pitbool_running) {
		sgv_pools_mgr.mgr.pitbool_running = 1;
		sched = 1;
	}

	spin_unlock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);

	if (sched)
		schedule_delayed_work(&sgv_pools_mgr.mgr.apit_pool,
			PURGE_INTERVAL);
}

/* Must be called under pool_mgr_lock held */
static void __sgv_pool_cached_purge(struct sgv_pool_obj *e)
{
	int pages = 1 << e->order_or_pages;

	list_del(&e->recycle_entry.sorted_recycling_list_entry);
	list_del(&e->recycle_entry.recycling_list_entry);
	e->owner_pool->acc.cached_entries--;
	e->owner_pool->acc.cached_pages -= pages;
	sgv_pools_mgr.mgr.throttle.inactive_pages_total -= pages;

	return;
}

/* Must be called under pool_mgr_lock held */
static int sgv_pool_cached_purge(struct sgv_pool_obj *e, int t,
	unsigned long rt)
{
	EXTRACHECKS_BUG_ON(t == 0);

	if (time_after(rt, (e->recycle_entry.time_stamp + t))) {
		__sgv_pool_cached_purge(e);
		return 0;
	}
	return 1;
}

/* Called under pool_mgr_lock held, but drops/reaquires it inside */
static int sgv_pool_oom_free_objs(int pgs)
	__releases(&sgv_pools_mgr.mgr.pool_mgr_lock)
	__acquires(&sgv_pools_mgr.mgr.pool_mgr_lock)
{
	TRACE_MEM("Shrinking pools about %d pages", pgs);
	while ((sgv_pools_mgr.mgr.throttle.inactive_pages_total >
			sgv_pools_mgr.mgr.throttle.lo_wmk) &&
	      (pgs > 0)) {
		struct sgv_pool_obj *e;

		sBUG_ON(list_empty(&sgv_pools_mgr.mgr.sorted_recycling_list));

		e = list_entry(sgv_pools_mgr.mgr.sorted_recycling_list.next,
			       struct sgv_pool_obj,
			       recycle_entry.sorted_recycling_list_entry);

		__sgv_pool_cached_purge(e);
		pgs -= 1 << e->order_or_pages;

		spin_unlock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);
		sgv_dtor_and_free(e);
		spin_lock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);
	}

	TRACE_MEM("Pages remaining %d ", pgs);
	return pgs;
}

static int sgv_pool_hiwmk_check(int pages_to_alloc)
{
	int res = 0;
	int pages = pages_to_alloc;

	spin_lock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);

	pages += sgv_pools_mgr.mgr.throttle.active_pages_total;
	pages += sgv_pools_mgr.mgr.throttle.inactive_pages_total;

	if (unlikely((u32)pages > sgv_pools_mgr.mgr.throttle.hi_wmk)) {
		pages -= sgv_pools_mgr.mgr.throttle.hi_wmk;
		sgv_pools_mgr.mgr.throttle.releases_on_hiwmk++;

		pages = sgv_pool_oom_free_objs(pages);
		if (pages > 0) {
			TRACE(TRACE_OUT_OF_MEM, "Requested amount of "
			    "memory (%d pages) for being executed "
			    "commands together with the already "
			    "allocated memory exceeds the allowed "
			    "maximum %d. Should you increase "
			    "scst_max_cmd_mem?", pages_to_alloc,
			   sgv_pools_mgr.mgr.throttle.hi_wmk);
			sgv_pools_mgr.mgr.throttle.releases_failed++;
			res = -ENOMEM;
			goto out_unlock;
		}
	}

	sgv_pools_mgr.mgr.throttle.active_pages_total += pages_to_alloc;

out_unlock:
	TRACE_MEM("pages_to_alloc %d, new active %d", pages_to_alloc,
		sgv_pools_mgr.mgr.throttle.active_pages_total);

	spin_unlock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);
	return res;
}

static void sgv_pool_hiwmk_uncheck(int pages)
{
	spin_lock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);
	sgv_pools_mgr.mgr.throttle.active_pages_total -= pages;
	TRACE_MEM("pages %d, new active %d", pages,
		sgv_pools_mgr.mgr.throttle.active_pages_total);
	spin_unlock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);
	return;
}

static bool scst_check_allowed_mem(struct scst_mem_lim *mem_lim, int pages)
{
	int alloced;
	bool res = true;

	alloced = atomic_add_return(pages, &mem_lim->alloced_pages);
	if (unlikely(alloced > mem_lim->max_allowed_pages)) {
		TRACE(TRACE_OUT_OF_MEM, "Requested amount of memory "
			"(%d pages) for being executed commands on a device "
			"together with the already allocated memory exceeds "
			"the allowed maximum %d. Should you increase "
			"scst_max_dev_cmd_mem?", pages,
			mem_lim->max_allowed_pages);
		atomic_sub(pages, &mem_lim->alloced_pages);
		res = false;
	}

	TRACE_MEM("mem_lim %p, pages %d, res %d, new alloced %d", mem_lim,
		pages, res, atomic_read(&mem_lim->alloced_pages));

	return res;
}

static void scst_uncheck_allowed_mem(struct scst_mem_lim *mem_lim, int pages)
{
	atomic_sub(pages, &mem_lim->alloced_pages);

	TRACE_MEM("mem_lim %p, pages %d, new alloced %d", mem_lim,
		pages, atomic_read(&mem_lim->alloced_pages));
	return;
}

struct scatterlist *sgv_pool_alloc(struct sgv_pool *pool, unsigned int size,
	gfp_t gfp_mask, int flags, int *count,
	struct sgv_pool_obj **sgv, struct scst_mem_lim *mem_lim, void *priv)
{
	struct sgv_pool_obj *obj;
	int order, pages, cnt;
	struct scatterlist *res = NULL;
	int pages_to_alloc;
	struct kmem_cache *cache;
	int no_cached = flags & SCST_POOL_ALLOC_NO_CACHED;
	bool allowed_mem_checked = false, hiwmk_checked = false;

	TRACE_ENTRY();

	if (unlikely(size == 0))
		goto out;

	sBUG_ON((gfp_mask & __GFP_NOFAIL) == __GFP_NOFAIL);

	pages = ((size + PAGE_SIZE - 1) >> PAGE_SHIFT);
	order = get_order(size);

	TRACE_MEM("size=%d, pages=%d, order=%d, flags=%x, *sgv %p", size, pages,
		order, flags, *sgv);

	if (*sgv != NULL) {
		obj = *sgv;
		pages_to_alloc = (1 << order);
		cache = pool->caches[obj->order_or_pages];

		TRACE_MEM("Supplied sgv_obj %p, sgv_order %d", obj,
			obj->order_or_pages);

		EXTRACHECKS_BUG_ON(obj->order_or_pages != order);
		EXTRACHECKS_BUG_ON(obj->sg_count != 0);

		if (unlikely(!scst_check_allowed_mem(mem_lim, pages_to_alloc)))
			goto out_fail_free_sg_entries;
		allowed_mem_checked = true;

		if (unlikely(sgv_pool_hiwmk_check(pages_to_alloc) != 0))
			goto out_fail_free_sg_entries;
		hiwmk_checked = true;
	} else if ((order < SGV_POOL_ELEMENTS) && !no_cached) {
		pages_to_alloc = (1 << order);
		cache = pool->caches[order];

		if (unlikely(!scst_check_allowed_mem(mem_lim, pages_to_alloc)))
			goto out_fail;
		allowed_mem_checked = true;

		obj = sgv_pool_cached_get(pool, order, gfp_mask);
		if (unlikely(obj == NULL)) {
			TRACE(TRACE_OUT_OF_MEM, "Allocation of "
				"sgv_pool_obj failed (size %d)", size);
			goto out_fail;
		}

		if (obj->sg_count != 0) {
			TRACE_MEM("Cached sgv_obj %p", obj);
			EXTRACHECKS_BUG_ON(obj->order_or_pages != order);
			atomic_inc(&pool->cache_acc[order].hit_alloc);
			goto success;
		}

		if (flags & SCST_POOL_NO_ALLOC_ON_CACHE_MISS) {
			if (!(flags & SCST_POOL_RETURN_OBJ_ON_ALLOC_FAIL))
				goto out_fail_free;
		}

		TRACE_MEM("Brand new sgv_obj %p", obj);

		if (order <= sgv_pools_mgr.sgv_max_local_order) {
			obj->sg_entries = obj->sg_entries_data;
			sg_init_table(obj->sg_entries, pages_to_alloc);
			TRACE_MEM("sg_entries %p", obj->sg_entries);
			if (sgv_pool_clustered(pool)) {
				obj->trans_tbl = (struct trans_tbl_ent *)
					(obj->sg_entries + pages_to_alloc);
				TRACE_MEM("trans_tbl %p", obj->trans_tbl);
				/*
				 * No need to clear trans_tbl, if needed, it
				 * will be fully rewritten in
				 * scst_alloc_sg_entries(),
				 */
			}
		} else {
			if (unlikely(sgv_alloc_arrays(obj, pages_to_alloc,
					order, gfp_mask) != 0))
				goto out_fail_free;
		}

		if ((flags & SCST_POOL_NO_ALLOC_ON_CACHE_MISS) &&
		    (flags & SCST_POOL_RETURN_OBJ_ON_ALLOC_FAIL))
			goto out_return;

		obj->allocator_priv = priv;

		if (unlikely(sgv_pool_hiwmk_check(pages_to_alloc) != 0))
			goto out_fail_free_sg_entries;
		hiwmk_checked = true;
	} else {
		int sz;

		pages_to_alloc = pages;

		if (unlikely(!scst_check_allowed_mem(mem_lim, pages_to_alloc)))
			goto out_fail;
		allowed_mem_checked = true;

		if (flags & SCST_POOL_NO_ALLOC_ON_CACHE_MISS)
			goto out_return2;

		cache = NULL;
		sz = sizeof(*obj) + pages*sizeof(obj->sg_entries[0]);

		obj = kmalloc(sz, gfp_mask);
		if (unlikely(obj == NULL)) {
			TRACE(TRACE_OUT_OF_MEM, "Allocation of "
				"sgv_pool_obj failed (size %d)", size);
			goto out_fail;
		}
		memset(obj, 0, sizeof(*obj));

		obj->owner_pool = pool;
		obj->order_or_pages = -pages_to_alloc;
		obj->allocator_priv = priv;

		obj->sg_entries = obj->sg_entries_data;
		sg_init_table(obj->sg_entries, pages);

		if (unlikely(sgv_pool_hiwmk_check(pages_to_alloc) != 0))
			goto out_fail_free_sg_entries;
		hiwmk_checked = true;

		TRACE_MEM("Big or no_cached sgv_obj %p (size %d)", obj,	sz);
	}

	obj->sg_count = scst_alloc_sg_entries(obj->sg_entries,
		pages_to_alloc, gfp_mask, pool->clustering_type,
		obj->trans_tbl, &pool->alloc_fns, priv);
	if (unlikely(obj->sg_count <= 0)) {
		obj->sg_count = 0;
		if ((flags & SCST_POOL_RETURN_OBJ_ON_ALLOC_FAIL) && cache)
			goto out_return1;
		else
			goto out_fail_free_sg_entries;
	}

	if (cache) {
		atomic_add(pages_to_alloc - obj->sg_count,
			&pool->cache_acc[order].merged);
	} else {
		if (no_cached) {
			atomic_add(pages_to_alloc,
				&pool->acc.other_pages);
			atomic_add(pages_to_alloc - obj->sg_count,
				&pool->acc.other_merged);
		} else {
			atomic_add(pages_to_alloc,
				&pool->acc.big_pages);
			atomic_add(pages_to_alloc - obj->sg_count,
				&pool->acc.big_merged);
		}
	}

success:
	if (cache) {
		int sg;
		atomic_inc(&pool->cache_acc[order].total_alloc);
		if (sgv_pool_clustered(pool))
			cnt = obj->trans_tbl[pages-1].sg_num;
		else
			cnt = pages;
		sg = cnt-1;
		obj->orig_sg = sg;
		obj->orig_length = obj->sg_entries[sg].length;
		if (sgv_pool_clustered(pool)) {
			obj->sg_entries[sg].length =
				(pages - obj->trans_tbl[sg].pg_count) << PAGE_SHIFT;
		}
	} else {
		cnt = obj->sg_count;
		if (no_cached)
			atomic_inc(&pool->acc.other_alloc);
		else
			atomic_inc(&pool->acc.big_alloc);
	}

	*count = cnt;
	res = obj->sg_entries;
	*sgv = obj;

	if (size & ~PAGE_MASK)
		obj->sg_entries[cnt-1].length -=
			PAGE_SIZE - (size & ~PAGE_MASK);

	TRACE_MEM("sgv_obj=%p, sg_entries %p (size=%d, pages=%d, sg_count=%d, "
		"count=%d, last_len=%d)", obj, obj->sg_entries, size, pages,
		obj->sg_count, *count, obj->sg_entries[obj->orig_sg].length);

out:
	TRACE_EXIT_HRES(res);
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
	goto out_uncheck;

out_fail_free_sg_entries:
	if (obj->sg_entries != obj->sg_entries_data) {
		if (obj->trans_tbl !=
			(struct trans_tbl_ent *)obj->sg_entries_data) {
			/* kfree() handles NULL parameter */
			kfree(obj->trans_tbl);
			obj->trans_tbl = NULL;
		}
		kfree(obj->sg_entries);
		obj->sg_entries = NULL;
	}

out_fail_free:
	if (cache)
		sgv_pool_cached_put(obj);
	else
		kfree(obj);

out_fail:
	res = NULL;
	*count = 0;
	*sgv = NULL;
	TRACE_MEM("%s", "Allocation failed");

out_uncheck:
	if (hiwmk_checked)
		sgv_pool_hiwmk_uncheck(pages_to_alloc);
	if (allowed_mem_checked)
		scst_uncheck_allowed_mem(mem_lim, pages_to_alloc);
	goto out;
}
EXPORT_SYMBOL(sgv_pool_alloc);

void *sgv_get_priv(struct sgv_pool_obj *sgv)
{
	return sgv->allocator_priv;
}
EXPORT_SYMBOL(sgv_get_priv);

void sgv_pool_free(struct sgv_pool_obj *sgv, struct scst_mem_lim *mem_lim)
{
	int pages;

	TRACE_MEM("Freeing sgv_obj %p, order %d, sg_entries %p, "
		"sg_count %d, allocator_priv %p", sgv, sgv->order_or_pages,
		sgv->sg_entries, sgv->sg_count, sgv->allocator_priv);

	if (sgv->order_or_pages >= 0) {
		sgv->sg_entries[sgv->orig_sg].length = sgv->orig_length;
		pages = (sgv->sg_count != 0) ? 1 << sgv->order_or_pages : 0;
		sgv_pool_cached_put(sgv);
	} else {
		sgv->owner_pool->alloc_fns.free_pages_fn(sgv->sg_entries,
			sgv->sg_count, sgv->allocator_priv);
		pages = (sgv->sg_count != 0) ? -sgv->order_or_pages : 0;
		kfree(sgv);
		sgv_pool_hiwmk_uncheck(pages);
	}

	scst_uncheck_allowed_mem(mem_lim, pages);

	return;
}
EXPORT_SYMBOL(sgv_pool_free);

struct scatterlist *scst_alloc(int size, gfp_t gfp_mask, int *count)
{
	struct scatterlist *res;
	int pages = (size >> PAGE_SHIFT) + ((size & ~PAGE_MASK) != 0);
	struct sgv_pool_alloc_fns sys_alloc_fns = {
		scst_alloc_sys_pages, scst_free_sys_sg_entries };
	int no_fail = ((gfp_mask & __GFP_NOFAIL) == __GFP_NOFAIL);

	TRACE_ENTRY();

	atomic_inc(&sgv_pools_mgr.sgv_other_total_alloc);

	if (unlikely(!no_fail)) {
		if (unlikely(sgv_pool_hiwmk_check(pages) != 0)) {
			res = NULL;
			goto out;
		}
	}

	res = kmalloc(pages*sizeof(*res), gfp_mask);
	if (res == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "Unable to allocate sg for %d pages",
			pages);
		goto out_uncheck;
	}

	sg_init_table(res, pages);

	/*
	 * If we allow use clustering here, we will have troubles in
	 * scst_free() to figure out how many pages are in the SG vector.
	 * So, always don't use clustering.
	 */
	*count = scst_alloc_sg_entries(res, pages, gfp_mask, sgv_no_clustering,
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

out_uncheck:
	if (!no_fail)
		sgv_pool_hiwmk_uncheck(pages);
	goto out;
}
EXPORT_SYMBOL(scst_alloc);

void scst_free(struct scatterlist *sg, int count)
{
	TRACE_MEM("Freeing sg=%p", sg);

	sgv_pool_hiwmk_uncheck(count);

	scst_free_sys_sg_entries(sg, count, NULL);
	kfree(sg);
	return;
}
EXPORT_SYMBOL(scst_free);

static void sgv_pool_cached_init(struct sgv_pool *pool)
{
	int i;
	for (i = 0; i < SGV_POOL_ELEMENTS; i++)
		INIT_LIST_HEAD(&pool->recycling_lists[i]);
}

int sgv_pool_init(struct sgv_pool *pool, const char *name,
	enum sgv_clustering_types clustering_type)
{
	int res = -ENOMEM;
	int i;
	struct sgv_pool_obj *obj;

	TRACE_ENTRY();

	memset(pool, 0, sizeof(*pool));

	atomic_set(&pool->acc.other_alloc, 0);
	atomic_set(&pool->acc.big_alloc, 0);
	atomic_set(&pool->acc.other_pages, 0);
	atomic_set(&pool->acc.big_pages, 0);
	atomic_set(&pool->acc.other_merged, 0);
	atomic_set(&pool->acc.big_merged, 0);

	pool->clustering_type = clustering_type;
	pool->alloc_fns.alloc_pages_fn = scst_alloc_sys_pages;
	pool->alloc_fns.free_pages_fn = scst_free_sys_sg_entries;

	TRACE_MEM("name %s, sizeof(*obj)=%zd, clustering_type=%d", name,
		sizeof(*obj), clustering_type);

	strncpy(pool->name, name, sizeof(pool->name)-1);
	pool->name[sizeof(pool->name)-1] = '\0';

	for (i = 0; i < SGV_POOL_ELEMENTS; i++) {
		int size;

		atomic_set(&pool->cache_acc[i].total_alloc, 0);
		atomic_set(&pool->cache_acc[i].hit_alloc, 0);
		atomic_set(&pool->cache_acc[i].merged, 0);

		if (i <= sgv_pools_mgr.sgv_max_local_order) {
			size = sizeof(*obj) + (1 << i) *
				(sizeof(obj->sg_entries[0]) +
				 ((clustering_type != sgv_no_clustering) ?
				 	sizeof(obj->trans_tbl[0]) : 0));
		} else if (i <= sgv_pools_mgr.sgv_max_trans_order) {
			/*
			 * sgv ie sg_entries is allocated outside object, but
			 * ttbl is still embedded.
			 */
			size = sizeof(*obj) + (1 << i) *
				(((clustering_type != sgv_no_clustering) ?
					sizeof(obj->trans_tbl[0]) : 0));
		} else {
			size = sizeof(*obj);

			/* both sgv and ttbl are kallocated() */
		}

		TRACE_MEM("pages=%d, size=%d", 1 << i, size);

		scnprintf(pool->cache_names[i], sizeof(pool->cache_names[i]),
			"%s-%luK", name, (PAGE_SIZE >> 10) << i);
		pool->caches[i] = kmem_cache_create(pool->cache_names[i],
			size, 0, SCST_SLAB_FLAGS, NULL
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23))
			, NULL);
#else
			);
#endif
		if (pool->caches[i] == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "Allocation of sgv_pool cache "
				"%s(%d) failed", name, i);
			goto out_free;
		}
	}

	sgv_pool_cached_init(pool);

	mutex_lock(&sgv_pools_mgr.scst_sgv_pool_mutex);
	list_add_tail(&pool->sgv_pool_list_entry,
		&sgv_pools_mgr.scst_sgv_pool_list);
	mutex_unlock(&sgv_pools_mgr.scst_sgv_pool_mutex);

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	for (i = 0; i < SGV_POOL_ELEMENTS; i++) {
		if (pool->caches[i]) {
			kmem_cache_destroy(pool->caches[i]);
			pool->caches[i] = NULL;
		} else
			break;
	}
	goto out;
}

static void sgv_pool_evaluate_local_order(struct scst_sgv_pools_manager *pmgr)
{
	int space4sgv_ttbl = PAGE_SIZE - sizeof(struct sgv_pool_obj);

	pmgr->sgv_max_local_order = get_order(
		(((space4sgv_ttbl /
		  (sizeof(struct trans_tbl_ent) + sizeof(struct scatterlist))) *
			PAGE_SIZE) & PAGE_MASK)) - 1;

	pmgr->sgv_max_trans_order = get_order(
		(((space4sgv_ttbl / sizeof(struct trans_tbl_ent)) * PAGE_SIZE)
		 & PAGE_MASK)) - 1;

	TRACE_MEM("sgv_max_local_order %d, sgv_max_trans_order %d",
		pmgr->sgv_max_local_order, pmgr->sgv_max_trans_order);
	TRACE_MEM("max object size with embedded sgv & ttbl %zd",
		(1 << pmgr->sgv_max_local_order) *
		(sizeof(struct trans_tbl_ent) + sizeof(struct scatterlist))
		+ sizeof(struct sgv_pool_obj));
	TRACE_MEM("max object size with embedded sgv (!clustered) %zd",
		(1 << pmgr->sgv_max_local_order) *
		(sizeof(struct scatterlist))
		+ sizeof(struct sgv_pool_obj));
	TRACE_MEM("max object size with embedded ttbl %zd",
		(1 << pmgr->sgv_max_trans_order) * sizeof(struct trans_tbl_ent)
		+ sizeof(struct sgv_pool_obj));
}

void sgv_pool_flush(struct sgv_pool *pool)
{
	int i;

	TRACE_ENTRY();

	for (i = 0; i < SGV_POOL_ELEMENTS; i++) {
		struct sgv_pool_obj *e;

		spin_lock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);
		while (!list_empty(&pool->recycling_lists[i])) {
			e = list_entry(pool->recycling_lists[i].next,
				struct sgv_pool_obj,
				recycle_entry.recycling_list_entry);

			__sgv_pool_cached_purge(e);
			spin_unlock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);

			EXTRACHECKS_BUG_ON(e->owner_pool != pool);
			sgv_dtor_and_free(e);

			spin_lock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);
		}
		spin_unlock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);
	}

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL(sgv_pool_flush);

void sgv_pool_deinit(struct sgv_pool *pool)
{
	int i;

	TRACE_ENTRY();

	mutex_lock(&sgv_pools_mgr.scst_sgv_pool_mutex);
	list_del(&pool->sgv_pool_list_entry);
	mutex_unlock(&sgv_pools_mgr.scst_sgv_pool_mutex);

	sgv_pool_flush(pool);

	for (i = 0; i < SGV_POOL_ELEMENTS; i++) {
		if (pool->caches[i])
			kmem_cache_destroy(pool->caches[i]);
		pool->caches[i] = NULL;
	}

	TRACE_EXIT();
	return;
}

void sgv_pool_set_allocator(struct sgv_pool *pool,
	struct page *(*alloc_pages_fn)(struct scatterlist *, gfp_t, void *),
	void (*free_pages_fn)(struct scatterlist *, int, void *))
{
	pool->alloc_fns.alloc_pages_fn = alloc_pages_fn;
	pool->alloc_fns.free_pages_fn = free_pages_fn;
	return;
}
EXPORT_SYMBOL(sgv_pool_set_allocator);

struct sgv_pool *sgv_pool_create(const char *name,
	enum sgv_clustering_types clustering_type)
{
	struct sgv_pool *pool;
	int rc;

	TRACE_ENTRY();

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (pool == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of sgv_pool failed");
		goto out;
	}

	rc = sgv_pool_init(pool, name, clustering_type);
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
EXPORT_SYMBOL(sgv_pool_create);

void sgv_pool_destroy(struct sgv_pool *pool)
{
	TRACE_ENTRY();

	sgv_pool_deinit(pool);
	kfree(pool);

	TRACE_EXIT();
}
EXPORT_SYMBOL(sgv_pool_destroy);

static int sgv_pool_cached_shrinker(int nr, gfp_t gfpm)
{
	TRACE_ENTRY();

	spin_lock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);

	if (nr > 0) {
		struct sgv_pool_obj *e;
		unsigned long rt = jiffies;

		while (!list_empty(&sgv_pools_mgr.mgr.sorted_recycling_list)) {
			e = list_entry(
				sgv_pools_mgr.mgr.sorted_recycling_list.next,
				struct sgv_pool_obj,
				recycle_entry.sorted_recycling_list_entry);

			if (sgv_pool_cached_purge(e, SHRINK_TIME_AFTER, rt) == 0) {
				nr -= 1 << e->order_or_pages;
				spin_unlock_bh(
					&sgv_pools_mgr.mgr.pool_mgr_lock);
				sgv_dtor_and_free(e);
				spin_lock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);
			} else
				break;

			if (nr <= 0)
				break;
		}
	}

	nr = sgv_pools_mgr.mgr.throttle.inactive_pages_total;

	spin_unlock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);

	TRACE_EXIT();
	return nr;
}

static void sgv_pool_cached_pitbool(void *p)
{
	u32 total_pages;
	struct sgv_pool_obj *e;
	unsigned long rt = jiffies;

	TRACE_ENTRY();

	spin_lock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);

	sgv_pools_mgr.mgr.pitbool_running = 0;

	while (!list_empty(&sgv_pools_mgr.mgr.sorted_recycling_list)) {
		e = list_entry(sgv_pools_mgr.mgr.sorted_recycling_list.next,
			struct sgv_pool_obj,
			recycle_entry.sorted_recycling_list_entry);

		if (sgv_pool_cached_purge(e, PURGE_TIME_AFTER, rt) == 0) {
			spin_unlock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);
			sgv_dtor_and_free(e);
			spin_lock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);
		} else
			break;
	}

	total_pages = sgv_pools_mgr.mgr.throttle.inactive_pages_total;

	spin_unlock_bh(&sgv_pools_mgr.mgr.pool_mgr_lock);

	if (total_pages) {
		schedule_delayed_work(&sgv_pools_mgr.mgr.apit_pool,
			PURGE_INTERVAL);
	}

	TRACE_EXIT();
	return;
}

/* Both parameters in pages */
int scst_sgv_pools_init(unsigned long mem_hwmark, unsigned long mem_lwmark)
{
	int res;
	struct scst_sgv_pools_manager *pools = &sgv_pools_mgr;

	TRACE_ENTRY();

	memset(pools, 0, sizeof(*pools));

	sgv_pools_mgr.mgr.throttle.hi_wmk = mem_hwmark;
	sgv_pools_mgr.mgr.throttle.lo_wmk = mem_lwmark;

	sgv_pool_evaluate_local_order(&sgv_pools_mgr);

	atomic_set(&pools->sgv_other_total_alloc, 0);
	INIT_LIST_HEAD(&pools->scst_sgv_pool_list);
	mutex_init(&pools->scst_sgv_pool_mutex);

	INIT_LIST_HEAD(&pools->mgr.sorted_recycling_list);
	spin_lock_init(&pools->mgr.pool_mgr_lock);

	res = sgv_pool_init(&pools->default_set.norm, "sgv", sgv_no_clustering);
	if (res != 0)
		goto out;

	res = sgv_pool_init(&pools->default_set.norm_clust, "sgv-clust",
		sgv_full_clustering);
	if (res != 0)
		goto out_free_clust;

	res = sgv_pool_init(&pools->default_set.dma, "sgv-dma",
		sgv_no_clustering);
	if (res != 0)
		goto out_free_norm;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20))
	INIT_DELAYED_WORK(&pools->mgr.apit_pool,
		(void (*)(struct work_struct *))sgv_pool_cached_pitbool);
#else
	INIT_WORK(&pools->mgr.apit_pool, sgv_pool_cached_pitbool, NULL);
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23))
	pools->mgr.sgv_shrinker = set_shrinker(DEFAULT_SEEKS,
		sgv_pool_cached_shrinker);
#else
	pools->mgr.sgv_shrinker.shrink = sgv_pool_cached_shrinker;
	pools->mgr.sgv_shrinker.seeks = DEFAULT_SEEKS;
	register_shrinker(&pools->mgr.sgv_shrinker);
#endif

out:
	TRACE_EXIT_RES(res);
	return res;

out_free_norm:
	sgv_pool_deinit(&pools->default_set.norm);

out_free_clust:
	sgv_pool_deinit(&pools->default_set.norm_clust);
	goto out;
}

void scst_sgv_pools_deinit(void)
{
	struct scst_sgv_pools_manager *pools = &sgv_pools_mgr;

	TRACE_ENTRY();

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23))
	remove_shrinker(pools->mgr.sgv_shrinker);
#else
	unregister_shrinker(&pools->mgr.sgv_shrinker);
#endif

	cancel_delayed_work(&pools->mgr.apit_pool);

	sgv_pool_deinit(&pools->default_set.dma);
	sgv_pool_deinit(&pools->default_set.norm);
	sgv_pool_deinit(&pools->default_set.norm_clust);

	flush_scheduled_work();

	TRACE_EXIT();
	return;
}

static void scst_do_sgv_read(struct seq_file *seq, const struct sgv_pool *pool)
{
	int i, total = 0, hit = 0, merged = 0, allocated = 0;
	int oa, om;

	for (i = 0; i < SGV_POOL_ELEMENTS; i++) {
		int t;

		hit += atomic_read(&pool->cache_acc[i].hit_alloc);
		total += atomic_read(&pool->cache_acc[i].total_alloc);

		t = atomic_read(&pool->cache_acc[i].total_alloc) -
			atomic_read(&pool->cache_acc[i].hit_alloc);
		allocated += t * (1 << i);
		merged += atomic_read(&pool->cache_acc[i].merged);
	}

	seq_printf(seq, "\n%-30s %-11d %-11d %-11d %d/%d (P/O)\n", pool->name,
		hit, total, (allocated != 0) ? merged*100/allocated : 0,
		pool->acc.cached_pages, pool->acc.cached_entries);

	for (i = 0; i < SGV_POOL_ELEMENTS; i++) {
		int t = atomic_read(&pool->cache_acc[i].total_alloc) -
			atomic_read(&pool->cache_acc[i].hit_alloc);
		allocated = t * (1 << i);
		merged = atomic_read(&pool->cache_acc[i].merged);

		seq_printf(seq, "  %-28s %-11d %-11d %d\n",
			pool->cache_names[i],
			atomic_read(&pool->cache_acc[i].hit_alloc),
			atomic_read(&pool->cache_acc[i].total_alloc),
			(allocated != 0) ? merged*100/allocated : 0);
	}

	allocated = atomic_read(&pool->acc.big_pages);
	merged = atomic_read(&pool->acc.big_merged);
	oa = atomic_read(&pool->acc.other_pages);
	om = atomic_read(&pool->acc.other_merged);

	seq_printf(seq, "  %-40s %d/%-9d %d/%d\n", "big/other",
		   atomic_read(&pool->acc.big_alloc),
		   atomic_read(&pool->acc.other_alloc),
		   (allocated != 0) ? merged*100/allocated : 0,
		   (oa != 0) ? om/oa : 0);

	return;
}

int sgv_pool_procinfo_show(struct seq_file *seq, void *v)
{
	struct sgv_pool *pool;

	TRACE_ENTRY();

	seq_printf(seq, "%-42s %d/%d\n%-42s %d/%d\n%-42s %d/%d\n\n",
		"Inactive/active pages",
		sgv_pools_mgr.mgr.throttle.inactive_pages_total,
		sgv_pools_mgr.mgr.throttle.active_pages_total,
		"Hi/lo watermarks [pages]", sgv_pools_mgr.mgr.throttle.hi_wmk,
		sgv_pools_mgr.mgr.throttle.lo_wmk,
		"Hi watermark releases/failures",
		sgv_pools_mgr.mgr.throttle.releases_on_hiwmk,
		sgv_pools_mgr.mgr.throttle.releases_failed);

	seq_printf(seq, "%-30s %-11s %-11s %-11s %-11s", "Name", "Hit", "Total",
		"% merged", "Cached");

	mutex_lock(&sgv_pools_mgr.scst_sgv_pool_mutex);
	list_for_each_entry(pool, &sgv_pools_mgr.scst_sgv_pool_list,
			sgv_pool_list_entry) {
		scst_do_sgv_read(seq, pool);
	}
	mutex_unlock(&sgv_pools_mgr.scst_sgv_pool_mutex);

	seq_printf(seq, "\n%-42s %-11d\n", "other",
		atomic_read(&sgv_pools_mgr.sgv_other_total_alloc));

	TRACE_EXIT();
	return 0;
}
