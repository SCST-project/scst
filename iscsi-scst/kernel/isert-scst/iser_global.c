/*
 * isert_global.c
 *
 * This file is part of iser target kernel module.
 *
 * Copyright (c) 2013 - 2014 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2013 - 2014 Yan Burman (yanb@mellanox.com)
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *            - Redistributions of source code must retain the above
 *              copyright notice, this list of conditions and the following
 *              disclaimer.
 *
 *            - Redistributions in binary form must reproduce the above
 *              copyright notice, this list of conditions and the following
 *              disclaimer in the documentation and/or other materials
 *              provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/kernel.h>

#include "isert_dbg.h"
#include "iser.h"

static struct isert_global isert_glob;

struct kmem_cache *isert_cmnd_cache;
struct kmem_cache *isert_conn_cache;

void isert_portal_list_add(struct isert_portal *portal)
{
	spin_lock(&isert_glob.portal_lock);
	list_add_tail(&portal->list_node, &isert_glob.portal_list);
	isert_glob.portal_cnt++;
	spin_unlock(&isert_glob.portal_lock);
}

void isert_portal_list_remove(struct isert_portal *portal)
{
	spin_lock(&isert_glob.portal_lock);
	list_del_init(&portal->list_node);
	spin_unlock(&isert_glob.portal_lock);
}

void isert_decrease_portal_cnt(void)
{
	spin_lock(&isert_glob.portal_lock);
	WARN_ON_ONCE(isert_glob.portal_cnt <= 0);
	spin_unlock(&isert_glob.portal_lock);

	if (--isert_glob.portal_cnt == 0)
		wake_up_all(&isert_glob.portal_wq);
}

static int isert_portal_cnt(void)
{
	int portal_cnt;

	spin_lock(&isert_glob.portal_lock);
	portal_cnt = isert_glob.portal_cnt;
	spin_unlock(&isert_glob.portal_lock);

	return portal_cnt;
}

void isert_wait_for_portal_release(void)
{
	wait_event(isert_glob.portal_wq, isert_portal_cnt() == 0);
}

void isert_dev_list_add(struct isert_device *isert_dev)
{
	list_add_tail(&isert_dev->devs_node, &isert_glob.dev_list);
}

void isert_dev_list_remove(struct isert_device *isert_dev)
{
	list_del_init(&isert_dev->devs_node);
}

struct isert_device *isert_device_find(struct ib_device *ib_dev)
{
	struct isert_device *isert_dev;
	struct isert_device *res = NULL;

	list_for_each_entry(isert_dev, &isert_glob.dev_list, devs_node) {
		if (isert_dev->ib_dev == ib_dev) {
			res = isert_dev;
			break;
		}
	}

	return res;
}

void isert_portal_list_release_all(void)
{
	struct isert_portal *portal, *n;

	list_for_each_entry_safe(portal, n, &isert_glob.portal_list, list_node)
		isert_portal_release(portal);
	isert_wait_for_portal_release();
}

void isert_conn_queue_work(struct work_struct *w)
{
	queue_work(isert_glob.conn_wq, w);
}

int isert_global_init(void)
{
	isert_glob.portal_cnt = 0;

	INIT_LIST_HEAD(&isert_glob.portal_list);
	INIT_LIST_HEAD(&isert_glob.dev_list);

	spin_lock_init(&isert_glob.portal_lock);
	init_waitqueue_head(&isert_glob.portal_wq);

	isert_glob.conn_wq = create_workqueue("isert_conn_wq");
	if (!isert_glob.conn_wq) {
		PRINT_ERROR("Failed to alloc iser conn work queue");
		return -ENOMEM;
	}

	isert_cmnd_cache = KMEM_CACHE(isert_cmnd,
				     SCST_SLAB_FLAGS|SLAB_HWCACHE_ALIGN);
	if (!isert_cmnd_cache) {
		destroy_workqueue(isert_glob.conn_wq);
		PRINT_ERROR("Failed to alloc iser command cache");
		return -ENOMEM;
	}

	isert_conn_cache = KMEM_CACHE(isert_connection,
				     SCST_SLAB_FLAGS|SLAB_HWCACHE_ALIGN);
	if (!isert_conn_cache) {
		destroy_workqueue(isert_glob.conn_wq);
		kmem_cache_destroy(isert_cmnd_cache);
		PRINT_ERROR("Failed to alloc iser connection cache");
		return -ENOMEM;
	}

	return 0;
}

void isert_global_cleanup(void)
{
	isert_portal_list_release_all();
	if (isert_glob.conn_wq)
		destroy_workqueue(isert_glob.conn_wq);
	if (isert_cmnd_cache)
		kmem_cache_destroy(isert_cmnd_cache);
	if (isert_conn_cache)
		kmem_cache_destroy(isert_conn_cache);
}

int isert_get_addr_size(struct sockaddr *sa, size_t *addr_len)
{
	int ret = 0;

	switch (sa->sa_family) {
	case AF_INET:
		*addr_len = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		*addr_len = sizeof(struct sockaddr_in6);
		break;
	default:
		PRINT_ERROR("Unknown address family");
		ret = -EINVAL;
		goto out;
	}
out:
	return ret;
}
