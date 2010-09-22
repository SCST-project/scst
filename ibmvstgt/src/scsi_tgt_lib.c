/*
 * SCSI target lib functions
 *
 * Copyright (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * Copyright (C) 2005 FUJITA Tomonori <tomof@acm.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <linux/blkdev.h>
#include <linux/hash.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_transport.h>
#include <scsi/scsi_tgt.h>

#include "scsi_tgt_priv.h"

static struct workqueue_struct *scsi_tgtd;
static struct kmem_cache *scsi_tgt_cmd_cache;

/*
 * TODO: this struct will be killed when the block layer supports large bios
 * and James's work struct code is in
 */
struct scsi_tgt_cmd {
	/* TODO replace work with James b's code */
	struct work_struct work;
	/* TODO fix limits of some drivers */
	struct bio *bio;

	struct list_head hash_list;
	struct request *rq;
	u64 itn_id;
	u64 tag;
};

#define TGT_HASH_ORDER	4
#define cmd_hashfn(tag)	hash_long((unsigned long) (tag), TGT_HASH_ORDER)

struct scsi_tgt_queuedata {
	struct Scsi_Host *shost;
	struct list_head cmd_hash[1 << TGT_HASH_ORDER];
	spinlock_t cmd_hash_lock;
};

static int __init scsi_tgt_init(void)
{
	int err;

	scsi_tgt_cmd_cache =  KMEM_CACHE(scsi_tgt_cmd, 0);
	if (!scsi_tgt_cmd_cache)
		return -ENOMEM;

	scsi_tgtd = create_workqueue("scsi_tgtd");
	if (!scsi_tgtd) {
		err = -ENOMEM;
		goto free_kmemcache;
	}

	err = scsi_tgt_if_init();
	if (err)
		goto destroy_wq;

	return 0;

destroy_wq:
	destroy_workqueue(scsi_tgtd);
free_kmemcache:
	kmem_cache_destroy(scsi_tgt_cmd_cache);
	return err;
}

static void __exit scsi_tgt_exit(void)
{
	destroy_workqueue(scsi_tgtd);
	scsi_tgt_if_exit();
	kmem_cache_destroy(scsi_tgt_cmd_cache);
}

module_init(scsi_tgt_init);
module_exit(scsi_tgt_exit);

MODULE_DESCRIPTION("SCSI target core");
MODULE_LICENSE("GPL");
