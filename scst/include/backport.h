#ifndef _SCST_BACKPORT_H_
#define _SCST_BACKPORT_H_

/*
 *  Copyright (C) 2015 - 2018 Western Digital Corporation
 *
 *  Backports of functions introduced in recent kernel versions.
 *
 *  Please keep the functions in this file sorted according to the name of the
 *  header file in which these have been defined.
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

#include <linux/version.h>
#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a, b) (((a) << 8) + (b))
#endif
#include <linux/bio.h>
#include <linux/blkdev.h>	/* struct request_queue */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 21, 0) || \
	(defined(RHEL_MAJOR) && RHEL_MAJOR -0 >= 8)
#include <linux/blk-mq.h>
#endif
#include <linux/bsg-lib.h>	/* struct bsg_job */
#include <linux/debugfs.h>
#include <linux/dmapool.h>
#include <linux/eventpoll.h>
#include <linux/iocontext.h>
#include <linux/kobject_ns.h>
#include <linux/scatterlist.h>	/* struct scatterlist */
#include <linux/slab.h>		/* kmalloc() */
#include <linux/stddef.h>	/* sizeof_field() */
#include <linux/timer.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/writeback.h>	/* sync_page_range() */
#include <net/net_namespace.h>  /* init_net */
#include <rdma/ib_verbs.h>
#include <scsi/scsi_cmnd.h>	/* struct scsi_cmnd */
#include <scsi/scsi_eh.h>	/* scsi_build_sense_buffer() */
struct scsi_target;
#include <scsi/scsi_transport_fc.h> /* struct bsg_job */
#include <asm/unaligned.h>	/* get_unaligned_be64() */

/* <asm-generic/barrier.h> */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
#define smp_mb__after_atomic_inc smp_mb__after_atomic
#define smp_mb__after_clear_bit smp_mb__after_atomic
#define smp_mb__before_atomic_dec smp_mb__before_atomic
#define smp_mb__after_atomic_dec smp_mb__after_atomic
#endif

/* <asm/msr.h> */

#ifdef CONFIG_X86
#include <asm/msr.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0) && !defined(RHEL_RELEASE_CODE)
static __always_inline unsigned long long rdtsc(void)
{
	return native_read_tsc();
}
#endif
#else
static __always_inline unsigned long long rdtsc(void)
{
	return 0;
}
#define tsc_khz 1000
#endif

/* <linux/err.h> */

/*
 * See also commit 6e8b8726ad50 ("PTR_RET is now PTR_ERR_OR_ZERO") # v3.12
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0) && !defined(RHEL_RELEASE_CODE)
#define PTR_ERR_OR_ZERO(p) PTR_RET(p)
#endif

/* <linux/bio.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0) &&	\
	!defined(CONFIG_SUSE_KERNEL)
static inline struct bio_set *bioset_create_backport(unsigned int pool_size,
						     unsigned int front_pad,
						     int flags)
{
	WARN_ON_ONCE(flags != 0);
	return bioset_create(pool_size, front_pad);
}
#define bioset_create bioset_create_backport
#define BIOSET_NEED_BVECS 0
#endif

/* See also commit 74d46992e0d9. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0) &&	\
	!defined(CONFIG_SUSE_KERNEL)
static inline void bio_set_dev(struct bio *bio, struct block_device *bdev)
{
	bio->bi_bdev = bdev;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
/*
 * See also commit a8affc03a9b3 ("block: rename BIO_MAX_PAGES to BIO_MAX_VECS")
 * # v5.12.
 */
#define BIO_MAX_VECS BIO_MAX_PAGES
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0) &&		\
	(!defined(RHEL_RELEASE_CODE) ||				\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(9, 1))
/*
 * See also commit 609be1066731 ("block: pass a block_device and opf to
 * bio_alloc_bioset") # v5.18
 */
static inline
struct bio *bio_alloc_bioset_backport(struct block_device *bdev,
		unsigned short nr_vecs, unsigned int opf, gfp_t gfp_mask,
		struct bio_set *bs)
{
	/*
	 * Check that @bdev and @opf parameters are zeros.
	 *
	 * The old API expects these parameters to be set implicitly.
	 * Therefore, warn about using an explicit setting that would
	 * cause these parameters to be lost.
	 */
	WARN_ON_ONCE(bdev || opf);

	return bio_alloc_bioset(gfp_mask, nr_vecs, bs);
}

#define bio_alloc_bioset bio_alloc_bioset_backport

/*
 * See also commit 07888c665b40 ("block: pass a block_device and opf to
 * bio_alloc") # v5.18
 */
static inline
struct bio *bio_alloc_backport(struct block_device *bdev,
		unsigned short nr_vecs, unsigned int opf, gfp_t gfp_mask)
{
	/*
	 * Check that @bdev and @opf parameters are zeros.
	 *
	 * The old API expects these parameters to be set implicitly.
	 * Therefore, warn about using an explicit setting that would
	 * cause these parameters to be lost.
	 */
	WARN_ON_ONCE(bdev || opf);

	return bio_alloc(gfp_mask, nr_vecs);
}

#define bio_alloc bio_alloc_backport

#endif

/* <linux/blk_types.h> */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
enum {
	REQ_OP_SCSI_IN	= REQ_OP_DRV_IN,
	REQ_OP_SCSI_OUT	= REQ_OP_DRV_OUT,
};
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0) &&		\
	(!defined(RHEL_RELEASE_CODE) ||				\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(9, 2))
/*
 * See also commit 342a72a33407 ("block: Introduce the type blk_opf_t") # v6.0
 */
typedef unsigned int blk_opf_t;
#endif

/* <linux/blk-mq.h> */

static inline unsigned int scst_blk_rq_cpu(struct request *rq)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 21, 0) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 8)
	return rq->cpu;
#else
	return blk_mq_rq_cpu(rq);
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0) &&		\
	(!defined(RHEL_RELEASE_CODE) ||				\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(9, 1))
/*
 * See also commit e2e530867245 ("blk-mq: remove the done argument to
 * blk_execute_rq_nowait") # v5.19.
 */
static inline
void blk_execute_rq_nowait_backport(struct request *rq, bool at_head)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
	/*
	 * See also commit 8eeed0b554b9 ("block: remove unnecessary argument from
	 * blk_execute_rq_nowait") # v5.12.
	 */
	blk_execute_rq_nowait(rq->q, NULL, rq, at_head, rq->end_io);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
	/*
	 * See also commit b84ba30b6c7a ("block: remove the gendisk argument to
	 * blk_execute_rq") # v5.17.
	 */
	blk_execute_rq_nowait(NULL, rq, at_head, rq->end_io);
#else
	blk_execute_rq_nowait(rq, at_head, rq->end_io);
#endif
}

#define blk_execute_rq_nowait blk_execute_rq_nowait_backport
#endif

/* <linux/blkdev.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0) &&		\
	(!defined(RHEL_RELEASE_CODE) ||				\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(9, 4))
/*
 * See also commit 05bdb9965305 ("block: replace fmode_t with a block-specific
 * type for block open flags") # v6.5.
 */
typedef fmode_t blk_mode_t;

#define BLK_OPEN_READ ((__force blk_mode_t)FMODE_READ)
#define BLK_OPEN_WRITE ((__force blk_mode_t)FMODE_WRITE)
#define BLK_OPEN_EXCL ((__force blk_mode_t)FMODE_EXCL)

/*
 * See also commit 0718afd47f70 ("block: introduce holder ops") # v6.5.
 */
struct blk_holder_ops {
	/* empty dummy */
};

static inline struct block_device *
blkdev_get_by_path_backport(const char *path, blk_mode_t mode,
		void *holder, const struct blk_holder_ops *hops)
{
	WARN_ON_ONCE(hops);

	/*
	 * See also commit 2736e8eeb0cc ("block: use the holder as
	 * indication for exclusive opens") # v6.5.
	 */
	if (holder)
		mode |= BLK_OPEN_EXCL;

	return blkdev_get_by_path(path, mode, holder);
}

#define blkdev_get_by_path blkdev_get_by_path_backport

/*
 * See also commit 2736e8eeb0cc ("block: use the holder as indication for
 * exclusive opens") # v6.5.
 */
static inline void blkdev_put_backport(struct block_device *bdev, void *holder)
{
	blkdev_put(bdev, holder ? BLK_OPEN_EXCL : 0);
}

#define blkdev_put blkdev_put_backport

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)
/*
 * See also commit e719b4d15674 ("block: Provide bdev_open_* functions") # v6.7.
 */
struct bdev_handle {
	struct block_device *bdev;
	void *holder;
	blk_mode_t mode;
};

static inline struct bdev_handle *
bdev_open_by_path_backport(const char *path, blk_mode_t mode, void *holder,
			   const struct blk_holder_ops *hops)
{
	struct bdev_handle *handle = kmalloc(sizeof(*handle), GFP_KERNEL);
	struct block_device *bdev;

	if (!handle)
		return ERR_PTR(-ENOMEM);

	bdev = blkdev_get_by_path(path, mode, holder, hops);
	if (IS_ERR(bdev)) {
		kfree(handle);
		return ERR_CAST(bdev);
	}

	handle->bdev = bdev;
	handle->holder = holder;
	handle->mode = mode;

	return handle;
}

#define bdev_open_by_path bdev_open_by_path_backport

static inline void bdev_release_backport(struct bdev_handle *handle)
{
	blkdev_put(handle->bdev, handle->holder);
	kfree(handle);
}

#define bdev_release bdev_release_backport

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0) &&		\
	(!defined(RHEL_RELEASE_CODE) ||				\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(9, 1))
/*
 * See also commit 44abff2c0b97 ("block: decouple REQ_OP_SECURE_ERASE
 * from REQ_OP_DISCARD") # v5.19.
 */
static inline int
blkdev_issue_discard_backport(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask)
{
	return blkdev_issue_discard(bdev, sector, nr_sects, gfp_mask, 0);
}

#define blkdev_issue_discard blkdev_issue_discard_backport
#endif

/* <linux/byteorder/generic.h> */
/*
 * See also f2f2efb807d3 ("byteorder: Move {cpu_to_be32, be32_to_cpu}_array()
 * from Thunderbolt to core") # v4.15.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0) && \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 7 ||	\
	 RHEL_MAJOR -0 == 7 && RHEL_MINOR -0 < 5) && \
	!defined(UEK_KABI_RENAME)
static inline void cpu_to_be32_array(__be32 *dst, const u32 *src, size_t len)
{
	int i;

	for (i = 0; i < len; i++)
		dst[i] = cpu_to_be32(src[i]);
}

static inline void be32_to_cpu_array(u32 *dst, const __be32 *src, size_t len)
{
	int i;

	for (i = 0; i < len; i++)
		dst[i] = be32_to_cpu(src[i]);
}
#endif

/* <linux/compiler.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0) && !defined(READ_ONCE)
/*
 * See also patch "kernel: Provide READ_ONCE and ASSIGN_ONCE" (commit ID
 * 230fa253df6352af12ad0a16128760b5cb3f92df).
 */
#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))

#endif

/* <linux/compiler_attributes.h> */

/* See also commit 294f69e662d1 ("compiler_attributes.h: Add 'fallthrough'
 * pseudo keyword for switch/case use") # v5.4
 */
#ifndef fallthrough
#if __GNUC__ >= 5
#if __has_attribute(__fallthrough__)
#define fallthrough __attribute__((__fallthrough__))
#else
#define fallthrough do {} while (0)  /* fallthrough */
#endif
#else
/* gcc 4.x doesn't support __has_attribute() */
#define fallthrough do {} while (0)  /* fallthrough */
#endif
#endif

/* <linux/debugfs.h> */

/*
 * See also commit c64688081490 ("debugfs: add support for self-protecting
 * attribute file fops") # v4.7.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
#define DEFINE_DEBUGFS_ATTRIBUTE(__fops, __get, __set, __fmt)		\
static int __fops ## _open(struct inode *inode, struct file *file)	\
{									\
	__simple_attr_check_format(__fmt, 0ull);			\
	return simple_attr_open(inode, file, __get, __set, __fmt);	\
}									\
static const struct file_operations __fops = {				\
	.owner	 = THIS_MODULE,						\
	.open	 = __fops ## _open,					\
	.release = simple_attr_release,					\
	.read	 = debugfs_attr_read,					\
	.write	 = debugfs_attr_write,					\
	.llseek  = no_llseek,						\
}

static inline ssize_t debugfs_attr_read(struct file *file, char __user *buf,
					size_t len, loff_t *ppos)
{
	return -ENOENT;
}
static inline ssize_t debugfs_attr_write(struct file *file,
		const char __user *buf, size_t len, loff_t *ppos)
{
	return -ENOENT;
}
#endif

/*
 * See also commit ff9fb72bc077 ("debugfs: return error values,
 * not NULL") # v5.0.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
static inline struct dentry *debugfs_create_dir_backport(const char *name, struct dentry *parent)
{
	struct dentry *dentry;

	dentry = debugfs_create_dir(name, parent);
	if (!dentry)
		return ERR_PTR(-ENOMEM);

	return dentry;
}

static inline struct dentry *debugfs_create_file_backport(const char *name, umode_t mode,
							  struct dentry *parent, void *data,
							  const struct file_operations *fops)
{
	struct dentry *dentry;

	dentry = debugfs_create_file(name, mode, parent, data, fops);
	if (!dentry)
		return ERR_PTR(-ENOMEM);

	return dentry;
}

#define debugfs_create_dir debugfs_create_dir_backport
#define debugfs_create_file debugfs_create_file_backport
#endif

/* <linux/device.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
/*
 * See also commit ced321bf9151 ("driver core: device.h: add RW and RO
 * attribute macros") # v3.11.
 */
#define DEVICE_ATTR_RW(_name) \
	struct device_attribute dev_attr_##_name = __ATTR_RW(_name)
#endif

/* <linux/dlm.h> */

/* <linux/dmapool.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0) && \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 7)
/* See also ad82362b2def ("mm: add dma_pool_zalloc() call to DMA API") # v4.3 */
static inline void *dma_pool_zalloc(struct dma_pool *pool, gfp_t mem_flags,
				    dma_addr_t *handle)
{
	return dma_pool_alloc(pool, mem_flags | __GFP_ZERO, handle);
}
#endif

/* <linux/eventpoll.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
/*
 * See also commit 65aaf87b3aa2 ("add EPOLLNVAL, annotate EPOLL... and
 * event_poll->event").
 */
typedef unsigned int __poll_t;
#define EPOLLNVAL	POLLNVAL
#endif

/*
 * See also commit 7e040726850a ("eventpoll.h: add missing epoll event masks").
 * Note: this commit got backported to multiple stable kernels, including
 * v3.18.93.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
#if !defined(EPOLLIN)
#define EPOLLIN		POLLIN
#endif
#if !defined(EPOLLPRI)
#define EPOLLPRI	POLLPRI
#endif
#if !defined(EPOLLOUT)
#define EPOLLOUT	POLLOUT
#endif
#if !defined(EPOLLERR)
#define EPOLLERR	POLLERR
#endif
#if !defined(EPOLLHUP)
#define EPOLLHUP	POLLHUP
#endif
#if !defined(EPOLLRDNORM)
#define EPOLLRDNORM	POLLRDNORM
#endif
#if !defined(EPOLLRDBAND)
#define EPOLLRDBAND	POLLRDBAND
#endif
#if !defined(EPOLLWRNORM)
#define EPOLLWRNORM	POLLWRNORM
#endif
#if !defined(EPOLLWRBAND)
#define EPOLLWRBAND	POLLWRBAND
#endif
#if !defined(EPOLLMSG)
#define EPOLLMSG	POLLMSG
#endif
#if !defined(EPOLLRDHUP)
#define EPOLLRDHUP	POLLRDHUP
#endif
#endif

/* <linux/fs.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
/* See also commit dde0c2e79848 ("fs: add IOCB_SYNC and IOCB_DSYNC") */
#define IOCB_DSYNC 0
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0) && \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
/*
 * See also commit bb7462b6fd64 ("vfs: use helpers for calling
 * f_op->{read,write}_iter()").
 */
static inline ssize_t call_read_iter(struct file *file, struct kiocb *kio,
				     struct iov_iter *iter)
{
	return file->f_op->read_iter(kio, iter);
}

static inline ssize_t call_write_iter(struct file *file, struct kiocb *kio,
				      struct iov_iter *iter)
{
	return file->f_op->write_iter(kio, iter);
}
#endif

/*
 * See also commit b745fafaf70c ("fs: Introduce RWF_NOWAIT and
 * FMODE_AIO_NOWAIT") # v4.13.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0) && \
	!defined(CONFIG_SUSE_KERNEL)
#define IOCB_NOWAIT 0
#endif

/* See also commit bdd1d2d3d251 ("fs: fix kernel_read prototype") # v4.14 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static inline ssize_t
kernel_read_backport(struct file *file, void *buf, size_t count, loff_t *pos)
{
	return kernel_read(file, *pos, buf, count);
}

#define kernel_read(file, buf, count, pos)			\
	kernel_read_backport((file), (buf), (count), (pos))

/*
 * See also commit 7bb307e894d5 ("export kernel_write(), convert open-coded
 * instances") # v3.9.
 */
static inline ssize_t
kernel_write_backport(struct file *file, const void *buf, size_t count,
		      loff_t *pos)
{
#ifndef CONFIG_SUSE_KERNEL
	int res = kernel_write(file, buf, count, *pos);

	if (res > 0)
		*pos += res;

	return res;
#else
	return kernel_write(file, buf, count, pos);
#endif
}

#define kernel_write kernel_write_backport
#endif

/* <linux/iocontext.h> */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 21, 0) || \
	(defined(RHEL_MAJOR) && RHEL_MAJOR -0 >= 8)

static inline struct io_context *
scst_get_task_io_context(struct task_struct *task,
			 gfp_t gfp_flags, int node)
{
	return NULL;
}

static inline void scst_put_io_context(struct io_context *ioc)
{
}

static inline void scst_ioc_task_link(struct io_context *ioc)
{
}

#define get_task_io_context scst_get_task_io_context
#define put_io_context scst_put_io_context
#define ioc_task_link scst_ioc_task_link

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
/* Suboptimal algorithm for computing the square root of a 64-bit number */
static inline u32 int_sqrt64(u64 x)
{
	u32 r = 0, s;
	int i;

	for (i = 8 * sizeof(r) - 2; i >= 0; i--) {
		s = r + (1 << i);
		if (1ull * s * s <= x)
			r = s;
	}

	return r;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
static inline long get_user_pages_backport(unsigned long start,
					   unsigned long nr_pages,
					   unsigned int gup_flags,
					   struct page **pages)
{
#if LINUX_VERSION_CODE >> 8 == KERNEL_VERSION(4, 4, 0) >> 8 &&	\
	LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 168)
	/*
	 * See also commit 8e50b8b07f46 ("mm: replace get_user_pages() write/force
	 * parameters with gup_flags") # v4.4.168.
	 */
	return get_user_pages(current, current->mm, start, nr_pages, gup_flags,
			      pages, NULL);
#elif (!defined(CONFIG_SUSE_KERNEL) &&				\
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)) ||	\
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	const bool write = gup_flags & FOLL_WRITE;
	const bool force = 0;

	WARN_ON_ONCE(gup_flags & ~FOLL_WRITE);
#if !defined(CONFIG_SUSE_KERNEL) &&				\
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
	/*
	 * See also commit cde70140fed8 ("mm/gup: Overload get_user_pages() functions")
	 * # v4.6.
	 */
	return get_user_pages(current, current->mm, start, nr_pages, write,
			      force, pages, NULL);
#else
	/*
	 * See also commit 768ae309a961 ("mm: replace get_user_pages() write/force
	 * parameters with gup_flags") # v4.9.
	 */
	return get_user_pages(start, nr_pages, write, force, pages, NULL);
#endif
#else
	/*
	 * See also commit 54d020692b34 ("mm/gup: remove unused vmas parameter from
	 * get_user_pages()") # v6.5.
	 */
	return get_user_pages(start, nr_pages, gup_flags, pages, NULL);
#endif
}
#define get_user_pages get_user_pages_backport
#endif

/* <linux/kobject_ns.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0) &&		\
	(!defined(RHEL_RELEASE_CODE) ||				\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(7, 6))
/*
 * See also commit 5f256becd868 ("[NET]: Basic network namespace
 * infrastructure."; v2.6.24). a685e08987d1 ("Delay struct net freeing while
 * there's a sysfs instance refering to it"; v3.0). See also commit
 * 172856eac7cf ("kobject: Export kobj_ns_grab_current() and kobj_ns_drop()";
 * v4.16).
 */
static inline void *kobj_ns_grab_current_backport(enum kobj_ns_type type)
{
	WARN_ON_ONCE(type != KOBJ_NS_TYPE_NET);
	return &init_net;
}

static inline void kobj_ns_drop_backport(enum kobj_ns_type type, void *ns)
{
}

#define kobj_ns_grab_current kobj_ns_grab_current_backport
#define kobj_ns_drop kobj_ns_drop_backport
#endif

/* <linux/kref.h> */

/* See also commit 2c935bc57221 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
#define kref_read(kref) (atomic_read(&(kref)->refcount))
#endif

/* <linux/ktime.h> */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 7)
/**
 * ktime_before - Compare if a ktime_t value is smaller than another one.
 * @cmp1:	comparable1
 * @cmp2:	comparable2
 *
 * Return: true if cmp1 happened before cmp2.
 */
static inline bool ktime_before(const ktime_t cmp1, const ktime_t cmp2)
{
	return ktime_compare(cmp1, cmp2) < 0;
}
#endif

/* <linux/list.h> */

#ifndef __list_for_each
/* ToDo: cleanup when both are the same for all relevant kernels */
#define __list_for_each list_for_each
#endif

/*
 * Returns true if entry is in its list. Entry must be deleted from the
 * list by using list_del_init()!
 */
static inline bool list_entry_in_list(const struct list_head *entry)
{
	return !list_empty(entry);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0) &&		\
	(!defined(RHEL_RELEASE_CODE) ||				\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(8, 1))
/*
 * See also commit 70b44595eafe ("mm, compaction: use free lists to quickly
 * locate a migration source") # v5.1.
 */
static inline int list_is_first(const struct list_head *list, const struct list_head *head)
{
	return list->prev == head;
}
#endif

/* <linux/lockdep.h> */

/*
 * See also commit 108c14858b9e ("locking/lockdep: Add support for dynamic
 * keys").
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 8 ||	\
	 (RHEL_MAJOR -0 == 8 && RHEL_MINOR -0 < 2))
static inline void lockdep_register_key(struct lock_class_key *key)
{
}

static inline void lockdep_unregister_key(struct lock_class_key *key)
{
}
#endif

/*
 * See also commit 5facae4f3549 ("locking/lockdep: Remove unused @nested
 * argument from lock_release()").
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0) &&		\
	(!defined(RHEL_RELEASE_CODE) ||				\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(8, 3))
#undef rwlock_release
#define rwlock_release(l, i) lock_release(l, 1, i)
#undef mutex_release
#define mutex_release(l, i) lock_release(l, 0, i)
#endif

/* <linux/mempoool.h> */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
/*
 * See also commit 4e3ca3e033d1 ("mm/mempool: allow NULL `pool' pointer in
 * mempool_destroy()") # v4.3.
 */
static inline void mempool_destroy_backport(mempool_t *pool)
{
	if (pool)
		mempool_destroy(pool);
}

#define mempool_destroy mempool_destroy_backport
#endif

/* <linux/mm.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 7 ||	\
	 (RHEL_MAJOR -0 == 7 && RHEL_MINOR -0 < 5)) &&	\
	!defined(_COMPAT_LINUX_MM_H)
#if !defined(UEK_KABI_RENAME)
/* See also commit a7c3e901a46f ("mm: introduce kv[mz]alloc helpers") # v4.12 */
static inline void *kvmalloc_node(size_t size, gfp_t flags, int node)
{
	gfp_t kmalloc_flags = flags;
	void *ret;

	WARN_ON_ONCE(flags & ~(GFP_KERNEL | __GFP_ZERO));

	/*
	 * vmalloc uses GFP_KERNEL for some internal allocations (e.g page
	 * tables) so the given set of flags has to be compatible.
	 */
	if ((flags & GFP_KERNEL) != GFP_KERNEL)
		return kmalloc_node(size, flags, node);

	/*
	 * We want to attempt a large physically contiguous block first because
	 * it is less likely to fragment multiple larger blocks and therefore
	 * contribute to a long term fragmentation less than vmalloc fallback.
	 * However make sure that larger requests are not too disruptive - no
	 * OOM killer and no allocation failure warnings as we have a fallback.
	 */
	if (size > PAGE_SIZE) {
		kmalloc_flags |= __GFP_NOWARN;

		if (!(kmalloc_flags & __GFP_REPEAT))
			kmalloc_flags |= __GFP_NORETRY;
	}

	ret = kmalloc_node(size, kmalloc_flags, node);

	/*
	 * It doesn't really make sense to fallback to vmalloc for sub page
	 * requests
	 */
	if (ret || size <= PAGE_SIZE)
		return ret;

	ret = vmalloc_node(size, node);
	if (ret && (flags & __GFP_ZERO))
		memset(ret, 0, size);

	return ret;
}

static inline void *kvmalloc(size_t size, gfp_t flags)
{
	return kvmalloc_node(size, flags, NUMA_NO_NODE);
}

static inline void *kvzalloc(size_t size, gfp_t flags)
{
	return kvmalloc(size, flags | __GFP_ZERO);
}
#endif

/*
 * See also commit 752ade68cbd8 ("treewide: use kv[mz]alloc* rather than
 * opencoded variants") # v4.12.
 */
static inline void *kvmalloc_array(size_t n, size_t size, gfp_t flags)
{
	return kvmalloc(n * size, flags);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 7 ||	\
	 RHEL_MAJOR -0 == 7 && RHEL_MINOR -0 < 7) &&	\
	!defined(CONFIG_SUSE_KERNEL) &&			\
	!defined(_COMPAT_LINUX_MM_H) &&			\
	!defined(UEK_KABI_RENAME)
/* See also commit 1c542f38ab8d ("mm: Introduce kvcalloc()") # v4.18. */
static inline void *kvcalloc(size_t n, size_t size, gfp_t flags)
{
	return kvmalloc(n * size, flags | __GFP_ZERO);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0) &&		       \
	!(LINUX_VERSION_CODE >> 8 == KERNEL_VERSION(3, 12, 0) >> 8 &&  \
	  LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 41)) &&	       \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 6)
/*
 * See also commit 39f1f78d53b9 ("nick kvfree() from apparmor") # v3.15.
 * See also commit fb6a2a8ebe27 ("nick kvfree() from apparmor") # v3.12.41.
 */
static inline void kvfree(void *addr)
{
	if (is_vmalloc_addr(addr))
		vfree(addr);
	else
		kfree(addr);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0) &&			\
	(LINUX_VERSION_CODE >> 8 != KERNEL_VERSION(5, 15, 0) >> 8 ||	\
	 LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 54)) &&		\
	(LINUX_VERSION_CODE >> 8 != KERNEL_VERSION(5, 10, 0) >> 8 ||	\
	 LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 210)) &&		\
	(!defined(RHEL_RELEASE_CODE) ||					\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(9, 0)) &&		\
	(!defined(UEK_KABI_RENAME) ||					\
	 LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0))
/*
 * See also commit a8749a35c3990 ("mm: vmalloc: introduce array allocation functions") # v5.18,
 * v5.15.54, v5.10.210.
 */
static inline void *vmalloc_array(size_t n, size_t size)
{
	return vmalloc(n * size);
}

static inline void *vcalloc(size_t n, size_t size)
{
	return vzalloc(n * size);
}
#endif

/* <linux/shrinker.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0) &&		\
	(!defined(RHEL_RELEASE_CODE) ||				\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(9, 3))
/*
 * See also commit e33c267ab70d ("mm: shrinkers: provide shrinkers with
 * names") # v6.0.
 */
static inline int
register_shrinker_backport(struct shrinker *shrinker, const char *fmt, ...)
{
/*
 * See also commit 1d3d4437eae1 ("vmscan: per-node deferred work") # v3.12
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
	return register_shrinker(shrinker);
#else
	register_shrinker(shrinker);
	return 0;
#endif
}

#define register_shrinker register_shrinker_backport
#endif

/* <linux/module.h> */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0)
#define MODULE_IMPORT_NS(ns)
#endif

/* <linux/nvme-fc.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 7)
#define FC_TYPE_NVME 0x28
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
enum nvmefc_fcp_datadir {
	NVMEFC_FCP_NODATA,
	NVMEFC_FCP_WRITE,
	NVMEFC_FCP_READ,
};
struct nvme_fc_ersp_iu {
};
struct nvmefc_fcp_req {
	void			*cmdaddr;
	void			*rspaddr;
	dma_addr_t		cmddma;
	dma_addr_t		rspdma;
	u16			cmdlen;
	u16			rsplen;

	u32			payload_length;
	struct sg_table		sg_table;
	struct scatterlist	*first_sgl;
	int			sg_cnt;
	enum nvmefc_fcp_datadir	io_dir;

	__le16			sqid;

	void (*done)(struct nvmefc_fcp_req *req);

	void			*private;

	u32			transferred_length;
	u16			rcv_rsplen;
	u32			status;
} __aligned(sizeof(u64));	/* alignment for other things alloc'd with */
#endif

/* <linux/percpu-refcount.h> */

#if defined(RHEL_MAJOR) && RHEL_MAJOR -0 >= 7 ||	\
	LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
#include <linux/percpu-refcount.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0) &&	\
	(!defined(RHEL_RELEASE_CODE) ||				\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(8, 3))
/*
 * See also commit 09ed79d6d75f ("percpu_ref: introduce PERCPU_REF_ALLOW_REINIT
 * flag") # v5.3.
 */
#define PERCPU_REF_ALLOW_REINIT 0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
#define PERCPU_COUNT_BIAS (1U << 31)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 7)
typedef unsigned int percpu_count_t;
#define READ_REF_COUNT(ref) atomic_read(&(ref)->count)
#else
typedef unsigned long percpu_count_t;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#define READ_REF_COUNT(ref) atomic_long_read(&(ref)->count)
#else
#define READ_REF_COUNT(ref) atomic_long_read(&(ref)->data->count)
#endif
#endif

/*
 * For kernel versions that have <linux/percpu-refcount.h>, backport the
 * functionality that is missing from that header file.
 */
#if (defined(RHEL_MAJOR) && RHEL_MAJOR -0 >= 7) ||	\
	LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 8)

/*
 * See also commit 18c9a6bbe064 ("percpu-refcount: Introduce
 * percpu_ref_resurrect()") # v4.20.
 */
static inline void percpu_ref_resurrect(struct percpu_ref *ref)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0) ||	\
	(defined(RHEL_MAJOR) && RHEL_MAJOR -0 >= 7)
	percpu_ref_reinit(ref);
#else
	unsigned __percpu *pcpu_count = (unsigned __percpu *)
		((uintptr_t)ref->pcpu_count & ~PCPU_REF_DEAD);
	int cpu;

	BUG_ON(!pcpu_count);
	//WARN_ON(!percpu_ref_is_zero(ref));

	atomic_set(&ref->count, 1 + PERCPU_COUNT_BIAS);

	/*
	 * Restore per-cpu operation. The barrier guarantees that the zeroing
	 * is visible to all percpu accesses which can see the following
	 * PCPU_REF_DEAD clearing.
	 */
	for_each_possible_cpu(cpu)
		*per_cpu_ptr(pcpu_count, cpu) = 0;

	ref->pcpu_count = (unsigned __percpu *)
		((uintptr_t)ref->pcpu_count & ~PCPU_REF_DEAD);
	smp_mb();
#endif
}

#if !(defined(RHEL_MAJOR) && RHEL_MAJOR -0 >= 7)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
/*
 * See also commit 4c907baf36d8 ("percpu_ref: implement percpu_ref_is_dying()")
 * # v4.0.
 */
static inline bool percpu_ref_is_dying(struct percpu_ref *ref)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
	return (uintptr_t)ref->pcpu_count & PCPU_REF_DEAD;
#else
	return ref->pcpu_count_ptr & PCPU_REF_DEAD;
#endif
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
static inline bool percpu_ref_is_dying(struct percpu_ref *ref)
{
	return ref->percpu_count_ptr & __PERCPU_REF_DEAD;
}
#endif
#endif /* !(defined(RHEL_MAJOR) && RHEL_MAJOR -0 >= 7) */

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0) &&	\
	!(defined(RHEL_MAJOR) && RHEL_MAJOR -0 >= 7)
/*
 * See also commit 2aad2a86f668 ("percpu_ref: add PERCPU_REF_INIT_* flags")
 * # v3.18.
 */
static inline int __must_check percpu_ref_init_backport(struct percpu_ref *ref,
				 percpu_ref_func_t *release, unsigned int flags,
				 gfp_t gfp)
{
	WARN_ON_ONCE(flags != 0);
	WARN_ON_ONCE(gfp != GFP_KERNEL);
	return percpu_ref_init(ref, release);
}
#define percpu_ref_init percpu_ref_init_backport

/*
 * See also commit 9e804d1f58da ("percpu_ref: rename things to prepare for
 * decoupling percpu/atomic mode switch") # v3.18.
 */
static inline bool __ref_is_percpu(struct percpu_ref *ref,
				   percpu_count_t __percpu **percpu_countp)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
	uintptr_t pcpu_ptr = (uintptr_t)ACCESS_ONCE(ref->pcpu_count);

	if (unlikely(pcpu_ptr & PCPU_REF_DEAD))
		return false;

	*percpu_countp = (percpu_count_t __percpu *)pcpu_ptr;
	return true;
#else
	return __pcpu_ref_alive(ref, percpu_countp);
#endif
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0) &&	\
	!(defined(RHEL_MAJOR) && RHEL_MAJOR -0 >= 7)
/*
 * See also commit 2d7227828e14 ("percpu-refcount: implement percpu_ref_reinit()
 * and percpu_ref_is_zero()") # v3.17.
 */
static inline bool percpu_ref_is_zero(struct percpu_ref *ref)
{
	return !atomic_read(&ref->count);
}
/*
 * See also commit 9a1049da9bd2 ("percpu-refcount: require percpu_ref to be
 * exited explicitly") # v3.17.
 */
static inline void percpu_ref_exit(struct percpu_ref *ref)
{
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0) &&	\
	!(defined(RHEL_MAJOR) && RHEL_MAJOR -0 >= 7)
static inline bool percpu_ref_tryget_live(struct percpu_ref *ref)
{
	percpu_count_t __percpu *percpu_count;
	bool ret = false;

	rcu_read_lock();

	if (__ref_is_percpu(ref, &percpu_count)) {
		this_cpu_inc(*percpu_count);
		ret = true;
	} else if (!percpu_ref_is_dying(ref)) {
		ret = atomic_long_inc_not_zero(&ref->count);
	}

	rcu_read_unlock();

	return ret;
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0) */

#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 7 ||	\
	 RHEL_MAJOR -0 == 7 && RHEL_MINOR -0 < 5)

struct percpu_ref;
typedef void (percpu_ref_func_t)(struct percpu_ref *);

struct percpu_ref {
	atomic_t		count;
	percpu_ref_func_t	*release;
	bool			dead;
};

static inline int __must_check percpu_ref_init(struct percpu_ref *ref,
				 percpu_ref_func_t *release, unsigned int flags,
				 gfp_t gfp)
{
	WARN_ON_ONCE(flags != 0);
	atomic_set(&ref->count, 1);
	ref->release = release;
	ref->dead = false;
	return 0;
}

static inline void percpu_ref_exit(struct percpu_ref *ref)
{
}

static inline void percpu_ref_get(struct percpu_ref *ref)
{
	atomic_inc(&ref->count);
}

static inline bool percpu_ref_tryget_live(struct percpu_ref *ref)
{
	bool ret = false;

	rcu_read_lock();
	if (!ref->dead)
		ret = atomic_inc_not_zero(&ref->count);
	rcu_read_unlock();

	return ret;
}

static inline void percpu_ref_put(struct percpu_ref *ref)
{
	if (unlikely(atomic_dec_and_test(&ref->count)))
		ref->release(ref);
}

static inline void
percpu_ref_kill_and_confirm(struct percpu_ref *ref, percpu_ref_func_t *confirm_kill)
{
	WARN_ON_ONCE(ref->dead);
	ref->dead = true;
	if (confirm_kill)
		confirm_kill(ref);
	percpu_ref_put(ref);
}

static inline void percpu_ref_kill(struct percpu_ref *ref)
{
	percpu_ref_kill_and_confirm(ref, NULL);
}

static inline void percpu_ref_resurrect(struct percpu_ref *ref)
{
	WARN_ON_ONCE(!ref->dead);
	ref->dead = false;
	percpu_ref_get(ref);
}

static inline bool __ref_is_percpu(struct percpu_ref *ref,
				   unsigned __percpu **percpu_countp)
{
	*percpu_countp = NULL;
	return !ref->dead;
}

static inline bool percpu_ref_is_dying(struct percpu_ref *ref)
{
	return ref->dead;
}

static inline bool percpu_ref_is_zero(struct percpu_ref *ref)
{
	return !atomic_read(&ref->count);
}
#endif

/* Only use this function for debugging purposes. Not upstream. */
static inline unsigned long percpu_ref_read(struct percpu_ref *ref)
{
	percpu_count_t __percpu *percpu_count;

	/* Do not try to read the counter if it is in per-cpu mode. */
	if (__ref_is_percpu(ref, &percpu_count))
		return 0;
	return READ_REF_COUNT(ref) - !percpu_ref_is_dying(ref);
}

/* <linux/rcupdate.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 7 ||	\
	 RHEL_MAJOR -0 == 7 && RHEL_MINOR -0 < 7)
/*
 * See also commit 546a9d8519ed ("rcu: Export debug_init_rcu_head() and
 * debug_init_rcu_head()") # v3.16.
 */
static inline void init_rcu_head(struct rcu_head *head) { }
static inline void destroy_rcu_head(struct rcu_head *head) { }
#endif

/* <linux/sched/prio.h> */

/*
 * See also commit 3ee237dddcd8 ("sched/prio: Add 3 macros of MAX_NICE,
 * MIN_NICE and NICE_WIDTH in prio.h") # v3.15.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0) && !defined(MIN_NICE)
#define MIN_NICE -20
#endif

/* <linux/seq_file.h> */

/*
 * See also commit a08f06bb7a07 ("seq_file: Introduce DEFINE_SHOW_ATTRIBUTE()
 * helper macro") # v4.16.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
#define DEFINE_SHOW_ATTRIBUTE(__name)					\
static int __name ## _open(struct inode *inode, struct file *file)	\
{									\
	return single_open(file, __name ## _show, inode->i_private);	\
}									\
									\
static const struct file_operations __name ## _fops = {			\
	.owner		= THIS_MODULE,					\
	.open		= __name ## _open,				\
	.read		= seq_read,					\
	.llseek		= seq_lseek,					\
	.release	= single_release,				\
}
#endif

/* <linux/slab.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0) &&	\
	!defined(_COMPAT_LINUX_MM_H)
/*
 * See also commit 3942d2991852 ("mm/slab_common: allow NULL cache pointer in
 * kmem_cache_destroy()") # v4.3.
 */
static inline void kmem_cache_destroy_backport(struct kmem_cache *s)
{
	if (s)
		kmem_cache_destroy(s);
}

#define kmem_cache_destroy kmem_cache_destroy_backport
#endif

/*
 * See also commit 8eb8284b4129 ("usercopy: Prepare for usercopy
 * whitelisting").
 *
 * UEK4 is based on kernel v4.1.12 and does not have a backport of the v4.16
 * API. UEK5 is based on kernel v4.14.35 and has a backport of the v4.16 API.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0) &&	\
	(!defined(UEK_KABI_RENAME) ||			\
	 LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0))
static inline struct kmem_cache *kmem_cache_create_usercopy(const char *name,
			unsigned int size, unsigned int align,
			unsigned long flags,
			unsigned int useroffset, unsigned int usersize,
			void (*ctor)(void *))
{
	return kmem_cache_create(name, size, align, flags, ctor);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
#define KMEM_CACHE_USERCOPY(__struct, __flags, __field)			\
		kmem_cache_create_usercopy(#__struct,			\
			sizeof(struct __struct),			\
			__alignof__(struct __struct), (__flags),	\
			offsetof(struct __struct, __field),		\
			sizeof_field(struct __struct, __field), NULL)
#endif

/* <linux/sockptr.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
#if !defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 8 ||	\
	 RHEL_MAJOR -0 == 8 && RHEL_MINOR -0 < 4
/* See also commit ba423fdaa589 ("net: add a new sockptr_t type") # v5.9 */
static inline void __user *KERNEL_SOCKPTR(void *p)
{
	return (void __force __user *)p;
}
#else
#define KERNEL_SOCKPTR(p) ((char __force __user *)p)
#endif
#endif

/* <linux/stddef.h> */

#ifndef sizeof_field
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#endif

#ifndef DECLARE_FLEX_ARRAY
#define DECLARE_FLEX_ARRAY(TYPE, NAME)	\
	struct { \
		struct { } __empty_ ## NAME; \
		TYPE NAME[]; \
	}
#endif

/* <linux/string.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 7)
/* See also commit e9d408e107db ("new helper: memdup_user_nul()") # v4.5 */
static inline void *memdup_user_nul(const void __user *src, size_t len)
{
	char *p;

	p = kmalloc(len + 1, GFP_KERNEL);
	if (!p)
		return ERR_PTR(-ENOMEM);

	if (copy_from_user(p, src, len)) {
		kfree(p);
		return ERR_PTR(-EFAULT);
	}
	p[len] = '\0';

	return p;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0) &&			\
	(LINUX_VERSION_CODE >> 8 != KERNEL_VERSION(3, 16, 0) >> 8 ||	\
	 LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 60)) &&		\
	(LINUX_VERSION_CODE >> 8 != KERNEL_VERSION(3, 18, 0) >> 8 ||	\
	 LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 64)) &&		\
	(!defined(RHEL_RELEASE_CODE) ||					\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(7, 7))
/*
 * See also commit 30035e45753b ("string: provide strscpy()") # v4.3, v3.16.60, v3.18.64.
 */
static inline ssize_t strscpy(char *dest, const char *src, size_t count)
{
	size_t ret;

	if (count == 0)
		return -E2BIG;

	ret = strlcpy(dest, src, count);

	return ret >= count ? -E2BIG : ret;
}
#endif

/* <linux/sysfs.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 7)
/* See also commit b9b3259746d7 ("sysfs.h: add __ATTR_RW() macro") # v3.11. */
#define __ATTR_RW(_name) __ATTR(_name, 0644, _name##_show, _name##_store)
#endif

/* <linux/t10-pi.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
struct t10_pi_tuple {
	__be16 guard_tag;
	__be16 app_tag;
	__be32 ref_tag;
};
#endif

/* <linux/timer.h> */

/*
 * See also commit 686fef928bba ("timer: Prepare to change timer callback
 * argument type") # v4.14. See also commit 0eeda71bc30d ("timer: Replace
 * timer base by a cpu index") # v4.2.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
#define timer_setup(_timer, _fn, _flags) do {			\
	init_timer(_timer);					\
	(_timer)->function = (void *)(_fn);	\
	(_timer)->data = (unsigned long)(_timer);		\
	WARN_ON_ONCE((_flags) != 0);				\
} while (0)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#define timer_setup(_timer, _fn, _flags) do {			\
	init_timer(_timer);					\
	(_timer)->function = (void *)(_fn);\
	(_timer)->data = (unsigned long)(_timer);		\
	(_timer)->flags = (_flags);				\
} while (0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#define from_timer(var, callback_timer, timer_fieldname)		\
	container_of(callback_timer, typeof(*var), timer_fieldname)
#endif

/*
 * See also commit 1d27e3e2252b ("timer: Remove expires and data arguments
 * from DEFINE_TIMER").
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
#undef DEFINE_TIMER
#define DEFINE_TIMER(_name, _function)					\
	struct timer_list _name = TIMER_INITIALIZER(			\
		(void (*)(unsigned long))(unsigned long)(_function), 0,	\
		(unsigned long)&(_name))
#endif

/* <linux/uio.h> */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
/* See also commit abb78f875f3f ("new helper: iov_iter_kvec()") # v3.19. */
static inline void
iov_iter_kvec_backport(struct iov_iter *i, unsigned int direction,
		       const struct kvec *kvec, unsigned long nr_segs,
		       size_t count)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0) ||	\
	(defined(RHEL_MAJOR) && \
	 (RHEL_MAJOR -0 > 8 || (RHEL_MAJOR -0 == 8 && RHEL_MINOR -0 >= 2)))
	/*
	 * For iov_iter_kvec() implementations that have a WARN_ON(direction &
	 * ~(READ | WRITE)) statement. See also commit aa563d7bca6e ("iov_iter:
	 * Separate type from direction and use accessor functions") # v4.20.
	 */
	iov_iter_kvec(i, direction, kvec, nr_segs, count);
#else
	iov_iter_kvec(i, ITER_KVEC | direction, kvec, nr_segs, count);
#endif
}

#define iov_iter_kvec iov_iter_kvec_backport
#endif

/* <linux/unaligned.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0) && \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 8 ||	\
	 RHEL_MAJOR -0 == 8 && RHEL_MINOR -0 < 4)
/* Only use get_unaligned_be24() if reading p - 1 is allowed. */
static inline uint32_t get_unaligned_be24(const uint8_t *const p)
{
	return get_unaligned_be32(p - 1) & 0xffffffU;
}

static inline void put_unaligned_be24(const uint32_t v, uint8_t *const p)
{
	p[0] = v >> 16;
	p[1] = v >>  8;
	p[2] = v >>  0;
}
#endif

/* <rdma/ib_verbs.h> */

/* commit ed082d36 */
#ifndef ib_alloc_pd
static inline struct ib_pd *ib_alloc_pd_backport(struct ib_device *device)
{
	return ib_alloc_pd(device);
}
#define ib_alloc_pd(device, flags)				\
	({							\
		(void)(flags), ib_alloc_pd_backport(device);	\
	})
#endif

/* <scsi/scsi.h> */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
#ifndef msg_byte
/*
 * See also commit 54cf31d07aa8 ("scsi: core: Drop message byte helper";
 * v5.14-rc1).
 */
static inline uint8_t msg_byte(uint32_t result)
{
	return (result >> 8) & 0xff;
}
#endif
#ifndef host_byte
static inline uint8_t host_byte(uint32_t result)
{
	return (result >> 16) & 0xff;
}
#endif
#ifndef driver_byte
/*
 * See also commit 54c29086195f ("scsi: core: Drop the now obsolete driver_byte
 * definitions"; v5.14-rc1).
 */
static inline uint8_t driver_byte(uint32_t result)
{
	return (result >> 24) & 0xff;
}
#endif
#endif

/* <scsi/scsi_cmnd.h> */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0) || \
	(defined(RHEL_RELEASE_CODE) &&			 \
	 RHEL_RELEASE_CODE -0 >= RHEL_RELEASE_VERSION(8, 3))
/*
 * See also patch "[SCSI] bidirectional command support" (commit ID
 * 6f9a35e2dafa). See also commit ae3d56d81507 ("scsi: remove bidirectional
 * command support") # v5.1.
 */
static inline int scsi_bidi_cmnd(struct scsi_cmnd *cmd)
{
	return false;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 7 ||	\
	 RHEL_MAJOR -0 == 7 && RHEL_MINOR -0 < 7)
/* See also commit b54197c43db8 ("virtio_scsi: use cmd_size") # v3.16. */
static inline void *scsi_cmd_priv(struct scsi_cmnd *cmd)
{
	return cmd + 1;
}
#endif

/*
 * The Debian 5.13.0 kernel has a scsi_build_sense() definition but does not
 * define bio_multiple_segments() while the upstream 5.13.0 kernel defines
 * bio_multiple_segments(). Hence the check two lines below for the Debian
 * kernel.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 14, 0) && \
	(LINUX_VERSION_CODE >> 8 != KERNEL_VERSION(5, 13, 0) >> 8 ||	\
	 defined(bio_multiple_segments))
/*
 * See also commit f2b1e9c6f867 ("scsi: core: Introduce scsi_build_sense()";
 * v5.14-rc1).
 */
static inline void scsi_build_sense(struct scsi_cmnd *scmd, int desc,
                            u8 key, u8 asc, u8 ascq)
{
	scsi_build_sense_buffer(desc, scmd->sense_buffer, key, asc, ascq);
	scmd->result = (DRIVER_SENSE << 24) | SAM_STAT_CHECK_CONDITION;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0) &&			\
	!(LINUX_VERSION_CODE >> 8 == KERNEL_VERSION(5, 4, 0) >> 8 &&	\
	  LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 263)) &&		\
	!(LINUX_VERSION_CODE >> 8 == KERNEL_VERSION(5, 10, 0) >> 8 &&	\
	  LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 203)) &&		\
	(!defined(RHEL_RELEASE_CODE) ||					\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(8, 7) ||		\
	 RHEL_RELEASE_CODE -0 == RHEL_RELEASE_VERSION(9, 0))
/*
 * See also 51f3a4788928 ("scsi: core: Introduce the scsi_cmd_to_rq()
 * function") # v5.15.
 * See also df0110425f42 ("scsi: core: Introduce the scsi_cmd_to_rq()
 * function") # v5.4.263.
 * See also b19fe82b4b92 ("scsi: core: Introduce the scsi_cmd_to_rq()
 * function") # v5.10.203.
 */
static inline struct request *scsi_cmd_to_rq(struct scsi_cmnd *scmd)
{
	return scmd->request;
}
#endif

/*
 * See also commits 7ba46799d346 ("scsi: core: Add scsi_prot_ref_tag()
 * helper") and ddd0bc756983 ("block: move ref_tag calculation func to the
 * block layer"; v4.19).
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0) &&		\
	(!defined(RHEL_RELEASE_CODE) ||				\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(9, 1))

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) ||		\
	(defined(RHEL_RELEASE_CODE) &&				\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(8, 7))
static inline u32 scsi_prot_ref_tag(struct scsi_cmnd *scmd)
{
#if defined(RHEL_MAJOR) && RHEL_MAJOR -0 == 7
	WARN_ON_ONCE(true);
	return 0;
#else
	struct request *rq = blk_mq_rq_from_pdu(scmd);

	return t10_pi_ref_tag(rq);
#endif
}
#endif
#endif

/*
 * See also commit c611529e7cd3 ("sd: Honor block layer integrity handling
 * flags"; v3.18).
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
static inline unsigned int scsi_prot_interval(struct scsi_cmnd *scmd)
{
	/* To do: backport this function properly. */
	WARN_ON_ONCE(true);
	return 512;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0) &&			\
	!(LINUX_VERSION_CODE >> 8 == KERNEL_VERSION(5, 15, 0) >> 8 &&	\
	  LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 136)) &&		\
	(!defined(RHEL_RELEASE_CODE) ||					\
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(9, 1))
/*
 * See also commit 11b68e36b167 ("scsi: core: Call scsi_done directly") # v5.16.
 * See also commit d2746cdfd5e5 ("scsi: core: Rename scsi_mq_done() into scsi_done() and export
 * it") # v5.15.136.
 */
static inline void scsi_done(struct scsi_cmnd *cmd)
{
	return cmd->scsi_done(cmd);
}
#endif

/* <scsi/scsi_request.h> */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
/*
 * See also commit 6aded12b10e0 ("scsi: core: Remove struct scsi_request") # v5.18
 */
static inline struct scsi_cmnd *scsi_req(struct request *rq)
{
	return blk_mq_rq_to_pdu(rq);
}

#define SREQ_SENSE(req) ((req)->sense_buffer)
#define SREQ_CP(req)    ((req)->cmnd)
#else
#define SREQ_SENSE(req) ((req)->sense)
#define SREQ_CP(req)    ((req)->cmd)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
static inline struct request *scsi_req(struct request *rq)
{
	return rq;
}

static inline void scsi_req_init(struct request *rq)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)
	rq->cmd_type = REQ_TYPE_BLOCK_PC;
	rq->__data_len = 0;
	rq->__sector = (sector_t) -1;
	rq->bio = rq->biotail = NULL;
	memset(rq->__cmd, 0, sizeof(rq->__cmd));
	rq->cmd = rq->__cmd;
#else
	return blk_rq_set_block_pc(rq);
#endif
}
#endif

/* <linux/bsg-lib.h> */

/*
 * Note: the function bsg_job_sense() exists only in SCST but not in any
 * upstream kernel.
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) &&	\
     !defined(CONFIG_SUSE_KERNEL)) ||			\
    (LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0) &&	\
     defined(CONFIG_SUSE_KERNEL))
static inline void *bsg_job_sense(struct fc_bsg_job *job)
{
	return job->req->sense;
}
#else
static inline void *bsg_job_sense(struct bsg_job *job)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
	return job->req->sense;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0) &&	\
	!defined(CONFIG_SUSE_KERNEL)
	return scsi_req(job->req)->sense;
#else
	return SREQ_SENSE(scsi_req(blk_mq_rq_from_pdu(job)));
#endif
}
#endif

/* <scsi/scsi_transport_fc.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 6)
/*
 * See also commit 624f28be8109 ("[SCSI] scsi_transport_fc: Add 32Gbps speed
 * definition.") # v3.15.
 */
enum {
	FC_PORTSPEED_32GBIT = 0x40
};
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0) &&	\
	!defined(FC_PORTSPEED_64GBIT)
/*
 * See also commit cc019a5a3b58 ("scsi: scsi_transport_fc: fix typos on 64/128
 * GBit define names") # v4.16.
 */
#define FC_PORTSPEED_64GBIT 0x1000
#endif

#ifndef FC_PORT_ROLE_UNKNOWN
#define FC_PORT_ROLE_UNKNOWN			0x00
#define FC_PORT_ROLE_FCP_TARGET			0x01
#define FC_PORT_ROLE_FCP_INITIATOR		0x02
#define FC_PORT_ROLE_IP_PORT			0x04
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
/*
 * See also commit d6d20012e116 ("nvme-fabrics: Add FC transport LLDD api
 * definitions") # v4.10.
 */
#define FC_PORT_ROLE_NVME_INITIATOR		0x10
#define FC_PORT_ROLE_NVME_TARGET		0x20
#define FC_PORT_ROLE_NVME_DISCOVERY		0x40
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
#define wwn_to_u64(wwn) get_unaligned_be64(wwn)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0) &&		\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 8 ||		\
	 RHEL_MAJOR -0 == 8 && RHEL_MINOR -0 < 9 ||		\
	 RHEL_MAJOR -0 == 9 && RHEL_MINOR -0 < 3) &&		\
	!defined(UEK_KABI_RENAME)
/*
 * See also commit 64fd2ba977b1 ("scsi: scsi_transport_fc: Add an additional
 * flag to fc_host_fpin_rcv()") # v6.3
 */
static inline void
fc_host_fpin_rcv_backport(struct Scsi_Host *shost, u32 fpin_len, char *fpin_buf,
			  u8 event_acknowledge)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0) && \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 8 ||	\
	 RHEL_MAJOR -0 == 8 && RHEL_MINOR -0 < 2)
	/*
	 * See also commit c39e0af64bce ("scsi: scsi_transport_fc: Add FPIN fc event
	 * codes") # v5.2
	 */
	return;
#else
	return fc_host_fpin_rcv(shost, fpin_len, fpin_buf);
#endif
}

#define fc_host_fpin_rcv fc_host_fpin_rcv_backport
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
/*
 * See also commit 67b465250e04 ("scsi: fc: start decoupling fc_block_scsi_eh
 * from scsi_cmnd"; v4.14).
 */
static inline int fc_block_rport(struct fc_rport *rport)
{
	/* To do: backport this function. */
	WARN_ON_ONCE(true);
	return 0;
}
#endif

/* <uapi/scsi/fc/fc_els.h> */

/* See also commit a7dff3ad4787 ("scsi: fc: add FPIN ELS definition") # v5.2 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 8 ||	\
	 (RHEL_MAJOR -0 == 8 && RHEL_MINOR -0 < 2))
#define ELS_FPIN 0x16
#endif

/*
 * See also commit 62e9dd177732 ("scsi: qla2xxx: Change in PUREX to handle FPIN
 * ELS requests").
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0) &&			\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 8 ||			\
	 RHEL_MAJOR -0 == 8 && RHEL_MINOR -0 < 4) &&			\
	!(defined(UEK_KABI_RENAME) && defined(FC_PORTSPEED_256GBIT))
#define ELS_RDP 0x18
#endif

/* <target/target_core_base.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
/* See also commit 68d81f40047c ("scsi: remove MSG_*_TAG defines") # v3.19. */
#define TCM_SIMPLE_TAG	0x20
#define TCM_HEAD_TAG	0x21
#define TCM_ORDERED_TAG	0x22
#define TCM_ACA_TAG	0x24
#endif

#endif /* _SCST_BACKPORT_H_ */
