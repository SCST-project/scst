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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0)
#include <linux/bsg-lib.h>	/* struct bsg_job */
#endif
#include <linux/dmapool.h>
#include <linux/eventpoll.h>
#include <linux/iocontext.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
#include <linux/kobject_ns.h>
#endif
#include <linux/scatterlist.h>	/* struct scatterlist */
#include <linux/slab.h>		/* kmalloc() */
#include <linux/stddef.h>	/* sizeof_field() */
#include <linux/timer.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/writeback.h>	/* sync_page_range() */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
#include <net/net_namespace.h>  /* init_net */
#endif
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

/* <asm-generic/bug.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27) && !defined(WARN)
/* See also commit a8f18b909c0a3f22630846207035c8b84bb252b8 */
#define WARN(condition, format...) do {		\
	if (unlikely(condition)) {		\
		printk(KERN_WARNING format);	\
		WARN_ON(true);			\
	}					\
} while (0)
#endif

/* <asm-generic/fcntl.h> */

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)
#ifndef O_DSYNC
#define O_DSYNC O_SYNC
#endif
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

/* <linux/blk_types.h> */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
enum {
	REQ_OP_SCSI_IN	= REQ_OP_DRV_IN,
	REQ_OP_SCSI_OUT	= REQ_OP_DRV_OUT,
};
#endif

/* <linux/blk-mq.h> */

static inline unsigned int scst_blk_rq_cpu(struct request *rq)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
	/*
	 * See also commit c7c22e4d5c1f ("block: add support for IO CPU
	 * affinity") # v2.6.28.
	 */
	return 0;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 21, 0) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 8)
	return rq->cpu;
#else
	return blk_mq_rq_cpu(rq);
#endif
}

/* <linux/blkdev.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
static inline unsigned int queue_max_hw_sectors(struct request_queue *q)
{
	return q->max_hw_sectors;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
/* See also commit ac481c20ef8f ("block: Topology ioctls") # v2.6.32 */
static inline int bdev_io_opt(struct block_device *bdev)
{
	return 0;
}
#endif

/*
 * See also commit d4d77629953e ("block: clean up blkdev_get() wrappers and
 * their users") # v2.6.38.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38)
static inline struct block_device *
blkdev_get_by_path(const char *path, fmode_t mode, void *holder)
{
	struct block_device *bdev;
	int err;

	bdev = lookup_bdev(path);
	if (IS_ERR(bdev))
		return bdev;

	err = blkdev_get(bdev, mode);
	if (err)
		return ERR_PTR(err);

	return bdev;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
/*
 * See also commit b84ba30b6c7a ("block: remove the gendisk argument to
 * blk_execute_rq") # v5.17.
 */
static inline
void blk_execute_rq_nowait_backport(struct request *rq, bool at_head,
				    rq_end_io_fn *done)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
	/*
	 * See also commit 8eeed0b554b9 ("block: remove unnecessary argument from
	 * blk_execute_rq_nowait") # v5.12.
	 */
	blk_execute_rq_nowait(rq->q, NULL, rq, at_head, done);
#else
	blk_execute_rq_nowait(NULL, rq, at_head, done);
#endif
}

#define blk_execute_rq_nowait blk_execute_rq_nowait_backport
#endif

/* <linux/bsg-lib.h> */

/*
 * Note: the function bsg_job_sense() exists only in SCST but not in any
 * upstream kernel.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
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
	return scsi_req(blk_mq_rq_from_pdu(job))->sense;
#endif
}
#endif
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31) */

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

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 20)
#ifndef __printf
#define __printf(a, b) __attribute__((format(printf, a, b)))
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 21)
#ifndef __aligned
#define __aligned(x) __attribute__((aligned(x)))
#endif
#ifndef __packed
#define __packed __attribute__((packed))
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0) && !defined(READ_ONCE)
/*
 * See also patch "kernel: Provide READ_ONCE and ASSIGN_ONCE" (commit ID
 * 230fa253df6352af12ad0a16128760b5cb3f92df).
 */
#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
#define ACCESS_ONCE(x) READ_ONCE(x)
#endif

#endif

/*
 * See also commit e0fdb0e050ea ("percpu: add __percpu for sparse.")
 * # v2.6.34.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34) && !defined(__percpu)
#define __percpu
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

/* <linux/cpumask.h> */

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 20) && !defined(BACKPORT_LINUX_CPUMASK_H)
#define nr_cpu_ids NR_CPUS
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28) && defined(__LINUX_CPUMASK_H)
/*
 * See also patch "cpumask: introduce new API, without changing anything"
 * (commit ID 2d3854a37e8b).
 */
typedef cpumask_t cpumask_var_t[1];
#define cpumask_bits(maskp) ((maskp)->bits)
#ifdef CONFIG_CPUMASK_OFFSTACK
/*
 * Assuming NR_CPUS is huge, a runtime limit is more efficient.  Also,
 * not all bits may be allocated.
 */
#define nr_cpumask_bits nr_cpu_ids
#else
#define nr_cpumask_bits NR_CPUS
#endif

#ifdef CONFIG_CPUMASK_OFFSTACK
bool alloc_cpumask_var(cpumask_var_t *mask, gfp_t flags);
void free_cpumask_var(cpumask_var_t mask);
#else
static inline void free_cpumask_var(cpumask_var_t mask)
{
}

static inline bool alloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
	return true;
}
#endif

/* verify cpu argument to cpumask_* operators */
static inline unsigned int cpumask_check(unsigned int cpu)
{
#ifdef CONFIG_DEBUG_PER_CPU_MAPS
	WARN_ON_ONCE(cpu >= nr_cpumask_bits);
#endif /* CONFIG_DEBUG_PER_CPU_MAPS */
	return cpu;
}

/**
 * cpumask_next - get the next cpu in a cpumask
 * @n: the cpu prior to the place to search (ie. return will be > @n)
 * @srcp: the cpumask pointer
 *
 * Returns >= nr_cpu_ids if no further cpus set.
 */
static inline unsigned int cpumask_next(int n, const cpumask_t *srcp)
{
	/* -1 is a legal arg here. */
	if (n != -1)
		cpumask_check(n);
	return find_next_bit(cpumask_bits(srcp), nr_cpumask_bits, n+1);
}

/**
 * for_each_cpu - iterate over every cpu in a mask
 * @cpu: the (optionally unsigned) integer iterator
 * @mask: the cpumask pointer
 *
 * After the loop, cpu is >= nr_cpu_ids.
 */
#define for_each_cpu(cpu, mask)                         \
	for ((cpu) = -1;                                \
		(cpu) = cpumask_next((cpu), (mask)),    \
		(cpu) < nr_cpu_ids;)

/**
 * cpumask_set_cpu - set a cpu in a cpumask
 * @cpu: cpu number (< nr_cpu_ids)
 * @dstp: the cpumask pointer
 */
static inline void cpumask_set_cpu(unsigned int cpu, cpumask_t *dstp)
{
	set_bit(cpu, cpumask_bits(dstp));
}

/**
 * cpumask_copy - *dstp = *srcp
 * @dstp: the result
 * @srcp: the input cpumask
 */
static inline void cpumask_copy(cpumask_t *dstp,
				const cpumask_t *srcp)
{
	bitmap_copy(cpumask_bits(dstp), cpumask_bits(srcp), nr_cpumask_bits);
}

/**
 * cpumask_setall - set all cpus (< nr_cpu_ids) in a cpumask
 * @dstp: the cpumask pointer
 */
static inline void cpumask_setall(cpumask_t *dstp)
{
	bitmap_fill(cpumask_bits(dstp), nr_cpumask_bits);
}

/**
 * cpumask_equal - *src1p == *src2p
 * @src1p: the first input
 * @src2p: the second input
 */
static inline bool cpumask_equal(const cpumask_t *src1p,
				 const cpumask_t *src2p)
{
	return bitmap_equal(cpumask_bits(src1p), cpumask_bits(src2p),
			    nr_cpumask_bits);
}
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

/* See also commit 0f8e0d9a317406612700426fad3efab0b7bbc467 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
enum {
	DLM_LSFL_NEWEXCL = 0
};
#endif

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0) && \
	!defined(CONFIG_COMPAT_KERNEL_3_12)
/*
 * See also patch "new helper: file_inode(file)" (commit ID
 * 496ad9aa8ef448058e36ca7a787c61f2e63f0f54). See also patch
 * "kill f_dentry macro" (commit ID 78d28e651f97).
 */
static inline struct inode *file_inode(const struct file *f)
{
	return f->f_dentry->d_inode;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)
static inline int vfs_fsync_backport(struct file *file, int datasync)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	struct inode *inode = file_inode(file);

	return sync_page_range(inode, file->f_mapping, 0, i_size_read(inode));
#else
	return vfs_fsync(file, file->f_path.dentry, datasync);
#endif
}

#define vfs_fsync vfs_fsync_backport
#endif

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0) || defined(RHEL_MAJOR)
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
#else
ssize_t kernel_write(struct file *file, const void *buf, size_t count,
		     loff_t *pos);
#endif
#endif

/* <linux/interrupt.h> */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39) && !defined(RHEL_MAJOR)
/*
 * See also commit cd7eab44e994 ("genirq: Add IRQ affinity notifiers";
 * v2.6.39).
 */
struct irq_affinity_notify;
static inline int
irq_set_affinity_notifier(unsigned int irq, struct irq_affinity_notify *notify)
{
	return 0;
}
#endif

/* <linux/iocontext.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25) ||	  \
	LINUX_VERSION_CODE >= KERNEL_VERSION(4, 21, 0) || \
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

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25) && \
	LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)
static inline struct io_context *get_task_io_context(struct task_struct *task,
						     gfp_t gfp_flags, int node)
{
	WARN_ON_ONCE(task != current);
	return get_io_context(gfp_flags, node);
}
#endif

/* <linux/kconfig.h> */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 1, 0) && !defined(RHEL_MAJOR)
/*
 * See also commit 2a11c8ea20bf ("kconfig: Introduce IS_ENABLED(), IS_BUILTIN()
 * and IS_MODULE()") # v3.1.
 */
#define __ARG_PLACEHOLDER_1 0,
#define __take_second_arg(__ignored, val, ...) val
#define __or(x, y)			___or(x, y)
#define ___or(x, y)			____or(__ARG_PLACEHOLDER_##x, y)
#define ____or(arg1_or_junk, y)		__take_second_arg(arg1_or_junk 1, y)
#define __is_defined(x)			___is_defined(x)
#define ___is_defined(val)		____is_defined(__ARG_PLACEHOLDER_##val)
#define ____is_defined(arg1_or_junk)	__take_second_arg(arg1_or_junk 1, 0)
#define IS_BUILTIN(option) __is_defined(option)
#define IS_MODULE(option) __is_defined(option##_MODULE)
#define IS_ENABLED(option) __or(IS_BUILTIN(option), IS_MODULE(option))
#endif

/* <linux/kernel.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
#ifndef RHEL_RELEASE_CODE
typedef _Bool bool;
#endif
#define true  1
#define false 0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
#ifndef swap
#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 6 ||	\
	 RHEL_MAJOR -0 == 6 && RHEL_MINOR -0 < 1)
extern int hex_to_bin(char ch);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34) && !defined(RHEL_MAJOR)
/* See also commit 9b3be9f99203 ("Move round_up/down to kernel.h") # v2.6.34 */
/*
 * This looks more complex than it should be. But we need to
 * get the type for the ~ right in round_down (it needs to be
 * as wide as the result!), and we want to evaluate the macro
 * arguments just once each.
 */
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
/**
 * round_up - round up to next specified power of 2
 * @x: the value to round
 * @y: multiple to round up to (must be a power of 2)
 *
 * Rounds @x up to next multiple of @y (which must be a power of 2).
 * To perform arbitrary rounding up, use roundup() below.
 */
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
/**
 * round_down - round down to next specified power of 2
 * @x: the value to round
 * @y: multiple to round down to (must be a power of 2)
 *
 * Rounds @x down to next multiple of @y (which must be a power of 2).
 * To perform arbitrary rounding down, use rounddown() below.
 */
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38)
/*
 * See also "lib: hex2bin converts ascii hexadecimal string to binary" (commit
 * dc88e46029486ed475c71fe1bb696d39511ac8fe).
 */
static inline void hex2bin(u8 *dst, const char *src, size_t count)
{
	while (count--) {
		*dst = hex_to_bin(*src++) << 4;
		*dst += hex_to_bin(*src++);
		dst++;
	}
}
#endif

/*
 * See also commit 33ee3b2e2eb9. That commit was introduced in kernel v2.6.39
 * and later backported to kernel v2.6.38.4.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39) &&		\
	LINUX_VERSION_CODE != KERNEL_VERSION(2, 6, 38) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 6)
static inline int __must_check kstrtoull(const char *s, unsigned int base,
					 unsigned long long *res)
{
	return strict_strtoull(s, base, res);
}

static inline int __must_check kstrtoll(const char *s, unsigned int base,
					long long *res)
{
	return strict_strtoll(s, base, res);
}

static inline int __must_check kstrtoul(const char *s, unsigned int base,
					unsigned long *res)
{
	return strict_strtoul(s, base, res);
}

static inline int __must_check kstrtol(const char *s, unsigned int base,
				       long *res)
{
	return strict_strtol(s, base, res);
}

static inline int __must_check kstrtoint(const char *s, unsigned int base,
					 int *result)
{
	long val;
	int ret = strict_strtol(s, base, &val);

	if (ret)
		return ret;
	*result = val;
	if (*result != val)
		return -EINVAL;
	return 0;
}
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

#if LINUX_VERSION_CODE >> 8 == KERNEL_VERSION(4, 4, 0) >> 8 &&	\
	LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 168)
/*
 * See also commit 8e50b8b07f46 ("mm: replace get_user_pages() write/force
 * parameters with gup_flags") # v4.4.168.
 */
static inline long get_user_pages_backport(unsigned long start,
					   unsigned long nr_pages,
					   unsigned int gup_flags,
					   struct page **pages,
					   struct vm_area_struct **vmas)
{
	return get_user_pages(current, current->mm, start, nr_pages, gup_flags,
			      pages, vmas);
}
#define get_user_pages get_user_pages_backport
#elif !defined(CONFIG_SUSE_KERNEL) &&				\
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
/*
 * See also commit cde70140fed8 ("mm/gup: Overload get_user_pages() functions")
 * # v4.6.
 */
static inline long get_user_pages_backport(unsigned long start,
					   unsigned long nr_pages,
					   unsigned int gup_flags,
					   struct page **pages,
					   struct vm_area_struct **vmas)
{
	const bool write = gup_flags & FOLL_WRITE;
	const bool force = 0;

	WARN_ON_ONCE(gup_flags & ~FOLL_WRITE);
	return get_user_pages(current, current->mm, start, nr_pages, write,
			      force, pages, vmas);
}
#define get_user_pages get_user_pages_backport
#elif (!defined(CONFIG_SUSE_KERNEL) &&				\
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)) ||	\
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
/*
 * See also commit 768ae309a961 ("mm: replace get_user_pages() write/force
 * parameters with gup_flags") # v4.9.
 */
static inline long get_user_pages_backport(unsigned long start,
					   unsigned long nr_pages,
					   unsigned int gup_flags,
					   struct page **pages,
					   struct vm_area_struct **vmas)
{
	const bool write = gup_flags & FOLL_WRITE;
	const bool force = 0;

	WARN_ON_ONCE(gup_flags & ~FOLL_WRITE);
	return get_user_pages(start, nr_pages, write, force, pages, vmas);
}
#define get_user_pages get_user_pages_backport
#endif

/* <linux/kmod.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23)
enum umh_wait {
	UMH_NO_WAIT = -1,       /* don't wait at all */
	UMH_WAIT_EXEC = 0,      /* wait for the exec, but not the process */
	UMH_WAIT_PROC = 1,      /* wait for the process to complete */
};
#endif

/* <linux/kobject_ns.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)
/*
 * See also commit 608b4b9548de ("netns: Teach network device kobjects which
 * namespace they are in.") # v2.6.35.
 */
enum kobj_ns_type {
	KOBJ_NS_TYPE_NET = 1,
};
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24) &&		      \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0) &&	      \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 7)
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0) &&		      \
	!(LINUX_VERSION_CODE >> 8 == KERNEL_VERSION(3, 4, 0) >> 8 &&  \
	  LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 41)) &&	      \
	!(LINUX_VERSION_CODE >> 8 == KERNEL_VERSION(3, 2, 0) >> 8 &&  \
	  LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 44)) &&	      \
	(!defined(CONFIG_SUSE_KERNEL) ||			      \
	 LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 101)) &&	      \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 6 ||		      \
	 (RHEL_MAJOR -0 == 6 && RHEL_MINOR -0 < 6))
/*
 * See also commit 4b20db3 (kref: Implement kref_get_unless_zero v3 -- v3.8).
 * See also commit e3a5505 in branch stable/linux-3.4.y (v3.4.41).
 * See also commit 3fa8ee5 in branch stable/linux-3.2.y (v3.2.44).
 * See also commit 6b9508d in the SuSE kernel tree.
 */
static inline int __must_check kref_get_unless_zero(struct kref *kref)
{
	return atomic_add_unless(&kref->refcount, 1, 0);
}
#endif

/* See also commit 2c935bc57221 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
#define kref_read(kref) (atomic_read(&(kref)->refcount))
#endif

/* <linux/kthread.h> */

/* See also commit 207205a2ba26 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39) && \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 6 || \
	 RHEL_MAJOR -0 == 6 && RHEL_MINOR -0 < 9)
#define kthread_create_on_node(threadfn, data, node, namefmt, arg...)\
	kthread_create((threadfn), (data), (namefmt), ##arg)
#endif

/* <linux/ktime.h> */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0) &&		\
	LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)) &&	\
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

/* <linux/lockdep.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
#define lockdep_assert_held(l) (void)(l)
#endif

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

/* <linux/pci.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0) && !defined(RHEL_MAJOR)
/*
 * See also commit 8c0d3a02c130 ("PCI: Add accessors for PCI Express
 * Capability") # v3.7.
 */
static inline int pcie_capability_read_word(struct pci_dev *dev, int pos,
					    u16 *val)
{
	WARN_ON_ONCE(true);
	*val = 0;
	return -EOPNOTSUPP;
}

static inline int pcie_capability_read_dword(struct pci_dev *dev, int pos,
					     u32 *val)
{
	WARN_ON_ONCE(true);
	*val = 0;
	return -EOPNOTSUPP;
}
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
typedef unsigned percpu_count_t;
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

static inline void percpu_ref_kill(struct percpu_ref *ref)
{
	WARN_ON_ONCE(ref->dead);
	ref->dead = true;
	percpu_ref_put(ref);
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

/* <linux/preempt.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)
/*
 * See also patch "sched: Fix softirq time accounting" (commit ID
 * 75e1056f5c57050415b64cb761a3acc35d91f013).
 */
#ifndef in_serving_softirq
#define in_serving_softirq() in_softirq()
#endif
#endif

/* <linux/printk.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24) && !defined(RHEL_MAJOR)
#define KERN_CONT       ""
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
/*
 * See also the following commits:
 * d091c2f5 - Introduction of pr_info() etc. in <linux/kernel.h>.
 * 311d0761 - Introduction of pr_cont() in <linux/kernel.h>.
 * 968ab183 - Moved pr_info() etc. from <linux/kernel.h> to <linux/printk.h>
 */
#ifndef pr_emerg

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

#define pr_emerg(fmt, ...)	printk(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_alert(fmt, ...)	printk(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit(fmt, ...)	printk(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err(fmt, ...)	printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn(fmt, ...)	printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_notice(fmt, ...)	printk(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)

#endif /* pr_emerg */

#ifndef pr_info
#define pr_info(fmt, ...)	printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#endif

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
#ifndef pr_cont
#define pr_cont(fmt, ...)	printk(KERN_CONT fmt, ##__VA_ARGS__)
#endif
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30) */

/* See also commit f036be96dd9c ("printk: introduce printk_once()") */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
#define printk_once(fmt, ...)					\
({								\
	static bool __print_once __read_mostly;			\
	bool __ret_print_once = !__print_once;			\
								\
	if (!__print_once) {					\
		__print_once = true;				\
		printk(fmt, ##__VA_ARGS__);			\
	}							\
	unlikely(__ret_print_once);				\
})
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38)
/*
 * See also commit 16cb839f1332 ("include/linux/printk.h: add pr_<level>_once
 * macros") # v2.6.38.
 */
#define pr_warn_once(fmt, ...)					\
	printk_once(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)
/*
 * See also patch "kernel.h: add pr_warn for symmetry to dev_warn,
 * netdev_warn" (commit fc62f2f19edf46c9bdbd1a54725b56b18c43e94f).
 */
#ifndef pr_warn
#define pr_warn pr_warning
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36) && \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 6)
/*
 * See also patch "Add a dummy printk function for the maintenance of unused
 * printks" (commit 12fdff3fc2483f906ae6404a6e8dcf2550310b6f).
 */
static inline __attribute__ ((format (printf, 1, 2)))
int no_printk(const char *s, ...) { return 0; }
#endif

/* <linux/ratelimit.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
/* See also commit 717115e1a585 */

#define DEFAULT_RATELIMIT_INTERVAL (5 * HZ)
#define DEFAULT_RATELIMIT_BURST 10

struct ratelimit_state {
	int interval;
	int burst;
};

#define DEFINE_RATELIMIT_STATE(name, interval, burst)	\
	struct ratelimit_state name = {interval, burst,}

static inline int __ratelimit(struct ratelimit_state *rs)
{
	return 1;
}
#endif

/* <linux/rcupdate.h> */

/* See also commit b62730baea32 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34)
#define rcu_dereference_protected(p, c) rcu_dereference(p)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0) && !defined(kfree_rcu)
typedef void (*rcu_callback_t)(struct rcu_head *);
#define __is_kfree_rcu_offset(offset) ((offset) < 4096)
#define kfree_call_rcu(head, rcb) call_rcu(head, rcb)
#define __kfree_rcu(head, offset)				\
	do {							\
		BUILD_BUG_ON(!__is_kfree_rcu_offset(offset));	\
		kfree_call_rcu(head, (rcu_callback_t)(unsigned long)(offset)); \
	} while (0)
#define kfree_rcu(ptr, rcu_head)				\
	__kfree_rcu(&((ptr)->rcu_head), offsetof(typeof(*(ptr)), rcu_head))
#endif

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

/* <linux/scatterlist.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
/*
 * The macro's sg_page(), sg_virt(), sg_init_table(), sg_assign_page() and
 * sg_set_page() have been introduced in the 2.6.24 kernel. The definitions
 * below are backports of the 2.6.24 macro's for older kernels. There is one
 * exception however: when compiling SCST on a system with a pre-2.6.24 kernel
 * (e.g. RHEL 5.x) where the OFED kernel headers have been installed, do not
 * define the backported macro's because OFED has already defined these.
 */

static inline bool sg_is_chain(struct scatterlist *sg)
{
	return false;
}

static inline struct scatterlist *sg_chain_ptr(struct scatterlist *sg)
{
	return NULL;
}

#define sg_is_last(sg) false

#ifndef sg_page
static inline struct page *sg_page(struct scatterlist *sg)
{
	return sg->page;
}
#endif

static inline void *sg_virt(struct scatterlist *sg)
{
	return page_address(sg_page(sg)) + sg->offset;
}

static inline void sg_mark_end(struct scatterlist *sg)
{
}

static inline void sg_unmark_end(struct scatterlist *sg)
{
}

#ifndef __BACKPORT_LINUX_SCATTERLIST_H_TO_2_6_23__

static inline void sg_init_table(struct scatterlist *sgl, unsigned int nents)
{
	memset(sgl, 0, sizeof(*sgl) * nents);
}

static inline void sg_assign_page(struct scatterlist *sg, struct page *page)
{
	sg->page = page;
}

static inline void sg_set_page(struct scatterlist *sg, struct page *page,
			       unsigned int len, unsigned int offset)
{
	sg_assign_page(sg, page);
	sg->offset = offset;
	sg->length = len;
}

#ifndef for_each_sg
/* See also commit 96b418c960af0d5c7185ff5c4af9376eb37ac9d3 */
#define for_each_sg(sglist, sg, nr, __i)       \
	for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next_inline(sg))
#endif /* for_each_sg */

#endif /* __BACKPORT_LINUX_SCATTERLIST_H_TO_2_6_23__ */
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
/*
 * See also commit c8164d8931fd ("scatterlist: introduce sg_unmark_end";
 * v3.10).
 */
static inline void sg_unmark_end(struct scatterlist *sg)
{
	sg->page_link &= ~0x02;
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24) */

/* <linux/sched.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26) && \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 6)
#define set_cpus_allowed_ptr(p, new_mask) set_cpus_allowed((p), *(new_mask))
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22)
#define KMEM_CACHE(__struct, __flags) kmem_cache_create(#__struct,\
	sizeof(struct __struct), __alignof__(struct __struct),\
	(__flags), NULL, NULL)
#endif

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0) &&	    \
	!(LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 52) && \
	  LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)) &&  \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 6)
static inline void *kmalloc_array(size_t n, size_t size, gfp_t flags)
{
	if (size != 0 && n > ULONG_MAX / size)
		return NULL;
	return kmalloc(n * size, flags);
}
#endif

/*
 * See also commit 8eb8284b4129 ("usercopy: Prepare for usercopy
 * whitelisting").
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23)
static inline struct kmem_cache *kmem_cache_create_usercopy(const char *name,
			unsigned int size, unsigned int align,
			unsigned long flags,
			unsigned int useroffset, unsigned int usersize,
			void (*ctor)(void *))
{
	return kmem_cache_create(name, size, align, flags, ctor, NULL);
}
/*
 * UEK4 is based on kernel v4.1.12 and does not have a backport of the v4.16
 * API. UEK5 is based on kernel v4.14.35 and has a backport of the v4.16 API.
 */
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0) &&	\
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

/* <linux/types.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
/*
 * See also patch "fix abuses of ptrdiff_t" (commit ID
 * 142956af525002c5378e7d91d81a01189841a785).
 */
typedef unsigned long uintptr_t;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22)
char *kvasprintf(gfp_t gfp, const char *fmt, va_list ap);
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

#if defined(RHEL_MAJOR) && RHEL_MAJOR -0 <= 5
static inline uint16_t get_unaligned_be16(const void *p)
{
	return be16_to_cpu(get_unaligned((__be16 *)p));
}

static inline void put_unaligned_be16(uint16_t i, void *p)
{
	put_unaligned(cpu_to_be16(i), (__be16 *)p);
}

static inline uint32_t get_unaligned_be32(const void *p)
{
	return be32_to_cpu(get_unaligned((__be32 *)p));
}

static inline void put_unaligned_be32(uint32_t i, void *p)
{
	put_unaligned(cpu_to_be32(i), (__be32 *)p);
}

static inline uint64_t get_unaligned_be64(const void *p)
{
	return be64_to_cpu(get_unaligned((__be64 *)p));
}

static inline void put_unaligned_be64(uint64_t i, void *p)
{
	put_unaligned(cpu_to_be64(i), (__be64 *)p);
}
#endif

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

/* <linux/vmalloc.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37) && \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 5 || \
	 RHEL_MAJOR -0 == 5 && RHEL_MINOR -0 < 10 || \
	 RHEL_MAJOR -0 == 6 && RHEL_MINOR -0 < 1)
/*
 * See also patch "mm: add vzalloc() and vzalloc_node() helpers" (commit
 * e1ca7788dec6773b1a2bce51b7141948f2b8bccf).
 */
static inline void *vzalloc(unsigned long size)
{
	return __vmalloc(size, GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO,
			 PAGE_KERNEL);
}
#endif

/* <linux/workqueue.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
/*
 * See also commit d320c03830b1 ("workqueue: s/__create_workqueue()/
 * alloc_workqueue()/, and add system workqueues") # v2.6.36.
 */
static inline struct workqueue_struct *alloc_workqueue(const char *fmt,
						       unsigned int flags,
						       int max_active, ...)
{
	WARN_ON_ONCE(flags | max_active);
	return create_workqueue(fmt);
}
#endif

/*
 * See also commits 18aa9effad4a ("workqueue: implement WQ_NON_REENTRANT";
 * v2.6.36) and commits dbf2576e37da ("workqueue: make all workqueues
 * non-reentrant"; v3.7).
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36) || \
	LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#define WQ_NON_REENTRANT 0
#endif

/*
 * See also commit 226223ab3c41 ("workqueue: implement sysfs interface for
 * workqueues"; v3.10).
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
#define WQ_SYSFS 0
#endif

/*
 * To do: backport alloc_ordered_workqueue(). See also commit 81dcaf6516d8
 * ("workqueue: implement alloc_ordered_workqueue()"; v2.6.37).
 */
#ifndef alloc_ordered_workqueue
#define alloc_ordered_workqueue(fmt, flags, args...)	\
	({ WARN_ON_ONCE(true); ERR_PTR(-ENOMEM); })
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24) || \
	LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0) || \
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
/*
 * See also 51f3a4788928 ("scsi: core: Introduce the scsi_cmd_to_rq()
 * function").
 */
static inline struct request *scsi_cmd_to_rq(struct scsi_cmnd *scmd)
{
	return scmd->request;
}

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

/*
 * See also commits 7ba46799d346 ("scsi: core: Add scsi_prot_ref_tag()
 * helper") and ddd0bc756983 ("block: move ref_tag calculation func to the
 * block layer"; v4.19).
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) || defined(RHEL_MAJOR)
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
/*
 * See also commit 11b68e36b167 ("scsi: core: Call scsi_done directly"; v5.16)
 */
static inline void scsi_done(struct scsi_cmnd *cmd)
{
	return cmd->scsi_done(cmd);
}
#endif

/* <scsi/scsi_request.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
static inline struct request *scsi_req(struct request *rq)
{
	return rq;
}

static inline void scsi_req_init(struct request *rq)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)
	rq->cmd_type = REQ_TYPE_BLOCK_PC;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
	rq->data_len = 0;
	rq->sector = (sector_t) -1;
#else
	rq->__data_len = 0;
	rq->__sector = (sector_t) -1;
#endif
	rq->bio = rq->biotail = NULL;
	memset(rq->__cmd, 0, sizeof(rq->__cmd));
	rq->cmd = rq->__cmd;
#else
	return blk_rq_set_block_pc(rq);
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

/*
 * See also commit c39e0af64bce ("scsi: scsi_transport_fc: Add FPIN fc event
 * codes") # v5.2
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0) && \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 8 ||	\
	 RHEL_MAJOR -0 == 8 && RHEL_MINOR -0 < 2)
static inline void
fc_host_fpin_rcv(struct Scsi_Host *shost, u32 fpin_len, char *fpin_buf)
{
}
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
