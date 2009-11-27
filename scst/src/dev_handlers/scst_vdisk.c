/*
 *  scst_vdisk.c
 *
 *  Copyright (C) 2004 - 2009 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 Ming Zhang <blackmagic02881 at gmail dot com>
 *  Copyright (C) 2007 Ross Walker <rswwalker at hotmail dot com>
 *  Copyright (C) 2007 - 2009 ID7 Ltd.
 *
 *  SCSI disk (type 0) and CDROM (type 5) dev handler using files
 *  on file systems or block devices (VDISK)
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

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/smp_lock.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/uio.h>
#include <linux/list.h>
#include <linux/ctype.h>
#include <linux/writeback.h>
#include <linux/vmalloc.h>
#include <asm/atomic.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <asm/div64.h>

#define LOG_PREFIX			"dev_vdisk"

#include "scst.h"

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

#define TRACE_ORDER	0x80000000

static struct scst_trace_log vdisk_local_trace_tbl[] =
{
    { TRACE_ORDER,		"order" },
    { 0,			NULL }
};
#define trace_log_tbl			vdisk_local_trace_tbl

#define VDISK_TRACE_TLB_HELP	", order"

#endif

#include "scst_dev_handler.h"

/* 8 byte ASCII Vendor */
#define SCST_FIO_VENDOR			"SCST_FIO"
#define SCST_BIO_VENDOR			"SCST_BIO"
/* 4 byte ASCII Product Revision Level - left aligned */
#define SCST_FIO_REV			" 200"

#define MAX_USN_LEN			(20+1) /* For '\0' */

#define INQ_BUF_SZ			128
#define EVPD				0x01
#define CMDDT				0x02

#define MSENSE_BUF_SZ			256
#define DBD				0x08	/* disable block descriptor */
#define WP				0x80	/* write protect */
#define DPOFUA				0x10	/* DPOFUA bit */
#define WCE				0x04	/* write cache enable */

#define PF				0x10	/* page format */
#define SP				0x01	/* save pages */
#define PS				0x80	/* parameter saveable */

#define	BYTE				8
#define	DEF_DISK_BLOCKSIZE_SHIFT	9
#define	DEF_DISK_BLOCKSIZE		(1 << DEF_DISK_BLOCKSIZE_SHIFT)
#define	DEF_CDROM_BLOCKSIZE_SHIFT	11
#define	DEF_CDROM_BLOCKSIZE		(1 << DEF_CDROM_BLOCKSIZE_SHIFT)
#define	DEF_SECTORS			56
#define	DEF_HEADS			255
#define LEN_MEM				(32 * 1024)

#define VDISK_NULLIO_SIZE		(3LL*1024*1024*1024*1024/2)

#define VDEV_NONE_FILENAME		"none"

#define DEF_TST				SCST_CONTR_MODE_SEP_TASK_SETS
/*
 * Since we can't control backstorage device's reordering, we have to always
 * report unrestricted reordering.
 */
#define DEF_QUEUE_ALG_WT	SCST_CONTR_MODE_QUEUE_ALG_UNRESTRICTED_REORDER
#define DEF_QUEUE_ALG		SCST_CONTR_MODE_QUEUE_ALG_UNRESTRICTED_REORDER
#define DEF_SWP			0
#define DEF_TAS			0

#define DEF_DSENSE		SCST_CONTR_MODE_FIXED_SENSE

#ifdef CONFIG_SCST_PROC
#define VDISK_PROC_HELP		"help"
#endif

static unsigned int random_values[256] = {
	    9862592UL,  3744545211UL,  2348289082UL,  4036111983UL,
	  435574201UL,  3110343764UL,  2383055570UL,  1826499182UL,
	 4076766377UL,  1549935812UL,  3696752161UL,  1200276050UL,
	 3878162706UL,  1783530428UL,  2291072214UL,   125807985UL,
	 3407668966UL,   547437109UL,  3961389597UL,   969093968UL,
	   56006179UL,  2591023451UL,     1849465UL,  1614540336UL,
	 3699757935UL,   479961779UL,  3768703953UL,  2529621525UL,
	 4157893312UL,  3673555386UL,  4091110867UL,  2193909423UL,
	 2800464448UL,  3052113233UL,   450394455UL,  3424338713UL,
	 2113709130UL,  4082064373UL,  3708640918UL,  3841182218UL,
	 3141803315UL,  1032476030UL,  1166423150UL,  1169646901UL,
	 2686611738UL,   575517645UL,  2829331065UL,  1351103339UL,
	 2856560215UL,  2402488288UL,   867847666UL,     8524618UL,
	  704790297UL,  2228765657UL,   231508411UL,  1425523814UL,
	 2146764591UL,  1287631730UL,  4142687914UL,  3879884598UL,
	  729945311UL,   310596427UL,  2263511876UL,  1983091134UL,
	 3500916580UL,  1642490324UL,  3858376049UL,   695342182UL,
	  780528366UL,  1372613640UL,  1100993200UL,  1314818946UL,
	  572029783UL,  3775573540UL,   776262915UL,  2684520905UL,
	 1007252738UL,  3505856396UL,  1974886670UL,  3115856627UL,
	 4194842288UL,  2135793908UL,  3566210707UL,     7929775UL,
	 1321130213UL,  2627281746UL,  3587067247UL,  2025159890UL,
	 2587032000UL,  3098513342UL,  3289360258UL,   130594898UL,
	 2258149812UL,  2275857755UL,  3966929942UL,  1521739999UL,
	 4191192765UL,   958953550UL,  4153558347UL,  1011030335UL,
	  524382185UL,  4099757640UL,   498828115UL,  2396978754UL,
	  328688935UL,   826399828UL,  3174103611UL,  3921966365UL,
	 2187456284UL,  2631406787UL,  3930669674UL,  4282803915UL,
	 1776755417UL,   374959755UL,  2483763076UL,   844956392UL,
	 2209187588UL,  3647277868UL,   291047860UL,  3485867047UL,
	 2223103546UL,  2526736133UL,  3153407604UL,  3828961796UL,
	 3355731910UL,  2322269798UL,  2752144379UL,   519897942UL,
	 3430536488UL,  1801511593UL,  1953975728UL,  3286944283UL,
	 1511612621UL,  1050133852UL,   409321604UL,  1037601109UL,
	 3352316843UL,  4198371381UL,   617863284UL,   994672213UL,
	 1540735436UL,  2337363549UL,  1242368492UL,   665473059UL,
	 2330728163UL,  3443103219UL,  2291025133UL,  3420108120UL,
	 2663305280UL,  1608969839UL,  2278959931UL,  1389747794UL,
	 2226946970UL,  2131266900UL,  3856979144UL,  1894169043UL,
	 2692697628UL,  3797290626UL,  3248126844UL,  3922786277UL,
	  343705271UL,  3739749888UL,  2191310783UL,  2962488787UL,
	 4119364141UL,  1403351302UL,  2984008923UL,  3822407178UL,
	 1932139782UL,  2323869332UL,  2793574182UL,  1852626483UL,
	 2722460269UL,  1136097522UL,  1005121083UL,  1805201184UL,
	 2212824936UL,  2979547931UL,  4133075915UL,  2585731003UL,
	 2431626071UL,   134370235UL,  3763236829UL,  1171434827UL,
	 2251806994UL,  1289341038UL,  3616320525UL,   392218563UL,
	 1544502546UL,  2993937212UL,  1957503701UL,  3579140080UL,
	 4270846116UL,  2030149142UL,  1792286022UL,   366604999UL,
	 2625579499UL,   790898158UL,   770833822UL,   815540197UL,
	 2747711781UL,  3570468835UL,  3976195842UL,  1257621341UL,
	 1198342980UL,  1860626190UL,  3247856686UL,   351473955UL,
	  993440563UL,   340807146UL,  1041994520UL,  3573925241UL,
	  480246395UL,  2104806831UL,  1020782793UL,  3362132583UL,
	 2272911358UL,  3440096248UL,  2356596804UL,   259492703UL,
	 3899500740UL,   252071876UL,  2177024041UL,  4284810959UL,
	 2775999888UL,  2653420445UL,  2876046047UL,  1025771859UL,
	 1994475651UL,  3564987377UL,  4112956647UL,  1821511719UL,
	 3113447247UL,   455315102UL,  1585273189UL,  2311494568UL,
	  774051541UL,  1898115372UL,  2637499516UL,   247231365UL,
	 1475014417UL,   803585727UL,  3911097303UL,  1714292230UL,
	  476579326UL,  2496900974UL,  3397613314UL,   341202244UL,
	  807790202UL,  4221326173UL,   499979741UL,  1301488547UL,
	 1056807896UL,  3525009458UL,  1174811641UL,  3049738746UL,
};

struct vdev_type;

struct scst_vdisk_dev {
	uint32_t block_size;
	uint64_t nblocks;
	int block_shift;
	loff_t file_size;	/* in bytes */

	/*
	 * This lock can be taken on both SIRQ and thread context, but in
	 * all cases for each particular instance it's taken consistenly either
	 * on SIRQ or thread context. Mix of them is forbidden.
	 */
	spinlock_t flags_lock;

	/*
	 * Below flags are protected by flags_lock or suspended activity
	 * with scst_vdisk_mutex.
	 */
	unsigned int rd_only:1;
	unsigned int wt_flag:1;
	unsigned int nv_cache:1;
	unsigned int o_direct_flag:1;
	unsigned int media_changed:1;
	unsigned int prevent_allow_medium_removal:1;
	unsigned int nullio:1;
	unsigned int blockio:1;
	unsigned int cdrom_empty:1;
	unsigned int removable:1;

	int virt_id;
	char name[16+1];	/* Name of the virtual device,
				   must be <= SCSI Model + 1 */
	char *file_name;	/* File name, protected by
				   scst_mutex and suspended activities */
	char usn[MAX_USN_LEN];
	struct scst_device *dev;
	struct list_head vdisk_dev_list_entry;

	const struct vdev_type *vdt;
};

struct scst_vdisk_tgt_dev {
	/*
	 * Used without locking since SCST core ensures that only commands
	 * with the same ORDERED type per tgt_dev can be processed
	 * simultaneously.
	 */
	enum scst_cmd_queue_type last_write_cmd_queue_type;
};

struct scst_vdisk_thr {
	struct scst_thr_data_hdr hdr;
	struct file *fd;
	struct block_device *bdev;
	struct iovec *iv;
	int iv_count;
};

/***
 *** We make virtual devices emulation in OOP-like fashion: vdev is
 *** an abstract class serving SPC set of commands and some common management
 *** tasks, vdisk - an SBC (abstract) class with fileio, blockio and nullio
 *** end classes, vcdrom - an MMC device class.
 ***
 *** Unfortunately, C doesn't support encapsulation and inheritance, so we
 *** have to open code it, which makes the code look much less beautiful, than
 *** it should.
 ***
 *** Only part to of the work is done. The second half is ToDo.
 ***/

/* VDEV sysfs actions */
#define VDEV_ACTION_OPEN		0
#define VDEV_ACTION_CLOSE		1

/* VDISK sysfs actions */
#define VDISK_ACTION_RESYNC_SIZE	100

/* VCDROM sysfs actions */
#define VCDROM_ACTION_CHANGE		100

struct vdev_type_funcs {
	struct scst_vdisk_dev *(*vdev_create) (struct vdev_type *vdt);
	void (*vdev_destroy) (struct scst_vdisk_dev *virt_dev);

	void (*vdev_init) (struct vdev_type *vdt,
		struct scst_vdisk_dev *virt_dev);
	void (*vdev_deinit) (struct scst_vdisk_dev *virt_dev);

	/* Both supposed to be called under scst_vdisk_mutex */
	int (*vdev_open) (struct vdev_type *vdt, char *p, const char *name);
	int (*vdev_close) (struct vdev_type *vdt, const char *name);

	/* All 3 supposed to be called under scst_vdisk_mutex */
	void (*vdev_add) (struct scst_vdisk_dev *virt_dev);
	void (*vdev_del) (struct scst_vdisk_dev *virt_dev);
	struct scst_vdisk_dev *(*vdev_find) (const char *name);

	int (*parse_option) (struct scst_vdisk_dev *virt_dev, char *p);

	int (*pre_register) (struct scst_vdisk_dev *virt_dev);
};

struct vdev_type {
	const char *vdt_name;
	const char *help_string;

	struct scst_dev_type *vdt_devt;

	struct vdev_type_funcs vfns;
};

struct vdisk_fileio_type {
	struct vdev_type parent_vdt;
	struct vdev_type_funcs parent_vdt_vfns;
};

struct vdisk_blockio_type {
	struct vdev_type parent_vdt;
	struct vdev_type_funcs parent_vdt_vfns;
};

struct vdisk_nullio_type {
	struct vdev_type parent_vdt;
	struct vdev_type_funcs parent_vdt_vfns;
};

struct vcdrom_type {
	struct vdev_type parent_vdt;
	struct vdev_type_funcs parent_vdt_vfns;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
#define DEF_NUM_THREADS		5
#else
/* Context RA patch supposed to be applied on the kernel */
#define DEF_NUM_THREADS		8
#endif
static int num_threads = DEF_NUM_THREADS;

module_param_named(num_threads, num_threads, int, S_IRUGO);
MODULE_PARM_DESC(num_threads, "vdisk threads count");

static int vdisk_attach(struct scst_device *dev);
static void vdisk_detach(struct scst_device *dev);
static int vdisk_attach_tgt(struct scst_tgt_dev *tgt_dev);
static void vdisk_detach_tgt(struct scst_tgt_dev *tgt_dev);
static int vdisk_parse(struct scst_cmd *);
static int vdisk_do_job(struct scst_cmd *cmd);
static int vcdrom_parse(struct scst_cmd *);
static int vcdrom_exec(struct scst_cmd *cmd);
static void vdisk_exec_read(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr, loff_t loff);
static void vdisk_exec_write(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr, loff_t loff);
static void blockio_exec_rw(struct scst_cmd *cmd, struct scst_vdisk_thr *thr,
	u64 lba_start, int write);
static void vdisk_exec_verify(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr, loff_t loff);
static void vdisk_exec_read_capacity(struct scst_cmd *cmd);
static void vdisk_exec_read_capacity16(struct scst_cmd *cmd);
static void vdisk_exec_inquiry(struct scst_cmd *cmd);
static void vdisk_exec_request_sense(struct scst_cmd *cmd);
static void vdisk_exec_mode_sense(struct scst_cmd *cmd);
static void vdisk_exec_mode_select(struct scst_cmd *cmd);
static void vdisk_exec_log(struct scst_cmd *cmd);
static void vdisk_exec_read_toc(struct scst_cmd *cmd);
static void vdisk_exec_prevent_allow_medium_removal(struct scst_cmd *cmd);
static int vdisk_fsync(struct scst_vdisk_thr *thr, loff_t loff,
	loff_t len, struct scst_cmd *cmd, struct scst_device *dev);
#ifdef CONFIG_SCST_PROC
static int vdisk_read_proc(struct seq_file *seq,
	struct scst_dev_type *dev_type);
static int vdisk_write_proc(char *buffer, char **start, off_t offset,
	int length, int *eof, struct scst_dev_type *dev_type);
static int vcdrom_read_proc(struct seq_file *seq,
	struct scst_dev_type *dev_type);
static int vcdrom_write_proc(char *buffer, char **start, off_t offset,
	int length, int *eof, struct scst_dev_type *dev_type);
#endif
static int vdisk_task_mgmt_fn(struct scst_mgmt_cmd *mcmd,
	struct scst_tgt_dev *tgt_dev);

/** SYSFS **/

#ifndef CONFIG_SCST_PROC

static ssize_t vdisk_mgmt_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdisk_mgmt_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count);

static struct kobj_attribute vdisk_mgmt_attr =
	__ATTR(mgmt, S_IRUGO | S_IWUSR, vdisk_mgmt_show, vdisk_mgmt_store);

static const struct attribute *vdisk_attrs[] = {
	&vdisk_mgmt_attr.attr,
	NULL,
};

static ssize_t vdisk_sysfs_size_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdisk_sysfs_blocksize_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdisk_sysfs_rd_only_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdisk_sysfs_wt_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdisk_sysfs_nv_cache_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdisk_sysfs_o_direct_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdisk_sysfs_removable_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdisk_sysfs_filename_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf);
static ssize_t vdisk_sysfs_resync_size_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count);

static ssize_t vcdrom_sysfs_filename_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count);

static struct kobj_attribute vdisk_size_attr =
	__ATTR(size, S_IRUGO, vdisk_sysfs_size_show, NULL);
static struct kobj_attribute vdisk_blocksize_attr =
	__ATTR(block_size, S_IRUGO, vdisk_sysfs_blocksize_show, NULL);
static struct kobj_attribute vdisk_rd_only_attr =
	__ATTR(read_only, S_IRUGO, vdisk_sysfs_rd_only_show, NULL);
static struct kobj_attribute vdisk_wt_attr =
	__ATTR(write_through, S_IRUGO, vdisk_sysfs_wt_show, NULL);
static struct kobj_attribute vdisk_nv_cache_attr =
	__ATTR(nv_cache, S_IRUGO, vdisk_sysfs_nv_cache_show, NULL);
static struct kobj_attribute vdisk_o_direct_attr =
	__ATTR(o_direct, S_IRUGO, vdisk_sysfs_o_direct_show, NULL);
static struct kobj_attribute vdisk_removable_attr =
	__ATTR(removable, S_IRUGO, vdisk_sysfs_removable_show, NULL);
static struct kobj_attribute vdisk_filename_attr =
	__ATTR(filename, S_IRUGO, vdisk_sysfs_filename_show, NULL);
static struct kobj_attribute vdisk_resync_size_attr =
	__ATTR(resync_size, S_IWUSR, NULL, vdisk_sysfs_resync_size_store);

static struct kobj_attribute vcdrom_filename_attr =
	__ATTR(filename, S_IRUGO|S_IWUSR, vdisk_sysfs_filename_show,
		vcdrom_sysfs_filename_store);

static const struct attribute *vdisk_fileio_attrs[] = {
	&vdisk_size_attr.attr,
	&vdisk_blocksize_attr.attr,
	&vdisk_rd_only_attr.attr,
	&vdisk_wt_attr.attr,
	&vdisk_nv_cache_attr.attr,
	&vdisk_o_direct_attr.attr,
	&vdisk_removable_attr.attr,
	&vdisk_filename_attr.attr,
	&vdisk_resync_size_attr.attr,
	NULL,
};

static const struct attribute *vdisk_blockio_attrs[] = {
	&vdisk_size_attr.attr,
	&vdisk_blocksize_attr.attr,
	&vdisk_rd_only_attr.attr,
	&vdisk_removable_attr.attr,
	&vdisk_filename_attr.attr,
	&vdisk_resync_size_attr.attr,
	NULL,
};

static const struct attribute *vdisk_nullio_attrs[] = {
	&vdisk_size_attr.attr,
	&vdisk_blocksize_attr.attr,
	&vdisk_rd_only_attr.attr,
	&vdisk_removable_attr.attr,
	NULL,
};

static const struct attribute *vcdrom_attrs[] = {
	&vdisk_size_attr.attr,
	&vdisk_removable_attr.attr,
	&vcdrom_filename_attr.attr,
	NULL,
};

#endif /* CONFIG_SCST_PROC */

/* Protects vdisks addition/deletion and related activities, like search */
static DEFINE_MUTEX(scst_vdisk_mutex);

/* Both protected by scst_vdisk_mutex */
static LIST_HEAD(vdisk_dev_list);
static LIST_HEAD(vcdrom_dev_list);

static struct vdisk_fileio_type fileio_type;
static struct kmem_cache *vdisk_thr_cachep;

/*
 * Be careful changing "name" field, since it is the name of the corresponding
 * /sys/kernel/scst_tgt entry, hence a part of user space ABI.
 */

static struct scst_dev_type vdisk_file_devtype = {
	.name =			"vdisk_fileio",
	.type =			TYPE_DISK,
	.exec_sync =		1,
	.threads_num =		-1,
	.parse_atomic =		1,
	.exec_atomic =		0,
	.dev_done_atomic =	1,
	.attach =		vdisk_attach,
	.detach =		vdisk_detach,
	.attach_tgt =		vdisk_attach_tgt,
	.detach_tgt =		vdisk_detach_tgt,
	.parse =		vdisk_parse,
	.exec =			vdisk_do_job,
	.task_mgmt_fn =		vdisk_task_mgmt_fn,
#ifdef CONFIG_SCST_PROC
	.read_proc =		vdisk_read_proc,
	.write_proc =		vdisk_write_proc,
#else
	.devt_attrs =		vdisk_attrs,
	.dev_attrs =		vdisk_fileio_attrs,
#endif
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags =	SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags =		&trace_flag,
	.trace_tbl =		vdisk_local_trace_tbl,
	.trace_tbl_help =	VDISK_TRACE_TLB_HELP,
#endif
};

static struct vdisk_blockio_type blockio_type;
static struct kmem_cache *blockio_work_cachep;

static struct scst_dev_type vdisk_blk_devtype = {
	.name =			"vdisk_blockio",
	.type =			TYPE_DISK,
	.threads_num =		0,
	.parse_atomic =		1,
	.exec_atomic =		0,
	.dev_done_atomic =	1,
#ifdef CONFIG_SCST_PROC
	.no_proc =		1,
#endif
	.attach =		vdisk_attach,
	.detach =		vdisk_detach,
	.attach_tgt =		vdisk_attach_tgt,
	.detach_tgt =		vdisk_detach_tgt,
	.parse =		vdisk_parse,
	.exec =			vdisk_do_job,
	.task_mgmt_fn =		vdisk_task_mgmt_fn,
#ifndef CONFIG_SCST_PROC
	.devt_attrs =		vdisk_attrs,
	.dev_attrs =		vdisk_blockio_attrs,
#endif
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags =	SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags =		&trace_flag,
	.trace_tbl =		vdisk_local_trace_tbl,
	.trace_tbl_help =	VDISK_TRACE_TLB_HELP,
#endif
};

static struct vdisk_blockio_type nullio_type;
static struct scst_dev_type vdisk_null_devtype = {
	.name =			"vdisk_nullio",
	.type =			TYPE_DISK,
	.threads_num =		0,
	.parse_atomic =		1,
	.exec_atomic =		1,
	.dev_done_atomic =	1,
#ifdef CONFIG_SCST_PROC
	.no_proc =		1,
#endif
	.attach =		vdisk_attach,
	.detach =		vdisk_detach,
	.attach_tgt =		vdisk_attach_tgt,
	.detach_tgt =		vdisk_detach_tgt,
	.parse =		vdisk_parse,
	.exec =			vdisk_do_job,
	.task_mgmt_fn =		vdisk_task_mgmt_fn,
#ifndef CONFIG_SCST_PROC
	.devt_attrs =		vdisk_attrs,
	.dev_attrs =		vdisk_nullio_attrs,
#endif
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags =	SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags =		&trace_flag,
	.trace_tbl =		vdisk_local_trace_tbl,
	.trace_tbl_help =	VDISK_TRACE_TLB_HELP,
#endif
};

static struct vcdrom_type vcdrom_type;
static struct scst_dev_type vcdrom_devtype = {
	.name =			"vcdrom",
	.type =			TYPE_ROM,
	.exec_sync =		1,
	.threads_num =		-1,
	.parse_atomic =		1,
	.exec_atomic =		0,
	.dev_done_atomic =	1,
	.attach =		vdisk_attach,
	.detach =		vdisk_detach,
	.attach_tgt =		vdisk_attach_tgt,
	.detach_tgt =		vdisk_detach_tgt,
	.parse =		vcdrom_parse,
	.exec =			vcdrom_exec,
	.task_mgmt_fn =		vdisk_task_mgmt_fn,
#ifdef CONFIG_SCST_PROC
	.read_proc =		vcdrom_read_proc,
	.write_proc =		vcdrom_write_proc,
#else
	.devt_attrs =		vdisk_attrs,
	.dev_attrs =		vcdrom_attrs,
#endif
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	.default_trace_flags =	SCST_DEFAULT_DEV_LOG_FLAGS,
	.trace_flags =		&trace_flag,
	.trace_tbl =		vdisk_local_trace_tbl,
	.trace_tbl_help =	VDISK_TRACE_TLB_HELP,
#endif
};

static struct scst_vdisk_thr nullio_thr_data;

#ifdef CONFIG_SCST_PROC
static char *vdisk_proc_help_string =
	"echo \"open|close|resync_size NAME [FILE_NAME [BLOCK_SIZE] "
	"[WRITE_THROUGH READ_ONLY O_DIRECT NULLIO NV_CACHE BLOCKIO]]\" "
	">/proc/scsi_tgt/vdisk/vdisk\n";

static char *vcdrom_proc_help_string =
	"echo \"open|change|close NAME [FILE_NAME]\" "
	">/proc/scsi_tgt/vcdrom/vcdrom\n";
#endif

static int scst_vdisk_ID;

module_param_named(scst_vdisk_ID, scst_vdisk_ID, int, S_IRUGO);
MODULE_PARM_DESC(scst_vdisk_ID, "SCST virtual disk subsystem ID");

/**************************************************************
 *  Function:  vdev_open_fd
 *
 *  Argument:
 *
 *  Returns :  fd, use IS_ERR(fd) to get error status
 *
 *  Description:
 *************************************************************/
static struct file *vdev_open_fd(const struct scst_vdisk_dev *virt_dev)
{
	int open_flags = 0;
	struct file *fd;

	TRACE_ENTRY();

	if (virt_dev->dev->rd_only)
		open_flags |= O_RDONLY;
	else
		open_flags |= O_RDWR;
	if (virt_dev->o_direct_flag)
		open_flags |= O_DIRECT;
	if (virt_dev->wt_flag && !virt_dev->nv_cache)
		open_flags |= O_SYNC;
	TRACE_DBG("Opening file %s, flags 0x%x",
		  virt_dev->file_name, open_flags);
	fd = filp_open(virt_dev->file_name, O_LARGEFILE | open_flags, 0600);

	TRACE_EXIT();
	return fd;
}

/**************************************************************
 *  Function:  vdisk_get_file_size
 *
 *  Argument:
 *
 *  Returns :  0 on success and file size in *file_size,
 *	       error code otherwise
 *
 *  Description:
 *************************************************************/
static int vdisk_get_file_size(const char *file_name, bool blockio,
	loff_t *file_size)
{
	struct inode *inode;
	int res = 0;
	struct file *fd;

	TRACE_ENTRY();

	*file_size = 0;

	fd = filp_open(file_name, O_LARGEFILE | O_RDONLY, 0600);
	if (IS_ERR(fd)) {
		res = PTR_ERR(fd);
		PRINT_ERROR("filp_open(%s) returned error %d", file_name, res);
		goto out;
	}

	inode = fd->f_dentry->d_inode;

	if (blockio && !S_ISBLK(inode->i_mode)) {
		PRINT_ERROR("File %s is NOT a block device", file_name);
		res = -EINVAL;
		goto out_close;
	}

	if (S_ISREG(inode->i_mode))
		/* Nothing to do*/;
	else if (S_ISBLK(inode->i_mode))
		inode = inode->i_bdev->bd_inode;
	else {
		res = -EINVAL;
		goto out_close;
	}

	*file_size = inode->i_size;

out_close:
	filp_close(fd, NULL);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/**************************************************************
 *  Function:  vdisk_attach
 *
 *  Argument:
 *
 *  Returns :  1 if attached, error code otherwise
 *
 *  Description:
 *************************************************************/
static int vdisk_attach(struct scst_device *dev)
{
	int res = 0;
	loff_t err;
	struct scst_vdisk_dev *virt_dev = NULL, *vv;
	struct list_head *vd;

	TRACE_ENTRY();

	TRACE_DBG("virt_id %d (%s)", dev->virt_id, dev->virt_name);

	if (dev->virt_id == 0) {
		PRINT_ERROR("%s", "Not a virtual device");
		res = -EINVAL;
		goto out;
	}

	vd = (dev->type == TYPE_DISK) ?
				&vdisk_dev_list :
				&vcdrom_dev_list;

	/*
	 * scst_vdisk_mutex must be already taken before
	 * scst_register_virtual_device()
	 */
	list_for_each_entry(vv, vd, vdisk_dev_list_entry) {
		if (strcmp(vv->name, dev->virt_name) == 0) {
			virt_dev = vv;
			break;
		}
	}

	if (virt_dev == NULL) {
		PRINT_ERROR("Device %s not found", dev->virt_name);
		res = -EINVAL;
		goto out;
	}

	virt_dev->dev = dev;

	dev->rd_only = virt_dev->rd_only;
	if (dev->type == TYPE_ROM)
		dev->rd_only = 1;

	if (!virt_dev->cdrom_empty) {
		if (virt_dev->nullio)
			err = VDISK_NULLIO_SIZE;
		else {
			res = vdisk_get_file_size(virt_dev->file_name,
				virt_dev->blockio, &err);
			if (res != 0)
				goto out;
		}
		virt_dev->file_size = err;
		TRACE_DBG("size of file: %lld", (long long unsigned int)err);
	} else
		virt_dev->file_size = 0;

	virt_dev->nblocks = virt_dev->file_size >> virt_dev->block_shift;

	if (!virt_dev->cdrom_empty) {
		PRINT_INFO("Attached SCSI target virtual %s %s "
		      "(file=\"%s\", fs=%lldMB, bs=%d, nblocks=%lld,"
		      " cyln=%lld%s)",
		      (dev->type == TYPE_DISK) ? "disk" : "cdrom",
		      virt_dev->name, virt_dev->file_name,
		      virt_dev->file_size >> 20, virt_dev->block_size,
		      (long long unsigned int)virt_dev->nblocks,
		      (long long unsigned int)virt_dev->nblocks/64/32,
		      virt_dev->nblocks < 64*32
		      ? " !WARNING! cyln less than 1" : "");
	} else {
		PRINT_INFO("Attached empty SCSI target virtual cdrom %s",
			virt_dev->name);
	}

	dev->dh_priv = virt_dev;

	dev->tst = DEF_TST;
	dev->d_sense = DEF_DSENSE;
	if (virt_dev->wt_flag && !virt_dev->nv_cache)
		dev->queue_alg = DEF_QUEUE_ALG_WT;
	else
		dev->queue_alg = DEF_QUEUE_ALG;
	dev->swp = DEF_SWP;
	dev->tas = DEF_TAS;

out:
	TRACE_EXIT();
	return res;
}

/************************************************************
 *  Function:  vdisk_detach
 *
 *  Argument:
 *
 *  Returns :  None
 *
 *  Description:  Called to detach this device type driver.
 *		  Scst_mutex supposed to be held.
 ************************************************************/
static void vdisk_detach(struct scst_device *dev)
{
	struct scst_vdisk_dev *virt_dev =
	    (struct scst_vdisk_dev *)dev->dh_priv;

	TRACE_ENTRY();

	TRACE_DBG("virt_id %d", dev->virt_id);

	PRINT_INFO("Detached SCSI target virtual device %s (\"%s\")",
		      virt_dev->name, virt_dev->file_name);

	/* virt_dev will be freed by the caller */
	dev->dh_priv = NULL;

	TRACE_EXIT();
	return;
}

static void vdisk_free_thr_data(struct scst_thr_data_hdr *d)
{
	struct scst_vdisk_thr *thr =
		container_of(d, struct scst_vdisk_thr, hdr);

	TRACE_ENTRY();

	if (thr->fd)
		filp_close(thr->fd, NULL);

	kfree(thr->iv);

	kmem_cache_free(vdisk_thr_cachep, thr);

	TRACE_EXIT();
	return;
}

static struct scst_vdisk_thr *vdisk_init_thr_data(
	struct scst_tgt_dev *tgt_dev)
{
	struct scst_vdisk_thr *res;
	struct scst_vdisk_dev *virt_dev =
	    (struct scst_vdisk_dev *)tgt_dev->dev->dh_priv;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(virt_dev->nullio);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 17)
	res = kmem_cache_alloc(vdisk_thr_cachep, GFP_KERNEL);
	if (res != NULL)
		memset(res, 0, sizeof(*res));
#else
	res = kmem_cache_zalloc(vdisk_thr_cachep, GFP_KERNEL);
#endif
	if (res == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Unable to allocate struct "
			"scst_vdisk_thr");
		goto out;
	}

	if (!virt_dev->cdrom_empty) {
		res->fd = vdev_open_fd(virt_dev);
		if (IS_ERR(res->fd)) {
			PRINT_ERROR("filp_open(%s) returned an error %ld",
				virt_dev->file_name, PTR_ERR(res->fd));
			goto out_free;
		}
		if (virt_dev->blockio)
			res->bdev = res->fd->f_dentry->d_inode->i_bdev;
		else
			res->bdev = NULL;
	} else
		res->fd = NULL;

	scst_add_thr_data(tgt_dev, &res->hdr, vdisk_free_thr_data);

out:
	TRACE_EXIT_HRES((unsigned long)res);
	return res;

out_free:
	kmem_cache_free(vdisk_thr_cachep, res);
	res = NULL;
	goto out;
}

static int vdisk_attach_tgt(struct scst_tgt_dev *tgt_dev)
{
	struct scst_vdisk_tgt_dev *ftgt_dev;
	int res = 0;

	TRACE_ENTRY();

	ftgt_dev = kzalloc(sizeof(*ftgt_dev), GFP_KERNEL);
	if (ftgt_dev == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of per-session "
			"virtual device failed");
		res = -ENOMEM;
		goto out;
	}

	tgt_dev->dh_priv = ftgt_dev;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void vdisk_detach_tgt(struct scst_tgt_dev *tgt_dev)
{
	struct scst_vdisk_tgt_dev *ftgt_dev =
		(struct scst_vdisk_tgt_dev *)tgt_dev->dh_priv;

	TRACE_ENTRY();

	scst_del_all_thr_data(tgt_dev);

	kfree(ftgt_dev);
	tgt_dev->dh_priv = NULL;

	TRACE_EXIT();
	return;
}

static inline int vdisk_sync_queue_type(enum scst_cmd_queue_type qt)
{
	switch (qt) {
	case SCST_CMD_QUEUE_ORDERED:
	case SCST_CMD_QUEUE_HEAD_OF_QUEUE:
		return 1;
	default:
		return 0;
	}
}

static inline int vdisk_need_pre_sync(enum scst_cmd_queue_type cur,
	enum scst_cmd_queue_type last)
{
	if (vdisk_sync_queue_type(cur))
		if (!vdisk_sync_queue_type(last))
			return 1;
	return 0;
}

static int vdisk_do_job(struct scst_cmd *cmd)
{
	int rc, res;
	uint64_t lba_start = 0;
	loff_t data_len = 0;
	uint8_t *cdb = cmd->cdb;
	int opcode = cdb[0];
	loff_t loff;
	struct scst_device *dev = cmd->dev;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	struct scst_vdisk_dev *virt_dev =
		(struct scst_vdisk_dev *)dev->dh_priv;
	struct scst_thr_data_hdr *d;
	struct scst_vdisk_thr *thr = NULL;
	int fua = 0;

	TRACE_ENTRY();

	switch (cmd->queue_type) {
	case SCST_CMD_QUEUE_ORDERED:
		TRACE(TRACE_ORDER, "ORDERED cmd %p (op %x)", cmd, cmd->cdb[0]);
		break;
	case SCST_CMD_QUEUE_HEAD_OF_QUEUE:
		TRACE(TRACE_ORDER, "HQ cmd %p (op %x)", cmd, cmd->cdb[0]);
		break;
	default:
		break;
	}

	rc = scst_check_local_events(cmd);
	if (unlikely(rc != 0))
		goto out_done;

	cmd->status = 0;
	cmd->msg_status = 0;
	cmd->host_status = DID_OK;
	cmd->driver_status = 0;

	if (!virt_dev->nullio) {
		d = scst_find_thr_data(tgt_dev);
		if (unlikely(d == NULL)) {
			thr = vdisk_init_thr_data(tgt_dev);
			if (thr == NULL) {
				scst_set_busy(cmd);
				goto out_compl;
			}
			scst_thr_data_get(&thr->hdr);
		} else
			thr = container_of(d, struct scst_vdisk_thr, hdr);
	} else {
		thr = &nullio_thr_data;
		scst_thr_data_get(&thr->hdr);
	}

	switch (opcode) {
	case READ_6:
	case WRITE_6:
	case VERIFY_6:
		lba_start = (((cdb[1] & 0x1f) << (BYTE * 2)) +
			     (cdb[2] << (BYTE * 1)) +
			     (cdb[3] << (BYTE * 0)));
		data_len = cmd->bufflen;
		break;
	case READ_10:
	case READ_12:
	case WRITE_10:
	case WRITE_12:
	case VERIFY:
	case WRITE_VERIFY:
	case WRITE_VERIFY_12:
	case VERIFY_12:
		lba_start |= ((u64)cdb[2]) << 24;
		lba_start |= ((u64)cdb[3]) << 16;
		lba_start |= ((u64)cdb[4]) << 8;
		lba_start |= ((u64)cdb[5]);
		data_len = cmd->bufflen;
		break;
	case READ_16:
	case WRITE_16:
	case WRITE_VERIFY_16:
	case VERIFY_16:
		lba_start |= ((u64)cdb[2]) << 56;
		lba_start |= ((u64)cdb[3]) << 48;
		lba_start |= ((u64)cdb[4]) << 40;
		lba_start |= ((u64)cdb[5]) << 32;
		lba_start |= ((u64)cdb[6]) << 24;
		lba_start |= ((u64)cdb[7]) << 16;
		lba_start |= ((u64)cdb[8]) << 8;
		lba_start |= ((u64)cdb[9]);
		data_len = cmd->bufflen;
		break;
	case SYNCHRONIZE_CACHE:
		lba_start |= ((u64)cdb[2]) << 24;
		lba_start |= ((u64)cdb[3]) << 16;
		lba_start |= ((u64)cdb[4]) << 8;
		lba_start |= ((u64)cdb[5]);
		data_len = ((cdb[7] << (BYTE * 1)) + (cdb[8] << (BYTE * 0)))
				<< virt_dev->block_shift;
		if (data_len == 0)
			data_len = virt_dev->file_size -
				((loff_t)lba_start << virt_dev->block_shift);
		break;
	}

	loff = (loff_t)lba_start << virt_dev->block_shift;
	TRACE_DBG("cmd %p, lba_start %lld, loff %lld, data_len %lld", cmd,
		  (long long unsigned int)lba_start,
		  (long long unsigned int)loff,
		  (long long unsigned int)data_len);
	if (unlikely(loff < 0) || unlikely(data_len < 0) ||
	    unlikely((loff + data_len) > virt_dev->file_size)) {
		PRINT_INFO("Access beyond the end of the device "
			"(%lld of %lld, len %lld)",
			   (long long unsigned int)loff,
			   (long long unsigned int)virt_dev->file_size,
			   (long long unsigned int)data_len);
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(
					scst_sense_block_out_range_error));
		goto out_compl;
	}

	switch (opcode) {
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		fua = (cdb[1] & 0x8);
		if (fua) {
			TRACE(TRACE_ORDER, "FUA: loff=%lld, "
				"data_len=%lld", (long long unsigned int)loff,
				(long long unsigned int)data_len);
		}
		break;
	}

	switch (opcode) {
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		if (virt_dev->blockio) {
			blockio_exec_rw(cmd, thr, lba_start, 0);
			goto out_thr;
		} else
			vdisk_exec_read(cmd, thr, loff);
		break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	{
		int do_fsync = vdisk_sync_queue_type(cmd->queue_type);
		struct scst_vdisk_tgt_dev *ftgt_dev =
			(struct scst_vdisk_tgt_dev *)tgt_dev->dh_priv;
		enum scst_cmd_queue_type last_queue_type =
			ftgt_dev->last_write_cmd_queue_type;
		ftgt_dev->last_write_cmd_queue_type = cmd->queue_type;
		if (vdisk_need_pre_sync(cmd->queue_type, last_queue_type)) {
			TRACE(TRACE_ORDER, "ORDERED WRITE(%d): loff=%lld, "
				"data_len=%lld", cmd->queue_type,
			      (long long unsigned int)loff,
			      (long long unsigned int)data_len);
			do_fsync = 1;
			if (vdisk_fsync(thr, 0, 0, cmd, dev) != 0)
				goto out_compl;
		}
		if (virt_dev->blockio) {
			blockio_exec_rw(cmd, thr, lba_start, 1);
			goto out_thr;
		} else
			vdisk_exec_write(cmd, thr, loff);
		/* O_SYNC flag is used for WT devices */
		if (do_fsync || fua)
			vdisk_fsync(thr, loff, data_len, cmd, dev);
		break;
	}
	case WRITE_VERIFY:
	case WRITE_VERIFY_12:
	case WRITE_VERIFY_16:
	{
		int do_fsync = vdisk_sync_queue_type(cmd->queue_type);
		struct scst_vdisk_tgt_dev *ftgt_dev =
			(struct scst_vdisk_tgt_dev *) tgt_dev->dh_priv;
		enum scst_cmd_queue_type last_queue_type =
			ftgt_dev->last_write_cmd_queue_type;
		ftgt_dev->last_write_cmd_queue_type = cmd->queue_type;
		if (vdisk_need_pre_sync(cmd->queue_type, last_queue_type)) {
			TRACE(TRACE_ORDER, "ORDERED "
			      "WRITE_VERIFY(%d): loff=%lld,"
			      " data_len=%lld", cmd->queue_type,
			      (long long unsigned int)loff,
			      (long long unsigned int)data_len);
			do_fsync = 1;
			if (vdisk_fsync(thr, 0, 0, cmd, dev) != 0)
				goto out_compl;
		}
		/* ToDo: BLOCKIO VERIFY */
		vdisk_exec_write(cmd, thr, loff);
		/* O_SYNC flag is used for WT devices */
		if (scsi_status_is_good(cmd->status))
			vdisk_exec_verify(cmd, thr, loff);
		else if (do_fsync)
			vdisk_fsync(thr, loff, data_len, cmd, dev);
		break;
	}
	case SYNCHRONIZE_CACHE:
	{
		int immed = cdb[1] & 0x2;
		TRACE(TRACE_ORDER, "SYNCHRONIZE_CACHE: "
			"loff=%lld, data_len=%lld, immed=%d",
			(long long unsigned int)loff,
			(long long unsigned int)data_len, immed);
		if (immed) {
			scst_cmd_get(cmd); /* to protect dev */
			cmd->completed = 1;
			cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT,
				SCST_CONTEXT_SAME);
			vdisk_fsync(thr, loff, data_len, NULL, dev);
			/* ToDo: vdisk_fsync() error processing */
			scst_cmd_put(cmd);
			goto out_thr;
		} else {
			vdisk_fsync(thr, loff, data_len, cmd, dev);
			break;
		}
	}
	case VERIFY_6:
	case VERIFY:
	case VERIFY_12:
	case VERIFY_16:
		vdisk_exec_verify(cmd, thr, loff);
		break;
	case MODE_SENSE:
	case MODE_SENSE_10:
		vdisk_exec_mode_sense(cmd);
		break;
	case MODE_SELECT:
	case MODE_SELECT_10:
		vdisk_exec_mode_select(cmd);
		break;
	case LOG_SELECT:
	case LOG_SENSE:
		vdisk_exec_log(cmd);
		break;
	case ALLOW_MEDIUM_REMOVAL:
		vdisk_exec_prevent_allow_medium_removal(cmd);
		break;
	case READ_TOC:
		vdisk_exec_read_toc(cmd);
		break;
	case START_STOP:
		vdisk_fsync(thr, 0, virt_dev->file_size, cmd, dev);
		break;
	case RESERVE:
	case RESERVE_10:
	case RELEASE:
	case RELEASE_10:
	case TEST_UNIT_READY:
		break;
	case INQUIRY:
		vdisk_exec_inquiry(cmd);
		break;
	case REQUEST_SENSE:
		vdisk_exec_request_sense(cmd);
		break;
	case READ_CAPACITY:
		vdisk_exec_read_capacity(cmd);
		break;
	case SERVICE_ACTION_IN:
		if ((cmd->cdb[1] & 0x1f) == SAI_READ_CAPACITY_16) {
			vdisk_exec_read_capacity16(cmd);
			break;
		}
		/* else go through */
	case REPORT_LUNS:
	default:
		TRACE_DBG("Invalid opcode %d", opcode);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_opcode));
	}

out_compl:
	cmd->completed = 1;

out_done:
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);

out_thr:
	if (likely(thr != NULL))
		scst_thr_data_put(&thr->hdr);

	res = SCST_EXEC_COMPLETED;

	TRACE_EXIT_RES(res);
	return res;
}

static int vdisk_get_block_shift(struct scst_cmd *cmd)
{
	struct scst_vdisk_dev *virt_dev =
	    (struct scst_vdisk_dev *)cmd->dev->dh_priv;
	return virt_dev->block_shift;
}

/********************************************************************
 *  Function:  vdisk_parse
 *
 *  Argument:
 *
 *  Returns :  The state of the command
 *
 *  Description:  This does the parsing of the command
 *
 *  Note:  Not all states are allowed on return
 ********************************************************************/
static int vdisk_parse(struct scst_cmd *cmd)
{
	scst_sbc_generic_parse(cmd, vdisk_get_block_shift);
	return SCST_CMD_STATE_DEFAULT;
}

/********************************************************************
 *  Function:  vcdrom_parse
 *
 *  Argument:
 *
 *  Returns :  The state of the command
 *
 *  Description:  This does the parsing of the command
 *
 *  Note:  Not all states are allowed on return
 ********************************************************************/
static int vcdrom_parse(struct scst_cmd *cmd)
{
	scst_cdrom_generic_parse(cmd, vdisk_get_block_shift);
	return SCST_CMD_STATE_DEFAULT;
}

/********************************************************************
 *  Function:  vcdrom_exec
 *
 *  Argument:
 *
 *  Returns :
 *
 *  Description:
 ********************************************************************/
static int vcdrom_exec(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_COMPLETED;
	int opcode = cmd->cdb[0];
	struct scst_vdisk_dev *virt_dev =
	    (struct scst_vdisk_dev *)cmd->dev->dh_priv;

	TRACE_ENTRY();

	cmd->status = 0;
	cmd->msg_status = 0;
	cmd->host_status = DID_OK;
	cmd->driver_status = 0;

	if (virt_dev->cdrom_empty && (opcode != INQUIRY)) {
		TRACE_DBG("%s", "CDROM empty");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_not_ready));
		goto out_done;
	}

	if (virt_dev->media_changed && scst_is_ua_command(cmd)) {
		spin_lock(&virt_dev->flags_lock);
		if (virt_dev->media_changed) {
			virt_dev->media_changed = 0;
			TRACE_DBG("%s", "Reporting media changed");
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_medium_changed_UA));
			spin_unlock(&virt_dev->flags_lock);
			goto out_done;
		}
		spin_unlock(&virt_dev->flags_lock);
	}

	res = vdisk_do_job(cmd);

out:
	TRACE_EXIT_RES(res);
	return res;

out_done:
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
	goto out;
}

static uint64_t vdisk_gen_dev_id_num(struct scst_vdisk_dev *virt_dev)
{
	unsigned int dev_id_num, i;

	for (dev_id_num = 0, i = 0; i < strlen(virt_dev->name); i++) {
		unsigned int rv = random_values[(int)(virt_dev->name[i])];
		/* Do some rotating of the bits */
		dev_id_num ^= ((rv << i) | (rv >> (32 - i)));
	}

	return ((uint64_t)scst_vdisk_ID << 32) | dev_id_num;
}

static void vdisk_exec_inquiry(struct scst_cmd *cmd)
{
	int32_t length, i, resp_len = 0;
	uint8_t *address;
	uint8_t *buf;
	struct scst_vdisk_dev *virt_dev =
	    (struct scst_vdisk_dev *)cmd->dev->dh_priv;

	/* ToDo: Performance Boost:
	 * 1. remove kzalloc, buf
	 * 2. do all checks before touching *address
	 * 3. zero *address
	 * 4. write directly to *address
	 */

	TRACE_ENTRY();

	buf = kzalloc(INQ_BUF_SZ,
		scst_cmd_atomic(cmd) ? GFP_ATOMIC : GFP_KERNEL);
	if (buf == NULL) {
		scst_set_busy(cmd);
		goto out;
	}

	length = scst_get_buf_first(cmd, &address);
	TRACE_DBG("length %d", length);
	if (unlikely(length <= 0)) {
		if (length < 0) {
			PRINT_ERROR("scst_get_buf_first() failed: %d", length);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
		}
		goto out_free;
	}

	if (cmd->cdb[1] & CMDDT) {
		TRACE_DBG("%s", "INQUIRY: CMDDT is unsupported");
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out_put;
	}

	buf[0] = cmd->dev->type;      /* type dev */
	if (virt_dev->removable)
		buf[1] = 0x80;      /* removable */
	/* Vital Product */
	if (cmd->cdb[1] & EVPD) {
		uint64_t dev_id_num;
		int dev_id_len;
		char dev_id_str[17];

		dev_id_num = vdisk_gen_dev_id_num(virt_dev);
		dev_id_len = scnprintf(dev_id_str, sizeof(dev_id_str), "%llx",
					dev_id_num);
		TRACE_DBG("dev_id num %lld, str %s, len %d", dev_id_num,
			dev_id_str, dev_id_len);
		if (0 == cmd->cdb[2]) {
			/* supported vital product data pages */
			buf[3] = 3;
			buf[4] = 0x0; /* this page */
			buf[5] = 0x80; /* unit serial number */
			buf[6] = 0x83; /* device identification */
			resp_len = buf[3] + 4;
		} else if (0x80 == cmd->cdb[2]) {
			/* unit serial number */
			int usn_len = strlen(virt_dev->usn);
			buf[1] = 0x80;
			buf[3] = usn_len;
			strncpy(&buf[4], virt_dev->usn, usn_len);
			resp_len = buf[3] + 4;
		} else if (0x83 == cmd->cdb[2]) {
			/* device identification */
			int num = 4;

			buf[1] = 0x83;
			/* T10 vendor identifier field format (faked) */
			buf[num + 0] = 0x2;	/* ASCII */
			buf[num + 1] = 0x1;	/* Vendor ID */
			if (virt_dev->blockio)
				memcpy(&buf[num + 4], SCST_BIO_VENDOR, 8);
			else
				memcpy(&buf[num + 4], SCST_FIO_VENDOR, 8);

			i = strlen(virt_dev->name) + 1; /* for ' ' */
			memset(&buf[num + 12], ' ', i + dev_id_len);
			memcpy(&buf[num + 12], virt_dev->name, i-1);
			memcpy(&buf[num + 12 + i], dev_id_str, dev_id_len);
			buf[num + 3] = 8 + i + dev_id_len;
			num += buf[num + 3];

#if 0 /* This isn't required and can be misleading, so let's disable it */
			num += 4;

			/* NAA IEEE registered identifier (faked) */
			buf[num] = 0x1;	/* binary */
			buf[num + 1] = 0x3;
			buf[num + 2] = 0x0;
			buf[num + 3] = 0x8;
			buf[num + 4] = 0x51; /* IEEE OUI=0x123456 (faked) */
			buf[num + 5] = 0x23;
			buf[num + 6] = 0x45;
			buf[num + 7] = 0x60;
			buf[num + 8] = (dev_id_num >> 24);
			buf[num + 9] = (dev_id_num >> 16) & 0xff;
			buf[num + 10] = (dev_id_num >> 8) & 0xff;
			buf[num + 11] = dev_id_num & 0xff;
			num = num + 12 - 4;
#endif

			resp_len = num;
			buf[2] = (resp_len >> 8) & 0xFF;
			buf[3] = resp_len & 0xFF;
			resp_len += 4;
		} else {
			TRACE_DBG("INQUIRY: Unsupported EVPD page %x",
				cmd->cdb[2]);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
			goto out_put;
		}
	} else {
		int len;

		if (cmd->cdb[2] != 0) {
			TRACE_DBG("INQUIRY: Unsupported page %x", cmd->cdb[2]);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
			goto out_put;
		}

		buf[2] = 5; /* Device complies to SPC-3 */
		buf[3] = 0x12;	/* HiSup + data in format specified in SPC */
		buf[4] = 31;/* n - 4 = 35 - 4 = 31 for full 36 byte data */
		buf[6] = 1; /* MultiP 1 */
		buf[7] = 2; /* CMDQUE 1, BQue 0 => commands queuing supported */

		/*
		 * 8 byte ASCII Vendor Identification of the target
		 * - left aligned.
		 */
		if (virt_dev->blockio)
			memcpy(&buf[8], SCST_BIO_VENDOR, 8);
		else
			memcpy(&buf[8], SCST_FIO_VENDOR, 8);

		/*
		 * 16 byte ASCII Product Identification of the target - left
		 * aligned.
		 */
		memset(&buf[16], ' ', 16);
		len = min(strlen(virt_dev->name), (size_t)16);
		memcpy(&buf[16], virt_dev->name, len);

		/*
		 * 4 byte ASCII Product Revision Level of the target - left
		 * aligned.
		 */
		memcpy(&buf[32], SCST_FIO_REV, 4);
		resp_len = buf[4] + 5;
	}

	sBUG_ON(resp_len >= INQ_BUF_SZ);
	if (length > resp_len)
		length = resp_len;
	memcpy(address, buf, length);

out_put:
	scst_put_buf(cmd, address);
	if (length < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, length);

out_free:
	kfree(buf);

out:
	TRACE_EXIT();
	return;
}

static void vdisk_exec_request_sense(struct scst_cmd *cmd)
{
	int32_t length, sl;
	uint8_t *address;
	uint8_t b[SCST_STANDARD_SENSE_LEN];

	TRACE_ENTRY();

	sl = scst_set_sense(b, sizeof(b), cmd->dev->d_sense,
		SCST_LOAD_SENSE(scst_sense_no_sense));

	length = scst_get_buf_first(cmd, &address);
	TRACE_DBG("length %d", length);
	if (length < 0) {
		PRINT_ERROR("scst_get_buf_first() failed: %d)", length);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out;
	}

	length = min(sl, length);
	memcpy(address, b, length);
	scst_set_resp_data_len(cmd, length);

	scst_put_buf(cmd, address);

out:
	TRACE_EXIT();
	return;
}

/*
 * <<Following mode pages info copied from ST318451LW with some corrections>>
 *
 * ToDo: revise them
 */
static int vdisk_err_recov_pg(unsigned char *p, int pcontrol,
			       struct scst_vdisk_dev *virt_dev)
{	/* Read-Write Error Recovery page for mode_sense */
	const unsigned char err_recov_pg[] = {0x1, 0xa, 0xc0, 11, 240, 0, 0, 0,
					      5, 0, 0xff, 0xff};

	memcpy(p, err_recov_pg, sizeof(err_recov_pg));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(err_recov_pg) - 2);
	return sizeof(err_recov_pg);
}

static int vdisk_disconnect_pg(unsigned char *p, int pcontrol,
				struct scst_vdisk_dev *virt_dev)
{ 	/* Disconnect-Reconnect page for mode_sense */
	const unsigned char disconnect_pg[] = {0x2, 0xe, 128, 128, 0, 10, 0, 0,
					       0, 0, 0, 0, 0, 0, 0, 0};

	memcpy(p, disconnect_pg, sizeof(disconnect_pg));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(disconnect_pg) - 2);
	return sizeof(disconnect_pg);
}

static int vdisk_rigid_geo_pg(unsigned char *p, int pcontrol,
	struct scst_vdisk_dev *virt_dev)
{
	unsigned char geo_m_pg[] = {0x04, 0x16, 0, 0, 0, DEF_HEADS, 0, 0,
				    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0x3a, 0x98/* 15K RPM */, 0, 0};
	int32_t ncyl, n, rem;
	uint64_t dividend;

	memcpy(p, geo_m_pg, sizeof(geo_m_pg));
	/*
	 * Divide virt_dev->nblocks by (DEF_HEADS * DEF_SECTORS) and store
	 * the quotient in ncyl and the remainder in rem.
	 */
	dividend = virt_dev->nblocks;
	rem = do_div(dividend, DEF_HEADS * DEF_SECTORS);
	ncyl = dividend;
	if (rem != 0)
		ncyl++;
	memcpy(&n, p + 2, sizeof(u32));
	n = n | (cpu_to_be32(ncyl) >> 8);
	memcpy(p + 2, &n, sizeof(u32));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(geo_m_pg) - 2);
	return sizeof(geo_m_pg);
}

static int vdisk_format_pg(unsigned char *p, int pcontrol,
			    struct scst_vdisk_dev *virt_dev)
{       /* Format device page for mode_sense */
	const unsigned char format_pg[] = {0x3, 0x16, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0x40, 0, 0, 0};

	memcpy(p, format_pg, sizeof(format_pg));
	p[10] = (DEF_SECTORS >> 8) & 0xff;
	p[11] = DEF_SECTORS & 0xff;
	p[12] = (virt_dev->block_size >> 8) & 0xff;
	p[13] = virt_dev->block_size & 0xff;
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(format_pg) - 2);
	return sizeof(format_pg);
}

static int vdisk_caching_pg(unsigned char *p, int pcontrol,
			     struct scst_vdisk_dev *virt_dev)
{ 	/* Caching page for mode_sense */
	const unsigned char caching_pg[] = {0x8, 18, 0x10, 0, 0xff, 0xff, 0, 0,
		0xff, 0xff, 0xff, 0xff, 0x80, 0x14, 0, 0, 0, 0, 0, 0};

	memcpy(p, caching_pg, sizeof(caching_pg));
	p[2] |= !(virt_dev->wt_flag || virt_dev->nv_cache) ? WCE : 0;
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(caching_pg) - 2);
	return sizeof(caching_pg);
}

static int vdisk_ctrl_m_pg(unsigned char *p, int pcontrol,
			    struct scst_vdisk_dev *virt_dev)
{ 	/* Control mode page for mode_sense */
	const unsigned char ctrl_m_pg[] = {0xa, 0xa, 0, 0, 0, 0, 0, 0,
					   0, 0, 0x2, 0x4b};

	memcpy(p, ctrl_m_pg, sizeof(ctrl_m_pg));
	switch (pcontrol) {
	case 0:
		p[2] |= virt_dev->dev->tst << 5;
		p[2] |= virt_dev->dev->d_sense << 2;
		p[3] |= virt_dev->dev->queue_alg << 4;
		p[4] |= virt_dev->dev->swp << 3;
		p[5] |= virt_dev->dev->tas << 6;
		break;
	case 1:
		memset(p + 2, 0, sizeof(ctrl_m_pg) - 2);
#if 0	/*
	 * It's too early to implement it, since we can't control the
	 * backstorage device parameters. ToDo
	 */
		p[2] |= 7 << 5;		/* TST */
		p[3] |= 0xF << 4;	/* QUEUE ALGORITHM MODIFIER */
#endif
		p[2] |= 1 << 2;		/* D_SENSE */
		p[4] |= 1 << 3;		/* SWP */
		p[5] |= 1 << 6;		/* TAS */
		break;
	case 2:
		p[2] |= DEF_TST << 5;
		p[2] |= DEF_DSENSE << 2;
		if (virt_dev->wt_flag || virt_dev->nv_cache)
			p[3] |= DEF_QUEUE_ALG_WT << 4;
		else
			p[3] |= DEF_QUEUE_ALG << 4;
		p[4] |= DEF_SWP << 3;
		p[5] |= DEF_TAS << 6;
		break;
	default:
		sBUG();
	}
	return sizeof(ctrl_m_pg);
}

static int vdisk_iec_m_pg(unsigned char *p, int pcontrol,
			   struct scst_vdisk_dev *virt_dev)
{	/* Informational Exceptions control mode page for mode_sense */
	const unsigned char iec_m_pg[] = {0x1c, 0xa, 0x08, 0, 0, 0, 0, 0,
					  0, 0, 0x0, 0x0};
	memcpy(p, iec_m_pg, sizeof(iec_m_pg));
	if (1 == pcontrol)
		memset(p + 2, 0, sizeof(iec_m_pg) - 2);
	return sizeof(iec_m_pg);
}

static void vdisk_exec_mode_sense(struct scst_cmd *cmd)
{
	int32_t length;
	uint8_t *address;
	uint8_t *buf;
	struct scst_vdisk_dev *virt_dev;
	uint32_t blocksize;
	uint64_t nblocks;
	unsigned char dbd, type;
	int pcontrol, pcode, subpcode;
	unsigned char dev_spec;
	int msense_6, offset = 0, len;
	unsigned char *bp;

	TRACE_ENTRY();

	buf = kzalloc(MSENSE_BUF_SZ,
		scst_cmd_atomic(cmd) ? GFP_ATOMIC : GFP_KERNEL);
	if (buf == NULL) {
		scst_set_busy(cmd);
		goto out;
	}

	virt_dev = (struct scst_vdisk_dev *)cmd->dev->dh_priv;
	blocksize = virt_dev->block_size;
	nblocks = virt_dev->nblocks;

	type = cmd->dev->type;    /* type dev */
	dbd = cmd->cdb[1] & DBD;
	pcontrol = (cmd->cdb[2] & 0xc0) >> 6;
	pcode = cmd->cdb[2] & 0x3f;
	subpcode = cmd->cdb[3];
	msense_6 = (MODE_SENSE == cmd->cdb[0]);
	dev_spec = (virt_dev->dev->rd_only ? WP : 0) | DPOFUA;

	length = scst_get_buf_first(cmd, &address);
	if (unlikely(length <= 0)) {
		if (length < 0) {
			PRINT_ERROR("scst_get_buf_first() failed: %d", length);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
		}
		goto out_free;
	}

	if (0x3 == pcontrol) {
		TRACE_DBG("%s", "MODE SENSE: Saving values not supported");
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_saving_params_unsup));
		goto out_put;
	}

	if (msense_6) {
		buf[1] = type;
		buf[2] = dev_spec;
		offset = 4;
	} else {
		buf[2] = type;
		buf[3] = dev_spec;
		offset = 8;
	}

	if (0 != subpcode) {
		/* TODO: Control Extension page */
		TRACE_DBG("%s", "MODE SENSE: Only subpage 0 is supported");
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out_put;
	}

	if (!dbd) {
		/* Create block descriptor */
		buf[offset - 1] = 0x08;		/* block descriptor length */
		if (nblocks >> 32) {
			buf[offset + 0] = 0xFF;
			buf[offset + 1] = 0xFF;
			buf[offset + 2] = 0xFF;
			buf[offset + 3] = 0xFF;
		} else {
			/* num blks */
			buf[offset + 0] = (nblocks >> (BYTE * 3)) & 0xFF;
			buf[offset + 1] = (nblocks >> (BYTE * 2)) & 0xFF;
			buf[offset + 2] = (nblocks >> (BYTE * 1)) & 0xFF;
			buf[offset + 3] = (nblocks >> (BYTE * 0)) & 0xFF;
		}
		buf[offset + 4] = 0;			/* density code */
		buf[offset + 5] = (blocksize >> (BYTE * 2)) & 0xFF;/* blklen */
		buf[offset + 6] = (blocksize >> (BYTE * 1)) & 0xFF;
		buf[offset + 7] = (blocksize >> (BYTE * 0)) & 0xFF;

		offset += 8;			/* increment offset */
	}

	bp = buf + offset;

	switch (pcode) {
	case 0x1:	/* Read-Write error recovery page, direct access */
		len = vdisk_err_recov_pg(bp, pcontrol, virt_dev);
		break;
	case 0x2:	/* Disconnect-Reconnect page, all devices */
		len = vdisk_disconnect_pg(bp, pcontrol, virt_dev);
		break;
	case 0x3:       /* Format device page, direct access */
		len = vdisk_format_pg(bp, pcontrol, virt_dev);
		break;
	case 0x4:	/* Rigid disk geometry */
		len = vdisk_rigid_geo_pg(bp, pcontrol, virt_dev);
		break;
	case 0x8:	/* Caching page, direct access */
		len = vdisk_caching_pg(bp, pcontrol, virt_dev);
		break;
	case 0xa:	/* Control Mode page, all devices */
		len = vdisk_ctrl_m_pg(bp, pcontrol, virt_dev);
		break;
	case 0x1c:	/* Informational Exceptions Mode page, all devices */
		len = vdisk_iec_m_pg(bp, pcontrol, virt_dev);
		break;
	case 0x3f:	/* Read all Mode pages */
		len = vdisk_err_recov_pg(bp, pcontrol, virt_dev);
		len += vdisk_disconnect_pg(bp + len, pcontrol, virt_dev);
		len += vdisk_format_pg(bp + len, pcontrol, virt_dev);
		len += vdisk_caching_pg(bp + len, pcontrol, virt_dev);
		len += vdisk_ctrl_m_pg(bp + len, pcontrol, virt_dev);
		len += vdisk_iec_m_pg(bp + len, pcontrol, virt_dev);
		len += vdisk_rigid_geo_pg(bp + len, pcontrol, virt_dev);
		break;
	default:
		TRACE_DBG("MODE SENSE: Unsupported page %x", pcode);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out_put;
	}

	offset += len;

	if (msense_6)
		buf[0] = offset - 1;
	else {
		buf[0] = ((offset - 2) >> 8) & 0xff;
		buf[1] = (offset - 2) & 0xff;
	}

	if (offset > length)
		offset = length;
	memcpy(address, buf, offset);

out_put:
	scst_put_buf(cmd, address);
	if (offset < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, offset);

out_free:
	kfree(buf);

out:
	TRACE_EXIT();
	return;
}

static int vdisk_set_wt(struct scst_vdisk_dev *virt_dev, int wt)
{
	int res = 0;

	TRACE_ENTRY();

	if ((virt_dev->wt_flag == wt) || virt_dev->nullio || virt_dev->nv_cache)
		goto out;

	spin_lock(&virt_dev->flags_lock);
	virt_dev->wt_flag = wt;
	spin_unlock(&virt_dev->flags_lock);

	scst_dev_del_all_thr_data(virt_dev->dev);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void vdisk_ctrl_m_pg_select(unsigned char *p,
	struct scst_vdisk_dev *virt_dev)
{
	struct scst_device *dev = virt_dev->dev;
	int old_swp = dev->swp, old_tas = dev->tas, old_dsense = dev->d_sense;

#if 0
	/* Not implemented yet, see comment in vdisk_ctrl_m_pg() */
	dev->tst = p[2] >> 5;
	dev->queue_alg = p[3] >> 4;
#endif
	dev->swp = (p[4] & 0x8) >> 3;
	dev->tas = (p[5] & 0x40) >> 6;
	dev->d_sense = (p[2] & 0x4) >> 2;

	PRINT_INFO("Device %s: new control mode page parameters: SWP %x "
		"(was %x), TAS %x (was %x), D_SENSE %d (was %d)",
		virt_dev->name, dev->swp, old_swp, dev->tas, old_tas,
		dev->d_sense, old_dsense);
	return;
}

static void vdisk_exec_mode_select(struct scst_cmd *cmd)
{
	int32_t length;
	uint8_t *address;
	struct scst_vdisk_dev *virt_dev;
	int mselect_6, offset;

	TRACE_ENTRY();

	virt_dev = (struct scst_vdisk_dev *)cmd->dev->dh_priv;
	mselect_6 = (MODE_SELECT == cmd->cdb[0]);

	length = scst_get_buf_first(cmd, &address);
	if (unlikely(length <= 0)) {
		if (length < 0) {
			PRINT_ERROR("scst_get_buf_first() failed: %d", length);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
		}
		goto out;
	}

	if (!(cmd->cdb[1] & PF) || (cmd->cdb[1] & SP)) {
		TRACE(TRACE_MINOR|TRACE_SCSI, "MODE SELECT: Unsupported "
			"value(s) of PF and/or SP bits (cdb[1]=%x)",
			cmd->cdb[1]);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out_put;
	}

	if (mselect_6)
		offset = 4;
	else
		offset = 8;

	if (address[offset - 1] == 8) {
		offset += 8;
	} else if (address[offset - 1] != 0) {
		PRINT_ERROR("%s", "MODE SELECT: Wrong parameters list "
			"lenght");
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_invalid_field_in_parm_list));
		goto out_put;
	}

	while (length > offset + 2) {
		if (address[offset] & PS) {
			PRINT_ERROR("%s", "MODE SELECT: Illegal PS bit");
			scst_set_cmd_error(cmd, SCST_LOAD_SENSE(
				scst_sense_invalid_field_in_parm_list));
			goto out_put;
		}
		if ((address[offset] & 0x3f) == 0x8) {
			/* Caching page */
			if (address[offset + 1] != 18) {
				PRINT_ERROR("%s", "MODE SELECT: Invalid "
					"caching page request");
				scst_set_cmd_error(cmd, SCST_LOAD_SENSE(
				    scst_sense_invalid_field_in_parm_list));
				goto out_put;
			}
			if (vdisk_set_wt(virt_dev,
			      (address[offset + 2] & WCE) ? 0 : 1) != 0) {
				scst_set_cmd_error(cmd,
				    SCST_LOAD_SENSE(scst_sense_hardw_error));
				goto out_put;
			}
			break;
		} else if ((address[offset] & 0x3f) == 0xA) {
			/* Control page */
			if (address[offset + 1] != 0xA) {
				PRINT_ERROR("%s", "MODE SELECT: Invalid "
					"control page request");
				scst_set_cmd_error(cmd, SCST_LOAD_SENSE(
				    scst_sense_invalid_field_in_parm_list));
				goto out_put;
			}
			vdisk_ctrl_m_pg_select(&address[offset], virt_dev);
		} else {
			PRINT_ERROR("MODE SELECT: Invalid request %x",
				address[offset] & 0x3f);
			scst_set_cmd_error(cmd, SCST_LOAD_SENSE(
			    scst_sense_invalid_field_in_parm_list));
			goto out_put;
		}
		offset += address[offset + 1];
	}

out_put:
	scst_put_buf(cmd, address);

out:
	TRACE_EXIT();
	return;
}

static void vdisk_exec_log(struct scst_cmd *cmd)
{
	TRACE_ENTRY();

	/* No log pages are supported */
	scst_set_cmd_error(cmd,
		SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));

	TRACE_EXIT();
	return;
}

static void vdisk_exec_read_capacity(struct scst_cmd *cmd)
{
	int32_t length;
	uint8_t *address;
	struct scst_vdisk_dev *virt_dev;
	uint32_t blocksize;
	uint64_t nblocks;
	uint8_t buffer[READ_CAP_LEN];

	TRACE_ENTRY();

	virt_dev = (struct scst_vdisk_dev *)cmd->dev->dh_priv;
	blocksize = virt_dev->block_size;
	nblocks = virt_dev->nblocks;

	/* last block on the virt_dev is (nblocks-1) */
	memset(buffer, 0, sizeof(buffer));
	if (nblocks >> 32) {
		buffer[0] = 0xFF;
		buffer[1] = 0xFF;
		buffer[2] = 0xFF;
		buffer[3] = 0xFF;
	} else {
		buffer[0] = ((nblocks - 1) >> (BYTE * 3)) & 0xFF;
		buffer[1] = ((nblocks - 1) >> (BYTE * 2)) & 0xFF;
		buffer[2] = ((nblocks - 1) >> (BYTE * 1)) & 0xFF;
		buffer[3] = ((nblocks - 1) >> (BYTE * 0)) & 0xFF;
	}
	buffer[4] = (blocksize >> (BYTE * 3)) & 0xFF;
	buffer[5] = (blocksize >> (BYTE * 2)) & 0xFF;
	buffer[6] = (blocksize >> (BYTE * 1)) & 0xFF;
	buffer[7] = (blocksize >> (BYTE * 0)) & 0xFF;

	length = scst_get_buf_first(cmd, &address);
	if (unlikely(length <= 0)) {
		if (length < 0) {
			PRINT_ERROR("scst_get_buf_first() failed: %d", length);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
		}
		goto out;
	}

	if (length > READ_CAP_LEN)
		length = READ_CAP_LEN;
	memcpy(address, buffer, length);

	scst_put_buf(cmd, address);

	if (length < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, length);

out:
	TRACE_EXIT();
	return;
}

static void vdisk_exec_read_capacity16(struct scst_cmd *cmd)
{
	int32_t length;
	uint8_t *address;
	struct scst_vdisk_dev *virt_dev;
	uint32_t blocksize;
	uint64_t nblocks;
	uint8_t buffer[READ_CAP16_LEN];

	TRACE_ENTRY();

	virt_dev = (struct scst_vdisk_dev *)cmd->dev->dh_priv;
	blocksize = virt_dev->block_size;
	nblocks = virt_dev->nblocks - 1;

	memset(buffer, 0, sizeof(buffer));

	buffer[0] = nblocks >> 56;
	buffer[1] = (nblocks >> 48) & 0xFF;
	buffer[2] = (nblocks >> 40) & 0xFF;
	buffer[3] = (nblocks >> 32) & 0xFF;
	buffer[4] = (nblocks >> 24) & 0xFF;
	buffer[5] = (nblocks >> 16) & 0xFF;
	buffer[6] = (nblocks >> 8) & 0xFF;
	buffer[7] = nblocks & 0xFF;

	buffer[8] = (blocksize >> (BYTE * 3)) & 0xFF;
	buffer[9] = (blocksize >> (BYTE * 2)) & 0xFF;
	buffer[10] = (blocksize >> (BYTE * 1)) & 0xFF;
	buffer[11] = (blocksize >> (BYTE * 0)) & 0xFF;

	switch (blocksize) {
	case 512:
		buffer[13] = 3;
		break;
	case 1024:
		buffer[13] = 2;
		break;
	case 2048:
		buffer[13] = 1;
		break;
	default:
		PRINT_ERROR("%s: Unexpected block size %d",
			cmd->op_name, blocksize);
		/* go through */
	case 4096:
		buffer[13] = 0;
		break;
	}

	length = scst_get_buf_first(cmd, &address);
	if (unlikely(length <= 0)) {
		if (length < 0) {
			PRINT_ERROR("scst_get_buf_first() failed: %d", length);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
			}
		goto out;
	}

	/*
	 * Some versions of Windows have a bug, which makes them consider
	 * response of READ CAPACITY(16) longer than 12 bytes as a faulty one.
	 * As the result, such Windows'es refuse to see SCST exported
	 * devices >2TB in size. This is fixed by MS in latter Windows
	 * versions, probably, by some hotfix.
	 *
	 * But if you're using such buggy Windows and experience this problem,
	 * change this '1' to '0'.
	 */
#if 1
	if (length > READ_CAP16_LEN)
		length = READ_CAP16_LEN;
#else
	if (length > 12)
		length = 12;
#endif
	memcpy(address, buffer, length);

	scst_put_buf(cmd, address);

	if (length < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, length);

out:
	TRACE_EXIT();
	return;
}

static void vdisk_exec_read_toc(struct scst_cmd *cmd)
{
	int32_t length, off = 0;
	uint8_t *address;
	struct scst_vdisk_dev *virt_dev;
	uint32_t nblocks;
	uint8_t buffer[4+8+8] = { 0x00, 0x0a, 0x01, 0x01, 0x00, 0x14,
				  0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };

	TRACE_ENTRY();

	if (cmd->dev->type != TYPE_ROM) {
		PRINT_ERROR("%s", "READ TOC for non-CDROM device");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_opcode));
		goto out;
	}

	if (cmd->cdb[2] & 0x0e/*Format*/) {
		PRINT_ERROR("%s", "READ TOC: invalid requested data format");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out;
	}

	if ((cmd->cdb[6] != 0 && (cmd->cdb[2] & 0x01)) ||
	    (cmd->cdb[6] > 1 && cmd->cdb[6] != 0xAA)) {
		PRINT_ERROR("READ TOC: invalid requested track number %x",
			cmd->cdb[6]);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out;
	}

	length = scst_get_buf_first(cmd, &address);
	if (unlikely(length <= 0)) {
		if (length < 0) {
			PRINT_ERROR("scst_get_buf_first() failed: %d", length);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
		}
		goto out;
	}

	virt_dev = (struct scst_vdisk_dev *)cmd->dev->dh_priv;
	/* ToDo when you have > 8TB ROM device. */
	nblocks = (uint32_t)virt_dev->nblocks;

	/* Header */
	memset(buffer, 0, sizeof(buffer));
	buffer[2] = 0x01;    /* First Track/Session */
	buffer[3] = 0x01;    /* Last Track/Session */
	off = 4;
	if (cmd->cdb[6] <= 1) {
		/* Fistr TOC Track Descriptor */
		/* ADDR    0x10 - Q Sub-channel encodes current position data
		   CONTROL 0x04 - Data track, recoreded uninterrupted */
		buffer[off+1] = 0x14;
		/* Track Number */
		buffer[off+2] = 0x01;
		off += 8;
	}
	if (!(cmd->cdb[2] & 0x01)) {
		/* Lead-out area TOC Track Descriptor */
		buffer[off+1] = 0x14;
		/* Track Number */
		buffer[off+2] = 0xAA;
		/* Track Start Address */
		buffer[off+4] = (nblocks >> (BYTE * 3)) & 0xFF;
		buffer[off+5] = (nblocks >> (BYTE * 2)) & 0xFF;
		buffer[off+6] = (nblocks >> (BYTE * 1)) & 0xFF;
		buffer[off+7] = (nblocks >> (BYTE * 0)) & 0xFF;
		off += 8;
	}

	buffer[1] = off - 2;    /* Data  Length */

	if (off > length)
		off = length;
	memcpy(address, buffer, off);

	scst_put_buf(cmd, address);

	if (off < cmd->resp_data_len)
		scst_set_resp_data_len(cmd, off);

out:
	TRACE_EXIT();
	return;
}

static void vdisk_exec_prevent_allow_medium_removal(struct scst_cmd *cmd)
{
	struct scst_vdisk_dev *virt_dev =
		(struct scst_vdisk_dev *)cmd->dev->dh_priv;

	TRACE_DBG("PERSIST/PREVENT 0x%02x", cmd->cdb[4]);

	if (cmd->dev->type == TYPE_ROM) {
		spin_lock(&virt_dev->flags_lock);
		virt_dev->prevent_allow_medium_removal =
			cmd->cdb[4] & 0x01 ? 1 : 0;
		spin_unlock(&virt_dev->flags_lock);
	}

	return;
}

static int vdisk_fsync(struct scst_vdisk_thr *thr, loff_t loff,
	loff_t len, struct scst_cmd *cmd, struct scst_device *dev)
{
	int res = 0;
	struct scst_vdisk_dev *virt_dev =
		(struct scst_vdisk_dev *)dev->dh_priv;
	struct file *file = thr->fd;
	struct inode *inode;
	struct address_space *mapping;

	TRACE_ENTRY();

	/* Hopefully, the compiler will generate the single comparison */
	if (virt_dev->nv_cache || virt_dev->blockio || virt_dev->wt_flag ||
	    virt_dev->o_direct_flag || virt_dev->nullio)
		goto out;

	inode = file->f_dentry->d_inode;
	mapping = file->f_mapping;

	res = sync_page_range(inode, mapping, loff, len);
	if (unlikely(res != 0)) {
		PRINT_ERROR("sync_page_range() failed (%d)", res);
		if (cmd != NULL) {
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_write_error));
		}
	}

	/* ToDo: flush the device cache, if needed */

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct iovec *vdisk_alloc_iv(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr)
{
	int iv_count;

	iv_count = scst_get_buf_count(cmd);
	if (iv_count > thr->iv_count) {
		kfree(thr->iv);
		/* It can't be called in atomic context */
		thr->iv = kmalloc(sizeof(*thr->iv) * iv_count, GFP_KERNEL);
		if (thr->iv == NULL) {
			PRINT_ERROR("Unable to allocate iv (%d)", iv_count);
			scst_set_busy(cmd);
			goto out;
		}
		thr->iv_count = iv_count;
	}

out:
	return thr->iv;
}

static void vdisk_exec_read(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr, loff_t loff)
{
	mm_segment_t old_fs;
	loff_t err;
	ssize_t length, full_len;
	uint8_t __user *address;
	struct scst_vdisk_dev *virt_dev =
	    (struct scst_vdisk_dev *)cmd->dev->dh_priv;
	struct file *fd = thr->fd;
	struct iovec *iv;
	int iv_count, i;

	TRACE_ENTRY();

	if (virt_dev->nullio)
		goto out;

	iv = vdisk_alloc_iv(cmd, thr);
	if (iv == NULL)
		goto out;

	iv_count = 0;
	full_len = 0;
	i = -1;
	length = scst_get_buf_first(cmd, (uint8_t __force **)&address);
	while (length > 0) {
		full_len += length;
		i++;
		iv_count++;
		iv[i].iov_base = address;
		iv[i].iov_len = length;
		length = scst_get_buf_next(cmd, (uint8_t __force **)&address);
	}
	if (unlikely(length < 0)) {
		PRINT_ERROR("scst_get_buf_() failed: %zd", length);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out_put;
	}

	old_fs = get_fs();
	set_fs(get_ds());

	TRACE_DBG("reading(iv_count %d, full_len %zd)", iv_count, full_len);
	/* SEEK */
	if (fd->f_op->llseek)
		err = fd->f_op->llseek(fd, loff, 0/*SEEK_SET*/);
	else
		err = default_llseek(fd, loff, 0/*SEEK_SET*/);
	if (err != loff) {
		PRINT_ERROR("lseek trouble %lld != %lld",
			    (long long unsigned int)err,
			    (long long unsigned int)loff);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out_set_fs;
	}

	/* READ */
	err = vfs_readv(fd, (struct iovec __force __user *)iv, iv_count,
			&fd->f_pos);

	if ((err < 0) || (err < full_len)) {
		PRINT_ERROR("readv() returned %lld from %zd",
			    (long long unsigned int)err,
			    full_len);
		if (err == -EAGAIN)
			scst_set_busy(cmd);
		else {
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_read_error));
		}
		goto out_set_fs;
	}

out_set_fs:
	set_fs(old_fs);

out_put:
	for (; i >= 0; i--)
		scst_put_buf(cmd, (void __force *)(iv[i].iov_base));

out:
	TRACE_EXIT();
	return;
}

static void vdisk_exec_write(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr, loff_t loff)
{
	mm_segment_t old_fs;
	loff_t err;
	ssize_t length, full_len;
	uint8_t __user *address;
	struct scst_vdisk_dev *virt_dev =
	    (struct scst_vdisk_dev *)cmd->dev->dh_priv;
	struct file *fd = thr->fd;
	struct iovec *iv, *eiv;
	int iv_count, eiv_count;

	TRACE_ENTRY();

	if (virt_dev->nullio)
		goto out;

	iv = vdisk_alloc_iv(cmd, thr);
	if (iv == NULL)
		goto out;

	iv_count = 0;
	full_len = 0;
	length = scst_get_buf_first(cmd, (uint8_t __force **)&address);
	while (length > 0) {
		full_len += length;
		iv[iv_count].iov_base = address;
		iv[iv_count].iov_len = length;
		iv_count++;
		length = scst_get_buf_next(cmd, (uint8_t __force **)&address);
	}
	if (unlikely(length < 0)) {
		PRINT_ERROR("scst_get_buf_() failed: %zd", length);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out_put;
	}

	old_fs = get_fs();
	set_fs(get_ds());

	eiv = iv;
	eiv_count = iv_count;
restart:
	TRACE_DBG("writing(eiv_count %d, full_len %zd)", eiv_count, full_len);

	/* SEEK */
	if (fd->f_op->llseek)
		err = fd->f_op->llseek(fd, loff, 0 /*SEEK_SET */);
	else
		err = default_llseek(fd, loff, 0 /*SEEK_SET */);
	if (err != loff) {
		PRINT_ERROR("lseek trouble %lld != %lld",
			    (long long unsigned int)err,
			    (long long unsigned int)loff);
		scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out_set_fs;
	}

	/* WRITE */
	err = vfs_writev(fd, (struct iovec __force __user *)eiv, eiv_count,
			 &fd->f_pos);

	if (err < 0) {
		PRINT_ERROR("write() returned %lld from %zd",
			    (long long unsigned int)err,
			    full_len);
		if (err == -EAGAIN)
			scst_set_busy(cmd);
		else {
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_write_error));
		}
		goto out_set_fs;
	} else if (err < full_len) {
		/*
		 * Probably that's wrong, but sometimes write() returns
		 * value less, than requested. Let's restart.
		 */
		int i, e = eiv_count;
		TRACE_MGMT_DBG("write() returned %d from %zd "
			"(iv_count=%d)", (int)err, full_len,
			eiv_count);
		if (err == 0) {
			PRINT_INFO("Suspicious: write() returned 0 from "
				"%zd (iv_count=%d)", full_len, eiv_count);
		}
		full_len -= err;
		for (i = 0; i < e; i++) {
			if ((long long)eiv->iov_len < err) {
				err -= eiv->iov_len;
				eiv++;
				eiv_count--;
			} else {
				eiv->iov_base =
					(uint8_t __force __user *)eiv->iov_base +
					err;
				eiv->iov_len -= err;
				break;
			}
		}
		goto restart;
	}

out_set_fs:
	set_fs(old_fs);

out_put:
	while (iv_count > 0) {
		scst_put_buf(cmd, (void __force *)(iv[iv_count-1].iov_base));
		iv_count--;
	}

out:
	TRACE_EXIT();
	return;
}

struct scst_blockio_work {
	atomic_t bios_inflight;
	struct scst_cmd *cmd;
};

static inline void blockio_check_finish(struct scst_blockio_work *blockio_work)
{
	/* Decrement the bios in processing, and if zero signal completion */
	if (atomic_dec_and_test(&blockio_work->bios_inflight)) {
		blockio_work->cmd->completed = 1;
		blockio_work->cmd->scst_cmd_done(blockio_work->cmd,
			SCST_CMD_STATE_DEFAULT, scst_estimate_context());
		kmem_cache_free(blockio_work_cachep, blockio_work);
	}
	return;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
static int blockio_endio(struct bio *bio, unsigned int bytes_done, int error)
#else
static void blockio_endio(struct bio *bio, int error)
#endif
{
	struct scst_blockio_work *blockio_work = bio->bi_private;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
	if (bio->bi_size)
		return 1;
#endif

	error = test_bit(BIO_UPTODATE, &bio->bi_flags) ? error : -EIO;

	if (unlikely(error != 0)) {
		PRINT_ERROR("cmd %p returned error %d", blockio_work->cmd,
			error);
		/*
		 * The race with other such bio's doesn't matter, since all
		 * scst_set_cmd_error() calls do the same local to this cmd
		 * operations.
		 */
		if (bio->bi_rw & WRITE)
			scst_set_cmd_error(blockio_work->cmd,
				SCST_LOAD_SENSE(scst_sense_write_error));
		else
			scst_set_cmd_error(blockio_work->cmd,
				SCST_LOAD_SENSE(scst_sense_read_error));
	}

	blockio_check_finish(blockio_work);

	bio_put(bio);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
	return 0;
#else
	return;
#endif
}

static void blockio_exec_rw(struct scst_cmd *cmd, struct scst_vdisk_thr *thr,
	u64 lba_start, int write)
{
	struct scst_vdisk_dev *virt_dev =
		(struct scst_vdisk_dev *)cmd->dev->dh_priv;
	struct block_device *bdev = thr->bdev;
	struct request_queue *q = bdev_get_queue(bdev);
	int length, max_nr_vecs = 0;
	uint8_t *address;
	struct bio *bio = NULL, *hbio = NULL, *tbio = NULL;
	int need_new_bio;
	struct scst_blockio_work *blockio_work;
	int bios = 0;

	TRACE_ENTRY();

	if (virt_dev->nullio)
		goto out;

	/* Allocate and initialize blockio_work struct */
	blockio_work = kmem_cache_alloc(blockio_work_cachep, GFP_KERNEL);
	if (blockio_work == NULL)
		goto out_no_mem;

	blockio_work->cmd = cmd;

	if (q)
		max_nr_vecs = min(bio_get_nr_vecs(bdev), BIO_MAX_PAGES);
	else
		max_nr_vecs = 1;

	need_new_bio = 1;

	length = scst_get_buf_first(cmd, &address);
	while (length > 0) {
		int len, bytes, off, thislen;
		uint8_t *addr;
		u64 lba_start0;

		addr = address;
		off = offset_in_page(addr);
		len = length;
		thislen = 0;
		lba_start0 = lba_start;

		while (len > 0) {
			int rc;
			struct page *page = virt_to_page(addr);

			if (need_new_bio) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
				bio = bio_kmalloc(GFP_KERNEL, max_nr_vecs);
#else
				bio = bio_alloc(GFP_KERNEL, max_nr_vecs);
#endif
				if (!bio) {
					PRINT_ERROR("Failed to create bio "
						"for data segment %d (cmd %p)",
						cmd->get_sg_buf_entry_num, cmd);
					goto out_no_bio;
				}

				bios++;
				need_new_bio = 0;
				bio->bi_end_io = blockio_endio;
				bio->bi_sector = lba_start0 <<
					(virt_dev->block_shift - 9);
				bio->bi_bdev = bdev;
				bio->bi_private = blockio_work;
#if 0 /* It could be win, but could be not, so a performance study is needed */
				bio->bi_rw |= 1 << BIO_RW_SYNC;
#endif
				if (!hbio)
					hbio = tbio = bio;
				else
					tbio = tbio->bi_next = bio;
			}

			bytes = min_t(unsigned int, len, PAGE_SIZE - off);

			rc = bio_add_page(bio, page, bytes, off);
			if (rc < bytes) {
				sBUG_ON(rc != 0);
				need_new_bio = 1;
				lba_start0 += thislen >> virt_dev->block_shift;
				thislen = 0;
				continue;
			}

			addr += PAGE_SIZE;
			thislen += bytes;
			len -= bytes;
			off = 0;
		}

		lba_start += length >> virt_dev->block_shift;

		scst_put_buf(cmd, address);
		length = scst_get_buf_next(cmd, &address);
	}

	/* +1 to prevent erroneous too early command completion */
	atomic_set(&blockio_work->bios_inflight, bios+1);

	while (hbio) {
		bio = hbio;
		hbio = hbio->bi_next;
		bio->bi_next = NULL;
		submit_bio(write, bio);
	}

	if (q && q->unplug_fn)
		q->unplug_fn(q);

	blockio_check_finish(blockio_work);

out:
	TRACE_EXIT();
	return;

out_no_bio:
	while (hbio) {
		bio = hbio;
		hbio = hbio->bi_next;
		bio_put(bio);
	}
	kmem_cache_free(blockio_work_cachep, blockio_work);

out_no_mem:
	scst_set_busy(cmd);
	goto out;
}

static void vdisk_exec_verify(struct scst_cmd *cmd,
	struct scst_vdisk_thr *thr, loff_t loff)
{
	mm_segment_t old_fs;
	loff_t err;
	ssize_t length, len_mem = 0;
	uint8_t *address_sav, *address;
	int compare;
	struct scst_vdisk_dev *virt_dev =
	    (struct scst_vdisk_dev *)cmd->dev->dh_priv;
	struct file *fd = thr->fd;
	uint8_t *mem_verify = NULL;

	TRACE_ENTRY();

	if (vdisk_fsync(thr, loff, cmd->bufflen, cmd, cmd->dev) != 0)
		goto out;

	/*
	 * Until the cache is cleared prior the verifying, there is not
	 * much point in this code. ToDo.
	 *
	 * Nevertherless, this code is valuable if the data have not read
	 * from the file/disk yet.
	 */

	/* SEEK */
	old_fs = get_fs();
	set_fs(get_ds());

	if (!virt_dev->nullio) {
		if (fd->f_op->llseek)
			err = fd->f_op->llseek(fd, loff, 0/*SEEK_SET*/);
		else
			err = default_llseek(fd, loff, 0/*SEEK_SET*/);
		if (err != loff) {
			PRINT_ERROR("lseek trouble %lld != %lld",
				    (long long unsigned int)err,
				    (long long unsigned int)loff);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_hardw_error));
			goto out_set_fs;
		}
	}

	mem_verify = vmalloc(LEN_MEM);
	if (mem_verify == NULL) {
		PRINT_ERROR("Unable to allocate memory %d for verify",
			       LEN_MEM);
		scst_set_cmd_error(cmd,
				   SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out_set_fs;
	}

	length = scst_get_buf_first(cmd, &address);
	address_sav = address;
	if (!length && cmd->data_len) {
		length = cmd->data_len;
		compare = 0;
	} else
		compare = 1;

	while (length > 0) {
		len_mem = (length > LEN_MEM) ? LEN_MEM : length;
		TRACE_DBG("Verify: length %zd - len_mem %zd", length, len_mem);

		if (!virt_dev->nullio)
			err = vfs_read(fd, (char __force __user *)mem_verify,
				len_mem, &fd->f_pos);
		else
			err = len_mem;
		if ((err < 0) || (err < len_mem)) {
			PRINT_ERROR("verify() returned %lld from %zd",
				    (long long unsigned int)err, len_mem);
			if (err == -EAGAIN)
				scst_set_busy(cmd);
			else {
				scst_set_cmd_error(cmd,
				    SCST_LOAD_SENSE(scst_sense_read_error));
			}
			if (compare)
				scst_put_buf(cmd, address_sav);
			goto out_set_fs;
		}
		if (compare && memcmp(address, mem_verify, len_mem) != 0) {
			TRACE_DBG("Verify: error memcmp length %zd", length);
			scst_set_cmd_error(cmd,
			    SCST_LOAD_SENSE(scst_sense_miscompare_error));
			scst_put_buf(cmd, address_sav);
			goto out_set_fs;
		}
		length -= len_mem;
		address += len_mem;
		if (compare && length <= 0) {
			scst_put_buf(cmd, address_sav);
			length = scst_get_buf_next(cmd, &address);
			address_sav = address;
		}
	}

	if (length < 0) {
		PRINT_ERROR("scst_get_buf_() failed: %zd", length);
		scst_set_cmd_error(cmd,
		    SCST_LOAD_SENSE(scst_sense_hardw_error));
	}

out_set_fs:
	set_fs(old_fs);
	if (mem_verify)
		vfree(mem_verify);

out:
	TRACE_EXIT();
	return;
}

static int vdisk_task_mgmt_fn(struct scst_mgmt_cmd *mcmd,
	struct scst_tgt_dev *tgt_dev)
{
	TRACE_ENTRY();

	if ((mcmd->fn == SCST_LUN_RESET) || (mcmd->fn == SCST_TARGET_RESET)) {
		/* Restore default values */
		struct scst_device *dev = tgt_dev->dev;
		struct scst_vdisk_dev *virt_dev =
			(struct scst_vdisk_dev *)dev->dh_priv;

		dev->tst = DEF_TST;
		dev->d_sense = DEF_DSENSE;
		if (virt_dev->wt_flag && !virt_dev->nv_cache)
			dev->queue_alg = DEF_QUEUE_ALG_WT;
		else
			dev->queue_alg = DEF_QUEUE_ALG;
		dev->swp = DEF_SWP;
		dev->tas = DEF_TAS;

		virt_dev->prevent_allow_medium_removal = 0;
	}

	TRACE_EXIT();
	return SCST_DEV_TM_NOT_COMPLETED;
}

static void vdisk_report_registering(const struct scst_vdisk_dev *virt_dev)
{
	char buf[128];
	int i, j;

	i = snprintf(buf, sizeof(buf), "Registering virtual %s device %s ",
		virt_dev->vdt->vdt_name, virt_dev->name);
	j = i;

	if (virt_dev->wt_flag)
		i += snprintf(&buf[i], sizeof(buf) - i, "(WRITE_THROUGH");

	if (virt_dev->nv_cache)
		i += snprintf(&buf[i], sizeof(buf) - i, "%sNV_CACHE",
			(j == i) ? "(" : ", ");

	if (virt_dev->rd_only)
		i += snprintf(&buf[i], sizeof(buf) - i, "%sREAD_ONLY",
			(j == i) ? "(" : ", ");

	if (virt_dev->o_direct_flag)
		i += snprintf(&buf[i], sizeof(buf) - i, "%sO_DIRECT",
			(j == i) ? "(" : ", ");

	if (virt_dev->nullio)
		i += snprintf(&buf[i], sizeof(buf) - i, "%sNULLIO",
			(j == i) ? "(" : ", ");

	if (virt_dev->blockio)
		i += snprintf(&buf[i], sizeof(buf) - i, "%sBLOCKIO",
			(j == i) ? "(" : ", ");

	if (virt_dev->removable)
		i += snprintf(&buf[i], sizeof(buf) - i, "%sREMOVABLE",
			(j == i) ? "(" : ", ");

	if (j == i)
		PRINT_INFO("%s", buf);
	else
		PRINT_INFO("%s)", buf);

	return;
}

static int vdisk_resync_size(struct scst_vdisk_dev *virt_dev)
{
	loff_t file_size;
	int res = 0;

	/*
	 * There's no need in any lock here, because SCST core serializes
	 * all device sysfs calls.
	 */

	if (!virt_dev->nullio) {
		res = vdisk_get_file_size(virt_dev->file_name,
				virt_dev->blockio, &file_size);
		if (res != 0)
			goto out;
	} else
		file_size = VDISK_NULLIO_SIZE;

	if (file_size == virt_dev->file_size) {
		PRINT_INFO("Size of virtual disk %s remained the same",
			virt_dev->name);
		goto out;
	}

	res = scst_suspend_activity(true);
	if (res != 0)
		goto out;

	virt_dev->file_size = file_size;
	virt_dev->nblocks = virt_dev->file_size >> virt_dev->block_shift;

	scst_dev_del_all_thr_data(virt_dev->dev);

	PRINT_INFO("New size of SCSI target virtual disk %s "
		"(fs=%lldMB, bs=%d, nblocks=%lld, cyln=%lld%s)",
		virt_dev->name, virt_dev->file_size >> 20,
		virt_dev->block_size,
		(long long unsigned int)virt_dev->nblocks,
		(long long unsigned int)virt_dev->nblocks/64/32,
		virt_dev->nblocks < 64*32 ? " !WARNING! cyln less "
						"than 1" : "");

	scst_capacity_data_changed(virt_dev->dev);

	scst_resume_activity();

out:
	return res;
}

static void vdev_init(struct vdev_type *vdt, struct scst_vdisk_dev *virt_dev)
{
	memset(virt_dev, 0, sizeof(*virt_dev));
	spin_lock_init(&virt_dev->flags_lock);
	virt_dev->vdt = vdt;

	virt_dev->block_size = DEF_DISK_BLOCKSIZE;
	virt_dev->block_shift = DEF_DISK_BLOCKSIZE_SHIFT;

	return;
}

static struct scst_vdisk_dev *vdev_create(struct vdev_type *vdt)
{
	struct scst_vdisk_dev *virt_dev;

	virt_dev = kmalloc(sizeof(*virt_dev), GFP_KERNEL);
	if (virt_dev == NULL) {
		PRINT_ERROR("Allocation of virtual device %s failed",
			vdt->vdt_name);
		goto out;
	}

	vdt->vfns.vdev_init(vdt, virt_dev);

out:
	return virt_dev;
}

static void vdev_deinit(struct scst_vdisk_dev *virt_dev)
{
	kfree(virt_dev->file_name);
	return;
}

static void vdev_destroy(struct scst_vdisk_dev *virt_dev)
{
	virt_dev->vdt->vfns.vdev_deinit(virt_dev);
	kfree(virt_dev);
	return;
}

static int vdisk_fileio_pre_register(struct scst_vdisk_dev *virt_dev)
{
	int res = 0;

	if ((virt_dev->file_name == NULL) ||
	    (strcmp(virt_dev->file_name, VDEV_NONE_FILENAME) == 0)) {
		PRINT_ERROR("%s", "File name required");
		res = -EINVAL;
		goto out;
	}

	if (virt_dev->rd_only && (virt_dev->wt_flag || virt_dev->nv_cache)) {
		PRINT_ERROR("Write options on read only device %s",
			virt_dev->name);
		res = -EINVAL;
		goto out;
	}

out:
	return res;
}

static int vdisk_blockio_pre_register(struct scst_vdisk_dev *virt_dev)
{
	int res = 0;

	if ((virt_dev->file_name == NULL) ||
	    (strcmp(virt_dev->file_name, VDEV_NONE_FILENAME) == 0)) {
		PRINT_ERROR("%s", "File name required");
		res = -EINVAL;
		goto out;
	}

out:
	return res;
}

static void vdisk_blockio_init(struct vdev_type *vdt,
	struct scst_vdisk_dev *virt_dev)
{
	struct vdisk_blockio_type *v;

	v = container_of(vdt, struct vdisk_blockio_type, parent_vdt);

	v->parent_vdt_vfns.vdev_init(vdt, virt_dev);

	virt_dev->blockio = 1;
	return;
}

static void vdisk_nullio_init(struct vdev_type *vdt,
	struct scst_vdisk_dev *virt_dev)
{
	struct vdisk_nullio_type *v;

	v = container_of(vdt, struct vdisk_nullio_type, parent_vdt);

	v->parent_vdt_vfns.vdev_init(vdt, virt_dev);

	virt_dev->nullio = 1;
	return;
}

static int vdisk_parse_option(struct scst_vdisk_dev *virt_dev, char *p)
{
	int res = -EINVAL;

	TRACE_ENTRY();

	if (!strncmp("READ_ONLY", p, 9)) {
		res = 9;
		virt_dev->rd_only = 1;
		TRACE_DBG("%s", "READ_ONLY");
	} else if (!strncmp("REMOVABLE", p, 9)) {
		res = 9;
		virt_dev->removable = 1;
		TRACE_DBG("%s", "REMOVABLE");
	}

	TRACE_EXIT_RES(res);
	return res;
}

static int vdisk_fileio_parse_option(struct scst_vdisk_dev *virt_dev, char *p)
{
	int res;

	TRACE_ENTRY();

	res = vdisk_parse_option(virt_dev, p);
	if (res >= 0)
		goto out;

	if (!strncmp("WRITE_THROUGH", p, 13)) {
		res = 13;
		virt_dev->wt_flag = 1;
		TRACE_DBG("%s", "WRITE_THROUGH");
	} else if (!strncmp("NV_CACHE", p, 8)) {
		res = 8;
		virt_dev->nv_cache = 1;
		TRACE_DBG("%s", "NON-VOLATILE CACHE");
	} else if (!strncmp("O_DIRECT", p, 8)) {
		res = 8;
#if 0
		virt_dev->o_direct_flag = 1;
		TRACE_DBG("%s", "O_DIRECT");
#else
		PRINT_INFO("%s flag doesn't currently"
			" work, ignoring it, use fileio_tgt "
			"in O_DIRECT mode instead", "O_DIRECT");
#endif
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* scst_vdisk_mutex supposed to be held */
static int vdev_open(struct vdev_type *vdt, char *p, const char *name)
{
	int res = 0;
	char *file_name;
	struct scst_vdisk_dev *virt_dev;
	size_t len;

	TRACE_ENTRY();

	virt_dev = vdt->vfns.vdev_find(name);
	if (virt_dev != NULL) {
		PRINT_ERROR("Virtual device with name %s already exist", name);
		res = -EINVAL;
		goto out;
	}

	while (isspace(*p) && *p != '\0')
		p++;
	file_name = p;
	if ((*file_name == '/') || (strcmp(file_name, VDEV_NONE_FILENAME) == 0)) {
		while (!isspace(*p) && *p != '\0')
			p++;
		*p++ = '\0';

		TRACE_DBG("file name %s", file_name);

		while (isspace(*p) && *p != '\0')
			p++;
	} else {
		TRACE_DBG("file name %s", "not specified");
		file_name = NULL;
	}

	virt_dev = vdt->vfns.vdev_create(vdt);
	if (virt_dev == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "Creation of virt_dev %s failed", name);
		res = -ENOMEM;
		goto out;
	}

	if (isdigit(*p)) {
		uint32_t block_size;
		int block_shift;
		char *pp;

		block_size = simple_strtoul(p, &pp, 0);
		p = pp;
		if ((*p != '\0') && !isspace(*p)) {
			PRINT_ERROR("Parse error: \"%s\"", p);
			res = -EINVAL;
			goto out_free_vdev;
		}
		while (isspace(*p) && *p != '\0')
			p++;

		block_shift = scst_calc_block_shift(block_size);
		if (block_shift < 9) {
			res = -EINVAL;
			goto out_free_vdev;
		}

		TRACE_DBG("block_size %d, block_shift %d", block_size,
			block_shift);

		virt_dev->block_size = block_size;
		virt_dev->block_shift = block_shift;
	}

	while (*p != '\0') {
		while (isspace(*p) && *p != '\0')
			p++;

		if (vdt->vfns.parse_option != NULL)
			res = vdt->vfns.parse_option(virt_dev, p);
		else
			res = -EINVAL;

		if (res < 0) {
			PRINT_ERROR("Unknown option \"%s\"", p);
			goto out_free_vdev;
		} else if (res == 0)
			break;

		p += res;

		if (!isspace(*p) && (*p != '\0')) {
			PRINT_ERROR("Syntax error on %s", p);
			goto out_free_vdev;
		}
	}

	strcpy(virt_dev->name, name);

	scnprintf(virt_dev->usn, sizeof(virt_dev->usn), "%llx",
			vdisk_gen_dev_id_num(virt_dev));
	TRACE_DBG("usn %s", virt_dev->usn);

	if (file_name != NULL) {
		len = strlen(file_name) + 1;
		virt_dev->file_name = kmalloc(len, GFP_KERNEL);
		if (virt_dev->file_name == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "Allocation of file_name %s "
				"failed", file_name);
			res = -ENOMEM;
			goto out_free_vdev;
		}
		strncpy(virt_dev->file_name, file_name, len);
	}

	if (vdt->vfns.pre_register != NULL) {
		res = vdt->vfns.pre_register(virt_dev);
		if (res != 0)
			goto out_free_vpath;
	}

	vdt->vfns.vdev_add(virt_dev);

	vdisk_report_registering(virt_dev);
	virt_dev->virt_id = scst_register_virtual_device(vdt->vdt_devt,
						 virt_dev->name);
	if (virt_dev->virt_id < 0) {
		res = virt_dev->virt_id;
		goto out_del;
	}

	TRACE_DBG("Added virt_dev (name %s, file name %s, id %d, block size "
		"%d) to vdisk_dev_list", virt_dev->name, virt_dev->file_name,
		virt_dev->virt_id, virt_dev->block_size);

out:
	TRACE_EXIT_RES(res);
	return res;

out_del:
	vdt->vfns.vdev_del(virt_dev);

out_free_vpath:
	kfree(virt_dev->file_name);

out_free_vdev:
	kfree(virt_dev);
	goto out;
}

/* scst_vdisk_mutex supposed to be held */
static int vdev_close(struct vdev_type *vdt, const char *name)
{
	int res = 0;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	virt_dev = vdt->vfns.vdev_find(name);
	if (virt_dev == NULL) {
		PRINT_ERROR("Device %s not found", name);
		res = -EINVAL;
		goto out;
	}

	scst_unregister_virtual_device(virt_dev->virt_id);

	PRINT_INFO("Virtual device %s unregistered", virt_dev->name);
	TRACE_DBG("virt_id %d unregister", virt_dev->virt_id);

	vdt->vfns.vdev_del(virt_dev);
	vdt->vfns.vdev_destroy(virt_dev);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* scst_vdisk_mutex supposed to be held */
static void vdev_del(struct scst_vdisk_dev *virt_dev)
{
	TRACE_ENTRY();

	list_del(&virt_dev->vdisk_dev_list_entry);

	TRACE_EXIT();
	return;
}

/* scst_vdisk_mutex supposed to be held */
static void vdisk_add(struct scst_vdisk_dev *virt_dev)
{
	TRACE_ENTRY();

	list_add_tail(&virt_dev->vdisk_dev_list_entry, &vdisk_dev_list);

	TRACE_EXIT();
	return;
}

/* scst_vdisk_mutex supposed to be held */
static struct scst_vdisk_dev *vdisk_find(const char *name)
{
	struct scst_vdisk_dev *res, *vv;

	TRACE_ENTRY();

	res = NULL;
	list_for_each_entry(vv, &vdisk_dev_list, vdisk_dev_list_entry) {
		if (strcmp(vv->name, name) == 0) {
			res = vv;
			break;
		}
	}

	TRACE_EXIT_HRES((unsigned long)res);
	return res;
}

/* scst_vdisk_mutex supposed to be held */
static void vcdrom_add(struct scst_vdisk_dev *virt_dev)
{
	TRACE_ENTRY();

	list_add_tail(&virt_dev->vdisk_dev_list_entry, &vcdrom_dev_list);

	TRACE_EXIT();
	return;
}

/* scst_vdisk_mutex supposed to be held */
static struct scst_vdisk_dev *vcdrom_find(const char *name)
{
	struct scst_vdisk_dev *res, *vv;

	TRACE_ENTRY();

	res = NULL;
	list_for_each_entry(vv, &vcdrom_dev_list, vdisk_dev_list_entry) {
		if (strcmp(vv->name, name) == 0) {
			res = vv;
			break;
		}
	}

	TRACE_EXIT_HRES((unsigned long)res);
	return res;
}

static void vcdrom_init(struct vdev_type *vdt,
	struct scst_vdisk_dev *virt_dev)
{
	struct vcdrom_type *vt;

	vt = container_of(vdt, struct vcdrom_type, parent_vdt);

	vt->parent_vdt_vfns.vdev_init(vdt, virt_dev);

	virt_dev->rd_only = 1;
	virt_dev->removable = 1;

	virt_dev->block_size = DEF_CDROM_BLOCKSIZE;
	virt_dev->block_shift = DEF_CDROM_BLOCKSIZE_SHIFT;

	return;
}

static int vcdrom_pre_register(struct scst_vdisk_dev *virt_dev)
{
	int res = 0;

	if ((virt_dev->file_name == NULL) ||
	    (strcmp(virt_dev->file_name, VDEV_NONE_FILENAME) == 0))
		virt_dev->cdrom_empty = 1;

	if (virt_dev->block_size != DEF_CDROM_BLOCKSIZE) {
		PRINT_WARNING("Block size %d for vortual device %s ignored",
			virt_dev->block_size, virt_dev->name);
		virt_dev->block_size = DEF_CDROM_BLOCKSIZE;
		virt_dev->block_shift = DEF_CDROM_BLOCKSIZE_SHIFT;
	}

	return res;
}

static int vcdrom_change(struct scst_vdisk_dev *virt_dev,
	const char *buffer, int length)
{
	loff_t err;
	char *old_fn, *i_buf, *p, *pp;
	const char *file_name = NULL;
	int res = 0;

	TRACE_ENTRY();

	/*
	 * There's no need in any lock here, because SCST core serializes
	 * all device sysfs calls.
	 */

	i_buf = kmalloc(length+1, GFP_KERNEL);
	if (i_buf == NULL) {
		PRINT_ERROR("Unable to alloc intermediate buffer with size %d",
			length+1);
		res = -ENOMEM;
		goto out;
	}

	memcpy(i_buf, buffer, length);
	i_buf[length] = '\0';
	p = i_buf;

	while (isspace(*p) && *p != '\0')
		p++;
	file_name = p;
	p = &i_buf[length-1];
	pp = p;
	while (isspace(*p) && *p != '\0') {
		pp = p;
		p--;
	}
	*pp = '\0';

	res = scst_suspend_activity(true);
	if (res != 0)
		goto out;

	/* To sync with detach*() functions */
	mutex_lock(&scst_mutex);

	if (*file_name == '\0') {
		virt_dev->cdrom_empty = 1;
		TRACE_DBG("%s", "No media");
	} else if (*file_name != '/') {
		PRINT_ERROR("File path \"%s\" is not "
			"absolute", file_name);
		res = -EINVAL;
		goto out_unlock;
	} else
		virt_dev->cdrom_empty = 0;

	old_fn = virt_dev->file_name;

	if (!virt_dev->cdrom_empty) {
		int len = strlen(file_name) + 1;
		char *fn = kmalloc(len, GFP_KERNEL);
		if (fn == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "%s",
				"Allocation of file_name failed");
			res = -ENOMEM;
			goto out_unlock;
		}

		strncpy(fn, file_name, len);
		virt_dev->file_name = fn;

		res = vdisk_get_file_size(virt_dev->file_name,
				virt_dev->blockio, &err);
		if (res != 0)
			goto out_free;
	} else {
		err = 0;
		virt_dev->file_name = NULL;
	}

	if (virt_dev->prevent_allow_medium_removal) {
		PRINT_ERROR("Prevent medium removal for "
			"virtual device with name %s", virt_dev->name);
		res = -EINVAL;
		goto out_free;
	}

	virt_dev->file_size = err;
	virt_dev->nblocks = virt_dev->file_size >> virt_dev->block_shift;
	if (!virt_dev->cdrom_empty)
		virt_dev->media_changed = 1;

	mutex_unlock(&scst_mutex);

	scst_dev_del_all_thr_data(virt_dev->dev);

	if (!virt_dev->cdrom_empty) {
		PRINT_INFO("Changed SCSI target virtual cdrom %s "
			"(file=\"%s\", fs=%lldMB, bs=%d, nblocks=%lld,"
			" cyln=%lld%s)", virt_dev->name, virt_dev->file_name,
			virt_dev->file_size >> 20, virt_dev->block_size,
			(long long unsigned int)virt_dev->nblocks,
			(long long unsigned int)virt_dev->nblocks/64/32,
			virt_dev->nblocks < 64*32 ? " !WARNING! cyln less "
							"than 1" : "");
	} else {
		PRINT_INFO("Removed media from SCSI target virtual cdrom %s",
			virt_dev->name);
	}

	kfree(old_fn);

out_resume:
	scst_resume_activity();

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	kfree(virt_dev->file_name);
	virt_dev->file_name = old_fn;

out_unlock:
	mutex_unlock(&scst_mutex);
	goto out_resume;
}

#ifndef CONFIG_SCST_PROC

static ssize_t vcdrom_sysfs_filename_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = (struct scst_vdisk_dev *)dev->dh_priv;

	res = vcdrom_change(virt_dev, buf, count);
	if (res != 0)
		goto out;

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int vdisk_mgmt_cmd(const char *buffer, int length,
	struct vdev_type *vdt)
{
	int res = 0, action;
	char *p, *name, *i_buf;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	if ((length == 0) || (buffer == NULL) || (buffer[0] == '\0'))
		goto out;

	i_buf = kmalloc(length+1, GFP_KERNEL);
	if (i_buf == NULL) {
		PRINT_ERROR("Unable to alloc intermediate buffer with size %d",
			length+1);
		res = -ENOMEM;
		goto out;
	}

	memcpy(i_buf, buffer, length);
	i_buf[length] = '\0';

	if (mutex_lock_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out_free;
	}

	p = i_buf;
	if (p[strlen(p) - 1] == '\n')
		p[strlen(p) - 1] = '\0';
	if (!strncmp("open", p, 4)) {
		p += 4;
		action = VDEV_ACTION_OPEN;
	} else if (!strncmp("close", p, 5)) {
		p += 5;
		action = VDEV_ACTION_CLOSE;
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out_up;
	}

	if (!isspace(*p)) {
		PRINT_ERROR("Syntax error on %s", p);
		res = -EINVAL;
		goto out_up;
	}

	while (isspace(*p) && *p != '\0')
		p++;
	name = p;
	while (!isspace(*p) && *p != '\0')
		p++;
	*p++ = '\0';
	if (*name == '\0') {
		PRINT_ERROR("%s", "Name required");
		res = -EINVAL;
		goto out_up;
	} else if (strlen(name) >= sizeof(virt_dev->name)) {
		PRINT_ERROR("Name is too long (max %zd "
			"characters)", sizeof(virt_dev->name)-1);
		res = -EINVAL;
		goto out_up;
	}

	if (action == VDEV_ACTION_OPEN) {
		res = vdt->vfns.vdev_open(vdt, p, name);
		if (res != 0)
			goto out_up;
	} else if (action == VDEV_ACTION_CLOSE) {
		res = vdt->vfns.vdev_close(vdt, name);
		if (res != 0)
			goto out_up;
	} else
		sBUG();

	res = length;

out_up:
	mutex_unlock(&scst_vdisk_mutex);

out_free:
	kfree(i_buf);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t vdisk_mgmt_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct scst_dev_type *devt;
	struct vdev_type *vdt;

	devt = container_of(kobj, struct scst_dev_type, devt_kobj);
	vdt = (struct vdev_type *)devt->devt_priv;

	return scnprintf(buf, SCST_SYSFS_BLOCK_SIZE, vdt->help_string);
}

static ssize_t vdisk_mgmt_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct scst_dev_type *devt;
	int res = count;

	devt = container_of(kobj, struct scst_dev_type, devt_kobj);

	res = vdisk_mgmt_cmd(buf, count, (struct vdev_type *)devt->devt_priv);

	return res;
}

static ssize_t vdisk_sysfs_size_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = (struct scst_vdisk_dev *)dev->dh_priv;

	pos = sprintf(buf, "%lld\n", virt_dev->file_size);

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdisk_sysfs_blocksize_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = (struct scst_vdisk_dev *)dev->dh_priv;

	pos = sprintf(buf, "%d\n", (int)virt_dev->block_size);

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdisk_sysfs_rd_only_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = (struct scst_vdisk_dev *)dev->dh_priv;

	pos = sprintf(buf, "%d\n", virt_dev->rd_only ? 1 : 0);

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdisk_sysfs_wt_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = (struct scst_vdisk_dev *)dev->dh_priv;

	pos = sprintf(buf, "%d\n", virt_dev->wt_flag ? 1 : 0);

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdisk_sysfs_nv_cache_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = (struct scst_vdisk_dev *)dev->dh_priv;

	pos = sprintf(buf, "%d\n", virt_dev->nv_cache ? 1 : 0);

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdisk_sysfs_o_direct_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = (struct scst_vdisk_dev *)dev->dh_priv;

	pos = sprintf(buf, "%d\n", virt_dev->o_direct_flag ? 1 : 0);

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdisk_sysfs_removable_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = (struct scst_vdisk_dev *)dev->dh_priv;

	pos = sprintf(buf, "%d\n", virt_dev->removable ? 1 : 0);

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdisk_sysfs_filename_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	int pos = 0;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = (struct scst_vdisk_dev *)dev->dh_priv;

	pos = sprintf(buf, "%s\n", virt_dev->file_name);

	TRACE_EXIT_RES(pos);
	return pos;
}

static ssize_t vdisk_sysfs_resync_size_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res;
	struct scst_device *dev;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	dev = container_of(kobj, struct scst_device, dev_kobj);
	virt_dev = (struct scst_vdisk_dev *)dev->dh_priv;

	res = vdisk_resync_size(virt_dev);
	if (res != 0)
		goto out;

	res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

#else /* CONFIG_SCST_PROC */

/*
 * ProcFS
 */

/*
 * Called when a file in the /proc/VDISK_NAME/VDISK_NAME is read
 */
static int vdisk_read_proc(struct seq_file *seq, struct scst_dev_type *dev_type)
{
	int res = 0;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	if (mutex_lock_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	seq_printf(seq, "%-17s %-11s %-11s %-15s %s\n",
		   "Name", "Size(MB)", "Block size", "Options", "File name");

	list_for_each_entry(virt_dev, &vdisk_dev_list, vdisk_dev_list_entry) {
		int c;
		seq_printf(seq, "%-17s %-11d %-12d", virt_dev->name,
			(uint32_t)(virt_dev->file_size >> 20),
			virt_dev->block_size);
		c = 0;
		if (virt_dev->wt_flag) {
			seq_printf(seq, "WT ");
			c += 3;
		}
		if (virt_dev->nv_cache) {
			seq_printf(seq, "NV ");
			c += 3;
		}
		if (virt_dev->dev != NULL) {
			if (virt_dev->dev->rd_only) {
				seq_printf(seq, "RO ");
				c += 3;
			}
		} else if (virt_dev->rd_only) {
			seq_printf(seq, "RO ");
			c += 3;
		}
		if (virt_dev->o_direct_flag) {
			seq_printf(seq, "DR ");
			c += 3;
		}
		if (virt_dev->nullio) {
			seq_printf(seq, "NIO ");
			c += 4;
		}
		if (virt_dev->blockio) {
			seq_printf(seq, "BIO ");
			c += 4;
		}
		if (virt_dev->removable) {
			seq_printf(seq, "RM ");
			c += 4;
		}
		while (c < 16) {
			seq_printf(seq, " ");
			c++;
		}
		seq_printf(seq, "%s\n", virt_dev->file_name);
	}
	mutex_unlock(&scst_vdisk_mutex);
out:
	TRACE_EXIT_RES(res);
	return res;
}

static int vdisk_proc_mgmt_cmd(const char *buffer, int length,
			       struct scst_dev_type *dev_type)
{
	int res = 0, action;
	char *p, *name, *file_name, *i_buf;
	struct scst_vdisk_dev *virt_dev, *vv;
	uint32_t block_size = DEF_DISK_BLOCKSIZE;
	int block_shift = DEF_DISK_BLOCKSIZE_SHIFT;
	size_t len;

	TRACE_ENTRY();

	if ((length == 0) || (buffer == NULL) || (buffer[0] == '\0'))
		goto out;

	i_buf = kmalloc(length+1, GFP_KERNEL);
	if (i_buf == NULL) {
		PRINT_ERROR("Unable to alloc intermediate buffer with size %d",
			length+1);
		res = -ENOMEM;
		goto out;
	}

	memcpy(i_buf, buffer, length);
	i_buf[length] = '\0';

	if (mutex_lock_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out_free;
	}

	p = i_buf;
	if (p[strlen(p) - 1] == '\n')
		p[strlen(p) - 1] = '\0';
	if (!strncmp("close ", p, 6)) {
		p += 6;
		action = 0;
	} else if (!strncmp("open ", p, 5)) {
		p += 5;
		action = 1;
	} else if (!strncmp("resync_size ", p, 12)) {
		p += 12;
		action = 2;
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out_up;
	}

	while (isspace(*p) && *p != '\0')
		p++;
	name = p;
	while (!isspace(*p) && *p != '\0')
		p++;
	*p++ = '\0';
	if (*name == '\0') {
		PRINT_ERROR("%s", "Name required");
		res = -EINVAL;
		goto out_up;
	} else if (strlen(name) >= sizeof(virt_dev->name)) {
		PRINT_ERROR("Name is too long (max %zd "
			"characters)", sizeof(virt_dev->name)-1);
		res = -EINVAL;
		goto out_up;
	}

	if (action == 1) {
		/* open */
		virt_dev = NULL;
		list_for_each_entry(vv, &vdisk_dev_list,
					vdisk_dev_list_entry) {
			if (strcmp(vv->name, name) == 0) {
				virt_dev = vv;
				break;
			}
		}
		if (virt_dev) {
			PRINT_ERROR("Virtual device with name "
				   "%s already exist", name);
			res = -EINVAL;
			goto out_up;
		}

		while (isspace(*p) && *p != '\0')
			p++;
		file_name = p;
		while (!isspace(*p) && *p != '\0')
			p++;
		*p++ = '\0';
		if (*file_name == '\0') {
			PRINT_ERROR("%s", "File name required");
			res = -EINVAL;
			goto out_up;
		}

		/* It's going to be removed code, anyway */
		virt_dev = kzalloc(sizeof(*virt_dev), GFP_KERNEL);
		if (virt_dev == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "%s",
				  "Allocation of virt_dev failed");
			res = -ENOMEM;
			goto out_up;
		}
		spin_lock_init(&virt_dev->flags_lock);
		virt_dev->vdt = &fileio_type.parent_vdt;

		while (isspace(*p) && *p != '\0')
			p++;

		if (isdigit(*p)) {
			char *pp;
			block_size = simple_strtoul(p, &pp, 0);
			p = pp;
			if ((*p != '\0') && !isspace(*p)) {
				PRINT_ERROR("Parse error: \"%s\"", p);
				res = -EINVAL;
				goto out_free_vdev;
			}
			while (isspace(*p) && *p != '\0')
				p++;

			block_shift = scst_calc_block_shift(block_size);
			if (block_shift < 9) {
				res = -EINVAL;
				goto out_free_vdev;
			}
		}
		virt_dev->block_size = block_size;
		virt_dev->block_shift = block_shift;

		while (*p != '\0') {
			if (!strncmp("WRITE_THROUGH", p, 13)) {
				p += 13;
				virt_dev->wt_flag = 1;
				TRACE_DBG("%s", "WRITE_THROUGH");
			} else if (!strncmp("NV_CACHE", p, 8)) {
				p += 8;
				virt_dev->nv_cache = 1;
				TRACE_DBG("%s", "NON-VOLATILE CACHE");
			} else if (!strncmp("READ_ONLY", p, 9)) {
				p += 9;
				virt_dev->rd_only = 1;
				TRACE_DBG("%s", "READ_ONLY");
			} else if (!strncmp("O_DIRECT", p, 8)) {
				p += 8;
#if 0

				virt_dev->o_direct_flag = 1;
				TRACE_DBG("%s", "O_DIRECT");
#else
				PRINT_INFO("%s flag doesn't currently"
					" work, ignoring it, use fileio_tgt "
					"in O_DIRECT mode instead", "O_DIRECT");
#endif
			} else if (!strncmp("NULLIO", p, 6)) {
				p += 6;
				virt_dev->nullio = 1;
				virt_dev->vdt = &nullio_type.parent_vdt;
				TRACE_DBG("%s", "NULLIO");
			} else if (!strncmp("BLOCKIO", p, 7)) {
				p += 7;
				virt_dev->blockio = 1;
				virt_dev->vdt = &blockio_type.parent_vdt;
				TRACE_DBG("%s", "BLOCKIO");
			} else if (!strncmp("REMOVABLE", p, 9)) {
				p += 9;
				virt_dev->removable = 1;
				TRACE_DBG("%s", "REMOVABLE");
			} else {
				PRINT_ERROR("Unknown flag \"%s\"", p);
				res = -EINVAL;
				goto out_free_vdev;
			}
			while (isspace(*p) && *p != '\0')
				p++;
		}

		if (!virt_dev->nullio && (*file_name != '/')) {
			PRINT_ERROR("File path \"%s\" is not "
				"absolute", file_name);
			res = -EINVAL;
			goto out_up;
		}

		strcpy(virt_dev->name, name);

		scnprintf(virt_dev->usn, sizeof(virt_dev->usn), "%llx",
				vdisk_gen_dev_id_num(virt_dev));
		TRACE_DBG("usn %s", virt_dev->usn);

		len = strlen(file_name) + 1;
		virt_dev->file_name = kmalloc(len, GFP_KERNEL);
		if (virt_dev->file_name == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "%s",
				  "Allocation of file_name failed");
			res = -ENOMEM;
			goto out_free_vdev;
		}
		strncpy(virt_dev->file_name, file_name, len);

		list_add_tail(&virt_dev->vdisk_dev_list_entry,
				  &vdisk_dev_list);

		vdisk_report_registering(virt_dev);
		virt_dev->virt_id = scst_register_virtual_device(
			virt_dev->vdt->vdt_devt, virt_dev->name);
		if (virt_dev->virt_id < 0) {
			res = virt_dev->virt_id;
			goto out_free_vpath;
		}
		TRACE_DBG("Added virt_dev (name %s, file name %s, "
			"id %d, block size %d) to "
			"vdisk_dev_list", virt_dev->name,
			virt_dev->file_name, virt_dev->virt_id,
			virt_dev->block_size);
	} else if (action == 0) {	/* close */
		virt_dev = NULL;
		list_for_each_entry(vv, &vdisk_dev_list,
					vdisk_dev_list_entry) {
			if (strcmp(vv->name, name) == 0) {
				virt_dev = vv;
				break;
			}
		}
		if (virt_dev == NULL) {
			PRINT_ERROR("Device %s not found", name);
			res = -EINVAL;
			goto out_up;
		}
		scst_unregister_virtual_device(virt_dev->virt_id);
		PRINT_INFO("Virtual device %s unregistered",
			virt_dev->name);
		TRACE_DBG("virt_id %d unregister", virt_dev->virt_id);

		list_del(&virt_dev->vdisk_dev_list_entry);

		kfree(virt_dev->file_name);
		kfree(virt_dev);
	} else {	/* resync_size */
		virt_dev = NULL;
		list_for_each_entry(vv, &vdisk_dev_list,
					vdisk_dev_list_entry) {
			if (strcmp(vv->name, name) == 0) {
				virt_dev = vv;
				break;
			}
		}
		if (virt_dev == NULL) {
			PRINT_ERROR("Device %s not found", name);
			res = -EINVAL;
			goto out_up;
		}

		res = vdisk_resync_size(virt_dev);
		if (res != 0)
			goto out_up;
	}
	res = length;

out_up:
	mutex_unlock(&scst_vdisk_mutex);

out_free:
	kfree(i_buf);

out:
	TRACE_EXIT_RES(res);
	return res;

out_free_vpath:
	list_del(&virt_dev->vdisk_dev_list_entry);
	kfree(virt_dev->file_name);

out_free_vdev:
	kfree(virt_dev);
	goto out_up;
}

/*
 * Called when a file in the /proc/VDISK_NAME/VDISK_NAME is written
 */
static int vdisk_write_proc(char *buffer, char **start, off_t offset,
	int length, int *eof, struct scst_dev_type *dev_type)
{
	int res;

	res = vdisk_proc_mgmt_cmd(buffer, length, dev_type);

	return res;
}

/*
 * Called when a file in the /proc/VCDROM_NAME/VCDROM_NAME is read
 */
static int vcdrom_read_proc(struct seq_file *seq,
			    struct scst_dev_type *dev_type)
{
	int res = 0;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	if (mutex_lock_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out;
	}

	seq_printf(seq, "%-17s %-9s %s\n", "Name", "Size(MB)", "File name");

	list_for_each_entry(virt_dev, &vcdrom_dev_list,
		vdisk_dev_list_entry) {
		seq_printf(seq, "%-17s %-9d %s\n", virt_dev->name,
			(uint32_t)(virt_dev->file_size >> 20),
			virt_dev->file_name);
	}

	mutex_unlock(&scst_vdisk_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* scst_vdisk_mutex supposed to be held */
static int vcdrom_proc_change(struct vdev_type *vdt, char *p, const char *name)
{
	struct scst_vdisk_dev *virt_dev;
	int res;

	virt_dev = vdt->vfns.vdev_find(name);
	if (virt_dev == NULL) {
		PRINT_ERROR("Virtual device with name "
		       "%s not found", name);
		res = -EINVAL;
		goto out;
	}

	res = vcdrom_change(virt_dev, p, strlen(p) + 1);

out:
	return res;
}

static int vcdrom_proc_mgmt_cmd(const char *buffer, int length,
	struct scst_dev_type *dev_type)
{
	int res = 0, action;
	char *p, *name, *i_buf;
	struct scst_vdisk_dev *virt_dev;

	TRACE_ENTRY();

	if ((length == 0) || (buffer == NULL) || (buffer[0] == '\0'))
		goto out;

	i_buf = kmalloc(length+1, GFP_KERNEL);
	if (i_buf == NULL) {
		PRINT_ERROR("Unable to alloc intermediate buffer with size %d",
			length+1);
		res = -ENOMEM;
		goto out;
	}

	memcpy(i_buf, buffer, length);
	i_buf[length] = '\0';

	if (mutex_lock_interruptible(&scst_vdisk_mutex) != 0) {
		res = -EINTR;
		goto out_free;
	}

	p = i_buf;
	if (p[strlen(p) - 1] == '\n')
		p[strlen(p) - 1] = '\0';
	if (!strncmp("close ", p, 6)) {
		p += 6;
		action = 0;
	} else if (!strncmp("change ", p, 7)) {
		p += 7;
		action = 1;
	} else if (!strncmp("open ", p, 5)) {
		p += 5;
		action = 2;
	} else {
		PRINT_ERROR("Unknown action \"%s\"", p);
		res = -EINVAL;
		goto out_up;
	}

	while (isspace(*p) && *p != '\0')
		p++;
	name = p;
	while (!isspace(*p) && *p != '\0')
		p++;
	*p++ = '\0';
	if (*name == '\0') {
		PRINT_ERROR("%s", "Name required");
		res = -EINVAL;
		goto out_up;
	} else if (strlen(name) >= sizeof(virt_dev->name)) {
		PRINT_ERROR("Name is too long (max %zd "
			"characters)", sizeof(virt_dev->name)-1);
		res = -EINVAL;
		goto out_up;
	}

	if (action == 2) {
		/* open */
		res = vdev_open(&vcdrom_type.parent_vdt, p, name);
		if (res != 0)
			goto out_up;
	} else if (action == 1) {
		/* change */
		res = vcdrom_proc_change(&vcdrom_type.parent_vdt, p, name);
		if (res != 0)
			goto out_up;
	} else {
		/* close */
		res = vdev_close(&vcdrom_type.parent_vdt, name);
		if (res != 0)
			goto out_up;
	}
	res = length;

out_up:
	mutex_unlock(&scst_vdisk_mutex);

out_free:
	kfree(i_buf);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/*
 * Called when a file in the /proc/VCDROM_NAME/VCDROM_NAME is written
 */
static int vcdrom_write_proc(char *buffer, char **start, off_t offset,
	int length, int *eof, struct scst_dev_type *dev_type)
{
	int res;

	res = vcdrom_proc_mgmt_cmd(buffer, length, dev_type);

	return res;
}

static int vdisk_help_info_show(struct seq_file *seq, void *v)
{
	char *s = (char *)seq->private;

	TRACE_ENTRY();

	seq_printf(seq, "%s", s);

	TRACE_EXIT();
	return 0;
}

static struct scst_proc_data vdisk_help_proc_data = {
	SCST_DEF_RW_SEQ_OP(NULL)
	.show = vdisk_help_info_show,
};

static int vdisk_proc_help_build(struct scst_dev_type *dev_type)
{
	int res = 0;
	struct proc_dir_entry *p, *root;

	TRACE_ENTRY();

	root = scst_proc_get_dev_type_root(dev_type);
	vdisk_help_proc_data.data = (dev_type->type == TYPE_DISK) ?
					vdisk_proc_help_string :
					vcdrom_proc_help_string;
	p = scst_create_proc_entry(root, VDISK_PROC_HELP,
				   &vdisk_help_proc_data);
	if (p == NULL) {
		PRINT_ERROR("Not enough memory to register dev "
		     "handler %s entry %s in /proc", "vdisk", VDISK_PROC_HELP);
		res = -ENOMEM;
	}

	TRACE_EXIT_RES(res);
	return res;
}

static void vdisk_proc_help_destroy(struct scst_dev_type *dev_type)
{
	struct proc_dir_entry *root;

	TRACE_ENTRY();

	root = scst_proc_get_dev_type_root(dev_type);
	if (root)
		remove_proc_entry(VDISK_PROC_HELP, root);

	TRACE_EXIT();
}

#endif /* CONFIG_SCST_PROC */

static int __init init_scst_vdisk(struct scst_dev_type *devtype,
	struct vdev_type *vdt)
{
	int res = 0;

	TRACE_ENTRY();

	vdt->vdt_devt = devtype;
	devtype->devt_priv = vdt;

	devtype->module = THIS_MODULE;

	res = scst_register_virtual_dev_driver(devtype);
	if (res < 0)
		goto out;

#ifdef CONFIG_SCST_PROC
	if (!devtype->no_proc) {
		res = scst_dev_handler_build_std_proc(devtype);
		if (res < 0)
			goto out_unreg;

		res = vdisk_proc_help_build(devtype);
		if (res < 0)
			goto out_destroy_proc;
	}
#endif

out:
	TRACE_EXIT_RES(res);
	return res;

#ifdef CONFIG_SCST_PROC
out_destroy_proc:
	if (!devtype->no_proc)
		scst_dev_handler_destroy_std_proc(devtype);

out_unreg:
	scst_unregister_virtual_dev_driver(devtype);
	goto out;
#endif
}

static void exit_scst_vdisk(struct scst_dev_type *devtype,
	struct list_head *vdisk_dev_list)
{
	TRACE_ENTRY();

	mutex_lock(&scst_vdisk_mutex);
	while (1) {
		struct scst_vdisk_dev *virt_dev;

		if (list_empty(vdisk_dev_list))
			break;

		virt_dev = list_entry(vdisk_dev_list->next, typeof(*virt_dev),
				vdisk_dev_list_entry);

		scst_unregister_virtual_device(virt_dev->virt_id);

		list_del(&virt_dev->vdisk_dev_list_entry);

		PRINT_INFO("Virtual device %s unregistered", virt_dev->name);
		TRACE_DBG("virt_id %d", virt_dev->virt_id);
		kfree(virt_dev->file_name);
		kfree(virt_dev);
	}
	mutex_unlock(&scst_vdisk_mutex);

#ifdef CONFIG_SCST_PROC
	if (!devtype->no_proc) {
		vdisk_proc_help_destroy(devtype);
		scst_dev_handler_destroy_std_proc(devtype);
	}
#endif

	scst_unregister_virtual_dev_driver(devtype);

	TRACE_EXIT();
	return;
}

static void __init init_vdev_type(struct vdev_type *vdt)
{
	/* vdt supposed to be already zeroed */

	vdt->vfns.vdev_create = vdev_create;
	vdt->vfns.vdev_destroy = vdev_destroy;
	vdt->vfns.vdev_open = vdev_open;
	vdt->vfns.vdev_close = vdev_close;
	vdt->vfns.vdev_del = vdev_del;
	vdt->vfns.vdev_init = vdev_init;
	vdt->vfns.vdev_deinit = vdev_deinit;
}

static void __init init_fileio_type(void)
{
	struct vdev_type *vdt = &fileio_type.parent_vdt;

	init_vdev_type(vdt);

	vdt->vdt_name = "FILEIO";
	vdt->help_string = "Usage:\n"
		"	echo \"open|close NAME [FILE_NAME "
		"[BLOCK_SIZE] [WRITE_THROUGH] [READ_ONLY] [O_DIRECT] "
		"[NV_CACHE] [REMOVABLE]]\" >mgmt\n";

	fileio_type.parent_vdt_vfns = vdt->vfns;

	vdt->vfns.vdev_add = vdisk_add;
	vdt->vfns.vdev_find = vdisk_find;
	vdt->vfns.parse_option = vdisk_fileio_parse_option;
	vdt->vfns.pre_register = vdisk_fileio_pre_register;

	return;
}

static void __init init_blockio_type(void)
{
	struct vdev_type *vdt = &blockio_type.parent_vdt;

	init_vdev_type(vdt);

	vdt->vdt_name = "BLOCKIO";
	vdt->help_string = "Usage:\n"
		"	echo \"open|close NAME [DEVICE_NAME "
		"[BLOCK_SIZE] [READ_ONLY] [REMOVABLE]]\" >mgmt\n";

	blockio_type.parent_vdt_vfns = vdt->vfns;

	vdt->vfns.vdev_init = vdisk_blockio_init;
	vdt->vfns.vdev_add = vdisk_add;
	vdt->vfns.vdev_find = vdisk_find;
	vdt->vfns.parse_option = vdisk_parse_option;
	vdt->vfns.pre_register = vdisk_blockio_pre_register;

	return;
}
static void __init init_nullio_type(void)
{
	struct vdev_type *vdt = &nullio_type.parent_vdt;

	init_vdev_type(vdt);

	vdt->vdt_name = "NULLIO";
	vdt->help_string = "Usage:\n"
		"	echo \"open|close NAME [none [BLOCK_SIZE] [READ_ONLY] "
		"[REMOVABLE]]\" >mgmt\n";

	nullio_type.parent_vdt_vfns = vdt->vfns;

	vdt->vfns.vdev_init = vdisk_nullio_init;
	vdt->vfns.vdev_add = vdisk_add;
	vdt->vfns.vdev_find = vdisk_find;
	vdt->vfns.parse_option = vdisk_parse_option;

	return;
}
static void __init init_vcdrom_type(void)
{
	struct vdev_type *vdt = &vcdrom_type.parent_vdt;

	init_vdev_type(vdt);

	vdt->vdt_name = "VCDROM";
	vdt->help_string = "Usage:\n"
		"	echo \"open|change|close NAME [FILE_NAME]\" >mgmt\n";

	vcdrom_type.parent_vdt_vfns = vdt->vfns;

	vdt->vfns.vdev_init = vcdrom_init;
	vdt->vfns.vdev_add = vcdrom_add;
	vdt->vfns.vdev_find = vcdrom_find;
	vdt->vfns.pre_register = vcdrom_pre_register;

	return;
}

static int __init init_scst_vdisk_driver(void)
{
	int res;

	vdisk_thr_cachep = KMEM_CACHE(scst_vdisk_thr, SCST_SLAB_FLAGS);
	if (vdisk_thr_cachep == NULL) {
		res = -ENOMEM;
		goto out;
	}

	blockio_work_cachep = KMEM_CACHE(scst_blockio_work, SCST_SLAB_FLAGS);
	if (blockio_work_cachep == NULL) {
		res = -ENOMEM;
		goto out_free_vdisk_cache;
	}

	if (num_threads < 1) {
		PRINT_ERROR("num_threads can not be less than 1, use "
			"default %d", DEF_NUM_THREADS);
		num_threads = DEF_NUM_THREADS;
	}

	vdisk_file_devtype.threads_num = num_threads;
	vcdrom_devtype.threads_num = num_threads;

	atomic_set(&nullio_thr_data.hdr.ref, 1); /* never destroy it */

	init_fileio_type();
	init_blockio_type();
	init_nullio_type();
	init_vcdrom_type();

	res = init_scst_vdisk(&vdisk_file_devtype, &fileio_type.parent_vdt);
	if (res != 0)
		goto out_free_slab;

	res = init_scst_vdisk(&vdisk_blk_devtype, &blockio_type.parent_vdt);
	if (res != 0)
		goto out_free_vdisk;

	res = init_scst_vdisk(&vdisk_null_devtype, &nullio_type.parent_vdt);
	if (res != 0)
		goto out_free_blk;

	res = init_scst_vdisk(&vcdrom_devtype, &vcdrom_type.parent_vdt);
	if (res != 0)
		goto out_free_null;

out:
	return res;

out_free_null:
	exit_scst_vdisk(&vdisk_null_devtype, &vdisk_dev_list);

out_free_blk:
	exit_scst_vdisk(&vdisk_blk_devtype, &vdisk_dev_list);

out_free_vdisk:
	exit_scst_vdisk(&vdisk_file_devtype, &vdisk_dev_list);

out_free_slab:
	kmem_cache_destroy(blockio_work_cachep);

out_free_vdisk_cache:
	kmem_cache_destroy(vdisk_thr_cachep);
	goto out;
}

static void __exit exit_scst_vdisk_driver(void)
{
	exit_scst_vdisk(&vdisk_null_devtype, &vdisk_dev_list);
	exit_scst_vdisk(&vdisk_blk_devtype, &vdisk_dev_list);
	exit_scst_vdisk(&vdisk_file_devtype, &vdisk_dev_list);
	exit_scst_vdisk(&vcdrom_devtype, &vcdrom_dev_list);
	kmem_cache_destroy(blockio_work_cachep);
	kmem_cache_destroy(vdisk_thr_cachep);
}

module_init(init_scst_vdisk_driver);
module_exit(exit_scst_vdisk_driver);

MODULE_AUTHOR("Vladislav Bolkhovitin & Leonid Stoljar");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SCSI disk (type 0) and CDROM (type 5) dev handler for "
	"SCST using files on file systems or block devices");
MODULE_VERSION(SCST_VERSION_STRING);
