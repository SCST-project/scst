/*
 * Copyright (C) 2008 Richard Sharpe
 * Copyright (C) 1992 Eric Youngdale
 * Copyright (C) 2008 - 2010 Vladislav Bolkhovitin <vst@vlnb.net>
 *
 * Simulate a host adapter and an SCST target adapter back to back
 *
 * Based on the scsi_debug.c driver originally by Eric Youngdale and
 * others, including D Gilbert et al
 *
 */

#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/genhd.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/moduleparam.h>
#include <linux/scatterlist.h>
#include <linux/blkdev.h>
#include <linux/completion.h>
#include <linux/stat.h>
#include <linux/spinlock.h>
#include <asm/unaligned.h>

#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsicam.h>
#include <scsi/scsi_eh.h>

/* SCST includes ... */
#include <scst_const.h>
#include <scst.h>

#define LOG_PREFIX "scst_local"

#include <scst_debug.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
#define SG_MAX_SINGLE_ALLOC	(PAGE_SIZE / sizeof(struct scatterlist))
#endif

#if defined(CONFIG_HIGHMEM4G) || defined(CONFIG_HIGHMEM64G)
#warning "HIGHMEM kernel configurations are not supported by this module,\
 because nowadays it isn't worth the effort. Consider changing\
 VMSPLIT option or use a 64-bit configuration instead. See SCST core\
 README file for details."
#endif

#ifdef CONFIG_SCST_DEBUG
#define SCST_LOCAL_DEFAULT_LOG_FLAGS (TRACE_FUNCTION | TRACE_PID | \
	TRACE_OUT_OF_MEM | TRACE_MGMT | TRACE_MGMT_DEBUG | \
	TRACE_MINOR | TRACE_SPECIAL)
#else
# ifdef CONFIG_SCST_TRACING
#define SCST_LOCAL_DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MGMT | \
	TRACE_SPECIAL)
# endif
#endif

#if defined(CONFIG_SCST_DEBUG)
#define trace_flag scst_local_trace_flag
static unsigned long scst_local_trace_flag = SCST_LOCAL_DEFAULT_LOG_FLAGS;
#endif

/*
 * Provide some local definitions that are not provided for some earlier
 * kernels so we operate over a wider range of kernels
 *
 * Some time before 2.6.24 scsi_sg_count, scsi_sglist and scsi_bufflen were
 * not available. Make it available for 2.6.18 which is used still on some
 * distros, like CentOS etc.
 */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19))
#define scsi_sg_count(cmd) ((cmd)->use_sg)
#define scsi_sglist(cmd) ((struct scatterlist *)(cmd)->request_buffer)
#define scsi_bufflen(cmd) ((cmd)->request_bufflen)
#endif

#define TRUE 1
#define FALSE 0

/*
 * Some definitions needed by the scst portion
 */
static void scst_local_remove_adapter(void);
static int scst_local_add_adapter(void);
static int scst_local_get_initiator_port_transport_id(
				struct scst_session *scst_sess,
				uint8_t **transport_id);

#define SCST_LOCAL_VERSION "0.9.3"
static const char *scst_local_version_date = "20100813";

/*
 * Target structures that are shared between the two pieces
 * This will have to change if we have more than one target
 */
static struct scst_tgt_template scst_local_targ_tmpl;

/*
 * Some max values
 */
#define DEF_NUM_HOST 1
#define DEF_NUM_TGTS 1
#define SCST_LOCAL_MAX_TARGETS 16
#define DEF_MAX_LUNS 256

/*
 * These following defines are the SCSI Host LLD (the initiator).
 * SCST Target Driver is below
 */

static int scst_local_add_host = DEF_NUM_HOST;
static int scst_local_num_tgts = DEF_NUM_TGTS;
static int scst_local_max_luns = DEF_MAX_LUNS;

static int num_aborts;
static int num_dev_resets;
static int num_target_resets;

/*
 * We put AEN items on a list on the scst_local_host_info structure so they
 * can be processed via a work function. We do not actually need the LUN, since
 * the whole target must be rescanned anyway.
 */
struct scst_local_work_item {
	struct list_head work_list_entry;
	struct scst_aen *aen;
};

/*
 * Each host has multiple targets, each of which has a separate session
 * to SCST.
 */

struct scst_local_host_info {
	struct list_head host_list;
	struct Scsi_Host *shost;
	struct scst_tgt *target;
	struct scst_session *session[SCST_LOCAL_MAX_TARGETS];
	struct device dev;
	char init_name[20];
	struct work_struct local_work;
	spinlock_t lock;
	struct list_head work_list;
};

#define to_scst_lcl_host(d) \
	container_of(d, struct scst_local_host_info, dev)

/*
 * Maintains data that is needed during command processing ...
 * We have a single element scatterlist in here in case the scst_cmnd
 * we are given has a buffer, not a scatterlist, but we only need this for
 * kernels less than 2.6.25.
 */
struct scst_local_tgt_specific {
	struct scsi_cmnd *cmnd;
	void (*done)(struct scsi_cmnd *);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	struct scatterlist sgl;
#endif
};

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
/*
 * We use a pool of objects maintaind by the kernel so that it is less
 * likely to have to allocate them when we are in the data path.
 *
 * Note, we only need this for kernels in which we are likely to get non
 * scatterlist requests.
 */
static struct kmem_cache *tgt_specific_pool;
#endif

static LIST_HEAD(scst_local_host_list);
static DEFINE_SPINLOCK(scst_local_host_list_lock);

static struct bus_type scst_fake_lld_bus;
static struct device scst_fake_primary;

static struct device_driver scst_local_driverfs_driver = {
	.name	= SCST_LOCAL_NAME,
	.bus	= &scst_fake_lld_bus,
};

module_param_named(add_host, scst_local_add_host, int, S_IRUGO);
module_param_named(num_tgts, scst_local_num_tgts, int, S_IRUGO);
module_param_named(max_luns, scst_local_max_luns, int, S_IRUGO);

MODULE_AUTHOR("Richard Sharpe + ideas from SCSI_DEBUG");
MODULE_DESCRIPTION("SCSI+SCST local adapter driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(SCST_LOCAL_VERSION);

MODULE_PARM_DESC(add_host, "0..127 hosts can be created (def=1)");
MODULE_PARM_DESC(num_tgts, "mumber of targets per host (def=1)");
MODULE_PARM_DESC(max_luns, "number of luns per target (def=1)");

static int scst_local_target_register(void);

static int scst_local_proc_info(struct Scsi_Host *host, char *buffer,
				char **start, off_t offset, int length,
				int inout)
{
	int len, pos, begin;

	TRACE_ENTRY();

	if (inout == 1)
		return -EACCES;

	begin = 0;
	pos = len = sprintf(buffer, "scst_local adapter driver, version "
			    "%s [%s]\n"
			    "num_tgts=%d, Aborts=%d, Device Resets=%d, "
			    "Target Resets=%d\n",
			    SCST_LOCAL_VERSION, scst_local_version_date,
			    scst_local_num_tgts, num_aborts, num_dev_resets,
			    num_target_resets);
	if (pos < offset) {
		len = 0;
		begin = pos;
	}
	if (start)
		*start = buffer + (offset - begin);
	len -= (offset - begin);
	if (len > length)
		len = length;

	TRACE_EXIT_RES(len);
	return len;
}

static ssize_t scst_local_add_host_show(struct device_driver *ddp, char *buf)
{
	int len = 0;
	struct scst_local_host_info *scst_lcl_host, *tmp;

	TRACE_ENTRY();

	list_for_each_entry_safe(scst_lcl_host, tmp, &scst_local_host_list,
				 host_list) {
		len += scnprintf(&buf[len], PAGE_SIZE - len, " Initiator: %s\n",
				 scst_lcl_host->session[0]->initiator_name);
	}

	TRACE_EXIT_RES(len);
	return len;
}

static ssize_t scst_local_add_host_store(struct device_driver *ddp,
					 const char *buf, size_t count)
{
	int delta_hosts;

	TRACE_ENTRY();

	if (sscanf(buf, "%d", &delta_hosts) != 1)
		return -EINVAL;
	if (delta_hosts > 0) {
		do {
			scst_local_add_adapter();
		} while (--delta_hosts);
	} else if (delta_hosts < 0) {
		do {
			scst_local_remove_adapter();
		} while (++delta_hosts);
	}

	TRACE_EXIT_RES(count);
	return count;
}

static DRIVER_ATTR(add_host, S_IRUGO | S_IWUSR, scst_local_add_host_show,
	    scst_local_add_host_store);

static int do_create_driverfs_files(void)
{
	int ret;

	TRACE_ENTRY();

	ret = driver_create_file(&scst_local_driverfs_driver,
				 &driver_attr_add_host);

	TRACE_EXIT_RES(ret);
	return ret;
}

static void do_remove_driverfs_files(void)
{
	driver_remove_file(&scst_local_driverfs_driver,
			   &driver_attr_add_host);
}

static char scst_local_info_buf[256];

static const char *scst_local_info(struct Scsi_Host *shp)
{
	TRACE_ENTRY();

	sprintf(scst_local_info_buf, "scst_local, version %s [%s], "
		"Aborts: %d, Device Resets: %d, Target Resets: %d",
		SCST_LOCAL_VERSION, scst_local_version_date,
		num_aborts, num_dev_resets, num_target_resets);

	TRACE_EXIT();
	return scst_local_info_buf;
}

#if 0
static int scst_local_ioctl(struct scsi_device *dev, int cmd, void __user *arg)
{
	TRACE_ENTRY();

	if (scst_local_opt_noise & SCST_LOCAL_OPT_LLD_NOISE)
		printk(KERN_INFO "scst_local: ioctl: cmd=0x%x\n", cmd);
	return -EINVAL;

	TRACE_EXIT();
}
#endif

static int scst_local_abort(struct scsi_cmnd *SCpnt)
{
	struct scst_local_host_info *scst_lcl_host;
	int ret = 0;
	DECLARE_COMPLETION_ONSTACK(dev_reset_completion);

	TRACE_ENTRY();

	scst_lcl_host = to_scst_lcl_host(scsi_get_device(SCpnt->device->host));

	ret = scst_rx_mgmt_fn_tag(scst_lcl_host->session[SCpnt->device->id],
				  SCST_ABORT_TASK, SCpnt->tag, FALSE,
				  &dev_reset_completion);

	wait_for_completion_interruptible(&dev_reset_completion);

	++num_aborts;

	TRACE_EXIT_RES(ret);
	return ret;
}

/*
 * We issue a mgmt function. We should pass a structure to the function
 * that contains our private data, so we can retrieve the status from the
 * done routine ... TODO
 */
static int scst_local_device_reset(struct scsi_cmnd *SCpnt)
{
	struct scst_local_host_info *scst_lcl_host;
	int lun;
	int ret = 0;
	DECLARE_COMPLETION_ONSTACK(dev_reset_completion);

	TRACE_ENTRY();

	scst_lcl_host = to_scst_lcl_host(scsi_get_device(SCpnt->device->host));

	lun = SCpnt->device->lun;
	lun = (lun & 0xFF) << 8 | ((lun & 0xFF00) >> 8); /* FIXME: LE only */

	ret = scst_rx_mgmt_fn_lun(scst_lcl_host->session[SCpnt->device->id],
				  SCST_LUN_RESET,
				  (const uint8_t *)&lun,
				  sizeof(lun), FALSE,
				  &dev_reset_completion);

	/*
	 * Now wait for the completion ...
	 */
	wait_for_completion_interruptible(&dev_reset_completion);

	++num_dev_resets;

	TRACE_EXIT_RES(ret);
	return ret;
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 25))
static int scst_local_target_reset(struct scsi_cmnd *SCpnt)
{
	struct scst_local_host_info *scst_lcl_host;
	int lun;
	int ret = 0;
	DECLARE_COMPLETION_ONSTACK(dev_reset_completion);

	TRACE_ENTRY();

	scst_lcl_host = to_scst_lcl_host(scsi_get_device(SCpnt->device->host));

	lun = SCpnt->device->lun;
	lun = (lun & 0xFF) << 8 | ((lun & 0xFF00) >> 8); /* FIXME: LE only */

	ret = scst_rx_mgmt_fn_lun(scst_lcl_host->session[SCpnt->device->id],
				  SCST_TARGET_RESET,
				  (const uint8_t *)&lun,
				  sizeof(lun), FALSE,
				  &dev_reset_completion);

	/*
	 * Now wait for the completion ...
	 */
	wait_for_completion_interruptible(&dev_reset_completion);

	++num_target_resets;

	TRACE_EXIT_RES(ret);
	return ret;
}
#endif

static void copy_sense(struct scsi_cmnd *cmnd, struct scst_cmd *scst_cmnd)
{
	int scst_cmnd_sense_len = scst_cmd_get_sense_buffer_len(scst_cmnd);

	TRACE_ENTRY();

	scst_cmnd_sense_len = (SCSI_SENSE_BUFFERSIZE < scst_cmnd_sense_len ?
			       SCSI_SENSE_BUFFERSIZE : scst_cmnd_sense_len);
	memcpy(cmnd->sense_buffer, scst_cmd_get_sense_buffer(scst_cmnd),
	       scst_cmnd_sense_len);

	TRACE_BUFFER("Sense set", cmnd->sense_buffer, scst_cmnd_sense_len);

	TRACE_EXIT();
	return;
}

/*
 * Utility function to handle processing of done and allow
 * easy insertion of error injection if desired
 */
static int scst_local_send_resp(struct scsi_cmnd *cmnd,
				struct scst_cmd *scst_cmnd,
				void (*done)(struct scsi_cmnd *),
				int scsi_result)
{
	int ret = 0;

	TRACE_ENTRY();

	if (scst_cmnd) {
		/* The buffer isn't ours, so let's be safe and restore it */
		scst_check_restore_sg_buff(scst_cmnd);

		/* Simulate autosense by this driver */
		if (unlikely(SCST_SENSE_VALID(scst_cmnd->sense)))
			copy_sense(cmnd, scst_cmnd);
	}

	cmnd->result = scsi_result;

	done(cmnd);

	TRACE_EXIT_RES(ret);
	return ret;
}

/*
 * This does the heavy lifting ... we pass all the commands on to the
 * target driver and have it do its magic ...
 */
static int scst_local_queuecommand(struct scsi_cmnd *SCpnt,
				   void (*done)(struct scsi_cmnd *))
	__acquires(&h->host_lock)
	__releases(&h->host_lock)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	struct scst_local_tgt_specific *tgt_specific = NULL;
#endif
	struct scst_local_host_info *scst_lcl_host;
	struct scatterlist *sgl = NULL;
	int sgl_count = 0;
	int target = SCpnt->device->id;
	int lun;
	struct scst_cmd *scst_cmd = NULL;
	scst_data_direction dir;

	TRACE_ENTRY();

	TRACE_DBG("targ: %d, init id %d, lun %d, cmd: 0X%02X\n",
	      target, SCpnt->device->host->hostt->this_id, SCpnt->device->lun,
	      SCpnt->cmnd[0]);

	scst_lcl_host = to_scst_lcl_host(scsi_get_device(SCpnt->device->host));

	scsi_set_resid(SCpnt, 0);

	if (target == SCpnt->device->host->hostt->this_id) {
		printk(KERN_ERR "%s: initiator's id used as target\n",
		       __func__);
		return scst_local_send_resp(SCpnt, NULL, done,
					    DID_NO_CONNECT << 16);
	}

	/*
	 * Tell the target that we have a command ... but first we need
	 * to get the LUN into a format that SCST understand
	 */
	lun = SCpnt->device->lun;
	lun = (lun & 0xFF) << 8 | ((lun & 0xFF00) >> 8); /* FIXME: LE only */
	scst_cmd = scst_rx_cmd(scst_lcl_host->session[SCpnt->device->id],
			       (const uint8_t *)&lun,
			       sizeof(lun), SCpnt->cmnd,
			       SCpnt->cmd_len, TRUE);
	if (!scst_cmd) {
		printk(KERN_ERR "%s out of memory at line %d\n",
		       __func__, __LINE__);
		return -ENOMEM;
	}

	scst_cmd_set_tag(scst_cmd, SCpnt->tag);
	switch (scsi_get_tag_type(SCpnt->device)) {
	case MSG_SIMPLE_TAG:
		scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_SIMPLE);
		break;
	case MSG_HEAD_TAG:
		scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_HEAD_OF_QUEUE);
		break;
	case MSG_ORDERED_TAG:
		scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_ORDERED);
		break;
	case SCSI_NO_TAG:
	default:
		scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_UNTAGGED);
		break;
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	/*
	 * Allocate a tgt_specific_structure. We need this in case we need
	 * to construct a single element SGL.
	 */
	tgt_specific = kmem_cache_alloc(tgt_specific_pool, GFP_ATOMIC);
	if (!tgt_specific) {
		printk(KERN_ERR "%s out of memory at line %d\n",
		       __func__, __LINE__);
		return -ENOMEM;
	}
	tgt_specific->cmnd = SCpnt;
	tgt_specific->done = done;
#else
	/*
	 * We save a pointer to the done routine in SCpnt->scsi_done and
	 * we save that as tgt specific stuff below.
	 */
	SCpnt->scsi_done = done;
#endif

	/*
	 * If the command has a request, not a scatterlist, then convert it
	 * to one. We use scsi_sg_count to isolate us from the changes from
	 * version to version
	 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	if (scsi_sg_count(SCpnt)) {
		sgl       = scsi_sglist(SCpnt);
		sgl_count = scsi_sg_count(SCpnt);
	} else {
		/*
		 * Build a one-element scatter list out of the buffer
		 * We will not even get here if the kernel version we
		 * are building on only supports scatterlists. See #if above.
		 *
		 * We use the sglist and bufflen function/macros to isolate
		 * us from kernel version differences.
		 */
		if (scsi_sglist(SCpnt)) {
			sg_init_one(&(tgt_specific->sgl),
				(const void *)scsi_sglist(SCpnt),
				scsi_bufflen(SCpnt));
			sgl	  = &(tgt_specific->sgl);
			sgl_count = 1;
		} else {
			sgl = NULL;
			sgl_count = 0;
		}
	}
#else
	sgl       = scsi_sglist(SCpnt);
	sgl_count = scsi_sg_count(SCpnt);
#endif

	dir = SCST_DATA_NONE;
	switch (SCpnt->sc_data_direction) {
	case DMA_TO_DEVICE:
		dir = SCST_DATA_WRITE;
		scst_cmd_set_expected(scst_cmd, dir, scsi_bufflen(SCpnt));
		scst_cmd_set_tgt_sg(scst_cmd, sgl, sgl_count);
		break;
	case DMA_FROM_DEVICE:
		dir = SCST_DATA_READ;
		scst_cmd_set_expected(scst_cmd, dir, scsi_bufflen(SCpnt));
		scst_cmd_set_tgt_sg(scst_cmd, sgl, sgl_count);
		break;
	case DMA_BIDIRECTIONAL:
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 24))
		/* Some of these symbols are only defined after 2.6.24 */
		dir = SCST_DATA_BIDI;
		scst_cmd_set_expected(scst_cmd, dir, scsi_bufflen(SCpnt));
		scst_cmd_set_expected_out_transfer_len(scst_cmd,
			scsi_in(SCpnt)->length);
		scst_cmd_set_tgt_sg(scst_cmd, scsi_in(SCpnt)->table.sgl,
			scsi_in(SCpnt)->table.nents);
		scst_cmd_set_tgt_out_sg(scst_cmd, sgl, sgl_count);
		break;
#endif
	case DMA_NONE:
	default:
		dir = SCST_DATA_NONE;
		scst_cmd_set_expected(scst_cmd, dir, 0);
		break;
	}

	/*
	 * Save the correct thing below depending on version
	 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	scst_cmd_set_tgt_priv(scst_cmd, tgt_specific);
#else
	scst_cmd_set_tgt_priv(scst_cmd, SCpnt);
#endif

#ifdef CONFIG_SCST_LOCAL_FORCE_DIRECT_PROCESSING
	{
		struct Scsi_Host *h = SCpnt->device->host;
		spin_unlock_irq(h->host_lock);
		scst_cmd_init_done(scst_cmd, scst_estimate_context_direct());
		spin_lock_irq(h->host_lock);
	}
#else
	/*
	 * Unfortunately, we called with IRQs disabled, so have no choice,
	 * except pass to the thread context.
	 */
	scst_cmd_init_done(scst_cmd, SCST_CONTEXT_THREAD);
#endif

	/*
	 * We are done here I think. Other callbacks move us forward.
	 */
	TRACE_EXIT();
	return 0;
}

static int scst_local_targ_pre_exec(struct scst_cmd *scst_cmd)
{
	int res = SCST_PREPROCESS_STATUS_SUCCESS;

	TRACE_ENTRY();

	if (scst_cmd_get_dh_data_buff_alloced(scst_cmd) &&
	    (scst_cmd_get_data_direction(scst_cmd) & SCST_DATA_WRITE))
		scst_copy_sg(scst_cmd, SCST_SG_COPY_FROM_TARGET);

	TRACE_EXIT_RES(res);
	return res;
}

static void scst_local_work_fn(struct work_struct *work)
{
	struct scst_local_host_info *scst_lcl_host =
		container_of(work, struct scst_local_host_info, local_work);
	struct scst_local_work_item *work_item = NULL;
	long unsigned flags;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Target work (tgt %p)", scst_lcl_host);

	/*
	 * Eventually, we need to lock things ...
	 */

	spin_lock_irqsave(&scst_lcl_host->lock, flags);
	while (!list_empty(&scst_lcl_host->work_list)) {
		work_item = list_entry(scst_lcl_host->work_list.next,
				struct scst_local_work_item, work_list_entry);
		list_del(&work_item->work_list_entry);
		spin_unlock_irqrestore(&scst_lcl_host->lock, flags);
		scsi_scan_target(&scst_lcl_host->shost->shost_gendev, 0, 0,
					SCAN_WILD_CARD, 1);
		scst_aen_done(work_item->aen);
		kfree(work_item);
		spin_lock_irqsave(&scst_lcl_host->lock, flags);
	}
	spin_unlock_irqrestore(&scst_lcl_host->lock, flags);

	TRACE_EXIT();
	return;
}

static int scst_local_report_aen(struct scst_aen *aen)
{
	int res = 0;
	int event_fn = scst_aen_get_event_fn(aen);
	struct scst_local_host_info *scst_lcl_host = scst_sess_get_tgt_priv(
							scst_aen_get_sess(aen));
	/*__be64 lun = scst_aen_get_lun(aen);*/
	struct scst_local_work_item *work_item = NULL;
	long unsigned flags;

	TRACE_ENTRY();

	switch (event_fn) {
	case SCST_AEN_SCSI:
		/*
		 * Allocate a work item and place it on the queue
		 */
		work_item = kzalloc(sizeof(*work_item), GFP_KERNEL);
		if (!work_item) {
			printk(KERN_ERR "%s: Unable to allocate work item "
				"to handle AEN!\n", __func__);
			return -ENOMEM;
		}

		spin_lock_irqsave(&scst_lcl_host->lock, flags);
		list_add_tail(&work_item->work_list_entry,
				&scst_lcl_host->work_list);
		work_item->aen = aen;
		spin_unlock_irqrestore(&scst_lcl_host->lock, flags);

		schedule_work(&scst_lcl_host->local_work);
		break;

	default:
		TRACE_MGMT_DBG("Unsupported AEN %d\n", event_fn);
		res = SCST_AEN_RES_NOT_SUPPORTED;
		break;
	}

	TRACE_EXIT_RES(res);
	return res;
}

static int scst_local_get_initiator_port_transport_id(
				struct scst_session *scst_sess,
				uint8_t **transport_id)
{
	int res = 0;
	int tr_id_size = 0, sess = -1, i = 0;
	uint8_t *tr_id = NULL;
	struct scst_local_host_info *scst_lcl_host;

	TRACE_ENTRY();

	if (scst_sess == NULL) {
		res = SCSI_TRANSPORTID_PROTOCOLID_SAS;
		goto out;
	}

	scst_lcl_host = (struct scst_local_host_info *)
				scst_sess_get_tgt_priv(scst_sess);

	tr_id_size = 24;  /* A SAS TransportID */

	tr_id = kzalloc(tr_id_size, GFP_KERNEL);
	if (tr_id == NULL) {
		PRINT_ERROR("Allocation of TransportID (size %d) failed",
			tr_id_size);
		res = -ENOMEM;
		goto out;
	}

	tr_id[0] = 0x00 | SCSI_TRANSPORTID_PROTOCOLID_SAS;

	for (i = 0; i < scst_local_num_tgts; i++) {
		/*
		 * We are called before the session is returned below
		 */
		if (scst_lcl_host->session[i] == NULL) {
			sess = i;
			break;
		}
	}

	if (sess == -1) {
		printk(KERN_INFO "%s: Unable to find a matching session\n",
			__func__);
		res = -ENOENT;
		goto out;
	}

	/*
	 * Assemble a valid SAS address = 0x5OOUUIIR12345678 ... Does SCST
	 * have one?
	 */

	tr_id[4]  = 0x5F;
	tr_id[5]  = 0xEE;
	tr_id[6]  = 0xDE;
	tr_id[7]  = 0x40 | ((sess >> 4) & 0x0F);
	tr_id[8]  = 0x0F | (sess & 0xF0);
	tr_id[9]  = 0xAD;
	tr_id[10] = 0xE0;
	tr_id[11] = 0x50;

	*transport_id = tr_id;

	TRACE_DBG("Created tid '%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X'",
		tr_id[4], tr_id[5], tr_id[6], tr_id[7],
		tr_id[8], tr_id[9], tr_id[10], tr_id[11]);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void scst_local_release_adapter(struct device *dev)
{
	struct scst_local_host_info *scst_lcl_host;
	int i = 0;

	TRACE_ENTRY();
	scst_lcl_host = to_scst_lcl_host(dev);
	if (scst_lcl_host) {
		for (i = 0; i < scst_local_num_tgts; i++)
			if (scst_lcl_host->session[i])
				scst_unregister_session(
					scst_lcl_host->session[i], TRUE, NULL);
		scst_unregister_target(scst_lcl_host->target);
		cancel_work_sync(&scst_lcl_host->local_work);
		kfree(scst_lcl_host);
	}

	TRACE_EXIT();
}

/*
 * Add an adapter on the host side ... We add the target before we add
 * the host (initiator) so that we don't get any requests before we are
 * ready for them.
 *
 * I want to convert this so we can map many hosts to a smaller number of
 * targets to support the simulation of multiple initiators.
 */
static int scst_local_add_adapter(void)
{
	int error = 0, i = 0;
	struct scst_local_host_info *scst_lcl_host;
	char name[32];

	TRACE_ENTRY();

	scst_lcl_host = kzalloc(sizeof(struct scst_local_host_info),
				GFP_KERNEL);
	if (NULL == scst_lcl_host) {
		printk(KERN_ERR "%s out of memory at line %d\n",
		       __func__, __LINE__);
		return -ENOMEM;
	}

	spin_lock(&scst_local_host_list_lock);
	list_add_tail(&scst_lcl_host->host_list, &scst_local_host_list);
	spin_unlock(&scst_local_host_list_lock);

	/*
	 * Register a target with SCST and add a session
	 */
	sprintf(name, "scstlcltgt%d", scst_local_add_host);
	scst_lcl_host->target = scst_register_target(&scst_local_targ_tmpl,
						     name);
	if (!scst_lcl_host) {
		printk(KERN_WARNING "scst_register_target() failed:\n");
		error = -1;
		goto cleanup;
	}

	/*
	 * Create a session for each device
	 */
	for (i = 0; i < scst_local_num_tgts; i++) {
		sprintf(name, "scstlclhst%d:%d", scst_local_add_host, i);
		scst_lcl_host->session[i] = scst_register_session(
						scst_lcl_host->target,
						0, name, (void *)scst_lcl_host,
						NULL, NULL);
		if (!scst_lcl_host->session[i]) {
			printk(KERN_WARNING "scst_register_session failed:\n");
			error = -1;
			goto unregister_target;
		}
	}

	scst_lcl_host->dev.bus     = &scst_fake_lld_bus;
	scst_lcl_host->dev.parent  = &scst_fake_primary;
	scst_lcl_host->dev.release = &scst_local_release_adapter;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	sprintf(scst_lcl_host->dev.bus_id, "scst_adp_%d", scst_local_add_host);
#else
	snprintf(scst_lcl_host->init_name, sizeof(scst_lcl_host->init_name),
		 "scst_adp_%d", scst_local_add_host);
	scst_lcl_host->dev.init_name = scst_lcl_host->init_name;
#endif

	error = device_register(&scst_lcl_host->dev);
	if (error)
		goto unregister_session;

	scst_local_add_host++; /* keep count of what we have added */

	TRACE_EXIT();
	return error;

unregister_session:
	for (i = 0; i < scst_local_num_tgts; i++) {
		if (scst_lcl_host->session[i])
			scst_unregister_session(scst_lcl_host->session[i],
			TRUE, NULL);
	}
unregister_target:
	scst_unregister_target(scst_lcl_host->target);
cleanup:
	kfree(scst_lcl_host);
	TRACE_EXIT();
	return error;
}

/*
 * Remove an adapter ...
 */
static void scst_local_remove_adapter(void)
{
	struct scst_local_host_info *scst_lcl_host = NULL;

	TRACE_ENTRY();

	spin_lock(&scst_local_host_list_lock);
	if (!list_empty(&scst_local_host_list)) {
		scst_lcl_host = list_entry(scst_local_host_list.prev,
					   struct scst_local_host_info,
					   host_list);
		list_del(&scst_lcl_host->host_list);
	}
	spin_unlock(&scst_local_host_list_lock);

	if (!scst_lcl_host)
		return;

	device_unregister(&scst_lcl_host->dev);

	--scst_local_add_host;

	TRACE_EXIT();
}

static struct scsi_host_template scst_lcl_ini_driver_template = {
	.proc_info			= scst_local_proc_info,
	.proc_name			= SCST_LOCAL_NAME,
	.name				= SCST_LOCAL_NAME,
	.info				= scst_local_info,
/*	.ioctl				= scst_local_ioctl, */
	.queuecommand			= scst_local_queuecommand,
	.eh_abort_handler		= scst_local_abort,
	.eh_device_reset_handler	= scst_local_device_reset,
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 25))
	.eh_target_reset_handler	= scst_local_target_reset,
#endif
	.can_queue			= 256,
	.this_id			= SCST_LOCAL_MAX_TARGETS,
	/* SCST doesn't support sg chaining */
	.sg_tablesize			= SG_MAX_SINGLE_ALLOC,
	.cmd_per_lun			= 32,
	.max_sectors			= 0xffff,
	/* SCST doesn't support sg chaining */
	.use_clustering			= ENABLE_CLUSTERING,
	.skip_settle_delay		= 1,
	.module				= THIS_MODULE,
};

static void scst_fake_0_release(struct device *dev)
{
	TRACE_ENTRY();

	TRACE_EXIT();
}

static struct device scst_fake_primary = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	.bus_id		= "scst_fake_0",
#else
	.init_name	= "scst_fake_0",
#endif
	.release	= scst_fake_0_release,
};

static int __init scst_local_init(void)
{
	int ret, k, adapters;

	TRACE_ENTRY();

#if defined(CONFIG_HIGHMEM4G) || defined(CONFIG_HIGHMEM64G)
	PRINT_ERROR("%s", "HIGHMEM kernel configurations are not supported. "
		"Consider changing VMSPLIT option or use a 64-bit "
		"configuration instead. See SCST core README file for "
		"details.");
	ret = -EINVAL;
	goto out;
#endif

	TRACE_DBG("Adapters: %d\n", scst_local_add_host);

	if (scst_local_num_tgts > SCST_LOCAL_MAX_TARGETS)
		scst_local_num_tgts = SCST_LOCAL_MAX_TARGETS;

	/*
	 * Allocate a pool of structures for tgt_specific structures
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23)
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	/*
	 * We only need this for kernels where we can get non scatterlists
	 */
	tgt_specific_pool = kmem_cache_create("scst_tgt_specific",
				      sizeof(struct scst_local_tgt_specific),
				      0, SCST_SLAB_FLAGS, NULL);
#endif
#else
	tgt_specific_pool = kmem_cache_create("scst_tgt_specific",
				      sizeof(struct scst_local_tgt_specific),
				      0, SCST_SLAB_FLAGS, NULL, NULL);
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	/*
	 * We only need this if we could get non scatterlist requests
	 */
	if (!tgt_specific_pool) {
		printk(KERN_WARNING "%s: out of memory for "
		       "tgt_specific structs",
		       __func__);
		return -ENOMEM;
	}
#endif

	ret = device_register(&scst_fake_primary);
	if (ret < 0) {
		printk(KERN_WARNING "%s: device_register error: %d\n",
		       __func__, ret);
		goto destroy_kmem;
	}
	ret = bus_register(&scst_fake_lld_bus);
	if (ret < 0) {
		printk(KERN_WARNING "%s: bus_register error: %d\n",
		       __func__, ret);
		goto dev_unreg;
	}
	ret = driver_register(&scst_local_driverfs_driver);
	if (ret < 0) {
		printk(KERN_WARNING "%s: driver_register error: %d\n",
		       __func__, ret);
		goto bus_unreg;
	}
	ret = do_create_driverfs_files();
	if (ret < 0) {
		printk(KERN_WARNING "%s: create_files error: %d\n",
		       __func__, ret);
		goto driver_unregister;
	}

	/*
	 * register the target driver and then create a host. This makes sure
	 * that we see any targets that are there. Gotta figure out how to
	 * tell the system that there are new targets when SCST creates them.
	 */

	ret = scst_local_target_register();
	if (ret < 0) {
		printk(KERN_WARNING "%s: unable to register targ griver: %d\n",
		       __func__, ret);
		goto del_files;
	}

	/*
	 * Add adapters ...
	 */
	adapters = scst_local_add_host;
	scst_local_add_host = 0;
	for (k = 0; k < adapters; k++) {
		if (scst_local_add_adapter()) {
			printk(KERN_ERR "%s: "
					"scst_local_add_adapter failed: %d\n",
					__func__, k);
			break;
		}
	}

out:
	TRACE_EXIT_RES(ret);
	return ret;

del_files:
	do_remove_driverfs_files();
driver_unregister:
	driver_unregister(&scst_local_driverfs_driver);
bus_unreg:
	bus_unregister(&scst_fake_lld_bus);
dev_unreg:
	device_unregister(&scst_fake_primary);
destroy_kmem:
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	/*
	 * We only need to do this if we could get non scatterlist requests
	 */
	kmem_cache_destroy(tgt_specific_pool);
#endif
	goto out;
}

static void __exit scst_local_exit(void)
{
	int k = scst_local_add_host;

	TRACE_ENTRY();

	for (; k; k--)
		scst_local_remove_adapter();

	do_remove_driverfs_files();
	driver_unregister(&scst_local_driverfs_driver);
	bus_unregister(&scst_fake_lld_bus);
	device_unregister(&scst_fake_primary);

	/*
	 * Now unregister the target template
	 */
	scst_unregister_target_template(&scst_local_targ_tmpl);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	/*
	 * Free the pool we allocated, but we only do this if we could get
	 * non scatterlist requests
	 */
	if (tgt_specific_pool)
		kmem_cache_destroy(tgt_specific_pool);
#endif

	TRACE_EXIT();
}

device_initcall(scst_local_init);
module_exit(scst_local_exit);

/*
 * Fake LLD Bus and functions
 */

static int scst_fake_lld_driver_probe(struct device *dev)
{
	int ret = 0;
	struct scst_local_host_info *scst_lcl_host;
	struct Scsi_Host *hpnt;

	TRACE_ENTRY();

	scst_lcl_host = to_scst_lcl_host(dev);

	printk(KERN_INFO "%s: scst_lcl_host: %p\n", __func__, scst_lcl_host);

	/*
	 * Init this stuff we need for scheduling work
	 */
	INIT_WORK(&scst_lcl_host->local_work, scst_local_work_fn);
	spin_lock_init(&scst_lcl_host->lock);
	INIT_LIST_HEAD(&scst_lcl_host->work_list);

	hpnt = scsi_host_alloc(&scst_lcl_ini_driver_template,
			       sizeof(scst_lcl_host));
	if (NULL == hpnt) {
		printk(KERN_ERR "%s: scsi_register failed\n", __func__);
		ret = -ENODEV;
		return ret;
	}

	scst_lcl_host->shost = hpnt;

	/*
	 * We are going to have to register with SCST here I think
	 * and fill in some of these from that info?
	 */

	*((struct scst_local_host_info **)hpnt->hostdata) = scst_lcl_host;
	if ((hpnt->this_id >= 0) && (scst_local_num_tgts > hpnt->this_id))
		hpnt->max_id = scst_local_num_tgts + 1;
	else
		hpnt->max_id = scst_local_num_tgts;
	hpnt->max_lun = scst_local_max_luns - 1;

	/*
	 * Because of a change in the size of this field at 2.6.26
	 * we use this check ... it allows us to work on earlier
	 * kernels. If we don't,  max_cmd_size gets set to 4 (and we get
	 * a compiler warning) so a scan never occurs.
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	hpnt->max_cmd_len = 16;
#else
	hpnt->max_cmd_len = 260;
#endif

	ret = scsi_add_host(hpnt, &scst_lcl_host->dev);
	if (ret) {
		printk(KERN_ERR "%s: scsi_add_host failed\n", __func__);
		ret = -ENODEV;
		scsi_host_put(hpnt);
	} else
		scsi_scan_host(hpnt);

	TRACE_EXIT_RES(ret);
	return ret;
}

static int scst_fake_lld_driver_remove(struct device *dev)
{
	struct scst_local_host_info *scst_lcl_host;

	TRACE_ENTRY();

	scst_lcl_host = to_scst_lcl_host(dev);

	if (!scst_lcl_host) {
		printk(KERN_ERR "%s: Unable to locate host info\n",
		       __func__);
		return -ENODEV;
	}

	scsi_remove_host(scst_lcl_host->shost);

	scsi_host_put(scst_lcl_host->shost);

	TRACE_EXIT();
	return 0;
}

static int scst_fake_lld_bus_match(struct device *dev,
				   struct device_driver *dev_driver)
{
	TRACE_ENTRY();

	TRACE_EXIT();
	return 1;
}

static struct bus_type scst_fake_lld_bus = {
	.name   = "scst_fake_bus",
	.match  = scst_fake_lld_bus_match,
	.probe  = scst_fake_lld_driver_probe,
	.remove = scst_fake_lld_driver_remove,
};

/*
 * SCST Target driver from here ... there are some forward declarations
 * above
 */

static int scst_local_targ_detect(struct scst_tgt_template *tgt_template)
{
	int adapter_count;

	TRACE_ENTRY();

	/*
	 * Register the adapter(s)
	 */

	adapter_count = scst_local_add_host;

	TRACE_EXIT_RES(adapter_count);
	return adapter_count;
};

static int scst_local_targ_release(struct scst_tgt *tgt)
{
	TRACE_ENTRY();

	TRACE_EXIT();
	return 0;
}

static int scst_local_targ_xmit_response(struct scst_cmd *scst_cmd)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	struct scst_local_tgt_specific *tgt_specific;
#endif
	struct scsi_cmnd *SCpnt = NULL;
	void (*done)(struct scsi_cmnd *);

	TRACE_ENTRY();

	if (unlikely(scst_cmd_aborted(scst_cmd))) {
		scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_ABORTED);
		scst_tgt_cmd_done(scst_cmd, SCST_CONTEXT_SAME);
		return SCST_TGT_RES_SUCCESS;
	}

	if (scst_cmd_get_dh_data_buff_alloced(scst_cmd) &&
	    (scst_cmd_get_data_direction(scst_cmd) & SCST_DATA_READ))
		scst_copy_sg(scst_cmd, SCST_SG_COPY_TO_TARGET);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	tgt_specific = scst_cmd_get_tgt_priv(scst_cmd);
	SCpnt = tgt_specific->cmnd;
	done = tgt_specific->done;
#else
	SCpnt = scst_cmd_get_tgt_priv(scst_cmd);
	done = SCpnt->scsi_done;
#endif

	/*
	 * This might have to change to use the two status flags
	 */
	if (scst_cmd_get_is_send_status(scst_cmd)) {
		int resid = 0, out_resid = 0;
		/*
		 * Calculate the residual ...
		 */
		if (likely(!scst_get_resid(scst_cmd, &resid, &out_resid))) {
			TRACE_DBG("No residuals for request %p", SCpnt);
		} else {
			if (out_resid != 0)
				PRINT_ERROR("Unable to return OUT residual %d "
					"(op %02x)", out_resid, SCpnt->cmnd[0]);
		}

		scsi_set_resid(SCpnt, resid);

		/*
		 * It seems like there is no way to set out_resid ...
		 */

		(void)scst_local_send_resp(SCpnt, scst_cmd, done,
					   scst_cmd_get_status(scst_cmd));
	}

	/*
	 * Now tell SCST that the command is done ...
	 */
	scst_tgt_cmd_done(scst_cmd, SCST_CONTEXT_SAME);

	TRACE_EXIT();

	return SCST_TGT_RES_SUCCESS;
}

static void scst_local_targ_on_free_cmd(struct scst_cmd *scst_cmd)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	struct scst_local_tgt_specific *tgt_specific;
#endif

	TRACE_ENTRY();

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
	/*
	 * We only have to do this if we are using these structures
	 */
	tgt_specific = scst_cmd_get_tgt_priv(scst_cmd);
	kmem_cache_free(tgt_specific_pool, tgt_specific);
#endif

	TRACE_EXIT();
	return;
}

static void scst_local_targ_task_mgmt_done(struct scst_mgmt_cmd *mgmt_cmd)
{
	struct completion *tgt_specific;

	TRACE_ENTRY();

	tgt_specific = (struct completion *)
			 scst_mgmt_cmd_get_tgt_priv(mgmt_cmd);

	if (tgt_specific)
		complete(tgt_specific);

	TRACE_EXIT();
	return;
}

static struct scst_tgt_template scst_local_targ_tmpl = {
	.name			= "scst_local_tgt",
	.sg_tablesize		= 0xffff,
	.xmit_response_atomic	= 1,
#ifndef CONFIG_SCST_PROC
	.enabled_attr_not_needed = 1,
#endif
	.detect			= scst_local_targ_detect,
	.release		= scst_local_targ_release,
	.pre_exec		= scst_local_targ_pre_exec,
	.xmit_response		= scst_local_targ_xmit_response,
	.on_free_cmd		= scst_local_targ_on_free_cmd,
	.task_mgmt_fn_done	= scst_local_targ_task_mgmt_done,
	.report_aen		= scst_local_report_aen,
	.get_initiator_port_transport_id
				= scst_local_get_initiator_port_transport_id,
};

/*
 * Register the target driver ... to get things going
 */
static int scst_local_target_register(void)
{
	int ret;

	TRACE_ENTRY();

	ret = scst_register_target_template(&scst_local_targ_tmpl);
	if (ret < 0) {
		printk(KERN_WARNING "scst_register_target_template "
		       "failed: %d\n",
		       ret);
		goto error;
	}

	TRACE_EXIT();
	return 0;

error:
	TRACE_EXIT_RES(ret);
	return ret;
}

