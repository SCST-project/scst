/*
 *  mpt_scst.c
 *
 *  Copyright (C) 2005 Beijing Soul Technology Co., Ltd.
 *  Copyright (C) 2002, 2003, 2004 LSI Logic Corporation
 *  Copyright (C) 2004 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 Leonid Stoljar
 *
 *  MPT SCSI target mode driver for SCST.
 *
 *  Originally   By: Stephen Shirron
 *  Port to SCST By: Hu Gang <hugang@soulinfo.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/blkdev.h>
#include <linux/interrupt.h>
#include <scsi/scsi.h>
#include <linux/seq_file.h>
#include <scsi/scsi_host.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 5, 0)
#include <linux/pci.h>
#endif

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#include <scst/scst_debug.h>
#else
#include "scst.h"
#include <scst_debug.h>
#endif

#include "mpt_scst.h"

#define MYNAM "mpt_scst"

#ifdef CONFIG_SCST_TRACING
static int trace_mpi;

#define TRACE_MPI	0x80000000

#endif

#ifdef CONFIG_SCST_DEBUG
static char *mpt_state_string[] = {
	"0",
	"new",
	"need data",
	"data in",
	"data out",
	"processed",
	"NULL",
};
#endif

#ifdef CONFIG_SCST_DEBUG
#define SCST_DEFAULT_MPT_LOG_FLAGS (TRACE_FUNCTION | TRACE_PID | \
	TRACE_OUT_OF_MEM | TRACE_MGMT | \
	TRACE_MGMT_DEBUG | TRACE_MINOR | TRACE_SPECIAL)
#else
# ifdef CONFIG_SCST_TRACING
#define SCST_DEFAULT_MPT_LOG_FLAGS (TRACE_FUNCTION | TRACE_PID | \
	TRACE_OUT_OF_MEM | TRACE_MGMT | TRACE_MINOR | TRACE_SPECIAL)
# endif
#endif

static MPT_STM_PRIV *mpt_stm_priv[MPT_MAX_ADAPTERS+1];

static int set_aliases_in_fcportpage1 = 1;
static int num_aliases;
static int stm_context;

static int mpt_stm_adapter_online(MPT_STM_PRIV *priv);
static void mpt_stm_adapter_dispose(MPT_STM_PRIV *priv);
static int mpt_stm_adapter_install(MPT_ADAPTER *ioc);

static int __init _mpt_stm_init(void);

static void stmapp_set_status(MPT_STM_PRIV *priv, CMD *cmd, int status);
static void stmapp_tgt_command(MPT_STM_PRIV *priv, u32 reply_word);
static void stm_cmd_buf_post(MPT_STM_PRIV *priv, int index);

static void stm_tgt_reply_high_pri(MPT_ADAPTER *ioc,
				   TargetCmdBufferPostErrorReply_t *rep);
static void stm_target_reply_error(MPT_ADAPTER *ioc, TargetErrorReply_t *rep);
static void stmapp_target_error(MPT_STM_PRIV *priv, u32 reply_word, int index,
		int status, int reason);
static void stm_link_service_reply(MPT_ADAPTER *ioc,
				   LinkServiceBufferPostReply_t *rep);
static void stm_link_service_rsp_reply(MPT_ADAPTER *ioc,
				       LinkServiceRspRequest_t *req,
				       LinkServiceRspReply_t *rep);
static void stmapp_set_sense_info(MPT_STM_PRIV *priv,
				  CMD *cmd, int sense_key, int asc, int ascq);
static void stmapp_srr_adjust_offset(MPT_STM_PRIV *priv, int index);
static void stmapp_srr_convert_ta_to_tss(MPT_STM_PRIV *priv, int index);
static void stmapp_abts_process(MPT_STM_PRIV *priv, int rx_id,
				LinkServiceBufferPostReply_t *rep, int index);
static int stm_do_config_action(MPT_STM_PRIV *priv, int action, int type,
				int number, int address, int length, int sleep);
static int stm_get_config_page(MPT_STM_PRIV *priv, int type, int number,
			       int address, int sleep);
static int stm_set_config_page(MPT_STM_PRIV *priv, int type, int number,
			       int address, int sleep);
static void stm_cmd_buf_post_list(MPT_STM_PRIV *priv, int index);
static int stm_send_target_status(MPT_STM_PRIV *priv, u32 reply_word,
				  int index, int flags, int lun, int tag);
static void stm_send_els(MPT_STM_PRIV *priv, LinkServiceBufferPostReply_t *rep,
			 int index, int length);
static void stm_link_serv_buf_post(MPT_STM_PRIV *priv, int index);

static void stm_wait(MPT_STM_PRIV *priv, int milliseconds, int sleep);
static int stm_wait_for(MPT_STM_PRIV *priv, volatile int *flag, int seconds,
			int sleep);
static void stmapp_srr_process(MPT_STM_PRIV *priv, int rx_id, int r_ctl,
			       u32 offset, LinkServiceBufferPostReply_t *rep,
			       int index);
static void stm_set_scsi_port_page1(MPT_STM_PRIV *priv, int sleep);

#ifdef CONFIG_SCST_DEBUG
#define trace_flag mpt_trace_flag
static unsigned long mpt_trace_flag = TRACE_FUNCTION | TRACE_OUT_OF_MEM | TRACE_SPECIAL;
#else
# ifdef CONFIG_SCST_TRACING
#define trace_flag mpt_trace_flag
static unsigned long mpt_trace_flag = TRACE_OUT_OF_MEM | TRACE_MGMT | TRACE_SPECIAL;
# endif
#endif

#ifdef CONFIG_SCST_PROC
static int mpt_target_show(struct seq_file *seq, void *v)
{
	struct mpt_tgt *tgt = (struct mpt_tgt *)seq->private;
	MPT_ADAPTER *ioc = tgt->priv->ioc;
	MPT_STM_PRIV *priv = tgt->priv;

	TRACE_ENTRY();
	TRACE_DBG("priv %p, tgt %p", priv, tgt);

	sBUG_ON(tgt == NULL);
	sBUG_ON(ioc == NULL);

	seq_printf(seq, "ProductID        :0x%04x (%s)\nTarget Enable    :%s\n",
		   ioc->facts.ProductID, ioc->prod_name,
		   tgt->target_enable ? "True" : "False");

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 15)
	if (ioc->bus_type == SCSI) {
#else
	if (ioc->bus_type == SPI) {
#endif
		int i = 0;
		seq_printf(seq, "Target ID        :%d\n"
			   "Capabilities     :0x%x\n"
			   "PhysicalInterface:0x%x\n",
			   priv->port_id,
			   priv->SCSIPortPage0.Capabilities,
			   priv->SCSIPortPage0.PhysicalInterface);

		seq_printf(seq, "Configuration    :0x%x\n"
			   "OnBusTimerValue  :0x%x\n"
			   "TargetConfig     :0x%x\n"
			   "IDConfig         :0x%x\n",
			   priv->SCSIPortPage1.Configuration,
			   priv->SCSIPortPage1.OnBusTimerValue,
			   priv->SCSIPortPage1.TargetConfig,
			   priv->SCSIPortPage1.IDConfig);

		seq_printf(seq, "PortFlags        :0x%x\n"
			   "PortSettings     :0x%x\n",
			   priv->SCSIPortPage2.PortFlags,
			   priv->SCSIPortPage2.PortSettings);
#if 0
		for (i = 0; i < 16; i++) {
			seq_printf(seq, " DeviceSeting %02d: 0x%x 0x%x 0x%x\n",
				   priv->SCSIPortPage2.DeviceSettings[i].Timeout,
				   priv->SCSIPortPage2.DeviceSettings[i].SyncFactor,
				   priv->SCSIPortPage2.DeviceSettings[i].DeviceFlags);
		}
#endif
		for (i = 0; i < NUM_SCSI_DEVICES; i++) {
			seq_printf(seq, "  Device %02d: 0x%x, 0x%x\n", i,
				   priv->SCSIDevicePage1[i].RequestedParameters,
				   priv->SCSIDevicePage1[i].Configuration);
		}
	}

	if (ioc->bus_type == FC) {
		seq_printf(seq, "WWN              :%08X%08X:%08X%08X\n",
			   ioc->fc_port_page0[0].WWNN.High,
			   ioc->fc_port_page0[0].WWNN.Low,
			   ioc->fc_port_page0[0].WWPN.High,
			   ioc->fc_port_page0[0].WWPN.Low);
	}

	TRACE_EXIT();
	return 0;
}

static ssize_t mpt_proc_target_write(struct file *file, const char __user *buf,
				     size_t length, loff_t *off)
{

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
	struct mpt_tgt *tgt = (struct mpt_tgt *)PDE(file->f_dentry->d_inode)->data;
#else
	struct mpt_tgt *tgt = (struct mpt_tgt *)PDE_DATA(file->f_dentry->d_inode);
#endif
	MPT_ADAPTER *ioc = tgt->priv->ioc;
	int res = 0;
	char tmp[32+1];

	TRACE_ENTRY();
	res = min_t(int, 32, length);
	if (copy_from_user(tmp, buf, res)) {
		res = -EFAULT;
		goto out;
	}
	tmp[res] = 0;

	TRACE_DBG("buff '%s'", tmp);
	if (strncmp("target:enable", tmp, strlen("target:enable")) == 0) {
		TRACE_DBG("Enable Target, %d, %d", ioc->id, tgt->target_enable);
		if (tgt->target_enable != 1) {
			mpt_stm_adapter_online(mpt_stm_priv[ioc->id]);
			tgt->target_enable = 1;
		}
	}

	if (strncmp("target:disable", tmp, strlen("target:disable")) == 0) {
		TRACE_DBG("Disable Target %d, %d", ioc->id, tgt->target_enable);
		if (tgt->target_enable != 0) {
			/* FIXME */
			tgt->target_enable = 0;
		}
	}

	if (strncmp("target_id:", tmp, strlen("target_id:")) == 0) {
		char *s = tmp + strlen("target_id:");
		int id = simple_strtoul(s, NULL, 0);
		if (id < MPT_MAX_SCSI_DEVICES) {
			if (IsScsi(tgt->priv)) {
				TRACE_DBG("Changing target id to %d\n", id);
				tgt->priv->port_id = id;
				stm_set_scsi_port_page1(tgt->priv, NO_SLEEP);
			}
		}
	}

out:
	TRACE_EXIT_RES(res);

	return length;
}

static struct scst_proc_data mpt_target_proc_data = {
	SCST_DEF_RW_SEQ_OP(mpt_proc_target_write)
	.show = mpt_target_show,
};
#endif

static int mpt_target_detect(struct scst_tgt_template *temp1);
static int mpt_target_release(struct scst_tgt *scst_tgt);
static int stmapp_pending_sense(struct mpt_cmd *mpt_cmd);
static int mpt_xmit_response(struct scst_cmd *scst_cmd);
static void mpt_inquiry_no_tagged_commands(MPT_STM_PRIV *priv,
		struct scst_cmd *scst_cmd);
static int mpt_rdy_to_xfer(struct scst_cmd *scst_cmd);
static void mpt_on_free_cmd(struct scst_cmd *scst_cmd);
static void mpt_task_mgmt_fn_done(struct scst_mgmt_cmd *mcmd);
static int mpt_handle_task_mgmt(MPT_STM_PRIV *priv, u32 reply_word,
				int task_mgmt, int lun);
static int mpt_send_cmd_to_scst(struct mpt_cmd *cmd,
	enum scst_exec_context context);

static struct scst_tgt_template tgt_template = {
	.name = MYNAM,
	.sg_tablesize = 128, /* FIXME */
	.use_clustering = 1,
#ifdef DEBUG_WORK_IN_THREAD
	.xmit_response_atomic = 0,
	.rdy_to_xfer_atomic = 0,
#else
	.xmit_response_atomic = 1,
	.rdy_to_xfer_atomic = 1,
#endif
	.detect = mpt_target_detect,
	.release = mpt_target_release,
	.xmit_response = mpt_xmit_response,
	.rdy_to_xfer = mpt_rdy_to_xfer,
	.on_free_cmd = mpt_on_free_cmd,
	.task_mgmt_fn_done = mpt_task_mgmt_fn_done,
};

static inline void mpt_msg_frame_free(MPT_STM_PRIV *priv, int index)
{
	MPT_ADAPTER *ioc = priv->ioc;
	if (priv->current_mf[index] != NULL) {
		TRACE_DBG("%s: free mf index %d, %p", ioc->name,
			  MF_TO_INDEX(priv->current_mf[index]),
			  priv->current_mf[index]);
		mpt_free_msg_frame(_HANDLE_IOC_ID, priv->current_mf[index]);
		priv->current_mf[index] = NULL;
	}
}

static inline MPT_FRAME_HDR *mpt_msg_frame_alloc(MPT_ADAPTER *ioc, int index)
{
	MPT_STM_PRIV *priv = mpt_stm_priv[ioc->id];
	MPT_FRAME_HDR *mf;

	if (index != -1) {
		TRACE_DBG("%s: current_mf %p, index %d",
				ioc->name, priv->current_mf[index], index);
		WARN_ON(priv->current_mf[index] != NULL);
	}

	mf = mpt_get_msg_frame(stm_context, _IOC_ID);

	sBUG_ON(mf == NULL);

	if (index != -1)
		priv->current_mf[index] = mf;

	TRACE_DBG("%s: alloc mf index %d, %p, %d", ioc->name,
			MF_TO_INDEX(mf), mf, index);

	return mf;
}

static int _mpt_ada_nums;

static int mptstm_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	MPT_ADAPTER	*ioc = pci_get_drvdata(pdev);
	int ret = 0;
	struct mpt_tgt *tgt;
#ifdef CONFIG_SCST_PROC
	struct proc_dir_entry *p;
	struct proc_dir_entry *root;
	char name[4];
#endif

	TRACE_ENTRY();
	ret = mpt_stm_adapter_install(ioc);
	if (ret != 0)
		goto out;

	tgt = kmalloc(sizeof(*tgt), GFP_KERNEL);
	TRACE_MEM("kmalloc(GFP_KERNEL) for tgt (%zd), %p",
		  sizeof(*tgt), tgt);
	if (tgt == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s",
		      "Allocation of tgt failed");
		ret = -ENOMEM;
		goto out;
	}
	memset(tgt, 0, sizeof(*tgt));
	tgt->priv = mpt_stm_priv[ioc->id];
	tgt->target_enable = 0;
	tgt->priv->port_id = 1;
	/* tgt->priv->scsi_port_config = MPI_SCSIPORTPAGE1_TARGCONFIG_INIT_TARG; */
	tgt->priv->scsi_port_config = MPI_SCSIPORTPAGE1_TARGCONFIG_TARG_ONLY;
	/* tgt->priv->scsi_id_config = 0x7; */
	tgt->priv->scsi_id_config = 0;
	atomic_set(&tgt->sess_count, 0);
	init_waitqueue_head(&tgt->waitQ);

	tgt->scst_tgt = scst_register_target(&tgt_template, MYNAM);
	if (tgt->scst_tgt == NULL) {
		PRINT_ERROR(MYNAM ": scst_register_target() failed for host %p",
			    pdev);

		ret = -ENODEV;
		goto out;
	}

#ifdef CONFIG_SCST_PROC
	root = scst_proc_get_tgt_root(&tgt_template);
	scnprintf(name, sizeof(name), "%d", ioc->id);
	mpt_target_proc_data.data = (void *)tgt;
	p = scst_create_proc_entry(root, name,
				   &mpt_target_proc_data);
	if (p == NULL) {
		PRINT_ERROR("Not enough memory to register "
			    "target driver %s entry %s in /proc",
			    tgt_template.name, name);
		scst_unregister_target(tgt->scst_tgt);
		ret = -ENOMEM;
		goto out;
	}
#endif

	scst_tgt_set_tgt_priv(tgt->scst_tgt, tgt);
	mpt_stm_priv[ioc->id]->tgt = tgt;
	_mpt_ada_nums++;

out:

	TRACE_EXIT_RES(ret);

	return ret;
}

static void mptstm_remove(struct pci_dev *pdev)
{
	MPT_ADAPTER	*ioc = pci_get_drvdata(pdev);
	MPT_STM_PRIV *priv;

	priv = mpt_stm_priv[ioc->id];
	if (priv != NULL)
		mpt_stm_adapter_dispose(priv);
}

static struct mpt_pci_driver mptstm_driver = {
	.probe = mptstm_probe,
	.remove = mptstm_remove,
};

/*
 * mpt_target_detect
 *
 * this function is intended to detect the target adapters that are present in
 * the system. Each found adapter should be registered by calling
 * scst_register_target(). The function should return a value >= 0 to signify
 * the number of detected target adapters. A negative value should be
 * returned whenever there is an error.
 */
static int mpt_target_detect(struct scst_tgt_template *templ)
{
	int ret  = 0;

	TRACE_ENTRY();
	ret = _mpt_stm_init();
	if (ret != 0)
		goto out;

	if (mpt_device_driver_register(&mptstm_driver, MPTSTM_DRIVER)) {
		printk(KERN_WARNING MYNAM
		       ": failed to register for device driver callbacks\n");
		ret = -ENODEV;
		goto out;
	}

	ret = _mpt_ada_nums;

out:
	TRACE_EXIT_RES(ret);

	return ret;
}

static struct scst_cmd *_stm_target_command(MPT_STM_PRIV *priv, int reply_word,
					    struct mpt_cmd *mpt_cmd)
{
	u8 *cdb;
	int lun, tag, dl, alias, index, init_index, task_mgmt;
	char alias_lun[32];
	CMD *cmd;
	struct scst_cmd *scst_cmd;
	struct mpt_sess *sess = mpt_cmd->sess;
#ifdef CONFIG_SCST_DEBUG
	MPT_ADAPTER *ioc = priv->ioc;
#endif
	/*
	 * Get the CBD, LUN, tag,  Task Mgmt flags, and data length from the
	 * receive packet
	 */
	TRACE_ENTRY();

	index = GET_IO_INDEX(reply_word);
	init_index = GET_INITIATOR_INDEX(reply_word);

	cmd = &priv->hw->cmd_buf[index];

	if (IsScsi(priv)) {
		SCSI_CMD *scsi_cmd = (SCSI_CMD *)cmd->cmd;

		cdb = scsi_cmd->CDB;
		lun = get2bytes(scsi_cmd->LogicalUnitNumber, 0);
		tag = scsi_cmd->Tag;
		task_mgmt = scsi_cmd->TaskManagementFlags;
		dl = 0;
		/*TRACE_DBG("AliasID %d, %d", scsi_cmd->AliasID, priv->port_id);*/
		if (reply_word & TARGET_MODE_REPLY_ALIAS_MASK) {
			alias = (scsi_cmd->AliasID - priv->port_id) & 15;
			sprintf(alias_lun, "alias %d lun %d", alias, lun);
		} else {
			alias = 0;
			sprintf(alias_lun, "lun %d", lun);
		}
	} else if (IsSas(priv)) {
		SSP_CMD *ssp_cmd = (SSP_CMD *)cmd->cmd;

		cdb = ssp_cmd->CDB;
		lun = get2bytes(ssp_cmd->LogicalUnitNumber, 0);
		if (ssp_cmd->FrameType == SSP_TASK_FRAME) {
			SSP_TASK	*ssp_task = (SSP_TASK *)cmd->cmd;

			tag = ssp_task->ManagedTaskTag;
			task_mgmt = ssp_task->TaskManagementFunction;
		} else {
			tag = ssp_cmd->InitiatorTag;
			task_mgmt = 0;
		}
		dl = 0;
		alias = 0;
		sprintf(alias_lun, "lun %d", lun);
	} else {
		FCP_CMD *fcp_cmd = (FCP_CMD *)cmd->cmd;

		cdb = fcp_cmd->FcpCdb;
		lun = get2bytes(fcp_cmd->FcpLun, 0);
		tag = 0;
		task_mgmt = fcp_cmd->FcpCntl[2];
		dl = be32_to_cpu(fcp_cmd->FcpDl);
		if (reply_word & TARGET_MODE_REPLY_ALIAS_MASK) {
			alias = fcp_cmd->AliasIndex;
			sprintf(alias_lun, "alias %d lun %d", alias, lun);
		} else {
			alias = 0;
			sprintf(alias_lun, "lun %d", lun);
		}
	}

	cmd->reply_word = reply_word;
	cmd->alias = alias;
	cmd->lun = lun;
	cmd->tag = tag;

	TRACE_DBG("%s: cmd %p, re_word %x, alias %x, lun %x, tag %x,"
			"%s, init_idx %d, %p, %d",
			ioc->name, cmd, reply_word, alias, lun, tag, alias_lun,
			init_index, priv->scst_cmd[index], dl);

	mpt_cmd->CMD = cmd;
	{
		uint16_t _lun = lun;
		_lun = swab16(le16_to_cpu(_lun));
		scst_cmd = scst_rx_cmd(sess->scst_sess, (uint8_t *)&_lun,
				sizeof(_lun), cdb, MPT_MAX_CDB_LEN, SCST_ATOMIC);
	}
	if (scst_cmd == NULL) {
		PRINT_ERROR(MYNAM ": scst_rx_cmd() failed for %p", cmd);
		goto out;
	}
	TRACE_DBG("scst cmd %p, index %d", priv->scst_cmd[index], index);

	WARN_ON(priv->scst_cmd[index] != NULL);
	priv->scst_cmd[index] = scst_cmd;

	scst_cmd_set_tag(scst_cmd, tag);
	scst_cmd_set_tgt_priv(scst_cmd, mpt_cmd);

	/* FIXME scst_cmd_set_expected */
out:
	TRACE_EXIT();

	return scst_cmd;
}

static void mpt_send_busy(struct mpt_cmd *cmd)
{
	stmapp_set_status(cmd->priv, cmd->CMD, STS_BUSY);
}

static void mpt_alloc_session_done(struct scst_session *scst_sess, void *data,
				   int result)
{
	struct mpt_sess *sess = (struct mpt_sess *) data;
	struct mpt_tgt *tgt = sess->tgt;
	struct mpt_cmd *cmd = NULL;
	int rc = 0;

	TRACE_ENTRY();
	if (result == 0) {
		while (!list_empty(&sess->delayed_cmds)) {
			cmd = list_entry(sess->delayed_cmds.next,
					 typeof(*cmd), delayed_cmds_entry);
			list_del(&cmd->delayed_cmds_entry);
			if (rc == 0)
				rc = mpt_send_cmd_to_scst(cmd, SCST_CONTEXT_THREAD);
			if (rc != 0) {
				PRINT_INFO(MYNAM ": Unable to get the command, sending BUSY state %p",
					   cmd);
				mpt_send_busy(cmd);
				kfree(cmd);
			}
		}
		__clear_bit(MPT_SESS_INITING, &sess->sess_flags);
	} else {
		PRINT_INFO(MYNAM ": Session initialization failed, "
			   "sending BUSY status to all deferred commands %p",
			   cmd);
		while (!list_empty(&sess->delayed_cmds)) {
			cmd = list_entry(sess->delayed_cmds.next,
					 typeof(*cmd), delayed_cmds_entry);
			list_del(&cmd->delayed_cmds_entry);
			TRACE(TRACE_MGMT, "Command <%p> Busy", cmd);
			mpt_send_busy(cmd);
			kfree(cmd);
		}
		tgt->sess[sess->init_index] = NULL;

		TRACE_MEM("kfree for sess %p", sess);
		kfree(sess);

		if (atomic_dec_and_test(&tgt->sess_count))
			wake_up_all(&tgt->waitQ);
	}

	TRACE_EXIT();
	return;
}

static int mpt_send_cmd_to_scst(struct mpt_cmd *cmd,
				enum scst_exec_context context)
{
	int res = 0;

	TRACE_ENTRY();

	cmd->scst_cmd = _stm_target_command(cmd->priv, cmd->reply_word, cmd);
	if (cmd->scst_cmd == NULL) {
		res = -EFAULT;
		goto out;
	}
#ifdef DEBUG_WORK_IN_THREAD
	context = SCST_CONTEXT_THREAD;
#endif
	scst_cmd_init_done(cmd->scst_cmd, context);

out:
	TRACE_EXIT_RES(res);

	return res;
}

static void stm_send_target_status_deferred(MPT_STM_PRIV *priv, u32 reply_word,
					    int index)
{
	int ret = 0;
	MPT_ADAPTER         *ioc = priv->ioc;
	MPT_FRAME_HDR       *mf;
	TargetStatusSendRequest_t   *req;

	TRACE_ENTRY();
	mf = priv->status_deferred_mf[index];
	TRACE_DBG("mf %p, index %d", mf, index);
	req = (TargetStatusSendRequest_t *)mf;

	priv->io_state[index] |= IO_STATE_STATUS_SENT;

	priv->current_mf[index] = mf;
	priv->status_deferred_mf[index] = NULL;
	if (priv->io_state[index] & IO_STATE_HIGH_PRIORITY) {
		ret = mpt_send_handshake_request(stm_context, _IOC_ID,
				sizeof(*req), (u32 *)req _HS_SLEEP);
	} else {
		mpt_put_msg_frame(stm_context, _IOC_ID, mf);
	}

	TRACE_EXIT_RES(ret);
}

static void stm_data_done(MPT_ADAPTER *ioc, u32 reply_word,
			  struct scst_cmd *scst_cmd, struct mpt_cmd *cmd,
			  int index)
{
	MPT_STM_PRIV *priv = mpt_stm_priv[ioc->id];

	TRACE_ENTRY();
	TRACE_DBG("scst cmd %p, index %d, data done",  scst_cmd, index);

	if (scst_cmd_get_resp_data_len(scst_cmd) > 0) {
		TRACE_DBG("clear the data flags <%p>", scst_cmd);
		sBUG_ON(scst_cmd_get_sg_cnt(scst_cmd) == 0);
		pci_unmap_sg(priv->ioc->pcidev,
			scst_cmd_get_sg(scst_cmd),
			scst_cmd_get_sg_cnt(scst_cmd),
			scst_to_tgt_dma_dir(scst_cmd_get_data_direction(scst_cmd)));
	}
	TRACE_EXIT();
}

static void stm_tgt_reply(MPT_ADAPTER *ioc, u32 reply_word)
{
	MPT_STM_PRIV *priv = mpt_stm_priv[ioc->id];
	int index, init_index;
	enum scst_exec_context context;
	struct scst_cmd *scst_cmd;
	struct mpt_cmd *cmd;
	volatile int *io_state;

	TRACE_ENTRY();

#ifdef DEBUG_WORK_IN_THREAD
	context = SCST_CONTEXT_THREAD;
#else
	context = SCST_CONTEXT_TASKLET;
#endif

	index = GET_IO_INDEX(reply_word);
	init_index = GET_INITIATOR_INDEX(reply_word);
	scst_cmd = priv->scst_cmd[index];
	io_state = priv->io_state + index;

	TRACE_DBG("index %d, state %x, scst cmd %p, current_mf %p",
			index, *io_state, scst_cmd, priv->current_mf[index]);
	/*
	 * if scst_cmd is NULL it show the command buffer not using by
	 * SCST, let parse the CDB
	 */
	if (scst_cmd == NULL) {
		WARN_ON((*io_state & ~IO_STATE_HIGH_PRIORITY) != IO_STATE_POSTED);
		*io_state &= ~IO_STATE_POSTED;

		mpt_msg_frame_free(priv, index);

		stmapp_tgt_command(priv, reply_word);
		goto out;
	}

	cmd = (struct mpt_cmd *)scst_cmd_get_tgt_priv(scst_cmd);
	TRACE_DBG("scst cmd %p, index %d, cmd %p, cmd state %s",
		  scst_cmd, index, cmd, mpt_state_string[cmd->state]);

	if (cmd->state == MPT_STATE_NEED_DATA) {
		int rx_status = SCST_RX_STATUS_SUCCESS;

		cmd->state = MPT_STATE_DATA_IN;

		TRACE_DBG("Data received, context %x, rx_status %d",
				context, rx_status);

		sBUG_ON(!(*io_state & IO_STATE_DATA_SENT));
		mpt_msg_frame_free(priv, index);
		if (*io_state & IO_STATE_DATA_SENT) {
			*io_state &= ~IO_STATE_DATA_SENT;
			stm_data_done(ioc, reply_word, scst_cmd, cmd, index);
		}
#if 0
		if ((*io_state & ~IO_STATE_HIGH_PRIORITY) == IO_STATE_AUTO_REPOST) {
			TRACE_DBG("%s", "io state auto repost");
			*io_state = IO_STATE_POSTED;
		} else if ((*io_state & ~IO_STATE_HIGH_PRIORITY) == 0) {
			TRACE_DBG("%s", "io state");
			stm_cmd_buf_post(priv, index);
		}
#endif
		scst_rx_data(scst_cmd, rx_status, context);

		goto out;
	}

	if (*io_state & IO_STATE_STATUS_SENT) {
		/*
		 *  status (and maybe data too) was being sent, so repost the
		 *  command buffer
		 */
		*io_state &= ~IO_STATE_STATUS_SENT;
		mpt_free_msg_frame(_HANDLE_IOC_ID, priv->current_mf[index]);
		if (*io_state & IO_STATE_DATA_SENT) {
			*io_state &= ~IO_STATE_DATA_SENT;
			stm_data_done(ioc, reply_word, scst_cmd, cmd, index);
		}
		TRACE_DBG("set priv->scst_cmd[%d] = NULL", index);
		priv->scst_cmd[index] = NULL;
		if ((*io_state & ~IO_STATE_HIGH_PRIORITY) == IO_STATE_AUTO_REPOST) {
			TRACE_DBG("%s", "io state auto repost");
			*io_state = IO_STATE_POSTED;
		} else if ((*io_state & ~IO_STATE_HIGH_PRIORITY) == 0) {
			TRACE_DBG("%s", "io state");
			stm_cmd_buf_post(priv, index);
		}

		/*
		 * figure out how we're handling cached sense data.
		 */
		if (IsScsi(priv)) {
			switch (atomic_read(&priv->pending_sense[init_index])) {
				/* attempt to send status and sense succeeded */
			case MPT_STATUS_SENSE_ATTEMPT:
				atomic_set(&priv->pending_sense[init_index],
					   MPT_STATUS_SENSE_IDLE);
				/* ToDo: check and set scst_set_delivery_status(), if necessary */
				scst_tgt_cmd_done(scst_cmd, context);
				break;

				/* we tried to send status and sense
				 * simltaneously and failed.  Prepare to handle
				 * the next command without SCST if it is
				 * REQUEST_SENSE */
			case MPT_STATUS_SENSE_NOT_SENT:
				atomic_set(&priv->pending_sense[init_index],
					   MPT_STATUS_SENSE_HANDLE_RQ);
				/* ToDo: check and set scst_set_delivery_status(), if necessary */
				scst_tgt_cmd_done(scst_cmd, context);
				break;

				/* we've handled REQUEST_SENSE ourselves and
				 * we're done with the command.  Clean up */
			case MPT_STATUS_SENSE_HANDLE_RQ:
				TRACE_DBG("%s: clearing pending sense",
					  ioc->name);
				atomic_set(&priv->pending_sense[init_index],
					   MPT_STATUS_SENSE_IDLE);
				mpt_on_free_cmd(scst_cmd);
				/* scst_cmd alloced in stmapp_pending_sense */
				kfree(scst_cmd);
				break;

			default:
				/* nothing much to do here, we aren't
				 * handling cached sense/status */
				/* ToDo: check and set scst_set_delivery_status(), if necessary */
				scst_tgt_cmd_done(scst_cmd, context);
				break;
			}
		} else {
			/* ToDo: check and set scst_set_delivery_status(), if necessary */
			scst_tgt_cmd_done(scst_cmd, context);
		}

		goto out;
	}

	/*
	 *  data (but not status) was being sent, so if status needs to be
	 *  set now, go ahead and do it; otherwise do nothing
	 */
	if (*io_state & IO_STATE_DATA_SENT) {
		*io_state &= ~IO_STATE_DATA_SENT;
		mpt_free_msg_frame(_HANDLE_IOC_ID, priv->current_mf[index]);
		stm_data_done(ioc, reply_word, scst_cmd, cmd, index);
		if (*io_state & IO_STATE_STATUS_DEFERRED) {
			*io_state &= ~IO_STATE_STATUS_DEFERRED;
			stm_send_target_status_deferred(priv, reply_word, index);
		}
		cmd->state = MPT_STATE_PROCESSED;
		goto out;
	}

	/*
	 * just insert into list
	 * bug how can i handle it
	 */
	if (*io_state == 0 && cmd->state == MPT_STATE_NEW) {
		WARN_ON(1);
		goto out;
	}
#if 0
	if (*io_state == IO_STATE_POSTED) {
		TRACE_DBG("%s", "io state posted");
		/*
		 *  command buffer was posted, so we now have a SCSI command
		 */
		*io_state &= ~IO_STATE_POSTED;
		goto out;
	}
#endif
	WARN_ON(1);
out:

	TRACE_EXIT();
}

static int mpt_is_task_mgm(MPT_STM_PRIV *priv, u32 reply_word, int *lun)
{
	int task_mgmt = 0, index;
	CMD *cmd;
	/*struct mpt_tgt *tgt = priv->tgt;*/

	TRACE_ENTRY();

	index = GET_IO_INDEX(reply_word);
	cmd = &priv->hw->cmd_buf[index];

	if (IsScsi(priv)) {
		SCSI_CMD *scsi_cmd = (SCSI_CMD *)cmd->cmd;
		task_mgmt = scsi_cmd->TaskManagementFlags;
		*lun = get2bytes(scsi_cmd->LogicalUnitNumber, 0);
	} else if (IsSas(priv)) {
		SSP_CMD *ssp_cmd = (SSP_CMD *)cmd->cmd;
		if (ssp_cmd->FrameType == SSP_TASK_FRAME) {
			SSP_TASK *ssp_task = (SSP_TASK *)cmd->cmd;
			task_mgmt = ssp_task->TaskManagementFunction;
		}
		*lun = get2bytes(ssp_cmd->LogicalUnitNumber, 0);
	} else {
		FCP_CMD *fcp_cmd = (FCP_CMD *)cmd->cmd;
		task_mgmt = fcp_cmd->FcpCntl[2];
		*lun = get2bytes(fcp_cmd->FcpLun, 0);
	}
	TRACE_EXIT_RES(task_mgmt);

	return task_mgmt;
}

static void stmapp_tgt_command(MPT_STM_PRIV *priv, u32 reply_word)
{
	struct mpt_tgt *tgt = NULL;
	struct mpt_sess *sess = NULL;
	struct mpt_cmd *cmd = NULL;
	int init_index, res = 0, task_mgmt, lun;

	TRACE_ENTRY();

	tgt = priv->tgt;

	task_mgmt = mpt_is_task_mgm(priv, reply_word, &lun);
	if (task_mgmt)
		mpt_handle_task_mgmt(priv, reply_word, task_mgmt, lun);

	init_index = GET_INITIATOR_INDEX(reply_word);

	if (test_bit(MPT_TGT_SHUTDOWN, &tgt->tgt_flags)) {
		TRACE_DBG("New command while the device %p is shutting down", tgt);
		res = -EFAULT;
		goto out;
	}

	cmd = kmalloc(sizeof(*cmd), GFP_ATOMIC);
	TRACE_MEM("kmalloc(GFP_ATOMIC) for cmd (%zd): %p", sizeof(*cmd), cmd);
	if (cmd == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of cmd failed");
		res = -ENOMEM;
		goto out;
	}

	memset(cmd, 0, sizeof(*cmd));
	cmd->priv = priv;
	cmd->reply_word = reply_word;
	cmd->state = MPT_STATE_NEW;

	sess = tgt->sess[init_index];
	if (sess == NULL) {
		sess = kmalloc(sizeof(*sess), GFP_ATOMIC);
		if (sess == NULL) {
			TRACE(TRACE_OUT_OF_MEM, "%s",
			      "Allocation of sess failed");
			res = -ENOMEM;
			goto out_free_cmd;
		}
		/* WWPN */

		atomic_inc(&tgt->sess_count);
		smp_mb__after_atomic_inc();

		memset(sess, 0, sizeof(*sess));
		sess->tgt = tgt;
		sess->init_index = init_index;
		INIT_LIST_HEAD(&sess->delayed_cmds);

		sess->scst_sess = scst_register_session(tgt->scst_tgt, 1,
							"", sess, sess,
							mpt_alloc_session_done);
		if (sess->scst_sess == NULL) {
			PRINT_ERROR(MYNAM ": scst_register_session failed %p",
				    tgt);
			res = -EFAULT;
			goto out_free_sess;
		}

		__set_bit(MPT_SESS_INITING, &sess->sess_flags);

		tgt->sess[init_index] = sess;

		cmd->sess = sess;
		list_add_tail(&cmd->delayed_cmds_entry, &sess->delayed_cmds);
		goto out;
	}

	/* seesion is ready let us do it */
	cmd->sess = sess;
	if (test_bit(MPT_SESS_INITING, &sess->sess_flags)) {
		list_add_tail(&cmd->delayed_cmds_entry, &sess->delayed_cmds);
	} else {
		/* if there is pending sense left over from the last command,
		 * we need to send that if this is a REQUEST SENSE command.
		 * Otherwise send the command to SCST */
		if (!stmapp_pending_sense(cmd)) {
			res = mpt_send_cmd_to_scst(cmd, SCST_CONTEXT_TASKLET);
			/*res = mpt_send_cmd_to_scst(cmd, SCST_CONTEXT_DIRECT_ATOMIC);*/
			if (res != 0)
				goto out_free_cmd;
		}
	}

out:
	TRACE_EXIT();
	return;

out_free_sess:
	TRACE_MEM("kfree for sess %p", sess);
	kfree(sess);

	if (atomic_dec_and_test(&tgt->sess_count))
		wake_up_all(&tgt->waitQ);
	/* go through */
out_free_cmd:
	TRACE_MEM("kfree for cmd %p", cmd);
	kfree(cmd);
	goto out;
}

/*
 * mpt_target_release
 *
 * this function is
 * intended to free up the resources allocated to the device. The function
 * should return 0 to indicate successful release or a negative value if
 * there are some issues with the release. In the current version of SCST
 * the return value is ignored. Must be defined.
 */
static int mpt_target_release(struct scst_tgt *scst_tgt)
{
	/* FIXME */
	return 0;
}

struct mpt_prm {
	struct mpt_tgt *tgt;
	uint16_t seg_cnt;
	unsigned short use_sg;
	struct scatterlist *sg;
	unsigned int bufflen;
	void *buffer;
	scst_data_direction data_direction;
	uint16_t rq_result;
	uint16_t scsi_status;
	unsigned char *sense_buffer;
	unsigned int sense_buffer_len;
	struct mpt_cmd *cmd;
};

static inline void mpt_dump_sge(MPT_SGE *sge, struct scatterlist *sg)
{
	if (sge) {
		void *address = NULL;
		struct page *page = NULL;

		address = bus_to_virt(sge->address);
		page = virt_to_page(address);
		TRACE_DBG("address %p, length %x, count %d, page %p",
				address, sge->length, page_count(page), page);
		TRACE_BUFFER("sge data", address, min_t(u32, sge->length, 0x10));
	}
	if (sg) {
		TRACE_DBG("sg %p, page %p, %p, offset %d, dma address %llx, len %d",
				sg, sg_page(sg), page_address(sg_page(sg)),
				sg->offset, sg->dma_address, sg->length);
		TRACE_BUFFER("sg data", page_address(sg_page(sg)), (u32)0x10);
	}
}

/* FIXME
 *
 * use_sg can not bigger then NUM_SGES
 *
 */
static inline void mpt_sge_to_sgl(struct mpt_prm *prm, MPT_STM_PRIV *priv,
				  MPT_SGL *sgl)
{
	unsigned int bufflen = prm->bufflen;
	int i;

	TRACE_ENTRY();
	TRACE_DBG("bufflen %d, %p", bufflen, prm->buffer);
	sBUG_ON(prm->use_sg == 0);

	prm->sg = (struct scatterlist *)prm->buffer;
	prm->seg_cnt = pci_map_sg(priv->ioc->pcidev, prm->sg, prm->use_sg,
				   scst_to_tgt_dma_dir(prm->data_direction));

	pci_dma_sync_sg_for_cpu(priv->ioc->pcidev, prm->sg, prm->use_sg,
			scst_to_tgt_dma_dir(prm->data_direction));
	for (i = 0; i < prm->use_sg; i++) {
		sgl->sge[i].length = sg_dma_len(&prm->sg[i]);
		sgl->sge[i].address = sg_dma_address(&prm->sg[i]);

		TRACE_DBG("%d, %d", bufflen, prm->sg[i].length);
		if (bufflen < prm->sg[i].length)
			sgl->sge[i].length = bufflen;
		mpt_dump_sge(&sgl->sge[i], &prm->sg[i]);
		bufflen -= sgl->sge[i].length;
	}
	pci_dma_sync_sg_for_device(priv->ioc->pcidev, prm->sg, prm->use_sg,
			scst_to_tgt_dma_dir(prm->data_direction));

	sgl->num_sges = prm->seg_cnt;

	TRACE_EXIT();
}

static inline void mpt_set_sense_info(MPT_STM_PRIV *priv, CMD *cmd, int len,
				      u8 *sense_buf)
{
	u8 *info = NULL;

	TRACE_ENTRY();

	if (IsScsi(priv)) {
		SCSI_RSP *rsp = (SCSI_RSP *)cmd->rsp;

		rsp->Status = STS_CHECK_CONDITION;
		rsp->Valid |= SCSI_SENSE_LEN_VALID;
		rsp->SenseDataListLength = cpu_to_be32(len);
		info = rsp->SenseData;
		if (rsp->Valid & SCSI_RSP_LEN_VALID)
			info += be32_to_cpu(rsp->PktFailuresListLength);
	} else if (IsSas(priv)) {
		SSP_RSP *rsp = (SSP_RSP *)cmd->rsp;

		rsp->Status = STS_CHECK_CONDITION;
		rsp->DataPres |= SSP_SENSE_LEN_VALID;
		rsp->SenseDataLength = cpu_to_be32(len);
		info = rsp->ResponseSenseData;
		if (rsp->DataPres & SSP_RSP_LEN_VALID)
			info += be32_to_cpu(rsp->ResponseDataLength);
	} else {
		FCP_RSP *rsp = (FCP_RSP *)cmd->rsp;

		rsp->FcpStatus = STS_CHECK_CONDITION;
		rsp->FcpFlags |= FCP_SENSE_LEN_VALID;
		rsp->FcpSenseLength = cpu_to_be32(len);
		info = rsp->FcpSenseData - sizeof(rsp->FcpResponseData);
		if (rsp->FcpFlags & FCP_RSP_LEN_VALID)
			info += be32_to_cpu(rsp->FcpResponseLength);
	}

	sBUG_ON(info == NULL);
	memcpy(info, sense_buf, len);
/*out:*/

	TRACE_EXIT();
}

static int mpt_send_tgt_data(MPT_STM_PRIV *priv, u32 reply_word, int index,
			     int flags, int lun, int tag, MPT_SGL *sgl,
			     int length, int offset)
{
	MPT_ADAPTER *ioc = priv->ioc;
	TargetAssistRequest_t *req;
	MPT_STM_SIMPLE	*sge_simple;
	MPT_STM_CHAIN	*sge_chain = NULL;
	u32 sge_flags;
	int chain_length, i, j, k, init_index, res = 1;
	dma_addr_t dma_addr;

	TRACE_ENTRY();
	req = (TargetAssistRequest_t *)mpt_msg_frame_alloc(ioc, index);
	memset(req, 0, sizeof(*req));

	if (priv->exiting)
		flags &= ~TARGET_ASSIST_FLAGS_REPOST_CMD_BUFFER;

	if (priv->io_state[index] & IO_STATE_HIGH_PRIORITY) {
		flags |= TARGET_ASSIST_FLAGS_HIGH_PRIORITY;
		if (flags & TARGET_ASSIST_FLAGS_AUTO_STATUS) {
			flags |= TARGET_ASSIST_FLAGS_REPOST_CMD_BUFFER;
			priv->io_state[index] |= IO_STATE_AUTO_REPOST;
		}
	}

	if (priv->fcp2_capable/* && priv->initiators != NULL*/) {
		init_index = GET_INITIATOR_INDEX(reply_word);
		/*init = priv->initiators[init_index];
		if (init != NULL && init->confirm_capable) {
			flags |= TARGET_ASSIST_FLAGS_CONFIRMED;
		}*/
	}
	TRACE_DBG("flags %x, tag %x, lun %x, offset %x, length %x",
		  flags, tag, lun, offset, length);

	req->StatusCode = 0;
	req->TargetAssistFlags = (u8)flags;
	req->Function = MPI_FUNCTION_TARGET_ASSIST;
	req->QueueTag = (u16)tag;
	req->ReplyWord = cpu_to_le32(reply_word);
	req->LUN[0] = (u8)(lun >> 8);
	req->LUN[1] = (u8)lun;
	req->RelativeOffset = cpu_to_le32(offset);
	req->DataLength = cpu_to_le32(length);
	sge_flags =
		MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_SIMPLE_ELEMENT |
				  MPI_SGE_FLAGS_MPT_STM_ADDRESSING);
	if (flags & TARGET_ASSIST_FLAGS_DATA_DIRECTION)
		sge_flags |= MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_HOST_TO_IOC);
	sge_simple = (MPT_STM_SIMPLE *)&req->SGL;
	for (i = 0, j = 0, k = 0; i < (int)sgl->num_sges; i++, j++) {
		if (k == 0) {
			/* still in mf, haven't chained yet -- do we need to? */
			if (j == priv->num_sge_target_assist) {
				/* yes, we need to chain */
				/* overwrite the last element in the mf with a chain */
				sge_chain = (MPT_STM_CHAIN *)(sge_simple - 1);
				sge_chain->Flags =
					(u8)(MPI_SGE_FLAGS_CHAIN_ELEMENT |
						 MPI_SGE_FLAGS_MPT_STM_ADDRESSING);
				dma_addr = priv->hw_dma +
					((u8 *)priv->hw->cmd_buf[index].chain_sge -
					 (u8 *)priv->hw);
				stm_set_dma_addr(sge_chain->Address, dma_addr);
				/* set the "last element" flag in the mf */
				sge_simple = (MPT_STM_SIMPLE *)(sge_chain - 1);
				sge_simple->FlagsLength |=
					cpu_to_le32(MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_LAST_ELEMENT));
				/* redo the last element in the mf */
				sge_simple =
					(MPT_STM_SIMPLE *)priv->hw->cmd_buf[index].chain_sge;
				sge_simple->FlagsLength =
					cpu_to_le32(sgl->sge[i-1].length | sge_flags);
				stm_set_dma_addr(sge_simple->Address, sgl->sge[i-1].address);
				mpt_dump_sge(&sgl->sge[i-1], NULL);
				sge_simple++;
				/* say we've chained */
				req->ChainOffset =
					((u8 *)sge_chain - (u8 *)req) / sizeof(u32);
				j = 1;
				k++;
			}
		} else {
			/* now in chain, do we need to chain again? */
			if (j == priv->num_sge_chain) {
				/* yes, we need to chain */
				/* fix up the previous chain element */
				chain_length = sizeof(MPT_STM_CHAIN) +
					(priv->num_sge_chain - 1) * sizeof(MPT_STM_SIMPLE);
				sge_chain->Length = cpu_to_le16(chain_length);
				sge_chain->NextChainOffset =
					(chain_length - sizeof(MPT_STM_CHAIN)) / sizeof(u32);
				/* overwrite the last element in the chain with another chain */
				sge_chain = (MPT_STM_CHAIN *)(sge_simple - 1);
				sge_chain->Flags =
					(u8)(MPI_SGE_FLAGS_CHAIN_ELEMENT |
						 MPI_SGE_FLAGS_MPT_STM_ADDRESSING);
				dma_addr = priv->hw_dma + ((u8 *)sge_simple - (u8 *)priv->hw);
				stm_set_dma_addr(sge_chain->Address, dma_addr);
				/* set the "last element" flag in the previous chain */
				sge_simple = (MPT_STM_SIMPLE *)(sge_chain - 1);
				sge_simple->FlagsLength |=
					cpu_to_le32(MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_LAST_ELEMENT));
				/* redo the last element in the previous chain */
				sge_simple = (MPT_STM_SIMPLE *)(sge_chain + 1);
				sge_simple->FlagsLength =
					cpu_to_le32(sgl->sge[i-1].length | sge_flags);
				stm_set_dma_addr(sge_simple->Address, sgl->sge[i-1].address);
				mpt_dump_sge(&sgl->sge[i-1], NULL);
				sge_simple++;
				/* say we've chained */
				j = 1;
				k++;
			}
		}
		sge_simple->FlagsLength = cpu_to_le32(sgl->sge[i].length | sge_flags);
		stm_set_dma_addr(sge_simple->Address, sgl->sge[i].address);
		mpt_dump_sge(&sgl->sge[i], NULL);
		sge_simple++;
	}
	/* did we chain? */
	if (k != 0) {
		/* fix up the last chain element */
		sge_chain->Length = cpu_to_le16(j * sizeof(MPT_STM_SIMPLE));
		sge_chain->NextChainOffset = 0;
	}
	/* fix up the last element */
	sge_simple--;
	sge_simple->FlagsLength |=
		cpu_to_le32(MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_LAST_ELEMENT |
					      MPI_SGE_FLAGS_END_OF_BUFFER |
					      MPI_SGE_FLAGS_END_OF_LIST));
#ifdef CONFIG_SCST_TRACING
	if (trace_mpi) {
		u32 *p = (u32 *)req;
		int i;
		/*dma_addr_t _data;*/
		/*u8 *_buf;*/

		TRACE(TRACE_MPI, "%s stm_send_target_data %d",
		      ioc->name, index);
		for (i = 0; i < (sizeof(*req) - sizeof(req->SGL)) / 4; i++) {
			TRACE(TRACE_MPI, "%s req[%02x] = %08x",
			      ioc->name, i * 4, le32_to_cpu(p[i]));
		}
		TRACE(TRACE_MPI, "%s num_sges = %d, j = %d, k = %d",
		      ioc->name, sgl->num_sges, j, k);
		p = (u32 *)&req->SGL;
		for (i = 0; i < ((k != 0) ? priv->num_sge_target_assist : j); i++) {
#if MPT_STM_64_BIT_DMA
			TRACE(TRACE_MPI, "%s req sgl[%04x] = %08x %08x %08x",
			      ioc->name, i * 12, le32_to_cpu(p[i*3]),
			      le32_to_cpu(p[i*3+1]), le32_to_cpu(p[i*3+2]));
#else
			_data = le32_to_cpu(p[i*2+1]);
			_buf = (u8 *)phys_to_virt(_data);
			TRACE(TRACE_MPI, "%s req sgl[%04x] = %08x %08x,%x,%x,%x,%x,%p",
			      ioc->name, i * 8, le32_to_cpu(p[i*2]), le32_to_cpu(p[i*2+1]),
			      _buf[0], _buf[1], _buf[2], _buf[3], _buf);
#endif
		}
		p = (u32 *)priv->hw->cmd_buf[index].chain_sge;
		for (i = 0; i < ((k != 0) ? (k - 1) * priv->num_sge_chain + j : 0); i++) {
#if MPT_STM_64_BIT_DMA
			TRACE(TRACE_MPI, "%s chain sgl[%04x] = %08x %08x %08x",
			      ioc->name, i * 12, le32_to_cpu(p[i*3]),
			      le32_to_cpu(p[i*3+1]), le32_to_cpu(p[i*3+2]));
#else
			_data = le32_to_cpu(p[i*2+1]);
			_buf = (u8 *)phys_to_virt(_data);
			TRACE(TRACE_MPI, "%s req sgl[%04x] = %08x %08x,%x,%x,%x,%x,%p",
			      ioc->name, i * 8, le32_to_cpu(p[i*2]), le32_to_cpu(p[i*2+1]),
			      _buf[0], _buf[1], _buf[2], _buf[3], _buf);
#endif
		}
	}
#endif
	res = 0;

	priv->io_state[index] |= IO_STATE_DATA_SENT;
	if (flags & TARGET_ASSIST_FLAGS_AUTO_STATUS)
		priv->io_state[index] |= IO_STATE_STATUS_SENT;


	if (priv->io_state[index] & IO_STATE_HIGH_PRIORITY) {
		res = mpt_send_handshake_request(stm_context, _IOC_ID,
						 ioc->req_sz,
						 (u32 *)req _HS_SLEEP);
	} else {
		mpt_put_msg_frame(stm_context, _IOC_ID, (MPT_FRAME_HDR *)req);
	}

	TRACE_EXIT_RES(res);

	return res;
}

/*
 * calling mpt_send_target_data
 *
 */
static void mpt_send_target_data(struct mpt_prm *prm, int flags)
{
	MPT_STM_PRIV *priv;
	u32 reply_word;
	int index, lun, tag, length, offset;
	MPT_SGL *sgl;

	TRACE_ENTRY();
	priv = prm->tgt->priv;
	sgl = &priv->sgl;

	mpt_sge_to_sgl(prm, priv, sgl);

	reply_word = prm->cmd->CMD->reply_word;
	index = GET_IO_INDEX(reply_word);

	lun = prm->cmd->CMD->lun;
	tag = prm->cmd->CMD->tag;

	if (prm->data_direction == SCST_DATA_READ)
		flags |= TARGET_ASSIST_FLAGS_DATA_DIRECTION;

	length = prm->bufflen;
	offset = 0;
#if 0
	TRACE_DBG("priv %p, reply_word %x, index %x, flags %x, lun %x, "
		  "tag %x, sgl %p, length %x, offset %x",
		  priv, reply_word, index, flags, lun, tag,
		  sgl, length, offset);
#endif
	mpt_send_tgt_data(priv, reply_word, index, flags, lun, tag,
			sgl, length, offset);

	TRACE_EXIT();
	return;
}

/*
 * this function checks if we need to handle REQUEST_SENSE on behalf of the
 * target device.  If the sense wasn't able to be sent simultaneously
 * with the status for the last command with a check condition, it needs
 * to either get sent for a REQUEST_SENSE command or forgotten.
 *
 * The pending_sense state and a buffer for holding sense is created for
 * each possible initiator.  The pending_sense state is used to tell if
 * sending sense failed and to track the progress of the following
 * REQUEST_SENSE command.
 *
 * There are four values for the pending_sense state:
 * - STATUS_SENSE_IDLE: no caching of sense data is in progress
 * - STATUS_SENSE_ATTEMPT: an attempt is being made to send status and
 *   sense in the same bus transaction.
 * - STATUS_SENSE_NOT_SENT: the attempt to send simultanous status and
 *   sense failed.
 * - STATUS_SENSE_HANDLE_RQ: the next command from the initiator needs
 *   to be handled by the LSI driver if it is REQUEST_SENSE using cached
 *   sense data, otherwise the cached sense data is ignored and the
 *   command is sent to SCST.
 *
 * In stmapp_pending_sense, if pending_sense state for an initiator ==
 * SENSE_HANDLE_RQ, the incoming command is inspected.  If it is
 * REQUEST_SENSE, the command is handled by the LSI driver without
 * involving SCST.  The cached sense data from the immediately previous
 * command is used.  This sense data was not sent along with the status
 * for that command (see below).  If the command is not REQUEST_SENSE,
 * the cached sense data is discarded and the command is sent to SCST
 * for processing.
 *
 * In stm_send_target_status, sense data about to be sent is saved in a
 * buffer and the pending_sense state for that initiator is set to
 * MPT_STATUS_SENSE_ATTEMPT.  The sense and status are sent to the LSI
 * hardware.
 *
 * If the LSI hardware determines that the sense and status could not be
 * sent in one operation, stm_reply is called with state == STATUS_SENT
 * and with IOCStatus of MPI_IOCSTATUS_TARGET_STS_DATA_NOT_SENT (0x6B).
 * This condition only happens in the non-packetized SCSI operating mode.
 * When this happens, the pending_sense state is advanced to
 * MPT_STATUS_SENSE_NOT_SENT.
 *
 * In stm_tgt_reply, if io_state == STATUS_SENT:
 * - if pending_sense state == SENSE_ATTEMPT, the status and sense attempt was
 *   successful, so the pending_sense state is set to IDLE and the command
 *   is sent to SCST for completion.
 * - if pending_sense state == SENSE_NOT_SENT, the status and sense attempt
 *   failed.  The pending_sense state is advanced to SENSE_HANDLE_RQ and the
 *   current command is sent to SCST for completion.  The next command from
 *   this initiator will enter stmapp_pending_sense as described above.
 * - if pending_sense state == SENSE_HANDLE_RQ, the REQUEST_SENSE command
 *   handled alone by the LSI driver is done and resources need to be
 *   released.  pending_sense state is set to IDLE.
 * - if pending_sense state == SENSE_IDLE, a normal SCST command is done
 *   and is sent to SCST for completion.
 *
 * Because of this caching sense behaviour, we think we need to turn off
 * tagged command queueing.  The mpt_inquiry_no_tagged_commands function
 * does this by modifying INQUIRY data before sending it over the wire.
 */
static int stmapp_pending_sense(struct mpt_cmd *mpt_cmd)
{
	int res = 0;
	MPT_STM_PRIV *priv;
	int index = 0;
	int init_index = 0;
	int flags = 0;
	SCSI_CMD *scsi_cmd = NULL;
	CMD *cmd;
	u8 *cdb;
	struct mpt_prm prm = { NULL };
	struct scst_cmd *scst_cmd;
	struct scatterlist sg;

	TRACE_ENTRY();

	priv = mpt_cmd->priv;
	if (IsScsi(priv)) {
		index = GET_IO_INDEX(mpt_cmd->reply_word);
		init_index = GET_INITIATOR_INDEX(mpt_cmd->reply_word);
		if (atomic_read(&priv->pending_sense[init_index]) ==
				MPT_STATUS_SENSE_HANDLE_RQ) {
			cmd = &priv->hw->cmd_buf[index];
			scsi_cmd = (SCSI_CMD *)cmd->cmd;
			cdb = scsi_cmd->CDB;

			if (cdb[0] == REQUEST_SENSE) {
				/* scst_cmd used as a container in stm_tgt_reply,
				 * command doesn't actually go to SCST */
				scst_cmd = kmalloc(sizeof(struct scst_cmd),
						GFP_ATOMIC);
				TRACE_DBG("scst_cmd 0x%p", scst_cmd);
				if (scst_cmd != NULL) {
					cmd->reply_word = mpt_cmd->reply_word;
					if (cmd->reply_word &
						TARGET_MODE_REPLY_ALIAS_MASK) {
						cmd->alias = (scsi_cmd->AliasID -
								priv->port_id) & 15;
					} else {
						cmd->alias = 0;
					}
					cmd->lun = get2bytes(scsi_cmd->LogicalUnitNumber,
							0);
					cmd->tag = scsi_cmd->Tag;
					mpt_cmd->CMD = cmd;

					memset(scst_cmd, 0x00,
						sizeof(struct scst_cmd));
					scst_cmd->resp_data_len = -1;
					memcpy(scst_cmd->cdb, cdb,
							MPT_MAX_CDB_LEN);
					priv->scst_cmd[index] = scst_cmd;
					scst_cmd_set_tag(scst_cmd, cmd->tag);
					scst_cmd_set_tgt_priv(scst_cmd, mpt_cmd);

					TRACE_BUFFER("CDB", cdb, MPT_MAX_CDB_LEN);

					flags = TARGET_ASSIST_FLAGS_AUTO_STATUS;
					prm.cmd = mpt_cmd;
					/* smallest amount of data between
					 * requested length, buffer size,
					 * and cached length */
					prm.bufflen = min_t(size_t, cdb[4],
						SCSI_SENSE_BUFFERSIZE);
					prm.bufflen = min_t(size_t, prm.bufflen,
						priv->pending_sense_buffer[init_index][7]
							 + 8);
					sg_set_page(&sg,
						virt_to_page(priv->pending_sense_buffer[init_index]),
						prm.bufflen,
						offset_in_page(priv->pending_sense_buffer[init_index]));
					prm.buffer = &sg;
					prm.use_sg = 1;
					prm.data_direction = SCST_DATA_READ;
					prm.tgt = priv->tgt->sess[init_index]->tgt;
					prm.cmd->state = MPT_STATE_DATA_OUT;

					TRACE_DBG("%s: sending pending sense",
							priv->ioc->name);
					mpt_send_target_data(&prm, flags);
					res = 1;
				} else {
					/* we couldn't create a scst_cmd, so
					 * we can't do anything.  Send the
					 * command to SCST. */
					atomic_set(&priv->pending_sense[init_index],
							MPT_STATUS_SENSE_IDLE);
				}
			} else {
				/* next command immediately after check
				 * condition is not REQUEST_SENSE, so we can
				 * discard the cached sense and send the
				 * command to SCST. */
				atomic_set(&priv->pending_sense[init_index],
						MPT_STATUS_SENSE_IDLE);
			}
		} else {
			/* we don't need to perform REQUEST_SENSE and can
			 * send the command to SCST */
			atomic_set(&priv->pending_sense[init_index],
					MPT_STATUS_SENSE_IDLE);
		}
	}

	TRACE_EXIT_RES(res);
	return res;
}

/*
 * this function is equivalent to the SCSI queuecommand(). The target should
 * transmit the response data and the status in the struct scst_cmd. See
 * below for details. Must be defined.
 */
static int mpt_xmit_response(struct scst_cmd *scst_cmd)
{
	int res = SCST_TGT_RES_SUCCESS;
	struct mpt_sess *sess;
	struct mpt_prm prm = { NULL };
	int is_send_status;
	/*uint16_t full_req_cnt;*/
	/*int data_sense_flag = 0;*/

	TRACE_ENTRY();

#ifdef DEBUG_WORK_IN_THREAD
	if (scst_cmd_atomic(scst_cmd))
		return SCST_TGT_RES_NEED_THREAD_CTX;
#endif

	prm.cmd = (struct mpt_cmd *)scst_cmd_get_tgt_priv(scst_cmd);
	sess = (struct mpt_sess *)
		scst_sess_get_tgt_priv(scst_cmd_get_session(scst_cmd));

	prm.sg = NULL;
	prm.bufflen = scst_cmd_get_resp_data_len(scst_cmd);
	prm.buffer = scst_cmd->sg;
	prm.use_sg = scst_cmd->sg_cnt;
	prm.data_direction = scst_cmd_get_data_direction(scst_cmd);
	prm.rq_result = scst_cmd_get_status(scst_cmd);
	prm.sense_buffer = scst_cmd_get_sense_buffer(scst_cmd);
	prm.sense_buffer_len = scst_cmd_get_sense_buffer_len(scst_cmd);
	prm.tgt = sess->tgt;
	prm.seg_cnt = 0;
	is_send_status = scst_cmd_get_is_send_status(scst_cmd);

	TRACE_DBG("rq_result=%x, is_send_status=%x, %x, %d", prm.rq_result,
			is_send_status, prm.bufflen, prm.sense_buffer_len);
	if ((prm.rq_result != 0) && (prm.sense_buffer != NULL))
		TRACE_BUFFER("Sense", prm.sense_buffer, prm.sense_buffer_len);

	if (!is_send_status) {
		/* ToDo, after it's done in SCST */
		PRINT_ERROR(MYNAM ": is_send_status not set: "
			    "feature not implemented %p", scst_cmd);
		res = SCST_TGT_RES_FATAL_ERROR;
		goto out_tgt_free;
	}

	if (test_bit(MPT_SESS_SHUTDOWN, &sess->sess_flags)) {
		TRACE_DBG("cmd %p while session %p is shutting down",
			  prm.cmd, sess);
		res = SCST_TGT_RES_SUCCESS;
		goto out_tgt_free;
	}

	if (scst_sense_valid(prm.sense_buffer)) {
		mpt_set_sense_info(prm.tgt->priv, prm.cmd->CMD,
				prm.sense_buffer_len, prm.sense_buffer);
	}

	if (scst_cmd_get_resp_data_len(scst_cmd) > 0) {
		int flags = 0;

		if (prm.rq_result == 0)
			flags |= TARGET_ASSIST_FLAGS_AUTO_STATUS;
		if (scst_get_may_need_dma_sync(scst_cmd)) {
			dma_sync_sg_for_cpu(&(prm.tgt->priv->ioc->pcidev->dev),
				scst_cmd->sg, scst_cmd->sg_cnt,
				scst_to_tgt_dma_dir(scst_cmd_get_data_direction(scst_cmd)));
		}
		mpt_send_target_data(&prm, flags);

		if (prm.rq_result == 0)
			goto out;
	}
	{
		int flags = 0;
		u32 reply_word = prm.cmd->CMD->reply_word;
		int index = GET_IO_INDEX(reply_word);
		int lun = prm.cmd->CMD->lun;
		int tag = prm.cmd->CMD->tag;
		MPT_STM_PRIV *priv = prm.tgt->priv;

		if (prm.rq_result == 0)
			flags |= TARGET_STATUS_SEND_FLAGS_AUTO_GOOD_STATUS;

		flags |= TARGET_STATUS_SEND_FLAGS_REPOST_CMD_BUFFER;
		priv->io_state[index] |= IO_STATE_AUTO_REPOST;

		TRACE_DBG("scst cmd %p, index %d, flags %d", scst_cmd, index,
			  flags);

		stm_send_target_status(priv, reply_word, index, flags, lun,
				       tag);
	}

out:
	TRACE_EXIT_RES(res);

	return res;

out_tgt_free:
	/* ToDo: check and set scst_set_delivery_status(), if necessary */
	scst_tgt_cmd_done(scst_cmd, SCST_CONTEXT_SAME);
	goto out;
}

/*
 * modifiy the response for an INQUIRY command to turn off
 * support for tagged command queuing if we're on a SCSI bus.
 * It's doubtful that caching sense data will work correctly
 * if tagging is enabled.
 */
static void
mpt_inquiry_no_tagged_commands(MPT_STM_PRIV *priv, struct scst_cmd *scst_cmd)
{
	int32_t length;
	uint8_t *address;

	TRACE_ENTRY();

	/*
	 * only modify INQUIRY if we're on a SCSI bus,
	 * and we are handling a standard INQUIRY command
	 * (EVPD = 0)
	 */
	if (IsScsi(priv) && (scst_cmd->cdb[0] == INQUIRY) &&
			!(scst_cmd->cdb[1] & 0x1)) {
		sBUG_ON(scst_cmd->sg_cnt == 0);
		length = scst_get_buf_first(scst_cmd, &address);
		if (length >= 8) {
			TRACE_DBG("clearing BQUE + CMDQUE 0x%p", address);
			address[6] &= ~0x80; /* turn off BQUE */
			address[7] &= ~0x02; /* turn off CMDQUE */
		}
		scst_put_buf(scst_cmd, address);
	}

	TRACE_EXIT();
}

/*
 * this function
 * informs the driver that data buffer corresponding to the said command
 * have now been allocated and it is OK to receive data for this command.
 * This function is necessary because a SCSI target does not have any
 * control over the commands it receives. Most lower-level protocols have a
 * corresponding function which informs the initiator that buffers have
 * been allocated e.g., XFER_RDY in Fibre Channel. After the data is
 * actually received the low-level driver should call scst_rx_data()
 * in order to continue processing this command. Returns one of the
 * SCST_TGT_RES_* constants, described below. Pay attention to
 * "atomic" attribute of the command, which can be get via
 * scst_cmd_get_atomic(): it is true if the function called in the
 * atomic (non-sleeping) context. Must be defined.
 */
static int mpt_rdy_to_xfer(struct scst_cmd *scst_cmd)
{
	int res = SCST_TGT_RES_SUCCESS;
	struct mpt_sess *sess;
	/*unsigned long flags = 0;*/
	struct mpt_prm prm = { NULL };

	TRACE_ENTRY();

#ifdef DEBUG_WORK_IN_THREAD
	if (scst_cmd_atomic(scst_cmd))
		return SCST_TGT_RES_NEED_THREAD_CTX;
#endif

	prm.cmd = (struct mpt_cmd *)scst_cmd_get_tgt_priv(scst_cmd);
	sess = (struct mpt_sess *)
		scst_sess_get_tgt_priv(scst_cmd_get_session(scst_cmd));
	mpt_inquiry_no_tagged_commands(sess->tgt->priv, scst_cmd);

	prm.sg = (struct scatterlist *)NULL;
	prm.bufflen = scst_cmd->bufflen;
	prm.buffer = scst_cmd->sg;
	prm.use_sg = scst_cmd->sg_cnt;
	prm.data_direction = scst_cmd_get_data_direction(scst_cmd);
	prm.tgt = sess->tgt;

	if (test_bit(MPT_SESS_SHUTDOWN, &sess->sess_flags)) {
		TRACE_DBG("cmd %p while session %p is shutting down",
			  prm.cmd, sess);
		scst_rx_data(scst_cmd, SCST_RX_STATUS_ERROR_FATAL,
			     SCST_CONTEXT_SAME);
		res = SCST_TGT_RES_SUCCESS;
		goto out;
	}

	prm.cmd->state = MPT_STATE_NEED_DATA;

	mpt_send_target_data(&prm, 0);

out:
	TRACE_EXIT_RES(res);

	return res;
}

/*
 * this function
 * called to notify the driver that the command is about to be freed.
 * Necessary, because for aborted commands <bf/xmit_response()/ could not be
 * called. Could be used on IRQ context. Must be defined.
 */
static void mpt_on_free_cmd(struct scst_cmd *scst_cmd)
{
	struct mpt_cmd *cmd =
		(struct mpt_cmd *)scst_cmd_get_tgt_priv(scst_cmd);

	TRACE_ENTRY();

	TRACE_DBG("cmd %p, scst_cmd %p", cmd, scst_cmd);

	scst_cmd_set_tgt_priv(scst_cmd, NULL);

#if 1
	memset(cmd, 0, sizeof(*cmd));
#endif
	kfree(cmd);

	TRACE_EXIT();
}

/*
 * this function informs the driver that a received task management
 * function has been completed. Completion status could be get via
 * scst_mgmt_cmd_get_status(). No return value expected. Must be
 * defined, if the target supports task management functionality.
 */
static void mpt_task_mgmt_fn_done(struct scst_mgmt_cmd *mgmt_cmd)
{
	TRACE_ENTRY();
	WARN_ON(1);
	TRACE_EXIT();
}

static void mpt_local_task_mgmt(struct mpt_sess *sess, int task_mgmt, int lun)
{
	struct mpt_cmd *cmd, *t;

	TRACE_ENTRY();
	switch (task_mgmt) {
	case IMM_NTFY_TARGET_RESET:
		while (!list_empty(&sess->delayed_cmds)) {
			cmd = list_entry(sess->delayed_cmds.next,
					 typeof(*cmd), delayed_cmds_entry);
			list_del(&cmd->delayed_cmds_entry);
			kfree(cmd);
		}
		break;

	case IMM_NTFY_LUN_RESET1:
	case IMM_NTFY_LUN_RESET2:
	case IMM_NTFY_CLEAR_TS:
	case IMM_NTFY_ABORT_TS1:
	case IMM_NTFY_ABORT_TS2:
		list_for_each_entry_safe(cmd, t, &sess->delayed_cmds,
					 delayed_cmds_entry) {
			if (cmd->CMD->lun == lun) {
				list_del(&cmd->delayed_cmds_entry);
				kfree(cmd);
			}
		}
		break;

	case IMM_NTFY_CLEAR_ACA:
	default:
		break;
	}
	TRACE_EXIT();
}

static int mpt_handle_task_mgmt(MPT_STM_PRIV *priv, u32 reply_word,
				int task_mgmt, int _lun)
{
	int res = 0, rc = 0;
	struct mpt_mgmt_cmd *mcmd;
	struct mpt_tgt *tgt;
	struct mpt_sess *sess;
	int init_index;
	uint16_t lun = _lun;

	TRACE_ENTRY();

	TRACE_DBG("task_mgmt %d", task_mgmt);
	tgt = priv->tgt;
	init_index = GET_INITIATOR_INDEX(reply_word);

	sess = tgt->sess[init_index];
	if (sess == NULL) {
		TRACE(TRACE_MGMT, "mpt_scst(%s): task mgmt fn %p for "
		      "unexisting session", priv->ioc->name, tgt);
		res = -EFAULT;
		goto out;
	}

	if (test_bit(MPT_SESS_INITING, &sess->sess_flags)) {
		TRACE(TRACE_MGMT, "mpt_scst(%s): task mgmt fn %p for "
		      "inited session", priv->ioc->name, tgt);
		mpt_local_task_mgmt(sess, reply_word, task_mgmt);
		res = -EFAULT;
		goto out;
	}

	mcmd = kmalloc(sizeof(*mcmd), GFP_ATOMIC);
	TRACE_MEM("kmalloc(GFP_ATOMIC) for mcmd (%zd): %p",
		  sizeof(*mcmd), mcmd);
	if (mcmd == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Allocation of mgmt cmd failed");
		res = -ENOMEM;
		goto out;
	}

	memset(mcmd, 0, sizeof(*mcmd));
	mcmd->sess = sess;
	mcmd->task_mgmt = task_mgmt;

	switch (task_mgmt) {
	case IMM_NTFY_CLEAR_ACA:
		TRACE(TRACE_MGMT, "%s", "IMM_NTFY_CLEAR_ACA received");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_CLEAR_ACA,
					 &lun, sizeof(lun), SCST_ATOMIC, mcmd);
		break;
	case IMM_NTFY_TARGET_RESET:
		TRACE(TRACE_MGMT, "%s", "IMM_NTFY_TARGET_RESET received");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_TARGET_RESET,
					 &lun, sizeof(lun), SCST_ATOMIC, mcmd);
		break;
	case IMM_NTFY_LUN_RESET1:
	case IMM_NTFY_LUN_RESET2:
		TRACE(TRACE_MGMT, "%s", "IMM_NTFY_LUN_RESET received");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_LUN_RESET,
					 &lun, sizeof(lun), SCST_ATOMIC, mcmd);
		break;
	case IMM_NTFY_CLEAR_TS:
		TRACE(TRACE_MGMT, "%s", "IMM_NTFY_CLEAR_TS received");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_CLEAR_TASK_SET,
					 &lun, sizeof(lun), SCST_ATOMIC, mcmd);
		break;

	case IMM_NTFY_ABORT_TS1:
	case IMM_NTFY_ABORT_TS2:
		TRACE(TRACE_MGMT, "%s", "IMM_NTFY_ABORT_TS received");
		rc = scst_rx_mgmt_fn_lun(sess->scst_sess, SCST_ABORT_TASK_SET,
					 &lun, sizeof(lun), SCST_ATOMIC, mcmd);
		break;

	default:
		PRINT_ERROR("mpt_scst(%s): Unknown task mgmt fn 0x%x",
			    priv->ioc->name, task_mgmt);
		break;
	}
	if (rc != 0) {
		PRINT_ERROR("mpt_scst(%s): scst_rx_mgmt_fn_lun() failed: %d",
			    priv->ioc->name, rc);
		res = -EFAULT;
		goto out_free;
	}

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	TRACE_MEM("kmem_cache_free for mcmd %p", mcmd);
	kfree(mcmd);
	goto out;
}



/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *  called when any target mode reply is received
 *  if mf_req is null, then this is a turbo reply; otherwise it's not
 */
static int stm_reply(MPT_ADAPTER *ioc, MPT_FRAME_HDR *mf_req,
		     MPT_FRAME_HDR *mf_rep)
{
	MPT_STM_PRIV	*priv = mpt_stm_priv[ioc->id];
	MPIDefaultReply_t	*rep = (MPIDefaultReply_t *)mf_rep;
	int	ioc_status;

	TRACE_ENTRY();
	if (mf_req == NULL) {
		TRACE_DBG("%s: got turbo reply, reply %x",
			  ioc->name, CAST_PTR_TO_U32(mf_rep));
		/*
		 *  this is a received SCSI command, so go handle it
		 */
		stm_tgt_reply(ioc, CAST_PTR_TO_U32(mf_rep));
		return 0;
	}

#if 0
	if (rep->Function == MPI_FUNCTION_EVENT_NOTIFICATION) {
		/*
		 *  this is an event notification -- do nothing for now
		 *  (this short-cuts the switch() below and avoids the printk)
		 */
		return 0;
	}
#endif
	ioc_status = le16_to_cpu(rep->IOCStatus);

	TRACE_DBG("%s: request %p, reply %p (%02x), %d",
		  ioc->name, mf_req, mf_rep, rep->Function, ioc_status);
	TRACE_DBG("%s: mf index = %d", ioc->name, MF_TO_INDEX(mf_req));

	if (ioc_status & MPI_IOCSTATUS_FLAG_LOG_INFO_AVAILABLE) {
		TRACE_DBG("%s Function = %02x, IOCStatus = %04x, IOCLogInfo = %08x",
			  ioc->name, rep->Function, ioc_status,
			  le32_to_cpu(rep->IOCLogInfo));
	}

	ioc_status &= MPI_IOCSTATUS_MASK;
	switch (rep->Function) {
	case MPI_FUNCTION_CONFIG:
		/*
		 *  this signals that the config is done
		 */
		priv->config_pending = 0;
		memcpy(&priv->config_rep, rep, sizeof(ConfigReply_t));
		/*
		 *  don't free the message frame, since we're remembering it
		 *  in priv->config_mf, and we'll be using it over and over
		 */
		return 0;

	case MPI_FUNCTION_PORT_ENABLE:
		/*
		 *  this signals that the port enable is done
		 */
		priv->port_enable_loginfo = le32_to_cpu(rep->IOCLogInfo);
		priv->port_enable_pending = 0;
		return 1;

	case MPI_FUNCTION_TARGET_CMD_BUFFER_POST:
	case MPI_FUNCTION_TARGET_CMD_BUF_LIST_POST:
		/*
		 *  this is the response to a command buffer post; if status
		 *  is success, then this just acknowledges the posting of a
		 *  command buffer, so do nothing
		 *
		 *  we can also get here for High Priority I/O (such as getting
		 *  a command while not being allowed to disconnect from the SCSI
		 *  bus), and if we're shutting down
		 */
		if (ioc_status == MPI_IOCSTATUS_SUCCESS) {
			TRACE_EXIT();
			return 1;
		}
		if (priv->target_mode_abort_pending &&
		    ioc_status == MPI_IOCSTATUS_TARGET_ABORTED) {
			TRACE_EXIT();
			return 0;
		}
		if (ioc_status == MPI_IOCSTATUS_TARGET_PRIORITY_IO) {
			stm_tgt_reply_high_pri(ioc,
					       (TargetCmdBufferPostErrorReply_t *)rep);
			TRACE_EXIT();
			return 0;
		}
		TRACE_DBG(":%s TargetCmdBufPostReq IOCStatus = %04x",
			  ioc->name, ioc_status);
		if (ioc_status == MPI_IOCSTATUS_INSUFFICIENT_RESOURCES) {
			/*
			 *  this should never happen since we carefully count
			 *  our resources, but if it does, tolerate it -- don't
			 *  repost the errant command buffer, lest we create an
			 *  endless loop
			 */
			WARN_ON(1);
			return 0;
		}
		if (ioc_status == MPI_IOCSTATUS_TARGET_NO_CONNECTION) {
			printk(KERN_ERR MYNAM
			       ": %s: Got MPI_IOCSTATUS_TARGET_NO_CONNECTION\n",
			       ioc->name);
			return 0;
		}
		if (rep->MsgLength > sizeof(*rep)/sizeof(u32)) {
			TRACE_DBG("MsgLength is %d, %zd",
				  rep->MsgLength, sizeof(*rep)/sizeof(u32));
			WARN_ON(1);
			/*
			 *  the TargetCmdBufferPostErrorReply and TargetErrorReply
			 *  structures are nearly identical; the exception is that
			 *  the former does not have a TransferCount field, while
			 *  the latter does; add one
			 */
			((TargetErrorReply_t *)rep)->TransferCount = 0;
			stm_target_reply_error(ioc, (TargetErrorReply_t *)rep);
			return 0;
		}
		WARN_ON(1);
		return 1;

	case MPI_FUNCTION_TARGET_CMD_BUF_BASE_POST:
		/*
		 *  this signals that the command buffer base post is done
		 */
		if (ioc_status != MPI_IOCSTATUS_SUCCESS) {
			printk(KERN_ERR MYNAM ":%s TargetCmdBufPostBaseReq IOCStatus = %04x\n",
			       ioc->name, ioc_status);
		}
		return 1;

	case MPI_FUNCTION_TARGET_ASSIST:
		/*
		 *  this is the response to a target assist command; we should
		 *  only get here if an error occurred
		 *
		 *  at this point we need to clean up the remains of the I/O
		 *  and repost the command buffer
		 */
		if (ioc_status != MPI_IOCSTATUS_SUCCESS) {
			printk(KERN_ERR MYNAM ":%s TargetAssistReq IOCStatus = %04x\n",
			       ioc->name, ioc_status);
		}
		stm_target_reply_error(ioc, (TargetErrorReply_t *)rep);
		return 0;

	case MPI_FUNCTION_TARGET_STATUS_SEND:
		/*
		 *  this is the response to a target status send command; we should
		 *  only get here if an error occurred
		 *
		 *  at this point we need to clean up the remains of the I/O
		 *  and repost the command buffer
		 */
		if (ioc_status != MPI_IOCSTATUS_SUCCESS) {
			/* if this is a MPI_IOCSTATUS_TARGET_STS_DATA_NOT_SENT
			 * and we're SCSI, only print if we're debugging and
			 * tracing.  This is a normal consequence of attempting
			 * to send sense data and status in the same
			 * transaction.
			 */
			if (IsScsi(priv) &&
			    (ioc_status == MPI_IOCSTATUS_TARGET_STS_DATA_NOT_SENT)) {
				TRACE_DBG(MYNAM ":%s TargetStatusSendReq IOCStatus = %04x\n",
					  ioc->name, ioc_status);
			} else {
				printk(KERN_ERR MYNAM ":%s TargetStatusSendReq IOCStatus = %04x\n",
				       ioc->name, ioc_status);
			}
		}
		stm_target_reply_error(ioc, (TargetErrorReply_t *)rep);
		return 0;

	case MPI_FUNCTION_TARGET_MODE_ABORT: {
		TargetModeAbort_t		*req = (TargetModeAbort_t *)mf_req;

		/*
		 *  this signals that the target mode abort is done
		 */
		if (ioc_status != MPI_IOCSTATUS_SUCCESS) {
			printk(KERN_ERR MYNAM ":%s TargetModeAbort IOCStatus = %04x\n",
			       ioc->name, ioc_status);
		}
		if (req->AbortType == TARGET_MODE_ABORT_TYPE_ALL_CMD_BUFFERS) {
			priv->target_mode_abort_pending = 0;
		} else {
			u32		reply_word;
			int		index;
			volatile int	*io_state;

			/*
			 *  a target mode abort has finished, so check to see if
			 *  the I/O was aborted, but there was no error reply for
			 *  that aborted I/O (this will be the case for I/Os that
			 *  have no outstanding target assist or target status send
			 *  at the time of the abort request) -- so pretend that
			 *  the error reply came in with a status indicating that
			 *  the I/O was aborted
			 */
			reply_word = le32_to_cpu(req->ReplyWord);
			index = GET_IO_INDEX(reply_word);
			io_state = priv->io_state + index;
			if ((*io_state & IO_STATE_ABORTED) &&
			    !(*io_state & IO_STATE_DATA_SENT) &&
			    !(*io_state & IO_STATE_STATUS_SENT)) {
				stmapp_target_error(priv, reply_word, index,
						    MPI_IOCSTATUS_TARGET_ABORTED, 0);
			}
			/*
			 *  see if we were trying to abort a target assist or target
			 *  status send, but the abort didn't work (if the abort had
			 *  worked, the flag we're checking would be clear) -- if so,
			 *  just clear the various SRR flags, and wait for the initiator
			 *  to retry the SRR
			 */
			if (*io_state & IO_STATE_REQUEST_ABORTED) {
				printk(KERN_ERR MYNAM ":%s index %d: io_state = %x\n",
				       ioc->name, index, *io_state);
				printk(KERN_ERR MYNAM ":%s   request was not aborted\n",
				       ioc->name);
				*io_state &= ~IO_STATE_REQUEST_ABORTED;
				*io_state &= ~IO_STATE_REISSUE_REQUEST;
				*io_state &= ~IO_STATE_ADJUST_OFFSET;
				*io_state &= ~IO_STATE_CONVERT_TA_TO_TSS;
				*io_state &= ~IO_STATE_REDO_COMMAND;
			}
		}
		TRACE_EXIT_RES(1);
		return 1;
	}

	case MPI_FUNCTION_FC_LINK_SRVC_BUF_POST:
		/*
		 *  if the length is that of a default reply, then this is the
		 *  response to a link service buffer post -- do nothing except
		 *  report errors (none are expected); otherwise this is a
		 *  received ELS, so go handle it
		 */
		if (ioc_status != MPI_IOCSTATUS_SUCCESS) {
			if (priv->link_serv_abort_pending &&
			    ioc_status == MPI_IOCSTATUS_FC_ABORTED) {
				return 0;
			}
			printk(KERN_ERR MYNAM ":%s FcLinkServBufPostReq IOCStatus = %04x\n",
			       ioc->name, ioc_status);
		}
		if (rep->MsgLength > sizeof(*rep)/sizeof(u32)) {
			stm_link_service_reply(ioc,
					       (LinkServiceBufferPostReply_t *)rep);
			return 0;
		}
		return 1;

	case MPI_FUNCTION_FC_LINK_SRVC_RSP:
		/*
		 *  this is the response to a link service send -- repost the
		 *  link service command buffer
		 */
		if (ioc_status != MPI_IOCSTATUS_SUCCESS) {
			printk(KERN_ERR MYNAM ":%s FcLinkServRspReq IOCStatus = %04x\n",
			       ioc->name, ioc_status);
		}
		stm_link_service_rsp_reply(ioc,
					   (LinkServiceRspRequest_t *)mf_req,
					   (LinkServiceRspReply_t *)mf_rep);
		return 1;

	case MPI_FUNCTION_FC_ABORT:
		/*
		 *  this signals that the target mode abort is done
		 */
		if (ioc_status != MPI_IOCSTATUS_SUCCESS) {
			printk(KERN_ERR MYNAM ":%s FcAbort IOCStatus = %04x\n",
			       ioc->name, ioc_status);
		}
		priv->link_serv_abort_pending = 0;
		return 1;

	case MPI_FUNCTION_FC_PRIMITIVE_SEND:
		/*
		 *  this signals that the FC primitive send is done
		 */
		if (ioc_status != MPI_IOCSTATUS_SUCCESS) {
			printk(KERN_ERR MYNAM ":%s FcPrimitiveSend IOCStatus = %04x\n",
			       ioc->name, ioc_status);
		}
		priv->fc_primitive_send_pending = 0;
		return 1;

	case MPI_FUNCTION_FC_EX_LINK_SRVC_SEND:
		/*
		 *  this signals that the extended link service send is done
		 */
		if (ioc_status != MPI_IOCSTATUS_SUCCESS) {
			printk(KERN_ERR MYNAM ":%s ExLinkServiceSend IOCStatus = %04x\n",
			       ioc->name, ioc_status);
		}
		priv->ex_link_service_send_pending = 0;
		return 1;

	default:
		/*
		 *  don't understand this reply, so dump to the screen
		 */
		printk(KERN_ERR MYNAM ":%s got a reply (function %02x) that "
		       "I don't know what to do with\n", ioc->name, rep->Function);
		if (1) {
			u32 *p = (u32 *)mf_req;
			int i;

			for (i = 0; i < 16; i++) {
				printk(KERN_ERR "%s mf_req[%02x] = %08x\n",
				       ioc->name, i * 4, le32_to_cpu(p[i]));
			}
		}
		if (1) {
			u32 *p = (u32 *)mf_rep;
			int i;

			for (i = 0; i < 16; i++) {
				printk(KERN_ERR "%s mf_rep[%02x] = %08x\n",
				       ioc->name, i * 4, le32_to_cpu(p[i]));
			}
		}
		break;
	}
	TRACE_EXIT();
	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void stm_tgt_reply_high_pri(MPT_ADAPTER *ioc,
				   TargetCmdBufferPostErrorReply_t *rep)
{
	MPT_STM_PRIV	*priv = mpt_stm_priv[ioc->id];
	u32			reply_word;
	int			reason;
	int			index;

	TRACE_ENTRY();
	reply_word = le32_to_cpu(rep->ReplyWord);
	reason = rep->PriorityReason;

	index = GET_IO_INDEX(reply_word);

	TRACE_DBG("%s: target reply high priority", ioc->name);
	TRACE_DBG("%s: ReplyWord = %08x, PriorityReason = %02x",
			ioc->name, reply_word, reason);

	priv->io_state[index] |= IO_STATE_HIGH_PRIORITY;
	if (reason == PRIORITY_REASON_NO_DISCONNECT ||
			reason == PRIORITY_REASON_SCSI_TASK_MANAGEMENT) {
		stm_tgt_reply(ioc, reply_word);
		goto out;
	}

	WARN_ON(1);
	if (reason == PRIORITY_REASON_TARGET_BUSY) {
		CMD		*cmd;
		int		lun;
		int		tag;

		priv->io_state[index] &= ~IO_STATE_POSTED;
		cmd = priv->hw->cmd_buf + index;
		if (IsScsi(priv)) {
			SCSI_CMD	*scsi_cmd = (SCSI_CMD *)cmd->cmd;

			lun = get2bytes(scsi_cmd->LogicalUnitNumber, 0);
			tag = scsi_cmd->Tag;
		} else if (IsSas(priv)) {
			SSP_CMD	*ssp_cmd = (SSP_CMD *)cmd->cmd;

			lun = get2bytes(ssp_cmd->LogicalUnitNumber, 0);
			tag = ssp_cmd->InitiatorTag;
		} else {
			FCP_CMD	*fcp_cmd = (FCP_CMD *)cmd->cmd;

			lun = get2bytes(fcp_cmd->FcpLun, 0);
			tag = 0;
		}
		memset(cmd->rsp, 0, sizeof(cmd->rsp));
		stmapp_set_status(priv, cmd, STS_TASK_SET_FULL);
		stm_send_target_status(priv, reply_word, index, 0, lun, tag);
	} else {
		stmapp_target_error(priv, reply_word, index,
				MPI_IOCSTATUS_TARGET_PRIORITY_IO, reason);
	}
out:
	TRACE_EXIT();
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void stm_target_reply_error(MPT_ADAPTER *ioc, TargetErrorReply_t *rep)
{
	MPT_STM_PRIV	*priv = mpt_stm_priv[ioc->id];
	u32			reply_word;
	int			index;
	int			status;
	int			reason;
	volatile int	*io_state;

	TRACE_ENTRY();
	reply_word = le32_to_cpu(rep->ReplyWord);
	status = le16_to_cpu(rep->IOCStatus) & MPI_IOCSTATUS_MASK;

	index = GET_IO_INDEX(reply_word);

	io_state = priv->io_state + index;

	if (status == MPI_IOCSTATUS_TARGET_PRIORITY_IO) {
		reason = rep->PriorityReason;
		*io_state |= IO_STATE_HIGH_PRIORITY;
	} else {
		reason = 0;
	}

	TRACE_DBG("%s: target reply error", ioc->name);
	TRACE_DBG("%s: ReplyWord = %08x, IOCStatus = %04x",
		  ioc->name, reply_word, status);

	if (*io_state & IO_STATE_REQUEST_ABORTED) {
		TRACE_DBG("%s: index %d: io_state = %x",
			  ioc->name, index, *io_state);
		TRACE_DBG("%s:   request was aborted", ioc->name);
		*io_state &= ~IO_STATE_REQUEST_ABORTED;
		if (*io_state & IO_STATE_REISSUE_REQUEST) {
			*io_state &= ~IO_STATE_REISSUE_REQUEST;
			TRACE_DBG("%s:   being reissued", ioc->name);
			if (*io_state & IO_STATE_ADJUST_OFFSET) {
				*io_state &= ~IO_STATE_ADJUST_OFFSET;
				stmapp_srr_adjust_offset(priv, index);
			}
			if (*io_state & IO_STATE_CONVERT_TA_TO_TSS) {
				*io_state &= ~IO_STATE_CONVERT_TA_TO_TSS;
				stmapp_srr_convert_ta_to_tss(priv, index);
				goto out;
			}
			if (*io_state & IO_STATE_REDO_COMMAND) {
				*io_state &= ~IO_STATE_REDO_COMMAND;
				*io_state &= ~IO_STATE_DATA_SENT;
				*io_state &= ~IO_STATE_STATUS_SENT;
				mpt_free_msg_frame(_HANDLE_IOC_ID, priv->current_mf[index]);
				stmapp_tgt_command(priv, reply_word);
				goto out;
			}
			mpt_put_msg_frame(stm_context, _IOC_ID, priv->current_mf[index]);
			goto out;
		}
	}

	stmapp_target_error(priv, reply_word, index, status, reason);
out:
	TRACE_EXIT();
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void stm_target_cleanup(MPT_STM_PRIV *priv, int index)
{
	MPT_ADAPTER	*ioc = priv->ioc;
	volatile int	*io_state;

	TRACE_ENTRY();
	io_state = priv->io_state + index;
	if (*io_state & (IO_STATE_DATA_SENT | IO_STATE_STATUS_SENT)) {
		*io_state &= ~IO_STATE_DATA_SENT;
		*io_state &= ~IO_STATE_STATUS_SENT;
		mpt_free_msg_frame(_HANDLE_IOC_ID, priv->current_mf[index]);
	}
	if (*io_state & IO_STATE_STATUS_DEFERRED) {
		*io_state &= ~IO_STATE_STATUS_DEFERRED;
		mpt_free_msg_frame(_HANDLE_IOC_ID, priv->status_deferred_mf[index]);
	}
	*io_state &= ~IO_STATE_REISSUE_REQUEST;
	*io_state &= ~IO_STATE_ADJUST_OFFSET;
	*io_state &= ~IO_STATE_CONVERT_TA_TO_TSS;
	*io_state &= ~IO_STATE_REDO_COMMAND;
	*io_state &= ~IO_STATE_REQUEST_ABORTED;
	*io_state &= ~IO_STATE_INCOMPLETE;
	/*  *io_state &= ~IO_STATE_AUTO_REPOST;*/
	*io_state &= ~IO_STATE_ABORTED;
	*io_state &= ~IO_STATE_POSTED;
	if ((*io_state & ~IO_STATE_HIGH_PRIORITY) == IO_STATE_AUTO_REPOST)
		*io_state = IO_STATE_POSTED;
	else if ((*io_state & ~IO_STATE_HIGH_PRIORITY) == 0)
		stm_cmd_buf_post(priv, index);
	TRACE_EXIT();
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_event_process(MPT_ADAPTER *ioc, EventNotificationReply_t *rep)
{
	MPT_STM_PRIV		*priv = mpt_stm_priv[ioc->id];
	EventDataScsi_t		*scsi_data;
	EventDataLinkStatus_t	*link_status_data;
	EventDataLoopState_t	*loop_state_data;
	EventDataLogout_t		*logout_data;
	EventDataSasPhyLinkStatus_t *sas_phy_link_status_data;
	int				id;
	int				i;
	int				ioc_status;
	int				event;
	int				rate;

	TRACE_ENTRY();
	if (priv == NULL)
		return 1;

	ioc_status = le16_to_cpu(rep->IOCStatus);
	event = le32_to_cpu(rep->Event);

	if (ioc_status & MPI_IOCSTATUS_FLAG_LOG_INFO_AVAILABLE) {
		printk(KERN_DEBUG "%s Event = %x, IOCLogInfo = %08x\n",
		       ioc->name, event, le32_to_cpu(rep->IOCLogInfo));
	}

	switch (event) {
	case MPI_EVENT_NONE:
	case MPI_EVENT_LOG_DATA:
	case MPI_EVENT_STATE_CHANGE:
	case MPI_EVENT_UNIT_ATTENTION:
	case MPI_EVENT_EVENT_CHANGE:
	case MPI_EVENT_INTEGRATED_RAID:
	case MPI_EVENT_SCSI_DEVICE_STATUS_CHANGE:
	case MPI_EVENT_ON_BUS_TIMER_EXPIRED:
	case MPI_EVENT_QUEUE_FULL:
	case MPI_EVENT_SAS_DEVICE_STATUS_CHANGE:
	case MPI_EVENT_SAS_SES:
	case MPI_EVENT_PERSISTENT_TABLE_FULL:
	case MPI_EVENT_SAS_DISCOVERY_ERROR:
		break;

	case MPI_EVENT_RESCAN:
		printk(KERN_DEBUG "%s Rescan\n", ioc->name);
		break;

	case MPI_EVENT_IOC_BUS_RESET:
		scsi_data = (EventDataScsi_t *)rep->Data;
		printk(KERN_DEBUG "%s IOC Bus Reset on port %d\n",
		       ioc->name, scsi_data->BusPort);
		break;

	case MPI_EVENT_EXT_BUS_RESET:
		scsi_data = (EventDataScsi_t *)rep->Data;
		printk(KERN_DEBUG "%s Ext Bus Reset on port %d\n",
		       ioc->name, scsi_data->BusPort);
		/*
		 * clear any pending sense flags on bus reset
		 */
		if (IsScsi(priv)) {
			for (i = 0; i < NUM_SCSI_DEVICES; i++) {
				atomic_set(&priv->pending_sense[i],
					   MPT_STATUS_SENSE_IDLE);
			}
		}
		break;

	case MPI_EVENT_LINK_STATUS_CHANGE:
		link_status_data = (EventDataLinkStatus_t *)rep->Data;
		printk(KERN_DEBUG "%s Link is now %s\n",
		       ioc->name, link_status_data->State ? "Up" : "Down");
		break;

	case MPI_EVENT_LOGOUT:
		logout_data = (EventDataLogout_t *)rep->Data;
		id = le32_to_cpu(logout_data->NPortID);
		break;

	case MPI_EVENT_LOOP_STATE_CHANGE:
		loop_state_data = (EventDataLoopState_t *)rep->Data;
		if (loop_state_data->Type == MPI_EVENT_LOOP_STATE_CHANGE_LIP) {
			printk(KERN_DEBUG "%s LIP Reset\n", ioc->name);
			break;
		} /* fall-through */

	case MPI_EVENT_SAS_PHY_LINK_STATUS:
		sas_phy_link_status_data = (EventDataSasPhyLinkStatus_t *)rep->Data;
		rate = (sas_phy_link_status_data->LinkRates &
			MPI_EVENT_SAS_PLS_LR_CURRENT_MASK) >>
			MPI_EVENT_SAS_PLS_LR_CURRENT_SHIFT;
		printk(KERN_DEBUG "%s Phy %d Handle %x is now %s\n",
		       ioc->name, sas_phy_link_status_data->PhyNum,
		       le16_to_cpu(sas_phy_link_status_data->DevHandle),
		       rate == MPI_EVENT_SAS_PLS_LR_RATE_UNKNOWN ? "offline" :
		       rate == MPI_EVENT_SAS_PLS_LR_RATE_PHY_DISABLED ? "disabled" :
		       rate == MPI_EVENT_SAS_PLS_LR_RATE_1_5 ? "online at 1.5 Gb" :
		       rate == MPI_EVENT_SAS_PLS_LR_RATE_3_0 ? "online at 3.0 Gb" :
		       "unknown");
		break;

	default:
		printk(KERN_DEBUG "%s event = %d, ack = %d, length = %d\n",
		       ioc->name, le32_to_cpu(rep->Event),
		       rep->AckRequired, le16_to_cpu(rep->EventDataLength));
		for (i = 0; i < le16_to_cpu(rep->EventDataLength); i++) {
			printk(KERN_DEBUG "%s data[%d] = %08x\n",
			       ioc->name, i, le32_to_cpu(rep->Data[i]));
		}
		break;
	}

	if (event == MPI_EVENT_EXT_BUS_RESET) {
#if 0
		if (IsScsi(priv))
			memset(priv->luns->drop, 0, sizeof(priv->luns->drop));
#endif
	}
	TRACE_EXIT();

	return 1;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_reset_process(MPT_ADAPTER *ioc, int phase)
{
	MPT_STM_PRIV	*priv = mpt_stm_priv[ioc->id];
	int			i;

	TRACE_ENTRY();
	if (priv == NULL)
		return 1;

	if (phase == MPT_IOC_PRE_RESET) {
		printk(KERN_ERR MYNAM ":%s IOC will be reset\n",
		       ioc->name);
		priv->in_reset = 1;
		priv->config_pending = 0;
		for (i = 0; i < priv->num_cmd_buffers; i++)
			priv->io_state[i] = 0;
	}

	if (phase == MPT_IOC_POST_RESET) {
		printk(KERN_ERR MYNAM ":%s IOC has been reset, restarting now\n",
		       ioc->name);
		mpt_stm_adapter_online(priv);
	}

	TRACE_EXIT();

	return 1;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void stm_link_service_reply(MPT_ADAPTER *ioc,
				   LinkServiceBufferPostReply_t *rep)
{
	MPT_STM_PRIV	*priv = mpt_stm_priv[ioc->id];
	FC_ELS		*fc_els_buf;
	int			index;
	int			rctl;
	int			type;
	int			sid;
	int			did;
	int			command;
	int			i;
	u32			wwnnh;
	u32			wwnnl;
	u32			wwpnh;
	u32			wwpnl;
	int			ox_id;
	int			rx_id;
	u32			offset;

	TRACE_ENTRY();
	index = le32_to_cpu(rep->TransactionContext);
	fc_els_buf = &priv->hw->fc_link_serv_buf[index];

	rctl =
		(le32_to_cpu(rep->Rctl_Did) & MPI_FC_RCTL_MASK) >> MPI_FC_RCTL_SHIFT;
	type =
		(le32_to_cpu(rep->Type_Fctl) & MPI_FC_TYPE_MASK) >> MPI_FC_TYPE_SHIFT;
	sid =
		(le32_to_cpu(rep->Csctl_Sid) & MPI_FC_SID_MASK) >> MPI_FC_SID_SHIFT;
	did =
		(le32_to_cpu(rep->Rctl_Did) & MPI_FC_DID_MASK) >> MPI_FC_DID_SHIFT;

	wwnnh = le32_to_cpu(rep->Wwn.NodeNameHigh);
	wwnnl = le32_to_cpu(rep->Wwn.NodeNameLow);
	wwpnh = le32_to_cpu(rep->Wwn.PortNameHigh);
	wwpnl = le32_to_cpu(rep->Wwn.PortNameLow);

	ox_id = le16_to_cpu(rep->Oxid);
	rx_id = le16_to_cpu(rep->Rxid);

	/*
	 *  if this is a received PRLI/PRLO, respond by sending our own PRLI/PRLO
	 */
	if (rctl == ELS && type == 0x01) {
		command = (be32_to_cpu(fc_els_buf->fc_els[0]) >> 24) & 0xff;
		switch (command) {
		case PRLI:
			TRACE_DBG("%s: PRLI to %06x from %06x (wwn %08x%08x)",
				  ioc->name, did, sid, wwpnh, wwpnl);
			i = be32_to_cpu(fc_els_buf->fc_els[4]);
			fc_els_buf->fc_els[0] = cpu_to_be32(0x02100014);
			fc_els_buf->fc_els[1] = cpu_to_be32(0x08002100);
			fc_els_buf->fc_els[2] = cpu_to_be32(0x00000000);
			fc_els_buf->fc_els[3] = cpu_to_be32(0x00000000);
			fc_els_buf->fc_els[4] = cpu_to_be32(0x00000012);
			if (priv->fcp2_capable)
				fc_els_buf->fc_els[4] |= cpu_to_be32(0x100);
			priv->els_state[index] = PRLI;
			stm_send_els(priv, rep, index, 20);
			return;

		case PRLO:
			TRACE_DBG("%s: PRLO to %06x from %06x (wwn %08x%08x)",
				  ioc->name, did, sid, wwpnh, wwpnl);
			fc_els_buf->fc_els[0] = cpu_to_be32(0x02100014);
			fc_els_buf->fc_els[1] = cpu_to_be32(0x08000100);
			fc_els_buf->fc_els[2] = cpu_to_be32(0x00000000);
			fc_els_buf->fc_els[3] = cpu_to_be32(0x00000000);
			fc_els_buf->fc_els[4] = cpu_to_be32(0x00000000);
			priv->els_state[index] = PRLO;
			stm_send_els(priv, rep, index, 20);
			return;

		case RSCN:
			TRACE_DBG("%s: RSCN", ioc->name);
			stm_link_serv_buf_post(priv, index);
			return;

		default:
			TRACE_DBG("%s: ELS %02x to %06x from %06x (wwn %08x%08x)",
				  ioc->name, command, did, sid, wwpnh, wwpnl);
			stm_link_serv_buf_post(priv, index);
			return;
		}
	}

	/*
	 *  if this is a received ABTS, respond by aborting the I/O and then
	 *  accepting it
	 */
	if (rctl == ABTS && type == 0x00) {
		TRACE_DBG("%s: ABTS to %06x from %06x (wwn %08x%08x)",
			  ioc->name, did, sid, wwpnh, wwpnl);
		fc_els_buf->fc_els[0] = cpu_to_be32(0x00000000);
		fc_els_buf->fc_els[1] = cpu_to_be32((ox_id << 16) | (rx_id << 0));
		fc_els_buf->fc_els[2] = cpu_to_be32(0x0000ffff);
		rep->Rctl_Did += cpu_to_le32((BA_ACC - ABTS) << MPI_FC_RCTL_SHIFT);
		priv->els_state[index] = ABTS;
		stmapp_abts_process(priv, rx_id, rep, index);
		stm_send_els(priv, rep, index, 12);
		return;
	}

	/*
	 *  if this is a received SRR, respond by aborting any current TargetAssist
	 *  or TargetStatusSend commands, accepting the SRR, and retransmitting the
	 *  requested data or status
	 */
	if (rctl == FC4LS && type == 0x08) {
		priv->els_state[index] = FC4LS;
		command = (be32_to_cpu(fc_els_buf->fc_els[0]) >> 24) & 0xff;
		switch (command) {
		case SRR:
			TRACE_DBG("%s: SRR to %06x from %06x (wwn %08x%08x)",
				  ioc->name, did, sid, wwpnh, wwpnl);
			rx_id = be32_to_cpu(fc_els_buf->fc_els[1]) & 0xffff;
			/*
			 *  if the rx_id is out of range, reject this SRR with
			 *  "invalid OX_ID/RX_ID combination"
			 */
			if (rx_id >= priv->num_cmd_buffers) {
				fc_els_buf->fc_els[0] = cpu_to_be32(0x01000000);
				fc_els_buf->fc_els[1] = cpu_to_be32(0x00090300);
				stm_send_els(priv, rep, index, 8);
				return;
			}
			i = (be32_to_cpu(fc_els_buf->fc_els[3]) >> 24) & 0xff;
			/*
			 *  if the IU to retransmit is not a recognized IU, reject
			 *  this SRR with "logical error"
			 */
			if (i != 1 && i != 5 && i != 7) {
				fc_els_buf->fc_els[0] = cpu_to_be32(0x01000000);
				fc_els_buf->fc_els[1] = cpu_to_be32(0x00030000);
				stm_send_els(priv, rep, index, 8);
				return;
			}
			offset = be32_to_cpu(fc_els_buf->fc_els[2]);
			/*
			 *  go process this SRR further
			 *
			 *  make the call to stm_send_els when any request in progress
			 *  has been aborted
			 *
			 *  note that the address of the LinkServiceBufferPostReply
			 *  that's passed as a parameter to stmapp_abts_process CANNOT
			 *  BE REMEMBERED; its contents must be copied if the call to
			 *  stm_send_els will not be made synchronously
			 */
			stmapp_srr_process(priv, rx_id, i, offset, rep, index);
			return;

		default:
			TRACE_DBG("%s: FC4LS %02x to %06x from %06x (wwn %08x%08x)",
				  ioc->name, command, did, sid, wwpnh, wwpnl);
			/*
			 *  the only FC4LS we recognize is SRR; all others get
			 *  rejected with "command not supported"
			 */
			fc_els_buf->fc_els[0] = cpu_to_be32(0x01000000);
			fc_els_buf->fc_els[1] = cpu_to_be32(0x000b0000);
			stm_send_els(priv, rep, index, 8);
			return;
		}
	}

#ifdef CONFIG_SCST_TRACING
	if (trace_mpi) {
		u32 *p = (u32 *)rep;
		int i;

		for (i = 0; i < 17; i++) {
			TRACE(TRACE_MPI, "%s: fc_els[%02x] = %08x",
			      ioc->name, i * 4, le32_to_cpu(p[i]));
		}
	}
	if (trace_mpi) {
		u32 *p = (u32 *)fc_els_buf;
		int i;

		for (i = 0; i < (int)le32_to_cpu(rep->TransferLength) / 4; i++) {
			TRACE(TRACE_MPI, "%s: fc_els_buf[%02x] = %08x",
			      ioc->name, i * 4, le32_to_cpu(p[i]));
		}
	}
#endif

	stm_link_serv_buf_post(priv, index);
	TRACE_EXIT();
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void stm_link_service_rsp_reply(MPT_ADAPTER *ioc,
				       LinkServiceRspRequest_t *req,
				       LinkServiceRspReply_t *rep)
{
	MPT_STM_PRIV	*priv = mpt_stm_priv[ioc->id];
	MPT_STM_SIMPLE	*sge_simple;
	int			*p_index;
	int			index;
	int			sid;
	int			did;
	int			els;
	int			init_index;

	TRACE_ENTRY();
	sge_simple = (MPT_STM_SIMPLE *)&req->SGL;
	p_index = (int *)(sge_simple + 1);
	index = *p_index;
	els = priv->els_state[index];

	sid = (le32_to_cpu(req->Csctl_Sid) & MPI_FC_SID_MASK) >> MPI_FC_SID_SHIFT;
	did = (le32_to_cpu(req->Rctl_Did) & MPI_FC_DID_MASK) >> MPI_FC_DID_SHIFT;
	init_index = le32_to_cpu(rep->InitiatorIndex);
	/*
	 *  after our link service reponse has been sent, repost the link service
	 *  buffer
	 */
	priv->els_state[index] = 0;
	stm_link_serv_buf_post(priv, index);
	TRACE_EXIT();
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void stm_cmd_buf_post(MPT_STM_PRIV *priv, int index)
{
	MPT_ADAPTER	*ioc = priv->ioc;
	TargetCmdBufferPostRequest_t *req;
	dma_addr_t	dma_addr;

	TRACE_ENTRY();
	if (priv->exiting) {
		priv->io_state[index] |= IO_STATE_POSTED;
		return;
	}

	if (IsSas(priv)) {
		stm_cmd_buf_post_list(priv, index);
		return;
	}

	/*
	 *  get a free message frame, and post a command buffer
	 */
	req = (TargetCmdBufferPostRequest_t *)mpt_msg_frame_alloc(ioc, -1);
	memset(req, 0, sizeof(*req));

#ifdef CMD_BUFFER_POST_FLAGS_HIGH_PRIORITY
	if (priv->io_state[index] & IO_STATE_HIGH_PRIORITY)
		req->BufferPostFlags = CMD_BUFFER_POST_FLAGS_HIGH_PRIORITY;
#else
	priv->io_state[index] &= ~IO_STATE_HIGH_PRIORITY;
#endif

	req->BufferCount = 1;
	req->Function = MPI_FUNCTION_TARGET_CMD_BUFFER_POST;
	req->BufferLength = sizeof(priv->hw->cmd_buf[index].cmd);
	req->Buffer[0].IoIndex = cpu_to_le16(index);
	dma_addr = priv->hw_dma +
		((u8 *)priv->hw->cmd_buf[index].cmd - (u8 *)priv->hw);
	req->Buffer[0].u.PhysicalAddress64.Low = cpu_to_le32(dma_addr);
#if MPT_STM_64_BIT_DMA
	req->Buffer[0].u.PhysicalAddress64.High = cpu_to_le32((u64)dma_addr>>32);
	req->BufferPostFlags = CMD_BUFFER_POST_FLAGS_64_BIT_ADDR;
#endif

	priv->io_state[index] |= IO_STATE_POSTED;

#ifdef CONFIG_SCST_TRACING
	if (trace_mpi) {
		u32 *p = (u32 *)req;
		int i;

		TRACE(TRACE_MPI, "%s: stm_cmd_buf_post %d", ioc->name, index);
		for (i = 0; i < sizeof(*req) / 4; i++) {
			TRACE(TRACE_MPI, "%s: req[%02x] = %08x",
			      ioc->name, i * 4, le32_to_cpu(p[i]));
		}
	}
#endif

	if (priv->io_state[index] & IO_STATE_HIGH_PRIORITY) {
		priv->io_state[index] &= ~IO_STATE_HIGH_PRIORITY;
		mpt_send_handshake_request(stm_context, _IOC_ID,
					   sizeof(*req), (u32 *)req _HS_SLEEP);
	} else {
		mpt_put_msg_frame(stm_context, _IOC_ID, (MPT_FRAME_HDR *)req);
	}

	TRACE_EXIT();
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void stm_cmd_buf_post_base(MPT_STM_PRIV *priv, int post_all)
{
	MPT_ADAPTER				*ioc = priv->ioc;
	TargetCmdBufferPostBaseRequest_t	*req;
	int					i;
	dma_addr_t				dma_addr;

	TRACE_ENTRY();
	req = (TargetCmdBufferPostBaseRequest_t *)mpt_msg_frame_alloc(ioc, -1);
	memset(req, 0, sizeof(*req));

	if (post_all)
		req->BufferPostFlags = CMD_BUFFER_POST_BASE_FLAGS_AUTO_POST_ALL;
	req->Function = MPI_FUNCTION_TARGET_CMD_BUF_BASE_POST;
	req->TotalCmdBuffers = cpu_to_le16(priv->num_cmd_buffers);
	req->CmdBufferLength = cpu_to_le16(sizeof(priv->hw->cmd_buf[0].cmd));
	req->NextCmdBufferOffset = cpu_to_le16(sizeof(priv->hw->cmd_buf[0]));
	dma_addr = priv->hw_dma +
		((u8 *)priv->hw->cmd_buf[0].cmd - (u8 *)priv->hw);
	req->BaseAddressLow = cpu_to_le32(dma_addr);
#if MPT_STM_64_BIT_DMA
	req->BaseAddressHigh = cpu_to_le32((u64)dma_addr>>32);
#endif

	if (post_all)
		for (i = 0; i < priv->num_cmd_buffers; i++)
			priv->io_state[i] |= IO_STATE_POSTED;

#ifdef CONFIG_SCST_TRACING
	if (trace_mpi) {
		u32 *p = (u32 *)req;
		int i;

		TRACE(TRACE_MPI, "%s: stm_cmd_buf_post_base", ioc->name);
		for (i = 0; i < sizeof(*req) / 4; i++) {
			TRACE(TRACE_MPI, "%s: req[%02x] = %08x",
			      ioc->name, i * 4, le32_to_cpu(p[i]));
		}
	}
#endif

	mpt_put_msg_frame(stm_context, _IOC_ID, (MPT_FRAME_HDR *)req);

	TRACE_EXIT();
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void stm_cmd_buf_post_list(MPT_STM_PRIV *priv, int index)
{
	MPT_ADAPTER				*ioc = priv->ioc;
	TargetCmdBufferPostListRequest_t	*req;

	TRACE_ENTRY();
	req = (TargetCmdBufferPostListRequest_t *)mpt_msg_frame_alloc(ioc, -1);
	memset(req, 0, sizeof(*req));

	req->Function = MPI_FUNCTION_TARGET_CMD_BUF_LIST_POST;
	req->CmdBufferCount = cpu_to_le16(1);
	req->IoIndex[0] = cpu_to_le16(index);

	priv->io_state[index] |= IO_STATE_POSTED;

#ifdef CONFIG_SCST_TRACING
	if (trace_mpi) {
		u32 *p = (u32 *)req;
		int i;

		TRACE(TRACE_MPI, "%s: stm_cmd_buf_post_list %d", ioc->name, index);
		for (i = 0; i < sizeof(*req) / 4; i++) {
			TRACE(TRACE_MPI, "%s: req[%02x] = %08x",
			      ioc->name, i * 4, le32_to_cpu(p[i]));
		}
	}
#endif

	mpt_put_msg_frame(stm_context, _IOC_ID, (MPT_FRAME_HDR *)req);
	TRACE_EXIT();
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void stm_link_serv_buf_post(MPT_STM_PRIV *priv, int index)
{
	MPT_ADAPTER				*ioc = priv->ioc;
	LinkServiceBufferPostRequest_t	*req;
	SGETransaction32_t			*sge_trans;
	MPT_STM_SIMPLE			*sge_simple;
	dma_addr_t				dma_addr;

	TRACE_ENTRY();
	req = (LinkServiceBufferPostRequest_t *)mpt_msg_frame_alloc(ioc, -1);
	memset(req, 0, sizeof(*req));

	req->BufferCount = 1;
	req->Function = MPI_FUNCTION_FC_LINK_SRVC_BUF_POST;
	sge_trans = (SGETransaction32_t *)&req->SGL;
	sge_trans->ContextSize = 4;
	sge_trans->DetailsLength = 0;
	sge_trans->Flags = 0;
	sge_trans->TransactionContext[0] = cpu_to_le32(index);
	sge_simple = (MPT_STM_SIMPLE *)&sge_trans->TransactionDetails[0];
	sge_simple->FlagsLength = cpu_to_le32(sizeof(FC_ELS) |
					      MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_SIMPLE_ELEMENT |
								MPI_SGE_FLAGS_LAST_ELEMENT |
								MPI_SGE_FLAGS_END_OF_BUFFER |
								MPI_SGE_FLAGS_END_OF_LIST |
								MPI_SGE_FLAGS_MPT_STM_ADDRESSING |
								MPI_SGE_FLAGS_HOST_TO_IOC));
	dma_addr = priv->hw_dma +
		((u8 *)priv->hw->fc_link_serv_buf[index].fc_els - (u8 *)priv->hw);
	stm_set_dma_addr(sge_simple->Address, dma_addr);

#ifdef CONFIG_SCST_TRACING
	if (trace_mpi) {
		u32 *p = (u32 *)req;
		int i;

		TRACE(TRACE_MPI, "%s: stm_link_serv_buf_post %d", ioc->name, index);
		for (i = 0; i < sizeof(*req) / 4; i++) {
			TRACE(TRACE_MPI, "%s: req[%02x] = %08x",
			      ioc->name, i * 4, le32_to_cpu(p[i]));
		}
	}
#endif
	mpt_put_msg_frame(stm_context, _IOC_ID, (MPT_FRAME_HDR *)req);
	TRACE_EXIT();
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_send_target_status(MPT_STM_PRIV *priv, u32 reply_word, int index,
				  int flags, int lun, int tag)
{
	MPT_ADAPTER			*ioc = priv->ioc;
	TargetStatusSendRequest_t	*req;
	MPT_STM_SIMPLE		*sge_simple;
	CMD				*cmd;
	int				length;
	int				status;
	int				init_index;
	dma_addr_t			dma_addr;

	TRACE_ENTRY();
	req = (TargetStatusSendRequest_t *)mpt_msg_frame_alloc(ioc, index);
	memset(req, 0, sizeof(*req));

	if (priv->exiting) {
		flags &= ~TARGET_ASSIST_FLAGS_REPOST_CMD_BUFFER;
		priv->io_state[index] &= ~IO_STATE_AUTO_REPOST;
	}

	if (priv->io_state[index] & IO_STATE_HIGH_PRIORITY) {
		flags |= TARGET_STATUS_SEND_FLAGS_HIGH_PRIORITY;
		flags |= TARGET_STATUS_SEND_FLAGS_REPOST_CMD_BUFFER;
		priv->io_state[index] |= IO_STATE_AUTO_REPOST;
	}

	if (priv->fcp2_capable/* && priv->initiators != NULL*/) {
		init_index = GET_INITIATOR_INDEX(reply_word);
		/*init = priv->initiators[init_index];
		  if (init != NULL && init->confirm_capable) {
		  flags |= TARGET_STATUS_SEND_FLAGS_CONFIRMED;
		  }*/
	}

	cmd = priv->hw->cmd_buf + index;

	if (flags & TARGET_STATUS_SEND_FLAGS_AUTO_GOOD_STATUS) {
		length = 0;
		req->StatusCode = 0;
	} else {
		length = 0;
		if (IsScsi(priv)) {
			SCSI_RSP	*rsp = (SCSI_RSP *)cmd->rsp;
			size_t sense_size;

			length += sizeof(*rsp);
			length -= sizeof(rsp->SenseData);
			status = rsp->Status;
			if (rsp->Valid & SCSI_SENSE_LEN_VALID) {
				length += be32_to_cpu(rsp->SenseDataListLength);
				init_index = GET_INITIATOR_INDEX(reply_word);
				/*
				 *  try to avoid a SCSI firmware bug by not using Auto Repost
				 *  here, unless required (High Priority requires it)
				 */
				if (!(priv->io_state[index] & IO_STATE_HIGH_PRIORITY)) {
					flags &= ~TARGET_STATUS_SEND_FLAGS_REPOST_CMD_BUFFER;
					priv->io_state[index] &= ~IO_STATE_AUTO_REPOST;
				}
				/*
				 * cache sense buffer so we can send it on the next
				 * REQUEST SENSE command if the IOC can't send the
				 * status and sense simultaneously (generating
				 * MPI_IOCSTATUS_TARGET_STS_DATA_NOT_SENT IOCStatus)
				 */
				sense_size = min(sizeof(rsp->SenseData),
						 (size_t)SCSI_SENSE_BUFFERSIZE);
				TRACE_DBG("caching %zd bytes pending sense", sense_size);
				memcpy(priv->pending_sense_buffer[init_index],
				       rsp->SenseData, sense_size);
				TRACE_BUFFER("priv->pending_sense_buffer",
					     priv->pending_sense_buffer[init_index],
					     sense_size);
				atomic_set(&priv->pending_sense[init_index],
					   MPT_STATUS_SENSE_ATTEMPT);
			}
			if (rsp->Valid & SCSI_RSP_LEN_VALID)
				length += be32_to_cpu(rsp->PktFailuresListLength);
		} else if (IsSas(priv)) {
			SSP_RSP	*rsp = (SSP_RSP *)cmd->rsp;

			length += sizeof(*rsp);
			length -= sizeof(rsp->ResponseSenseData);
			status = rsp->Status;
			if (rsp->DataPres & SSP_SENSE_LEN_VALID)
				length += be32_to_cpu(rsp->SenseDataLength);
			if (rsp->DataPres & SSP_RSP_LEN_VALID)
				length += be32_to_cpu(rsp->ResponseDataLength);
		} else {
			FCP_RSP	*rsp = (FCP_RSP *)cmd->rsp;

			length += sizeof(*rsp);
			length -= sizeof(rsp->FcpSenseData) + sizeof(rsp->FcpResponseData);
			status = rsp->FcpStatus;
			if (flags & TARGET_STATUS_SEND_FLAGS_CONFIRMED)
				rsp->FcpFlags |= FCP_REQUEST_CONFIRM;
			if (rsp->FcpFlags & FCP_SENSE_LEN_VALID)
				length += be32_to_cpu(rsp->FcpSenseLength);
			if (rsp->FcpFlags & FCP_RSP_LEN_VALID) {
				length += be32_to_cpu(rsp->FcpResponseLength);
				/* FCP_RSP_LEN_VALID will only be set for Task Mgmt responses */
				/* and Task Mgmt responses can't be confirmed */
				rsp->FcpFlags &= ~FCP_REQUEST_CONFIRM;
				flags &= ~TARGET_STATUS_SEND_FLAGS_CONFIRMED;
			}
		}
		req->StatusCode = (u8)status;
	}

	req->StatusFlags = (u8)flags;
	req->Function = MPI_FUNCTION_TARGET_STATUS_SEND;
	req->QueueTag = (u16)tag;
	req->ReplyWord = cpu_to_le32(reply_word);
	req->LUN[0] = (u8)(lun >> 8);
	req->LUN[1] = (u8)lun;
	if (length != 0) {
		sge_simple = (MPT_STM_SIMPLE *)&req->StatusDataSGE;
		sge_simple->FlagsLength =
			cpu_to_le32(length |
				MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_SIMPLE_ELEMENT |
						  MPI_SGE_FLAGS_LAST_ELEMENT |
						  MPI_SGE_FLAGS_END_OF_BUFFER |
						  MPI_SGE_FLAGS_END_OF_LIST |
						  MPI_SGE_FLAGS_MPT_STM_ADDRESSING |
						  MPI_SGE_FLAGS_HOST_TO_IOC));
		dma_addr = priv->hw_dma +
			((u8 *)priv->hw->cmd_buf[index].rsp - (u8 *)priv->hw);
		stm_set_dma_addr(sge_simple->Address, dma_addr);
	}

	/*
	 *  there's a limitation here -- if target data is outstanding, we must
	 *  wait for it to finish before we send the target status
	 */
	if (priv->io_state[index] & IO_STATE_DATA_SENT) {
		priv->status_deferred_mf[index] = (MPT_FRAME_HDR *)req;
		priv->io_state[index] |= IO_STATE_STATUS_DEFERRED;
		TRACE_EXIT_RES(1);
		return 1;
	}
	priv->io_state[index] |= IO_STATE_STATUS_SENT;

#ifdef CONFIG_SCST_TRACING
	if (trace_mpi) {
		u32 *p = (u32 *)req;
		int i;

		TRACE(TRACE_MPI, "%s: stm_send_target_status %d",
		      ioc->name, index);
		for (i = 0; i < sizeof(*req) / 4; i++) {
			TRACE(TRACE_MPI, "%s: req[%02x] = %08x",
			      ioc->name, i * 4, le32_to_cpu(p[i]));
		}
	}
#endif

	if (priv->io_state[index] & IO_STATE_HIGH_PRIORITY) {
		mpt_send_handshake_request(stm_context, _IOC_ID,
					   sizeof(*req), (u32 *)req _HS_SLEEP);
	} else {
		mpt_put_msg_frame(stm_context, _IOC_ID, (MPT_FRAME_HDR *)req);
	}
	TRACE_EXIT_RES(1);
	return 1;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void stm_send_els(MPT_STM_PRIV *priv, LinkServiceBufferPostReply_t *rep,
			 int index, int length)
{
	MPT_ADAPTER			*ioc = priv->ioc;
	LinkServiceRspRequest_t	*req;
	MPT_STM_SIMPLE		*sge_simple;
	int				*p_index;
	dma_addr_t			dma_addr;

	TRACE_ENTRY();
	req = (LinkServiceRspRequest_t *)mpt_msg_frame_alloc(ioc, -1);
	memset(req, 0, sizeof(*req));

	req->RspLength = (u8)length;
	req->Function = MPI_FUNCTION_FC_LINK_SRVC_RSP;
	memcpy((u8 *)req + 0x0c, (u8 *)rep + 0x1c, 24);
	sge_simple = (MPT_STM_SIMPLE *)&req->SGL;
	sge_simple->FlagsLength = cpu_to_le32(length |
					      MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_SIMPLE_ELEMENT |
								MPI_SGE_FLAGS_LAST_ELEMENT |
								MPI_SGE_FLAGS_END_OF_BUFFER |
								MPI_SGE_FLAGS_END_OF_LIST |
								MPI_SGE_FLAGS_MPT_STM_ADDRESSING |
								MPI_SGE_FLAGS_HOST_TO_IOC));
	dma_addr = priv->hw_dma +
		((u8 *)priv->hw->fc_link_serv_buf[index].fc_els - (u8 *)priv->hw);
	stm_set_dma_addr(sge_simple->Address, dma_addr);
	p_index = (int *)(sge_simple + 1);
	*p_index = index;

#ifdef CONFIG_SCST_TRACING
	if (trace_mpi) {
		u32 *p = (u32 *)req;
		int i;

		TRACE(TRACE_MPI, "%s: stm_send_els %d", ioc->name, index);
		for (i = 0; i < sizeof(*req) / 4; i++) {
			TRACE(TRACE_MPI, "%s: req[%02x] = %08x",
			      ioc->name, i * 4, le32_to_cpu(p[i]));
		}
	}
#endif
	mpt_put_msg_frame(stm_context, _IOC_ID, (MPT_FRAME_HDR *)req);
	TRACE_EXIT();
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_port_enable(MPT_STM_PRIV *priv)
{
	MPT_ADAPTER		*ioc = priv->ioc;
	PortEnable_t	*req;
	int ret;

	TRACE_ENTRY();
	req = (PortEnable_t *)mpt_msg_frame_alloc(ioc, -1);
	memset(req, 0, sizeof(*req));

	req->Function = MPI_FUNCTION_PORT_ENABLE;

	priv->port_enable_pending = 1;

	mpt_put_msg_frame(stm_context, _IOC_ID, (MPT_FRAME_HDR *)req);

	ret = stm_wait_for(priv, &priv->port_enable_pending, 60, NO_SLEEP);

	TRACE_EXIT_RES(ret);

	return ret;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_target_mode_abort_command(MPT_STM_PRIV *priv, u32 reply_word,
					 int index)
{
	MPT_ADAPTER		*ioc = priv->ioc;
	TargetModeAbort_t	*req;

	TRACE_ENTRY();
	req = (TargetModeAbort_t *)mpt_msg_frame_alloc(ioc, -1);
	memset(req, 0, sizeof(*req));

	req->AbortType = TARGET_MODE_ABORT_TYPE_EXACT_IO;
	req->Function = MPI_FUNCTION_TARGET_MODE_ABORT;
	req->ReplyWord = cpu_to_le32(reply_word);

	priv->io_state[index] |= IO_STATE_ABORTED;

	if (IsScsi(priv)) {
		mpt_send_handshake_request(stm_context, _IOC_ID,
					   sizeof(*req), (u32 *)req _HS_SLEEP);
	} else {
		mpt_put_msg_frame(stm_context, _IOC_ID, (MPT_FRAME_HDR *)req);
	}
	TRACE_EXIT();

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_target_mode_abort_request(MPT_STM_PRIV *priv, u32 reply_word,
					 u32 msg_context, int index)
{
	MPT_ADAPTER		*ioc = priv->ioc;
	TargetModeAbort_t	*req;

	TRACE_ENTRY();
	req = (TargetModeAbort_t *)mpt_msg_frame_alloc(ioc, -1);
	memset(req, 0, sizeof(*req));

	req->AbortType = TARGET_MODE_ABORT_TYPE_EXACT_IO_REQUEST;
	req->Function = MPI_FUNCTION_TARGET_MODE_ABORT;
	req->ReplyWord = cpu_to_le32(reply_word);
	req->MsgContextToAbort = cpu_to_le32(msg_context);

	priv->io_state[index] |= IO_STATE_REQUEST_ABORTED;

	if (IsScsi(priv)) {
		mpt_send_handshake_request(stm_context, _IOC_ID,
					   sizeof(*req), (u32 *)req _HS_SLEEP);
	} else {
		mpt_put_msg_frame(stm_context, _IOC_ID, (MPT_FRAME_HDR *)req);
	}
	TRACE_EXIT();

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_target_mode_abort_all(MPT_STM_PRIV *priv)
{
	MPT_ADAPTER		*ioc = priv->ioc;
	TargetModeAbort_t	*req;
	int ret;
	TRACE_ENTRY();

	req = (TargetModeAbort_t *)mpt_msg_frame_alloc(ioc, -1);
	memset(req, 0, sizeof(*req));

	req->AbortType = TARGET_MODE_ABORT_TYPE_ALL_CMD_BUFFERS;
	req->Function = MPI_FUNCTION_TARGET_MODE_ABORT;

	priv->target_mode_abort_pending = 1;

	if (IsScsi(priv)) {
		mpt_send_handshake_request(stm_context, _IOC_ID,
					   sizeof(*req), (u32 *)req _HS_SLEEP);
	} else {
		mpt_put_msg_frame(stm_context, _IOC_ID, (MPT_FRAME_HDR *)req);
	}

	ret = stm_wait_for(priv, &priv->target_mode_abort_pending, 60,
			   NO_SLEEP);
	TRACE_EXIT_RES(ret);

	return ret;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_target_mode_abort(MPT_STM_PRIV *priv)
{
#ifdef CONFIG_SCST_DEBUG
	MPT_ADAPTER		*ioc = priv->ioc;
#endif
	int			i;
	int			n;

	TRACE_ENTRY();
	while (1) {
		n = 0;
		for (i = 0; i < priv->num_cmd_buffers; i++)
			if (priv->io_state[i] & IO_STATE_AUTO_REPOST)
				n++;

		if (n == 0)
			break;

		TRACE_DBG("%s: %d out of %d commands being auto-reposted, waiting...",
			  ioc->name, n, priv->num_cmd_buffers);
		stm_wait(priv, 10, CAN_SLEEP);
	}

	while (1) {
		stm_target_mode_abort_all(priv);

		n = 0;
		for (i = 0; i < priv->num_cmd_buffers; i++)
			if (priv->io_state[i] & IO_STATE_POSTED)
				n++;

		if (n == priv->num_cmd_buffers)
			break;

		TRACE_DBG("%s: %d out of %d commands still active, waiting...",
			  ioc->name, n, priv->num_cmd_buffers);
		stm_wait(priv, 10, CAN_SLEEP);
	}

	TRACE_EXIT();
	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_link_serv_abort(MPT_STM_PRIV *priv)
{
	MPT_ADAPTER		*ioc = priv->ioc;
	FcAbortRequest_t	*req;
	int ret;

	TRACE_ENTRY();

	req = (FcAbortRequest_t *)mpt_msg_frame_alloc(ioc, -1);
	memset(req, 0, sizeof(*req));

	req->AbortType = FC_ABORT_TYPE_ALL_FC_BUFFERS;
	req->Function = MPI_FUNCTION_FC_ABORT;

	priv->link_serv_abort_pending = 1;

	mpt_put_msg_frame(stm_context, _IOC_ID, (MPT_FRAME_HDR *)req);

	ret = stm_wait_for(priv, &priv->link_serv_abort_pending, 60, NO_SLEEP);

	TRACE_EXIT_RES(ret);

	return ret;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_reset_link(MPT_STM_PRIV *priv)
{
	MPT_ADAPTER			*ioc = priv->ioc;
	FcPrimitiveSendRequest_t	*req;
	int ret;

	TRACE_ENTRY();
	req = (FcPrimitiveSendRequest_t *)mpt_msg_frame_alloc(ioc, -1);
	memset(req, 0, sizeof(*req));

	req->SendFlags = MPI_FC_PRIM_SEND_FLAGS_RESET_LINK;
	req->Function = MPI_FUNCTION_FC_PRIMITIVE_SEND;

	priv->fc_primitive_send_pending = 1;

	mpt_put_msg_frame(stm_context, _IOC_ID, (MPT_FRAME_HDR *)req);

	ret = stm_wait_for(priv, &priv->fc_primitive_send_pending, 60, NO_SLEEP);
	TRACE_EXIT_RES(ret);

	return ret;
}

#if 0
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_login_port(MPT_STM_PRIV *priv, int port_id, int sleep)
{
	MPT_ADAPTER			*ioc = priv->ioc;
	ExLinkServiceSendRequest_t	*req;
	MPT_STM_SIMPLE		*sge_simple;
	u32				*buf;
	int				len, ret;
	dma_addr_t			dma_addr;

	TRACE_ENTRY();
	req = (ExLinkServiceSendRequest_t *)mpt_msg_frame_alloc(ioc, -1);
	memset(req, 0, sizeof(*req));

	req->Function = MPI_FUNCTION_FC_EX_LINK_SRVC_SEND;
	req->MsgFlags_Did = cpu_to_le32(port_id);
	req->ElsCommandCode	= cpu_to_le32(PLOGI);

	len = 29 * 4;
	buf = priv->hw->exlink_buf;
	memset(buf, 0, len);

	buf[0] = cpu_to_be32(PLOGI << 24);
	/*
	 *  the firmware builds the rest of the PLOGI payload
	 */

	sge_simple = (MPT_STM_SIMPLE *)&req->SGL;
	sge_simple->FlagsLength = cpu_to_le32(len |
					      MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_SIMPLE_ELEMENT |
								MPI_SGE_FLAGS_END_OF_BUFFER |
								MPI_SGE_FLAGS_MPT_STM_ADDRESSING |
								MPI_SGE_FLAGS_HOST_TO_IOC));
	dma_addr = priv->hw_dma + ((u8 *)priv->hw->exlink_buf - (u8 *)priv->hw);
	stm_set_dma_addr(sge_simple->Address, dma_addr);
	sge_simple++;
	sge_simple->FlagsLength = cpu_to_le32(len |
					      MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_SIMPLE_ELEMENT |
								MPI_SGE_FLAGS_LAST_ELEMENT |
								MPI_SGE_FLAGS_END_OF_BUFFER |
								MPI_SGE_FLAGS_END_OF_LIST |
								MPI_SGE_FLAGS_MPT_STM_ADDRESSING |
								MPI_SGE_FLAGS_IOC_TO_HOST));
	dma_addr = priv->hw_dma + ((u8 *)priv->hw->exlink_buf - (u8 *)priv->hw);
	stm_set_dma_addr(sge_simple->Address, dma_addr);

	priv->ex_link_service_send_pending = 1;

	mpt_put_msg_frame(stm_context, _IOC_ID, mf);

	if (stm_wait_for(priv, &priv->ex_link_service_send_pending, 5, sleep) < 0)
		return -1;

	req = (ExLinkServiceSendRequest_t *)mpt_msg_frame_alloc(ioc, -1);
	memset(req, 0, sizeof(*req));

	req->Function = MPI_FUNCTION_FC_EX_LINK_SRVC_SEND;
	req->MsgFlags_Did = cpu_to_le32(port_id);
	req->ElsCommandCode	= cpu_to_le32(PRLI);

	len = 5 * 4;
	buf = priv->hw->exlink_buf;
	memset(buf, 0, len);

	buf[0] = cpu_to_be32(0x00100014 | (PRLI << 24));
	buf[1] = cpu_to_be32(0x08002000);
	buf[2] = cpu_to_be32(0x00000000);
	buf[3] = cpu_to_be32(0x00000000);
	buf[4] = cpu_to_be32(0x000000b2);

	sge_simple = (MPT_STM_SIMPLE *)&req->SGL;
	sge_simple->FlagsLength =
		cpu_to_le32(len |
			    MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_SIMPLE_ELEMENT |
					      MPI_SGE_FLAGS_END_OF_BUFFER |
					      MPI_SGE_FLAGS_MPT_STM_ADDRESSING |
					      MPI_SGE_FLAGS_HOST_TO_IOC));
	dma_addr = priv->hw_dma + ((u8 *)priv->hw->exlink_buf - (u8 *)priv->hw);
	stm_set_dma_addr(sge_simple->Address, dma_addr);
	sge_simple++;
	sge_simple->FlagsLength =
		cpu_to_le32(len |
			    MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_SIMPLE_ELEMENT |
					      MPI_SGE_FLAGS_LAST_ELEMENT |
					      MPI_SGE_FLAGS_END_OF_BUFFER |
					      MPI_SGE_FLAGS_END_OF_LIST |
					      MPI_SGE_FLAGS_MPT_STM_ADDRESSING |
					      MPI_SGE_FLAGS_IOC_TO_HOST));
	dma_addr = priv->hw_dma + ((u8 *)priv->hw->exlink_buf - (u8 *)priv->hw);
	stm_set_dma_addr(sge_simple->Address, dma_addr);

	priv->ex_link_service_send_pending = 1;

	mpt_put_msg_frame(stm_context, _IOC_ID, mf);

	ret = stm_wait_for(priv, &priv->ex_link_service_send_pending, 5, sleep);

	TRACE_EXIT_RES(ret);

	return ret;
}

static int stm_logout_port(MPT_STM_PRIV *priv, int port_id, int sleep)
{
	MPT_ADAPTER			*ioc = priv->ioc;
	ExLinkServiceSendRequest_t	*req;
	MPT_STM_SIMPLE		*sge_simple;
	u32				*buf;
	int				len, ret;
	dma_addr_t			dma_addr;

	TRACE_ENTRY();
	req = (ExLinkServiceSendRequest_t *)mpt_msg_frame_alloc(ioc, -1);
	memset(req, 0, sizeof(*req));

	req->Function = MPI_FUNCTION_FC_EX_LINK_SRVC_SEND;
	req->MsgFlags_Did = cpu_to_le32(port_id);
	req->ElsCommandCode	= cpu_to_le32(LOGO);

	len = 4 * 4;
	buf = priv->hw->exlink_buf;
	memset(buf, 0, len);

	buf[0] = cpu_to_be32(LOGO << 24);
	/*
	 *  the firmware builds the rest of the LOGO payload
	 */

	sge_simple = (MPT_STM_SIMPLE *)&req->SGL;
	sge_simple->FlagsLength =
		cpu_to_le32(len |
			    MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_SIMPLE_ELEMENT |
					      MPI_SGE_FLAGS_END_OF_BUFFER |
					      MPI_SGE_FLAGS_MPT_STM_ADDRESSING |
					      MPI_SGE_FLAGS_HOST_TO_IOC));
	dma_addr = priv->hw_dma + ((u8 *)priv->hw->exlink_buf - (u8 *)priv->hw);
	stm_set_dma_addr(sge_simple->Address, dma_addr);
	sge_simple++;
	sge_simple->FlagsLength =
		cpu_to_le32(len |
			    MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_SIMPLE_ELEMENT |
					      MPI_SGE_FLAGS_LAST_ELEMENT |
					      MPI_SGE_FLAGS_END_OF_BUFFER |
					      MPI_SGE_FLAGS_END_OF_LIST |
					      MPI_SGE_FLAGS_MPT_STM_ADDRESSING |
					      MPI_SGE_FLAGS_IOC_TO_HOST));
	dma_addr = priv->hw_dma + ((u8 *)priv->hw->exlink_buf - (u8 *)priv->hw);
	stm_set_dma_addr(sge_simple->Address, dma_addr);

	priv->ex_link_service_send_pending = 1;

	mpt_put_msg_frame(stm_context, _IOC_ID, mf);

	ret = stm_wait_for(priv, &priv->ex_link_service_send_pending, 5, sleep);

	TRACE_EXIT_RES(ret);

	return ret;
}

static int stm_process_logout_port(MPT_STM_PRIV *priv, int port_id, int sleep)
{
	MPT_ADAPTER			*ioc = priv->ioc;
	ExLinkServiceSendRequest_t	*req;
	MPT_STM_SIMPLE		*sge_simple;
	u32				*buf;
	int				len, ret;
	dma_addr_t			dma_addr;

	TRACE_ENTRY();
	req = (ExLinkServiceSendRequest_t *)mpt_msg_frame_alloc(ioc, -1);
	memset(req, 0, sizeof(*req));

	req->Function = MPI_FUNCTION_FC_EX_LINK_SRVC_SEND;
	req->MsgFlags_Did = cpu_to_le32(port_id);
	req->ElsCommandCode	= cpu_to_le32(PRLO);

	len = 5 * 4;
	buf = priv->hw->exlink_buf;
	memset(buf, 0, len);

	buf[0] = cpu_to_be32(0x00100014 | (PRLO << 24));
	buf[1] = cpu_to_be32(0x08002000);
	buf[2] = cpu_to_be32(0x00000000);
	buf[3] = cpu_to_be32(0x00000000);
	buf[4] = cpu_to_be32(0x00000000);

	sge_simple = (MPT_STM_SIMPLE *)&req->SGL;
	sge_simple->FlagsLength =
		cpu_to_le32(len |
			    MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_SIMPLE_ELEMENT |
					      MPI_SGE_FLAGS_END_OF_BUFFER |
					      MPI_SGE_FLAGS_MPT_STM_ADDRESSING |
					      MPI_SGE_FLAGS_HOST_TO_IOC));
	dma_addr = priv->hw_dma + ((u8 *)priv->hw->exlink_buf - (u8 *)priv->hw);
	stm_set_dma_addr(sge_simple->Address, dma_addr);
	sge_simple++;
	sge_simple->FlagsLength =
		cpu_to_le32(len |
			    MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_SIMPLE_ELEMENT |
					      MPI_SGE_FLAGS_LAST_ELEMENT |
					      MPI_SGE_FLAGS_END_OF_BUFFER |
					      MPI_SGE_FLAGS_END_OF_LIST |
					      MPI_SGE_FLAGS_MPT_STM_ADDRESSING |
					      MPI_SGE_FLAGS_IOC_TO_HOST));
	dma_addr = priv->hw_dma + ((u8 *)priv->hw->exlink_buf - (u8 *)priv->hw);
	stm_set_dma_addr(sge_simple->Address, dma_addr);

	priv->ex_link_service_send_pending = 1;

	mpt_put_msg_frame(stm_context, _IOC_ID, mf);

	ret = stm_wait_for(priv, &priv->ex_link_service_send_pending, 5, sleep);

	TRACE_EXIT_RES(ret);

	return ret;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_get_hard_address(MPT_STM_PRIV *priv, int port_id,
				int *hard_address, int sleep)
{
	MPT_ADAPTER			*ioc = priv->ioc;
	ExLinkServiceSendRequest_t	*req;
	MPT_STM_SIMPLE		*sge_simple;
	u32				*buf;
	int				len;
	dma_addr_t			dma_addr;

	TRACE_ENTRY();
	req = (ExLinkServiceSendRequest_t *)mpt_msg_frame_alloc(ioc, -1);
	memset(req, 0, sizeof(*req));

	req->Function = MPI_FUNCTION_FC_EX_LINK_SRVC_SEND;
	req->MsgFlags_Did = cpu_to_le32(port_id);
	req->ElsCommandCode	= cpu_to_le32(ADISC);

	len = 7 * 4;
	buf = priv->hw->exlink_buf;
	memset(buf, 0, len);

	buf[0] = cpu_to_be32(ADISC << 24);
	buf[1] = cpu_to_be32(0x00000000);	/* or get HardALPA from FCPortPage1 */
	buf[2] = cpu_to_be32(priv->wwpn.High);
	buf[3] = cpu_to_be32(priv->wwpn.Low);
	buf[4] = cpu_to_be32(priv->wwnn.High);
	buf[5] = cpu_to_be32(priv->wwnn.Low);
	buf[6] = cpu_to_be32(priv->port_id);

	sge_simple = (MPT_STM_SIMPLE *)&req->SGL;
	sge_simple->FlagsLength =
		cpu_to_le32(len |
			    MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_SIMPLE_ELEMENT |
					      MPI_SGE_FLAGS_END_OF_BUFFER |
					      MPI_SGE_FLAGS_MPT_STM_ADDRESSING |
					      MPI_SGE_FLAGS_HOST_TO_IOC));
	dma_addr = priv->hw_dma + ((u8 *)priv->hw->exlink_buf - (u8 *)priv->hw);
	stm_set_dma_addr(sge_simple->Address, dma_addr);
	sge_simple++;
	sge_simple->FlagsLength =
		cpu_to_le32(len |
			    MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_SIMPLE_ELEMENT |
					      MPI_SGE_FLAGS_LAST_ELEMENT |
					      MPI_SGE_FLAGS_END_OF_BUFFER |
					      MPI_SGE_FLAGS_END_OF_LIST |
					      MPI_SGE_FLAGS_MPT_STM_ADDRESSING |
					      MPI_SGE_FLAGS_IOC_TO_HOST));
	dma_addr = priv->hw_dma + ((u8 *)priv->hw->exlink_buf - (u8 *)priv->hw);
	stm_set_dma_addr(sge_simple->Address, dma_addr);

	priv->ex_link_service_send_pending = 1;

	mpt_put_msg_frame(stm_context, _IOC_ID, mf);

	if (stm_wait_for(priv, &priv->ex_link_service_send_pending, 5, sleep) < 0)
		return -1;

	if ((be32_to_cpu(buf[0]) >> 24) != LS_ACC)
		return -2;

	*hard_address = be32_to_cpu(buf[1]);

	TRACE_EXIT();

	return 0;
}
#endif

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_scsi_configuration(MPT_STM_PRIV *priv, int sleep)
{
#ifdef CONFIG_SCST_DEBUG
	MPT_ADAPTER		*ioc = priv->ioc;
#endif
	SCSIPortPage0_t	*ScsiPort0;
	SCSIPortPage2_t	*ScsiPort2;
	int			cap;
	int			wcap;
	int			ncap;
	int			sync;
	int			flags;
	int			i;

	TRACE_ENTRY();
	memset(priv->hw->config_buf, 0, sizeof(priv->hw->config_buf));
	if (stm_get_config_page(priv, MPI_CONFIG_PAGETYPE_SCSI_PORT, 2, 0, sleep))
		return -1;
	ScsiPort2 = &priv->SCSIPortPage2;
	memcpy(&priv->SCSIPortPage2, priv->hw->config_buf, sizeof(SCSIPortPage2_t));

	TRACE_DBG("%s scsi id is %d", ioc->name, priv->port_id);

	memset(priv->hw->config_buf, 0, sizeof(priv->hw->config_buf));
	if (stm_get_config_page(priv, MPI_CONFIG_PAGETYPE_SCSI_PORT, 0, 0, sleep))
		return -1;
	memcpy(&priv->SCSIPortPage0, priv->hw->config_buf, sizeof(SCSIPortPage0_t));
	ScsiPort0 = &priv->SCSIPortPage0;

	cap = le32_to_cpu(ScsiPort0->Capabilities);
	TRACE_DBG("%s target %d capabilities = %08x",
		  ioc->name, priv->port_id, cap);

	stm_set_scsi_port_page1(priv, sleep);

	wcap = cap & ~MPI_SCSIPORTPAGE0_CAP_MIN_SYNC_PERIOD_MASK;
	ncap = wcap & ~MPI_SCSIPORTPAGE0_CAP_WIDE;

	memset(priv->hw->config_buf, 0, sizeof(priv->hw->config_buf));
	memset(priv->SCSIDevicePage1, 0, sizeof(SCSIDevicePage1_t) * NUM_SCSI_DEVICES);

	for (i = 0; i < NUM_SCSI_DEVICES; i++) {
		int wide = 0;
		SCSIDevicePage1_t *ScsiDevice1 = &priv->SCSIDevicePage1[i];
		sync = ScsiPort2->DeviceSettings[i].SyncFactor;
		if (ioc->facts.FWVersion.Word >= 0x01032900) {
			/* these firmware versions don't send the correct
			 * amount of data except at the slowest transfer
			 * factors */
			sync = max(0x32, sync);
			printk(KERN_ERR "forcing FAST-5 negotiation due to broken fw 0x%08X\n",
			       ioc->facts.FWVersion.Word);
		}
		flags = le16_to_cpu(ScsiPort2->DeviceSettings[i].DeviceFlags);
		if (flags & MPI_SCSIPORTPAGE2_DEVICE_WIDE_DISABLE) {
			cap = ncap;
		} else {
			cap = wcap;
			wide = 1;
		}
		/*cap &= ~MPI_SCSIDEVPAGE1_RP_IU;
		  cap &= ~MPI_SCSIDEVPAGE1_RP_DT;
		  cap &= ~MPI_SCSIDEVPAGE1_RP_QAS;*/
		ScsiDevice1->RequestedParameters = cpu_to_le32(cap | (sync << 8));
		TRACE_DBG("%s initiator %d parameters = %08x, %s %s",
			  ioc->name, i, le32_to_cpu(ScsiDevice1->RequestedParameters),
			  sync ? "SYNC" : " ",
			  wide ? "WIDE" : " ");
		memcpy(priv->hw->config_buf, ScsiDevice1, sizeof(*ScsiDevice1));
		stm_set_config_page(priv, MPI_CONFIG_PAGETYPE_SCSI_DEVICE, 1, i, sleep);
		atomic_set(&priv->pending_sense[i], MPT_STATUS_SENSE_IDLE);
	}
	TRACE_EXIT();

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void stm_set_scsi_port_page1(MPT_STM_PRIV *priv, int sleep)
{
#ifdef CONFIG_SCST_DEBUG
	MPT_ADAPTER		*ioc = priv->ioc;
#endif
	SCSIPortPage1_t *ScsiPort1;
	int i;
	int id = priv->port_id;

	TRACE_ENTRY();

	memset(priv->hw->config_buf, 0, sizeof(priv->hw->config_buf));
	memset(&priv->SCSIPortPage1, 0, sizeof(priv->SCSIPortPage1));
	ScsiPort1 = &priv->SCSIPortPage1;
	ScsiPort1->Configuration = cpu_to_le32(id | (1 << (id + 16)));
	for (i = 1; i <= priv->num_aliases; i++) {
		id = (priv->port_id + i) & 15;
		TRACE_DBG("%s alias %d is target %d",
			  ioc->name, i, id);
		ScsiPort1->Configuration |= cpu_to_le32(1 << (id + 16));
	}
	ScsiPort1->TargetConfig = priv->scsi_port_config;
	ScsiPort1->IDConfig = priv->scsi_id_config;
	memcpy(priv->hw->config_buf, (u32 *)ScsiPort1, sizeof(*ScsiPort1));
	stm_set_config_page(priv, MPI_CONFIG_PAGETYPE_SCSI_PORT, 1, 0, sleep);

	TRACE_EXIT();
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_sas_configuration(MPT_STM_PRIV *priv, int sleep)
{
	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_fc_configuration(MPT_STM_PRIV *priv, int sleep)
{
	MPT_ADAPTER		*ioc = priv->ioc;
	U64			wwnn;
	U64			wwpn;
	int			port_id;
	int			protocol;
	int			flags;
	int			current_speed;
	int			port_state;
	int			target;
	char		*attach;
	char		*speed;
	FCPortPage0_t	*FcPort0;
	FCDevicePage0_t	*FcDevice0;
	int			page;

	TRACE_ENTRY();
	memset(priv->hw->config_buf, 0, sizeof(priv->hw->config_buf));
	if (stm_get_config_page(priv, MPI_CONFIG_PAGETYPE_FC_PORT, 0, 0, sleep))
		return -1;
	FcPort0 = (FCPortPage0_t *)priv->hw->config_buf;
	flags = le32_to_cpu(FcPort0->Flags) &
		MPI_FCPORTPAGE0_FLAGS_ATTACH_TYPE_MASK;
	current_speed = le32_to_cpu(FcPort0->CurrentSpeed);
	port_state = FcPort0->PortState;

	switch (flags) {
	case MPI_FCPORTPAGE0_FLAGS_ATTACH_NO_INIT:
		attach = NULL;
		break;
	case MPI_FCPORTPAGE0_FLAGS_ATTACH_POINT_TO_POINT:
		attach = "point to point";
		break;
	case MPI_FCPORTPAGE0_FLAGS_ATTACH_PRIVATE_LOOP:
		attach = "private loop";
		break;
	case MPI_FCPORTPAGE0_FLAGS_ATTACH_FABRIC_DIRECT:
		attach = "fabric direct attach";
		break;
	case MPI_FCPORTPAGE0_FLAGS_ATTACH_PUBLIC_LOOP:
		attach = "public loop";
		break;
	default:
		attach = "unknown";
		break;
	}

	switch (current_speed) {
	case MPI_FCPORTPAGE0_CURRENT_SPEED_1GBIT:
		speed = "1 Gbaud";
		break;
	case MPI_FCPORTPAGE0_CURRENT_SPEED_2GBIT:
		speed = "2 Gbaud";
		break;
	case MPI_FCPORTPAGE0_CURRENT_SPEED_10GBIT:
		speed = "10 Gbaud";
		break;
	default:
		speed = "unknown";
		break;
	}

	if (priv->port_flags != flags ||
	    priv->port_speed != current_speed ||
	    priv->port_state != port_state) {
		priv->port_flags = flags;
		priv->port_speed = current_speed;
		priv->port_state = port_state;
		priv->device_changed = 1;
		if (attach)
			printk(KERN_INFO "%s link is online, type is %s, speed is %s\n",
			       ioc->name, attach, speed);
		else
			printk(KERN_INFO "%s link is offline\n", ioc->name);
	}

	wwnn.Low = le32_to_cpu(FcPort0->WWNN.Low);
	wwnn.High = le32_to_cpu(FcPort0->WWNN.High);
	wwpn.Low = le32_to_cpu(FcPort0->WWPN.Low);
	wwpn.High = le32_to_cpu(FcPort0->WWPN.High);
	port_id = le32_to_cpu(FcPort0->PortIdentifier);
	protocol = le32_to_cpu(FcPort0->Flags) & MPI_FCPORTPAGE0_FLAGS_PROT_MASK;

	if (priv->wwpn.Low != wwpn.Low ||
	    priv->wwpn.High != wwpn.High ||
	    priv->port_id != port_id) {
		priv->wwnn.Low = wwnn.Low;
		priv->wwnn.High = wwnn.High;
		priv->wwpn.Low = wwpn.Low;
		priv->wwpn.High = wwpn.High;
		priv->port_id = port_id;
		priv->protocol = protocol;
		priv->device_changed = 1;
		if (attach)
			printk(KERN_INFO "%s port is wwn %08x%08x, port id %x\n",
			       ioc->name, wwpn.High, wwpn.Low, port_id);
		else
			printk(KERN_INFO "%s port is wwn %08x%08x\n",
			       ioc->name, wwpn.High, wwpn.Low);
	}

	page = MPI_FC_DEVICE_PAGE0_PGAD_FORM_NEXT_DID + 0xffffff;

	while (1) {
		memset(priv->hw->config_buf, 0, sizeof(priv->hw->config_buf));
		if (stm_get_config_page(priv, MPI_CONFIG_PAGETYPE_FC_DEVICE,
					0, page, sleep)) {
			break;
		}
		FcDevice0 = (FCDevicePage0_t *)priv->hw->config_buf;

		wwnn.Low = le32_to_cpu(FcDevice0->WWNN.Low);
		wwnn.High = le32_to_cpu(FcDevice0->WWNN.High);
		wwpn.Low = le32_to_cpu(FcDevice0->WWPN.Low);
		wwpn.High = le32_to_cpu(FcDevice0->WWPN.High);
		port_id = le32_to_cpu(FcDevice0->PortIdentifier);
		protocol = FcDevice0->Protocol;
		if (FcDevice0->Flags & MPI_FC_DEVICE_PAGE0_FLAGS_TARGETID_BUS_VALID)
			target = FcDevice0->CurrentTargetID;
		else
			target = -1;

#if 0
		printk(KERN_INFO "%s using ADISC to get hard address of port id %x\n",
		       ioc->name, port_id);
		if (stm_get_hard_address(priv, port_id, &i, sleep))
			printk(KERN_ERR "%s ADISC failed!\n", ioc->name);
		else
			printk(KERN_INFO "%s port id's %x hard address is %x\n",
			       ioc->name, port_id, i);
#endif

		page = MPI_FC_DEVICE_PAGE0_PGAD_FORM_NEXT_DID + port_id;

	}
	TRACE_EXIT();

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_fc_enable_els(MPT_STM_PRIV *priv, int els, int sleep)
{
	FCPortPage8_t	*FcPort8;
	TRACE_ENTRY();
	memset(priv->hw->config_buf, 0, sizeof(priv->hw->config_buf));
	if (stm_get_config_page(priv, MPI_CONFIG_PAGETYPE_FC_PORT, 8, 0, sleep))
		return -1;
	FcPort8 = (FCPortPage8_t *)priv->hw->config_buf;
	/* clear the ELS bit */
	FcPort8->BitVector[els / 32] &= ~cpu_to_le32(1 << (els & 31));
	if (stm_set_config_page(priv, MPI_CONFIG_PAGETYPE_FC_PORT, 8, 0, sleep))
		return -1;
	TRACE_EXIT();

	return 0;
}

#if 0
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_fc_enable_immediate_errors(MPT_STM_PRIV *priv, int sleep)
{
	FCPortPage1_t	*FcPort1;

	memset(priv->hw->config_buf, 0, sizeof(priv->hw->config_buf));
	if (stm_get_config_page(priv, MPI_CONFIG_PAGETYPE_FC_PORT, 1, 0, sleep))
		return -1;
	FcPort1 = (FCPortPage1_t *)priv->hw->config_buf;
	/* set the Immediate Error Reply bit */
	FcPort1->Flags |= cpu_to_le32(MPI_FCPORTPAGE1_FLAGS_IMMEDIATE_ERROR_REPLY);
	if (stm_set_config_page(priv, MPI_CONFIG_PAGETYPE_FC_PORT, 1, 0, sleep))
		return -1;

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_fc_enable_target_mode_oxid(MPT_STM_PRIV *priv, int sleep)
{
	FCPortPage1_t	*FcPort1;

	TRACE_ENTRY();
	memset(priv->hw->config_buf, 0, sizeof(priv->hw->config_buf));
	if (stm_get_config_page(priv, MPI_CONFIG_PAGETYPE_FC_PORT, 1, 0, sleep))
		return -1;
	FcPort1 = (FCPortPage1_t *)priv->hw->config_buf;
	/* set the Target Mode OX_ID bit */
	FcPort1->Flags |= cpu_to_le32(MPI_FCPORTPAGE1_FLAGS_TARGET_MODE_OXID);
	if (stm_set_config_page(priv, MPI_CONFIG_PAGETYPE_FC_PORT, 1, 0, sleep))
		return -1;
	TRACE_EXIT();

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_fc_set_wwn(MPT_STM_PRIV *priv, WwnFormat_t *wwn, int sleep)
{
	FCPortPage1_t	*FcPort1;

	TRACE_ENTRY();
	memset(priv->hw->config_buf, 0, sizeof(priv->hw->config_buf));
	if (stm_get_config_page(priv, MPI_CONFIG_PAGETYPE_FC_PORT, 1, 0, sleep))
		return -1;
	FcPort1 = (FCPortPage1_t *)priv->hw->config_buf;
	/* set the WWPN and WWNN */
	FcPort1->NoSEEPROMWWPN.Low = cpu_to_le32(wwn->PortNameLow);
	FcPort1->NoSEEPROMWWPN.High = cpu_to_le32(wwn->PortNameHigh);
	FcPort1->NoSEEPROMWWNN.Low = cpu_to_le32(wwn->NodeNameLow);
	FcPort1->NoSEEPROMWWNN.High = cpu_to_le32(wwn->NodeNameHigh);
	/* set the Ignore SEEPROM WWNs bit */
	FcPort1->Flags |=
		cpu_to_le32(MPI_FCPORTPAGE1_FLAGS_FORCE_USE_NOSEEPROM_WWNS);
	if (stm_set_config_page(priv, MPI_CONFIG_PAGETYPE_FC_PORT, 1, 0, sleep))
		return -1;

	stm_reset_link(priv);
	TRACE_EXIT();
	return 0;
}
#endif

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_fc_enable_aliases(MPT_STM_PRIV *priv, int num_aliases, int sleep)
{
	FCPortPage1_t	*FcPort1;

	TRACE_ENTRY();
	memset(priv->hw->config_buf, 0, sizeof(priv->hw->config_buf));
	if (stm_get_config_page(priv, MPI_CONFIG_PAGETYPE_FC_PORT, 1, 0, sleep))
		return -1;
	FcPort1 = (FCPortPage1_t *)priv->hw->config_buf;
	if (set_aliases_in_fcportpage1) {
		/* set the number of aliases requested */
		FcPort1->NumRequestedAliases = (u8)num_aliases;
	} else {
		/* make sure the value in the page is low enough */
		if (FcPort1->NumRequestedAliases > NUM_ALIASES)
			FcPort1->NumRequestedAliases = NUM_ALIASES;
	}

	if (num_aliases > 0)
		FcPort1->TopologyConfig = MPI_FCPORTPAGE1_TOPOLOGY_NLPORT;
	if (stm_set_config_page(priv, MPI_CONFIG_PAGETYPE_FC_PORT, 1, 0, sleep))
		return -1;
	TRACE_EXIT();
	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_get_config_page(MPT_STM_PRIV *priv, int type, int number,
			       int address, int sleep)
{
	MPT_ADAPTER		*ioc = priv->ioc;
	ConfigReply_t	*rep;
	int			ioc_status;
	int			i;
	int			length;

	TRACE_ENTRY();
	rep = &priv->config_rep;
	memset(rep, 0, sizeof(*rep));

	i = stm_do_config_action(priv, MPI_CONFIG_ACTION_PAGE_HEADER,
				 type, number, address, 0, sleep);
	if (i) {
		if (!priv->in_reset)
			printk(KERN_ERR MYNAM
			       ":%s timed out getting config page header\n", ioc->name);
		return -1;
	}

	if (priv->in_reset) {
		printk(KERN_ERR MYNAM
		       ":%s reset while getting config page header\n", ioc->name);
		return -1;
	}

	ioc_status = le16_to_cpu(rep->IOCStatus) & MPI_IOCSTATUS_MASK;
	if (type > MPI_CONFIG_PAGETYPE_EXTENDED)
		length = le16_to_cpu(rep->ExtPageLength);
	else
		length = rep->Header.PageLength;
	if (ioc_status != MPI_IOCSTATUS_SUCCESS || length == 0) {
		if (ioc_status != MPI_IOCSTATUS_CONFIG_INVALID_PAGE) {
			printk(KERN_ERR MYNAM
			       ":%s failed to get config page header\n", ioc->name);
			printk(KERN_ERR MYNAM
			       ":%s   IOCStatus = %04x, PageLength = %x\n",
			       ioc->name, ioc_status, length);
			printk(KERN_ERR MYNAM
			       ":%s   type = %d, number = %d, address = %x\n",
			       ioc->name, type, number, address);
		}
		return -1;
	}

	i = stm_do_config_action(priv, MPI_CONFIG_ACTION_PAGE_READ_CURRENT,
				 type, number, address, length, sleep);
	if (i) {
		if (!priv->in_reset) {
			printk(KERN_ERR MYNAM
			       ":%s timed out getting config page = %d\n", ioc->name, type);
		}
		return -1;
	}

	if (priv->in_reset) {
		printk(KERN_ERR MYNAM
		       ":%s reset while getting config page\n", ioc->name);
		return -1;
	}

	ioc_status = le16_to_cpu(rep->IOCStatus) & MPI_IOCSTATUS_MASK;
	if (ioc_status != MPI_IOCSTATUS_SUCCESS) {
		if ((type == 6 && number == 0) || (type == 18 && number == 0)) {
			/* no error messages, please! */
		} else {
			printk(KERN_ERR MYNAM
			       ":%s failed to get config page\n", ioc->name);
			printk(KERN_ERR MYNAM
			       ":%s   IOCStatus = %04x, PageLength = %x\n",
			       ioc->name, ioc_status, length);
			printk(KERN_ERR MYNAM
			       ":%s   type = %d, number = %d, address = %x\n",
			       ioc->name, type, number, address);
		}
		return -1;
	}

#ifdef CONFIG_SCST_TRACING
	if (trace_mpi) {
		u32 *p = (u32 *)priv->hw->config_buf;
		int i;

		TRACE(TRACE_MPI, "%s config page %02x/%02x/%08x read",
		      ioc->name, type, number, address);
		for (i = 0; i < length; i++) {
			TRACE(TRACE_MPI, "%s page[%02x] = %08x",
			      ioc->name, i * 4, le32_to_cpu(p[i]));
		}
	}
#endif
	TRACE_EXIT();

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_set_config_page(MPT_STM_PRIV *priv, int type, int number,
			       int address, int sleep)
{
	MPT_ADAPTER		*ioc = priv->ioc;
	ConfigReply_t	*rep;
	int			ioc_status;
	int			i;
	int			length;

	TRACE_ENTRY();
	rep = &priv->config_rep;
	memset(rep, 0, sizeof(*rep));

	i = stm_do_config_action(priv, MPI_CONFIG_ACTION_PAGE_HEADER,
				 type, number, address, 0, sleep);
	if (i) {
		if (!priv->in_reset) {
			printk(KERN_ERR MYNAM
			       ":%s timed out getting config page header\n", ioc->name);
		}
		return -1;
	}

	if (priv->in_reset) {
		printk(KERN_ERR MYNAM
		       ":%s reset while getting config page header\n", ioc->name);
		return -1;
	}

	ioc_status = le16_to_cpu(rep->IOCStatus) & MPI_IOCSTATUS_MASK;
	if (type > MPI_CONFIG_PAGETYPE_EXTENDED)
		length = le16_to_cpu(rep->ExtPageLength);
	else
		length = rep->Header.PageLength;
	if (ioc_status != MPI_IOCSTATUS_SUCCESS || length == 0) {
		if (ioc_status != MPI_IOCSTATUS_CONFIG_INVALID_PAGE) {
			printk(KERN_ERR MYNAM
			       ":%s failed to get config page header\n", ioc->name);
			printk(KERN_ERR MYNAM
			       ":%s   IOCStatus = %04x, PageLength = %x\n",
			       ioc->name, ioc_status, length);
			printk(KERN_ERR MYNAM
			       ":%s   type = %d, number = %d, address = %x\n",
			       ioc->name, type, number, address);
		}
		return -1;
	}

	*(ConfigPageHeader_t *)priv->hw->config_buf = rep->Header;

	i = stm_do_config_action(priv, MPI_CONFIG_ACTION_PAGE_WRITE_CURRENT,
				 type, number, address, length, sleep);
	if (i) {
		if (!priv->in_reset)
			printk(KERN_ERR MYNAM
			       ":%s timed out setting config page\n", ioc->name);
		return -1;
	}

	if (priv->in_reset) {
		printk(KERN_ERR MYNAM
		       ":%s reset while setting config page\n", ioc->name);
		return -1;
	}

	ioc_status = le16_to_cpu(rep->IOCStatus) & MPI_IOCSTATUS_MASK;
	if (ioc_status != MPI_IOCSTATUS_SUCCESS) {
		printk(KERN_ERR MYNAM
		       ":%s failed to set config page\n", ioc->name);
		printk(KERN_ERR MYNAM
		       ":%s   IOCStatus = %04x, PageLength = %x\n",
		       ioc->name, ioc_status, length);
		printk(KERN_ERR MYNAM
		       ":%s   type = %d, number = %d, address = %x\n",
		       ioc->name, type, number, address);
		printk(KERN_ERR MYNAM
		       ":%s   Header = %08x\n",
		       ioc->name, le32_to_cpu(*(u32 *)priv->hw->config_buf));
		return -1;
	}

#ifdef CONFIG_SCST_TRACING
	if (trace_mpi) {
		u32 *p = (u32 *)priv->hw->config_buf;
		int i;

		TRACE(TRACE_MPI, "%s config page %02x/%02x/%08x written",
		      ioc->name, type, number, address);
		for (i = 0; i < length; i++) {
			TRACE(TRACE_MPI, "%s page[%02x] = %08x",
			      ioc->name, i * 4, le32_to_cpu(p[i]));
		}
	}
#endif
	TRACE_EXIT();

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int stm_do_config_action(MPT_STM_PRIV *priv, int action, int type,
				int number, int address, int length, int sleep)
{
	MPT_ADAPTER		*ioc = priv->ioc;
	MPT_FRAME_HDR	*mf;
	Config_t		*req;
	MPT_STM_SIMPLE	*sge_simple;
	dma_addr_t		dma_addr;
	int ret;

	TRACE_ENTRY();
	if (priv->in_reset) {
		printk(KERN_ERR MYNAM ":%s reset while doing config action %x\n",
		       ioc->name, action);
		return -1;
	}

	/*
	 *  get a message frame, and send the config action request
	 */
	mf = priv->config_mf;
	if (mf == NULL) {
		mf = mpt_msg_frame_alloc(ioc, -1);
		if (mf == NULL) {
			printk(KERN_ERR MYNAM
			       ":%s failed to get message frame\n", ioc->name);
			return -1;
		} else {
			TRACE_DBG(
				  "%s in stm_do_config_action, got mf index %d",
				  ioc->name, MF_TO_INDEX(mf));
			priv->config_mf = mf;
		}
	}

	req = (Config_t *)mf;
	memset(req, 0, sizeof(*req));

	req->Function = MPI_FUNCTION_CONFIG;
	req->Action = (u8)action;
	if (action == MPI_CONFIG_ACTION_PAGE_WRITE_CURRENT ||
	    action == MPI_CONFIG_ACTION_PAGE_WRITE_NVRAM) {
		req->Header = *(ConfigPageHeader_t *)priv->hw->config_buf;
	} else {
		if (type > MPI_CONFIG_PAGETYPE_EXTENDED) {
			req->Header.PageType = MPI_CONFIG_PAGETYPE_EXTENDED;
			req->ExtPageType = (u8)type;
			req->ExtPageLength = cpu_to_le16(length);
		} else {
			req->Header.PageType = (u8)type;
		}
		req->Header.PageNumber = (u8)number;
		req->Header.PageLength = (u8)length;
	}
	req->PageAddress = cpu_to_le32(address);
	if (length) {
		sge_simple = (MPT_STM_SIMPLE *)&req->PageBufferSGE;
		sge_simple->FlagsLength = cpu_to_le32((length * 4) |
						      MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_SIMPLE_ELEMENT |
									MPI_SGE_FLAGS_LAST_ELEMENT |
									MPI_SGE_FLAGS_END_OF_BUFFER |
									MPI_SGE_FLAGS_END_OF_LIST |
									MPI_SGE_FLAGS_MPT_STM_ADDRESSING));
		if (action == MPI_CONFIG_ACTION_PAGE_WRITE_CURRENT ||
		    action == MPI_CONFIG_ACTION_PAGE_WRITE_NVRAM) {
			sge_simple->FlagsLength |=
				cpu_to_le32(MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_HOST_TO_IOC));
		}
		dma_addr = priv->hw_dma + ((u8 *)priv->hw->config_buf - (u8 *)priv->hw);
		stm_set_dma_addr(sge_simple->Address, dma_addr);
	}

#if 1
	priv->config_pending = 1;

	mpt_put_msg_frame(stm_context, _IOC_ID, (MPT_FRAME_HDR *)req);

	ret = stm_wait_for(priv, &priv->config_pending, 10, sleep);
#else
	ret = mpt_handshake_req_reply_wait(ioc, sizeof(*req), (u32 *)req,
					   sizeof(priv->config_rep),
					   (u16 *)&priv->config_rep, 10, sleep);
#endif
	TRACE_EXIT_RES(ret);

	return ret;
}

static void stm_wait(MPT_STM_PRIV *priv, int milliseconds, int sleep)
{
	MPT_ADAPTER		*ioc = priv->ioc;

	TRACE_ENTRY();
	if (mpt_GetIocState(ioc, 1) != MPI_IOC_STATE_OPERATIONAL) {
		printk(KERN_ERR MYNAM
		       ":%s IOC is not operational (doorbell = %x)\n",
		       ioc->name, mpt_GetIocState(ioc, 0));
	} else {
		if (sleep == CAN_SLEEP) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(milliseconds);
		} else {
#ifndef __linux__
			if (priv->poll_enabled)
				_mpt_poll(priv->ioc);
#endif
			mdelay(milliseconds);
		}
	}
	TRACE_EXIT();
}

static int
stm_wait_for(MPT_STM_PRIV *priv, volatile int *flag, int seconds, int sleep)
{
	MPT_ADAPTER		*ioc = priv->ioc;
	int			i;

	TRACE_ENTRY();
	for (i = 0; i < seconds * ((sleep == CAN_SLEEP) ? HZ : 1000); i++) {
		if (!(*flag))
			return 0;
		if (mpt_GetIocState(ioc, 1) != MPI_IOC_STATE_OPERATIONAL) {
			printk(KERN_ERR MYNAM
			       ":%s IOC is not operational (doorbell = %x)\n",
			       ioc->name, mpt_GetIocState(ioc, 0));
			return -1;
		}
		if (sleep == CAN_SLEEP) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(1);
		} else {
#ifndef __linux__
			if (priv->poll_enabled)
				_mpt_poll(priv->ioc);
#endif
			mdelay(1);
		}
	}

	/* timed out, so return failure */

	printk(KERN_ERR MYNAM ":%s timed out in stm_wait_for!\n", ioc->name);
	TRACE_EXIT();

	return -1;
}

static int __init _mpt_stm_init(void)
{
	static char function_name[sizeof(__func__)];
	int i;

	TRACE_ENTRY();

	if (function_name[0] == '\0')
		strcpy(function_name, __func__);

	for (i = 0; i < MPT_MAX_ADAPTERS; i++)
		mpt_stm_priv[i] = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	/*
	 * See also patch "mptfusion: Extra debug prints added relavent to
	 * Device missing delay error handling" (commit ID
	 * 213aaca3e5727f3eb56002b04a1405db34a54ed8).
	 */
	stm_context = mpt_register(stm_reply, MPTSTM_DRIVER);
#else
	stm_context = mpt_register(stm_reply, MPTSTM_DRIVER, function_name);
#endif
	if (stm_context < 0) {
		printk(KERN_ERR MYNAM
		       ": failed to register with MPT driver core\n");
		return -EBUSY;
	}

	if (mpt_event_register(stm_context, stm_event_process)) {
		printk(KERN_WARNING MYNAM
		       ": failed to register for event notification\n");
	}

	if (mpt_reset_register(stm_context, stm_reset_process)) {
		printk(KERN_WARNING MYNAM
		       ": failed to register for reset process\n");
	}

	TRACE_DBG(": assigned context of %d", stm_context);

	TRACE_EXIT();

	return 0;
}

static int mpt_stm_adapter_install(MPT_ADAPTER *ioc)
{
	MPT_STM_PRIV		*priv;
	int				max_aliases;

	TRACE_ENTRY();
	priv = kmalloc(sizeof(*priv), GFP_KERNEL);
	if (priv == NULL) {
		printk(KERN_ERR MYNAM
		       ":%s failed to allocate private structure\n", ioc->name);
		return -ENOMEM;
	}
	memset(priv, 0, sizeof(*priv));
	if (ioc->pfacts[0].ProtocolFlags & MPI_PORTFACTS_PROTOCOL_TARGET)
		priv->enable_target_mode = 1;

	priv->ioc = ioc;

	priv->num_sge_chain = ioc->req_sz / sizeof(MPT_STM_SIMPLE);
	priv->num_sge_target_assist = (ioc->req_sz -
				       offsetof(TargetAssistRequest_t, SGL)) / sizeof(MPT_STM_SIMPLE);

	priv->num_cmd_buffers = NUM_CMD_BUFFERS;
	if (priv->num_cmd_buffers > ioc->pfacts[0].MaxPostedCmdBuffers)
		priv->num_cmd_buffers = ioc->pfacts[0].MaxPostedCmdBuffers;
	if (priv->num_cmd_buffers > ioc->req_depth - 16)
		priv->num_cmd_buffers = ioc->req_depth - 16;
	priv->num_els_buffers = NUM_ELS_BUFFERS;

	priv->poll_enabled = 1;

	priv->hw = pci_alloc_consistent(ioc->pcidev, sizeof(*priv->hw),
					&priv->hw_dma);
	if (priv->hw == NULL) {
		printk(KERN_ERR MYNAM
		       ":%s failed to allocate hardware structure\n", ioc->name);
		kfree(priv);
		return -1;
	}
	memset(priv->hw, 0, sizeof(*priv->hw));
	printk(KERN_INFO ":%s priv = %p, priv->hw = %p, priv->hw_dma = %llx\n",
	       ioc->name, priv, priv->hw, (u64)priv->hw_dma);

	mpt_stm_priv[ioc->id] = priv;

	max_aliases = 0;
	if (IsScsi(priv))
		max_aliases = 14;
	if (IsFc(priv)) {
		memset(priv->hw->config_buf, 0, sizeof(priv->hw->config_buf));
		if (!stm_get_config_page(priv, MPI_CONFIG_PAGETYPE_FC_PORT, 0, 0,
					 NO_SLEEP)) {
			max_aliases =
				((FCPortPage0_t *)priv->hw->config_buf)->MaxAliasesSupported;
		}
	}

	if (num_aliases < max_aliases)
		priv->num_aliases = num_aliases;
	else
		priv->num_aliases = max_aliases;

	TRACE_EXIT();

	return 0;
}

static int mpt_stm_adapter_online(MPT_STM_PRIV *priv)
{
	MPT_ADAPTER		*ioc;
	int			i;

	TRACE_ENTRY();
	ioc = priv->ioc;

	priv->fcp2_capable = 0;
#ifdef MPT_STM_ALLOW_FCP2
	switch (ioc->pcidev->device) {
	case MPI_MANUFACTPAGE_DEVICEID_FC919:
	case MPI_MANUFACTPAGE_DEVICEID_FC929:
		if (ioc->facts.FWVersion.Word >= 0x01630002) {
			/* firmware version 1.99.00.02 (and later) is FCP-2 capable */
			priv->fcp2_capable = 1;
		}
		break;
	case MPI_MANUFACTPAGE_DEVICEID_FC919X:
	case MPI_MANUFACTPAGE_DEVICEID_FC929X:
		if (ioc->facts.FWVersion.Word >= 0x01013200) {
			/* firmware version 1.01.50 (and later) is FCP-2 capable */
			priv->fcp2_capable = 1;
		}
		break;
	case MPI_MANUFACTPAGE_DEVICEID_FC939X:
	case MPI_MANUFACTPAGE_DEVICEID_FC949X:
		priv->fcp2_capable = 1;
		break;
	default:
		break;
	}
#endif

	priv->port_enable_pending = 0;
	priv->target_mode_abort_pending = 0;
	priv->link_serv_abort_pending = 0;
	priv->fc_primitive_send_pending = 0;

	priv->config_pending = 0;
	priv->config_mf = NULL;

	priv->port_flags = 0;
	priv->port_speed = 0;

	priv->in_reset = 0;
	priv->poll_enabled = 1;

	for (i = 0; i < priv->num_cmd_buffers; i++)
		priv->io_state[i] = 0;

	if (IsScsi(priv))
		stm_scsi_configuration(priv, NO_SLEEP);

	if (IsSas(priv))
		stm_sas_configuration(priv, NO_SLEEP);

	if (priv->enable_target_mode) {
		if (IsSas(priv)) {
			stm_cmd_buf_post_base(priv, 1);
		} else {
			for (i = 0; i < priv->num_cmd_buffers; i++)
				stm_cmd_buf_post(priv, i);
		}

		if (IsFc(priv)) {
			for (i = 0; i < priv->num_els_buffers; i++)
				stm_link_serv_buf_post(priv, i);

			stm_fc_enable_els(priv, RSCN, NO_SLEEP);

#ifdef STMAPP_VERIFY_OXIDS
			stm_fc_enable_target_mode_oxid(priv, NO_SLEEP);
#endif

			stm_fc_enable_aliases(priv, priv->num_aliases, NO_SLEEP);
		}
	}

	stm_port_enable(priv);

	if (IsFc(priv))
		stm_reset_link(priv);

	if (IsFc(priv)) {
		/* wait up to 5 seconds for the link to come up */
		for (i = 0; i < 50; i++) {
			stm_fc_configuration(priv, NO_SLEEP);
			if (priv->port_flags != MPI_FCPORTPAGE0_FLAGS_ATTACH_NO_INIT)
				break;
			mdelay(100);
		}
	}
	TRACE_EXIT();

	return 0;
}

static void _mpt_stm_exit(void)
{
	TRACE_ENTRY();
	if (stm_context > 0) {
		mpt_reset_deregister(stm_context);
		mpt_event_deregister(stm_context);

		mpt_device_driver_deregister(MPTSTM_DRIVER);

		mpt_deregister(stm_context);
		stm_context = 0;
	}

	TRACE_EXIT();
}

static void mpt_stm_adapter_dispose(MPT_STM_PRIV *priv)
{
	MPT_ADAPTER *ioc;

	TRACE_ENTRY();
	priv->exiting = 1;

	ioc = priv->ioc;

	if (mpt_GetIocState(ioc, 1) == MPI_IOC_STATE_OPERATIONAL) {
		if (priv->enable_target_mode && priv->tgt->target_enable) {
			stm_target_mode_abort(priv);
			if (IsFc(priv))
				stm_link_serv_abort(priv);
		}
	}

	mpt_stm_priv[ioc->id] = NULL;
	if (priv->hw != NULL)
		pci_free_consistent(ioc->pcidev, sizeof(*priv->hw),
				    priv->hw, priv->hw_dma);
	if (priv->config_mf != NULL)
		mpt_free_msg_frame(_HANDLE_IOC_ID, priv->config_mf);
	kfree(priv);

	TRACE_EXIT();
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void stmapp_set_status(MPT_STM_PRIV *priv, CMD *cmd, int status)
{
	TRACE_ENTRY();
	if (IsScsi(priv)) {
		SCSI_RSP *rsp = (SCSI_RSP *)cmd->rsp;

		rsp->Status = (u8)status;
	} else if (IsSas(priv)) {
		SSP_RSP *rsp = (SSP_RSP *)cmd->rsp;

		rsp->Status = (u8)status;
	} else {
		FCP_RSP *rsp = (FCP_RSP *)cmd->rsp;

		rsp->FcpStatus = (u8)status;
	}
	TRACE_EXIT();
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void stmapp_abts_process(MPT_STM_PRIV *priv, int rx_id,
				LinkServiceBufferPostReply_t *rep, int index)
{
#ifdef CONFIG_SCST_DEBUG
	MPT_ADAPTER		*ioc = priv->ioc;
#endif
	volatile int	*io_state;
	CMD			*cmd;

	TRACE_ENTRY();
	io_state = priv->io_state + rx_id;

	if (*io_state & IO_STATE_ABORTED)
		return;

	if (*io_state & IO_STATE_POSTED)
		return;

	cmd = priv->hw->cmd_buf + rx_id;

	TRACE_DBG("%s index %d: io_state = %x",
		  ioc->name, rx_id, *io_state);
	TRACE_DBG("%s reply_word = %x, alias = %d, lun = %d, tag = %x",
		  ioc->name, cmd->reply_word, cmd->alias, cmd->lun, cmd->tag);

	/*
	 *  if we are processing an SRR, there could be some other flags set
	 *  in io_state that we need to get rid of; ABTS overrides SRR
	 */
	*io_state &= ~IO_STATE_REQUEST_ABORTED;
	*io_state &= ~IO_STATE_REISSUE_REQUEST;
	*io_state &= ~IO_STATE_ADJUST_OFFSET;
	*io_state &= ~IO_STATE_CONVERT_TA_TO_TSS;
	*io_state &= ~IO_STATE_REDO_COMMAND;

	/*
	 *  if we get here, the firmware thinks a command is active,
	 *  so it should be aborted
	 */
	TRACE_DBG("%s index %d needs to be aborted", ioc->name, rx_id);
	stm_target_mode_abort_command(priv, cmd->reply_word, rx_id);

	TRACE_EXIT();
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void stmapp_srr_process(MPT_STM_PRIV *priv, int rx_id, int r_ctl,
			       u32 offset, LinkServiceBufferPostReply_t *rep,
			       int index)
{
#ifdef CONFIG_SCST_DEBUG
	MPT_ADAPTER	*ioc = priv->ioc;
#endif
	FC_ELS		*fc_els_buf;
	volatile int	*io_state;
	u32		msg_context;
	CMD		*cmd;
	int		need_abort = 0;
	u32		rel_off;
	u32		dat_len;
	u32		adjust;
	u32		block_size = 512;

	TRACE_ENTRY();
	fc_els_buf = &priv->hw->fc_link_serv_buf[index];
	io_state = priv->io_state + rx_id;

	if (*io_state & IO_STATE_ABORTED) {
		/*
		 *  the initiator wants to continue an I/O that we're aborting;
		 *  just accept this SRR, and continue aborting
		 */
		fc_els_buf->fc_els[0] = cpu_to_be32(0x02000000);
		stm_send_els(priv, rep, index, 4);
		return;
	}

	if (*io_state & IO_STATE_POSTED) {
		/*
		 *  the firmware should prevent this from happening, but if it does,
		 *  reject this SRR with "invalid OX_ID/RX_ID combination"
		 */
		fc_els_buf->fc_els[0] = cpu_to_be32(0x01000000);
		fc_els_buf->fc_els[1] = cpu_to_be32(0x00090300);
		stm_send_els(priv, rep, index, 8);
		return;
	}

	cmd = priv->hw->cmd_buf + rx_id;

	TRACE_DBG("%s index %d: r_ctl = %x, io_state = %x",
		  ioc->name, rx_id, r_ctl, *io_state);
	TRACE_DBG("%s reply_word = %x, alias = %d, lun = %d, tag = %x",
		  ioc->name, cmd->reply_word, cmd->alias, cmd->lun, cmd->tag);

	if (*io_state & (IO_STATE_DATA_SENT | IO_STATE_STATUS_SENT)) {
		/*
		 *  if we get here, the firmware thinks a request is active,
		 *  so it should be aborted
		 */
		TRACE_DBG("%s index %d needs to be aborted",
			  ioc->name, rx_id);
		if (*io_state & IO_STATE_DATA_SENT) {
			TargetAssistRequest_t	*req;

			req = (TargetAssistRequest_t *)priv->current_mf[rx_id];
			msg_context = le32_to_cpu(req->MsgContext);
			rel_off = le32_to_cpu(req->RelativeOffset);
			dat_len = le32_to_cpu(req->DataLength);
			TRACE_DBG("%s SRR offset = %x, TA offset = %x, TA length = %x",
				  ioc->name, offset, rel_off, dat_len);
			if (r_ctl == 1 || r_ctl == 5) {
				if (offset < rel_off && (offset % block_size) == 0) {
					TRACE_DBG("%s request can be reissued",
						  ioc->name);
					adjust = rel_off + dat_len - offset;
					*io_state |= IO_STATE_INCOMPLETE;
					*io_state |= IO_STATE_REDO_COMMAND;
					*io_state |= IO_STATE_REISSUE_REQUEST;
					need_abort = 1;
				}
				if (offset >= rel_off && offset <= rel_off + dat_len) {
					TRACE_DBG("%s request can be reissued",
						  ioc->name);
					if (offset != rel_off) {
						if (offset != rel_off + dat_len) {
							/*cmd->offset = offset;*/
							*io_state |= IO_STATE_ADJUST_OFFSET;
						} else {
							*io_state |= IO_STATE_CONVERT_TA_TO_TSS;
						}
					}
					*io_state |= IO_STATE_REISSUE_REQUEST;
					need_abort = 1;
				}
			} else if (r_ctl == 7) {
				if (*io_state & IO_STATE_STATUS_SENT) {
					TRACE_DBG("%s request can be reissued",
						  ioc->name);
					*io_state |= IO_STATE_CONVERT_TA_TO_TSS;
					*io_state |= IO_STATE_REISSUE_REQUEST;
					need_abort = 1;
				}
				if (*io_state & IO_STATE_STATUS_DEFERRED) {
					TRACE_DBG("%s request can be reissued",
						  ioc->name);
					*io_state |= IO_STATE_REISSUE_REQUEST;
					need_abort = 1;
				}
			} else {
				TRACE_DBG("%s request cannot be reissued",
					  ioc->name);
			}
		} else {
			TargetStatusSendRequest_t	*req;

			req = (TargetStatusSendRequest_t *)priv->current_mf[rx_id];
			msg_context = le32_to_cpu(req->MsgContext);
			if (r_ctl == 7) {
				TRACE_DBG("%s request can be reissued",
					  ioc->name);
				*io_state |= IO_STATE_REISSUE_REQUEST;
				need_abort = 1;
			} else {
				TRACE_DBG("%s request cannot be reissued",
					  ioc->name);
			}
		}
		if (need_abort) {
			stm_target_mode_abort_request(priv, cmd->reply_word, msg_context,
						      rx_id);
		}
	}

	if (*io_state & IO_STATE_REISSUE_REQUEST) {
		/*
		 *  if we can continue this I/O, accept this SRR
		 */
		fc_els_buf->fc_els[0] = cpu_to_be32(0x02000000);
		stm_send_els(priv, rep, index, 4);
	} else {
		/*
		 *  we can't continue the I/O, so reject this SRR with "unable to
		 *  supply requested data"
		 */
		fc_els_buf->fc_els[0] = cpu_to_be32(0x01000000);
		fc_els_buf->fc_els[1] = cpu_to_be32(0x00092a00);
		stm_send_els(priv, rep, index, 8);
	}
	TRACE_EXIT();
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void stmapp_srr_convert_ta_to_tss(MPT_STM_PRIV *priv, int index)
{
	MPT_ADAPTER		*ioc = priv->ioc;
	volatile int	*io_state;
	CMD			*cmd;
	u32			reply_word;
	int			lun;
	int			tag;
	int			flags;

	TRACE_ENTRY();
	io_state = priv->io_state + index;

	cmd = priv->hw->cmd_buf + index;

	reply_word = cmd->reply_word;
	lun = cmd->lun;
	tag = cmd->tag;

	*io_state &= ~IO_STATE_DATA_SENT;
	*io_state &= ~IO_STATE_STATUS_SENT;
	mpt_free_msg_frame(_HANDLE_IOC_ID, priv->current_mf[index]);

	flags = TARGET_STATUS_SEND_FLAGS_AUTO_GOOD_STATUS;
	if (*io_state & IO_STATE_AUTO_REPOST)
		flags |= TARGET_STATUS_SEND_FLAGS_REPOST_CMD_BUFFER;
	stm_send_target_status(priv, reply_word, index, flags, lun, tag);
	TRACE_EXIT();
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void stmapp_srr_adjust_offset(MPT_STM_PRIV *priv, int index)
{
	CMD				*cmd;
	TargetAssistRequest_t	*req;
	u32				old_offset;
	u32				new_offset = 0;
	u32				offset;
	MPT_STM_SIMPLE		*sge_simple;
	MPT_STM_CHAIN		*sge_chain = NULL;
	u32				flags_length;
	int				type;
	int				old_length;
	int				new_length;
	int				length;
	dma_addr_t			dma_addr;
	int				n;

	TRACE_ENTRY();
	cmd = priv->hw->cmd_buf + index;
	req = (TargetAssistRequest_t *)priv->current_mf[index];

	old_offset = le32_to_cpu(req->RelativeOffset);

	/* walk the SGL, skipping along until we get to the right offset */
	offset = old_offset;
	sge_simple = (MPT_STM_SIMPLE *)&req->SGL;
	n = 0;
	while (1) {
		flags_length = le32_to_cpu(sge_simple->FlagsLength);
		type = MPI_SGE_GET_FLAGS(flags_length) & MPI_SGE_FLAGS_ELEMENT_MASK;
		if (type == MPI_SGE_FLAGS_CHAIN_ELEMENT) {
			if (sge_chain == NULL) {
				sge_chain = (MPT_STM_CHAIN *)sge_simple;
				stm_get_dma_addr(dma_addr, sge_chain->Address);
				sge_simple = (MPT_STM_SIMPLE *)
					((u8 *)priv->hw + (dma_addr - priv->hw_dma));
			} else {
				sge_chain = (MPT_STM_CHAIN *)sge_simple;
				sge_simple = (MPT_STM_SIMPLE *)(sge_chain + 1);
			}
			n = 0;
		} else {
			length = MPI_SGE_LENGTH(flags_length);
			if (offset + length > new_offset)
				break;
			offset += length;
			sge_simple++;
			n++;
		}
	}

	/* fix up the current SGE */
	flags_length -= new_offset - offset;
	sge_simple->FlagsLength = le32_to_cpu(flags_length);
	stm_get_dma_addr(dma_addr, sge_simple->Address);
	dma_addr += new_offset - offset;
	stm_set_dma_addr(sge_simple->Address, dma_addr);

	/* if we have skipped any SGEs, we need to use a chain to point to */
	/* the new "first" SGE */
	if (sge_simple != (MPT_STM_SIMPLE *)&req->SGL) {
		/* see if we've already walked past a chain */
		if (sge_chain == NULL) {
			/* all we have to do here is move the SGEs in the request frame */
			memmove(&req->SGL, sge_simple,
				(priv->num_sge_target_assist - n) *
				sizeof(MPT_STM_SIMPLE));
			if (req->ChainOffset != 0)
				req->ChainOffset -= n * sizeof(MPT_STM_SIMPLE) / sizeof(u32);
		} else {
			/* we have to build a chain on top of the first SGE */
			length = le16_to_cpu(sge_chain->Length) -
				n * sizeof(MPT_STM_SIMPLE);
			offset = sge_chain->NextChainOffset;
			sge_chain = (MPT_STM_CHAIN *)&req->SGL;
			sge_chain->Length = cpu_to_le16(length);
			sge_chain->NextChainOffset = (u8)offset;
			sge_chain->Flags =
				(u8)(MPI_SGE_FLAGS_CHAIN_ELEMENT |
				     MPI_SGE_FLAGS_MPT_STM_ADDRESSING);
			dma_addr = priv->hw_dma + ((u8 *)sge_simple - (u8 *)priv->hw);
			stm_set_dma_addr(sge_chain->Address, dma_addr);
			req->ChainOffset = (u32 *)sge_chain - (u32 *)req;
		}
	}

	/* fix up the offset and length */
	old_length = le32_to_cpu(req->DataLength);
	new_length = old_length - (new_offset - old_offset);

	req->RelativeOffset = cpu_to_le32(new_offset);
	req->DataLength = cpu_to_le32(new_length);
	TRACE_EXIT();
}

static void stmapp_target_error_prioprity_io(MPT_STM_PRIV *priv, u32 reply_word,
					     int index, int status, int reason,
					     int lun, int tag)
{
	MPT_ADAPTER		*ioc = priv->ioc;
	struct mpt_cmd *mpt_cmd;
	struct scst_cmd *scst_cmd;
	volatile int	*io_state;
	CMD			*cmd;

	/*
	 *  we want stm_target_cleanup to do everything except repost the
	 *  command buffer, so fake it out a bit
	 */
	TRACE_ENTRY();
	io_state = priv->io_state + index;
	*io_state |= IO_STATE_AUTO_REPOST;
	scst_cmd = priv->scst_cmd[index];
	mpt_cmd = (struct mpt_cmd *)scst_cmd_get_tgt_priv(scst_cmd);
	mpt_cmd->state = MPT_STATE_PROCESSED;

	stm_target_cleanup(priv, index);
	*io_state = IO_STATE_HIGH_PRIORITY;
	printk(KERN_ERR MYNAM ": HIGH_PRIORITY %s\n", __func__);

	cmd = priv->hw->cmd_buf + index;
	memset(cmd->rsp, 0, sizeof(cmd->rsp));

	switch (reason) {
	case PRIORITY_REASON_CMD_PARITY_ERR:
		printk(KERN_ERR MYNAM ":%s "
		       "detected parity error during Command phase\n",
		       ioc->name);
		stmapp_set_sense_info(priv, cmd,
				      SK_ABORTED_COMMAND, 0x47, 0x00);
		break;
	case PRIORITY_REASON_MSG_OUT_PARITY_ERR:
		printk(KERN_ERR MYNAM ":%s "
		       "detected parity error during Message Out phase\n",
		       ioc->name);
		stmapp_set_sense_info(priv, cmd,
				      SK_ABORTED_COMMAND, 0x43, 0x00);
		break;
	case PRIORITY_REASON_CMD_CRC_ERR:
		printk(KERN_ERR MYNAM ":%s "
		       "detected CRC error while receiving CMD_IU\n",
		       ioc->name);
		stmapp_set_sense_info(priv, cmd,
				      SK_ABORTED_COMMAND, 0x47, 0x03);
		break;
	case PRIORITY_REASON_PROTOCOL_ERR:
		printk(KERN_ERR MYNAM ":%s "
		       "received Initiator Detected Error message\n",
		       ioc->name);
		stmapp_set_sense_info(priv, cmd,
				      SK_ABORTED_COMMAND, 0x48, 0x00);
		break;
	case PRIORITY_REASON_DATA_OUT_PARITY_ERR:
		printk(KERN_ERR MYNAM ":%s "
		       "detected parity error during Data Out phase\n",
		       ioc->name);
		stmapp_set_sense_info(priv, cmd,
				      SK_ABORTED_COMMAND, 0x47, 0x02);
		break;
	case PRIORITY_REASON_DATA_OUT_CRC_ERR:
		printk(KERN_ERR MYNAM ":%s "
		       "detected CRC error during Data Out phase\n",
		       ioc->name);
		stmapp_set_sense_info(priv, cmd,
				      SK_ABORTED_COMMAND, 0x47, 0x01);
		break;
	default:
		printk(KERN_ERR MYNAM ":%s unknown PriorityReason = %x\n",
		       ioc->name, reason);
		stmapp_set_sense_info(priv, cmd,
				      SK_ABORTED_COMMAND, 0x00, 0x00);
	}

	stm_send_target_status(priv, reply_word, index, 0, lun, tag);

	TRACE_EXIT();
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void stmapp_target_error(MPT_STM_PRIV *priv, u32 reply_word, int index,
				int status, int reason)
{
	MPT_ADAPTER		*ioc = priv->ioc;
	volatile int	*io_state;
	CMD			*cmd;
	int			lun = 0;
	int			tag = 0;
	int			init_index = 0;

	TRACE_ENTRY();
	TRACE_DBG("%s target error, index %d, status %x, reason %x",
		  ioc->name, index, status, reason);

	io_state = priv->io_state + index;
	init_index = GET_INITIATOR_INDEX(reply_word);

	if (*io_state & IO_STATE_DATA_SENT) {
		TargetAssistRequest_t	*req;

		req = (TargetAssistRequest_t *)priv->current_mf[index];
		lun = get2bytes(req->LUN, 0);
		tag = req->QueueTag;
	}

	if (*io_state & IO_STATE_STATUS_SENT) {
		TargetStatusSendRequest_t	*req;

		req = (TargetStatusSendRequest_t *)priv->current_mf[index];
		lun = get2bytes(req->LUN, 0);
		tag = req->QueueTag;
	}

	/*
	 *  if the status is Target Priority I/O, the I/O is still
	 *  active and a response is needed
	 */
	if (status == MPI_IOCSTATUS_TARGET_PRIORITY_IO) {
		stmapp_target_error_prioprity_io(priv, reply_word, index, status,
						 reason, lun, tag);
		return;
	}

	/*
	 *  if the status is Target Transfer Count Mismatch, Target Data Offset
	 *  Error, Target Too Much Write Data, Target IU Too Short, EEDP Guard
	 *  Error, EEDP Reference Tag Error, or EEDP Application Tag Error, thes
	 *  I/O is still active and a response is needed
	 */
	if (status == MPI_IOCSTATUS_TARGET_XFER_COUNT_MISMATCH ||
	    status == MPI_IOCSTATUS_TARGET_DATA_OFFSET_ERROR   ||
	    status == MPI_IOCSTATUS_TARGET_TOO_MUCH_WRITE_DATA ||
	    status == MPI_IOCSTATUS_TARGET_IU_TOO_SHORT ||
	    status == MPI_IOCSTATUS_EEDP_GUARD_ERROR ||
	    status == MPI_IOCSTATUS_EEDP_REF_TAG_ERROR ||
	    status == MPI_IOCSTATUS_EEDP_APP_TAG_ERROR) {
		/*
		 *  we want stm_target_cleanup to do everything except repost the
		 *  command buffer, so fake it out a bit
		 */
		*io_state |= IO_STATE_AUTO_REPOST;
		stm_target_cleanup(priv, index);
		*io_state = 0;

		cmd = priv->hw->cmd_buf + index;
		memset(cmd->rsp, 0, sizeof(cmd->rsp));

		switch (status) {
		case MPI_IOCSTATUS_TARGET_XFER_COUNT_MISMATCH:
			printk(KERN_ERR MYNAM ":%s transfer count mismatch\n",
			       ioc->name);
			stmapp_set_sense_info(priv, cmd,
					      SK_ABORTED_COMMAND, 0x4b, 0x00);
			break;
		case MPI_IOCSTATUS_TARGET_DATA_OFFSET_ERROR:
			printk(KERN_ERR MYNAM ":%s data offset error\n",
			       ioc->name);
			stmapp_set_sense_info(priv, cmd,
					      SK_ABORTED_COMMAND, 0x4b, 0x05);
			break;
		case MPI_IOCSTATUS_TARGET_TOO_MUCH_WRITE_DATA:
			printk(KERN_ERR MYNAM ":%s too much write data\n",
			       ioc->name);
			stmapp_set_sense_info(priv, cmd,
					      SK_ABORTED_COMMAND, 0x4b, 0x02);
			break;
		case MPI_IOCSTATUS_TARGET_IU_TOO_SHORT:
			printk(KERN_ERR MYNAM ":%s IU too short\n",
			       ioc->name);
			stmapp_set_sense_info(priv, cmd,
					      SK_ABORTED_COMMAND, 0x0e, 0x01);
			break;
		case MPI_IOCSTATUS_EEDP_GUARD_ERROR:
			printk(KERN_ERR MYNAM ":%s EEDP Guard Error\n",
			       ioc->name);
			stmapp_set_sense_info(priv, cmd,
					      SK_ABORTED_COMMAND, 0x10, 0x01);
			break;
		case MPI_IOCSTATUS_EEDP_REF_TAG_ERROR:
			printk(KERN_ERR MYNAM ":%s EEDP Reference Tag Error\n",
			       ioc->name);
			stmapp_set_sense_info(priv, cmd,
					      SK_ABORTED_COMMAND, 0x10, 0x03);
			break;
		case MPI_IOCSTATUS_EEDP_APP_TAG_ERROR:
			printk(KERN_ERR MYNAM ":%s EEDP Application Tag Error\n",
			       ioc->name);
			stmapp_set_sense_info(priv, cmd,
					      SK_ABORTED_COMMAND, 0x10, 0x02);
			break;
		}

		stm_send_target_status(priv, reply_word, index, 0, lun, tag);
		return;
	}

	/*
	 *  the SCSI firmware has a bug, where if the Status Data Not Sent error
	 *  is returned, and the original command requested Auto Repost, the
	 *  command buffer is reposted, even though an error is generated; so,
	 *  ignore the error here, so that we don't post this command buffer again
	 *  (that is, treat this as a successful completion, which is what it is)
	 */
	/*
	 *  Allow STATUS_SENT status to go through also, this is the
	 *  result of an attempt to send a check condition with
	 *  attached sense bytes.
	 *  The IOC knows it can't send status and sense over a
	 *  traditional SCSI cable (if non-packetized), so we should
	 *  treat this as a successful completion, manually repost the
	 *  command to the IOC, and free the SCST command.
	 */
	if (IsScsi(priv) && (status == MPI_IOCSTATUS_TARGET_STS_DATA_NOT_SENT)) {
		if ((*io_state & IO_STATE_AUTO_REPOST) ||
		    (*io_state & IO_STATE_STATUS_SENT)) {
			/* if we know we were attempting to send status and sense
			 * simultaneously, indicate that we failed */
			if (atomic_read(&priv->pending_sense[init_index]) ==
			    MPT_STATUS_SENSE_ATTEMPT) {
				atomic_set(&priv->pending_sense[init_index],
					   MPT_STATUS_SENSE_NOT_SENT);
			}
			stm_tgt_reply(ioc, reply_word);
			TRACE_EXIT();
			return;
		}
	}

	*io_state &= ~IO_STATE_AUTO_REPOST;
	stm_target_cleanup(priv, index);
	TRACE_EXIT();
}

static void stmapp_set_sense_info(MPT_STM_PRIV *priv, CMD *cmd, int sense_key,
				  int asc, int ascq)
{
	u8	*info;

	TRACE_ENTRY();
	if (IsScsi(priv)) {
		SCSI_RSP *rsp = (SCSI_RSP *)cmd->rsp;

		rsp->Status = STS_CHECK_CONDITION;
		rsp->Valid |= SCSI_SENSE_LEN_VALID;
		rsp->SenseDataListLength = cpu_to_be32(14);
		info = rsp->SenseData;
		if (rsp->Valid & SCSI_RSP_LEN_VALID)
			info += be32_to_cpu(rsp->PktFailuresListLength);
	} else if (IsSas(priv)) {
		SSP_RSP *rsp = (SSP_RSP *)cmd->rsp;

		rsp->Status = STS_CHECK_CONDITION;
		rsp->DataPres |= SSP_SENSE_LEN_VALID;
		rsp->SenseDataLength = cpu_to_be32(14);
		info = rsp->ResponseSenseData;
		if (rsp->DataPres & SSP_RSP_LEN_VALID)
			info += be32_to_cpu(rsp->ResponseDataLength);
	} else {
		FCP_RSP *rsp = (FCP_RSP *)cmd->rsp;

		rsp->FcpStatus = STS_CHECK_CONDITION;
		rsp->FcpFlags |= FCP_SENSE_LEN_VALID;
		rsp->FcpSenseLength = cpu_to_be32(14);
		info = rsp->FcpSenseData - sizeof(rsp->FcpResponseData);
		if (rsp->FcpFlags & FCP_RSP_LEN_VALID)
			info += be32_to_cpu(rsp->FcpResponseLength);
	}

	info[0] = 0x70;
	info[2] = (u8)sense_key;
	info[7] = 6;

	info[12] = (u8)asc;
	info[13] = (u8)ascq;
	TRACE_EXIT();
}

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

#define MPT_PROC_LOG_ENTRY_NAME "trace_level"

#ifdef CONFIG_SCST_PROC
#include <linux/proc_fs.h>

static int mpt_log_info_show(struct seq_file *seq, void *v)
{
	int res = 0;

	TRACE_ENTRY();

	res = scst_proc_log_entry_read(seq, trace_flag, NULL);

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t mpt_proc_log_entry_write(struct file *file,
					const char __user *buf,
					size_t length, loff_t *off)
{
	int res = 0;

	TRACE_ENTRY();

	res = scst_proc_log_entry_write(file, buf, length, &trace_flag,
		SCST_DEFAULT_MPT_LOG_FLAGS, NULL);

	TRACE_EXIT_RES(res);
	return res;
}

static struct scst_proc_data mpt_log_proc_data = {
	SCST_DEF_RW_SEQ_OP(mpt_proc_log_entry_write)
	.show = mpt_log_info_show,
};
#endif
#endif

static int mpt_proc_log_entry_build(struct scst_tgt_template *templ)
{
	int res = 0;
#ifdef CONFIG_SCST_PROC
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	struct proc_dir_entry *p, *root;

	TRACE_ENTRY();

	root = scst_proc_get_tgt_root(templ);
	if (root) {
		mpt_log_proc_data.data = (void *)templ->name;
		p = scst_create_proc_entry(root, MPT_PROC_LOG_ENTRY_NAME,
					&mpt_log_proc_data);
		if (p == NULL) {
			PRINT_ERROR("Not enough memory to register "
					"target driver %s entry %s in /proc",
					templ->name, MPT_PROC_LOG_ENTRY_NAME);
			res = -ENOMEM;
			goto out;
		}

	}
out:

	TRACE_EXIT_RES(res);
#endif
#endif
	return res;
}

static void mpt_proc_log_entry_clean(struct scst_tgt_template *templ)
{
#ifdef CONFIG_SCST_PROC
#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	struct proc_dir_entry *root;

	TRACE_ENTRY();

	root = scst_proc_get_tgt_root(templ);
	if (root)
		remove_proc_entry(MPT_PROC_LOG_ENTRY_NAME, root);

	TRACE_EXIT();
#endif
#endif
}

static int __init mpt_target_init(void)
{
	int res = 0;

	TRACE_ENTRY();

	res = scst_register_target_template(&tgt_template);
	if (res < 0)
		goto out;

	res = mpt_proc_log_entry_build(&tgt_template);
	if (res < 0)
		goto out_unreg_target;

out:
	TRACE_EXIT_RES(res);

	return res;

out_unreg_target:
	scst_unregister_target_template(&tgt_template);
	goto out;
}

static void __exit mpt_target_exit(void)
{
	TRACE_ENTRY();

	mpt_proc_log_entry_clean(&tgt_template);
	scst_unregister_target_template(&tgt_template);
	_mpt_stm_exit();

	TRACE_EXIT();
	return;
}

module_init(mpt_target_init);
module_exit(mpt_target_exit);

MODULE_AUTHOR("Hu Gang <hugang@soulinfo.com>");
MODULE_DESCRIPTION("Fusion MPT SCSI Target Mode Driver for SCST Version 0.1");
MODULE_LICENSE("GPL");
