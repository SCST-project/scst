/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2011 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#include "qla_def.h"

#include "qla2x_tgt.h"

#include <linux/delay.h>
#include <linux/vmalloc.h>

#undef DEFAULT_SYMBOL_NAMESPACE
#define DEFAULT_SYMBOL_NAMESPACE	SCST_QLA16_NAMESPACE

/*
 * qla2x00_mailbox_command
 *	Issue mailbox command and waits for completion.
 *
 * Input:
 *	ha = adapter block pointer.
 *	mcp = driver internal mbx struct pointer.
 *
 * Output:
 *	mb[MAX_MAILBOX_REGISTER_COUNT] = returned mailbox data.
 *
 * Returns:
 *	QLA_SUCCESS: cmd performed success
 *	QLA_FUNCTION_FAILED:   (error encountered)
 *	QLA_FUNCTION_TIMEOUT: (timeout condition encountered)
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_mailbox_command(scsi_qla_host_t *vha, mbx_cmd_t *mcp)
{
	int		rval;
	unsigned long    flags = 0;
	device_reg_t __iomem *reg;
	uint8_t		abort_active;
	uint8_t		io_lock_on;
	uint16_t	command = 0;
	uint16_t	*iptr;
	uint16_t __iomem *optr;
	uint32_t	cnt;
	uint32_t	mboxes;
	unsigned long	wait_time;
	struct qla_hw_data *ha = vha->hw;
	scsi_qla_host_t *base_vha = pci_get_drvdata(ha->pdev);

	ql_dbg(ql_dbg_mbx, vha, 0x1000, "Entered %s.\n", __func__);

	if (ha->pdev->error_state > pci_channel_io_frozen) {
		ql_log(ql_log_warn, vha, 0x1001,
		    "error_state is greater than pci_channel_io_frozen, "
		    "exiting.\n");
		return QLA_FUNCTION_TIMEOUT;
	}

	if (vha->device_flags & DFLG_DEV_FAILED) {
		ql_log(ql_log_warn, vha, 0x1002,
		    "Device in failed state, exiting.\n");
		return QLA_FUNCTION_TIMEOUT;
	}

	reg = ha->iobase;
	io_lock_on = base_vha->flags.init_done;

	rval = QLA_SUCCESS;
	abort_active = test_bit(ABORT_ISP_ACTIVE, &base_vha->dpc_flags);

	if (ha->flags.pci_channel_io_perm_failure) {
		ql_log(ql_log_warn, vha, 0x1003,
		    "Perm failure on EEH timeout MBX, exiting.\n");
		return QLA_FUNCTION_TIMEOUT;
	}

	if (ha->flags.isp82xx_fw_hung) {
		/* Setting Link-Down error */
		mcp->mb[0] = MBS_LINK_DOWN_ERROR;
		ql_log(ql_log_warn, vha, 0x1004,
		    "FW hung = %d.\n", ha->flags.isp82xx_fw_hung);
		return QLA_FUNCTION_TIMEOUT;
	}

	/*
	 * Wait for active mailbox commands to finish by waiting at most tov
	 * seconds. This is to serialize actual issuing of mailbox cmds during
	 * non ISP abort time.
	 */
	if (!wait_for_completion_timeout(&ha->mbx_cmd_comp, mcp->tov * HZ)) {
		/* Timeout occurred. Return error. */
		ql_log(ql_log_warn, vha, 0x1005,
		    "Cmd access timeout, cmd=0x%x, Exiting.\n",
		    mcp->mb[0]);
		return QLA_FUNCTION_TIMEOUT;
	}

	ha->flags.mbox_busy = 1;
	/* Save mailbox command for debug */
	ha->mcp = mcp;

	ql_dbg(ql_dbg_mbx, vha, 0x1006,
	    "Prepare to issue mbox cmd=0x%x.\n", mcp->mb[0]);

	spin_lock_irqsave(&ha->hardware_lock, flags);

	/* Load mailbox registers. */
	if (IS_QLA82XX(ha))
		optr = (uint16_t __iomem *)&reg->isp82.mailbox_in[0];
	else if (IS_FWI2_CAPABLE(ha) && !IS_QLA82XX(ha))
		optr = (uint16_t __iomem *)&reg->isp24.mailbox0;
	else
		optr = (uint16_t __iomem *)MAILBOX_REG(ha, &reg->isp, 0);

	iptr = mcp->mb;
	command = mcp->mb[0];
	mboxes = mcp->out_mb;

	for (cnt = 0; cnt < ha->mbx_count; cnt++) {
		if (IS_QLA2200(ha) && cnt == 8)
			optr =
			    (uint16_t __iomem *)MAILBOX_REG(ha, &reg->isp, 8);
		if (mboxes & BIT_0)
			WRT_REG_WORD(optr, *iptr);

		mboxes >>= 1;
		optr++;
		iptr++;
	}

	ql_dbg(ql_dbg_mbx + ql_dbg_buffer, vha, 0x1111,
	    "Loaded MBX registers (displayed in bytes) =.\n");
	ql_dump_buffer(ql_dbg_mbx + ql_dbg_buffer, vha, 0x1112,
	    (uint8_t *)mcp->mb, 16);
	ql_dbg(ql_dbg_mbx + ql_dbg_buffer, vha, 0x1113,
	    ".\n");
	ql_dump_buffer(ql_dbg_mbx + ql_dbg_buffer, vha, 0x1114,
	    ((uint8_t *)mcp->mb + 0x10), 16);
	ql_dbg(ql_dbg_mbx + ql_dbg_buffer, vha, 0x1115,
	    ".\n");
	ql_dump_buffer(ql_dbg_mbx + ql_dbg_buffer, vha, 0x1116,
	    ((uint8_t *)mcp->mb + 0x20), 8);
	ql_dbg(ql_dbg_mbx + ql_dbg_buffer, vha, 0x1117,
	    "I/O Address = %p.\n", optr);
	ql_dump_regs(ql_dbg_mbx + ql_dbg_buffer, vha, 0x100e);

	/* Issue set host interrupt command to send cmd out. */
	ha->flags.mbox_int = 0;
	clear_bit(MBX_INTERRUPT, &ha->mbx_cmd_flags);

	/* Unlock mbx registers and wait for interrupt */
	ql_dbg(ql_dbg_mbx, vha, 0x100f,
	    "Going to unlock irq & waiting for interrupts. "
	    "jiffies=%lx.\n", jiffies);

	/* Wait for mbx cmd completion until timeout */

	if ((!abort_active && io_lock_on) || IS_NOPOLLING_TYPE(ha)) {
		set_bit(MBX_INTR_WAIT, &ha->mbx_cmd_flags);

		if (IS_QLA82XX(ha)) {
			if (RD_REG_DWORD(&reg->isp82.hint) &
				HINT_MBX_INT_PENDING) {
				spin_unlock_irqrestore(&ha->hardware_lock,
					flags);
				ha->flags.mbox_busy = 0;
				ql_dbg(ql_dbg_mbx, vha, 0x1010,
				    "Pending mailbox timeout, exiting.\n");
				rval = QLA_FUNCTION_TIMEOUT;
				goto premature_exit;
			}
			WRT_REG_DWORD(&reg->isp82.hint, HINT_MBX_INT_PENDING);
		} else if (IS_FWI2_CAPABLE(ha))
			WRT_REG_DWORD(&reg->isp24.hccr, HCCRX_SET_HOST_INT);
		else
			WRT_REG_WORD(&reg->isp.hccr, HCCR_SET_HOST_INT);
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		wait_for_completion_timeout(&ha->mbx_intr_comp, mcp->tov * HZ);

		clear_bit(MBX_INTR_WAIT, &ha->mbx_cmd_flags);

	} else {
		ql_dbg(ql_dbg_mbx, vha, 0x1011,
		    "Cmd=%x Polling Mode.\n", command);

		if (IS_QLA82XX(ha)) {
			if (RD_REG_DWORD(&reg->isp82.hint) &
				HINT_MBX_INT_PENDING) {
				spin_unlock_irqrestore(&ha->hardware_lock,
					flags);
				ha->flags.mbox_busy = 0;
				ql_dbg(ql_dbg_mbx, vha, 0x1012,
				    "Pending mailbox timeout, exiting.\n");
				rval = QLA_FUNCTION_TIMEOUT;
				goto premature_exit;
			}
			WRT_REG_DWORD(&reg->isp82.hint, HINT_MBX_INT_PENDING);
		} else if (IS_FWI2_CAPABLE(ha))
			WRT_REG_DWORD(&reg->isp24.hccr, HCCRX_SET_HOST_INT);
		else
			WRT_REG_WORD(&reg->isp.hccr, HCCR_SET_HOST_INT);
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		wait_time = jiffies + mcp->tov * HZ; /* wait at most tov secs */
		while (!ha->flags.mbox_int) {
			if (time_after(jiffies, wait_time))
				break;

			/* Check for pending interrupts. */
			qla2x00_poll(ha->rsp_q_map[0]);

			if (!ha->flags.mbox_int &&
			    !(IS_QLA2200(ha) &&
			    command == MBC_LOAD_RISC_RAM_EXTENDED))
				msleep(10);
		} /* while */
		ql_dbg(ql_dbg_mbx, vha, 0x1013,
		    "Waited %d sec.\n",
		    (uint)((jiffies - (wait_time - (mcp->tov * HZ)))/HZ));
	}

	/* Check whether we timed out */
	if (ha->flags.mbox_int) {
		uint16_t *iptr2;

		ql_dbg(ql_dbg_mbx, vha, 0x1014,
		    "Cmd=%x completed.\n", command);

		/* Got interrupt. Clear the flag. */
		ha->flags.mbox_int = 0;
		clear_bit(MBX_INTERRUPT, &ha->mbx_cmd_flags);

		if (ha->flags.isp82xx_fw_hung) {
			ha->flags.mbox_busy = 0;
			/* Setting Link-Down error */
			mcp->mb[0] = MBS_LINK_DOWN_ERROR;
			ha->mcp = NULL;
			rval = QLA_FUNCTION_FAILED;
			ql_log(ql_log_warn, vha, 0x1015,
			    "FW hung = %d.\n", ha->flags.isp82xx_fw_hung);
			goto premature_exit;
		}

		if (ha->mailbox_out[0] != MBS_COMMAND_COMPLETE)
			rval = QLA_FUNCTION_FAILED;

		/* Load return mailbox registers. */
		iptr2 = mcp->mb;
		iptr = (uint16_t *)&ha->mailbox_out[0];
		mboxes = mcp->in_mb;
		for (cnt = 0; cnt < ha->mbx_count; cnt++) {
			if (mboxes & BIT_0)
				*iptr2 = *iptr;

			mboxes >>= 1;
			iptr2++;
			iptr++;
		}
	} else {

		uint16_t mb0;
		uint32_t ictrl;

		if (IS_FWI2_CAPABLE(ha)) {
			mb0 = RD_REG_WORD(&reg->isp24.mailbox0);
			ictrl = RD_REG_DWORD(&reg->isp24.ictrl);
		} else {
			mb0 = RD_MAILBOX_REG(ha, &reg->isp, 0);
			ictrl = RD_REG_WORD(&reg->isp.ictrl);
		}
		ql_dbg(ql_dbg_mbx + ql_dbg_buffer, vha, 0x1119,
		    "MBX Command timeout for cmd %x, iocontrol=%x jiffies=%lx "
		    "mb[0]=0x%x\n", command, ictrl, jiffies, mb0);
		ql_dump_regs(ql_dbg_mbx + ql_dbg_buffer, vha, 0x1019);

		/*
		 * Attempt to capture a firmware dump for further analysis
		 * of the current firmware state
		 */
		ha->isp_ops->fw_dump(vha, 0);

		rval = QLA_FUNCTION_TIMEOUT;
	}

	ha->flags.mbox_busy = 0;

	/* Clean up */
	ha->mcp = NULL;

	if ((abort_active || !io_lock_on) && !IS_NOPOLLING_TYPE(ha)) {
		ql_dbg(ql_dbg_mbx, vha, 0x101a,
		    "Checking for additional resp interrupt.\n");

		/* polling mode for non isp_abort commands. */
		qla2x00_poll(ha->rsp_q_map[0]);
	}

	if (rval == QLA_FUNCTION_TIMEOUT &&
	    mcp->mb[0] != MBC_GEN_SYSTEM_ERROR) {
		if (!io_lock_on || (mcp->flags & IOCTL_CMD) ||
		    ha->flags.eeh_busy) {
			/* not in dpc. schedule it for dpc to take over. */
			ql_dbg(ql_dbg_mbx, vha, 0x101b,
			    "Timeout, schedule isp_abort_needed.\n");

			if (!test_bit(ISP_ABORT_NEEDED, &vha->dpc_flags) &&
			    !test_bit(ABORT_ISP_ACTIVE, &vha->dpc_flags) &&
			    !test_bit(ISP_ABORT_RETRY, &vha->dpc_flags)) {
				if (IS_QLA82XX(ha)) {
					ql_dbg(ql_dbg_mbx, vha, 0x112a,
					    "disabling pause transmit on port "
					    "0 & 1.\n");
					qla82xx_wr_32(ha,
					    QLA82XX_CRB_NIU + 0x98,
					    CRB_NIU_XG_PAUSE_CTL_P0|
					    CRB_NIU_XG_PAUSE_CTL_P1);
				}
				ql_log(ql_log_info, base_vha, 0x101c,
				    "Mailbox cmd timeout occurred, cmd=0x%x, "
				    "mb[0]=0x%x, eeh_busy=0x%x. Scheduling ISP "
				    "abort.\n", command, mcp->mb[0],
				    ha->flags.eeh_busy);
				set_bit(ISP_ABORT_NEEDED, &vha->dpc_flags);
				qla2xxx_wake_dpc(vha);
			}
		} else if (!abort_active) {
			/* call abort directly since we are in the DPC thread */
			ql_dbg(ql_dbg_mbx, vha, 0x101d,
			    "Timeout, calling abort_isp.\n");

			if (!test_bit(ISP_ABORT_NEEDED, &vha->dpc_flags) &&
			    !test_bit(ABORT_ISP_ACTIVE, &vha->dpc_flags) &&
			    !test_bit(ISP_ABORT_RETRY, &vha->dpc_flags)) {
				if (IS_QLA82XX(ha)) {
					ql_dbg(ql_dbg_mbx, vha, 0x112b,
					    "disabling pause transmit on port "
					    "0 & 1.\n");
					qla82xx_wr_32(ha,
					    QLA82XX_CRB_NIU + 0x98,
					    CRB_NIU_XG_PAUSE_CTL_P0|
					    CRB_NIU_XG_PAUSE_CTL_P1);
				}
				ql_log(ql_log_info, base_vha, 0x101e,
				    "Mailbox cmd timeout occurred, cmd=0x%x, "
				    "mb[0]=0x%x. Scheduling ISP abort ",
				    command, mcp->mb[0]);
				set_bit(ABORT_ISP_ACTIVE, &vha->dpc_flags);
				clear_bit(ISP_ABORT_NEEDED, &vha->dpc_flags);
				/* Allow next mbx cmd to come in. */
				complete(&ha->mbx_cmd_comp);
				if (ha->isp_ops->abort_isp(vha)) {
					/* Failed. retry later. */
					set_bit(ISP_ABORT_NEEDED,
					    &vha->dpc_flags);
				}
				clear_bit(ABORT_ISP_ACTIVE, &vha->dpc_flags);
				ql_dbg(ql_dbg_mbx, vha, 0x101f,
				    "Finished abort_isp.\n");
				goto mbx_done;
			}
		}
	}

premature_exit:
	/* Allow next mbx cmd to come in. */
	complete(&ha->mbx_cmd_comp);

mbx_done:
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, base_vha, 0x1020,
		    "**** Failed mbx[0]=%x, mb[1]=%x, mb[2]=%x, mb[3]=%x, cmd=%x ****.\n",
		    mcp->mb[0], mcp->mb[1], mcp->mb[2], mcp->mb[3], command);
	} else {
		ql_dbg(ql_dbg_mbx, base_vha, 0x1021, "Done %s.\n", __func__);
	}

	return rval;
}

int
qla2x00_load_ram(scsi_qla_host_t *vha, dma_addr_t req_dma, uint32_t risc_addr,
    uint32_t risc_code_size)
{
	int rval;
	struct qla_hw_data *ha = vha->hw;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1022,
	    "Entered %s.\n", __func__);

	if (MSW(risc_addr) || IS_FWI2_CAPABLE(ha)) {
		mcp->mb[0] = MBC_LOAD_RISC_RAM_EXTENDED;
		mcp->mb[8] = MSW(risc_addr);
		mcp->out_mb = MBX_8|MBX_0;
	} else {
		mcp->mb[0] = MBC_LOAD_RISC_RAM;
		mcp->out_mb = MBX_0;
	}
	mcp->mb[1] = LSW(risc_addr);
	mcp->mb[2] = MSW(req_dma);
	mcp->mb[3] = LSW(req_dma);
	mcp->mb[6] = MSW(MSD(req_dma));
	mcp->mb[7] = LSW(MSD(req_dma));
	mcp->out_mb |= MBX_7|MBX_6|MBX_3|MBX_2|MBX_1;
	if (IS_FWI2_CAPABLE(ha)) {
		mcp->mb[4] = MSW(risc_code_size);
		mcp->mb[5] = LSW(risc_code_size);
		mcp->out_mb |= MBX_5|MBX_4;
	} else {
		mcp->mb[4] = LSW(risc_code_size);
		mcp->out_mb |= MBX_4;
	}

	mcp->in_mb = MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1023,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1024,
		    "Done %s.\n", __func__);
	}

	return rval;
}

#define	EXTENDED_BB_CREDITS	BIT_0
/*
 * qla2x00_execute_fw
 *     Start adapter firmware.
 *
 * Input:
 *     ha = adapter block pointer.
 *     TARGET_QUEUE_LOCK must be released.
 *     ADAPTER_STATE_LOCK must be released.
 *
 * Returns:
 *     qla2x00 local function return status code.
 *
 * Context:
 *     Kernel context.
 */
int
qla2x00_execute_fw(scsi_qla_host_t *vha, uint32_t risc_addr)
{
	int rval;
	struct qla_hw_data *ha = vha->hw;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1025,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_EXECUTE_FIRMWARE;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_0;
	if (IS_FWI2_CAPABLE(ha)) {
		mcp->mb[1] = MSW(risc_addr);
		mcp->mb[2] = LSW(risc_addr);
		mcp->mb[3] = 0;
		if (IS_QLA81XX(ha) || IS_QLA83XX(ha)) {
			struct nvram_81xx *nv = ha->nvram;
			mcp->mb[4] = (nv->enhanced_features &
			    EXTENDED_BB_CREDITS);
		} else
			mcp->mb[4] = 0;
		mcp->out_mb |= MBX_4|MBX_3|MBX_2|MBX_1;
		mcp->in_mb |= MBX_1;
	} else {
		mcp->mb[1] = LSW(risc_addr);
		mcp->out_mb |= MBX_1;
		if (IS_QLA2322(ha) || IS_QLA6322(ha)) {
			mcp->mb[2] = 0;
			mcp->out_mb |= MBX_2;
		}
	}

	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1026,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		if (IS_FWI2_CAPABLE(ha)) {
			ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1027,
			    "Done exchanges=%x.\n", mcp->mb[1]);
		} else {
			ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1028,
			    "Done %s.\n", __func__);
		}
	}

	return rval;
}

/*
 * qla2x00_get_fw_version
 *	Get firmware version.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	major:		pointer for major number.
 *	minor:		pointer for minor number.
 *	subminor:	pointer for subminor number.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_get_fw_version(scsi_qla_host_t *vha)
{
	int		rval;
	mbx_cmd_t	mc;
	mbx_cmd_t	*mcp = &mc;
	struct qla_hw_data *ha = vha->hw;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1029,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_GET_FIRMWARE_VERSION;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	if (IS_QLA81XX(vha->hw) || IS_QLA8031(ha))
		mcp->in_mb |= MBX_13|MBX_12|MBX_11|MBX_10|MBX_9|MBX_8;
	if (IS_QLA83XX(vha->hw))
		mcp->in_mb |= MBX_17|MBX_16|MBX_15;
	mcp->flags = 0;
	mcp->tov = MBX_TOV_SECONDS;
	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS)
		goto failed;

	/* Return mailbox data. */
	ha->fw_major_version = mcp->mb[1];
	ha->fw_minor_version = mcp->mb[2];
	ha->fw_subminor_version = mcp->mb[3];
	ha->fw_attributes = mcp->mb[6];
	if (IS_QLA2100(vha->hw) || IS_QLA2200(vha->hw))
		ha->fw_memory_size = 0x1FFFF;		/* Defaults to 128KB. */
	else
		ha->fw_memory_size = (mcp->mb[5] << 16) | mcp->mb[4];
	if (IS_QLA81XX(vha->hw) || IS_QLA8031(vha->hw)) {
		ha->mpi_version[0] = mcp->mb[10] & 0xff;
		ha->mpi_version[1] = mcp->mb[11] >> 8;
		ha->mpi_version[2] = mcp->mb[11] & 0xff;
		ha->mpi_capabilities = (mcp->mb[12] << 16) | mcp->mb[13];
		ha->phy_version[0] = mcp->mb[8] & 0xff;
		ha->phy_version[1] = mcp->mb[9] >> 8;
		ha->phy_version[2] = mcp->mb[9] & 0xff;
	}
	if (IS_QLA83XX(ha)) {
		if (mcp->mb[6] & BIT_15) {
			ha->fw_attributes_h = mcp->mb[15];
			ha->fw_attributes_ext[0] = mcp->mb[16];
			ha->fw_attributes_ext[1] = mcp->mb[17];
			ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1139,
			    "%s: FW_attributes Upper: 0x%x, Lower: 0x%x.\n",
			    __func__, mcp->mb[15], mcp->mb[6]);
		} else
			ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x112f,
			    "%s: FwAttributes [Upper]  invalid, MB6:%04x\n",
			    __func__, mcp->mb[6]);
	}

failed:
	if (rval != QLA_SUCCESS) {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx, vha, 0x102a, "Failed=%x.\n", rval);
	} else {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x102b,
		    "Done %s.\n", __func__);
	}
	return rval;
}

/*
 * qla2x00_get_fw_options
 *	Set firmware options.
 *
 * Input:
 *	ha = adapter block pointer.
 *	fwopt = pointer for firmware options.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_get_fw_options(scsi_qla_host_t *vha, uint16_t *fwopts)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x102c,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_GET_FIRMWARE_OPTION;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx, vha, 0x102d, "Failed=%x.\n", rval);
	} else {
		fwopts[0] = mcp->mb[0];
		fwopts[1] = mcp->mb[1];
		fwopts[2] = mcp->mb[2];
		fwopts[3] = mcp->mb[3];

		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x102e,
		    "Done %s.\n", __func__);
	}

	return rval;
}


/*
 * qla2x00_set_fw_options
 *	Set firmware options.
 *
 * Input:
 *	ha = adapter block pointer.
 *	fwopt = pointer for firmware options.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_set_fw_options(scsi_qla_host_t *vha, uint16_t *fwopts)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x102f,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_SET_FIRMWARE_OPTION;
	mcp->mb[1] = fwopts[1];
	mcp->mb[2] = fwopts[2];
	mcp->mb[3] = fwopts[3];
	mcp->out_mb = MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	if (IS_FWI2_CAPABLE(vha->hw)) {
		mcp->in_mb |= MBX_1;
	} else {
		mcp->mb[10] = fwopts[10];
		mcp->mb[11] = fwopts[11];
		mcp->mb[12] = 0;	/* Undocumented, but used */
		mcp->out_mb |= MBX_12|MBX_11|MBX_10;
	}
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	fwopts[0] = mcp->mb[0];

	if (rval != QLA_SUCCESS) {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx, vha, 0x1030,
		    "Failed=%x (%x/%x).\n", rval, mcp->mb[0], mcp->mb[1]);
	} else {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1031,
		    "Done %s.\n", __func__);
	}

	return rval;
}

/*
 * qla2x00_mbx_reg_test
 *	Mailbox register wrap test.
 *
 * Input:
 *	ha = adapter block pointer.
 *	TARGET_QUEUE_LOCK must be released.
 *	ADAPTER_STATE_LOCK must be released.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_mbx_reg_test(scsi_qla_host_t *vha)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1032,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_MAILBOX_REGISTER_TEST;
	mcp->mb[1] = 0xAAAA;
	mcp->mb[2] = 0x5555;
	mcp->mb[3] = 0xAA55;
	mcp->mb[4] = 0x55AA;
	mcp->mb[5] = 0xA5A5;
	mcp->mb[6] = 0x5A5A;
	mcp->mb[7] = 0x2525;
	mcp->out_mb = MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval == QLA_SUCCESS) {
		if (mcp->mb[1] != 0xAAAA || mcp->mb[2] != 0x5555 ||
		    mcp->mb[3] != 0xAA55 || mcp->mb[4] != 0x55AA)
			rval = QLA_FUNCTION_FAILED;
		if (mcp->mb[5] != 0xA5A5 || mcp->mb[6] != 0x5A5A ||
		    mcp->mb[7] != 0x2525)
			rval = QLA_FUNCTION_FAILED;
	}

	if (rval != QLA_SUCCESS) {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx, vha, 0x1033, "Failed=%x.\n", rval);
	} else {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1034,
		    "Done %s.\n", __func__);
	}

	return rval;
}

/*
 * qla2x00_verify_checksum
 *	Verify firmware checksum.
 *
 * Input:
 *	ha = adapter block pointer.
 *	TARGET_QUEUE_LOCK must be released.
 *	ADAPTER_STATE_LOCK must be released.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_verify_checksum(scsi_qla_host_t *vha, uint32_t risc_addr)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1035,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_VERIFY_CHECKSUM;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_0;
	if (IS_FWI2_CAPABLE(vha->hw)) {
		mcp->mb[1] = MSW(risc_addr);
		mcp->mb[2] = LSW(risc_addr);
		mcp->out_mb |= MBX_2|MBX_1;
		mcp->in_mb |= MBX_2|MBX_1;
	} else {
		mcp->mb[1] = LSW(risc_addr);
		mcp->out_mb |= MBX_1;
		mcp->in_mb |= MBX_1;
	}

	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1036,
		    "Failed=%x chm sum=%x.\n", rval, IS_FWI2_CAPABLE(vha->hw) ?
		    (mcp->mb[2] << 16) | mcp->mb[1] : mcp->mb[1]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1037,
		    "Done %s.\n", __func__);
	}

	return rval;
}

/*
 * qla2x00_issue_iocb
 *	Issue IOCB using mailbox command
 *
 * Input:
 *	ha = adapter state pointer.
 *	buffer = buffer pointer.
 *	phys_addr = physical address of buffer.
 *	size = size of buffer.
 *	TARGET_QUEUE_LOCK must be released.
 *	ADAPTER_STATE_LOCK must be released.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_issue_iocb_timeout(scsi_qla_host_t *vha, void *buffer,
    dma_addr_t phys_addr, size_t size, uint32_t tov)
{
	int		rval;
	mbx_cmd_t	mc;
	mbx_cmd_t	*mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1038,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_IOCB_COMMAND_A64;
	mcp->mb[1] = 0;
	mcp->mb[2] = MSW(phys_addr);
	mcp->mb[3] = LSW(phys_addr);
	mcp->mb[6] = MSW(MSD(phys_addr));
	mcp->mb[7] = LSW(MSD(phys_addr));
	mcp->out_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_2|MBX_0;
	mcp->tov = tov;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx, vha, 0x1039, "Failed=%x.\n", rval);
	} else {
		sts_entry_t *sts_entry = (sts_entry_t *) buffer;

		/* Mask reserved bits. */
		sts_entry->entry_status &=
		    IS_FWI2_CAPABLE(vha->hw) ? RF_MASK_24XX : RF_MASK;
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x103a,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla2x00_issue_iocb(scsi_qla_host_t *vha, void *buffer, dma_addr_t phys_addr,
    size_t size)
{
	return qla2x00_issue_iocb_timeout(vha, buffer, phys_addr, size,
	    MBX_TOV_SECONDS);
}

/*
 * qla2x00_abort_command
 *	Abort command aborts a specified IOCB.
 *
 * Input:
 *	ha = adapter block pointer.
 *	sp = SB structure pointer.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_abort_command(srb_t *sp)
{
	unsigned long   flags = 0;
	int		rval;
	uint32_t	handle = 0;
	mbx_cmd_t	mc;
	mbx_cmd_t	*mcp = &mc;
	fc_port_t	*fcport = sp->fcport;
	scsi_qla_host_t *vha = fcport->vha;
	struct qla_hw_data *ha = vha->hw;
	struct req_que *req = vha->req;
	struct scsi_cmnd *cmd = GET_CMD_SP(sp);

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x103b,
	    "Entered %s.\n", __func__);

	spin_lock_irqsave(&ha->hardware_lock, flags);
	for (handle = 1; handle < MAX_OUTSTANDING_COMMANDS; handle++) {
		if (req->outstanding_cmds[handle] == sp)
			break;
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	if (handle == MAX_OUTSTANDING_COMMANDS) {
		/* command not found */
		return QLA_FUNCTION_FAILED;
	}

	mcp->mb[0] = MBC_ABORT_COMMAND;
	if (HAS_EXTENDED_IDS(ha))
		mcp->mb[1] = fcport->loop_id;
	else
		mcp->mb[1] = fcport->loop_id << 8;
	mcp->mb[2] = (uint16_t)handle;
	mcp->mb[3] = (uint16_t)(handle >> 16);
	mcp->mb[6] = (uint16_t)cmd->device->lun;
	mcp->out_mb = MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x103c, "Failed=%x.\n", rval);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x103d,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla2x00_abort_target(struct fc_port *fcport, unsigned int l, int tag)
{
	int rval, rval2;
	mbx_cmd_t  mc;
	mbx_cmd_t  *mcp = &mc;
	scsi_qla_host_t *vha;
	struct req_que *req;
	struct rsp_que *rsp;

	vha = fcport->vha;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x103e,
	    "Entered %s.\n", __func__);

	req = vha->hw->req_q_map[0];
	rsp = req->rsp;
	mcp->mb[0] = MBC_ABORT_TARGET;
	mcp->out_mb = MBX_9|MBX_2|MBX_1|MBX_0;
	if (HAS_EXTENDED_IDS(vha->hw)) {
		mcp->mb[1] = fcport->loop_id;
		mcp->mb[10] = 0;
		mcp->out_mb |= MBX_10;
	} else {
		mcp->mb[1] = fcport->loop_id << 8;
	}
	mcp->mb[2] = vha->hw->loop_reset_delay;
	mcp->mb[9] = vha->vp_idx;

	mcp->in_mb = MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x103f,
		    "Failed=%x.\n", rval);
	}

	/* Issue marker IOCB. */
	rval2 = qla2x00_marker(vha, req, rsp, fcport->loop_id, 0,
							MK_SYNC_ID);
	if (rval2 != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1040,
		    "Failed to issue marker IOCB (%x).\n", rval2);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1041,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla2x00_lun_reset(struct fc_port *fcport, unsigned int l, int tag)
{
	int rval, rval2;
	mbx_cmd_t  mc;
	mbx_cmd_t  *mcp = &mc;
	scsi_qla_host_t *vha;
	struct req_que *req;
	struct rsp_que *rsp;

	vha = fcport->vha;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1042,
	    "Entered %s.\n", __func__);

	req = vha->hw->req_q_map[0];
	rsp = req->rsp;
	mcp->mb[0] = MBC_LUN_RESET;
	mcp->out_mb = MBX_9|MBX_3|MBX_2|MBX_1|MBX_0;
	if (HAS_EXTENDED_IDS(vha->hw))
		mcp->mb[1] = fcport->loop_id;
	else
		mcp->mb[1] = fcport->loop_id << 8;
	mcp->mb[2] = l;
	mcp->mb[3] = 0;
	mcp->mb[9] = vha->vp_idx;

	mcp->in_mb = MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1043, "Failed=%x.\n", rval);
	}

	/* Issue marker IOCB. */
	rval2 = qla2x00_marker(vha, req, rsp, fcport->loop_id, l,
								MK_SYNC_ID_LUN);
	if (rval2 != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1044,
		    "Failed to issue marker IOCB (%x).\n", rval2);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1045,
		    "Done %s.\n", __func__);
	}

	return rval;
}

/*
 * qla2x00_get_adapter_id
 *	Get adapter ID and topology.
 *
 * Input:
 *	ha = adapter block pointer.
 *	id = pointer for loop ID.
 *	al_pa = pointer for AL_PA.
 *	area = pointer for area.
 *	domain = pointer for domain.
 *	top = pointer for topology.
 *	TARGET_QUEUE_LOCK must be released.
 *	ADAPTER_STATE_LOCK must be released.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_get_adapter_id(scsi_qla_host_t *vha, uint16_t *id, uint8_t *al_pa,
    uint8_t *area, uint8_t *domain, uint16_t *top, uint16_t *sw_cap)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1046,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_GET_ADAPTER_LOOP_ID;
	mcp->mb[9] = vha->vp_idx;
	mcp->out_mb = MBX_9|MBX_0;
	mcp->in_mb = MBX_9|MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	if (IS_CNA_CAPABLE(vha->hw))
		mcp->in_mb |= MBX_13|MBX_12|MBX_11|MBX_10;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);
	if (mcp->mb[0] == MBS_COMMAND_ERROR)
		rval = QLA_COMMAND_ERROR;
	else if (mcp->mb[0] == MBS_INVALID_COMMAND)
		rval = QLA_INVALID_COMMAND;

	/* Return data. */
	*id = mcp->mb[1];
	*al_pa = LSB(mcp->mb[2]);
	*area = MSB(mcp->mb[2]);
	*domain	= LSB(mcp->mb[3]);
	*top = mcp->mb[6];
	*sw_cap = mcp->mb[7];

	if (rval != QLA_SUCCESS) {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx, vha, 0x1047, "Failed=%x.\n", rval);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1048,
		    "Done %s.\n", __func__);

		if (IS_CNA_CAPABLE(vha->hw)) {
			vha->fcoe_vlan_id = mcp->mb[9] & 0xfff;
			vha->fcoe_fcf_idx = mcp->mb[10];
			vha->fcoe_vn_port_mac[5] = mcp->mb[11] >> 8;
			vha->fcoe_vn_port_mac[4] = mcp->mb[11] & 0xff;
			vha->fcoe_vn_port_mac[3] = mcp->mb[12] >> 8;
			vha->fcoe_vn_port_mac[2] = mcp->mb[12] & 0xff;
			vha->fcoe_vn_port_mac[1] = mcp->mb[13] >> 8;
			vha->fcoe_vn_port_mac[0] = mcp->mb[13] & 0xff;
		}
	}

	return rval;
}

/*
 * qla2x00_get_retry_cnt
 *	Get current firmware login retry count and delay.
 *
 * Input:
 *	ha = adapter block pointer.
 *	retry_cnt = pointer to login retry count.
 *	tov = pointer to login timeout value.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_get_retry_cnt(scsi_qla_host_t *vha, uint8_t *retry_cnt, uint8_t *tov,
    uint16_t *r_a_tov)
{
	int rval;
	uint16_t ratov;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1049,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_GET_RETRY_COUNT;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx, vha, 0x104a,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		/* Convert returned data and check our values. */
		*r_a_tov = mcp->mb[3] / 2;
		ratov = (mcp->mb[3]/2) / 10;  /* mb[3] value is in 100ms */
		if (mcp->mb[1] * ratov > (*retry_cnt) * (*tov)) {
			/* Update to the larger values */
			*retry_cnt = (uint8_t)mcp->mb[1];
			*tov = ratov;
		}

		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x104b,
		    "Done %s mb3=%d ratov=%d.\n", __func__, mcp->mb[3], ratov);
	}

	return rval;
}

/*
 * qla2x00_init_firmware
 *	Initialize adapter firmware.
 *
 * Input:
 *	ha = adapter block pointer.
 *	dptr = Initialization control block pointer.
 *	size = size of initialization control block.
 *	TARGET_QUEUE_LOCK must be released.
 *	ADAPTER_STATE_LOCK must be released.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_init_firmware(scsi_qla_host_t *vha, uint16_t size)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	struct qla_hw_data *ha = vha->hw;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x104c,
	    "Entered %s.\n", __func__);

	if (!qla_firmware_active(vha)) {
		printk("qla2x00_init_firmware(%ld): Neither initiator, "
			"nor target mode enabled\n", vha->host_no);
		rval = QLA_SUCCESS;
		goto out;
	}

	if (IS_QLA82XX(ha) && ql2xdbwr)
		qla82xx_wr_32(ha, ha->nxdb_wr_ptr,
			(0x04 | (ha->portnum << 5) | (0 << 8) | (0 << 16)));
#if 0
	if (IS_FWI2_CAPABLE(ha)) {
		struct init_cb_24xx *icb = (struct init_cb_24xx *)ha->init_cb;

		DEBUG5(printk(KERN_INFO "%s(): firmware_options_1 %x, "
			"firmware_options_2 %x, firmware_options_3 %x\n",
			__func__, icb->firmware_options_1,
			icb->firmware_options_2, icb->firmware_options_3));
		DEBUG5(printk(KERN_INFO "%s(): Control Block:\n", __func__));
		DEBUG5(qla2x00_dump_buffer((uint8_t *)icb, sizeof(*icb)));
	} else {
		init_cb_t *icb = (init_cb_t *)ha->init_cb;

		DEBUG5(printk(KERN_INFO "%s(): firmware_options[0] %x, "
			"firmware_options[1] %x, add_firmware_options[0] %x, "
			"add_firmware_options[1] %x\n", __func__,
			icb->firmware_options[0], icb->firmware_options[1],
			icb->add_firmware_options[0],
			icb->add_firmware_options[1]));
		DEBUG5(printk(KERN_INFO "%s(): Control Block:\n", __func__));
		DEBUG5(qla2x00_dump_buffer((uint8_t *)icb, sizeof(*icb)));
	}
#endif

	if (ha->flags.npiv_supported)
		mcp->mb[0] = MBC_MID_INITIALIZE_FIRMWARE;
	else
		mcp->mb[0] = MBC_INITIALIZE_FIRMWARE;

	mcp->mb[1] = 0;
	mcp->mb[2] = MSW(ha->init_cb_dma);
	mcp->mb[3] = LSW(ha->init_cb_dma);
	mcp->mb[4] = 0;
	mcp->mb[5] = 0;
	mcp->mb[6] = MSW(MSD(ha->init_cb_dma));
	mcp->mb[7] = LSW(MSD(ha->init_cb_dma));
	mcp->out_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	if ((IS_QLA81XX(ha) || IS_QLA83XX(ha)) && ha->ex_init_cb->ex_version) {
		mcp->mb[1] = BIT_0;
		mcp->mb[10] = MSW(ha->ex_init_cb_dma);
		mcp->mb[11] = LSW(ha->ex_init_cb_dma);
		mcp->mb[12] = MSW(MSD(ha->ex_init_cb_dma));
		mcp->mb[13] = LSW(MSD(ha->ex_init_cb_dma));
		mcp->mb[14] = sizeof(*ha->ex_init_cb);
		mcp->out_mb |= MBX_14|MBX_13|MBX_12|MBX_11|MBX_10;
	}
	/* 1 and 2 should normally be captured. */
	mcp->in_mb = MBX_2|MBX_1|MBX_0;
	if (IS_QLA83XX(ha))
		/* mb3 is additional info about the installed SFP. */
		mcp->in_mb  |= MBX_3;
	mcp->buf_size = size;
	mcp->flags = MBX_DMA_OUT;
	mcp->tov = MBX_TOV_SECONDS;
#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	if (IS_FWI2_CAPABLE(ha)) {
		struct mid_init_cb_24xx *micb = (struct mid_init_cb_24xx *)ha->init_cb;

		memset(micb->entries, 0, sizeof(micb->entries));

		if (ha->flags.npiv_supported && (ha->num_vhosts > 0)) {
			scsi_qla_host_t *vha;

			list_for_each_entry(vha, &ha->vp_list, list) {
				struct mid_conf_entry_24xx *vpe;

				if (!qla_tgt_mode_enabled(vha) &&
				    !qla_ini_mode_enabled(vha))
					continue;

				if (vha->vp_idx == 0)
					continue;

				vpe = &micb->entries[vha->vp_idx-1];
				vpe->options = BIT_3|BIT_4|BIT_5;

				/* Enable target mode */
				if (qla_tgt_mode_enabled(vha))
					vpe->options &= ~BIT_5;
				/* Disable ini mode, if requested */
				if (!qla_ini_mode_enabled(vha))
					vpe->options &= ~BIT_4;
				memcpy(vpe->node_name, vha->node_name, WWN_SIZE);
				memcpy(vpe->port_name, vha->port_name, WWN_SIZE);
			}
		}
	}
#endif
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx, vha, 0x104d,
		    "Failed=%x mb[0]=%x, mb[1]=%x, mb[2]=%x, mb[3]=%x,.\n",
		    rval, mcp->mb[0], mcp->mb[1], mcp->mb[2], mcp->mb[3]);
	} else {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x104e,
		    "Done %s.\n", __func__);
	}
#ifdef CONFIG_SCSI_QLA2XXX_TARGET
out:
#endif
	return rval;
}

#ifdef CONFIG_SCSI_QLA2XXX_TARGET
/*
 * qla2x00_get_node_name_list
 *	Issue get node name list mailbox command, vmalloc()
 *	and return the resulting list. Caller must vfree() it!
 *
 * Input:
 *	ha = adapter state pointer.
 *	include_initiators = include initiators in the resulting list
 *	out_data = resulting list
 *	out_len = length of the resulting list
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_get_node_name_list(scsi_qla_host_t *vha, bool include_initiators,
	void **out_data, int *out_len)
{
	struct qla_hw_data *ha = vha->hw;
	struct qla_port24_data *list = NULL;
	void *pmap;
	mbx_cmd_t mc;
	dma_addr_t pmap_dma;
	ulong dma_size;
	int rval, left;

	BUILD_BUG_ON(sizeof(struct qla_port24_data) <
		     sizeof(struct qla_port23_data));

	left = 1;
	while (left > 0) {
		dma_size = left * sizeof(*list);
		pmap = dma_alloc_coherent(&ha->pdev->dev, dma_size,
					 &pmap_dma, GFP_KERNEL);
		if (pmap == NULL) {
			printk(KERN_ERR "%s(%ld): DMA Alloc failed of "
				"%ld\n", __func__, vha->host_no, dma_size);
			rval = QLA_MEMORY_ALLOC_FAILED;
			goto out;
		}

		mc.mb[0] = MBC_PORT_NODE_NAME_LIST;
		mc.mb[1] = BIT_1;
		if (include_initiators)
			mc.mb[1] |= BIT_3;
		mc.mb[2] = MSW(pmap_dma);
		mc.mb[3] = LSW(pmap_dma);
		mc.mb[6] = MSW(MSD(pmap_dma));
		mc.mb[7] = LSW(MSD(pmap_dma));
		mc.mb[8] = dma_size;
		mc.out_mb = MBX_0|MBX_1|MBX_2|MBX_3|MBX_6|MBX_7|MBX_8;
		mc.in_mb = MBX_0|MBX_1|MBX_2;
		mc.tov = 30;
		mc.flags = MBX_DMA_IN;

		rval = qla2x00_mailbox_command(vha, &mc);
		if (rval != QLA_SUCCESS) {
			if ((mc.mb[0] == MBS_COMMAND_ERROR) &&
			    (mc.mb[1] == 0xA)) {
				ql_dbg(ql_dbg_mbx, vha, 0x11020,
				    "Not enough buffer, increasing...\n");
				if (IS_FWI2_CAPABLE(ha))
					left += le16_to_cpu(mc.mb[2]) / sizeof(struct qla_port24_data);
				else
					left += le16_to_cpu(mc.mb[2]) / sizeof(struct qla_port23_data);
				goto restart;
			}
			goto out_free;
		}

		left = 0;

		list = vmalloc(dma_size);
		if (list == NULL) {
			printk(KERN_ERR "%s(%ld): failed to allocate node names"
				" list structure.\n", __func__, vha->host_no);
			rval = QLA_MEMORY_ALLOC_FAILED;
			goto out_free;
		}

		memcpy(list, pmap, dma_size);
restart:
		dma_free_coherent(&ha->pdev->dev, dma_size, pmap, pmap_dma);
	}

	*out_data = list;
	*out_len = dma_size;

out:
	return rval;

out_free:
	dma_free_coherent(&ha->pdev->dev, dma_size, pmap, pmap_dma);
	return rval;
}
EXPORT_SYMBOL(qla2x00_get_node_name_list);
#endif /* CONFIG_SCSI_QLA2XXX_TARGET */

/*
 * qla2x00_get_port_database
 *	Issue normal/enhanced get port database mailbox command
 *	and copy device name as necessary.
 *
 * Input:
 *	ha = adapter state pointer.
 *	dev = structure pointer.
 *	opt = enhanced cmd option byte.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_get_port_database(scsi_qla_host_t *vha, fc_port_t *fcport, uint8_t opt)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	port_database_t *pd;
	struct port_database_24xx *pd24;
	dma_addr_t pd_dma;
	struct qla_hw_data *ha = vha->hw;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x104f,
	    "Entered %s.\n", __func__);

	pd24 = NULL;
	pd = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &pd_dma);
	if (pd  == NULL) {
		ql_log(ql_log_warn, vha, 0x1050,
		    "Failed to allocate port database structure.\n");
		return QLA_MEMORY_ALLOC_FAILED;
	}
	memset(pd, 0, max(PORT_DATABASE_SIZE, PORT_DATABASE_24XX_SIZE));

	mcp->mb[0] = MBC_GET_PORT_DATABASE;
	if (opt != 0 && !IS_FWI2_CAPABLE(ha))
		mcp->mb[0] = MBC_ENHANCED_GET_PORT_DATABASE;
	mcp->mb[2] = MSW(pd_dma);
	mcp->mb[3] = LSW(pd_dma);
	mcp->mb[6] = MSW(MSD(pd_dma));
	mcp->mb[7] = LSW(MSD(pd_dma));
	mcp->mb[9] = vha->vp_idx;
	mcp->out_mb = MBX_9|MBX_7|MBX_6|MBX_3|MBX_2|MBX_0;
	mcp->in_mb = MBX_0;
	if (IS_FWI2_CAPABLE(ha)) {
		mcp->mb[1] = fcport->loop_id;
		mcp->mb[10] = opt;
		mcp->out_mb |= MBX_10|MBX_1;
		mcp->in_mb |= MBX_1;
	} else if (HAS_EXTENDED_IDS(ha)) {
		mcp->mb[1] = fcport->loop_id;
		mcp->mb[10] = opt;
		mcp->out_mb |= MBX_10|MBX_1;
	} else {
		mcp->mb[1] = fcport->loop_id << 8 | opt;
		mcp->out_mb |= MBX_1;
	}
	mcp->buf_size = IS_FWI2_CAPABLE(ha) ?
	    PORT_DATABASE_24XX_SIZE : PORT_DATABASE_SIZE;
	mcp->flags = MBX_DMA_IN;
	mcp->tov = (ha->login_timeout * 2) + (ha->login_timeout / 2);
	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS)
		goto gpd_error_out;

	if (IS_FWI2_CAPABLE(ha)) {
		uint64_t zero = 0;
		pd24 = (struct port_database_24xx *) pd;

		/* Check for logged in state. */
		if (pd24->current_login_state != PDS_PRLI_COMPLETE &&
		    pd24->last_login_state != PDS_PRLI_COMPLETE) {
			ql_dbg(ql_dbg_mbx, vha, 0x1051,
			    "Unable to verify login-state (%x/%x) for "
			    "loop_id %x.\n", pd24->current_login_state,
			    pd24->last_login_state, fcport->loop_id);
			rval = QLA_FUNCTION_FAILED;
			goto gpd_error_out;
		}

		if (fcport->loop_id == FC_NO_LOOP_ID ||
		    (memcmp(fcport->port_name, (uint8_t *)&zero, 8) &&
		     memcmp(fcport->port_name, pd24->port_name, 8))) {
			/* We lost the device mid way. */
			rval = QLA_NOT_LOGGED_IN;
			goto gpd_error_out;
		}

		/* Names are little-endian. */
		memcpy(fcport->node_name, pd24->node_name, WWN_SIZE);
		memcpy(fcport->port_name, pd24->port_name, WWN_SIZE);

		/* Get port_id of device. */
		fcport->d_id.b.domain = pd24->port_id[0];
		fcport->d_id.b.area = pd24->port_id[1];
		fcport->d_id.b.al_pa = pd24->port_id[2];
		fcport->d_id.b.rsvd_1 = 0;

		/* If not target must be initiator or unknown type. */
		if ((pd24->prli_svc_param_word_3[0] & BIT_4))
			fcport->port_type = FCT_TARGET;
		else if ((pd24->prli_svc_param_word_3[0] & BIT_5))
			fcport->port_type = FCT_INITIATOR;
		else
			fcport->port_type = FCT_UNKNOWN;

		/* Passback COS information. */
		fcport->supported_classes = (pd24->flags & PDF_CLASS_2) ?
		    FC_COS_CLASS2 : FC_COS_CLASS3;

#ifdef CONFIG_SCSI_QLA2XXX_TARGET
		if (pd24->prli_svc_param_word_3[0] & BIT_7)
			fcport->conf_compl_supported = 1;
#endif /* CONFIG_SCSI_QLA2XXX_TARGET */
	} else {
		uint64_t zero = 0;

		/* Check for logged in state. */
		if (pd->master_state != PD_STATE_PORT_LOGGED_IN &&
		    pd->slave_state != PD_STATE_PORT_LOGGED_IN) {
			ql_dbg(ql_dbg_mbx, vha, 0x100a,
			    "Unable to verify login-state (%x/%x) - "
			    "portid=%02x%02x%02x.\n", pd->master_state,
			    pd->slave_state, fcport->d_id.b.domain,
			    fcport->d_id.b.area, fcport->d_id.b.al_pa);
			rval = QLA_FUNCTION_FAILED;
			goto gpd_error_out;
		}

		if (fcport->loop_id == FC_NO_LOOP_ID ||
		    (memcmp(fcport->port_name, (uint8_t *)&zero, 8) &&
		     memcmp(fcport->port_name, pd->port_name, 8))) {
			/* We lost the device mid way. */
			rval = QLA_NOT_LOGGED_IN;
			goto gpd_error_out;
		}

		/* Names are little-endian. */
		memcpy(fcport->node_name, pd->node_name, WWN_SIZE);
		memcpy(fcport->port_name, pd->port_name, WWN_SIZE);

		/* Get port_id of device. */
		fcport->d_id.b.domain = pd->port_id[0];
		fcport->d_id.b.area = pd->port_id[3];
		fcport->d_id.b.al_pa = pd->port_id[2];
		fcport->d_id.b.rsvd_1 = 0;

		/* Check for device require authentication. */
		pd->common_features & BIT_5 ? (fcport->flags |= FCF_AUTH_REQ) :
		    (fcport->flags &= ~FCF_AUTH_REQ);

		/* If not target must be initiator or unknown type. */
		if ((pd->prli_svc_param_word_3[0] & BIT_4))
			fcport->port_type = FCT_TARGET;
		else if ((pd->prli_svc_param_word_3[0] & BIT_5))
			fcport->port_type = FCT_INITIATOR;
		else
			fcport->port_type = FCT_UNKNOWN;

		/* Passback COS information. */
		fcport->supported_classes = (pd->options & BIT_4) ?
		    FC_COS_CLASS2 : FC_COS_CLASS3;

#ifdef CONFIG_SCSI_QLA2XXX_TARGET
		if (pd->prli_svc_param_word_3[0] & BIT_7)
			fcport->conf_compl_supported = 1;
#endif /* CONFIG_SCSI_QLA2XXX_TARGET */
	}

gpd_error_out:
	dma_pool_free(ha->s_dma_pool, pd, pd_dma);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1052,
		    "Failed=%x mb[0]=%x mb[1]=%x.\n", rval,
		    mcp->mb[0], mcp->mb[1]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1053,
		    "Done %s.\n", __func__);
	}

	return rval;
}
EXPORT_SYMBOL(qla2x00_get_port_database);

/*
 * qla2x00_get_firmware_state
 *	Get adapter firmware state.
 *
 * Input:
 *	ha = adapter block pointer.
 *	dptr = pointer for firmware state.
 *	TARGET_QUEUE_LOCK must be released.
 *	ADAPTER_STATE_LOCK must be released.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_get_firmware_state(scsi_qla_host_t *vha, uint16_t *states)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1054,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_GET_FIRMWARE_STATE;
	mcp->out_mb = MBX_0;
	if (IS_FWI2_CAPABLE(vha->hw))
		mcp->in_mb = MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	else
		mcp->in_mb = MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	/* Return firmware states. */
	states[0] = mcp->mb[1];
	if (IS_FWI2_CAPABLE(vha->hw)) {
		states[1] = mcp->mb[2];
		states[2] = mcp->mb[3];
		states[3] = mcp->mb[4];
		states[4] = mcp->mb[5];
	}

	if (rval != QLA_SUCCESS) {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx, vha, 0x1055, "Failed=%x.\n", rval);
	} else {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1056,
		    "Done %s.\n", __func__);
	}

	return rval;
}

/*
 * qla2x00_get_port_name
 *	Issue get port name mailbox command.
 *	Returned name is in big endian format.
 *
 * Input:
 *	ha = adapter block pointer.
 *	loop_id = loop ID of device.
 *	name = pointer for name.
 *	TARGET_QUEUE_LOCK must be released.
 *	ADAPTER_STATE_LOCK must be released.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_get_port_name(scsi_qla_host_t *vha, uint16_t loop_id, uint8_t *name,
    uint8_t opt)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1057,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_GET_PORT_NAME;
	mcp->mb[9] = vha->vp_idx;
	mcp->out_mb = MBX_9|MBX_1|MBX_0;
	if (HAS_EXTENDED_IDS(vha->hw)) {
		mcp->mb[1] = loop_id;
		mcp->mb[10] = opt;
		mcp->out_mb |= MBX_10;
	} else {
		mcp->mb[1] = loop_id << 8 | opt;
	}

	mcp->in_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx, vha, 0x1058, "Failed=%x.\n", rval);
	} else {
		if (name != NULL) {
			/* This function returns name in big endian. */
			name[0] = MSB(mcp->mb[2]);
			name[1] = LSB(mcp->mb[2]);
			name[2] = MSB(mcp->mb[3]);
			name[3] = LSB(mcp->mb[3]);
			name[4] = MSB(mcp->mb[6]);
			name[5] = LSB(mcp->mb[6]);
			name[6] = MSB(mcp->mb[7]);
			name[7] = LSB(mcp->mb[7]);
		}

		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1059,
		    "Done %s.\n", __func__);
	}

	return rval;
}

/*
 * qla2x00_lip_reset
 *	Issue LIP reset mailbox command.
 *
 * Input:
 *	ha = adapter block pointer.
 *	TARGET_QUEUE_LOCK must be released.
 *	ADAPTER_STATE_LOCK must be released.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_lip_reset(scsi_qla_host_t *vha)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x105a,
	    "Entered %s.\n", __func__);

	if (IS_CNA_CAPABLE(vha->hw)) {
		/* Logout across all FCFs. */
		mcp->mb[0] = MBC_LIP_FULL_LOGIN;
		mcp->mb[1] = BIT_1;
		mcp->mb[2] = 0;
		mcp->out_mb = MBX_2|MBX_1|MBX_0;
	} else if (IS_FWI2_CAPABLE(vha->hw)) {
		mcp->mb[0] = MBC_LIP_FULL_LOGIN;
		mcp->mb[1] = BIT_6;
		mcp->mb[2] = 0;
		mcp->mb[3] = vha->hw->loop_reset_delay;
		mcp->out_mb = MBX_3|MBX_2|MBX_1|MBX_0;
	} else {
		mcp->mb[0] = MBC_LIP_RESET;
		mcp->out_mb = MBX_3|MBX_2|MBX_1|MBX_0;
		if (HAS_EXTENDED_IDS(vha->hw)) {
			mcp->mb[1] = 0x00ff;
			mcp->mb[10] = 0;
			mcp->out_mb |= MBX_10;
		} else {
			mcp->mb[1] = 0xff00;
		}
		mcp->mb[2] = vha->hw->loop_reset_delay;
		mcp->mb[3] = 0;
	}
	mcp->in_mb = MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx, vha, 0x105b, "Failed=%x.\n", rval);
	} else {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x105c,
		    "Done %s.\n", __func__);
	}

	return rval;
}

/*
 * qla2x00_send_sns
 *	Send SNS command.
 *
 * Input:
 *	ha = adapter block pointer.
 *	sns = pointer for command.
 *	cmd_size = command size.
 *	buf_size = response/command size.
 *	TARGET_QUEUE_LOCK must be released.
 *	ADAPTER_STATE_LOCK must be released.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_send_sns(scsi_qla_host_t *vha, dma_addr_t sns_phys_address,
    uint16_t cmd_size, size_t buf_size)
{
	int rval;
	mbx_cmd_t mc = {};
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x105d,
	    "Entered %s.\n", __func__);

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x105e,
	    "Retry cnt=%d ratov=%d total tov=%d.\n",
	    vha->hw->retry_count, vha->hw->login_timeout, mcp->tov);

	mcp->mb[0] = MBC_SEND_SNS_COMMAND;
	mcp->mb[1] = cmd_size;
	mcp->mb[2] = MSW(sns_phys_address);
	mcp->mb[3] = LSW(sns_phys_address);
	mcp->mb[6] = MSW(MSD(sns_phys_address));
	mcp->mb[7] = LSW(MSD(sns_phys_address));
	mcp->out_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0|MBX_1;
	mcp->buf_size = buf_size;
	mcp->flags = MBX_DMA_OUT|MBX_DMA_IN;
	mcp->tov = (vha->hw->login_timeout * 2) + (vha->hw->login_timeout / 2);
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx, vha, 0x105f,
		    "Failed=%x mb[0]=%x mb[1]=%x.\n",
		    rval, mcp->mb[0], mcp->mb[1]);
	} else {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1060,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla24xx_login_fabric(scsi_qla_host_t *vha, uint16_t loop_id, uint8_t domain,
    uint8_t area, uint8_t al_pa, uint16_t *mb, uint8_t opt)
{
	int		rval;

	struct logio_entry_24xx *lg;
	dma_addr_t	lg_dma;
	uint32_t	iop[2];
	struct qla_hw_data *ha = vha->hw;
	struct req_que *req;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1061,
	    "Entered %s.\n", __func__);

	if (ha->flags.cpu_affinity_enabled)
		req = ha->req_q_map[0];
	else
		req = vha->req;

	lg = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &lg_dma);
	if (lg == NULL) {
		ql_log(ql_log_warn, vha, 0x1062,
		    "Failed to allocate login IOCB.\n");
		return QLA_MEMORY_ALLOC_FAILED;
	}
	memset(lg, 0, sizeof(struct logio_entry_24xx));

	lg->entry_type = LOGINOUT_PORT_IOCB_TYPE;
	lg->entry_count = 1;
	lg->handle = MAKE_HANDLE(req->id, lg->handle);
	lg->nport_handle = cpu_to_le16(loop_id);
	lg->control_flags = cpu_to_le16(LCF_COMMAND_PLOGI);
	if (opt & BIT_0)
		lg->control_flags |= cpu_to_le16(LCF_COND_PLOGI);
	if (opt & BIT_1)
		lg->control_flags |= cpu_to_le16(LCF_SKIP_PRLI);
	lg->port_id[0] = al_pa;
	lg->port_id[1] = area;
	lg->port_id[2] = domain;
	lg->vp_index = vha->vp_idx;
	rval = qla2x00_issue_iocb_timeout(vha, lg, lg_dma, 0,
	    (ha->r_a_tov / 10 * 2) + 2);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1063,
		    "Failed to issue login IOCB (%x).\n", rval);
	} else if (lg->entry_status != 0) {
		ql_dbg(ql_dbg_mbx, vha, 0x1064,
		    "Failed to complete IOCB -- error status (%x).\n",
		    lg->entry_status);
		rval = QLA_FUNCTION_FAILED;
	} else if (lg->comp_status != cpu_to_le16(CS_COMPLETE)) {
		iop[0] = le32_to_cpu(lg->io_parameter[0]);
		iop[1] = le32_to_cpu(lg->io_parameter[1]);

		ql_dbg(ql_dbg_mbx, vha, 0x1065,
		    "Failed to complete IOCB -- completion  status (%x) "
		    "ioparam=%x/%x.\n", le16_to_cpu(lg->comp_status),
		    iop[0], iop[1]);

		switch (iop[0]) {
		case LSC_SCODE_PORTID_USED:
			mb[0] = MBS_PORT_ID_USED;
			mb[1] = LSW(iop[1]);
			break;
		case LSC_SCODE_NPORT_USED:
			mb[0] = MBS_LOOP_ID_USED;
			break;
		case LSC_SCODE_NOLINK:
		case LSC_SCODE_NOIOCB:
		case LSC_SCODE_NOXCB:
		case LSC_SCODE_CMD_FAILED:
		case LSC_SCODE_NOFABRIC:
		case LSC_SCODE_FW_NOT_READY:
		case LSC_SCODE_NOT_LOGGED_IN:
		case LSC_SCODE_NOPCB:
		case LSC_SCODE_ELS_REJECT:
		case LSC_SCODE_CMD_PARAM_ERR:
		case LSC_SCODE_NONPORT:
		case LSC_SCODE_LOGGED_IN:
		case LSC_SCODE_NOFLOGI_ACC:
		default:
			mb[0] = MBS_COMMAND_ERROR;
			break;
		}
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1066,
		    "Done %s.\n", __func__);

		iop[0] = le32_to_cpu(lg->io_parameter[0]);

		mb[0] = MBS_COMMAND_COMPLETE;
		mb[1] = 0;
		if (iop[0] & BIT_4) {
			if (iop[0] & BIT_8)
				mb[1] |= BIT_1;
		} else
			mb[1] = BIT_0;

		/* Passback COS information. */
		mb[10] = 0;
		if (lg->io_parameter[7] || lg->io_parameter[8])
			mb[10] |= BIT_0;	/* Class 2. */
		if (lg->io_parameter[9] || lg->io_parameter[10])
			mb[10] |= BIT_1;	/* Class 3. */
		if (lg->io_parameter[0] & cpu_to_le32(BIT_7))
			mb[10] |= BIT_7;	/* Confirmed Completion Allowed */
	}

	dma_pool_free(ha->s_dma_pool, lg, lg_dma);

	return rval;
}

/*
 * qla2x00_login_fabric
 *	Issue login fabric port mailbox command.
 *
 * Input:
 *	ha = adapter block pointer.
 *	loop_id = device loop ID.
 *	domain = device domain.
 *	area = device area.
 *	al_pa = device AL_PA.
 *	status = pointer for return status.
 *	opt = command options.
 *	TARGET_QUEUE_LOCK must be released.
 *	ADAPTER_STATE_LOCK must be released.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_login_fabric(scsi_qla_host_t *vha, uint16_t loop_id, uint8_t domain,
    uint8_t area, uint8_t al_pa, uint16_t *mb, uint8_t opt)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	struct qla_hw_data *ha = vha->hw;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1067,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_LOGIN_FABRIC_PORT;
	mcp->out_mb = MBX_3|MBX_2|MBX_1|MBX_0;
	if (HAS_EXTENDED_IDS(ha)) {
		mcp->mb[1] = loop_id;
		mcp->mb[10] = opt;
		mcp->out_mb |= MBX_10;
	} else {
		mcp->mb[1] = (loop_id << 8) | opt;
	}
	mcp->mb[2] = domain;
	mcp->mb[3] = area << 8 | al_pa;

	mcp->in_mb = MBX_7|MBX_6|MBX_2|MBX_1|MBX_0;
	mcp->tov = (ha->login_timeout * 2) + (ha->login_timeout / 2);
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	/* Return mailbox statuses. */
	if (mb != NULL) {
		mb[0] = mcp->mb[0];
		mb[1] = mcp->mb[1];
		mb[2] = mcp->mb[2];
		mb[6] = mcp->mb[6];
		mb[7] = mcp->mb[7];
		/* COS retrieved from Get-Port-Database mailbox command. */
		mb[10] = 0;
	}

	if (rval != QLA_SUCCESS) {
		/* RLU tmp code: need to change main mailbox_command function to
		 * return ok even when the mailbox completion value is not
		 * SUCCESS. The caller needs to be responsible to interpret
		 * the return values of this mailbox command if we're not
		 * to change too much of the existing code.
		 */
		if (mcp->mb[0] == 0x4001 || mcp->mb[0] == 0x4002 ||
		    mcp->mb[0] == 0x4003 || mcp->mb[0] == 0x4005 ||
		    mcp->mb[0] == 0x4006)
			rval = QLA_SUCCESS;

		/*EMPTY*/
		ql_dbg(ql_dbg_mbx, vha, 0x1068,
		    "Failed=%x mb[0]=%x mb[1]=%x mb[2]=%x.\n",
		    rval, mcp->mb[0], mcp->mb[1], mcp->mb[2]);
	} else {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1069,
		    "Done %s.\n", __func__);
	}

	return rval;
}

/*
 * qla2x00_login_local_device
 *           Issue login loop port mailbox command.
 *
 * Input:
 *           ha = adapter block pointer.
 *           loop_id = device loop ID.
 *           opt = command options.
 *
 * Returns:
 *            Return status code.
 *
 * Context:
 *            Kernel context.
 *
 */
int
qla2x00_login_local_device(scsi_qla_host_t *vha, fc_port_t *fcport,
    uint16_t *mb_ret, uint8_t opt)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	struct qla_hw_data *ha = vha->hw;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x106a,
	    "Entered %s.\n", __func__);

	if (IS_FWI2_CAPABLE(ha))
		return qla24xx_login_fabric(vha, fcport->loop_id,
		    fcport->d_id.b.domain, fcport->d_id.b.area,
		    fcport->d_id.b.al_pa, mb_ret, opt);

	mcp->mb[0] = MBC_LOGIN_LOOP_PORT;
	if (HAS_EXTENDED_IDS(ha))
		mcp->mb[1] = fcport->loop_id;
	else
		mcp->mb[1] = fcport->loop_id << 8;
	mcp->mb[2] = opt;
	mcp->out_mb = MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_7|MBX_6|MBX_1|MBX_0;
	mcp->tov = (ha->login_timeout * 2) + (ha->login_timeout / 2);
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	/* Return mailbox statuses. */
	if (mb_ret != NULL) {
		mb_ret[0] = mcp->mb[0];
		mb_ret[1] = mcp->mb[1];
		mb_ret[6] = mcp->mb[6];
		mb_ret[7] = mcp->mb[7];
	}

	if (rval != QLA_SUCCESS) {
		/* AV tmp code: need to change main mailbox_command function to
		 * return ok even when the mailbox completion value is not
		 * SUCCESS. The caller needs to be responsible to interpret
		 * the return values of this mailbox command if we're not
		 * to change too much of the existing code.
		 */
		if (mcp->mb[0] == 0x4005 || mcp->mb[0] == 0x4006)
			rval = QLA_SUCCESS;

		ql_dbg(ql_dbg_mbx, vha, 0x106b,
		    "Failed=%x mb[0]=%x mb[1]=%x mb[6]=%x mb[7]=%x.\n",
		    rval, mcp->mb[0], mcp->mb[1], mcp->mb[6], mcp->mb[7]);
	} else {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x106c,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla24xx_fabric_logout(scsi_qla_host_t *vha, uint16_t loop_id, uint8_t domain,
    uint8_t area, uint8_t al_pa)
{
	int		rval;
	struct logio_entry_24xx *lg;
	dma_addr_t	lg_dma;
	struct qla_hw_data *ha = vha->hw;
	struct req_que *req;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x106d,
	    "Entered %s.\n", __func__);

	lg = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &lg_dma);
	if (lg == NULL) {
		ql_log(ql_log_warn, vha, 0x106e,
		    "Failed to allocate logout IOCB.\n");
		return QLA_MEMORY_ALLOC_FAILED;
	}
	memset(lg, 0, sizeof(struct logio_entry_24xx));

	if (ql2xmaxqueues > 1)
		req = ha->req_q_map[0];
	else
		req = vha->req;
	lg->entry_type = LOGINOUT_PORT_IOCB_TYPE;
	lg->entry_count = 1;
	lg->handle = MAKE_HANDLE(req->id, lg->handle);
	lg->nport_handle = cpu_to_le16(loop_id);
	lg->control_flags =
	    cpu_to_le16(LCF_COMMAND_LOGO|LCF_IMPL_LOGO|
		LCF_FREE_NPORT);
	lg->port_id[0] = al_pa;
	lg->port_id[1] = area;
	lg->port_id[2] = domain;
	lg->vp_index = vha->vp_idx;
	rval = qla2x00_issue_iocb_timeout(vha, lg, lg_dma, 0,
	    (ha->r_a_tov / 10 * 2) + 2);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x106f,
		    "Failed to issue logout IOCB (%x).\n", rval);
	} else if (lg->entry_status != 0) {
		ql_dbg(ql_dbg_mbx, vha, 0x1070,
		    "Failed to complete IOCB -- error status (%x).\n",
		    lg->entry_status);
		rval = QLA_FUNCTION_FAILED;
	} else if (lg->comp_status != cpu_to_le16(CS_COMPLETE)) {
		ql_dbg(ql_dbg_mbx, vha, 0x1071,
		    "Failed to complete IOCB -- completion status (%x) "
		    "ioparam=%x/%x.\n", le16_to_cpu(lg->comp_status),
		    le32_to_cpu(lg->io_parameter[0]),
		    le32_to_cpu(lg->io_parameter[1]));
	} else {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1072,
		    "Done %s.\n", __func__);
	}

	dma_pool_free(ha->s_dma_pool, lg, lg_dma);

	return rval;
}

/*
 * qla2x00_fabric_logout
 *	Issue logout fabric port mailbox command.
 *
 * Input:
 *	ha = adapter block pointer.
 *	loop_id = device loop ID.
 *	TARGET_QUEUE_LOCK must be released.
 *	ADAPTER_STATE_LOCK must be released.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_fabric_logout(scsi_qla_host_t *vha, uint16_t loop_id, uint8_t domain,
    uint8_t area, uint8_t al_pa)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1073,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_LOGOUT_FABRIC_PORT;
	mcp->out_mb = MBX_1|MBX_0;
	if (HAS_EXTENDED_IDS(vha->hw)) {
		mcp->mb[1] = loop_id;
		mcp->mb[10] = 0;
		mcp->out_mb |= MBX_10;
	} else {
		mcp->mb[1] = loop_id << 8;
	}

	mcp->in_mb = MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx, vha, 0x1074,
		    "Failed=%x mb[1]=%x.\n", rval, mcp->mb[1]);
	} else {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1075,
		    "Done %s.\n", __func__);
	}

	return rval;
}

/*
 * qla2x00_full_login_lip
 *	Issue full login LIP mailbox command.
 *
 * Input:
 *	ha = adapter block pointer.
 *	TARGET_QUEUE_LOCK must be released.
 *	ADAPTER_STATE_LOCK must be released.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_full_login_lip(scsi_qla_host_t *vha)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1076,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_LIP_FULL_LOGIN;
	mcp->mb[1] = IS_FWI2_CAPABLE(vha->hw) ? BIT_3 : 0;
	mcp->mb[2] = 0;
	mcp->mb[3] = 0;
	mcp->out_mb = MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx, vha, 0x1077, "Failed=%x.\n", rval);
	} else {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1078,
		    "Done %s.\n", __func__);
	}

	return rval;
}

/*
 * qla2x00_get_id_list
 *
 * Input:
 *	ha = adapter block pointer.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_get_id_list(scsi_qla_host_t *vha, void *id_list, dma_addr_t id_list_dma,
    uint16_t *entries)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	struct qla_hw_data *ha = vha->hw;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1079,
	    "Entered %s.\n", __func__);

	if (id_list == NULL)
		return QLA_FUNCTION_FAILED;

	mcp->mb[0] = MBC_GET_ID_LIST;
	mcp->out_mb = MBX_0;
	if (IS_FWI2_CAPABLE(vha->hw)) {
		mcp->mb[2] = MSW(id_list_dma);
		mcp->mb[3] = LSW(id_list_dma);
		mcp->mb[6] = MSW(MSD(id_list_dma));
		mcp->mb[7] = LSW(MSD(id_list_dma));
		mcp->mb[8] = 0;
		mcp->mb[9] = vha->vp_idx;
		mcp->out_mb |= MBX_9|MBX_8|MBX_7|MBX_6|MBX_3|MBX_2;
	} else {
		mcp->mb[1] = MSW(id_list_dma);
		mcp->mb[2] = LSW(id_list_dma);
		mcp->mb[3] = MSW(MSD(id_list_dma));
		mcp->mb[6] = LSW(MSD(id_list_dma));
		mcp->out_mb |= MBX_6|MBX_3|MBX_2|MBX_1;
	}
	mcp->in_mb = MBX_1|MBX_0;
	mcp->tov = (ha->login_timeout * 2) + (ha->login_timeout / 2);
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		if ((mcp->mb[0] == MBS_COMMAND_ERROR) &&
		    (mcp->mb[1] == 0x7))
			rval = QLA_FW_NOT_READY;
		ql_dbg(ql_dbg_mbx, vha, 0x107a, "Failed=%x.\n", rval);
	} else {
		*entries = mcp->mb[1];
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x107b,
		    "Done %s.\n", __func__);
	}

	return rval;
}
EXPORT_SYMBOL(qla2x00_get_id_list);

/*
 * qla2x00_get_resource_cnts
 *	Get current firmware resource counts.
 *
 * Input:
 *	ha = adapter block pointer.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_get_resource_cnts(scsi_qla_host_t *vha, uint16_t *cur_xchg_cnt,
    uint16_t *orig_xchg_cnt, uint16_t *cur_iocb_cnt,
    uint16_t *orig_iocb_cnt, uint16_t *max_npiv_vports, uint16_t *max_fcfs)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x107c,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_GET_RESOURCE_COUNTS;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_11|MBX_10|MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	if (IS_QLA81XX(vha->hw) || IS_QLA83XX(vha->hw))
		mcp->in_mb |= MBX_12;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx, vha, 0x107d,
		    "Failed mb[0]=%x.\n", mcp->mb[0]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x107e,
		    "Done %s mb1=%x mb2=%x mb3=%x mb6=%x mb7=%x mb10=%x "
		    "mb11=%x mb12=%x.\n", __func__, mcp->mb[1], mcp->mb[2],
		    mcp->mb[3], mcp->mb[6], mcp->mb[7], mcp->mb[10],
		    mcp->mb[11], mcp->mb[12]);

		if (cur_xchg_cnt)
			*cur_xchg_cnt = mcp->mb[3];
		if (orig_xchg_cnt)
			*orig_xchg_cnt = mcp->mb[6];
		if (cur_iocb_cnt)
			*cur_iocb_cnt = mcp->mb[7];
		if (orig_iocb_cnt)
			*orig_iocb_cnt = mcp->mb[10];
		if (vha->hw->flags.npiv_supported && max_npiv_vports)
			*max_npiv_vports = mcp->mb[11];
		if ((IS_QLA81XX(vha->hw) || IS_QLA83XX(vha->hw)) && max_fcfs)
			*max_fcfs = mcp->mb[12];
	}

	return rval;
}

/*
 * qla2x00_get_fcal_position_map
 *	Get FCAL (LILP) position map using mailbox command
 *
 * Input:
 *	ha = adapter state pointer.
 *	pos_map = buffer pointer (can be NULL).
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla2x00_get_fcal_position_map(scsi_qla_host_t *vha, char *pos_map)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	char *pmap;
	dma_addr_t pmap_dma;
	struct qla_hw_data *ha = vha->hw;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x107f,
	    "Entered %s.\n", __func__);

	pmap = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &pmap_dma);
	if (pmap  == NULL) {
		ql_log(ql_log_warn, vha, 0x1080,
		    "Memory alloc failed.\n");
		return QLA_MEMORY_ALLOC_FAILED;
	}
	memset(pmap, 0, FCAL_MAP_SIZE);

	mcp->mb[0] = MBC_GET_FC_AL_POSITION_MAP;
	mcp->mb[2] = MSW(pmap_dma);
	mcp->mb[3] = LSW(pmap_dma);
	mcp->mb[6] = MSW(MSD(pmap_dma));
	mcp->mb[7] = LSW(MSD(pmap_dma));
	mcp->out_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->buf_size = FCAL_MAP_SIZE;
	mcp->flags = MBX_DMA_IN;
	mcp->tov = (ha->login_timeout * 2) + (ha->login_timeout / 2);
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval == QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx + ql_dbg_buffer, vha, 0x1081,
		    "mb0/mb1=%x/%X FC/AL position map size (%x).\n",
		    mcp->mb[0], mcp->mb[1], (unsigned)pmap[0]);
		ql_dump_buffer(ql_dbg_mbx + ql_dbg_buffer, vha, 0x111d,
		    pmap, pmap[0] + 1);

		if (pos_map)
			memcpy(pos_map, pmap, FCAL_MAP_SIZE);
	}
	dma_pool_free(ha->s_dma_pool, pmap, pmap_dma);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1082, "Failed=%x.\n", rval);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1083,
		    "Done %s.\n", __func__);
	}

	return rval;
}

/*
 * qla2x00_get_link_status
 *
 * Input:
 *	ha = adapter block pointer.
 *	loop_id = device loop ID.
 *	ret_buf = pointer to link status return buffer.
 *
 * Returns:
 *	0 = success.
 *	BIT_0 = mem alloc error.
 *	BIT_1 = mailbox error.
 */
int
qla2x00_get_link_status(scsi_qla_host_t *vha, uint16_t loop_id,
    struct link_statistics *stats, dma_addr_t stats_dma)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	uint32_t *siter, *diter, dwords;
	struct qla_hw_data *ha = vha->hw;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1084,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_GET_LINK_STATUS;
	mcp->mb[2] = MSW(stats_dma);
	mcp->mb[3] = LSW(stats_dma);
	mcp->mb[6] = MSW(MSD(stats_dma));
	mcp->mb[7] = LSW(MSD(stats_dma));
	mcp->out_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_0;
	mcp->in_mb = MBX_0;
	if (IS_FWI2_CAPABLE(ha)) {
		mcp->mb[1] = loop_id;
		mcp->mb[4] = 0;
		mcp->mb[10] = 0;
		mcp->out_mb |= MBX_10|MBX_4|MBX_1;
		mcp->in_mb |= MBX_1;
	} else if (HAS_EXTENDED_IDS(ha)) {
		mcp->mb[1] = loop_id;
		mcp->mb[10] = 0;
		mcp->out_mb |= MBX_10|MBX_1;
	} else {
		mcp->mb[1] = loop_id << 8;
		mcp->out_mb |= MBX_1;
	}
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = IOCTL_CMD;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval == QLA_SUCCESS) {
		if (mcp->mb[0] != MBS_COMMAND_COMPLETE) {
			ql_dbg(ql_dbg_mbx, vha, 0x1085,
			    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
			rval = QLA_FUNCTION_FAILED;
		} else {
			/* Copy over data -- firmware data is LE. */
			ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1086,
			    "Done %s.\n", __func__);
			dwords = offsetof(struct link_statistics, unused1) / 4;
			siter = diter = &stats->link_fail_cnt;
			while (dwords--)
				*diter++ = le32_to_cpu(*siter++);
		}
	} else {
		/* Failed. */
		ql_dbg(ql_dbg_mbx, vha, 0x1087, "Failed=%x.\n", rval);
	}

	return rval;
}

int
qla24xx_get_isp_stats(scsi_qla_host_t *vha, struct link_statistics *stats,
    dma_addr_t stats_dma)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	uint32_t *siter, *diter, dwords;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1088,
	    "Entered %s.\n", __func__);

#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	if (!qla_firmware_active(vha)) {
		printk("%s(%ld): neither initiator, nor target "
			"mode enabled, no stats returned\n",
			__func__, vha->host_no);
		return QLA_FUNCTION_FAILED;
	}
#endif

	mcp->mb[0] = MBC_GET_LINK_PRIV_STATS;
	mcp->mb[2] = MSW(stats_dma);
	mcp->mb[3] = LSW(stats_dma);
	mcp->mb[6] = MSW(MSD(stats_dma));
	mcp->mb[7] = LSW(MSD(stats_dma));
	mcp->mb[8] = sizeof(struct link_statistics) / 4;
	mcp->mb[9] = vha->vp_idx;
	mcp->mb[10] = 0;
	mcp->out_mb = MBX_10|MBX_9|MBX_8|MBX_7|MBX_6|MBX_3|MBX_2|MBX_0;
	mcp->in_mb = MBX_2|MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = IOCTL_CMD;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval == QLA_SUCCESS) {
		if (mcp->mb[0] != MBS_COMMAND_COMPLETE) {
			ql_dbg(ql_dbg_mbx, vha, 0x1089,
			    "Failed mb[0]=%x.\n", mcp->mb[0]);
			rval = QLA_FUNCTION_FAILED;
		} else {
			ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x108a,
			    "Done %s.\n", __func__);
			/* Copy over data -- firmware data is LE. */
			dwords = sizeof(struct link_statistics) / 4;
			siter = diter = &stats->link_fail_cnt;
			while (dwords--)
				*diter++ = le32_to_cpu(*siter++);
		}
	} else {
		/* Failed. */
		ql_dbg(ql_dbg_mbx, vha, 0x108b, "Failed=%x.\n", rval);
	}

	return rval;
}

int
qla24xx_abort_command(srb_t *sp)
{
	int		rval;
	unsigned long   flags = 0;

	struct abort_entry_24xx *abt;
	dma_addr_t	abt_dma;
	uint32_t	handle;
	fc_port_t	*fcport = sp->fcport;
	struct scsi_qla_host *vha = fcport->vha;
	struct qla_hw_data *ha = vha->hw;
	struct req_que *req = vha->req;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x108c,
	    "Entered %s.\n", __func__);

	spin_lock_irqsave(&ha->hardware_lock, flags);
	for (handle = 1; handle < MAX_OUTSTANDING_COMMANDS; handle++) {
		if (req->outstanding_cmds[handle] == sp)
			break;
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);
	if (handle == MAX_OUTSTANDING_COMMANDS) {
		/* Command not found. */
		return QLA_FUNCTION_FAILED;
	}

	abt = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &abt_dma);
	if (abt == NULL) {
		ql_log(ql_log_warn, vha, 0x108d,
		    "Failed to allocate abort IOCB.\n");
		return QLA_MEMORY_ALLOC_FAILED;
	}
	memset(abt, 0, sizeof(struct abort_entry_24xx));

	abt->entry_type = ABORT_IOCB_TYPE;
	abt->entry_count = 1;
	abt->handle = MAKE_HANDLE(req->id, abt->handle);
	abt->nport_handle = cpu_to_le16(fcport->loop_id);
	abt->handle_to_abort = MAKE_HANDLE(req->id, handle);
	abt->port_id[0] = fcport->d_id.b.al_pa;
	abt->port_id[1] = fcport->d_id.b.area;
	abt->port_id[2] = fcport->d_id.b.domain;
	abt->vp_index = fcport->vha->vp_idx;

	abt->req_que_no = cpu_to_le16(req->id);

	rval = qla2x00_issue_iocb(vha, abt, abt_dma, 0);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x108e,
		    "Failed to issue IOCB (%x).\n", rval);
	} else if (abt->entry_status != 0) {
		ql_dbg(ql_dbg_mbx, vha, 0x108f,
		    "Failed to complete IOCB -- error status (%x).\n",
		    abt->entry_status);
		rval = QLA_FUNCTION_FAILED;
	} else if (abt->nport_handle != cpu_to_le16(0)) {
		ql_dbg(ql_dbg_mbx, vha, 0x1090,
		    "Failed to complete IOCB -- completion status (%x).\n",
		    le16_to_cpu(abt->nport_handle));
		rval = QLA_FUNCTION_FAILED;
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1091,
		    "Done %s.\n", __func__);
	}

	dma_pool_free(ha->s_dma_pool, abt, abt_dma);

	return rval;
}

struct tsk_mgmt_cmd {
	union {
		struct tsk_mgmt_entry tsk;
		struct sts_entry_24xx sts;
	} p;
};

static int
__qla24xx_issue_tmf(char *name, uint32_t type, struct fc_port *fcport,
    unsigned int l, int tag)
{
	int		rval, rval2;
	struct tsk_mgmt_cmd *tsk;
	struct sts_entry_24xx *sts;
	dma_addr_t	tsk_dma;
	scsi_qla_host_t *vha;
	struct qla_hw_data *ha;
	struct req_que *req;
	struct rsp_que *rsp;

	vha = fcport->vha;
	ha = vha->hw;
	req = vha->req;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1092,
	    "Entered %s.\n", __func__);

	if (ha->flags.cpu_affinity_enabled)
		rsp = ha->rsp_q_map[tag + 1];
	else
		rsp = req->rsp;
	tsk = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &tsk_dma);
	if (tsk == NULL) {
		ql_log(ql_log_warn, vha, 0x1093,
		    "Failed to allocate task management IOCB.\n");
		return QLA_MEMORY_ALLOC_FAILED;
	}
	memset(tsk, 0, sizeof(struct tsk_mgmt_cmd));

	tsk->p.tsk.entry_type = TSK_MGMT_IOCB_TYPE;
	tsk->p.tsk.entry_count = 1;
	tsk->p.tsk.handle = MAKE_HANDLE(req->id, tsk->p.tsk.handle);
	tsk->p.tsk.nport_handle = cpu_to_le16(fcport->loop_id);
	tsk->p.tsk.timeout = cpu_to_le16(ha->r_a_tov / 10 * 2);
	tsk->p.tsk.control_flags = cpu_to_le32(type);
	tsk->p.tsk.port_id[0] = fcport->d_id.b.al_pa;
	tsk->p.tsk.port_id[1] = fcport->d_id.b.area;
	tsk->p.tsk.port_id[2] = fcport->d_id.b.domain;
	tsk->p.tsk.vp_index = fcport->vha->vp_idx;
	if (type == TCF_LUN_RESET) {
		int_to_scsilun(l, &tsk->p.tsk.lun);
		host_to_fcp_swap((uint8_t *)&tsk->p.tsk.lun,
		    sizeof(tsk->p.tsk.lun));
	}

	sts = &tsk->p.sts;
	rval = qla2x00_issue_iocb(vha, tsk, tsk_dma, 0);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1094,
		    "Failed to issue %s reset IOCB (%x).\n", name, rval);
	} else if (sts->entry_status != 0) {
		ql_dbg(ql_dbg_mbx, vha, 0x1095,
		    "Failed to complete IOCB -- error status (%x).\n",
		    sts->entry_status);
		rval = QLA_FUNCTION_FAILED;
	} else if (sts->comp_status !=
	    cpu_to_le16(CS_COMPLETE)) {
		ql_dbg(ql_dbg_mbx, vha, 0x1096,
		    "Failed to complete IOCB -- completion status (%x).\n",
		    le16_to_cpu(sts->comp_status));
		rval = QLA_FUNCTION_FAILED;
	} else if (le16_to_cpu(sts->scsi_status) &
	    SS_RESPONSE_INFO_LEN_VALID) {
		if (le32_to_cpu(sts->rsp_data_len) < 4) {
			ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1097,
			    "Ignoring inconsistent data length -- not enough "
			    "response info (%d).\n",
			    le32_to_cpu(sts->rsp_data_len));
		} else if (sts->data[3]) {
			ql_dbg(ql_dbg_mbx, vha, 0x1098,
			    "Failed to complete IOCB -- response (%x).\n",
			    sts->data[3]);
			rval = QLA_FUNCTION_FAILED;
		}
	}

	/* Issue marker IOCB. */
	rval2 = qla2x00_marker(vha, req, rsp, fcport->loop_id, l,
	    type == TCF_LUN_RESET ? MK_SYNC_ID_LUN : MK_SYNC_ID);
	if (rval2 != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1099,
		    "Failed to issue marker IOCB (%x).\n", rval2);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x109a,
		    "Done %s.\n", __func__);
	}

	dma_pool_free(ha->s_dma_pool, tsk, tsk_dma);

	return rval;
}

int
qla24xx_abort_target(struct fc_port *fcport, unsigned int l, int tag)
{
	struct qla_hw_data *ha = fcport->vha->hw;

	if ((ql2xasynctmfenable) && IS_FWI2_CAPABLE(ha))
		return qla2x00_async_tm_cmd(fcport, TCF_TARGET_RESET, l, tag);

	return __qla24xx_issue_tmf("Target", TCF_TARGET_RESET, fcport, l, tag);
}

int
qla24xx_lun_reset(struct fc_port *fcport, unsigned int l, int tag)
{
	struct qla_hw_data *ha = fcport->vha->hw;

	if ((ql2xasynctmfenable) && IS_FWI2_CAPABLE(ha))
		return qla2x00_async_tm_cmd(fcport, TCF_LUN_RESET, l, tag);

	return __qla24xx_issue_tmf("Lun", TCF_LUN_RESET, fcport, l, tag);
}

int
qla2x00_system_error(scsi_qla_host_t *vha)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	struct qla_hw_data *ha = vha->hw;

	if (!IS_QLA23XX(ha) && !IS_FWI2_CAPABLE(ha))
		return QLA_FUNCTION_FAILED;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x109b,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_GEN_SYSTEM_ERROR;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_0;
	mcp->tov = 5;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x109c, "Failed=%x.\n", rval);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x109d,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla2x00_set_serdes_params(scsi_qla_host_t *vha, uint16_t sw_em_1g,
    uint16_t sw_em_2g, uint16_t sw_em_4g)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x109e,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_SERDES_PARAMS;
	mcp->mb[1] = BIT_0;
	mcp->mb[2] = sw_em_1g | BIT_15;
	mcp->mb[3] = sw_em_2g | BIT_15;
	mcp->mb[4] = sw_em_4g | BIT_15;
	mcp->out_mb = MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx, vha, 0x109f,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		/*EMPTY*/
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10a0,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla2x00_stop_firmware(scsi_qla_host_t *vha)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	if (!IS_FWI2_CAPABLE(vha->hw))
		return QLA_FUNCTION_FAILED;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10a1,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_STOP_FIRMWARE;
	mcp->mb[1] = 0;
	mcp->out_mb = MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->tov = 5;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10a2, "Failed=%x.\n", rval);
		if (mcp->mb[0] == MBS_INVALID_COMMAND)
			rval = QLA_INVALID_COMMAND;
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10a3,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla2x00_enable_eft_trace(scsi_qla_host_t *vha, dma_addr_t eft_dma,
    uint16_t buffers)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10a4,
	    "Entered %s.\n", __func__);

	if (!IS_FWI2_CAPABLE(vha->hw))
		return QLA_FUNCTION_FAILED;

	if (unlikely(pci_channel_offline(vha->hw->pdev)))
		return QLA_FUNCTION_FAILED;

	mcp->mb[0] = MBC_TRACE_CONTROL;
	mcp->mb[1] = TC_EFT_ENABLE;
	mcp->mb[2] = LSW(eft_dma);
	mcp->mb[3] = MSW(eft_dma);
	mcp->mb[4] = LSW(MSD(eft_dma));
	mcp->mb[5] = MSW(MSD(eft_dma));
	mcp->mb[6] = buffers;
	mcp->mb[7] = TC_AEN_DISABLE;
	mcp->out_mb = MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10a5,
		    "Failed=%x mb[0]=%x mb[1]=%x.\n",
		    rval, mcp->mb[0], mcp->mb[1]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10a6,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla2x00_disable_eft_trace(scsi_qla_host_t *vha)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10a7,
	    "Entered %s.\n", __func__);

	if (!IS_FWI2_CAPABLE(vha->hw))
		return QLA_FUNCTION_FAILED;

	if (unlikely(pci_channel_offline(vha->hw->pdev)))
		return QLA_FUNCTION_FAILED;

	mcp->mb[0] = MBC_TRACE_CONTROL;
	mcp->mb[1] = TC_EFT_DISABLE;
	mcp->out_mb = MBX_1|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10a8,
		    "Failed=%x mb[0]=%x mb[1]=%x.\n",
		    rval, mcp->mb[0], mcp->mb[1]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10a9,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla2x00_enable_fce_trace(scsi_qla_host_t *vha, dma_addr_t fce_dma,
    uint16_t buffers, uint16_t *mb, uint32_t *dwords)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10aa,
	    "Entered %s.\n", __func__);

	if (!IS_QLA25XX(vha->hw) && !IS_QLA81XX(vha->hw) &&
	    !IS_QLA83XX(vha->hw))
		return QLA_FUNCTION_FAILED;

	if (unlikely(pci_channel_offline(vha->hw->pdev)))
		return QLA_FUNCTION_FAILED;

	mcp->mb[0] = MBC_TRACE_CONTROL;
	mcp->mb[1] = TC_FCE_ENABLE;
	mcp->mb[2] = LSW(fce_dma);
	mcp->mb[3] = MSW(fce_dma);
	mcp->mb[4] = LSW(MSD(fce_dma));
	mcp->mb[5] = MSW(MSD(fce_dma));
	mcp->mb[6] = buffers;
	mcp->mb[7] = TC_AEN_DISABLE;
	mcp->mb[8] = 0;
	mcp->mb[9] = TC_FCE_DEFAULT_RX_SIZE;
	mcp->mb[10] = TC_FCE_DEFAULT_TX_SIZE;
	mcp->out_mb = MBX_10|MBX_9|MBX_8|MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|
	    MBX_1|MBX_0;
	mcp->in_mb = MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10ab,
		    "Failed=%x mb[0]=%x mb[1]=%x.\n",
		    rval, mcp->mb[0], mcp->mb[1]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10ac,
		    "Done %s.\n", __func__);

		if (mb)
			memcpy(mb, mcp->mb, 8 * sizeof(*mb));
		if (dwords)
			*dwords = buffers;
	}

	return rval;
}

int
qla2x00_disable_fce_trace(scsi_qla_host_t *vha, uint64_t *wr, uint64_t *rd)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10ad,
	    "Entered %s.\n", __func__);

	if (!IS_FWI2_CAPABLE(vha->hw))
		return QLA_FUNCTION_FAILED;

	if (unlikely(pci_channel_offline(vha->hw->pdev)))
		return QLA_FUNCTION_FAILED;

	mcp->mb[0] = MBC_TRACE_CONTROL;
	mcp->mb[1] = TC_FCE_DISABLE;
	mcp->mb[2] = TC_FCE_DISABLE_TRACE;
	mcp->out_mb = MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_9|MBX_8|MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|
	    MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10ae,
		    "Failed=%x mb[0]=%x mb[1]=%x.\n",
		    rval, mcp->mb[0], mcp->mb[1]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10af,
		    "Done %s.\n", __func__);

		if (wr)
			*wr = (uint64_t) mcp->mb[5] << 48 |
			    (uint64_t) mcp->mb[4] << 32 |
			    (uint64_t) mcp->mb[3] << 16 |
			    (uint64_t) mcp->mb[2];
		if (rd)
			*rd = (uint64_t) mcp->mb[9] << 48 |
			    (uint64_t) mcp->mb[8] << 32 |
			    (uint64_t) mcp->mb[7] << 16 |
			    (uint64_t) mcp->mb[6];
	}

	return rval;
}

int
qla2x00_get_idma_speed(scsi_qla_host_t *vha, uint16_t loop_id,
	uint16_t *port_speed, uint16_t *mb)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10b0,
	    "Entered %s.\n", __func__);

	if (!IS_IIDMA_CAPABLE(vha->hw))
		return QLA_FUNCTION_FAILED;

	mcp->mb[0] = MBC_PORT_PARAMS;
	mcp->mb[1] = loop_id;
	mcp->mb[2] = mcp->mb[3] = 0;
	mcp->mb[9] = vha->vp_idx;
	mcp->out_mb = MBX_9|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_3|MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	/* Return mailbox statuses. */
	if (mb != NULL) {
		mb[0] = mcp->mb[0];
		mb[1] = mcp->mb[1];
		mb[3] = mcp->mb[3];
	}

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10b1, "Failed=%x.\n", rval);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10b2,
		    "Done %s.\n", __func__);
		if (port_speed)
			*port_speed = mcp->mb[3];
	}

	return rval;
}

int
qla2x00_set_idma_speed(scsi_qla_host_t *vha, uint16_t loop_id,
    uint16_t port_speed, uint16_t *mb)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10b3,
	    "Entered %s.\n", __func__);

	if (!IS_IIDMA_CAPABLE(vha->hw))
		return QLA_FUNCTION_FAILED;

	mcp->mb[0] = MBC_PORT_PARAMS;
	mcp->mb[1] = loop_id;
	mcp->mb[2] = BIT_0;
	if (IS_CNA_CAPABLE(vha->hw))
		mcp->mb[3] = port_speed & (BIT_5|BIT_4|BIT_3|BIT_2|BIT_1|BIT_0);
	else
		mcp->mb[3] = port_speed & (BIT_2|BIT_1|BIT_0);
	mcp->mb[4] = mcp->mb[5] = 0;
	mcp->mb[9] = vha->vp_idx;
	mcp->out_mb = MBX_9|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_3|MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	/* Return mailbox statuses. */
	if (mb != NULL) {
		mb[0] = mcp->mb[0];
		mb[1] = mcp->mb[1];
		mb[3] = mcp->mb[3];
		mb[4] = mcp->mb[4];
		mb[5] = mcp->mb[5];
	}

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10b4,
		    "Failed=%x.\n", rval);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10b5,
		    "Done %s.\n", __func__);
	}

	return rval;
}

void
qla24xx_report_id_acquisition(scsi_qla_host_t *vha,
	struct vp_rpt_id_entry_24xx *rptid_entry)
{
	uint8_t vp_idx;
	uint16_t stat = le16_to_cpu(rptid_entry->vp_idx);
	struct qla_hw_data *ha = vha->hw;
	scsi_qla_host_t *vp;
	unsigned long   flags;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10b6,
	    "Entered %s.\n", __func__);

	if (rptid_entry->entry_status != 0)
		return;

	if (rptid_entry->format == 0) {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10b7,
		    "Format 0 : Number of VPs setup %d, number of "
		    "VPs acquired %d.\n",
		    MSB(le16_to_cpu(rptid_entry->vp_count)),
		    LSB(le16_to_cpu(rptid_entry->vp_count)));
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10b8,
		    "Primary port id %02x%02x%02x.\n",
		    rptid_entry->port_id[2], rptid_entry->port_id[1],
		    rptid_entry->port_id[0]);
	} else if (rptid_entry->format == 1) {
		bool found;

		vp_idx = LSB(stat);
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10b9,
		    "Format 1: VP[%d] enabled - status %d - with "
		    "port id %02x%02x%02x.\n", vp_idx, MSB(stat),
		    rptid_entry->port_id[2], rptid_entry->port_id[1],
		    rptid_entry->port_id[0]);

		vp = vha;
		if (vp_idx == 0 && (MSB(stat) != 1))
			goto reg_needed;

		if (MSB(stat) != 0) {
			ql_dbg(ql_dbg_mbx, vha, 0x10ba,
			    "Could not acquire ID for VP[%d].\n", vp_idx);
			return;
		}

		found = false;
		spin_lock_irqsave(&ha->vport_slock, flags);
		list_for_each_entry(vp, &ha->vp_list, list)
			if (vp_idx == vp->vp_idx) {
				found = true;
				break;
			}
		spin_unlock_irqrestore(&ha->vport_slock, flags);

		if (!found)
			return;

		vp->d_id.b.domain = rptid_entry->port_id[2];
		vp->d_id.b.area =  rptid_entry->port_id[1];
		vp->d_id.b.al_pa = rptid_entry->port_id[0];

		/*
		 * Cannot configure here as we are still sitting on the
		 * response queue. Handle it in dpc context.
		 */
		set_bit(VP_IDX_ACQUIRED, &vp->vp_flags);

reg_needed:
		set_bit(REGISTER_FC4_NEEDED, &vp->dpc_flags);
		set_bit(REGISTER_FDMI_NEEDED, &vp->dpc_flags);
		set_bit(VP_DPC_NEEDED, &vha->dpc_flags);
		qla2xxx_wake_dpc(vha);
	}
}

/*
 * qla24xx_modify_vp_config
 *	Change VP configuration for vha
 *
 * Input:
 *	vha = adapter block pointer.
 *
 * Returns:
 *	qla2xxx local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla24xx_modify_vp_config(scsi_qla_host_t *vha)
{
	int		rval;
	struct vp_config_entry_24xx *vpmod;
	dma_addr_t	vpmod_dma;
	struct qla_hw_data *ha = vha->hw;
	struct scsi_qla_host *base_vha = pci_get_drvdata(ha->pdev);

	if (!qla_firmware_active(vha)) {
		rval = QLA_SUCCESS;
		goto out;
	}

	/* This can be called by the parent */

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10bb,
	    "Entered %s.\n", __func__);

	vpmod = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &vpmod_dma);
	if (!vpmod) {
		ql_log(ql_log_warn, vha, 0x10bc,
		    "Failed to allocate modify VP IOCB.\n");
		return QLA_MEMORY_ALLOC_FAILED;
	}

	memset(vpmod, 0, sizeof(struct vp_config_entry_24xx));
	vpmod->entry_type = VP_CONFIG_IOCB_TYPE;
	vpmod->entry_count = 1;
	vpmod->command = VCT_COMMAND_MOD_ENABLE_VPS;
	vpmod->vp_count = 1;
	vpmod->vp_index1 = vha->vp_idx;
	vpmod->options_idx1 = BIT_3|BIT_4|BIT_5;
#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	/* Enable target mode */
	if (qla_tgt_mode_enabled(vha))
		vpmod->options_idx1 &= ~BIT_5;
	/* Disable ini mode, if requested */
	if (!qla_ini_mode_enabled(vha))
		vpmod->options_idx1 &= ~BIT_4;
#endif
	memcpy(vpmod->node_name_idx1, vha->node_name, WWN_SIZE);
	memcpy(vpmod->port_name_idx1, vha->port_name, WWN_SIZE);
	vpmod->entry_count = 1;

	rval = qla2x00_issue_iocb(base_vha, vpmod, vpmod_dma, 0);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10bd,
		    "Failed to issue VP config IOCB (%x).\n", rval);
	} else if (vpmod->comp_status != 0) {
		ql_dbg(ql_dbg_mbx, vha, 0x10be,
		    "Failed to complete IOCB -- error status (%x).\n",
		    vpmod->comp_status);
		rval = QLA_FUNCTION_FAILED;
	} else if (vpmod->comp_status != cpu_to_le16(CS_COMPLETE)) {
		ql_dbg(ql_dbg_mbx, vha, 0x10bf,
		    "Failed to complete IOCB -- completion status (%x).\n",
		    le16_to_cpu(vpmod->comp_status));
		rval = QLA_FUNCTION_FAILED;
	} else {
		/* EMPTY */
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10c0,
		    "Done %s.\n", __func__);
		fc_vport_set_state(vha->fc_vport, FC_VPORT_INITIALIZING);
	}
	dma_pool_free(ha->s_dma_pool, vpmod, vpmod_dma);

out:
	return rval;
}

/*
 * qla24xx_control_vp
 *	Enable a virtual port for given host
 *
 * Input:
 *	ha = adapter block pointer.
 *	vhba = virtual adapter (unused)
 *	index = index number for enabled VP
 *
 * Returns:
 *	qla2xxx local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qla24xx_control_vp(scsi_qla_host_t *vha, int cmd)
{
	int		rval;
	int		map, pos;
	struct vp_ctrl_entry_24xx   *vce;
	dma_addr_t	vce_dma;
	struct qla_hw_data *ha = vha->hw;
	int	vp_index = vha->vp_idx;
	struct scsi_qla_host *base_vha = pci_get_drvdata(ha->pdev);

	if (!qla_firmware_active(vha)) {
		rval = QLA_SUCCESS;
		goto out;
	}

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10c1,
	    "Entered %s enabling index %d.\n", __func__, vp_index);

	if (vp_index == 0 || vp_index >= ha->max_npiv_vports)
		return QLA_PARAMETER_ERROR;

	vce = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &vce_dma);
	if (!vce) {
		ql_log(ql_log_warn, vha, 0x10c2,
		    "Failed to allocate VP control IOCB.\n");
		return QLA_MEMORY_ALLOC_FAILED;
	}
	memset(vce, 0, sizeof(struct vp_ctrl_entry_24xx));

	vce->entry_type = VP_CTRL_IOCB_TYPE;
	vce->entry_count = 1;
	vce->command = cpu_to_le16(cmd);
	vce->vp_count = cpu_to_le16(1);

	/* index map in firmware starts with 1; decrement index
	 * this is ok as we never use index 0
	 */
	map = (vp_index - 1) / 8;
	pos = (vp_index - 1) & 7;
	mutex_lock(&ha->vport_lock);
	vce->vp_idx_map[map] |= 1 << pos;
	mutex_unlock(&ha->vport_lock);

	rval = qla2x00_issue_iocb(base_vha, vce, vce_dma, 0);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10c3,
		    "Failed to issue VP control IOCB (%x).\n", rval);
	} else if (vce->entry_status != 0) {
		ql_dbg(ql_dbg_mbx, vha, 0x10c4,
		    "Failed to complete IOCB -- error status (%x).\n",
		    vce->entry_status);
		rval = QLA_FUNCTION_FAILED;
	} else if (vce->comp_status != cpu_to_le16(CS_COMPLETE)) {
		/*
		 * It can fail, because this function can be called 2 times on
		 * VPs delete: one from q2t_target_stop() and another - from
		 * qla24xx_vport_delete(). The second call will fail.
		 */
		ql_dbg(ql_dbg_mbx, vha, 0x10c5,
		    "Failed to complet IOCB -- completion status (%x).\n",
		    le16_to_cpu(vce->comp_status));
		rval = QLA_FUNCTION_FAILED;
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10c6,
		    "Done %s.\n", __func__);
	}

	dma_pool_free(ha->s_dma_pool, vce, vce_dma);

out:
	return rval;
}

/*
 * qla2x00_send_change_request
 *	Receive or disable RSCN request from fabric controller
 *
 * Input:
 *	ha = adapter block pointer
 *	format = registration format:
 *		0 - Reserved
 *		1 - Fabric detected registration
 *		2 - N_port detected registration
 *		3 - Full registration
 *		FF - clear registration
 *	vp_idx = Virtual port index
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel Context
 */

int
qla2x00_send_change_request(scsi_qla_host_t *vha, uint16_t format,
			    uint16_t vp_idx)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10c7,
	    "Entered %s.\n", __func__);

	/*
	 * This command is implicitly executed by firmware during login for the
	 * physical hosts if initiator mode is enabled.
	 */
	if (vp_idx == 0 && (vha->host->active_mode & MODE_INITIATOR))
		return QLA_FUNCTION_FAILED;

	mcp->mb[0] = MBC_SEND_CHANGE_REQUEST;
	mcp->mb[1] = format;
	mcp->mb[9] = vp_idx;
	mcp->out_mb = MBX_9|MBX_1|MBX_0;
	mcp->in_mb = MBX_0|MBX_1;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval == QLA_SUCCESS) {
		if (mcp->mb[0] != MBS_COMMAND_COMPLETE) {
			rval = BIT_1;
		}
	} else
		rval = BIT_1;

	return rval;
}
EXPORT_SYMBOL(qla2x00_send_change_request);

int
qla2x00_dump_ram(scsi_qla_host_t *vha, dma_addr_t req_dma, uint32_t addr,
    uint32_t size)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1009,
	    "Entered %s.\n", __func__);

	if (MSW(addr) || IS_FWI2_CAPABLE(vha->hw)) {
		mcp->mb[0] = MBC_DUMP_RISC_RAM_EXTENDED;
		mcp->mb[8] = MSW(addr);
		mcp->out_mb = MBX_8|MBX_0;
	} else {
		mcp->mb[0] = MBC_DUMP_RISC_RAM;
		mcp->out_mb = MBX_0;
	}
	mcp->mb[1] = LSW(addr);
	mcp->mb[2] = MSW(req_dma);
	mcp->mb[3] = LSW(req_dma);
	mcp->mb[6] = MSW(MSD(req_dma));
	mcp->mb[7] = LSW(MSD(req_dma));
	mcp->out_mb |= MBX_7|MBX_6|MBX_3|MBX_2|MBX_1;
	if (IS_FWI2_CAPABLE(vha->hw)) {
		mcp->mb[4] = MSW(size);
		mcp->mb[5] = LSW(size);
		mcp->out_mb |= MBX_5|MBX_4;
	} else {
		mcp->mb[4] = LSW(size);
		mcp->out_mb |= MBX_4;
	}

	mcp->in_mb = MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1008,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1007,
		    "Done %s.\n", __func__);
	}

	return rval;
}

/* 84XX Support **************************************************************/

struct cs84xx_mgmt_cmd {
	union {
		struct verify_chip_entry_84xx req;
		struct verify_chip_rsp_84xx rsp;
	} p;
};

int
qla84xx_verify_chip(struct scsi_qla_host *vha, uint16_t *status)
{
	int rval, retry;
	struct cs84xx_mgmt_cmd *mn;
	dma_addr_t mn_dma;
	uint16_t options;
	unsigned long flags;
	struct qla_hw_data *ha = vha->hw;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10c8,
	    "Entered %s.\n", __func__);

	mn = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &mn_dma);
	if (mn == NULL) {
		return QLA_MEMORY_ALLOC_FAILED;
	}

	/* Force Update? */
	options = ha->cs84xx->fw_update ? VCO_FORCE_UPDATE : 0;
	/* Diagnostic firmware? */
	/* options |= MENLO_DIAG_FW; */
	/* We update the firmware with only one data sequence. */
	options |= VCO_END_OF_DATA;

	do {
		retry = 0;
		memset(mn, 0, sizeof(*mn));
		mn->p.req.entry_type = VERIFY_CHIP_IOCB_TYPE;
		mn->p.req.entry_count = 1;
		mn->p.req.options = cpu_to_le16(options);

		ql_dbg(ql_dbg_mbx + ql_dbg_buffer, vha, 0x111c,
		    "Dump of Verify Request.\n");
		ql_dump_buffer(ql_dbg_mbx + ql_dbg_buffer, vha, 0x111e,
		    (uint8_t *)mn, sizeof(*mn));

		rval = qla2x00_issue_iocb_timeout(vha, mn, mn_dma, 0, 120);
		if (rval != QLA_SUCCESS) {
			ql_dbg(ql_dbg_mbx, vha, 0x10cb,
			    "Failed to issue verify IOCB (%x).\n", rval);
			goto verify_done;
		}

		ql_dbg(ql_dbg_mbx + ql_dbg_buffer, vha, 0x1110,
		    "Dump of Verify Response.\n");
		ql_dump_buffer(ql_dbg_mbx + ql_dbg_buffer, vha, 0x1118,
		    (uint8_t *)mn, sizeof(*mn));

		status[0] = le16_to_cpu(mn->p.rsp.comp_status);
		status[1] = status[0] == CS_VCS_CHIP_FAILURE ?
		    le16_to_cpu(mn->p.rsp.failure_code) : 0;
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10ce,
		    "cs=%x fc=%x.\n", status[0], status[1]);

		if (status[0] != CS_COMPLETE) {
			rval = QLA_FUNCTION_FAILED;
			if (!(options & VCO_DONT_UPDATE_FW)) {
				ql_dbg(ql_dbg_mbx, vha, 0x10cf,
				    "Firmware update failed. Retrying "
				    "without update firmware.\n");
				options |= VCO_DONT_UPDATE_FW;
				options &= ~VCO_FORCE_UPDATE;
				retry = 1;
			}
		} else {
			ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10d0,
			    "Firmware updated to %x.\n",
			    le32_to_cpu(mn->p.rsp.fw_ver));

			/* NOTE: we only update OP firmware. */
			spin_lock_irqsave(&ha->cs84xx->access_lock, flags);
			ha->cs84xx->op_fw_version =
			    le32_to_cpu(mn->p.rsp.fw_ver);
			spin_unlock_irqrestore(&ha->cs84xx->access_lock,
			    flags);
		}
	} while (retry);

verify_done:
	dma_pool_free(ha->s_dma_pool, mn, mn_dma);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10d1,
		    "Failed=%x.\n", rval);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10d2,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla25xx_init_req_que(struct scsi_qla_host *vha, struct req_que *req)
{
	int rval;
	unsigned long flags;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	struct device_reg_25xxmq __iomem *reg;
	struct qla_hw_data *ha = vha->hw;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10d3,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_INITIALIZE_MULTIQ;
	mcp->mb[1] = req->options;
	mcp->mb[2] = MSW(LSD(req->dma));
	mcp->mb[3] = LSW(LSD(req->dma));
	mcp->mb[6] = MSW(MSD(req->dma));
	mcp->mb[7] = LSW(MSD(req->dma));
	mcp->mb[5] = req->length;
	if (req->rsp)
		mcp->mb[10] = req->rsp->id;
	mcp->mb[12] = req->qos;
	mcp->mb[11] = req->vp_idx;
	mcp->mb[13] = req->rid;
	if (IS_QLA83XX(ha))
		mcp->mb[15] = 0;

	reg = (struct device_reg_25xxmq *)((void *)(ha->mqiobase) +
		QLA_QUE_PAGE * req->id);

	mcp->mb[4] = req->id;
	/* que in ptr index */
	mcp->mb[8] = 0;
	/* que out ptr index */
	mcp->mb[9] = 0;
	mcp->out_mb = MBX_14|MBX_13|MBX_12|MBX_11|MBX_10|MBX_9|MBX_8|MBX_7|
			MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->flags = MBX_DMA_OUT;
	mcp->tov = MBX_TOV_SECONDS * 2;

	if (IS_QLA81XX(ha) || IS_QLA83XX(ha))
		mcp->in_mb |= MBX_1;
	if (IS_QLA83XX(ha)) {
		mcp->out_mb |= MBX_15;
		/* debug q create issue in SR-IOV */
		mcp->in_mb |= MBX_9 | MBX_8 | MBX_7;
	}

	spin_lock_irqsave(&ha->hardware_lock, flags);
	if (!(req->options & BIT_0)) {
		WRT_REG_DWORD(&reg->req_q_in, 0);
		if (!IS_QLA83XX(ha))
			WRT_REG_DWORD(&reg->req_q_out, 0);
	}
	req->req_q_in = &reg->req_q_in;
	req->req_q_out = &reg->req_q_out;
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10d4,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10d5,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla25xx_init_rsp_que(struct scsi_qla_host *vha, struct rsp_que *rsp)
{
	int rval;
	unsigned long flags;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	struct device_reg_25xxmq __iomem *reg;
	struct qla_hw_data *ha = vha->hw;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10d6,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_INITIALIZE_MULTIQ;
	mcp->mb[1] = rsp->options;
	mcp->mb[2] = MSW(LSD(rsp->dma));
	mcp->mb[3] = LSW(LSD(rsp->dma));
	mcp->mb[6] = MSW(MSD(rsp->dma));
	mcp->mb[7] = LSW(MSD(rsp->dma));
	mcp->mb[5] = rsp->length;
	mcp->mb[14] = rsp->msix->entry;
	mcp->mb[13] = rsp->rid;
	if (IS_QLA83XX(ha))
		mcp->mb[15] = 0;

	reg = (struct device_reg_25xxmq *)((void *)(ha->mqiobase) +
		QLA_QUE_PAGE * rsp->id);

	mcp->mb[4] = rsp->id;
	/* que in ptr index */
	mcp->mb[8] = 0;
	/* que out ptr index */
	mcp->mb[9] = 0;
	mcp->out_mb = MBX_14|MBX_13|MBX_9|MBX_8|MBX_7
			|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->flags = MBX_DMA_OUT;
	mcp->tov = MBX_TOV_SECONDS * 2;

	if (IS_QLA81XX(ha)) {
		mcp->out_mb |= MBX_12|MBX_11|MBX_10;
		mcp->in_mb |= MBX_1;
	} else if (IS_QLA83XX(ha)) {
		mcp->out_mb |= MBX_15|MBX_12|MBX_11|MBX_10;
		mcp->in_mb |= MBX_1;
		/* debug q create issue in SR-IOV */
		mcp->in_mb |= MBX_9 | MBX_8 | MBX_7;
	}

	spin_lock_irqsave(&ha->hardware_lock, flags);
	if (!(rsp->options & BIT_0)) {
		WRT_REG_DWORD(&reg->rsp_q_out, 0);
		if (!IS_QLA83XX(ha))
			WRT_REG_DWORD(&reg->rsp_q_in, 0);
	}

	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10d7,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10d8,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla81xx_idc_ack(scsi_qla_host_t *vha, uint16_t *mb)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10d9,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_IDC_ACK;
	memcpy(&mcp->mb[1], mb, QLA_IDC_ACK_REGS * sizeof(uint16_t));
	mcp->out_mb = MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10da,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10db,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla81xx_fac_get_sector_size(scsi_qla_host_t *vha, uint32_t *sector_size)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10dc,
	    "Entered %s.\n", __func__);

	if (!IS_QLA81XX(vha->hw) && !IS_QLA83XX(vha->hw))
		return QLA_FUNCTION_FAILED;

	mcp->mb[0] = MBC_FLASH_ACCESS_CTRL;
	mcp->mb[1] = FAC_OPT_CMD_GET_SECTOR_SIZE;
	mcp->out_mb = MBX_1|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10dd,
		    "Failed=%x mb[0]=%x mb[1]=%x.\n",
		    rval, mcp->mb[0], mcp->mb[1]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10de,
		    "Done %s.\n", __func__);
		*sector_size = mcp->mb[1];
	}

	return rval;
}

int
qla81xx_fac_do_write_enable(scsi_qla_host_t *vha, int enable)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	if (!IS_QLA81XX(vha->hw) && !IS_QLA83XX(vha->hw))
		return QLA_FUNCTION_FAILED;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10df,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_FLASH_ACCESS_CTRL;
	mcp->mb[1] = enable ? FAC_OPT_CMD_WRITE_ENABLE :
	    FAC_OPT_CMD_WRITE_PROTECT;
	mcp->out_mb = MBX_1|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10e0,
		    "Failed=%x mb[0]=%x mb[1]=%x.\n",
		    rval, mcp->mb[0], mcp->mb[1]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10e1,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla81xx_fac_erase_sector(scsi_qla_host_t *vha, uint32_t start, uint32_t finish)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	if (!IS_QLA81XX(vha->hw) && !IS_QLA83XX(vha->hw))
		return QLA_FUNCTION_FAILED;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10e2,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_FLASH_ACCESS_CTRL;
	mcp->mb[1] = FAC_OPT_CMD_ERASE_SECTOR;
	mcp->mb[2] = LSW(start);
	mcp->mb[3] = MSW(start);
	mcp->mb[4] = LSW(finish);
	mcp->mb[5] = MSW(finish);
	mcp->out_mb = MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_2|MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10e3,
		    "Failed=%x mb[0]=%x mb[1]=%x mb[2]=%x.\n",
		    rval, mcp->mb[0], mcp->mb[1], mcp->mb[2]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10e4,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla81xx_restart_mpi_firmware(scsi_qla_host_t *vha)
{
	int rval = 0;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10e5,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_RESTART_MPI_FW;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_0|MBX_1;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10e6,
		    "Failed=%x mb[0]=%x mb[1]=%x.\n",
		    rval, mcp->mb[0], mcp->mb[1]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10e7,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla2x00_read_sfp(scsi_qla_host_t *vha, dma_addr_t sfp_dma, uint8_t *sfp,
	uint16_t dev, uint16_t off, uint16_t len, uint16_t opt)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	struct qla_hw_data *ha = vha->hw;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10e8,
	    "Entered %s.\n", __func__);

	if (!IS_FWI2_CAPABLE(ha))
		return QLA_FUNCTION_FAILED;

	if (len == 1)
		opt |= BIT_0;

	mcp->mb[0] = MBC_READ_SFP;
	mcp->mb[1] = dev;
	mcp->mb[2] = MSW(sfp_dma);
	mcp->mb[3] = LSW(sfp_dma);
	mcp->mb[6] = MSW(MSD(sfp_dma));
	mcp->mb[7] = LSW(MSD(sfp_dma));
	mcp->mb[8] = len;
	mcp->mb[9] = off;
	mcp->mb[10] = opt;
	mcp->out_mb = MBX_10|MBX_9|MBX_8|MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (opt & BIT_0)
		*sfp = mcp->mb[1];

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10e9,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10ea,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla2x00_write_sfp(scsi_qla_host_t *vha, dma_addr_t sfp_dma, uint8_t *sfp,
	uint16_t dev, uint16_t off, uint16_t len, uint16_t opt)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	struct qla_hw_data *ha = vha->hw;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10eb,
	    "Entered %s.\n", __func__);

	if (!IS_FWI2_CAPABLE(ha))
		return QLA_FUNCTION_FAILED;

	if (len == 1)
		opt |= BIT_0;

	if (opt & BIT_0)
		len = *sfp;

	mcp->mb[0] = MBC_WRITE_SFP;
	mcp->mb[1] = dev;
	mcp->mb[2] = MSW(sfp_dma);
	mcp->mb[3] = LSW(sfp_dma);
	mcp->mb[6] = MSW(MSD(sfp_dma));
	mcp->mb[7] = LSW(MSD(sfp_dma));
	mcp->mb[8] = len;
	mcp->mb[9] = off;
	mcp->mb[10] = opt;
	mcp->out_mb = MBX_10|MBX_9|MBX_8|MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10ec,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10ed,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla2x00_get_xgmac_stats(scsi_qla_host_t *vha, dma_addr_t stats_dma,
    uint16_t size_in_bytes, uint16_t *actual_size)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10ee,
	    "Entered %s.\n", __func__);

	if (!IS_CNA_CAPABLE(vha->hw))
		return QLA_FUNCTION_FAILED;

	mcp->mb[0] = MBC_GET_XGMAC_STATS;
	mcp->mb[2] = MSW(stats_dma);
	mcp->mb[3] = LSW(stats_dma);
	mcp->mb[6] = MSW(MSD(stats_dma));
	mcp->mb[7] = LSW(MSD(stats_dma));
	mcp->mb[8] = size_in_bytes >> 2;
	mcp->out_mb = MBX_8|MBX_7|MBX_6|MBX_3|MBX_2|MBX_0;
	mcp->in_mb = MBX_2|MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10ef,
		    "Failed=%x mb[0]=%x mb[1]=%x mb[2]=%x.\n",
		    rval, mcp->mb[0], mcp->mb[1], mcp->mb[2]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10f0,
		    "Done %s.\n", __func__);


		*actual_size = mcp->mb[2] << 2;
	}

	return rval;
}

int
qla2x00_get_dcbx_params(scsi_qla_host_t *vha, dma_addr_t tlv_dma,
    uint16_t size)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10f1,
	    "Entered %s.\n", __func__);

	if (!IS_CNA_CAPABLE(vha->hw))
		return QLA_FUNCTION_FAILED;

	mcp->mb[0] = MBC_GET_DCBX_PARAMS;
	mcp->mb[1] = 0;
	mcp->mb[2] = MSW(tlv_dma);
	mcp->mb[3] = LSW(tlv_dma);
	mcp->mb[6] = MSW(MSD(tlv_dma));
	mcp->mb[7] = LSW(MSD(tlv_dma));
	mcp->mb[8] = size;
	mcp->out_mb = MBX_8|MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_2|MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10f2,
		    "Failed=%x mb[0]=%x mb[1]=%x mb[2]=%x.\n",
		    rval, mcp->mb[0], mcp->mb[1], mcp->mb[2]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10f3,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla2x00_read_ram_word(scsi_qla_host_t *vha, uint32_t risc_addr, uint32_t *data)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10f4,
	    "Entered %s.\n", __func__);

	if (!IS_FWI2_CAPABLE(vha->hw))
		return QLA_FUNCTION_FAILED;

	mcp->mb[0] = MBC_READ_RAM_EXTENDED;
	mcp->mb[1] = LSW(risc_addr);
	mcp->mb[8] = MSW(risc_addr);
	mcp->out_mb = MBX_8|MBX_1|MBX_0;
	mcp->in_mb = MBX_3|MBX_2|MBX_0;
	mcp->tov = 30;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10f5,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10f6,
		    "Done %s.\n", __func__);
		*data = mcp->mb[3] << 16 | mcp->mb[2];
	}

	return rval;
}

int
qla2x00_loopback_test(scsi_qla_host_t *vha, struct msg_echo_lb *mreq, uint16_t *mresp)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	uint32_t iter_cnt = 0x1;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10f7,
	    "Entered %s.\n", __func__);

	memset(mcp->mb, 0, sizeof(mcp->mb));
	mcp->mb[0] = MBC_DIAGNOSTIC_LOOP_BACK;
	mcp->mb[1] = mreq->options | BIT_6;	// BIT_6 specifies 64 bit addressing

	/* transfer count */
	mcp->mb[10] = LSW(mreq->transfer_size);
	mcp->mb[11] = MSW(mreq->transfer_size);

	/* send data address */
	mcp->mb[14] = LSW(mreq->send_dma);
	mcp->mb[15] = MSW(mreq->send_dma);
	mcp->mb[20] = LSW(MSD(mreq->send_dma));
	mcp->mb[21] = MSW(MSD(mreq->send_dma));

	/* receive data address */
	mcp->mb[16] = LSW(mreq->rcv_dma);
	mcp->mb[17] = MSW(mreq->rcv_dma);
	mcp->mb[6] = LSW(MSD(mreq->rcv_dma));
	mcp->mb[7] = MSW(MSD(mreq->rcv_dma));

	/* Iteration count */
	mcp->mb[18] = LSW(iter_cnt);
	mcp->mb[19] = MSW(iter_cnt);

	mcp->out_mb = MBX_21|MBX_20|MBX_19|MBX_18|MBX_17|MBX_16|MBX_15|
	    MBX_14|MBX_13|MBX_12|MBX_11|MBX_10|MBX_7|MBX_6|MBX_1|MBX_0;
	if (IS_CNA_CAPABLE(vha->hw))
		mcp->out_mb |= MBX_2;
	mcp->in_mb = MBX_19|MBX_18|MBX_3|MBX_2|MBX_1|MBX_0;

	mcp->buf_size = mreq->transfer_size;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = MBX_DMA_OUT|MBX_DMA_IN|IOCTL_CMD;

	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10f8,
		    "Failed=%x mb[0]=%x mb[1]=%x mb[2]=%x mb[3]=%x mb[18]=%x "
		    "mb[19]=%x.\n", rval, mcp->mb[0], mcp->mb[1], mcp->mb[2],
		    mcp->mb[3], mcp->mb[18], mcp->mb[19]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10f9,
		    "Done %s.\n", __func__);
	}

	/* Copy mailbox information */
	memcpy(mresp, mcp->mb, 64);
	return rval;
}

int
qla2x00_echo_test(scsi_qla_host_t *vha, struct msg_echo_lb *mreq, uint16_t *mresp)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	struct qla_hw_data *ha = vha->hw;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10fa,
	    "Entered %s.\n", __func__);

	memset(mcp->mb, 0, sizeof(mcp->mb));
	mcp->mb[0] = MBC_DIAGNOSTIC_ECHO;
	mcp->mb[1] = mreq->options | BIT_6;	/* BIT_6 specifies 64bit address */
	if (IS_CNA_CAPABLE(ha)) {
		mcp->mb[1] |= BIT_15;
		mcp->mb[2] = vha->fcoe_fcf_idx;
	}
	mcp->mb[16] = LSW(mreq->rcv_dma);
	mcp->mb[17] = MSW(mreq->rcv_dma);
	mcp->mb[6] = LSW(MSD(mreq->rcv_dma));
	mcp->mb[7] = MSW(MSD(mreq->rcv_dma));

	mcp->mb[10] = LSW(mreq->transfer_size);

	mcp->mb[14] = LSW(mreq->send_dma);
	mcp->mb[15] = MSW(mreq->send_dma);
	mcp->mb[20] = LSW(MSD(mreq->send_dma));
	mcp->mb[21] = MSW(MSD(mreq->send_dma));

	mcp->out_mb = MBX_21|MBX_20|MBX_17|MBX_16|MBX_15|
	    MBX_14|MBX_10|MBX_7|MBX_6|MBX_1|MBX_0;
	if (IS_CNA_CAPABLE(ha))
		mcp->out_mb |= MBX_2;

	mcp->in_mb = MBX_0;
	if (IS_QLA24XX_TYPE(ha) || IS_QLA25XX(ha) ||
	    IS_CNA_CAPABLE(ha) || IS_QLA2031(ha))
		mcp->in_mb |= MBX_1;
	if (IS_CNA_CAPABLE(ha) || IS_QLA2031(ha))
		mcp->in_mb |= MBX_3;

	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = MBX_DMA_OUT|MBX_DMA_IN|IOCTL_CMD;
	mcp->buf_size = mreq->transfer_size;

	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10fb,
		    "Failed=%x mb[0]=%x mb[1]=%x.\n",
		    rval, mcp->mb[0], mcp->mb[1]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10fc,
		    "Done %s.\n", __func__);
	}

	/* Copy mailbox information */
	memcpy(mresp, mcp->mb, 64);
	return rval;
}

int
qla84xx_reset_chip(scsi_qla_host_t *vha, uint16_t enable_diagnostic)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10fd,
	    "Entered %s enable_diag=%d.\n", __func__, enable_diagnostic);

	mcp->mb[0] = MBC_ISP84XX_RESET;
	mcp->mb[1] = enable_diagnostic;
	mcp->out_mb = MBX_1|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = MBX_DMA_OUT|MBX_DMA_IN|IOCTL_CMD;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS)
		ql_dbg(ql_dbg_mbx, vha, 0x10fe, "Failed=%x.\n", rval);
	else
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10ff,
		    "Done %s.\n", __func__);

	return rval;
}

int
qla2x00_write_ram_word(scsi_qla_host_t *vha, uint32_t risc_addr, uint32_t data)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1100,
	    "Entered %s.\n", __func__);

	if (!IS_FWI2_CAPABLE(vha->hw))
		return QLA_FUNCTION_FAILED;

	mcp->mb[0] = MBC_WRITE_RAM_WORD_EXTENDED;
	mcp->mb[1] = LSW(risc_addr);
	mcp->mb[2] = LSW(data);
	mcp->mb[3] = MSW(data);
	mcp->mb[8] = MSW(risc_addr);
	mcp->out_mb = MBX_8|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->tov = 30;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1101,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1102,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla81xx_write_mpi_register(scsi_qla_host_t *vha, uint16_t *mb)
{
	int rval;
	uint32_t stat, timer;
	uint16_t mb0 = 0;
	struct qla_hw_data *ha = vha->hw;
	struct device_reg_24xx __iomem *reg = &ha->iobase->isp24;

	rval = QLA_SUCCESS;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1103,
	    "Entered %s.\n", __func__);

	clear_bit(MBX_INTERRUPT, &ha->mbx_cmd_flags);

	/* Write the MBC data to the registers */
	WRT_REG_WORD(&reg->mailbox0, MBC_WRITE_MPI_REGISTER);
	WRT_REG_WORD(&reg->mailbox1, mb[0]);
	WRT_REG_WORD(&reg->mailbox2, mb[1]);
	WRT_REG_WORD(&reg->mailbox3, mb[2]);
	WRT_REG_WORD(&reg->mailbox4, mb[3]);

	WRT_REG_DWORD(&reg->hccr, HCCRX_SET_HOST_INT);

	/* Poll for MBC interrupt */
	for (timer = 6000000; timer; timer--) {
		/* Check for pending interrupts. */
		stat = RD_REG_DWORD(&reg->host_status);
		if (stat & HSRX_RISC_INT) {
			stat &= 0xff;

			if (stat == 0x1 || stat == 0x2 ||
			    stat == 0x10 || stat == 0x11) {
				set_bit(MBX_INTERRUPT,
				    &ha->mbx_cmd_flags);
				mb0 = RD_REG_WORD(&reg->mailbox0);
				WRT_REG_DWORD(&reg->hccr,
				    HCCRX_CLR_RISC_INT);
				RD_REG_DWORD(&reg->hccr);
				break;
			}
		}
		udelay(5);
	}

	if (test_and_clear_bit(MBX_INTERRUPT, &ha->mbx_cmd_flags))
		rval = mb0 & MBS_MASK;
	else
		rval = QLA_FUNCTION_FAILED;

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1104,
		    "Failed=%x mb[0]=%x.\n", rval, mb[0]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1105,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla2x00_get_data_rate(scsi_qla_host_t *vha)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	struct qla_hw_data *ha = vha->hw;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1106,
	    "Entered %s.\n", __func__);

	if (!IS_FWI2_CAPABLE(ha))
		return QLA_FUNCTION_FAILED;

	mcp->mb[0] = MBC_DATA_RATE;
	mcp->mb[1] = 0;
	mcp->out_mb = MBX_1|MBX_0;
	mcp->in_mb = MBX_2|MBX_1|MBX_0;
	if (IS_QLA83XX(ha))
		mcp->in_mb |= MBX_3;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1107,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1108,
		    "Done %s.\n", __func__);
		if (mcp->mb[1] != 0x7)
			ha->link_data_rate = mcp->mb[1];
	}

	return rval;
}

int
qla81xx_get_port_config(scsi_qla_host_t *vha, uint16_t *mb)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	struct qla_hw_data *ha = vha->hw;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1109,
	    "Entered %s.\n", __func__);

	if (!IS_QLA81XX(ha) && !IS_QLA83XX(ha))
		return QLA_FUNCTION_FAILED;
	mcp->mb[0] = MBC_GET_PORT_CONFIG;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;

	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x110a,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		/* Copy all bits to preserve original value */
		memcpy(mb, &mcp->mb[1], sizeof(uint16_t) * 4);

		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x110b,
		    "Done %s.\n", __func__);
	}
	return rval;
}

int
qla81xx_set_port_config(scsi_qla_host_t *vha, uint16_t *mb)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x110c,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_SET_PORT_CONFIG;
	/* Copy all bits to preserve original setting */
	memcpy(&mcp->mb[1], mb, sizeof(uint16_t) * 4);
	mcp->out_mb = MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x110d,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x110e,
		    "Done %s.\n", __func__);

	return rval;
}


int
qla24xx_set_fcp_prio(scsi_qla_host_t *vha, uint16_t loop_id, uint16_t priority,
		uint16_t *mb)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	struct qla_hw_data *ha = vha->hw;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x110f,
	    "Entered %s.\n", __func__);

	if (!IS_QLA24XX_TYPE(ha) && !IS_QLA25XX(ha))
		return QLA_FUNCTION_FAILED;

	mcp->mb[0] = MBC_PORT_PARAMS;
	mcp->mb[1] = loop_id;
	if (ha->flags.fcp_prio_enabled)
		mcp->mb[2] = BIT_1;
	else
		mcp->mb[2] = BIT_2;
	mcp->mb[4] = priority & 0xf;
	mcp->mb[9] = vha->vp_idx;
	mcp->out_mb = MBX_9|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_4|MBX_3|MBX_1|MBX_0;
	mcp->tov = 30;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);
	if (mb != NULL) {
		mb[0] = mcp->mb[0];
		mb[1] = mcp->mb[1];
		mb[3] = mcp->mb[3];
		mb[4] = mcp->mb[4];
	}

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10cd, "Failed=%x.\n", rval);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10cc,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla2x00_get_thermal_temp(scsi_qla_host_t *vha, uint16_t *temp, uint16_t *frac)
{
	int rval;
	uint8_t byte;
	struct qla_hw_data *ha = vha->hw;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x10ca,
	    "Entered %s.\n", __func__);

	/* Integer part */
	rval = qla2x00_read_sfp(vha, 0, &byte, 0x98, 0x01, 1, BIT_13|BIT_0);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x10c9, "Failed=%x.\n", rval);
		ha->flags.thermal_supported = 0;
		goto fail;
	}
	*temp = byte;

	/* Fraction part */
	rval = qla2x00_read_sfp(vha, 0, &byte, 0x98, 0x10, 1, BIT_13|BIT_0);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1019, "Failed=%x.\n", rval);
		ha->flags.thermal_supported = 0;
		goto fail;
	}
	*frac = (byte >> 6) * 25;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1018,
	    "Done %s.\n", __func__);
fail:
	return rval;
}

int
qla82xx_mbx_intr_enable(scsi_qla_host_t *vha)
{
	int rval;
	struct qla_hw_data *ha = vha->hw;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1017,
	    "Entered %s.\n", __func__);

	if (!IS_FWI2_CAPABLE(ha))
		return QLA_FUNCTION_FAILED;

	memset(mcp, 0, sizeof(mbx_cmd_t));
	mcp->mb[0] = MBC_TOGGLE_INTERRUPT;
	mcp->mb[1] = 1;

	mcp->out_mb = MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->tov = 30;
	mcp->flags = 0;

	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1016,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x100e,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla82xx_mbx_intr_disable(scsi_qla_host_t *vha)
{
	int rval;
	struct qla_hw_data *ha = vha->hw;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x100d,
	    "Entered %s.\n", __func__);

	if (!IS_QLA82XX(ha))
		return QLA_FUNCTION_FAILED;

	memset(mcp, 0, sizeof(mbx_cmd_t));
	mcp->mb[0] = MBC_TOGGLE_INTERRUPT;
	mcp->mb[1] = 0;

	mcp->out_mb = MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->tov = 30;
	mcp->flags = 0;

	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x100c,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x100b,
		    "Done %s.\n", __func__);
	}

	return rval;
}
int
qla82xx_mbx_beacon_ctl(scsi_qla_host_t *vha, int enable)
{
	int rval;
	struct qla_hw_data *ha = vha->hw;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	if (!IS_QLA82XX(ha))
		return QLA_FUNCTION_FAILED;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1127,
	    "Entered %s.\n", __func__);

	memset(mcp, 0, sizeof(mbx_cmd_t));
	mcp->mb[0] = MBC_SET_LED_CONFIG;
	if (enable)
		mcp->mb[7] = 0xE;
	else
		mcp->mb[7] = 0xD;

	mcp->out_mb = MBX_7|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;

	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1128,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1129,
		    "Done %s.\n", __func__);
	}

	return rval;
}

/*
 *  Command used establish parameters to enable fw to allocate resources for VFs, and
 *  is therefore only valid from the PF driver in a "write" mode. The command may also
 *  be used to determine current configuration parameters after fw has been initialised.
 *
 *  FIXME - come back and set this to used passed in parameter block.
 */
int
qla83xx_configure_vfs(scsi_qla_host_t *vha)
{
	int rval;
	struct qla_hw_data *ha = vha->hw;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	uint16_t	options;
	uint32_t	vf_cfgblk_size;
	dma_addr_t	buf_dma;
	uint8_t		*buf;

	if (!IS_QLA83XX(ha))
		return QLA_FUNCTION_FAILED;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x113a,
	    "Entered %s.\n", __func__);

	options = BIT_0;	// write enable
	vf_cfgblk_size = 64;
	buf = dma_alloc_coherent(&ha->pdev->dev,
	    vf_cfgblk_size, &buf_dma, GFP_KERNEL);
	if (buf == NULL) {
		ql_log(ql_log_warn, vha, 0x112e,
		    "%s: can't allocate memory.\n", __func__);
		return QLA_FUNCTION_FAILED;
	}

	memset(buf, 0, vf_cfgblk_size);
	buf[0] = 0x0f;		//  enable VFs 0-3 as trusted
	buf[0x10] = 0;		// 256 total VPS
	buf[0x11] = 0x01;
	buf[0x12] = 0x10;	// 16 VPs / function
	buf[0x13] = 0;
	buf[0x14] = 0x40;	// 64 NPortHandles / function
	buf[0x15] = 0;
	buf[0x16] = 0x10;	// 16 queue pairs / function
	buf[0x17] = 0;
	buf[0x18] = 0x20;	// should be 32 byte pages for VF queue pairs (128 system pages)
	buf[0x19] = 0;
	buf[0x1a] = 0;		// 128 system pages
	buf[0x1b] = 0x80;	// local paging enabled for VF

	mcp->mb[7] = LSW(MSD(buf_dma));
	mcp->mb[6] = MSW(MSD(buf_dma));
	mcp->mb[3] = LSW(buf_dma);
	mcp->mb[2] = MSW(buf_dma);
	mcp->mb[1] = options;
	mcp->mb[0] = MBC_CONFIGURE_VF;

	mcp->in_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->out_mb = MBX_10|MBX_9|MBX_8|MBX_7|MBX_6|
	    MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x112d,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x112c,
		    "Done %s.\n", __func__);

	dma_free_coherent(&ha->pdev->dev, vf_cfgblk_size, buf, buf_dma);
	return rval;
}

int
qla82xx_md_get_template_size(scsi_qla_host_t *vha)
{
	struct qla_hw_data *ha = vha->hw;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	int rval = QLA_FUNCTION_FAILED;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x111f,
	    "Entered %s.\n", __func__);

	memset(mcp->mb, 0, sizeof(mcp->mb));
	mcp->mb[0] = LSW(MBC_DIAGNOSTIC_MINIDUMP_TEMPLATE);
	mcp->mb[1] = MSW(MBC_DIAGNOSTIC_MINIDUMP_TEMPLATE);
	mcp->mb[2] = LSW(RQST_TMPLT_SIZE);
	mcp->mb[3] = MSW(RQST_TMPLT_SIZE);

	mcp->out_mb = MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_14|MBX_13|MBX_12|MBX_11|MBX_10|MBX_9|MBX_8|
	    MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;

	mcp->flags = MBX_DMA_OUT|MBX_DMA_IN|IOCTL_CMD;
	mcp->tov = MBX_TOV_SECONDS;
	rval = qla2x00_mailbox_command(vha, mcp);

	/* Always copy back return mailbox values. */
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1120,
		    "mailbox command FAILED=0x%x, subcode=%x.\n",
		    (mcp->mb[1] << 16) | mcp->mb[0],
		    (mcp->mb[3] << 16) | mcp->mb[2]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1121,
		    "Done %s.\n", __func__);
		ha->md_template_size = ((mcp->mb[3] << 16) | mcp->mb[2]);
		if (!ha->md_template_size) {
			ql_dbg(ql_dbg_mbx, vha, 0x1122,
			    "Null template size obtained.\n");
			rval = QLA_FUNCTION_FAILED;
		}
	}
	return rval;
}

int
qla82xx_md_get_template(scsi_qla_host_t *vha)
{
	struct qla_hw_data *ha = vha->hw;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	int rval = QLA_FUNCTION_FAILED;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1123,
	    "Entered %s.\n", __func__);

	ha->md_tmplt_hdr = dma_alloc_coherent(&ha->pdev->dev,
	   ha->md_template_size, &ha->md_tmplt_hdr_dma, GFP_KERNEL);
	if (!ha->md_tmplt_hdr) {
		ql_log(ql_log_warn, vha, 0x1124,
		    "Unable to allocate memory for Minidump template.\n");
		return rval;
	}

	memset(mcp->mb, 0, sizeof(mcp->mb));
	mcp->mb[0] = LSW(MBC_DIAGNOSTIC_MINIDUMP_TEMPLATE);
	mcp->mb[1] = MSW(MBC_DIAGNOSTIC_MINIDUMP_TEMPLATE);
	mcp->mb[2] = LSW(RQST_TMPLT);
	mcp->mb[3] = MSW(RQST_TMPLT);
	mcp->mb[4] = LSW(LSD(ha->md_tmplt_hdr_dma));
	mcp->mb[5] = MSW(LSD(ha->md_tmplt_hdr_dma));
	mcp->mb[6] = LSW(MSD(ha->md_tmplt_hdr_dma));
	mcp->mb[7] = MSW(MSD(ha->md_tmplt_hdr_dma));
	mcp->mb[8] = LSW(ha->md_template_size);
	mcp->mb[9] = MSW(ha->md_template_size);

	mcp->flags = MBX_DMA_OUT|MBX_DMA_IN|IOCTL_CMD;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->out_mb = MBX_11|MBX_10|MBX_9|MBX_8|
	    MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_3|MBX_2|MBX_1|MBX_0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1125,
		    "mailbox command FAILED=0x%x, subcode=%x.\n",
		    ((mcp->mb[1] << 16) | mcp->mb[0]),
		    ((mcp->mb[3] << 16) | mcp->mb[2]));
	} else
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1126,
		    "Done %s.\n", __func__);
	return rval;
}

int
qla81xx_set_led_config(scsi_qla_host_t *vha, uint16_t *led_cfg)
{
	int rval;
	struct qla_hw_data *ha = vha->hw;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	if (!IS_QLA81XX(ha) && !IS_QLA8031(ha))
		return QLA_FUNCTION_FAILED;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1133,
	    "Entered %s.\n", __func__);

	memset(mcp, 0, sizeof(mbx_cmd_t));
	mcp->mb[0] = MBC_SET_LED_CONFIG;
	mcp->mb[1] = led_cfg[0];
	mcp->mb[2] = led_cfg[1];
	if (IS_QLA8031(ha)) {
		mcp->mb[3] = led_cfg[2];
		mcp->mb[4] = led_cfg[3];
		mcp->mb[5] = led_cfg[4];
		mcp->mb[6] = led_cfg[5];
	}

	mcp->out_mb = MBX_2|MBX_1|MBX_0;
	if (IS_QLA8031(ha)) {
		mcp->out_mb |= MBX_6|MBX_5|MBX_4|MBX_3;
	}
	mcp->in_mb = MBX_0;
	mcp->tov = 30;
	mcp->flags = 0;

	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1134,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1135,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla81xx_get_led_config(scsi_qla_host_t *vha, uint16_t *led_cfg)
{
	int rval;
	struct qla_hw_data *ha = vha->hw;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	if (!IS_QLA81XX(ha) && !IS_QLA8031(ha))
		return QLA_FUNCTION_FAILED;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1136,
	    "Entered %s.\n", __func__);

	memset(mcp, 0, sizeof(mbx_cmd_t));
	mcp->mb[0] = MBC_GET_LED_CONFIG;

	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_2|MBX_1|MBX_0;
	if (IS_QLA8031(ha)) {
		mcp->in_mb |= MBX_6|MBX_5|MBX_4|MBX_3;
	}
	mcp->tov = 30;
	mcp->flags = 0;

	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1137,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		led_cfg[0] = mcp->mb[1];
		led_cfg[1] = mcp->mb[2];
		if (IS_QLA8031(ha)) {
			led_cfg[2] = mcp->mb[3];
			led_cfg[3] = mcp->mb[4];
			led_cfg[4] = mcp->mb[5];
			led_cfg[5] = mcp->mb[6];
		}
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1138, "Done %s\n", __func__);
	}

	return rval;
}

int
qla83xx_write_remote_reg(scsi_qla_host_t *vha, uint32_t reg, uint32_t data)
{
	int rval;
	struct qla_hw_data *ha = vha->hw;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	if (!IS_QLA83XX(ha))
		return QLA_FUNCTION_FAILED;

	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1130,
	    "Entered %s.\n", __func__);

	mcp->mb[0] = MBC_WRITE_REMOTE_REG;
	mcp->mb[1] = LSW(reg);
	mcp->mb[2] = MSW(reg);
	mcp->mb[3] = LSW(data);
	mcp->mb[4] = MSW(data);
	mcp->out_mb = MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;

	mcp->in_mb = MBX_1|MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);

	if (rval != QLA_SUCCESS) {
		ql_dbg(ql_dbg_mbx, vha, 0x1131,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	} else {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x1132,
		    "Done %s.\n", __func__);
	}

	return rval;
}

int
qla2x00_port_logout(scsi_qla_host_t *vha, struct fc_port *fcport)
{
	int rval;
	struct qla_hw_data *ha = vha->hw;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	if (IS_QLA2100(ha) || IS_QLA2200(ha)) {
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x113b,
		    "Implicit LOGO Unsupported.\n");
		return QLA_FUNCTION_FAILED;
	}


	ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x113c,
	    "Entering %s.\n",  __func__);

	/* Perform Implicit LOGO. */
	mcp->mb[0] = MBC_PORT_LOGOUT;
	mcp->mb[1] = fcport->loop_id;
	mcp->mb[10] = BIT_15;
	mcp->out_mb = MBX_10|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->tov = MBX_TOV_SECONDS;
	mcp->flags = 0;
	rval = qla2x00_mailbox_command(vha, mcp);
	if (rval != QLA_SUCCESS)
		ql_dbg(ql_dbg_mbx, vha, 0x113d,
		    "Failed=%x mb[0]=%x.\n", rval, mcp->mb[0]);
	else
		ql_dbg(ql_dbg_mbx + ql_dbg_verbose, vha, 0x113e,
		    "Done %s.\n", __func__);

	return rval;
}
