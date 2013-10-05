/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2008 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#include "qla_def.h"

#include <linux/delay.h>
#include <linux/vmalloc.h>

#include "qla_devtbl.h"

#ifdef CONFIG_SPARC
#include <asm/prom.h>
#endif

#include "qla2x_tgt.h"

#ifndef CONFIG_SCSI_QLA2XXX_TARGET
#warning "CONFIG_SCSI_QLA2XXX_TARGET is not set"
#endif

/*
*  QLogic ISP2x00 Hardware Support Function Prototypes.
*/
static int qla2x00_isp_firmware(scsi_qla_host_t *);
static void qla2x00_resize_request_q(scsi_qla_host_t *);
static int qla2x00_setup_chip(scsi_qla_host_t *);
static void qla2x00_init_response_q_entries(scsi_qla_host_t *);
static int qla2x00_init_rings(scsi_qla_host_t *);
static int qla2x00_fw_ready(scsi_qla_host_t *);
static int qla2x00_configure_hba(scsi_qla_host_t *);
static int qla2x00_find_all_fabric_devs(scsi_qla_host_t *, struct list_head *);
static int qla2x00_device_resync(scsi_qla_host_t *);
static int qla2x00_fabric_dev_login(scsi_qla_host_t *, fc_port_t *,
    uint16_t *);

static int qla2x00_restart_isp(scsi_qla_host_t *);

static int qla2x00_find_new_loop_id(scsi_qla_host_t *ha, fc_port_t *dev);

static struct qla_chip_state_84xx *qla84xx_get_chip(struct scsi_qla_host *);
static int qla84xx_init_chip(scsi_qla_host_t *);

/****************************************************************************/
/*                QLogic ISP2x00 Hardware Support Functions.                */
/****************************************************************************/

/*
* qla2x00_initialize_adapter
*      Initialize board.
*
* Input:
*      ha = adapter block pointer.
*
* Returns:
*      0 = success
*/
int
qla2x00_initialize_adapter(scsi_qla_host_t *ha)
{
	int	rval;

	/* Clear adapter flags. */
	ha->flags.online = 0;
	ha->flags.reset_active = 0;
	atomic_set(&ha->loop_down_timer, LOOP_DOWN_TIME);
	atomic_set(&ha->loop_state, LOOP_DOWN);
	ha->device_flags = DFLG_NO_CABLE;
	ha->dpc_flags = 0;
	ha->flags.management_server_logged_in = 0;
	ha->marker_needed = 0;
	ha->mbx_flags = 0;
	ha->isp_abort_cnt = 0;
	ha->beacon_blink_led = 0;
	set_bit(REGISTER_FDMI_NEEDED, &ha->dpc_flags);

	qla_printk(KERN_INFO, ha, "Configuring PCI space...\n");
	rval = ha->isp_ops->pci_config(ha);
	if (rval) {
		DEBUG2(printk("scsi(%ld): Unable to configure PCI space.\n",
		    ha->host_no));
		return (rval);
	}

	ha->isp_ops->reset_chip(ha);

	ha->isp_ops->get_flash_version(ha, ha->request_ring);

	qla_printk(KERN_INFO, ha, "Configure NVRAM parameters...\n");

	ha->isp_ops->nvram_config(ha);

	if (ha->flags.disable_serdes) {
		/* Mask HBA via NVRAM settings? */
		qla_printk(KERN_INFO, ha, "Masking HBA WWPN "
		    "%02x%02x%02x%02x%02x%02x%02x%02x (via NVRAM).\n",
		    ha->port_name[0], ha->port_name[1],
		    ha->port_name[2], ha->port_name[3],
		    ha->port_name[4], ha->port_name[5],
		    ha->port_name[6], ha->port_name[7]);
		return QLA_FUNCTION_FAILED;
	}

	qla_printk(KERN_INFO, ha, "Verifying loaded RISC code...\n");

	if (qla2x00_isp_firmware(ha) != QLA_SUCCESS) {
		rval = ha->isp_ops->chip_diag(ha);
		if (rval)
			return (rval);
		rval = qla2x00_setup_chip(ha);
		if (rval)
			return (rval);
		qla2xxx_get_flash_info(ha);
	}
	if (IS_QLA84XX(ha)) {
		ha->cs84xx = qla84xx_get_chip(ha);
		if (!ha->cs84xx) {
			qla_printk(KERN_ERR, ha,
			    "Unable to configure ISP84XX.\n");
			return QLA_FUNCTION_FAILED;
		}
	}
	rval = qla2x00_init_rings(ha);

#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	if (rval == QLA_SUCCESS) {
		/* Enable target response to SCSI bus. */
		if (qla_tgt_mode_enabled(ha))
			qla2x00_send_enable_lun(ha, true);
		else if (qla_ini_mode_enabled(ha))
			qla2x00_send_enable_lun(ha, false);
	}
#endif

	return (rval);
}

/**
 * qla2100_pci_config() - Setup ISP21xx PCI configuration registers.
 * @ha: HA context
 *
 * Returns 0 on success.
 */
int
qla2100_pci_config(scsi_qla_host_t *ha)
{
	uint16_t w;
	uint32_t d;
	unsigned long flags;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;

	pci_set_master(ha->pdev);
	pci_try_set_mwi(ha->pdev);

	pci_read_config_word(ha->pdev, PCI_COMMAND, &w);
	w |= (PCI_COMMAND_PARITY | PCI_COMMAND_SERR);
	pci_write_config_word(ha->pdev, PCI_COMMAND, w);

	/* Reset expansion ROM address decode enable */
	pci_read_config_dword(ha->pdev, PCI_ROM_ADDRESS, &d);
	d &= ~PCI_ROM_ADDRESS_ENABLE;
	pci_write_config_dword(ha->pdev, PCI_ROM_ADDRESS, d);

	/* Get PCI bus information. */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	ha->pci_attr = RD_REG_WORD(&reg->ctrl_status);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return QLA_SUCCESS;
}

/**
 * qla2300_pci_config() - Setup ISP23xx PCI configuration registers.
 * @ha: HA context
 *
 * Returns 0 on success.
 */
int
qla2300_pci_config(scsi_qla_host_t *ha)
{
	uint16_t	w;
	uint32_t	d;
	unsigned long   flags = 0;
	uint32_t	cnt;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;

	pci_set_master(ha->pdev);
	pci_try_set_mwi(ha->pdev);

	pci_read_config_word(ha->pdev, PCI_COMMAND, &w);
	w |= (PCI_COMMAND_PARITY | PCI_COMMAND_SERR);

	if (IS_QLA2322(ha) || IS_QLA6322(ha))
		w &= ~PCI_COMMAND_INTX_DISABLE;
	pci_write_config_word(ha->pdev, PCI_COMMAND, w);

	/*
	 * If this is a 2300 card and not 2312, reset the
	 * COMMAND_INVALIDATE due to a bug in the 2300. Unfortunately,
	 * the 2310 also reports itself as a 2300 so we need to get the
	 * fb revision level -- a 6 indicates it really is a 2300 and
	 * not a 2310.
	 */
	if (IS_QLA2300(ha)) {
		spin_lock_irqsave(&ha->hardware_lock, flags);

		/* Pause RISC. */
		WRT_REG_WORD(&reg->hccr, HCCR_PAUSE_RISC);
		for (cnt = 0; cnt < 30000; cnt++) {
			if ((RD_REG_WORD(&reg->hccr) & HCCR_RISC_PAUSE) != 0)
				break;

			udelay(10);
		}

		/* Select FPM registers. */
		WRT_REG_WORD(&reg->ctrl_status, 0x20);
		RD_REG_WORD(&reg->ctrl_status);

		/* Get the fb rev level */
		ha->fb_rev = RD_FB_CMD_REG(ha, reg);

		if (ha->fb_rev == FPM_2300)
			pci_clear_mwi(ha->pdev);

		/* Deselect FPM registers. */
		WRT_REG_WORD(&reg->ctrl_status, 0x0);
		RD_REG_WORD(&reg->ctrl_status);

		/* Release RISC module. */
		WRT_REG_WORD(&reg->hccr, HCCR_RELEASE_RISC);
		for (cnt = 0; cnt < 30000; cnt++) {
			if ((RD_REG_WORD(&reg->hccr) & HCCR_RISC_PAUSE) == 0)
				break;

			udelay(10);
		}

		spin_unlock_irqrestore(&ha->hardware_lock, flags);
	}

	pci_write_config_byte(ha->pdev, PCI_LATENCY_TIMER, 0x80);

	/* Reset expansion ROM address decode enable */
	pci_read_config_dword(ha->pdev, PCI_ROM_ADDRESS, &d);
	d &= ~PCI_ROM_ADDRESS_ENABLE;
	pci_write_config_dword(ha->pdev, PCI_ROM_ADDRESS, d);

	/* Get PCI bus information. */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	ha->pci_attr = RD_REG_WORD(&reg->ctrl_status);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return QLA_SUCCESS;
}

/**
 * qla24xx_pci_config() - Setup ISP24xx PCI configuration registers.
 * @ha: HA context
 *
 * Returns 0 on success.
 */
int
qla24xx_pci_config(scsi_qla_host_t *ha)
{
	uint16_t w;
	uint32_t d;
	unsigned long flags = 0;
	struct device_reg_24xx __iomem *reg = &ha->iobase->isp24;

	pci_set_master(ha->pdev);
	pci_try_set_mwi(ha->pdev);

	pci_read_config_word(ha->pdev, PCI_COMMAND, &w);
	w |= (PCI_COMMAND_PARITY | PCI_COMMAND_SERR);
	w &= ~PCI_COMMAND_INTX_DISABLE;
	pci_write_config_word(ha->pdev, PCI_COMMAND, w);

	pci_write_config_byte(ha->pdev, PCI_LATENCY_TIMER, 0x80);

	/* PCI-X -- adjust Maximum Memory Read Byte Count (2048). */
	if (pci_find_capability(ha->pdev, PCI_CAP_ID_PCIX))
		pcix_set_mmrbc(ha->pdev, 2048);

	/* PCIe -- adjust Maximum Read Request Size (2048). */
	if (pci_find_capability(ha->pdev, PCI_CAP_ID_EXP))
		pcie_set_readrq(ha->pdev, 2048);

	/* Reset expansion ROM address decode enable */
	pci_read_config_dword(ha->pdev, PCI_ROM_ADDRESS, &d);
	d &= ~PCI_ROM_ADDRESS_ENABLE;
	pci_write_config_dword(ha->pdev, PCI_ROM_ADDRESS, d);

	ha->chip_revision = ha->pdev->revision;

	/* Get PCI bus information. */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	ha->pci_attr = RD_REG_DWORD(&reg->ctrl_status);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return QLA_SUCCESS;
}

/**
 * qla25xx_pci_config() - Setup ISP25xx PCI configuration registers.
 * @ha: HA context
 *
 * Returns 0 on success.
 */
int
qla25xx_pci_config(scsi_qla_host_t *ha)
{
	uint16_t w;
	uint32_t d;

	pci_set_master(ha->pdev);
	pci_try_set_mwi(ha->pdev);

	pci_read_config_word(ha->pdev, PCI_COMMAND, &w);
	w |= (PCI_COMMAND_PARITY | PCI_COMMAND_SERR);
	w &= ~PCI_COMMAND_INTX_DISABLE;
	pci_write_config_word(ha->pdev, PCI_COMMAND, w);

	/* PCIe -- adjust Maximum Read Request Size (2048). */
	if (pci_find_capability(ha->pdev, PCI_CAP_ID_EXP))
		pcie_set_readrq(ha->pdev, 2048);

	/* Reset expansion ROM address decode enable */
	pci_read_config_dword(ha->pdev, PCI_ROM_ADDRESS, &d);
	d &= ~PCI_ROM_ADDRESS_ENABLE;
	pci_write_config_dword(ha->pdev, PCI_ROM_ADDRESS, d);

	ha->chip_revision = ha->pdev->revision;

	return QLA_SUCCESS;
}

/**
 * qla2x00_isp_firmware() - Choose firmware image.
 * @ha: HA context
 *
 * Returns 0 on success.
 */
static int
qla2x00_isp_firmware(scsi_qla_host_t *ha)
{
	int  rval;

	/* Assume loading risc code */
	rval = QLA_FUNCTION_FAILED;

	if (ha->flags.disable_risc_code_load) {
		DEBUG2(printk("scsi(%ld): RISC CODE NOT loaded\n",
		    ha->host_no));
		qla_printk(KERN_INFO, ha, "RISC CODE NOT loaded\n");

		/* Verify checksum of loaded RISC code. */
		rval = qla2x00_verify_checksum(ha, ha->fw_srisc_address);
	}

	if (rval) {
		DEBUG2_3(printk("scsi(%ld): **** Load RISC code ****\n",
		    ha->host_no));
	}

	return (rval);
}

/**
 * qla2x00_reset_chip() - Reset ISP chip.
 * @ha: HA context
 *
 * Returns 0 on success.
 */
void
qla2x00_reset_chip(scsi_qla_host_t *ha)
{
	unsigned long   flags = 0;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;
	uint32_t	cnt;
	uint16_t	cmd;

	ha->isp_ops->disable_intrs(ha);

	spin_lock_irqsave(&ha->hardware_lock, flags);

	/* Turn off master enable */
	cmd = 0;
	pci_read_config_word(ha->pdev, PCI_COMMAND, &cmd);
	cmd &= ~PCI_COMMAND_MASTER;
	pci_write_config_word(ha->pdev, PCI_COMMAND, cmd);

	if (!IS_QLA2100(ha)) {
		/* Pause RISC. */
		WRT_REG_WORD(&reg->hccr, HCCR_PAUSE_RISC);
		if (IS_QLA2200(ha) || IS_QLA2300(ha)) {
			for (cnt = 0; cnt < 30000; cnt++) {
				if ((RD_REG_WORD(&reg->hccr) &
				    HCCR_RISC_PAUSE) != 0)
					break;
				udelay(100);
			}
		} else {
			RD_REG_WORD(&reg->hccr);	/* PCI Posting. */
			udelay(10);
		}

		/* Select FPM registers. */
		WRT_REG_WORD(&reg->ctrl_status, 0x20);
		RD_REG_WORD(&reg->ctrl_status);		/* PCI Posting. */

		/* FPM Soft Reset. */
		WRT_REG_WORD(&reg->fpm_diag_config, 0x100);
		RD_REG_WORD(&reg->fpm_diag_config);	/* PCI Posting. */

		/* Toggle Fpm Reset. */
		if (!IS_QLA2200(ha)) {
			WRT_REG_WORD(&reg->fpm_diag_config, 0x0);
			RD_REG_WORD(&reg->fpm_diag_config); /* PCI Posting. */
		}

		/* Select frame buffer registers. */
		WRT_REG_WORD(&reg->ctrl_status, 0x10);
		RD_REG_WORD(&reg->ctrl_status);		/* PCI Posting. */

		/* Reset frame buffer FIFOs. */
		if (IS_QLA2200(ha)) {
			WRT_FB_CMD_REG(ha, reg, 0xa000);
			RD_FB_CMD_REG(ha, reg);		/* PCI Posting. */
		} else {
			WRT_FB_CMD_REG(ha, reg, 0x00fc);

			/* Read back fb_cmd until zero or 3 seconds max */
			for (cnt = 0; cnt < 3000; cnt++) {
				if ((RD_FB_CMD_REG(ha, reg) & 0xff) == 0)
					break;
				udelay(100);
			}
		}

		/* Select RISC module registers. */
		WRT_REG_WORD(&reg->ctrl_status, 0);
		RD_REG_WORD(&reg->ctrl_status);		/* PCI Posting. */

		/* Reset RISC processor. */
		WRT_REG_WORD(&reg->hccr, HCCR_RESET_RISC);
		RD_REG_WORD(&reg->hccr);		/* PCI Posting. */

		/* Release RISC processor. */
		WRT_REG_WORD(&reg->hccr, HCCR_RELEASE_RISC);
		RD_REG_WORD(&reg->hccr);		/* PCI Posting. */
	}

	WRT_REG_WORD(&reg->hccr, HCCR_CLR_RISC_INT);
	WRT_REG_WORD(&reg->hccr, HCCR_CLR_HOST_INT);

	/* Reset ISP chip. */
	WRT_REG_WORD(&reg->ctrl_status, CSR_ISP_SOFT_RESET);

	/* Wait for RISC to recover from reset. */
	if (IS_QLA2100(ha) || IS_QLA2200(ha) || IS_QLA2300(ha)) {
		/*
		 * It is necessary to for a delay here since the card doesn't
		 * respond to PCI reads during a reset. On some architectures
		 * this will result in an MCA.
		 */
		udelay(20);
		for (cnt = 30000; cnt; cnt--) {
			if ((RD_REG_WORD(&reg->ctrl_status) &
			    CSR_ISP_SOFT_RESET) == 0)
				break;
			udelay(100);
		}
	} else
		udelay(10);

	/* Reset RISC processor. */
	WRT_REG_WORD(&reg->hccr, HCCR_RESET_RISC);

	WRT_REG_WORD(&reg->semaphore, 0);

	/* Release RISC processor. */
	WRT_REG_WORD(&reg->hccr, HCCR_RELEASE_RISC);
	RD_REG_WORD(&reg->hccr);			/* PCI Posting. */

	if (IS_QLA2100(ha) || IS_QLA2200(ha) || IS_QLA2300(ha)) {
		for (cnt = 0; cnt < 30000; cnt++) {
			if (RD_MAILBOX_REG(ha, reg, 0) != MBS_BUSY)
				break;

			udelay(100);
		}
	} else
		udelay(100);

	/* Turn on master enable */
	cmd |= PCI_COMMAND_MASTER;
	pci_write_config_word(ha->pdev, PCI_COMMAND, cmd);

	/* Disable RISC pause on FPM parity error. */
	if (!IS_QLA2100(ha)) {
		WRT_REG_WORD(&reg->hccr, HCCR_DISABLE_PARITY_PAUSE);
		RD_REG_WORD(&reg->hccr);		/* PCI Posting. */
	}

	spin_unlock_irqrestore(&ha->hardware_lock, flags);
}

/**
 * qla24xx_reset_risc() - Perform full reset of ISP24xx RISC.
 * @ha: HA context
 *
 * Returns 0 on success.
 */
static inline void
qla24xx_reset_risc(scsi_qla_host_t *ha)
{
	int hw_evt = 0;
	unsigned long flags = 0;
	struct device_reg_24xx __iomem *reg = &ha->iobase->isp24;
	uint32_t cnt, d2;
	uint16_t wd;

	spin_lock_irqsave(&ha->hardware_lock, flags);

	/* Reset RISC. */
	WRT_REG_DWORD(&reg->ctrl_status, CSRX_DMA_SHUTDOWN|MWB_4096_BYTES);
	for (cnt = 0; cnt < 30000; cnt++) {
		if ((RD_REG_DWORD(&reg->ctrl_status) & CSRX_DMA_ACTIVE) == 0)
			break;

		udelay(10);
	}

	WRT_REG_DWORD(&reg->ctrl_status,
	    CSRX_ISP_SOFT_RESET|CSRX_DMA_SHUTDOWN|MWB_4096_BYTES);
	pci_read_config_word(ha->pdev, PCI_COMMAND, &wd);

	udelay(100);
	/* Wait for firmware to complete NVRAM accesses. */
	d2 = (uint32_t) RD_REG_WORD(&reg->mailbox0);
	for (cnt = 10000 ; cnt && d2; cnt--) {
		udelay(5);
		d2 = (uint32_t) RD_REG_WORD(&reg->mailbox0);
		barrier();
	}
	if (cnt == 0)
		hw_evt = 1;

	/* Wait for soft-reset to complete. */
	d2 = RD_REG_DWORD(&reg->ctrl_status);
	for (cnt = 6000000 ; cnt && (d2 & CSRX_ISP_SOFT_RESET); cnt--) {
		udelay(5);
		d2 = RD_REG_DWORD(&reg->ctrl_status);
		barrier();
	}
	if (cnt == 0 || hw_evt)
		qla2xxx_hw_event_log(ha, HW_EVENT_RESET_ERR,
		    RD_REG_WORD(&reg->mailbox1), RD_REG_WORD(&reg->mailbox2),
		    RD_REG_WORD(&reg->mailbox3));

	WRT_REG_DWORD(&reg->hccr, HCCRX_SET_RISC_RESET);
	RD_REG_DWORD(&reg->hccr);

	WRT_REG_DWORD(&reg->hccr, HCCRX_REL_RISC_PAUSE);
	RD_REG_DWORD(&reg->hccr);

	WRT_REG_DWORD(&reg->hccr, HCCRX_CLR_RISC_RESET);
	RD_REG_DWORD(&reg->hccr);

	d2 = (uint32_t) RD_REG_WORD(&reg->mailbox0);
	for (cnt = 6000000 ; cnt && d2; cnt--) {
		udelay(5);
		d2 = (uint32_t) RD_REG_WORD(&reg->mailbox0);
		barrier();
	}

	spin_unlock_irqrestore(&ha->hardware_lock, flags);
}

/**
 * qla24xx_reset_chip() - Reset ISP24xx chip.
 * @ha: HA context
 *
 * Returns 0 on success.
 */
void
qla24xx_reset_chip(scsi_qla_host_t *ha)
{
	ha->isp_ops->disable_intrs(ha);

	/* Perform RISC reset. */
	qla24xx_reset_risc(ha);
}

/**
 * qla2x00_chip_diag() - Test chip for proper operation.
 * @ha: HA context
 *
 * Returns 0 on success.
 */
int
qla2x00_chip_diag(scsi_qla_host_t *ha)
{
	int		rval;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;
	unsigned long	flags = 0;
	uint16_t	data;
	uint32_t	cnt;
	uint16_t	mb[5];

	/* Assume a failed state */
	rval = QLA_FUNCTION_FAILED;

	DEBUG3(printk(KERN_WARNING "scsi(%ld): Testing device at %p\n",
		      ha->host_no, &reg->flash_address));

	spin_lock_irqsave(&ha->hardware_lock, flags);

	/* Disable PCI "Bus Master Enable bit" */
	if (IS_QLA23XX(ha)) {
		data = RD_REG_WORD(&reg->unused_1[0]);
		WRT_REG_WORD(&reg->unused_1[0], data&~BIT_2);
	}

	/* Reset ISP chip. */
	WRT_REG_WORD(&reg->ctrl_status, CSR_ISP_SOFT_RESET);

	if (!IS_QLA23XX(ha)) {
		/*
		 * We need to have a delay here since the card will not respond while
		 * in reset causing an MCA on some architectures.
		 */
		udelay(30);
		data = qla2x00_debounce_register(&reg->ctrl_status);
		for (cnt = 6000000; cnt && (data & CSR_ISP_SOFT_RESET); cnt--) {
			udelay(5);
			data = RD_REG_WORD(&reg->ctrl_status);
			barrier();
		}
		if (!cnt)
			goto chip_diag_failed;

		DEBUG3(printk("scsi(%ld): Reset register cleared by chip reset\n",
		    ha->host_no));
	} else {
		/*
		 * Should be 16 PCI Clock cycles, but this is arbitrarily safer
		 */
		udelay(100);
		data = RD_REG_WORD(&reg->unused_1[0]);
		WRT_REG_WORD(&reg->unused_1[0], data&BIT_2);
	}

	/* Reset RISC processor. */
	WRT_REG_WORD(&reg->hccr, HCCR_RESET_RISC);
	WRT_REG_WORD(&reg->hccr, HCCR_RELEASE_RISC);

	/* Workaround for QLA2312 PCI parity error */
	if (IS_QLA2100(ha) || IS_QLA2200(ha) || IS_QLA2300(ha)) {
		data = qla2x00_debounce_register(MAILBOX_REG(ha, reg, 0));
		for (cnt = 6000000; cnt && (data == MBS_BUSY); cnt--) {
			udelay(5);
			data = RD_MAILBOX_REG(ha, reg, 0);
			barrier();
		}
		if (!cnt)
			goto chip_diag_failed;
	} else
		udelay(10);

	/* Check product ID of chip */
	DEBUG3(printk("scsi(%ld): Checking product ID of chip\n", ha->host_no));

	mb[1] = RD_MAILBOX_REG(ha, reg, 1);
	mb[2] = RD_MAILBOX_REG(ha, reg, 2);
	mb[3] = RD_MAILBOX_REG(ha, reg, 3);
	mb[4] = qla2x00_debounce_register(MAILBOX_REG(ha, reg, 4));
	if (mb[1] != PROD_ID_1 || (mb[2] != PROD_ID_2 && mb[2] != PROD_ID_2a) ||
	    mb[3] != PROD_ID_3) {
		qla_printk(KERN_WARNING, ha,
		    "Wrong product ID = 0x%x,0x%x,0x%x\n", mb[1], mb[2], mb[3]);

		goto chip_diag_failed;
	}
	ha->product_id[0] = mb[1];
	ha->product_id[1] = mb[2];
	ha->product_id[2] = mb[3];
	ha->product_id[3] = mb[4];

	/* Adjust fw RISC transfer size */
	if (ha->request_q_length > 1024)
		ha->fw_transfer_size = REQUEST_ENTRY_SIZE * 1024;
	else
		ha->fw_transfer_size = REQUEST_ENTRY_SIZE *
		    ha->request_q_length;

	if (IS_QLA2200(ha) &&
	    RD_MAILBOX_REG(ha, reg, 7) == QLA2200A_RISC_ROM_VER) {
		/* Limit firmware transfer size with a 2200A */
		DEBUG3(printk("scsi(%ld): Found QLA2200A chip.\n",
		    ha->host_no));

		ha->device_type |= DT_ISP2200A;
		ha->fw_transfer_size = 128;
	}

	/* Wrap Incoming Mailboxes Test. */
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	DEBUG3(printk("scsi(%ld): Checking mailboxes.\n", ha->host_no));
	rval = qla2x00_mbx_reg_test(ha);
	if (rval != QLA_SUCCESS)
		qla_printk(KERN_WARNING, ha,
		    "Failed mailbox send register test (%x)\n", rval);

	spin_lock_irqsave(&ha->hardware_lock, flags);

chip_diag_failed:
	if (rval != QLA_SUCCESS)
		DEBUG2_3(printk("scsi(%ld): Chip diagnostics **** FAILED "
		    "****\n", ha->host_no));

	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return (rval);
}

/**
 * qla24xx_chip_diag() - Test ISP24xx for proper operation.
 * @ha: HA context
 *
 * Returns 0 on success.
 */
int
qla24xx_chip_diag(scsi_qla_host_t *ha)
{
	int rval;

	/* Perform RISC reset. */
	qla24xx_reset_risc(ha);

	ha->fw_transfer_size = REQUEST_ENTRY_SIZE * 1024;

	rval = qla2x00_mbx_reg_test(ha);
	if (rval != QLA_SUCCESS)
		qla_printk(KERN_WARNING, ha,
		    "Failed mailbox send register test (%x)\n", rval);

	return rval;
}

void
qla2x00_alloc_fw_dump(scsi_qla_host_t *ha)
{
	int rval;
	uint32_t dump_size, fixed_size, mem_size, req_q_size, rsp_q_size,
	    eft_size, fce_size;
	dma_addr_t tc_dma;
	void *tc;

	if (ha->fw_dump) {
		qla_printk(KERN_WARNING, ha,
		    "Firmware dump previously allocated.\n");
		return;
	}

	ha->fw_dumped = 0;
	fixed_size = mem_size = eft_size = fce_size = 0;
	if (IS_QLA2100(ha) || IS_QLA2200(ha)) {
		fixed_size = sizeof(struct qla2100_fw_dump);
	} else if (IS_QLA23XX(ha)) {
		fixed_size = offsetof(struct qla2300_fw_dump, data_ram);
		mem_size = (ha->fw_memory_size - 0x11000 + 1) *
		    sizeof(uint16_t);
	} else if (IS_FWI2_CAPABLE(ha)) {
		fixed_size = IS_QLA25XX(ha) ?
		    offsetof(struct qla25xx_fw_dump, ext_mem):
		    offsetof(struct qla24xx_fw_dump, ext_mem);
		mem_size = (ha->fw_memory_size - 0x100000 + 1) *
		    sizeof(uint32_t);

		/* Allocate memory for Extended Trace Buffer. */
		tc = dma_alloc_coherent(&ha->pdev->dev, EFT_SIZE, &tc_dma,
		    GFP_KERNEL);
		if (!tc) {
			qla_printk(KERN_WARNING, ha, "Unable to allocate "
			    "(%d KB) for EFT.\n", EFT_SIZE / 1024);
			goto cont_alloc;
		}

		memset(tc, 0, EFT_SIZE);
		rval = qla2x00_enable_eft_trace(ha, tc_dma, EFT_NUM_BUFFERS);
		if (rval) {
			qla_printk(KERN_WARNING, ha, "Unable to initialize "
			    "EFT (%d).\n", rval);
			dma_free_coherent(&ha->pdev->dev, EFT_SIZE, tc,
			    tc_dma);
			goto cont_alloc;
		}

		qla_printk(KERN_INFO, ha, "Allocated (%d KB) for EFT...\n",
		    EFT_SIZE / 1024);

		eft_size = EFT_SIZE;
		ha->eft_dma = tc_dma;
		ha->eft = tc;

		/* Allocate memory for Fibre Channel Event Buffer. */
		if (!IS_QLA25XX(ha))
			goto cont_alloc;

		tc = dma_alloc_coherent(&ha->pdev->dev, FCE_SIZE, &tc_dma,
		    GFP_KERNEL);
		if (!tc) {
			qla_printk(KERN_WARNING, ha, "Unable to allocate "
			    "(%d KB) for FCE.\n", FCE_SIZE / 1024);
			goto cont_alloc;
		}

		memset(tc, 0, FCE_SIZE);
		rval = qla2x00_enable_fce_trace(ha, tc_dma, FCE_NUM_BUFFERS,
		    ha->fce_mb, &ha->fce_bufs);
		if (rval) {
			qla_printk(KERN_WARNING, ha, "Unable to initialize "
			    "FCE (%d).\n", rval);
			dma_free_coherent(&ha->pdev->dev, FCE_SIZE, tc,
			    tc_dma);
			ha->flags.fce_enabled = 0;
			goto cont_alloc;
		}

		qla_printk(KERN_INFO, ha, "Allocated (%d KB) for FCE...\n",
		    FCE_SIZE / 1024);

		fce_size = sizeof(struct qla2xxx_fce_chain) + EFT_SIZE;
		ha->flags.fce_enabled = 1;
		ha->fce_dma = tc_dma;
		ha->fce = tc;
	}
cont_alloc:
	req_q_size = ha->request_q_length * sizeof(request_t);
	rsp_q_size = ha->response_q_length * sizeof(response_t);

	dump_size = offsetof(struct qla2xxx_fw_dump, isp);
	dump_size += fixed_size + mem_size + req_q_size + rsp_q_size +
	    eft_size + fce_size;

	ha->fw_dump = vmalloc(dump_size);
	if (!ha->fw_dump) {
		qla_printk(KERN_WARNING, ha, "Unable to allocate (%d KB) for "
		    "firmware dump!!!\n", dump_size / 1024);

		if (ha->eft) {
			dma_free_coherent(&ha->pdev->dev, eft_size, ha->eft,
			    ha->eft_dma);
			ha->eft = NULL;
			ha->eft_dma = 0;
		}
		return;
	}

	qla_printk(KERN_INFO, ha, "Allocated (%d KB) for firmware dump...\n",
	    dump_size / 1024);

	ha->fw_dump_len = dump_size;
	ha->fw_dump->signature[0] = 'Q';
	ha->fw_dump->signature[1] = 'L';
	ha->fw_dump->signature[2] = 'G';
	ha->fw_dump->signature[3] = 'C';
	ha->fw_dump->version = __constant_htonl(1);

	ha->fw_dump->fixed_size = htonl(fixed_size);
	ha->fw_dump->mem_size = htonl(mem_size);
	ha->fw_dump->req_q_size = htonl(req_q_size);
	ha->fw_dump->rsp_q_size = htonl(rsp_q_size);

	ha->fw_dump->eft_size = htonl(eft_size);
	ha->fw_dump->eft_addr_l = htonl(LSD(ha->eft_dma));
	ha->fw_dump->eft_addr_h = htonl(MSD(ha->eft_dma));

	ha->fw_dump->header_size =
	    htonl(offsetof(struct qla2xxx_fw_dump, isp));
}

/**
 * qla2x00_resize_request_q() - Resize request queue given available ISP memory.
 * @ha: HA context
 *
 * Returns 0 on success.
 */
static void
qla2x00_resize_request_q(scsi_qla_host_t *ha)
{
	int rval;
	uint16_t fw_iocb_cnt = 0;
	uint16_t request_q_length = REQUEST_ENTRY_CNT_2XXX_EXT_MEM;
	dma_addr_t request_dma;
	request_t *request_ring;

	/* Valid only on recent ISPs. */
	if (IS_QLA2100(ha) || IS_QLA2200(ha))
		return;

	/* Retrieve IOCB counts available to the firmware. */
	rval = qla2x00_get_resource_cnts(ha, NULL, NULL, NULL, &fw_iocb_cnt,
	    &ha->max_npiv_vports);
	if (rval)
		return;
	/* No point in continuing if current settings are sufficient. */
	if (fw_iocb_cnt < 1024)
		return;
	if (ha->request_q_length >= request_q_length)
		return;

	/* Attempt to claim larger area for request queue. */
	request_ring = dma_alloc_coherent(&ha->pdev->dev,
	    (request_q_length + 1) * sizeof(request_t), &request_dma,
	    GFP_KERNEL);
	if (request_ring == NULL)
		return;

	/* Resize successful, report extensions. */
	qla_printk(KERN_INFO, ha, "Extended memory detected (%d KB)...\n",
	    (ha->fw_memory_size + 1) / 1024);
	qla_printk(KERN_INFO, ha, "Resizing request queue depth "
	    "(%d -> %d)...\n", ha->request_q_length, request_q_length);

	/* Clear old allocations. */
	dma_free_coherent(&ha->pdev->dev,
	    (ha->request_q_length + 1) * sizeof(request_t), ha->request_ring,
	    ha->request_dma);

	/* Begin using larger queue. */
	ha->request_q_length = request_q_length;
	ha->request_ring = request_ring;
	ha->request_dma = request_dma;
}

/**
 * qla2x00_setup_chip() - Load and start RISC firmware.
 * @ha: HA context
 *
 * Returns 0 on success.
 */
static int
qla2x00_setup_chip(scsi_qla_host_t *ha)
{
	int rval;
	uint32_t srisc_address = 0;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;
	unsigned long flags;

	if (!IS_FWI2_CAPABLE(ha) && !IS_QLA2100(ha) && !IS_QLA2200(ha)) {
		/* Disable SRAM, Instruction RAM and GP RAM parity.  */
		spin_lock_irqsave(&ha->hardware_lock, flags);
		WRT_REG_WORD(&reg->hccr, (HCCR_ENABLE_PARITY + 0x0));
		RD_REG_WORD(&reg->hccr);
		spin_unlock_irqrestore(&ha->hardware_lock, flags);
	}

	/* Load firmware sequences */
	rval = ha->isp_ops->load_risc(ha, &srisc_address);
	if (rval == QLA_SUCCESS) {
		DEBUG(printk("scsi(%ld): Verifying Checksum of loaded RISC "
		    "code.\n", ha->host_no));

		rval = qla2x00_verify_checksum(ha, srisc_address);
		if (rval == QLA_SUCCESS) {
			/* Start firmware execution. */
			DEBUG(printk("scsi(%ld): Checksum OK, start "
			    "firmware.\n", ha->host_no));

			rval = qla2x00_execute_fw(ha, srisc_address);
			/* Retrieve firmware information. */
			if (rval == QLA_SUCCESS && ha->fw_major_version == 0) {
				qla2x00_get_fw_version(ha,
				    &ha->fw_major_version,
				    &ha->fw_minor_version,
				    &ha->fw_subminor_version,
				    &ha->fw_attributes, &ha->fw_memory_size);
				qla2x00_resize_request_q(ha);
				ha->flags.npiv_supported = 0;
				if ((IS_QLA24XX(ha) || IS_QLA25XX(ha)) &&
				    (ha->fw_attributes & BIT_2)) {
					ha->flags.npiv_supported = 1;
					if ((!ha->max_npiv_vports) ||
					    ((ha->max_npiv_vports + 1) %
					    MIN_MULTI_ID_FABRIC))
						ha->max_npiv_vports =
						    MIN_MULTI_ID_FABRIC - 1;
				}

				if (ql2xallocfwdump)
					qla2x00_alloc_fw_dump(ha);
			}
		} else {
			DEBUG2(printk(KERN_INFO
			    "scsi(%ld): ISP Firmware failed checksum.\n",
			    ha->host_no));
		}
	}

	if (!IS_FWI2_CAPABLE(ha) && !IS_QLA2100(ha) && !IS_QLA2200(ha)) {
		/* Enable proper parity. */
		spin_lock_irqsave(&ha->hardware_lock, flags);
		if (IS_QLA2300(ha))
			/* SRAM parity */
			WRT_REG_WORD(&reg->hccr, HCCR_ENABLE_PARITY + 0x1);
		else
			/* SRAM, Instruction RAM and GP RAM parity */
			WRT_REG_WORD(&reg->hccr, HCCR_ENABLE_PARITY + 0x7);
		RD_REG_WORD(&reg->hccr);
		spin_unlock_irqrestore(&ha->hardware_lock, flags);
	}

	if (rval != QLA_SUCCESS) {
		DEBUG2_3(printk("scsi(%ld): Setup chip **** FAILED ****.\n",
		    ha->host_no));
	}

	return (rval);
}

/**
 * qla2x00_init_response_q_entries() - Initializes response queue entries.
 * @ha: HA context
 *
 * Beginning of request ring has initialization control block already built
 * by nvram config routine.
 *
 * Returns 0 on success.
 */
static void
qla2x00_init_response_q_entries(scsi_qla_host_t *ha)
{
	uint16_t cnt;
	response_t *pkt;

	pkt = ha->response_ring_ptr;
	for (cnt = 0; cnt < ha->response_q_length; cnt++) {
		pkt->signature = RESPONSE_PROCESSED;
		pkt++;
	}

}

#ifdef CONFIG_SCSI_QLA2XXX_TARGET
/**
 * qla2x00_init_atio_q_entries() - Initializes ATIO queue entries.
 * @ha: HA context
 *
 * Beginning of ATIO ring has initialization control block already built
 * by nvram config routine.
 *
 * Returns 0 on success.
 */
static void
qla2x00_init_atio_q_entries(scsi_qla_host_t *ha)
{
	uint16_t cnt;
	atio_t *pkt;

	pkt = ha->atio_ring;
	for (cnt = 0; cnt < ha->atio_q_length; cnt++) {
		pkt->signature = ATIO_PROCESSED;
		pkt++;
	}

}
#endif /* CONFIG_SCSI_QLA2XXX_TARGET */

/**
 * qla2x00_update_fw_options() - Read and process firmware options.
 * @ha: HA context
 *
 * Returns 0 on success.
 */
void
qla2x00_update_fw_options(scsi_qla_host_t *ha)
{
	uint16_t swing, emphasis, tx_sens, rx_sens;

	memset(ha->fw_options, 0, sizeof(ha->fw_options));
	qla2x00_get_fw_options(ha, ha->fw_options);

	if (IS_QLA2100(ha) || IS_QLA2200(ha))
		return;

	/* Serial Link options. */
	DEBUG3(printk("scsi(%ld): Serial link options:\n",
	    ha->host_no));
	DEBUG3(qla2x00_dump_buffer((uint8_t *)&ha->fw_seriallink_options,
	    sizeof(ha->fw_seriallink_options)));

	ha->fw_options[1] &= ~FO1_SET_EMPHASIS_SWING;
	if (ha->fw_seriallink_options[3] & BIT_2) {
		ha->fw_options[1] |= FO1_SET_EMPHASIS_SWING;

		/*  1G settings */
		swing = ha->fw_seriallink_options[2] & (BIT_2 | BIT_1 | BIT_0);
		emphasis = (ha->fw_seriallink_options[2] &
		    (BIT_4 | BIT_3)) >> 3;
		tx_sens = ha->fw_seriallink_options[0] &
		    (BIT_3 | BIT_2 | BIT_1 | BIT_0);
		rx_sens = (ha->fw_seriallink_options[0] &
		    (BIT_7 | BIT_6 | BIT_5 | BIT_4)) >> 4;
		ha->fw_options[10] = (emphasis << 14) | (swing << 8);
		if (IS_QLA2300(ha) || IS_QLA2312(ha) || IS_QLA6312(ha)) {
			if (rx_sens == 0x0)
				rx_sens = 0x3;
			ha->fw_options[10] |= (tx_sens << 4) | rx_sens;
		} else if (IS_QLA2322(ha) || IS_QLA6322(ha))
			ha->fw_options[10] |= BIT_5 |
			    ((rx_sens & (BIT_1 | BIT_0)) << 2) |
			    (tx_sens & (BIT_1 | BIT_0));

		/*  2G settings */
		swing = (ha->fw_seriallink_options[2] &
		    (BIT_7 | BIT_6 | BIT_5)) >> 5;
		emphasis = ha->fw_seriallink_options[3] & (BIT_1 | BIT_0);
		tx_sens = ha->fw_seriallink_options[1] &
		    (BIT_3 | BIT_2 | BIT_1 | BIT_0);
		rx_sens = (ha->fw_seriallink_options[1] &
		    (BIT_7 | BIT_6 | BIT_5 | BIT_4)) >> 4;
		ha->fw_options[11] = (emphasis << 14) | (swing << 8);
		if (IS_QLA2300(ha) || IS_QLA2312(ha) || IS_QLA6312(ha)) {
			if (rx_sens == 0x0)
				rx_sens = 0x3;
			ha->fw_options[11] |= (tx_sens << 4) | rx_sens;
		} else if (IS_QLA2322(ha) || IS_QLA6322(ha))
			ha->fw_options[11] |= BIT_5 |
			    ((rx_sens & (BIT_1 | BIT_0)) << 2) |
			    (tx_sens & (BIT_1 | BIT_0));
	}

	/* FCP2 options. */
	/*  Return command IOCBs without waiting for an ABTS to complete. */
	ha->fw_options[3] |= BIT_13;

	/* LED scheme. */
	if (ha->flags.enable_led_scheme)
		ha->fw_options[2] |= BIT_12;

	/* Detect ISP6312. */
	if (IS_QLA6312(ha))
		ha->fw_options[2] |= BIT_13;

	/* Update firmware options. */
	qla2x00_set_fw_options(ha, ha->fw_options);
}

void
qla24xx_update_fw_options(scsi_qla_host_t *ha)
{
	int rval;

	/* Update Serial Link options. */
	if ((le16_to_cpu(ha->fw_seriallink_options24[0]) & BIT_0) == 0)
		return;

	rval = qla2x00_set_serdes_params(ha,
	    le16_to_cpu(ha->fw_seriallink_options24[1]),
	    le16_to_cpu(ha->fw_seriallink_options24[2]),
	    le16_to_cpu(ha->fw_seriallink_options24[3]));
	if (rval != QLA_SUCCESS) {
		qla_printk(KERN_WARNING, ha,
		    "Unable to update Serial Link options (%x).\n", rval);
	}
}

void
qla2x00_config_rings(struct scsi_qla_host *ha)
{
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;

	/* Setup ring parameters in initialization control block. */
	ha->init_cb->request_q_outpointer = __constant_cpu_to_le16(0);
	ha->init_cb->response_q_inpointer = __constant_cpu_to_le16(0);
	ha->init_cb->request_q_length = cpu_to_le16(ha->request_q_length);
	ha->init_cb->response_q_length = cpu_to_le16(ha->response_q_length);
	ha->init_cb->request_q_address[0] = cpu_to_le32(LSD(ha->request_dma));
	ha->init_cb->request_q_address[1] = cpu_to_le32(MSD(ha->request_dma));
	ha->init_cb->response_q_address[0] = cpu_to_le32(LSD(ha->response_dma));
	ha->init_cb->response_q_address[1] = cpu_to_le32(MSD(ha->response_dma));

	WRT_REG_WORD(ISP_REQ_Q_IN(ha, reg), 0);
	WRT_REG_WORD(ISP_REQ_Q_OUT(ha, reg), 0);
	WRT_REG_WORD(ISP_RSP_Q_IN(ha, reg), 0);
	WRT_REG_WORD(ISP_RSP_Q_OUT(ha, reg), 0);
	RD_REG_WORD(ISP_RSP_Q_OUT(ha, reg));		/* PCI Posting. */
}

void
qla24xx_config_rings(struct scsi_qla_host *ha)
{
	struct device_reg_24xx __iomem *reg = &ha->iobase->isp24;
	struct init_cb_24xx *icb;

	/* Setup ring parameters in initialization control block. */
	icb = (struct init_cb_24xx *)ha->init_cb;
	icb->request_q_outpointer = __constant_cpu_to_le16(0);
	icb->response_q_inpointer = __constant_cpu_to_le16(0);
	icb->request_q_length = cpu_to_le16(ha->request_q_length);
	icb->response_q_length = cpu_to_le16(ha->response_q_length);
	icb->request_q_address[0] = cpu_to_le32(LSD(ha->request_dma));
	icb->request_q_address[1] = cpu_to_le32(MSD(ha->request_dma));
	icb->response_q_address[0] = cpu_to_le32(LSD(ha->response_dma));
	icb->response_q_address[1] = cpu_to_le32(MSD(ha->response_dma));

#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	icb->atio_q_inpointer = __constant_cpu_to_le16(0);
	icb->atio_q_length = cpu_to_le16(ha->atio_q_length);
	icb->atio_q_address[0] = cpu_to_le32(LSD(ha->atio_dma));
	icb->atio_q_address[1] = cpu_to_le32(MSD(ha->atio_dma));
#endif

	WRT_REG_DWORD(&reg->req_q_in, 0);
	WRT_REG_DWORD(&reg->req_q_out, 0);
	WRT_REG_DWORD(&reg->rsp_q_in, 0);
	WRT_REG_DWORD(&reg->rsp_q_out, 0);
	RD_REG_DWORD(&reg->rsp_q_out);

#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	WRT_REG_DWORD(&reg->atio_q_in, 0);
	WRT_REG_DWORD(&reg->atio_q_out, 0);
	RD_REG_DWORD(&reg->atio_q_out);
#endif
}

/**
 * qla2x00_init_rings() - Initializes firmware.
 * @ha: HA context
 *
 * Beginning of request ring has initialization control block already built
 * by nvram config routine.
 *
 * Returns 0 on success.
 */
static int
qla2x00_init_rings(scsi_qla_host_t *ha)
{
	int	rval;
	unsigned long flags = 0;
	int cnt;
	struct mid_init_cb_24xx *mid_init_cb =
	    (struct mid_init_cb_24xx *) ha->init_cb;

	spin_lock_irqsave(&ha->hardware_lock, flags);

	/* Clear outstanding commands array. */
	for (cnt = 0; cnt < MAX_OUTSTANDING_COMMANDS; cnt++)
		ha->outstanding_cmds[cnt] = NULL;

	ha->current_outstanding_cmd = 0;

	/* Clear RSCN queue. */
	ha->rscn_in_ptr = 0;
	ha->rscn_out_ptr = 0;

	/* Initialize firmware. */
	ha->request_ring_ptr  = ha->request_ring;
	ha->req_ring_index    = 0;
	ha->req_q_cnt         = ha->request_q_length;
	ha->response_ring_ptr = ha->response_ring;
	ha->rsp_ring_index    = 0;

	/* Initialize response queue entries */
	qla2x00_init_response_q_entries(ha);

#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	ha->atio_ring_ptr     = ha->atio_ring;
	ha->atio_ring_index   = 0;
	qla2x00_init_atio_q_entries(ha); /* Initialize ATIO queue entries */
#endif

	ha->isp_ops->config_rings(ha);

	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	/* Update any ISP specific firmware options before initialization. */
	ha->isp_ops->update_fw_options(ha);

	DEBUG(printk("scsi(%ld): Issue init firmware.\n", ha->host_no));

	if (ha->flags.npiv_supported)
		mid_init_cb->count = cpu_to_le16(ha->max_npiv_vports);

	mid_init_cb->options = __constant_cpu_to_le16(BIT_1);

	rval = qla2x00_init_firmware(ha, ha->init_cb_size);
	if (rval != QLA_SUCCESS) {
		DEBUG2_3(printk("scsi(%ld): Init firmware **** FAILED ****.\n",
		    ha->host_no));
	} else {
		DEBUG3(printk("scsi(%ld): Init firmware -- success.\n",
		    ha->host_no));
	}

	return (rval);
}

/**
 * qla2x00_fw_ready() - Waits for firmware ready.
 * @ha: HA context
 *
 * Returns 0 on success.
 */
static int
qla2x00_fw_ready(scsi_qla_host_t *ha)
{
	int		rval;
	unsigned long	wtime, mtime, cs84xx_time;
	uint16_t	min_wait;	/* Minimum wait time if loop is down */
	uint16_t	wait_time;	/* Wait time if loop is coming ready */
	uint16_t	state[3];

	rval = QLA_SUCCESS;

	/* 20 seconds for loop down. */
	min_wait = 20;

	/*
	 * Firmware should take at most one RATOV to login, plus 5 seconds for
	 * our own processing.
	 */
	if ((wait_time = (ha->retry_count*ha->login_timeout) + 5) < min_wait) {
		wait_time = min_wait;
	}

	/* Min wait time if loop down */
	mtime = jiffies + (min_wait * HZ);

	/* wait time before firmware ready */
	wtime = jiffies + (wait_time * HZ);

	/* Wait for ISP to finish LIP */
	if (!ha->flags.init_done)
 		qla_printk(KERN_INFO, ha, "Waiting for LIP to complete...\n");

	DEBUG3(printk("scsi(%ld): Waiting for LIP to complete...\n",
	    ha->host_no));

	do {
		rval = qla2x00_get_firmware_state(ha, state);
		if (rval == QLA_SUCCESS) {
			if (state[0] < FSTATE_LOSS_OF_SYNC) {
				ha->device_flags &= ~DFLG_NO_CABLE;
			}
			if (IS_QLA84XX(ha) && state[0] != FSTATE_READY) {
				DEBUG16(printk("scsi(%ld): fw_state=%x "
				    "84xx=%x.\n", ha->host_no, state[0],
				    state[2]));
				if ((state[2] & FSTATE_LOGGED_IN) &&
				     (state[2] & FSTATE_WAITING_FOR_VERIFY)) {
					DEBUG16(printk("scsi(%ld): Sending "
					    "verify iocb.\n", ha->host_no));

					cs84xx_time = jiffies;
					rval = qla84xx_init_chip(ha);
					if (rval != QLA_SUCCESS)
						break;

					/* Add time taken to initialize. */
					cs84xx_time = jiffies - cs84xx_time;
					wtime += cs84xx_time;
					mtime += cs84xx_time;
					DEBUG16(printk("scsi(%ld): Increasing "
					    "wait time by %ld. New time %ld\n",
					    ha->host_no, cs84xx_time, wtime));
				}
			} else if (state[0] == FSTATE_READY) {
				DEBUG(printk("scsi(%ld): F/W Ready - OK \n",
				    ha->host_no));

				qla2x00_get_retry_cnt(ha, &ha->retry_count,
				    &ha->login_timeout, &ha->r_a_tov);

				rval = QLA_SUCCESS;
				break;
			}

			rval = QLA_FUNCTION_FAILED;

			if (atomic_read(&ha->loop_down_timer) &&
			    state[0] != FSTATE_READY) {
				/* Loop down. Timeout on min_wait for states
				 * other than Wait for Login.
				 */
				if (time_after_eq(jiffies, mtime)) {
					qla_printk(KERN_INFO, ha,
					    "Cable is unplugged...\n");

					ha->device_flags |= DFLG_NO_CABLE;
					break;
				}
			}
		} else {
			/* Mailbox cmd failed. Timeout on min_wait. */
			if (time_after_eq(jiffies, mtime))
				break;
		}

		if (time_after_eq(jiffies, wtime))
			break;

		/* Delay for a while */
		msleep(500);

		DEBUG3(printk("scsi(%ld): fw_state=%x curr time=%lx.\n",
		    ha->host_no, state[0], jiffies));
	} while (1);

	DEBUG(printk("scsi(%ld): fw_state=%x curr time=%lx.\n",
	    ha->host_no, state[0], jiffies));

	if (rval != QLA_SUCCESS) {
		DEBUG2_3(printk(KERN_INFO "scsi(%ld): Firmware not ready "
		    "(%x).\n", ha->host_no, rval));
	}

	return (rval);
}

/*
*  qla2x00_configure_hba
*      Setup adapter context.
*
* Input:
*      ha = adapter state pointer.
*
* Returns:
*      0 = success
*
* Context:
*      Kernel context.
*/
static int
qla2x00_configure_hba(scsi_qla_host_t *ha)
{
	int       rval;
	uint16_t      loop_id;
	uint16_t      topo;
	uint16_t      sw_cap;
	uint8_t       al_pa;
	uint8_t       area;
	uint8_t       domain;
	char		connect_type[22];
#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	scsi_qla_host_t *pha = ha->parent;
#endif
	/* Get host addresses. */
	rval = qla2x00_get_adapter_id(ha,
	    &loop_id, &al_pa, &area, &domain, &topo, &sw_cap);
	if (rval != QLA_SUCCESS) {
		if (LOOP_TRANSITION(ha) || atomic_read(&ha->loop_down_timer) ||
		    (rval == QLA_COMMAND_ERROR && loop_id == 0x7)) {
			DEBUG2(printk("%s(%ld) Loop is in a transition state\n",
			    __func__, ha->host_no));
		} else {
			qla_printk(KERN_WARNING, ha,
			    "ERROR -- Unable to get host loop ID.\n");
			set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
		}
		return (rval);
	}

	if (topo == 4) {
		qla_printk(KERN_INFO, ha,
			"Cannot get topology - retrying.\n");
		return (QLA_FUNCTION_FAILED);
	}

	ha->loop_id = loop_id;

	/* initialize */
	ha->min_external_loopid = SNS_FIRST_LOOP_ID+1;
	ha->operating_mode = LOOP;
	ha->switch_cap = 0;

	switch (topo) {
	case 0:
		DEBUG3(printk("scsi(%ld): HBA in NL topology.\n",
		    ha->host_no));
		ha->current_topology = ISP_CFG_NL;
		strcpy(connect_type, "(Loop)");
		break;

	case 1:
		DEBUG3(printk("scsi(%ld): HBA in FL topology.\n",
		    ha->host_no));
		ha->switch_cap = sw_cap;
		ha->current_topology = ISP_CFG_FL;
		strcpy(connect_type, "(FL_Port)");
		break;

	case 2:
		DEBUG3(printk("scsi(%ld): HBA in N P2P topology.\n",
		    ha->host_no));
		ha->operating_mode = P2P;
		ha->current_topology = ISP_CFG_N;
		strcpy(connect_type, "(N_Port-to-N_Port)");
		break;

	case 3:
		DEBUG3(printk("scsi(%ld): HBA in F P2P topology.\n",
		    ha->host_no));
		ha->switch_cap = sw_cap;
		ha->operating_mode = P2P;
		ha->current_topology = ISP_CFG_F;
		strcpy(connect_type, "(F_Port)");
		break;

	default:
		DEBUG3(printk("scsi(%ld): HBA in unknown topology %x. "
		    "Using NL.\n",
		    ha->host_no, topo));
		ha->current_topology = ISP_CFG_NL;
		strcpy(connect_type, "(Loop)");
		break;
	}

	/* Save Host port and loop ID. */
	/* byte order - Big Endian */
	ha->d_id.b.domain = domain;
	ha->d_id.b.area = area;
	ha->d_id.b.al_pa = al_pa;
#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	if (pha)
		pha->tgt_vp_map[al_pa].idx = ha->vp_idx;
#endif
	if (!ha->flags.init_done)
 		qla_printk(KERN_INFO, ha,
		    "Topology - %s, Host Loop address 0x%x\n",
 		    connect_type, ha->loop_id);

	if (rval) {
		DEBUG2_3(printk("scsi(%ld): FAILED.\n", ha->host_no));
	} else {
		DEBUG3(printk("scsi(%ld): exiting normally.\n", ha->host_no));
	}

	return(rval);
}

static inline void
qla2x00_set_model_info(scsi_qla_host_t *ha, uint8_t *model, size_t len, char *def)
{
	char *st, *en;
	uint16_t index;

	if (memcmp(model, BINZERO, len) != 0) {
		strncpy(ha->model_number, model, len);
		st = en = ha->model_number;
		en += len - 1;
		while (en > st) {
			if (*en != 0x20 && *en != 0x00)
				break;
			*en-- = '\0';
		}

		index = (ha->pdev->subsystem_device & 0xff);
		if (ha->pdev->subsystem_vendor == PCI_VENDOR_ID_QLOGIC &&
		    index < QLA_MODEL_NAMES)
			ha->model_desc = qla2x00_model_name[index * 2 + 1];
	} else {
		index = (ha->pdev->subsystem_device & 0xff);
		if (ha->pdev->subsystem_vendor == PCI_VENDOR_ID_QLOGIC &&
		    index < QLA_MODEL_NAMES) {
			strcpy(ha->model_number,
			    qla2x00_model_name[index * 2]);
			ha->model_desc = qla2x00_model_name[index * 2 + 1];
		} else {
			strcpy(ha->model_number, def);
		}
	}
}

/* On sparc systems, obtain port and node WWN from firmware
 * properties.
 */
static void qla2xxx_nvram_wwn_from_ofw(scsi_qla_host_t *ha, nvram_t *nv)
{
#ifdef CONFIG_SPARC
	struct pci_dev *pdev = ha->pdev;
	struct device_node *dp = pci_device_to_OF_node(pdev);
	const u8 *val;
	int len;

	val = of_get_property(dp, "port-wwn", &len);
	if (val && len >= WWN_SIZE)
		memcpy(nv->port_name, val, WWN_SIZE);

	val = of_get_property(dp, "node-wwn", &len);
	if (val && len >= WWN_SIZE)
		memcpy(nv->node_name, val, WWN_SIZE);
#endif
}

/*
* NVRAM configuration for ISP 2xxx
*
* Input:
*      ha                = adapter block pointer.
*
* Output:
*      initialization control block in response_ring
*      host adapters parameters in host adapter block
*
* Returns:
*      0 = success.
*/
int
qla2x00_nvram_config(scsi_qla_host_t *ha)
{
	int             rval;
	uint8_t         chksum = 0;
	uint16_t        cnt;
	uint8_t         *dptr1, *dptr2;
	init_cb_t       *icb = ha->init_cb;
	nvram_t         *nv = ha->nvram;
	uint8_t         *ptr = ha->nvram;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;

	rval = QLA_SUCCESS;

	if (unlikely(nv == NULL)) {
		qla_printk(KERN_ERR, ha, "request_ring pointer is NULL\n");
		dump_stack();
		rval = 1;
		goto out;
	}

	/* Determine NVRAM starting address. */
	ha->nvram_size = sizeof(nvram_t);
	ha->nvram_base = 0;
	if (!IS_QLA2100(ha) && !IS_QLA2200(ha) && !IS_QLA2300(ha))
		if ((RD_REG_WORD(&reg->ctrl_status) >> 14) == 1)
			ha->nvram_base = 0x80;

	/* Get NVRAM data and calculate checksum. */
	ha->isp_ops->read_nvram(ha, ptr, ha->nvram_base, ha->nvram_size);
	for (cnt = 0, chksum = 0; cnt < ha->nvram_size; cnt++)
		chksum += *ptr++;

	DEBUG5(printk("scsi(%ld): Contents of NVRAM\n", ha->host_no));
	DEBUG5(qla2x00_dump_buffer((uint8_t *)nv, ha->nvram_size));

	/* Bad NVRAM data, set defaults parameters. */
	if (chksum || nv->id[0] != 'I' || nv->id[1] != 'S' ||
	    nv->id[2] != 'P' || nv->id[3] != ' ' || nv->nvram_version < 1) {
		/* Reset NVRAM data. */
		qla_printk(KERN_WARNING, ha, "Inconsistent NVRAM detected: "
		    "checksum=0x%x id=%c version=0x%x.\n", chksum, nv->id[0],
		    nv->nvram_version);
		qla_printk(KERN_WARNING, ha, "Falling back to functioning (yet "
		    "invalid -- WWPN) defaults.\n");

		if (chksum)
			qla2xxx_hw_event_log(ha, HW_EVENT_NVRAM_CHKSUM_ERR, 0,
			    MSW(chksum), LSW(chksum));

		/*
		 * Set default initialization control block.
		 */
		memset(nv, 0, ha->nvram_size);
		nv->parameter_block_version = ICB_VERSION;

		if (IS_QLA23XX(ha)) {
			nv->firmware_options[0] = BIT_2 | BIT_1;
			nv->firmware_options[1] = BIT_7 | BIT_5;
			nv->add_firmware_options[0] = BIT_5;
			nv->add_firmware_options[1] = BIT_5 | BIT_4;
			nv->frame_payload_size = __constant_cpu_to_le16(2048);
			nv->special_options[1] = BIT_7;
		} else if (IS_QLA2200(ha)) {
			nv->firmware_options[0] = BIT_2 | BIT_1;
			nv->firmware_options[1] = BIT_7 | BIT_5;
			nv->add_firmware_options[0] = BIT_5;
			nv->add_firmware_options[1] = BIT_5 | BIT_4;
			nv->frame_payload_size = __constant_cpu_to_le16(1024);
		} else if (IS_QLA2100(ha)) {
			nv->firmware_options[0] = BIT_3 | BIT_1;
			nv->firmware_options[1] = BIT_5;
			nv->frame_payload_size = __constant_cpu_to_le16(1024);
		}

		nv->max_iocb_allocation = __constant_cpu_to_le16(256);
		nv->execution_throttle = __constant_cpu_to_le16(16);
		nv->retry_count = 8;
		nv->retry_delay = 1;

		nv->port_name[0] = 33;
		nv->port_name[3] = 224;
		nv->port_name[4] = 139;

		qla2xxx_nvram_wwn_from_ofw(ha, nv);

		nv->login_timeout = 4;

		/*
		 * Set default host adapter parameters
		 */
		nv->host_p[1] = BIT_2;
		nv->reset_delay = 5;
		nv->port_down_retry_count = 8;
		nv->max_luns_per_target = __constant_cpu_to_le16(8);
		nv->link_down_timeout = 60;

		rval = 1;
	}

#if defined(CONFIG_IA64_GENERIC) || defined(CONFIG_IA64_SGI_SN2)
	/*
	 * The SN2 does not provide BIOS emulation which means you can't change
	 * potentially bogus BIOS settings. Force the use of default settings
	 * for link rate and frame size.  Hope that the rest of the settings
	 * are valid.
	 */
	if (ia64_platform_is("sn2")) {
		nv->frame_payload_size = __constant_cpu_to_le16(2048);
		if (IS_QLA23XX(ha))
			nv->special_options[1] = BIT_7;
	}
#endif

	/* Reset Initialization control block */
	memset(icb, 0, ha->init_cb_size);

	/*
	 * Setup driver NVRAM options.
	 */
#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	if (!IS_QLA2100(ha)) {
		/* Check if target mode enabled */
		if (qla_tgt_mode_enabled(ha)) {
			if (!ha->saved_set) {
				/* We save only once */
				ha->saved_firmware_options[0] = nv->firmware_options[0];
				ha->saved_firmware_options[1] = nv->firmware_options[1];
				ha->saved_add_firmware_options[0] = nv->add_firmware_options[0];
				ha->saved_add_firmware_options[1] = nv->add_firmware_options[1];
				ha->saved_set = 1;
			}

			/* Enable target mode */
			nv->firmware_options[0] |= BIT_4;

			/* Disable ini mode, if requested */
			if (!qla_ini_mode_enabled(ha))
				nv->firmware_options[0] |= BIT_5;

			/* Disable Full Login after LIP */
			nv->firmware_options[1] &= ~BIT_5;
			/* Enable initial LIP */
			nv->firmware_options[1] &= BIT_1;
			/* Enable FC tapes support */
			nv->add_firmware_options[1] |= BIT_4;
			/* Enable Command Queuing in Target Mode */
			nv->add_firmware_options[1] |= BIT_6;
		} else {
			if (ha->saved_set) {
				nv->firmware_options[0] = ha->saved_firmware_options[0];
				nv->firmware_options[1] = ha->saved_firmware_options[1];
				nv->add_firmware_options[0] = ha->saved_add_firmware_options[0];
				nv->add_firmware_options[1] = ha->saved_add_firmware_options[1];
			}
		}
	}
#endif /* CONFIG_SCSI_QLA2XXX_TARGET */

	if (!IS_QLA2100(ha)) {
		if (ha->enable_class_2) {
			if (ha->flags.init_done) {
				fc_host_supported_classes(ha->host) =
					FC_COS_CLASS2 |	FC_COS_CLASS3;
			}
			nv->add_firmware_options[1] |= BIT_0;
		} else {
			if (ha->flags.init_done) {
				fc_host_supported_classes(ha->host) =
					FC_COS_CLASS3;
			}
			nv->add_firmware_options[1] &= BIT_0;
		}
	}

	/* Enable ADISC and fairness */
	nv->firmware_options[0] |= (BIT_6 | BIT_1);
	/* Enable PDB changed AE */
	nv->firmware_options[1] |= BIT_0;
	/* Stop Port Queue on Full Status */
	nv->firmware_options[1] &= ~BIT_4;

	if (IS_QLA23XX(ha)) {
		/* Enable full duplex */
		nv->firmware_options[0] |= BIT_2;
		/* Disable Fast Status Posting */
		nv->firmware_options[0] &= ~BIT_3;

		/* P2P preferred, otherwise loop */
		nv->add_firmware_options[1] |= BIT_5 | BIT_4;

		/* out-of-order frames rassembly */
		nv->special_options[0] |= BIT_6;

		if (IS_QLA2300(ha)) {
			if (ha->fb_rev == FPM_2310) {
				strcpy(ha->model_number, "QLA2310");
			} else {
				strcpy(ha->model_number, "QLA2300");
			}
		} else {
			qla2x00_set_model_info(ha, nv->model_number,
			    sizeof(nv->model_number), "QLA23xx");
		}
	} else if (IS_QLA2200(ha)) {
		/* Enable full duplex */
		nv->firmware_options[0] |= BIT_2;
		/*
		 * 'Point-to-point preferred, else loop' is not a safe
		 * connection mode setting.
		 */
		if ((nv->add_firmware_options[0] & (BIT_6 | BIT_5 | BIT_4)) ==
		    (BIT_5 | BIT_4)) {
			/* Force 'loop preferred, else point-to-point'. */
			nv->add_firmware_options[0] &= ~(BIT_6 | BIT_5 | BIT_4);
			nv->add_firmware_options[0] |= BIT_5;
		}
		strcpy(ha->model_number, "QLA22xx");
	} else /*if (IS_QLA2100(ha))*/ {
		strcpy(ha->model_number, "QLA2100");
	}

	/*
	 * Copy over NVRAM RISC parameter block to initialization control block.
	 */
	dptr1 = (uint8_t *)icb;
	dptr2 = (uint8_t *)&nv->parameter_block_version;
	cnt = (uint8_t *)&icb->request_q_outpointer - (uint8_t *)&icb->version;
	while (cnt--)
		*dptr1++ = *dptr2++;

	/* Copy 2nd half. */
	dptr1 = (uint8_t *)icb->add_firmware_options;
	cnt = (uint8_t *)icb->reserved_3 - (uint8_t *)icb->add_firmware_options;
	while (cnt--)
		*dptr1++ = *dptr2++;

	/* Prepare nodename */
#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	if (ha->node_name_set) {
		memcpy(icb->node_name, ha->tgt_node_name, WWN_SIZE);
		icb->firmware_options[1] |= BIT_6;
	} else
#endif
		if (nv->host_p[1] & BIT_7) {
			/* Use alternate WWN? */
			memcpy(icb->node_name, nv->alternate_node_name, WWN_SIZE);
			memcpy(icb->port_name, nv->alternate_port_name, WWN_SIZE);
		}

	if ((icb->firmware_options[1] & BIT_6) == 0) {
		/*
		 * Firmware will apply the following mask if the nodename was
		 * not provided.
		 */
		memcpy(icb->node_name, icb->port_name, WWN_SIZE);
		icb->node_name[0] &= 0xF0;
	}

	/*
	 * Set host adapter parameters.
	 */
	if (nv->host_p[0] & BIT_7)
		ql2xextended_error_logging = 1;
	ha->flags.disable_risc_code_load = ((nv->host_p[0] & BIT_4) ? 1 : 0);
	/* Always load RISC code on non ISP2[12]00 chips. */
	if (!IS_QLA2100(ha) && !IS_QLA2200(ha))
		ha->flags.disable_risc_code_load = 0;
	ha->flags.enable_lip_reset = ((nv->host_p[1] & BIT_1) ? 1 : 0);
	ha->flags.enable_lip_full_login = ((nv->host_p[1] & BIT_2) ? 1 : 0);
	ha->flags.enable_target_reset = ((nv->host_p[1] & BIT_3) ? 1 : 0);
	ha->flags.enable_led_scheme = (nv->special_options[1] & BIT_4) ? 1 : 0;
	ha->flags.disable_serdes = 0;

	ha->operating_mode =
	    (icb->add_firmware_options[0] & (BIT_6 | BIT_5 | BIT_4)) >> 4;

	memcpy(ha->fw_seriallink_options, nv->seriallink_options,
	    sizeof(ha->fw_seriallink_options));

	/* save HBA serial number */
	ha->serial0 = icb->port_name[5];
	ha->serial1 = icb->port_name[6];
	ha->serial2 = icb->port_name[7];
	ha->node_name = icb->node_name;
	ha->port_name = icb->port_name;

	icb->execution_throttle = __constant_cpu_to_le16(0xFFFF);

	ha->retry_count = nv->retry_count;

	/* Set minimum login_timeout to 4 seconds. */
	if (nv->login_timeout < ql2xlogintimeout)
		nv->login_timeout = ql2xlogintimeout;
	if (nv->login_timeout < 4)
		nv->login_timeout = 4;
	ha->login_timeout = nv->login_timeout;
	icb->login_timeout = nv->login_timeout;

	/* Set minimum RATOV to 100 tenths of a second. */
	ha->r_a_tov = 100;

	ha->loop_reset_delay = nv->reset_delay;

	/* Link Down Timeout = 0:
	 *
	 * 	When Port Down timer expires we will start returning
	 *	I/O's to OS with "DID_NO_CONNECT".
	 *
	 * Link Down Timeout != 0:
	 *
	 *	 The driver waits for the link to come up after link down
	 *	 before returning I/Os to OS with "DID_NO_CONNECT".
	 */
	if (nv->link_down_timeout == 0) {
		ha->loop_down_abort_time =
		    (LOOP_DOWN_TIME - LOOP_DOWN_TIMEOUT);
	} else {
		ha->link_down_timeout =	 nv->link_down_timeout;
		ha->loop_down_abort_time =
		    (LOOP_DOWN_TIME - ha->link_down_timeout);
	}

	/*
	 * Need enough time to try and get the port back.
	 */
	ha->port_down_retry_count = nv->port_down_retry_count;
	if (qlport_down_retry)
		ha->port_down_retry_count = qlport_down_retry;
	/* Set login_retry_count */
	ha->login_retry_count  = nv->retry_count;
	if (ha->port_down_retry_count == nv->port_down_retry_count &&
	    ha->port_down_retry_count > 3)
		ha->login_retry_count = ha->port_down_retry_count;
	else if (ha->port_down_retry_count > (int)ha->login_retry_count)
		ha->login_retry_count = ha->port_down_retry_count;
	if (ql2xloginretrycount)
		ha->login_retry_count = ql2xloginretrycount;

	icb->lun_enables = __constant_cpu_to_le16(0);
	icb->command_resource_count = 0;
	icb->immediate_notify_resource_count = 0;
	icb->timeout = __constant_cpu_to_le16(0);

	if (IS_QLA2100(ha) || IS_QLA2200(ha)) {
		/* Enable RIO */
		icb->firmware_options[0] &= ~BIT_3;
		icb->add_firmware_options[0] &=
		    ~(BIT_3 | BIT_2 | BIT_1 | BIT_0);
		icb->add_firmware_options[0] |= BIT_2;
		icb->response_accumulation_timer = 3;
		icb->interrupt_delay_timer = 5;

		ha->flags.process_response_queue = 1;
	} else {
		/* Enable ZIO. */
		if (!ha->flags.init_done) {
			ha->zio_mode = icb->add_firmware_options[0] &
			    (BIT_3 | BIT_2 | BIT_1 | BIT_0);
			ha->zio_timer = icb->interrupt_delay_timer ?
			    icb->interrupt_delay_timer: 2;
		}
		icb->add_firmware_options[0] &=
		    ~(BIT_3 | BIT_2 | BIT_1 | BIT_0);
		ha->flags.process_response_queue = 0;
		if (ha->zio_mode != QLA_ZIO_DISABLED) {
			ha->zio_mode = QLA_ZIO_MODE_6;

			DEBUG2(printk("scsi(%ld): ZIO mode %d enabled; timer "
			    "delay (%d us).\n", ha->host_no, ha->zio_mode,
			    ha->zio_timer * 100));
			qla_printk(KERN_INFO, ha,
			    "ZIO mode %d enabled; timer delay (%d us).\n",
			    ha->zio_mode, ha->zio_timer * 100);

			icb->add_firmware_options[0] |= (uint8_t)ha->zio_mode;
			icb->interrupt_delay_timer = (uint8_t)ha->zio_timer;
			ha->flags.process_response_queue = 1;
		}
	}
out:
	if (rval) {
		DEBUG2_3(printk(KERN_WARNING
		    "scsi(%ld): NVRAM configuration failed!\n", ha->host_no));
	}
	return (rval);
}

static void
qla2x00_rport_del(void *data)
{
	fc_port_t *fcport = data;
	struct fc_rport *rport;

	spin_lock_irq(fcport->ha->host->host_lock);
	rport = fcport->drport;
	fcport->drport = NULL;
	spin_unlock_irq(fcport->ha->host->host_lock);
	if (rport) {
		fc_remote_port_delete(rport);
#ifdef CONFIG_SCSI_QLA2XXX_TARGET
		if (qla_target.tgt_fc_port_deleted)
			qla_target.tgt_fc_port_deleted(fcport->ha, fcport);
#endif
	}
}

/**
 * qla2x00_alloc_fcport() - Allocate a generic fcport.
 * @ha: HA context
 * @flags: allocation flags
 *
 * Returns a pointer to the allocated fcport, or NULL, if none available.
 */
static fc_port_t *
qla2x00_alloc_fcport(scsi_qla_host_t *ha, gfp_t flags)
{
	fc_port_t *fcport;

	fcport = kzalloc(sizeof(fc_port_t), flags);
	if (!fcport)
		return NULL;

	/* Setup fcport template structure. */
	fcport->ha = ha;
	fcport->vp_idx = ha->vp_idx;
	fcport->port_type = FCT_UNKNOWN;
	fcport->loop_id = FC_NO_LOOP_ID;
	atomic_set(&fcport->state, FCS_UNCONFIGURED);
	fcport->flags = FCF_RLC_SUPPORT;
	fcport->supported_classes = FC_COS_UNSPECIFIED;

	return fcport;
}

/*
 * qla2x00_configure_loop
 *      Updates Fibre Channel Device Database with what is actually on loop.
 *
 * Input:
 *      ha                = adapter block pointer.
 *
 * Returns:
 *      0 = success.
 *      1 = error.
 *      2 = database was full and device was not configured.
 */
 int
qla2x00_configure_loop(scsi_qla_host_t *ha)
{
	int  rval;
	unsigned long flags, save_flags;

	rval = QLA_SUCCESS;

	/* Get Initiator ID */
	if (test_bit(LOCAL_LOOP_UPDATE, &ha->dpc_flags)) {
		rval = qla2x00_configure_hba(ha);
		if (rval != QLA_SUCCESS) {
			DEBUG(printk("scsi(%ld): Unable to configure HBA.\n",
			    ha->host_no));
			return (rval);
		}
	}

	save_flags = flags = ha->dpc_flags;
	DEBUG(printk("scsi(%ld): Configure loop -- dpc flags =0x%lx\n",
	    ha->host_no, flags));

	/*
	 * If we have both an RSCN and PORT UPDATE pending then handle them
	 * both at the same time.
	 */
	clear_bit(LOCAL_LOOP_UPDATE, &ha->dpc_flags);
	clear_bit(RSCN_UPDATE, &ha->dpc_flags);

	/* Determine what we need to do */
	if (ha->current_topology == ISP_CFG_FL &&
	    (test_bit(LOCAL_LOOP_UPDATE, &flags))) {

		ha->flags.rscn_queue_overflow = 1;
		set_bit(RSCN_UPDATE, &flags);

	} else if (ha->current_topology == ISP_CFG_F &&
	    (test_bit(LOCAL_LOOP_UPDATE, &flags))) {

		ha->flags.rscn_queue_overflow = 1;
		set_bit(RSCN_UPDATE, &flags);
		clear_bit(LOCAL_LOOP_UPDATE, &flags);

	} else if (ha->current_topology == ISP_CFG_N) {
		clear_bit(RSCN_UPDATE, &flags);

	} else if (!ha->flags.online ||
	    (test_bit(ABORT_ISP_ACTIVE, &flags))) {

		ha->flags.rscn_queue_overflow = 1;
		set_bit(RSCN_UPDATE, &flags);
		set_bit(LOCAL_LOOP_UPDATE, &flags);
	}

	if (test_bit(LOCAL_LOOP_UPDATE, &flags)) {
		if (test_bit(LOOP_RESYNC_NEEDED, &ha->dpc_flags)) {
			rval = QLA_FUNCTION_FAILED;
		} else {
			rval = qla2x00_configure_local_loop(ha);
		}
	}

	if (rval == QLA_SUCCESS && test_bit(RSCN_UPDATE, &flags)) {
		if (LOOP_TRANSITION(ha)) {
			rval = QLA_FUNCTION_FAILED;
		} else {
			rval = qla2x00_configure_fabric(ha);
		}
	}

	if (rval == QLA_SUCCESS) {
		if (atomic_read(&ha->loop_down_timer) ||
		    test_bit(LOOP_RESYNC_NEEDED, &ha->dpc_flags)) {
			rval = QLA_FUNCTION_FAILED;
		} else {
			atomic_set(&ha->loop_state, LOOP_READY);

			DEBUG(printk("scsi(%ld): LOOP READY\n", ha->host_no));
		}
	}

	if (rval) {
		DEBUG2_3(printk("%s(%ld): *** FAILED ***\n",
		    __func__, ha->host_no));
	} else {
		DEBUG3(printk("%s: exiting normally\n", __func__));
	}

	/* Restore state if a resync event occured during processing */
	if (test_bit(LOOP_RESYNC_NEEDED, &ha->dpc_flags)) {
		if (test_bit(LOCAL_LOOP_UPDATE, &save_flags))
			set_bit(LOCAL_LOOP_UPDATE, &ha->dpc_flags);
		if (test_bit(RSCN_UPDATE, &save_flags))
			set_bit(RSCN_UPDATE, &ha->dpc_flags);
	}

	return (rval);
}



/*
 * qla2x00_configure_local_loop
 *	Updates Fibre Channel Device Database with local loop devices.
 *
 * Input:
 *	ha = adapter block pointer.
 *
 * Returns:
 *	0 = success.
 */
 int
qla2x00_configure_local_loop(scsi_qla_host_t *ha)
{
	int		rval, rval2;
	int		found_devs;
	int		found;
	fc_port_t	*fcport, *new_fcport;

	uint16_t	index;
	uint16_t	entries;
	char		*id_iter;
	uint16_t	loop_id;
	uint8_t		domain, area, al_pa;
	scsi_qla_host_t *pha = to_qla_parent(ha);

	found_devs = 0;
	new_fcport = NULL;
	entries = MAX_FIBRE_DEVICES;

	DEBUG3(printk("scsi(%ld): Getting FCAL position map\n", ha->host_no));
	DEBUG3(qla2x00_get_fcal_position_map(ha, NULL));

	/* Get list of logged in devices. */
	memset(ha->gid_list, 0, GID_LIST_SIZE);
	rval = qla2x00_get_id_list(ha, ha->gid_list, ha->gid_list_dma,
	    &entries);
	if (rval != QLA_SUCCESS)
		goto cleanup_allocation;

	DEBUG3(printk("scsi(%ld): Entries in ID list (%d)\n",
	    ha->host_no, entries));
	DEBUG3(qla2x00_dump_buffer((uint8_t *)ha->gid_list,
	    entries * sizeof(struct gid_list_info)));

	/* Allocate temporary fcport for any new fcports discovered. */
	new_fcport = qla2x00_alloc_fcport(ha, GFP_KERNEL);
	if (new_fcport == NULL) {
		rval = QLA_MEMORY_ALLOC_FAILED;
		goto cleanup_allocation;
	}
	new_fcport->flags &= ~FCF_FABRIC_DEVICE;

	/*
	 * Mark local devices that were present with FCF_DEVICE_LOST for now.
	 */
	list_for_each_entry_rcu(fcport, &pha->fcports, list) {
		if (fcport->vp_idx != ha->vp_idx)
			continue;

		if (atomic_read(&fcport->state) == FCS_ONLINE &&
		    fcport->port_type != FCT_BROADCAST &&
		    (fcport->flags & FCF_FABRIC_DEVICE) == 0) {

			DEBUG(printk("scsi(%ld): Marking port lost, "
			    "loop_id=0x%04x\n",
			    ha->host_no, fcport->loop_id));

			atomic_set(&fcport->state, FCS_DEVICE_LOST);
			fcport->flags &= ~FCF_FARP_DONE;
		}
	}

	/* Add devices to port list. */
	id_iter = (char *)ha->gid_list;
	for (index = 0; index < entries; index++) {
		domain = ((struct gid_list_info *)id_iter)->domain;
		area = ((struct gid_list_info *)id_iter)->area;
		al_pa = ((struct gid_list_info *)id_iter)->al_pa;
		if (IS_QLA2100(ha) || IS_QLA2200(ha))
			loop_id = (uint16_t)
			    ((struct gid_list_info *)id_iter)->loop_id_2100;
		else
			loop_id = le16_to_cpu(
			    ((struct gid_list_info *)id_iter)->loop_id);
		id_iter += ha->gid_list_info_size;

		/* Bypass reserved domain fields. */
		if ((domain & 0xf0) == 0xf0)
			continue;

		/* Bypass if not same domain and area of adapter. */
		if (area && domain &&
		    (area != ha->d_id.b.area || domain != ha->d_id.b.domain))
			continue;

		/* Bypass invalid local loop ID. */
		if (loop_id > LAST_LOCAL_LOOP_ID)
			continue;

		/* Fill in member data. */
		new_fcport->d_id.b.domain = domain;
		new_fcport->d_id.b.area = area;
		new_fcport->d_id.b.al_pa = al_pa;
		new_fcport->loop_id = loop_id;
		new_fcport->vp_idx = ha->vp_idx;
		rval2 = qla2x00_get_port_database(ha, new_fcport, 0);
		if (rval2 != QLA_SUCCESS) {
			DEBUG2(printk("scsi(%ld): Failed to retrieve fcport "
			    "information -- get_port_database=%x, "
			    "loop_id=0x%04x\n",
			    ha->host_no, rval2, new_fcport->loop_id));
			DEBUG2(printk("scsi(%ld): Scheduling resync...\n",
			    ha->host_no));
			set_bit(LOOP_RESYNC_NEEDED, &ha->dpc_flags);
			continue;
		}

		/* Check for matching device in port list. */
		found = 0;
		fcport = NULL;
		list_for_each_entry_rcu(fcport, &pha->fcports, list) {
			if (fcport->vp_idx != ha->vp_idx)
				continue;

			if (memcmp(new_fcport->port_name, fcport->port_name,
			    WWN_SIZE))
				continue;

			fcport->flags &= ~(FCF_FABRIC_DEVICE |
			    FCF_PERSISTENT_BOUND);
			fcport->loop_id = new_fcport->loop_id;
			fcport->port_type = new_fcport->port_type;
			fcport->d_id.b24 = new_fcport->d_id.b24;
			memcpy(fcport->node_name, new_fcport->node_name,
			    WWN_SIZE);

			found++;
			break;
		}

		if (!found) {
			/* New device, add to fcports list. */
			new_fcport->flags &= ~FCF_PERSISTENT_BOUND;
			if (ha->parent) {
				new_fcport->ha = ha;
				new_fcport->vp_idx = ha->vp_idx;
				list_add_tail(&new_fcport->vp_fcport,
				    &ha->vp_fcports);
			}
			list_add_tail_rcu(&new_fcport->list, &pha->fcports);

			/* Allocate a new replacement fcport. */
			fcport = new_fcport;
			new_fcport = qla2x00_alloc_fcport(ha, GFP_KERNEL);
			if (new_fcport == NULL) {
				rval = QLA_MEMORY_ALLOC_FAILED;
				goto cleanup_allocation;
			}
			new_fcport->flags &= ~FCF_FABRIC_DEVICE;
		}

		/* Base iIDMA settings on HBA port speed. */
		fcport->fp_speed = ha->link_data_rate;

		qla2x00_update_fcport(ha, fcport);

		found_devs++;
	}

cleanup_allocation:
	kfree(new_fcport);

	if (rval != QLA_SUCCESS) {
		DEBUG2(printk("scsi(%ld): Configure local loop error exit: "
		    "rval=%x\n", ha->host_no, rval));
	}

	if (found_devs) {
		ha->device_flags |= DFLG_LOCAL_DEVICES;
		ha->device_flags &= ~DFLG_RETRY_LOCAL_DEVICES;
	}

	return (rval);
}

static void
qla2x00_iidma_fcport(scsi_qla_host_t *ha, fc_port_t *fcport)
{
#define LS_UNKNOWN      2
	static char *link_speeds[5] = { "1", "2", "?", "4", "8" };
	int rval;
	uint16_t mb[6];

	if (!IS_IIDMA_CAPABLE(ha))
		return;

	if (fcport->fp_speed == PORT_SPEED_UNKNOWN ||
	    fcport->fp_speed > ha->link_data_rate)
		return;

	rval = qla2x00_set_idma_speed(ha, fcport->loop_id, fcport->fp_speed,
	    mb);
	if (rval != QLA_SUCCESS) {
		DEBUG2(printk("scsi(%ld): Unable to adjust iIDMA "
		    "%02x%02x%02x%02x%02x%02x%02x%02x -- %04x %x %04x %04x.\n",
		    ha->host_no, fcport->port_name[0], fcport->port_name[1],
		    fcport->port_name[2], fcport->port_name[3],
		    fcport->port_name[4], fcport->port_name[5],
		    fcport->port_name[6], fcport->port_name[7], rval,
		    fcport->fp_speed, mb[0], mb[1]));
	} else {
		DEBUG2(qla_printk(KERN_INFO, ha,
		    "iIDMA adjusted to %s GB/s on "
		    "%02x%02x%02x%02x%02x%02x%02x%02x.\n",
		    link_speeds[fcport->fp_speed], fcport->port_name[0],
		    fcport->port_name[1], fcport->port_name[2],
		    fcport->port_name[3], fcport->port_name[4],
		    fcport->port_name[5], fcport->port_name[6],
		    fcport->port_name[7]));
	}
}

static void
qla2x00_reg_remote_port(scsi_qla_host_t *ha, fc_port_t *fcport)
{
	struct fc_rport_identifiers rport_ids;
	struct fc_rport *rport;

	if (fcport->drport)
		qla2x00_rport_del(fcport);

	rport_ids.node_name = wwn_to_u64(fcport->node_name);
	rport_ids.port_name = wwn_to_u64(fcport->port_name);
	rport_ids.port_id = fcport->d_id.b.domain << 16 |
	    fcport->d_id.b.area << 8 | fcport->d_id.b.al_pa;
	rport_ids.roles = FC_RPORT_ROLE_UNKNOWN;
	fcport->rport = rport = fc_remote_port_add(ha->host, 0, &rport_ids);
	if (!rport) {
		qla_printk(KERN_WARNING, ha,
		    "Unable to allocate fc remote port!\n");
		return;
	}
#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	if (qla_target.tgt_fc_port_added)
		qla_target.tgt_fc_port_added(ha, fcport);
#endif
	spin_lock_irq(fcport->ha->host->host_lock);
	*((fc_port_t **)rport->dd_data) = fcport;
	spin_unlock_irq(fcport->ha->host->host_lock);

	rport->supported_classes = fcport->supported_classes;

	rport_ids.roles = FC_RPORT_ROLE_UNKNOWN;
	if (fcport->port_type == FCT_INITIATOR)
		rport_ids.roles |= FC_RPORT_ROLE_FCP_INITIATOR;
	if (fcport->port_type == FCT_TARGET)
		rport_ids.roles |= FC_RPORT_ROLE_FCP_TARGET;
	fc_remote_port_rolechg(rport, rport_ids.roles);
}

/*
 * qla2x00_update_fcport
 *	Updates device on list.
 *
 * Input:
 *	ha = adapter block pointer.
 *	fcport = port structure pointer.
 *
 * Return:
 *	0  - Success
 *  BIT_0 - error
 *
 * Context:
 *	Kernel context.
 */
void
qla2x00_update_fcport(scsi_qla_host_t *ha, fc_port_t *fcport)
{
	scsi_qla_host_t *pha = to_qla_parent(ha);

	fcport->ha = ha;
	fcport->login_retry = 0;
	fcport->port_login_retry_count = pha->port_down_retry_count *
	    PORT_RETRY_TIME;
	atomic_set(&fcport->port_down_timer, pha->port_down_retry_count *
	    PORT_RETRY_TIME);
	fcport->flags &= ~FCF_LOGIN_NEEDED;

	qla2x00_iidma_fcport(ha, fcport);

	atomic_set(&fcport->state, FCS_ONLINE);

	qla2x00_reg_remote_port(ha, fcport);
}

/*
 * qla2x00_configure_fabric
 *      Setup SNS devices with loop ID's.
 *
 * Input:
 *      ha = adapter block pointer.
 *
 * Returns:
 *      0 = success.
 *      BIT_0 = error
 */
 int
qla2x00_configure_fabric(scsi_qla_host_t *ha)
{
	int	rval, rval2;
	fc_port_t	*fcport, *fcptemp;
	uint16_t	next_loopid;
	uint16_t	mb[MAILBOX_REGISTER_COUNT];
	uint16_t	loop_id;
	LIST_HEAD(new_fcports);
	scsi_qla_host_t *pha = to_qla_parent(ha);

	/* If FL port exists, then SNS is present */
	if (IS_FWI2_CAPABLE(ha))
		loop_id = NPH_F_PORT;
	else
		loop_id = SNS_FL_PORT;
	rval = qla2x00_get_port_name(ha, loop_id, ha->fabric_node_name, 1);
	if (rval != QLA_SUCCESS) {
		DEBUG2(printk("scsi(%ld): MBC_GET_PORT_NAME Failed, No FL "
		    "Port\n", ha->host_no));

		ha->device_flags &= ~SWITCH_FOUND;
		return (QLA_SUCCESS);
	}
	ha->device_flags |= SWITCH_FOUND;

	/* Mark devices that need re-synchronization. */
	rval2 = qla2x00_device_resync(ha);
	if (rval2 == QLA_RSCNS_HANDLED) {
		/* No point doing the scan, just continue. */
		return (QLA_SUCCESS);
	}
	do {
		/* FDMI support. */
		if (ql2xfdmienable &&
		    test_and_clear_bit(REGISTER_FDMI_NEEDED, &ha->dpc_flags))
			qla2x00_fdmi_register(ha);

		/* Ensure we are logged into the SNS. */
		if (IS_FWI2_CAPABLE(ha))
			loop_id = NPH_SNS;
		else
			loop_id = SIMPLE_NAME_SERVER;
		ha->isp_ops->fabric_login(ha, loop_id, 0xff, 0xff,
		    0xfc, mb, BIT_1 | BIT_0);
		if (mb[0] != MBS_COMMAND_COMPLETE) {
			DEBUG2(qla_printk(KERN_INFO, ha,
			    "Failed SNS login: loop_id=%x mb[0]=%x mb[1]=%x "
			    "mb[2]=%x mb[6]=%x mb[7]=%x\n", loop_id,
			    mb[0], mb[1], mb[2], mb[6], mb[7]));
			return (QLA_SUCCESS);
		}

		if (test_and_clear_bit(REGISTER_FC4_NEEDED, &ha->dpc_flags)) {
			if (qla2x00_rft_id(ha)) {
				/* EMPTY */
				DEBUG2(printk("scsi(%ld): Register FC-4 "
				    "TYPE failed.\n", ha->host_no));
			}
			if (qla2x00_rff_id(ha)) {
				/* EMPTY */
				DEBUG2(printk("scsi(%ld): Register FC-4 "
				    "Features failed.\n", ha->host_no));
			}
			if (qla2x00_rnn_id(ha)) {
				/* EMPTY */
				DEBUG2(printk("scsi(%ld): Register Node Name "
				    "failed.\n", ha->host_no));
			} else if (qla2x00_rsnn_nn(ha)) {
				/* EMPTY */
				DEBUG2(printk("scsi(%ld): Register Symbolic "
				    "Node Name failed.\n", ha->host_no));
			}
		}

		rval = qla2x00_find_all_fabric_devs(ha, &new_fcports);
		if (rval != QLA_SUCCESS) {
			break;
		}

		/*
		 * Logout all previous fabric devices marked lost, except
		 * tape devices.
		 */
		list_for_each_entry_rcu(fcport, &pha->fcports, list) {
			if (fcport->vp_idx !=ha->vp_idx)
				continue;

			if (test_bit(LOOP_RESYNC_NEEDED, &ha->dpc_flags))
				break;

			if ((fcport->flags & FCF_FABRIC_DEVICE) == 0)
				continue;

			if (atomic_read(&fcport->state) == FCS_DEVICE_LOST) {
				qla2x00_mark_device_lost(ha, fcport,
				    ql2xplogiabsentdevice, 0);
				if (fcport->loop_id != FC_NO_LOOP_ID &&
				    (fcport->flags & FCF_TAPE_PRESENT) == 0 &&
				    fcport->port_type != FCT_INITIATOR &&
				    fcport->port_type != FCT_BROADCAST) {
					ha->isp_ops->fabric_logout(ha,
					    fcport->loop_id,
					    fcport->d_id.b.domain,
					    fcport->d_id.b.area,
					    fcport->d_id.b.al_pa);
					fcport->loop_id = FC_NO_LOOP_ID;
				}
			}
		}

		/* Starting free loop ID. */
		next_loopid = pha->min_external_loopid;

		/*
		 * Scan through our port list and login entries that need to be
		 * logged in.
		 */
		list_for_each_entry_rcu(fcport, &pha->fcports, list) {
			if (fcport->vp_idx != ha->vp_idx)
				continue;

			if (atomic_read(&ha->loop_down_timer) ||
			    test_bit(LOOP_RESYNC_NEEDED, &ha->dpc_flags))
				break;

			if ((fcport->flags & FCF_FABRIC_DEVICE) == 0 ||
			    (fcport->flags & FCF_LOGIN_NEEDED) == 0)
				continue;

			if (fcport->loop_id == FC_NO_LOOP_ID) {
				fcport->loop_id = next_loopid;
				rval = qla2x00_find_new_loop_id(
				    to_qla_parent(ha), fcport);
				if (rval != QLA_SUCCESS) {
					/* Ran out of IDs to use */
					break;
				}
			}
			/* Login and update database */
			qla2x00_fabric_dev_login(ha, fcport, &next_loopid);
		}

		/* Exit if out of loop IDs. */
		if (rval != QLA_SUCCESS) {
			break;
		}

		/*
		 * Login and add the new devices to our port list.
		 */
		list_for_each_entry_safe(fcport, fcptemp, &new_fcports, list) {
			if (atomic_read(&ha->loop_down_timer) ||
			    test_bit(LOOP_RESYNC_NEEDED, &ha->dpc_flags))
				break;

			/* Find a new loop ID to use. */
			fcport->loop_id = next_loopid;
			rval = qla2x00_find_new_loop_id(to_qla_parent(ha),
			    fcport);
			if (rval != QLA_SUCCESS) {
				/* Ran out of IDs to use */
				break;
			}

			/* Login and update database */
			qla2x00_fabric_dev_login(ha, fcport, &next_loopid);

			if (ha->parent) {
				fcport->ha = ha;
				fcport->vp_idx = ha->vp_idx;
				list_add_tail(&fcport->vp_fcport,
				    &ha->vp_fcports);
				list_del(&fcport->list);
				list_add_tail_rcu(&fcport->list,
				    &ha->parent->fcports);
			} else {
				list_del(&fcport->list);
				list_add_tail_rcu(&fcport->list, &ha->fcports);
			}
		}
	} while (0);

	/* Free all new device structures not processed. */
	list_for_each_entry_safe(fcport, fcptemp, &new_fcports, list) {
		list_del(&fcport->list);
		kfree(fcport);
	}

	if (rval) {
		DEBUG2(printk("scsi(%ld): Configure fabric error exit: "
		    "rval=%d\n", ha->host_no, rval));
	}

	return (rval);
}


/*
 * qla2x00_find_all_fabric_devs
 *
 * Input:
 *	ha = adapter block pointer.
 *	dev = database device entry pointer.
 *
 * Returns:
 *	0 = success.
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_find_all_fabric_devs(scsi_qla_host_t *ha, struct list_head *new_fcports)
{
	int		rval;
	uint16_t	loop_id;
	fc_port_t	*fcport, *new_fcport, *fcptemp;
	int		found;

	sw_info_t	*swl;
	int		swl_idx;
	int		first_dev, last_dev;
	port_id_t	wrap, nxt_d_id;
	int 		vp_index;
	int		empty_vp_index;
	int		found_vp;
	scsi_qla_host_t *vha;
	scsi_qla_host_t *pha = to_qla_parent(ha);

	rval = QLA_SUCCESS;
	wrap.b24 = 0; /* undefined */

	/* Try GID_PT to get device list, else GAN. */
	swl = kcalloc(MAX_FIBRE_DEVICES, sizeof(sw_info_t), GFP_ATOMIC);
	if (!swl) {
		/*EMPTY*/
		DEBUG2(printk("scsi(%ld): GID_PT allocations failed, fallback "
		    "on GA_NXT\n", ha->host_no));
	} else {
		if (qla2x00_gid_pt(ha, swl) != QLA_SUCCESS) {
			kfree(swl);
			swl = NULL;
		} else if (qla2x00_gpn_id(ha, swl) != QLA_SUCCESS) {
			kfree(swl);
			swl = NULL;
		} else if (qla2x00_gnn_id(ha, swl) != QLA_SUCCESS) {
			kfree(swl);
			swl = NULL;
		} else if (qla2x00_gfpn_id(ha, swl) == QLA_SUCCESS) {
			qla2x00_gpsc(ha, swl);
		}
	}
	swl_idx = 0;

	/* Allocate temporary fcport for any new fcports discovered. */
	new_fcport = qla2x00_alloc_fcport(ha, GFP_KERNEL);
	if (new_fcport == NULL) {
		kfree(swl);
		return (QLA_MEMORY_ALLOC_FAILED);
	}
	new_fcport->flags |= (FCF_FABRIC_DEVICE | FCF_LOGIN_NEEDED);
	new_fcport->vp_idx = ha->vp_idx;
	/* Set start port ID scan at adapter ID. */
	first_dev = 1;
	last_dev = 0;

	/* Starting free loop ID. */
	loop_id = pha->min_external_loopid;
	for (; loop_id <= ha->last_loop_id; loop_id++) {
		if (qla2x00_is_reserved_id(ha, loop_id))
			continue;

		if (atomic_read(&ha->loop_down_timer) || LOOP_TRANSITION(ha))
			break;

		if (swl != NULL) {
			if (last_dev) {
				wrap.b24 = new_fcport->d_id.b24;
			} else {
				new_fcport->d_id.b24 = swl[swl_idx].d_id.b24;
				memcpy(new_fcport->node_name,
				    swl[swl_idx].node_name, WWN_SIZE);
				memcpy(new_fcport->port_name,
				    swl[swl_idx].port_name, WWN_SIZE);
				memcpy(new_fcport->fabric_port_name,
				    swl[swl_idx].fabric_port_name, WWN_SIZE);
				new_fcport->fp_speed = swl[swl_idx].fp_speed;

				if (swl[swl_idx].d_id.b.rsvd_1 != 0) {
					last_dev = 1;
				}
				swl_idx++;
			}
		} else {
			/* Send GA_NXT to the switch */
			rval = qla2x00_ga_nxt(ha, new_fcport);
			if (rval != QLA_SUCCESS) {
				qla_printk(KERN_WARNING, ha,
				    "SNS scan failed -- assuming zero-entry "
				    "result...\n");
				list_for_each_entry_safe(fcport, fcptemp,
				    new_fcports, list) {
					list_del(&fcport->list);
					kfree(fcport);
				}
				rval = QLA_SUCCESS;
				break;
			}
		}

		/* If wrap on switch device list, exit. */
		if (first_dev) {
			wrap.b24 = new_fcport->d_id.b24;
			first_dev = 0;
		} else if (new_fcport->d_id.b24 == wrap.b24) {
			DEBUG2(printk("scsi(%ld): device wrap (%02x%02x%02x)\n",
			    ha->host_no, new_fcport->d_id.b.domain,
			    new_fcport->d_id.b.area, new_fcport->d_id.b.al_pa));
			break;
		}

		/* Bypass if same physical adapter. */
		if (new_fcport->d_id.b24 == pha->d_id.b24)
			continue;

		/* Bypass virtual ports of the same host. */
		if (pha->num_vhosts) {
			for_each_mapped_vp_idx(pha, vp_index) {
				empty_vp_index = 1;
				found_vp = 0;
				list_for_each_entry(vha, &pha->vp_list,
				    vp_list) {
					if (vp_index == vha->vp_idx) {
						empty_vp_index = 0;
						found_vp = 1;
						break;
					}
				}

				if (empty_vp_index)
					continue;

				if (found_vp &&
				    new_fcport->d_id.b24 == vha->d_id.b24)
					break;
			}

			if (vp_index <= pha->max_npiv_vports)
				continue;
		}

		/* Bypass if same domain and area of adapter. */
		if (((new_fcport->d_id.b24 & 0xffff00) ==
		    (ha->d_id.b24 & 0xffff00)) && ha->current_topology ==
			ISP_CFG_FL)
			    continue;

		/* Bypass reserved domain fields. */
		if ((new_fcport->d_id.b.domain & 0xf0) == 0xf0)
			continue;

		/* Locate matching device in database. */
		found = 0;
		list_for_each_entry_rcu(fcport, &pha->fcports, list) {
			if (new_fcport->vp_idx != fcport->vp_idx)
				continue;
			if (memcmp(new_fcport->port_name, fcport->port_name,
			    WWN_SIZE))
				continue;

			found++;

			/* Update port state. */
			memcpy(fcport->fabric_port_name,
			    new_fcport->fabric_port_name, WWN_SIZE);
			fcport->fp_speed = new_fcport->fp_speed;

			/*
			 * If address the same and state FCS_ONLINE, nothing
			 * changed.
			 */
			if (fcport->d_id.b24 == new_fcport->d_id.b24 &&
			    atomic_read(&fcport->state) == FCS_ONLINE) {
				break;
			}

			/*
			 * If device was not a fabric device before.
			 */
			if ((fcport->flags & FCF_FABRIC_DEVICE) == 0) {
				fcport->d_id.b24 = new_fcport->d_id.b24;
				fcport->loop_id = FC_NO_LOOP_ID;
				fcport->flags |= (FCF_FABRIC_DEVICE |
				    FCF_LOGIN_NEEDED);
				fcport->flags &= ~FCF_PERSISTENT_BOUND;
				break;
			}

			/*
			 * Port ID changed or device was marked to be updated;
			 * Log it out if still logged in and mark it for
			 * relogin later.
			 */
			fcport->d_id.b24 = new_fcport->d_id.b24;
			fcport->flags |= FCF_LOGIN_NEEDED;
			if (fcport->loop_id != FC_NO_LOOP_ID &&
			    (fcport->flags & FCF_TAPE_PRESENT) == 0 &&
			    fcport->port_type != FCT_INITIATOR &&
			    fcport->port_type != FCT_BROADCAST) {
				ha->isp_ops->fabric_logout(ha, fcport->loop_id,
				    fcport->d_id.b.domain, fcport->d_id.b.area,
				    fcport->d_id.b.al_pa);
				fcport->loop_id = FC_NO_LOOP_ID;
			}

			break;
		}

		if (found)
			continue;

		/* If device was not in our fcports list, then add it. */
		list_add_tail_rcu(&new_fcport->list, new_fcports);

		/* Allocate a new replacement fcport. */
		nxt_d_id.b24 = new_fcport->d_id.b24;
		new_fcport = qla2x00_alloc_fcport(ha, GFP_KERNEL);
		if (new_fcport == NULL) {
			kfree(swl);
			return (QLA_MEMORY_ALLOC_FAILED);
		}
		new_fcport->flags |= (FCF_FABRIC_DEVICE | FCF_LOGIN_NEEDED);
		new_fcport->d_id.b24 = nxt_d_id.b24;
		new_fcport->vp_idx = ha->vp_idx;
	}

	kfree(swl);
	kfree(new_fcport);

	if (!list_empty(new_fcports))
		ha->device_flags |= DFLG_FABRIC_DEVICES;

	return (rval);
}

/*
 * qla2x00_find_new_loop_id
 *	Scan through our port list and find a new usable loop ID.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	dev:	port structure pointer.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_find_new_loop_id(scsi_qla_host_t *ha, fc_port_t *dev)
{
	int	rval;
	int	found;
	fc_port_t *fcport;
	uint16_t first_loop_id;
	scsi_qla_host_t *pha = to_qla_parent(ha);

	rval = QLA_SUCCESS;

	/* Save starting loop ID. */
	first_loop_id = dev->loop_id;

	for (;;) {
		/* Skip loop ID if already used by adapter. */
		if (dev->loop_id == ha->loop_id) {
			dev->loop_id++;
		}

		/* Skip reserved loop IDs. */
		while (qla2x00_is_reserved_id(ha, dev->loop_id)) {
			dev->loop_id++;
		}

		/* Reset loop ID if passed the end. */
		if (dev->loop_id > ha->last_loop_id) {
			/* first loop ID. */
			dev->loop_id = ha->min_external_loopid;
		}

		/* Check for loop ID being already in use. */
		found = 0;
		fcport = NULL;
		list_for_each_entry_rcu(fcport, &pha->fcports, list) {
			if (fcport->loop_id == dev->loop_id && fcport != dev) {
				/* ID possibly in use */
				found++;
				break;
			}
		}

		/* If not in use then it is free to use. */
		if (!found) {
			break;
		}

		/* ID in use. Try next value. */
		dev->loop_id++;

		/* If wrap around. No free ID to use. */
		if (dev->loop_id == first_loop_id) {
			dev->loop_id = FC_NO_LOOP_ID;
			rval = QLA_FUNCTION_FAILED;
			break;
		}
	}

	return (rval);
}

/*
 * qla2x00_device_resync
 *	Marks devices in the database that needs resynchronization.
 *
 * Input:
 *	ha = adapter block pointer.
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_device_resync(scsi_qla_host_t *ha)
{
	int	rval;
	uint32_t mask;
	fc_port_t *fcport;
	uint32_t rscn_entry;
	uint8_t rscn_out_iter;
	uint8_t format;
	port_id_t d_id;
	scsi_qla_host_t *pha = to_qla_parent(ha);

	rval = QLA_RSCNS_HANDLED;

	while (ha->rscn_out_ptr != ha->rscn_in_ptr ||
	    ha->flags.rscn_queue_overflow) {

		rscn_entry = ha->rscn_queue[ha->rscn_out_ptr];
		format = MSB(MSW(rscn_entry));
		d_id.b.domain = LSB(MSW(rscn_entry));
		d_id.b.area = MSB(LSW(rscn_entry));
		d_id.b.al_pa = LSB(LSW(rscn_entry));

		DEBUG(printk("scsi(%ld): RSCN queue entry[%d] = "
		    "[%02x/%02x%02x%02x].\n",
		    ha->host_no, ha->rscn_out_ptr, format, d_id.b.domain,
		    d_id.b.area, d_id.b.al_pa));

		ha->rscn_out_ptr++;
		if (ha->rscn_out_ptr == MAX_RSCN_COUNT)
			ha->rscn_out_ptr = 0;

		/* Skip duplicate entries. */
		for (rscn_out_iter = ha->rscn_out_ptr;
		    !ha->flags.rscn_queue_overflow &&
		    rscn_out_iter != ha->rscn_in_ptr;
		    rscn_out_iter = (rscn_out_iter ==
			(MAX_RSCN_COUNT - 1)) ? 0: rscn_out_iter + 1) {

			if (rscn_entry != ha->rscn_queue[rscn_out_iter])
				break;

			DEBUG(printk("scsi(%ld): Skipping duplicate RSCN queue "
			    "entry found at [%d].\n", ha->host_no,
			    rscn_out_iter));

			ha->rscn_out_ptr = rscn_out_iter;
		}

		/* Queue overflow, set switch default case. */
		if (ha->flags.rscn_queue_overflow) {
			DEBUG(printk("scsi(%ld): device_resync: rscn "
			    "overflow.\n", ha->host_no));

			format = 3;
			ha->flags.rscn_queue_overflow = 0;
		}

		switch (format) {
		case 0:
			mask = 0xffffff;
			break;
		case 1:
			mask = 0xffff00;
			break;
		case 2:
			mask = 0xff0000;
			break;
		default:
			mask = 0x0;
			d_id.b24 = 0;
			ha->rscn_out_ptr = ha->rscn_in_ptr;
			break;
		}

		rval = QLA_SUCCESS;

		list_for_each_entry_rcu(fcport, &pha->fcports, list) {
			if (fcport->vp_idx != ha->vp_idx)
				continue;

			if ((fcport->flags & FCF_FABRIC_DEVICE) == 0 ||
			    (fcport->d_id.b24 & mask) != d_id.b24 ||
			    fcport->port_type == FCT_BROADCAST)
				continue;

			if (atomic_read(&fcport->state) == FCS_ONLINE) {
#ifndef CONFIG_SCSI_QLA2XXX_TARGET
				if (format != 3 ||
				    fcport->port_type != FCT_INITIATOR)
#endif
					qla2x00_mark_device_lost(ha, fcport,
					    0, 0);
			}
			fcport->flags &= ~FCF_FARP_DONE;
		}
	}
	return (rval);
}

/*
 * qla2x00_fabric_dev_login
 *	Login fabric target device and update FC port database.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	fcport:		port structure list pointer.
 *	next_loopid:	contains value of a new loop ID that can be used
 *			by the next login attempt.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
qla2x00_fabric_dev_login(scsi_qla_host_t *ha, fc_port_t *fcport,
    uint16_t *next_loopid)
{
	int	rval;
	int	retry;
	uint8_t opts;

	rval = QLA_SUCCESS;
	retry = 0;

	rval = qla2x00_fabric_login(ha, fcport, next_loopid);
	if (rval == QLA_SUCCESS) {
		/* Send an ADISC to tape devices.*/
		opts = 0;
		if (fcport->flags & FCF_TAPE_PRESENT)
			opts |= BIT_1;
		rval = qla2x00_get_port_database(ha, fcport, opts);
		if (rval != QLA_SUCCESS) {
			ha->isp_ops->fabric_logout(ha, fcport->loop_id,
			    fcport->d_id.b.domain, fcport->d_id.b.area,
			    fcport->d_id.b.al_pa);
			qla2x00_mark_device_lost(ha, fcport, 1, 0);
		} else {
			qla2x00_update_fcport(ha, fcport);
		}
	}

	return (rval);
}

/*
 * qla2x00_fabric_login
 *	Issue fabric login command.
 *
 * Input:
 *	ha = adapter block pointer.
 *	device = pointer to FC device type structure.
 *
 * Returns:
 *      0 - Login successfully
 *      1 - Login failed
 *      2 - Initiator device
 *      3 - Fatal error
 */
int
qla2x00_fabric_login(scsi_qla_host_t *ha, fc_port_t *fcport,
    uint16_t *next_loopid)
{
	int	rval;
	int	retry;
	uint16_t tmp_loopid;
	uint16_t mb[MAILBOX_REGISTER_COUNT];

	retry = 0;
	tmp_loopid = 0;

	for (;;) {
		DEBUG(printk("scsi(%ld): Trying Fabric Login w/loop id 0x%04x "
 		    "for port %02x%02x%02x.\n",
 		    ha->host_no, fcport->loop_id, fcport->d_id.b.domain,
		    fcport->d_id.b.area, fcport->d_id.b.al_pa));

		/* Login fcport on switch. */
		ha->isp_ops->fabric_login(ha, fcport->loop_id,
		    fcport->d_id.b.domain, fcport->d_id.b.area,
		    fcport->d_id.b.al_pa, mb, BIT_0);
		if (mb[0] == MBS_PORT_ID_USED) {
			/*
			 * Device has another loop ID.  The firmware team
			 * recommends the driver perform an implicit login with
			 * the specified ID again. The ID we just used is save
			 * here so we return with an ID that can be tried by
			 * the next login.
			 */
			retry++;
			tmp_loopid = fcport->loop_id;
			fcport->loop_id = mb[1];

			DEBUG(printk("Fabric Login: port in use - next "
 			    "loop id=0x%04x, port Id=%02x%02x%02x.\n",
			    fcport->loop_id, fcport->d_id.b.domain,
			    fcport->d_id.b.area, fcport->d_id.b.al_pa));

		} else if (mb[0] == MBS_COMMAND_COMPLETE) {
			/*
			 * Login succeeded.
			 */
			if (retry) {
				/* A retry occurred before. */
				*next_loopid = tmp_loopid;
			} else {
				/*
				 * No retry occurred before. Just increment the
				 * ID value for next login.
				 */
				*next_loopid = (fcport->loop_id + 1);
			}

			if (mb[1] & BIT_0) {
				fcport->port_type = FCT_INITIATOR;
			} else {
				fcport->port_type = FCT_TARGET;
				if (mb[1] & BIT_1) {
					fcport->flags |= FCF_TAPE_PRESENT;
				}
			}

			if (mb[10] & BIT_0)
				fcport->supported_classes |= FC_COS_CLASS2;
			if (mb[10] & BIT_1)
				fcport->supported_classes |= FC_COS_CLASS3;

			if (IS_FWI2_CAPABLE(ha)) {
				if (mb[10] & BIT_7)
					fcport->conf_compl_supported = 1;
			} else {
				/* mb[10] bits are undocumented, ToDo */
			}

			rval = QLA_SUCCESS;
			break;
		} else if (mb[0] == MBS_LOOP_ID_USED) {
			/*
			 * Loop ID already used, try next loop ID.
			 */
			fcport->loop_id++;
			rval = qla2x00_find_new_loop_id(ha, fcport);
			if (rval != QLA_SUCCESS) {
				/* Ran out of loop IDs to use */
				break;
			}
		} else if (mb[0] == MBS_COMMAND_ERROR) {
			/*
			 * Firmware possibly timed out during login. If NO
			 * retries are left to do then the device is declared
			 * dead.
			 */
			*next_loopid = fcport->loop_id;
			ha->isp_ops->fabric_logout(ha, fcport->loop_id,
			    fcport->d_id.b.domain, fcport->d_id.b.area,
			    fcport->d_id.b.al_pa);
			qla2x00_mark_device_lost(ha, fcport, 1, 0);

			rval = 1;
			break;
		} else {
			/*
			 * unrecoverable / not handled error
			 */
			DEBUG2(printk("%s(%ld): failed=%x port_id=%02x%02x%02x "
 			    "loop_id=%x jiffies=%lx.\n",
 			    __func__, ha->host_no, mb[0],
			    fcport->d_id.b.domain, fcport->d_id.b.area,
			    fcport->d_id.b.al_pa, fcport->loop_id, jiffies));

			*next_loopid = fcport->loop_id;
			ha->isp_ops->fabric_logout(ha, fcport->loop_id,
			    fcport->d_id.b.domain, fcport->d_id.b.area,
			    fcport->d_id.b.al_pa);
			fcport->loop_id = FC_NO_LOOP_ID;
			fcport->login_retry = 0;

			rval = 3;
			break;
		}
	}

	return (rval);
}

/*
 * qla2x00_local_device_login
 *	Issue local device login command.
 *
 * Input:
 *	ha = adapter block pointer.
 *	loop_id = loop id of device to login to.
 *
 * Returns (Where's the #define!!!!):
 *      0 - Login successfully
 *      1 - Login failed
 *      3 - Fatal error
 */
int
qla2x00_local_device_login(scsi_qla_host_t *ha, fc_port_t *fcport)
{
	int		rval;
	uint16_t	mb[MAILBOX_REGISTER_COUNT];

	memset(mb, 0, sizeof(mb));
	rval = qla2x00_login_local_device(ha, fcport, mb, BIT_0);
	if (rval == QLA_SUCCESS) {
		/* Interrogate mailbox registers for any errors */
		if (mb[0] == MBS_COMMAND_ERROR)
			rval = 1;
		else if (mb[0] == MBS_COMMAND_PARAMETER_ERROR)
			/* device not in PCB table */
			rval = 3;
	}

	return (rval);
}

/*
 *  qla2x00_loop_resync
 *      Resync with fibre channel devices.
 *
 * Input:
 *      ha = adapter block pointer.
 *
 * Returns:
 *      0 = success
 */
int
qla2x00_loop_resync(scsi_qla_host_t *ha)
{
	int   rval;
	uint32_t wait_time;

	rval = QLA_SUCCESS;

	atomic_set(&ha->loop_state, LOOP_UPDATE);
	clear_bit(ISP_ABORT_RETRY, &ha->dpc_flags);
	if (ha->flags.online) {
		if (!(rval = qla2x00_fw_ready(ha))) {
			/* Wait at most MAX_TARGET RSCNs for a stable link. */
			wait_time = 256;
			do {
				atomic_set(&ha->loop_state, LOOP_UPDATE);

				/* Issue a marker after FW becomes ready. */
				qla2x00_marker(ha, 0, 0, MK_SYNC_ALL);
				ha->marker_needed = 0;

				/* Remap devices on Loop. */
				clear_bit(LOOP_RESYNC_NEEDED, &ha->dpc_flags);

				qla2x00_configure_loop(ha);
				wait_time--;
			} while (!atomic_read(&ha->loop_down_timer) &&
				!(test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags)) &&
				wait_time &&
				(test_bit(LOOP_RESYNC_NEEDED, &ha->dpc_flags)));
		}
	}

	if (test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags)) {
		return (QLA_FUNCTION_FAILED);
	}

	if (rval != QLA_SUCCESS)
		DEBUG2_3(printk("%s(): **** FAILED ****\n", __func__));

	return (rval);
}

void
qla2x00_update_fcports(scsi_qla_host_t *ha)
{
	fc_port_t *fcport;

	/* Go with deferred removal of rport references. */
	list_for_each_entry_rcu(fcport, &ha->fcports, list) {
		if (fcport->drport)
			qla2x00_rport_del(fcport);
	}
}

/*
*  qla2x00_abort_isp
*      Resets ISP and aborts all outstanding commands.
*
* Input:
*      ha           = adapter block pointer.
*
* Returns:
*      0 = success
*/
int
qla2x00_abort_isp(scsi_qla_host_t *ha)
{
	int rval;
	uint8_t        status = 0;

	if (ha->flags.online) {
		ha->flags.online = 0;
		clear_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);

		qla_printk(KERN_INFO, ha,
		    "Performing ISP abort - ha= %p.\n", ha);
		ha->isp_ops->reset_chip(ha);

		atomic_set(&ha->loop_down_timer, LOOP_DOWN_TIME);
		if (atomic_read(&ha->loop_state) != LOOP_DOWN) {
			atomic_set(&ha->loop_state, LOOP_DOWN);
			qla2x00_mark_all_devices_lost(ha, 0);
		} else {
			if (!atomic_read(&ha->loop_down_timer))
				atomic_set(&ha->loop_down_timer,
				    LOOP_DOWN_TIME);
		}

		/* Requeue all commands in outstanding command list. */
		qla2x00_abort_all_cmds(ha, DID_RESET << 16);

		ha->isp_ops->get_flash_version(ha, ha->request_ring);

		ha->isp_ops->nvram_config(ha);

		if (!qla2x00_restart_isp(ha)) {
			clear_bit(RESET_MARKER_NEEDED, &ha->dpc_flags);

			if (!atomic_read(&ha->loop_down_timer)) {
				/*
				 * Issue marker command only when we are going
				 * to start the I/O .
				 */
				ha->marker_needed = 1;
			}

			ha->flags.online = 1;

#ifdef CONFIG_SCSI_QLA2XXX_TARGET
			/* Enable target response to SCSI bus. */
			if (qla_tgt_mode_enabled(ha))
				qla2x00_send_enable_lun(ha, true);
#endif

			ha->isp_ops->enable_intrs(ha);

			ha->isp_abort_cnt = 0;
			clear_bit(ISP_ABORT_RETRY, &ha->dpc_flags);

			if (ha->eft) {
				memset(ha->eft, 0, EFT_SIZE);
				rval = qla2x00_enable_eft_trace(ha,
				    ha->eft_dma, EFT_NUM_BUFFERS);
				if (rval) {
					qla_printk(KERN_WARNING, ha,
					    "Unable to reinitialize EFT "
					    "(%d).\n", rval);
				}
			}

			if (ha->fce) {
				ha->flags.fce_enabled = 1;
				memset(ha->fce, 0,
				    fce_calc_size(ha->fce_bufs));
				rval = qla2x00_enable_fce_trace(ha,
				    ha->fce_dma, ha->fce_bufs, ha->fce_mb,
				    &ha->fce_bufs);
				if (rval) {
					qla_printk(KERN_WARNING, ha,
					    "Unable to reinitialize FCE "
					    "(%d).\n", rval);
					ha->flags.fce_enabled = 0;
				}
			}
		} else {	/* failed the ISP abort */
			ha->flags.online = 1;
			if (test_bit(ISP_ABORT_RETRY, &ha->dpc_flags)) {
				if (ha->isp_abort_cnt == 0) {
 					qla_printk(KERN_WARNING, ha,
					    "ISP error recovery failed - "
					    "board disabled\n");
					/*
					 * The next call disables the board
					 * completely.
					 */
					ha->isp_ops->reset_adapter(ha);
					ha->flags.online = 0;
					clear_bit(ISP_ABORT_RETRY,
					    &ha->dpc_flags);
					status = 0;
				} else { /* schedule another ISP abort */
					ha->isp_abort_cnt--;
					DEBUG(printk("qla%ld: ISP abort - "
					    "retry remaining %d\n",
					    ha->host_no, ha->isp_abort_cnt));
					status = 1;
				}
			} else {
				ha->isp_abort_cnt = MAX_RETRIES_OF_ISP_ABORT;
				DEBUG(printk("qla2x00(%ld): ISP error recovery "
				    "- retrying (%d) more times\n",
				    ha->host_no, ha->isp_abort_cnt));
				set_bit(ISP_ABORT_RETRY, &ha->dpc_flags);
				status = 1;
			}
		}

	}

	if (status) {
		qla_printk(KERN_INFO, ha,
			"qla2x00_abort_isp: **** FAILED ****\n");
	} else {
		DEBUG(printk(KERN_INFO
				"qla2x00_abort_isp(%ld): exiting.\n",
				ha->host_no));
	}

	return(status);
}

/*
*  qla2x00_restart_isp
*      restarts the ISP after a reset
*
* Input:
*      ha = adapter block pointer.
*
* Returns:
*      0 = success
*/
static int
qla2x00_restart_isp(scsi_qla_host_t *ha)
{
	uint8_t		status = 0;
	uint32_t wait_time;

	/* If firmware needs to be loaded */
	if (qla2x00_isp_firmware(ha)) {
		ha->flags.online = 0;
		if (!(status = ha->isp_ops->chip_diag(ha)))
			status = qla2x00_setup_chip(ha);
	}

	if (!status && !(status = qla2x00_init_rings(ha))) {
		clear_bit(RESET_MARKER_NEEDED, &ha->dpc_flags);
		if (!(status = qla2x00_fw_ready(ha))) {
			DEBUG(printk("%s(): Start configure loop, "
			    "status = %d\n", __func__, status));

			/* Issue a marker after FW becomes ready. */
			qla2x00_marker(ha, 0, 0, MK_SYNC_ALL);

			ha->flags.online = 1;
			/* Wait at most MAX_TARGET RSCNs for a stable link. */
			wait_time = 256;
			do {
				clear_bit(LOOP_RESYNC_NEEDED, &ha->dpc_flags);
				qla2x00_configure_loop(ha);
				wait_time--;
			} while (!atomic_read(&ha->loop_down_timer) &&
				!(test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags)) &&
				wait_time &&
				(test_bit(LOOP_RESYNC_NEEDED, &ha->dpc_flags)));
		}

		/* if no cable then assume it's good */
		if ((ha->device_flags & DFLG_NO_CABLE))
			status = 0;

		DEBUG(printk("%s(): Configure loop done, status = 0x%x\n",
				__func__,
				status));
	}
	return (status);
}

/*
* qla2x00_reset_adapter
*      Reset adapter.
*
* Input:
*      ha = adapter block pointer.
*/
void
qla2x00_reset_adapter(scsi_qla_host_t *ha)
{
	unsigned long flags = 0;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;

	ha->flags.online = 0;
	ha->isp_ops->disable_intrs(ha);

	spin_lock_irqsave(&ha->hardware_lock, flags);
	WRT_REG_WORD(&reg->hccr, HCCR_RESET_RISC);
	RD_REG_WORD(&reg->hccr);			/* PCI Posting. */
	WRT_REG_WORD(&reg->hccr, HCCR_RELEASE_RISC);
	RD_REG_WORD(&reg->hccr);			/* PCI Posting. */
	spin_unlock_irqrestore(&ha->hardware_lock, flags);
}

void
qla24xx_reset_adapter(scsi_qla_host_t *ha)
{
	unsigned long flags = 0;
	struct device_reg_24xx __iomem *reg = &ha->iobase->isp24;

	ha->flags.online = 0;
	ha->isp_ops->disable_intrs(ha);

	spin_lock_irqsave(&ha->hardware_lock, flags);
	WRT_REG_DWORD(&reg->hccr, HCCRX_SET_RISC_RESET);
	RD_REG_DWORD(&reg->hccr);
	WRT_REG_DWORD(&reg->hccr, HCCRX_REL_RISC_PAUSE);
	RD_REG_DWORD(&reg->hccr);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);
}

/* On sparc systems, obtain port and node WWN from firmware
 * properties.
 */
static void qla24xx_nvram_wwn_from_ofw(scsi_qla_host_t *ha, struct nvram_24xx *nv)
{
#ifdef CONFIG_SPARC
	struct pci_dev *pdev = ha->pdev;
	struct device_node *dp = pci_device_to_OF_node(pdev);
	const u8 *val;
	int len;

	val = of_get_property(dp, "port-wwn", &len);
	if (val && len >= WWN_SIZE)
		memcpy(nv->port_name, val, WWN_SIZE);

	val = of_get_property(dp, "node-wwn", &len);
	if (val && len >= WWN_SIZE)
		memcpy(nv->node_name, val, WWN_SIZE);
#endif
}

int
qla24xx_nvram_config(scsi_qla_host_t *ha)
{
	int   rval;
	struct init_cb_24xx *icb;
	struct nvram_24xx *nv;
	uint32_t *dptr;
	uint8_t  *dptr1, *dptr2;
	uint32_t chksum;
	uint16_t cnt;

	rval = QLA_SUCCESS;
	icb = (struct init_cb_24xx *)ha->init_cb;
	nv = ha->nvram;

	/* Determine NVRAM starting address. */
	ha->nvram_size = sizeof(struct nvram_24xx);
	ha->nvram_base = FA_NVRAM_FUNC0_ADDR;
	ha->vpd_size = FA_NVRAM_VPD_SIZE;
	ha->vpd_base = FA_NVRAM_VPD0_ADDR;
	if (PCI_FUNC(ha->pdev->devfn)) {
		ha->nvram_base = FA_NVRAM_FUNC1_ADDR;
		ha->vpd_base = FA_NVRAM_VPD1_ADDR;
	}

	/* Get VPD data into cache */
	ha->vpd = ha->nvram + VPD_OFFSET;
	ha->isp_ops->read_nvram(ha, (uint8_t *)ha->vpd,
	    ha->nvram_base - FA_NVRAM_FUNC0_ADDR, FA_NVRAM_VPD_SIZE * 4);

	/* Get NVRAM data into cache and calculate checksum. */
	dptr = (uint32_t *)nv;
	ha->isp_ops->read_nvram(ha, (uint8_t *)dptr, ha->nvram_base,
	    ha->nvram_size);
	for (cnt = 0, chksum = 0; cnt < ha->nvram_size >> 2; cnt++)
		chksum += le32_to_cpu(*dptr++);

	DEBUG5(printk("scsi(%ld): Contents of NVRAM\n", ha->host_no));
	DEBUG5(qla2x00_dump_buffer((uint8_t *)nv, ha->nvram_size));

	/* Bad NVRAM data, set defaults parameters. */
	if (chksum || nv->id[0] != 'I' || nv->id[1] != 'S' || nv->id[2] != 'P'
	    || nv->id[3] != ' ' ||
	    nv->nvram_version < __constant_cpu_to_le16(ICB_VERSION)) {
		/* Reset NVRAM data. */
		qla_printk(KERN_WARNING, ha, "Inconsistent NVRAM detected: "
		    "checksum=0x%x id=%c version=0x%x.\n", chksum, nv->id[0],
		    le16_to_cpu(nv->nvram_version));
		qla_printk(KERN_WARNING, ha, "Falling back to functioning (yet "
		    "invalid -- WWPN) defaults.\n");

		/*
		 * Set default initialization control block.
		 */
		memset(nv, 0, ha->nvram_size);
		nv->nvram_version = __constant_cpu_to_le16(ICB_VERSION);
		nv->version = __constant_cpu_to_le16(ICB_VERSION);
		nv->frame_payload_size = __constant_cpu_to_le16(2048);
		nv->execution_throttle = __constant_cpu_to_le16(0xFFFF);
		nv->exchange_count = __constant_cpu_to_le16(0);
		nv->hard_address = __constant_cpu_to_le16(124);
		nv->port_name[0] = 0x21;
		nv->port_name[1] = 0x00 + PCI_FUNC(ha->pdev->devfn);
		nv->port_name[2] = 0x00;
		nv->port_name[3] = 0xe0;
		nv->port_name[4] = 0x8b;
		nv->port_name[5] = 0x1c;
		nv->port_name[6] = 0x55;
		nv->port_name[7] = 0x86;
		nv->node_name[0] = 0x20;
		nv->node_name[1] = 0x00;
		nv->node_name[2] = 0x00;
		nv->node_name[3] = 0xe0;
		nv->node_name[4] = 0x8b;
		nv->node_name[5] = 0x1c;
		nv->node_name[6] = 0x55;
		nv->node_name[7] = 0x86;
		qla24xx_nvram_wwn_from_ofw(ha, nv);
		nv->login_retry_count = __constant_cpu_to_le16(8);
		nv->interrupt_delay_timer = __constant_cpu_to_le16(0);
		nv->login_timeout = __constant_cpu_to_le16(0);
		nv->firmware_options_1 =
		    __constant_cpu_to_le32(BIT_14|BIT_13|BIT_2|BIT_1);
		nv->firmware_options_2 = __constant_cpu_to_le32(2 << 4);
		nv->firmware_options_2 |= __constant_cpu_to_le32(BIT_12);
		nv->firmware_options_3 = __constant_cpu_to_le32(2 << 13);
		nv->host_p = __constant_cpu_to_le32(BIT_11|BIT_10);
		nv->efi_parameters = __constant_cpu_to_le32(0);
		nv->reset_delay = 5;
		nv->max_luns_per_target = __constant_cpu_to_le16(128);
		nv->port_down_retry_count = __constant_cpu_to_le16(30);
		nv->link_down_timeout = __constant_cpu_to_le16(30);

		rval = 1;
	}

#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	/* Check if target mode enabled */
	if (qla_tgt_mode_enabled(ha)) {
		if (!ha->saved_set) {
			/* We save only once */
			ha->saved_exchange_count = nv->exchange_count;
			ha->saved_firmware_options_1 = nv->firmware_options_1;
			ha->saved_firmware_options_2 = nv->firmware_options_2;
			ha->saved_firmware_options_3 = nv->firmware_options_3;
			ha->saved_set = 1;
		}

		nv->exchange_count = __constant_cpu_to_le16(0xFFFF);

		/* Enable target mode */
		nv->firmware_options_1 |= __constant_cpu_to_le32(BIT_4);

		/* Disable ini mode, if requested */
		if (!qla_ini_mode_enabled(ha))
			nv->firmware_options_1 |= __constant_cpu_to_le32(BIT_5);

		/* Disable Full Login after LIP */
		nv->firmware_options_1 &= __constant_cpu_to_le32(~BIT_13);
		/* Enable initial LIP */
		nv->firmware_options_1 &= __constant_cpu_to_le32(~BIT_9);
		/* Enable FC tapes support */
		nv->firmware_options_2 |= __constant_cpu_to_le32(BIT_12);
	} else {
		if (ha->saved_set) {
			nv->exchange_count = ha->saved_exchange_count;
			nv->firmware_options_1 = ha->saved_firmware_options_1;
			nv->firmware_options_2 = ha->saved_firmware_options_2;
			nv->firmware_options_3 = ha->saved_firmware_options_3;
		}
	}
#endif
	/* out-of-order frames reassembly */
	nv->firmware_options_3 |= __constant_cpu_to_le32(BIT_6|BIT_9);

	if (ha->enable_class_2) {
		if (ha->flags.init_done) {
			fc_host_supported_classes(ha->host) =
				FC_COS_CLASS2 |	FC_COS_CLASS3;
		}
		nv->firmware_options_2 |= __constant_cpu_to_le32(BIT_8);
	} else {
		if (ha->flags.init_done)
			fc_host_supported_classes(ha->host) = FC_COS_CLASS3;
		nv->firmware_options_2 &= ~__constant_cpu_to_le32(BIT_8);
	}

#if 0
	/*
	 * firmware_options_3 bits 3-2 are reserved, but for some reason
	 * sometimes set by BIOS. Let's explicitly reset them.
	 */
	nv->firmware_options_3 &= ~__constant_cpu_to_le32(BIT_3|BIT_2);
#endif

	/* Reset Initialization control block */
	memset(icb, 0, sizeof(struct init_cb_24xx));

	/* Copy 1st segment. */
	dptr1 = (uint8_t *)icb;
	dptr2 = (uint8_t *)&nv->version;
	cnt = (uint8_t *)&icb->response_q_inpointer - (uint8_t *)&icb->version;
	while (cnt--)
		*dptr1++ = *dptr2++;

	icb->login_retry_count = nv->login_retry_count;
	icb->link_down_on_nos = nv->link_down_on_nos;

	/* Copy 2nd segment. */
	dptr1 = (uint8_t *)&icb->interrupt_delay_timer;
	dptr2 = (uint8_t *)&nv->interrupt_delay_timer;
	cnt = (uint8_t *)&icb->reserved_3 -
	    (uint8_t *)&icb->interrupt_delay_timer;
	while (cnt--)
		*dptr1++ = *dptr2++;

	/*
	 * Setup driver NVRAM options.
	 */
	qla2x00_set_model_info(ha, nv->model_name, sizeof(nv->model_name),
	    "QLA2462");

	/* Prepare nodename */
#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	if (ha->node_name_set) {
		memcpy(icb->node_name, ha->tgt_node_name, WWN_SIZE);
		icb->firmware_options_1 |= __constant_cpu_to_le32(BIT_14);
	} else
#endif
		if (nv->host_p & __constant_cpu_to_le32(BIT_15)) {
			/* Use alternate WWN? */
			memcpy(icb->node_name, nv->alternate_node_name, WWN_SIZE);
			memcpy(icb->port_name, nv->alternate_port_name, WWN_SIZE);
		}

	if ((icb->firmware_options_1 & __constant_cpu_to_le32(BIT_14)) == 0) {
		/*
		 * Firmware will apply the following mask if the nodename was
		 * not provided.
		 */
		memcpy(icb->node_name, icb->port_name, WWN_SIZE);
		icb->node_name[0] &= 0xF0;
	}

	/* Set host adapter parameters. */
	ha->flags.disable_risc_code_load = 0;
	ha->flags.enable_lip_reset = 0;
	ha->flags.enable_lip_full_login =
	    le32_to_cpu(nv->host_p) & BIT_10 ? 1: 0;
	ha->flags.enable_target_reset =
	    le32_to_cpu(nv->host_p) & BIT_11 ? 1: 0;
	ha->flags.enable_led_scheme = 0;
	ha->flags.disable_serdes = le32_to_cpu(nv->host_p) & BIT_5 ? 1: 0;

	ha->operating_mode = (le32_to_cpu(icb->firmware_options_2) &
	    (BIT_6 | BIT_5 | BIT_4)) >> 4;

	memcpy(ha->fw_seriallink_options24, nv->seriallink_options,
	    sizeof(ha->fw_seriallink_options24));

	/* save HBA serial number */
	ha->serial0 = icb->port_name[5];
	ha->serial1 = icb->port_name[6];
	ha->serial2 = icb->port_name[7];
	ha->node_name = icb->node_name;
	ha->port_name = icb->port_name;

	icb->execution_throttle = __constant_cpu_to_le16(0xFFFF);

	ha->retry_count = le16_to_cpu(nv->login_retry_count);

	/* Set minimum login_timeout to 4 seconds. */
	if (le16_to_cpu(nv->login_timeout) < ql2xlogintimeout)
		nv->login_timeout = cpu_to_le16(ql2xlogintimeout);
	if (le16_to_cpu(nv->login_timeout) < 4)
		nv->login_timeout = __constant_cpu_to_le16(4);
	ha->login_timeout = le16_to_cpu(nv->login_timeout);
	icb->login_timeout = nv->login_timeout;

	/* Set minimum RATOV to 100 tenths of a second. */
	ha->r_a_tov = 100;

	ha->loop_reset_delay = nv->reset_delay;

	/* Link Down Timeout = 0:
	 *
	 * 	When Port Down timer expires we will start returning
	 *	I/O's to OS with "DID_NO_CONNECT".
	 *
	 * Link Down Timeout != 0:
	 *
	 *	 The driver waits for the link to come up after link down
	 *	 before returning I/Os to OS with "DID_NO_CONNECT".
	 */
	if (le16_to_cpu(nv->link_down_timeout) == 0) {
		ha->loop_down_abort_time =
		    (LOOP_DOWN_TIME - LOOP_DOWN_TIMEOUT);
	} else {
		ha->link_down_timeout =	le16_to_cpu(nv->link_down_timeout);
		ha->loop_down_abort_time =
		    (LOOP_DOWN_TIME - ha->link_down_timeout);
	}

	/* Need enough time to try and get the port back. */
	ha->port_down_retry_count = le16_to_cpu(nv->port_down_retry_count);
	if (qlport_down_retry)
		ha->port_down_retry_count = qlport_down_retry;

	/* Set login_retry_count */
	ha->login_retry_count  = le16_to_cpu(nv->login_retry_count);
	if (ha->port_down_retry_count ==
	    le16_to_cpu(nv->port_down_retry_count) &&
	    ha->port_down_retry_count > 3)
		ha->login_retry_count = ha->port_down_retry_count;
	else if (ha->port_down_retry_count > (int)ha->login_retry_count)
		ha->login_retry_count = ha->port_down_retry_count;
	if (ql2xloginretrycount)
		ha->login_retry_count = ql2xloginretrycount;

	/* Enable ZIO. */
	if (!ha->flags.init_done) {
		ha->zio_mode = le32_to_cpu(icb->firmware_options_2) &
		    (BIT_3 | BIT_2 | BIT_1 | BIT_0);
		ha->zio_timer = le16_to_cpu(icb->interrupt_delay_timer) ?
		    le16_to_cpu(icb->interrupt_delay_timer): 2;
	}
	icb->firmware_options_2 &= __constant_cpu_to_le32(
	    ~(BIT_3 | BIT_2 | BIT_1 | BIT_0));
	ha->flags.process_response_queue = 0;
	if (ha->zio_mode != QLA_ZIO_DISABLED) {
		ha->zio_mode = QLA_ZIO_MODE_6;

		DEBUG2(printk("scsi(%ld): ZIO mode %d enabled; timer delay "
		    "(%d us).\n", ha->host_no, ha->zio_mode,
		    ha->zio_timer * 100));
		qla_printk(KERN_INFO, ha,
		    "ZIO mode %d enabled; timer delay (%d us).\n",
		    ha->zio_mode, ha->zio_timer * 100);

		icb->firmware_options_2 |= cpu_to_le32(
		    (uint32_t)ha->zio_mode);
		icb->interrupt_delay_timer = cpu_to_le16(ha->zio_timer);
		ha->flags.process_response_queue = 1;
	}

	if (rval) {
		DEBUG2_3(printk(KERN_WARNING
		    "scsi(%ld): NVRAM configuration failed!\n", ha->host_no));
	}
	return (rval);
}

static int
qla24xx_load_risc_flash(scsi_qla_host_t *ha, uint32_t *srisc_addr)
{
	int	rval;
	int	segments, fragment;
	uint32_t faddr;
	uint32_t *dcode, dlen;
	uint32_t risc_addr;
	uint32_t risc_size;
	uint32_t i;

	rval = QLA_SUCCESS;

	segments = FA_RISC_CODE_SEGMENTS;
	faddr = FA_RISC_CODE_ADDR;
	dcode = (uint32_t *)ha->request_ring;
	*srisc_addr = 0;

	/* Validate firmware image by checking version. */
	qla24xx_read_flash_data(ha, dcode, faddr + 4, 4);
	for (i = 0; i < 4; i++)
		dcode[i] = be32_to_cpu(dcode[i]);
	if ((dcode[0] == 0xffffffff && dcode[1] == 0xffffffff &&
	    dcode[2] == 0xffffffff && dcode[3] == 0xffffffff) ||
	    (dcode[0] == 0 && dcode[1] == 0 && dcode[2] == 0 &&
		dcode[3] == 0)) {
		qla_printk(KERN_WARNING, ha,
		    "Unable to verify integrity of flash firmware image!\n");
		qla_printk(KERN_WARNING, ha,
		    "Firmware data: %08x %08x %08x %08x!\n", dcode[0],
		    dcode[1], dcode[2], dcode[3]);

		return QLA_FUNCTION_FAILED;
	}

	while (segments && rval == QLA_SUCCESS) {
		/* Read segment's load information. */
		qla24xx_read_flash_data(ha, dcode, faddr, 4);

		risc_addr = be32_to_cpu(dcode[2]);
		*srisc_addr = *srisc_addr == 0 ? risc_addr : *srisc_addr;
		risc_size = be32_to_cpu(dcode[3]);

		fragment = 0;
		while (risc_size > 0 && rval == QLA_SUCCESS) {
			dlen = (uint32_t)(ha->fw_transfer_size >> 2);
			if (dlen > risc_size)
				dlen = risc_size;

			DEBUG7(printk("scsi(%ld): Loading risc segment@ risc "
			    "addr %x, number of dwords 0x%x, offset 0x%x.\n",
			    ha->host_no, risc_addr, dlen, faddr));

			qla24xx_read_flash_data(ha, dcode, faddr, dlen);
			for (i = 0; i < dlen; i++)
				dcode[i] = swab32(dcode[i]);

			rval = qla2x00_load_ram(ha, ha->request_dma, risc_addr,
			    dlen);
			if (rval) {
				DEBUG(printk("scsi(%ld):[ERROR] Failed to load "
				    "segment %d of firmware\n", ha->host_no,
				    fragment));
				qla_printk(KERN_WARNING, ha,
				    "[ERROR] Failed to load segment %d of "
				    "firmware\n", fragment);
				break;
			}

			faddr += dlen;
			risc_addr += dlen;
			risc_size -= dlen;
			fragment++;
		}

		/* Next segment. */
		segments--;
	}

	return rval;
}

#define QLA_FW_URL "http://ldriver.qlogic.com/firmware/"

int
qla2x00_load_risc(scsi_qla_host_t *ha, uint32_t *srisc_addr)
{
	int	rval;
	int	i, fragment;
	uint16_t *wcode, *fwcode;
	uint32_t risc_addr, risc_size, fwclen, wlen, *seg;
	struct fw_blob *blob;

	/* Load firmware blob. */
	blob = qla2x00_request_firmware(ha);
	if (!blob) {
		qla_printk(KERN_ERR, ha, "Firmware image unavailable.\n");
		qla_printk(KERN_ERR, ha, "Firmware images can be retrieved "
		    "from: " QLA_FW_URL ".\n");
		return QLA_FUNCTION_FAILED;
	}

	rval = QLA_SUCCESS;

	wcode = (uint16_t *)ha->request_ring;
	*srisc_addr = 0;
	fwcode = (uint16_t *)blob->fw->data;
	fwclen = 0;

	/* Validate firmware image by checking version. */
	if (blob->fw->size < 8 * sizeof(uint16_t)) {
		qla_printk(KERN_WARNING, ha,
		    "Unable to verify integrity of firmware image (%Zd)!\n",
		    blob->fw->size);
		goto fail_fw_integrity;
	}
	for (i = 0; i < 4; i++)
		wcode[i] = be16_to_cpu(fwcode[i + 4]);
	if ((wcode[0] == 0xffff && wcode[1] == 0xffff && wcode[2] == 0xffff &&
	    wcode[3] == 0xffff) || (wcode[0] == 0 && wcode[1] == 0 &&
		wcode[2] == 0 && wcode[3] == 0)) {
		qla_printk(KERN_WARNING, ha,
		    "Unable to verify integrity of firmware image!\n");
		qla_printk(KERN_WARNING, ha,
		    "Firmware data: %04x %04x %04x %04x!\n", wcode[0],
		    wcode[1], wcode[2], wcode[3]);
		goto fail_fw_integrity;
	}

	seg = blob->segs;
	while (*seg && rval == QLA_SUCCESS) {
		risc_addr = *seg;
		*srisc_addr = *srisc_addr == 0 ? *seg : *srisc_addr;
		risc_size = be16_to_cpu(fwcode[3]);

		/* Validate firmware image size. */
		fwclen += risc_size * sizeof(uint16_t);
		if (blob->fw->size < fwclen) {
			qla_printk(KERN_WARNING, ha,
			    "Unable to verify integrity of firmware image "
			    "(%Zd)!\n", blob->fw->size);
			goto fail_fw_integrity;
		}

		fragment = 0;
		while (risc_size > 0 && rval == QLA_SUCCESS) {
			wlen = (uint16_t)(ha->fw_transfer_size >> 1);
			if (wlen > risc_size)
				wlen = risc_size;

			DEBUG7(printk("scsi(%ld): Loading risc segment@ risc "
			    "addr %x, number of words 0x%x.\n", ha->host_no,
			    risc_addr, wlen));

			for (i = 0; i < wlen; i++)
				wcode[i] = swab16(fwcode[i]);

			rval = qla2x00_load_ram(ha, ha->request_dma, risc_addr,
			    wlen);
			if (rval) {
				DEBUG(printk("scsi(%ld):[ERROR] Failed to load "
				    "segment %d of firmware\n", ha->host_no,
				    fragment));
				qla_printk(KERN_WARNING, ha,
				    "[ERROR] Failed to load segment %d of "
				    "firmware\n", fragment);
				break;
			}

			fwcode += wlen;
			risc_addr += wlen;
			risc_size -= wlen;
			fragment++;
		}

		/* Next segment. */
		seg++;
	}
	return rval;

fail_fw_integrity:
	return QLA_FUNCTION_FAILED;
}

#ifdef CONFIG_SCSI_QLA2XXX_TARGET

/*
 * qla2x00_enable_tgt_mode - NO LOCK HELD
 *
 * host_reset, bring up w/ Target Mode Enabled
 */
void
qla2x00_enable_tgt_mode(scsi_qla_host_t *ha)
{
	unsigned long flags;
	scsi_qla_host_t *pha = to_qla_parent(ha);

	spin_lock_irqsave(&pha->hardware_lock, flags);
	qla_set_tgt_mode(ha);
	spin_unlock_irqrestore(&pha->hardware_lock, flags);

	if (ha->parent)
		ha = ha->parent;

	set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
	qla2xxx_wake_dpc(ha);
	qla2x00_wait_for_hba_online(ha);
}
EXPORT_SYMBOL(qla2x00_enable_tgt_mode);

/*
 * qla2x00_disable_tgt_mode - NO LOCK HELD
 *
 * Disable Target Mode and reset the adapter
 */
void
qla2x00_disable_tgt_mode(scsi_qla_host_t *ha)
{
	unsigned long flags;
	scsi_qla_host_t *vha = to_qla_parent(ha);

	spin_lock_irqsave(&vha->hardware_lock, flags);
	qla_clear_tgt_mode(ha);
	spin_unlock_irqrestore(&vha->hardware_lock, flags);

	set_bit(ISP_ABORT_NEEDED, &vha->dpc_flags);
	qla2xxx_wake_dpc(vha);
	qla2x00_wait_for_hba_online(vha);
}
EXPORT_SYMBOL(qla2x00_disable_tgt_mode);

/*
 * qla2x00_issue_marker
 *	Issue marker
 *	Caller CAN have hardware lock held as specified by ha_locked parameter.
 *	Might release it, then reacquire.
 */
int qla2x00_issue_marker(scsi_qla_host_t *ha, int ha_locked)
{
	if (ha_locked) {
		if (__qla2x00_marker(ha, 0, 0, MK_SYNC_ALL) !=
		    QLA_SUCCESS)
			return QLA_FUNCTION_FAILED;
	} else {
		if (qla2x00_marker(ha, 0, 0, MK_SYNC_ALL) !=
		    QLA_SUCCESS)
			return QLA_FUNCTION_FAILED;
	}
	ha->marker_needed = 0;
	return QLA_SUCCESS;
}
EXPORT_SYMBOL(qla2x00_issue_marker);

int qla2xxx_tgt_register_driver(struct qla_tgt_data *tgt_data)
{
	int res = 0;

	ENTER(__func__);

	if (tgt_data == NULL) {
		printk(KERN_ERR "***ERROR*** Wrong version of the target mode "
			"add-on: tgt_data == NULL\n");
		res = -EINVAL;
		goto out;
	} else if (tgt_data->magic != QLA2X_TARGET_MAGIC) {
		printk(KERN_ERR "***ERROR*** Wrong version of the target mode "
			"add-on: %d\n", tgt_data->magic);
		res = -EINVAL;
		goto out;
	}

	memcpy(&qla_target, tgt_data, sizeof(qla_target));

	res = QLA2X_INITIATOR_MAGIC;

out:
	LEAVE(__func__);
	return res;
}
EXPORT_SYMBOL_GPL(qla2xxx_tgt_register_driver);

void qla2xxx_tgt_unregister_driver(void)
{
	ENTER(__func__);
	memset(&qla_target, 0, sizeof(qla_target));
	LEAVE(__func__);
	return;
}
EXPORT_SYMBOL_GPL(qla2xxx_tgt_unregister_driver);

#endif /* CONFIG_SCSI_QLA2XXX_TARGET */

int
qla24xx_load_risc(scsi_qla_host_t *ha, uint32_t *srisc_addr)
{
	int	rval;
	int	segments, fragment;
	uint32_t *dcode, dlen;
	uint32_t risc_addr;
	uint32_t risc_size;
	uint32_t i;
	struct fw_blob *blob;
	uint32_t *fwcode, fwclen;

	/* Load firmware blob. */
	blob = qla2x00_request_firmware(ha);
	if (!blob) {
		qla_printk(KERN_ERR, ha, "Firmware image unavailable.\n");
		qla_printk(KERN_ERR, ha, "Firmware images can be retrieved "
		    "from: " QLA_FW_URL ".\n");

		/* Try to load RISC code from flash. */
		qla_printk(KERN_ERR, ha, "Attempting to load (potentially "
		    "outdated) firmware from flash.\n");
		return qla24xx_load_risc_flash(ha, srisc_addr);
	}

	rval = QLA_SUCCESS;

	segments = FA_RISC_CODE_SEGMENTS;
	dcode = (uint32_t *)ha->request_ring;
	*srisc_addr = 0;
	fwcode = (uint32_t *)blob->fw->data;
	fwclen = 0;

	/* Validate firmware image by checking version. */
	if (blob->fw->size < 8 * sizeof(uint32_t)) {
		qla_printk(KERN_WARNING, ha,
		    "Unable to verify integrity of firmware image (%Zd)!\n",
		    blob->fw->size);
		goto fail_fw_integrity;
	}
	for (i = 0; i < 4; i++)
		dcode[i] = be32_to_cpu(fwcode[i + 4]);
	if ((dcode[0] == 0xffffffff && dcode[1] == 0xffffffff &&
	    dcode[2] == 0xffffffff && dcode[3] == 0xffffffff) ||
	    (dcode[0] == 0 && dcode[1] == 0 && dcode[2] == 0 &&
		dcode[3] == 0)) {
		qla_printk(KERN_WARNING, ha,
		    "Unable to verify integrity of firmware image!\n");
		qla_printk(KERN_WARNING, ha,
		    "Firmware data: %08x %08x %08x %08x!\n", dcode[0],
		    dcode[1], dcode[2], dcode[3]);
		goto fail_fw_integrity;
	}

	while (segments && rval == QLA_SUCCESS) {
		risc_addr = be32_to_cpu(fwcode[2]);
		*srisc_addr = *srisc_addr == 0 ? risc_addr : *srisc_addr;
		risc_size = be32_to_cpu(fwcode[3]);

		/* Validate firmware image size. */
		fwclen += risc_size * sizeof(uint32_t);
		if (blob->fw->size < fwclen) {
			qla_printk(KERN_WARNING, ha,
			    "Unable to verify integrity of firmware image "
			    "(%Zd)!\n", blob->fw->size);

			goto fail_fw_integrity;
		}

		fragment = 0;
		while (risc_size > 0 && rval == QLA_SUCCESS) {
			dlen = (uint32_t)(ha->fw_transfer_size >> 2);
			if (dlen > risc_size)
				dlen = risc_size;

			DEBUG7(printk("scsi(%ld): Loading risc segment@ risc "
			    "addr %x, number of dwords 0x%x.\n", ha->host_no,
			    risc_addr, dlen));

			for (i = 0; i < dlen; i++)
				dcode[i] = swab32(fwcode[i]);

			rval = qla2x00_load_ram(ha, ha->request_dma, risc_addr,
			    dlen);
			if (rval) {
				DEBUG(printk("scsi(%ld):[ERROR] Failed to load "
				    "segment %d of firmware\n", ha->host_no,
				    fragment));
				qla_printk(KERN_WARNING, ha,
				    "[ERROR] Failed to load segment %d of "
				    "firmware\n", fragment);
				break;
			}

			fwcode += dlen;
			risc_addr += dlen;
			risc_size -= dlen;
			fragment++;
		}

		/* Next segment. */
		segments--;
	}
	return rval;

fail_fw_integrity:
	return QLA_FUNCTION_FAILED;
}

void
qla2x00_try_to_stop_firmware(scsi_qla_host_t *ha)
{
	int ret, retries;

	if (!IS_FWI2_CAPABLE(ha))
		return;
	if (!ha->fw_major_version)
		return;

	ret = qla2x00_stop_firmware(ha);
	for (retries = 5; ret != QLA_SUCCESS && ret != QLA_FUNCTION_TIMEOUT &&
	    retries ; retries--) {
		qla2x00_reset_chip(ha);
		if (qla2x00_chip_diag(ha) != QLA_SUCCESS)
			continue;
		if (qla2x00_setup_chip(ha) != QLA_SUCCESS)
			continue;
		qla_printk(KERN_INFO, ha,
		    "Attempting retry of stop-firmware command...\n");
		ret = qla2x00_stop_firmware(ha);
	}
}

int
qla24xx_configure_vhba(scsi_qla_host_t *ha)
{
	int rval = QLA_SUCCESS;
	uint16_t mb[MAILBOX_REGISTER_COUNT];

	if (!ha->parent)
		return -EINVAL;

	rval = qla2x00_fw_ready(ha->parent);
	if (rval == QLA_SUCCESS) {
		clear_bit(RESET_MARKER_NEEDED, &ha->dpc_flags);
		qla2x00_marker(ha->parent, 0, 0, MK_SYNC_ALL);
	}

	ha->flags.management_server_logged_in = 0;

	/* Login to SNS first */
	qla24xx_login_fabric(ha->parent, NPH_SNS, 0xff, 0xff, 0xfc,
	    mb, BIT_1);
	if (mb[0] != MBS_COMMAND_COMPLETE) {
		DEBUG15(qla_printk(KERN_INFO, ha,
		    "Failed SNS login: loop_id=%x mb[0]=%x mb[1]=%x "
		    "mb[2]=%x mb[6]=%x mb[7]=%x\n", NPH_SNS,
		    mb[0], mb[1], mb[2], mb[6], mb[7]));
		return (QLA_FUNCTION_FAILED);
	}

	atomic_set(&ha->loop_down_timer, 0);
	atomic_set(&ha->loop_state, LOOP_UP);
	set_bit(LOOP_RESYNC_NEEDED, &ha->dpc_flags);
	set_bit(LOCAL_LOOP_UPDATE, &ha->dpc_flags);
	rval = qla2x00_loop_resync(ha->parent);

	return rval;
}

/* 84XX Support **************************************************************/

static LIST_HEAD(qla_cs84xx_list);
static DEFINE_MUTEX(qla_cs84xx_mutex);

static struct qla_chip_state_84xx *
qla84xx_get_chip(struct scsi_qla_host *ha)
{
	struct qla_chip_state_84xx *cs84xx;

	mutex_lock(&qla_cs84xx_mutex);

	/* Find any shared 84xx chip. */
	list_for_each_entry(cs84xx, &qla_cs84xx_list, list) {
		if (cs84xx->bus == ha->pdev->bus) {
			kref_get(&cs84xx->kref);
			goto done;
		}
	}

	cs84xx = kzalloc(sizeof(*cs84xx), GFP_KERNEL);
	if (!cs84xx)
		goto done;

	kref_init(&cs84xx->kref);
	spin_lock_init(&cs84xx->access_lock);
	mutex_init(&cs84xx->fw_update_mutex);
	cs84xx->bus = ha->pdev->bus;

	list_add_tail(&cs84xx->list, &qla_cs84xx_list);
done:
	mutex_unlock(&qla_cs84xx_mutex);
	return cs84xx;
}

static void
__qla84xx_chip_release(struct kref *kref)
{
	struct qla_chip_state_84xx *cs84xx =
	    container_of(kref, struct qla_chip_state_84xx, kref);

	mutex_lock(&qla_cs84xx_mutex);
	list_del(&cs84xx->list);
	mutex_unlock(&qla_cs84xx_mutex);
	kfree(cs84xx);
}

void
qla84xx_put_chip(struct scsi_qla_host *ha)
{
	if (ha->cs84xx)
		kref_put(&ha->cs84xx->kref, __qla84xx_chip_release);
}

static int
qla84xx_init_chip(scsi_qla_host_t *ha)
{
	int rval;
	uint16_t status[2];

	mutex_lock(&ha->cs84xx->fw_update_mutex);

	rval = qla84xx_verify_chip(ha, status);

	mutex_unlock(&ha->cs84xx->fw_update_mutex);

	return rval != QLA_SUCCESS || status[0] ? QLA_FUNCTION_FAILED:
	    QLA_SUCCESS;
}
