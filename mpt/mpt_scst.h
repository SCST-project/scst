#ifndef __MPT_SCST_H
#define __MPT_SCST_H

#if defined(MODULE) && !defined(__GENKSYMS__)
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19))
#include <linux/config.h>
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)
#include <linux/autoconf.h>
#else
#include <generated/autoconf.h>
#endif
#include <linux/module.h>
#endif

#ifdef __linux__
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/highmem.h>
#include <linux/version.h>
#include <scsi/scsi_device.h>

#include <linux/uaccess.h>
#include <linux/io.h>
#include <asm/div64.h>
#endif

#define _HS_SLEEP ,0
#define _IOC_ID ioc
#define _HANDLE_IOC_ID ioc

#ifndef MPT_STM_64_BIT_DMA  /* determines the size of DMA addresses */
#define MPT_STM_64_BIT_DMA 1
#endif

#include "../drivers/message/fusion/mptbase.h"

#ifndef MPI_IOCLOGINFO_FC_LINK_ALREADY_INITIALIZED
#define MPI_IOCLOGINFO_FC_LINK_ALREADY_INITIALIZED 0x24000002
#endif

#define MF_TO_INDEX(mf) le16_to_cpu(mf->u.frame.hwhdr.msgctxu.fld.req_idx)

#include "scsi3.h"

/*****************************************************************************/
#ifdef MPI_STM_IO_DEBUG
#define dioprintk printk
#else
#define dioprintk printk
#endif

typedef MPI_TARGET_FCP_CMD_BUFFER FCP_CMD;

typedef MPI_TARGET_SCSI_SPI_CMD_BUFFER SCSI_CMD;

#define SSP_CMD_FRAME		0x06
#define	SSP_TASK_FRAME		0x16

typedef MPI_TARGET_SSP_CMD_BUFFER SSP_CMD;
typedef MPI_TARGET_SSP_TASK_BUFFER SSP_TASK;

#define FCP_REQUEST_CONFIRM	(1<<4)
#define FCP_RESID_UNDER		(1<<3)
#define FCP_RESID_OVER		(1<<2)
#define FCP_SENSE_LEN_VALID	(1<<1)
#define FCP_RSP_LEN_VALID	(1<<0)

typedef struct _FCP_RSP { /*this struct is wrong in rev 1.02.04 of mpi_targ.h*/
	U8      Reserved0[8];                               /* 00h */
	U8      Reserved1[2];                               /* 08h */
	U8      FcpFlags;                                   /* 0Ah */
	U8      FcpStatus;                                  /* 0Bh */
	U32     FcpResid;                                   /* 0Ch */
	U32     FcpSenseLength;                             /* 10h */
	U32     FcpResponseLength;                          /* 14h */
	U8      FcpResponseData[8];                         /* 18h */
	U8      FcpSenseData[32]; /* Pad to 64 bytes */     /* 20h */
} FCP_RSP;

#define SCSI_SENSE_LEN_VALID	(1<<1)
#define SCSI_RSP_LEN_VALID	(1<<0)

typedef MPI_TARGET_SCSI_SPI_STATUS_IU SCSI_RSP;

#define SSP_SENSE_LEN_VALID	(1<<1)
#define SSP_RSP_LEN_VALID	(1<<0)

typedef MPI_TARGET_SSP_RSP_IU SSP_RSP;


/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/

/*
 *  Fusion MPT STM private structures
 */

#define IsFc(priv)      \
	(priv->ioc->pfacts[0].PortType == MPI_PORTFACTS_PORTTYPE_FC)
#define IsScsi(priv)    \
	(priv->ioc->pfacts[0].PortType == MPI_PORTFACTS_PORTTYPE_SCSI)
#define IsSas(priv)    \
	(priv->ioc->pfacts[0].PortType == MPI_PORTFACTS_PORTTYPE_SAS)

#define ABORT_ALL		(-1)

#define NUM_CMD_BUFFERS		128
#define NUM_ELS_BUFFERS		64

#define NUM_ALIASES		0  /* 0 to 125, hardware restriction */

#define ELS			0x22
#define FC4LS			0x32
#define ABTS			0x81
#define BA_ACC			0x84

#define LS_RJT			0x01
#define LS_ACC			0x02
#define PLOGI			0x03
#define LOGO			0x05
#define SRR			0x14
#define PRLI			0x20
#define PRLO			0x21
#define ADISC			0x52
#define RSCN			0x61

typedef struct _MPT_SGE {
	u32			length;
#if MPT_STM_64_BIT_DMA
	u64			address;
#else
	u32			address;
#endif
} MPT_SGE;

#define NUM_SGES	64
#define NUM_CHAINS	(NUM_SGES/8)	/* one chain for every 8 SGEs */

typedef struct _CMD {
	u8			cmd[64];
	u8			rsp[64];
	MPT_SGE		chain_sge[NUM_SGES+NUM_CHAINS];
	u32			reply_word;
	int			alias;
	int			lun;
	int			tag;
} CMD;

typedef struct _FC_ELS {
	u32			fc_els[32];
} FC_ELS;

typedef struct _MPT_STM_HW {
	CMD			cmd_buf[NUM_CMD_BUFFERS];
	FC_ELS		fc_link_serv_buf[NUM_ELS_BUFFERS];
	u32			config_buf[256];
	u32			ctsend_buf[256];
	u32			exlink_buf[32];
} MPT_STM_HW;

typedef struct _MPT_SGL {
	u32			num_sges;
	MPT_SGE		sge[NUM_SGES];
} MPT_SGL;

typedef struct _MPT_STM_PRIV {
	MPT_ADAPTER		*ioc;
	int			enable_target_mode;
	int			fcp2_capable;
	int			num_sge_chain;
	int			num_sge_target_assist;
	int			num_cmd_buffers;
	int			num_els_buffers;
	int			num_aliases;
	MPT_STM_HW		*hw;
	dma_addr_t		hw_dma;
	U64			wwnn;
	U64			wwpn;
	int			port_id;
	int			scsi_port_config;
	int			scsi_id_config;
	int			protocol;
	volatile int	port_flags;
	volatile int	port_speed;
	volatile int	port_state;
	volatile int	device_changed;
	int			port_enable_loginfo;
	volatile int	port_enable_pending;
	volatile int	target_mode_abort_pending;
	volatile int	link_serv_abort_pending;
	volatile int	fc_primitive_send_pending;
	volatile int	ex_link_service_send_pending;
	volatile int	config_pending;
	volatile int	in_reset;
	volatile int	poll_enabled;
	volatile int	exiting;
	MPT_FRAME_HDR	*config_mf;
	ConfigReply_t	config_rep;
	volatile int	io_state[NUM_CMD_BUFFERS];
	volatile int	els_state[NUM_ELS_BUFFERS];
	MPT_FRAME_HDR	*current_mf[NUM_CMD_BUFFERS];
	MPT_FRAME_HDR	*status_deferred_mf[NUM_CMD_BUFFERS];
	MPT_SGL		sgl;
	SCSIPortPage0_t SCSIPortPage0;
	SCSIPortPage1_t SCSIPortPage1;
	SCSIPortPage2_t SCSIPortPage2;
#define NUM_SCSI_DEVICES       16
	SCSIDevicePage1_t SCSIDevicePage1[NUM_SCSI_DEVICES];
	struct mpt_tgt *tgt;
	struct scst_cmd *scst_cmd[NUM_CMD_BUFFERS];
	atomic_t pending_sense[NUM_SCSI_DEVICES];
	u8 pending_sense_buffer[NUM_SCSI_DEVICES][SCSI_SENSE_BUFFERSIZE];
} MPT_STM_PRIV;

#define IO_STATE_POSTED			0x1
#define IO_STATE_DATA_SENT		0x2
#define IO_STATE_STATUS_SENT		0x4
#define IO_STATE_STATUS_DEFERRED	0x8
#define IO_STATE_INCOMPLETE		0x10
#define IO_STATE_AUTO_REPOST		0x20
#define IO_STATE_ABORTED		0x40
#define IO_STATE_HIGH_PRIORITY		0x80
#define IO_STATE_REQUEST_ABORTED	0x100
#define IO_STATE_REISSUE_REQUEST	0x200
#define IO_STATE_ADJUST_OFFSET		0x400
#define IO_STATE_CONVERT_TA_TO_TSS	0x800
#define IO_STATE_REDO_COMMAND		0x1000

#define get2bytes(x, y) ((x[y] << 8) + x[y+1])
#define get3bytes(x, y) ((x[y] << 16) + (x[y+1] << 8) + x[y+2])
#define get4bytes(x, y) ((x[y] << 24) + (x[y+1] << 16) + (x[y+2] << 8) + x[y+3])
#define get8bytes(x, y) (((u64)get4bytes(x, y) << 32) + get4bytes(x, y+4))

#define InitiatorIndex_0100 Reserved_0100_InitiatorIndex
#define FWVersion_0101 Reserved_0101_FWVersion
#define EventDataSasPhyLinkStatus_t MpiEventDataSasPhyLinkStatus_t

#ifndef MPI_FCPORTPAGE1_FLAGS_FORCE_USE_NOSEEPROM_WWNS
#define MPI_FCPORTPAGE1_FLAGS_FORCE_USE_NOSEEPROM_WWNS  (0x02000000)
#endif

#ifndef PRIORITY_REASON_TARGET_BUSY
#define PRIORITY_REASON_TARGET_BUSY             (0x09)
#endif

#if MPT_STM_64_BIT_DMA
#define MPT_STM_SIMPLE SGESimple64_t
#define MPT_STM_CHAIN SGEChain64_t
#define MPI_SGE_FLAGS_MPT_STM_ADDRESSING MPI_SGE_FLAGS_64_BIT_ADDRESSING
#define stm_get_dma_addr(x, y)					\
	do {							\
		(x) = le32_to_cpu((y).Low);				\
		if (sizeof(dma_addr_t) == sizeof(u64))		\
			(x) |= (u64)le32_to_cpu((y).High)<<32;	\
	} while (0)
#define stm_set_dma_addr(x, y)					\
	do {							\
		(x).Low = cpu_to_le32((y));				\
		if (sizeof(dma_addr_t) == sizeof(u64))		\
			(x).High = cpu_to_le32((u64)(y)>>32);	\
		else						\
			(x).High = 0;				\
	} while (0)
#else
#define MPT_STM_SIMPLE SGESimple32_t
#define MPT_STM_CHAIN SGEChain32_t
#define MPI_SGE_FLAGS_MPT_STM_ADDRESSING MPI_SGE_FLAGS_32_BIT_ADDRESSING
#define stm_get_dma_addr(x, y) ((x) = le32_to_cpu((y)))
#define stm_set_dma_addr(x, y) ((x) = cpu_to_le32((y)))
#endif

#ifndef MPT_MAX_ADAPTERS
#define MPT_MAX_ADAPTERS 18
#endif

#ifndef MPI_MANUFACTPAGE_DEVICEID_FC949X
#define MPI_MANUFACTPAGE_DEVICEID_FC949X 0x640
#endif
#ifndef MPI_MANUFACTPAGE_DEVICEID_FC939X
#define MPI_MANUFACTPAGE_DEVICEID_FC939X 0x642
#endif

#ifndef MPI_IOCSTATUS_EEDP_GUARD_ERROR
#define MPI_IOCSTATUS_EEDP_GUARD_ERROR 0x4d
#endif
#ifndef MPI_IOCSTATUS_EEDP_REF_TAG_ERROR
#define MPI_IOCSTATUS_EEDP_REF_TAG_ERROR 0x4e
#endif
#ifndef MPI_IOCSTATUS_EEDP_APP_TAG_ERROR
#define MPI_IOCSTATUS_EEDP_APP_TAG_ERROR 0x4f
#endif

#define MPT_MAX_CDB_LEN 16
#define MPT_TIMEOUT 30

/* Immediate notify status constants */
#define IMM_NTFY_LIP_RESET          MPI_EVENT_LOOP_STATE_CHANGE
#define IMM_NTFY_IOCB_OVERFLOW      0x0016
#define IMM_NTFY_ABORT_TASK         0x0020
#define IMM_NTFY_PORT_LOGOUT        MPI_EVENT_LOGOUT
#define IMM_NTFY_PORT_CONFIG        MPI_EVENT_LINK_STATUS_CHANGE
#define IMM_NTFY_GLBL_TPRLO         MPI_EVENT_LINK_STATUS_CHANGE
#define IMM_NTFY_GLBL_LOGO          MPI_EVENT_LINK_STATUS_CHANGE
#define IMM_NTFY_RESOURCE           0x0034
#define IMM_NTFY_MSG_RX             0x0036

/* Immediate notify task flags */
#define IMM_NTFY_ABORT_TS1          0x01
#define IMM_NTFY_ABORT_TS2          0x02
#define IMM_NTFY_CLEAR_TS           0x04
#define IMM_NTFY_LUN_RESET1         0x08
#define IMM_NTFY_LUN_RESET2         0x10
#define IMM_NTFY_TARGET_RESET       0x20
#define IMM_NTFY_CLEAR_ACA          0x40

/* Command's states */
#define MPT_STATE_NEW              1    /* New command and SCST processes it */
#define MPT_STATE_NEED_DATA        2    /* SCST needs data to process */
#define MPT_STATE_DATA_IN          3    /* Data arrived and SCST processes it */
#define MPT_STATE_DATA_OUT         4
#define MPT_STATE_PROCESSED        5    /* SCST done processing */

/* Target's flags */
#define MPT_TGT_SHUTDOWN            0   /* The driver is being released */
#define MPT_TGT_ENABLE_64BIT_ADDR   1   /* 64-bits PCI addressing enabled */

/* Session's flags */
#define MPT_SESS_INITING            0   /* The session is being unregistered */
#define MPT_SESS_SHUTDOWN           1   /* The session is being unregistered */

/* pending sense states */
#define MPT_STATUS_SENSE_IDLE      0 /* no cached pending sense */
#define MPT_STATUS_SENSE_ATTEMPT   1 /* attempt to send status and sense */
#define MPT_STATUS_SENSE_NOT_SENT  2 /* sense couldn't be sent with status */
#define MPT_STATUS_SENSE_HANDLE_RQ 3 /* REQUEST SENSE handled with cached sense */

struct mpt_cmd {
	struct mpt_sess *sess;
	struct scst_cmd *scst_cmd;
	MPT_STM_PRIV *priv;
	CMD *CMD;
	u32 reply_word;
	struct list_head delayed_cmds_entry;
	int state;
	dma_addr_t dma_handle;
};

struct mpt_sess {
	struct scst_session *scst_sess;
	struct mpt_tgt *tgt;
	int init_index;
	unsigned long sess_flags;
	struct list_head delayed_cmds;
};

struct mpt_tgt {
	struct scst_tgt *scst_tgt;
	MPT_STM_PRIV *priv;
	int datasegs_per_cmd, datasegs_per_cont;
	unsigned long tgt_flags;
	atomic_t sess_count;
	wait_queue_head_t waitQ;
	struct mpt_sess *sess[256];
	int target_enable;
};

struct mpt_mgmt_cmd {
	struct mpt_sess *sess;
	int task_mgmt;
};

#endif
