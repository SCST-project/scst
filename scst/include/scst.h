/*
 *  include/scst.h
 *
 *  Copyright (C) 2004 - 2015 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 - 2015 SanDisk Corporation
 *  Copyright (C) 2010 - 2011 Bart Van Assche <bvanassche@acm.org>.
 *
 *  Main SCSI target mid-level include file.
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

#ifndef __SCST_H
#define __SCST_H

/** See README for description of those conditional defines **/
/* #define CONFIG_SCST_MEASURE_LATENCY */
/* #define CONFIG_SCST_DEBUG_TM */
/* #define CONFIG_SCST_TM_DBG_GO_OFFLINE */

/** See README for description of those conditional defines **/
#define CONFIG_SCST_DIF_INJECT_CORRUPTED_TAGS

#include <linux/types.h>
#ifndef INSIDE_KERNEL_TREE
#include <linux/version.h>
#endif
#include <linux/blkdev.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/cpumask.h>
#ifdef CONFIG_SCST_MEASURE_LATENCY
#include <linux/log2.h>
#endif
#include <asm/unaligned.h>

#if 0 /* Let's disable it for now to see if users will complain about it */
#define CONFIG_SCST_PER_DEVICE_CMD_COUNT_LIMIT
#endif

/* #define CONFIG_SCST_PROC */

#ifdef CONFIG_SCST_PROC
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#elif defined(RHEL_MAJOR) && RHEL_MAJOR -0 <= 5
#error The SCST sysfs interface is not supported on RHEL 5. Please run make enable_proc.
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
#error The SCST sysfs interface is supported from kernel version 2.6.26 on. Please run make enable_proc.
#endif

#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi.h>

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst_const.h>
#else
#include <scst_const.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
#define smp_mb__after_atomic_inc smp_mb__after_atomic
#define smp_mb__after_clear_bit smp_mb__after_atomic
#define smp_mb__before_atomic_dec smp_mb__before_atomic
#define smp_mb__after_atomic_dec smp_mb__after_atomic
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
#ifndef RHEL_RELEASE_CODE
typedef _Bool bool;
#endif
#define true  1
#define false 0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 21)
#ifndef __packed
#define __packed __attribute__((packed))
#endif
#ifndef __aligned
#define __aligned(x) __attribute__((aligned(x)))
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22)
char *kvasprintf(gfp_t gfp, const char *fmt, va_list ap);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
#define lockdep_assert_held(l) do { (void)(l); } while (0)
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)
#ifndef O_DSYNC
#define O_DSYNC O_SYNC
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
/*
 * See also patch "Move ACCESS_ONCE() to <linux/compiler.h>" (commit ID
 * 9c3cdc1f83a6e07092392ff4aba6466517dbd1d0).
 */
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#endif

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst_sgv.h>
#else
#include "scst_sgv.h"
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 20)
#ifndef __printf
#define __printf(a, b) __attribute__((format(printf,a,b)))
#endif
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 20) && !defined(BACKPORT_LINUX_CPUMASK_H)
#define nr_cpu_ids NR_CPUS
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
/*
 * See also patch "fix abuses of ptrdiff_t" (commit ID
 * 142956af525002c5378e7d91d81a01189841a785).
 */
typedef unsigned long uintptr_t;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
#define cpumask_bits(maskp) ((maskp)->bits)
#ifdef CONFIG_CPUMASK_OFFSTACK
/* Assuming NR_CPUS is huge, a runtime limit is more efficient.  Also,
 * not all bits may be allocated. */
#define nr_cpumask_bits nr_cpu_ids
#else
#define nr_cpumask_bits NR_CPUS
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26) && \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 6)
#define set_cpus_allowed_ptr(p, new_mask) set_cpus_allowed((p), *(new_mask))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
#ifndef swap
#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
static inline unsigned int queue_max_hw_sectors(struct request_queue *q)
{
	return q->max_hw_sectors;
}
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)
/*
 * See also patch "sched: Fix softirq time accounting" (commit ID
 * 75e1056f5c57050415b64cb761a3acc35d91f013).
 */
#ifndef in_serving_softirq
#define in_serving_softirq() in_softirq()
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 6 ||	\
	 RHEL_MAJOR -0 == 6 && RHEL_MINOR -0 < 1)
extern int hex_to_bin(char ch);
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
/*
 * See also patch "new helper: file_inode(file)" (commit ID
 * 496ad9aa8ef448058e36ca7a787c61f2e63f0f54).
 */
static inline struct inode *file_inode(const struct file *f)
{
	return f->f_path.dentry->d_inode;
}
#endif

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

#define SCST_INTERFACE_VERSION	    \
		SCST_VERSION_STRING SCST_INTF_VER SCST_CONST_VERSION

#define SCST_LOCAL_NAME			"scst_local"

/*************************************************************
 ** States of command processing state machine. At first,
 ** "active" states, then - "passive" ones. This is to have
 ** more efficient generated code of the corresponding
 ** "switch" statements.
 **
 ** !! Adding new states don't forget to update scst_cmd_state_name
 ** !! as well!
 *************************************************************/
enum {
	/** Active states **/

	/* Dev handler's parse() is going to be called */
	SCST_CMD_STATE_PARSE = 0,

	/* Allocation of the cmd's data buffer */
	SCST_CMD_STATE_PREPARE_SPACE,

	/* Calling preprocessing_done() */
	SCST_CMD_STATE_PREPROCESSING_DONE,

	/* Target driver's rdy_to_xfer() is going to be called */
	SCST_CMD_STATE_RDY_TO_XFER,

	/* Target driver's pre_exec() is going to be called */
	SCST_CMD_STATE_TGT_PRE_EXEC,

	/*
	 * Cmd is going to be sent for execution. The first stage of it is
	 * order checking
	 */
	SCST_CMD_STATE_EXEC_CHECK_SN,

	/* Internal post-exec checks */
	SCST_CMD_STATE_PRE_DEV_DONE,

	/* Internal MODE SELECT pages related checks */
	SCST_CMD_STATE_MODE_SELECT_CHECKS,

	/* Dev handler's dev_done() is going to be called */
	SCST_CMD_STATE_DEV_DONE,

	/* Checks before target driver's xmit_response() is called */
	SCST_CMD_STATE_PRE_XMIT_RESP,

	/* Checks 1 before target driver's xmit_response() is called */
	SCST_CMD_STATE_PRE_XMIT_RESP1,

	/* Checks 2 before target driver's xmit_response() is called */
	SCST_CMD_STATE_PRE_XMIT_RESP2,

	/* Target driver's xmit_response() is going to be called */
	SCST_CMD_STATE_XMIT_RESP,

	/* Cmd finished */
	SCST_CMD_STATE_FINISHED,

	/* Internal cmd finished */
	SCST_CMD_STATE_FINISHED_INTERNAL,

	SCST_CMD_STATE_LAST_ACTIVE = (SCST_CMD_STATE_FINISHED_INTERNAL+100),

	/** Passive states **/

	/* A cmd is created, but scst_cmd_init_done() not called */
	SCST_CMD_STATE_INIT_WAIT,

	/* LUN translation (cmd->tgt_dev assignment) */
	SCST_CMD_STATE_INIT,

	/* Waiting for scst_restart_cmd() */
	SCST_CMD_STATE_PREPROCESSING_DONE_CALLED,

	/* Waiting for data from the initiator (until scst_rx_data() called) */
	SCST_CMD_STATE_DATA_WAIT,

	/*
	 * Cmd is ready for exec (after check if its device is blocked or should
	 * be blocked)
	 */
	SCST_CMD_STATE_EXEC_CHECK_BLOCKING,

	/* Cmd is being checked if it should be executed locally */
	SCST_CMD_STATE_LOCAL_EXEC,

	/* Cmd is ready for execution */
	SCST_CMD_STATE_REAL_EXEC,

	/* Waiting for CDB's execution finish */
	SCST_CMD_STATE_EXEC_WAIT,

	/* Waiting for response's transmission finish */
	SCST_CMD_STATE_XMIT_WAIT,
};

/*************************************************************
 * Can be returned instead of cmd's state by dev handlers'
 * functions, if the command's state should be set by default
 *************************************************************/
#define SCST_CMD_STATE_DEFAULT        500

/*************************************************************
 * Can be returned instead of cmd's state by dev handlers'
 * functions, if it is impossible to complete requested
 * task in atomic context. The cmd will be restarted in thread
 * context.
 *************************************************************/
#define SCST_CMD_STATE_NEED_THREAD_CTX 1000

/*************************************************************
 * Can be returned instead of cmd's state by dev handlers'
 * parse function, if the cmd processing should be stopped
 * for now. The cmd will be restarted by dev handlers itself.
 *************************************************************/
#define SCST_CMD_STATE_STOP           1001

/*************************************************************
 ** States of mgmt command processing state machine
 **
 ** !! Adding new states don't forget to update
 ** !! scst_mcmd_state_name as well!
 *************************************************************/
enum {
	/* LUN translation (mcmd->tgt_dev assignment) */
	SCST_MCMD_STATE_INIT = 0,

	/* Mgmt cmd is being processed */
	SCST_MCMD_STATE_EXEC,

	/* Waiting for affected commands done */
	SCST_MCMD_STATE_WAITING_AFFECTED_CMDS_DONE,

	/* Post actions when affected commands done */
	SCST_MCMD_STATE_AFFECTED_CMDS_DONE,

	/* Waiting for affected local commands finished */
	SCST_MCMD_STATE_WAITING_AFFECTED_CMDS_FINISHED,

	/* Target driver's task_mgmt_fn_done() is going to be called */
	SCST_MCMD_STATE_DONE,

	/* The mcmd finished */
	SCST_MCMD_STATE_FINISHED,
};

/*************************************************************
 ** Constants for "atomic" parameter of SCST's functions
 *************************************************************/
#define SCST_NON_ATOMIC              0
#define SCST_ATOMIC                  1

/*************************************************************
 ** Values for pref_context parameter of scst_cmd_init_done(),
 ** scst_rx_data(), scst_restart_cmd(), scst_tgt_cmd_done()
 ** and scst_cmd_done()
 *************************************************************/

enum scst_exec_context {
	/*
	 * Direct cmd's processing (i.e. regular function calls in the current
	 * context) sleeping is not allowed
	 */
	SCST_CONTEXT_DIRECT_ATOMIC,

	/*
	 * Direct cmd's processing (i.e. regular function calls in the current
	 * context), sleeping is allowed, no restrictions
	 */
	SCST_CONTEXT_DIRECT,

	/* Tasklet or thread context required for cmd's processing */
	SCST_CONTEXT_TASKLET,

	/* Thread context required for cmd's processing */
	SCST_CONTEXT_THREAD,

	/*
	 * Context is the same as it was in previous call of the corresponding
	 * callback. For example, if dev handler's exec() does sync. data
	 * reading this value should be used for scst_cmd_done(). The same is
	 * true if scst_tgt_cmd_done() called directly from target driver's
	 * xmit_response(). Not allowed in scst_cmd_init_done() and
	 * scst_cmd_init_stage1_done().
	 */
	SCST_CONTEXT_SAME
};

/*************************************************************
 ** Values for status parameter of scst_rx_data()
 *************************************************************/

/* Success */
#define SCST_RX_STATUS_SUCCESS       0

/*
 * Data receiving finished with error, so set the sense and
 * finish the command, including xmit_response() call
 */
#define SCST_RX_STATUS_ERROR         1

/*
 * Data receiving finished with error and the sense is set,
 * so finish the command, including xmit_response() call
 */
#define SCST_RX_STATUS_ERROR_SENSE_SET 2

/*
 * Data receiving finished with fatal error, so finish the command,
 * but don't call xmit_response()
 */
#define SCST_RX_STATUS_ERROR_FATAL   3

/*************************************************************
 ** Values for status parameter of scst_restart_cmd()
 *************************************************************/

/* Success */
#define SCST_PREPROCESS_STATUS_SUCCESS       0

/*
 * Command's processing finished with error, so set the sense and
 * finish the command, including xmit_response() call
 */
#define SCST_PREPROCESS_STATUS_ERROR         1

/*
 * Command's processing finished with error and the sense is set,
 * so finish the command, including xmit_response() call
 */
#define SCST_PREPROCESS_STATUS_ERROR_SENSE_SET 2

/*
 * Command's processing finished with fatal error, so finish the command,
 * but don't call xmit_response()
 */
#define SCST_PREPROCESS_STATUS_ERROR_FATAL   3

/*************************************************************
 ** Values for AEN functions
 *************************************************************/

/*
 * SCSI Asynchronous Event. Parameter contains SCSI sense
 * (Unit Attention). AENs generated only for 2 the following UAs:
 * CAPACITY DATA HAS CHANGED and REPORTED LUNS DATA HAS CHANGED.
 * Other UAs reported regularly as CHECK CONDITION status,
 * because it doesn't look safe to report them using AENs, since
 * reporting using AENs opens delivery race windows even in case of
 * untagged commands.
 */
#define SCST_AEN_SCSI                0

/*
 * Notifies that CPU affinity mask on the corresponding session changed
 */
#define SCST_AEN_CPU_MASK_CHANGED    1

/*************************************************************
 ** Allowed return/status codes for report_aen() callback and
 ** scst_set_aen_delivery_status() function
 *************************************************************/

/* Success */
#define SCST_AEN_RES_SUCCESS         0

/* Not supported */
#define SCST_AEN_RES_NOT_SUPPORTED  -1

/* Failure */
#define SCST_AEN_RES_FAILED         -2

/*************************************************************
 ** Allowed return codes for xmit_response(), rdy_to_xfer()
 *************************************************************/

/* Success */
#define SCST_TGT_RES_SUCCESS         0

/* Internal device queue is full, retry again later */
#define SCST_TGT_RES_QUEUE_FULL      -1

/*
 * It is impossible to complete requested task in atomic context.
 * The cmd will be restarted in thread  context.
 */
#define SCST_TGT_RES_NEED_THREAD_CTX -2

/*
 * Fatal error, if returned by xmit_response() the cmd will
 * be destroyed, if by any other function, xmit_response()
 * will be called with READ or WRITE FAILED sense data
 */
#define SCST_TGT_RES_FATAL_ERROR     -3

/*************************************************************
 ** Return codes for dev handler's exec()
 *************************************************************/

/*
 * The cmd is completed, go to other ones. It doesn't necessary to be really
 * completed, it can still be being processed. This code means that SCST
 * core should start performing post processing actions for this cmd, like
 * increase SN and reactivate deferred commands, if allowed, and start
 * processing other commands.
 */
#define SCST_EXEC_COMPLETED          0

/* The cmd should continue staying on the EXEC phase */
#define SCST_EXEC_NOT_COMPLETED      1

/*************************************************************
 ** Session initialization phases
 *************************************************************/

/* Set if session is being initialized */
#define SCST_SESS_IPH_INITING        0

/* Set if the session is successfully initialized */
#define SCST_SESS_IPH_SUCCESS        1

/* Set if the session initialization failed */
#define SCST_SESS_IPH_FAILED         2

/* Set if session is initialized and ready */
#define SCST_SESS_IPH_READY          3

/*************************************************************
 ** Session shutdown phases
 *************************************************************/

/* Set if session is initialized and ready */
#define SCST_SESS_SPH_READY          0

/* Set if session is shutting down */
#define SCST_SESS_SPH_SHUTDOWN       1

/* Set if session is shutting down */
#define SCST_SESS_SPH_UNREG_DONE_CALLING 2

/*************************************************************
 ** Session's async (atomic) flags
 *************************************************************/

/* Set if the sess's hw pending work is scheduled */
#define SCST_SESS_HW_PENDING_WORK_SCHEDULED	0

/*************************************************************
 ** Cmd's async (atomic) flags
 *************************************************************/

/*
 * Set if the cmd is aborted and should be unconditionally finished
 * as soon as possible.
 *
 * !! Direct check of this bit must not be done anywhere outside of  !!
 * !! SCST core! Use the corresponding helper functions listed below !!
 * !! for that!							     !!
 */
#define SCST_CMD_ABORTED		0

/* Set if the cmd is aborted by other initiator */
#define SCST_CMD_ABORTED_OTHER		1

/*
 * Set if no response should be sent to the target about this cmd.
 * Must be set together with SCST_CMD_ABORTED for better processing
 * in scst_pre_xmit_response2().
 */
#define SCST_CMD_NO_RESP		2

/* Set if the cmd is dead and can be destroyed at any time */
#define SCST_CMD_CAN_BE_DESTROYED	3

/*
 * Set if the cmd's device has TAS flag set. Used only when aborted by
 * other initiator.
 */
#define SCST_CMD_DEVICE_TAS		4

#ifdef CONFIG_SCST_EXTRACHECKS
/* Set if scst_inc_expected_sn() passed for this cmd */
#define SCST_CMD_INC_EXPECTED_SN_PASSED	10
#endif

/*************************************************************
 ** Tgt_dev's async. flags (tgt_dev_flags)
 *************************************************************/

/* Set if tgt_dev has Unit Attention sense */
#define SCST_TGT_DEV_UA_PENDING		0

/* Cache of acg->acg_black_hole_type */
#define SCST_TGT_DEV_BLACK_HOLE		1

/* Cache of tgt->tgt_forwarding */
#define SCST_TGT_DEV_FORWARDING		5

/*************************************************************
 ** I/O grouping types. Changing them don't forget to change
 ** the corresponding *_STR values in scst_const.h!
 *************************************************************/

/*
 * All initiators with the same name connected to this group will have
 * shared IO context, for each name own context. All initiators with
 * different names will have own IO context.
 */
#define SCST_IO_GROUPING_AUTO			0

/* All initiators connected to this group will have shared IO context */
#define SCST_IO_GROUPING_THIS_GROUP_ONLY	-1

/* Each initiator connected to this group will have own IO context */
#define SCST_IO_GROUPING_NEVER			-2

#ifdef CONFIG_SCST_PROC

/*************************************************************
 ** Name of the entry in /proc
 *************************************************************/
#define SCST_PROC_ENTRY_NAME         "scsi_tgt"

#endif

/*************************************************************
 ** Kernel cache creation helper
 *************************************************************/
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22)
#define KMEM_CACHE(__struct, __flags) kmem_cache_create(#__struct,\
	sizeof(struct __struct), __alignof__(struct __struct),\
	(__flags), NULL, NULL)
#endif

/*************************************************************
 ** Valid_mask constants for scst_analyze_sense()
 *************************************************************/

#define SCST_SENSE_KEY_VALID		1
#define SCST_SENSE_ASC_VALID		2
#define SCST_SENSE_ASCQ_VALID		4

#define SCST_SENSE_ASCx_VALID		(SCST_SENSE_ASC_VALID | \
					 SCST_SENSE_ASCQ_VALID)

#define SCST_SENSE_ALL_VALID		(SCST_SENSE_KEY_VALID | \
					 SCST_SENSE_ASC_VALID | \
					 SCST_SENSE_ASCQ_VALID)

/*************************************************************
 ** T10-PI (DIF) support
 *************************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
struct t10_pi_tuple {
	__be16 guard_tag;
	__be16 app_tag;
	__be32 ref_tag;
};
#endif

/*
 * Defines where and how to deal with DIF tags. Can be OR'ed to get
 * multilevel checks
 */
enum scst_dif_mode {
	SCST_DIF_MODE_NONE = 0,

	/* STRIP/INSERT/CHECK inside target HW */
	SCST_DIF_MODE_TGT = 1,

	/* SCST checking or creating tags on the fly */
	SCST_DIF_MODE_SCST = 2,

	/* Backend device checking tags */
	SCST_DIF_MODE_DEV_CHECK = 4,

	/* Backend device storing tags, creating them on writes, if needed */
	SCST_DIF_MODE_DEV_STORE = 8,
};
#define SCST_DIF_MODE_DEV		(SCST_DIF_MODE_DEV_CHECK|SCST_DIF_MODE_DEV_STORE)

#define SCST_DIF_MODE_TGT_STR		"tgt"
#define SCST_DIF_MODE_SCST_STR		"scst"
#define SCST_DIF_MODE_DEV_CHECK_STR	"dev_check"
#define SCST_DIF_MODE_DEV_STORE_STR	"dev_store"

/*
 * T10-PI actions.
 *
 * Don't use masks and shifts directly! Use helper functions instead!
 */
enum scst_dif_actions {
	SCST_DIF_ACTION_NONE = 0, /* do nothing */

#define SCST_DIF_CHECKS_SHIFT	0
	/* OR'able tags to check */
	SCST_DIF_CHECK_GUARD_TAG = 1,
	SCST_DIF_CHECK_APP_TAG = 2,
	SCST_DIF_CHECK_REF_TAG = 4,
#define SCST_DIF_CHECKS_MASK	(SCST_DIF_CHECK_GUARD_TAG|SCST_DIF_CHECK_APP_TAG| \
			         SCST_DIF_CHECK_REF_TAG)

#define SCST_DIF_ACTION_SHIFT	4
	/* How to handle PI */
	SCST_DIF_ACTION_STRIP = (1 << SCST_DIF_ACTION_SHIFT), /* check then strip, if OK */
	SCST_DIF_ACTION_INSERT = (2 << SCST_DIF_ACTION_SHIFT),
	SCST_DIF_ACTION_PASS_CHECK = (3 << SCST_DIF_ACTION_SHIFT), /* check then pass, if OK */
	SCST_DIF_ACTION_PASS = (4 << SCST_DIF_ACTION_SHIFT), /* just pass, no check */

#define SCST_DIF_ACTION_MASK	(SCST_DIF_ACTION_STRIP|SCST_DIF_ACTION_INSERT| \
				 SCST_DIF_ACTION_PASS_CHECK|SCST_DIF_ACTION_PASS)
};

/* Shift for target driver DIF actions */
#define SCST_DIF_TGT_ACTION_SHIFT	0

/* Shift for SCST DIF actions */
#define SCST_DIF_SCST_ACTION_SHIFT	(SCST_DIF_TGT_ACTION_SHIFT+4)

/* Shift for dev handler DIF actions */
#define SCST_DIF_DEV_ACTION_SHIFT	(SCST_DIF_SCST_ACTION_SHIFT+4)

/* Returns DIF checks by stripping the action part from a */
static inline enum scst_dif_actions scst_get_dif_checks(enum scst_dif_actions a)
{
	return (a & SCST_DIF_CHECKS_MASK);
}

/* Sets the DIF checks part in a */
static inline void scst_set_dif_checks(enum scst_dif_actions *a,
	enum scst_dif_actions checks)
{
	checks &= ~SCST_DIF_CHECKS_MASK;
	*a |= checks << SCST_DIF_CHECKS_SHIFT;
	return;
}

/* Returns DIF action by stripping the checks part from a */
static inline enum scst_dif_actions scst_get_dif_action(enum scst_dif_actions a)
{
	return (a & SCST_DIF_ACTION_MASK);
}

/* Sets the DIF action part in a */
static inline void scst_set_dif_action(enum scst_dif_actions *a,
	enum scst_dif_actions action)
{
	action &= ~SCST_DIF_ACTION_MASK;
	*a |= action;
	return;
}

/* Returns TGT DIF actions from a, including checks */
static inline enum scst_dif_actions scst_get_tgt_dif_actions(enum scst_dif_actions a)
{
	BUILD_BUG_ON(SCST_DIF_CHECKS_SHIFT != 0);
	return ((a >> SCST_DIF_TGT_ACTION_SHIFT) & SCST_DIF_ACTION_MASK) |
	       (a & SCST_DIF_CHECKS_MASK);
}

/* Sets TGT DIF action in a. DIF checks in a are not affected by this function. */
static inline void scst_set_tgt_dif_action(enum scst_dif_actions *a,
	enum scst_dif_actions tgt_a)
{
	tgt_a &= SCST_DIF_ACTION_MASK;
	*a |= tgt_a << SCST_DIF_TGT_ACTION_SHIFT;
	return;
}

/* Returns SCST DIF actions from a, including checks */
static inline enum scst_dif_actions scst_get_scst_dif_actions(enum scst_dif_actions a)
{
	BUILD_BUG_ON(SCST_DIF_CHECKS_SHIFT != 0);
	return ((a >> SCST_DIF_SCST_ACTION_SHIFT) & SCST_DIF_ACTION_MASK) |
	       (a & SCST_DIF_CHECKS_MASK);
}

/* Sets SCST DIF action in a. DIF checks in a are not affected by this function. */
static inline void scst_set_scst_dif_action(enum scst_dif_actions *a,
	enum scst_dif_actions scst_a)
{
	scst_a &= SCST_DIF_ACTION_MASK;
	*a |= scst_a << SCST_DIF_SCST_ACTION_SHIFT;
	return;
}

/* Returns DEV DIF actions from a, including checks */
static inline enum scst_dif_actions scst_get_dev_dif_actions(enum scst_dif_actions a)
{
	BUILD_BUG_ON(SCST_DIF_CHECKS_SHIFT != 0);
	return ((a >> SCST_DIF_DEV_ACTION_SHIFT) & SCST_DIF_ACTION_MASK) |
	       (a & SCST_DIF_CHECKS_MASK);
}

/* Sets SCST DIF action in a. DIF checks in a are not affected by this function. */
static inline void scst_set_dev_dif_action(enum scst_dif_actions *a,
	enum scst_dif_actions dev_a)
{
	dev_a &= SCST_DIF_ACTION_MASK;
	*a |= dev_a << SCST_DIF_DEV_ACTION_SHIFT;
	return;
}

/*************************************************************
 *                     TYPES
 *************************************************************/

struct scst_tgt;
struct scst_session;
struct scst_cmd;
struct scst_mgmt_cmd;
struct scst_device;
struct scst_tgt_dev;
struct scst_dev_type;
struct scst_acg;
struct scst_acg_dev;
struct scst_acn;
struct scst_aen;
struct scst_opcode_descriptor;

/*
 * SCST uses 64-bit numbers to represent LUN's internally. The value
 * NO_SUCH_LUN is guaranteed to be different of every valid LUN.
 */
#define NO_SUCH_LUN ((uint64_t)-1)

typedef enum dma_data_direction scst_data_direction;

/*
 * SCST target template: defines target driver's parameters and callback
 * functions.
 *
 * MUST HAVEs define functions that are expected to be defined in order to
 * work. OPTIONAL says that there is a choice.
 */
struct scst_tgt_template {
	/* public: */

	/*
	 * If not NULL, points to 0-terminated array of integers listing all
	 * supported for T10-PI DIF-enabled devices block sizes. SCST will not
	 * allow to add DIF-enabled devices with another block sizes to this
	 * target driver's initiator groups.
	 *
	 * Can be overiden by scst_tgt_set_supported_dif_block_sizes()
	 *
	 * OPTIONAL
	 */
	const int *const supported_dif_block_sizes;

	/*
	 * Preferred SCSI LUN addressing method.
	 */
	enum scst_lun_addr_method preferred_addr_method;

	/*
	 * The maximum time in seconds cmd can stay inside the target
	 * hardware, i.e. after rdy_to_xfer() and xmit_response(), before
	 * on_hw_pending_cmd_timeout() will be called, if defined.
	 *
	 * In the current implementation a cmd will be aborted in time t
	 * max_hw_pending_time <= t < 2*max_hw_pending_time.
	 */
	int max_hw_pending_time;

	/*
	 * SG tablesize allows to check whether scatter/gather can be used
	 * or not.
	 */
	int sg_tablesize;

	/*
	 * True, if this target adapter uses unchecked DMA onto an ISA bus.
	 */
	unsigned unchecked_isa_dma:1;

	/*
	 * True, if this target adapter can benefit from using SG-vector
	 * clustering (i.e. smaller number of segments).
	 */
	unsigned use_clustering:1;

	/*
	 * True, if this target adapter doesn't support SG-vector clustering
	 */
	unsigned no_clustering:1;

	/*
	 * True, if corresponding function supports execution in
	 * the atomic (non-sleeping) context
	 */
	unsigned xmit_response_atomic:1;
	unsigned rdy_to_xfer_atomic:1;

#ifdef CONFIG_SCST_PROC
	/* True, if the template doesn't need the entry in /proc */
	unsigned no_proc_entry:1;
#else
	/* True, if this target doesn't need "enabled" attribute */
	unsigned enabled_attr_not_needed:1;
#endif

	/*
	 * True if SCST should report that it supports ACA although it does
	 * not yet support ACA. Necessary for the IBM virtual SCSI target
	 * driver.
	 */
	unsigned fake_aca:1;

	/*
	 * True, if this target adapter can call scst_cmd_init_done() from
	 * several threads at the same time.
	 */
	unsigned multithreaded_init_done:1;

	/*
	 * True, if this target driver supports T10-PI (DIF), i.e. sending and
	 * receiving DIF PI tags. If false, SCST will not allow to add
	 * DIF-enabled devices to this target driver's initiator groups.
	 *
	 * Can be overriden per target by scst_tgt_set_dif_supported()
	 */
	unsigned dif_supported:1;

	/*
	 * True, if this target driver supports T10-PI (DIF), i.e. INSERT/STRIPE
	 * mode, in hardware for type 1 protection. If false, SCST will not
	 * allow to add type 1 devices with TGT DIF mode to this target driver's
	 * initiator groups.
	 *
	 * Can be overriden per target by scst_tgt_set_hw_dif_type1_supported()
	 */
	unsigned hw_dif_type1_supported:1;

	/*
	 * True, if this target driver supports T10-PI (DIF), i.e. INSERT/STRIPE
	 * mode, in hardware for type 2 protection. If false, SCST will not
	 * allow to add type 2 devices with TGT DIF mode to this target driver's
	 * initiator groups.
	 *
	 * Can be overriden per target by scst_tgt_set_hw_dif_type2_supported()
	 */
	unsigned hw_dif_type2_supported:1;

	/*
	 * True, if this target driver supports T10-PI (DIF), i.e. INSERT/STRIPE
	 * mode, in hardware for type 3 protection. If false, SCST will not
	 * allow to add type 3 devices with TGT DIF mode to this target driver's
	 * initiator groups.
	 *
	 * Can be overriden per target by scst_tgt_set_hw_dif_type3_supported()
	 */
	unsigned hw_dif_type3_supported:1;

	/*
	 * True, if this target driver supports IP checksum format of T10-PI
	 * (DIF) guard tags, i.e. hardware translation of guard tags between IP
	 * and CRC on SCST/target driver boundary for better performance,
	 * because IP checksums are much cheaper for CPU, than CRC.
	 *
	 * Can be overriden per target by scst_tgt_set_hw_dif_ip_supported()
	 */
	unsigned hw_dif_ip_supported:1;

	/*
	 * True, if this target driver requires the same layout for both data
	 * and DIF tags SG vectors. Otherwise, for DIF tags minimally possible
	 * SG vector size will be allocated.
	 *
	 * Can be overriden per target by scst_tgt_set_hw_dif_same_sg_layout_required()
	 */
	unsigned hw_dif_same_sg_layout_required:1;

	/*
	 * This function is equivalent to the SCSI
	 * queuecommand. The target should transmit the response
	 * buffer and the status in the scst_cmd struct.
	 * The expectation is that this executing this command is NON-BLOCKING.
	 * If it is blocking, consider to set threads_num to some none 0 number.
	 *
	 * After the response is actually transmitted, the target
	 * should call the scst_tgt_cmd_done() function of the
	 * mid-level, which will allow it to free up the command.
	 * Returns one of the SCST_TGT_RES_* constants.
	 *
	 * Pay attention to "atomic" attribute of the cmd, which can be get
	 * by scst_cmd_atomic(): it is true if the function called in the
	 * atomic (non-sleeping) context.
	 *
	 * MUST HAVE
	 */
	int (*xmit_response)(struct scst_cmd *cmd);

	/*
	 * This function informs the driver that data
	 * buffer corresponding to the said command have now been
	 * allocated and it is OK to receive data for this command.
	 * This function is necessary because a SCSI target does not
	 * have any control over the commands it receives. Most lower
	 * level protocols have a corresponding function which informs
	 * the initiator that buffers have been allocated e.g., XFER_
	 * RDY in Fibre Channel. After the data is actually received
	 * the low-level driver needs to call scst_rx_data() in order to
	 * continue processing this command.
	 * Returns one of the SCST_TGT_RES_* constants.
	 *
	 * This command is expected to be NON-BLOCKING.
	 * If it is blocking, consider to set threads_num to some none 0 number.
	 *
	 * Pay attention to "atomic" attribute of the cmd, which can be get
	 * by scst_cmd_atomic(): it is true if the function called in the
	 * atomic (non-sleeping) context.
	 *
	 * OPTIONAL
	 */
	int (*rdy_to_xfer)(struct scst_cmd *cmd);

	/*
	 * Called if cmd stays inside the target hardware, i.e. after
	 * rdy_to_xfer() and xmit_response(), more than max_hw_pending_time
	 * time. The target driver supposed to cleanup this command and
	 * resume cmd's processing.
	 *
	 * OPTIONAL
	 */
	void (*on_hw_pending_cmd_timeout)(struct scst_cmd *cmd);

	/*
	 * Called to notify the driver that the command is about to be freed.
	 * Necessary, because for aborted commands xmit_response() could not
	 * be called. Could be called on IRQ context.
	 *
	 * This callback is called when the last reference to cmd is dropped,
	 * which can be much later after scst_tgt_cmd_done() called by the
	 * target driver, so it is not recommended that the target driver
	 * clean hardware or connection related cmd resources in this callback.
	 * It is recommended to clean them before calling scst_tgt_cmd_done()
	 * instead.
	 *
	 * OPTIONAL
	 */
	void (*on_free_cmd)(struct scst_cmd *cmd);

	/*
	 * This function allows target driver to handle data buffer
	 * allocations on its own.
	 *
	 * Target driver doesn't have to always allocate buffer in this
	 * function, but if it decide to do it, it must check that
	 * scst_cmd_get_data_buff_alloced() returns 0, otherwise to avoid
	 * double buffer allocation and memory leaks tgt_alloc_data_buf() shall
	 * fail.
	 *
	 * Shall return 0 in case of success or < 0 (preferably -ENOMEM)
	 * in case of error, or > 0 if the regular SCST allocation should be
	 * done. In case of returning successfully,
	 * scst_cmd->tgt_i_data_buf_alloced will be set by SCST.
	 *
	 * It is possible that both target driver and dev handler request own
	 * memory allocation. In this case, data will be memcpy() between
	 * buffers, where necessary.
	 *
	 * If allocation in atomic context - cf. scst_cmd_atomic() - is not
	 * desired or fails and consequently < 0 is returned, this function
	 * will be re-called in thread context.
	 *
	 * Please note that the driver will have to handle itself all relevant
	 * details such as scatterlist setup, highmem, freeing the allocated
	 * memory, etc.
	 *
	 * OPTIONAL.
	 */
	int (*tgt_alloc_data_buf)(struct scst_cmd *cmd);

	/*
	 * This function informs the driver that data
	 * buffer corresponding to the said command have now been
	 * allocated and other preprocessing tasks have been done.
	 * A target driver could need to do some actions at this stage.
	 * After the target driver done the needed actions, it shall call
	 * scst_restart_cmd() in order to continue processing this command.
	 * In case of preliminary the command completion, this function will
	 * also be called before xmit_response().
	 *
	 * Called only if the cmd is queued using scst_cmd_init_stage1_done()
	 * instead of scst_cmd_init_done().
	 *
	 * Returns void, the result is expected to be returned using
	 * scst_restart_cmd().
	 *
	 * This command is expected to be NON-BLOCKING.
	 * If it is blocking, consider to set threads_num to some none 0 number.
	 *
	 * Pay attention to "atomic" attribute of the cmd, which can be get
	 * by scst_cmd_atomic(): it is true if the function called in the
	 * atomic (non-sleeping) context.
	 *
	 * OPTIONAL.
	 */
	void (*preprocessing_done)(struct scst_cmd *cmd);

	/*
	 * This function informs the driver that the said command is about
	 * to be executed.
	 *
	 * Returns one of the SCST_PREPROCESS_* constants.
	 *
	 * This command is expected to be NON-BLOCKING.
	 * If it is blocking, consider to set threads_num to some none 0 number.
	 *
	 * OPTIONAL
	 */
	int (*pre_exec)(struct scst_cmd *cmd);

	/*
	 * This function informs the driver that all affected by the
	 * corresponding task management function commands have beed completed.
	 * No return value expected.
	 *
	 * This function is expected to be NON-BLOCKING.
	 *
	 * Called without any locks held from a thread context.
	 *
	 * OPTIONAL
	 */
	void (*task_mgmt_affected_cmds_done)(struct scst_mgmt_cmd *mgmt_cmd);

	/*
	 * This function informs the driver that the corresponding task
	 * management function has been completed, i.e. all the corresponding
	 * commands completed and freed. No return value expected.
	 *
	 * This function is expected to be NON-BLOCKING.
	 *
	 * Called without any locks held from a thread context.
	 *
	 * MUST HAVE if the target supports task management.
	 */
	void (*task_mgmt_fn_done)(struct scst_mgmt_cmd *mgmt_cmd);

	/*
	 * Called to notify target driver that the command is being aborted.
	 * If target driver wants to redirect processing to some outside
	 * processing, it should get it using scst_cmd_get(). Since this
	 * function is invoked from the context of a task management function
	 * it runs asynchronously with the regular command processing finite
	 * state machine. In other words, it is only safe to invoke functions
	 * like scst_tgt_cmd_done() or scst_rx_data() from this callback
	 * function if the target driver owns the command and if appropriate
	 * measures have been taken to avoid that the target driver would
	 * invoke one of these functions from the regular command processing
	 * path. Note: if scst_tgt_cmd_done() or scst_rx_data() is invoked
	 * from this callback function these must be invoked with the
	 * SCST_CONTEXT_THREAD argument.
	 *
	 * OPTIONAL
	 */
	void (*on_abort_cmd)(struct scst_cmd *cmd);

	/*
	 * This function should detect the target adapters that
	 * are present in the system. The function should return a value
	 * >= 0 to signify the number of detected target adapters.
	 * A negative value should be returned whenever there is
	 * an error.
	 *
	 * OBSOLETE
	 */
	int (*detect)(struct scst_tgt_template *tgt_template);

	/*
	 * This function should free up the resources allocated to the device.
	 * The function should return 0 to indicate successful release
	 * or a negative value if there are some issues with the release.
	 * In the current version the return value is ignored.
	 *
	 * MUST HAVE
	 */
	int (*release)(struct scst_tgt *tgt);

	/*
	 * This function is used for Asynchronous Event Notifications.
	 *
	 * Returns one of the SCST_AEN_RES_* constants.
	 * After AEN is sent, target driver must call scst_aen_done() and,
	 * optionally, scst_set_aen_delivery_status().
	 *
	 * This function is expected to be NON-BLOCKING, but can sleep.
	 *
	 * This function must be prepared to handle AENs between calls for the
	 * corresponding session of scst_unregister_session() and
	 * unreg_done_fn() callback called or before scst_unregister_session()
	 * returned, if its called in the blocking mode. AENs for such sessions
	 * should be ignored.
	 *
	 * MUST HAVE, if low-level protocol supports AENs.
	 */
	int (*report_aen)(struct scst_aen *aen);

#ifdef CONFIG_SCST_PROC
	/*
	 * Those functions can be used to export the driver's statistics and
	 * other infos to the world outside the kernel as well as to get some
	 * management commands from it.
	 *
	 * OPTIONAL
	 */
	int (*read_proc)(struct seq_file *seq, struct scst_tgt *tgt);
	int (*write_proc)(char *buffer, char **start, off_t offset,
		int length, int *eof, struct scst_tgt *tgt);
#endif

	/*
	 * This function returns in tr_id the corresponding to sess initiator
	 * port TransportID in the form as it's used by PR commands, see
	 * "Transport Identifiers" in SPC. Space for the initiator port
	 * TransportID must be allocated via kmalloc(). Caller supposed to
	 * kfree() it, when it isn't needed anymore.
	 *
	 * If sess is NULL, this function must return TransportID PROTOCOL
	 * IDENTIFIER for the requested target.
	 *
	 * Returns 0 on success or negative error code otherwise.
	 *
	 * SHOULD HAVE, because it's required for Persistent Reservations.
	 */
	int (*get_initiator_port_transport_id)(struct scst_tgt *tgt,
		struct scst_session *sess, uint8_t **transport_id);

	/*
	 * This function allows to enable or disable particular target.
	 * A disabled target doesn't receive and process any SCSI commands.
	 *
	 * SHOULD HAVE to avoid race when there are connected initiators,
	 * while target not yet completed the initial configuration. In this
	 * case the too early connected initiators would see not those devices,
	 * which they intended to see.
	 *
	 * If you are sure your target driver doesn't need enabling target,
	 * you should set enabled_attr_not_needed in 1.
	 */
	int (*enable_target)(struct scst_tgt *tgt, bool enable);

	/*
	 * This function shows if particular target is enabled or not.
	 *
	 * SHOULD HAVE, see above why.
	 */
	bool (*is_target_enabled)(struct scst_tgt *tgt);

	/*
	 * This function adds a virtual target.
	 *
	 * If both add_target and del_target callbacks defined, then this
	 * target driver supposed to support virtual targets. In this case
	 * an "mgmt" entry will be created in the sysfs root for this driver.
	 * The "mgmt" entry will support 2 commands: "add_target" and
	 * "del_target", for which the corresponding callbacks will be called.
	 * Also target driver can define own commands for the "mgmt" entry, see
	 * mgmt_cmd and mgmt_cmd_help below.
	 *
	 * This approach allows uniform targets management to simplify external
	 * management tools like scstadmin. See README for more details.
	 *
	 * Either both add_target and del_target must be defined, or none.
	 *
	 * MUST HAVE if virtual targets are supported.
	 */
	ssize_t (*add_target)(const char *target_name, char *params);

	/*
	 * This function deletes a virtual target. See comment for add_target
	 * above.
	 *
	 * MUST HAVE if virtual targets are supported.
	 */
	ssize_t (*del_target)(const char *target_name);

	/*
	 * This function called if not "add_target" or "del_target" command is
	 * sent to the mgmt entry (see comment for add_target above). In this
	 * case the command passed to this function as is in a string form.
	 *
	 * OPTIONAL.
	 */
	ssize_t (*mgmt_cmd)(char *cmd);

	/*
	 * Forcibly close a session. Note: this function may operate
	 * asynchronously - there is no guarantee the session will actually
	 * have been closed at the time this function returns. May be called
	 * with scst_mutex held. Activity may be suspended while this function
	 * is invoked. May sleep but must not wait until session
	 * unregistration finished. Must return 0 upon success and -EINTR if
	 * the session has not been closed because a signal has been received.
	 *
	 * OPTIONAL
	 */
	int (*close_session)(struct scst_session *sess);

	/*
	 * Should return physical transport version. Used in the corresponding
	 * INQUIRY version descriptor. See SPC for the list of available codes.
	 *
	 * OPTIONAL
	 */
	uint16_t (*get_phys_transport_version)(struct scst_tgt *tgt);

	/*
	 * Should return SCSI transport version. Used in the corresponding
	 * INQUIRY version descriptor. See SPC for the list of available codes.
	 *
	 * OPTIONAL
	 */
	uint16_t (*get_scsi_transport_version)(struct scst_tgt *tgt);

	/*
	 * Name of the template. Must be unique to identify
	 * the template. MUST HAVE
	 */
	const char name[SCST_MAX_NAME];

	/*
	 * Number of additional threads to the pool of dedicated threads.
	 * Used if xmit_response() or rdy_to_xfer() is blocking.
	 * It is the target driver's duty to ensure that not more, than that
	 * number of threads, are blocked in those functions at any time.
	 */
	int threads_num;

	/* Optional default log flags */
	const unsigned long default_trace_flags;

	/* Optional pointer to trace flags */
	unsigned long *trace_flags;

	/* Optional local trace table */
	struct scst_trace_log *trace_tbl;

	/* Optional local trace table help string */
	const char *trace_tbl_help;

#ifndef CONFIG_SCST_PROC
	/* sysfs attributes, if any */
	const struct attribute **tgtt_attrs;

	/* sysfs target attributes, if any */
	const struct attribute **tgt_attrs;

	/* sysfs session attributes, if any */
	const struct attribute **sess_attrs;
#endif

	/* Optional help string for mgmt_cmd commands */
	const char *mgmt_cmd_help;

	/* List of parameters for add_target command, if any */
	const char *add_target_parameters;

	/*
	 * List of optional, i.e. which could be added by add_attribute command
	 * and deleted by del_attribute command, sysfs attributes, if any.
	 * Helpful for scstadmin to work correctly.
	 */
	const char *tgtt_optional_attributes;

	/*
	 * List of optional, i.e. which could be added by add_target_attribute
	 * command and deleted by del_target_attribute command, sysfs
	 * attributes, if any. Helpful for scstadmin to work correctly.
	 */
	const char *tgt_optional_attributes;

	/** Private, must be inited to 0 by memset() **/

	/* List of targets per template, protected by scst_mutex */
	struct list_head tgt_list;

	/* List entry of global templates list */
	struct list_head scst_template_list_entry;

#ifdef CONFIG_SCST_PROC
	/* The pointer to the /proc directory entry */
	struct proc_dir_entry *proc_tgt_root;

	/* Device number in /proc */
	int proc_dev_num;
#else
	struct kobject tgtt_kobj; /* target driver sysfs entry */

	/* Number of currently active sysfs mgmt works (scst_sysfs_work_item) */
	int tgtt_active_sysfs_works_count;

	/* sysfs release completion */
	struct completion *tgtt_kobj_release_cmpl;
#endif

	/*
	 * Optional method that writes the serial number of a target device in
	 * [buf, buf+size) and returns the number of bytes written.
	 *
	 * Note: SCST can be configured such that a device can be accessed
	 * from several different transports at the same time. It is important
	 * that all clients see the same USN for proper operation. Overriding
	 * the serial number can lead to subtle misbehavior. Particularly,
	 * "usn" sysfs attribute of the corresponding devices will still show
	 * the devices generated or assigned serial numbers.
	 */
	int (*get_serial)(const struct scst_tgt_dev *tgt_dev, char *buf,
			  int size);
};

/*
 * Threads pool types. Changing them don't forget to change
 * the corresponding *_STR values in scst_const.h!
 */
enum scst_dev_type_threads_pool_type {
	/* Each initiator will have dedicated threads pool. */
	SCST_THREADS_POOL_PER_INITIATOR = 0,

	/* All connected initiators will use shared threads pool */
	SCST_THREADS_POOL_SHARED,

	/* Invalid value for scst_parse_threads_pool_type() */
	SCST_THREADS_POOL_TYPE_INVALID,
};

/*
 * SCST dev handler template: defines dev handler's parameters and callback
 * functions.
 *
 * MUST HAVEs define functions that are expected to be defined in order to
 * work. OPTIONAL says that there is a choice.
 */
struct scst_dev_type {
	/* SCSI type of the supported device. MUST HAVE */
	int type;

	/*
	 * True, if corresponding function supports execution in
	 * the atomic (non-sleeping) context
	 */
	unsigned parse_atomic:1;
	unsigned dev_alloc_data_buf_atomic:1;
	unsigned dev_done_atomic:1;

#ifdef CONFIG_SCST_PROC
	/* True, if no /proc files should be automatically created by SCST */
	unsigned no_proc:1;
#endif

	/*
	 * Should be true, if exec() is synchronous. This is a hint to SCST core
	 * to optimize commands order management.
	 */
	unsigned exec_sync:1;

	/*
	 * Should be set if the device wants to receive notification of
	 * Persistent Reservation commands (PR OUT only)
	 * Note: The notification will not be send if the command failed
	 */
	unsigned pr_cmds_notifications:1;

	/*
	 * Called to parse CDB from the cmd and initialize
	 * cmd->bufflen and cmd->data_direction (both - REQUIRED).
	 *
	 * Returns the command's next state or SCST_CMD_STATE_DEFAULT,
	 * if the next default state should be used, or
	 * SCST_CMD_STATE_NEED_THREAD_CTX if the function called in atomic
	 * context, but requires sleeping, or SCST_CMD_STATE_STOP if the
	 * command should not be further processed for now. In the
	 * SCST_CMD_STATE_NEED_THREAD_CTX case the function
	 * will be recalled in the thread context, where sleeping is allowed.
	 *
	 * Pay attention to "atomic" attribute of the cmd, which can be get
	 * by scst_cmd_atomic(): it is true if the function called in the
	 * atomic (non-sleeping) context.
	 *
	 * MUST HAVE
	 */
	int (*parse)(struct scst_cmd *cmd);

	/*
	 * This function allows dev handler to handle data buffer
	 * allocations on its own.
	 *
	 * Returns the command's next state or SCST_CMD_STATE_DEFAULT,
	 * if the next default state should be used, or
	 * SCST_CMD_STATE_NEED_THREAD_CTX if the function called in atomic
	 * context, but requires sleeping, or SCST_CMD_STATE_STOP if the
	 * command should not be further processed for now. In the
	 * SCST_CMD_STATE_NEED_THREAD_CTX case the function
	 * will be recalled in the thread context, where sleeping is allowed.
	 *
	 * Pay attention to "atomic" attribute of the cmd, which can be get
	 * by scst_cmd_atomic(): it is true if the function called in the
	 * atomic (non-sleeping) context.
	 *
	 * OPTIONAL
	 */
	int (*dev_alloc_data_buf)(struct scst_cmd *cmd);

	/*
	 * Called to execute CDB. Useful, for instance, to implement
	 * data caching. The result of CDB execution is reported via
	 * cmd->scst_cmd_done() callback.
	 * Returns:
	 *  - SCST_EXEC_COMPLETED - the cmd is done, go to other ones
	 *  - SCST_EXEC_NOT_COMPLETED - the cmd should be sent to SCSI
	 *	mid-level.
	 *
	 * If this function provides sync execution, you should set
	 * exec_sync flag and consider to setup dedicated threads by
	 * setting threads_num > 0.
	 *
	 * Dev handlers implementing internal queuing in their exec() callback
	 * should call scst_check_local_events() just before the actual
	 * command's execution (i.e. after it's taken from the internal queue).
	 *
	 * OPTIONAL, if not set, the commands will be sent directly to SCSI
	 * device.
	 */
	int (*exec)(struct scst_cmd *cmd);

	/*
	 * Called to notify dev handler about the result of cmd execution
	 * and perform some post processing. Cmd's fields is_send_status and
	 * resp_data_len should be set by this function, but SCST offers good
	 * defaults.
	 * Returns the command's next state or SCST_CMD_STATE_DEFAULT,
	 * if the next default state should be used, or
	 * SCST_CMD_STATE_NEED_THREAD_CTX if the function called in atomic
	 * context, but requires sleeping. In the last case, the function
	 * will be recalled in the thread context, where sleeping is allowed.
	 *
	 * Pay attention to "atomic" attribute of the cmd, which can be get
	 * by scst_cmd_atomic(): it is true if the function called in the
	 * atomic (non-sleeping) context.
	 *
	 * OPTIONAL
	 */
	int (*dev_done)(struct scst_cmd *cmd);

	/*
	 * Called to notify dev handler that the command is about to be freed.
	 *
	 * Could be called on IRQ context.
	 *
	 * OPTIONAL
	 */
	void (*on_free_cmd)(struct scst_cmd *cmd);

	/*
	 * Called to notify dev handler that a task management command received
	 *
	 * Can be called under many internal SCST locks, including under
	 * disabled IRQs, so dev handler should be careful with locking and,
	 * if necessary, pass processing somewhere outside (in a work, e.g.)
	 *
	 * But at the moment it's called under disabled IRQs only for
	 * SCST_ABORT_TASK, however dev handler using it should add a BUG_ON
	 * trap to catch if it's changed in future.
	 *
	 * OPTIONAL
	 */
	void (*task_mgmt_fn_received)(struct scst_mgmt_cmd *mgmt_cmd,
		struct scst_tgt_dev *tgt_dev);

	/*
	 * Called to execute a task management command. On any problem, error
	 * code (one of SCST_MGMT_STATUS_* codes) should be set using function
	 * scst_mgmt_cmd_set_status().
	 *
	 * Can be called under many internal SCST locks, including under
	 * disabled IRQs, so dev handler should be careful with locking and,
	 * if necessary, pass processing somewhere outside (in a work, e.g.)
	 *
	 * But at the moment it's called under disabled IRQs only for
	 * SCST_ABORT_TASK, however dev handler using it should add a BUG_ON
	 * trap to catch if it's changed in future.
	 *
	 * OPTIONAL
	 */
	void (*task_mgmt_fn_done)(struct scst_mgmt_cmd *mgmt_cmd,
		struct scst_tgt_dev *tgt_dev);

	/*
	 * Called to reassign retained states (mode pages, etc.) from
	 * old_tgt_dev to new_tgt_dev during nexus loss (iSCSI sessions
	 * reinstatement, etc.) processing.
	 *
	 * Can be called under scst_mutex.
	 *
	 * OPTIONAL
	 */
	void (*reassign_retained_states)(struct scst_tgt_dev *new_tgt_dev,
		struct scst_tgt_dev *old_tgt_dev);

	/*
	 * Called to notify dev handler that its sg_tablesize is too low to
	 * satisfy this command's data transfer requirements. Should return
	 * true if exec() callback will split this command's CDB on smaller
	 * transfers, false otherwise.
	 *
	 * Could be called on SIRQ context.
	 *
	 * MUST HAVE, if dev handler supports CDB splitting.
	 */
	bool (*on_sg_tablesize_low)(struct scst_cmd *cmd);

	/*
	 * Called to return array of supported opcodes in out_supp_opcodes
	 * argument with out_supp_opcodes_cnt elements count or execute
	 * REPORT SUPPORTED OPERATION CODES command in place. Must return
	 * 0 on success or any other code otherwise. In the latter case,
	 * cmd supposed to have correct sense set.
	 *
	 * OPTIONAL
	 */
	int (*get_supported_opcodes)(struct scst_cmd *cmd,
		const struct scst_opcode_descriptor ***out_supp_opcodes,
		int *out_supp_opcodes_cnt);

	/*
	 * Called to put (release) array of supported opcodes returned
	 * by get_supported_opcodes() callback.
	 *
	 * OPTIONAL
	 */
	void (*put_supported_opcodes)(struct scst_cmd *cmd,
		const struct scst_opcode_descriptor **supp_opcodes,
		int supp_opcodes_cnt);

	/*
	 * Called when new device is attaching to the dev handler
	 * Returns 0 on success, error code otherwise.
	 *
	 * OPTIONAL
	 */
	int (*attach)(struct scst_device *dev);

	/*
	 * Called when a device is detaching from the dev handler.
	 *
	 * OPTIONAL
	 */
	void (*detach)(struct scst_device *dev);

	/*
	 * Called when new tgt_dev (session) is attaching to the dev handler.
	 * Returns 0 on success, error code otherwise.
	 *
	 * OPTIONAL
	 */
	int (*attach_tgt)(struct scst_tgt_dev *tgt_dev);

	/*
	 * Called when tgt_dev (session) is detaching from the dev handler.
	 *
	 * OPTIONAL
	 */
	void (*detach_tgt)(struct scst_tgt_dev *tgt_dev);

#ifdef CONFIG_SCST_PROC
	/*
	 * Those functions can be used to export the handler's statistics and
	 * other infos to the world outside the kernel as well as to get some
	 * management commands from it.
	 *
	 * OPTIONAL
	 */
	int (*read_proc)(struct seq_file *seq, struct scst_dev_type *dev_type);
	int (*write_proc)(char *buffer, char **start, off_t offset,
		int length, int *eof, struct scst_dev_type *dev_type);
#else
	/*
	 * This function adds a virtual device.
	 *
	 * If both add_device and del_device callbacks defined, then this
	 * dev handler supposed to support adding/deleting virtual devices.
	 * In this case an "mgmt" entry will be created in the sysfs root for
	 * this handler. The "mgmt" entry will support 2 commands: "add_device"
	 * and "del_device", for which the corresponding callbacks will be called.
	 * Also dev handler can define own commands for the "mgmt" entry, see
	 * mgmt_cmd and mgmt_cmd_help below.
	 *
	 * This approach allows uniform devices management to simplify external
	 * management tools like scstadmin. See README for more details.
	 *
	 * Either both add_device and del_device must be defined, or none.
	 *
	 * MUST HAVE if virtual devices are supported.
	 */
	ssize_t (*add_device)(const char *device_name, char *params);

	/*
	 * This function deletes a virtual device. See comment for add_device
	 * above.
	 *
	 * MUST HAVE if virtual devices are supported.
	 */
	ssize_t (*del_device)(const char *device_name);

	/*
	 * This function called if not "add_device" or "del_device" command is
	 * sent to the mgmt entry (see comment for add_device above). In this
	 * case the command passed to this function as is in a string form.
	 *
	 * OPTIONAL.
	 */
	ssize_t (*mgmt_cmd)(char *cmd);
#endif

	/*
	 * Name of the dev handler. Must be unique. MUST HAVE.
	 *
	 * It's SCST_MAX_NAME + few more bytes to match scst_user expectations.
	 */
	char name[SCST_MAX_NAME + 10];

	/*
	 * Number of threads in this handler's devices' threads pools.
	 * If 0 - no threads will be created, if <0 - creation of the threads
	 * pools is prohibited. Also pay attention to threads_pool_type below.
	 */
	int threads_num;

	/* Threads pool type. Valid only if threads_num > 0. */
	enum scst_dev_type_threads_pool_type threads_pool_type;

	/* Optional default log flags */
	const unsigned long default_trace_flags;

	/* Optional pointer to trace flags */
	unsigned long *trace_flags;

	/* Optional local trace table */
	struct scst_trace_log *trace_tbl;

#ifndef CONFIG_SCST_PROC
	/* Optional local trace table help string */
	const char *trace_tbl_help;

	/* Optional help string for mgmt_cmd commands */
	const char *mgmt_cmd_help;

	/* List of parameters for add_device command, if any */
	const char *add_device_parameters;

	/*
	 * List of optional, i.e. which could be added by add_attribute command
	 * and deleted by del_attribute command, sysfs attributes, if any.
	 * Helpful for scstadmin to work correctly.
	 */
	const char *devt_optional_attributes;

	/*
	 * List of optional, i.e. which could be added by add_device_attribute
	 * command and deleted by del_device_attribute command, sysfs
	 * attributes, if any. Helpful for scstadmin to work correctly.
	 */
	const char *dev_optional_attributes;

	/* sysfs attributes, if any */
	const struct attribute **devt_attrs;

	/* sysfs device attributes, if any */
	const struct attribute **dev_attrs;
#endif

	/* Pointer to dev handler's private data */
	void *devt_priv;

	/* Pointer to parent dev type in the sysfs hierarchy */
	struct scst_dev_type *parent;

	struct module *module;

	/** Private, must be inited to 0 by memset() **/

	/* list entry in scst_(virtual_)dev_type_list */
	struct list_head dev_type_list_entry;

#ifdef CONFIG_SCST_PROC
	/* The pointer to the /proc directory entry */
	struct proc_dir_entry *proc_dev_type_root;
#else
	struct kobject devt_kobj; /* main handlers/driver */

	/* Number of currently active sysfs mgmt works (scst_sysfs_work_item) */
	int devt_active_sysfs_works_count;

	/* To wait until devt_kobj released */
	struct completion *devt_kobj_release_compl;
#endif
};

/*
 * An SCST target, analog of SCSI target port.
 */
struct scst_tgt {
	/* List of remote sessions per target, protected by scst_mutex */
	struct list_head sess_list;

	/*
	 * List of remote sessions registered in sysfs per target, protected
	 * by scst_mutex.
	 */
	struct list_head sysfs_sess_list;

	/* List entry of targets per template (tgts_list) */
	struct list_head tgt_list_entry;

	struct scst_tgt_template *tgtt;	/* corresponding target template */

#ifndef CONFIG_SCST_PROC
	struct scst_acg *default_acg; /* default acg for this target */

	struct list_head tgt_acg_list; /* target ACG groups */
#endif

	/*
	 * Set, if this target is forwarding target, i.e. does not check
	 * any local SCSI events (reservations, etc.). Those event supposed
	 * to be checked on the another, requester's side.
	 */
	unsigned tgt_forwarding:1;

	/* Per target analog of the corresponding driver's fields */
	unsigned tgt_dif_supported:1;
	unsigned tgt_hw_dif_type1_supported:1;
	unsigned tgt_hw_dif_type2_supported:1;
	unsigned tgt_hw_dif_type3_supported:1;
	unsigned tgt_hw_dif_ip_supported:1;
	unsigned tgt_hw_dif_same_sg_layout_required:1;

	/*
	 * Maximum SG table size. Needed here, since different cards on the
	 * same target template can have different SG table limitations.
	 */
	int sg_tablesize;

	const int *tgt_supported_dif_block_sizes;

	/* Used for storage of target driver private stuff */
	void *tgt_priv;

	/*
	 * The following fields used to store and retry cmds if target's
	 * internal queue is full, so the target is unable to accept
	 * the cmd returning QUEUE FULL.
	 * They protected by tgt_lock, where necessary.
	 */
	bool retry_timer_active;
	int retry_cmds;
	struct timer_list retry_timer;
	struct list_head retry_cmd_list;
	spinlock_t tgt_lock;

	/* Used to wait until session finished to unregister */
	wait_queue_head_t unreg_waitQ;

#ifdef CONFIG_SCST_PROC
	/* Device number in /proc */
	int proc_num;
#endif

	/* Name of the target */
	char *tgt_name;

	/* User comment to it to let easier distinguish targets */
	char *tgt_comment;

	uint16_t rel_tgt_id;

	/* How many DIF failures detected on this target on the corresponding stage */
	atomic_t tgt_dif_app_failed_tgt, tgt_dif_ref_failed_tgt, tgt_dif_guard_failed_tgt;
	atomic_t tgt_dif_app_failed_scst, tgt_dif_ref_failed_scst, tgt_dif_guard_failed_scst;
	atomic_t tgt_dif_app_failed_dev, tgt_dif_ref_failed_dev, tgt_dif_guard_failed_dev;

#ifdef CONFIG_SCST_PROC
	/* Name of the default security group ("Default_target_name") */
	char *default_group_name;
#else
	/* sysfs release completion */
	struct completion *tgt_kobj_release_cmpl;

	struct kobject tgt_kobj; /* main targets/target kobject */
	struct kobject *tgt_sess_kobj; /* target/sessions/ */
	struct kobject *tgt_luns_kobj; /* target/luns/ */
	struct kobject *tgt_ini_grp_kobj; /* target/ini_groups/ */
#endif
};

#ifdef CONFIG_SCST_MEASURE_LATENCY

/* Divide two 64-bit numbers with reasonably accuracy. */
static inline void __scst_time_per_cmd(uint64_t *t, uint64_t n)
{
	unsigned shift;

	if (!n)
		return;
	shift = max(0, ilog2(n) - 32 + 1);
	*t >>= shift;
	n >>= shift;
	WARN_ON(n != (uint32_t)n);
	do_div(*t, (uint32_t)n);
}

#define scst_time_per_cmd(t, n) __scst_time_per_cmd(&(t), (n))

/* Defines extended latency statistics */
struct scst_ext_latency_stat {
	uint64_t scst_time_rd, tgt_time_rd, dev_time_rd;
	uint64_t processed_cmds_rd;
	uint64_t min_scst_time_rd, min_tgt_time_rd, min_dev_time_rd;
	uint64_t max_scst_time_rd, max_tgt_time_rd, max_dev_time_rd;

	uint64_t scst_time_wr, tgt_time_wr, dev_time_wr;
	uint64_t processed_cmds_wr;
	uint64_t min_scst_time_wr, min_tgt_time_wr, min_dev_time_wr;
	uint64_t max_scst_time_wr, max_tgt_time_wr, max_dev_time_wr;
};

#define SCST_IO_SIZE_THRESHOLD_SMALL		(8*1024)
#define SCST_IO_SIZE_THRESHOLD_MEDIUM		(32*1024)
#define SCST_IO_SIZE_THRESHOLD_LARGE		(128*1024)
#define SCST_IO_SIZE_THRESHOLD_VERY_LARGE	(512*1024)

#define SCST_LATENCY_STAT_INDEX_SMALL		0
#define SCST_LATENCY_STAT_INDEX_MEDIUM		1
#define SCST_LATENCY_STAT_INDEX_LARGE		2
#define SCST_LATENCY_STAT_INDEX_VERY_LARGE	3
#define SCST_LATENCY_STAT_INDEX_OTHER		4
#define SCST_LATENCY_STATS_NUM		(SCST_LATENCY_STAT_INDEX_OTHER + 1)

#endif /* CONFIG_SCST_MEASURE_LATENCY */

struct scst_io_stat_entry {
	uint64_t cmd_count;
	uint64_t io_byte_count;
	uint64_t unaligned_cmd_count;
};

/*
 * SCST session, analog of SCSI I_T nexus
 */
struct scst_session {
	/*
	 * Initialization phase, one of SCST_SESS_IPH_* constants, protected by
	 * sess_list_lock
	 */
	int init_phase;

	struct scst_tgt *tgt;	/* corresponding target */

	/* Used for storage of target driver private stuff */
	void *sess_tgt_priv;

	/* session's async flags */
	unsigned long sess_aflags;

	/*
	 * Hash list for tgt_dev's for this session with size and fn. It isn't
	 * hlist_entry, because we need ability to go over the list in the
	 * reverse order. Protected by scst_mutex and suspended activity.
	 */
#define	SESS_TGT_DEV_LIST_HASH_SIZE (1 << 5)
#define	SESS_TGT_DEV_LIST_HASH_FN(val) ((val) & (SESS_TGT_DEV_LIST_HASH_SIZE - 1))
	struct list_head sess_tgt_dev_list[SESS_TGT_DEV_LIST_HASH_SIZE];

	/*
	 * List of cmds in this session. Protected by sess_list_lock.
	 *
	 * We must always keep commands in the sess list from the
	 * very beginning, because otherwise they can be missed during
	 * TM processing.
	 */
	struct list_head sess_cmd_list ____cacheline_aligned_in_smp;

	spinlock_t sess_list_lock; /* protects sess_cmd_list, etc */

	atomic_t refcnt;		/* get/put counter */

	/*
	 * Alive commands for this session. ToDo: make it part of the common
	 * IO flow control.
	 */
	atomic_t sess_cmd_count;

	/* Some statistics. Protected by sess_list_lock. */
	struct scst_io_stat_entry io_stats[SCST_DATA_DIR_MAX];

	/* Access control for this session and list entry there */
	struct scst_acg *acg;

	/* Initiator port transport id */
	uint8_t *transport_id;

	/* List entry for the sessions list inside ACG */
	struct list_head acg_sess_list_entry;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20))
	struct delayed_work hw_pending_work;
#else
	struct work_struct hw_pending_work;
#endif

	/* Name of attached initiator */
	const char *initiator_name;

	/* Unique session name: initiator name + optional _%d. */
	const char *sess_name;

	/* List entry of sessions per target */
	struct list_head sess_list_entry;

	/* Per target list entry for sessions registered in sysfs. */
	struct list_head sysfs_sess_list_entry;

	/* List entry for the list that keeps session, waiting for the init */
	struct list_head sess_init_list_entry;

	/*
	 * List entry for the list that keeps session, waiting for the shutdown
	 */
	struct list_head sess_shut_list_entry;

	/*
	 * Lists of deferred during session initialization commands.
	 * Protected by sess_list_lock.
	 */
	struct list_head init_deferred_cmd_list;
	struct list_head init_deferred_mcmd_list;

	/*
	 * Shutdown phase, one of SCST_SESS_SPH_* constants, unprotected.
	 * Async. relating to init_phase, must be a separate variable, because
	 * session could be unregistered before async. registration is finished.
	 */
	unsigned long shut_phase;

	/* Used if scst_unregister_session() called in wait mode */
	struct completion *shutdown_compl;

	/* sysfs release completion */
	struct completion *sess_kobj_release_cmpl;

#ifndef CONFIG_SCST_PROC
	unsigned int sess_kobj_ready:1;

	struct kobject sess_kobj; /* session sysfs entry */
#endif

	/*
	 * Functions and data for user callbacks from scst_register_session()
	 * and scst_unregister_session()
	 */
	void *reg_sess_data;
	void (*init_result_fn)(struct scst_session *sess, void *data,
				int result);
	void (*unreg_done_fn)(struct scst_session *sess);

#ifdef CONFIG_SCST_MEASURE_LATENCY
	spinlock_t lat_lock;
	uint64_t scst_time, tgt_time, dev_time;
	uint64_t processed_cmds;
	uint64_t min_scst_time, min_tgt_time, min_dev_time;
	uint64_t max_scst_time, max_tgt_time, max_dev_time;
	struct scst_ext_latency_stat sess_latency_stat[SCST_LATENCY_STATS_NUM];
#endif
};

/*
 * SCST_PR_ABORT_ALL TM function helper structure
 */
struct scst_pr_abort_all_pending_mgmt_cmds_counter {
	/*
	 * How many there are pending for this cmd SCST_PR_ABORT_ALL TM
	 * commands.
	 */
	atomic_t pr_abort_pending_cnt;

	/* Saved completion routine */
	void (*saved_cmd_done)(struct scst_cmd *cmd, int next_state,
		enum scst_exec_context pref_context);

	/*
	 * How many there are pending for this cmd SCST_PR_ABORT_ALL TM
	 * commands, which not yet aborted all affected commands and
	 * a completion to signal, when it's done.
	 */
	atomic_t pr_aborting_cnt;
	struct completion pr_aborting_cmpl;
};

/*
 * Structure to control commands' queuing and threads pool processing the queue
 */
struct scst_cmd_threads {
	spinlock_t cmd_list_lock;
	struct list_head active_cmd_list; /* commands queue */
	wait_queue_head_t cmd_list_waitQ;

	struct io_context *io_context; /* IO context of the threads pool */
	int io_context_refcnt;

	bool io_context_ready;

	/* io_context_mutex protects io_context and io_context_refcnt. */
	struct mutex io_context_mutex;

	spinlock_t thr_lock; /* Protects nr_threads and threads_list */
	int nr_threads; /* number of processing threads */
	struct list_head threads_list; /* processing threads */

	struct list_head lists_list_entry;
};

int scst_set_thr_cpu_mask(struct scst_cmd_threads *cmd_threads,
			  cpumask_t *cpu_mask);

/*
 * Used to execute cmd's in order of arrival, honoring SCSI task attributes
 */
struct scst_order_data {
	/*
	 * All fields, when needed, protected by sn_lock. Curr_sn must have
	 * the same type as expected_sn to overflow simultaneously!
	 */

	struct list_head skipped_sn_list;
	struct list_head deferred_cmd_list;

	spinlock_t sn_lock;

	int hq_cmd_count;

	/* Set if the prev cmd was ORDERED */
	bool prev_cmd_ordered;

	int def_cmd_count;
	unsigned int expected_sn;
	unsigned int curr_sn;
	int pending_simple_inc_expected_sn;

	atomic_t *cur_sn_slot;
	atomic_t sn_slots[15];

	/*
	 * Used to serialized scst_cmd_init_done() if the corresponding
	 * session's target template has multithreaded_init_done set
	 */
	spinlock_t init_done_lock;
};

struct scst_orig_sg_data {
	int *p_orig_sg_cnt;
	int orig_sg_cnt;
	struct scatterlist *orig_sg_entry;
	int orig_entry_offs, orig_entry_len;
};

/*
 * SCST command, analog of I_T_L_Q nexus or task
 */
struct scst_cmd {
	/* List entry for below *_cmd_threads */
	struct list_head cmd_list_entry;

	/* Pointer to lists of commands with the lock */
	struct scst_cmd_threads *cmd_threads;

	atomic_t cmd_ref;

	struct scst_session *sess;	/* corresponding session */

	atomic_t *cpu_cmd_counter;

	/* Cmd state, one of SCST_CMD_STATE_* constants */
	int state;

	/*************************************************************
	 ** Cmd's flags
	 *************************************************************/

	/*
	 * Set if cmd was sent for execution to optimize aborts waiting.
	 * Also it is a sign under contract that if inc_expected_sn_on_done
	 * is not set, the thread setting it is committing obligation to
	 * call scst_inc_expected_sn() after this cmd was sent to exec.
	 */
	unsigned int sent_for_exec:1;

	/* Set if cmd's SN was set */
	unsigned int sn_set:1;

	/* Set if increment expected_sn in cmd->scst_cmd_done() */
	unsigned int inc_expected_sn_on_done:1;

	/* Set if the cmd's action is completed */
	unsigned int completed:1;

	/* Set if we should ignore Unit Attention in scst_check_sense() */
	unsigned int ua_ignore:1;

	/* Set if cmd is being processed in atomic context */
	unsigned int atomic:1;

	/* Set if this command was sent in double UA possible state */
	unsigned int double_ua_possible:1;

	/* Set if DIF check for just read data was deferred to thread context */
	unsigned int deferred_dif_read_check:1;

	/* Set if this command contains status */
	unsigned int is_send_status:1;

	/* Set if cmd is being retried */
	unsigned int retry:1;

	/* Set if cmd is internally generated */
	unsigned int internal:1;

	/* Set if the device was blocked by scst_check_blocked_dev() */
	unsigned int unblock_dev:1;

	/* Set if scst_dec_on_dev_cmd() call is needed on the cmd's finish */
	unsigned int dec_on_dev_needed:1;

	/* Set if cmd is queued as hw pending */
	unsigned int cmd_hw_pending:1;

	/* Set if cmd has NACA bit set in CDB */
	unsigned int cmd_naca:1;

	/*
	 * Set if the target driver wants to alloc data buffers on its own.
	 * In this case tgt_alloc_data_buf() must be provided in the target
	 * driver template.
	 */
	unsigned int tgt_need_alloc_data_buf:1;

	/*
	 * Set by SCST if the custom data buffer allocated by the target driver
	 * or, for internal commands, by SCST core.
	 */
	unsigned int tgt_i_data_buf_alloced:1;

	/* Set if custom data buffer allocated by dev handler */
	unsigned int dh_data_buf_alloced:1;

	/*
	 * Set length of each member of dif_sg was normalized to match
	 * tgtt->hw_dif_same_sg_layout_required requirements
	 */
	unsigned int dif_sg_normalized:1;

	/* Set if the target driver called scst_set_expected() */
	unsigned int expected_values_set:1;

	/* Set if the SG buffer was modified by scst_adjust_sg*() */
	unsigned int sg_buff_modified:1;

	/* Set if the DIF SG buffer was modified by scst_adjust_sg*() */
	unsigned int dif_sg_buff_modified:1;

	/*
	 * Set if cmd buffer was vmallocated and copied from more
	 * then one sg chunk
	 */
	unsigned int sg_buff_vmallocated:1;

	/*
	 * Set if scst_cmd_init_stage1_done() called and the target
	 * want that preprocessing_done() will be called
	 */
	unsigned int preprocessing_only:1;

	/* Set if hq_cmd_count was incremented */
	unsigned int hq_cmd_inced:1;

	/*
	 * Set if scst_cmd_init_stage1_done() called and the target wants
	 * that the SN for the cmd won't be assigned until scst_restart_cmd()
	 */
	unsigned int set_sn_on_restart_cmd:1;

	/* Set if the cmd's must not use sgv cache for data buffer */
	unsigned int no_sgv:1;

	/*
	 * Set if target driver may need to call dma_sync_sg() or similar
	 * function before transferring cmd' data to the target device
	 * via DMA.
	 */
	unsigned int may_need_dma_sync:1;

	/* Set if the cmd was done or aborted out of its SN */
	unsigned int out_of_sn:1;

	/* Set if tgt_sn field is valid */
	unsigned int tgt_sn_set:1;

	/* Set if any direction residual is possible */
	unsigned int resid_possible:1;

	/* Set if DIF data should be included in the residual considerations */
	unsigned int tgt_dif_data_expected:1;

	/* Set if cmd is done */
	unsigned int done:1;

	/*
	 * Set if cmd is finished. Used under sess_list_lock to sync
	 * between scst_finish_cmd() and scst_abort_cmd()
	 */
	unsigned int finished:1;

	/* Set if cmd was pre-alloced by target driver */
	unsigned int pre_alloced:1;

	/* Set if scst_cmd_set_write_not_received_data_len() was called */
	unsigned int write_not_received_set:1;

	/* Set if cmd has LINK bit set in CDB */
	unsigned int cmd_linked:1;

	/**************************************************************/

	/* cmd's async flags */
	unsigned long cmd_flags;

	/*
	 * GFP mask with which memory on READ or WRITE data path for this cmd
	 * should be allocated, if the current context is not ATOMIC. Useful
	 * for cases like if this cmd required to not have any IO or FS calls
	 * on allocations, like for file systems mounted over scst_local's
	 * devices.
	 */
	gfp_t cmd_gfp_mask;

	/* Keeps status of cmd's status/data delivery to remote initiator */
	int delivery_status;

	struct scst_tgt_template *tgtt;	/* to save extra dereferences */
	struct scst_tgt *tgt;		/* to save extra dereferences */
	struct scst_device *dev;	/* to save extra dereferences */
	struct scst_dev_type *devt;	/* to save extra dereferences */

	/* corresponding I_T_L device for this cmd */
	struct scst_tgt_dev *tgt_dev;

	struct scst_order_data *cur_order_data; /* to save extra dereferences */

	uint64_t lun;			/* LUN for this cmd */

	unsigned long start_time;

	/* List entry for tgt_dev's deferred (SN, etc.) lists */
	struct list_head deferred_cmd_list_entry;

	/* Cmd's serial number, used to execute cmd's in order of arrival */
	unsigned int sn;

	/* The corresponding sn_slot in tgt_dev->sn_slots */
	atomic_t *sn_slot;

	/* List entry for sess's sess_cmd_list */
	struct list_head sess_cmd_list_entry;

	/*
	 * Used to found the cmd by scst_find_cmd_by_tag(). Set by the
	 * target driver on the cmd's initialization time
	 */
	uint64_t tag;

	uint32_t tgt_sn; /* SN set by target driver (for TM purposes) */

	uint8_t *cdb; /* Pointer on CDB. Points on cdb_buf for small CDBs. */
	unsigned short cdb_len;
	uint8_t cdb_buf[SCST_MAX_CDB_SIZE];

	uint8_t lba_off;	/* LBA offset in cdb */
	uint8_t lba_len;	/* LBA length in cdb */
	uint8_t len_off;	/* length offset in cdb */
	uint8_t len_len;	/* length length in cdb */
	uint32_t op_flags;	/* various flags of this opcode */
	const char *op_name;	/* op code SCSI full name */

	enum scst_cmd_queue_type queue_type;

	int timeout; /* CDB execution timeout in seconds */
	int retries; /* Amount of retries that will be done by SCSI mid-level */

	/*
	 * Data direction derived from the opcode and the ANSI T10 SCSI specs.
	 * One of SCST_DATA_* constants.
	 */
	scst_data_direction data_direction;

	/* Values supplied by the initiator in the transport layer header, if any */
	scst_data_direction expected_data_direction;
	int expected_transfer_len_full; /* both data and DIF tags, if any */
	int expected_out_transfer_len; /* for bidi writes */

	int64_t lba; /* LBA of this cmd */

	/*
	 * Cmd data length. Could be different from bufflen for commands like
	 * VERIFY, which transfer different amount of data (if any), than
	 * processed.
	 */
	int64_t data_len;

	/* Completion routine */
	void (*scst_cmd_done)(struct scst_cmd *cmd, int next_state,
		enum scst_exec_context pref_context);

	struct sgv_pool_obj *sgv;	/* data sgv object */
	int bufflen;			/* cmd buffer length */
	int sg_cnt;			/* SG segments count */
	struct scatterlist *sg;		/* cmd data buffer SG vector */

	struct sgv_pool_obj *dif_sgv;	/* DIF sgv object */
	struct scatterlist *dif_sg;	/* cmd DIF tags buffer SG vector */
	int dif_sg_cnt;			/* DIF SG segments count */

	/*
	 * Response data length in data buffer. Must not be set
	 * directly, use scst_set_resp_data_len() for that.
	 */
	int resp_data_len;

	/*
	 * Response data length adjusted on residual, i.e.
	 * min(expected_len, resp_len), if expected len set.
	 */
	int adjusted_resp_data_len;

	/*
	 * Data length to write, i.e. transfer from the initiator. Might be
	 * different from (out_)bufflen, if the initiator asked too big or too
	 * small expected(_out_)transfer_len.
	 */
	int write_len;

	/*
	 * Write sg and sg_cnt to point out either on sg/sg_cnt, or on
	 * out_sg/out_sg_cnt.
	 */
	struct scatterlist **write_sg;
	int *write_sg_cnt;

	/* scst_get_sg_buf_[first,next]() support */
	struct scatterlist *get_sg_buf_cur_sg_entry;
	int get_sg_buf_entry_num;

	/* Bidirectional transfers support */
	int out_bufflen;		/* WRITE buffer length */
	struct sgv_pool_obj *out_sgv;	/* WRITE sgv object */
	struct scatterlist *out_sg;	/* WRITE data buffer SG vector */
	int out_sg_cnt;			/* WRITE SG segments count */
	/* No out DIF tags buffer, because there's no BIDI command with them */

	/*
	 * Used if both target driver or SCST core for internal commands and
	 * dev handler request own memory allocation. In other cases, both
	 * are equal to sg and sg_cnt correspondingly.
	 *
	 * If target driver requests own memory allocations, it MUST use
	 * functions scst_cmd_get_tgt_sg*() to get sg and sg_cnt! Otherwise,
	 * it may use functions scst_cmd_get_sg*().
	 */
	struct scatterlist *tgt_i_sg;
	int tgt_i_sg_cnt;
	int tgt_i_dif_sg_cnt;
	struct scatterlist *tgt_i_dif_sg; /* DIF tags */
	/*
	 * There's no tgt_i_dif_sg_cnt, because it's supposed to be strictly
	 * bound to tgt_i_sg_cnt.
	 */
	struct scatterlist *tgt_out_sg;	/* bidirectional */
	int tgt_out_sg_cnt;		/* bidirectional */
	/* No out DIF tags buffer, because there's no BIDI command with them */

	/*
	 * The status fields in case of errors must be set using
	 * scst_set_cmd_error_status()!
	 */
	uint8_t status;		/* status byte from target device */
	uint8_t msg_status;	/* return status from host adapter itself */
	uint8_t host_status;	/* set by low-level driver to indicate status */
	uint8_t driver_status;	/* set by mid-level */

	/* DIF actions on this cmd */
	enum scst_dif_actions cmd_dif_actions;
#ifdef CONFIG_SCST_DIF_INJECT_CORRUPTED_TAGS
	uint32_t cmd_corrupt_dif_tag;
#endif

	uint8_t *sense;		/* pointer to sense buffer */
	unsigned short sense_valid_len; /* length of valid sense data */
	unsigned short sense_buflen; /* length of the sense buffer, if any */

	/* Start time when cmd was sent to rdy_to_xfer() or xmit_response() */
	unsigned long hw_pending_start;

	/* Used for storage of target driver or internal commands private stuff */
	void *tgt_i_priv;

	/* Used for storage of dev handler private stuff */
	void *dh_priv;

	/* List entry for dev's blocked_cmd_list */
	struct list_head blocked_cmd_list_entry;

	/* Used to retry commands in case of double UA */
	int dbl_ua_orig_resp_data_len, dbl_ua_orig_data_direction;

	/*
	 * List of the corresponding mgmt cmds, if any. Protected by
	 * sess_list_lock.
	 */
	struct list_head mgmt_cmd_list;

	/* Used to restore sg if it was modified by scst_adjust_sg*() */
	struct scst_orig_sg_data orig_sg, orig_dif_sg;

	/* Per opcode stuff */
	union {
		/* Counter of the corresponding SCST_PR_ABORT_ALL TM commands */
		struct scst_pr_abort_all_pending_mgmt_cmds_counter *pr_abort_counter;

		/*
		 * List of parsed data descriptors for commands operating with
		 * several lba and data_len pairs, like UNMAP, and its size
		 * in elements.
		 */
		struct {
			void *cmd_data_descriptors;
			int cmd_data_descriptors_cnt;
		};
	};

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
	char not_parsed_op_name[8];
#endif

#ifdef CONFIG_SCST_MEASURE_LATENCY
	uint64_t start, curr_start, parse_time, alloc_buf_time;
	uint64_t restart_waiting_time, rdy_to_xfer_time;
	uint64_t pre_exec_time, exec_time, dev_done_time;
	uint64_t xmit_time;
#endif

#ifdef CONFIG_SCST_DEBUG_TM
	/* Set if the cmd was delayed by task management debugging code */
	unsigned int tm_dbg_delayed:1;

	/* Set if the cmd must be ignored by task management debugging code */
	unsigned int tm_dbg_immut:1;
#endif
};

/*
 * Parameters for SCST management commands
 */
struct scst_rx_mgmt_params {
	int fn;
	uint64_t tag;
	const uint8_t *lun;
	int lun_len;
	uint32_t cmd_sn;
	int atomic;
	void *tgt_priv;
	unsigned char tag_set;
	unsigned char lun_set;
	unsigned char cmd_sn_set;
};

/*
 * A stub structure to link an management command and affected regular commands
 */
struct scst_mgmt_cmd_stub {
	struct scst_mgmt_cmd *mcmd;

	/* List entry in cmd->mgmt_cmd_list */
	struct list_head cmd_mgmt_cmd_list_entry;

	/* Set if the cmd was counted in  mcmd->cmd_done_wait_count */
	unsigned int done_counted:1;

	/* Set if the cmd was counted in  mcmd->cmd_finish_wait_count */
	unsigned int finish_counted:1;
};

/*
 * SCST task management structure
 */
struct scst_mgmt_cmd {
	/* List entry for *_mgmt_cmd_list */
	struct list_head mgmt_cmd_list_entry;

	struct scst_session *sess;

	atomic_t *cpu_cmd_counter;

	/* Mgmt cmd state, one of SCST_MCMD_STATE_* constants */
	int state;

	int fn; /* task management function */

	/* Set if device(s) should be unblocked after mcmd's finish */
	unsigned int needs_unblocking:1;
	unsigned int lun_set:1;		/* set, if lun field is valid */
	unsigned int cmd_sn_set:1;	/* set, if cmd_sn field is valid */
	unsigned int scst_get_called:1;	/* set, if scst_get() was called */
	/* Set if dev handler's task_mgmt_fn_received was called */
	unsigned int task_mgmt_fn_received_called:1;
	unsigned int mcmd_dropped:1; /* set if mcmd was dropped */

	/*
	 * Number of commands to finish before sending response,
	 * protected by scst_mcmd_lock
	 */
	int cmd_finish_wait_count;

	/*
	 * Number of commands to complete (done) before resetting reservation,
	 * protected by scst_mcmd_lock
	 */
	int cmd_done_wait_count;

	/* Number of completed commands, protected by scst_mcmd_lock */
	int completed_cmd_count;

	uint64_t lun;	/* LUN for this mgmt cmd */
	/* or (and for iSCSI) */
	uint64_t tag;	/* for ABORT TASK, tag of the cmd to abort */

	uint32_t cmd_sn; /* affected command's highest SN */

	/* corresponding cmd (to be aborted, found by tag) */
	struct scst_cmd *cmd_to_abort;

	/* corresponding device for this mgmt cmd (found by lun or by tag) */
	struct scst_tgt_dev *mcmd_tgt_dev;

	/* completion status, one of the SCST_MGMT_STATUS_* constants */
	int status;

	/* Used for storage of target driver private stuff or origin PR cmd */
	union {
		void *tgt_priv;
		struct scst_cmd *origin_pr_cmd;
	};
};

/*
 * Persistent reservations registrant
 */
struct scst_dev_registrant {
	uint8_t *transport_id;
	uint16_t rel_tgt_id;
	__be64 key;

	/* tgt_dev (I_T nexus) for this registrant, if any */
	struct scst_tgt_dev *tgt_dev;

	/* List entry for dev_registrants_list */
	struct list_head dev_registrants_list_entry;

	/* 2 auxiliary fields used to rollback changes for errors, etc. */
	struct list_head aux_list_entry;
	__be64 rollback_key;
};

/*
 * SCST device
 */
struct scst_device {
	unsigned int type;	/* SCSI type of the device */

	/*************************************************************
	 ** Dev's flags. Updates serialized by dev_lock or suspended
	 ** activity
	 *************************************************************/

	/* Set if double reset UA is possible */
	unsigned int dev_double_ua_possible:1;

	/* If set, dev is read only */
	unsigned int dev_rd_only:1;

	/* Set, if a strictly serialized cmd is waiting blocked */
	unsigned int strictly_serialized_cmd_waiting:1;

	/*
	 * Set, if this device is being unregistered. Useful to let sysfs
	 * attributes know when they should exit immediately to prevent
	 * possible deadlocks with their device unregistration waiting for
	 * their kobj last put.
	 */
	unsigned int dev_unregistering:1;

	/* Set if this device does not support DIF IP checking */
	unsigned int dev_dif_ip_not_supported:1;

	/**************************************************************/

	/*************************************************************
	 ** Dev's control mode page related values. Updates serialized
	 ** by device blocking. Since device blocking protects only
	 ** commands on the execution stage, in all other read cases
	 ** use ACCESS_ONCE(), if necessary. Modified independently
	 ** to the above fields, hence the alignment.
	 *************************************************************/

	unsigned int queue_alg:4 __aligned(sizeof(long));
	unsigned int tst:3;
	unsigned int qerr:2;
	unsigned int tmf_only:1;
	unsigned int tas:1;
	unsigned int swp:1;
	unsigned int d_sense:1;
	unsigned int dpicz:1;
	unsigned int ato:1;

	/**
	 ** Saved and default versions of them, which supported. TST is not
	 ** among them, because it's hard to switch curr_order_data on the
	 ** fly. To ensure that no commands lost, we need to flush the previous
	 ** curr_order_data at first and with one being active command (MODE
	 ** SELECT), we don't have facility for that at the moment. Suspending
	 ** activities will hang waiting for the active MODE SELECT. ToDo.
	 **/

	unsigned int queue_alg_saved:4;
	unsigned int queue_alg_default:4;

	unsigned int tmf_only_saved:1;
	unsigned int tmf_only_default:1;

	unsigned int qerr_saved:2;
	unsigned int qerr_default:2;

	unsigned int tas_saved:1;
	unsigned int tas_default:1;

	unsigned int swp_saved:1;
	unsigned int swp_default:1;

	unsigned int d_sense_saved:1;
	unsigned int d_sense_default:1;

	unsigned int dpicz_saved:1;
	unsigned int dpicz_default:1;

	/*
	 * Set if device implements own ordered commands management. If not set
	 * and queue_alg is SCST_QUEUE_ALG_0_RESTRICTED_REORDER, expected_sn
	 * will be incremented only after commands finished.
	 */
	unsigned int has_own_order_mgmt:1;

	/**************************************************************/

	/*
	 * SCST_DIF_CHECK_APP_TAG (to match usage in the xPROTECT parsing
	 * routines), if app tag is checked, or 0 otherwise. Might be used
	 * as bool.
	 */
	unsigned int dif_app_chk;

	/*
	 * SCST_DIF_CHECK_REF_TAG (to match usage in the xPROTECT parsing
	 * routines), if ref tag is checked, or 0 otherwise. Might be used
	 * as bool.
	 */
	unsigned int dif_ref_chk;

	/**************************************************************/

	/*
	 * Device block size and block shift if fixed size blocks used. Supposed
	 * to be read-only or serialized the same way as MODE pages changes.
	 */
	int block_size;
	int block_shift;

	struct scst_dev_type *handler;	/* corresponding dev handler */

	/* Used for storage of dev handler private stuff */
	void *dh_priv;

	/* Corresponding real SCSI device, could be NULL for virtual devices */
	struct scsi_device *scsi_dev;

	/* Device lock */
	spinlock_t dev_lock ____cacheline_aligned_in_smp;

#ifdef CONFIG_SCST_PER_DEVICE_CMD_COUNT_LIMIT
	/* How many cmds alive on this dev */
	atomic_t dev_cmd_count;
#endif

	/*
	 * How many times device was blocked for new cmds execution.
	 * Protected by dev_lock.
	 */
	int block_count;

	/*
	 * How many there are "on_dev" commands, i.e. ones who passed
	 * scst_check_blocked_dev(). Protected by dev_lock.
	 */
	int on_dev_cmd_count;

	/* Memory limits for this device */
	struct scst_mem_lim dev_mem_lim;

	/* List of commands with lock, if dedicated threads are used */
	struct scst_cmd_threads dev_cmd_threads;

	/*************************************************************
	 ** T10-PI fields. Read-only, hence no protection.
	 *************************************************************/

	enum scst_dif_mode dev_dif_mode;
	int dev_dif_type; /* SCSI DIF type */

	/*
	 * Callback to process DIF tags by SCST as required by device
	 * formatting and *protect cmd's bits. Supposed to return 0 on
	 * success, i.e. when cmd processing should proceed normally, or
	 * negative error code otherwise, i.e. when cmd processing should
	 * be stopped and status send to its initiator.
	 */
	int (*dev_dif_fn)(struct scst_cmd *cmd);

	__be16 dev_dif_static_app_tag; /* fixed APP TAG for all blocks in dev */
	__be32 dev_dif_static_app_ref_tag; /* fixed APP TAG part from REF
					    * TAG for all blocks in dev.
					    * Valid only with dif type 3 */

	/* Cache to optimize scst_parse_*protect() routines */
	enum scst_dif_actions dev_dif_rd_actions;
	enum scst_dif_actions dev_dif_wr_actions;
	enum scst_dif_actions dev_dif_rd_prot0_actions;
	enum scst_dif_actions dev_dif_wr_prot0_actions;
	enum scst_dif_actions dev_dif_vr_actions;

	/* Set if reserved via the SPC-2 SCSI RESERVE command. */
	struct scst_session *reserved_by;

	/**********************************************************************
	 * Persistent reservation fields. Protected as follows:
	 * - Reading PR data must be protected via scst_pr_read_lock() /
	 *   scst_pr_read_unlock().
	 * - Modifying PR data modifications must be protected via
	 *   scst_pr_write_lock() / scst_pr_write_unlock().
	 **********************************************************************/

	/*
	 * Set if dev is persistently reserved. Modified independently
	 * to the above field, hence the alignment.
	 */
	unsigned short pr_is_set:1 __aligned(sizeof(long));

	/* True if persist through power loss is activated. */
	unsigned short pr_aptpl:1;

	/* Whether or not pr_file_name has been modified via sysfs. */
	unsigned int pr_file_name_is_set:1;

	/* Persistent reservation type */
	uint8_t pr_type;

	/* Persistent reservation scope */
	uint8_t pr_scope;

	/* Mutex to protect PR operations */
	struct mutex dev_pr_mutex;

	/* Persistent reservation generation value */
	uint32_t pr_generation;

	/* Reference to registrant - persistent reservation holder */
	struct scst_dev_registrant *pr_holder;

	/* List of dev's registrants */
	struct list_head dev_registrants_list;

	/* End of persistent reservation fields protected by dev_pr_mutex. */

	/*
	 * Count of connected tgt_devs from transports, which don't support
	 * PRs, i.e. don't have get_initiator_port_transport_id(). Protected
	 * by scst_mutex.
	 */
	int not_pr_supporting_tgt_devs_num;

	struct scst_order_data dev_order_data;

	/*
	 * Where to save persistent reservation information. Protected by
	 * dev_pr_mutex.
	 */
	char *pr_file_name;
	char *pr_file_name1;

	/**************************************************************/

	/* List of blocked commands, protected by dev_lock. */
	struct list_head blocked_cmd_list;

	/* MAXIMUM WRITE SAME LENGTH in bytes */
	uint64_t max_write_same_len;

	/* A list entry used during TM */
	struct list_head tm_dev_list_entry;

	int virt_id; /* virtual device internal ID */

	/* Pointer to virtual device name, for convenience only */
	char *virt_name;

	struct list_head dev_list_entry; /* list entry in global devices list */

	/*
	 * List of tgt_dev's, one per session, protected by scst_mutex or
	 * dev_lock for reads and both for writes
	 */
	struct list_head dev_tgt_dev_list;

	/* List of acg_dev's, one per acg, protected by scst_mutex */
	struct list_head dev_acg_dev_list;

	/* Number of threads in the device's threads pools */
	int threads_num;

	/* Threads pool type of the device. Valid only if threads_num > 0. */
	enum scst_dev_type_threads_pool_type threads_pool_type;

#ifndef CONFIG_SCST_PROC
	/* sysfs release completion */
	struct completion *dev_kobj_release_cmpl;

	struct kobject dev_kobj; /* device sysfs entry */
	struct kobject *dev_exp_kobj; /* exported groups */

	/* Export number in the dev's sysfs list. Protected by scst_mutex */
	int dev_exported_lun_num;
#endif
};

/*
 * Used to clearly dispose async io_context
 */
struct scst_async_io_context_keeper {
	struct kref aic_keeper_kref;
	bool aic_ready;
	struct io_context *aic;
	struct task_struct *aic_keeper_thr;
	wait_queue_head_t aic_keeper_waitQ;
};

/*
 * Used to store per-session specific device information, analog of
 * SCSI I_T_L nexus.
 */
struct scst_tgt_dev {
	/* List entry in sess->sess_tgt_dev_list */
	struct list_head sess_tgt_dev_list_entry;

	struct scst_device *dev; /* to save extra dereferences */
	uint64_t lun;		 /* to save extra dereferences */

	/*
	 * Extra flags in GFP mask for data buffers allocations of this
	 * tgt_dev's cmds
	 */
	gfp_t tgt_dev_gfp_mask;

	/* SGV pool from which buffers of this tgt_dev's cmds should be allocated */
	struct sgv_pool *pool;

	/* Max number of allowed in this tgt_dev SG segments */
	int max_sg_cnt;

	/*************************************************************
	 ** Tgt_dev's flags
	 *************************************************************/

	/* Set if tgt_dev is read only (to save extra dereferences) */
	unsigned int tgt_dev_rd_only:1;

	/* Set if the corresponding context should be atomic */
	unsigned int tgt_dev_after_init_wr_atomic:1;
	unsigned int tgt_dev_after_exec_atomic:1;

	/* Set if tgt_dev uses clustered SGV pool */
	unsigned int tgt_dev_clust_pool:1;

	/* Taken from the target on initialization to save a cache miss */
	unsigned hw_dif_same_sg_layout_required:1;

	/**************************************************************/

	/*
	 * Tgt_dev's async flags. Modified independently to the neighbour
	 * fields.
	 */
	unsigned long tgt_dev_flags;

	/* Used for storage of dev handler private stuff */
	void *dh_priv;

	/* Pointer to function to compute DIF guard tag */
	__be16 (*tgt_dev_dif_crc_fn)(const void *buffer, unsigned int len);

	/*
	 * Guard tags format, one of SCST_DIF_GUARD_FORMAT_* constants.
	 * Put here to save extra dereferences, this space isn't used anyway.
	 */
	int tgt_dev_dif_guard_format;

	/* How many cmds alive on this dev in this session */
	atomic_t tgt_dev_cmd_count ____cacheline_aligned_in_smp;

	/* ALUA command filter */
	bool (*alua_filter)(struct scst_cmd *cmd);

	struct scst_order_data *curr_order_data;
	struct scst_order_data tgt_dev_order_data;

	/* Pointer to lists of commands with the lock */
	struct scst_cmd_threads *active_cmd_threads;

	/* Union to save some CPU cache footprint */
	union {
		struct {
			/* Copy to save fast path dereference */
			struct io_context *async_io_context;

			struct scst_async_io_context_keeper *aic_keeper;
		};

		/* Lists of commands with lock, if dedicated threads are used */
		struct scst_cmd_threads tgt_dev_cmd_threads;
	};

	spinlock_t tgt_dev_lock;	/* per-session device lock */

	/* List of UA's for this device, protected by tgt_dev_lock */
	struct list_head UA_list;

	struct scst_session *sess;	/* corresponding session */
	struct scst_acg_dev *acg_dev;	/* corresponding acg_dev */

	/* Reference to registrant to find quicker */
	struct scst_dev_registrant *registrant;

	/* List entry in dev->dev_tgt_dev_list */
	struct list_head dev_tgt_dev_list_entry;

	/* Internal tmp list entry. User must hold scst_mutex. */
	struct list_head extra_tgt_dev_list_entry;

	/* Set if INQUIRY DATA HAS CHANGED UA is needed */
	unsigned int inq_changed_ua_needed:1;

	/* How many DIF failures detected on this tgt_dev on the corresponding stage */
	atomic_t tgt_dev_dif_app_failed_tgt, tgt_dev_dif_ref_failed_tgt, tgt_dev_dif_guard_failed_tgt;
	atomic_t tgt_dev_dif_app_failed_scst, tgt_dev_dif_ref_failed_scst, tgt_dev_dif_guard_failed_scst;
	atomic_t tgt_dev_dif_app_failed_dev, tgt_dev_dif_ref_failed_dev, tgt_dev_dif_guard_failed_dev;

	/*
	 * Stored Unit Attention sense and its length for possible
	 * subsequent REQUEST SENSE. Both protected by tgt_dev_lock.
	 */
	unsigned short tgt_dev_valid_sense_len;
	uint8_t tgt_dev_sense[SCST_SENSE_BUFFERSIZE];

#ifndef CONFIG_SCST_PROC
	/* sysfs release completion */
	struct completion *tgt_dev_kobj_release_cmpl;

	struct kobject tgt_dev_kobj; /* sessions' LUNs sysfs entry */
#endif

#ifdef CONFIG_SCST_MEASURE_LATENCY
	/*
	 * Protected by sess->lat_lock.
	 */
	uint64_t scst_time, tgt_time, dev_time;
	uint64_t processed_cmds;
	struct scst_ext_latency_stat dev_latency_stat[SCST_LATENCY_STATS_NUM];
#endif
};

/*
 * Used to store ACG-specific device information, like LUN
 */
struct scst_acg_dev {
	struct scst_device *dev; /* corresponding device */

	uint64_t lun; /* device's LUN in this acg */

	/* If set, the corresponding LU is read only */
	unsigned int acg_dev_rd_only:1;

	/* Guard tags format, one of SCST_DIF_GUARD_FORMAT_* constants */
	int acg_dev_dif_guard_format;

	struct scst_acg *acg; /* parent acg */

	/* List entry in dev->dev_acg_dev_list */
	struct list_head dev_acg_dev_list_entry;

	/* List entry in acg->acg_dev_list */
	struct list_head acg_dev_list_entry;

#ifndef CONFIG_SCST_PROC
	struct kobject acg_dev_kobj; /* targets' LUNs sysfs entry */

	/* sysfs release completion */
	struct completion *acg_dev_kobj_release_cmpl;

	/* Name of the link to the corresponding LUN */
	char acg_dev_link_name[20];
#endif
};

/*
 * ACG - access control group. Used to store group related
 * control information.
 */
struct scst_acg {
	/* One more than the number of sessions in acg_sess_list */
	struct kref acg_kref;

	/* Owner target */
	struct scst_tgt *tgt;

	/* List of acg_dev's in this acg, protected by scst_mutex */
	struct list_head acg_dev_list;

	/* List of attached sessions, protected by scst_mutex */
	struct list_head acg_sess_list;

	/* List of attached acn's, protected by scst_mutex */
	struct list_head acn_list;

	/* List entry in acg_lists (procfs) or tgt_acg_list (sysfs) */
	struct list_head acg_list_entry;

	/* Name of this acg */
	const char *acg_name;

#ifdef CONFIG_SCST_PROC
	/* The pointer to the /proc directory entry */
	struct proc_dir_entry *acg_proc_root;
#endif

	/* Type of I/O initiators grouping */
	int acg_io_grouping_type;

	/* CPU affinity for threads in this ACG */
	cpumask_t acg_cpu_mask;

	unsigned int tgt_acg:1;

/* Not a black hole */
#define SCST_ACG_BLACK_HOLE_NONE	0

/* Immediately abort all coming commands */
#define SCST_ACG_BLACK_HOLE_CMD		1

/*
 * Immediately abort all coming commands and drop all coming TM commands.
 *
 * CAUTION! With some target drivers it can cause internal resources
 * leaks, so don't abuse this option!
 */
#define SCST_ACG_BLACK_HOLE_ALL		2

/* Immediately abort all coming data transfer commands */
#define SCST_ACG_BLACK_HOLE_DATA_CMD	3

/*
 * Immediately abort all coming data transfer commands and drop all
 * coming TM commands.
 *
 * CAUTION! With some target drivers it can cause internal resources
 * leaks, so don't abuse this option!
 */
#define SCST_ACG_BLACK_HOLE_DATA_MCMD	4
	volatile int acg_black_hole_type;

	/* sysfs release completion */
	struct completion *acg_kobj_release_cmpl;

#ifndef CONFIG_SCST_PROC
	struct kobject acg_kobj; /* targets' ini_groups sysfs entry */

	struct kobject *luns_kobj;
	struct kobject *initiators_kobj;
#endif

	enum scst_lun_addr_method addr_method;
};

/*
 * ACN - access control name. Used to store names, by which
 * incoming sessions will be assigned to appropriate ACG.
 */
struct scst_acn {
	struct scst_acg *acg; /* owner ACG */

	const char *name; /* initiator's name */

	/* List entry in acg->acn_list */
	struct list_head acn_list_entry;

	/* sysfs file attributes */
	struct kobj_attribute *acn_attr;
};

/**
 * struct scst_dev_group - A group of SCST devices (struct scst_device).
 * @name:        Name of this device group.
 * @entry:       Entry in scst_dev_group_list.
 * @dev_list:    List of scst_dg_dev structures; protected by scst_mutex.
 * @tg_list:     List of scst_target_group structures; protected by scst_mutex.
 * @kobj:        For making this object visible in sysfs.
 * @dev_kobj:    Sysfs devices directory.
 * @tg_kobj:     Sysfs target groups directory.
 *
 * Each device is member of zero or one device groups. With each device group
 * there are zero or more target groups associated.
 */
struct scst_dev_group {
	char			*name;
	struct list_head	entry;
	struct list_head	dev_list;
	struct list_head	tg_list;
	struct kobject		kobj;
	struct kobject		*dev_kobj;
	struct kobject		*tg_kobj;
};

/**
 * struct scst_dg_dev - A node in scst_dev_group.dev_list.
 */
struct scst_dg_dev {
	struct list_head	entry;
	struct scst_device	*dev;
};

/**
 * struct scst_target_group - A group of SCSI targets (struct scst_tgt).
 * @dg:          Pointer to the device group that contains this target group.
 * @name:        Name of this target group.
 * @group_id:    SPC-4 target port group ID.
 * @state:       SPC-4 target port group ALUA state.
 * @preferred:   Value of the SPC-4 target port group PREF attribute.
 * @entry:       Entry in scst_dev_group.tg_list.
 * @tgt_list:    list of scst_tg_tgt elements; protected by scst_mutex.
 * @kobj:        For making this object visible in sysfs.
 *
 * Such a group is either a primary target port group or a secondary
 * port group. See also SPC-4 for more information.
 */
struct scst_target_group {
	struct scst_dev_group	*dg;
	char			*name;
	uint16_t		group_id;
	enum scst_tg_state	state;
	bool			preferred;
	struct list_head	entry;
	struct list_head	tgt_list;
	struct kobject		kobj;
};

/**
 * struct scst_tg_tgt - A node in scst_target_group.tgt_list.
 *
 * Such a node can either represent a local storage target (struct scst_tgt)
 * or a storage target on another system running SCST. In the former case tgt
 * != NULL and rel_tgt_id is ignored. In the latter case tgt == NULL and
 * rel_tgt_id is relevant.
 */
struct scst_tg_tgt {
	struct list_head	entry;
	struct scst_target_group *tg;
	struct kobject          kobj;
	struct scst_tgt		*tgt;
	char			*name;
	uint16_t		rel_tgt_id;
};

/*
 * Used to store per-session UNIT ATTENTIONs
 */
struct scst_tgt_dev_UA {
	/* List entry in tgt_dev->UA_list */
	struct list_head UA_list_entry;

	/* Set if UA is global for session */
	unsigned short global_UA:1;

	/* Unit Attention valid sense len */
	unsigned short UA_valid_sense_len;
	/* Unit Attention sense buf */
	uint8_t UA_sense_buffer[SCST_SENSE_BUFFERSIZE];
};

/* Used to deliver AENs */
struct scst_aen {
	int event_fn; /* AEN fn */

	struct scst_session *sess;	/* corresponding session */
	__be64 lun;			/* corresponding LUN in SCSI form */

	union {
		/* SCSI AEN data */
		struct {
			int aen_sense_len;
			uint8_t aen_sense[SCST_STANDARD_SENSE_LEN];
		};
	};

	/* Keeps status of AEN's delivery to remote initiator */
	int delivery_status;
};

#define SCST_OD_DEFAULT_CONTROL_BYTE	0

struct scst_opcode_descriptor {
	uint16_t od_serv_action;
	uint8_t od_opcode;
	uint8_t od_serv_action_valid:1;
	uint8_t od_support:3; /* SUPPORT bits */
	uint16_t od_cdb_size;
	uint8_t od_comm_specific_timeout;
	uint32_t od_nominal_timeout;
	uint32_t od_recommended_timeout;
	uint8_t od_cdb_usage_bits[];
} __packed;

extern const struct scst_opcode_descriptor scst_op_descr_log_select;
extern const struct scst_opcode_descriptor scst_op_descr_log_sense;
extern const struct scst_opcode_descriptor scst_op_descr_mode_select6;
extern const struct scst_opcode_descriptor scst_op_descr_mode_sense6;
extern const struct scst_opcode_descriptor scst_op_descr_mode_select10;
extern const struct scst_opcode_descriptor scst_op_descr_mode_sense10;
extern const struct scst_opcode_descriptor scst_op_descr_rtpg;
extern const struct scst_opcode_descriptor scst_op_descr_stpg;
extern const struct scst_opcode_descriptor scst_op_descr_send_diagnostic;

extern const struct scst_opcode_descriptor scst_op_descr_inquiry;
extern const struct scst_opcode_descriptor scst_op_descr_tur;
extern const struct scst_opcode_descriptor scst_op_descr_reserve6;
extern const struct scst_opcode_descriptor scst_op_descr_release6;
extern const struct scst_opcode_descriptor scst_op_descr_reserve10;
extern const struct scst_opcode_descriptor scst_op_descr_release10;
extern const struct scst_opcode_descriptor scst_op_descr_pr_in;
extern const struct scst_opcode_descriptor scst_op_descr_pr_out;
extern const struct scst_opcode_descriptor scst_op_descr_report_luns;
extern const struct scst_opcode_descriptor scst_op_descr_request_sense;
extern const struct scst_opcode_descriptor scst_op_descr_report_supp_tm_fns;
extern const struct scst_opcode_descriptor scst_op_descr_report_supp_opcodes;

#define SCST_OPCODE_DESCRIPTORS			\
	&scst_op_descr_inquiry,			\
	&scst_op_descr_tur,			\
	&scst_op_descr_reserve6,		\
	&scst_op_descr_release6,		\
	&scst_op_descr_reserve10,		\
	&scst_op_descr_release10,		\
	&scst_op_descr_pr_in,			\
	&scst_op_descr_pr_out,			\
	&scst_op_descr_report_luns,		\
	&scst_op_descr_request_sense,		\
	&scst_op_descr_report_supp_opcodes,	\
	&scst_op_descr_report_supp_tm_fns,


#ifndef smp_mb__after_set_bit
/* There is no smp_mb__after_set_bit() in the kernel */
#define smp_mb__after_set_bit()                 smp_mb()
#endif

/*
 * Registers target template.
 * Returns 0 on success or appropriate error code otherwise.
 */
int __scst_register_target_template(struct scst_tgt_template *vtt,
	const char *version);
static inline int scst_register_target_template(struct scst_tgt_template *vtt)
{
	return __scst_register_target_template(vtt, SCST_INTERFACE_VERSION);
}

/*
 * Registers target template, non-GPL version.
 * Returns 0 on success or appropriate error code otherwise.
 *
 * Note: *vtt must be static!
 */
int __scst_register_target_template_non_gpl(struct scst_tgt_template *vtt,
	const char *version);
static inline int scst_register_target_template_non_gpl(
	struct scst_tgt_template *vtt)
{
	return __scst_register_target_template_non_gpl(vtt,
		SCST_INTERFACE_VERSION);
}

void scst_unregister_target_template(struct scst_tgt_template *vtt);

struct scst_tgt *scst_register_target(struct scst_tgt_template *vtt,
	const char *target_name);
void scst_unregister_target(struct scst_tgt *tgt);

struct scst_session *scst_register_session(struct scst_tgt *tgt, int atomic,
	const char *initiator_name, void *tgt_priv, void *result_fn_data,
	void (*result_fn)(struct scst_session *sess, void *data, int result));
struct scst_session *scst_register_session_non_gpl(struct scst_tgt *tgt,
	const char *initiator_name, void *tgt_priv);
void scst_unregister_session(struct scst_session *sess, int wait,
	void (*unreg_done_fn)(struct scst_session *sess));
void scst_unregister_session_non_gpl(struct scst_session *sess);

int __scst_register_dev_driver(struct scst_dev_type *dev_type,
	const char *version);
static inline int scst_register_dev_driver(struct scst_dev_type *dev_type)
{
	return __scst_register_dev_driver(dev_type, SCST_INTERFACE_VERSION);
}
void scst_unregister_dev_driver(struct scst_dev_type *dev_type);

int __scst_register_virtual_dev_driver(struct scst_dev_type *dev_type,
	const char *version);
/*
 * Registers dev handler driver for virtual devices (eg VDISK).
 * Returns 0 on success or appropriate error code otherwise.
 */
static inline int scst_register_virtual_dev_driver(
	struct scst_dev_type *dev_type)
{
	return __scst_register_virtual_dev_driver(dev_type,
		SCST_INTERFACE_VERSION);
}

void scst_unregister_virtual_dev_driver(struct scst_dev_type *dev_type);

bool scst_initiator_has_luns(struct scst_tgt *tgt, const char *initiator_name);

struct scst_cmd *scst_rx_cmd(struct scst_session *sess,
	const uint8_t *lun, int lun_len, const uint8_t *cdb,
	unsigned int cdb_len, bool atomic);
int scst_rx_cmd_prealloced(struct scst_cmd *cmd, struct scst_session *sess,
	const uint8_t *lun, int lun_len, const uint8_t *cdb,
	unsigned int cdb_len, bool atomic);
void scst_cmd_init_done(struct scst_cmd *cmd,
	enum scst_exec_context pref_context);

/*
 * Notifies SCST that the driver finished the first stage of the command
 * initialization, and the command is ready for execution, but after
 * SCST done the command's preprocessing preprocessing_done() function
 * should be called. The second argument sets preferred command execution
 * context. See SCST_CONTEXT_* constants for details.
 *
 * See comment for scst_cmd_init_done() for the serialization requirements.
 */
static inline void scst_cmd_init_stage1_done(struct scst_cmd *cmd,
	enum scst_exec_context pref_context, int set_sn)
{
	cmd->preprocessing_only = 1;
	cmd->set_sn_on_restart_cmd = !set_sn;
	scst_cmd_init_done(cmd, pref_context);
}

void scst_restart_cmd(struct scst_cmd *cmd, int status,
	enum scst_exec_context pref_context);

void scst_rx_data(struct scst_cmd *cmd, int status,
	enum scst_exec_context pref_context);

void scst_tgt_cmd_done(struct scst_cmd *cmd,
	enum scst_exec_context pref_context);

int scst_rx_mgmt_fn(struct scst_session *sess,
	const struct scst_rx_mgmt_params *params);

static inline void scst_rx_mgmt_params_init(
		struct scst_rx_mgmt_params *params)
{
	memset(params, 0, sizeof(*params));
}

/*
 * Creates new management command using tag and sends it for execution.
 * Can be used for SCST_ABORT_TASK only.
 * Must not be called in parallel with scst_unregister_session() for the
 * same sess. Returns 0 for success, error code otherwise.
 *
 * Obsolete in favor of scst_rx_mgmt_fn()
 */
static inline int scst_rx_mgmt_fn_tag(struct scst_session *sess, int fn,
	uint64_t tag, int atomic, void *tgt_priv)
{
	struct scst_rx_mgmt_params params;

	BUG_ON(fn != SCST_ABORT_TASK);

	scst_rx_mgmt_params_init(&params);

	params.fn = fn;
	params.tag = tag;
	params.tag_set = 1;
	params.atomic = atomic;
	params.tgt_priv = tgt_priv;
	return scst_rx_mgmt_fn(sess, &params);
}

/*
 * Creates new management command using LUN and sends it for execution.
 * Currently can be used for any fn, except SCST_ABORT_TASK.
 * Must not be called in parallel with scst_unregister_session() for the
 * same sess. Returns 0 for success, error code otherwise.
 *
 * Obsolete in favor of scst_rx_mgmt_fn()
 */
static inline int scst_rx_mgmt_fn_lun(struct scst_session *sess, int fn,
	const void *lun, int lun_len, int atomic, void *tgt_priv)
{
	struct scst_rx_mgmt_params params;

	BUG_ON(fn == SCST_ABORT_TASK);

	scst_rx_mgmt_params_init(&params);

	params.fn = fn;
	params.lun = lun;
	params.lun_len = lun_len;
	params.lun_set = !!lun;
	params.atomic = atomic;
	params.tgt_priv = tgt_priv;
	return scst_rx_mgmt_fn(sess, &params);
}

int scst_get_cdb_info(struct scst_cmd *cmd);

int scst_set_cmd_error_status(struct scst_cmd *cmd, int status);
int scst_set_cmd_error(struct scst_cmd *cmd, int key, int asc, int ascq);
int scst_set_cmd_error_and_inf(struct scst_cmd *cmd, int key, int asc,
			       int ascq, uint64_t information);
void scst_set_busy(struct scst_cmd *cmd);

void scst_check_convert_sense(struct scst_cmd *cmd);

void scst_set_initial_UA(struct scst_session *sess, int key, int asc, int ascq);

void scst_capacity_data_changed(struct scst_device *dev);

struct scst_cmd *scst_find_cmd_by_tag(struct scst_session *sess, uint64_t tag);
struct scst_cmd *scst_find_cmd(struct scst_session *sess, void *data,
			       int (*cmp_fn)(struct scst_cmd *cmd,
					     void *data));

enum dma_data_direction scst_to_dma_dir(int scst_dir);
enum dma_data_direction scst_to_tgt_dma_dir(int scst_dir);

int scst_register_virtual_device(struct scst_dev_type *dev_handler,
	const char *dev_name);
void scst_unregister_virtual_device(int id);

/*
 * Get/Set functions for tgt's sg_tablesize
 */
static inline int scst_tgt_get_sg_tablesize(struct scst_tgt *tgt)
{
	return tgt->sg_tablesize;
}

static inline void scst_tgt_set_sg_tablesize(struct scst_tgt *tgt, int val)
{
	tgt->sg_tablesize = val;
}

/*
 * Get/Set functions for tgt's target private data
 */
static inline void *scst_tgt_get_tgt_priv(struct scst_tgt *tgt)
{
	return tgt->tgt_priv;
}

static inline void scst_tgt_set_tgt_priv(struct scst_tgt *tgt, void *val)
{
	tgt->tgt_priv = val;
}

/*
 * Get/Set functions for tgt's tgt_dif_supported
 */
static inline bool scst_tgt_get_dif_supported(struct scst_tgt *tgt)
{
	return tgt->tgt_dif_supported;
}

static inline void scst_tgt_set_dif_supported(struct scst_tgt *tgt, bool val)
{
	tgt->tgt_dif_supported = !!val;
}

/*
 * Get/Set functions for tgt's tgt_hw_dif_type1_supported
 */
static inline bool scst_tgt_get_hw_dif_type1_supported(struct scst_tgt *tgt)
{
	return tgt->tgt_hw_dif_type1_supported;
}

static inline void scst_tgt_set_hw_dif_type1_supported(struct scst_tgt *tgt, bool val)
{
	tgt->tgt_hw_dif_type1_supported = !!val;
}

/*
 * Get/Set functions for tgt's tgt_hw_dif_type2_supported
 */
static inline bool scst_tgt_get_hw_dif_type2_supported(struct scst_tgt *tgt)
{
	return tgt->tgt_hw_dif_type2_supported;
}

static inline void scst_tgt_set_hw_dif_type2_supported(struct scst_tgt *tgt, bool val)
{
	tgt->tgt_hw_dif_type2_supported = !!val;
}

/*
 * Get/Set functions for tgt's tgt_hw_dif_type3_supported
 */
static inline bool scst_tgt_get_hw_dif_type3_supported(struct scst_tgt *tgt)
{
	return tgt->tgt_hw_dif_type3_supported;
}

static inline void scst_tgt_set_hw_dif_type3_supported(struct scst_tgt *tgt, bool val)
{
	tgt->tgt_hw_dif_type3_supported = !!val;
}

/*
 * Get/Set functions for tgt's tgt_hw_dif_ip_supported
 */
static inline bool scst_tgt_get_hw_dif_ip_supported(struct scst_tgt *tgt)
{
	return tgt->tgt_hw_dif_ip_supported;
}

static inline void scst_tgt_set_hw_dif_ip_supported(struct scst_tgt *tgt, bool val)
{
	tgt->tgt_hw_dif_ip_supported = !!val;
}

/*
 * Get/Set functions for tgt's tgt_hw_dif_same_sg_layout_required
 */
static inline bool scst_tgt_get_hw_dif_same_sg_layout_required(struct scst_tgt *tgt)
{
	return tgt->tgt_hw_dif_same_sg_layout_required;
}

static inline void scst_tgt_set_hw_dif_same_sg_layout_required(struct scst_tgt *tgt, bool val)
{
	tgt->tgt_hw_dif_same_sg_layout_required = !!val;
}

/*
 * Get/Set functions for tgt's tgt_supported_dif_block_sizes
 */
static inline const int *scst_tgt_get_supported_dif_block_sizes(
	struct scst_tgt *tgt)
{
	return tgt->tgt_supported_dif_block_sizes;
}

static inline void scst_tgt_set_supported_dif_block_sizes(struct scst_tgt *tgt,
	const int *const val)
{
	tgt->tgt_supported_dif_block_sizes = val;
}

void scst_update_hw_pending_start(struct scst_cmd *cmd);

/*
 * Get/Set functions for session's target private data
 */
static inline void *scst_sess_get_tgt_priv(struct scst_session *sess)
{
	return sess->sess_tgt_priv;
}

static inline void scst_sess_set_tgt_priv(struct scst_session *sess,
					      void *val)
{
	sess->sess_tgt_priv = val;
}

uint16_t scst_lookup_tg_id(struct scst_device *dev, struct scst_tgt *tgt);
bool scst_impl_alua_configured(struct scst_device *dev);
int scst_tg_get_group_info(void **buf, uint32_t *response_length,
			   struct scst_device *dev, uint8_t data_format);

/*
 * Get/set functions for dev's static DIF APP TAG
 */
static inline __be16 scst_dev_get_dif_static_app_tag(struct scst_device *dev)
{
	return dev->dev_dif_static_app_tag;
}

static inline __be32 scst_dev_get_dif_static_app_ref_tag(struct scst_device *dev)
{
	return dev->dev_dif_static_app_ref_tag;
}

static inline __be64 scst_dev_get_dif_static_app_tag_combined(
	struct scst_device *dev)
{
	uint64_t a = (((uint64_t)be32_to_cpu(dev->dev_dif_static_app_ref_tag)) << 16) |
			be16_to_cpu(dev->dev_dif_static_app_tag);
	return cpu_to_be64(a);
}

void scst_dev_set_dif_static_app_tag_combined(struct scst_device *dev,
	__be64 app_tag);

/*
 * Get/set functions for dev's DIF APP TAG checking
 */
static inline bool scst_dev_get_dif_app_tag_check(struct scst_device *dev)
{
	return dev->dif_app_chk == SCST_DIF_CHECK_APP_TAG;
}

int scst_set_dif_params(struct scst_device *dev,
	enum scst_dif_mode dif_mode, int dif_type);

/*
 * Functions to account detected DIF errors on the corresponding stages
 */
static inline void scst_dif_acc_app_check_failed_tgt(struct scst_cmd *cmd)
{
	atomic_inc(&cmd->tgt->tgt_dif_app_failed_tgt);
	atomic_inc(&cmd->tgt_dev->tgt_dev_dif_app_failed_tgt);
}

static inline void scst_dif_acc_ref_check_failed_tgt(struct scst_cmd *cmd)
{
	atomic_inc(&cmd->tgt->tgt_dif_ref_failed_tgt);
	atomic_inc(&cmd->tgt_dev->tgt_dev_dif_ref_failed_tgt);
}

static inline void scst_dif_acc_guard_check_failed_tgt(struct scst_cmd *cmd)
{
	atomic_inc(&cmd->tgt->tgt_dif_guard_failed_tgt);
	atomic_inc(&cmd->tgt_dev->tgt_dev_dif_guard_failed_tgt);
}

static inline void scst_dif_acc_app_check_failed_scst(struct scst_cmd *cmd)
{
	atomic_inc(&cmd->tgt->tgt_dif_app_failed_scst);
	atomic_inc(&cmd->tgt_dev->tgt_dev_dif_app_failed_scst);
}

static inline void scst_dif_acc_ref_check_failed_scst(struct scst_cmd *cmd)
{
	atomic_inc(&cmd->tgt->tgt_dif_ref_failed_scst);
	atomic_inc(&cmd->tgt_dev->tgt_dev_dif_ref_failed_scst);
}

static inline void scst_dif_acc_guard_check_failed_scst(struct scst_cmd *cmd)
{
	atomic_inc(&cmd->tgt->tgt_dif_guard_failed_scst);
	atomic_inc(&cmd->tgt_dev->tgt_dev_dif_guard_failed_scst);
}

static inline void scst_dif_acc_app_check_failed_dev(struct scst_cmd *cmd)
{
	atomic_inc(&cmd->tgt->tgt_dif_app_failed_dev);
	atomic_inc(&cmd->tgt_dev->tgt_dev_dif_app_failed_dev);
}

static inline void scst_dif_acc_ref_check_failed_dev(struct scst_cmd *cmd)
{
	atomic_inc(&cmd->tgt->tgt_dif_ref_failed_dev);
	atomic_inc(&cmd->tgt_dev->tgt_dev_dif_ref_failed_dev);
}

static inline void scst_dif_acc_guard_check_failed_(struct scst_cmd *cmd)
{
	atomic_inc(&cmd->tgt->tgt_dif_guard_failed_dev);
	atomic_inc(&cmd->tgt_dev->tgt_dev_dif_guard_failed_dev);
}

/*
 * Functions to process DIF tags by SCST as required by device
 * formatting and *protect cmd's bits.
 *
 * Return 0 on success, i.e. when cmd processing should proceed normally,
 * or negative error code otherwise, i.e. when cmd processing should be
 * stopped and status send to its initiator.
 */
static inline int scst_dif_process_read(struct scst_cmd *cmd)
{
	return cmd->dev->dev_dif_fn(cmd);
}
static inline int scst_dif_process_write(struct scst_cmd *cmd)
{
	return cmd->dev->dev_dif_fn(cmd);
}

/**
 * Returns TRUE if cmd is being executed in atomic context.
 *
 * This function must be used outside of spinlocks and preempt/BH/IRQ
 * disabled sections, because of the EXTRACHECK in it.
 */
static inline bool scst_cmd_atomic(struct scst_cmd *cmd)
{
	int res = cmd->atomic;
#ifdef CONFIG_SCST_EXTRACHECKS
	/*
	 * Checkpatch will complain on the use of in_atomic() below. You
	 * can safely ignore this warning since in_atomic() is used here
	 * only for debugging purposes.
	 */
	if (unlikely((in_atomic() || in_interrupt() || irqs_disabled()) &&
		     !res)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
		printk(KERN_ERR "ERROR: atomic context and non-atomic cmd!\n");
#else
		pr_err("ERROR: atomic context and non-atomic cmd!\n");
#endif
		dump_stack();
		cmd->atomic = 1;
		res = 1;
	}
#endif
	return res;
}

/* Returns TRUE if cmd completed with SAM_STAT_GOOD */
static inline bool scst_cmd_completed_good(struct scst_cmd *cmd)
{
	return cmd->completed && (cmd->status == SAM_STAT_GOOD);
}

/*
 * Returns TRUE if cmd has been preliminary completed, i.e. completed or
 * aborted.
 */
static inline bool scst_cmd_prelim_completed(struct scst_cmd *cmd)
{
	return cmd->completed || test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags);
}

static inline enum scst_exec_context __scst_estimate_context(bool atomic)
{
	if (in_irq())
		return SCST_CONTEXT_TASKLET;
/*
 * We come here from many non reliable places, like the block layer, and don't
 * have any reliable way to detect if we called under atomic context or not
 * (in_atomic() isn't reliable), so let's be safe and disable this section
 * for now to unconditionally return thread context.
 */
#if 0
	else if (irqs_disabled())
		return SCST_CONTEXT_THREAD;
	else if (in_atomic())
		return SCST_CONTEXT_DIRECT_ATOMIC;
	else
		return atomic ? SCST_CONTEXT_DIRECT :
				SCST_CONTEXT_DIRECT_ATOMIC;
#else
	return SCST_CONTEXT_THREAD;
#endif
}

static inline enum scst_exec_context scst_estimate_context(void)
{
	return __scst_estimate_context(false);
}

static inline enum scst_exec_context scst_estimate_context_atomic(void)
{
	return __scst_estimate_context(true);
}

/* Returns cmd's CDB */
static inline const uint8_t *scst_cmd_get_cdb(struct scst_cmd *cmd)
{
	return cmd->cdb;
}

/* Returns cmd's CDB length */
static inline unsigned int scst_cmd_get_cdb_len(struct scst_cmd *cmd)
{
	return cmd->cdb_len;
}

void scst_cmd_set_ext_cdb(struct scst_cmd *cmd,
	uint8_t *ext_cdb, unsigned int ext_cdb_len, gfp_t gfp_mask);

/* Returns cmd's session */
static inline struct scst_session *scst_cmd_get_session(struct scst_cmd *cmd)
{
	return cmd->sess;
}

/* Returns cmd's response data length */
static inline int scst_cmd_get_resp_data_len(struct scst_cmd *cmd)
{
	return cmd->resp_data_len;
}

/* Returns cmd's adjusted response data length */
static inline int scst_cmd_get_adjusted_resp_data_len(struct scst_cmd *cmd)
{
	return cmd->adjusted_resp_data_len;
}

/* Returns if status should be sent for cmd */
static inline int scst_cmd_get_is_send_status(struct scst_cmd *cmd)
{
	return cmd->is_send_status;
}

/*
 * Returns pointer to cmd's SG data buffer.
 *
 * Usage of this function is not recommended, use scst_get_buf_*()
 * family of functions instead.
 */
static inline struct scatterlist *scst_cmd_get_sg(struct scst_cmd *cmd)
{
	return cmd->sg;
}

/*
 * Returns cmd's sg_cnt.
 *
 * Usage of this function is not recommended, use scst_get_buf_*()
 * family of functions instead.
 */
static inline int scst_cmd_get_sg_cnt(struct scst_cmd *cmd)
{
	return cmd->sg_cnt;
}

/*
 * Returns pointer to cmd's DIF tags SG data buffer.
 *
 * Usage of this function is not recommended, use scst_get_dif_buf()
 * function instead.
 */
static inline struct scatterlist *scst_cmd_get_dif_sg(struct scst_cmd *cmd)
{
	return cmd->dif_sg;
}

/*
 * Returns pointer to cmd's DIF tags SG data buffer elements count.
 *
 * Usage of this function is not recommended, use scst_get_dif_buf()
 * function instead.
 */
static inline int scst_cmd_get_dif_sg_cnt(struct scst_cmd *cmd)
{
	return cmd->dif_sg_cnt;
}

/* Returns cmd's LBA */
static inline int64_t scst_cmd_get_lba(struct scst_cmd *cmd)
{
	return cmd->lba;
}

/*
 * Returns cmd's data buffer length.
 *
 * In case if you need to iterate over data in the buffer, usage of
 * this function is not recommended, use scst_get_buf_*()
 * family of functions instead.
 */
static inline int scst_cmd_get_bufflen(struct scst_cmd *cmd)
{
	return cmd->bufflen;
}

/*
 * Returns cmd's data_len. See the corresponding field's description in
 * struct scst_cmd above.
 */
static inline int64_t scst_cmd_get_data_len(struct scst_cmd *cmd)
{
	return cmd->data_len;
}

/* Returns true, if cmd needs DIF buffer */
static inline bool scst_cmd_needs_dif_buf(struct scst_cmd *cmd)
{
	return (scst_get_dif_action(scst_get_scst_dif_actions(cmd->cmd_dif_actions)) != SCST_DIF_ACTION_NONE) ||
	       (scst_get_dif_action(scst_get_dev_dif_actions(cmd->cmd_dif_actions)) != SCST_DIF_ACTION_NONE);
}

/* Returns length of DIF buffer of this cmd */
static inline int __scst_cmd_get_bufflen_dif(struct scst_cmd *cmd)
{
	return (cmd->bufflen >> cmd->dev->block_shift) << SCST_DIF_TAG_SHIFT;
}

static inline int scst_cmd_get_bufflen_dif(struct scst_cmd *cmd)
{
	if (scst_cmd_needs_dif_buf(cmd))
		return __scst_cmd_get_bufflen_dif(cmd);
	else
		return 0;
}

/*
 * Returns pointer to cmd's bidirectional in (WRITE) SG data buffer.
 *
 * Usage of this function is not recommended, use scst_get_out_buf_*()
 * family of functions instead.
 */
static inline struct scatterlist *scst_cmd_get_out_sg(struct scst_cmd *cmd)
{
	return cmd->out_sg;
}

/*
 * Returns cmd's bidirectional in (WRITE) sg_cnt.
 *
 * Usage of this function is not recommended, use scst_get_out_buf_*()
 * family of functions instead.
 */
static inline int scst_cmd_get_out_sg_cnt(struct scst_cmd *cmd)
{
	return cmd->out_sg_cnt;
}

void scst_restore_sg_buff(struct scst_cmd *cmd);

/* Restores modified sg buffer in the original state, if necessary */
static inline void scst_check_restore_sg_buff(struct scst_cmd *cmd)
{
	if (unlikely(cmd->sg_buff_modified || cmd->dif_sg_buff_modified))
		scst_restore_sg_buff(cmd);
}

/*
 * Returns cmd's bidirectional in (WRITE) data buffer length.
 *
 * In case if you need to iterate over data in the buffer, usage of
 * this function is not recommended, use scst_get_out_buf_*()
 * family of functions instead.
 */
static inline unsigned int scst_cmd_get_out_bufflen(struct scst_cmd *cmd)
{
	return cmd->out_bufflen;
}

/*
 * Returns pointer to cmd's target's SG data buffer. Since it's for target
 * drivers, the "_i_" part is omitted.
 */
static inline struct scatterlist *scst_cmd_get_tgt_sg(struct scst_cmd *cmd)
{
	return cmd->tgt_i_sg;
}

/*
 * Returns cmd's target's sg_cnt. Since it's for target
 * drivers, the "_i_" part is omitted.
 */
static inline int scst_cmd_get_tgt_sg_cnt(struct scst_cmd *cmd)
{
	return cmd->tgt_i_sg_cnt;
}

/*
 * Sets cmd's target's SG data buffer. Since it's for target
 * drivers, the "_i_" part is omitted.
 */
static inline void scst_cmd_set_tgt_sg(struct scst_cmd *cmd,
	struct scatterlist *sg, int sg_cnt)
{
	cmd->tgt_i_sg = sg;
	cmd->tgt_i_sg_cnt = sg_cnt;
	cmd->tgt_i_data_buf_alloced = 1;
}

/*
 * Returns pointer to cmd's target's DIF tags SG data buffer. Since it's
 * for target drivers, the "_i_" part is omitted.
 */
static inline struct scatterlist *scst_cmd_get_tgt_dif_sg(struct scst_cmd *cmd)
{
	return cmd->tgt_i_dif_sg;
}

/*
 * Returns cmd's target's DIF tags SG data buffer elements count. Since it's
 * for target drivers, the "_i_" part is omitted.
 */
static inline int scst_cmd_get_tgt_dif_sg_cnt(struct scst_cmd *cmd)
{
	return cmd->tgt_i_dif_sg_cnt;
}

/*
 * Sets cmd's target's DIF tags SG data buffer. Since it's for target
 * drivers, the "_i_" part is omitted.
 */
static inline void scst_cmd_set_tgt_dif_sg(struct scst_cmd *cmd,
	struct scatterlist *dif_sg, int cnt)
{
	cmd->tgt_i_dif_sg = dif_sg;
	cmd->tgt_i_dif_sg_cnt = cnt;
}

/* Returns pointer to cmd's target's OUT SG data buffer */
static inline struct scatterlist *scst_cmd_get_out_tgt_sg(struct scst_cmd *cmd)
{
	return cmd->tgt_out_sg;
}

/* Returns cmd's target's OUT sg_cnt */
static inline int scst_cmd_get_tgt_out_sg_cnt(struct scst_cmd *cmd)
{
	return cmd->tgt_out_sg_cnt;
}

/* Sets cmd's target's OUT SG data buffer */
static inline void scst_cmd_set_tgt_out_sg(struct scst_cmd *cmd,
	struct scatterlist *sg, int sg_cnt)
{
	WARN_ON(!cmd->tgt_i_data_buf_alloced);

	cmd->tgt_out_sg = sg;
	cmd->tgt_out_sg_cnt = sg_cnt;
}

/* Returns cmd's data direction */
static inline scst_data_direction scst_cmd_get_data_direction(
	struct scst_cmd *cmd)
{
	return cmd->data_direction;
}

/* Returns cmd's write len as well as write SG and sg_cnt */
static inline int scst_cmd_get_write_fields(struct scst_cmd *cmd,
	struct scatterlist **sg, int *sg_cnt)
{
	*sg = *cmd->write_sg;
	*sg_cnt = *cmd->write_sg_cnt;
	return cmd->write_len;
}

void scst_cmd_set_write_not_received_data_len(struct scst_cmd *cmd,
	int not_received);

bool __scst_get_resid(struct scst_cmd *cmd, int *resid, int *bidi_out_resid);

/*
 * Returns true if cmd has residual(s) and returns them in the corresponding
 * parameters(s).
 */
static inline bool scst_get_resid(struct scst_cmd *cmd,
	int *resid, int *bidi_out_resid)
{
	if (likely(!cmd->resid_possible))
		return false;
	return __scst_get_resid(cmd, resid, bidi_out_resid);
}

/* Returns cmd's status byte from host device */
static inline uint8_t scst_cmd_get_status(struct scst_cmd *cmd)
{
	return cmd->status;
}

/* Returns cmd's status from host adapter itself */
static inline uint8_t scst_cmd_get_msg_status(struct scst_cmd *cmd)
{
	return cmd->msg_status;
}

/* Returns cmd's status set by low-level driver to indicate its status */
static inline uint8_t scst_cmd_get_host_status(struct scst_cmd *cmd)
{
	return cmd->host_status;
}

/* Returns cmd's status set by SCSI mid-level */
static inline uint8_t scst_cmd_get_driver_status(struct scst_cmd *cmd)
{
	return cmd->driver_status;
}

/* Returns pointer to cmd's sense buffer */
static inline uint8_t *scst_cmd_get_sense_buffer(struct scst_cmd *cmd)
{
	return cmd->sense;
}

/* Returns cmd's valid sense length */
static inline int scst_cmd_get_sense_buffer_len(struct scst_cmd *cmd)
{
	return cmd->sense_valid_len;
}

/*
 * Get/Set functions for cmd's queue_type
 */
static inline enum scst_cmd_queue_type scst_cmd_get_queue_type(
	struct scst_cmd *cmd)
{
	return cmd->queue_type;
}

static inline void scst_cmd_set_queue_type(struct scst_cmd *cmd,
	enum scst_cmd_queue_type queue_type)
{
	cmd->queue_type = queue_type;
}

/*
 * Get/Set functions for cmd's target SN
 */
static inline uint64_t scst_cmd_get_tag(struct scst_cmd *cmd)
{
	return cmd->tag;
}

static inline void scst_cmd_set_tag(struct scst_cmd *cmd, uint64_t tag)
{
	cmd->tag = tag;
}

/*
 * Get/Set functions for cmd's target private data.
 * Variant with *_lock must be used if target driver uses
 * scst_find_cmd() to avoid race with it, except inside scst_find_cmd()'s
 * callback, where lock is already taken.
 */
static inline void *scst_cmd_get_tgt_priv(struct scst_cmd *cmd)
{
	return cmd->tgt_i_priv;
}

static inline void scst_cmd_set_tgt_priv(struct scst_cmd *cmd, void *val)
{
	cmd->tgt_i_priv = val;
}

/*
 * Get/Set functions for tgt_need_alloc_data_buf flag
 */
static inline int scst_cmd_get_tgt_need_alloc_data_buf(struct scst_cmd *cmd)
{
	return cmd->tgt_need_alloc_data_buf;
}

static inline void scst_cmd_set_tgt_need_alloc_data_buf(struct scst_cmd *cmd)
{
	cmd->tgt_need_alloc_data_buf = 1;
}

/*
 * Get/Set functions for tgt_i_data_buf_alloced flag. Since they are for target
 * drivers, the "_i_" part is omitted.
 */
static inline int scst_cmd_get_tgt_data_buff_alloced(struct scst_cmd *cmd)
{
	return cmd->tgt_i_data_buf_alloced;
}

static inline void scst_cmd_set_tgt_data_buff_alloced(struct scst_cmd *cmd)
{
	cmd->tgt_i_data_buf_alloced = 1;
}

/*
 * Get/Set functions for dh_data_buf_alloced flag
 */
static inline int scst_cmd_get_dh_data_buff_alloced(struct scst_cmd *cmd)
{
	return cmd->dh_data_buf_alloced;
}

static inline void scst_cmd_set_dh_data_buff_alloced(struct scst_cmd *cmd)
{
	cmd->dh_data_buf_alloced = 1;
}

/*
 * Get/Set functions for no_sgv flag
 */
static inline int scst_cmd_get_no_sgv(struct scst_cmd *cmd)
{
	return cmd->no_sgv;
}

static inline void scst_cmd_set_no_sgv(struct scst_cmd *cmd)
{
	cmd->no_sgv = 1;
}

/*
 * Get/Set functions for tgt_sn
 */
static inline int scst_cmd_get_tgt_sn(struct scst_cmd *cmd)
{
	BUG_ON(!cmd->tgt_sn_set);
	return cmd->tgt_sn;
}

static inline void scst_cmd_set_tgt_sn(struct scst_cmd *cmd, uint32_t tgt_sn)
{
	cmd->tgt_sn_set = 1;
	cmd->tgt_sn = tgt_sn;
}

/*
 * Forbids for this cmd any IO-causing allocations.
 *
 * !! Must be called before scst_cmd_init_done() !!
 */
static inline void scst_cmd_set_noio_mem_alloc(struct scst_cmd *cmd)
{
	cmd->cmd_gfp_mask = GFP_NOIO;
}

/*
 * Returns true if the cmd was aborted, so the caller should complete it as
 * soon as possible.
 *
 * !! Xmit_response() callback must use scst_cmd_aborted_on_xmit() instead !!
 * !! to allow status of completed commands aborted by other initiators be !!
 * !! delivered to their initiators !!
 */
static inline bool scst_cmd_aborted(struct scst_cmd *cmd)
{
	return test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags);
}

/*
 * Returns true if the cmd was aborted by its initiator or aborted by another
 * initiator and not completed, so its status is invalid and no reply shall
 * be sent to the remote initiator. A target driver should only clear
 * internal resources, associated with cmd.
 *
 * This functions shall be called by all target drivers in the beginning of
 * xmit_response() callback.
 */
static inline bool scst_cmd_aborted_on_xmit(struct scst_cmd *cmd)
{
	return test_bit(SCST_CMD_ABORTED, &cmd->cmd_flags) &&
		!test_bit(SCST_CMD_ABORTED_OTHER, &cmd->cmd_flags);
}

/* Returns sense data format for cmd's dev */
static inline bool scst_get_cmd_dev_d_sense(struct scst_cmd *cmd)
{
	return (cmd->dev != NULL) ? cmd->dev->d_sense : 0;
}

/*
 * Get/Set functions for expected data direction, transfer length
 * and its validity flag
 */
static inline int scst_cmd_is_expected_set(struct scst_cmd *cmd)
{
	return cmd->expected_values_set;
}

static inline scst_data_direction scst_cmd_get_expected_data_direction(
	struct scst_cmd *cmd)
{
	return cmd->expected_data_direction;
}

/*
 * Returns full expected transfer length, i.e. including both data and
 * DIF tags, if any.
 */
static inline int scst_cmd_get_expected_transfer_len_full(
	struct scst_cmd *cmd)
{
	return cmd->expected_transfer_len_full;
}

int scst_cmd_get_expected_transfer_len_data(struct scst_cmd *cmd);
int scst_cmd_get_expected_transfer_len_dif(struct scst_cmd *cmd);

static inline int scst_cmd_get_expected_out_transfer_len(
	struct scst_cmd *cmd)
{
	return cmd->expected_out_transfer_len;
}

static inline void scst_cmd_set_expected(struct scst_cmd *cmd,
	scst_data_direction expected_data_direction,
	int expected_transfer_len_full)
{
	cmd->expected_data_direction = expected_data_direction;
	cmd->expected_transfer_len_full = expected_transfer_len_full;
	cmd->expected_values_set = 1;
}

static inline void scst_cmd_set_expected_out_transfer_len(struct scst_cmd *cmd,
	int expected_out_transfer_len)
{
	WARN_ON(!cmd->expected_values_set);
	cmd->expected_out_transfer_len = expected_out_transfer_len;
}

/*
 * Get/clear functions for cmd's may_need_dma_sync
 */
static inline int scst_get_may_need_dma_sync(struct scst_cmd *cmd)
{
	return cmd->may_need_dma_sync;
}

static inline void scst_clear_may_need_dma_sync(struct scst_cmd *cmd)
{
	cmd->may_need_dma_sync = 0;
}

/*
 * Get/set functions for cmd's delivery_status. It is one of
 * SCST_CMD_DELIVERY_* constants. It specifies the status of the
 * command's delivery to initiator.
 */
static inline int scst_get_delivery_status(struct scst_cmd *cmd)
{
	return cmd->delivery_status;
}

static inline void scst_set_delivery_status(struct scst_cmd *cmd,
	int delivery_status)
{
	cmd->delivery_status = delivery_status;
}

/*
 * Returns T10-PI actions, including checks, which target driver should do
 * with this command on READ direction transfers (xmit_response()). Might
 * be different from WRITE direction for BIDI commands.
 */
static inline enum scst_dif_actions scst_get_read_dif_tgt_actions(
	struct scst_cmd *cmd)
{
	return scst_get_tgt_dif_actions(cmd->cmd_dif_actions);
}

/*
 * Returns T10-PI actions, including checks, which target driver should do
 * with this command on WRITE direction transfers (rdy_to_xfer()). Might
 * be different from READ direction for BIDI commands.
 */
static inline enum scst_dif_actions scst_get_write_dif_tgt_actions(
	struct scst_cmd *cmd)
{
	return scst_get_tgt_dif_actions(cmd->cmd_dif_actions);
}

/*
 * Returns T10-PI actions, including checks, which dev handler should do
 * with this command on READ direction transfers. Might be different
 * from WRITE direction for BIDI commands.
 */
static inline enum scst_dif_actions scst_get_read_dif_dev_actions(
	struct scst_cmd *cmd)
{
	return scst_get_dev_dif_actions(cmd->cmd_dif_actions);
}

/*
 * Returns T10-PI actions, including checks, which dev handler should do
 * with this command on WRITE direction transfers. Might be different
 * from READ direction for BIDI commands.
 */
static inline enum scst_dif_actions scst_get_write_dif_dev_actions(
	struct scst_cmd *cmd)
{
	return scst_get_dev_dif_actions(cmd->cmd_dif_actions);
}

/*
 * Returns T10-PI protection type for this cmd's device. Supposed to be used
 * by target drivers.
 */
static inline int scst_cmd_get_dif_prot_type(struct scst_cmd *cmd)
{
	return cmd->dev->dev_dif_type;
}

/*
 * Returns T10-PI application tag for this cmd's device's lba.
 *
 * If SCST_DIF_NO_CHECK_APP_TAG returned, the target driver should not
 * check app tag for this lba (SCSI requirement).
 *
 * Parameter out_lba_end returns end LBA of the area, where this app tag
 * is valid. Then, if necessary, the target driver supposed to call
 * this function again for the next app tag area. This is intended to
 * support Application Tag mode page. ToDo, not implemented yet.
 */
static inline __be16 scst_cmd_get_dif_app_tag(struct scst_cmd *cmd,
	uint64_t lba_start/*, uint64_t *out_lba_end*/)
{
#ifdef CONFIG_SCST_EXTRACHECKS
	WARN_ON(!(scst_get_dif_checks(cmd->cmd_dif_actions) & SCST_DIF_CHECK_APP_TAG));
#endif
	return cmd->dev->dev_dif_static_app_tag;
}

/*
 * Returns T10-PI type 2 expected initial reference tag as LBA, i.e. converted
 * into CPU endianness. Valid only with protection type 2.
 */
static inline uint32_t scst_cmd_get_dif_exp_ref_tag(struct scst_cmd *cmd)
{
#ifdef CONFIG_SCST_EXTRACHECKS
	BUG_ON(cmd->dev->dev_dif_type != 2);
	WARN_ON(cmd->cdb_len > 32);
#endif
	if (cmd->cdb_len == 32)
		return get_unaligned_be32(&cmd->cdb[20]);
	else
		return cmd->lba & 0xFFFFFFFF;
}

/*
 * Returns T10-PI type 2 expected logical block application tag converted
 * into CPU endianness. Valid only with protection type 2.
 */
static inline uint16_t scst_cmd_get_dif_exp_app_tag(struct scst_cmd *cmd)
{
#ifdef CONFIG_SCST_EXTRACHECKS
	BUG_ON(cmd->dev->dev_dif_type != 2);
	WARN_ON(cmd->cdb_len > 32);
#endif
	if (cmd->cdb_len == 32)
		return get_unaligned_be16(&cmd->cdb[24]);
	else {
		/* cmd->dev must be alive at this point */
		return be16_to_cpu(cmd->dev->dev_dif_static_app_tag);
	}
}

/*
 * Returns T10-PI type 2 logical block application tag mask converted
 * into CPU endianness. Valid only with protection type 2.
 */
static inline uint16_t scst_cmd_get_dif_app_tag_mask(struct scst_cmd *cmd)
{
#ifdef CONFIG_SCST_EXTRACHECKS
	BUG_ON(cmd->dev->dev_dif_type != 2);
	WARN_ON(cmd->cdb_len > 32);
#endif
	if (cmd->cdb_len == 32)
		return get_unaligned_be16(&cmd->cdb[26]);
	else {
		if (scst_get_dif_checks(cmd->cmd_dif_actions) & SCST_DIF_CHECK_APP_TAG)
			return 0xFFFF;
		else
			return 0;
	}
}

/*
 * Returns T10-PI type 3 application/reference tag. Valid only with type 3
 * protection type. Alternatively, scst_dev_get_dif_static_app_tag_combined()
 * can be used.
 *
 * If SCST_DIF_NO_CHECK_ALL_REF_TAG returned, the target driver should not
 * check the tag for this lba (SCSI requirement).
 */
static inline __be32 scst_cmd_get_dif_app_ref_tag(struct scst_cmd *cmd)
{
#ifdef CONFIG_SCST_EXTRACHECKS
	BUG_ON(cmd->dev->dev_dif_type != 3);
	WARN_ON(!(scst_get_dif_checks(cmd->cmd_dif_actions) & SCST_DIF_CHECK_REF_TAG));
#endif
	return cmd->dev->dev_dif_static_app_ref_tag;
}

/*
 * Returns format of T10-PI GUARD TAGs as one of SCST_DIF_GUARD_FORMAT_*
 * constants
 */
static inline int scst_cmd_get_dif_guard_format(struct scst_cmd *cmd)
{
	return cmd->tgt_dev->tgt_dev_dif_guard_format;
}

/*
 * Returns block size of this cmd's device. Supposed to be used
 * by target drivers during T10-PI processing.
 */
static inline int scst_cmd_get_block_size(struct scst_cmd *cmd)
{
	return cmd->dev->block_size;
}

static inline unsigned int scst_get_active_cmd_count(struct scst_cmd *cmd)
{
	if (likely(cmd->tgt_dev != NULL))
		return atomic_read(&cmd->tgt_dev->tgt_dev_cmd_count);
	else
		return (unsigned int)-1;
}

int scst_set_cdb_lba(struct scst_cmd *cmd, int64_t len);
int scst_set_cdb_transf_len(struct scst_cmd *cmd, int len);

/*
 * Get/Set function for mgmt cmd's target private data
 */
static inline void *scst_mgmt_cmd_get_tgt_priv(struct scst_mgmt_cmd *mcmd)
{
	return mcmd->tgt_priv;
}

static inline void scst_mgmt_cmd_set_tgt_priv(struct scst_mgmt_cmd *mcmd,
	void *val)
{
	mcmd->tgt_priv = val;
}

/* Returns mgmt cmd's completion status (SCST_MGMT_STATUS_* constants) */
static inline int scst_mgmt_cmd_get_status(struct scst_mgmt_cmd *mcmd)
{
	return mcmd->status;
}

static inline void scst_mgmt_cmd_set_status(struct scst_mgmt_cmd *mcmd,
	int status)
{
	/* Don't replace existing, i.e. the first, not success status */
	if ((mcmd->status == SCST_MGMT_STATUS_SUCCESS) &&
	    (status != SCST_MGMT_STATUS_RECEIVED_STAGE_COMPLETED))
		mcmd->status = status;
}

/* Returns mgmt cmd's TM fn */
static inline int scst_mgmt_cmd_get_fn(struct scst_mgmt_cmd *mcmd)
{
	return mcmd->fn;
}

/* Returns true if mgmt cmd should be dropped, i.e. response not sent */
static inline bool scst_mgmt_cmd_dropped(struct scst_mgmt_cmd *mcmd)
{
	return mcmd->mcmd_dropped;
}

/*
 * Called by dev handler's task_mgmt_fn_*() to notify SCST core that mcmd
 * is going to complete asynchronously.
 */
void scst_prepare_async_mcmd(struct scst_mgmt_cmd *mcmd);

/*
 * Called by dev handler to notify SCST core that async. mcmd is completed
 * with status "status".
 */
void scst_async_mcmd_completed(struct scst_mgmt_cmd *mcmd, int status);

/* Returns AEN's fn */
static inline int scst_aen_get_event_fn(struct scst_aen *aen)
{
	return aen->event_fn;
}

/* Returns AEN's session */
static inline struct scst_session *scst_aen_get_sess(struct scst_aen *aen)
{
	return aen->sess;
}

/* Returns AEN's LUN */
static inline __be64 scst_aen_get_lun(struct scst_aen *aen)
{
	return aen->lun;
}

/* Returns SCSI AEN's sense */
static inline const uint8_t *scst_aen_get_sense(struct scst_aen *aen)
{
	return aen->aen_sense;
}

/* Returns SCSI AEN's sense length */
static inline int scst_aen_get_sense_len(struct scst_aen *aen)
{
	return aen->aen_sense_len;
}

/*
 * Get/set functions for AEN's delivery_status. It is one of
 * SCST_AEN_RES_* constants. It specifies the status of the
 * command's delivery to initiator.
 */
static inline int scst_get_aen_delivery_status(struct scst_aen *aen)
{
	return aen->delivery_status;
}

static inline void scst_set_aen_delivery_status(struct scst_aen *aen,
	int status)
{
	aen->delivery_status = status;
}

void scst_aen_done(struct scst_aen *aen);

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

#endif /* __BACKPORT_LINUX_SCATTERLIST_H_TO_2_6_23__ */

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24) */

static inline struct scatterlist *__sg_next_inline(struct scatterlist *sg)
{
	sg++;
	if (unlikely(sg_is_chain(sg)))
		sg = sg_chain_ptr(sg);

	return sg;
}

static inline struct scatterlist *sg_next_inline(struct scatterlist *sg)
{
	if (sg_is_last(sg))
		return NULL;

	return __sg_next_inline(sg);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
#ifndef __BACKPORT_LINUX_SCATTERLIST_H_TO_2_6_23__

#ifndef for_each_sg
/* See also commit 96b418c960af0d5c7185ff5c4af9376eb37ac9d3 */
#define for_each_sg(sglist, sg, nr, __i)       \
	for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next_inline(sg))
#endif

#endif /* __BACKPORT_LINUX_SCATTERLIST_H_TO_2_6_23__ */
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24) */

static inline void sg_clear(struct scatterlist *sg)
{
	memset(sg, 0, sizeof(*sg));
#ifdef CONFIG_DEBUG_SG
	sg->sg_magic = SG_MAGIC;
#endif
}

enum scst_sg_copy_dir {
	SCST_SG_COPY_FROM_TARGET,
	SCST_SG_COPY_TO_TARGET
};

void scst_copy_sg(struct scst_cmd *cmd, enum scst_sg_copy_dir copy_dir);

/*
 * Functions for access to the commands data (SG) buffer. Should be used
 * instead of direct access. Returns the buffer length for success, 0 for EOD,
 * negative error code otherwise.
 *
 * Never EVER use this function to process only "the first page" of the buffer.
 * The first SG entry can be as low as few bytes long. Use scst_get_buf_full()
 * instead for such cases.
 *
 * "Buf" argument returns the mapped buffer
 *
 * The "put" function unmaps the buffer.
 */
static inline int __scst_get_buf(struct scst_cmd *cmd, int sg_cnt,
	uint8_t **buf)
{
	int res = 0;
	struct scatterlist *sg = cmd->get_sg_buf_cur_sg_entry;

	if (cmd->get_sg_buf_entry_num >= sg_cnt) {
		*buf = NULL;
		goto out;
	}

	*buf = page_address(sg_page(sg));
	*buf += sg->offset;

	res = sg->length;

	cmd->get_sg_buf_entry_num++;
	cmd->get_sg_buf_cur_sg_entry = __sg_next_inline(sg);

out:
	return res;
}

static inline int scst_get_buf_first(struct scst_cmd *cmd, uint8_t **buf)
{
	if (unlikely(cmd->sg == NULL)) {
		*buf = NULL;
		return 0;
	}
	cmd->get_sg_buf_entry_num = 0;
	cmd->get_sg_buf_cur_sg_entry = cmd->sg;
	cmd->may_need_dma_sync = 1;
	return __scst_get_buf(cmd, cmd->sg_cnt, buf);
}

static inline int scst_get_buf_next(struct scst_cmd *cmd, uint8_t **buf)
{
	return __scst_get_buf(cmd, cmd->sg_cnt, buf);
}

static inline void scst_put_buf(struct scst_cmd *cmd, void *buf)
{
	/* Nothing to do */
}

/*
 * Functions for access to the commands DIF tags (SG) buffer. It doesn't
 * return any error code, because this buffer is strictly connected to the
 * data buffer, so for each block in that buffer, there must be tag here.
 *
 * Parameter psg on entrance specifies previous DIF tags SG in the access.
 * Must point to NULL for the first access. On exit returns current DIF
 * tags SG.
 *
 * The "put" function unmaps the buffer.
 *
 * !!! NOTE: this function does not check DIF SG cnt, hence must be used !!!
 * !!! only inside code bound to the corresponding data SG cnt!		 !!!
 */
static inline uint8_t *scst_get_dif_buf(struct scst_cmd *cmd,
	struct scatterlist **psg, int *length)
{
	uint8_t *buf;
	struct scatterlist *sg;

	if (*psg == NULL)
		sg = cmd->dif_sg;
	else
		sg = __sg_next_inline(*psg);

	buf = page_address(sg_page(sg));
	buf += sg->offset;
	*length = sg->length;

	*psg = sg;

	return buf;
}

static inline void scst_put_dif_buf(struct scst_cmd *cmd, void *buf)
{
	/* Nothing to do */
}

static inline int scst_get_out_buf_first(struct scst_cmd *cmd, uint8_t **buf)
{
	if (unlikely(cmd->out_sg == NULL)) {
		*buf = NULL;
		return 0;
	}
	cmd->get_sg_buf_entry_num = 0;
	cmd->get_sg_buf_cur_sg_entry = cmd->out_sg;
	cmd->may_need_dma_sync = 1;
	return __scst_get_buf(cmd, cmd->out_sg_cnt, buf);
}

static inline int scst_get_out_buf_next(struct scst_cmd *cmd, uint8_t **buf)
{
	return __scst_get_buf(cmd, cmd->out_sg_cnt, buf);
}

static inline void scst_put_out_buf(struct scst_cmd *cmd, void *buf)
{
	/* Nothing to do */
}

static inline int scst_get_sg_buf_first(struct scst_cmd *cmd, uint8_t **buf,
	struct scatterlist *sg, int sg_cnt)
{
	if (unlikely(sg == NULL)) {
		*buf = NULL;
		return 0;
	}
	cmd->get_sg_buf_entry_num = 0;
	cmd->get_sg_buf_cur_sg_entry = cmd->sg;
	cmd->may_need_dma_sync = 1;
	return __scst_get_buf(cmd, sg_cnt, buf);
}

static inline int scst_get_sg_buf_next(struct scst_cmd *cmd, uint8_t **buf,
	struct scatterlist *sg, int sg_cnt)
{
	return __scst_get_buf(cmd, sg_cnt, buf);
}

static inline void scst_put_sg_buf(struct scst_cmd *cmd, void *buf,
	struct scatterlist *sg, int sg_cnt)
{
	/* Nothing to do */
}

/*
 * Functions for access to the commands data (SG) page. Should be used
 * instead of direct access. Returns the buffer length for success, 0 for EOD,
 * negative error code otherwise.
 *
 * "Page" argument returns the starting page, "offset" - offset in it.
 *
 * The "put" function "puts" the buffer. It should be always be used, because
 * in future may need to do some additional operations.
 */
static inline int __scst_get_sg_page(struct scst_cmd *cmd, int sg_cnt,
	struct page **page, int *offset)
{
	int res = 0;
	struct scatterlist *sg = cmd->get_sg_buf_cur_sg_entry;

	if (cmd->get_sg_buf_entry_num >= sg_cnt) {
		*page = NULL;
		*offset = 0;
		goto out;
	}

	*page = sg_page(sg);
	*offset = sg->offset;
	res = sg->length;

	cmd->get_sg_buf_entry_num++;
	cmd->get_sg_buf_cur_sg_entry = __sg_next_inline(sg);

out:
	return res;
}

static inline int scst_get_sg_page_first(struct scst_cmd *cmd,
	struct page **page, int *offset)
{
	if (unlikely(cmd->sg == NULL)) {
		*page = NULL;
		*offset = 0;
		return 0;
	}
	cmd->get_sg_buf_entry_num = 0;
	cmd->get_sg_buf_cur_sg_entry = cmd->sg;
	return __scst_get_sg_page(cmd, cmd->sg_cnt, page, offset);
}

static inline int scst_get_sg_page_next(struct scst_cmd *cmd,
	struct page **page, int *offset)
{
	return __scst_get_sg_page(cmd, cmd->sg_cnt, page, offset);
}

static inline void scst_put_sg_page(struct scst_cmd *cmd,
	struct page *page, int offset)
{
	/* Nothing to do */
}

static inline int scst_get_out_sg_page_first(struct scst_cmd *cmd,
	struct page **page, int *offset)
{
	if (unlikely(cmd->out_sg == NULL)) {
		*page = NULL;
		*offset = 0;
		return 0;
	}
	cmd->get_sg_buf_entry_num = 0;
	cmd->get_sg_buf_cur_sg_entry = cmd->out_sg;
	return __scst_get_sg_page(cmd, cmd->out_sg_cnt, page, offset);
}

static inline int scst_get_out_sg_page_next(struct scst_cmd *cmd,
	struct page **page, int *offset)
{
	return __scst_get_sg_page(cmd, cmd->out_sg_cnt, page, offset);
}

static inline void scst_put_out_sg_page(struct scst_cmd *cmd,
	struct page *page, int offset)
{
	/* Nothing to do */
}

/*
 * Returns approximate higher rounded buffers count that
 * scst_get_buf_[first|next]() return.
 */
static inline int scst_get_buf_count(struct scst_cmd *cmd)
{
	return (cmd->sg_cnt == 0) ? 1 : cmd->sg_cnt;
}

/*
 * Returns approximate higher rounded buffers count that
 * scst_get_out_buf_[first|next]() return.
 */
static inline int scst_get_out_buf_count(struct scst_cmd *cmd)
{
	return (cmd->out_sg_cnt == 0) ? 1 : cmd->out_sg_cnt;
}

int scst_get_buf_full(struct scst_cmd *cmd, uint8_t **buf);
int scst_get_buf_full_sense(struct scst_cmd *cmd, uint8_t **buf);
void scst_put_buf_full(struct scst_cmd *cmd, uint8_t *buf);

static inline gfp_t scst_cmd_get_gfp_mask(struct scst_cmd *cmd)
{
	return cmd->cmd_gfp_mask;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23) && !defined(BACKPORT_LINUX_WORKQUEUE_TO_2_6_19)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20))
static inline int cancel_delayed_work_sync(struct delayed_work *work)
{
	int res;

	res = cancel_delayed_work(work);
	flush_scheduled_work();
	return res;
}
#else
/*
 * While cancel_delayed_work_sync() has not been defined in the vanilla kernel
 * 2.6.18 nor in 2.6.19 nor in RHEL/CentOS 5.0..5.5, a definition is available
 * in RHEL/CentOS 5.6. Unfortunately that definition is incompatible with what
 * we need. So define cancel_delayed_work() as a macro such that it overrides
 * the RHEL/CentOS 5.6 inline function definition in <linux/workqueue.h>.
 */
#define cancel_delayed_work_sync(work)		\
({						\
	int res;				\
						\
	res = cancel_delayed_work((work));	\
	flush_scheduled_work();			\
	res;					\
})
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29) && defined(CONFIG_LOCKDEP)
extern struct lockdep_map scst_suspend_dep_map;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32) && \
	defined(CONFIG_DEBUG_LOCK_ALLOC)
#define scst_assert_activity_suspended()		\
	WARN_ON(debug_locks && !lock_is_held(&scst_suspend_dep_map))
#else
/*
 * See also patch "lockdep: Introduce lockdep_assert_held()" (commit ID
 * f607c6685774811b8112e124f10a053d77015485)
 */
#define scst_assert_activity_suspended() do { } while (0)
#endif

/* Default suspending timeout for user interface actions */
#define SCST_SUSPEND_TIMEOUT_USER	(90 * HZ)

/* No timeout in scst_suspend_activity() */
#define SCST_SUSPEND_TIMEOUT_UNLIMITED	0

int scst_suspend_activity(unsigned long timeout);
void scst_resume_activity(void);

void scst_process_active_cmd(struct scst_cmd *cmd, bool atomic);

void scst_post_parse(struct scst_cmd *cmd);
void scst_post_alloc_data_buf(struct scst_cmd *cmd);

int __scst_check_local_events(struct scst_cmd *cmd, bool preempt_tests_only);

/**
 * scst_check_local_events() - check if there are any local SCSI events
 *
 * See description of __scst_check_local_events().
 *
 * Dev handlers implementing internal queuing in their exec() callback should
 * call this function just before the actual command's execution (i.e.
 * after it's taken from the internal queue).
 */
static inline int scst_check_local_events(struct scst_cmd *cmd)
{
	return __scst_check_local_events(cmd, true);
}

int scst_get_cmd_abnormal_done_state(struct scst_cmd *cmd);
void scst_set_cmd_abnormal_done_state(struct scst_cmd *cmd);

struct scst_trace_log {
	unsigned int val;
	const char *token;
};

extern struct mutex scst_mutex;

#ifdef CONFIG_SCST_PROC

/*
 * Returns target driver's root entry in SCST's /proc hierarchy.
 * The driver can create own files/directories here, which should
 * be deleted in the driver's release().
 */
struct proc_dir_entry *scst_proc_get_tgt_root(
	struct scst_tgt_template *vtt);

/*
 * Returns device handler's root entry in SCST's /proc hierarchy.
 * The driver can create own files/directories here, which should
 * be deleted in the driver's detach()/release().
 */
struct proc_dir_entry *scst_proc_get_dev_type_root(
	struct scst_dev_type *dtt);

/**
 ** Two library functions and the structure to help the drivers
 ** that use scst_debug.* facilities manage "trace_level" /proc entry.
 ** The functions service "standard" log levels and allow to work
 ** with driver specific levels, which should be passed inside as
 ** NULL-terminated array of struct scst_trace_log's, where:
 **   - val - the level's numeric value
 **   - token - its string representation
 **/

int scst_proc_log_entry_read(struct seq_file *seq, unsigned long log_level,
	const struct scst_trace_log *tbl);
int scst_proc_log_entry_write(struct file *file, const char __user *buf,
	unsigned long length, unsigned long *log_level,
	unsigned long default_level, const struct scst_trace_log *tbl);

/*
 * helper data structure and function to create proc entry.
 */
struct scst_proc_data {
	const struct file_operations seq_op;
	int (*show)(struct seq_file *, void *);
	void *data;
};

int scst_single_seq_open(struct inode *inode, struct file *file);

struct proc_dir_entry *scst_create_proc_entry(struct proc_dir_entry *root,
	const char *name, struct scst_proc_data *pdata);

#define SCST_DEF_RW_SEQ_OP(x)                          \
	.seq_op = {                                    \
		.owner          = THIS_MODULE,         \
		.open           = scst_single_seq_open,\
		.read           = seq_read,            \
		.write          = x,                   \
		.llseek         = seq_lseek,           \
		.release        = single_release,      \
	},

#else /* CONFIG_SCST_PROC */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34))
const struct sysfs_ops *scst_sysfs_get_sysfs_ops(void);
#else
struct sysfs_ops *scst_sysfs_get_sysfs_ops(void);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29) && defined(CONFIG_LOCKDEP)
#define SCST_SET_DEP_MAP(work, dm) ((work)->dep_map = (dm))
#define SCST_KOBJECT_PUT_AND_WAIT(kobj, category, c, dep_map) \
	scst_kobject_put_and_wait(kobj, category, c, dep_map)
void scst_kobject_put_and_wait(struct kobject *kobj, const char *category,
			       struct completion *c,
			       struct lockdep_map *dep_map);
#else
#define SCST_SET_DEP_MAP(work, dm) do { } while (0)
#define SCST_KOBJECT_PUT_AND_WAIT(kobj, category, c, dep_map) \
	scst_kobject_put_and_wait(kobj, category, c)
void scst_kobject_put_and_wait(struct kobject *kobj, const char *category,
			       struct completion *c);
#endif

/*
 * Returns target driver's root sysfs kobject.
 * The driver can create own files/directories/links here.
 */
static inline struct kobject *scst_sysfs_get_tgtt_kobj(
	struct scst_tgt_template *tgtt)
{
	return &tgtt->tgtt_kobj;
}

int scst_create_tgtt_attr(struct scst_tgt_template *tgtt,
	struct kobj_attribute *attribute);

/*
 * Returns target's root sysfs kobject.
 * The driver can create own files/directories/links here.
 */
static inline struct kobject *scst_sysfs_get_tgt_kobj(
	struct scst_tgt *tgt)
{
	return &tgt->tgt_kobj;
}

int scst_create_tgt_attr(struct scst_tgt *tgt,
	struct kobj_attribute *attribute);

/*
 * Returns device handler's root sysfs kobject.
 * The driver can create own files/directories/links here.
 */
static inline struct kobject *scst_sysfs_get_devt_kobj(
	struct scst_dev_type *devt)
{
	return &devt->devt_kobj;
}

int scst_create_devt_attr(struct scst_dev_type *devt,
	struct kobj_attribute *attribute);

/*
 * Returns device's root sysfs kobject.
 * The driver can create own files/directories/links here.
 */
static inline struct kobject *scst_sysfs_get_dev_kobj(
	struct scst_device *dev)
{
	return &dev->dev_kobj;
}

int scst_create_dev_attr(struct scst_device *dev,
	struct kobj_attribute *attribute);

/*
 * Returns session's root sysfs kobject.
 * The driver can create own files/directories/links here.
 */
static inline struct kobject *scst_sysfs_get_sess_kobj(
	struct scst_session *sess)
{
	return &sess->sess_kobj;
}

#endif /* CONFIG_SCST_PROC */

/* Returns target name */
static inline const char *scst_get_tgt_name(const struct scst_tgt *tgt)
{
	return tgt->tgt_name;
}

int scst_alloc_sense(struct scst_cmd *cmd, int atomic);
int scst_alloc_set_sense(struct scst_cmd *cmd, int atomic,
	const uint8_t *sense, unsigned int len);

int scst_set_sense(uint8_t *buffer, int len, bool d_sense,
	int key, int asc, int ascq);

#define SCST_INVAL_FIELD_BIT_OFFS_VALID		0x8000
int scst_set_invalid_field_in_cdb(struct scst_cmd *cmd, int field_offs,
	int bit_offs);
int scst_set_invalid_field_in_parm_list(struct scst_cmd *cmd, int field_offs,
	int bit_offs);

bool scst_is_ua_sense(const uint8_t *sense, int len);

bool scst_analyze_sense(const uint8_t *sense, int len,
	unsigned int valid_mask, int key, int asc, int ascq);

unsigned long scst_random(void);

void scst_set_resp_data_len(struct scst_cmd *cmd, int resp_data_len);

void scst_cmd_get(struct scst_cmd *cmd);
void scst_cmd_put(struct scst_cmd *cmd);

struct scatterlist *scst_alloc_sg(int size, gfp_t gfp_mask, int *count);
void scst_free_sg(struct scatterlist *sg, int count);

int scst_calc_block_shift(int sector_size);
int scst_sbc_generic_parse(struct scst_cmd *cmd);
int scst_cdrom_generic_parse(struct scst_cmd *cmd);
int scst_modisk_generic_parse(struct scst_cmd *cmd);
int scst_tape_generic_parse(struct scst_cmd *cmd);
int scst_changer_generic_parse(struct scst_cmd *cmd);
int scst_processor_generic_parse(struct scst_cmd *cmd);
int scst_raid_generic_parse(struct scst_cmd *cmd);

int scst_block_generic_dev_done(struct scst_cmd *cmd,
	void (*set_block_shift)(struct scst_cmd *cmd, int block_shift));
int scst_tape_generic_dev_done(struct scst_cmd *cmd,
	void (*set_block_size)(struct scst_cmd *cmd, int block_size));

int scst_obtain_device_parameters(struct scst_device *dev,
	const uint8_t *mode_select_cdb);

void scst_reassign_retained_sess_states(struct scst_session *new_sess,
	struct scst_session *old_sess);

int scst_get_max_lun_commands(struct scst_session *sess, uint64_t lun);

/*
 * Has to be put here open coded, because Linux doesn't have equivalent, which
 * allows exclusive wake ups of threads in LIFO order. We need it to let (yet)
 * unneeded threads sleep and not pollute CPU cache by their stacks.
 */
static inline void prepare_to_wait_exclusive_head(wait_queue_head_t *q,
						  wait_queue_t *wait, int state)
{
	unsigned long flags;

	wait->flags |= WQ_FLAG_EXCLUSIVE;
	spin_lock_irqsave(&q->lock, flags);
	if (list_empty(&wait->task_list))
		__add_wait_queue(q, wait);
	set_current_state(state);
	spin_unlock_irqrestore(&q->lock, flags);
}

/**
 * wait_event_locked() - Wait until a condition becomes true.
 * @wq: Wait queue to wait on if @condition is false.
 * @condition: Condition to wait for. Can be any C expression.
 * @lock_type: One of lock, lock_bh or lock_irq.
 * @lock: A spinlock.
 *
 * Caller must hold lock of type @lock_type on @lock.
 */
#define wait_event_locked(wq, condition, lock_type, lock)		\
if (!(condition)) {							\
	DEFINE_WAIT(__wait);						\
									\
	do {								\
		prepare_to_wait_exclusive_head(&(wq), &__wait,		\
					       TASK_INTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		spin_un ## lock_type(&(lock));				\
		schedule();						\
		spin_ ## lock_type(&(lock));				\
	} while (!(condition));						\
	finish_wait(&(wq), &__wait);					\
}

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

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
const char *scst_get_opcode_name(struct scst_cmd *cmd);
#else
static inline const char *scst_get_opcode_name(struct scst_cmd *cmd)
{
	return cmd->op_name;
}
#endif

#ifndef CONFIG_SCST_PROC

/*
 * Structure to match events to user space and replies on them
 */
struct scst_sysfs_user_info {
	/* Unique cookie to identify request */
	uint32_t info_cookie;

	/* Entry in the global list */
	struct list_head info_list_entry;

	/* Set if reply from the user space is being executed */
	unsigned int info_being_executed:1;

	/* Set if this info is in the info_list */
	unsigned int info_in_list:1;

	/* Completion to wait on for the request completion */
	struct completion info_completion;

	/* Request completion status and optional data */
	int info_status;
	void *data;
};

int scst_sysfs_user_add_info(struct scst_sysfs_user_info **out_info);
void scst_sysfs_user_del_info(struct scst_sysfs_user_info *info);
struct scst_sysfs_user_info *scst_sysfs_user_get_info(uint32_t cookie);
int scst_wait_info_completion(struct scst_sysfs_user_info *info,
	unsigned long timeout);

unsigned int scst_get_setup_id(void);


/*
 * Needed to avoid potential circular locking dependency between scst_mutex
 * and internal sysfs locking (s_active). It could be since most sysfs entries
 * are created and deleted under scst_mutex AND scst_mutex is taken inside
 * sysfs functions. So, we push from the sysfs functions all the processing
 * taking scst_mutex. To avoid deadlock, we return from them with EAGAIN
 * if processing is taking too long. User space then should poll
 * last_sysfs_mgmt_res until it returns the result of the processing
 * (something other than EAGAIN).
 */
struct scst_sysfs_work_item {
	/*
	 * If true, then last_sysfs_mgmt_res will not be updated. This is
	 * needed to allow read only sysfs monitoring during management actions.
	 * All management actions are supposed to be externally serialized,
	 * so then last_sysfs_mgmt_res automatically serialized too.
	 * Otherwise a monitoring action can overwrite value of simultaneous
	 * management action's last_sysfs_mgmt_res.
	 */
	bool read_only_action;

	struct list_head sysfs_work_list_entry;
	struct kref sysfs_work_kref;
	int (*sysfs_work_fn)(struct scst_sysfs_work_item *work);
	struct completion sysfs_work_done;
	char *buf;
	/*
	 * If the caller of scst_sysfs_queue_wait_work() holds a reference on
	 * a kobject, must point at the lockdep_map structure associated with
	 * that kobject.
	 */
	struct lockdep_map *dep_map;

	union {
		struct scst_dev_type *devt;
		struct scst_tgt_template *tgtt;
		struct {
			struct scst_tgt *tgt;
			struct scst_acg *acg;
			union {
				bool is_tgt_kobj;
				int io_grouping_type;
				bool enable;
				cpumask_t cpu_mask;
			};
		};
		struct {
			struct scst_device *dev;
			union {
				int new_threads_num;
				bool default_val;
			};
			enum scst_dev_type_threads_pool_type new_threads_pool_type;
		};
		struct scst_session *sess;
		struct {
			struct scst_tgt *tgt_r;
			unsigned long rel_tgt_id;
		};
		struct {
			struct kobject *kobj;
		};
	};
	int work_res;
	char *res_buf;
};

int scst_alloc_sysfs_work(int (*sysfs_work_fn)(struct scst_sysfs_work_item *),
	bool read_only_action, struct scst_sysfs_work_item **res_work);
int scst_sysfs_queue_wait_work(struct scst_sysfs_work_item *work);
void scst_sysfs_work_get(struct scst_sysfs_work_item *work);
void scst_sysfs_work_put(struct scst_sysfs_work_item *work);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
#ifdef CONFIG_LOCKDEP
extern struct lockdep_map scst_dev_dep_map;
#endif
#endif

#endif /* CONFIG_SCST_PROC */

char *scst_get_next_lexem(char **token_str);
void scst_restore_token_str(char *prev_lexem, char *token_str);
char *scst_get_next_token_str(char **input_str);

void scst_init_threads(struct scst_cmd_threads *cmd_threads);
void scst_deinit_threads(struct scst_cmd_threads *cmd_threads);

void scst_pass_through_cmd_done(void *data, char *sense, int result, int resid);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
int scst_scsi_exec_async(struct scst_cmd *cmd, void *data,
	void (*done)(void *data, char *sense, int result, int resid));
#endif

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

int scst_get_file_mode(const char *path);
bool scst_parent_dir_exists(const char *path);

struct scst_data_descriptor {
	uint64_t sdd_lba;
	uint64_t sdd_blocks;
};

void scst_write_same(struct scst_cmd *cmd);

__be64 scst_pack_lun(const uint64_t lun, enum scst_lun_addr_method addr_method);
uint64_t scst_unpack_lun(const uint8_t *lun, int len);

int scst_save_global_mode_pages(const struct scst_device *dev,
	uint8_t *buf, int size);
int scst_restore_global_mode_pages(struct scst_device *dev, char *params,
	char **last_param);

int scst_read_file_transactional(const char *name, const char *name1,
	const char *signature, int signature_len, uint8_t *buf, int size);
int scst_write_file_transactional(const char *name, const char *name1,
	const char *signature, int signature_len, const uint8_t *buf, int size);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
void scst_path_put(struct nameidata *nd);
#endif
int scst_remove_file(const char *name);

#endif /* __SCST_H */
