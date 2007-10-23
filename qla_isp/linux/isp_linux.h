/* $Id: isp_linux.h,v 1.138 2007/10/11 22:08:07 mjacob Exp $ */
/*
 *  Copyright (c) 1997-2007 by Matthew Jacob
 *  All rights reserved.
 * 
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 * 
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 
 *  THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 *  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE.
 * 
 * 
 *  Alternatively, this software may be distributed under the terms of the
 *  the GNU Public License ("GPL") with platforms where the prevalant license
 *  is the GNU Public License:
 * 
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of The Version 2 GNU General Public License as published
 *   by the Free Software Foundation.
 * 
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *  
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 * 
 * 
 *  Matthew Jacob
 *  Feral Software
 *  421 Laurel Avenue
 *  Menlo Park, CA 94025
 *  USA
 * 
 *  gplbsd at feral com
 */
/*
 * Qlogic ISP SCSI Host Adapter Linux Wrapper Definitions
 */

#ifndef _ISP_LINUX_H
#define _ISP_LINUX_H

#ifndef ISP_MODULE
#define __NO_VERSION__
#endif
#ifdef  MODULE
#define EXPORT_SYMTAB   1
#endif

#include <linux/version.h>
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(v,p,s)   (((v)<<16)+(p<<8)+s)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#error  "Only Linux 2.6 kernels are supported with this driver"
#endif

#ifndef UNUSED_PARAMETER
#define UNUSED_PARAMETER(x) (void) x
#endif

#include <linux/autoconf.h>
#ifdef  CONFIG_SMP
#define __SMP__ 1
#endif

#include <linux/module.h>
#include <linux/autoconf.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/pci.h>
#include <asm/dma.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/byteorder.h>
#include <linux/interrupt.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_device.h>

#include <linux/cdev.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
#include <linux/devfs_fs_kernel.h>
#define ISP_CLASS           struct class_simple
#define CREATE_ISP_CLASS    class_simple_create
#define DESTROY_ISP_CLASS   class_simple_destroy
#define CREATE_ISP_DEV(isp)     \
    class_simple_device_add(isp_class, MKDEV(MAJOR(isp_dev), isp->isp_unit), NULL, "%s%d", ISP_NAME, isp->isp_unit),     \
    devfs_mk_cdev(MKDEV(MAJOR(isp_dev), isp->isp_unit), S_IFCHR | S_IRUGO | S_IWUGO, "%s%d", ISP_NAME, isp->isp_unit)
#define DESTROY_ISP_DEV(isp)    \
    devfs_remove("%s%d", ISP_NAME, isp->isp_unit), class_simple_device_remove(MKDEV(MAJOR(isp_dev), isp->isp_unit))
#else
#define ISP_CLASS struct class
#define CREATE_ISP_CLASS    class_create
#define DESTROY_ISP_CLASS   class_destroy
#define CREATE_ISP_DEV(isp)     \
    class_device_create(isp_class, NULL, MKDEV(MAJOR(isp_dev), isp->isp_unit), NULL, "%s%d", ISP_NAME, isp->isp_unit)
#define DESTROY_ISP_DEV(isp)    \
    class_device_destroy(isp_class, MKDEV(MAJOR(isp_dev), (isp)->isp_unit));
#endif

typedef struct scsi_cmnd Scsi_Cmnd;
typedef struct scsi_request Scsi_Request;
typedef struct scsi_host_template Scsi_Host_Template;
#ifdef  CONFIG_PROC_FS
#include <linux/proc_fs.h>
#endif

/*
 * These bits and pieces of keeping track of Linux versions
 * and some of the various foo items for locking/unlocking
 * gratefully borrowed from (amongst others) Doug Ledford
 * and Gerard Roudier.
 */

#define PWRB(p, o, r)   pci_write_config_byte(p->pci_dev, o, r)
#define PWRW(p, o, r)   pci_write_config_word(p->pci_dev, o, r)
#define PWRL(p, o, r)   pci_write_config_dword(p->pci_dev, o, r)
#define PRDW(p, o, r)   pci_read_config_word(p->pci_dev, o, r)
#define PRDD(p, o, r)   pci_read_config_dword(p->pci_dev, o, r)
#define PRDB(p, o, r)   pci_read_config_byte(p->pci_dev, o, r)

/*
 * Efficiency- get rid of SBus code && tests unless we need them.
 */
#if defined(__sparcv9__ ) || defined(__sparc__)
#define ISP_SBUS_SUPPORTED  1
#else
#define ISP_SBUS_SUPPORTED  0
#endif

#ifndef ISP_NAME
#define ISP_NAME    "isp"
#endif

#define ISP_PLATFORM_VERSION_MAJOR  5
#define ISP_PLATFORM_VERSION_MINOR  0

#ifndef BIG_ENDIAN
#define BIG_ENDIAN  4321
#endif
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN   1234
#endif

#ifdef  __BIG_ENDIAN
#define BYTE_ORDER  BIG_ENDIAN
#endif
#ifdef  __LITTLE_ENDIAN
#define BYTE_ORDER  LITTLE_ENDIAN
#endif

#ifndef __WORDSIZE
#define __WORDSIZE  BITS_PER_LONG
#endif

#define DMA_HTYPE_T     dma_addr_t
#define QLA_HANDLE(cmd) (cmd)->SCp.dma_handle

#ifdef  min
#undef  min
#endif
#ifdef  max
#undef  max
#endif


/*
 * Normally this should be taken care of by typedefs,
 * but linux includes are a complete dog's breakfast.
 */

#define uint8_t    u8
#define uint16_t   u16
#define uint32_t   u32
#define uint64_t   u64
#define int8_t      char
#define int16_t     short
#define int32_t     int

#define u_long      unsigned long
#define uint       unsigned int
#define u_char      unsigned char
typedef u_long  vm_offset_t;

#ifdef  ISP_TARGET_MODE

#ifndef DEFAULT_DEVICE_TYPE
#define DEFAULT_DEVICE_TYPE 0
#endif
#define NTGT_CMDS           1024
#define N_NOTIFIES          256
#define DEFAULT_INQSIZE     32

#define _WIX(isp, b, ix)    (((b << 6)) | (ix >> 5))
#define _BIX(isp, ix)       (1 << (ix & 0x1f))

#define LUN_BTST(isp, b, ix)    (((isp)->isp_osinfo.lunbmap[_WIX(isp, b, ix)] & _BIX(isp, ix)) != 0)
#define LUN_BSET(isp, b, ix)    isp->isp_osinfo.lunbmap[_WIX(isp, b, ix)] |= _BIX(isp, ix)
#define LUN_BCLR(isp, b, ix)    isp->isp_osinfo.lunbmap[_WIX(isp, b, ix)] &= ~_BIX(isp, ix)

typedef struct isp_notify isp_notify_t;

#define cd_action   cd_lreserved[0].shorts[0]
#define cd_oxid     cd_lreserved[0].shorts[1]
#define cd_next     cd_lreserved[1].ptrs[0]
#define cd_nphdl    cd_lreserved[2].shorts[0]
#define cd_nseg     cd_lreserved[2].shorts[1]
#define cd_portid   cd_lreserved[3].longs[0]

#define CDFL_LCL        0x80000000
#define CDFL_RESRC_FILL 0x40000000
#define CDFL_CALL_CMPLT 0x20000000
#define CDFL_ABORTED    0x10000000
#define CDFL_NEED_CLNUP 0x08000000

#endif  /* ISP_TARGET_MODE */

typedef struct {
    enum {
        ISP_THREAD_NIL=1,
        ISP_THREAD_FC_RESCAN,
        ISP_THREAD_REINIT,
        ISP_THREAD_FW_CRASH_DUMP,
        ISP_THREAD_LOGOUT,
        ISP_THREAD_FINDIID,
        ISP_THREAD_TERMINATE,
        ISP_THREAD_FC_PUTBACK,
        ISP_THREAD_EXIT=99
    }   thread_action;
    void * arg;
    struct semaphore *  thread_waiter;
} isp_thread_action_t;
#define MAX_THREAD_ACTION   32

union pstore;
struct isposinfo {
    struct Scsi_Host *  host;
    u32                 mcorig;     /* original maxcmds */
    void                *device;    /* hardware device structure */
    Scsi_Cmnd           *wqnext, *wqtail;
    Scsi_Cmnd           *dqnext, *dqtail;
    union pstore        *storep;
#ifdef  CONFIG_PROC_FS
    struct proc_dir_entry *pdp;
#endif
    char                hbaname[16];
    long                bins[8];
    u16                 wqcnt;
    u16                 wqhiwater;
    u16                 hiwater;
    struct timer_list   timer;
    struct timer_list   _mbtimer;
    struct semaphore    _mbox_sem;
    struct semaphore    _mbox_c_sem;
    struct semaphore    _fcs_sem;
    spinlock_t          slock;
    unsigned volatile int
        _downcnt        : 8,
                        : 2,
        _qfdelay        : 6,
                        : 5,
        _isopen         : 1,
        _deadloop       : 1,
        _draining       : 1,
        _blocked        : 1,
        _fcrswdog       : 1,
        _fcrspend       : 1,
        _dogactive      : 1,
        _mboxcmd_done   : 1,
        _mbox_waiting   : 1,
        _mbintsok       : 1,
        _intsok         : 1;
    void *              misc[8]; /* private platform variant usage */
    struct task_struct *    task_thread;
    struct semaphore *  task_request;
    struct semaphore *  task_ctl_sem;
    spinlock_t          tlock;
    unsigned int        nt_actions;
    unsigned int        device_id;
    isp_thread_action_t t_actions[MAX_THREAD_ACTION];
#ifdef  ISP_TARGET_MODE
#define TM_WANTED           0x08
#define TM_BUSY             0x04
#define TM_TMODE_ENABLED    0x03
    uint32_t   rollinfo    : 16,
                rstatus     : 8,
                            : 1,
                isget       : 1,
                wildcarded  : 1,
                hcb         : 1,
                tmflags     : 4;
    struct semaphore    tgt_inisem;
    struct semaphore *  rsemap;
   /*
    * This is very inefficient, but is in fact big enough
    * to cover a complete bitmap for Fibre Channel, as well
    * as the dual bus SCSI cards. This works out without
    * overflow easily because the most you can enable
    * for the SCSI cards is 64 luns (x 2 busses).
    *
    * For Fibre Channel, we can run the max luns up to 16384
    * but we'll default to the minimum we can support here.
    */
#define TM_MAX_LUN_FC   64
#define TM_MAX_LUN_SCSI 64
    uint32_t                lunbmap[TM_MAX_LUN_FC >> 5];
    struct tmd_cmd *        pending_t;  /* pending list of commands going upstream */
    struct tmd_cmd *        tfreelist;  /* freelist head */
    struct tmd_cmd *        bfreelist;  /* freelist tail */
    struct tmd_cmd *        pool;       /* pool itself */
    isp_notify_t *          pending_n;  /* pending list of notifies going upstream */
    isp_notify_t *          nfreelist;  /* freelist */
    isp_notify_t *          npool;      /* pool itself */
    struct scatterlist *    dpwrk;
    uint8_t *               inqdata;
    uint64_t                cmds_started;
    uint64_t                cmds_completed;
    struct {
        uint32_t portid;
        uint32_t nphdl;
        uint64_t iid;
#define TM_CS   256
    } tgt_cache[TM_CS];
#endif
};
#define mbtimer         isp_osinfo._mbtimer
#define dogactive       isp_osinfo._dogactive
#define mbox_sem        isp_osinfo._mbox_sem
#define mbox_c_sem      isp_osinfo._mbox_c_sem
#define fcs_sem         isp_osinfo._fcs_sem
#define mbintsok        isp_osinfo._mbintsok
#define intsok          isp_osinfo._intsok
#define mbox_waiting    isp_osinfo._mbox_waiting
#define mboxcmd_done    isp_osinfo._mboxcmd_done
#define isp_pbuf        isp_osinfo._pbuf
#define isp_fcrspend    isp_osinfo._fcrspend
#define isp_fcrswdog    isp_osinfo._fcrswdog
#define isp_qfdelay     isp_osinfo._qfdelay
#define isp_blocked     isp_osinfo._blocked
#define isp_draining    isp_osinfo._draining
#define isp_downcnt     isp_osinfo._downcnt
#define isp_isopen      isp_osinfo._isopen
#define isp_deadloop    isp_osinfo._deadloop

#define SEND_THREAD_EVENT(isp, action, a, dowait, file, line)           \
if (isp->isp_osinfo.task_request) {                                     \
    unsigned long flags;                                                \
    spin_lock_irqsave(&isp->isp_osinfo.tlock, flags);                   \
    if (isp->isp_osinfo.nt_actions >= MAX_THREAD_ACTION) {              \
        spin_unlock_irqrestore(&isp->isp_osinfo.tlock, flags);          \
        isp_prt(isp, ISP_LOGERR, "thread event overflow");              \
    } else if (action == ISP_THREAD_FC_RESCAN && isp->isp_fcrspend) {   \
        spin_unlock_irqrestore(&isp->isp_osinfo.tlock, flags);          \
    } else {                                                            \
        DECLARE_MUTEX_LOCKED(sem);                                      \
        isp_thread_action_t *tap;                                       \
        tap = &isp->isp_osinfo.t_actions[isp->isp_osinfo.nt_actions++]; \
        tap->thread_action = action;                                    \
        tap->arg = a;                                                   \
        if (dowait) {                                                   \
            tap->thread_waiter = &sem;                                  \
        } else {                                                        \
            tap->thread_waiter = 0;                                     \
        }                                                               \
        if (action == ISP_THREAD_FC_RESCAN) {                           \
            isp->isp_fcrspend = 1;                                      \
        }                                                               \
        up(isp->isp_osinfo.task_request);                               \
        if (dowait) {                                                   \
            isp_prt(isp, ISP_LOGDEBUG1,                                 \
                "action %d sent from %s:%d and now waiting on %p", action, file, line, &sem);  \
            spin_unlock_irqrestore(&isp->isp_osinfo.tlock, flags);      \
            down(&sem);                                                 \
            isp_prt(isp, ISP_LOGDEBUG1,                                 \
                "action %d done from %p", action, &sem);                \
        } else {                                                        \
            isp_prt(isp, ISP_LOGDEBUG1, "action %d from %s:%d sent", action, file, line);      \
            spin_unlock_irqrestore(&isp->isp_osinfo.tlock, flags);      \
        }                                                               \
    }                                                                   \
}

/*
 * Locking macros...
 */
#define ISP_LOCK_INIT(isp)          spin_lock_init(&isp->isp_osinfo.slock)
#define ISP_LOCK_SOFTC(isp)         spin_lock_irqsave(&isp->isp_osinfo.slock, flags)
#define ISP_UNLK_SOFTC(isp)         spin_unlock_irqrestore(&isp->isp_osinfo.slock, flags)
#define ISP_ILOCK_SOFTC             ISP_LOCK_SOFTC
#define ISP_IUNLK_SOFTC             ISP_UNLK_SOFTC
#define ISP_IGET_LK_SOFTC(isp)      spin_lock_irq(&isp->isp_osinfo.slock)
#define ISP_DROP_LK_SOFTC(isp)      spin_unlock_irq(&isp->isp_osinfo.slock)
#define ISP_LOCK_SCSI_DONE(isp)     do { } while(0)
#define ISP_UNLK_SCSI_DONE(isp)     do { } while(0)
#define ISP_LOCKU_SOFTC             ISP_ILOCK_SOFTC
#define ISP_UNLKU_SOFTC             ISP_IUNLK_SOFTC
#define ISP_TLOCK_INIT(isp)         spin_lock_init(&isp->isp_osinfo.tlock)
#define ISP_DRIVER_ENTRY_LOCK(isp)  spin_unlock_irq(isp->isp_osinfo.host->host_lock)
#define ISP_DRIVER_EXIT_LOCK(isp)   spin_lock_irq(isp->isp_osinfo.host->host_lock)
#define ISP_DRIVER_CTL_ENTRY_LOCK(isp)  do { } while (0)
#define ISP_DRIVER_CTL_EXIT_LOCK(isp)   do { } while (0)

#define ISP_ATOMIC in_atomic

#define ISP_MUST_POLL(isp)          (ISP_ATOMIC() || isp->mbintsok == 0)

/*
 * Required Macros/Defines
 */

#if defined(CONFIG_HIGHMEM64G) || defined(CONFIG_X86_64)
#define ISP_DAC_SUPPORTED   1
#endif

#define ISP2100_SCRLEN  0x1000

#define MEMZERO(b, a)   memset(b, 0, a)
#define MEMCPY          memcpy
#define SNPRINTF        snprintf
#define USEC_DELAY      _isp_usec_delay
#define USEC_SLEEP(isp, x)                              \
        ISP_DROP_LK_SOFTC(isp);                         \
        __set_current_state(TASK_UNINTERRUPTIBLE);      \
        (void) schedule_timeout(_usec_to_jiffies(x));   \
        ISP_IGET_LK_SOFTC(isp)

#define NANOTIME_T      struct timeval
/* for prior to 2.2.19, use do_gettimeofday, and, well, it'll be inaccurate */
#define GET_NANOTIME(ptr)   (ptr)->tv_sec = 0, (ptr)->tv_usec = 0, do_gettimeofday(ptr)
#define GET_NANOSEC(x)      ((uint64_t) ((((uint64_t)(x)->tv_sec) * 1000000 + (x)->tv_usec)))
#define NANOTIME_SUB        _isp_microtime_sub

#define MAXISPREQUEST(isp)  ((IS_FC(isp) || IS_ULTRA2(isp))? 1024 : 256)

#if   defined(__powerpc__)
#define`MEMORYBARRIER(isp, type, offset, size)  __asm__ __volatile__("eieio" ::: "memory")
#else
#  ifdef mb
#    define MEMORYBARRIER(isp, type, offset, size)  mb()
#  else
#    define MEMORYBARRIER(isp, type, offset, size)  barrier()
#  endif
#endif

#define MBOX_ACQUIRE        mbox_acquire
#define MBOX_WAIT_COMPLETE  mbox_wait_complete
#define MBOX_NOTIFY_COMPLETE(isp)   \
    if (isp->mbox_waiting) {        \
        isp->mbox_waiting = 0;      \
        up(&isp->mbox_c_sem);       \
    }                               \
    isp->mboxcmd_done = 1
#define MBOX_RELEASE(isp)   up(&isp->mbox_sem)

#define FC_SCRATCH_ACQUIRE(isp)                         \
    /*                                                  \
     * Try and acquire semaphore the easy way first-    \
     * with our lock already held.                      \
     */                                                 \
    if (ISP_ATOMIC()) {                                 \
        while (down_trylock(&isp->fcs_sem)) {           \
            ISP_DROP_LK_SOFTC(isp);                     \
            USEC_DELAY(5000);                           \
            ISP_IGET_LK_SOFTC(isp);                     \
        }                                               \
    } else {                                            \
        ISP_DROP_LK_SOFTC(isp);                         \
        down(&isp->fcs_sem);                            \
        ISP_IGET_LK_SOFTC(isp);                         \
    }

#define FC_SCRATCH_RELEASE(isp) up(&isp->fcs_sem)


#ifndef SCSI_GOOD
#define SCSI_GOOD   0x0
#endif
#ifndef SCSI_CHECK
#define SCSI_CHECK  0x2
#endif
#ifndef SCSI_BUSY
#define SCSI_BUSY   0x8
#endif
#ifndef SCSI_QFULL
#define SCSI_QFULL  0x28
#endif

#ifndef REPORT_LUNS
#define REPORT_LUNS 0xa0
#endif

#define XS_T                Scsi_Cmnd
#define XS_DMA_ADDR_T       dma_addr_t

#define XS_HOST(Cmnd)       Cmnd->device->host
#define XS_CHANNEL(Cmnd)    (Cmnd)->device->channel
#define XS_TGT(Cmnd)        (Cmnd)->device->id
#define XS_LUN(Cmnd)        (Cmnd)->device->lun

#define SCSI_DATA_NONE      DMA_NONE
#define SCSI_DATA_READ      DMA_FROM_DEVICE
#define SCSI_DATA_WRITE     DMA_TO_DEVICE
#define scsi_to_pci_dma_dir(x)  x

#define XS_ISP(Cmnd)        ((ispsoftc_t *)XS_HOST(Cmnd)->hostdata)
#define XS_CDBP(Cmnd)       (Cmnd)->cmnd
#define XS_CDBLEN(Cmnd)     (Cmnd)->cmd_len
#define XS_XFRLEN(Cmnd)     (Cmnd)->request_bufflen
#define XS_TIME(Cmnd)       ((((Cmnd)->timeout_per_command) * HZ)*1000)
#define XS_RESID(Cmnd)      (Cmnd)->SCp.this_residual
#define XS_STSP(Cmnd)       (&(Cmnd)->SCp.Status)
#define XS_SNSP(Cmnd)       (Cmnd)->sense_buffer
#define XS_SNSLEN(Cmnd)     (sizeof (Cmnd)->sense_buffer)
#define XS_SNSKEY(Cmnd)     ((Cmnd)->sense_buffer[2] & 0xf)
#define XS_TAG_P(Cmnd)      (Cmnd->device->tagged_supported != 0)
#define XS_TAG_TYPE         isplinux_tagtype

#define XS_SETERR(xs, v)                \
    if ((v) == HBA_TGTBSY) {            \
        (xs)->SCp.Status = SCSI_BUSY;   \
    } else {                            \
        (xs)->result &= ~0xff0000;      \
        (xs)->result |= ((v) << 16);    \
    }

#define HBA_NOERROR     DID_OK
#define HBA_BOTCH       DID_ERROR
#define HBA_CMDTIMEOUT  DID_TIME_OUT
#define HBA_SELTIMEOUT  DID_NO_CONNECT
#define HBA_TGTBSY      123456 /* special handling */
#define HBA_BUSRESET    DID_RESET
#define HBA_ABORTED     DID_ABORT
#define HBA_DATAOVR     DID_ERROR
#define HBA_ARQFAIL     DID_ERROR

#define XS_ERR(xs)      host_byte((xs)->result)

#define XS_NOERR(xs)    host_byte((xs)->result) == DID_OK

#define XS_INITERR(xs)  (xs)->result = 0, (xs)->SCp.Status = 0

#define XS_SAVE_SENSE(Cmnd, s, l)     \
    MEMCPY(&Cmnd->sense_buffer, s, min(sizeof Cmnd->sense_buffer, l))

#define XS_SET_STATE_STAT(a, b, c)

#define DEFAULT_IID             isplinux_default_id
#define DEFAULT_LOOPID          isplinux_default_id
#define DEFAULT_NODEWWN(isp)    (isp)->isp_defwwnn
#define DEFAULT_PORTWWN(isp)    (isp)->isp_defwwpn
#define DEFAULT_FRAME_SIZE(isp) (IS_SCSI(isp)? 0 : isp->isp_osinfo.storep->fibre_scsi.default_frame_size)
#define DEFAULT_EXEC_ALLOC(isp) (IS_SCSI(isp)? 0 : isp->isp_osinfo.storep->fibre_scsi.default_exec_alloc)
#define ISP_NODEWWN(isp)        (isp)->isp_actvwwnn
#define ISP_PORTWWN(isp)        (isp)->isp_actvwwpn

#define ISP_IOXPUT_8(isp, s, d)     *(d) = s
#define ISP_IOXPUT_16(isp, s, d)    *(d) = cpu_to_le16(s)
#define ISP_IOXPUT_32(isp, s, d)    *(d) = cpu_to_le32(s)
#define ISP_IOXGET_8(isp, s, d)     d = *(s)
#define ISP_IOXGET_16(isp, s, d)    d = le16_to_cpu(*((uint16_t *)s))
#define ISP_IOXGET_32(isp, s, d)    d = le32_to_cpu(*((uint32_t *)s))

#if BYTE_ORDER == BIG_ENDIAN
#define ISP_IOX_8X2(isp, sptr, dptr, tag1, tag2)    \
    dptr ## -> ## tag1 = sptr ## -> ## tag2;        \
    dptr ## -> ## tag2 = sptr ## -> ## tag1
#define ISP_IOZ_8X2(isp, sptr, dptr, tag1, tag2)    \
    dptr ## -> ## tag1 = sptr ## -> ## tag1;        \
    dptr ## -> ## tag2 = sptr ## -> ## tag2
#else
#define ISP_IOX_8X2(isp, sptr, dptr, tag1, tag2)    \
    dptr ## -> ## tag1 = sptr ## -> ## tag1;        \
    dptr ## -> ## tag2 = sptr ## -> ## tag2
#define ISP_IOZ_8X2(isp, sptr, dptr, tag1, tag2)    \
    dptr ## -> ## tag1 = sptr ## -> ## tag2;        \
    dptr ## -> ## tag2 = sptr ## -> ## tag1
#endif

#define ISP_IOZPUT_8                ISP_IOXPUT_8
#define ISP_IOZPUT_16(isp, s, d)    *(d) = cpu_to_be16(s)
#define ISP_IOZPUT_32(isp, s, d)    *(d) = cpu_to_be32(s)
#define ISP_IOZGET_8                ISP_IOXGET_8
#define ISP_IOZGET_16(isp, s, d)    d = be16_to_cpu(*((uint16_t *)s))
#define ISP_IOZGET_32(isp, s, d)    d = be32_to_cpu(*((uint32_t *)s))

#define ISP_SWIZZLE_NVRAM_WORD(isp, rp) *rp = le16_to_cpu(*rp)
#define ISP_SWIZZLE_NVRAM_LONG(isp, rp) *rp = le32_to_cpu(*rp)

#define ISP_SWAP16(isp, x)  swab16(x)
#define ISP_SWAP32(isp, x)  swab32(x)


/*
 * Includes of common header files
 */
#include "ispreg.h"
#include "ispvar.h"

#if defined(__GNUC__) || defined(__INTEL_COMPILER)
void isp_prt(ispsoftc_t *, int level, const char *, ...) __attribute__((__format__(__printf__, 3, 4)));
#else
void isp_prt(ispsoftc_t *, int level, const char *, ...);
#endif


/*
 * isp_osinfo definitions, extensions and shorthand.
 */

/*
 * Parameter storage. The order of tags is important- sdparam && fcp
 * must come first because isp->isp_params is set to point there...
 */
union pstore {
    struct {
        sdparam _sdp[2];    /* they need to be sequential */
        u_char psc_opts[2][MAX_TARGETS];
        u_char dutydone;
    } parallel_scsi;
    struct {
        fcparam fcp;
        uint64_t def_wwnn;
        uint64_t def_wwpn;
        uint64_t actv_wwnn;
        uint64_t actv_wwpn;
        uint16_t default_frame_size;
        uint16_t default_exec_throttle;
    } fibre_scsi;
};
#define isp_name        isp_osinfo.hbaname
#define isp_host        isp_osinfo.host
#define isp_unit        isp_osinfo.host->unique_id
#define isp_psco        isp_osinfo.storep->parallel_scsi.psc_opts
#define isp_dutydone    isp_osinfo.storep->parallel_scsi.dutydone
#define isp_defwwnn     isp_osinfo.storep->fibre_scsi.def_wwnn
#define isp_defwwpn     isp_osinfo.storep->fibre_scsi.def_wwpn
#define isp_actvwwnn    isp_osinfo.storep->fibre_scsi.actv_wwnn
#define isp_actvwwpn    isp_osinfo.storep->fibre_scsi.actv_wwpn

/*
 * Driver prototypes..
 */
void isplinux_timer(unsigned long);
void isplinux_mbtimer(unsigned long);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
irqreturn_t isplinux_intr(int, void *, struct pt_regs *);
#else
irqreturn_t isplinux_intr(int, void *);
#endif
int isplinux_common_init(ispsoftc_t *);
#ifdef  CONFIG_PROC_FS
void isplinux_init_proc(ispsoftc_t *);
void isplinux_undo_proc(ispsoftc_t *);
#endif
int isplinux_reinit(ispsoftc_t *);
void isplinux_sqd(struct Scsi_Host *, struct scsi_device *);

int isp_drain_reset(ispsoftc_t *, char *);
int isp_drain(ispsoftc_t *, char *);

static __inline uint64_t _isp_microtime_sub(struct timeval *, struct timeval *);
static __inline void _isp_usec_delay(unsigned int);
static __inline unsigned long _usec_to_jiffies(unsigned int);
static __inline unsigned long _jiffies_to_usec(unsigned long);
static __inline int isplinux_tagtype(Scsi_Cmnd *);
static __inline int mbox_acquire(ispsoftc_t *);
static __inline void mbox_wait_complete(ispsoftc_t *, mbreg_t *);

int isplinux_proc_info(struct Scsi_Host *, char *, char **, off_t, int, int);
const char *isplinux_info(struct Scsi_Host *);
int isplinux_queuecommand(Scsi_Cmnd *, void (* done)(Scsi_Cmnd *));
int isplinux_biosparam(struct scsi_device *, struct block_device *, sector_t, int[]); 
int isplinux_default_id(ispsoftc_t *);

/*
 * Driver wide data...
 */
extern int isp_debug;
extern int isp_unit_seed;
extern int isp_disable;
extern int isp_nofwreload;
extern int isp_nonvram;
extern int isp_fcduplex;
extern int isp_maxsectors;
extern struct scsi_host_template *isp_template;
extern const char *class3_roles[4];
extern dev_t isp_dev;
extern struct cdev isp_cdev;
extern struct file_operations isp_ioctl_operations;
extern ISP_CLASS *isp_class;

/*
 * This used to be considered bad form, but locking crasp made it more attractive.
 */
#define MAX_ISP     32
extern ispsoftc_t *isplist[MAX_ISP];
extern ispsoftc_t *api_isp;

/*
 * Platform private flags
 */
#ifndef NULL
#define NULL ((void *) 0)
#endif

#define ISP_WATCH_TPS   10
#define ISP_WATCH_TIME  (HZ / ISP_WATCH_TPS)

#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef max
#define max(a, b)   (((a) > (b)) ? (a) : (b))
#endif
#ifndef roundup
#define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#endif
#ifndef ARGSUSED
#define ARGSUSED(x) x = x
#endif

/*
 * Platform specific 'inline' or support functions
 */

#ifdef  __sparc__
#define _SBSWAP(isp, b, c)                      \
    if (isp->isp_bustype == ISP_BT_SBUS) {      \
        uint8_t tmp = b;                       \
        b = c;                                  \
        c = tmp;                                \
    }
#else
#define _SBSWAP(a, b, c)
#endif

static __inline uint64_t
_isp_microtime_sub(struct timeval *b, struct timeval *a)
{
    uint64_t elapsed;
    struct timeval x = *b;
    x.tv_sec -= a->tv_sec;
    x.tv_usec -= a->tv_usec;
    if (x.tv_usec < 0) {
        x.tv_sec--;
        x.tv_usec += 1000000;
    }
    if (x.tv_usec >= 1000000) {
        x.tv_sec++;
        x.tv_usec -= 1000000;
    }
    elapsed = GET_NANOSEC(&x);
    if (elapsed == 0)
        elapsed++;
    if ((int64_t) elapsed < 0)  /* !!!! */
        return (1000);
    return (elapsed * 1000);
}

static __inline void
_isp_usec_delay(unsigned int usecs)
{
    while (usecs > 1000) {
        mdelay(1);
        usecs -= 1000;
    }
    if (usecs)
        udelay(usecs);
}

static __inline unsigned long
_usec_to_jiffies(unsigned int usecs)
{
    struct timespec lt;
    if (usecs == 0)
        usecs++;
    lt.tv_sec = 0;
    lt.tv_nsec = usecs * 1000;
    return (timespec_to_jiffies(&lt));
}

static __inline unsigned long
_jiffies_to_usec(unsigned long jiffies)
{
    unsigned long usecs;
    struct timespec lt;
    jiffies++;
    jiffies_to_timespec((unsigned long) jiffies, &lt);
    usecs = (lt.tv_sec * 1000000L);
    usecs += (lt.tv_nsec * 1000);
    return (usecs);
}

#ifndef MSG_SIMPLE_TAG
#define MSG_SIMPLE_TAG  0x20
#endif
#ifndef MSG_HEAD_TAG
#define MSG_HEAD_TAG    0x21
#endif
#ifndef MSG_ORDERED_TAG
#define MSG_ORDERED_TAG 0x22
#endif

static __inline int
isplinux_tagtype(Scsi_Cmnd *Cmnd)
{
    switch (Cmnd->tag) {
    case MSG_ORDERED_TAG:
        return (REQFLAG_OTAG);
    case MSG_SIMPLE_TAG:
        return (REQFLAG_STAG);
    case MSG_HEAD_TAG:
        return (REQFLAG_HTAG);
    default:
        return (REQFLAG_STAG);
    }
}

static __inline int
mbox_acquire(ispsoftc_t *isp)
{
    /*
     * Try and acquire semaphore the easy way first-
     * with our lock already held.k
     */
    if (down_trylock(&isp->mbox_sem)) {
        if (ISP_ATOMIC()) {
            isp_prt(isp, ISP_LOGERR, "cannot acquire MBOX sema");
            return (1);
        }
        ISP_DROP_LK_SOFTC(isp);
        down(&isp->mbox_sem);
        ISP_IGET_LK_SOFTC(isp);
    }
    return (0);
}

static __inline void
mbox_wait_complete(ispsoftc_t *isp, mbreg_t *mbp)
{
    uint32_t lim = mbp->timeout;
    unsigned long long tt = jiffies;

    if (lim == 0) {
        lim = MBCMD_DEFAULT_TIMEOUT;
    }
    if (isp->isp_mbxwrk0) {
        lim *= isp->isp_mbxwrk0;
    }

    isp->mboxcmd_done = 0;
    if (ISP_MUST_POLL(isp)) {
        int j;

        for (j = 0; j < lim; j += 100) {
            uint32_t isr;
            uint16_t  sema, mbox;
            if (isp->mboxcmd_done) {
                break;
            }
            if (ISP_READ_ISR(isp, &isr, &sema, &mbox)) {
                isp_intr(isp, isr, sema, mbox);
                if (isp->mboxcmd_done) {
                    break;
                }
            }
            udelay(100);
        }
        if (isp->mboxcmd_done == 0) {
            isp_prt(isp, ISP_LOGWARN, "Polled Mailbox Command (0x%x) Timeout (%llu elapsed jiffies)", isp->isp_lastmbxcmd, ((unsigned long long) jiffies) - tt);
            mbp->param[0] = MBOX_TIMEOUT;
        }
    } else {
        isp_prt(isp, ISP_LOGDEBUG1, "Start Interrupting Mailbox Command (%x)", isp->isp_lastmbxcmd);
        init_timer(&isp->mbtimer);
        isp->mbtimer.data = (unsigned long) isp;
        isp->mbtimer.function = isplinux_mbtimer;
        isp->mbtimer.expires = tt;
        isp->mbtimer.expires += ((lim/1000000) * HZ);
        isp->mbtimer.expires += ((lim%1000000) / HZ);
        add_timer(&isp->mbtimer);
        isp->mbox_waiting = 1;
        ISP_ENABLE_INTS(isp);
        ISP_DROP_LK_SOFTC(isp);
        down(&isp->mbox_c_sem);
        ISP_IGET_LK_SOFTC(isp);
        isp->mbox_waiting = 0;
        del_timer(&isp->mbtimer);
        if (isp->mboxcmd_done == 0) {
            isp_prt(isp, ISP_LOGWARN, "Interrupting Mailbox Command (0x%x) Timeout (elapsed time %llu jiffies)", isp->isp_lastmbxcmd,
                ((unsigned long long) jiffies) - tt);
            mbp->param[0] = MBOX_TIMEOUT;
        } else {
            isp_prt(isp, ISP_LOGDEBUG1, "Interrupting Mailbox Command (0x%x) done (%llu jiffies)", isp->isp_lastmbxcmd, ((unsigned long long) jiffies) - tt);
        }
    }
}


/*
 * Note that these allocators aren't interrupt safe
 */
static __inline void * isp_kalloc(size_t, int);
static __inline void   isp_kfree(void *, size_t);
static __inline void * isp_kzalloc(size_t, int);

static __inline void *
isp_kalloc(size_t size, int flags)
{
    void *ptr;
    if (size >= PAGE_SIZE) {
        ptr = vmalloc(size);
    } else {
        ptr = kmalloc(size, flags);
    }
    return (ptr);
}

static __inline void
isp_kfree(void *ptr, size_t size)
{
    if (size >= PAGE_SIZE) {
        vfree(ptr);
    } else {
        kfree(ptr);
    }
}

static __inline void *
isp_kzalloc(size_t size, int flags)
{
    void *ptr = isp_kalloc(size, flags);
    if (ptr != NULL){
        memset(ptr, 0, size);
    }
    return (ptr);
}

#define COPYIN(uarg, karg, amt)     copy_from_user(karg, uarg, amt)
#define COPYOUT(karg, uarg, amt)    copy_to_user(uarg, karg, amt)

/*
 * Common inline functions
 */

#include "isp_library.h"

#ifdef  ISP_TARGET_MODE
#include "isp_tpublic.h"

int isp_init_target(ispsoftc_t *);
void isp_attach_target(ispsoftc_t *);
void isp_deinit_target(ispsoftc_t *);
void isp_detach_target(ispsoftc_t *);
int isp_target_async(ispsoftc_t *, int, int);
int isp_target_notify(ispsoftc_t *, void *, uint32_t *);
int isp_en_dis_lun(ispsoftc_t *, int, uint16_t, uint64_t, uint16_t);

struct isp_notify {
    tmd_notify_t    notify;
    uint8_t         qentry[QENTRY_LEN]; /* original immediate notify entry */
    uint8_t         qevalid;
};
#endif
/*
 * Config data
 */

int isplinux_abort(Scsi_Cmnd *);
int isplinux_bdr(Scsi_Cmnd *);
int isplinux_sreset(Scsi_Cmnd *);
int isplinux_hreset(Scsi_Cmnd *);
#endif /* _ISP_LINUX_H */
/*
 * vim:ts=4:sw=4:expandtab
 */
