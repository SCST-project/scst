/* $Id: isp_linux.h,v 1.176 2009/09/06 00:37:07 mjacob Exp $ */
/*
 *  Copyright (c) 1997-2009 by Matthew Jacob
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0) || LINUX_VERSION_CODE >=  KERNEL_VERSION(2,7,0)
#error  "Only Linux 2.5/2.6 kernels are supported with this driver"
#endif

#ifndef UNUSED_PARAMETER
#define UNUSED_PARAMETER(x) (void) x
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)
#include <linux/autoconf.h>
#else
#include <generated/autoconf.h>
#endif

#ifdef  CONFIG_SMP
#define __SMP__ 1
#endif

#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/kthread.h>
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,13)
#include <linux/devfs_fs_kernel.h>
#define ISP_CLASS           struct class_simple
#define CREATE_ISP_CLASS    class_simple_create
#define DESTROY_ISP_CLASS   class_simple_destroy

#define CREATE_ISP_DEV(isp, class)     \
    class_simple_device_add(class, MKDEV(MAJOR(isp_dev), isp->isp_unit), NULL, "%s%d", ISP_NAME, isp->isp_unit),     \
    devfs_mk_cdev(MKDEV(MAJOR(isp_dev), isp->isp_unit), S_IFCHR | S_IRUGO | S_IWUGO, "%s%d", ISP_NAME, isp->isp_unit)
#define DESTROY_ISP_DEV(isp)    \
    devfs_remove("%s%d", ISP_NAME, isp->isp_unit), class_simple_device_remove(MKDEV(MAJOR(isp_dev), isp->isp_unit))

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
#define ISP_CLASS               struct class
#define CREATE_ISP_CLASS        class_create
#define DESTROY_ISP_CLASS       class_destroy

#define CREATE_ISP_DEV(isp, class)     \
    class_device_create(class, NULL, MKDEV(MAJOR(isp_dev), isp->isp_unit), NULL, "%s%d", ISP_NAME, isp->isp_unit)
#define DESTROY_ISP_DEV(isp)    \
    class_device_destroy(isp_class, MKDEV(MAJOR(isp_dev), (isp)->isp_unit));

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
#define ISP_CLASS               struct class
#define CREATE_ISP_CLASS        class_create
#define DESTROY_ISP_CLASS       class_destroy
#define CREATE_ISP_DEV(i, c)    (void) device_create(c, NULL, MKDEV(MAJOR(isp_dev), (i)->isp_unit), "%s%d", ISP_NAME, (i)->isp_unit);
#define DESTROY_ISP_DEV(i)      device_destroy(isp_class, MKDEV(MAJOR(isp_dev), (i)->isp_unit));
#else
#define ISP_CLASS               struct class
#define CREATE_ISP_CLASS        class_create
#define DESTROY_ISP_CLASS       class_destroy
#define CREATE_ISP_DEV(i, c)    (void) device_create(c, NULL, MKDEV(MAJOR(isp_dev), (i)->isp_unit), NULL, "%s%d", ISP_NAME, (i)->isp_unit);
#define DESTROY_ISP_DEV(i)      device_destroy(isp_class, MKDEV(MAJOR(isp_dev), (i)->isp_unit));
#endif

typedef struct scsi_cmnd Scsi_Cmnd;
typedef struct scsi_request Scsi_Request;
typedef struct scsi_host_template Scsi_Host_Template;
#ifdef  CONFIG_PROC_FS
#include <linux/proc_fs.h>
#endif

/*
 * Efficiency- get rid of SBus code && tests unless we need them.
 */
#if defined(__sparcv9__ ) || defined(__sparc__)
#define ISP_SBUS_SUPPORTED  1
#else
#define ISP_SBUS_SUPPORTED  0
#endif

#define ISP_PLATFORM_VERSION_MAJOR  6
#define ISP_PLATFORM_VERSION_MINOR  1

#ifndef ISP_NAME
#define ISP_NAME    "isp"
#endif

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

#define	ull	unsigned long long

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define sg_page(_sg)                ((_sg)->page)
#define sg_assign_page(_sg, _pg)    ((_sg)->page = (_pg))
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

/* bit map using 8 bit arrays */
typedef uint8_t isp_bmap_t;
#define _ISP_WIX(isp, ix)   (ix >> 3)
#define _ISP_BIX(isp, ix)   (1 << (ix & 0x7))
#define ISP_NBPIDX(x)       ((x + 7) / 8)  /* index width from bits */
#define ISP_BTST(map, ix)   (((map)[_ISP_WIX(isp, ix)] & _ISP_BIX(isp, ix)) != 0)
#define ISP_BSET(map, ix)   (map)[_ISP_WIX(isp, ix)] |= _ISP_BIX(isp, ix)
#define ISP_BCLR(map, ix)   (map)[_ISP_WIX(isp, ix)] &= ~_ISP_BIX(isp, ix)

#ifdef  ISP_TARGET_MODE

#include "isp_tpublic.h"

#ifndef DEFAULT_DEVICE_TYPE
#define DEFAULT_DEVICE_TYPE 0
#endif
#define NTGT_CMDS           1024
#define N_NOTIFIES          256
#define DEFAULT_INQSIZE     32

typedef struct notify notify_t;

#define cd_action   cd_lreserved[0].shorts[0]
#define cd_oxid     cd_lreserved[0].shorts[1]
#define cd_lflags   cd_lreserved[0].shorts[2]
#define cd_nphdl    cd_lreserved[0].shorts[3]
#define cd_nseg     cd_lreserved[1].longs[0]
#define cd_portid   cd_lreserved[1].longs[1]
#define cd_next     cd_lreserved[2].ptrs[0]
#define cd_lastoff  cd_lreserved[3].longs[0]
#define cd_lastsize cd_lreserved[3].longs[1]

#define CDFL_LCL        0x8000
#define CDFL_RESRC_FILL 0x4000
#define CDFL_ABORTED    0x2000
#define CDFL_NEED_CLNUP 0x1000
#define CDFL_BUSY       0x0800

typedef struct enalun tgt_enalun_t;
struct enalun {
    tgt_enalun_t *  next;
    uint16_t        lun;
    uint16_t        bus;
};

typedef struct {
    struct scatterlist sg;
    tmd_xact_t         xact;
} tgt_auxcmd_t;
#define	N_TGT_AUX	32

#define ISP_CT_TIMEOUT  120
#endif  /* ISP_TARGET_MODE */

typedef struct isp_thread_action isp_thread_action_t;
struct isp_thread_action {
    isp_thread_action_t *next;
    enum {
        ISP_THREAD_NIL=1,
        ISP_THREAD_FC_RESCAN,
        ISP_THREAD_REINIT,
        ISP_THREAD_FW_CRASH_DUMP,
        ISP_THREAD_LOGOUT,
        ISP_THREAD_FINDIID,
        ISP_THREAD_FINDPORTID,
        ISP_THREAD_TERMINATE,
        ISP_THREAD_RESTART_AT7,
        ISP_THREAD_FC_PUTBACK,
        ISP_THREAD_SCSI_SCAN,
    }   thread_action;
    void * arg;
    wait_queue_head_t thread_waiter;
    uint32_t
        waiting :   1,
        done    :   1,
        count   :   30;
};
#define MAX_THREAD_ACTION   128
#define MAX_FC_CHAN         128

#define ISP_HOST2ISP(host)  (ispsoftc_t *) host->hostdata

struct isposinfo {
    struct Scsi_Host *  host;
    unsigned int        device_id;
    u32                 mcorig;     /* original maxcmds */
    void                *device;    /* hardware device structure */
    Scsi_Cmnd           *wqnext, *wqtail;
    Scsi_Cmnd           *dqnext, *dqtail;
    void *              storep;
    size_t              storep_amt;
    size_t              param_amt;
    const struct firmware *fwp;
#ifdef  CONFIG_PROC_FS
    struct proc_dir_entry *pdp;
#endif
    char                hbaname[16];
    long                bins[8];
    u16                 wqcnt;
    u16                 wqhiwater;
    u16                 hiwater;
    struct timer_list   timer;
    struct semaphore    mbox_sem;
    wait_queue_head_t   mboxwq;
    struct semaphore    mbox_c_sem;
    spinlock_t          slock;
    uint32_t
        dogcnt          : 5,
        isopen          : 1,
        is_64bit_dma    : 1,
        dogactive       : 1,
        mboxcmd_done    : 1,
        mbintsok        : 1,
        intsok          : 1;
    u16                 scan_timeout;
    u16                 rescan_timeout;
    u16                 frame_size;
    u16                 exec_throttle;
    struct task_struct *thread_task;
    wait_queue_head_t   trq;
    spinlock_t          tlock;
    isp_thread_action_t t_actions[MAX_THREAD_ACTION];
    isp_thread_action_t *t_free;
    isp_thread_action_t *t_busy, *t_busy_t;
#ifdef  ISP_TARGET_MODE
    u32         isget       : 16,
                rstatus     : 8,
                            : 7,
                hcb         : 1;
    struct semaphore    tgt_inisem;
    struct semaphore *  rsemap;
    tgt_enalun_t *          luns;       /* enabled { lun, port } tuples */
    struct tmd_cmd *        pending_t;  /* pending list of commands going upstream */
    struct tmd_cmd *        waiting_t;  /* pending list of commands waiting to be fleshed out */
    struct tmd_cmd *        tfreelist;  /* freelist head */
    struct tmd_cmd *        bfreelist;  /* freelist tail */
    struct tmd_cmd *        pool;       /* pool itself */
    notify_t *              pending_n;  /* pending list of notifies going upstream */
    notify_t *              nfreelist;  /* freelist */
    notify_t *              npool;      /* pool itself */
    struct tmd_xact *       pending_x;  /* pending list of xacts going upstream */
    /*
     * When we have inquiry commands that we have to xfer data with
     * locally we have to have some aux info (scatterlist, tmd_xact_t)
     * to manage those commands.
     */
    tgt_auxcmd_t            auxinfo[N_TGT_AUX];
    isp_bmap_t              auxbmap[ISP_NBPIDX(N_TGT_AUX)];
    u8                      inqdata[DEFAULT_INQSIZE];

    u64                     cmds_started;
    u64                     cmds_completed;
    unsigned long           out_of_tmds;
#endif
};
#define mbtimer         isp_osinfo.mbtimer
#define dogactive       isp_osinfo.dogactive
#define mbintsok        isp_osinfo.mbintsok
#define intsok          isp_osinfo.intsok
#define mbox_waiting    isp_osinfo.mbox_waiting
#define mboxcmd_done    isp_osinfo.mboxcmd_done
#define isp_isopen      isp_osinfo.isopen

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

#define ISP_MUST_POLL(isp)          (in_interrupt() || isp->mbintsok == 0)

/*
 * Required Macros/Defines
 */

#define ISP_FC_SCRLEN   0x1000

#define ISP_MEMZERO(b, a)   memset(b, 0, a)
#define ISP_MEMCPY          memcpy
#define ISP_SNPRINTF        snprintf
#define ISP_DELAY           _isp_usec_delay
#define ISP_SLEEP(isp, x)                               \
        ISP_DROP_LK_SOFTC(isp);                         \
        __set_current_state(TASK_UNINTERRUPTIBLE);      \
        (void) schedule_timeout(_usec_to_jiffies(x));   \
        ISP_IGET_LK_SOFTC(isp)

#define ISP_INLINE          inline

#define NANOTIME_T      struct timeval
/* for prior to 2.2.19, use do_gettimeofday, and, well, it'll be inaccurate */
#define GET_NANOTIME(ptr)   (ptr)->tv_sec = 0, (ptr)->tv_usec = 0, do_gettimeofday(ptr)
#define GET_NANOSEC(x)      ((uint64_t) ((((uint64_t)(x)->tv_sec) * 1000000 + (x)->tv_usec)))
#define NANOTIME_SUB        _isp_microtime_sub

#define MAXISPREQUEST(isp)  (IS_24XX(isp)? 2048 : ((IS_FC(isp) || IS_ULTRA2(isp))? 1024 : 256))

#if   defined(__powerpc__)
#define MEMORYBARRIER(isp, type, offset, size)  __asm__ __volatile__("eieio" ::: "memory")
#else
#  ifdef mb
#    define MEMORYBARRIER(isp, type, offset, size)  mb()
#  else
#    define MEMORYBARRIER(isp, type, offset, size)  barrier()
#  endif
#endif

#define MBOX_ACQUIRE(isp)   down_trylock(&isp->isp_osinfo.mbox_sem)
#define MBOX_WAIT_COMPLETE  mbox_wait_complete
#define MBOX_NOTIFY_COMPLETE(isp)       \
    wake_up(&isp->isp_osinfo.mboxwq);   \
    isp->mboxcmd_done = 1
#define MBOX_RELEASE(isp)   up(&isp->isp_osinfo.mbox_sem)

#define FC_SCRATCH_ACQUIRE              fc_scratch_acquire
#define FC_SCRATCH_RELEASE(isp, chan)   ISP_DATA(isp, chan)->scratch_busy = 0


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
#define XS_GET_DMA64_SEG    isp_get_dma64_seg
#define XS_GET_DMA_SEG      isp_get_dma_seg
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define XS_GET_RESID(Cmnd)          (Cmnd)->SCp.this_residual
#define XS_SET_RESID(Cmnd, resid)   (Cmnd)->SCp.this_residual = resid
#define XS_XFRLEN(Cmnd)             (Cmnd)->request_bufflen
#else
#define XS_GET_RESID        scsi_get_resid
#define XS_SET_RESID        scsi_set_resid
#define XS_XFRLEN           scsi_bufflen
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
#define XS_TIME(Cmnd)       ((((Cmnd)->timeout_per_command) * HZ)*1000)
#else
#define XS_TIME(Cmnd)       ((((Cmnd)->request->timeout) * HZ)*1000)
#endif
#define XS_STSP(Cmnd)       (&(Cmnd)->SCp.Status)
#define XS_SNSP(Cmnd)       (Cmnd)->sense_buffer
#define XS_SNSLEN(Cmnd)     SCSI_SENSE_BUFFERSIZE
#define XS_SNSKEY(Cmnd)     (XS_SNSP(Cmnd)[2] & 0xf)
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

#define XS_SAVE_SENSE(Cmnd, s, l)   memcpy(XS_SNSP(Cmnd), s, min(XS_SNSLEN(Cmnd), l))

#define XS_SET_STATE_STAT(a, b, c)

#define GET_DEFAULT_ROLE            isplinux_get_default_role
#define SET_DEFAULT_ROLE            isplinux_set_default_role
#define DEFAULT_IID                 isplinux_get_default_id
#define DEFAULT_LOOPID              isplinux_get_default_id
#define DEFAULT_FRAMESIZE(isp)      isp->isp_osinfo.frame_size
#define DEFAULT_EXEC_THROTTLE(isp)  isp->isp_osinfo.exec_throttle
#define DEFAULT_NODEWWN(isp, chan)  isplinux_default_wwn(isp, chan, 0, 1)
#define DEFAULT_PORTWWN(isp, chan)  isplinux_default_wwn(isp, chan, 0, 0)
#define ACTIVE_NODEWWN(isp, chan)   isplinux_default_wwn(isp, chan, 1, 1)
#define ACTIVE_PORTWWN(isp, chan)   isplinux_default_wwn(isp, chan, 1, 0)

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
 * Parameter and platform per-channel storage.
 */
typedef struct {
    uint64_t def_wwnn;
    uint64_t def_wwpn;
    uint32_t
        tgts_tested             :   16,
                                :   11,
        scratch_busy            :   1,
        blocked                 :   1,
        deadloop                :   1,
        role                    :   2;
    unsigned long downcount, nextscan;
    unsigned int qfdelay;
} isp_data;

#define ISP_DATA(isp, chan)     (&((isp_data *)((isp)->isp_osinfo.storep))[chan])

#define isp_name        isp_osinfo.hbaname
#define isp_host        isp_osinfo.host
#define isp_unit        isp_osinfo.host->unique_id

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
int isplinux_reinit(ispsoftc_t *, int);
void isplinux_sqd(struct Scsi_Host *, struct scsi_device *);

int isp_thread_event(ispsoftc_t *, int, void *, int, const char *, const int line);

static ISP_INLINE uint64_t _isp_microtime_sub(struct timeval *, struct timeval *);
static ISP_INLINE void _isp_usec_delay(unsigned int);
static ISP_INLINE unsigned long _usec_to_jiffies(unsigned int);
static ISP_INLINE unsigned long _jiffies_to_usec(unsigned long);
static ISP_INLINE int isplinux_tagtype(Scsi_Cmnd *);
static ISP_INLINE void mbox_wait_complete(ispsoftc_t *, mbreg_t *);

int isplinux_proc_info(struct Scsi_Host *, char *, char **, off_t, int, int);
const char *isplinux_info(struct Scsi_Host *);
int isplinux_queuecommand(Scsi_Cmnd *, void (* done)(Scsi_Cmnd *));
int isplinux_biosparam(struct scsi_device *, struct block_device *, sector_t, int[]);
int isplinux_get_default_id(ispsoftc_t *, int);
int isplinux_get_default_role(ispsoftc_t *, int);
void isplinux_set_default_role(ispsoftc_t *, int, int);
uint64_t isplinux_default_wwn(ispsoftc_t *, int, int, int);


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
extern int isp_vports;
extern dev_t isp_dev;
extern struct cdev isp_cdev;
extern struct file_operations isp_ioctl_operations;
extern ISP_CLASS *isp_class;

/*
 * This used to be considered bad form, but locking crap made it more attractive.
 */
#define MAX_ISP     32
extern ispsoftc_t *isplist[MAX_ISP];
extern ispsoftc_t *api_isp;
extern int api_channel;

/*
 * Platform private flags
 */
#ifndef NULL
#define NULL ((void *) 0)
#endif

#define ISP_WATCH_TPS   10
#define ISP_WATCH_TIME  (HZ / ISP_WATCH_TPS)
#define ISP_SCAN_TIMEOUT    (2 * ISP_WATCH_TPS)
#define ISP_RESCAN_TIMEOUT  ISP_WATCH_TPS

#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef max
#define max(a, b)   (((a) > (b)) ? (a) : (b))
#endif
#ifndef roundup
#define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
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

static ISP_INLINE uint64_t
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

static ISP_INLINE void
_isp_usec_delay(unsigned int usecs)
{
    while (usecs > 1000) {
        mdelay(1);
        usecs -= 1000;
    }
    if (usecs)
        udelay(usecs);
}

static ISP_INLINE unsigned long
_usec_to_jiffies(unsigned int usecs)
{
    struct timespec lt;
    if (usecs == 0)
        usecs++;
    lt.tv_sec = 0;
    lt.tv_nsec = usecs * 1000;
    return (timespec_to_jiffies(&lt));
}

static ISP_INLINE unsigned long
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

static ISP_INLINE int
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

static ISP_INLINE void
mbox_wait_complete(ispsoftc_t *isp, mbreg_t *mbp)
{
    uint32_t lim = mbp->timeout;
    unsigned long et, tt = jiffies;

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
            ISP_ENABLE_INTS(isp);
            ISP_DROP_LK_SOFTC(isp);
            udelay(100);
            ISP_IGET_LK_SOFTC(isp);
            if (isp->mboxcmd_done) {
                break;
            }
        }
        if (isp->mboxcmd_done == 0) {
            isp_prt(isp, ISP_LOGWARN, "Polled Mailbox Command (0x%x) Timeout (%lu elapsed usec)", isp->isp_lastmbxcmd, _jiffies_to_usec(jiffies - tt));
            mbp->param[0] = MBOX_TIMEOUT;
        }
    } else {
        isp_prt(isp, ISP_LOGDEBUG1, "Start Interrupting Mailbox Command (%x)", isp->isp_lastmbxcmd);
        ISP_ENABLE_INTS(isp);
        ISP_DROP_LK_SOFTC(isp);
        et = wait_event_timeout(isp->isp_osinfo.mboxwq, isp->mboxcmd_done, usecs_to_jiffies(lim));
        ISP_IGET_LK_SOFTC(isp);
        if (et == 0) {
            isp_prt(isp, ISP_LOGWARN, "Interrupting Mailbox Command (0x%x) Timeout (elapsed time %lu usec)", isp->isp_lastmbxcmd, _jiffies_to_usec(jiffies - tt));
            mbp->param[0] = MBOX_TIMEOUT;
        } else {
            isp_prt(isp, ISP_LOGDEBUG1, "Interrupting Mailbox Command (0x%x) done (%lu usec)", isp->isp_lastmbxcmd, _jiffies_to_usec(et));
        }
    }
}

static ISP_INLINE int
fc_scratch_acquire(ispsoftc_t *isp, int chan)
{
    if (ISP_DATA(isp, chan)->scratch_busy) {
        return (-1);
    }
    ISP_DATA(isp, chan)->scratch_busy = 1;
    return (0);
}

/*
 * Note that these allocators aren't interrupt safe
 */
static ISP_INLINE void * isp_kalloc(size_t, int);
static ISP_INLINE void   isp_kfree(void *, size_t);
static ISP_INLINE void * isp_kzalloc(size_t, int);

static ISP_INLINE void *
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

static ISP_INLINE void
isp_kfree(void *ptr, size_t size)
{
    if (size >= PAGE_SIZE) {
        vfree(ptr);
    } else {
        kfree(ptr);
    }
}

static ISP_INLINE void *
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

static ISP_INLINE void
isp_get_dma64_seg(ispds64_t *dsp, struct scatterlist *sg, uint32_t sgidx)
{
    sg += sgidx;
    dsp->ds_base    = DMA_LO32(sg_dma_address(sg));
    dsp->ds_basehi  = DMA_HI32(sg_dma_address(sg));
    dsp->ds_count   = sg_dma_len(sg);
}

static ISP_INLINE void
isp_get_dma_seg(ispds_t *dsp, struct scatterlist *sg, uint32_t sgidx)
{
    sg += sgidx;
    dsp->ds_base = sg_dma_address(sg);
    dsp->ds_count = sg_dma_len(sg);
}

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
int isp_enable_lun(ispsoftc_t *, uint16_t, uint16_t);
int isp_disable_lun(ispsoftc_t *,  uint16_t, uint16_t);

struct notify {
    isp_notify_t    notify;
    uint8_t         qentry[QENTRY_LEN]; /* original immediate notify entry */
    uint8_t         qevalid;
    uint8_t         tmf_resp;
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
