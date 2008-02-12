/* $Id: scsi_target.c,v 1.74 2007/11/27 17:57:26 mjacob Exp $ */
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
 * SCSI Target Mode "toy disk" target device for Linux.
 */

#include <linux/version.h>
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(v,p,s)   (((v)<<16)+(p<<8)+s)
#endif
#include <linux/autoconf.h>
#include <linux/module.h>
#include <linux/autoconf.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <scsi/scsi.h>
#include <asm/dma.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <asm/scatterlist.h>
#include <asm/system.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#ifdef  min
#undef  min
#endif
#define min(a,b) (((a)<(b))?(a):(b))
#ifndef roundup
#define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#endif

#include "isp_tpublic.h"
#include "linux/smp_lock.h"

#define DEFAULT_DEVICE_TYPE 0       /* DISK */
#define MAX_BUS             8
#define MAX_LUN             64
#define N_SENSE_BUFS        256

#define cd_dp       cd_hreserved[0].ptrs[0]
#define cd_nsgelems cd_hreserved[1].longs[0]
#define cd_off      cd_hreserved[2].llongs[0]
#define cd_next     cd_hreserved[3].ptrs[0]

#define CDF_PRIVATE_0       0x8000  /* small (non page) data allocation */
#define CDF_PRIVATE_1       0x4000  /* page allocation attached */
#define CDF_PRIVATE_2       0x2000  /* sent status already */
#define CDF_PRIVATE_3       0x1000  /* sg list from sg element cache */
#ifndef SCSI_GOOD
#define SCSI_GOOD   0x0
#endif
#ifndef SCSI_BUSY
#define SCSI_BUSY   0x8
#endif
#ifndef SCSI_CHECK
#define SCSI_CHECK  0x2
#endif
#ifndef SCSI_QFULL
#define SCSI_QFULL  0x28
#endif

#ifndef SERVICE_ACTION_IN
#define SERVICE_ACTION_IN       0x9e
#endif
#ifndef SAI_READ_CAPACITY_16
#define SAI_READ_CAPACITY_16    0x10
#endif
#ifndef READ_12
#define READ_12                 0xa8
#endif
#ifndef READ_16
#define READ_16                 0x88
#endif
#ifndef WRITE_12
#define WRITE_12                0xaa
#endif
#ifndef WRITE_16
#define WRITE_16                0x8a
#endif
#ifndef REPORT_LUNS
#define REPORT_LUNS             0xa0
#endif
#ifndef REPORT_LUNS
#define REPORT_LUNS             0xa0
#endif

#define MODE_ALL_PAGES          0x3f
#define MODE_VU_PAGE            0x00
#define MODE_RWER               0x01
#define MODE_DISCO_RECO         0x02
#define MODE_FORMAT_DEVICE      0x03
#define MODE_GEOMETRY           0x04
#define MODE_CACHE              0x08
#define MODE_PERIPH             0x09
#define MODE_CONTROL            0x0A

#define MODE_DBD                0x08

#define MODE_PF                 0x08
#define MODE_SP                 0x01

#define MODE_PGCTL_MASK         0xC0
#define MODE_PGCTL_CURRENT      0x00
#define MODE_PGCTL_CHANGEABLE   0x40
#define MODE_PGCTL_DEFAULT      0x80
#define MODE_PGCTL_SAVED        0xC0

#define PSEUDO_SPT  64  /* sectors per track */
#define PSEUDO_HDS  64  /* number of heads */
#define PSEUDO_SPC  (PSEUDO_SPT * PSEUDO_HDS)

/*
 * Size to allocate both a scatterlist + payload for small allocations
 */ 
#define SGS_SIZE            1024
#define SGS0                (roundup(sizeof (struct scatterlist), sizeof (void *)))
#define SGS_PAYLOAD_SIZE    (SGS_SIZE - SGS0)
#define SGS_SGP(x)          ((struct scatterlist *)&((u8 *)(x))[SGS_PAYLOAD_SIZE])
#define COPYIN(u, k, n)     copy_from_user((void*)(k), (const void*)(u), (n))
#define COPYOUT(k, u, n)    copy_to_user((void*)(u), (const void*)(k), (n))

static __inline void *  scsi_target_kalloc(size_t, int);
static __inline void    scsi_target_kfree(void *, size_t);
static __inline void *  scsi_target_kzalloc(size_t, int);

static __inline void *
scsi_target_kalloc(size_t size, int flags)
{
    void *ptr;
    if (size > PAGE_SIZE) {
        ptr = vmalloc(size);
    } else {
        ptr = kmalloc(size, flags);
    }
    return (ptr);
}

static __inline void
scsi_target_kfree(void *ptr, size_t size)
{
    if (size > PAGE_SIZE) {
        vfree(ptr);
    } else {
        kfree(ptr);
    }
}

static __inline void *
scsi_target_kzalloc(size_t size, int flags)
{
    void *ptr = scsi_target_kalloc(size, flags);
    if (ptr != NULL){
        memset(ptr, 0, size);
    }
    return (ptr);
}

static __inline void init_sg_elem(struct scatterlist *, struct page *, int, void *, size_t);

static __inline void
init_sg_elem(struct scatterlist *sgp, struct page *p, int offset, void *addr, size_t length)
{
    sgp->length = length;
    if (p) {
        sgp->page = p;
        sgp->offset = offset;
    } else {
        sgp->page = virt_to_page(addr);
        sgp->offset = offset_in_page(addr);
    }
}

#include "scsi_target.h"


#ifndef SERNO
#define SERNO   "000000"
#endif

typedef struct bus bus_t;
typedef struct initiator ini_t;
typedef struct sdata sdata_t;

struct sdata {
    sdata_t *next;
    uint8_t sdata[TMD_SENSELEN];
};


struct initiator {
    ini_t *            ini_next;
    bus_t *            ini_bus;        /* backpointer to containing bus */
    sdata_t *          ini_sdata;      /* pending sense data list */
    sdata_t *          ini_sdata_tail; /* pending sense data list, tail */
    uint64_t           ini_iid;        /* initiator identifier */
};

#define    HASH_WIDTH    16
#define    INI_HASH_LISTP(busp, ini_id)    busp->list[ini_id & (HASH_WIDTH - 1)]

/*
 * We maintain a reasonable cache of large sized (8MB) scatterlists
 */
#define SGELEM_CACHE_SIZE   2048
#define SGELEM_CACHE_COUNT  128
static struct scatterlist *sg_cache = NULL;


/*
 * A memory disk is constructed of a two dimensional array of pointers to pages. 
 *
 * Allocate a series of chunks of memory, each of which becomes a flat array
 * of pointers to pages that we allocate one at a time.
 */
#define PGLIST_SIZE         (32 << 10)                              /* how big each list is, in bytes */
#define PG_PER_LIST         (PGLIST_SIZE / sizeof (struct page *))  /* how many page pointers fist into that list */
#define PGLIST_MAPPING_SIZE (PG_PER_LIST << PAGE_SHIFT)             /* how many bytes each list covers */
#define START_LIST_IDX(x)   ((x) / PGLIST_MAPPING_SIZE)
#define START_PAGE_IDX(x)   (((x) % PGLIST_MAPPING_SIZE) >> PAGE_SHIFT)

/*
 * An overcommit disk is a cache of a fixed size.
 */
#define OC_SIZE             (64 << 20)
#define NextPage(pp)        pp->private
#define NextPageType        unsigned long

typedef struct {
    struct page ***     pagelists;
    int                 npglists;
    int                             :   28,
                        outtagas    :   1,
                        wce         :   1,
                        overcommit  :   1,
                        enabled     :   1;
    struct semaphore    sema;
    tmd_cmd_t *         u_front;
    tmd_cmd_t *         u_tail;
    uint64_t            nbytes;
} lun_t;
#define LUN_BLOCK_SHIFT 9

struct bus {
    hba_register_t  h;                  /* must be first */
    ini_t *         list[HASH_WIDTH];   /* hash list of known initiators */
    lun_t           luns[MAX_LUN];      /* luns */
};

#define    SDprintk     if (scsi_tdebug) printk
#define    SDprintk2    if (scsi_tdebug > 1) printk
#define    SDprintk3    if (scsi_tdebug > 2) printk


static int scsi_tdebug = 0;

static int
scsi_target_ioctl(struct inode *, struct file *, unsigned int, unsigned long);
static void scsi_target_handler(qact_e, void *);

static __inline bus_t *bus_from_tmd(tmd_cmd_t *);
static __inline bus_t *bus_from_name(char *);
static __inline ini_t *ini_from_tmd(bus_t *, tmd_cmd_t *);

static void add_sdata(ini_t *, void *);
static void rem_sdata(ini_t *);
static void free_sdata_chain(sdata_t *);
static void scsi_target_start_cmd(tmd_cmd_t *, int);
static void scsi_target_read_capacity_16(tmd_cmd_t *, ini_t *);
static void scsi_target_read_capacity(tmd_cmd_t *, ini_t *);
static void scsi_target_modesense(tmd_cmd_t *, ini_t *);
static int scsi_target_rdwr(tmd_cmd_t *, ini_t *, int);
static int scsi_target_thread(void *);
static int scsi_alloc_disk(bus_t *, int, int, uint64_t);
static void scsi_free_disk(bus_t *, int);
static int scsi_target_copydata(struct scatterlist *, void *, uint32_t, int);
static int scsi_target_start_user_io(sc_io_t *);
static int scsi_target_end_user_io(sc_io_t *);
static int scsi_target_endis(char *, uint64_t, int, int);

/*
 * Local Declarations
 */
#define INQ_SIZE    36
static uint8_t inqdata[INQ_SIZE] = {
    DEFAULT_DEVICE_TYPE, 0x0, 0x2, 0x2, 32, 0, 0, 0x32,
    'L', 'I', 'N', 'U', 'X', ' ', ' ', ' ',
    'S', 'C', 'S', 'I', ' ', 'M', 'E', 'M',
    'O', 'R', 'Y', ' ', 'D', 'I', 'S', 'K',
    '0', '0', '0', '1'
};
static uint8_t vp0data[7] = {
    DEFAULT_DEVICE_TYPE, 0, 0, 0x3, 0, 0x80, 0x83 
};
static uint8_t vp80data[36] = {
    DEFAULT_DEVICE_TYPE, 0x80, 0, 0x20,
};
/* Binary, Associated with Target Port, FC-FS Identifier */
static uint8_t vp83data[18] = {
    DEFAULT_DEVICE_TYPE, 0x83, 0, 0xc, 0x01, 0x13, 0, 0x8
};
static uint8_t enomem[TMD_SENSELEN] = {
    0xf0, 0, 0x4, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0x55, 0x03
};
static uint8_t illfld[TMD_SENSELEN] = {
    0xf0, 0, 0x5, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0x24
};
static uint8_t nolun[TMD_SENSELEN] = {
    0xf0, 0, 0x5, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0x25
};
static uint8_t invfld[TMD_SENSELEN] = {
    0xf0, 0, 0x5, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0x26
};
#if 0
static uint8_t notrdy[TMD_SENSELEN] = {
    0xf0, 0, 0x2, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0x04
};
#endif
static uint8_t mediaerr[TMD_SENSELEN] = {
    0xf0, 0, 0x3
};
static uint8_t ifailure[TMD_SENSELEN] = {
    0xf0, 0, 0x4, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0x44
};
static uint8_t ua[TMD_SENSELEN] = {
    0xf0, 0, 0x6, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0x29, 0x1
};
static uint8_t nosense[TMD_SENSELEN] = {
    0xf0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
static uint8_t invchg[TMD_SENSELEN] = {
    0xf0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x3f, 0x0e
};

static bus_t busses[MAX_BUS];
static sdata_t *sdp = NULL;

DECLARE_MUTEX_LOCKED(scsi_thread_sleep_semaphore);
DECLARE_MUTEX_LOCKED(scsi_thread_entry_exit_semaphore);
static tmd_cmd_t *p_front = NULL, *p_last = NULL;
static tmd_cmd_t *q_front = NULL, *q_last = NULL;
static spinlock_t scsi_target_lock = SPIN_LOCK_UNLOCKED;
static int scsi_target_thread_exit = 0;

static struct file_operations scsi_target_fops = {
    .ioctl  =   scsi_target_ioctl,
    .owner  =   THIS_MODULE,
};

static int
scsi_target_ioctl(struct inode *ip, struct file *fp, unsigned int cmd, unsigned long arg)
{
    int rv = 0;

    switch(cmd) {
    case SC_ENABLE_LUN:
    case SC_DISABLE_LUN:
    {
        sc_enable_t local, *sc = &local;
        if (COPYIN((void *)arg, (void *)sc, sizeof (*sc))) {
            rv = -EFAULT;
            break;
        }
        rv = scsi_target_endis(sc->hba_name_unit, sc->nbytes, sc->lun, (cmd == SC_ENABLE_LUN)?((sc->flags == SC_EF_OVERCOMMIT)? 2 : 1) : 0);
        break;
    }
    case SC_PUT_IO:
    case SC_GET_IO:
    {
        sc_io_t sc;

        if (COPYIN((void *)arg, (void *)&sc, sizeof (sc))) {
            rv = -EFAULT;
            break;
        }
        if (cmd == SC_PUT_IO) {
            rv = scsi_target_end_user_io(&sc);
        } else {
            rv = scsi_target_start_user_io(&sc);
        }
        if (COPYOUT((void *)&sc, (void *)arg, sizeof (sc))) {
            if (rv == 0) {
                rv = EFAULT;
            }
        }
        break;
    }
    case SC_DEBUG:
    {
        int odebug = scsi_tdebug;
        if (COPYIN((void *)arg, (void *)&scsi_tdebug, sizeof (int))) {
            rv = EFAULT;
            break;
        }
        if (COPYOUT((void *)&odebug, (void *)arg, sizeof (int))) {
            rv = EFAULT;
            break;
        }
        break;
    }
    default:
        rv = -EINVAL;
        break;
    }
    return (rv);
}

static __inline int
validate_bus_pointer(bus_t *bp, void *identity)
{
    if (bp >= busses && bp < &busses[MAX_BUS]) {
        if (bp->h.r_action) {
            if (bp->h.r_identity == identity) {
                return (1);
            }
        }
    }
    return (0);
}

static __inline bus_t *
bus_from_tmd(tmd_cmd_t *tmd)
{
    bus_t *bp;
    for (bp = busses; bp < &busses[MAX_BUS]; bp++) {
        if (validate_bus_pointer(bp, tmd->cd_hba)) {
            return (bp);
        }
    }
    return (NULL);
}

static __inline bus_t *
bus_from_name(char *name)
{
    bus_t *bp;
    for (bp = busses; bp < &busses[MAX_BUS]; bp++) {
        char localbuf[32];
        if (bp->h.r_action == NULL) {
            continue;
        }
        snprintf(localbuf, sizeof (localbuf), "%s%d", bp->h.r_name, bp->h.r_inst);
        if (strncmp(name, localbuf, sizeof (localbuf) - 1) == 0) {
            return (bp);
        }
    }
    return (NULL);
}

static __inline ini_t *
ini_from_tmd(bus_t *bp, tmd_cmd_t *tmd)
{
   ini_t *ptr = INI_HASH_LISTP(bp, tmd->cd_iid);
   if (ptr) {
        do {
            if (ptr->ini_iid == tmd->cd_iid) {
                return (ptr);
            }
        } while ((ptr = ptr->ini_next) != NULL);
   }
   return (ptr);
}

static __inline bus_t *
bus_from_notify(tmd_notify_t *np)
{
    bus_t *bp;
    for (bp = busses; bp < &busses[MAX_BUS]; bp++) {
        if (bp->h.r_action == NULL) {
            continue;
        }
        if (bp->h.r_identity == np->nt_hba) {
            return (bp);
        }
    }
    return (NULL);
}


/*
 * Make an initiator structure
 */
static void
add_ini(bus_t *bp, uint64_t iid, ini_t *nptr)
{
   ini_t **ptrlptr = &INI_HASH_LISTP(bp, iid);

   nptr->ini_iid = iid;
   nptr->ini_bus = (struct bus *) bp;
   nptr->ini_next = *ptrlptr;

   *ptrlptr = nptr;
}

/*
 * Add this sense data from the list of
 * sense data structures for this initiator.
 * We always add to the tail of the list.
 */
static void
add_sdata(ini_t *ini, void *sd)
{
    unsigned long flags;
    sdata_t *t;

    spin_lock_irqsave(&scsi_target_lock, flags);
    t = sdp;
    if (t == NULL) {
        spin_unlock_irqrestore(&scsi_target_lock, flags);
        printk(KERN_WARNING "outta sense data structures\n");
        t = scsi_target_kalloc(sizeof (sdata_t), GFP_KERNEL|GFP_ATOMIC);
        if (t == NULL) {
            panic("REALLY outta sense data structures\n");
        }
        spin_lock_irqsave(&scsi_target_lock, flags);
    } else {
        sdp = t->next;
    }
    t->next = NULL;
    memcpy(t->sdata, sd, sizeof (t->sdata));
    if (ini->ini_sdata == NULL) {
        ini->ini_sdata = t;
    } else {
        ini->ini_sdata_tail->next = t;
    }
    ini->ini_sdata_tail = t;
    spin_unlock_irqrestore(&scsi_target_lock, flags);
}

/*
 * Remove one sense data item from the list of
 * sense data structures for this initiator.
 */
static void
rem_sdata(ini_t *ini)
{
    sdata_t *t = ini->ini_sdata;
    if (t) {
        unsigned long flags;
        spin_lock_irqsave(&scsi_target_lock, flags);
        if ((ini->ini_sdata = t->next) == NULL) {
            ini->ini_sdata_tail = NULL;
        }
        t->next = sdp;
        sdp = t;
        spin_unlock_irqrestore(&scsi_target_lock, flags);
    }
}

static void
free_sdata_chain(sdata_t *sdp)
{
    while (sdp) {
        sdata_t *nxt = sdp->next;
        scsi_target_kfree(sdp, sizeof (*sdp)); 
        sdp = nxt;
    }
}


static __inline void scsi_cmd_sched_restart_locked(tmd_cmd_t *, int, const char *);
static __inline void scsi_cmd_sched_restart(tmd_cmd_t *, const char *);

static __inline void
scsi_cmd_sched_restart_locked(tmd_cmd_t *tmd, int donotify, const char *msg)
{
    SDprintk("scsi_cmd_sched_restart[%llx]: %s\n", tmd->cd_tagval, msg);
    tmd->cd_next = NULL;
    if (p_front) {
        p_last->cd_next = tmd;
    } else {
        p_front = tmd;
    }
    p_last = tmd;
    if (donotify) {
        up(&scsi_thread_sleep_semaphore);
    }
}


static __inline void
scsi_cmd_sched_restart(tmd_cmd_t *tmd, const char *msg)
{
    unsigned long flags;
    spin_lock_irqsave(&scsi_target_lock, flags);
    scsi_cmd_sched_restart_locked(tmd, 1, msg);
    spin_unlock_irqrestore(&scsi_target_lock, flags);
}

static void
scsi_target_start_cmd(tmd_cmd_t *tmd, int from_intr)
{
    unsigned long flags;
    tmd_xact_t *xact = &tmd->cd_xact;
    bus_t *bp;
    void *addr;
    ini_t *ini;

    /*
     * First, find the bus.
     */
    spin_lock_irqsave(&scsi_target_lock, flags);
    bp = bus_from_tmd(tmd);
    if (bp == NULL) {
        spin_unlock_irqrestore(&scsi_target_lock, flags);
        printk(KERN_WARNING "cannot find bus for incoming command\n");
        return;
    }

    /*
     * Next check if we have commands pending on the front
     * queue and we're coming in at interrupt level. In order
     * to preserve ordering, we force commands to come in at thread
     * level if there are commands already at thread level
     */
    if (from_intr && p_front) {
        scsi_cmd_sched_restart_locked(tmd, 1, "from_intr && p_front");
        spin_unlock_irqrestore(&scsi_target_lock, flags);
        return;
    }

    ini = ini_from_tmd(bp, tmd);
    if (ini == NULL) {
        ini_t *nptr;

        if (from_intr) {
            scsi_cmd_sched_restart_locked(tmd, 1, "had to make ini");
            spin_unlock_irqrestore(&scsi_target_lock, flags);
            return;
        }

        spin_unlock_irqrestore(&scsi_target_lock, flags);
        nptr = scsi_target_kzalloc(sizeof (ini_t), GFP_KERNEL|GFP_ATOMIC);
        spin_lock_irqsave(&scsi_target_lock, flags);

        /*
         * Check again to see if it showed while we were allocating...
         */
        ini = ini_from_tmd(bp, tmd);
        if (ini) {
            spin_unlock_irqrestore(&scsi_target_lock, flags);
            if (nptr) {
                scsi_target_kfree(nptr, sizeof (ini_t));
            }
        } else {
            if (nptr == NULL) {
                spin_unlock_irqrestore(&scsi_target_lock, flags);
                tmd->cd_scsi_status = SCSI_BUSY;
                xact->td_hflags |= TDFH_STSVALID;
                xact->td_hflags &= ~TDFH_DATA_MASK;
                xact->td_xfrlen = 0;
                (*bp->h.r_action)(QIN_TMD_CONT, xact);
                return;
            }
            add_ini(bp, tmd->cd_iid, nptr);
            spin_unlock_irqrestore(&scsi_target_lock, flags);
            ini = nptr;
            /*
             * Start off with a Unit Attention condition.
             */
            add_sdata(ini, ua);
        }
    } else {
        spin_unlock_irqrestore(&scsi_target_lock, flags);
    }

    /*
     * Commands get lumped into 5 rough groups:
     *
     *   + Commands which don't ever really return CHECK CONDITIONS and
     *     always work. These are typically INQUIRY.
     *
     *   + Commands that we accept, but also report CHECK CONDITIONS against if
     *     we have pending contingent allegiance (e..g, TEST UNIT READY).
     *
     *   + Commands that retrieve Sense Data (REQUEST SENSE)
     *
     *   + Commmands that do something (like READ or WRITE)
     *
     *   + All others (which we bounce with either ILLEGAL COMMAND or BAD LUN).
     */

    if (unlikely(tmd->cd_cdb[0] == INQUIRY)) {
        uint8_t vpdcd = tmd->cd_cdb[2];
        uint8_t legal = (((tmd->cd_cdb[1] & 0x1f) == 0 && vpdcd == 0) || (tmd->cd_cdb[1] & 0x1f) == 1);
        uint8_t isvpd = (tmd->cd_cdb[1] & 0x1f) == 1;

        if (legal) {
            struct scatterlist *dp = NULL;
            uint8_t *buf;
            uint32_t len;

            if (from_intr) {
                scsi_cmd_sched_restart(tmd, "INQUIRY");
                return;
            }
            if (tmd->cd_totlen == 0) {
                xact->td_hflags |= TDFH_STSVALID;
                goto doit;
            }
            len = min(tmd->cd_totlen, tmd->cd_cdb[4]);

            addr = scsi_target_kzalloc(SGS_SIZE, GFP_KERNEL|GFP_ATOMIC);
            if (addr == NULL) {
                printk(KERN_WARNING "scsi_target_alloc: out of memory for inquiry data\n");
                add_sdata(ini, enomem);
                xact->td_hflags |= TDFH_SNSVALID;
                goto doit;
            }
            buf = addr;
            dp = SGS_SGP(addr);
            if (isvpd) {
                int i, j;
                switch (vpdcd) {
                case 0:     /* Supported VPD Pages */
                    len = min(sizeof(vp0data), len);
                    if (len) {
                        memcpy(addr, vp0data, len);
                    }
                    break;
                case 0x80:  /* Unit Serial Number */
                    len = min(sizeof(vp80data), len);
                    if (len) {
                        memcpy(addr, vp80data, len);
                        snprintf(&buf[4], sizeof (vp80data) - 4, "FERAL_%s%d_LUN%06dSER%s", bp->h.r_name, bp->h.r_inst,
                            L0LUN_TO_FLATLUN(tmd->cd_lun), SERNO);
                        for (j = 0, i = 4; i < sizeof (vp80data); i++) {
                            if (j == 0) {
                                if (buf[i] == 0) {
                                    j = 1;
                                    buf[i] = ' ';
                                }
                            } else {
                                buf[i] = ' ';
                            }
                        }
                    }
                    break;
                case 0x83:  /* Device Identification */
                    len = min(sizeof(vp83data), len);
                    if (len) {
                        memcpy(addr, vp83data, len);
                        for (j = 8, i = 56; i >= 0; i -= 8, j++) {
                            buf[j] = tmd->cd_tgt >> i;
                        }
                    }
                    break;
                default:
                    scsi_target_kfree(addr, SGS_SIZE);
                    add_sdata(ini, invfld);
                    xact->td_hflags |= TDFH_SNSVALID;
                    goto doit;
                }
            } else {
                len = min(sizeof(inqdata), len);
                if (len) {
                    memcpy(addr, inqdata, len);
                }
            }
            if (len == 0) {
                scsi_target_kfree(addr, SGS_SIZE);
                xact->td_hflags |= TDFH_STSVALID;
            } else {
                init_sg_elem(dp, NULL, 0, addr, len);
                xact->td_xfrlen = dp->length;
                xact->td_data = dp;
                xact->td_hflags |= TDFH_STSVALID|TDFH_DATA_IN;
                tmd->cd_flags |= CDF_PRIVATE_0;
                /*
                 * If we're not here, say we aren't here.
                 */
                if (L0LUN_TO_FLATLUN(tmd->cd_lun) >= MAX_LUN || bp->luns[L0LUN_TO_FLATLUN(tmd->cd_lun)].enabled == 0) {
                    ((u8 *)addr)[0] = 0x7f;
                }
                SDprintk2("scsi_target(%s%d): %p (%p) length %d byte0 0x%x\n", bp->h.r_name, bp->h.r_inst, addr, dp, dp->length, ((u8 *)addr)[0]);
            }
        } else {
            SDprintk2("scsi_target(%s%d): illegal field for inquiry data\n", bp->h.r_name, bp->h.r_inst);
            add_sdata(ini, illfld);
            xact->td_hflags |= TDFH_SNSVALID;
        }
        goto doit;
    }

    if (tmd->cd_cdb[0] == REQUEST_SENSE) {
        struct scatterlist *dp = NULL;
        xact->td_xfrlen = TMD_SENSELEN;
        xact->td_xfrlen = min(tmd->cd_cdb[4], xact->td_xfrlen);
        xact->td_xfrlen = min(tmd->cd_totlen, xact->td_xfrlen);
        if (xact->td_xfrlen != 0) {
            if (from_intr) {
                scsi_cmd_sched_restart(tmd, "REQUEST_SENSE");
                return;
            }
            addr = scsi_target_kzalloc(SGS_SIZE, GFP_KERNEL|GFP_ATOMIC);
            if (addr == NULL) {
                printk("scsi_target_alloc: out of memory for sense data\n");
                tmd->cd_scsi_status = SCSI_BUSY;
                xact->td_xfrlen = 0;
            } else {
                dp = SGS_SGP(addr);
                init_sg_elem(dp, NULL, 0, addr, TMD_SENSELEN);
                if (ini->ini_sdata == NULL) {
                    memcpy(addr, nosense, TMD_SENSELEN);
                } else {
                    memcpy(addr, ini->ini_sdata->sdata, TMD_SENSELEN);
                    rem_sdata(ini);
                }
                xact->td_data = dp;
                xact->td_hflags |= TDFH_DATA_IN;
                tmd->cd_flags |= CDF_PRIVATE_0;
                SDprintk2("sense data in scsi_target for %s%d: %p (%p) len %d, key/asc/ascq 0x%x/0x%x/0x%x\n",
                    bp->h.r_name, bp->h.r_inst, addr, dp, dp->length,
                    ((u8 *)addr)[2]&0xf, ((u8 *)addr)[12]&0xff, ((u8 *)addr)[13]);
            }
        }
        xact->td_hflags |= TDFH_STSVALID;
        goto doit;
    }

    if (tmd->cd_cdb[0] == REPORT_LUNS) {
        struct scatterlist *dp = NULL;
        if (tmd->cd_totlen != 0) {
            if (from_intr) {
                scsi_cmd_sched_restart(tmd, "REPORT_LUNS");
                return;
            }
            addr = scsi_target_kzalloc(SGS_SIZE, GFP_KERNEL|GFP_ATOMIC);
            if (addr == NULL) {
                printk("scsi_target_alloc: out of memory for report luns\n");
                tmd->cd_scsi_status = SCSI_BUSY;
                xact->td_xfrlen = 0;
            } else {
                int i;
                uint32_t lim, nluns;
                uint8_t *rpa = addr;

                lim = (tmd->cd_cdb[6] << 24) | (tmd->cd_cdb[7] << 16) | (tmd->cd_cdb[8] << 8) | tmd->cd_cdb[9];

                spin_lock_irqsave(&scsi_target_lock, flags);
                for (nluns = i = 0; i < MAX_LUN; i++) {
                    lun_t *lp = &bp->luns[i];
                    if (lp->enabled) {
                        uint8_t *ptr = &rpa[8 + (nluns << 3)];
                        if (i >= 256) {
                            ptr[0] = 0x40 | ((i >> 8) & 0x3f);
                        }
                        ptr[1] = i;
                        nluns++;
                    }
                }
                spin_unlock_irqrestore(&scsi_target_lock, flags);

                /*
                 * Make sure we always have *one* (lun 0) enabled
                 */
                if (nluns == 0) {
                    nluns = 1;
                }
                rpa[0] = (nluns << 3) >> 24;
                rpa[1] = (nluns << 3) >> 16;
                rpa[2] = (nluns << 3) >> 8;
                rpa[3] = (nluns << 3);

                dp = SGS_SGP(addr);
                lim = min(lim, tmd->cd_totlen);
                lim = min(lim, (nluns << 3) + 8);
                init_sg_elem(dp, NULL, 0, addr, lim);
                xact->td_xfrlen = dp->length;
                xact->td_data = dp;
                xact->td_hflags |= TDFH_DATA_IN;
                tmd->cd_flags |= CDF_PRIVATE_0;
            }
        }
        xact->td_hflags |= TDFH_STSVALID;
        goto doit;
    }

    if (tmd->cd_cdb[0] == REPORT_LUNS) {
        struct scatterlist *dp = NULL;
        if (tmd->cd_totlen != 0) {
            if (from_intr) {
                scsi_cmd_sched_restart(tmd, "REPORT_LUNS");
                return;
            }
            addr = scsi_target_kzalloc(SGS_SIZE, GFP_KERNEL|GFP_ATOMIC);
            if (addr == NULL) {
                printk("scsi_target_alloc: out of memory for report luns\n");
                tmd->cd_scsi_status = SCSI_BUSY;
                xact->td_xfrlen = 0;
            } else {
                int i;
                uint32_t lim, nluns;
                uint8_t *rpa = addr;

                lim = (tmd->cd_cdb[6] << 24) | (tmd->cd_cdb[7] << 16) | (tmd->cd_cdb[8] << 8) | tmd->cd_cdb[9];

                spin_lock_irqsave(&scsi_target_lock, flags);
                for (nluns = i = 0; i < MAX_LUN; i++) {
                    lun_t *lp = &bp->luns[i];
                    if (lp->enabled) {
                        uint8_t *ptr = &rpa[8 + (nluns << 3)];
                        if (i >= 256) {
                            ptr[0] = 0x40 | ((i >> 8) & 0x3f);
                        }
                        ptr[1] = i;
                        nluns++;
                    }
                }
                spin_unlock_irqrestore(&scsi_target_lock, flags);

                /*
                 * Make sure we always have *one* (lun 0) enabled
                 */
                if (nluns == 0) {
                    nluns = 1;
                }
                rpa[0] = (nluns << 3) >> 24;
                rpa[1] = (nluns << 3) >> 16;
                rpa[2] = (nluns << 3) >> 8;
                rpa[3] = (nluns << 3);

                dp = SGS_SGP(addr);
                lim = min(lim, tmd->cd_totlen);
                lim = min(lim, (nluns << 3) + 8);
                init_sg_elem(dp, NULL, 0, addr, lim);
                xact->td_xfrlen = dp->length;
                xact->td_data = dp;
                xact->td_hflags |= TDFH_DATA_IN;
                tmd->cd_flags |= CDF_PRIVATE_0;
            }
        }
        xact->td_hflags |= TDFH_STSVALID;
        goto doit;
    }

    /*
     * Make sure we have a legal and open lun
     */
    if (L0LUN_TO_FLATLUN(tmd->cd_lun) >= MAX_LUN || bp->luns[L0LUN_TO_FLATLUN(tmd->cd_lun)].enabled == 0) {
            if (from_intr) {
                scsi_cmd_sched_restart(tmd, "bad or disabled lun");
                return;
            }
            add_sdata(ini, nolun);
            xact->td_hflags |= TDFH_SNSVALID;
            goto doit;
    }

    /*
     * All other commands first check for Contingent Allegiance
     */
    if (ini->ini_sdata) {
        xact->td_hflags |= TDFH_SNSVALID;
        goto doit;
    }

    switch (tmd->cd_cdb[0]) {
    case VERIFY:    /* lie */
    case REZERO_UNIT:
    case FORMAT_UNIT:
    case SYNCHRONIZE_CACHE:
    case START_STOP:
    case TEST_UNIT_READY:
        xact->td_hflags |= TDFH_STSVALID;
        break;
    case READ_CAPACITY:
        if (from_intr) {
            scsi_cmd_sched_restart(tmd, "READ CAPACITY");
            return;
        }
        scsi_target_read_capacity(tmd, ini);
        break;
    case MODE_SENSE:
        if (from_intr) {
            scsi_cmd_sched_restart(tmd, "MODE SENSE");
            return;
        }
        scsi_target_modesense(tmd, ini);
        break;
    case READ_6:
    case READ_10:
    case READ_12:
    case READ_16:
    case WRITE_6:
    case WRITE_10:
    case WRITE_12:
    case WRITE_16:
        if (scsi_target_rdwr(tmd, ini, from_intr)) {
            return;
        }
        break;
    case SERVICE_ACTION_IN:
        if ((tmd->cd_cdb[1] & 0x1f) == SAI_READ_CAPACITY_16) {
            if (from_intr) {
                scsi_cmd_sched_restart(tmd, "READ CAPACITY 16");
                return;
            }
            scsi_target_read_capacity_16(tmd, ini);
            break;
        }
        /* FALLTHROUGH */
    default:
        if (from_intr) {
            scsi_cmd_sched_restart(tmd, "RANDOM OTHER COMMAND");
            return;
        }
        add_sdata(ini, illfld);
        xact->td_hflags |= TDFH_SNSVALID;
        break;
    }

doit:
    if (xact->td_hflags & TDFH_SNSVALID) {
        tmd->cd_scsi_status = SCSI_CHECK;
        xact->td_hflags |= TDFH_STSVALID;
        if (ini && ini->ini_sdata) {
            memcpy(tmd->cd_sense, ini->ini_sdata->sdata, TMD_SENSELEN);
        } else {
            memset(tmd->cd_sense, 0, TMD_SENSELEN);
        }
        printk("INI(%#llx)=>LUN %d: [%llx] cdb0=0x%02x tl=%u CHECK (0x%x 0x%x 0x%x)\n", tmd->cd_iid, L0LUN_TO_FLATLUN(tmd->cd_lun),
            tmd->cd_tagval, tmd->cd_cdb[0] & 0xff, tmd->cd_totlen, tmd->cd_sense[2] & 0xf, tmd->cd_sense[12], tmd->cd_sense[13]);
    } else {
        SDprintk("INI(%#llx)=>LUN %d: [%llx] cdb0=0x%02x tl=%u ssts=%x hf 0x%x\n", tmd->cd_iid, L0LUN_TO_FLATLUN(tmd->cd_lun),
            tmd->cd_tagval, tmd->cd_cdb[0] & 0xff, tmd->cd_totlen, tmd->cd_scsi_status, xact->td_hflags);
    }
    (*bp->h.r_action)(QIN_TMD_CONT, xact);
}

static void
scsi_target_read_capacity_16(tmd_cmd_t *tmd, ini_t *ini)
{
    bus_t *bp;
    void *addr;
    struct scatterlist *dp;
    tmd_xact_t *xact = &tmd->cd_xact;
    lun_t *lp;

    bp = ini->ini_bus;

    addr = scsi_target_kzalloc(SGS_SIZE, GFP_KERNEL|GFP_ATOMIC);
    if (addr == NULL) {
        printk(KERN_WARNING "scsi_target_read_capacity: alloc failed\n");
        tmd->cd_scsi_status = SCSI_BUSY;
        xact->td_hflags |= TDFH_STSVALID;
        return;
    }

    lp = &bp->luns[L0LUN_TO_FLATLUN(tmd->cd_lun)];

    dp = SGS_SGP(addr);
    if (tmd->cd_cdb[14] & 0x1) { /* PMI */
        ((u8 *)addr)[0] = 0xff;
        ((u8 *)addr)[1] = 0xff;
        ((u8 *)addr)[2] = 0xff;
        ((u8 *)addr)[3] = 0xff;
        ((u8 *)addr)[4] = 0xff;
        ((u8 *)addr)[5] = 0xff;
        ((u8 *)addr)[6] = 0xff;
        ((u8 *)addr)[7] = 0xff;
    } else {
        uint64_t blks = (lp->nbytes >> LUN_BLOCK_SHIFT) - 1;
        if (tmd->cd_cdb[2] || tmd->cd_cdb[3] || tmd->cd_cdb[4] || tmd->cd_cdb[5] ||
            tmd->cd_cdb[6] || tmd->cd_cdb[7] || tmd->cd_cdb[8] || tmd->cd_cdb[9]) {
            scsi_target_kfree(addr, SGS_SIZE);
            add_sdata(ini, illfld);
            xact->td_hflags |= TDFH_SNSVALID;
            return;
        }
        ((u8 *)addr)[0] = (blks >> 56) & 0xff;
        ((u8 *)addr)[1] = (blks >> 48) & 0xff;
        ((u8 *)addr)[2] = (blks >> 40) & 0xff;
        ((u8 *)addr)[3] = (blks >> 32) & 0xff;
        ((u8 *)addr)[4] = (blks >> 24) & 0xff;
        ((u8 *)addr)[5] = (blks >> 16) & 0xff;
        ((u8 *)addr)[6] = (blks >>  8) & 0xff;
        ((u8 *)addr)[7] = (blks) & 0xff;
    }
    ((u8 *)addr)[8] = ((1 << LUN_BLOCK_SHIFT) >> 24) & 0xff;
    ((u8 *)addr)[9] = ((1 << LUN_BLOCK_SHIFT) >> 16) & 0xff;
    ((u8 *)addr)[10] = ((1 << LUN_BLOCK_SHIFT) >>  8) & 0xff;
    ((u8 *)addr)[11] = ((1 << LUN_BLOCK_SHIFT)) & 0xff;
    init_sg_elem(dp, NULL, 0, addr, min(32, tmd->cd_totlen));
    xact->td_xfrlen = dp->length;
    xact->td_data = dp;
    xact->td_hflags |= TDFH_DATA_IN|TDFH_STSVALID;
    tmd->cd_flags |= CDF_PRIVATE_0;
}

static void
scsi_target_read_capacity(tmd_cmd_t *tmd, ini_t *ini)
{
    bus_t *bp;
    void *addr;
    struct scatterlist *dp;
    tmd_xact_t *xact = &tmd->cd_xact;
    lun_t *lp;

    bp = ini->ini_bus;

    addr = scsi_target_kzalloc(SGS_SIZE, GFP_KERNEL|GFP_ATOMIC);
    if (addr == NULL) {
        printk(KERN_WARNING "scsi_target_read_capacity: alloc failed\n");
        tmd->cd_scsi_status = SCSI_BUSY;
        xact->td_hflags |= TDFH_STSVALID;
        return;
    }

    lp = &bp->luns[L0LUN_TO_FLATLUN(tmd->cd_lun)];

    dp = SGS_SGP(addr);
    if (tmd->cd_cdb[8] & 0x1) { /* PMI */
        ((u8 *)addr)[0] = 0xff;
        ((u8 *)addr)[1] = 0xff;
        ((u8 *)addr)[2] = 0xff;
        ((u8 *)addr)[3] = 0xff;
    } else {
        uint64_t blks = (lp->nbytes >> LUN_BLOCK_SHIFT) - 1;
        if (tmd->cd_cdb[2] || tmd->cd_cdb[3] || tmd->cd_cdb[4] || tmd->cd_cdb[5]) {
            scsi_target_kfree(addr, SGS_SIZE);
            add_sdata(ini, illfld);
            xact->td_hflags |= TDFH_SNSVALID;
            return;
        }
        if (blks < 0xffffffffull) {
            ((u8 *)addr)[0] = (blks >> 24) & 0xff;
            ((u8 *)addr)[1] = (blks >> 16) & 0xff;
            ((u8 *)addr)[2] = (blks >>  8) & 0xff;
            ((u8 *)addr)[3] = (blks) & 0xff;
        } else {
            ((u8 *)addr)[0] = 0xff;
            ((u8 *)addr)[1] = 0xff;
            ((u8 *)addr)[2] = 0xff;
            ((u8 *)addr)[3] = 0xff;
        }
    }
    ((u8 *)addr)[4] = ((1 << LUN_BLOCK_SHIFT) >> 24) & 0xff;
    ((u8 *)addr)[5] = ((1 << LUN_BLOCK_SHIFT) >> 16) & 0xff;
    ((u8 *)addr)[6] = ((1 << LUN_BLOCK_SHIFT) >>  8) & 0xff;
    ((u8 *)addr)[7] = ((1 << LUN_BLOCK_SHIFT)) & 0xff;
    init_sg_elem(dp, NULL, 0, addr, min(8, tmd->cd_totlen));
    xact->td_xfrlen = dp->length;
    xact->td_data = dp;
    xact->td_hflags |= TDFH_DATA_IN|TDFH_STSVALID;
    tmd->cd_flags |= CDF_PRIVATE_0;
}

static void
scsi_target_modesense(tmd_cmd_t *tmd, ini_t *ini)
{
    bus_t *bp;
    lun_t *lp;
    int dlen, pgctl, page;
    tmd_xact_t *xact = &tmd->cd_xact;
    struct scatterlist *dp;
    uint8_t *pgdata;
    uint32_t nblks;
    void *addr;

    bp = ini->ini_bus;
    lp = &bp->luns[L0LUN_TO_FLATLUN(tmd->cd_lun)];
    pgctl = tmd->cd_cdb[2] & MODE_PGCTL_MASK;
    page = tmd->cd_cdb[2] & MODE_ALL_PAGES;

    SDprintk("scsi_target_modesense(%s%d): page 0x%x, ctl %x, dbd %d for lun %d\n", bp->h.r_name, bp->h.r_inst,
        page, pgctl, (tmd->cd_cdb[1] & MODE_DBD) != 0, L0LUN_TO_FLATLUN(tmd->cd_lun));

    switch (page) {
    case MODE_ALL_PAGES:
    case MODE_CACHE:
    case MODE_FORMAT_DEVICE:
    case MODE_GEOMETRY:
    case MODE_CONTROL:
        break;
    default:
        add_sdata(ini, illfld);
        xact->td_hflags |= TDFH_SNSVALID;
        return;
    }

    addr = scsi_target_kzalloc(SGS_SIZE, GFP_KERNEL|GFP_ATOMIC);
    if (addr == NULL) {
        printk(KERN_WARNING "scsi_target_modesense: alloc failure\n");
        tmd->cd_scsi_status = SCSI_BUSY;
        xact->td_hflags |= TDFH_STSVALID;
        return;
    }
    dp = SGS_SGP(addr);

    nblks = lp->nbytes >> LUN_BLOCK_SHIFT;
    pgdata = addr;

    if (tmd->cd_cdb[1] & MODE_DBD) {
        pgdata += 4;
    } else {
        pgdata[3] = 8;
        pgdata[4] = ((1 << LUN_BLOCK_SHIFT) >> 24) & 0xff;
        pgdata[5] = ((1 << LUN_BLOCK_SHIFT) >> 16) & 0xff;
        pgdata[6] = ((1 << LUN_BLOCK_SHIFT) >>  8) & 0xff;
        pgdata[7] = ((1 << LUN_BLOCK_SHIFT)) & 0xff;

        pgdata[8] = (nblks >> 24) & 0xff;
        pgdata[9] = (nblks >> 16) & 0xff;
        pgdata[10] = (nblks >> 8) & 0xff;
        pgdata[11] = nblks & 0xff;
        pgdata += 12;
    }

    if (page == MODE_ALL_PAGES || page == MODE_FORMAT_DEVICE) {
        pgdata[0] = MODE_FORMAT_DEVICE;
        pgdata[1] = 24;
        if (pgctl != MODE_PGCTL_CHANGEABLE) {
            /* tracks per zone */
            /* pgdata[2] = 0; */
            /* pgdata[3] = 0; */
            /* alternate sectors per zone */
            /* pgdata[4] = 0; */
            /* pgdata[5] = 0; */
            /* alternate tracks per zone */
            /* pgdata[6] = 0; */
            /* pgdata[7] = 0; */
            /* alternate tracks per logical unit */
            /* pgdata[8] = 0; */
            /* pgdata[9] = 0; */
            /* sectors per track */
            pgdata[10] = (PSEUDO_SPT >> 8) & 0xff;
            pgdata[11] = PSEUDO_SPT & 0xff;
            /* data bytes per physical sector */
            pgdata[12] = ((1 << LUN_BLOCK_SHIFT) >> 8) & 0xff;
            pgdata[13] = (1 << LUN_BLOCK_SHIFT) & 0xff;
            /* interleave */
            /* pgdata[14] = 0; */
            /* pgdata[15] = 1; */
            /* track skew factor */
            /* pgdata[16] = 0; */
            /* pgdata[17] = 0; */
            /* cylinder skew factor */
            /* pgdata[18] = 0; */
            /* pgdata[19] = 0; */
            /* SSRC, HSEC, RMB, SURF */
        }
        pgdata += 26;
    }

    if (page == MODE_ALL_PAGES || page == MODE_GEOMETRY) {
        pgdata[0] = MODE_GEOMETRY;
        pgdata[1] = 24;
        if (pgctl != MODE_PGCTL_CHANGEABLE) {
            uint32_t cyl = (nblks + ((PSEUDO_SPC - 1))) / PSEUDO_SPC;
            /* number of cylinders */
            pgdata[2] = (cyl >> 24) & 0xff;
            pgdata[3] = (cyl >> 16) & 0xff;
            pgdata[4] = cyl & 0xff;
            /* number of heads */
            pgdata[5] = PSEUDO_HDS;
            /* starting cylinder- write precompensation */
            /* pgdata[6] = 0; */
            /* pgdata[7] = 0; */
            /* pgdata[8] = 0; */
            /* starting cylinder- reduced write current */
            /* pgdata[9] = 0; */
            /* pgdata[10] = 0; */
            /* pgdata[11] = 0; */
            /* drive step rate */
            /* pgdata[12] = 0; */
            /* pgdata[13] = 0; */
            /* landing zone cylinder */
            /* pgdata[14] = 0; */
            /* pgdata[15] = 0; */
            /* pgdata[16] = 0; */
            /* RPL */
            /* pgdata[17] = 0; */
            /* rotational offset */
            /* pgdata[18] = 0; */
            /* medium rotation rate -  7200 RPM */
            pgdata[20] = 0x1c;
            pgdata[21] = 0x20;
        }
        pgdata += 26;
    }

    if (page == MODE_ALL_PAGES || page == MODE_CACHE) {
        pgdata[0] = MODE_CACHE;
        pgdata[1] = 18;
#if 0
        if (pgctl == MODE_PGCTL_CHANGEABLE) {
            pgdata[2] = 1 << 2;
        } else {
            pgdata[2] = 1 << 2;
        }
#else
        pgdata[2] = 1 << 2;
#endif
        pgdata += 20;
    }

    if (page == MODE_ALL_PAGES || page == MODE_CONTROL) {
        pgdata[0] = MODE_CONTROL;
        pgdata[1] = 10;
        if (pgctl != MODE_PGCTL_CHANGEABLE) {
            pgdata[3] = 1 << 4; /* unrestricted reordering allowed */
            pgdata[8] = 0x75;   /* 30000 ms */
            pgdata[9] = 0x30;
        }
        pgdata += 12;
    }

    ((u8 *)addr)[0] = (u8 *)pgdata - (u8 *) addr - 4;
    dlen = min(tmd->cd_cdb[4], tmd->cd_totlen);
    dlen = min(dlen, SGS_PAYLOAD_SIZE);
    init_sg_elem(dp, NULL, 0, addr, dlen);
    xact->td_xfrlen = dp->length;
    xact->td_data = dp;
    xact->td_hflags |= TDFH_DATA_IN|TDFH_STSVALID;
    tmd->cd_flags |= CDF_PRIVATE_0;
}

static int
scsi_target_rdwr(tmd_cmd_t *tmd, ini_t *ini, int from_intr)
{
    bus_t *bp;
    lun_t *lp;
    struct page **pglist;
    uint64_t lba, devoff;
    uint32_t transfer_count, byte_count, count, first_offset;
    struct scatterlist *dp;
    tmd_xact_t *xact = &tmd->cd_xact;
    int iswrite, page_idx, list_idx, sgidx;
    unsigned long flags;

    bp = ini->ini_bus;
    lp = &bp->luns[L0LUN_TO_FLATLUN(tmd->cd_lun)];
    iswrite = 0;

    switch (tmd->cd_cdb[0]) {
    case WRITE_16:
        iswrite++;
        /* FALLTHROUGH */
    case READ_16:
        transfer_count =
            (((uint32_t)tmd->cd_cdb[10]) <<  24) |
            (((uint32_t)tmd->cd_cdb[11]) <<  16) |
            (((uint32_t)tmd->cd_cdb[12]) <<   8) |
            ((uint32_t)tmd->cd_cdb[13]);
        lba =
            (((uint64_t)tmd->cd_cdb[2]) << 56) |
            (((uint64_t)tmd->cd_cdb[3]) << 48) |
            (((uint64_t)tmd->cd_cdb[4]) << 40) |
            (((uint64_t)tmd->cd_cdb[5]) << 32) |
            (((uint64_t)tmd->cd_cdb[6]) << 24) |
            (((uint64_t)tmd->cd_cdb[7]) << 16) |
            (((uint64_t)tmd->cd_cdb[8]) <<  8) |
            ((uint64_t)tmd->cd_cdb[9]);
        break;
    case WRITE_12:
        iswrite++;
        /* FALLTHROUGH */
    case READ_12:
        transfer_count =
            (((uint32_t)tmd->cd_cdb[6]) <<  16) |
            (((uint32_t)tmd->cd_cdb[7]) <<   8) |
            ((u_int32_t)tmd->cd_cdb[8]);
        lba =
            (((uint32_t)tmd->cd_cdb[2]) << 24) |
            (((uint32_t)tmd->cd_cdb[3]) << 16) |
            (((uint32_t)tmd->cd_cdb[4]) <<  8) |
            ((uint32_t)tmd->cd_cdb[5]);
        break;
    case WRITE_10:
        iswrite++;
        /* FALLTHROUGH */
    case READ_10:
        transfer_count = (((uint32_t)tmd->cd_cdb[7]) <<  8) | ((u_int32_t)tmd->cd_cdb[8]);
        lba =
            (((uint32_t)tmd->cd_cdb[2]) << 24) |
            (((uint32_t)tmd->cd_cdb[3]) << 16) |
            (((uint32_t)tmd->cd_cdb[4]) <<  8) |
            ((uint32_t)tmd->cd_cdb[5]);
        break;
    case WRITE_6:
        iswrite++;
        /* FALLTHROUGH */
    case READ_6:
        transfer_count = tmd->cd_cdb[4];
        if (transfer_count == 0) {
            transfer_count = 256;
        }
        lba =
            (((uint32_t)tmd->cd_cdb[1] & 0x1f) << 16) |
            (((uint32_t)tmd->cd_cdb[2]) << 8) |
            ((uint32_t)tmd->cd_cdb[3]);
        break;
    default:
        if (from_intr) {
            scsi_cmd_sched_restart(tmd, "OTHER READ_WR command");
            return (-1);
        }
        add_sdata(ini, illfld);
        xact->td_hflags |= TDFH_SNSVALID;
        return (0);
    }

    /*
     * Bounds checks.
     */
    devoff = lba << LUN_BLOCK_SHIFT;
    if (unlikely((devoff + (((uint64_t)transfer_count) << LUN_BLOCK_SHIFT)) > lp->nbytes)) {
        printk(KERN_WARNING "scsi_target: overflow devoff (0x%llx) + count (0x%llx) > limit (0x%llx)\n", (unsigned long long) devoff,
            (unsigned long long)(((uint64_t)transfer_count) << LUN_BLOCK_SHIFT), (unsigned long long) lp->nbytes);
        add_sdata(ini, illfld);
        xact->td_hflags |= TDFH_SNSVALID;
        return (0);
    }

    if (unlikely(transfer_count == 0)) {
        printk(KERN_WARNING "%s: zero length transfer count\n", __FUNCTION__);
        xact->td_hflags |= TDFH_STSVALID;
        return (0);
    }

    /*
     * Make sure that the transfer_count doesn't exceed total data length
     */
    byte_count = transfer_count << LUN_BLOCK_SHIFT;
    if (unlikely(byte_count > tmd->cd_totlen)) {
        byte_count = tmd->cd_totlen;
        byte_count &= ~((1 << LUN_BLOCK_SHIFT) - 1);
        if (byte_count == 0) {
            printk(KERN_WARNING "%s: byte count less than a block\n", __FUNCTION__);
            xact->td_hflags |= TDFH_STSVALID;
            return (0);
        }
        transfer_count = byte_count >> LUN_BLOCK_SHIFT;
    }
    tmd->cd_off = devoff;

    if (lp->overcommit) {
        first_offset = 0;
        tmd->cd_nsgelems = (byte_count + PAGE_SIZE - 1) >> PAGE_SHIFT;
    } else {
        /*
         * Calculate the initial offset into the first page
         */
        first_offset = devoff & (PAGE_SIZE - 1);

        /*
         * Allocate a scatterlist that will cover this I/O
         */
        tmd->cd_nsgelems = (byte_count + first_offset + PAGE_SIZE - 1) >> PAGE_SHIFT;
    }
    dp = NULL;
    if (likely(from_intr && tmd->cd_nsgelems < SGELEM_CACHE_SIZE)) {
        spin_lock_irqsave(&scsi_target_lock, flags);
        dp = sg_cache;
        if (dp) {
            sg_cache = (struct scatterlist *) dp->page;
            dp->page = NULL;
            tmd->cd_flags |= CDF_PRIVATE_3;
        }
        spin_unlock_irqrestore(&scsi_target_lock, flags);
    }
    if (unlikely(dp == NULL)) {
        if (from_intr) {
            if (tmd->cd_nsgelems < SGELEM_CACHE_SIZE)
                scsi_cmd_sched_restart(tmd, "scatterlist restart: none available");
            else
                scsi_cmd_sched_restart(tmd, "scatterlist restart: large_xfr");
            return (-1);
        }
        dp = scsi_target_kzalloc(tmd->cd_nsgelems * sizeof (struct scatterlist), GFP_KERNEL|GFP_ATOMIC);
        if (dp == NULL) {
            printk(KERN_WARNING "unable to allocate %d entry scatterlist\n", tmd->cd_nsgelems);
            tmd->cd_scsi_status = SCSI_BUSY;
            xact->td_hflags |= TDFH_STSVALID;
            return (0);
        }
    }

    /*
     * If this is an overcommit disk, get pages for it.
     */
    if (lp->overcommit) {
        sgidx = 0;
        count = 0;
        SDprintk2("scsi_target: [%llx] get overcommit pages page_count %d\n", tmd->cd_tagval, lp->npglists);
        spin_lock_irqsave(&scsi_target_lock, flags);
        while (count < byte_count) {
            struct page *pp;
            dp[sgidx].page = (struct page *) lp->pagelists;
            if (dp[sgidx].page == NULL) {
                lp->outtagas = 1;
                scsi_cmd_sched_restart_locked(tmd, 0, "out of pages");
                while (--sgidx >= 0) {
                    struct page *pp = dp[sgidx].page;
                    NextPage(pp) = (NextPageType) lp->pagelists;
                    lp->pagelists = (struct page ***) pp;
                }
                if (tmd->cd_flags & CDF_PRIVATE_3) {
                    dp->page = (struct page *) sg_cache;
                    sg_cache = (struct scatterlist *) dp;
                    spin_unlock_irqrestore(&scsi_target_lock, flags);
                    tmd->cd_flags ^= CDF_PRIVATE_3;
                } else {
                    spin_unlock_irqrestore(&scsi_target_lock, flags);
                    scsi_target_kfree(dp, tmd->cd_nsgelems * sizeof (struct scatterlist));
                }
                return (-1);
            }
            dp[sgidx].length = min(PAGE_SIZE, byte_count - count);
            count += dp[sgidx].length;
            pp = dp[sgidx].page;
            lp->pagelists = (struct page ***) NextPage(pp);
            lp->npglists -= 1;
            SDprintk2("scsi_target: [%llx] dp[%d]:off %u len %u\n", tmd->cd_tagval, sgidx, dp[sgidx].offset, dp[sgidx].length);
            sgidx++;
        }
        spin_unlock_irqrestore(&scsi_target_lock, flags);
        goto out;
    }


    /*
     * Find the indices for the start of the transfer.
     */
    list_idx = START_LIST_IDX(devoff);
    page_idx = START_PAGE_IDX(devoff);

    SDprintk("%s lba %llu %u bytes dp %p np %d off %u %u:%u\n", iswrite? "write" : "read", lba, byte_count,
        dp, tmd->cd_nsgelems, first_offset, list_idx, page_idx);

    pglist = lp->pagelists[list_idx];
    sgidx = 0;
    count = 0;
    while (count < byte_count) {
        if (count == 0 && first_offset != 0) {
            dp[sgidx].offset = first_offset;
            dp[sgidx].length = min(PAGE_SIZE - first_offset, byte_count);
        } else {
            dp[sgidx].offset = 0;
            dp[sgidx].length = min(PAGE_SIZE, byte_count - count);
        }
        SDprintk2(" dp[%d]:off %u len %u %u:%u\n", sgidx, dp[sgidx].offset, dp[sgidx].length, list_idx, page_idx);
        dp[sgidx].page = pglist[page_idx++];
        count += dp[sgidx++].length;
        if (count != byte_count) {
            if (page_idx == PG_PER_LIST) {
                page_idx = 0;
                if (++list_idx >= lp->npglists) {
                    printk(KERN_WARNING "bad list_idx for block %lld\n", lba);
                    xact->td_data = dp;
                    tmd->cd_dp = dp;
                    xact->td_xfrlen = 0;
                    add_sdata(ini, ifailure);
                    xact->td_hflags |= TDFH_SNSVALID|TDFH_STSVALID;
                    tmd->cd_flags |= CDF_PRIVATE_1;
                    return (0);
                }
                pglist = lp->pagelists[list_idx];
            }
        }
    }

out:
    xact->td_xfrlen = byte_count;
    xact->td_data = dp;
    tmd->cd_dp = dp;
    tmd->cd_flags |= CDF_PRIVATE_1;
    if (iswrite) {
            xact->td_hflags |= TDFH_DATA_OUT;
            /*
             * WCE is set, or we're *not* an overcommit disk,
             * the command is done as soon as data lands
             * in memory.
             */
            if (/* lp->wce || */ lp->overcommit == 0) {
                xact->td_hflags |= TDFH_STSVALID;
            }
    } else {
            xact->td_hflags |= TDFH_DATA_IN;
            /*
             * If we're an overcommit disk, then we don't do
             * anything with this command yet- we put it on
             * a queue for a user agent to fill. The amount
             * to fill by the user agent is known by the
             * tmd->cd_totlen;
             *
             * When the user agent is done, the command is
             * then released back to move the fetched data
             * back to the initiator.
             */
            if (lp->overcommit) {
                spin_lock_irqsave(&scsi_target_lock, flags);
                tmd->cd_next = NULL;
                if (lp->u_front) {
                    lp->u_tail->cd_next = tmd;
                } else {
                    lp->u_front = tmd;
                }
                lp->u_tail = tmd;
                up(&lp->sema);
                spin_unlock_irqrestore(&scsi_target_lock, flags);
                return (1);
            } else {
                xact->td_hflags |= TDFH_STSVALID;
            }
    }
    return (0);
}

static int
scsi_target_ldfree(bus_t *bp, tmd_xact_t *xact, int from_intr)
{
    int i;
    unsigned long flags;
    tmd_cmd_t *tmd = xact->td_cmd;

    if (tmd->cd_flags & CDF_PRIVATE_0) {
        struct scatterlist *dp = xact->td_data;
        if (from_intr) {
            goto resched;
        }
        SDprintk("scsi_target: LDFREE[%llx] %p xact->td_data %p\n", tmd->cd_tagval, tmd, dp);
        if (dp) {
            scsi_target_kfree(page_address(dp->page) + dp->offset, SGS_SIZE);
        } else {
            printk(KERN_ERR "scsi_target: LDFREE[%llx] null dp @ line %d\n", tmd->cd_tagval, __LINE__);
            return (0);
        }
        xact->td_data = NULL;
        tmd->cd_flags &= ~CDF_PRIVATE_0;
    } else if (tmd->cd_flags & CDF_PRIVATE_1) {
        struct scatterlist *dp = tmd->cd_dp;
        lun_t *lp = &bp->luns[L0LUN_TO_FLATLUN(tmd->cd_lun)];

        if (dp == NULL) {
            printk(KERN_ERR "scsi_target: LDFREE[%llx] null dp @ line %d\n", tmd->cd_tagval, __LINE__);
            return (0);
        }

        if ((tmd->cd_flags & CDF_PRIVATE_3) == 0 && from_intr) {
            goto resched;
        }
        spin_lock_irqsave(&scsi_target_lock, flags);
        if (lp->outtagas) {
            lp->outtagas = 0;
            up(&scsi_thread_sleep_semaphore);
        }
        if (lp->overcommit) {
            for (i = 0; i < tmd->cd_nsgelems; i++) {
                struct page *pp = dp[i].page;
                if (pp == NULL) {
                    printk(KERN_ERR "%s: LDFREE[%llx] whoa! nullpage at index %d of %d for command 0x%x\n", __FUNCTION__, tmd->cd_tagval, i, tmd->cd_nsgelems - 1, tmd->cd_cdb[0] & 0xff);
                    continue;
                }
                NextPage(pp) = (NextPageType) lp->pagelists;
                lp->pagelists = (struct page ***) pp;
                lp->npglists += 1;
            }
            SDprintk("scsi_target: LDFREE[%llx] %s freeing nsgelems %d free count now %u\n", tmd->cd_tagval, from_intr? "intr" : "task", tmd->cd_nsgelems, lp->npglists);
        } else {
            SDprintk("scsi_target: LDFREE[%llx] %s freeing nsgelems %d\n", tmd->cd_tagval, from_intr? "intr" : "task", tmd->cd_nsgelems);
        }
        if (tmd->cd_flags & CDF_PRIVATE_3) {
            memset(dp, 0, tmd->cd_nsgelems * sizeof (struct scatterlist));
            dp->page = (struct page *) sg_cache;
            sg_cache = dp;
            spin_unlock_irqrestore(&scsi_target_lock, flags);
            tmd->cd_flags &= ~CDF_PRIVATE_3;
        } else {
            spin_unlock_irqrestore(&scsi_target_lock, flags);
            scsi_target_kfree(dp, tmd->cd_nsgelems * sizeof (struct scatterlist));
        }
        xact->td_data = NULL;
        tmd->cd_flags &= ~CDF_PRIVATE_1;
    }
    return (1);
resched:
    tmd->cd_next = NULL;
    spin_lock_irqsave(&scsi_target_lock, flags);
    if (q_front) {
        q_last->cd_next = tmd;
    } else {
        q_front = tmd;
    }
    q_last = tmd;
    up(&scsi_thread_sleep_semaphore);
    spin_unlock_irqrestore(&scsi_target_lock, flags);
    return (0);
}


void
scsi_target_handler(qact_e action, void *arg)
{
    unsigned long flags;
    bus_t *bp;

    switch (action) {
    case QOUT_HBA_REG:
    {
        hba_register_t *hp;
        spin_lock_irqsave(&scsi_target_lock, flags);
        for (bp = busses; bp < &busses[MAX_BUS]; bp++) {
            if (bp->h.r_action == NULL) {
                break;
           }
        }
        if (bp == &busses[MAX_BUS]) {
            spin_unlock_irqrestore(&scsi_target_lock, flags);
            printk("scsi_target: cannot register any more SCSI busses\n");
            break;
        }
        hp = arg;
        if (hp->r_version != QR_VERSION) {
            spin_unlock_irqrestore(&scsi_target_lock, flags);
            printk("scsi_target: version mismatch- compiled with %d, got %d\n", QR_VERSION, hp->r_version);
            break;
        }
        bp->h = *hp;
        spin_unlock_irqrestore(&scsi_target_lock, flags);
        printk("scsi_target: registering %s%d\n", hp->r_name, hp->r_inst);
        (hp->r_action)(QIN_HBA_REG, arg);
        break;
    }
    case QOUT_ENABLE:
    {
        enadis_t *ep = arg;
        if (ep->en_private) {
            up(ep->en_private);
        }
        break;
    }
    case QOUT_DISABLE:
    {
        enadis_t *ep = arg;
        if (ep->en_private) {
            up(ep->en_private);
        }
        break;
    }
    case QOUT_TMD_START:
    {
        tmd_cmd_t *tmd = arg;

        SDprintk2("scsi_target: TMD_START[%llx] %p cdb0=%x\n", tmd->cd_tagval, tmd, tmd->cd_cdb[0] & 0xff);

        tmd->cd_xact.td_cmd = tmd;
        scsi_target_start_cmd(tmd, 1);
        break;
    }
    case QOUT_TMD_DONE:
    {
        tmd_xact_t *xact = arg;
        tmd_cmd_t *tmd = xact->td_cmd;
        ini_t *nptr;

        bp = bus_from_tmd(tmd);
        if (bp == NULL) {
            printk(KERN_WARNING "%s: TMD_DONE cannot find bus again\n", __FUNCTION__);
            break;
        }

        SDprintk2("scsi_target: TMD_DONE[%llx] %p hf %x lf %x\n", tmd->cd_tagval, tmd, xact->td_hflags, xact->td_lflags);

        /*
         * Okay- were we moving data? If so, deal with the result.
         *
         * If so, check to see if we sent it.
         */
        if (xact->td_hflags & TDFH_DATA_OUT) {
            lun_t *lp;
            SDprintk("scsi_target: [%llx] data receive done\n", tmd->cd_tagval);
            spin_lock_irqsave(&scsi_target_lock, flags);
            lp = &bp->luns[L0LUN_TO_FLATLUN(tmd->cd_lun)];
            /*
             * If we're an overcommit disk we don't complete the command here.
             *
             * Instead, we give the data to a user agent. It knows how much
             * to write based upon tmd->cd_totlen.
             *
             * When the user agent is done, it will send back status for the command.
             */
            if (lp->enabled && lp->overcommit) {
                tmd->cd_next = NULL;
                if (lp->u_front) {
                    lp->u_tail->cd_next = tmd;
                } else {
                    lp->u_front = tmd;
                }
                lp->u_tail = tmd;
                spin_unlock_irqrestore(&scsi_target_lock, flags);
                up(&lp->sema);
                break;
            }
            spin_unlock_irqrestore(&scsi_target_lock, flags);
        } else if (xact->td_hflags & TDFH_DATA_IN) {
            SDprintk("scsi_target: [%llx] data transmit done\n", tmd->cd_tagval);
        }
        xact->td_hflags &= ~TDFH_DATA_MASK;
        xact->td_xfrlen = 0;


        /*
         * Did we send status already?
         */
        if (xact->td_hflags & TDFH_STSVALID) {
            if ((xact->td_lflags & TDFL_SENTSTATUS) == 0) {
                if (tmd->cd_flags & CDF_PRIVATE_2) {
                    printk(KERN_ERR "[%llx] already tried to send status\n", tmd->cd_tagval);
                } else {
                    tmd->cd_flags |= CDF_PRIVATE_2;
                    SDprintk("[%llx] sending status\n", tmd->cd_tagval);
                    (*bp->h.r_action)(QIN_TMD_CONT, xact);
                    break;
                }
            }
        }

        /*
         * Did we send sense? If so, remove one sense structure.
         */
        if (xact->td_hflags & TDFH_SNSVALID) {
            if (xact->td_lflags & TDFL_SENTSENSE) {
                spin_lock_irqsave(&scsi_target_lock, flags);
                nptr = ini_from_tmd(bp, tmd);
                spin_unlock_irqrestore(&scsi_target_lock, flags);
                if (nptr) {
                    rem_sdata(nptr);
                }
            }
        }

        if (scsi_target_ldfree(bp, xact, 1)) {
            SDprintk("%s: TMD_FIN[%llx]\n", __FUNCTION__, tmd->cd_tagval);
            (*bp->h.r_action)(QIN_TMD_FIN, tmd);
        }
        break;
    }
    case QOUT_NOTIFY:
    {
        tmd_notify_t *np = arg;
        spin_lock_irqsave(&scsi_target_lock, flags);
        bp = bus_from_notify(arg);
        if (bp == NULL) {
            spin_unlock_irqrestore(&scsi_target_lock, flags);
            printk(KERN_WARNING "%s: TMD_NOTIFY cannot find bus\n", __FUNCTION__);
            break;
        }
        if (np->nt_ncode == NT_ABORT_TASK) {
            tmd_cmd_t *tmd;
            lun_t *lp = &bp->luns[np->nt_lun];
            int i;

            for (i = 0, tmd = p_front; tmd; tmd = tmd->cd_next, i++) {
                if (tmd->cd_tagval == np->nt_tagval) {
                    printk(KERN_WARNING "scsi_target: ABORT_TASK[%llx] found %d into global waitq\n", tmd->cd_tagval, i);
                    break;
                }
            }
            if (tmd == NULL) {
                for (i = 0, tmd = lp->u_front; tmd; tmd = tmd->cd_next, i++) {
                    if (tmd->cd_tagval == np->nt_tagval) {
                        printk(KERN_WARNING "scsi_target: ABORT_TASK[%llx] found %d into waitq for lun %d\n", tmd->cd_tagval, i, np->nt_lun);
                        break;
                    }
                }
                if (tmd == NULL) {
                    printk(KERN_WARNING "scsi_target: ABORT_TASK[%llx] cannot find tmd\n", np->nt_tagval);
                }
            }
            spin_unlock_irqrestore(&scsi_target_lock, flags);
        } else {
            spin_unlock_irqrestore(&scsi_target_lock, flags);
            SDprintk("scsi_target: MGT code %x from %s%d\n", np->nt_ncode, bp->h.r_name, bp->h.r_inst);
        }
        (*bp->h.r_action)(QIN_NOTIFY_ACK, arg);
        break;
    }
    case QOUT_HBA_UNREG:
    {
        hba_register_t *hp = arg;
        int j;

        spin_lock_irqsave(&scsi_target_lock, flags);
        for (bp = busses; bp < &busses[MAX_BUS]; bp++) {
            if (bp->h.r_action == NULL) {
                continue;
            }
            if (bp->h.r_identity == hp->r_identity) {
                break;
           }
        }
        if (bp == &busses[MAX_BUS]) {
            spin_unlock_irqrestore(&scsi_target_lock, flags);
            printk(KERN_WARNING "%s: HBA_UNREG cannot find busp)\n", __FUNCTION__);
            break;
        }
        spin_unlock_irqrestore(&scsi_target_lock, flags);
        for (j = 0; j < HASH_WIDTH; j++) {
            ini_t *nptr = bp->list[j];
            while (nptr) {
                ini_t *next = nptr->ini_next;
                free_sdata_chain(nptr->ini_sdata);
                scsi_target_kfree(nptr, sizeof (ini_t));
                nptr = next;
            }
        }
        for (j = 0; j < MAX_BUS; j++) {
            if (bp->luns[j].enabled) {
                printk("scsi_target: %s%d had lun %d enabled\n", bp->h.r_name, bp->h.r_inst, j);
                scsi_free_disk(bp, j);
            }
        }
        printk("scsi_target: unregistering %s%d\n", bp->h.r_name, bp->h.r_inst);
        (hp->r_action)(QIN_HBA_UNREG, arg);
        break;
    }
    default:
        printk("scsi_target: action code %d (0x%x)?\n", action, action);
        break;
    }
}

static int
scsi_target_thread(void *arg)
{
    unsigned long flags;

    siginitsetinv(&current->blocked, 0);
    lock_kernel();
    daemonize("scsi_target_thread");
    unlock_kernel();
    up(&scsi_thread_entry_exit_semaphore);
    SDprintk("scsi_target_thread starting\n");

    while (scsi_target_thread_exit == 0) {
        tmd_cmd_t *tp;

        SDprintk3("scsi_task_thread sleeping\n");
        down_interruptible(&scsi_thread_sleep_semaphore);
        SDprintk3("scsi_task_thread running\n");

        spin_lock_irqsave(&scsi_target_lock, flags);
        if ((tp = p_front) != NULL) {
            p_last = p_front = NULL;
        }
        spin_unlock_irqrestore(&scsi_target_lock, flags);
        while (tp) {
            tmd_cmd_t *nxt = tp->cd_next;
            tp->cd_next = NULL;
            scsi_target_start_cmd(tp, 0);
            tp = nxt;
        }
        spin_lock_irqsave(&scsi_target_lock, flags);
        if ((tp = q_front) != NULL) {
            q_last = q_front = NULL;
        }
        spin_unlock_irqrestore(&scsi_target_lock, flags);
        while (tp) {
            bus_t *bp;
            tmd_cmd_t *tmd;

            tmd = tp;
            tp = tmd->cd_next;
            tmd->cd_next = NULL;
            bp = bus_from_tmd(tmd);
            if (bp == NULL) {
                printk(KERN_WARNING "lost bus when tring to call TMD_FIN\n");
            } else {
                if (scsi_target_ldfree(bp, &tmd->cd_xact, 0)) {
                    SDprintk("%s: TMD_FIN[%llx]\n", __FUNCTION__, tmd->cd_tagval);
                    (*bp->h.r_action)(QIN_TMD_FIN, tmd);
                }
            }
        }
    }
    SDprintk("scsi_target_thread exiting\n");
    up(&scsi_thread_entry_exit_semaphore);
    return (0);
}

static int
scsi_alloc_disk(bus_t *bp, int lun, int overcommit, uint64_t nbytes)
{
    int i;
    lun_t *lp;

    if (nbytes == 0) {
        return (-EINVAL);
    }
    /*
     * Round up the size to the next 512 byte boundary
     */
    if (nbytes & ((1 << LUN_BLOCK_SHIFT) - 1)) {
        uint64_t rusz = nbytes + (1 << LUN_BLOCK_SHIFT) - 1;
        rusz &= ~((1 << LUN_BLOCK_SHIFT) - 1);
        printk(KERN_WARNING "%s: rounding disk size from %llu to %llu\n", __FUNCTION__, nbytes, rusz);
        nbytes = rusz;
    }

    lp = &bp->luns[lun];
    lp->nbytes = nbytes;

    if (overcommit) {
        struct page *pp;
        int npgs = OC_SIZE >> PAGE_SHIFT;

        lp->overcommit = 1;
        lp->npglists = 0;
        for (i = 0; i < npgs; i++) {
                pp = alloc_page(__GFP_HIGHMEM | __GFP_WAIT);
                if (pp == NULL) {
                    printk(KERN_ERR "%s: unable to allocate memory pages\n", __FUNCTION__);
                    goto fail;
                }
                NextPage(pp) = (NextPageType) lp->pagelists;
                lp->pagelists = (struct page ***) pp;
                lp->npglists += 1;
            }
    } else {
        int npgs, j;
        size_t npgl;
        struct page **pptr;

        npgs = (nbytes + PAGE_SIZE - 1) >> PAGE_SHIFT;
        lp->npglists = (nbytes + PGLIST_MAPPING_SIZE - 1) / PGLIST_MAPPING_SIZE;
        npgl = lp->npglists * sizeof (struct page **);
        lp->pagelists = scsi_target_kzalloc(npgl, GFP_KERNEL);
        if (lp->pagelists == NULL) {
            return (-ENOMEM);
        }

        for (i = 0; i < lp->npglists; i++) {
            lp->pagelists[i] = scsi_target_kzalloc(PGLIST_SIZE, GFP_KERNEL);
            pptr = lp->pagelists[i];
            if (pptr == NULL) {
                goto fail;
            }
            for (j = 0; j < PG_PER_LIST; j++) {
                pptr[j] = alloc_page(__GFP_HIGHMEM | __GFP_WAIT);
                if (pptr[j] == NULL) {
                    printk(KERN_ERR "%s: unable to allocate memory pages\n", __FUNCTION__);
                    goto fail;
                }
                if (--npgs == 0) {
                    break;
                }
            }
            if (npgs == 0) {
                break;
            }
        }
    }
    return (0);

fail:
    scsi_free_disk(bp, lun);
    return (-ENOMEM);
}

static void
scsi_free_disk(bus_t *bp, int lun)
{
    lun_t *lp = &bp->luns[lun];

    if (lp->overcommit) {
        while (lp->pagelists) {
            struct page *pp = (struct page *) lp->pagelists;
            lp->pagelists = (struct page ***) NextPage(pp);
            __free_page(pp);
        }
        lp->npglists = 0;
    } else {
        if (lp->pagelists && lp->npglists) {
            int i, j;
            struct page **pptr;
            for (i = 0; i < lp->npglists; i++) {
                pptr = lp->pagelists[i];
                if (pptr == NULL) {
                    continue;
                }
                for (j = 0; j < PG_PER_LIST; j++) {
                    if (pptr[j] != NULL) {
                        __free_page(pptr[j]);
                        pptr[j] = NULL;
                }
                }
                scsi_target_kfree(pptr, PGLIST_SIZE);
            }
            scsi_target_kfree(lp->pagelists, lp->npglists * sizeof (struct page **));
            lp->pagelists = NULL;
            lp->npglists = 0;
        }
    }
    lp->overcommit = 0;
}

static int
scsi_target_copydata(struct scatterlist *dp, void *ubuf, uint32_t len, int from_user)
{
    struct page *pp;
    uint32_t count;
    char *kva, *uva;
    int err, idx, cpylen;

    idx = count = 0;
    uva = ubuf;
    while (count < len) {
        pp = dp[idx].page;
        kva = kmap(pp);
        if (kva == NULL) {
            return (-EFAULT);
        }
        cpylen = min(PAGE_SIZE, len - count);
        if (from_user) {
            err = copy_from_user(kva, uva, cpylen);
            SDprintk3("scsi_target: copy from user %p dp[%d].length=%u\n", uva, idx, cpylen);
        } else {
            err = copy_to_user(uva, kva, cpylen);
            SDprintk3("scsi_target: copy   to user %p dp[%d].length=%u\n", uva, idx, cpylen);
        }
        kunmap(pp);
        if (err) {
            return (err);
        }
        uva += cpylen;
        count += cpylen;
        idx++;
    }
    return (0);
}

static int
scsi_target_start_user_io(sc_io_t *sc)
{
    unsigned long flags;
    tmd_cmd_t *tmd;
    bus_t *bp;
    lun_t *lp;

    bp = bus_from_name(sc->hba_name_unit);
    if (bp == NULL) {
        SDprintk("%s: cannot find bus for %s\n", __FUNCTION__, sc->hba_name_unit);
        return (-ENXIO);
    }

    if (sc->lun >= MAX_LUN) {
        SDprintk("%s: bad lun (%d)\n", __FUNCTION__, sc->lun);
        return (-EINVAL);
    }
    lp = &bp->luns[sc->lun];

    SDprintk2("%s: waiting for a R/W IO operation\n", __FUNCTION__);
    if (down_interruptible(&lp->sema)) {
        return (-EINTR);
    }
    spin_lock_irqsave(&scsi_target_lock, flags);
    if ((tmd = lp->u_front) != NULL) {
        if ((lp->u_front = tmd->cd_next) == NULL) {
            lp->u_tail = NULL;
        }
    }
    spin_unlock_irqrestore(&scsi_target_lock, flags);
    if (tmd == NULL) {
        return (-ENOENT);
    }

    sc->off = tmd->cd_off;
    sc->tag = tmd;

    /*
     * If data is coming to us, copy it out to user space first.
     */
    if (tmd->cd_flags & CDF_DATA_OUT) {
        int r;

        sc->amt = tmd->cd_totlen;
        if (sc->amt > sc->len) {
            sc->amt = sc->len;
            printk(KERN_WARNING "scsi_target: A write to us (%u bytes) that is bigger than the user supplied buffer (%u bytes)\n", sc->amt, sc->len);
        }
        r = scsi_target_copydata(tmd->cd_dp, sc->addr, sc->amt, 0);
        if (r) {
            printk(KERN_ERR "scsi_target: failed to copy data to user space\n");
            memcpy(tmd->cd_sense, ifailure, TMD_SENSELEN);
            tmd->cd_scsi_status = CHECK_CONDITION;
            tmd->cd_xact.td_hflags &= ~TDFH_DATA_MASK;
            tmd->cd_xact.td_hflags |= TDFH_SNSVALID|TDFH_STSVALID;
            tmd->cd_xact.td_xfrlen = 0;
            (*bp->h.r_action)(QIN_TMD_CONT, &tmd->cd_xact);
            return (r);
        }
        sc->read = 0;
        if (lp->wce == 0) {
            sc->sync = 1;
        }
        SDprintk2("scsi_target: WR->USER [%llx] %p amt %u \n", tmd->cd_tagval, tmd, sc->amt);
    } else {
        sc->amt = tmd->cd_totlen;
        sc->read = 1;
        SDprintk2("scsi_target: RD->USER [%llx] %p amt %u\n", tmd->cd_tagval, tmd, sc->amt);
    }
    return (0);
}

static int
scsi_target_end_user_io(sc_io_t *sc)
{
    bus_t *bp;
    lun_t *lp;
    tmd_cmd_t *tmd;
    tmd_xact_t *xact;

    bp = bus_from_name(sc->hba_name_unit);
    if (bp == NULL) {
        SDprintk("%s: cannot find bus for %s\n", __FUNCTION__, sc->hba_name_unit);
        return (-ENXIO);
    }

    if (sc->lun >= MAX_LUN) {
        SDprintk("%s: bad lun (%d)\n", __FUNCTION__, sc->lun);
        return (-EINVAL);
    }
    lp = &bp->luns[sc->lun];
    tmd = sc->tag;
    xact = &tmd->cd_xact;
    SDprintk2("scsi_target: USER->KERN [%llx] %p err %d len %u\n", tmd->cd_tagval, tmd, sc->err, sc->len);
    /*
     * If we had an error, stop right here and return something to the initiator.
     */
    if (sc->err) {
        printk(KERN_ERR "err %d from user app\n", sc->err);
        memcpy(tmd->cd_sense, mediaerr, TMD_SENSELEN);
 barf:
        tmd->cd_scsi_status = CHECK_CONDITION;
        xact->td_hflags &= ~TDFH_DATA_MASK;
        xact->td_hflags |= TDFH_SNSVALID|TDFH_STSVALID;
        xact->td_xfrlen = 0;
        (*bp->h.r_action)(QIN_TMD_CONT, xact);
        return (0);
    }

    /*
     * If we were reading from us to the initiator, copy the data in and set it up for transmit back to the initiator.
     */
    if (tmd->cd_flags & CDF_DATA_IN) {
        /*
         * In this context, a user buffer length that is not equal to what the amount we told the user agent to move is not legal.
         */
        if (sc->len != tmd->cd_totlen) {
            printk(KERN_ERR "scsi_target: user read length %u not equal to required amount of %u\n", sc->len, tmd->cd_totlen);
            memcpy(tmd->cd_sense, ifailure, TMD_SENSELEN);
            goto barf;
        }
        if (scsi_target_copydata(tmd->cd_dp, sc->addr, sc->len, 1)) {
            printk(KERN_ERR "failed to copy in data for read\n");
            memcpy(tmd->cd_sense, ifailure, TMD_SENSELEN);
            goto barf;
        }
        xact->td_xfrlen = sc->len;
        xact->td_hflags |= TDFH_DATA_IN;
    } else {
        xact->td_xfrlen = 0;
        xact->td_hflags &= ~TDFH_DATA_MASK;
    }
    xact->td_hflags |= TDFH_STSVALID;
    (*bp->h.r_action)(QIN_TMD_CONT, xact);
    return (0);
}

static int
scsi_target_endis(char *hba_name_unit, uint64_t nbytes, int lun, int en)
{
    DECLARE_MUTEX_LOCKED(rsem);
    unsigned long flags;
    enadis_t ec;
    lun_t *lp;
    bus_t *bp;
    int rv, i;

    /*
     * XXX: yes, there is a race condition here where the bus can
     * XXX: go away. But in order to solve it, we have to make the
     * XXX: bus structure stay around while we call into the HBA
     * XXX: anyway, so fooey,.
     */
    bp = bus_from_name(hba_name_unit);
    if (bp == NULL) {
        SDprintk("%s: cannot find bus for %s\n", __FUNCTION__, hba_name_unit);
        return (-ENXIO);
    }

    if (lun < 0 || lun >= MAX_LUN) {
        SDprintk("%s: bad lun (%d)\n", __FUNCTION__, lun);
        return (-EINVAL);
    }
    lp = &bp->luns[lun];

    if (en) {
        if (bp->luns[lun].enabled) {
            printk("%s: lun %d already enabled\n", __FUNCTION__, lun);
            return (-EBUSY);
        }
        rv = scsi_alloc_disk(bp, lun, en == 2, nbytes);
        if (rv) {
            return (rv);
        }
    } else {
        lp->enabled = 0;
    }

    memset(&ec, 0, sizeof (ec));
    ec.en_hba = bp->h.r_identity;
    ec.en_tgt = TGT_ANY;
    ec.en_lun = lun;
    ec.en_private = &rsem;

    (*bp->h.r_action)(en? QIN_ENABLE : QIN_DISABLE, &ec);
    down(&rsem);

    if (ec.en_error) {
        SDprintk("%s: HBA returned %d for %s action\n", __FUNCTION__, ec.en_error, en? "enable" : "disable");
        scsi_free_disk(bp, lun);
        return (ec.en_error);
    }

    spin_lock_irqsave(&scsi_target_lock, flags);
    for (i = 0; i < HASH_WIDTH; i++) {
        ini_t *ini = bp->list[i];
        while (ini) {
            spin_unlock_irqrestore(&scsi_target_lock, flags);
            add_sdata(ini, invchg);
            spin_lock_irqsave(&scsi_target_lock, flags);
            ini = ini->ini_next;
        }
    }
    spin_unlock_irqrestore(&scsi_target_lock, flags);
    
    if (en == 0) {
        scsi_free_disk(bp, lun);
    } else {
        lp->u_tail = lp->u_front = NULL;
        sema_init(&lp->sema, 0);
        lp->wce = 1;
        lp->enabled = 1;
    }
    return (0);
}

EXPORT_SYMBOL(scsi_target_handler);
module_param(scsi_tdebug, int, 0);
#ifdef    MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif

int init_module(void)
{
    int i;
    struct proc_dir_entry *e;

    e = create_proc_entry(SCSI_TARGET, S_IFREG|S_IRUGO|S_IWUSR, 0);
    if (e == NULL){
        printk(KERN_ERR "cannot make %s\n", SCSI_TARGET);
        return (-EIO);
    }
    e->proc_fops = &scsi_target_fops;
    spin_lock_init(&scsi_target_lock);
    kernel_thread(scsi_target_thread, NULL, 0);
    down(&scsi_thread_entry_exit_semaphore);
    for (i = 0; i < N_SENSE_BUFS; i++) {
        sdata_t *t = scsi_target_kalloc(sizeof (sdata_t), GFP_KERNEL);
        if (t) {
            t->next = sdp;
            sdp = t;
        } else {
            break;
        }
    }
    printk(KERN_INFO "Allocated %d sense buffers\n", i);
    for (i = 0; i < SGELEM_CACHE_COUNT; i++) {
        struct scatterlist *sg = scsi_target_kzalloc(SGELEM_CACHE_SIZE * sizeof (struct scatterlist), GFP_KERNEL);
        if (sg == NULL) {
            break;
        }
        sg->page = (struct page *) sg_cache;
        sg_cache = sg;
    }
    printk(KERN_INFO "Allocated %d cached sg elements\n", i);
    return (0);
}

/*
 * We can't get here until all hbas have deregistered
 */
void cleanup_module(void)
{
    scsi_target_thread_exit = 1;
    up(&scsi_thread_sleep_semaphore);
    down(&scsi_thread_entry_exit_semaphore);
    free_sdata_chain(sdp);
    while (sg_cache) {
        struct scatterlist *sg = (struct scatterlist *) sg_cache->page;
        scsi_target_kfree(sg_cache, SGELEM_CACHE_SIZE * sizeof (struct scatterlist));
        sg_cache = sg;
    }
    remove_proc_entry(SCSI_TARGET, 0);
}
/*
 * vim:ts=4:sw=4:expandtab
 */
