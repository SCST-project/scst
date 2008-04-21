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
 *    by the Free Software Foundation.
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
 *
 */

/*
 * Qlogic ISP target driver for SCST.
 * Copyright (c) 2007 Stanislaw Gruszka
 * Copyright (c) 2007, 2008 Open-E Inc
 */

#ifndef  MODULE
#error  "this can only be built as a module"
#endif

#include <linux/version.h>
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
#include <linux/seq_file.h>

#include <scsi/scsi_host.h>
#include <scst.h>
#include <scst_debug.h>

#ifdef  min
#undef  min
#endif
#define min(a,b) (((a)<(b))?(a):(b))

#include "isp_tpublic.h"
#include "isp_linux.h"
#include "linux/smp_lock.h"

#define DEFAULT_DEVICE_TYPE 0       /* DISK */
#define MAX_BUS             8
#define MAX_LUN             64

/* usefull pointers when data is processed */
#define cd_scst_cmd      cd_hreserved[0].ptrs[0]
#define cd_bus           cd_hreserved[1].ptrs[0]
#define cd_hnext         cd_hreserved[2].ptrs[0]
#define cd_ini           cd_hreserved[3].ptrs[0]

/* command private flags */
#define CDF_PRIVATE_ABORTED     0x1000

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

#include "scsi_target.h"

#ifndef SERNO
#define SERNO   "000000"
#endif

typedef struct bus bus_t;
typedef struct bus_chan bus_chan_t;
typedef struct initiator ini_t;

struct initiator {
    ini_t *                 ini_next;
    uint64_t                ini_iid;        /* initiator identifier */
    struct scst_session *   ini_scst_sess;  /* sesson established by this remote initiator */
    int                     ini_refcnt;     /* reference counter, protected by bus_chan_t::tmds_lock */
};

#define    HASH_WIDTH    16
#define    INI_HASH_LISTP(bc, ini_id)    bc->list[ini_id & (HASH_WIDTH - 1)]

struct bus_chan {
    ini_t *                  list[HASH_WIDTH];   /* hash list of known initiators */
    spinlock_t               tmds_lock;
    tmd_cmd_t *              tmds_front;
    tmd_cmd_t *              tmds_tail;
    struct tasklet_struct    tasklet;
    struct scst_tgt *        scst_tgt;
    int                      enable;             /* is target mode enabled in low level driver */
    bus_t *                  bus;                /* back pointer */
};

struct bus {
    hba_register_t           h;                  /* must be first */
    int                      need_reg;           /* helpers for registration / unregistration */
    hba_register_t *         unreg_hp;
    bus_chan_t *             bchan;              /* channels */
};

#define    SDprintk     if (debug) printk
#define    SDprintk2    if (debug > 1) printk

static int debug = 0;

#define    Eprintk(fmt, args...) printk(KERN_ERR "isp_scst(%s): " fmt, __FUNCTION__, ##args)
#define    Iprintk(fmt, args...) printk(KERN_INFO "isp_scst(%s): " fmt, __FUNCTION__, ##args)

static void scsi_target_handler(qact_e, void *);

static __inline bus_t *bus_from_tmd(tmd_cmd_t *);
static __inline bus_t *bus_from_name(const char *);

static void scsi_target_start_cmd(tmd_cmd_t *, int);
static void scsi_target_done_cmd(tmd_cmd_t *, int);
static int scsi_target_thread(void *);
static int scsi_target_enadis(bus_chan_t *, int);

static bus_t busses[MAX_BUS];

DECLARE_MUTEX_LOCKED(scsi_thread_sleep_semaphore);
DECLARE_MUTEX_LOCKED(scsi_thread_entry_exit_semaphore);

static spinlock_t scsi_target_lock = SPIN_LOCK_UNLOCKED;
static int scsi_target_thread_exit = 0;

static unsigned long schedule_flags = 0;
#define SF_ADD_INITIATORS  0
#define SF_REGISTER_SCST   1
#define SF_UNREGISTER_SCST 2

static __inline void
schedule_scsi_thread(int flag)
{
    set_bit(flag, &schedule_flags);
    up(&scsi_thread_sleep_semaphore);
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
bus_from_name(const char *name)
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

static __inline ini_t *
ini_from_iid(bus_chan_t *bc, uint64_t iid)
{
   ini_t *ptr = INI_HASH_LISTP(bc, iid);
   if (ptr) {
        do {
            if (ptr->ini_iid == iid) {
                return (ptr);
            }
        } while ((ptr = ptr->ini_next) != NULL);
   }
   return (ptr);
}

static ini_t *
alloc_ini(bus_chan_t *bc, uint64_t iid)
{
    ini_t *nptr;
    char ini_name[24];

    SDprintk("scsi_target: alloc initiator 0x%016llx\n", iid);

    nptr = kmalloc(sizeof(ini_t), GFP_KERNEL);
    if (!nptr) {
        Eprintk("cannot allocate initiator data\n");
        return (NULL);
    }
    memset(nptr, 0, sizeof(ini_t));

    #define GET(byte) (uint8_t) ((iid >> 8*byte) & 0xff)
    snprintf(ini_name, sizeof(ini_name), "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
             GET(7), GET(6), GET(5) , GET(4), GET(3), GET(2), GET(1), GET(0));
    #undef GET

    nptr->ini_scst_sess = scst_register_session(bc->scst_tgt, 0, ini_name, NULL, NULL);
    if (!nptr->ini_scst_sess) {
        Eprintk("cannot register SCST session\n");
        kfree(nptr);
        return (NULL);
    }

    return (nptr);
}

static void
free_ini(ini_t *ini, int wait)
{
    scst_unregister_session(ini->ini_scst_sess, wait, NULL);
    kfree(ini);
}

static void
add_ini(bus_chan_t *bc, uint64_t iid, ini_t *nptr)
{
    ini_t **ptrlptr = &INI_HASH_LISTP(bc, iid);

    nptr->ini_iid = iid;
    nptr->ini_next = *ptrlptr;
    nptr->ini_refcnt = 0;
    *ptrlptr = nptr;
}

static void
del_ini(bus_chan_t *bc, uint64_t iid)
{
    ini_t *ptr, *prev;
    ini_t **ptrlptr = &INI_HASH_LISTP(bc, iid);

    ptr = *ptrlptr;
    if (ptr == NULL) {
        return;
    }
    if (ptr->ini_iid == iid) {
        *ptrlptr = ptr->ini_next;
        ptr->ini_next = NULL;
    } else {
        while (1) {
            prev = ptr;
            ptr = ptr->ini_next;
            if (ptr == NULL) {
                break;
            }
            if (ptr->ini_iid == iid) {
                prev->ini_next = ptr->ini_next;
                ptr->ini_next = NULL;
                break;
            }
        }
    }
}

static __inline void
__ini_get(ini_t *ini)
{
    if (ini != NULL) {
        ini->ini_refcnt++;
        SDprintk2("ini 0x%016llx ++refcnt (%d)\n", ini->ini_iid, ini->ini_refcnt);
    }
}

static __inline void
ini_get(bus_chan_t *bc, ini_t *ini)
{
    unsigned long flags;
    spin_lock_irqsave(&bc->tmds_lock, flags);
    __ini_get(ini);
    spin_unlock_irqrestore(&bc->tmds_lock, flags);
}

static __inline void
__ini_put(ini_t *ini)
{
    if (ini != NULL) {
        ini->ini_refcnt--;
        SDprintk2("ini 0x%016llx --refcnt (%d)\n", ini->ini_iid, ini->ini_refcnt);
    }
}

static __inline void
ini_put(bus_chan_t *bc, ini_t *ini)
{
    unsigned long flags;
    spin_lock_irqsave(&bc->tmds_lock, flags);
    __ini_put(ini);
    spin_unlock_irqrestore(&bc->tmds_lock, flags);
}

static void
tasklet_rx_cmds(unsigned long data)
{
    bus_chan_t *bc = (bus_chan_t *) data;
    bus_t *bp = bc->bus;
    ini_t *ini;
    tmd_cmd_t *tmd;
    tmd_xact_t *xact;
    struct scst_cmd *scst_cmd;

rx_loop:
    spin_lock_irq(&bc->tmds_lock);
    tmd = bc->tmds_front;
    if (tmd == NULL || tmd->cd_ini == NULL) {
        spin_unlock_irq(&bc->tmds_lock);
        return;
    }

    /* remove from queue */
    bc->tmds_front = tmd->cd_hnext;
    if (bc->tmds_front == NULL) {
        bc->tmds_tail = NULL;
    }

    /* free command if aborted */
    if (tmd->cd_flags & CDF_PRIVATE_ABORTED) {
        __ini_put(tmd->cd_ini);
        spin_unlock_irq(&bc->tmds_lock);
        SDprintk("%s: ABORTED TMD_FIN[%llx]\n", __FUNCTION__, tmd->cd_tagval);
        (*bp->h.r_action)(QIN_TMD_FIN, tmd);
        goto rx_loop;
    }

    ini = tmd->cd_ini;
    scst_cmd = scst_rx_cmd(ini->ini_scst_sess, tmd->cd_lun, sizeof(tmd->cd_lun), tmd->cd_cdb, sizeof(tmd->cd_cdb), 1);
    if (scst_cmd == NULL) {
        spin_unlock_irq(&bc->tmds_lock);
        tmd->cd_scsi_status = SCSI_BUSY;
        xact = &tmd->cd_xact;
        xact->td_hflags |= TDFH_STSVALID;
        xact->td_hflags &= ~TDFH_DATA_MASK;
        xact->td_xfrlen = 0;
        (*bp->h.r_action)(QIN_TMD_CONT, xact);
        goto rx_loop;
    }

    scst_cmd_set_tgt_priv(scst_cmd, tmd);
    scst_cmd_set_tag(scst_cmd, tmd->cd_tagval);
    tmd->cd_scst_cmd = scst_cmd;

    switch (tmd->cd_tagtype) {
        case CD_UNTAGGED:
            scst_cmd->queue_type = SCST_CMD_QUEUE_UNTAGGED;
            break;
        case CD_SIMPLE_TAG:
            scst_cmd->queue_type = SCST_CMD_QUEUE_SIMPLE;
            break;
        case CD_ORDERED_TAG:
            scst_cmd->queue_type = SCST_CMD_QUEUE_ORDERED;
            break;
        case CD_HEAD_TAG:
            scst_cmd->queue_type = SCST_CMD_QUEUE_HEAD_OF_QUEUE;
            break;
        case CD_ACA_TAG:
            scst_cmd->queue_type = SCST_CMD_QUEUE_ACA;
            break;
        default:
            scst_cmd->queue_type = SCST_CMD_QUEUE_ORDERED;
            break;
    }

    if (bp->h.r_type == R_FC) {
        scst_data_direction dir;
        int len;

        dir = SCST_DATA_NONE;
        if ((tmd->cd_flags & CDF_BIDIR) == CDF_BIDIR) {
            dir = SCST_DATA_UNKNOWN;
        } else if (tmd->cd_flags & CDF_DATA_OUT) {
            dir = SCST_DATA_WRITE;
        } else if (tmd->cd_flags & CDF_DATA_IN) {
            dir = SCST_DATA_READ;
        }
        len = tmd->cd_totlen;
        if (tmd->cd_cdb[0] == INQUIRY) {
            len = min(len, tmd->cd_cdb[4]);
        }
        scst_cmd_set_expected(scst_cmd, dir, len);
    }
    scst_cmd_init_done(scst_cmd, SCST_CONTEXT_TASKLET);
    spin_unlock_irq(&bc->tmds_lock);

    goto rx_loop;
}

static void
scsi_target_start_cmd(tmd_cmd_t *tmd, int from_intr)
{
    unsigned long flags;
    bus_t *bp;
    bus_chan_t *bc;

    /* first, find the bus */
    spin_lock_irqsave(&scsi_target_lock, flags);
    bp = bus_from_tmd(tmd);
    if (unlikely(bp == NULL || bp->bchan == NULL)) {
        spin_unlock_irqrestore(&scsi_target_lock, flags);
        Eprintk("cannot find %s for incoming command\n", (bp == NULL) ? "bus" : "channel");
        return;
    }
    spin_unlock_irqrestore(&scsi_target_lock, flags);

    tmd->cd_bus = bp;
    tmd->cd_hnext = NULL;
    bc = &bp->bchan[tmd->cd_channel];

    /* then, add commands to queue */
    spin_lock_irqsave(&bc->tmds_lock, flags);
    tmd->cd_ini = ini_from_iid(bc, tmd->cd_iid);
    __ini_get(tmd->cd_ini);
    if (bc->tmds_front == NULL) {
        bc->tmds_front = tmd;
    } else {
        bc->tmds_tail->cd_hnext = tmd;
    }
    bc->tmds_tail = tmd;
    spin_unlock_irqrestore(&bc->tmds_lock, flags);

    /* finally, shedule proper action */
    if (unlikely(tmd->cd_ini == NULL)) {
        schedule_scsi_thread(SF_ADD_INITIATORS);
    } else {
        tasklet_schedule(&bc->tasklet);
    }

    /* old bug warrning */
    if (unlikely(tmd->cd_cdb[0] == REQUEST_SENSE)) {
        Eprintk("REQUEST SENSE in auto sense mode !?!\n");
    }
}

static void
bus_chan_add_initiators(bus_t *bp, int chan)
{
    bus_chan_t *bc = &bp->bchan[chan];
    ini_t *ini;
    tmd_cmd_t *tmd;
    tmd_cmd_t *prev_tmd = NULL;
    tmd_xact_t *xact;

    SDprintk("scsi_target: searching new initiators for %s%d Chan %d\n", bp->h.r_name, bp->h.r_inst, chan);

    /* iterate over queue and find any commands not assigned to initiator */
    spin_lock_irq(&bc->tmds_lock);
    tmd = bc->tmds_front;
    while (tmd) {
        BUG_ON(tmd->cd_channel != chan);
        if (tmd->cd_ini != NULL) {
            /* ini assigned, go to the next command */
            prev_tmd = tmd;
            tmd = tmd->cd_hnext;
        } else {
            /* check if proper initiator exist already */
            ini = ini_from_iid(bc, tmd->cd_iid);
            if (ini != NULL) {
                tmd->cd_ini = ini;
                __ini_get(ini);
            } else {
                spin_unlock_irq(&bc->tmds_lock);

                ini = alloc_ini(bc, tmd->cd_iid);

                spin_lock_irq(&bc->tmds_lock);
                if (ini != NULL) {
                    tmd->cd_ini = ini;
                    add_ini(bc, tmd->cd_iid, ini);
                    __ini_get(ini);
                } else {
                    /* fail to alloc initiator, remove from queue and send busy */
                    if (prev_tmd == NULL) {
                        bc->tmds_front = tmd->cd_hnext;
                    } else {
                        prev_tmd->cd_hnext = tmd->cd_hnext;
                    }
                    if (bc->tmds_tail == tmd) {
                        bc->tmds_tail = prev_tmd;
                    }
                    spin_unlock_irq(&bc->tmds_lock);

                    tmd->cd_scsi_status = SCSI_BUSY;
                    xact = &tmd->cd_xact;
                    xact->td_hflags |= TDFH_STSVALID;
                    xact->td_hflags &= ~TDFH_DATA_MASK;
                    xact->td_xfrlen = 0;
                    (*bp->h.r_action)(QIN_TMD_CONT, xact);

                    spin_lock_irq(&bc->tmds_lock);
                    /* iterate to the next command, previous is not changed */
                    tmd = tmd->cd_hnext;
                }
            }
        }
    }
    spin_unlock_irq(&bc->tmds_lock);
    /* now we can run queue and pass commands to scst */
    tasklet_schedule(&bc->tasklet);
}

static void
bus_add_initiators(void)
{
    bus_t *bp;
    int chan;

    for (bp = busses; bp < &busses[MAX_BUS]; bp++) {
        spin_lock_irq(&scsi_target_lock);
        if (bp->h.r_action == NULL) {
            spin_unlock_irq(&scsi_target_lock);
            continue;
        }
        spin_unlock_irq(&scsi_target_lock);

        for (chan = 0; chan < bp->h.r_nchannels; chan++) {
            bus_chan_add_initiators(bp, chan);
        }
    }
}

static void
scsi_target_done_cmd(tmd_cmd_t *tmd, int from_intr)
{
    bus_t *bp;
    struct scst_cmd *scst_cmd;
    tmd_xact_t *xact = &tmd->cd_xact;

    SDprintk2("scsi_target: TMD_DONE[%llx] %p hf %x lf %x xfrlen %d totlen %d moved %d\n",
              tmd->cd_tagval, tmd, xact->td_hflags, xact->td_lflags, xact->td_xfrlen, tmd->cd_totlen, tmd->cd_moved);

    bp = tmd->cd_bus;
    scst_cmd = tmd->cd_scst_cmd;
    if (!scst_cmd) {
        /* command returned by us with status BUSY */
        SDprintk("%s: BUSY TMD_FIN[%llx]\n", __FUNCTION__, tmd->cd_tagval);
        ini_put(&bp->bchan[tmd->cd_channel], tmd->cd_ini);
        (*bp->h.r_action)(QIN_TMD_FIN, tmd);
        return;
    }

    if (xact->td_hflags & TDFH_STSVALID) {
        if (xact->td_hflags & TDFH_DATA_IN) {
            xact->td_hflags &= ~TDFH_DATA_MASK;
            xact->td_xfrlen = 0;
        }
        if (xact->td_error) {
            scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_FAILED);
        }
        scst_tgt_cmd_done(scst_cmd);
        return;
    }

    if (xact->td_hflags & TDFH_DATA_OUT) {
        if (tmd->cd_totlen == tmd->cd_moved) {
            if (xact->td_xfrlen) {
                int rx_status = SCST_RX_STATUS_SUCCESS;

                if (xact->td_error) {
                    rx_status = SCST_RX_STATUS_ERROR;
                }
                scst_rx_data(scst_cmd, SCST_RX_STATUS_SUCCESS, SCST_CONTEXT_TASKLET);
            } else {
                if (xact->td_error) {
                    scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_FAILED);
                }
                scst_tgt_cmd_done(scst_cmd);
            }
        } else {
            ; /* we don't have all data, do nothing */
        }
    } else if (xact->td_hflags & TDFH_DATA_IN) {
        xact->td_hflags &= ~TDFH_DATA_MASK;
        xact->td_xfrlen = 0;
        if (xact->td_error) {
            scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_FAILED);
        }
        scst_tgt_cmd_done(scst_cmd);
    }
}

static int
abort_task(bus_chan_t *bc, uint64_t iid, uint64_t tagval)
{
    unsigned long flags;
    tmd_cmd_t *tmd;

    spin_lock_irqsave(&bc->tmds_lock, flags);
    for (tmd = bc->tmds_front; tmd; tmd = tmd->cd_hnext) {
        if (tmd->cd_tagval == tagval && tmd->cd_iid == iid) {
            tmd->cd_flags |= CDF_PRIVATE_ABORTED;
            spin_unlock_irqrestore(&bc->tmds_lock, flags);
            tasklet_schedule(&bc->tasklet);
            return (1);
        }
    }
    spin_unlock_irqrestore(&bc->tmds_lock, flags);
    return (0);
}

static void
abort_all_tasks(bus_chan_t *bc, uint64_t iid)
{
    unsigned long flags;
    tmd_cmd_t *tmd;

    spin_lock_irqsave(&bc->tmds_lock, flags);
    for (tmd = bc->tmds_front; tmd; tmd = tmd->cd_hnext) {
        if (tmd->cd_iid == iid) {
            tmd->cd_flags |= CDF_PRIVATE_ABORTED;
        }
    }
    spin_unlock_irqrestore(&bc->tmds_lock, flags);
    tasklet_schedule(&bc->tasklet);
}

static void
scsi_target_notify(tmd_notify_t *np)
{
    bus_t *bp;
    bus_chan_t *bc;
    ini_t *ini;
    int fn;
    char *tmf = NULL;
    uint16_t lun;
    uint8_t lunbuf[8];
    unsigned long flags;

    /*
     * XXX If task management fail we can't give info to isp driver via tpublic
     * XXX notifies interface. FC stuff is capable to handle errors in TM.
     * XXX But TM is rare and TM errors are even more rare, so we can ignore errors
     * XXX now. Maybe tpublic API change, than we could uncomment passing errors to
     * XXX low level driver.
     */

    spin_lock_irqsave(&scsi_target_lock, flags);
    bp = bus_from_notify(np);
    if (unlikely(bp == NULL || bp->bchan == NULL)) {
        spin_unlock_irqrestore(&scsi_target_lock, flags);
        Eprintk("cannot find %s for incoming notify\n", bp == NULL ? "bus" : "channel");
        return;
    }
    spin_unlock_irqrestore(&scsi_target_lock, flags);

    SDprintk("scsi_target: MGT code %x from %s%d iid 0x%016llx\n", np->nt_ncode, bp->h.r_name, bp->h.r_inst, np->nt_iid);

    bc = &bp->bchan[np->nt_channel];

    spin_lock_irqsave(&bc->tmds_lock, flags);
    ini = ini_from_iid(bc, np->nt_iid);
    __ini_get(ini);
    spin_unlock_irqrestore(&bc->tmds_lock, flags);

    switch (np->nt_ncode) {
        case NT_ABORT_TASK:
            tmf = "ABORT TASK";
            if (ini == NULL) {
               goto err_no_ini;
            }
            if (abort_task(bc, np->nt_iid, np->nt_tagval)) {
                SDprintk("TMD_NOTIFY abort task [%llx]\n", np->nt_tagval);
                goto notify_ack;
            }
            if (scst_rx_mgmt_fn_tag(ini->ini_scst_sess, SCST_ABORT_TASK, np->nt_tagval, 1, np) < 0) {
                //np->nt_error = NT_FAILED;
                goto notify_ack;
            }
            /* wait for SCST now */
            return;
        case NT_ABORT_TASK_SET:
            tmf = "ABORT TASK SET";
            if (ini == NULL) {
                goto err_no_ini;
            }
            abort_all_tasks(bc, np->nt_iid);
            fn = SCST_ABORT_TASK_SET;
            break;
        case NT_CLEAR_TASK_SET:
            tmf = "CLEAR TASK SET";
            if (ini == NULL) {
                goto err_no_ini;
            }
            abort_all_tasks(bc, np->nt_iid);
            fn = SCST_CLEAR_TASK_SET;
            break;
        case NT_CLEAR_ACA:
            tmf = "CLEAR ACA";
            fn = SCST_CLEAR_ACA;
            break;
        case NT_LUN_RESET:
            tmf = "LUN RESET";
            if (np->nt_lun == LUN_ANY) {
                //np->nt_error = NT_REJECT;
                goto notify_ack;
            }
            fn = SCST_LUN_RESET;
            break;
        case NT_TARGET_RESET:
            tmf = "TARGET RESET";
            fn = SCST_TARGET_RESET;
            break;
        case NT_BUS_RESET:
        case NT_HBA_RESET:
            ini_put(bc, ini);
            //schedule_reset();
            return;
        case NT_LIP_RESET:
        case NT_LINK_UP:
        case NT_LINK_DOWN:
            /* we don't care about lip resets and link up/down */
            goto notify_ack;
        case NT_LOGOUT:
            spin_lock_irqsave(&bc->tmds_lock, flags);
            /* check if current notify is only pending request for initiator */
            if (ini != NULL && ini->ini_refcnt <= 1) {
                /* if so, we can delete initiator */
                del_ini(bc, np->nt_iid);
                free_ini(ini, 0);
                ini = NULL;
            } else {
                Eprintk("cannot logout initiator 0x%016llx\n", np->nt_iid);
            }
            spin_unlock_irqrestore(&bc->tmds_lock, flags);
            goto notify_ack;
        default:
            Eprintk("unknown notify 0x%x\n", np->nt_ncode);
            ini_put(bc, ini);
            return;
    }

    if (tmf) {
        if (ini == NULL) {
            goto err_no_ini;
        }
        if (np->nt_lun == LUN_ANY) {
            lun = 0;
        } else {
            lun = np->nt_lun;
        }
        FLATLUN_TO_L0LUN(lunbuf, lun);
        if (scst_rx_mgmt_fn_lun(ini->ini_scst_sess, fn, lunbuf, sizeof(lunbuf), 1, np) < 0) {
            //np->nt_error = NT_FAILED;
            goto notify_ack;
        }
    }
    return;

err_no_ini:
    Eprintk("cannot find initiator 0x%016llx for %s\n", np->nt_iid, tmf);
    //np->nt_error = NT_REJECT;
notify_ack:
    ini_put(bc, ini);
    (*bp->h.r_action) (QIN_NOTIFY_ACK, np);
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
            Eprintk("cannot register any more SCSI busses\n");
            break;
        }
        hp = arg;
        if (hp->r_version != QR_VERSION) {
            spin_unlock_irqrestore(&scsi_target_lock, flags);
            Eprintk("version mismatch - compiled with %d, got %d\n", QR_VERSION, hp->r_version);
            break;
        }
        bp->h = *hp;
        bp->need_reg = 1;
        spin_unlock_irqrestore(&scsi_target_lock, flags);
        schedule_scsi_thread(SF_REGISTER_SCST);
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
        scsi_target_start_cmd(arg, 1);
        break;
    }
    case QOUT_TMD_DONE:
    {
        tmd_xact_t *xact = arg;
        tmd_cmd_t *tmd = xact->td_cmd;
        scsi_target_done_cmd(tmd, 1);
        break;
    }
    case QOUT_NOTIFY:
    {
        tmd_notify_t *np = arg;
        SDprintk("scsi_target: TMD_NOTIFY %p code=0x%x\n", np, np->nt_ncode);
        scsi_target_notify(np);
        break;
    }
    case QOUT_HBA_UNREG:
    {
        hba_register_t *hp = arg;

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
            Eprintk("HBA_UNREG cannot find bus\n");
            break;
        }
        bp->unreg_hp = hp;
        spin_unlock_irqrestore(&scsi_target_lock, flags);
        schedule_scsi_thread(SF_UNREGISTER_SCST);
        break;
    }
    default:
        Eprintk("action code %d (0x%x)?\n", action, action);
        break;
    }
}

static void register_scst(void);
static void unregister_scst(void);

static int
scsi_target_thread(void *arg)
{
    siginitsetinv(&current->blocked, 0);
    lock_kernel();
    daemonize("scsi_target_thread");
    unlock_kernel();
    up(&scsi_thread_entry_exit_semaphore);
    SDprintk("scsi_target_thread starting\n");

    while (scsi_target_thread_exit == 0) {
        SDprintk2("scsi_task_thread sleeping\n");
        down(&scsi_thread_sleep_semaphore);
        SDprintk2("scsi_task_thread running\n");

        if (test_and_clear_bit(SF_REGISTER_SCST, &schedule_flags)) {
            register_scst();
        }
        if (test_and_clear_bit(SF_ADD_INITIATORS, &schedule_flags)) {
            bus_add_initiators();
        }
        if (test_and_clear_bit(SF_UNREGISTER_SCST, &schedule_flags)) {
            unregister_scst();
        }
    }
    SDprintk("scsi_target_thread exiting\n");
    up(&scsi_thread_entry_exit_semaphore);
    return (0);
}

static int
scsi_target_enadis(bus_chan_t *bc, int en)
{
    DECLARE_MUTEX_LOCKED(rsem);
    enadis_t ec;
    info_t info;
    int chan, err;
    bus_t *bp;

    if (en == bc->enable) {
        return (0);
    }
    bp = bc->bus;
    chan = (bc - bp->bchan);
    BUG_ON(bp == NULL || chan >= bp->h.r_nchannels);

    memset(&info, 0, sizeof (info));
    info.i_identity = bp->h.r_identity;
    info.i_channel = chan;
    (*bp->h.r_action)(QIN_GETINFO, &info);
    if (info.i_error) {
        err = info.i_error;
        goto failed;
    }

    memset(&ec, 0, sizeof (ec));
    ec.en_hba = bp->h.r_identity;
    ec.en_chan = chan;
    if (bp->h.r_type == R_FC) {
        ec.en_lun = LUN_ANY;
    } else {
        ec.en_lun = 0;
    }
    ec.en_private = &rsem;

    (*bp->h.r_action)(en ? QIN_ENABLE : QIN_DISABLE, &ec);
    down(&rsem);
    if (ec.en_error) {
       err = ec.en_error;
       goto failed;
    }

    bc->enable = en;
    return (0);

failed:
    Eprintk("%s%d: %s channel %d failed with error %d\n", bp->h.r_name, bp->h.r_inst, en ? "enable" : "disable", chan, err);
    return (err);
}

static int
isp_detect(struct scst_tgt_template *tgt_template)
{
    schedule_scsi_thread(SF_REGISTER_SCST);
    return (0);
}

static int
isp_release(struct scst_tgt *tgt)
{
    return (0);
}

static int
isp_rdy_to_xfer(struct scst_cmd *scst_cmd)
{
    bus_t *bp;

    if (scst_cmd_get_data_direction(scst_cmd) == SCST_DATA_WRITE) {
        tmd_cmd_t *tmd = (tmd_cmd_t *) scst_cmd_get_tgt_priv(scst_cmd);
        tmd_xact_t *xact = &tmd->cd_xact;

        xact->td_hflags |= TDFH_DATA_OUT;
        xact->td_data = scst_cmd_get_sg(scst_cmd);
        xact->td_xfrlen = scst_cmd_get_bufflen(scst_cmd);
        SDprintk2("%s: write nbytes %u\n", __FUNCTION__, scst_cmd_get_bufflen(scst_cmd));

        bp = tmd->cd_bus;
        (*bp->h.r_action)(QIN_TMD_CONT, xact);
    }

    return (0);
}

static int
isp_xmit_response(struct scst_cmd *scst_cmd)
{
    tmd_cmd_t *tmd = (tmd_cmd_t *) scst_cmd_get_tgt_priv(scst_cmd);
    bus_t *bp = tmd->cd_bus;
    tmd_xact_t *xact = &tmd->cd_xact;

    if (unlikely(scst_cmd_aborted(scst_cmd))) {
        scst_tgt_cmd_done(scst_cmd);
        return 0;
    }

    if (scst_cmd_get_data_direction(scst_cmd) == SCST_DATA_READ) {
        unsigned int len = scst_cmd_get_resp_data_len(scst_cmd);
        if (len > tmd->cd_totlen) {
            /* some broken initiators may send SCSI commands with data load
             * larger than underlaying transport specified */
            const uint8_t ifailure[TMD_SENSELEN] = { 0xf0, 0, 0x4, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0x44 };

            Eprintk("data size too big (totlen %u len %u)\n", tmd->cd_totlen, len);

            memcpy(tmd->cd_sense, ifailure, TMD_SENSELEN);
            xact->td_hflags |= TDFH_STSVALID;
            tmd->cd_scsi_status = SCSI_CHECK;
            goto out;
        } else {
            xact->td_hflags |= TDFH_DATA_IN;
            xact->td_xfrlen = len;
            xact->td_data = scst_cmd_get_sg(scst_cmd);
        }
    } else {
        /* finished write to target or command with no data */
        xact->td_xfrlen = 0;
        xact->td_hflags &= ~TDFH_DATA_MASK;
    }

    if (scst_cmd_get_tgt_resp_flags(scst_cmd) & SCST_TSC_FLAG_STATUS) {
        xact->td_hflags |= TDFH_STSVALID;
        tmd->cd_scsi_status = scst_cmd_get_status(scst_cmd);

        if (tmd->cd_scsi_status == SCSI_CHECK) {
            uint8_t *sbuf = scst_cmd_get_sense_buffer(scst_cmd);
            unsigned int slen = scst_cmd_get_sense_buffer_len(scst_cmd);
            if (unlikely(slen > TMD_SENSELEN)) {
                /* 18 bytes sense code not cover vendor specific sense data,
                 * we can't send more than 18 bytes through low level driver,
                 * so print error on this very unlikely situation */
                SDprintk("sense data too big (totlen %u len %u)\n", TMD_SENSELEN, slen);
                slen = TMD_SENSELEN;
            }
            memcpy(tmd->cd_sense, sbuf, slen);
            if (unlikely(debug > 0)) {
                uint8_t key, asc, ascq;
                key = (slen >= 2) ? sbuf[2] : 0;
                asc = (slen >= 12) ? sbuf[12] : 0;
                ascq = (slen >= 13) ? sbuf[13] : 0;
                SDprintk("sense code: key 0x%02x asc 0x%02x ascq 0x%02x\n", key, asc, ascq);
            }
        }
        SDprintk2("%s: status %d\n", __FUNCTION__, scst_cmd_get_status(scst_cmd));
    }

out:
    if ((xact->td_hflags & TDFH_STSVALID) && (tmd->cd_scsi_status == SCSI_CHECK)) {
        xact->td_xfrlen = 0;
        xact->td_hflags &= ~TDFH_DATA_MASK;
        xact->td_hflags |= TDFH_SNSVALID;
    }

    (*bp->h.r_action)(QIN_TMD_CONT, xact);
    return (0);
}

static void
isp_on_free_cmd(struct scst_cmd *scst_cmd)
{
    tmd_cmd_t *tmd = (tmd_cmd_t *) scst_cmd_get_tgt_priv(scst_cmd);
    bus_t *bp = tmd->cd_bus;
    tmd_xact_t *xact = &tmd->cd_xact;

    xact->td_data = NULL;
    ini_put(&bp->bchan[tmd->cd_channel], tmd->cd_ini);
    SDprintk2("%s: TMD_FIN[%llx]\n", __FUNCTION__, tmd->cd_tagval);
    (*bp->h.r_action)(QIN_TMD_FIN, tmd);
}

static void
isp_task_mgmt_fn_done(struct scst_mgmt_cmd *mgmt_cmd)
{
    tmd_notify_t *np = mgmt_cmd->tgt_priv;
    bus_t *bp;

    bp = bus_from_notify(np);
    SDprintk("%s: NOTIFY_ACK[%llx]\n", __FUNCTION__, np->nt_tagval);
    (*bp->h.r_action) (QIN_NOTIFY_ACK, np);
}

static int
isp_read_proc(struct seq_file *seq, struct scst_tgt *tgt)
{
    bus_chan_t *bc;

    bc = tgt->tgt_priv;
    if (!bc) {
        return (-ENODEV);
    }
    seq_printf(seq, "%d\n", bc->enable);
    return (0);
}

static int
isp_write_proc(char *buf, char **start, off_t offset, int len, int *eof, struct scst_tgt *tgt)
{
    bus_chan_t *bc = tgt->tgt_priv;
    int ret, en;

    if (!bc) {
        return (-ENODEV);
    }
    if (len < 2 || len > 3) {
        return (-EINVAL);
    }
    en = buf[0] - '0';
    if (en < 0 || en > 1) {
        return (-EINVAL);
    }
    ret = scsi_target_enadis(bc, en);
    if (ret < 0) {
        return (ret);
    }
    *eof = 1;
    return (len);
}

static struct scst_tgt_template isp_tgt_template =
{
    .sg_tablesize = SG_ALL, // FIXME do this depending of hardware ?
    .name = "qla_isp",
    .unchecked_isa_dma = 0,
    .use_clustering = 1,
    .xmit_response_atomic = 1,
    .rdy_to_xfer_atomic = 1,
    //.report_aen_atomic = 0,

    .detect = isp_detect,
    .release = isp_release,

    .xmit_response = isp_xmit_response,
    .rdy_to_xfer = isp_rdy_to_xfer,
    .on_free_cmd = isp_on_free_cmd,
    .task_mgmt_fn_done = isp_task_mgmt_fn_done,

    //.report_aen = isp_report_aen,
    .read_proc = isp_read_proc,
    .write_proc = isp_write_proc,
};

static void
register_hba(bus_t *bp)
{
    char name[32];
    info_t info;
    int chan;
    bus_chan_t *bchan, *bc;
    struct scst_tgt *scst_tgt;

    bchan = kzalloc(bp->h.r_nchannels * sizeof(bus_chan_t), GFP_KERNEL);
    if (bchan == NULL) {
        Eprintk("cannot allocate %d channels for %s%d\n", bp->h.r_nchannels, bp->h.r_name, bp->h.r_inst);
        goto err_free_bus;
    }

    for (chan = 0; chan < bp->h.r_nchannels; chan++) {
        memset(&info, 0, sizeof(info_t));
        info.i_identity = bp->h.r_identity;
        if (bp->h.r_type == R_FC) {
            info.i_type = I_FC;
        } else {
            info.i_type = I_SPI;
        }
        info.i_channel = chan;
        (*bp->h.r_action)(QIN_GETINFO, &info);
        if (info.i_error) {
            Eprintk("cannot get device name from %s%d!\n", bp->h.r_name, bp->h.r_inst);
            goto err_free_chan;
        }

        if (info.i_type == I_FC) {
            #define GET(byte) (uint8_t) ((info.i_id.fc.wwpn >> 8*byte) & 0xff)
            snprintf(name, sizeof(name), "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
                     GET(7), GET(6), GET(5) , GET(4), GET(3), GET(2), GET(1), GET(0));
            #undef GET
        } else { // SPI
            #define GET(byte) (uint8_t) ((info.i_id.spi.iid >> 8*byte) & 0xff)
            snprintf(name, sizeof(name), "%02x:%02x:%02x:%02x", GET(3), GET(2), GET(1), GET(0));
            #undef GET
        }

        scst_tgt = scst_register(&isp_tgt_template, name);
        if (scst_tgt == NULL) {
            Eprintk("cannot register scst device %s for %s%d\n", name, bp->h.r_name, bp->h.r_inst);
            goto err_free_chan;
        }

        bc = &bchan[chan];
        spin_lock_init(&bc->tmds_lock);
        tasklet_init(&bc->tasklet, tasklet_rx_cmds, (unsigned long) bc);
        bc->bus = bp;
        bc->scst_tgt = scst_tgt;
        scst_tgt->tgt_priv = bc;
    }

    spin_lock_irq(&scsi_target_lock);
    bp->bchan = bchan;
    spin_unlock_irq(&scsi_target_lock);

    Iprintk("registering %s%d\n", bp->h.r_name, bp->h.r_inst);
    (bp->h.r_action)(QIN_HBA_REG, &bp->h);
    return;

err_free_chan:
    for ( ; chan >= 0; chan--) {
        if (bchan[chan].scst_tgt) {
            scst_unregister(bchan[chan].scst_tgt);
        }
    }
    kfree(bchan);

err_free_bus:
    spin_lock_irq(&scsi_target_lock);
    memset(&bp->h, 0, sizeof (hba_register_t));
    spin_unlock_irq(&scsi_target_lock);
}

static void
unregister_hba(bus_t *bp, hba_register_t *unreg_hp)
{
    int i, chan;

    for (chan = 0; chan < bp->h.r_nchannels; chan++) {
        /* remove existing initiators */
        for (i = 0; i < HASH_WIDTH; i++) {
            ini_t *ini_next;
            ini_t *ptr = bp->bchan[chan].list[i];
            if (ptr) {
                do {
                    ini_next = ptr->ini_next;
                    free_ini(ptr, 1);
                } while ((ptr = ini_next) != NULL);
            }
        }

        if (bp->bchan[chan].scst_tgt) {
            scst_unregister(bp->bchan[chan].scst_tgt);
        }
    }

    /* it's safe now to reinit bp */
    kfree(bp->bchan);
    spin_lock_irq(&scsi_target_lock);
    memset(bp, 0, sizeof(bus_t));
    spin_unlock_irq(&scsi_target_lock);

    Iprintk("unregistering %s%d\n", unreg_hp->r_name, unreg_hp->r_inst);
    (unreg_hp->r_action)(QIN_HBA_UNREG, unreg_hp);
}

/* Register SCST target, must be called in process context */
static void
register_scst(void)
{
    bus_t *bp;

    for (bp = busses; bp < &busses[MAX_BUS]; bp++) {
        spin_lock_irq(&scsi_target_lock);
        if (bp->need_reg == 0) {
            spin_unlock_irq(&scsi_target_lock);
            continue;
        }
        bp->need_reg = 0;
        spin_unlock_irq(&scsi_target_lock);

        register_hba(bp);
   }
}

/* Unregister SCST target, must be called in process context */
static void
unregister_scst(void)
{
    bus_t *bp;
    hba_register_t *unreg_hp;

    for (bp = busses; bp < &busses[MAX_BUS]; bp++) {
        spin_lock_irq(&scsi_target_lock);
        if (bp->unreg_hp == NULL) {
            spin_unlock_irq(&scsi_target_lock);
            continue;
        }
        unreg_hp = bp->unreg_hp;
        bp->unreg_hp = NULL;
        spin_unlock_irq(&scsi_target_lock);

        unregister_hba(bp, unreg_hp);
    }
}

EXPORT_SYMBOL(scsi_target_handler);
module_param(debug, int, 0);

#ifdef    MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif

static void
start_scsi_target_thread(void)
{
    kernel_thread(scsi_target_thread, NULL, 0);
    down(&scsi_thread_entry_exit_semaphore);
}

static void
stop_scsi_target_thread(void)
{
    scsi_target_thread_exit = 1;
    up(&scsi_thread_sleep_semaphore);
    down(&scsi_thread_entry_exit_semaphore);
}

int init_module(void)
{
    int ret;

    spin_lock_init(&scsi_target_lock);
    start_scsi_target_thread();

    ret = scst_register_target_template(&isp_tgt_template);
    if (ret < 0) {
        Eprintk("cannot register scst target template\n");
        stop_scsi_target_thread();
    }
    return (ret);
}

/*
 * We can't get here until all hbas have deregistered
 */
void cleanup_module(void)
{
    stop_scsi_target_thread();
    scst_unregister_target_template(&isp_tgt_template);
}
/*
 * vim:ts=4:sw=4:expandtab
 */
