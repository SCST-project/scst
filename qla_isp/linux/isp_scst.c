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

/*
 * This file connects tpublic API from the low level ISP driver (see common/isp_tpublic.h)
 * with the SCST target driver API. Such a design does have certain disadvantages as
 * opposed to using SCST target API directly in the low level driver:
 * - we need to maintain duplicate data structures which are already maintained in the low
 *   level driver (commands queue, initiator data),
 * - processing takes additional cpu time for calling procedures and processing data.
 * However, the performance/memory cost is not so big, and such a design is flexible, as we
 * don't need to worry about low level details (e.g. if there is support for a new chipset
 * added to the low level ISP driver this code will not need to be changed).
 */

#ifndef  MODULE
#error  "this can only be built as a module"
#endif

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kthread.h>

#include <asm/byteorder.h>

#define LOG_PREFIX "qla_isp"

#include <scsi/scsi_host.h>
#include <scsi/scsi.h>
#include <scst.h>
#include <scst_debug.h>

#include "isp_tpublic.h"
#include "isp_linux.h"
#include "linux/smp_lock.h"

#define MAX_BUS             8
#define MAX_LUN             64

/* usefull pointers when data is processed */
#define cd_scst_cmd      cd_hreserved[0].ptrs[0]
#define cd_bus           cd_hreserved[1].ptrs[0]
#define cd_hnext         cd_hreserved[2].ptrs[0]
#define cd_ini           cd_hreserved[3].ptrs[0]
#define nt_ini           nt_hreserved

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
    uint64_t                 enable;             /* is target mode enabled in low level driver, one bit per lun */
    bus_t *                  bus;                /* back pointer */
    wait_queue_head_t        wait_queue;
    atomic_t                 sess_count;
};

struct bus {
    hba_register_t           h;                  /* must be first */
    int                      need_reg;           /* helpers for registration / unregistration */
    hba_register_t *         unreg_hp;
    bus_chan_t *             bchan;              /* channels */
    struct scst_proc_data    proc_data;
};

#define DEBUG 1

#ifdef DEBUG
#define    BUS_DBG(bp, fmt, args...)    if (debug > 0) printk("%s%d: %s " fmt, bp->h.r_name, bp->h.r_inst, __func__, ##args)
#define    BUS_DBG2(bp, fmt, args...)   if (debug > 1) printk("%s%d: %s " fmt, bp->h.r_name, bp->h.r_inst, __func__, ##args)
static int debug = 0;
module_param(debug, int, 0);
#else
#define    BUS_DBG(bp, fmt, args...)
#define    BUS_DBG2(bp, fmt, args...)
#endif

#define    Eprintk(fmt, args...) printk(KERN_ERR "isp_scst(%s): " fmt, __func__, ##args)
#define    Iprintk(fmt, args...) printk(KERN_INFO "isp_scst(%s): " fmt, __func__, ##args)

static void scsi_target_handler(qact_e, void *);

static __inline bus_t *bus_from_tmd(tmd_cmd_t *);
static __inline bus_t *bus_from_name(const char *);

static void scsi_target_start_cmd(tmd_cmd_t *);
static void scsi_target_done_cmd(tmd_cmd_t *);
static int scsi_target_enadis(bus_t *, uint64_t, int, int);
static void bus_chan_unregister_sessions(bus_chan_t *bc, int wait);

static bus_t busses[MAX_BUS];

static DEFINE_SPINLOCK(scsi_target_lock);

DECLARE_WAIT_QUEUE_HEAD(qlaispd_waitq);
struct task_struct *qlaispd_task;

static unsigned long qlaispd_flags = 0;
#define SF_ADD_INITIATORS  0
#define SF_REGISTER_SCST   1
#define SF_UNREGISTER_SCST 2

static __inline void
schedule_qlaispd(int flag)
{
    set_bit(flag, &qlaispd_flags);
    wake_up_interruptible(&qlaispd_waitq);
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
bus_from_notify(isp_notify_t *np)
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

    /* Set the iid here so the callback to get transport ID will be able to extract it
     * to generate the transport ID
     */
    nptr->ini_iid = iid;
    nptr->ini_scst_sess = scst_register_session(bc->scst_tgt, 0, ini_name, nptr, NULL, NULL);
    if (!nptr->ini_scst_sess) {
        Eprintk("cannot register SCST session\n");
        kfree(nptr);
        return (NULL);
    }

    atomic_inc(&bc->sess_count);
    BUS_DBG(bc->bus, "0x%016llx, ++sess_count %d\n", iid, atomic_read(&bc->sess_count));
    return (nptr);
}

static void
free_ini(bus_chan_t *bc, ini_t *ini, int wait)
{
    BUS_DBG(bc->bus, "0x%016llx, sess_count-- %d, wait %d\n", ini->ini_iid, atomic_read(&bc->sess_count), wait);
    scst_unregister_session(ini->ini_scst_sess, wait, NULL);
    /* no wait call is only when there are no pending commands, so we can free stuff here */
    kfree(ini);
    atomic_dec(&bc->sess_count);
    wake_up(&bc->wait_queue);
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

static int
del_ini(bus_chan_t *bc, uint64_t iid)
{
    ini_t *ptr, *prev;
    ini_t **ptrlptr = &INI_HASH_LISTP(bc, iid);

    ptr = *ptrlptr;
    if (ptr == NULL) {
        return (0);
    }
    if (ptr->ini_iid == iid) {
        *ptrlptr = ptr->ini_next;
        ptr->ini_next = NULL;
    } else {
        while (1) {
            prev = ptr;
            ptr = ptr->ini_next;
            if (ptr == NULL) {
                return (0);
            }
            if (ptr->ini_iid == iid) {
                prev->ini_next = ptr->ini_next;
                ptr->ini_next = NULL;
                break;
            }
        }
    }
    return (1);
}

static __inline void
__ini_get(bus_chan_t *bc, ini_t *ini)
{
    if (ini != NULL) {
        ini->ini_refcnt++;
        BUS_DBG2(bc->bus, "0x%016llx ++refcnt (%d)\n", ini->ini_iid, ini->ini_refcnt);
    }
}

static __inline void
ini_get(bus_chan_t *bc, ini_t *ini)
{
    unsigned long flags;
    spin_lock_irqsave(&bc->tmds_lock, flags);
    __ini_get(bc, ini);
    spin_unlock_irqrestore(&bc->tmds_lock, flags);
}

static __inline void
__ini_put(bus_chan_t *bc, ini_t *ini)
{
    if (ini != NULL) {
        ini->ini_refcnt--;
        BUS_DBG2(bc->bus, "0x%016llx --refcnt (%d)\n", ini->ini_iid, ini->ini_refcnt);
        if (ini->ini_refcnt < 0) {
            free_ini(bc, ini, 0);
        }
    }
}

static __inline void
ini_put(bus_chan_t *bc, ini_t *ini)
{
    unsigned long flags;
    spin_lock_irqsave(&bc->tmds_lock, flags);
    __ini_put(bc, ini);
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
        __ini_put(bc, tmd->cd_ini);
        spin_unlock_irq(&bc->tmds_lock);
        BUS_DBG(bp, "ABORTED TMD_FIN[%llx]\n", tmd->cd_tagval);
        (*bp->h.r_action)(QIN_TMD_FIN, tmd);
        goto rx_loop;
    }

    ini = tmd->cd_ini;
    scst_cmd = scst_rx_cmd(ini->ini_scst_sess, tmd->cd_lun, sizeof(tmd->cd_lun), tmd->cd_cdb, sizeof(tmd->cd_cdb), 1);
    if (scst_cmd == NULL) {
        spin_unlock_irq(&bc->tmds_lock);
        tmd->cd_scsi_status = SCSI_BUSY;
        xact = &tmd->cd_xact;
        xact->td_hflags = TDFH_STSVALID;
        xact->td_lflags = 0;
        xact->td_xfrlen = 0;
        (*bp->h.r_action)(QIN_TMD_CONT, xact);
        goto rx_loop;
    }

    scst_cmd_set_tgt_priv(scst_cmd, tmd);
    scst_cmd_set_tag(scst_cmd, tmd->cd_tagval);
    tmd->cd_scst_cmd = scst_cmd;

    switch (tmd->cd_tagtype) {
        case CD_UNTAGGED:
            scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_UNTAGGED);
            break;
        case CD_SIMPLE_TAG:
            scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_SIMPLE);
            break;
        case CD_ORDERED_TAG:
            scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_ORDERED);
            break;
        case CD_HEAD_TAG:
            scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_HEAD_OF_QUEUE);
            break;
        case CD_ACA_TAG:
            scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_ACA);
            break;
        default:
            scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_ORDERED);
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
    spin_unlock_irq(&bc->tmds_lock);

    scst_cmd_init_done(scst_cmd, SCST_CONTEXT_DIRECT_ATOMIC);

    goto rx_loop;
}

static void
scsi_target_start_cmd(tmd_cmd_t *tmd)
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

    BUS_DBG2(bp, "TMD_START[%llx] %p cdb0=%x\n", tmd->cd_tagval, tmd, tmd->cd_cdb[0] & 0xff);

    bc = &bp->bchan[tmd->cd_channel];
    if (unlikely(bc->enable == 0)) {
         BUS_DBG2(bp, "TMD_START[%llx] Chan %d not enabled - finishing command\n", tmd->cd_tagval, tmd->cd_channel);
         (*bp->h.r_action)(QIN_TMD_FIN, tmd);
         return;
    }
 
    tmd->cd_bus = bp;
    tmd->cd_hnext = NULL;

    /* then, add commands to queue */
    spin_lock_irqsave(&bc->tmds_lock, flags);
    tmd->cd_ini = ini_from_iid(bc, tmd->cd_iid);
    __ini_get(bc, tmd->cd_ini);
    if (bc->tmds_front == NULL) {
        bc->tmds_front = tmd;
    } else {
        bc->tmds_tail->cd_hnext = tmd;
    }
    bc->tmds_tail = tmd;
    spin_unlock_irqrestore(&bc->tmds_lock, flags);

    /* finally, schedule proper action */
    if (unlikely(tmd->cd_ini == NULL)) {
        schedule_qlaispd(SF_ADD_INITIATORS);
    } else {
        tasklet_schedule(&bc->tasklet);
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

    BUS_DBG(bp, "Chan %d searching new initiators\n", chan);

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
                __ini_get(bc, ini);
            } else {
                spin_unlock_irq(&bc->tmds_lock);

                ini = alloc_ini(bc, tmd->cd_iid);

                spin_lock_irq(&bc->tmds_lock);
                if (ini != NULL) {
                    tmd->cd_ini = ini;
                    add_ini(bc, tmd->cd_iid, ini);
                    __ini_get(bc, ini);
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
                    xact->td_hflags = TDFH_STSVALID;
                    xact->td_lflags = 0;
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
scsi_target_done_cmd(tmd_cmd_t *tmd)
{
    bus_t *bp;
    struct scst_cmd *scst_cmd;
    tmd_xact_t *xact = &tmd->cd_xact;
    enum scst_exec_context context = scst_estimate_context();

    bp = tmd->cd_bus;

    BUS_DBG2(bp,"TMD_DONE[%llx] %p hf %x lf %x xfrlen %d totlen %d moved %d\n",
             tmd->cd_tagval, tmd, xact->td_hflags, xact->td_lflags, xact->td_xfrlen, tmd->cd_totlen, tmd->cd_moved);

    scst_cmd = tmd->cd_scst_cmd;
    if (!scst_cmd) {
        /* command returned by us with status BUSY */
        BUS_DBG(bp, "BUSY TMD_FIN[%llx]\n", tmd->cd_tagval);
        ini_put(&bp->bchan[tmd->cd_channel], tmd->cd_ini);
        (*bp->h.r_action)(QIN_TMD_FIN, tmd);
        return;
    }

    if (xact->td_hflags & TDFH_STSVALID) {
        if (xact->td_hflags & TDFH_DATA_IN) {
            xact->td_hflags &= ~TDFH_DATA_MASK;
            xact->td_xfrlen = 0;
        }
        if (unlikely(xact->td_error)) {
            scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_FAILED);
        }
        scst_tgt_cmd_done(scst_cmd, context);
        return;
    }

    if (xact->td_hflags & TDFH_DATA_OUT) {
        if (likely(tmd->cd_totlen == tmd->cd_moved) || unlikely(xact->td_error)) {
            if (xact->td_xfrlen) {
                int rx_status = SCST_RX_STATUS_SUCCESS;
                if (unlikely(xact->td_error)) {
                    rx_status = SCST_RX_STATUS_ERROR;
                }
                scst_rx_data(scst_cmd, rx_status, context);
            } else {
                if (unlikely(xact->td_error)) {
                    scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_FAILED);
                }
                scst_tgt_cmd_done(scst_cmd, context);
            }
        } else {
            ; /* we don't have all data, do nothing */
        }
    } else if (xact->td_hflags & TDFH_DATA_IN) {
        xact->td_hflags &= ~TDFH_DATA_MASK;
        xact->td_xfrlen = 0;
        if (unlikely(xact->td_error)) {
            scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_FAILED);
        }
        scst_tgt_cmd_done(scst_cmd, context);
    } else {
        Eprintk("don't know what to do with TMD_DONE[%llx] cdb0 %x hf %x lf %x xfrlen %d totlen %d moved %d\n",
                tmd->cd_tagval, tmd->cd_cdb[0], xact->td_hflags, xact->td_lflags, xact->td_xfrlen, tmd->cd_totlen, tmd->cd_moved);
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
scsi_target_notify(notify_t *ins)
{
    bus_t *bp;
    bus_chan_t *bc;
    ini_t *ini;
    int fn;
    char *tmf = NULL;
    uint16_t lun;
    uint8_t lunbuf[8];
    unsigned long flags;
    isp_notify_t *np = &ins->notify;

    spin_lock_irqsave(&scsi_target_lock, flags);
    bp = bus_from_notify(np);
    if (unlikely(bp == NULL || bp->bchan == NULL)) {
        spin_unlock_irqrestore(&scsi_target_lock, flags);
        Eprintk("cannot find %s for incoming notify\n", bp == NULL ? "bus" : "channel");
        return;
    }
    spin_unlock_irqrestore(&scsi_target_lock, flags);

    BUS_DBG(bp, "TMD_NOTIFY %p code %x iid 0x%016llx tag %llx\n", np, np->nt_ncode, np->nt_wwn, np->nt_tagval);

    bc = &bp->bchan[np->nt_channel];

    spin_lock_irqsave(&bc->tmds_lock, flags);
    ini = ini_from_iid(bc, np->nt_wwn);
    np->nt_ini = ini;
    __ini_get(bc, np->nt_ini);
    spin_unlock_irqrestore(&bc->tmds_lock, flags);

    switch (np->nt_ncode) {
        case NT_ABORT_TASK:
            tmf = "ABORT TASK";
            if (ini == NULL) {
               goto err_no_ini;
            }
            if (abort_task(bc, np->nt_wwn, np->nt_tagval)) {
                BUS_DBG(bp, "TMD_NOTIFY abort task [%llx]\n", np->nt_tagval);
                goto notify_ack;
            }
            if (scst_rx_mgmt_fn_tag(ini->ini_scst_sess, SCST_ABORT_TASK, np->nt_tagval, 1, np) < 0) {
                np->nt_failed = 1;
                goto notify_ack;
            }
            /* wait for SCST now */
            return;
        case NT_ABORT_TASK_SET:
            tmf = "ABORT TASK SET";
            if (ini == NULL) {
                goto err_no_ini;
            }
            abort_all_tasks(bc, np->nt_wwn);
            fn = SCST_ABORT_TASK_SET;
            break;
        case NT_CLEAR_TASK_SET:
            tmf = "CLEAR TASK SET";
            if (ini == NULL) {
                goto err_no_ini;
            }
            abort_all_tasks(bc, np->nt_wwn);
            fn = SCST_CLEAR_TASK_SET;
            break;
        case NT_CLEAR_ACA:
            tmf = "CLEAR ACA";
            fn = SCST_CLEAR_ACA;
            break;
        case NT_LUN_RESET:
            tmf = "LUN RESET";
            if (np->nt_lun == LUN_ANY) {
                np->nt_failed = 1;
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
            /*
             * If someone disables the target during this notify, reference to initiator
             * is currently dropped, so we need to check if IID is still in initiators
             * table to avoid double free
             */
            if (del_ini(bc, np->nt_wwn)) {
                BUS_DBG(bp, "droping reference to initiator 0x%016llx\n", np->nt_wwn);
                __ini_put(bc, ini);
            } else {
                Eprintk("cannot logout initiator 0x%016llx\n", np->nt_wwn);
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
	if (scst_rx_mgmt_fn_lun(ini->ini_scst_sess, fn, lunbuf,
				sizeof(lunbuf), 1, ins) < 0) {
		np->nt_failed = 1;
		goto notify_ack;
        }
    }
    return;

err_no_ini:
    Eprintk("cannot find initiator 0x%016llx for %s\n", np->nt_wwn, tmf);
    np->nt_failed = 1;
notify_ack:
    ini_put(bc, ini);
    (*bp->h.r_action) (QIN_NOTIFY_ACK, ins);
}

static void
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
        schedule_qlaispd(SF_REGISTER_SCST);
        break;
    }
    case QOUT_ENABLE:
    {
        enadis_t *ep = arg;
        if (ep->en_private) {
            up((struct semaphore *)ep->en_private);
        }
        break;
    }
    case QOUT_DISABLE:
    {
        enadis_t *ep = arg;
        if (ep->en_private) {
            up((struct semaphore *)ep->en_private);
        }
        break;
    }
    case QOUT_TMD_START:
    {
        tmd_cmd_t *tmd = arg;
        tmd->cd_xact.td_cmd = tmd;
        scsi_target_start_cmd(arg);
        break;
    }
    case QOUT_TMD_DONE:
    {
        tmd_xact_t *xact = arg;
        tmd_cmd_t *tmd = xact->td_cmd;
        scsi_target_done_cmd(tmd);
        break;
    }
    case QOUT_NOTIFY:
    {
	notify_t *ins = arg;
	scsi_target_notify(ins);
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
        schedule_qlaispd(SF_UNREGISTER_SCST);
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
qlaispd_function(void *arg)
{
    printk(KERN_DEBUG "qlaispd starting\n");
    while (!kthread_should_stop()) {
        printk(KERN_DEBUG "qlaispd sleeping\n");
        wait_event_interruptible(qlaispd_waitq, qlaispd_flags || kthread_should_stop());
        printk(KERN_DEBUG "qlaispd running\n");

        if (test_and_clear_bit(SF_REGISTER_SCST, &qlaispd_flags)) {
            register_scst();
        }
        if (test_and_clear_bit(SF_ADD_INITIATORS, &qlaispd_flags)) {
            bus_add_initiators();
        }
        if (test_and_clear_bit(SF_UNREGISTER_SCST, &qlaispd_flags)) {
            unregister_scst();
        }
    }
    printk(KERN_DEBUG "qlaispd exiting\n");
    return (0);
}

static int
scsi_target_enable(bus_t *bp, int chan, int lun)
{
    struct semaphore rsem;
    bus_chan_t *bc;
    uint64_t mask;
    enadis_t ec;

    memset(&ec, 0, sizeof (ec));
    ec.en_hba = bp->h.r_identity;
    ec.en_chan = chan;
    if (bp->h.r_type == R_FC) {
        ec.en_lun = LUN_ANY;
    } else {
        ec.en_lun = lun;
    }
    sema_init(&rsem, 0);
    ec.en_private = &rsem;
    (*bp->h.r_action)(QIN_ENABLE, &ec);
    down(&rsem);
    if (ec.en_error) {
        return (ec.en_error);
    }

    bc = &bp->bchan[chan];
    if (bp->h.r_type == R_FC) {
        bc->enable = 1;
    } else {
        mask = ~(1 << lun);
        bc->enable &= mask;
        bc->enable |= (1 << lun);
    }

    return (0);
}

static int
scsi_target_disable(bus_t *bp, int chan, int lun)
{
    uint64_t mask;
    uint64_t old_enable;
    struct semaphore rsem;
    enadis_t ec;
    bus_chan_t *bc;

    bc = &bp->bchan[chan];
    old_enable = bc->enable;

    if (bp->h.r_type == R_FC) {
        bc->enable = 0;
    } else {
        mask = ~(1 << lun);
        bc->enable &= mask;
    }

    // FIXME I don't know what I'm doing .... but I will know ... some day
    smp_wmb();

    if (bc->enable == 0) {
        BUS_DBG(bp, "Chan %d drop all initiators references\n", chan);
        /*
         * If no lun is active on channel we want to logoff from SCST. At this point we ignore all
         * new commands and notifies comeing from low level driver, but we need to care on pending
         * ones. We just drop reference to initiators. When last command/notify finish for initiator,
         * we will unregister session from SCST and disable target mode in low lever driver here.
         */
        bus_chan_unregister_sessions(bc, 0);

        /*
         * Now wait for all sessions associated with channel stop.
         */
        BUS_DBG(bp, "Chan %d waiting for finishing %d sessions\n", chan, atomic_read(&bc->sess_count));
        wait_event(bc->wait_queue, atomic_read(&bc->sess_count) == 0);
        BUS_DBG(bp, "Chan %d all sessions finished\n", chan);
    }

    memset(&ec, 0, sizeof (ec));
    ec.en_hba = bp->h.r_identity;
    ec.en_chan = chan;
    if (bp->h.r_type == R_FC) {
        ec.en_lun = LUN_ANY;
    } else {
        ec.en_lun = lun;
    }
    sema_init(&rsem, 0);
    ec.en_private = &rsem;
    (*bp->h.r_action)(QIN_DISABLE, &ec);
    down(&rsem);
    if (ec.en_error) {
        bc->enable = old_enable;
        return (ec.en_error);
    }

    return (0);
}

static int
scsi_target_enadis(bus_t *bp, uint64_t en, int chan, int lun)
{
    bus_chan_t *bc;
    info_t info;
    uint64_t mask;

    BUG_ON(chan < 0 || chan >= bp->h.r_nchannels);
    BUG_ON(lun != LUN_ANY && (lun < 0 || lun >= MAX_LUN));

    bc = &bp->bchan[chan];

    if (bp->h.r_type == R_FC) {
        if (en == bc->enable) {
            return (0);
        }
    } else {
        if (lun == LUN_ANY) {
            return (-EINVAL);
        } else {
            mask = ~(1 << lun);
            if ((en << lun) == (bc->enable & mask)) {
                return (0);
            }
        }
    }

    /*
     * Check if requested HBA is there
     */
    memset(&info, 0, sizeof (info));
    info.i_identity = bp->h.r_identity;
    info.i_channel = chan;
    (*bp->h.r_action)(QIN_GETINFO, &info);
    if (info.i_error) {
        return (info.i_error);
    }

    if (en) {
        return scsi_target_enable(bp, chan, lun);
    } else {
        return scsi_target_disable(bp, chan, lun);
    }
}

static int
isp_detect(struct scst_tgt_template *tgt_template)
{
    schedule_qlaispd(SF_REGISTER_SCST);
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
    /* don't need to check against aborted, low level driver handle
     * this and call us back with error */

    if (scst_cmd_get_data_direction(scst_cmd) == SCST_DATA_WRITE) {
        tmd_cmd_t *tmd = (tmd_cmd_t *) scst_cmd_get_tgt_priv(scst_cmd);
        tmd_xact_t *xact = &tmd->cd_xact;
        bus_t *bp = tmd->cd_bus;
        int len = scst_cmd_get_bufflen(scst_cmd);

        xact->td_hflags = TDFH_DATA_OUT;
        xact->td_lflags = 0;
        xact->td_data = scst_cmd_get_sg(scst_cmd);
        xact->td_xfrlen = len;
        if (bp->h.r_type == R_SPI) {
            tmd->cd_totlen = len;
        }

        BUS_DBG2(bp, "TMD[%llx] write nbytes %u\n", tmd->cd_tagval, scst_cmd_get_bufflen(scst_cmd));

        (*bp->h.r_action)(QIN_TMD_CONT, xact);
        /*
         * Did we have an error starting this particular transaction?
         */
        if (unlikely((xact->td_lflags & (TDFL_ERROR|TDFL_SYNCERROR)) == (TDFL_ERROR|TDFL_SYNCERROR))) {
            if (xact->td_error == -ENOMEM) {
                return (SCST_TGT_RES_QUEUE_FULL);
            } else {
                return (SCST_TGT_RES_FATAL_ERROR);
            }
        }
    }
    return (SCST_TGT_RES_SUCCESS);
}

static int
isp_xmit_response(struct scst_cmd *scst_cmd)
{
    tmd_cmd_t *tmd = (tmd_cmd_t *) scst_cmd_get_tgt_priv(scst_cmd);
    bus_t *bp = tmd->cd_bus;
    tmd_xact_t *xact = &tmd->cd_xact;

    if (unlikely(scst_cmd_aborted_on_xmit(scst_cmd))) {
        scst_set_delivery_status(scst_cmd, SCST_CMD_DELIVERY_ABORTED);
        scst_tgt_cmd_done(scst_cmd, SCST_CONTEXT_SAME);
        return (SCST_TGT_RES_SUCCESS);
    }

    if (scst_cmd_get_data_direction(scst_cmd) == SCST_DATA_READ) {
        unsigned int len = scst_cmd_get_resp_data_len(scst_cmd);
        if (bp->h.r_type == R_SPI) {
            tmd->cd_totlen = len;
        }
        if (unlikely(len > tmd->cd_totlen)) {
            /* some broken FC initiators may send SCSI commands with data load
             * larger than underlaying transport specified */
            const uint8_t ifailure[TMD_SENSELEN] = { 0xf0, 0, 0x4, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0x44 };

            Eprintk("data size too big (totlen %u len %u)\n", tmd->cd_totlen, len);

            memcpy(tmd->cd_sense, ifailure, TMD_SENSELEN);
            xact->td_hflags = TDFH_STSVALID;
            tmd->cd_scsi_status = SCSI_CHECK;
            goto out;
        } else {
            xact->td_hflags = TDFH_DATA_IN;
            xact->td_xfrlen = len;
            xact->td_data = scst_cmd_get_sg(scst_cmd);
        }
    } else {
        /* finished write to target or command with no data */
        xact->td_xfrlen = 0;
        xact->td_hflags &= ~TDFH_DATA_MASK;
    }

    xact->td_lflags = 0;

    if (scst_cmd_get_is_send_status(scst_cmd)) {
        xact->td_hflags |= TDFH_STSVALID;
        tmd->cd_scsi_status = scst_cmd_get_status(scst_cmd);

        if (tmd->cd_scsi_status == SCSI_CHECK) {
            uint8_t *sbuf = scst_cmd_get_sense_buffer(scst_cmd);
            unsigned int slen = scst_cmd_get_sense_buffer_len(scst_cmd);
            if (likely(slen > TMD_SENSELEN)) {
                /* 18 bytes sense code not cover vendor specific sense data,
                 * we can't send more than 18 bytes through low level driver,
                 * however SCST give us 96 bytes, so truncate */
                slen = TMD_SENSELEN;
            }
            memcpy(tmd->cd_sense, sbuf, slen);
#ifdef DEBUG
            if (unlikely(debug > 0)) {
                uint8_t key, asc, ascq;
                key = (slen >= 2) ? sbuf[2] : 0;
                asc = (slen >= 12) ? sbuf[12] : 0;
                ascq = (slen >= 13) ? sbuf[13] : 0;
                BUS_DBG(bp, "sense code: key 0x%02x asc 0x%02x ascq 0x%02x\n", key, asc, ascq);
            }
#endif
        }
        BUS_DBG2(bp, "TMD[%llx] status %d\n", tmd->cd_tagval, scst_cmd_get_status(scst_cmd));
    }

out:
    if ((xact->td_hflags & TDFH_STSVALID) && (tmd->cd_scsi_status == SCSI_CHECK)) {
        xact->td_xfrlen = 0;
        xact->td_hflags &= ~TDFH_DATA_MASK;
        xact->td_hflags |= TDFH_SNSVALID;
    }

    (*bp->h.r_action)(QIN_TMD_CONT, xact);
    /*
     * Did we have an error starting this particular transaction?
     */
    if (unlikely((xact->td_lflags & (TDFL_ERROR|TDFL_SYNCERROR)) == (TDFL_ERROR|TDFL_SYNCERROR))) {
        if (xact->td_error == -ENOMEM) {
            return (SCST_TGT_RES_QUEUE_FULL);
        } else {
            return (SCST_TGT_RES_FATAL_ERROR);
        }
    }
    return (SCST_TGT_RES_SUCCESS);
}

static void
isp_on_free_cmd(struct scst_cmd *scst_cmd)
{
    tmd_cmd_t *tmd = (tmd_cmd_t *) scst_cmd_get_tgt_priv(scst_cmd);
    bus_t *bp = tmd->cd_bus;
    tmd_xact_t *xact = &tmd->cd_xact;

    xact->td_data = NULL;
    ini_put(&bp->bchan[tmd->cd_channel], tmd->cd_ini);
    BUS_DBG2(bp, "TMD_FIN[%llx]\n", tmd->cd_tagval);
    (*bp->h.r_action)(QIN_TMD_FIN, tmd);
}

static int
isp_task_mgmt_fn_get_resp(int scst_mgmt_status)
{
	switch (scst_mgmt_status) {
	case SCST_MGMT_STATUS_SUCCESS:
		return FCP_RSPNS_TMF_SUCCEEDED;

	case SCST_MGMT_STATUS_TASK_NOT_EXIST:
		return FCP_RSPNS_BADCMND;

	case SCST_MGMT_STATUS_LUN_NOT_EXIST:
		return FCP_RSPNS_TMF_INCORRECT_LUN;

	case SCST_MGMT_STATUS_FN_NOT_SUPPORTED:
	case SCST_MGMT_STATUS_REJECTED:
		return FCP_RSPNS_TMF_REJECT;

	case SCST_MGMT_STATUS_FAILED:
	default:
		return FCP_RSPNS_TMF_FAILED;
	}
}

static void
isp_task_mgmt_fn_done(struct scst_mgmt_cmd *mgmt_cmd)
{
    notify_t *ins = scst_mgmt_cmd_get_tgt_priv(mgmt_cmd);
    isp_notify_t *np = &ins->notify;
    bus_t *bp = bus_from_notify(np);
    ins->tmf_resp =
	    isp_task_mgmt_fn_get_resp(scst_mgmt_cmd_get_status(mgmt_cmd));

    ini_put(&bp->bchan[np->nt_channel], np->nt_ini);
    BUS_DBG(bp, "NOTIFY_ACK[%llx]\n", np->nt_tagval);
    (*bp->h.r_action) (QIN_NOTIFY_ACK, ins);
}

int isp_get_initiator_port_transport_id(struct scst_tgt *tgt,
	struct scst_session *scst_sess, uint8_t **transport_id)
{
	ini_t *ini;
	int res = 0;
	int tr_id_size;
	uint8_t *tr_id;
	uint64_t iid;
	uint64_t *n_port_name;

	TRACE_ENTRY();

	if (scst_sess == NULL) {
		res = SCSI_TRANSPORTID_PROTOCOLID_FCP2;
		goto out;
	}

	TRACE_DBG("Called to get transport ID (iid = %llu)", ini->ini_iid);
	ini = (ini_t*)scst_sess_get_tgt_priv(scst_sess);

	iid = ini->ini_iid;

	tr_id_size = 24;
	tr_id = kzalloc(tr_id_size, GFP_KERNEL);
	if (tr_id == NULL) {
		PRINT_ERROR("Allocation of TransportID (size %d) failed",
			tr_id_size);
		res = -ENOMEM;
		goto out;
	}
	n_port_name = (uint64_t*)&tr_id[8];
	*n_port_name = __cpu_to_be64(iid);

	PRINT_BUFF_FLAG(TRACE_DEBUG, "PR transport ID: 0x%x", tr_id, tr_id_size);

	*transport_id = tr_id;

out:
	TRACE_EXIT_RES(res);
	return res;
}


static DEFINE_MUTEX(proc_mutex);

/*
 * Many procfs things is taken from scst/src/scst_proc.c
 */

#if !defined(CONFIG_PPC) && (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22))

int strncasecmp(const char *s1, const char *s2, size_t n)
{
	int c1, c2;
	do {
		c1 = tolower(*s1++);
		c2 = tolower(*s2++);
	} while ((--n > 0) && c1 == c2 && c1 != 0);
	return c1 - c2;
}

#endif

static int
isp_read_proc(struct seq_file *seq, void *v)
{
    bus_t *bp = seq->private;
    bus_chan_t *bc;
    int chan;

    if (bp == NULL || bp->bchan == NULL) {
        return (-ENODEV);
    }

    if (mutex_lock_interruptible(&proc_mutex)) {
        return (-ERESTARTSYS);
    }

    seq_printf(seq, "%s HBA %s%d DEVID %x\n", bp->h.r_type == R_FC ? "FC" : "SPI", bp->h.r_name, bp->h.r_inst, bp->h.r_locator);
    for (chan = 0; chan < bp->h.r_nchannels; chan++) {
        bc = &bp->bchan[chan];
        if (bp->h.r_type == R_FC) {
            seq_printf(seq, "%-2d: %d\n", chan, bc->enable ? 1 : 0);
        } else {
            seq_printf(seq, "%-2d: 0x%llx\n", chan, bc->enable);
        }
    }

    mutex_unlock(&proc_mutex);
    return (0);
}

static ssize_t
isp_write_proc(struct file *file, const char __user *buf, size_t len, loff_t *off)
{
    char *ptr, *p, *old;
    enum { DISABLE = 0, ENABLE = 1, TEST } action;
    int en = -1, res = -EINVAL;
    int all_channels = 0, all_luns = 0;
    int lun = 0, chan = 0;
    bus_t *bp = PDE(file->f_dentry->d_inode)->data;

    if (bp == NULL || bp->bchan == NULL) {
        return (-ENODEV);
    }
    if (!buf) {
        goto out;
    }
    ptr = (char *)__get_free_page(GFP_KERNEL);
    if (ptr == NULL) {
        res = -ENOMEM;
        goto out;
    }
    if (copy_from_user(ptr, buf, len)) {
        res = -EFAULT;
        goto out_free;
    }
    if (len < PAGE_SIZE) {
        ptr[len] = '\0';
    } else if (ptr[PAGE_SIZE-1]) {
        goto out_free;
    }

    /*
     * Usage: echo "enable|disable chan lun" > /proc/scsi_tgt/qla_isp/N
     *   or   echo "test" > /proc/scsi_tgt/qla_isp/N
     */
    p = ptr;
    if (p[strlen(p) - 1] == '\n') {
        p[strlen(p) - 1] = '\0';
    }
    if (!strncasecmp("enable", p, 6)) {
        p += 6;
        action = ENABLE;
    } else if (!strncasecmp("disable", p, 7)) {
        p += 7;
        action = DISABLE;
    } else if (!strncasecmp("test", p, 4)) {
        action = TEST;
    } else {
        PRINT_ERROR("unknown action \"%s\"", p);
        goto out_free;
    }

    switch (action) {
    case ENABLE:
    case DISABLE:
        if (!isspace(*p)) {
            PRINT_ERROR("cannot parse arguments for action \"%s\"", action == DISABLE ? "disable" : "enable");
            goto out_free;
        }

        /* get channel */
        while (isspace(*p) && *p != '\0') {
            p++;
        }
        old = p;
        chan = simple_strtoul(p, &p, 0);
        if (old == p) {
            if (!strncasecmp("all", p, 3)) {
                all_channels = 1;
            } else {
                PRINT_ERROR("cannot parse channel for action \"%s\"", action == DISABLE ? "disable" : "enable");
                goto out_free;
            }
        } else if (chan < 0 || chan >= bp->h.r_nchannels) {
            PRINT_ERROR("bad channel number %d", chan);
            goto out_free;
        }

        /* get lun */
        if (bp->h.r_type == R_SPI) {
            while (isspace(*p) && *p != '\0') {
                p++;
            }
            old = p;
            lun = simple_strtoul(p, &p, 0);
            if (old == p) {
                if (!strncasecmp("all", p, 3)) {
                    all_luns = 1;
                } else {
                    PRINT_ERROR("cannot parse lun for action \"%s\"", action == DISABLE ? "disable" : "enable");
                    goto out_free;
                }
            } else if (lun < 0 && lun >= MAX_LUN) {
                PRINT_ERROR("bad lun %d", lun);
                goto out_free;
            }
        } else {
            lun = LUN_ANY;
        }

        en = action;
        break;
    case TEST:
        printk("%s test\n", __FUNCTION__);
        res = len;
        break;
    }

    if (en == 0 || en == 1) {
        /*
         * channel 0 must be enabled first and disabled last, so when enabling all
         * channels do it in ascending order and when disabling all in descending order
         */
        int chan_srt, chan_end, chan_inc;
        int lun_srt, lun_end;

        if (all_channels) {
            if (en) {
                chan_srt = 0;
                chan_end = bp->h.r_nchannels;
                chan_inc = 1;
            } else {
                chan_srt = bp->h.r_nchannels - 1;
                chan_end = -1;
                chan_inc = -1;
            }
        } else {
            chan_srt = chan;
            chan_end = chan + 1;
            chan_inc = 1;
        }

        if (bp->h.r_type == R_FC) {
            lun_srt = LUN_ANY;
            lun_end = LUN_ANY + 1;
        } else {
            if (all_luns) {
                 lun_srt = 0;
                 lun_end = MAX_LUN;
            } else {
                lun_srt = lun;
                lun_end = lun + 1;
            }
        }

        if (mutex_lock_interruptible(&proc_mutex)) {
            res = -ERESTARTSYS;
            goto out_free;
        }
        for (chan = chan_srt; chan != chan_end; chan += chan_inc) {
            for (lun = lun_srt; lun != lun_end; lun++) {
               res = scsi_target_enadis(bp, en, chan, lun);
                if (res < 0) {
                    PRINT_ERROR("%s channel %d failed with error %d", en ? "enable" : "disable", chan, res);
                     /* processed anyway */
                }
            }
        }
        res = len;
        mutex_unlock(&proc_mutex);
    }

out_free:
    free_page((unsigned long)ptr);
out:
    return (res);
}

static uint16_t isp_get_scsi_transport_version(struct scst_tgt *scst_tgt)
{
	return 0x0900; /* FCP-2 */
}

static struct scst_tgt_template isp_tgt_template =
{
    .sg_tablesize = SG_ALL, /* we set this value lately based on hardware */
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
    .get_scsi_transport_version = isp_get_scsi_transport_version,

    //.report_aen = isp_report_aen,
    .get_initiator_port_transport_id = isp_get_initiator_port_transport_id,
};

#ifdef ISP_DAC_SUPPORTED
#define ISP_A64 1
#else
#define ISP_A64 0
#endif

static int
get_sg_tablesize(ispsoftc_t *isp)
{
    // FIXME: check if this is correct? What about multichannel ?
    // FIXME: move to the low level driver and export via tpublic API
    int rq_seglim, ct_seglim;
    int nctios = (isp->isp_maxcmds < 4) ? 0 : isp->isp_maxcmds - 4;

    if (IS_24XX(isp)) {
        rq_seglim = 1;
        ct_seglim = ISP_CDSEG64;
    } else if (IS_2322(isp) || ISP_A64) {
        rq_seglim = ISP_RQDSEG_T3;
        ct_seglim = ISP_CDSEG64;
    } else if (IS_FC(isp)) {
        rq_seglim = ISP_RQDSEG_T2;
        ct_seglim = ISP_CDSEG;
    } else { // SPI
        rq_seglim = ISP_RQDSEG;
        ct_seglim = ISP_RQDSEG;
    }

    return rq_seglim + nctios * ct_seglim;
}

static void
bus_set_proc_data(bus_t *bp)
{
    const struct scst_proc_data proc_data = {
        SCST_DEF_RW_SEQ_OP(isp_write_proc)
        .show = isp_read_proc,
    };
    memcpy(&bp->proc_data, &proc_data, sizeof(bp->proc_data));
    bp->proc_data.data = bp;
}

static void
register_hba(bus_t *bp)
{
    char name[32];
    info_t info;
    int chan;
    bus_chan_t *bchan, *bc;
    struct scst_tgt *scst_tgt;
    struct proc_dir_entry *pde;

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

        isp_tgt_template.sg_tablesize = get_sg_tablesize(bp->h.r_identity);
        scst_tgt = scst_register_target(&isp_tgt_template, name);
        if (scst_tgt == NULL) {
            Eprintk("cannot register scst device %s for %s%d\n", name, bp->h.r_name, bp->h.r_inst);
            goto err_free_chan;
        }

        bc = &bchan[chan];
        spin_lock_init(&bc->tmds_lock);
        tasklet_init(&bc->tasklet, tasklet_rx_cmds, (unsigned long) bc);
        init_waitqueue_head(&bc->wait_queue);
        atomic_set(&bc->sess_count, 0);
        bc->bus = bp;
        bc->scst_tgt = scst_tgt;
        scst_tgt->tgt_priv = bc;
    }

    snprintf(name, sizeof(name), "%d", ((ispsoftc_t *)bp->h.r_identity)->isp_osinfo.host->host_no);
    bus_set_proc_data(bp);
    pde = scst_create_proc_entry(scst_proc_get_tgt_root(&isp_tgt_template), name, &bp->proc_data);
    if (pde == NULL) {
        Eprintk("cannot create entry %s in /proc\n", name);
        goto err_free_chan;
    }

    spin_lock_irq(&scsi_target_lock);
    bp->bchan = bchan;
    spin_unlock_irq(&scsi_target_lock);

    Iprintk("registering %s%d\n", bp->h.r_name, bp->h.r_inst);
    (bp->h.r_action)(QIN_HBA_REG, &bp->h);
    return;

err_free_chan:
    for (chan = bp->h.r_nchannels -1; chan >= 0; chan--) {
        if (bchan[chan].scst_tgt) {
            scst_unregister_target(bchan[chan].scst_tgt);
        }
    }
    kfree(bchan);

err_free_bus:
    spin_lock_irq(&scsi_target_lock);
    memset(&bp->h, 0, sizeof (hba_register_t));
    spin_unlock_irq(&scsi_target_lock);
}

static void
bus_chan_unregister_sessions(bus_chan_t *bc, int wait)
{
    int i;
    ini_t *ini_next, *ptr;

    for (i = 0; i < HASH_WIDTH; i++) {
        spin_lock_irq(&bc->tmds_lock);
        ptr = bc->list[i];
        bc->list[i] = NULL;
        spin_unlock_irq(&bc->tmds_lock);

        if (ptr) {
            do {
                ini_next = ptr->ini_next;
                if (wait) {
                    free_ini(bc, ptr, 1);
                } else {
                    ini_put(bc, ptr);
                }
            } while ((ptr = ini_next) != NULL);
        }
    }
}

static void
unregister_hba(bus_t *bp, hba_register_t *unreg_hp)
{
    int chan;
    char name[32];
    bus_chan_t *bc;

    snprintf(name, sizeof(name), "%d", ((ispsoftc_t *)bp->h.r_identity)->isp_osinfo.host->host_no);
    remove_proc_entry(name, scst_proc_get_tgt_root(&isp_tgt_template));

    /* it's safe now to unregister and reinit bp */
    for (chan = 0; chan < bp->h.r_nchannels; chan++) {
        bc = &bp->bchan[chan];
        bus_chan_unregister_sessions(bc, 1);
        if (bc->scst_tgt) {
            BUS_DBG(bp, "Chan %d waiting for finishing %d sessions\n", chan, atomic_read(&bc->sess_count));
            wait_event(bc->wait_queue, atomic_read(&bc->sess_count) == 0);
            BUS_DBG(bp, "Chan %d all sessions finished\n", chan);
            scst_unregister_target(bc->scst_tgt);
        }
    }
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

#ifdef    MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif

int init_module(void)
{
    int ret;

    qlaispd_task = kthread_run(qlaispd_function, NULL, "qlaispd");
    if (IS_ERR(qlaispd_task)) {
        Eprintk("running qlaispd failed\n");
        return PTR_ERR(qlaispd_task);
    }

    ret = scst_register_target_template(&isp_tgt_template);
    if (ret < 0) {
        Eprintk("cannot register scst target template\n");
        kthread_stop(qlaispd_task);
    }
    return (ret);
}

/*
 * We can't get here until all hbas have deregistered
 */
void cleanup_module(void)
{
    kthread_stop(qlaispd_task);
    scst_unregister_target_template(&isp_tgt_template);
}
/*
 * vim:ts=4:sw=4:expandtab
 */
