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
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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
 * Copyright 2007 by Stanislaw Gruszka <stanislawg1@open-e.com> 
 */

#ifndef  MODULE
#error  "this can only be built as a module"
#endif

#include <linux/version.h>
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(v,p,s)   (((v)<<16)+(p<<8)+s)
#endif
#include <linux/autoconf.h>
#ifdef  CONFIG_SMP
#define __SMP__ 1
#endif

#include <linux/module.h>
#include <linux/autoconf.h>
#include <linux/init.h>
#include <linux/types.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
#include <linux/blk.h>
#endif
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
#include <scsi_tgt.h>
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
typedef struct initiator ini_t;

/* this is very experimental, need review and tests */
//#define NO_AUTOSENSE 1

struct initiator {
    ini_t *                 ini_next;
    bus_t *                 ini_bus;        /* backpointer to containing bus */
    uint64_t                ini_iid;        /* initiator identifier */
    struct scst_session *   ini_scst_sess;  /* sesson established by this remote initiator */ 
#ifdef NO_AUTOSENSE
    /*
     * There are cases when Autosense not work for some reason, at least for 24xx chipsets.
     * This is workaround. Here we do not try to send sense in autosense mode. Insted if 
     * command terminate with "check status" (FIXME: some other should be attended too?) 
     * we turn on CA (Contingent allegiance) condition and save sense. In SCSI standarts v2 
     * (v3 tell autosense must work) CA condition finish when any new command arrive to target, 
     * but we do differently, we reject  any new command except REQUEST_SENSE with "busy" status. 
     * All commands returned from upper SCST layer are queued and wait for CA finish. If we get 
     * REQUEST_SENSE we send saved sense data and finish CA condition. Task management functions
     * finish CA too. We assume initiator will send REQUEST SENSE command or task management 
     * functions. Other solution will be limit command queue to 1 and finish CA when any new 
     * command arrive, but this may degrade performance.
     */
    int                     ini_ca_cond;    /* is contingent allegiance condition on */
    spinlock_t              ini_ca_lock;    
    tmd_cmd_t *             ini_ca_front;   /* list of finished command by SCST under Contingent Allegiance condition */ 
    tmd_cmd_t *             ini_ca_tail;    
    uint8_t                 ini_sense[TMD_SENSELEN]; /* saved sense */
    struct scatterlist      ini_sense_sg;   /* saved sense passed to low level driver */
#endif
};

#define    HASH_WIDTH    16
#define    INI_HASH_LISTP(busp, ini_id)    busp->list[ini_id & (HASH_WIDTH - 1)]

struct bus {
    hba_register_t      h;                  /* must be first */
    ini_t *             list[HASH_WIDTH];   /* hash list of known initiators */
    struct scst_tgt *   scst_tgt;
    hba_register_t *    unreg_hp;           /* help to synchronize low level and SCST unregistration */
    int                 enable;             /* is target mode enabled in low level driver */
    int                 need_reg;           /* before SCST registration */
#ifdef NO_AUTOSENSE
    int                 no_autosense;       /* autosense not work for this hba */
#endif
};

#define    SDprintk     if (scsi_tdebug) printk
#define    SDprintk2    if (scsi_tdebug > 1) printk
#define    SDprintk3    if (scsi_tdebug > 2) printk

static int scsi_tdebug = 0;

#define    Eprintk(fmt, args...) printk(KERN_ERR "isp_scst(%s): " fmt, __FUNCTION__, ##args)
#define    Iprintk(fmt, args...) printk(KERN_INFO "isp_scst(%s): " fmt, __FUNCTION__, ##args)

static void scsi_target_handler(qact_e, void *);

static __inline bus_t *bus_from_tmd(tmd_cmd_t *);
static __inline bus_t *bus_from_name(const char *);
static __inline ini_t *ini_from_tmd(bus_t *, tmd_cmd_t *);
static __inline ini_t *ini_from_notify(bus_t *, tmd_notify_t *);

static void scsi_target_start_cmd(tmd_cmd_t *, int);
static void scsi_target_done_cmd(tmd_cmd_t *, int);
static int scsi_target_thread(void *);
static int scsi_target_enadis(bus_t *, int);

static bus_t busses[MAX_BUS];

DECLARE_MUTEX_LOCKED(scsi_thread_sleep_semaphore);
DECLARE_MUTEX_LOCKED(scsi_thread_entry_exit_semaphore);
static tmd_cmd_t *p_front = NULL, *p_last = NULL;

static spinlock_t scsi_target_lock = SPIN_LOCK_UNLOCKED;
static int scsi_target_thread_exit = 0;
static int register_scst_flg = 0;
static int unregister_scst_flg = 0; 

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

static __inline ini_t *
ini_from_notify(bus_t *bp, tmd_notify_t *np)
{
   ini_t *ptr = INI_HASH_LISTP(bp, np->nt_iid);
   if (ptr) {
        do {
            if (ptr->ini_iid == np->nt_iid) {
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

static ini_t *
alloc_ini(bus_t *bp, uint64_t iid)
{
    ini_t *nptr;
    char ini_name[24];

    if (!bp->scst_tgt) {
        Eprintk("cannot find SCST target for incoming command\n");
        return (NULL);
    }

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
    
    nptr->ini_scst_sess = scst_register_session(bp->scst_tgt, 0, ini_name, NULL, NULL);    
    if (!nptr->ini_scst_sess) {
        Eprintk("cannot register SCST session\n");
        kfree(nptr); 
        return (NULL);
    } 

    return (nptr);
}

static void
add_ini(bus_t *bp, uint64_t iid, ini_t *nptr)
{
    ini_t **ptrlptr = &INI_HASH_LISTP(bp, iid);

    nptr->ini_iid = iid;
    nptr->ini_bus = (struct bus *) bp;
    nptr->ini_next = *ptrlptr;

#ifdef NO_AUTOSENSE
    nptr->ini_ca_cond = 0;
    spin_lock_init(&nptr->ini_ca_lock);
    nptr->ini_sense_sg.page = virt_to_page(nptr->ini_sense);
    nptr->ini_sense_sg.offset = offset_in_page(nptr->ini_sense);
    nptr->ini_sense_sg.length = TMD_SENSELEN;
#endif

    *ptrlptr = nptr;
}

static void
free_ini(ini_t *ini)
{
    scst_unregister_session(ini->ini_scst_sess, 0, NULL);
    kfree(ini);
}

static __inline void
scsi_cmd_sched_restart_locked(tmd_cmd_t *tmd, int donotify, const char *msg)
{
    SDprintk("scsi_cmd_sched_restart[%llx]: %s\n", tmd->cd_tagval, msg);
    tmd->cd_private = NULL;
    if (p_front) {
        p_last->cd_private = tmd;
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

static __inline void
schedule_register_scst(void)
{
    register_scst_flg = 1;
    up(&scsi_thread_sleep_semaphore);
}

static __inline void
schedule_unregister_scst(void)
{
    unregister_scst_flg = 1;
    up(&scsi_thread_sleep_semaphore);
}

#ifdef NO_AUTOSENSE 

static int
ca_xmit_response(bus_t *bp, tmd_cmd_t *tmd)
{
    if (bp->no_autosense) {
        ini_t *ini;
        unsigned long flags;

        ini = ini_from_tmd(bp, tmd);
        if (!ini) {
            Eprintk("cannot find initiator for tmd\n");
            WARN_ON(1);
            return (-ENODEV);
        }
        
        spin_lock_irqsave(&ini->ini_ca_lock, flags);
        if (ini->ini_ca_cond) {
            /* we are under Contingent Allegiance condition, save finished command 
             * with all state: status, data, sense. As long we not call scst_tgt_cmd_done()
             * scst will keep all data and scst task mgmt functions will work
             */
            tmd->cd_private = NULL;
            if (!ini->ini_ca_front) {
                ini->ini_ca_front = tmd;
            } else {
                ini->ini_ca_tail->cd_private = tmd;
            }
            ini->ini_ca_tail = tmd;
        
            spin_unlock_irqrestore(&ini->ini_ca_lock, flags);
            return (0);
        } else {
            if ((tmd->cd_hflags & CDFH_STSVALID) && (tmd->cd_scsi_status == SCSI_CHECK)) {
                ini->ini_ca_cond = 1; 
                /* save sense and send only status (check condition) for this command */
                memcpy(ini->ini_sense, tmd->cd_sense, TMD_SENSELEN);
                tmd->cd_xfrlen = 0;
                tmd->cd_hflags &= ~CDFH_DATA_MASK;
            }
        }
        spin_unlock_irqrestore(&ini->ini_ca_lock, flags);
    
    } else {
        if ((tmd->cd_hflags & CDFH_STSVALID) && (tmd->cd_scsi_status == SCSI_CHECK)) {
            tmd->cd_xfrlen = 0;
            tmd->cd_hflags &= ~CDFH_DATA_MASK;
            tmd->cd_hflags |= CDFH_SNSVALID;
        }
    }
    
    (*bp->h.r_action)(QIN_TMD_CONT, tmd);
    return (0);
}

static void
ca_finish(bus_t *bp, ini_t *ini)
{
    tmd_cmd_t *tmd;
    unsigned long flags;

    if (!bp->no_autosense) {
        return;
    }

    spin_lock_irqsave(&ini->ini_ca_lock, flags);
    while (ini->ini_ca_front && !ini->ini_ca_cond) {
        tmd = ini->ini_ca_front;
        ini->ini_ca_front = tmd->cd_private;
        spin_unlock_irqrestore(&ini->ini_ca_lock, flags);
        
        ca_xmit_response(bp, tmd);  
        
        spin_lock_irqsave(&ini->ini_ca_lock, flags);
    }   

    if (ini->ini_ca_front == NULL) {
        ini->ini_ca_tail = NULL;
    }
    spin_unlock_irqrestore(&ini->ini_ca_lock, flags);
}

static void 
ca_abort_task(bus_t *bp, ini_t *ini, uint64_t tagval)
{    
    tmd_cmd_t *tmd, *prev_tmd;
    unsigned long flags;
    
    if (!bp->no_autosense) {
        return;
    }

    spin_lock_irqsave(&ini->ini_ca_lock, flags);
    tmd = ini->ini_ca_front;
    if (!tmd) {
        goto out;
    }
    
    if (tmd->cd_tagval == tagval) {
        ini->ini_ca_front = tmd->cd_private;
        goto out;
    }
   
    while (1) {
        prev_tmd = tmd;
        tmd = tmd->cd_private;
        if (!tmd)
            goto out;

        if (tmd->cd_tagval == tagval) {
            prev_tmd->cd_private = tmd->cd_private;
            goto out;
        }   
    } 

out:
    if (ini->ini_ca_front == NULL) {
        ini->ini_ca_tail = NULL;
    }
    spin_unlock_irqrestore(&ini->ini_ca_lock, flags);
}

static void
ca_abort_all_tasks(bus_t *bp, ini_t *ini, uint16_t lun)
{
    tmd_cmd_t *tmd, *next_tmd;
    unsigned long flags;

    if (!bp->no_autosense) {
        return;
    }
   
    spin_lock_irqsave(&ini->ini_ca_lock, flags);
    tmd = ini->ini_ca_front;
    while (tmd && L0LUN_TO_FLATLUN(tmd->cd_lun) == lun) {
        ini->ini_ca_front = tmd->cd_private;
        tmd->cd_private = NULL;
        tmd = ini->ini_ca_front;
    }

    if (!tmd) {
        goto out;
    }

    next_tmd = tmd->cd_private;
    while (next_tmd) {
        if (L0LUN_TO_FLATLUN(next_tmd->cd_lun) == lun) {
            tmd->cd_private = next_tmd->cd_private;
            next_tmd->cd_private = NULL;
        } else {
            tmd = next_tmd;
            next_tmd = tmd->cd_private;
        }
    } 

out:
    if (ini->ini_ca_front == NULL) { 
        ini->ini_ca_tail = NULL;
    }
    spin_unlock_irqrestore(&ini->ini_ca_lock, flags);
}

#else // NO_AUTOSENSE

static int
ca_xmit_response(bus_t *bp, tmd_cmd_t *tmd)
{
    if ((tmd->cd_hflags & CDFH_STSVALID) && (tmd->cd_scsi_status == SCSI_CHECK)) {
        tmd->cd_xfrlen = 0;
        tmd->cd_hflags &= ~CDFH_DATA_MASK;
        tmd->cd_hflags |= CDFH_SNSVALID;
    }
    
    (*bp->h.r_action)(QIN_TMD_CONT, tmd);
    return (0);
}

#define ca_finish(bp, ini)                  do { } while (0)
#define ca_abort_task(bp, ini, tagval)      do { } while (0)
#define ca_abort_all_tasks(bp, ini, lun)    do { } while (0)

#endif // NO_AUTOSENSE 

static int    
scsi_target_rx_cmd(ini_t *ini, tmd_cmd_t *tmd, int from_intr)
{
    struct scst_cmd *scst_cmd;
    scst_data_direction dir;

    scst_cmd = scst_rx_cmd(ini->ini_scst_sess, tmd->cd_lun, sizeof(tmd->cd_lun), tmd->cd_cdb, sizeof(tmd->cd_cdb), from_intr);
    if (!scst_cmd)
        return (-ENOMEM);
 
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
    
    dir = SCST_DATA_UNKNOWN; // bidirectional or no transfer
    if ((tmd->cd_lflags & CDFL_DATA_OUT) && !(tmd->cd_lflags & CDFL_DATA_IN)) {
        dir = SCST_DATA_WRITE;
    } else if (tmd->cd_lflags & CDFL_DATA_IN) {
        dir = SCST_DATA_READ;
    }
    scst_cmd_set_expected(scst_cmd, dir, tmd->cd_totlen);
    
    scst_cmd_init_done(scst_cmd, SCST_CONTEXT_TASKLET); 
    return (0);
}

static void
scsi_target_start_cmd(tmd_cmd_t *tmd, int from_intr)
{
    unsigned long flags;
    bus_t *bp;
    ini_t *ini;
    int ret;

    tmd->cd_hflags = 0;
    tmd->cd_scsi_status = SCSI_GOOD;
    tmd->cd_data = NULL;
    tmd->cd_xfrlen = 0;
    tmd->cd_resid = tmd->cd_totlen;
    tmd->cd_private = NULL;

    /*
     * First, find the bus.
     */
    spin_lock_irqsave(&scsi_target_lock, flags);
    bp = bus_from_tmd(tmd);
    if (bp == NULL || bp->scst_tgt == NULL) {
        spin_unlock_irqrestore(&scsi_target_lock, flags);
        Eprintk("cannot find %s for incoming command\n", (bp == NULL) ? "bus" : "SCST target");
        return;
    } 
    tmd->cd_bus = bp;

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
        nptr = alloc_ini(bp, tmd->cd_iid);
        spin_lock_irqsave(&scsi_target_lock, flags);

        /*
         * Check again to see if it showed while we were allocating...
         */
        ini = ini_from_tmd(bp, tmd);
        if (ini) {
            spin_unlock_irqrestore(&scsi_target_lock, flags);
            if (nptr) {
                free_ini(nptr);
            }
        } else {
            if (nptr == NULL) {
                spin_unlock_irqrestore(&scsi_target_lock, flags);
                goto err;
            }
            add_ini(bp, tmd->cd_iid, nptr);
            spin_unlock_irqrestore(&scsi_target_lock, flags);
            ini = nptr;
        }
    } else {
        spin_unlock_irqrestore(&scsi_target_lock, flags);
    }

#ifdef NO_AUTOSENSE 
    if (bp->no_autosense) {
        spin_lock_irqsave(&ini->ini_ca_lock, flags);    
        if (ini->ini_ca_cond) {
            spin_unlock_irqrestore(&ini->ini_ca_lock, flags);
            // FIXME: other commands which finish contingent allegiance
            if (tmd->cd_cdb[0] == REQUEST_SENSE) {
                tmd->cd_data = &ini->ini_sense_sg; 
                tmd->cd_xfrlen = TMD_SENSELEN; 
                tmd->cd_hflags |= CDFH_STSVALID | CDFH_DATA_IN;
                tmd->cd_scsi_status = SCSI_GOOD;

                (*bp->h.r_action)(QIN_TMD_CONT, tmd);
                return;
            } else {
                /* we send bussy in CA, this not conform any version of scsi standard */
                goto err; 
            }
        } else {
            spin_unlock_irqrestore(&ini->ini_ca_lock, flags);
        }
    }
#else
    if (tmd->cd_cdb[0] == REQUEST_SENSE) { 
        Eprintk("REQUEST SENSE in auto sense mode !?! Maybe compile with NO_AUTOSENSE flag.\n");
    }
#endif

    ret = scsi_target_rx_cmd(ini, tmd, from_intr);
    if (ret < 0) 
        goto err;
    
    return;

err:
    tmd->cd_scsi_status = SCSI_BUSY;
    tmd->cd_hflags |= CDFH_STSVALID;
    tmd->cd_hflags &= ~CDFH_DATA_MASK;
    tmd->cd_xfrlen = 0;
    (*bp->h.r_action)(QIN_TMD_CONT, tmd);
    return;
}

static void 
scsi_target_done_cmd(tmd_cmd_t *tmd, int from_intr)
{
    bus_t *bp;
    struct scst_cmd *scst_cmd;

    SDprintk2("scsi_target: TMD_DONE[%llx] %p hf %x lf %x xfrlen %d resid %d\n",
              tmd->cd_tagval, tmd, tmd->cd_hflags, tmd->cd_lflags, tmd->cd_xfrlen, tmd->cd_resid);
   
    bp = bus_from_tmd(tmd);
    EXTRACHECKS_BUG_ON(!bp);

#ifdef NO_AUTOSENSE
    if (bp->no_autosense && tmd->cd_cdb[0] == REQUEST_SENSE) {
        unsigned long flags;
        ini_t *ini;
        
        if (tmd->cd_lflags & CDFL_ERROR) {
            Eprintk("Transport error when reponse REQUEST_SENSE command");
            SDprintk("%s: TMD_FIN[%llx]\n", __FUNCTION__, tmd->cd_tagval);
            (*bp->h.r_action)(QIN_TMD_FIN, tmd);
            return;
        }
            
        /* sense was transfered, we may exit now from CA */
        ini = ini_from_tmd(bp, tmd);
        EXTRACHECKS_BUG_ON(!ini);
        EXTRACHECKS_BUG_ON(tmd->cd_data != &ini->ini_sense_sg);
        SDprintk("%s: TMD_FIN[%llx]\n", __FUNCTION__, tmd->cd_tagval);
        (*bp->h.r_action)(QIN_TMD_FIN, tmd);
                
        spin_lock_irqsave(&ini->ini_ca_lock, flags);
        ini->ini_ca_cond = 0;
        spin_unlock_irqrestore(&ini->ini_ca_lock, flags);
        ca_finish(bp, ini);
        return;
    }
#endif 
    
    scst_cmd = tmd->cd_scst_cmd; 
    if (!scst_cmd) {
        /* command returned by us with status BUSY */
        SDprintk("%s: TMD_FIN[%llx]\n", __FUNCTION__, tmd->cd_tagval);
        (*bp->h.r_action)(QIN_TMD_FIN, tmd);
        return;
    }
 
    if (tmd->cd_hflags & CDFH_STSVALID) {
        if (tmd->cd_hflags & CDFH_DATA_IN) {
            tmd->cd_hflags &= ~CDFH_DATA_MASK;
            tmd->cd_xfrlen = 0;
        }
        scst_tgt_cmd_done(scst_cmd);
        return;
    }
    
    if (tmd->cd_hflags & CDFH_DATA_OUT) {
        if (tmd->cd_resid == 0) {
            if (tmd->cd_xfrlen) {
                int rx_status = SCST_RX_STATUS_SUCCESS;

                if (tmd->cd_lflags & CDFL_ERROR) {
                    rx_status = SCST_RX_STATUS_ERROR;
                }
                scst_rx_data(scst_cmd, SCST_RX_STATUS_SUCCESS, SCST_CONTEXT_TASKLET);
            } else {
                scst_tgt_cmd_done(scst_cmd);
            }
        } else {
            ; /* we don't have all data, do nothing */
        }
    } else if (tmd->cd_hflags & CDFH_DATA_IN) {
        tmd->cd_hflags &= ~CDFH_DATA_MASK;
        tmd->cd_xfrlen = 0;
        scst_tgt_cmd_done(scst_cmd);
    }
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
#ifdef NO_AUTOSENSE
        // FIXME: on some 24xx cards autosense may work so this should be user selectable  
        if (IS_24XX((ispsoftc_t *)hp->r_identity)) {
            bp->no_autosense = 1;
        }
#endif
        bp->need_reg = 1;
        spin_unlock_irqrestore(&scsi_target_lock, flags);
        schedule_register_scst();
        Iprintk("registering %s%d\n", hp->r_name, hp->r_inst);
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
        scsi_target_start_cmd(arg, 1);
        break;
    }
    case QOUT_TMD_DONE:
    {
        tmd_cmd_t *tmd = arg;
        SDprintk2("scsi_target: TMD_DONE[%llx] %p cdb0=%x\n", tmd->cd_tagval, tmd, tmd->cd_cdb[0] & 0xff);
        scsi_target_done_cmd(arg, 1);
        break;
    }
    case QOUT_NOTIFY:
    {
        ini_t *ini;
        tmd_notify_t *np = arg;
        spin_lock_irqsave(&scsi_target_lock, flags);
        
        // FIXME: good handle for all notifies and TGT_ALL, INI_ALL, ...
        
        bp = bus_from_notify(arg);
        if (bp == NULL) {
            spin_unlock_irqrestore(&scsi_target_lock, flags);
            Eprintk("TMD_NOTIFY cannot find bus\n");
            break;
        }
        
        ini = ini_from_notify(bp, np);
        if (ini == NULL) {
            spin_unlock_irqrestore(&scsi_target_lock, flags);
            Eprintk("TMD_NOTIFY cannot find initiator\n");
            (*bp->h.r_action) (QIN_NOTIFY_ACK, arg);
            break;
        }
       
        // FIXME: if scst mgmt fail we can't give info to isp driver via tpublic
        // FIXME: interface, but seems low level stuff is capable to handle error case 
        // FIXME: now smile and assume mgmt_fn not fail 
        if (np->nt_ncode == NT_ABORT_TASK) {
            uint64_t tagval;
            spin_unlock_irqrestore(&scsi_target_lock, flags);
             
            tagval = np->nt_tagval; /* after scst return "np" may not be valid */
            scst_rx_mgmt_fn_tag(ini->ini_scst_sess, SCST_ABORT_TASK, np->nt_tagval, 1, np); 
            ca_abort_task(bp, ini, tagval);
            ca_finish(bp, ini);
        } else {
            uint16_t lun;
            uint8_t lunbuf[8];
            spin_unlock_irqrestore(&scsi_target_lock, flags);
            
            SDprintk("scsi_target: MGT code %x from %s%d\n", np->nt_ncode, bp->h.r_name, bp->h.r_inst);
            FLATLUN_TO_L0LUN(lunbuf, np->nt_lun);
            
            lun = np->nt_lun; /* after scst return "np" may not be valid */
            scst_rx_mgmt_fn_lun(ini->ini_scst_sess, np->nt_ncode, lunbuf, sizeof(lunbuf), 1, np);
            ca_abort_all_tasks(bp, ini, lun);
            ca_finish(bp, ini);
        }
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
        memset(&bp->h, 0, sizeof (hba_register_t));
        bp->unreg_hp = hp;
        spin_unlock_irqrestore(&scsi_target_lock, flags);
        schedule_unregister_scst();
        break;
    }
    default:
        Eprintk("action code %d (0x%x)?\n", action, action);
        break;
    }
}

static int register_scst(void);
static void unregister_scst(void);

static int
scsi_target_thread(void *arg)
{
    unsigned long flags;

    siginitsetinv(&current->blocked, 0);
    lock_kernel();
#if    LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
    daemonize();
    snprintf(current->comm, sizeof (current->comm), "scsi_target_thread");
#else
    daemonize("scsi_target_thread");
#endif
    unlock_kernel();
    up(&scsi_thread_entry_exit_semaphore);
    SDprintk("scsi_target_thread starting\n");

    while (scsi_target_thread_exit == 0) {
        tmd_cmd_t *tp;

        SDprintk3("scsi_task_thread sleeping\n");
        down(&scsi_thread_sleep_semaphore);
        SDprintk3("scsi_task_thread running\n");

        spin_lock_irqsave(&scsi_target_lock, flags);
        if ((tp = p_front) != NULL) {
            p_last = p_front = NULL;
        }
        spin_unlock_irqrestore(&scsi_target_lock, flags);
        while (tp) {
            tmd_cmd_t *nxt = tp->cd_private;
            tp->cd_private = NULL;
            scsi_target_start_cmd(tp, 0);
            tp = nxt;
        }
        
        if (register_scst_flg) {
            register_scst_flg = 0;
            register_scst();
        }
        
        if (unregister_scst_flg) {
            unregister_scst_flg = 0;
            unregister_scst();  
        }
    }
    SDprintk("scsi_target_thread exiting\n");
    up(&scsi_thread_entry_exit_semaphore);
    return (0);
}

static int
scsi_target_enadis(bus_t *bp, int en)
{
    DECLARE_MUTEX_LOCKED(rsem);
    enadis_t ec;

    /*
     * XXX: yes, there is a race condition here where the bus can
     * XXX: go away. But in order to solve it, we have to make the
     * XXX: bus structure stay around while we call into the HBA
     * XXX: anyway, so fooey,.
     */
    if (bp == NULL) {
        SDprintk("%s: cannot find bus\n", __FUNCTION__);
        return (-ENXIO);
    }
    
    if (bp->enable == en)
        return (0);
 
    memset(&ec, 0, sizeof (ec));
    ec.en_hba = bp->h.r_identity;
    ec.en_tgt = TGT_ANY;
    if (bp->h.r_type == R_FC) {
        SDprintk("%s: ANY LUN acceptable\n", __FUNCTION__);
        ec.en_lun = LUN_ANY;
    } else {
        ec.en_lun = 0;
    }
    ec.en_private = &rsem;

    (*bp->h.r_action)(en ? QIN_ENABLE : QIN_DISABLE, &ec);
    down(&rsem);

    if (ec.en_error) {
        SDprintk("%s: HBA returned %d for %s action\n", __FUNCTION__, ec.en_error, en? "enable" : "disable");
        return (ec.en_error);
    }

    bp->enable = en; 
    return (0);
}

static int
isp_detect(struct scst_tgt_template *tgt_template)
{
    schedule_register_scst();
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
    tmd_cmd_t *tmd;
    bus_t *bp;
    
    tmd = (tmd_cmd_t *) scst_cmd_get_tgt_priv(scst_cmd);
    
    if (scst_cmd_get_data_direction(scst_cmd) == SCST_DATA_WRITE) {
        tmd->cd_hflags |= CDFH_DATA_OUT; 
        tmd->cd_data = scst_cmd_get_sg(scst_cmd);
        tmd->cd_xfrlen = scst_cmd_get_bufflen(scst_cmd);
        SDprintk("%s: write nbytes %u\n", __FUNCTION__, scst_cmd_get_bufflen(scst_cmd));

        bp = bus_from_tmd(tmd);
        (*bp->h.r_action)(QIN_TMD_CONT, tmd);
    }

    return (0);
}

static void 
SDprint_sense(const uint8_t *sbuf, uint8_t slen)
{
    if (scsi_tdebug) {
        uint8_t key, asc, ascq;
        key = (slen >= 2) ? sbuf[2] : 0;
        asc = (slen >= 12) ? sbuf[12] : 0;
        ascq = (slen >= 13) ? sbuf[13] : 0;
        SDprintk("%s: key 0x%02x asc 0x%02x ascq 0x%02x\n", __FUNCTION__, key, asc, ascq);
    }
}

static int
isp_xmit_response(struct scst_cmd *scst_cmd)
{   
    tmd_cmd_t *tmd;
    bus_t *bp;

    tmd = (tmd_cmd_t *) scst_cmd_get_tgt_priv(scst_cmd);
    bp = bus_from_tmd(tmd);

    if (scst_cmd_get_data_direction(scst_cmd) == SCST_DATA_READ) {
        unsigned int len = scst_cmd_get_resp_data_len(scst_cmd);
        if (len > tmd->cd_totlen) { 
            /* this shouldn't happen */
            const uint8_t ifailure[TMD_SENSELEN] = { 0xf0, 0, 0x4, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0x44 };
            
            Eprintk("data size too big (totlen %u len %u)\n", tmd->cd_totlen, len);
            WARN_ON(1);
            
            memcpy(tmd->cd_sense, ifailure, TMD_SENSELEN);
            tmd->cd_hflags |= CDFH_STSVALID;
            tmd->cd_scsi_status = SCSI_CHECK; 
            goto out;
        } else {
            tmd->cd_hflags |= CDFH_DATA_IN;
            tmd->cd_xfrlen = len;
            tmd->cd_data = scst_cmd_get_sg(scst_cmd);
        }
    } else { 
        /* finished write to target or command with no data */
        tmd->cd_xfrlen = 0;
        tmd->cd_hflags &= ~CDFH_DATA_MASK;
    }
            
    if (scst_cmd_get_tgt_resp_flags(scst_cmd) & SCST_TSC_FLAG_STATUS) {
        tmd->cd_hflags |= CDFH_STSVALID;
        tmd->cd_scsi_status = scst_cmd_get_status(scst_cmd);
        
        if (tmd->cd_scsi_status == SCSI_CHECK) {
            uint8_t *sbuf = scst_cmd_get_sense_buffer(scst_cmd);
            unsigned int slen = scst_cmd_get_sense_buffer_len(scst_cmd);
            if (slen > TMD_SENSELEN) {
                // FIXME: maybe increase TMD_SENSELEN ?
                // Eprintk("sense data too big (totlen %u len %u)\n", TMD_SENSELEN, slen);
                slen = TMD_SENSELEN;
            }
            memcpy(tmd->cd_sense, sbuf, slen);
            SDprint_sense(sbuf, slen);
        }
        SDprintk2("%s: status %d\n", __FUNCTION__, scst_cmd_get_status(scst_cmd));
    }

out:
    return ca_xmit_response(bp, tmd);
}

static void
isp_on_free_cmd(struct scst_cmd *scst_cmd)
{
    tmd_cmd_t *tmd;
    bus_t *bp; 

    tmd = (tmd_cmd_t *) scst_cmd_get_tgt_priv(scst_cmd);
    tmd->cd_data = NULL;
    
    SDprintk("%s: TMD_FIN[%llx]\n", __FUNCTION__, tmd->cd_tagval);
    bp = bus_from_tmd(tmd);
    (*bp->h.r_action)(QIN_TMD_FIN, tmd);
}

static void 
isp_task_mgmt_fn_done(struct scst_mgmt_cmd *mgmt_cmd)
{
    tmd_notify_t *np = mgmt_cmd->tgt_priv;
    bus_t *bp;

    // FIXME bus can not dissapear
    bp = bus_from_notify(np);
    SDprintk("%s: NOTIFY_ACK[%llx]\n", __FUNCTION__, np->nt_tagval);
    (*bp->h.r_action) (QIN_NOTIFY_ACK, np);
}

static int
isp_read_proc(struct seq_file *seq, struct scst_tgt *tgt)
{
    bus_t *bp;
   
    SDprintk("%s\n", __FUNCTION__);
    
    bp = tgt->tgt_priv;
    if (!bp)
        return -ENODEV;
    
    seq_printf(seq, "%d\n", bp->enable);
    return 0;
}

static int
isp_write_proc(char *buf, char **start, off_t offset, int len, int *eof, struct scst_tgt *tgt)
{
    bus_t *bp;
    int ret, en;

    SDprintk("%s\n", __FUNCTION__);
    
    bp = tgt->tgt_priv;
    if (!bp)
        return (-ENODEV);

    if (len != 2 && len != 3)    
        return (-EINVAL);
    
    en = buf[0] - '0';
    if (en < 0 || en > 1)
        return (-EINVAL);

    ret = scsi_target_enadis(bp, en);
    if (ret < 0)
        return (ret);

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

static int 
register_scst(void)
{
    bus_t *bp;
    int ntgts = 0;
    
    for (bp = busses; bp < &busses[MAX_BUS]; bp++) {
        char name[32];
         
        spin_lock_irq(&scsi_target_lock);
        if (bp->h.r_action == NULL || !bp->need_reg) {
            spin_unlock_irq(&scsi_target_lock);
            continue;
        }
        bp->need_reg = 0;
        spin_unlock_irq(&scsi_target_lock);
        
        // FIXME: give scst WWN or something like that  
        snprintf(name, sizeof(name), "%s%d", bp->h.r_name, bp->h.r_inst);
        
        // FIXME: we curently can not pass error to low level driver by tpublic interface 
        // FIXME: we reject tmd's when scst_tgt is NULL
        bp->scst_tgt = scst_register(&isp_tgt_template, name);
        if (bp->scst_tgt) {
            SDprintk("%s: device %s\n", __FUNCTION__ ,name);
            bp->scst_tgt->tgt_priv = bp;
            ntgts++;
        } else {
            Eprintk("cannot register scst device %s\n", name); 
        }
    }

    return (ntgts);
}

static void
unregister_scst(void)
{
    bus_t *bp;

    for (bp = busses; bp < &busses[MAX_BUS]; bp++) {
        int i;
        struct scst_tgt *scst_tgt;
        ini_t *list[HASH_WIDTH];
        hba_register_t *unreg_hp;

        spin_lock_irq(&scsi_target_lock);
        if (bp->h.r_action != NULL || bp->unreg_hp == NULL) {
            spin_unlock_irq(&scsi_target_lock);
            continue;
            
        }
        /* make bp ready for next registration */
        scst_tgt = bp->scst_tgt;
        memcpy(list, bp->list, sizeof(bp->list));
        unreg_hp = bp->unreg_hp;
        memset(bp, 0, sizeof(bus_t));
        spin_unlock_irq(&scsi_target_lock);   

        /* remove existing initiators */
        for (i = 0; i < HASH_WIDTH; i++) {
            ini_t *ini_next;
            ini_t *ptr = list[i];
            if (ptr) {
                do {
                    ini_next = ptr->ini_next;
                    free_ini(ptr);
                } while ((ptr = ini_next) != NULL);
            }
        }
        
        if (scst_tgt)    
            scst_unregister(scst_tgt);
        /* now no one will call low level functions */
        Iprintk("unregistering %s%d\n", unreg_hp->r_name, unreg_hp->r_inst);
        (unreg_hp->r_action)(QIN_HBA_UNREG, unreg_hp);
    }
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
EXPORT_SYMBOL_NOVERS(scsi_target_handler);
MODULE_PARM(scsi_tdebug, "i");
#else
EXPORT_SYMBOL(scsi_target_handler);
module_param(scsi_tdebug, int, 0);
#endif
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
