/* $Id: isp_linux.c,v 1.185 2007/06/01 17:19:34 mjacob Exp $ */
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
 */
/*
 * Qlogic ISP Host Adapter Common Bus Linux routies
 *
 * Bug fixes from Janice McLaughlin (janus@somemore.com)
 * gratefully acknowledged.
 *
 */

#define    ISP_MODULE    1
#include "isp_linux.h"
#include "linux/smp_lock.h"

static int isp_task_thread(void *);

ispsoftc_t *isplist[MAX_ISP] = { NULL };
ispsoftc_t *api_isp = NULL;
int api_channel = 0;
const char *class3_roles[4] = {
    "None", "Target", "Initiator", "Target/Initiator"
};

int isp_debug = 0;
int isp_throttle = 0;
int isp_cmd_per_lun = 0;
int isp_maxsectors = 1024;
int isp_unit_seed = 0;
int isp_disable = 0;
int isp_nofwreload = 0;
int isp_nonvram = 0;
int isp_maxluns = 8;
int isp_fcduplex = 0;
int isp_nport_only = 0;
int isp_loop_only = 0;
int isp_deadloop_time = 30;    /* how long to wait before assume loop dead */
int isp_fc_id = 111;
int isp_spi_id = 7;
int isp_own_id = 0;
int isp_default_frame_size;
int isp_default_exec_throttle;

static char *isp_roles;
static char *isp_wwpns;
static char *isp_wwnns;


#ifdef    ISP_TARGET_MODE
#ifndef    ISP_PARENT_TARGET
#define    ISP_PARENT_TARGET    scsi_target_handler
#endif

#define    CALL_PARENT_TARGET(hba, cmd, action) \
    cmd->cd_action = action;                    \
    cmd->cd_next = hba->isp_osinfo.pending_t;   \
    hba->isp_osinfo.pending_t = cmd

#define    CALL_PARENT_NOTIFY(hba, ins)                         \
    ins->notify.nt_lreserved = hba->isp_osinfo.pending_n;       \
    hba->isp_osinfo.pending_n = ins

extern void ISP_PARENT_TARGET (qact_e, void *);
static __inline tmd_cmd_t *isp_find_tmd(ispsoftc_t *, uint64_t);
static __inline int isp_find_iid_wwn(ispsoftc_t *, int, uint32_t, uint64_t *);
static __inline void isp_clear_iid_wwn(ispsoftc_t *, int, uint32_t, uint64_t);
static void isp_taction(qact_e, void *);
static void isp_target_start_ctio(ispsoftc_t *, tmd_cmd_t *);
static void isp_handle_platform_atio(ispsoftc_t *, at_entry_t *);
static void isp_handle_platform_atio2(ispsoftc_t *, at2_entry_t *);
static void isp_handle_platform_atio7(ispsoftc_t *, at7_entry_t *);
static int isp_terminate_cmd(ispsoftc_t *, tmd_cmd_t *);
static void isp_handle_platform_ctio(ispsoftc_t *, void *);
static int isp_target_putback_atio(ispsoftc_t *, tmd_cmd_t *);
static void isp_complete_ctio(ispsoftc_t *, tmd_cmd_t *);
static void isp_tgt_tq(ispsoftc_t *);
#endif

extern int isplinux_pci_detect(Scsi_Host_Template *);
extern void isplinux_pci_release(struct Scsi_Host *);

int
isplinux_detect(Scsi_Host_Template *tmpt)
{
    int rval;
    tmpt->proc_name = "isp";
    tmpt->max_sectors = isp_maxsectors;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
    spin_unlock_irq(&io_request_lock);
    rval = isplinux_pci_detect(tmpt);
    spin_lock_irq(&io_request_lock); 
#else
    rval = isplinux_pci_detect(tmpt);
#endif
    return (rval);
}

#ifdef    MODULE
/* io_request_lock *not* held here */
int
isplinux_release(struct Scsi_Host *host)
{
    ispsoftc_t *isp = (ispsoftc_t *) host->hostdata;
    unsigned long flags;

#ifdef    ISP_TARGET_MODE
    isp_detach_target(isp);
#endif
    if (isp->isp_osinfo.task_thread) {
        SEND_THREAD_EVENT(isp, ISP_THREAD_EXIT, NULL, 1, __FUNCTION__, __LINE__);
    }
    ISP_LOCKU_SOFTC(isp);
    isp_shutdown(isp);
    isp->dogactive = 0;
    del_timer(&isp->isp_osinfo.timer);
    isp->isp_role = ISP_ROLE_NONE;
    ISP_DISABLE_INTS(isp);
    ISP_UNLKU_SOFTC(isp);
    if (isp->isp_bustype == ISP_BT_PCI) {
        isplinux_pci_release(host);
    }
#ifdef    ISP_FW_CRASH_DUMP
    if (FCPARAM(isp, 0)->isp_dump_data) {
        size_t amt;
        if (IS_2200(isp)) {
            amt = QLA2200_RISC_IMAGE_DUMP_SIZE;
        } else {
            amt = QLA2200_RISC_IMAGE_DUMP_SIZE;
        }
        isp_prt(isp, ISP_LOGCONFIG, "freeing crash dump area");
        isp_kfree(FCPARAM(isp, 0)->isp_dump_data, amt);
        FCPARAM(isp, 0)->isp_dump_data = 0;
    }
#endif
#if defined(CONFIG_PROC_FS)
    /*
     * Undo any PROCFS stuff
     */
    isplinux_undo_proc(isp);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
    scsi_unregister(host);
#else
    scsi_remove_host(host);
    scsi_host_put(host);
#endif
    return (1);
}
#endif

const char *
isplinux_info(struct Scsi_Host *host)
{
    ispsoftc_t *isp = (ispsoftc_t *) host->hostdata;
#if defined(CONFIG_PROC_FS)
    /*
     * Initialize any PROCFS stuff (again) to get any subsidiary devices in place.
     */
    isplinux_init_proc(isp);
#endif
    if (IS_FC(isp)) {
        static char *foo = "Driver for a Qlogic ISP 2X00 Host Adapter";
        foo[26] = '0';
        foo[27] = '0';
        if (isp->isp_type == ISP_HA_FC_2100) {
            foo[25] = '1';
        } else if (isp->isp_type == ISP_HA_FC_2200) {
            foo[25] = '2';
        } else if (isp->isp_type == ISP_HA_FC_2300) {
            foo[25] = '3';
        } else if (isp->isp_type == ISP_HA_FC_2312) {
            foo[25] = '3';
            foo[26] = '1';
            foo[27] = '2';
        } else if (isp->isp_type == ISP_HA_FC_2322) {
            foo[25] = '3';
            foo[26] = '2';
            foo[27] = '2';
        } else if (isp->isp_type == ISP_HA_FC_2400) {
            foo[25] = '4';
            foo[26] = '2';
            foo[27] = '2';
        }
        return (foo);
    } else if (IS_1240(isp)) {
        return ("Driver for a Qlogic ISP 1240 Host Adapter");
    } else if (IS_1080(isp)) {
        return ("Driver for a Qlogic ISP 1080 Host Adapter");
    } else if (IS_1280(isp)) {
        return ("Driver for a Qlogic ISP 1280 Host Adapter");
    } else if (IS_10160(isp)) {
        return ("Driver for a Qlogic ISP 10160 Host Adapter");
    } else if (IS_12160(isp)) {
        return ("Driver for a Qlogic ISP 12160 Host Adapter");
    } else {
        return ("Driver for a Qlogic ISP 1020/1040 Host Adapter");
    }
}

static __inline void
isplinux_append_to_waitq(ispsoftc_t *isp, Scsi_Cmnd *Cmnd)
{
    /*
     * If we're a fibre channel card and we consider the loop to be
     * down, we just finish the command here and now.
     */
    if (IS_FC(isp) && isp->isp_deadloop) {
        XS_INITERR(Cmnd);
        XS_SETERR(Cmnd, DID_NO_CONNECT);

        /*
         * Add back a timer else scsi_done drops this on the floor.
         */
        if (Cmnd->eh_timeout.function) {
            mod_timer(&Cmnd->eh_timeout, jiffies + Cmnd->timeout_per_command);
        }
        isp_prt(isp, ISP_LOGDEBUG0, "giving up on target %d", XS_TGT(Cmnd));
        ISP_DROP_LK_SOFTC(isp);
        ISP_LOCK_SCSI_DONE(isp);
        (*Cmnd->scsi_done)(Cmnd);
        ISP_UNLK_SCSI_DONE(isp);
        ISP_IGET_LK_SOFTC(isp);
        return;
    }

    isp->isp_osinfo.wqcnt++;
    if (isp->isp_osinfo.wqhiwater < isp->isp_osinfo.wqcnt) {
        isp->isp_osinfo.wqhiwater = isp->isp_osinfo.wqcnt;
    }
    if (isp->isp_osinfo.wqnext == NULL) {
        isp->isp_osinfo.wqtail = isp->isp_osinfo.wqnext = Cmnd;
    } else {
        isp->isp_osinfo.wqtail->host_scribble = (unsigned char *) Cmnd;
        isp->isp_osinfo.wqtail = Cmnd;
    }
    Cmnd->host_scribble = NULL;

    /*
     * Stop the clock for this command.
     */
    if (Cmnd->eh_timeout.function) {
        del_timer(&Cmnd->eh_timeout);
    }
}

static __inline void
isplinux_insert_head_waitq(ispsoftc_t *isp, Scsi_Cmnd *Cmnd)
{
    isp->isp_osinfo.wqcnt++;
    if (isp->isp_osinfo.wqnext == NULL) {
        isp->isp_osinfo.wqtail = isp->isp_osinfo.wqnext = Cmnd;
        Cmnd->host_scribble = NULL;
    } else {
        Cmnd->host_scribble = (unsigned char *) isp->isp_osinfo.wqnext;
        isp->isp_osinfo.wqnext = Cmnd;
    }
}

static __inline Scsi_Cmnd *
isp_remove_from_waitq(Scsi_Cmnd *Cmnd)
{
    ispsoftc_t *isp;
    Scsi_Cmnd *f;
    if (Cmnd == NULL) {
        return (Cmnd);
    }
    isp = XS_ISP(Cmnd);
    if ((f = isp->isp_osinfo.wqnext) == Cmnd) {
        isp->isp_osinfo.wqnext = (Scsi_Cmnd *) Cmnd->host_scribble;
    } else {
        Scsi_Cmnd *b = f;
        while (f) {
            f = (Scsi_Cmnd *) b->host_scribble;
            if (f == Cmnd) {
                b->host_scribble = f->host_scribble;
                if (isp->isp_osinfo.wqtail == Cmnd) {
                     isp->isp_osinfo.wqtail = b;
                }
                break;
            }
            b = f;
        }
    }
    if (f) {
        f->host_scribble = NULL;
        isp->isp_osinfo.wqcnt -= 1;
    }
    return (f);
}

static __inline void
isplinux_runwaitq(ispsoftc_t *isp)
{
    Scsi_Cmnd *f;

    if (isp->isp_blocked || isp->isp_draining || isp->isp_qfdelay) {
        return;
    }

    while ((f = isp_remove_from_waitq(isp->isp_osinfo.wqnext)) != NULL) {
        int result = isp_start(f);
        /*
         * Restart the timer for this command if it is queued or completing.
         */
        if (result == CMD_QUEUED || result == CMD_COMPLETE) {
            if (f->eh_timeout.function) {
                mod_timer(&f->eh_timeout, jiffies + f->timeout_per_command);
            }
        }
        if (result == CMD_QUEUED) {
            if (isp->isp_osinfo.hiwater < isp->isp_nactive)
            isp->isp_osinfo.hiwater = isp->isp_nactive;
            continue;
        }

        /*
         * If we cannot start a command on a fibre channel card, it means
         * that loop state isn't ready for us to do so. Activate the FC
         * thread to rediscover loop and fabric residency- but not if
         * we consider the loop to be dead. If the loop is considered dead,
         * we wait until a PDB Changed after a Loop UP activates the FC
         * thread.
         */
        if (result == CMD_RQLATER && IS_FC(isp) && isp->isp_deadloop == 0) {
            SEND_THREAD_EVENT(isp, ISP_THREAD_FC_RESCAN, FCPARAM(isp, XS_CHANNEL(f)), 0, __FUNCTION__, __LINE__);
        }

        /*
         * Put the command back on the wait queue. Don't change any
         * timer parameters for it because they were established
         * when we originally put the command on the waitq in the first
         * place.
         */
        if (result == CMD_EAGAIN || result == CMD_RQLATER) {
            isplinux_insert_head_waitq(isp, f);
            break;
        }
        if (result == CMD_COMPLETE) {
            isp_done(f);
        } else {
            panic("isplinux_runwaitq: result %d", result);
            /*NOTREACHED*/
        }
    }
}

static __inline void
isplinux_flushwaitq(ispsoftc_t *isp)
{
    Scsi_Cmnd *Cmnd, *Ncmnd;
   
    if ((Cmnd = isp->isp_osinfo.wqnext) == NULL) {
        return;
    }
    isp->isp_osinfo.wqnext = isp->isp_osinfo.wqtail = NULL;
    isp->isp_osinfo.wqcnt = 0;
    ISP_DROP_LK_SOFTC(isp);
    do {
        Ncmnd = (Scsi_Cmnd *) Cmnd->host_scribble;
        Cmnd->host_scribble = NULL;
        XS_INITERR(Cmnd);
        XS_SETERR(Cmnd, DID_NO_CONNECT);
        /*
         * Add back a timer else scsi_done drops this on the floor.
         */
        if (Cmnd->eh_timeout.function) {
            mod_timer(&Cmnd->eh_timeout, jiffies + Cmnd->timeout_per_command);
        }
        ISP_LOCK_SCSI_DONE(isp);
        (*Cmnd->scsi_done)(Cmnd);
        ISP_UNLK_SCSI_DONE(isp);
    } while ((Cmnd = Ncmnd) != NULL);
    ISP_IGET_LK_SOFTC(isp);
}

static __inline Scsi_Cmnd *
isplinux_remove_from_doneq(Scsi_Cmnd *Cmnd)
{
    Scsi_Cmnd *f;
    ispsoftc_t *isp;

    if (Cmnd == NULL) {
        return (NULL);
    }
    isp = XS_ISP(Cmnd);
    if (isp->isp_osinfo.dqnext == NULL) {
        return (NULL);
    }
    if ((f = isp->isp_osinfo.dqnext) == Cmnd) {
        isp->isp_osinfo.dqnext = (Scsi_Cmnd *) Cmnd->host_scribble;
    } else {
        Scsi_Cmnd *b = f;
        while (f) {
            f = (Scsi_Cmnd *) b->host_scribble;
            if (f == Cmnd) {
                b->host_scribble = f->host_scribble;
                if (isp->isp_osinfo.dqtail == Cmnd) {
                     isp->isp_osinfo.dqtail = b;
                }
                break;
            }
            b = f;
        }
    }
    if (f) {
        f->host_scribble = NULL;
    }
    return (f);
}

int
isplinux_queuecommand(Scsi_Cmnd *Cmnd, void (*donecmd)(Scsi_Cmnd *))
{
    struct Scsi_Host *host = XS_HOST(Cmnd);
    ispsoftc_t *isp = (ispsoftc_t *) (host->hostdata);
    int result;
    unsigned long flags;

    Cmnd->scsi_done = donecmd;
    Cmnd->sense_buffer[0] = 0;

    ISP_DRIVER_ENTRY_LOCK(isp);
    ISP_LOCK_SOFTC(isp);

    /*
     * First off, see whether we need to (re)init the HBA.
     * If we need to and fail to, pretend that this was a selection timeout.
     */
    if (isp->isp_state != ISP_RUNSTATE) {
        if (isp->isp_role != ISP_ROLE_NONE) {
            /*
             * The check below will catch a reinit failure
             */
            (void) isplinux_reinit(isp);
        }
        if (isp->isp_state != ISP_RUNSTATE) {
            isp_prt(isp, ISP_LOGDEBUG0,
                "DID_NOCONNECT because isp not at RUNSTATE");
            ISP_UNLK_SOFTC(isp);
            ISP_DRIVER_EXIT_LOCK(isp);
            XS_INITERR(Cmnd);
            XS_SETERR(Cmnd, DID_NO_CONNECT);
            ISP_LOCK_SCSI_DONE(isp);
            (*Cmnd->scsi_done)(Cmnd);
            ISP_UNLK_SCSI_DONE(isp);
            return (0);
        }
    }

    /*
     * See if we're currently blocked. If we are, just queue up the command
     * to be run later.
     */
    if (isp->isp_blocked || isp->isp_draining || isp->isp_qfdelay) {
        isp_prt(isp, ISP_LOGDEBUG0, "appending cmd to waitq due to %d/%d/%d", isp->isp_blocked, isp->isp_draining, isp->isp_qfdelay);
        isplinux_append_to_waitq(isp, Cmnd);
        ISP_UNLK_SOFTC(isp);
        ISP_DRIVER_EXIT_LOCK(isp);
        return (0);
    }

    /*
     * Next see if we have any stored up commands to run. If so, run them.
     * If we get back from this with commands still ready to run, put the
     * current command at the tail of waiting commands to be run later.
     */

    isplinux_runwaitq(isp);
    if (isp->isp_osinfo.wqnext) {
        isp_prt(isp, ISP_LOGDEBUG0, "appending cmd to waitq");
        isplinux_append_to_waitq(isp, Cmnd);
        ISP_UNLK_SOFTC(isp);
        ISP_DRIVER_EXIT_LOCK(isp);
        return (0);
    }

    /*
     * Finally, try and run this command.
     */
    result = isp_start(Cmnd);
    if (result == CMD_QUEUED) {
        if (isp->isp_osinfo.hiwater < isp->isp_nactive) {
            isp->isp_osinfo.hiwater = isp->isp_nactive;
        }
        result = 0;
    } else if (result == CMD_EAGAIN) {
        /*
         * We ran out of request queue space (or could not
         * get DMA resources). Tell the upper layer to try
         * later.
         */
        result = 1;
    } else if (result == CMD_RQLATER) {
        /*
         * Temporarily hold off on this one.
         * Typically this means for fibre channel
         * that the loop is down or we're processing
         * some other change (e.g., fabric membership
         * change)
         */
        isplinux_append_to_waitq(isp, Cmnd);
        if (IS_FC(isp) && isp->isp_deadloop == 0) {
            SEND_THREAD_EVENT(isp, ISP_THREAD_FC_RESCAN, FCPARAM(isp, XS_CHANNEL(Cmnd)), 0, __FUNCTION__, __LINE__);
        }
        result = 0;
    } else if (result == CMD_COMPLETE) {
        result = -1;
    } else {
        panic("unknown return code %d from isp_start", result);
        /*NOTREACHED*/
    }
    ISP_UNLK_SOFTC(isp);
    ISP_DRIVER_EXIT_LOCK(isp);
    if (result == -1) {
        Cmnd->result &= ~0xff;
        Cmnd->result |= Cmnd->SCp.Status;
        Cmnd->host_scribble = NULL;
        ISP_LOCK_SCSI_DONE(isp);
        (*Cmnd->scsi_done)(Cmnd);
        ISP_UNLK_SCSI_DONE(isp);
        result = 0;
    }
    return (result);
}

static __inline void isplinux_scsi_probe_done(Scsi_Cmnd *);

static __inline void
isplinux_scsi_probe_done(Scsi_Cmnd *Cmnd)
{
    ispsoftc_t *isp = XS_ISP(Cmnd);

    /*
     * If we haven't seen this target yet, check the command result. If
     * it was an inquiry and it succeeded okay, then we can update our
     * notions about this target's capabilities.
     *
     * If the command did *not* succeed, we also update our notions about
     * this target's capabilities (pessimistically) - it's probably not there.
     * All of this so we can know when we're done so we stop wasting cycles
     * seeing whether we can enable sync mode or not.
     */

    if (isp->isp_psco[XS_CHANNEL(Cmnd)][XS_TGT(Cmnd)] == 0) {
        int i, b;
        caddr_t iqd;
        sdparam *sdp = SDPARAM(isp, XS_CHANNEL(Cmnd));

        if (Cmnd->cmnd[0] == 0x12 && host_byte(Cmnd->result) == DID_OK) {
            if (Cmnd->use_sg == 0) {
                iqd = (caddr_t) Cmnd->request_buffer;
            } else {
#if    LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
                iqd = ((struct scatterlist *) Cmnd->request_buffer)->address;
#else
                struct scatterlist *sg;
                sg = (struct scatterlist *) Cmnd->request_buffer;
                iqd = page_address(sg->page) + sg->offset;
#endif
            }
            sdp->isp_devparam[XS_TGT(Cmnd)].goal_flags &= ~(DPARM_TQING|DPARM_SYNC|DPARM_WIDE);
            if (iqd[7] & 0x2) {
                sdp->isp_devparam[XS_TGT(Cmnd)].goal_flags |= DPARM_TQING;
            }
            if (iqd[7] & 0x10) {
                sdp->isp_devparam[XS_TGT(Cmnd)].goal_flags |= DPARM_SYNC;
            }
            if (iqd[7] & 0x20) {
                sdp->isp_devparam[XS_TGT(Cmnd)].goal_flags |= DPARM_WIDE;
            }
            sdp->isp_devparam[XS_TGT(Cmnd)].dev_update = 1;
            isp->isp_psco[XS_CHANNEL(Cmnd)][XS_TGT(Cmnd)] = 1;
        } else if (host_byte(Cmnd->result) != DID_OK) {
            isp->isp_psco[XS_CHANNEL(Cmnd)][XS_TGT(Cmnd)] = 1;
        }

        isp->isp_dutydone = 1;
        for (b = 0; b < (IS_DUALBUS(isp)?2 : 1) && isp->isp_dutydone; b++) {
            for (i = 0; i < MAX_TARGETS; i++) {
                if (i != sdp->isp_initiator_id) {
                    if (isp->isp_psco[b][i] == 0) {
                        isp->isp_dutydone = 0;
                        break;
                    }
                }
            }
        }

        /*
         * Have we scanned all busses and all targets? You only get
         * one chance (per reset) to see what devices on this bus have
         * to offer.
         */
        if (isp->isp_dutydone) {
            for (b = 0; b < (IS_DUALBUS(isp)?2 : 1) && isp->isp_dutydone; b++) {
                for (i = 0; i < MAX_TARGETS; i++) {
                    isp->isp_psco[b][i] = 0;
                }
                isp->isp_update |= (1 << b);
            }
        }        
    }
}

void
isp_done(Scsi_Cmnd *Cmnd)
{
    ispsoftc_t *isp = XS_ISP(Cmnd);

    if (IS_SCSI(isp) && isp->isp_dutydone == 0)  {
        isplinux_scsi_probe_done(Cmnd);
    }

    Cmnd->result &= ~0xff;
    Cmnd->result |= Cmnd->SCp.Status;

    if (Cmnd->SCp.Status != GOOD) {
        isp_prt(isp, ISP_LOGDEBUG0, "%d.%d.%d: cmd finishes with status 0x%x", XS_CHANNEL(Cmnd), XS_TGT(Cmnd), XS_LUN(Cmnd), Cmnd->SCp.Status);
        if (Cmnd->SCp.Status == SCSI_QFULL) {
            isp->isp_qfdelay = 2 * ISP_WATCH_TPS;
            /*
             * Too many hangups in the midlayer
             */
            isplinux_append_to_waitq(isp, Cmnd);
            return;
        }
    }

    Cmnd->resid = XS_RESID(Cmnd);
    /*
     * Queue command on completion queue.
     */
    if (isp->isp_osinfo.dqnext == NULL) {
        isp->isp_osinfo.dqnext = Cmnd;
    } else {
        isp->isp_osinfo.dqtail->host_scribble = (unsigned char *) Cmnd;
    }
    isp->isp_osinfo.dqtail = Cmnd;
    Cmnd->host_scribble = NULL;
}

/*
 * Error handling routines
 */

int
isplinux_abort(Scsi_Cmnd *Cmnd)
{
    ispsoftc_t *isp;
    uint32_t handle;
    unsigned long flags;

    if (Cmnd == NULL || XS_HOST(Cmnd) == NULL) {
        return (FAILED);
    }

    isp = XS_ISP(Cmnd);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
    if (Cmnd->serial_number != Cmnd->serial_number_at_timeout) {
        isp_prt(isp, ISP_LOGWARN, "isplinux_abort: serial number mismatch");
        return (FAILED);
    }
#endif
    ISP_DRIVER_CTL_ENTRY_LOCK(isp);
    ISP_LOCKU_SOFTC(isp);
    handle = isp_find_handle(isp, Cmnd);
    if (handle == 0) {
        int wqfnd = 0;
        Scsi_Cmnd *NewCmnd = isp_remove_from_waitq(Cmnd);
        if (NewCmnd == NULL) {
            NewCmnd = isplinux_remove_from_doneq(Cmnd);
            wqfnd++;
        }
        ISP_UNLKU_SOFTC(isp);
        isp_prt(isp, ISP_LOGINFO, "isplinux_abort: found %d:%p for non-running cmd for %d.%d.%d",
            wqfnd, NewCmnd, XS_CHANNEL(Cmnd), XS_TGT(Cmnd), XS_LUN(Cmnd));
        if (NewCmnd == NULL) {
            ISP_DRIVER_CTL_EXIT_LOCK(isp);
            return (FAILED);
        }
    } else {
        isp->isp_qfdelay = ISP_WATCH_TPS;
        if (isp_control(isp, ISPCTL_ABORT_CMD, Cmnd)) {
            ISP_UNLKU_SOFTC(isp);
            ISP_DRIVER_CTL_EXIT_LOCK(isp);
            return (FAILED);
        }
        if (isp->isp_nactive > 0) {
            isp->isp_nactive--;
        }
        isp_destroy_handle(isp, handle);
        ISP_UNLKU_SOFTC(isp);
        ISP_DRIVER_CTL_EXIT_LOCK(isp);
        isp_prt(isp, ISP_LOGINFO, "isplinux_abort: aborted running cmd (handle 0x%x) for %d.%d.%d",
            handle, XS_CHANNEL(Cmnd), XS_TGT(Cmnd), XS_LUN(Cmnd));
    }
    Cmnd->result = DID_ABORT << 16;
    ISP_LOCK_SCSI_DONE(isp);
    (*Cmnd->scsi_done)(Cmnd);
    ISP_UNLK_SCSI_DONE(isp);
    return (SUCCESS);
}

int
isplinux_bdr(Scsi_Cmnd *Cmnd)
{
    ispsoftc_t *isp;
    int r;
    unsigned long flags;

    if (Cmnd == NULL || XS_HOST(Cmnd) == NULL) {
        return (FAILED);
    }

    isp = XS_ISP(Cmnd);
    ISP_DRIVER_CTL_ENTRY_LOCK(isp);
    ISP_LOCKU_SOFTC(isp);
    r = isp_control(isp, ISPCTL_RESET_DEV, XS_CHANNEL(Cmnd), XS_TGT(Cmnd));
    ISP_UNLKU_SOFTC(isp);
    ISP_DRIVER_CTL_EXIT_LOCK(isp);
    isp_prt(isp, ISP_LOGINFO, "Bus Device Reset %succesfully sent to %d.%d.%d",
        r == 0? "s" : "uns", XS_CHANNEL(Cmnd), XS_TGT(Cmnd), XS_LUN(Cmnd));
    return ((r == 0)? SUCCESS : FAILED);
}

int
isplinux_sreset(Scsi_Cmnd *Cmnd)
{
    ispsoftc_t *isp;
    int r;
    fcparam *fcp;
    unsigned long flags;

    if (Cmnd == NULL || XS_HOST(Cmnd) == NULL) {
        return (FAILED);
    }
    isp = XS_ISP(Cmnd);
    fcp = FCPARAM(isp, XS_CHANNEL(Cmnd));
    ISP_DRIVER_CTL_ENTRY_LOCK(isp);
    ISP_LOCKU_SOFTC(isp);
    isp->isp_qfdelay = ISP_WATCH_TPS;
    if (IS_FC(isp) && fcp->isp_fwstate == FW_READY && fcp->isp_loopstate == LOOP_READY && fcp->isp_topo == TOPO_F_PORT) {
        ISP_UNLKU_SOFTC(isp);
        ISP_DRIVER_CTL_EXIT_LOCK(isp);
        isp_prt(isp, ISP_LOGINFO, "SCSI Bus Reset request ignored");
        return (SUCCESS);
    }
    r = isp_control(isp, ISPCTL_RESET_DEV, XS_CHANNEL(Cmnd), XS_TGT(Cmnd));
    ISP_UNLKU_SOFTC(isp);
    ISP_DRIVER_CTL_EXIT_LOCK(isp);
    isp_prt(isp, ISP_LOGINFO, "SCSI Bus Reset on Channel %d %succesful", XS_CHANNEL(Cmnd), r == 0? "s" : "uns");
    return ((r == 0)? SUCCESS : FAILED);
}

/*
 * We call completion on any commands owned here-
 * except the one we were called with.
 */
int
isplinux_hreset(Scsi_Cmnd *Cmnd)
{
    Scsi_Cmnd *tmp, *dq, *wq, *xqf, *xql;
    ispsoftc_t *isp;
    uint32_t handle;
    unsigned long flags;

    if (Cmnd == NULL || XS_HOST(Cmnd) == NULL) {
        return (FAILED);
    }

    isp = XS_ISP(Cmnd);

    isp_prt(isp, ISP_LOGINFO, "Resetting Host Adapter");

    ISP_DRIVER_CTL_ENTRY_LOCK(isp);
    ISP_LOCKU_SOFTC(isp);

    /*
     * Save pending, running, and completed commands.
     */
    xql = xqf = NULL;
    for (handle = 1; handle <= isp->isp_maxcmds; handle++) {
        tmp = isp_find_xs(isp, handle);
        if (tmp == NULL) {
            continue;
        }
        isp_destroy_handle(isp, handle);
        tmp->host_scribble = NULL;
        if (xqf) {
            xql->host_scribble = (unsigned char *) tmp;
        } else {
            xqf = xql = tmp;
        }
        xql = tmp;
    }
    dq = isp->isp_osinfo.dqnext;
    isp->isp_osinfo.dqnext = NULL;
    wq = isp->isp_osinfo.wqnext;
    isp->isp_osinfo.wqnext = NULL;
    isp->isp_nactive = 0;

    (void) isplinux_reinit(isp);

    ISP_UNLKU_SOFTC(isp);
    ISP_DRIVER_CTL_EXIT_LOCK(isp);

    /*
     * Call completion on the detritus, skipping the one we were called with.
     */
    while ((tmp = xqf) != NULL) {
        xqf = (Scsi_Cmnd *) tmp->host_scribble;
        tmp->host_scribble = NULL;
        if (tmp == Cmnd) {
            continue;
        }
        tmp->result = DID_RESET << 16;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
        /*
         * Get around silliness in midlayer.
         */
        tmp->flags |= IS_RESETTING;
#endif
        if (tmp->scsi_done) {
            ISP_LOCK_SCSI_DONE(isp);
            (*tmp->scsi_done)(tmp);
            ISP_UNLK_SCSI_DONE(isp);
        }
    }
    while ((tmp = wq) != NULL) {
        wq = (Scsi_Cmnd *) tmp->host_scribble;
        tmp->host_scribble = NULL;
        if (tmp == Cmnd) {
            continue;
        }
        tmp->result = DID_RESET << 16;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
        /*
         * Get around silliness in midlayer.
         */
        tmp->flags |= IS_RESETTING;
#endif
        if (tmp->scsi_done) {
            ISP_LOCK_SCSI_DONE(isp);
            (*tmp->scsi_done)(tmp);
            ISP_UNLK_SCSI_DONE(isp);
        }
    }
    while ((tmp = dq) != NULL) {
        dq = (Scsi_Cmnd *) tmp->host_scribble;
        tmp->host_scribble = NULL;
        if (tmp == Cmnd) {
            continue;
        }
        tmp->result = DID_RESET << 16;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
        /*
         * Get around silliness in midlayer.
         */
        tmp->flags |= IS_RESETTING;
#endif
        if (tmp->scsi_done) {
            ISP_LOCK_SCSI_DONE(isp);
            (*tmp->scsi_done)(tmp);
            ISP_UNLK_SCSI_DONE(isp);
        }
    }
    Cmnd->result = DID_RESET << 16;
    return (SUCCESS);
}

#ifdef    ISP_TARGET_MODE
int
isp_init_target(ispsoftc_t *isp)
{
    int i;
    void *pool, *npool, *inqdata, *dpwrk;
    unsigned long flags;
    static const uint8_t inqdsd[DEFAULT_INQSIZE] = {
        0x7f, 0x00, 0x03, 0x02, 0x1c, 0x00, 0x00, 0x00,
         'L',  'I',  'N',  'U',  'X',  'I',  'S',  'P',
         ' ',  'T',  'A',  'R',  'G',  'E',  'T',  ' ',
         'D',  'E',  'V',  'I',  'C',  'E',  ' ',  ' '
    };


    pool = isp_kzalloc(NTGT_CMDS * TMD_SIZE, GFP_KERNEL);
    if (pool == NULL) {
        isp_prt(isp, ISP_LOGERR, "cannot allocate TMD structures");
        return (-ENOMEM);
    }
    npool = isp_kzalloc(N_NOTIFIES * sizeof (isp_notify_t), GFP_KERNEL);
    if (npool == NULL) {
        isp_prt(isp, ISP_LOGERR, "cannot allocate TMD NOTIFY structures");
        isp_kfree(pool, NTGT_CMDS * TMD_SIZE);
        return (-ENOMEM);
    }
    inqdata = isp_kalloc(DEFAULT_INQSIZE, GFP_KERNEL|GFP_DMA);
    if (inqdata == NULL) {
        isp_prt(isp, ISP_LOGERR, "cannot allocate static Inquiry Data");
        isp_kfree(pool, NTGT_CMDS * TMD_SIZE);
        isp_kfree(npool, N_NOTIFIES * sizeof (isp_notify_t));
        return (-ENOMEM);
    }
    dpwrk = isp_kzalloc(NTGT_CMDS * sizeof (struct scatterlist), GFP_KERNEL);
    if (dpwrk == NULL) {
        isp_prt(isp, ISP_LOGERR, "cannot allocate static scatterlists");
        isp_kfree(pool, NTGT_CMDS * TMD_SIZE);
        isp_kfree(npool, N_NOTIFIES * sizeof (isp_notify_t));
        isp_kfree(inqdata, DEFAULT_INQSIZE);
        return (-ENOMEM);
    }

    sema_init(&isp->isp_osinfo.tgt_inisem, 1);

    ISP_LOCK_SOFTC(isp);
    isp->isp_osinfo.pool = pool;
    for (i = 0; i < NTGT_CMDS-1; i++) {
        isp->isp_osinfo.pool[i].cd_next = &isp->isp_osinfo.pool[i+1];
    }
    isp->isp_osinfo.npool = npool;
    for (i = 0; i < N_NOTIFIES-1; i++) {
        isp->isp_osinfo.npool[i].notify.nt_lreserved = &isp->isp_osinfo.npool[i+1];
    }
    isp->isp_osinfo.inqdata = inqdata;
    MEMCPY(isp->isp_osinfo.inqdata, inqdsd, DEFAULT_INQSIZE);
    isp->isp_osinfo.dpwrk = dpwrk;
    isp->isp_osinfo.pending_t = NULL;
    isp->isp_osinfo.tfreelist = isp->isp_osinfo.pool;
    isp->isp_osinfo.bfreelist = &isp->isp_osinfo.pool[NTGT_CMDS-1];
    isp->isp_osinfo.nfreelist = isp->isp_osinfo.npool;
    ISP_UNLK_SOFTC(isp);
    return (0);
}

void
isp_attach_target(ispsoftc_t *isp)
{
    hba_register_t hba;
    hba.r_identity = isp;
    snprintf(hba.r_name, sizeof (hba.r_name), "isp");
    hba.r_inst = isp->isp_unit;
    hba.r_version = QR_VERSION;
    hba.r_action = isp_taction;
    hba.r_locator = isp->isp_osinfo.device_id;
    if (IS_FC(isp)) {
        hba.r_nchannels = 1;
        hba.r_type = R_FC;
    } else{
        hba.r_nchannels = IS_DUALBUS(isp)? 2 : 1;
        hba.r_type = R_SPI;
    }
    hba.r_private = NULL;
    ISP_PARENT_TARGET(QOUT_HBA_REG, &hba);
}

void
isp_deinit_target(ispsoftc_t *isp)
{
    void *pool, *npool, *inqdata, *dpwrk;
    unsigned long flags;

    ISP_LOCK_SOFTC(isp);
    pool = isp->isp_osinfo.pool;
    isp->isp_osinfo.pool = NULL;
    npool = isp->isp_osinfo.npool;
    isp->isp_osinfo.npool = NULL;
    inqdata = isp->isp_osinfo.inqdata;
    isp->isp_osinfo.inqdata = NULL;
    dpwrk = isp->isp_osinfo.dpwrk;
    isp->isp_osinfo.dpwrk = NULL;
    ISP_UNLK_SOFTC(isp);
    if (pool) {
        isp_kfree(pool, NTGT_CMDS * TMD_SIZE);
    }
    if (npool) {
        isp_kfree(npool, N_NOTIFIES * sizeof (isp_notify_t));
    }
    if (inqdata) {
        isp_kfree(inqdata, DEFAULT_INQSIZE);
    }
    if (dpwrk) {
        isp_kfree(dpwrk, NTGT_CMDS * sizeof (struct scatterlist));
    }
}

void
isp_detach_target(ispsoftc_t *isp)
{
    hba_register_t hba;
    DECLARE_MUTEX_LOCKED(rsem);

    hba.r_identity = isp;
    snprintf(hba.r_name, sizeof (hba.r_name), "isp");
    hba.r_inst = isp->isp_unit;
    hba.r_version = QR_VERSION;
    hba.r_action = isp_taction;
    if (IS_FC(isp)) {
        hba.r_type = R_FC;
    } else{
        hba.r_type = R_SPI;
    }
    hba.r_private = &rsem;
    ISP_PARENT_TARGET(QOUT_HBA_UNREG, &hba);
    down(&rsem);
}

static void
isp_tgt_tq(ispsoftc_t *isp)
{
    isp_notify_t *ins;
    tmd_cmd_t *tmd;
    unsigned long flags;

    ISP_LOCK_SOFTC(isp);
    ins = isp->isp_osinfo.pending_n;
    if (ins) {
        isp->isp_osinfo.pending_n = NULL;
    }
    tmd = isp->isp_osinfo.pending_t;
    if (tmd) {
        isp->isp_osinfo.pending_t = NULL;
    }
    ISP_UNLK_SOFTC(isp);
    while (ins != NULL) {
        isp_notify_t *next = ins->notify.nt_lreserved;
        ins->notify.nt_lreserved = NULL;
        isp_prt(isp, ISP_LOGTDEBUG2, "isp_tgt_tq -> notify 0x%x", ins->notify.nt_ncode);
        ISP_PARENT_TARGET(QOUT_NOTIFY, ins);
        ins = next;
    }
    while (tmd != NULL) {
        tmd_cmd_t *next = tmd->cd_next;
        tmd->cd_next = NULL;
        isp_prt(isp, ISP_LOGTDEBUG2, "isp_tgt_tq[%llx] -> code 0x%x", tmd->cd_tagval, tmd->cd_action);
        ISP_PARENT_TARGET(tmd->cd_action, tmd);
        tmd = next;
    }
}

static __inline tmd_cmd_t *
isp_find_tmd(ispsoftc_t *isp, uint64_t tagval)
{
    int i;
    tmd_cmd_t *tmd = isp->isp_osinfo.pool;

    if (tmd == NULL || tagval == TAG_ANY) {
        return (NULL);
    }
    for (i = 0; i < NTGT_CMDS; i++) {
        if (tmd->cd_lflags && tmd->cd_tagval == tagval) {
            return (tmd);
        }
        tmd++;
    }
    return (NULL);
}

static __inline int
isp_find_iid_wwn(ispsoftc_t *isp, int chan, uint32_t iid, uint64_t *wwnp)
{
    fcparam *fcp;
    int i;

    if (IS_SCSI(isp)) {
        return (0);
    }

    fcp = FCPARAM(isp, chan);
    for (i = 0; i < MAX_FC_TARG; i++) {
        fcportdb_t *lp = &fcp->portdb[i];

        if (lp->state != FC_PORTDB_STATE_VALID) {
            continue;
        }
        if (lp->handle == iid) {
            *wwnp = lp->port_wwn;
            return (1);
        }
    }
    return (0);
}

static __inline int
isp_find_pdb_sid(ispsoftc_t *isp, int chan, uint32_t sid, fcportdb_t **lptr)
{
    fcparam *fcp;
    int i;

    if (IS_SCSI(isp)) {
        return (0);
    }

    fcp = FCPARAM(isp, chan);
    for (i = 0; i < MAX_FC_TARG; i++) {
        fcportdb_t *lp = &fcp->portdb[i];

        if (lp->state != FC_PORTDB_STATE_VALID) {
            continue;
        }
        if (lp->portid == sid) {
            *lptr = lp;
            return (1);
        }
    }
    return (0);
}

static __inline void
isp_clear_iid_wwn(ispsoftc_t *isp, int chan, uint32_t iid, uint64_t wwpn)
{
    int i, lo, hi;

    if (IS_SCSI(isp)) {
        return;
    }
    if (wwpn == INI_ANY) {
        lo = 0;
        hi = MAX_FC_TARG;
    } else if (iid >= MAX_FC_TARG) {
        return;
    } else {
        lo = iid;
        hi = lo + 1;
    }
    for (i = lo; i < hi; i++) {
        fcportdb_t *lp = &FCPARAM(isp, chan)->portdb[i];
        if (lp->state == FC_PORTDB_STATE_VALID && (wwpn == INI_ANY || wwpn == lp->port_wwn)) {
            isp_prt(isp, ISP_LOGINFO, "Clearing pordb %u validity for WWN 0x%016llx", iid, lp->port_wwn);
            lp->state = FC_PORTDB_STATE_NIL;
        }
    }
}

static void
isp_taction(qact_e action, void *arg)
{
    tmd_cmd_t *tmd;
    hba_register_t *hp;
    enadis_t *ep;
    ispsoftc_t *isp = NULL;
    unsigned long flags;

    switch (action) {
    case QIN_HBA_REG:
        hp = (hba_register_t *) arg;
        isp = hp->r_identity;
        if (isp == NULL) {
            printk(KERN_ERR "null isp @ %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
            break;
        }
        isp_prt(isp, ISP_LOGINFO, "completed target registration");
        ISP_LOCK_SOFTC(isp);
        isp->isp_osinfo.hcb = 1;
        ISP_UNLK_SOFTC(isp);
        break;

    case QIN_GETINFO:
    {
        info_t *ip = arg;
        isp = ip->i_identity;
        if (ip->i_type == I_FC) {
            ip->i_id.fc.wwnn_nvram = FCPARAM(isp, ip->i_channel)->isp_wwnn_nvram;
            ip->i_id.fc.wwpn_nvram = FCPARAM(isp, ip->i_channel)->isp_wwpn_nvram;
            ip->i_id.fc.wwnn = ISP_NODEWWN(isp);
            ip->i_id.fc.wwpn = ISP_PORTWWN(isp);;
            ip->i_error = 0;
        } else if (ip->i_type == I_SPI) {
            sdparam *sdp = SDPARAM(isp, ip->i_channel);
            ip->i_id.spi.iid = sdp->isp_initiator_id;
            ip->i_error = 0;
        } else {
            ip->i_error = -EINVAL;
        }
        break;
    }
    case QIN_SETINFO:
    {
        info_t *ip = arg;
        isp = ip->i_identity;
        if (ip->i_type == I_FC) {
            ISP_NODEWWN(isp) = isp->isp_defwwnn = ip->i_id.fc.wwnn;
            ISP_PORTWWN(isp) = isp->isp_defwwpn = ip->i_id.fc.wwpn;
            isp->isp_confopts |= ISP_CFG_OWNWWNN|ISP_CFG_OWNWWPN;
            ip->i_error = 0;
        } else {
            ip->i_error = -EINVAL;
        }
        break;
    }
    case QIN_GETDLIST:
    {
        fc_dlist_t *ua = arg;
        int rv, nph, nphe, lim, chan;
        uint64_t wwpn;

        isp = ua->d_identity;
        if (IS_SCSI(isp)) {
            ua->d_error = -EINVAL;
            break;
        }

        lim = ua->d_count;
        chan = ua->d_channel;
        ua->d_count = 0;
        if (ISP_CAP_2KLOGIN(isp)) {
            nphe = NPH_MAX_2K;
        } else {
            nphe = NPH_MAX;
        }

        for (rv = 0, nph = 1; ua->d_count < lim && nph != nphe; nph++) {
            ISP_LOCKU_SOFTC(isp);
            rv = isp_control(isp, ISPCTL_GET_PORTNAME, chan, nph, &wwpn);
            ISP_UNLKU_SOFTC(isp);
            if (rv == 0 && wwpn != (uint64_t) 0) {
                ua->d_wwpns[ua->d_count++] = wwpn;
            }
        }
        ua->d_error = 0;
        break;
    }
    case QIN_ENABLE:
        ep = arg;
        isp = ep->en_hba;
        if (isp == NULL) {
            printk(KERN_ERR "null isp @ %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
            break;
        }
        ep->en_error = isp_en_dis_lun(isp, 1, ep->en_chan, ep->en_tgt, ep->en_lun);
        ISP_PARENT_TARGET(QOUT_ENABLE, ep);
        break;

    case QIN_DISABLE:
        ep = arg;
        isp = ep->en_hba;
        if (isp == NULL) {
            printk(KERN_ERR "null isp @ %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
            break;
        }
        ep->en_error = isp_en_dis_lun(isp, 0, ep->en_chan, ep->en_tgt, ep->en_lun);
        ISP_PARENT_TARGET(QOUT_DISABLE, ep);
        ISP_LOCK_SOFTC(isp);
        (void) isp_target_async(isp, 0, ASYNC_LOOP_DOWN);
        ISP_UNLK_SOFTC(isp);
        break;

    case QIN_TMD_CONT:
        tmd = (tmd_cmd_t *) arg;
        isp = tmd->cd_hba;
        if (isp == NULL) {
            printk(KERN_ERR "null isp @ %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
            break;
        }
        isp_target_start_ctio(isp, tmd);
        break;

    case QIN_TMD_FIN:
        tmd = (tmd_cmd_t *) arg;
        isp = tmd->cd_hba;
        if (isp == NULL) {
            printk(KERN_ERR "null isp @ %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
            break;
        }
        ISP_LOCK_SOFTC(isp);
        isp_prt(isp, ISP_LOGTDEBUG1, "freeing tmd %p [%llx]", tmd, tmd->cd_tagval);
/*      //printk("freeing tmd %p [%llx]", tmd, tmd->cd_tagval);
        if ((isp->isp_osinfo.tmflags & TM_TMODE_ENABLED) == 0) {
            isp_prt(isp, ISP_LOGTDEBUG1, "FIN with tm disabled");
            //printk("FIN with tm disabled");
            ISP_UNLK_SOFTC(isp);
            break;
        }
*/      
        if (tmd->cd_lflags & CDFL_CALL_CMPLT) {
            isp_prt(isp, ISP_LOGWARN, "CALL_CMPLT set for %llx, LFLAGS 0x%x", tmd->cd_tagval, tmd->cd_lflags);
            tmd->cd_lflags ^= CDFL_CALL_CMPLT;
        }
        
        if (tmd->cd_lflags & CDFL_RESRC_FILL) {
            if (isp_target_putback_atio(isp, tmd)) {
                    SEND_THREAD_EVENT(isp, ISP_THREAD_FC_PUTBACK, tmd, 0, __FUNCTION__, __LINE__);
                    ISP_UNLK_SOFTC(isp);
                    break;
            }
        }
        if (tmd->cd_lflags & CDFL_NEED_CLNUP) {
            tmd->cd_lflags &= ~CDFL_NEED_CLNUP;
            (void) isp_terminate_cmd(isp, tmd);
        }
        tmd->cd_hba = NULL;
        tmd->cd_lflags = 0;
        tmd->cd_next = NULL;
        /* don't zero cd_hflags or cd_tagval- it may be being used to catch duplicate frees */
        if (isp->isp_osinfo.tfreelist) {
            isp->isp_osinfo.bfreelist->cd_next = tmd;
        } else {
            isp->isp_osinfo.tfreelist = tmd;
        }
        isp->isp_osinfo.bfreelist = tmd; /* remember to move the list tail pointer */
        isp_prt(isp, ISP_LOGTDEBUG1, "DONE freeing tmd %p [%llx]", tmd, tmd->cd_tagval);
        ISP_UNLK_SOFTC(isp);
        break;

    case QIN_NOTIFY_ACK:
    {
        isp_notify_t *ins = (isp_notify_t *) arg;

        isp = ins->notify.nt_hba;
        if (isp == NULL) {
            printk(KERN_ERR "null isp @ %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
            break;
        }
        ISP_LOCK_SOFTC(isp);
        switch (ins->notify.nt_ncode) {
        case NT_HBA_RESET:
        case NT_LINK_UP:
        case NT_LINK_DOWN:
            isp_prt(isp, ISP_LOGINFO, "s/w notify code %x acked", ins->notify.nt_ncode);
            break;
        default:
            if (isp->isp_state != ISP_RUNSTATE) {
                isp_prt(isp, ISP_LOGINFO, "[%llx] Notify Code 0x%x (qevalid=%d) acked- h/w not ready (dropping)",
                    ins->notify.nt_tagval, ins->notify.nt_ncode, ins->qevalid);
            } else if (IS_24XX(isp) && ins->qevalid && ((isphdr_t *)ins->qentry)->rqs_entry_type == RQSTYPE_ABTS_RCVD) {
                abts_t *abt = (abts_t *)ins->qentry;
                abts_rsp_t *rsp = (abts_rsp_t *)ins->qentry;
                uint16_t rx_id, ox_id;

                isp_prt(isp, ISP_LOGINFO, "ABTS for 0x%x being BA_ACC'd", rsp->abts_rsp_rxid_abts);
                rx_id = abt->abts_rx_id;
                ox_id = abt->abts_ox_id;
                rsp->abts_rsp_header.rqs_entry_type = RQSTYPE_ABTS_RSP;
                rsp->abts_rsp_handle = rsp->abts_rsp_rxid_abts;
                rsp->abts_rsp_r_ctl = BA_ACC;
                MEMZERO(&rsp->abts_rsp_payload.ba_acc, sizeof (rsp->abts_rsp_payload.ba_acc));
                rsp->abts_rsp_payload.ba_acc.aborted_rx_id = rx_id;
                rsp->abts_rsp_payload.ba_acc.aborted_ox_id = ox_id;
                rsp->abts_rsp_payload.ba_acc.high_seq_cnt = 0xffff;
                isp_notify_ack(isp, ins->qentry);
            } else if (ins->notify.nt_need_ack) {
                isp_prt(isp, ISP_LOGDEBUG0, "[%llx] Notify Code 0x%x (qevalid=%d) being acked", ins->notify.nt_tagval, ins->notify.nt_ncode, ins->qevalid);
                if (ins->qevalid) {
                    isp_notify_ack(isp, ins->qentry);
                } else {
                    isp_notify_ack(isp, NULL);
                }
            }
            break;
        }
        ins->notify.nt_lreserved = isp->isp_osinfo.nfreelist;
        isp->isp_osinfo.nfreelist = ins;
        ISP_UNLK_SOFTC(isp);
        break;
    }
    case QIN_HBA_UNREG:
        hp = (hba_register_t *) arg;
        isp = hp->r_identity;
        if (isp == NULL) {
            printk(KERN_ERR "null isp @ %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
            break;
        }
        isp_prt(isp, ISP_LOGINFO, "completed target unregistration");
        ISP_LOCK_SOFTC(isp);
        isp->isp_osinfo.hcb = 0;
        if (hp->r_private) {
            struct semaphore *rsemap = hp->r_private;
            up(rsemap);
        }
        ISP_UNLK_SOFTC(isp);
        break;
    default:
        printk(KERN_ERR "isp_taction: unknown action %x, arg %p\n", action, arg);
        break;
    }
    if (isp) {
        isp_tgt_tq(isp);
    }
}

static void
isp_target_start_ctio(ispsoftc_t *isp, tmd_cmd_t *tmd)
{
    void *qe;
    uint32_t handle;
    uint32_t *rp;
    uint32_t nxti, optr;
    uint8_t local[QENTRY_LEN];
    unsigned long flags;

    /*
     * Check for commands that are already dead
     */
    if (tmd->cd_lflags & CDFL_ABORTED) {
        isp_prt(isp, ISP_LOGINFO, "[%llx] already ABORTED- not sending a CTIO", tmd->cd_tagval);
        tmd->cd_error = -ENXIO;
        tmd->cd_lflags |= CDFL_ERROR;
        ISP_LOCK_SOFTC(isp);
        goto out;
    }

    /*
     * If the transfer length is zero, we have to be sending status.
     * If we're sending data, we have to have one and only one data
     * direction set.
     */
    if (tmd->cd_xfrlen == 0) {
        if ((tmd->cd_hflags & CDFH_STSVALID) == 0) {
            isp_prt(isp, ISP_LOGERR, "CTIO, no data, and no status is wrong");
            tmd->cd_error = -EINVAL;
            tmd->cd_lflags |= CDFL_ERROR;
            ISP_LOCK_SOFTC(isp);
            goto out;
        }
    } else {
        if ((tmd->cd_hflags & CDFH_DATA_MASK) == 0) {
            isp_prt(isp, ISP_LOGERR, "data CTIO with no direction is wrong");
            tmd->cd_error = -EINVAL;
            tmd->cd_lflags |= CDFL_ERROR;
            ISP_LOCK_SOFTC(isp);
            goto out;
        }
        if ((tmd->cd_hflags & CDFH_DATA_MASK) == CDFH_DATA_MASK) {
            isp_prt(isp, ISP_LOGERR, "data CTIO with both directions is wrong");
            tmd->cd_error = -EINVAL;
            tmd->cd_lflags |= CDFL_ERROR;
            ISP_LOCK_SOFTC(isp);
            goto out;
        }
    }
    tmd->cd_lflags &= ~CDFL_ERROR;


    MEMZERO(local, QENTRY_LEN);

    ISP_LOCK_SOFTC(isp);
    if (isp_getrqentry(isp, &nxti, &optr, &qe)) {
        isp_prt(isp, ISP_LOGWARN, "%s: request queue overflow", __FUNCTION__);
        tmd->cd_error = -ENOMEM;
        tmd->cd_lflags |= CDFL_ERROR;
        goto out;
    }

    /*
     * We're either moving data or completing a command here (or both).
     */
    if (IS_24XX(isp)) {
        ct7_entry_t *cto = (ct7_entry_t *) local;

        cto->ct_header.rqs_entry_type = RQSTYPE_CTIO7;
        cto->ct_header.rqs_entry_count = 1;
        cto->ct_nphdl = tmd->cd_nphdl;
        cto->ct_rxid = tmd->cd_tagval;
        cto->ct_iid_lo = tmd->cd_portid;
        cto->ct_iid_hi = tmd->cd_portid >> 16;
        cto->ct_oxid = tmd->cd_oxid;
        cto->ct_scsi_status = tmd->cd_scsi_status;

        if (tmd->cd_xfrlen == 0) {
            cto->ct_flags |= CT7_FLAG_MODE1 | CT7_NO_DATA | CT7_SENDSTATUS;
            if ((tmd->cd_hflags & CDFH_SNSVALID) != 0) {
                cto->rsp.m1.ct_resplen = min(TMD_SENSELEN, MAXRESPLEN_24XX);
                MEMCPY(cto->rsp.m1.ct_resp, tmd->cd_sense, cto->rsp.m1.ct_resplen);
            }
        } else {
            cto->ct_flags |= CT7_FLAG_MODE0;
            if (tmd->cd_hflags & CDFH_DATA_IN) {
                cto->ct_flags |= CT7_DATA_IN;
            } else {
                cto->ct_flags |= CT7_DATA_OUT;
            }
            if (tmd->cd_hflags & CDFH_STSVALID) {
                cto->ct_flags |= CT7_SENDSTATUS;
            }
            /*
             * We assume we'll transfer what we say we'll transfer.
             * It should get added back in if we fail.
             */
            tmd->cd_resid -= tmd->cd_xfrlen;
        }

        if ((cto->ct_flags & CT7_SENDSTATUS) && tmd->cd_resid) {
            cto->ct_resid = tmd->cd_resid;
            cto->ct_scsi_status |= CT2_DATA_UNDER;  /* XXX SHOULD BE IN ISP_STDS.H */
        } else {
            cto->ct_resid = 0;
        }
        isp_prt(isp, ISP_LOGTDEBUG0, "CTIO7[%llx] ssts %x flags %x resid %d", tmd->cd_tagval, tmd->cd_scsi_status, cto->ct_flags, cto->ct_resid);
        rp = &cto->ct_resid;

    } else if (IS_FC(isp)) {
        ct2_entry_t *cto = (ct2_entry_t *) local;
        uint16_t *ssptr = NULL;

        cto->ct_header.rqs_entry_type = RQSTYPE_CTIO2;
        cto->ct_header.rqs_entry_count = 1;
        if (ISP_CAP_2KLOGIN(isp)) {
            ((ct2e_entry_t *)cto)->ct_iid = tmd->cd_nphdl;
        } else {
            cto->ct_iid = tmd->cd_nphdl;
        }
        if (ISP_CAP_SCCFW(isp)) {
            cto->ct_lun = 0;    /* unused for SCC fw */
        } else {
            cto->ct_lun = L0LUN_TO_FLATLUN(tmd->cd_lun);
        }
        cto->ct_rxid = AT2_GET_TAG(tmd->cd_tagval);
        if (cto->ct_rxid == 0) {
            isp_prt(isp, ISP_LOGERR, "a tagval of zero is not acceptable");
            tmd->cd_error = -EINVAL;
            tmd->cd_lflags |= CDFL_ERROR;
            goto out;
        }
#if    0
        /*
         * XXX: I've had problems with this at varying times- dunno why
         */
        cto->ct_flags = CT2_FASTPOST;
#else
        cto->ct_flags = 0;
#endif

        if (tmd->cd_xfrlen == 0) {
            cto->ct_flags |= CT2_FLAG_MODE1 | CT2_NO_DATA | CT2_SENDSTATUS;
            ssptr = &cto->rsp.m1.ct_scsi_status;
            *ssptr = tmd->cd_scsi_status;
            if ((tmd->cd_hflags & CDFH_SNSVALID) != 0) {
                cto->rsp.m1.ct_senselen = min(TMD_SENSELEN, MAXRESPLEN);
                MEMCPY(cto->rsp.m1.ct_resp, tmd->cd_sense, cto->rsp.m1.ct_senselen);
                cto->rsp.m1.ct_scsi_status |= CT2_SNSLEN_VALID;
            }
        } else {
            cto->ct_flags |= CT2_FLAG_MODE0;
            if (tmd->cd_hflags & CDFH_DATA_IN) {
                cto->ct_flags |= CT2_DATA_IN;
            } else {
                cto->ct_flags |= CT2_DATA_OUT;
            }
            if (tmd->cd_hflags & CDFH_STSVALID) {
                ssptr = &cto->rsp.m0.ct_scsi_status;
                cto->ct_flags |= CT2_SENDSTATUS;
                cto->rsp.m0.ct_scsi_status = tmd->cd_scsi_status;
                /*
                 * It will be up to the low level mapping routine
                 * to check for sense data.
                 */
            }
            /*
             * We assume we'll transfer what we say we'll transfer.
             * It should get added back in if we fail.
             */
            tmd->cd_resid -= tmd->cd_xfrlen;
        }

        if (ssptr && tmd->cd_resid) {
            cto->ct_resid = tmd->cd_resid;
            *ssptr |= CT2_DATA_UNDER;
        } else {
            cto->ct_resid = 0;
        }
        isp_prt(isp, ISP_LOGTDEBUG0, "CTIO2[%llx] ssts %x flags %x resid %d", tmd->cd_tagval, tmd->cd_scsi_status, cto->ct_flags, cto->ct_resid);
        rp = &cto->ct_resid;
        if (cto->ct_flags & CT2_SENDSTATUS) {
            cto->ct_flags |= CT2_CCINCR;
        }
    } else {
        ct_entry_t *cto = (ct_entry_t *) local;

        cto->ct_header.rqs_entry_type = RQSTYPE_CTIO;
        cto->ct_header.rqs_entry_count = 1;
        cto->ct_iid = tmd->cd_iid;
        cto->ct_tgt = tmd->cd_tgt;
        cto->ct_lun = L0LUN_TO_FLATLUN(tmd->cd_lun);
        cto->ct_flags = 0;
        cto->ct_fwhandle = AT_GET_HANDLE(tmd->cd_tagval);
        if (AT_HAS_TAG(tmd->cd_tagval)) {
            cto->ct_tag_val = AT_GET_TAG(tmd->cd_tagval);
            cto->ct_flags |= CT_TQAE;
        }
        if (tmd->cd_lflags & CDFL_NODISC) {
            cto->ct_flags |= CT_NODISC;
        }
        if (tmd->cd_xfrlen == 0) {
            cto->ct_flags |= CT_NO_DATA | CT_SENDSTATUS;
            cto->ct_scsi_status = tmd->cd_scsi_status;
            cto->ct_resid = 0;
        } else {
            if (tmd->cd_hflags & CDFH_STSVALID) {
                cto->ct_flags |= CT_SENDSTATUS;
            }
            if (tmd->cd_hflags & CDFH_DATA_IN) {
                cto->ct_flags |= CT_DATA_IN;
            } else {
                cto->ct_flags |= CT_DATA_OUT;
            }
            /*
             * We assume we'll transfer what we say we'll transfer.
             * Otherwise, the command is dead.
             */
            tmd->cd_resid -= tmd->cd_xfrlen;
            if (tmd->cd_hflags & CDFH_STSVALID) {
                cto->ct_resid = tmd->cd_resid;
            }
        }
        isp_prt(isp, ISP_LOGTDEBUG0, "CTIO[%llx] ssts %x resid %d cd_hflags %x", tmd->cd_tagval, tmd->cd_scsi_status, tmd->cd_resid, tmd->cd_hflags);
        rp = &cto->ct_resid;
        if (cto->ct_flags & CT_SENDSTATUS) {
            cto->ct_flags |= CT_CCINCR;
        }
    }

    if (isp_save_xs_tgt(isp, tmd, &handle)) {
        isp_prt(isp, ISP_LOGERR, "isp_target_start_ctio: No XFLIST pointers");
        tmd->cd_error = -ENOMEM;
        tmd->cd_lflags |= CDFL_ERROR;
        goto out;
    }

    if (IS_24XX(isp)) {
        ((ct7_entry_t *) local)->ct_syshandle = handle;
    } else if (IS_FC(isp)) {
        ((ct2_entry_t *) local)->ct_syshandle = handle;
    } else {
        ((ct_entry_t *) local)->ct_syshandle = handle;
    }

    /*
     * Call the dma setup routines for this entry (and any subsequent
     * CTIOs) if there's data to move, and then tell the f/w it's got
     * new things to play with. As with isp_start's usage of DMA setup,
     * any swizzling is done in the machine dependent layer. Because
     * of this, we put the request onto the queue area first in native
     * format.
     */

    switch (ISP_DMASETUP(isp, (XS_T *)tmd, (ispreq_t *) local, &nxti, optr)) {
    case CMD_QUEUED:
        ISP_ADD_REQUEST(isp, nxti);
        /*
         * If we're sending status, we're going to try and do resource replenish.
         * If the CTIO fails, we still do resource replenish, but handle it at
         * CTIO completion time.
         */
        if (tmd->cd_hflags & CDFH_STSVALID) {
            tmd->cd_lflags &= ~CDFL_RESRC_FILL;
        }
        ISP_UNLK_SOFTC(isp);
        return;

    case CMD_EAGAIN:
        tmd->cd_error = -ENOMEM;
        tmd->cd_lflags |= CDFL_ERROR;
        isp_destroy_tgt_handle(isp, handle);
        break;

    case CMD_COMPLETE:
        tmd->cd_error = *rp;    /* propagated back */
        tmd->cd_lflags |= CDFL_ERROR;
        isp_destroy_tgt_handle(isp, handle);
        break;

    default:
        tmd->cd_error = -EFAULT;    /* probably dma mapping failure */
        tmd->cd_lflags |= CDFL_ERROR;
        isp_destroy_tgt_handle(isp, handle);
        break;
    }
out:
    if ((tmd->cd_lflags & CDFL_LCL) == 0) {
        CALL_PARENT_TARGET(isp, tmd, QOUT_TMD_DONE);
    }
    ISP_UNLK_SOFTC(isp);
}

/*
 * Handle ATIO stuff that the generic code can't.
 * This means handling CDBs.
 */

static void
isp_handle_platform_atio(ispsoftc_t *isp, at_entry_t *aep)
{
    tmd_cmd_t *tmd;
    int status;

    isp->isp_osinfo.cmds_started++;
    /*
     * The firmware status (except for the QLTM_SVALID bit)
     * indicates why this ATIO was sent to us.
     *
     * If QLTM_SVALID is set, the firware has recommended Sense Data.
     *
     * If the DISCONNECTS DISABLED bit is set in the flags field,
     * we're still connected on the SCSI bus.
     */
    status = aep->at_status;

    if ((status & ~QLTM_SVALID) == AT_PHASE_ERROR) {
        /*
         * Bus Phase Sequence error. We should have sense data
         * suggested by the f/w. I'm not sure quite yet what
         * to do about this.
         */
        isp_prt(isp, ISP_LOGERR, "PHASE ERROR in atio");
        isp_endcmd(isp, aep, SCSI_BUSY, 0);
        return;
    }

    if ((status & ~QLTM_SVALID) != AT_CDB) {
        isp_prt(isp, ISP_LOGERR, "bad atio (0x%x) leaked to platform", status);
        isp_endcmd(isp, aep, SCSI_BUSY, 0);
        return;
    }

    if ((tmd = isp->isp_osinfo.tfreelist) == NULL) {
        /*
         * We're out of resources.
         *
         * Because we can't autofeed sense data back with a command for
         * parallel SCSI, we can't give back a CHECK CONDITION. We'll give
         * back a QUEUE FULL or BUSY status instead.
         */
        isp_prt(isp, ISP_LOGWARN, "out of TMDs for command from initiator %d for lun %u on channel %d",
            GET_IID_VAL(aep->at_iid), aep->at_lun, GET_BUS_VAL(aep->at_iid));
        if (aep->at_flags & AT_TQAE) {
            isp_endcmd(isp, aep, SCSI_QFULL, 0);
        } else {
            isp_endcmd(isp, aep, SCSI_BUSY, 0);
        }
        return;
    }
    if ((isp->isp_osinfo.tfreelist = tmd->cd_next) == NULL) {
        isp->isp_osinfo.bfreelist = NULL;
    }
    /*
     * Set the local flags to BUSY. Also set the flags
     * to force a resource replenish just in case we never
     * get around to sending a CTIO.
     */
    tmd->cd_lflags = CDFL_BUSY|CDFL_RESRC_FILL;
    tmd->cd_channel = GET_BUS_VAL(aep->at_iid);
    tmd->cd_iid = GET_IID_VAL(aep->at_iid);
    tmd->cd_tgt = aep->at_tgt;
    FLATLUN_TO_L0LUN(tmd->cd_lun, aep->at_lun);
    if (aep->at_flags & AT_NODISC) {
        tmd->cd_lflags |= CDFL_NODISC;
    }
    if (status & QLTM_SVALID) {
        MEMCPY(tmd->cd_sense, aep->at_sense, QLTM_SENSELEN);
        tmd->cd_lflags |= CDFL_SNSVALID;
    }
    MEMCPY(tmd->cd_cdb, aep->at_cdb, min(TMD_CDBLEN, ATIO_CDBLEN));
    AT_MAKE_TAGID(tmd->cd_tagval, tmd->cd_channel, isp->isp_unit, aep);
    tmd->cd_tagtype = aep->at_tag_type;
    tmd->cd_hba = isp;
    tmd->cd_data = NULL;
    tmd->cd_totlen = tmd->cd_resid = tmd->cd_xfrlen = tmd->cd_error = 0;
    tmd->cd_scsi_status = 0;
    isp_prt(isp, ISP_LOGTDEBUG1, "ATIO[%llx] CDB=0x%x bus %d iid%d->lun%d ttype 0x%x %s", tmd->cd_tagval, aep->at_cdb[0] & 0xff,
        GET_BUS_VAL(aep->at_iid), GET_IID_VAL(aep->at_iid), aep->at_lun, aep->at_tag_type,
        (aep->at_flags & AT_NODISC)? "nondisc" : "disconnecting");
    if (isp->isp_osinfo.hcb == 0) {
        tmd->cd_next = NULL;
        if (isp->isp_osinfo.tfreelist) {
            isp->isp_osinfo.bfreelist->cd_next = tmd;
        } else {
            isp->isp_osinfo.tfreelist = tmd;
        }
        isp->isp_osinfo.bfreelist = tmd;
        isp_endcmd(isp, aep, SCSI_BUSY, 0);
    } else {
        CALL_PARENT_TARGET(isp, tmd, QOUT_TMD_START);
    }
}

static void
isp_handle_platform_atio2(ispsoftc_t *isp, at2_entry_t *aep)
{
    tmd_cmd_t *tmd;
    int lun, iid;

    isp->isp_osinfo.cmds_started++;
    /*
     * The firmware status (except for the QLTM_SVALID bit)
     * indicates why this ATIO was sent to us.
     *
     * If QLTM_SVALID is set, the firware has recommended Sense Data.
     */
    if ((aep->at_status & ~QLTM_SVALID) != AT_CDB) {
        isp_prt(isp, ISP_LOGERR, "bad atio (0x%x) leaked to platform", aep->at_status);
        isp_endcmd(isp, aep, SCSI_BUSY, 0);
        return;
    }

    if (ISP_CAP_2KLOGIN(isp)) {
        at2e_entry_t *aep2 = (at2e_entry_t *) aep;
        lun = aep2->at_scclun;
        iid = aep2->at_iid;
    } else {
        iid = aep->at_iid;
        if (ISP_CAP_SCCFW(isp)) {
            lun = aep->at_scclun;
        } else {
            lun = aep->at_lun;
        }
    }

    /*
     * If we're out of resources, just send a QFULL status back.
     */
    if ((tmd = isp->isp_osinfo.tfreelist) == NULL) {
        isp_prt(isp, ISP_LOGWARN, "out of TMDs for command from 0x%016llx to lun %u",
            (((uint64_t) aep->at_wwpn[0]) << 48) |
            (((uint64_t) aep->at_wwpn[1]) << 32) |
            (((uint64_t) aep->at_wwpn[2]) << 16) |
            (((uint64_t) aep->at_wwpn[3]) <<  0), lun);
        isp_endcmd(isp, aep, SCSI_QFULL, 0);
        return;
    }
    if ((isp->isp_osinfo.tfreelist = tmd->cd_next) == NULL) {
        isp->isp_osinfo.bfreelist = NULL;
    }

    /*
     * Set the local flags to BUSY. Also set the flags
     * to force a resource replenish just in case we never
     * get around to sending a CTIO.
     */
    tmd->cd_lflags = CDFL_BUSY|CDFL_RESRC_FILL;
    tmd->cd_iid =
        (((uint64_t) aep->at_wwpn[0]) << 48) |
        (((uint64_t) aep->at_wwpn[1]) << 32) |
        (((uint64_t) aep->at_wwpn[2]) << 16) |
        (((uint64_t) aep->at_wwpn[3]) <<  0);
    tmd->cd_nphdl = iid;
    tmd->cd_nseg = 0;
    tmd->cd_tgt = ISP_PORTWWN(isp);
    FLATLUN_TO_L0LUN(tmd->cd_lun, lun);
    tmd->cd_channel = 0;
    MEMCPY(tmd->cd_cdb, aep->at_cdb, min(TMD_CDBLEN, ATIO2_CDBLEN));

    switch (aep->at_taskflags & ATIO2_TC_ATTR_MASK) {
    case ATIO2_TC_ATTR_SIMPLEQ:
        tmd->cd_tagtype = CD_SIMPLE_TAG;
        break;
    case ATIO2_TC_ATTR_HEADOFQ:
        tmd->cd_tagtype = CD_HEAD_TAG;
        break;
    case ATIO2_TC_ATTR_ORDERED:
        tmd->cd_tagtype = CD_ORDERED_TAG;
        break;
    case ATIO2_TC_ATTR_ACAQ:
        tmd->cd_tagtype = CD_ACA_TAG;
        break;
    case ATIO2_TC_ATTR_UNTAGGED:
    default:
        tmd->cd_tagtype = CD_UNTAGGED;
        break;
    }

    switch (aep->at_execodes & (ATIO2_EX_WRITE|ATIO2_EX_READ)) {
    case ATIO2_EX_WRITE:
        tmd->cd_lflags |= CDFL_DATA_OUT;
        break;
    case ATIO2_EX_READ:
        tmd->cd_lflags |= CDFL_DATA_IN;
        break;
    case ATIO2_EX_WRITE|ATIO2_EX_READ:
        tmd->cd_lflags |= CDFL_BIDIR;
        isp_prt(isp, ISP_LOGWARN, "ATIO2 with both read/write set");
        break;
    default:
        break;
    }

    AT2_MAKE_TAGID(tmd->cd_tagval, 0, isp->isp_unit, aep);
    tmd->cd_hba = isp;
    tmd->cd_data = NULL;
    tmd->cd_hflags = 0;
    tmd->cd_totlen = aep->at_datalen;
    tmd->cd_resid = tmd->cd_xfrlen = tmd->cd_error = 0;
    tmd->cd_scsi_status = 0;
    if ((isp->isp_dblev & ISP_LOGTDEBUG0) || isp->isp_osinfo.hcb == 0) {
        const char *sstr;
        switch (tmd->cd_lflags & CDFL_BIDIR) {
        default:
            sstr = "nodatadir";
            break;
        case CDFL_DATA_OUT:
            sstr = "DATA OUT";
            break;
        case CDFL_DATA_IN:
            sstr = "DATA IN";
            break;
        case CDFL_DATA_OUT|CDFL_DATA_IN:
            sstr = "BIDIR";
            break;
        }
        isp_prt(isp, ISP_LOGALL, "ATIO2[%llx] CDB=0x%x 0x%016llx for lun %d tcode 0x%x dlen %d %s", tmd->cd_tagval,
            aep->at_cdb[0] & 0xff, tmd->cd_iid, lun, aep->at_taskcodes, aep->at_datalen, sstr);
    }

    if (isp->isp_osinfo.hcb == 0) {
        tmd->cd_next = NULL;
        if (isp->isp_osinfo.tfreelist) {
            isp->isp_osinfo.bfreelist->cd_next = tmd;
        } else {
            isp->isp_osinfo.tfreelist = tmd;
        }
        isp->isp_osinfo.bfreelist = tmd;
        if (aep->at_cdb[0] == INQUIRY && lun == 0) {
            if (aep->at_cdb[1] == 0 && aep->at_cdb[2] == 0 && aep->at_cdb[3] == 0 && aep->at_cdb[5] == 0) {
                struct scatterlist *dp;
                int amt, idx;

                idx = tmd - isp->isp_osinfo.pool;
                dp = &isp->isp_osinfo.dpwrk[idx];
                MEMZERO(dp, sizeof (*dp));
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
                dp->address = (char *) isp->isp_osinfo.inqdata;
#else
                dp->page = virt_to_page(isp->isp_osinfo.inqdata);
                dp->offset = offset_in_page(isp->isp_osinfo.inqdata);
#endif
                dp->length = DEFAULT_INQSIZE;
                tmd->cd_xfrlen = min(DEFAULT_INQSIZE, tmd->cd_totlen);
                tmd->cd_data = dp;
                if ((amt = tmd->cd_cdb[4]) == 0) {
                    amt = 256;
                }
                if (tmd->cd_xfrlen > amt) {
                    tmd->cd_xfrlen = amt;
                }
                tmd->cd_resid = tmd->cd_totlen;
                tmd->cd_hflags |= CDFH_DATA_IN|CDFH_STSVALID;
                tmd->cd_lflags |= CDFL_LCL;
                ISP_DROP_LK_SOFTC(isp);
                isp_target_start_ctio(isp, tmd);
                ISP_IGET_LK_SOFTC(isp);
                return;
            } else {
                /*
                 * Illegal field in CDB
                 *  0x24 << 24 | 0x5 << 12 | ECMD_SVALID | SCSI_CHECK
                 */
                isp_endcmd(isp, aep, 0x24005102, 0);
            }
        } else if (lun == 0) {
            /*
             * Not Ready, Cause Not Reportable
             *
             *  0x4 << 24 | 0x2 << 12 | ECMD_SVALID | SCSI_CHECK
             */
            isp_endcmd(isp, aep, 0x04002102, 0);
        } else {
            /*
             * Logical Unit Not Supported:
             *     0x25 << 24 | 0x5 << 12 | ECMD_SVALID | SCSI_CHECK
             */
            isp_endcmd(isp, aep, 0x25005102, 0);
        }
        MEMZERO(tmd, TMD_SIZE);
        if (isp->isp_osinfo.tfreelist) {
            isp->isp_osinfo.bfreelist->cd_next = tmd;
        } else {
            isp->isp_osinfo.tfreelist = tmd;
        }
        isp->isp_osinfo.bfreelist = tmd;
        return;
    }
    CALL_PARENT_TARGET(isp, tmd, QOUT_TMD_START);
}

static void
isp_handle_platform_atio7(ispsoftc_t *isp, at7_entry_t *aep)
{
    int tattr, iulen, cdbxlen;
    uint16_t lun, hdl;
    uint32_t did, sid;
    uint64_t iid;
    fcportdb_t *lp;
    tmd_cmd_t *tmd;
    
    isp->isp_osinfo.cmds_started++;
    tattr = aep->at_ta_len >> 12;
    iulen = aep->at_ta_len & 0xffffff;

    did = (aep->at_hdr.d_id[0] << 16) | (aep->at_hdr.d_id[1] << 8) | aep->at_hdr.d_id[2];
    sid = (aep->at_hdr.s_id[0] << 16) | (aep->at_hdr.s_id[1] << 8) | aep->at_hdr.s_id[2];
    lun = (aep->at_cmnd.fcp_cmnd_lun[0] << 8) | aep->at_cmnd.fcp_cmnd_lun[1];

    /*
     * Find the WWN for this command in our port database.
     *
     * If we can't, we're somewhat in trouble because we can't actually respond w/o that information.
     */
/* XXXXXXXXXXXXXXXXXXXXXXXX NOT RIGHT FOR CHAN XXXXXXXXXXXXXXXXXXXXXXX */
    if (isp_find_pdb_sid(isp, 0, sid, &lp)) {
        hdl = lp->handle;
        iid = lp->port_wwn;
    } else {
        int i;
        /* look in our NPHDL cache */
        iid = INI_ANY;
        hdl = 0xffff;
        for (i = 0; i < TM_CS; i++) {
            if (isp->isp_osinfo.tgt_cache[i].portid == sid) {
                isp_prt(isp, ISP_LOGTDEBUG0, "[0x%x] assigning NPHDL from target cache", aep->at_rxid);
                hdl = isp->isp_osinfo.tgt_cache[i].nphdl;
                iid = isp->isp_osinfo.tgt_cache[i].iid;
                break;
            }
        }
    }

    /*
     * If we're out of resources, just send a QFULL status back.
     */
    if ((tmd = isp->isp_osinfo.tfreelist) == NULL) {
        isp_prt(isp, ISP_LOGWARN, "out of TMDs for command from 0x%06x to lun %u", sid, lun);
        aep->at_hdr.seq_id = hdl;   /* XXXX */
        isp_endcmd(isp, aep, SCSI_QFULL, 0);
        return;
    }
    if ((isp->isp_osinfo.tfreelist = tmd->cd_next) == NULL) {
        isp->isp_osinfo.bfreelist = NULL;
    }

    /*
     * Set the local flags to BUSY. Also set the flags
     * to force a resource replenish just in case we never
     * get around to sending a CTIO.
     */
    tmd->cd_lflags = CDFL_BUSY|CDFL_RESRC_FILL;

    cdbxlen = aep->at_cmnd.fcp_cmnd_alen_datadir >> FCP_CMND_ADDTL_CDBLEN_SHIFT;
    if (cdbxlen) {
        isp_prt(isp, ISP_LOGWARN, "XXX: additional CDBLEN ignored");
    }
    cdbxlen = sizeof (aep->at_cmnd.cdb_dl.sf.fcp_cmnd_cdb);
    MEMCPY(tmd->cd_cdb, aep->at_cmnd.cdb_dl.sf.fcp_cmnd_cdb, cdbxlen);
    tmd->cd_totlen = aep->at_cmnd.cdb_dl.sf.fcp_cmnd_dl;

    switch (aep->at_cmnd.fcp_cmnd_task_attribute & FCP_CMND_TASK_ATTR_MASK) {
    case FCP_CMND_TASK_ATTR_SIMPLE:
        tmd->cd_tagtype = CD_SIMPLE_TAG;
        break;
    case FCP_CMND_TASK_ATTR_HEAD:
        tmd->cd_tagtype = CD_HEAD_TAG;
        break;
    case FCP_CMND_TASK_ATTR_ORDERED:
        tmd->cd_tagtype = CD_ORDERED_TAG;
        break;
    case FCP_CMND_TASK_ATTR_ACA:
        tmd->cd_tagtype = CD_ACA_TAG;
        break;
    case FCP_CMND_TASK_ATTR_UNTAGGED:
        tmd->cd_tagtype = CD_UNTAGGED;
        break;
    default:
        isp_prt(isp, ISP_LOGWARN, "unknown task attribute %x", aep->at_cmnd.fcp_cmnd_task_attribute & FCP_CMND_TASK_ATTR_MASK);
        tmd->cd_tagtype = CD_UNTAGGED;
        break;
    }

    switch (aep->at_cmnd.fcp_cmnd_alen_datadir & FCP_CMND_DATA_DIR_MASK) {
    case FCP_CMND_DATA_WRITE:
        tmd->cd_lflags |= CDFL_DATA_OUT;
        break;
    case FCP_CMND_DATA_READ:
        tmd->cd_lflags |= CDFL_DATA_IN;
        break;
    case FCP_CMND_DATA_READ|FCP_CMND_DATA_WRITE:
        tmd->cd_lflags |= CDFL_BIDIR;
        isp_prt(isp, ISP_LOGINFO, "FCP_CMND_IU with both read/write set");
        break;
    default:
        break;
    }

    tmd->cd_tgt = ISP_PORTWWN(isp);
    FLATLUN_TO_L0LUN(tmd->cd_lun, lun);
    tmd->cd_portid = sid;
    tmd->cd_nphdl = hdl;
    tmd->cd_iid = iid;
    tmd->cd_channel = 0;
    tmd->cd_nseg = 0;
    /* XXX: bus/vpidx not known at this level! */
    AT2_MAKE_TAGID(tmd->cd_tagval, 0, 0, aep);
    tmd->cd_hba = isp;
    tmd->cd_data = NULL;
    tmd->cd_hflags = 0;
    tmd->cd_resid = 0;
    tmd->cd_xfrlen = 0;
    tmd->cd_error = 0;
    tmd->cd_scsi_status = 0;
    tmd->cd_oxid = aep->at_hdr.ox_id;
    if ((isp->isp_dblev & ISP_LOGTDEBUG0) || isp->isp_osinfo.hcb == 0) {
        const char *sstr;
        switch (tmd->cd_lflags & CDFL_BIDIR) {
        default:
            sstr = "nodatadir";
            break;
        case CDFL_DATA_OUT:
            sstr = "DATA OUT";
            break;
        case CDFL_DATA_IN:
            sstr = "DATA IN";
            break;
        case CDFL_DATA_OUT|CDFL_DATA_IN:
            sstr = "BIDIR";
            break;
        }
        if (tmd->cd_nphdl) {
            isp_prt(isp, ISP_LOGALL, "ATIO7[%llx] CDB=0x%x from 0x%016llx/0x%06x ox_id 0x%x for lun %u dlen %d %s", tmd->cd_tagval,
                tmd->cd_cdb[0] & 0xff, (unsigned long long) tmd->cd_iid, tmd->cd_portid, tmd->cd_oxid, lun, tmd->cd_totlen, sstr);
        } else {
            isp_prt(isp, ISP_LOGALL, "ATIO7[%llx] CDB=0x%x from (?)/0x%06x ox_id 0x%x for lun %u dlen %d %s", tmd->cd_tagval,
                tmd->cd_cdb[0] & 0xff, tmd->cd_portid, tmd->cd_oxid, lun, tmd->cd_totlen, sstr);
        }
    }

    if (tmd->cd_nphdl == 0xffff) {
        /*
         * We really don't know this S_ID. Terminate the exchange
         */
        SEND_THREAD_EVENT(isp, ISP_THREAD_TERMINATE, tmd, 0, __FUNCTION__, __LINE__);
        return;
    }

    if (isp->isp_osinfo.hcb == 0) {
        tmd->cd_next = NULL;
        if (isp->isp_osinfo.tfreelist) {
            isp->isp_osinfo.bfreelist->cd_next = tmd;
        } else {
            isp->isp_osinfo.tfreelist = tmd;
        }
        isp->isp_osinfo.bfreelist = tmd;
        if (tmd->cd_cdb[0] == INQUIRY && lun == 0) {
            if (tmd->cd_cdb[1] == 0 && tmd->cd_cdb[2] == 0 && tmd->cd_cdb[3] == 0 && tmd->cd_cdb[5] == 0) {
                struct scatterlist *dp;
                int amt, idx;

                idx = tmd - isp->isp_osinfo.pool;
                dp = &isp->isp_osinfo.dpwrk[idx];
                MEMZERO(dp, sizeof (*dp));
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
                dp->address = (char *) isp->isp_osinfo.inqdata;
#else
                dp->page = virt_to_page(isp->isp_osinfo.inqdata);
                dp->offset = offset_in_page(isp->isp_osinfo.inqdata);
#endif
                dp->length = DEFAULT_INQSIZE;
                tmd->cd_xfrlen = min(DEFAULT_INQSIZE, tmd->cd_totlen);
                tmd->cd_data = dp;
                if ((amt = tmd->cd_cdb[4]) == 0) {
                    amt = 256;
                }
                if (tmd->cd_xfrlen > amt) {
                    tmd->cd_xfrlen = amt;
                }
                tmd->cd_resid = tmd->cd_totlen;
                tmd->cd_hflags |= CDFH_DATA_IN|CDFH_STSVALID;
                tmd->cd_lflags |= CDFL_LCL;
                ISP_DROP_LK_SOFTC(isp);
                isp_target_start_ctio(isp, tmd);
                ISP_IGET_LK_SOFTC(isp);
                return;
            } else {
                /*
                 * Illegal field in CDB
                 *  0x24 << 24 | 0x5 << 12 | ECMD_SVALID | SCSI_CHECK
                 */
                aep->at_hdr.seq_id = tmd->cd_nphdl;
                isp_endcmd(isp, aep, 0x24005102, 0);
            }
        } else if (lun == 0) {
            /*
             * Not Ready, Cause Not Reportable
             *
             *  0x4 << 24 | 0x2 << 12 | ECMD_SVALID | SCSI_CHECK
             */
            aep->at_hdr.seq_id = tmd->cd_nphdl;
            isp_endcmd(isp, aep, 0x04002102, 0);
        } else {
            /*
             * Logical Unit Not Supported:
             *     0x25 << 24 | 0x5 << 12 | ECMD_SVALID | SCSI_CHECK
             */
            aep->at_hdr.seq_id = tmd->cd_nphdl;
            isp_endcmd(isp, aep, 0x25005102, 0);
        }
        MEMZERO(tmd, TMD_SIZE);
        if (isp->isp_osinfo.tfreelist) {
            isp->isp_osinfo.bfreelist->cd_next = tmd;
        } else {
            isp->isp_osinfo.tfreelist = tmd;
        }
        isp->isp_osinfo.bfreelist = tmd;
        return;
    }
    if (tmd->cd_iid == INI_ANY) {
        isp_prt(isp, ISP_LOGINFO, "[%llx] asking taskthread to find iid of initiator", tmd->cd_tagval);
        SEND_THREAD_EVENT(isp, ISP_THREAD_FINDIID, tmd, 0, __FUNCTION__, __LINE__);
    } else {
        CALL_PARENT_TARGET(isp, tmd, QOUT_TMD_START);
    }
}

/*
 * Terminate a command
 */
static int
isp_terminate_cmd(ispsoftc_t *isp, tmd_cmd_t *tmd)
{
    ct7_entry_t local, *cto = &local;;

    if (IS_24XX(isp)) {
        isp_prt(isp, ISP_LOGINFO, "isp_terminate_cmd: [%llx] is being terminated", tmd->cd_tagval);
        MEMZERO(&local, sizeof (local));
        cto->ct_header.rqs_entry_type = RQSTYPE_CTIO7;
        cto->ct_header.rqs_entry_count = 1;
        cto->ct_nphdl = tmd->cd_nphdl;
        cto->ct_rxid = AT2_GET_TAG(tmd->cd_tagval);
        cto->ct_vpindex = AT2_GET_BUS(tmd->cd_tagval);
        cto->ct_iid_lo = tmd->cd_portid;
        cto->ct_iid_hi = tmd->cd_portid >> 16;
        cto->ct_oxid = tmd->cd_oxid;
        cto->ct_flags = CT7_TERMINATE;
        cto->ct_syshandle = 0;
        return (isp_target_put_entry(isp, &local));
    } else {
        return (-1);
    }
}

static void
isp_handle_platform_ctio(ispsoftc_t *isp, void *arg)
{
    tmd_cmd_t *tmd;
    int sentstatus, ok, resid = 0, sts, id;

    /*
     * CTIO, CTIO2, and CTIO7 are close enough....
     */
    tmd = (tmd_cmd_t *) isp_find_xs_tgt(isp, ((ct_entry_t *)arg)->ct_syshandle);
    if (tmd == NULL) {
        isp_prt(isp, ISP_LOGERR, "isp_handle_platform_ctio: null tmd");
        return;
    }

    if (IS_24XX(isp)) {
        ct7_entry_t *ct = arg;
        isp_destroy_tgt_handle(isp, ct->ct_syshandle);
        sentstatus = ct->ct_flags & CT7_SENDSTATUS;
        if (sentstatus) {
            tmd->cd_lflags |= CDFL_SENTSTATUS;
        }
        sts = ct->ct_nphdl;
        ok = sts == CT7_OK;
        if (ok && sentstatus && (tmd->cd_hflags & CDFH_SNSVALID)) {
            tmd->cd_lflags |= CDFL_SENTSENSE;
        }
        isp_prt(isp, ISP_LOGTDEBUG1, "CTIO7[%llx] sts 0x%x flg 0x%x sns %d %s", tmd->cd_tagval, ct->ct_nphdl, ct->ct_flags,
            (tmd->cd_lflags & CDFL_SENTSENSE) != 0, sentstatus? "FIN" : "MID");
        if ((ct->ct_flags & CT7_DATAMASK) != CT7_NO_DATA) {
            resid = ct->ct_resid;
        }
        id = ct->ct_iid_lo | (ct->ct_iid_hi << 16);
    } else if (IS_FC(isp)) {
        ct2_entry_t *ct = arg;
        isp_destroy_tgt_handle(isp, ct->ct_syshandle);
        sentstatus = ct->ct_flags & CT2_SENDSTATUS;
        if (sentstatus) {
            tmd->cd_lflags |= CDFL_SENTSTATUS;
        }
        sts = ct->ct_status & ~QLTM_SVALID;
        ok = (ct->ct_status & ~QLTM_SVALID) == CT_OK;
        if (ok && sentstatus && (tmd->cd_hflags & CDFH_SNSVALID)) {
            tmd->cd_lflags |= CDFL_SENTSENSE;
        }
        isp_prt(isp, ISP_LOGTDEBUG1, "CTIO2[%llx] sts 0x%x flg 0x%x sns %d %s", tmd->cd_tagval, ct->ct_status, ct->ct_flags,
            (tmd->cd_lflags & CDFL_SENTSENSE) != 0, sentstatus? "FIN" : "MID");
        if ((ct->ct_flags & CT2_DATAMASK) != CT2_NO_DATA) {
            resid = ct->ct_resid;
        }
        id = ct->ct_iid;
    } else {
        ct_entry_t *ct = arg;
        isp_destroy_tgt_handle(isp, ct->ct_syshandle);
        sts = ct->ct_status & ~QLTM_SVALID;
        sentstatus = ct->ct_flags & CT_SENDSTATUS;
        if (sentstatus) {
            tmd->cd_lflags |= CDFL_SENTSTATUS;
        }
        ok = (ct->ct_status & ~QLTM_SVALID) == CT_OK;
        if (ok && sentstatus && (tmd->cd_hflags & CDFH_SNSVALID)) {
            tmd->cd_lflags |= CDFL_SENTSENSE;
        }
        isp_prt(isp, ISP_LOGTDEBUG1, "CTIO[%llx] loopid 0x%x tgt %d lun %d sts 0x%x flg %x %s", tmd->cd_tagval, ct->ct_iid, ct->ct_tgt, ct->ct_lun,
            ct->ct_status, ct->ct_flags, sentstatus? "FIN" : "MID");
        if (ct->ct_status & QLTM_SVALID) {
            char *sp = (char *)ct;
            sp += CTIO_SENSE_OFFSET;
            MEMCPY(tmd->cd_sense, sp, QLTM_SENSELEN);
            tmd->cd_lflags |= CDFL_SNSVALID;
        }
        if ((ct->ct_flags & CT_DATAMASK) != CT_NO_DATA) {
            resid = ct->ct_resid;
        }
        id = ct->ct_iid;
    }
    tmd->cd_resid += resid;

    /*
     * We're here either because intermediate data transfers are done
     * and/or the final status CTIO (which may have joined with a
     * Data Transfer) is done.
     *
     * In any case, for this platform, the upper layers figure out
     * what to do next, so all we do here is collect status and
     * pass information along.
     */
    isp_prt(isp, ISP_LOGTDEBUG0, "%s CTIO done (resid %d)", (sentstatus)? "  FINAL " : "MIDTERM ", tmd->cd_resid);

    if (!ok) {
        const char *cx;
        if (IS_24XX(isp)) {
            cx = "O7";
        } else if (IS_FC(isp)) {
            cx = "O2";
        } else {
            cx = "O";
        }
        if (sts == CT_ABORTED) {
            isp_prt(isp, ISP_LOGINFO, "[%llx] CTI%s aborted", tmd->cd_tagval, cx);
            tmd->cd_lflags |= CDFL_ABORTED;
        } else if (sts == CT_LOGOUT) {
            isp_prt(isp, ISP_LOGINFO, "[%llx] CTI%s killed by Port Logout", tmd->cd_tagval, cx);
        } else {
            isp_prt(isp, ISP_LOGINFO, "[%llx] CTI%s ended with badstate (0x%x)", tmd->cd_tagval, cx, sts);
        }
        tmd->cd_lflags |= CDFL_ERROR|CDFL_CALL_CMPLT;
        tmd->cd_error = -EIO;
        if (isp_target_putback_atio(isp, tmd)) {
            tmd->cd_lflags |= CDFL_RESRC_FILL;
            isp_complete_ctio(isp, tmd);
        }
        if (sts == CT_LOGOUT) {
            int i;

            for (i = 0; i < MAX_FC_TARG; i++) {
                if (FCPARAM(isp, tmd->cd_channel)->portdb[i].state != FC_PORTDB_STATE_VALID) {
                    continue;
                }
                if (IS_24XX(isp)) {
                    if (id != FCPARAM(isp, tmd->cd_channel)->portdb[i].portid) {
                        continue;
                    }
                } else {
                    if (id != FCPARAM(isp, tmd->cd_channel)->portdb[i].handle) {
                        continue;
                    }
                }
                SEND_THREAD_EVENT(isp, ISP_THREAD_LOGOUT, &FCPARAM(isp, tmd->cd_channel)->portdb[i], 0, __FUNCTION__, __LINE__);
                break;
            }
        }
    } else {
        isp_complete_ctio(isp, tmd);
    }
}

static int
isp_target_putback_atio(ispsoftc_t *isp, tmd_cmd_t *tmd)
{
    uint32_t nxti;
    uint8_t local[QENTRY_LEN];
    void *qe;

    tmd->cd_lflags &= ~CDFL_RESRC_FILL;
    if (IS_24XX(isp)) {
        if (tmd->cd_lflags & CDFL_CALL_CMPLT) {
            isp_complete_ctio(isp, tmd);
        }
        return (0);
    }
    if (isp_getrqentry(isp, &nxti, NULL, &qe)) {
        isp_prt(isp, ISP_LOGWARN, "%s: Request Queue Overflow", __FUNCTION__);
        return (-ENOMEM);
    }
    isp_prt(isp, ISP_LOGINFO, "[%llx] resource putback being sent", tmd->cd_tagval);
    MEMZERO(local, sizeof (local));
    if (IS_FC(isp)) {
        at2_entry_t *at = (at2_entry_t *) local;
        at->at_header.rqs_entry_type = RQSTYPE_ATIO2;
        at->at_header.rqs_entry_count = 1;
        at->at_status = CT_OK;
        at->at_rxid = AT2_GET_TAG(tmd->cd_tagval);
        if (ISP_CAP_2KLOGIN(isp)) {
            at2e_entry_t *ate = (at2e_entry_t *) local;
            FLATLUN_TO_L0LUN(tmd->cd_lun, ate->at_scclun);
        } else {
            if (ISP_CAP_SCCFW(isp)) {
                FLATLUN_TO_L0LUN(tmd->cd_lun, at->at_scclun);
            } else {
                FLATLUN_TO_L0LUN(tmd->cd_lun, at->at_lun);
            }
        }
        isp_put_atio2(isp, at, qe);
    } else {
        at_entry_t *at = (at_entry_t *)local;
        at->at_header.rqs_entry_type = RQSTYPE_ATIO;
        at->at_header.rqs_entry_count = 1;
        at->at_iid = tmd->cd_iid;
        at->at_iid |= tmd->cd_channel << 7;
        at->at_tgt = tmd->cd_tgt;
        FLATLUN_TO_L0LUN(tmd->cd_lun, at->at_lun);
        at->at_status = CT_OK;
        at->at_tag_val = AT_GET_TAG(tmd->cd_tagval);
        at->at_handle = AT_GET_HANDLE(tmd->cd_tagval);
        isp_put_atio(isp, at, qe);
    }
    ISP_TDQE(isp, "isp_target_putback_atio", isp->isp_reqidx, qe);
    ISP_ADD_REQUEST(isp, nxti);
    if (tmd->cd_lflags & CDFL_CALL_CMPLT) {
        isp_complete_ctio(isp, tmd);
    }
    return (0);
}

static void
isp_complete_ctio(ispsoftc_t *isp, tmd_cmd_t *tmd)
{
    isp->isp_osinfo.cmds_completed++;
    tmd->cd_lflags &= ~CDFL_CALL_CMPLT;
    if (isp->isp_osinfo.hcb || (tmd->cd_lflags & CDFL_LCL)) {
        if (isp->isp_osinfo.hcb == 0) {
            isp_prt(isp, ISP_LOGWARN, "nobody to tell about CTIO complete");
            MEMZERO(tmd, TMD_SIZE);
            if (isp->isp_osinfo.tfreelist) {
                isp->isp_osinfo.bfreelist->cd_next = tmd;
            } else {
                isp->isp_osinfo.tfreelist = tmd;
            }
            isp->isp_osinfo.bfreelist = tmd;
        } else {
            CALL_PARENT_TARGET(isp, tmd, QOUT_TMD_DONE);
        }
    }
}

int
isp_en_dis_lun(ispsoftc_t *isp, int enable, uint16_t bus, uint64_t tgt, uint16_t lun)
{
    DECLARE_MUTEX_LOCKED(rsem);
    uint16_t rstat;
    mbreg_t mbs;
    int rv, benabled, cmd;
    unsigned long flags;

    /*
     * First, we can't do anything unless we have an upper
     * level target driver to route commands to.
     */
    if (isp->isp_osinfo.hcb == 0) {
        return (-EINVAL);
    }

    /*
     * Check for overflows
     */
    if (IS_FC(isp)) {
        if (bus >= min(isp->isp_nchan, TM_MAX_BUS_FC)) {
            isp_prt(isp, ISP_LOGERR, "bad channel %u- max is %u", bus, TM_MAX_BUS_FC);
            return (-EINVAL);
        }
        if (lun != LUN_ANY) {
            isp_prt(isp, ISP_LOGERR, "only wildcard luns supported for fibre channel cards");
            return (-EINVAL);
        }
    } else {
        if (bus >= min(isp->isp_nchan, TM_MAX_BUS_SPI)) {
            isp_prt(isp, ISP_LOGERR, "bad channel %u- max is %u", bus, TM_MAX_BUS_SPI);
            return (-EINVAL);
        }
        if (lun == LUN_ANY) {
            isp_prt(isp, ISP_LOGERR, "wildcard luns prohibited lun SPI");
            return (-EINVAL);
        }
        if (lun >= TM_MAX_LUN_SPI) {
            isp_prt(isp, ISP_LOGERR, "bad lun %u- max is %u", lun, TM_MAX_LUN_SPI);
            return (-EINVAL);
        }
    }

    /*
     * Second, check for sanity of enable argument.
     */
    benabled = ISP_BTST(isp->isp_osinfo.benabled, bus);
    if (enable == 0 && benabled == 0) {
        return (-EINVAL);
    }

    /*
     * Third, check to see if we're enabling on fibre channel
     * and don't yet have a notion of who the heck we are (no
     * loop yet).
     */
    if (IS_FC(isp)) {
        if (enable && benabled == 0) {
            ISP_LOCK_SOFTC(isp);
            if ((isp->isp_role & ISP_ROLE_TARGET) == 0) {
                isp->isp_role |= ISP_ROLE_TARGET;
                if (isp_drain_reset(isp, "lun enables")) {
                    ISP_UNLK_SOFTC(isp);
                    return (-EIO);
                }
            }
            ISP_UNLK_SOFTC(isp);
            SEND_THREAD_EVENT(isp, ISP_THREAD_FC_RESCAN, FCPARAM(isp, bus), 1, __FUNCTION__, __LINE__);
            ISP_BSET(isp->isp_osinfo.benabled, bus);
        }
        if (enable && benabled) {
            return (0);
        }
    } else {
        int lenabled = ISP_BTST(isp->isp_osinfo.spi_lun_enabled[bus], lun);

        if (enable && lenabled) {
            return (-EEXIST);
        }

        if (enable == 0 && lenabled == 0) {
            return (-ENODEV);
        }

        if (enable && benabled == 0) {
            MEMZERO(&mbs, sizeof (mbs));
			mbs.param[0] = MBOX_ENABLE_TARGET_MODE;
			mbs.param[1] = ENABLE_TARGET_FLAG;
			mbs.param[2] = bus;
			mbs.logval = MBLOGALL;
            ISP_LOCK_SOFTC(isp);
            rv = isp_control(isp, ISPCTL_RUN_MBOXCMD, &mbs);
            ISP_UNLK_SOFTC(isp);
            if (rv || mbs.param[0] != MBOX_COMMAND_COMPLETE) {
                return (-EIO);
            }
            ISP_BSET(isp->isp_osinfo.benabled, bus);
        }
    }

    /*
     * If this is a wildcard target, select our initiator
     * id/loop id for use as what we enable as.
     */
    if (tgt == TGT_ANY) {
        if (IS_FC(isp)) {
            tgt = FCPARAM(isp, bus)->isp_loopid;
        } else {
            tgt = SDPARAM(isp, bus)->isp_initiator_id;
        }
    }

    /*
     * Snag the semaphore on the return state value on enables/disables.
     */
    if (down_interruptible(&isp->isp_osinfo.tgt_inisem)) {
        return (-EINTR);
    }

    ISP_LOCK_SOFTC(isp);
    isp->isp_osinfo.rsemap = &rsem;
    if (IS_24XX(isp)) {
        rstat = LUN_OK;
    } else if (enable) {
        uint16_t ulun = lun;

        cmd = RQSTYPE_ENABLE_LUN;
        if (IS_FC(isp)) {
            ulun = 0;
        }
        rstat = LUN_ERR;
        if (isp_lun_cmd(isp, cmd, bus, tgt, ulun, DFLT_CMND_CNT, DFLT_INOT_CNT)) {
            isp_prt(isp, ISP_LOGERR, "isp_lun_cmd failed");
            goto out;
        }
        ISP_UNLK_SOFTC(isp);
        down(isp->isp_osinfo.rsemap);
        ISP_LOCK_SOFTC(isp);
        isp->isp_osinfo.rsemap = NULL;
        rstat = isp->isp_osinfo.rstatus;
        if (rstat != LUN_OK) {
            isp_prt(isp, ISP_LOGERR, "MODIFY/ENABLE LUN returned 0x%x", rstat);
            goto out;
        }
    } else {
        uint16_t ulun = lun;

        rstat = LUN_ERR;
        cmd = -RQSTYPE_MODIFY_LUN;

        if (IS_FC(isp) && lun != 0) {
            ulun = 0;
        }
        if (isp_lun_cmd(isp, cmd, bus, tgt, ulun, DFLT_CMND_CNT, DFLT_INOT_CNT)) {
            isp_prt(isp, ISP_LOGINFO, "isp_lun_cmd failed");
            /* but proceed anyway */
            rstat = LUN_OK;
        }
        ISP_UNLK_SOFTC(isp);
        down(isp->isp_osinfo.rsemap);
        ISP_LOCK_SOFTC(isp);
        isp->isp_osinfo.rsemap = NULL;
        rstat = isp->isp_osinfo.rstatus;
        if (rstat != LUN_OK) {
            isp_prt(isp, ISP_LOGINFO, "MODIFY LUN returned 0x%x", rstat);
            /* but proceed anyway */
            rstat = LUN_OK;
        }
        isp->isp_osinfo.rsemap = &rsem;

        rstat = LUN_ERR;
        cmd = -RQSTYPE_ENABLE_LUN;
        if (isp_lun_cmd(isp, cmd, bus, tgt, ulun, 0, 0)) {
            isp_prt(isp, ISP_LOGERR, "isp_lun_cmd failed");
            goto out;
        }
        ISP_UNLK_SOFTC(isp);
        down(isp->isp_osinfo.rsemap);
        ISP_LOCK_SOFTC(isp);
        isp->isp_osinfo.rsemap = NULL;
        rstat = isp->isp_osinfo.rstatus;
        if (rstat != LUN_OK) {
            isp_prt(isp, ISP_LOGINFO, "DISABLE LUN returned 0x%x", rstat);
            /* but proceed anyway */
            rstat = LUN_OK;
        }
    }
out:

    if (rstat != LUN_OK) {
        isp_prt(isp, ISP_LOGERR, "lun %d %sable failed", lun, (enable) ? "en" : "dis");
        ISP_UNLK_SOFTC(isp);
        up(&isp->isp_osinfo.tgt_inisem);
        return (-EIO);
    } else {
        if (IS_FC(isp)) {
            isp_prt(isp, ISP_LOGINFO, "All luns now %sabled for target mode on channel %d", (enable)? "en" : "dis", bus);
        } else {
            isp_prt(isp, ISP_LOGINFO, "lun %u now %sabled for target mode on channel %d", lun, (enable)? "en" : "dis", bus);
        }
        if (enable == 0) {
            if (IS_SCSI(isp)) {
                int i, j;

                ISP_BCLR(isp->isp_osinfo.spi_lun_enabled[bus], lun);
                for (i = 0; i < TM_MAX_BUS_SPI; i++) {
                    for (j = 0; j < ISP_NBPIDX(TM_MAX_LUN_SPI); j++) {
                        if (isp->isp_osinfo.spi_lun_enabled[i][j]) {
                            break;
                        }
                    }
                    if (j < ISP_NBPIDX(TM_MAX_LUN_SPI)) {
                        break;
                    }
                }
                if (i < TM_MAX_BUS_SPI) {
                    MEMZERO(&mbs, sizeof (mbs));
                    mbs.param[0] = MBOX_ENABLE_TARGET_MODE;
                    mbs.param[1] = 0;
                    mbs.param[2] = bus;
                    mbs.logval = MBLOGALL;
                    ISP_LOCK_SOFTC(isp);
                    (void) isp_control(isp, ISPCTL_RUN_MBOXCMD, &mbs);
                    ISP_UNLK_SOFTC(isp);
                    ISP_BCLR(isp->isp_osinfo.benabled, bus);
                    benabled = 0;
                }
            } else {
                isp->isp_role &= ~ISP_ROLE_TARGET;
                if (isp_drain_reset(isp, "lun disables") == 0) {
                    if ((isp->isp_role & ISP_ROLE_INITIATOR) != 0) {
                        ISP_UNLK_SOFTC(isp);
                        SEND_THREAD_EVENT(isp, ISP_THREAD_FC_RESCAN, FCPARAM(isp, bus), 1, __FUNCTION__, __LINE__);
                        ISP_LOCK_SOFTC(isp);
                    }
                }
                benabled = 0;
            }
            if (benabled == 0) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
                /*
                 * Can now unload.
                 */
                MOD_DEC_USE_COUNT;
#else
                if (isp->isp_osinfo.isget) {
                    isp->isp_osinfo.isget = 0;
                    ISP_UNLK_SOFTC(isp);
                    module_put(isp->isp_osinfo.host->hostt->module);
                    ISP_LOCK_SOFTC(isp);
                }
#endif
            }
        } else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
            isp->isp_osinfo.isget = 1;
            /*
             * Stay loaded while we have any enabled luns
             */
            MOD_INC_USE_COUNT;
#else
            ISP_UNLK_SOFTC(isp);
            if (try_module_get(isp->isp_osinfo.host->hostt->module)) {
                ISP_LOCK_SOFTC(isp);
                isp->isp_osinfo.isget = 1;
            } else {
                ISP_LOCK_SOFTC(isp);
                isp->isp_osinfo.isget = 0;
            }
#endif
            if (IS_SCSI(isp)) {
                ISP_BSET(isp->isp_osinfo.spi_lun_enabled[bus], lun);
            }
        }
        ISP_UNLK_SOFTC(isp);
        up(&isp->isp_osinfo.tgt_inisem);
        return (0);
    }
}
#endif

void
isp_async(ispsoftc_t *isp, ispasync_t cmd, ...)
{
    static const char prom[] = "PortID 0x%06x handle 0x%x role %s %s WWNN 0x%016llx WWPN 0x%016llx";
    static const char prom2[] = "PortID 0x%06x handle 0x%x role %s %s tgt %u WWNN 0x%016llx WWPN 0x%016llx";
    fcportdb_t *lp;
    va_list ap;
    int bus, tgt;

    switch (cmd) {
    case ISPASYNC_NEW_TGT_PARAMS:
        if (IS_SCSI(isp)) {
            sdparam *sdp;
            char *wt;
            int mhz, flags, period;

            va_start(ap, cmd);
            bus = va_arg(ap, int);
            tgt = va_arg(ap, int);
            va_end(ap);

            sdp = SDPARAM(isp, bus);

            flags = sdp->isp_devparam[tgt].actv_flags;
            period = sdp->isp_devparam[tgt].actv_period;
            if ((flags & DPARM_SYNC) && period && (sdp->isp_devparam[tgt].actv_offset) != 0) {
                if (sdp->isp_lvdmode || period < 0xc) {
                    switch (period) {
                        case 0x9:
                        mhz = 80;
                        break;
                    case 0xa:
                        mhz = 40;
                        break;
                    case 0xb:
                        mhz = 33;
                        break;
                    case 0xc:
                        mhz = 25;
                        break;
                    default:
                        mhz = 1000 / (period * 4);
                        break;
                    }
                } else {
                    mhz = 1000 / (period * 4);
                }
            } else {
                mhz = 0;
            }
            switch (flags & (DPARM_WIDE|DPARM_TQING)) {
            case DPARM_WIDE:
                wt = ", 16 bit wide";
                break;
            case DPARM_TQING:
                wt = ", Tagged Queueing Enabled";
                break;
            case DPARM_WIDE|DPARM_TQING:
                wt = ", 16 bit wide, Tagged Queueing Enabled";
                break;
            default:
                wt = " ";
                break;
            }
            if (mhz) {
                isp_prt(isp, ISP_LOGINFO, "Channel %d Target %d at %dMHz Max Offset %d%s", bus, tgt, mhz, sdp->isp_devparam[tgt].actv_offset, wt);
            } else {
                isp_prt(isp, ISP_LOGINFO, "Channel %d Target %d Async Mode%s", bus, tgt, wt);
            }
        }
        break;
    case ISPASYNC_LIP:
        isp_prt(isp, ISP_LOGINFO, "LIP Received");
        break;
    case ISPASYNC_LOOP_RESET:
        isp_prt(isp, ISP_LOGINFO, "Loop Reset Received");
        break;
    case ISPASYNC_BUS_RESET:
        va_start(ap, cmd);
        bus = va_arg(ap, int);
        va_end(ap);
        isp_prt(isp, ISP_LOGINFO, "SCSI bus %d reset detected", bus);
        break;
    case ISPASYNC_LOOP_DOWN:
        isp_prt(isp, ISP_LOGINFO, "Loop DOWN");
        break;
    case ISPASYNC_LOOP_UP:
        isp_prt(isp, ISP_LOGINFO, "Loop UP");
        break;
    case ISPASYNC_DEV_ARRIVED:
        va_start(ap, cmd);
        bus = va_arg(ap, int);
        lp = va_arg(ap, fcportdb_t *);
        va_end(ap);
        if ((isp->isp_role & ISP_ROLE_INITIATOR) && (lp->roles & (SVC3_TGT_ROLE >> SVC3_ROLE_SHIFT))) {
            int dbidx = lp - FCPARAM(isp, bus)->portdb;
            int i;

            for (i = 0; i < MAX_FC_TARG; i++) {
                if (i >= FL_ID && i <= SNS_ID) {
                    continue;
                }
                if (FCPARAM(isp, bus)->isp_ini_map[i] == 0) {
                    break;
                }
            }
            if (i < MAX_FC_TARG) {
                FCPARAM(isp, bus)->isp_ini_map[i] = dbidx + 1;
                lp->ini_map_idx = i + 1;
            } else {
                isp_prt(isp, ISP_LOGWARN, "out of target ids");
                isp_dump_portdb(isp, bus);
            }
        }
        if (lp->ini_map_idx) {
            tgt = lp->ini_map_idx - 1;
            isp_prt(isp, ISP_LOGCONFIG, prom2, lp->portid, lp->handle, class3_roles[lp->roles], "arrived at", tgt, lp->node_wwn, lp->port_wwn);
        } else {
            isp_prt(isp, ISP_LOGCONFIG, prom, lp->portid, lp->handle, class3_roles[lp->roles], "arrived", lp->node_wwn, lp->port_wwn);
        }
        break;
    case ISPASYNC_DEV_CHANGED:
        va_start(ap, cmd);
        bus = va_arg(ap, int);
        lp = va_arg(ap, fcportdb_t *);
        va_end(ap);
        lp->portid = lp->new_portid;
        lp->roles = lp->new_roles;
        if (lp->ini_map_idx) {
            int t = lp->ini_map_idx - 1;
            FCPARAM(isp, bus)->isp_ini_map[t] = (lp - FCPARAM(isp, bus)->portdb) + 1;
            tgt = lp->ini_map_idx - 1;
            isp_prt(isp, ISP_LOGCONFIG, prom2, lp->portid, lp->handle, class3_roles[lp->roles], "changed at", tgt, lp->node_wwn, lp->port_wwn);
        } else {
            isp_prt(isp, ISP_LOGCONFIG, prom, lp->portid, lp->handle, class3_roles[lp->roles], "changed", lp->node_wwn, lp->port_wwn);
        }
        break;
    case ISPASYNC_DEV_STAYED:
        va_start(ap, cmd);
        bus = va_arg(ap, int);
        lp = va_arg(ap, fcportdb_t *);
        va_end(ap);
        if (lp->ini_map_idx) {
            tgt = lp->ini_map_idx - 1;
            isp_prt(isp, ISP_LOGCONFIG, prom2, lp->portid, lp->handle, class3_roles[lp->roles], "stayed at", tgt, lp->node_wwn, lp->port_wwn);
        } else {
            isp_prt(isp, ISP_LOGCONFIG, prom, lp->portid, lp->handle, class3_roles[lp->roles], "stayed", lp->node_wwn, lp->port_wwn);
        }
        break;
    case ISPASYNC_DEV_GONE:
        va_start(ap, cmd);
        bus = va_arg(ap, int);
        lp = va_arg(ap, fcportdb_t *);
        va_end(ap);
        if (lp->ini_map_idx) {
            tgt = lp->ini_map_idx - 1;
            FCPARAM(isp, bus)->isp_ini_map[tgt] = 0;
            lp->state = FC_PORTDB_STATE_NIL;
            lp->ini_map_idx = 0;
            isp_prt(isp, ISP_LOGCONFIG, prom2, lp->portid, lp->handle, class3_roles[lp->roles], "departed", tgt, lp->node_wwn, lp->port_wwn);
        } else if (lp->reserved == 0) {
            isp_prt(isp, ISP_LOGCONFIG, prom, lp->portid, lp->handle, class3_roles[lp->roles], "departed", lp->node_wwn, lp->port_wwn);
        }
        break;
    case ISPASYNC_CHANGE_NOTIFY:
    {
        int chg;

        va_start(ap, cmd);
        bus = va_arg(ap, int);
        chg = va_arg(ap, int);
        va_end(ap);
        if (chg == ISPASYNC_CHANGE_PDB) {
            isp_prt(isp, ISP_LOGINFO, "Port Database Changed");
        } else if (chg == ISPASYNC_CHANGE_SNS) {
            isp_prt(isp, ISP_LOGINFO, "Name Server Database Changed");
        } else {
            isp_prt(isp, ISP_LOGINFO, "Other Change Notify");
        }
        if (isp->isp_state >= ISP_INITSTATE) {
            SEND_THREAD_EVENT(isp, ISP_THREAD_FC_RESCAN, FCPARAM(isp, bus), 0, __FUNCTION__, __LINE__);
        }
        break;
    }
#ifdef    ISP_TARGET_MODE
    case ISPASYNC_TARGET_NOTIFY:
    {
        isp_notify_t *ins;
        tmd_notify_t *mp;

        va_start(ap, cmd);
        mp = va_arg(ap, tmd_notify_t *);
        va_end(ap);

        if (isp->isp_osinfo.hcb == 0) {
            isp_prt(isp, ISP_LOGWARN, "ISPASYNC_TARGET_NOTIFY with target mode not enabled");
            isp_notify_ack(isp, mp->nt_lreserved);
            break;
        }

        ins = isp->isp_osinfo.nfreelist;
        if (ins == NULL) {
            isp_prt(isp, ISP_LOGERR, "out of TMD NOTIFY structs");
            isp_notify_ack(isp, mp->nt_lreserved);
            break;
        }
        isp->isp_osinfo.nfreelist = ins->notify.nt_lreserved;

        MEMCPY(&ins->notify, mp, sizeof (tmd_notify_t));
        if (mp->nt_lreserved) {
            MEMCPY(ins->qentry, mp->nt_lreserved, QENTRY_LEN);
            ins->qevalid = 1;
        } else {
            ins->qevalid = 0;
        }
        mp = &ins->notify;

        if (IS_24XX(isp)) {
            fcportdb_t *lp;
            at7_entry_t *aep = mp->nt_lreserved;
            uint32_t sid;
            int i;

            if (aep) {
                sid = (aep->at_hdr.s_id[0] << 16) | (aep->at_hdr.s_id[1] << 8) | aep->at_hdr.s_id[2];
            } else {
                sid = 0xffffff;
            }
            switch (mp->nt_ncode) {
            case NT_HBA_RESET:
            case NT_LINK_UP:
            case NT_LINK_DOWN:
                break;
            case NT_LUN_RESET:
            case NT_TARGET_RESET:
                /*
                 * Mark all pertinent commands as dead and needing cleanup.
                 */
                for (i = 0; i < NTGT_CMDS; i++) {
                    tmd_cmd_t *tmd = &isp->isp_osinfo.pool[i];
                    if (tmd->cd_lflags & CDFL_BUSY) {
                        if (mp->nt_lun == LUN_ANY || mp->nt_lun == L0LUN_TO_FLATLUN(tmd->cd_lun)) {
                            tmd->cd_lflags |= CDFL_ABORTED|CDFL_NEED_CLNUP;
                        }
                    }
                }
                /* FALLTHROUGH */
            default:
                if (isp_find_pdb_sid(isp, mp->nt_channel, sid, &lp)) {
                    mp->nt_iid = lp->port_wwn;
                }
                break;
            }

            /*
             * Replace target with our port WWN.
             */
            mp->nt_tgt = ISP_PORTWWN(isp);
        } else if (IS_FC(isp)) {
            uint16_t loopid;

            FC_TAG_INSERT_INST(mp->nt_tagval, isp->isp_unit);
            /*
             * The outer layer just set the loopid into nt_iid. We try and find the WWPN.
             */
            loopid = ins->notify.nt_iid;
            switch (mp->nt_ncode) {
            case NT_HBA_RESET:
            case NT_LINK_UP:
            case NT_LINK_DOWN:
                ins->notify.nt_iid = INI_ANY;
                break;
            default:
                if (isp_find_iid_wwn(isp, mp->nt_channel, loopid, &ins->notify.nt_iid) == 0) {
                    isp_prt(isp, ISP_LOGDEBUG0, "cannot find WWN for loopid 0x%x for notify action 0x%x", loopid, mp->nt_ncode);
                    ins->notify.nt_iid = INI_ANY;
                }
                break;
            }
            /*
             * Replace target with our port WWN.
             */
            mp->nt_tgt = ISP_PORTWWN(isp);
        } else {
            TAG_INSERT_INST(mp->nt_tagval, isp->isp_unit);
        }
        isp_prt(isp, ISP_LOGDEBUG0, "Notify Code 0x%x iid 0x%016llx tgt 0x%016llx lun %u tag %llx",
            mp->nt_ncode, (unsigned long long) mp->nt_iid, (unsigned long long) mp->nt_tgt,
            mp->nt_lun, mp->nt_tagval);
        CALL_PARENT_NOTIFY(isp, ins);
        break;
    }
    case ISPASYNC_TARGET_ACTION:
    {
        void *qe;

        va_start(ap, cmd);
        qe = va_arg(ap, void *);
        va_end(ap);

        switch (((isphdr_t *)qe)->rqs_entry_type) {
        case RQSTYPE_ATIO:
            if (IS_24XX(isp)) {
                isp_handle_platform_atio7(isp, (at7_entry_t *) qe);
            } else {
                isp_handle_platform_atio(isp, (at_entry_t *) qe);
            }
            break;
        case RQSTYPE_ATIO2:
            isp_handle_platform_atio2(isp, (at2_entry_t *)qe);
            break;
        case RQSTYPE_CTIO7:
        case RQSTYPE_CTIO3:
        case RQSTYPE_CTIO2:
        case RQSTYPE_CTIO:
            isp_handle_platform_ctio(isp, qe);
            break;
        case RQSTYPE_ENABLE_LUN:
        case RQSTYPE_MODIFY_LUN:
            isp->isp_osinfo.rstatus = ((lun_entry_t *)qe)->le_status;
            if (isp->isp_osinfo.rsemap) {
                up(isp->isp_osinfo.rsemap);
            }
            break;
        case RQSTYPE_ABTS_RCVD:
        {
            isp_notify_t *ins = NULL;
            abts_t *abts = qe;
            abts_rsp_t *rsp = qe;
            int i;

            if (isp->isp_osinfo.hcb == 0) {
                isp_prt(isp, ISP_LOGINFO, "RQSTYPE_ABTS_RCVD: with no upstream listener");
                rsp->abts_rsp_handle = rsp->abts_rsp_rxid_abts;
                rsp->abts_rsp_ctl_flags = ISP24XX_ABTS_RSP_TERMINATE;
                isp_notify_ack(isp, qe);
                break;
            }
            ins = isp->isp_osinfo.nfreelist;
            if (ins == NULL) {
                isp_prt(isp, ISP_LOGINFO, "out of TMD NOTIFY structs for RQSTYPE_ABTS_RCVD!");
                rsp->abts_rsp_handle = rsp->abts_rsp_rxid_abts;
                rsp->abts_rsp_ctl_flags = ISP24XX_ABTS_RSP_TERMINATE;
                isp_notify_ack(isp, qe);
                break;
            }
            isp->isp_osinfo.nfreelist = ins->notify.nt_lreserved;
            MEMZERO(&ins->notify, sizeof (tmd_notify_t));
/* XXXXXXXXXXXXXXX NOT RIGHT FOR CHANNEL XXXXXXXXXXXXXXXX */
            if (isp_find_iid_wwn(isp, 0, abts->abts_nphdl, &ins->notify.nt_iid) == 0) {
                isp_prt(isp, ISP_LOGINFO, "cannot find WWN for N-port handle 0x%x for ABTS", abts->abts_nphdl);
                rsp->abts_rsp_handle = rsp->abts_rsp_rxid_abts;
                rsp->abts_rsp_ctl_flags = ISP24XX_ABTS_RSP_TERMINATE;
                isp_notify_ack(isp, qe);
                ins->notify.nt_lreserved = isp->isp_osinfo.nfreelist;
                isp->isp_osinfo.nfreelist = ins;
                break;
            }
            MEMCPY(ins->qentry, qe, QENTRY_LEN);
            ins->qevalid = 1;
            ins->notify.nt_hba = isp;
            ins->notify.nt_tgt = ISP_PORTWWN(isp);
            ins->notify.nt_lun = LUN_ANY;
            ins->notify.nt_tagval = abts->abts_rxid_task;
            ins->notify.nt_ncode = NT_ABORT_TASK;
            ins->notify.nt_need_ack = 1;
            /*
             * Find the command if possible and mark it aborted and needing cleanup
             */
            for (i = 0; i < NTGT_CMDS; i++) {
                tmd_cmd_t *tmd = &isp->isp_osinfo.pool[i];
                if (tmd->cd_lflags & CDFL_BUSY) {
                    if (ins->notify.nt_tagval == tmd->cd_tagval) {
                            tmd->cd_lflags |= CDFL_ABORTED|CDFL_NEED_CLNUP;
                            break;
                    }
                }
            }
            if (ins->notify.nt_tagval == 0xffffffff) {
                abts_rsp_t *rsp = (abts_rsp_t *)ins->qentry;
                rsp->abts_rsp_header.rqs_entry_type = RQSTYPE_ABTS_RSP;
                rsp->abts_rsp_handle = rsp->abts_rsp_rxid_abts;
                rsp->abts_rsp_r_ctl = BA_RJT;
                MEMZERO(&rsp->abts_rsp_payload.ba_rjt, sizeof (rsp->abts_rsp_payload.ba_rjt));
                rsp->abts_rsp_payload.ba_rjt.reason = 9;        /* unable to perform request */
                rsp->abts_rsp_payload.ba_rjt.explanation = 3;   /* invalid ox_id/rx_id combo */
                isp_notify_ack(isp, ins->qentry);
                ins->notify.nt_lreserved = isp->isp_osinfo.nfreelist;
                isp->isp_osinfo.nfreelist = ins;
            } else {
                isp_prt(isp, ISP_LOGINFO, "ABTS [%llx] from 0x%016llx", ins->notify.nt_tagval, ins->notify.nt_iid);
                CALL_PARENT_NOTIFY(isp, ins);
            }
            break;
        }
        case RQSTYPE_NOTIFY:
        {
            isp_notify_t *ins = NULL;
            uint16_t status;
            uint32_t iid, lun, seqid;

            if (isp->isp_osinfo.hcb == 0) {
                isp_prt(isp, ISP_LOGWARN, "TARGET_NOTIFY with no upstream listener");
                isp_notify_ack(isp, qe);
                break;
            }

            if (qe == NULL) {
                isp_prt(isp, ISP_LOGERR, "null argument for RQSTYPE_NOTIFY");
                break;
            }

            if (IS_SCSI(isp)) {
                in_entry_t *inot = qe;

                status = inot->in_status;
                if (inot->in_status == IN_ABORT_TASK) {
                    ins = isp->isp_osinfo.nfreelist;
                    if (ins == NULL) {
                        isp_prt(isp, ISP_LOGERR, "out of TMD NOTIFY structs for RQSTYPE_NOTIFY!");
                        isp_notify_ack(isp, qe);
                        break;
                    }
                    isp->isp_osinfo.nfreelist = ins->notify.nt_lreserved;
                    MEMZERO(&ins->notify, sizeof (tmd_notify_t));
                    MEMCPY(ins->qentry, qe, QENTRY_LEN);
                    ins->qevalid = 1;
                    ins->notify.nt_hba = isp;
                    ins->notify.nt_iid = GET_IID_VAL(inot->in_iid);
                    ins->notify.nt_tgt = inot->in_tgt;
                    ins->notify.nt_lun = inot->in_lun;
                    IN_MAKE_TAGID(ins->notify.nt_tagval, GET_BUS_VAL(inot->in_iid), isp->isp_unit, inot);
                    ins->notify.nt_ncode = NT_ABORT_TASK;
                    ins->notify.nt_need_ack = 1;
                    isp_prt(isp, ISP_LOGINFO, "ABORT TASK [%llx] from iid %u to lun %u", ins->notify.nt_tagval,
                        (uint32_t) ins->notify.nt_iid, inot->in_lun);
                    CALL_PARENT_NOTIFY(isp, ins);
                    break;
                } else {
                    isp_notify_ack(isp, qe);
                }
                break;
            } else if (IS_24XX(isp)) {
                in_fcentry_24xx_t *inot = qe;

                iid = inot->in_nphdl;
                status = inot->in_status;
                seqid = inot->in_rxid;
                lun = 0;

                switch (status) {
                case IN24XX_ELS_RCVD:
                {
/* XXXXXXXXXXXXXXXXXXXXXXXXX NOT RIGHT FOR VPIDX STUFF XXXXXXXXXXXXXXXXXXXXXXXXXX */
                    char *msg = NULL;
                    uint32_t portid = inot->in_portid_hi << 16 | inot->in_portid_lo;
                    switch (inot->in_status_subcode) {
                    case PLOGI:
                        msg = "PLOGI";
                        /* FALLTHROUGH */
                    case LOGO:
                        if (msg == NULL) {
                            msg = "LOGO";
                        }
                        /* FALLTHROUGH */
                    case PRLO:
                    {
                        int i;
                        for (i = 0; i < TM_CS; i++) {
                            if (isp->isp_osinfo.tgt_cache[i].portid == portid) {
                                isp->isp_osinfo.tgt_cache[i].portid = 0;
                                isp->isp_osinfo.tgt_cache[i].nphdl = 0;
                                isp->isp_osinfo.tgt_cache[i].iid = INI_ANY;
                                break;
                            }
                        }
                        if (msg == NULL) {
                            msg = "PRLO";
                        }
                        break;
                    }
                    case PRLI:
                    {
                        int i, empty;
                        for (empty = -1, i = 0; i < TM_CS; i++) {
                            if (isp->isp_osinfo.tgt_cache[i].portid == portid) {
                                isp->isp_osinfo.tgt_cache[i].nphdl = inot->in_nphdl; 
                                isp->isp_osinfo.tgt_cache[i].iid = INI_ANY;
                                break;
                            }
                            if (empty < 0 && isp->isp_osinfo.tgt_cache[i].portid == 0) {
                                empty = i;
                            }
                        }
                        if (i == TM_CS) {
                            if (empty >= 0) {
                                isp->isp_osinfo.tgt_cache[empty].portid = portid;
                                isp->isp_osinfo.tgt_cache[empty].nphdl = inot->in_nphdl;
                                isp->isp_osinfo.tgt_cache[empty].iid = INI_ANY;
                            }
                        }
                        msg = "PRLI";
                        break;
                    }
                    default:
                        isp_prt(isp, ISP_LOGINFO, "ELS CODE %x Received from 0x%06x", inot->in_status_subcode, portid);
                        break;
                    }
                    if (msg) {
                        isp_prt(isp, ISP_LOGINFO, "%s ELS N-port handle %x PortID 0x%06x", msg, inot->in_nphdl, portid);
                    }
                    if ((inot->in_flags & IN24XX_FLAG_PUREX_IOCB) == 0) {
                        isp_notify_ack(isp, qe);
                    }
                    break;
                }
                case IN24XX_PORT_CHANGED:
                case IN24XX_PORT_LOGOUT:

                    ins = isp->isp_osinfo.nfreelist;
                    if (ins == NULL) {
                        isp_prt(isp, ISP_LOGERR, "out of TMD NOTIFY structs for RQSTYPE_NOTIFY!");
                        isp_notify_ack(isp, qe);
                        break;
                    }
                    isp->isp_osinfo.nfreelist = ins->notify.nt_lreserved;
                    MEMZERO(ins, sizeof (*ins));
                    if (isp_find_iid_wwn(isp, inot->in_vpindex, iid, &ins->notify.nt_iid) == 0) {
                        isp_prt(isp, ISP_LOGTDEBUG0, "cannot find WWN for N-port handle 0x%x for ABORT TASK", iid);
                        isp_notify_ack(isp, qe);
                        ins->notify.nt_lreserved = isp->isp_osinfo.nfreelist;
                        isp->isp_osinfo.nfreelist = ins;
                        break;
                    }
                    MEMCPY(ins->qentry, qe, QENTRY_LEN);
                    ins->qevalid = 1;
                    ins->notify.nt_hba = isp;
                    ins->notify.nt_ncode = NT_LOGOUT;
                    isp_clear_iid_wwn(isp, inot->in_vpindex, iid, ins->notify.nt_iid);
                    ins->notify.nt_tagval = seqid;
                    isp_prt(isp, ISP_LOGINFO, "PORT %s [%llx] from 0x%016llx", status == IN24XX_PORT_CHANGED? "CHANGED" : "LOGOUT",
                        ins->notify.nt_tagval, ins->notify.nt_iid);
                    CALL_PARENT_NOTIFY(isp, ins);
                    break;

                case IN24XX_LIP_RESET:  /* XXX: SHOULD BE TREATED LIKE BUS RESET */
                case IN24XX_LINK_RESET: /* XXX: EXCEPT THAT WE HAVE TO HAVE THE */
                case IN24XX_LINK_FAILED:/* XXX: ENTRY TO ACK BACK WITH */
                case IN24XX_SRR_RCVD:
                default:
                    isp_notify_ack(isp, qe);
                    break;
                }
            } else if (IS_FC(isp)) {
                if (ISP_CAP_2KLOGIN(isp)) {
                    in_fcentry_e_t *inot = qe;
                    iid = inot->in_iid;
                    status = inot->in_status;
                    seqid = inot->in_seqid;
                    lun = inot->in_scclun;
                } else {
                    in_fcentry_t *inot = qe;
                    iid = inot->in_iid;
                    status = inot->in_status;
                    seqid = inot->in_seqid;
                    if (ISP_CAP_SCCFW(isp)) {
                        lun = inot->in_scclun;
                    } else {
                        lun = inot->in_lun;
                    }
                }

                if (status == IN_ABORT_TASK || status == IN_PORT_LOGOUT || status == IN_GLOBAL_LOGO) {
                    ins = isp->isp_osinfo.nfreelist;
                    if (ins == NULL) {
                        isp_prt(isp, ISP_LOGWARN, "out of TMD NOTIFY structs for RQSTYPE_NOTIFY!");
                        isp_notify_ack(isp, qe);
                        break;
                    }
                    isp->isp_osinfo.nfreelist = ins->notify.nt_lreserved;
                    MEMZERO(&ins->notify, sizeof (tmd_notify_t));
                    MEMCPY(ins->qentry, qe, QENTRY_LEN);
                    ins->qevalid = 1;
                    ins->notify.nt_hba = isp;
                } else {
                    isp_prt(isp, ISP_LOGINFO, "skipping handling of Notify Status 0x%x", status);
                    isp_notify_ack(isp, qe);
                    break;
                }

                if (status == IN_ABORT_TASK) {
                    if (isp_find_iid_wwn(isp, 0, iid, &ins->notify.nt_iid) == 0) {
                        isp_prt(isp, ISP_LOGINFO, "cannot find WWN for loopid 0x%x for ABORT TASK", iid);
                        ins->notify.nt_iid = INI_ANY;
                    }
                    ins->notify.nt_tgt = ISP_PORTWWN(isp);
                    ins->notify.nt_lun = lun;
                    ins->notify.nt_need_ack = 1;
                    IN_FC_MAKE_TAGID(ins->notify.nt_tagval, 0, isp->isp_unit, seqid);
                    ins->notify.nt_ncode = NT_ABORT_TASK;
                    isp_prt(isp, ISP_LOGINFO, "ABORT TASK [%llx] from 0x%016llx to lun %u", ins->notify.nt_tagval,
                        (unsigned long long) ins->notify.nt_iid, lun);
                    CALL_PARENT_NOTIFY(isp, ins);
                    break;
                } else if (status == IN_PORT_LOGOUT) {
                    /*
                     * The port specified by the loop id listed in iid has logged out. We need to tell our upstream listener about it.
                     */
                    if (isp_find_iid_wwn(isp, 0, iid, &ins->notify.nt_iid)) {
                        ins->notify.nt_ncode = NT_LOGOUT;
                        isp_clear_iid_wwn(isp, 0, iid, ins->notify.nt_iid);
                        IN_FC_MAKE_TAGID(ins->notify.nt_tagval, 0, isp->isp_unit, seqid);
                        isp_prt(isp, ISP_LOGINFO, "PORT LOGOUT [%llx] from 0x%016llx", ins->notify.nt_tagval, (unsigned long long) ins->notify.nt_iid);
                        ins->notify.nt_need_ack = 1;
                        CALL_PARENT_NOTIFY(isp, ins);
                        break;
                    }
                    /*
                     * We don't know the WWPN for this loop ID. This likely
                     * is because we've not as yet received a command from
                     * this initiator (and we're not maintaining an active
                     * port database ourselves).
                     *
                     * We could turn this into a (synthesized) global
                     * logout, but it's just as well that we just ack
                     * it and move on. After all, if we've not yet received
                     * a command for this initiator, we don't have to
                     * note that it left as it hasn't really arrived yet
                     * (at least to any upstream command interpreter),
                     * now has it?
                     */
                    ins->notify.nt_lreserved = isp->isp_osinfo.nfreelist;
                    isp->isp_osinfo.nfreelist = ins;
                    isp_prt(isp, ISP_LOGINFO, "Port Logout at handle 0x%x (seqid 0x%x) but have no WWPN for it- just ACKing", iid, seqid);
                    isp_notify_ack(isp, qe);
                } else if (status == IN_GLOBAL_LOGO) {
                    /*
                     * Everyone Logged Out
                     */
                    ins->notify.nt_iid = INI_ANY;
                    isp_clear_iid_wwn(isp, 0, iid, ins->notify.nt_iid);
                    ins->notify.nt_ncode = NT_LOGOUT;
                    ins->notify.nt_need_ack = 1;
                    CALL_PARENT_NOTIFY(isp, ins);
                } else {
                    isp_prt(isp, ISP_LOGINFO, "%s: ACKing unknown status 0x%x", __FUNCTION__, status);
                    isp_notify_ack(isp, qe);
                }
            }
            break;
        }
        default:
            isp_prt(isp, ISP_LOGWARN, "event 0x%x for unhandled target action", ((isphdr_t *)qe)->rqs_entry_type);
            break;
        }
        break;
    }
#endif
    case ISPASYNC_FW_CRASH:
    {
        uint16_t mbox1, mbox6;
        mbox1 = ISP_READ(isp, OUTMAILBOX1);
        if (IS_DUALBUS(isp)) {
            mbox6 = ISP_READ(isp, OUTMAILBOX6);
        } else {
            mbox6 = 0;
        }
        isp_prt(isp, ISP_LOGERR, "Internal F/W Error on bus %d @ RISC Address 0x%x", mbox6, mbox1);
#ifdef    ISP_FW_CRASH_DUMP
        if (IS_FC(isp)) {
            isp->isp_blocked = 1;
            SEND_THREAD_EVENT(isp, ISP_THREAD_FW_CRASH_DUMP, NULL, 0, __FUNCTION__, __LINE__);
            break;
        }
#endif
        SEND_THREAD_EVENT(isp, ISP_THREAD_REINIT, NULL, 0, __FUNCTION__, __LINE__);
        break;
    }
    case ISPASYNC_FW_RESTARTED:
    {
        if (IS_FC(isp)) {
            int i;
            for (i = 0; i < isp->isp_nchan; i++) {
                SEND_THREAD_EVENT(isp, ISP_THREAD_FC_RESCAN, FCPARAM(isp, i), 0, __FUNCTION__, __LINE__);
            }
        }
        break;
    }
    default:
        break;
    }
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
#include "sd.h"
int
isplinux_biosparam(Disk *disk, kdev_t n, int ip[])
{
    int size = disk->capacity;

    ip[0] = 64;
    ip[1] = 32;
    ip[2] = size >> 11;
    if (ip[2] > 1024) {
        ip[0] = 255;
        ip[1] = 63;
        ip[2] = size / (ip[0] * ip[1]);
    }
    return (0);
}

/*
 * Set the queue depth for this device.
 */

void
isplinux_sqd(struct Scsi_Host *host, struct scsi_device *devs)
{
    while (devs) {
        if (devs->host != host) {
            devs = devs->next;
            continue;
        }
        if (devs->tagged_supported == 0) {
            /*
             * If this device doesn't support tagged operations, don't waste
             * queue space for it, even if it has multiple luns.
             */
            devs->queue_depth = 2;
        } else {
            int depth = 2;
            ispsoftc_t *isp = (ispsoftc_t *) host->hostdata;

            if (IS_SCSI(isp)) {
                sdparam *sdp = SDPARAM(isp, devs->channel);
                depth = sdp->isp_devparam[devs->id].exc_throttle;
            } else {
                depth = FCPARAM(isp, 0)->isp_execthrottle;
            }

            /*
             * isp_throttle overrides execution throttle.
             */
            if (isp_throttle) {
                /*
                 * This limit is due to the size of devs->queue_depth
                 */
                depth = (unsigned char) min(isp_throttle, 255);;
            }
            if (depth < 1) {
                depth = 1;
            }
            devs->queue_depth = depth;
        }
        if (isp_maxsectors) {
            host->max_sectors = isp_maxsectors;
        }
        devs = devs->next;
    }
}

#else

int
isplinux_biosparam(struct scsi_device *sdev, struct block_device *n,
           sector_t capacity, int ip[])
{
    int size = capacity;
    ip[0] = 64;
    ip[1] = 32;
    ip[2] = size >> 11;
    if (ip[2] > 1024) {
        ip[0] = 255;
        ip[1] = 63;
        ip[2] = size / (ip[0] * ip[1]);
    }
    return (0);
}

static int
isplinux_slave_configure(struct scsi_device * device)
{
    if (device->tagged_supported) {
        /*
         *  XXX: FIX LATER
         */
        scsi_adjust_queue_depth(device, MSG_ORDERED_TAG, 63);
    }
    return 0;
}
#endif

int
isplinux_default_id(ispsoftc_t *isp)
{
    if (IS_FC(isp))
        return (isp_fc_id);
    else
        return (isp_spi_id);
}

/*
 * Periodic watchdog timer.. the main purpose here is to restart
 * commands that were pegged on resources, etc...
 */
void
isplinux_timer(unsigned long arg)
{
    Scsi_Cmnd *Cmnd;
    ispsoftc_t *isp = (ispsoftc_t *) arg;
    uint32_t isr;
    uint16_t sema, mbox;
    unsigned long flags;
#ifdef  ISP_TARGET_MODE
    int didintr = 0;
#endif

    ISP_ILOCK_SOFTC(isp);
    if (ISP_READ_ISR(isp, &isr, &sema, &mbox)) {
        isp_intr(isp, isr, sema, mbox);
        if (isp->intsok) {
            ISP_ENABLE_INTS(isp);
        }
#ifdef  ISP_TARGET_MODE
        didintr = 1;
#endif
    }
    if (isp->isp_qfdelay) {
        isp->isp_qfdelay--;
    }
    if (IS_FC(isp) && isp->isp_state == ISP_RUNSTATE && isp->isp_deadloop == 0 && isp->isp_role != ISP_ROLE_NONE) {
        int i;
        for (i = 0 ; i < isp->isp_nchan; i++) {
            if (ISP_BTST(isp->isp_fcrswdog, i)) {
                ISP_BCLR(isp->isp_fcrswdog, i);
                SEND_THREAD_EVENT(isp, ISP_THREAD_FC_RESCAN, FCPARAM(isp, i), 0, __FUNCTION__, __LINE__);
            }
        }
    }
    isplinux_runwaitq(isp);
    if ((Cmnd = isp->isp_osinfo.dqnext) != NULL) {
        isp->isp_osinfo.dqnext = isp->isp_osinfo.dqtail = NULL;
    }
    if (isp->dogactive) {
        isp->isp_osinfo.timer.expires = jiffies + ISP_WATCH_TIME;
        add_timer(&isp->isp_osinfo.timer);
    }
    ISP_IUNLK_SOFTC(isp);
#ifdef  ISP_TARGET_MODE
    if (didintr) {
        isp_tgt_tq(isp);
    }
#endif
    if (Cmnd) {
        ISP_LOCK_SCSI_DONE(isp);
        while (Cmnd) {
            Scsi_Cmnd *f = (Scsi_Cmnd *) Cmnd->host_scribble;
            Cmnd->host_scribble = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
            /*
             * Get around silliness in midlayer.
             */
            if (host_byte(Cmnd->result) == DID_RESET) {
                Cmnd->flags |= IS_RESETTING;
            }
#endif
            (*Cmnd->scsi_done)(Cmnd);
            Cmnd = f;
        }
        ISP_UNLK_SCSI_DONE(isp);
    }
}

void
isplinux_mbtimer(unsigned long arg)
{
    ispsoftc_t *isp = (ispsoftc_t *) arg;
    unsigned long flags;
    ISP_ILOCK_SOFTC(isp);
    if (isp->mbox_waiting) {
        isp->mbox_waiting = 0;
        up(&isp->mbox_c_sem);
    }
    ISP_IUNLK_SOFTC(isp);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
#define ISPLINUX_INTR_TYPE      void
#define ISPLINUX_INTR_RET       return
#define ISPLINUX_INTR_RET_BOGUS return
#define PTARG                   , struct pt_regs *pt
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#define ISPLINUX_INTR_TYPE      irqreturn_t
#define ISPLINUX_INTR_RET       return IRQ_HANDLED
#define ISPLINUX_INTR_RET_BOGUS return IRQ_NONE
#define PTARG                   , struct pt_regs *pt
#else
#define ISPLINUX_INTR_TYPE      irqreturn_t
#define ISPLINUX_INTR_RET       return IRQ_HANDLED
#define ISPLINUX_INTR_RET_BOGUS return IRQ_NONE
#define PTARG
#endif

ISPLINUX_INTR_TYPE
isplinux_intr(int irq, void *arg PTARG)
{
    ispsoftc_t *isp = arg;
    uint32_t isr;
    uint16_t sema, mbox;
    Scsi_Cmnd *Cmnd;
    unsigned long flags;

    ISP_ILOCK_SOFTC(isp);
    isp->isp_intcnt++;
    if (ISP_READ_ISR(isp, &isr, &sema, &mbox) == 0) {
        isp->isp_intbogus++;
        if (isp->intsok) {
            ISP_ENABLE_INTS(isp);
        }
        ISP_IUNLK_SOFTC(isp);
        ISPLINUX_INTR_RET_BOGUS;
    }
    isp_intr(isp, isr, sema, mbox);
    isplinux_runwaitq(isp);
    if ((Cmnd = isp->isp_osinfo.dqnext) != NULL) {
        isp->isp_osinfo.dqnext = isp->isp_osinfo.dqtail = NULL;
    }
    if (isp->intsok) {
        ISP_ENABLE_INTS(isp);
    }
    ISP_IUNLK_SOFTC(isp);
    if (Cmnd) {
        ISP_LOCK_SCSI_DONE(isp);
        while (Cmnd) {
            Scsi_Cmnd *f = (Scsi_Cmnd *) Cmnd->host_scribble;
            Cmnd->host_scribble = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
            /*
             * Get around silliness in midlayer.
             */
            if (host_byte(Cmnd->result) == DID_RESET) {
                Cmnd->flags |= IS_RESETTING;
            }
#endif
            (*Cmnd->scsi_done)(Cmnd);
            Cmnd = f;
        }
        ISP_UNLK_SCSI_DONE(isp);
    }
#ifdef  ISP_TARGET_MODE
    isp_tgt_tq(isp);
#endif
    ISPLINUX_INTR_RET;
}

static int
isp_parse_rolearg(ispsoftc_t *isp, char *roles)
{
    char *role = roles;

    while (role && *role) {
        unsigned int id;
        char *eqtok, *commatok, *p, *q;
    
        eqtok = role;
        eqtok = strchr(role, '=');
        if (eqtok == NULL) {
           break;
        }
        *eqtok = 0;
        commatok = strchr(eqtok+1, ',');
        if (commatok) {
            *commatok = 0;
        }
        if (strncmp(role, "0x", 2) == 0) {
            q = role + 2;
        } else {
            q = role;
        }
        if (*q == '*') {
            id = isp->isp_osinfo.device_id;
            p = NULL;
        } else {
            id = simple_strtoul(q, &p, 16);
        }
        *eqtok = '=';
        if (p != q && id == isp->isp_osinfo.device_id) {
            p = eqtok + 1;
            if (strcmp(p, "none") == 0) {
                if (commatok) {
                    *commatok = ',';
                }
                return (ISP_ROLE_NONE);
            }
            if (strcmp(p, "target") == 0) {
                if (commatok) {
                    *commatok = ',';
                }
                return (ISP_ROLE_TARGET);
            }
            if (strcmp(p, "initiator") == 0) {
                if (commatok) {
                    *commatok = ',';
                }
                return (ISP_ROLE_INITIATOR);
            }
            if (strcmp(p, "both") == 0) {
                if (commatok) {
                    *commatok = ',';
                }
                return (ISP_ROLE_BOTH);
            }
            break;
        }
        if (commatok) {
            role = commatok+1;
            *commatok = ',';
        } else {
            break;
        }
    }
    return (ISP_DEFAULT_ROLES);
}

static __inline uint64_t
isp_parse_wwnarg(ispsoftc_t *isp, char *wwns)
{
    char *wwnt = wwns;
    uint64_t wwn = 0;

    while (wwn == 0 && wwnt && *wwnt) {
        unsigned int id;
        char *eqtok, *commatok, *p, *q;
    
        eqtok = wwnt;
        eqtok = strchr(wwnt, '=');
        if (eqtok == NULL) {
           break;
        }
        *eqtok = 0;
        commatok = strchr(eqtok+1, ',');
        if (commatok) {
            *commatok = 0;
        }
        if (strncmp(wwnt, "0x", 2) == 0) {
            q = wwnt + 2;
        } else {
            q = wwnt;
        }
        id = simple_strtoul(q, &p, 16);
        if (p != q && id == isp->isp_osinfo.device_id) {
            unsigned long t, t2;
            p = eqtok + 1;
            while (*p) {
                p++;
            }
            p -= 8;
            if (p > eqtok + 1) {
                char *q;
                char c;
                q = p;
                t = simple_strtoul(p, &q, 16);
                c = *p;
                *p = 0;
                t2 = simple_strtoul(eqtok+1, NULL, 16);
                *p = c;
            } else {
                t = simple_strtoul(eqtok+1, NULL, 16);
                t2 = 0;
            }
            wwn = (((uint64_t) t2) << 32) | (uint64_t) t;
        }
        *eqtok = '=';
        if (commatok) {
            wwnt = commatok+1;
            *commatok = ',';
        } else {
            break;
        }
    }
    return (wwn);
}

int
isplinux_common_init(ispsoftc_t *isp)
{
    int retval;
    unsigned long flags;

    /*
     * Set up config options, etc...
     */
    if (isp_debug) {
        isp->isp_dblev = isp_debug;
    } else {
        isp->isp_dblev = ISP_LOGCONFIG|ISP_LOGINFO|ISP_LOGWARN|ISP_LOGERR;
    }

    if (isp_nofwreload & (1 << isp->isp_unit)) {
        isp->isp_confopts |= ISP_CFG_NORELOAD;
    }
    if (isp_nonvram & (1 << isp->isp_unit)) {
        isp->isp_confopts |= ISP_CFG_NONVRAM;
    }
    if (IS_FC(isp)) {
        if (isp_fcduplex & (1 << isp->isp_unit)) {
            isp->isp_confopts |= ISP_CFG_FULL_DUPLEX;
        }
        isp->isp_defwwpn = isp_parse_wwnarg(isp, isp_wwpns);
        if (isp->isp_defwwpn) {
            isp->isp_confopts |= ISP_CFG_OWNWWPN;
        }
        isp->isp_defwwnn = isp_parse_wwnarg(isp, isp_wwnns);
        if (isp->isp_defwwnn) {
            isp->isp_confopts |= ISP_CFG_OWNWWNN;
        }
        isp->isp_osinfo.host->max_id = MAX_FC_TARG; 
        if (IS_2200(isp) || IS_2300(isp)) {
            if (isp_nport_only & (1 << isp->isp_unit)) {
                isp->isp_confopts |= ISP_CFG_NPORT_ONLY;
            } else if (isp_loop_only & (1 << isp->isp_unit)) {
                isp->isp_confopts |= ISP_CFG_LPORT_ONLY;
            } else {
                isp->isp_confopts |= ISP_CFG_NPORT;
            }
        }
        isp->isp_osinfo.host->this_id = MAX_FC_TARG+1;
#ifdef    ISP_FW_CRASH_DUMP
        if (IS_2200(isp)) {
            FCPARAM(isp, 0)->isp_dump_data = isp_kalloc(QLA2200_RISC_IMAGE_DUMP_SIZE, GFP_KERNEL);
        } else if (IS_23XX(isp)) {
            FCPARAM(isp, 0)->isp_dump_data = isp_kalloc(QLA2300_RISC_IMAGE_DUMP_SIZE, GFP_KERNEL);
        }
        if (FCPARAM(isp, 0)->isp_dump_data) {
            isp_prt(isp, ISP_LOGCONFIG, "f/w crash dump area allocated");
            FCPARAM(isp, 0)->isp_dump_data[0] = 0;
        }
#endif
        if (isp_default_frame_size) {
            if (isp_default_frame_size != 512 && isp_default_frame_size != 1024 && isp_default_frame_size != 2048) {
                isp_prt(isp, ISP_LOGERR, "bad frame size (%d), defaulting to (%d)", isp_default_frame_size, ICB_DFLT_FRMLEN);
                isp_default_frame_size = 0;
            }
        }
        if (isp_default_frame_size) {
            isp->isp_confopts |= ISP_CFG_OWNFSZ;
            isp->isp_osinfo.storep->fibre_scsi.default_frame_size = isp_default_frame_size;
        } else {
            isp->isp_osinfo.storep->fibre_scsi.default_frame_size = isp_default_frame_size = ICB_DFLT_FRMLEN;
        }
        if (isp_default_exec_throttle) {
            if (isp_default_exec_throttle < 1 || isp_default_exec_throttle > 255) {
                isp_prt(isp, ISP_LOGERR, "bad execution throttle size (%d), defaulting to (%d)", isp_default_exec_throttle, ICB_DFLT_THROTTLE);
                isp_default_exec_throttle = 0;
            }
        }
        if (isp_default_exec_throttle) {
            isp->isp_confopts |= ISP_CFG_OWNEXCTHROTTLE;
            isp->isp_osinfo.storep->fibre_scsi.default_exec_throttle = isp_default_exec_throttle;
        } else {
            isp->isp_osinfo.storep->fibre_scsi.default_exec_throttle = ICB_DFLT_THROTTLE;
        }
    } else {
        isp->isp_osinfo.host->max_id = MAX_TARGETS;
        isp->isp_osinfo.host->this_id = 7;    /* temp default */
    }
    isp->isp_role = isp_parse_rolearg(isp, isp_roles);

    if (isp_own_id) {
        isp->isp_confopts |= ISP_CFG_OWNLOOPID;
    }

    /*
     * Initialize locks
     */
    ISP_LOCK_INIT(isp);
    ISP_TLOCK_INIT(isp);
    sema_init(&isp->mbox_sem, 1);
    sema_init(&isp->mbox_c_sem, 0);
    sema_init(&isp->fcs_sem, 1);

#if defined(CONFIG_PROC_FS)
    /*
     * Initialize any PROCFS stuff
     */
    isplinux_init_proc(isp);
#endif

#ifdef ISP_TARGET_MODE
    /*
     * Initialize target stuff here
     */
    if (isp_init_target(isp)) {
        return (-1);
    }
#endif
    /*
     * Start watchdog timer, create FC handler thread and reinit hardware.
     */
    ISP_LOCK_SOFTC(isp);
    init_timer(&isp->isp_osinfo.timer);
    isp->isp_osinfo.timer.data = (unsigned long) isp;
    isp->isp_osinfo.timer.function = isplinux_timer;
    isp->isp_osinfo.timer.expires = jiffies + ISP_WATCH_TIME;
    add_timer(&isp->isp_osinfo.timer);
    isp->dogactive = 1;
    if (IS_FC(isp)) {
        DECLARE_MUTEX_LOCKED(sem);
        ISP_UNLK_SOFTC(isp);
        isp->isp_osinfo.task_ctl_sem = &sem;
        kernel_thread(isp_task_thread, isp, 0);
        down(&sem);
        isp->isp_osinfo.task_ctl_sem = NULL;
        ISP_LOCK_SOFTC(isp);
    }

    retval = isplinux_reinit(isp);

    if (retval) {
        isp_prt(isp, ISP_LOGWARN, "failed to init HBA port (%d): skipping it", retval);
#if defined(CONFIG_PROC_FS)
        isplinux_undo_proc(isp);
#endif
        del_timer(&isp->isp_osinfo.timer);
        isp->dogactive = 0;
        ISP_UNLK_SOFTC(isp);
#ifdef ISP_TARGET_MODE
        isp_deinit_target(isp);
#endif
        if (isp->isp_osinfo.task_thread) {
            SEND_THREAD_EVENT(isp, ISP_THREAD_EXIT, NULL, 1, __FUNCTION__, __LINE__);
        }
        return (-1);
    }
    ISP_UNLK_SOFTC(isp);
#ifdef ISP_TARGET_MODE
    isp_attach_target(isp);
#endif
    return (0);
}

int
isplinux_reinit(ispsoftc_t *isp)
{
    int maxluns = isp_maxluns;

    isp_reset(isp);

    if (isp->isp_state != ISP_RESETSTATE) {
        isp_prt(isp, ISP_LOGERR, "failed to enter RESET state");
        return (-1);
    } 

    /*
     * Until the midlayer starts using REPORT LUNS to dertermine how many
     * luns there are for SCSI-3 devices and sets a reasonable limit for
     * SCSI-2 devices, we'll follow this ruleset:
     * 
     *     If our isp_maxluns parameter is unchanged from its default, we
     *     limit ourselves to 8 luns for parallel SCSI, 256 for FC-SCSI.
     *
     *     If somebody has set isp_maxluns away from the fefault, we follow that.
     *
     *     We filter any value through the HBA maximum
     */
    if (isp_maxluns == 8) {
        if (IS_FC(isp)) {
            maxluns = 256;
        }
    }
    isp->isp_osinfo.host->max_lun = min(maxluns, ISP_MAX_LUNS(isp));

    /*
     * If we're not taking a role, set some 'defaults' and turn off lasers (for FC cards).
     */
    if (isp->isp_role == ISP_ROLE_NONE) {
        isp->isp_osinfo.host->can_queue = 16;
        isp->isp_osinfo.host->can_queue = 1;
        isp->isp_osinfo.host->cmd_per_lun = 1;
        isp->isp_osinfo.host->this_id = IS_FC(isp)? MAX_FC_TARG : 7;
        return (0);
    } else {
        isp_init(isp);
        if (isp->isp_state != ISP_INITSTATE) {
            isp_prt(isp, ISP_LOGERR, "failed to enter INIT state");
            return (-1);
        }
    }

    isp->isp_osinfo.host->can_queue = isp->isp_maxcmds;

    if (IS_FC(isp)) {
        isp->isp_osinfo.host->this_id = MAX_FC_TARG;
        /*
         * This is *not* the same as execution throttle- that is set
         * in isplinux_sqd and is per-device.
         *
         * What we try and do here is take how much we can queue at
         * a given time and spread it, reasonably, over all the luns
         * we expect to run at a time.
         */
        if (isp_cmd_per_lun) {
            isp->isp_osinfo.host->cmd_per_lun = isp_cmd_per_lun;
        } else {
            /*
             * JAWAG.
             */
            isp->isp_osinfo.host->cmd_per_lun = isp->isp_maxcmds >> 3;
        }

        /*
         * We seem to need a bit of settle time.
         */
        USEC_SLEEP(isp, 1 * 1000000);

    } else {
	int chan;

        if (isp_cmd_per_lun) {
            isp->isp_osinfo.host->cmd_per_lun = isp_cmd_per_lun;
        } else {
            /*
             * Maximum total commands spread over either 8 targets,
             * or 4 targets, 2 luns, etc.
             */
            isp->isp_osinfo.host->cmd_per_lun = isp->isp_maxcmds >> 3;
        }

        /*
         * No way to give different ID's for the second bus.
         */
        isp->isp_osinfo.host->this_id = SDPARAM(isp, 0)->isp_initiator_id;
	for (chan = 0; chan < isp->isp_nchan; chan++) {
		(void) isp_control(isp, ISPCTL_RESET_BUS, chan);
        }
        /*
         * Bus Reset delay handled by firmware.
         */
    }
    isp->isp_state = ISP_RUNSTATE;
    return (0);
}

int
isp_drain_reset(ispsoftc_t *isp, char *msg)
{
    isp->isp_blocked = 1;
    /*
     * Drain active commands.
     */
    if (isp_drain(isp, msg)) {
        isp->isp_blocked = 0;
        return (-1);
    }
    isp_reinit(isp);
    if ((isp->isp_role == ISP_ROLE_NONE && isp->isp_state < ISP_RESETSTATE) || (isp->isp_role != ISP_ROLE_NONE && isp->isp_state < ISP_RUNSTATE)) {
        isp->isp_blocked = 0;
        return (-1);
    }
    isp->isp_blocked = 0;
    return (0);
}

int
isp_drain(ispsoftc_t *isp, char *whom)
{
    int nslept;

    if (isp->isp_nactive == 0) {
        return (0);
    }

    isp->isp_draining = 1;
    nslept = 0;
    isp_prt(isp, ISP_LOGDEBUG0, "draining %d commands", isp->isp_nactive);
    while (isp->isp_nactive) {
        USEC_SLEEP(isp, 100000);    /* drops lock */
        if (++nslept >= (60 * 10)) {    /* 60 seconds */
            isp_prt(isp, ISP_LOGERR, "%s: command drain timed out", whom);
            isp->isp_draining = 0;
            return (-1);
        }
    }
    isp_prt(isp, ISP_LOGDEBUG0, "done draining commands");
    isp->isp_draining = 0;
    isplinux_runwaitq(isp);
    return (0);
}

#if    LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
#define    ISP_THREAD_CAN_EXIT    isp->isp_host->loaded_as_module
#else
#define    ISP_THREAD_CAN_EXIT    1
#endif

static int
isp_task_thread(void *arg)
{
    DECLARE_MUTEX_LOCKED(thread_sleep_semaphore);
    struct semaphore *last_waiter = NULL;
    ispsoftc_t *isp = arg;
    unsigned long flags;
    int action, nactions, exit_thread = 0;
    isp_thread_action_t curactions[MAX_THREAD_ACTION];

#if    LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
    if (ISP_THREAD_CAN_EXIT) {
        siginitsetinv(&current->blocked, sigmask(SIGHUP));
    } else {
        siginitsetinv(&current->blocked, 0);
    }
    lock_kernel();
    daemonize();
    snprintf(current->comm, sizeof (current->comm), "isp_thrd%d", isp->isp_unit);
#else
    siginitsetinv(&current->blocked, 0);
    lock_kernel();
    daemonize("isp_thrd%d", isp->isp_unit);
#endif
    isp->isp_osinfo.task_thread = current;
    isp->isp_osinfo.task_request = &thread_sleep_semaphore;
    unlock_kernel();

    if (isp->isp_osinfo.task_ctl_sem) {
        up(isp->isp_osinfo.task_ctl_sem);
    }
    isp_prt(isp, ISP_LOGDEBUG1, "isp_task_thread starting");

    while (exit_thread == 0) {
        isp_prt(isp, ISP_LOGDEBUG1, "isp_task_thread sleeping");
        down_interruptible(&thread_sleep_semaphore);
        if (ISP_THREAD_CAN_EXIT) {
            if (signal_pending(current)) {
                break;
            }
        }
        isp_prt(isp, ISP_LOGDEBUG1, "isp_task_thread running");

        spin_lock_irqsave(&isp->isp_osinfo.tlock, flags);
        nactions = isp->isp_osinfo.nt_actions;
        isp->isp_osinfo.nt_actions = 0;
        for (action = 0; action < nactions; action++) {
            curactions[action] = isp->isp_osinfo.t_actions[action];
            isp->isp_osinfo.t_actions[action].thread_action = 0;
            isp->isp_osinfo.t_actions[action].thread_waiter = 0;
        }
        spin_unlock_irqrestore(&isp->isp_osinfo.tlock, flags);

        for (action = 0; action < nactions; action++) {
            isp_thread_action_t *tap = &curactions[action];
            isp_prt(isp, ISP_LOGDEBUG1, "isp_task_thread[%d]: action %d (%p)", action, tap->thread_action, tap->thread_waiter);

            switch (tap->thread_action) {
            case ISP_THREAD_NIL:
                break;

#ifdef    ISP_FW_CRASH_DUMP
            case ISP_THREAD_FW_CRASH_DUMP:
                ISP_LOCKU_SOFTC(isp);
                FCPARAM(isp, 0)->isp_fwstate = FW_CONFIG_WAIT;
                FCPARAM(isp, 0)->isp_loopstate = LOOP_NIL;
                isp_fw_dump(isp);
                SEND_THREAD_EVENT(isp, ISP_THREAD_REINIT, NULL, 0, __FUNCTION__, __LINE__);
                ISP_UNLKU_SOFTC(isp);
                break;
#endif

            case ISP_THREAD_REINIT:
            {
                int level;

                ISP_LOCKU_SOFTC(isp);
                level = (isp->isp_role == ISP_ROLE_NONE)? ISP_RESETSTATE : ISP_INITSTATE;
                isp_reinit(isp);
                if (isp->isp_state >= level) {
                    isp_async(isp, ISPASYNC_FW_RESTARTED);
                } else {
                    isp_prt(isp, ISP_LOGERR, "unable to restart chip");
                }
                ISP_UNLKU_SOFTC(isp);
                break;
            }
            case ISP_THREAD_FC_RESCAN:
            {
                fcparam *fcp = tap->arg;
                int chan = fcp - FCPARAM(isp, 0);
                ISP_LOCKU_SOFTC(isp);
                ISP_BCLR(isp->isp_fcrswdog, chan);
                if (isp_fc_runstate(isp, chan, 250000) == 0) {
                    isp->isp_deadloop = 0;
                    isp->isp_downcnt = 0;
                    isp->isp_fcrspend = 0;
                    isp->isp_blocked = 0;
                    isplinux_runwaitq(isp);
                } else {
                    /*
                     * Try again in a little while.
                     */
                    isp->isp_fcrspend = 0;
                    if (++isp->isp_downcnt == isp_deadloop_time) {
                        isp_prt(isp, ISP_LOGWARN, "assuming loop is dead");
                        FCPARAM(isp, 0)->loop_seen_once = 0;
                        isp->isp_deadloop = 1;
                        isp->isp_downcnt = 0;
                        isp->isp_blocked = 0;    /* unblock anyway */
                        isplinux_flushwaitq(isp);
                    } else {
                        ISP_BSET(isp->isp_fcrswdog, chan);
                    }
                }
                ISP_UNLKU_SOFTC(isp);
                break;
            }
            case ISP_THREAD_EXIT:
                if (ISP_THREAD_CAN_EXIT) {
                    exit_thread = 1;
                }
                break;
#ifdef  ISP_TARGET_MODE
            case ISP_THREAD_LOGOUT:
            {
                mbreg_t mbs;
                union {
                    isp_pdb_t pdb;
                    int id;
                } u;
                fcportdb_t *lp = tap->arg;

                ISP_LOCKU_SOFTC(isp);
                if (lp->state != FC_PORTDB_STATE_VALID) {
                    isp_prt(isp, ISP_LOGALL, "target entry no longer valid");
                    ISP_UNLKU_SOFTC(isp);
                    break;
                }
                MEMZERO(&u, sizeof (u));
                u.id = lp->handle;
                isp_prt(isp, ISP_LOGALL, "Doing Port Logout repair for 0x%016llx@0x%x (loop id) %u",
                    lp->port_wwn, lp->portid, lp->handle);
                MEMZERO(&mbs, sizeof (mbs));
                mbs.param[0] = MBOX_FABRIC_LOGOUT;
                if (ISP_CAP_2KLOGIN(isp)) {
                        mbs.param[1] = lp->handle;
                        mbs.obits |= (1 << 10);
                } else {
                        mbs.param[1] = lp->handle << 8;
                }
                mbs.logval = MBLOGNONE;
                (void) isp_control(isp, ISPCTL_RUN_MBOXCMD, &mbs);
                if (mbs.param[0] != MBOX_COMMAND_COMPLETE) {
                    isp_prt(isp, ISP_LOGERR, "failed to get logout loop id %u", lp->handle);
                    lp->state = FC_PORTDB_STATE_PROBATIONAL;
                    ISP_UNLKU_SOFTC(isp);
                    break;
                }
                MEMZERO(&mbs, sizeof (mbs));
                mbs.param[0] = MBOX_FABRIC_LOGIN;
                if (ISP_CAP_2KLOGIN(isp)) {
                        mbs.param[1] = lp->handle;
                        mbs.obits |= (1 << 10);
                } else {
                        mbs.param[1] = lp->handle << 8;
                }
                mbs.param[2] = lp->portid >> 16;
                mbs.param[3] = lp->portid & 0xffff;
                (void) isp_control(isp, ISPCTL_RUN_MBOXCMD, &mbs);
                if (mbs.param[0] != MBOX_COMMAND_COMPLETE) {
                    isp_prt(isp, ISP_LOGERR, "failed to get login port id %x at loop id %u", lp->portid, lp->handle);
                    lp->state = FC_PORTDB_STATE_PROBATIONAL;
                    ISP_UNLKU_SOFTC(isp);
                    break;
                }
                lp->state = FC_PORTDB_STATE_VALID;
                ISP_UNLKU_SOFTC(isp);
                break;
            }
            case ISP_THREAD_FINDIID:
            {
                tmd_cmd_t *tmd = tap->arg;
                fcportdb_t *lp;
                uint64_t wwn;

                if (tmd->cd_lflags & CDFL_ABORTED) {
                    SEND_THREAD_EVENT(isp, ISP_THREAD_TERMINATE, tmd, 0, __FUNCTION__, __LINE__);
                    break;
                }
                ISP_LOCKU_SOFTC(isp);
                if (isp_find_pdb_sid(isp, tmd->cd_channel, tmd->cd_portid, &lp)) {
                    tmd->cd_iid = lp->port_wwn;
                    tmd->cd_nphdl = lp->handle;
                    isp_prt(isp, ISP_LOGINFO, "%s: [%llx] found iid (0x%016llx)-sending upstream", __FUNCTION__, tmd->cd_tagval, (unsigned long long)tmd->cd_iid);
                    CALL_PARENT_TARGET(isp, tmd, QOUT_TMD_START);
                    ISP_UNLKU_SOFTC(isp);
                    isp_tgt_tq(isp);
                    break;
                }
                if (isp_control(isp, ISPCTL_GET_PORTNAME, tmd->cd_channel, tmd->cd_nphdl, &wwn)) {
                    ISP_UNLKU_SOFTC(isp);
                    SEND_THREAD_EVENT(isp, ISP_THREAD_FINDIID, tmd, 0, __FUNCTION__, __LINE__);
                } else {
                    int i;
                    for (i = 0; i < TM_CS; i++) {
                        if (isp->isp_osinfo.tgt_cache[i].portid == tmd->cd_portid) {
                            isp->isp_osinfo.tgt_cache[i].iid = wwn;
                            break;
                        }
                    }
                    tmd->cd_iid = wwn;
                    isp_prt(isp, ISP_LOGINFO, "[%llx] found iid (0x%016llx) via GET_PORT_NAME- sending upstream", tmd->cd_tagval,
                        (unsigned long long) tmd->cd_iid);
                    CALL_PARENT_TARGET(isp, tmd, QOUT_TMD_START);
                    ISP_UNLKU_SOFTC(isp);
                    isp_tgt_tq(isp);
                }
                break;
            }
            case ISP_THREAD_TERMINATE:
            {
                fcportdb_t *lp;
                ct7_entry_t local, *cto = &local;
                uint32_t optr, nxti;
                void *qe;
                tmd_cmd_t *tmd = tap->arg;

                ISP_LOCKU_SOFTC(isp);
                if (isp_find_pdb_sid(isp, tmd->cd_channel, tmd->cd_portid, &lp)) {
                    tmd->cd_iid = lp->port_wwn;
                    tmd->cd_nphdl = lp->handle;
                    CALL_PARENT_TARGET(isp, tmd, QOUT_TMD_START);
                    ISP_UNLKU_SOFTC(isp);
                    isp_tgt_tq(isp);
                    break;
                }

                if (isp_getrqentry(isp, &nxti, &optr, &qe)) {
                    ISP_UNLKU_SOFTC(isp);
                    isp_prt(isp, ISP_LOGWARN, "%s: request queue overflow", __FUNCTION__);
                    SEND_THREAD_EVENT(isp, ISP_THREAD_TERMINATE, tmd, 0, __FUNCTION__, __LINE__);
                    break;
                }
                isp_prt(isp, ISP_LOGINFO, "Terminating %llx from 0x%06x", tmd->cd_tagval, tmd->cd_portid);
                MEMZERO(cto, sizeof (ct7_entry_t));
                cto->ct_header.rqs_entry_type = RQSTYPE_CTIO7;
                cto->ct_header.rqs_entry_count = 1;
                cto->ct_nphdl = 0xffff;
                cto->ct_rxid = AT2_GET_TAG(tmd->cd_tagval);
                cto->ct_vpindex = AT2_GET_BUS(tmd->cd_tagval);
                cto->ct_oxid = tmd->cd_oxid;
                cto->ct_flags = CT7_TERMINATE;
                cto->ct_iid_hi = tmd->cd_portid >> 16;
                cto->ct_iid_lo = tmd->cd_portid;
                isp_put_ctio7(isp, cto, (ct7_entry_t *)qe);
                ISP_ADD_REQUEST(isp, nxti);
                tmd->cd_next = NULL;
                if (isp->isp_osinfo.tfreelist) {
                    isp->isp_osinfo.bfreelist->cd_next = tmd;
                } else {
                    isp->isp_osinfo.tfreelist = tmd;
                }
                isp->isp_osinfo.bfreelist = tmd;
                ISP_UNLKU_SOFTC(isp);
                break;
            }
            case ISP_THREAD_FC_PUTBACK:
            {
                tmd_cmd_t *tmd = tap->arg;
                ISP_LOCKU_SOFTC(isp);
                isp_prt(isp, ISP_LOGINFO, "%s: [%llx] calling putback", __FUNCTION__, tmd->cd_tagval);
                if (isp_target_putback_atio(isp, tmd)) {
                    ISP_UNLKU_SOFTC(isp);
                    SEND_THREAD_EVENT(isp, ISP_THREAD_FC_PUTBACK, tmd, 0, __FUNCTION__, __LINE__);
                    break;
                }
                if (tmd->cd_lflags & CDFL_NEED_CLNUP) {
                    tmd->cd_lflags &= ~CDFL_NEED_CLNUP;
                    (void) isp_terminate_cmd(isp, tmd);
                }
                tmd->cd_hba = NULL;
                tmd->cd_lflags = 0;
                tmd->cd_next = NULL;
                /* don't zero cd_hflags or cd_tagval- it may be being used to catch duplicate frees */
                if (isp->isp_osinfo.tfreelist) {
                    isp->isp_osinfo.bfreelist->cd_next = tmd;
                } else {
                    isp->isp_osinfo.tfreelist = tmd;
                }
                isp->isp_osinfo.bfreelist = tmd; /* remember to move the list tail pointer */
                isp_prt(isp, ISP_LOGTDEBUG0, "DONE freeing tmd %p [%llx] after retry", tmd, tmd->cd_tagval);
                ISP_UNLKU_SOFTC(isp);
                break;
            }
#endif
            default:
                break;
            }

            if (exit_thread) {
                last_waiter = tap->thread_waiter;
                break;
            }

            if (tap->thread_waiter) {
                isp_prt(isp, ISP_LOGDEBUG1, "isp_task_thread signalling %p", tap->thread_waiter);
                up(tap->thread_waiter);
            }
        }
    }
    isp_prt(isp, ISP_LOGDEBUG1, "isp_task_thread exiting");
    isp->isp_osinfo.task_request = NULL;
    if (last_waiter) {
        isp_prt(isp, ISP_LOGDEBUG1, "isp_task_thread signalling %p for exit", last_waiter);
        up(last_waiter);
    }
    return (0);
}

void
isp_prt(ispsoftc_t *isp, int level, const char *fmt, ...)
{
    char buf[256];
    char *prefl;
    va_list ap;

    if (level != ISP_LOGALL && (level & isp->isp_dblev) == 0) {
        return;
    }
    if (level & ISP_LOGERR) {
        prefl = KERN_ERR "%s: ";
    } else if (level & ISP_LOGWARN) {
        prefl = KERN_WARNING "%s: ";
    } else if (level & ISP_LOGINFO) {
        prefl = KERN_INFO "%s: ";
    } else if (level & ISP_LOGCONFIG) {
        prefl = KERN_INFO "%s: ";
    } else {
        prefl = "%s: ";
    }
    printk(prefl, isp->isp_name);
    va_start(ap, fmt);
    vsnprintf(buf, sizeof (buf), fmt, ap);
    va_end(ap);
    printk("%s\n", buf);
}

#ifdef MODULE
#ifndef    ISP_LICENSE
#define    ISP_LICENSE    "GPL"
#endif
#ifdef    MODULE_LICENSE
MODULE_LICENSE( ISP_LICENSE );
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
MODULE_PARM(isp_debug, "i");
MODULE_PARM(isp_disable, "i");
MODULE_PARM(isp_nonvram, "i");
MODULE_PARM(isp_nofwreload, "i");
MODULE_PARM(isp_maxluns, "i");
MODULE_PARM(isp_throttle, "i");
MODULE_PARM(isp_cmd_per_lun, "i");
MODULE_PARM(isp_maxsectors, "i");
MODULE_PARM(isp_fcduplex, "i");
MODULE_PARM(isp_nport_only, "i");
MODULE_PARM(isp_loop_only, "i");
MODULE_PARM(isp_deadloop_time, "i");
MODULE_PARM(isp_fc_id, "i");
MODULE_PARM(isp_spi_id, "i");
MODULE_PARM(isp_own_id, "i");
MODULE_PARM(isp_default_frame_size, "i");
MODULE_PARM(isp_default_exec_throttle, "i");
MODULE_PARM(isp_roles, "s");
MODULE_PARM(isp_wwpns, "s");
MODULE_PARM(isp_wwnns, "s");
#else
module_param(isp_debug, int, 0);
module_param(isp_disable, int, 0);
module_param(isp_nonvram, int, 0);
module_param(isp_nofwreload, int, 0);
module_param(isp_maxluns, int, 0);
module_param(isp_throttle, int, 0);
module_param(isp_cmd_per_lun, int, 0);
module_param(isp_maxsectors, int, 0);
module_param(isp_fcduplex, int, 0);
module_param(isp_nport_only, int, 0);
module_param(isp_loop_only, int, 0);
module_param(isp_deadloop_time, int, 0);
module_param(isp_fc_id, int, 0);
module_param(isp_spi_id, int, 0);
module_param(isp_own_id, int, 0);
module_param(isp_default_frame_size, int, 0);
module_param(isp_default_exec_throttle, int, 0);
module_param(isp_roles, charp, 0);
module_param(isp_wwpns, charp, 0);
module_param(isp_wwnns, charp, 0);
#endif
#else

static int __init isp_roleinit(char *str)
{
    isp_roles = str;
    return 0;
}
__setup("isp_roles=", isp_roleinit);

#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
Scsi_Host_Template driver_template = {
#ifdef  CONFIG_PROC_FS
    .proc_info =                isplinux_proc_info,
#endif
    .name =                     "Qlogic ISP 10X0/2X00",
    .module =                   THIS_MODULE,
    .detect =                   isplinux_detect,
    .release =                  ISPLINUX_RELEASE,
    .info =                     isplinux_info,
    .queuecommand =             isplinux_queuecommand,
    .use_new_eh_code =          1,
    .eh_abort_handler =         isplinux_abort,
    .eh_device_reset_handler =  isplinux_bdr,
    .eh_bus_reset_handler =     isplinux_sreset,
    .eh_host_reset_handler =    isplinux_hreset,
    .bios_param =               isplinux_biosparam,
    .can_queue =                1,
    .sg_tablesize =             SG_ALL,
    .use_clustering =           ENABLE_CLUSTERING
};
#include "scsi_module.c"
#else
static struct scsi_host_template driver_template = {
    .name =                     "Qlogic ISP 10X0/2X00",
    .module =                   THIS_MODULE,
    .detect =                   isplinux_detect,
    .release =                  ISPLINUX_RELEASE,
    .info =                     isplinux_info,
    .queuecommand =             isplinux_queuecommand,
    .eh_abort_handler =         isplinux_abort,
    .eh_device_reset_handler =  isplinux_bdr,
    .eh_bus_reset_handler =     isplinux_sreset,
    .eh_host_reset_handler =    isplinux_hreset,
    .slave_configure =          isplinux_slave_configure,
    .bios_param =               isplinux_biosparam,
#ifdef  CONFIG_PROC_FS
    .proc_info =                isplinux_proc_info_26,
#endif
    .can_queue =                1,
    .sg_tablesize =             SG_ALL,
    .use_clustering =           ENABLE_CLUSTERING
};

#ifdef  MODULE
static int __init
isplinux_init(void)
{
    int n, i;
    ispsoftc_t *isp;

    n = isplinux_detect(&driver_template);
    if (n) {
        for (i = 0; i < MAX_ISP; i++) {
            isp = isplist[i];
            if (isp == NULL) {
                continue;
            }
            scsi_scan_host(isp->isp_host);
        }
    }
    return (n);
}

static void __exit
isplinux_exit(void)
{
    int i;
    ispsoftc_t *isp;

    for (i = 0; i < MAX_ISP; i++) {
        isp = isplist[i];
        if (isp) {
            isplinux_release(isp->isp_host);
        }
    }
}
#endif

module_init(isplinux_init);
module_exit(isplinux_exit);
#endif
/*
 * vim:ts=4:sw=4:expandtab
 */
