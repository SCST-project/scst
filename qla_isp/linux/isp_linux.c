/* $Id: isp_linux.c,v 1.252 2009/09/08 01:22:53 mjacob Exp $ */
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
int isp_deadloop_time = 10;    /* how long to wait before assume loop dead */
int isp_fc_id = 111;
int isp_spi_id = 7;
int isp_own_id = 0;
int isp_default_frame_size;
int isp_default_exec_throttle;
int isp_vports = 0;

static char *isp_roles;
static char *isp_wwpns;
static char *isp_wwnns;


#ifdef  ISP_TARGET_MODE

#ifndef ISP_PARENT_TARGET
#define ISP_PARENT_TARGET   scsi_target_handler
#endif

#define CALL_PARENT_TMD(hba, tmd, action)       \
    tmd->cd_action = action;                    \
    tmd->cd_next = hba->isp_osinfo.pending_t;   \
    hba->isp_osinfo.pending_t = tmd

#define CALL_PARENT_NOTIFY(hba, ins)                            \
    ins->notify.nt_lreserved = hba->isp_osinfo.pending_n;       \
    hba->isp_osinfo.pending_n = ins

#define CALL_PARENT_XFR(hba, xact)                  \
    xact->td_lprivate = hba->isp_osinfo.pending_x;  \
    hba->isp_osinfo.pending_x = xact

extern void ISP_PARENT_TARGET (qact_e, void *);
static ISP_INLINE tmd_cmd_t *isp_find_tmd(ispsoftc_t *, uint64_t);
static void isp_taction(qact_e, void *);
static void isp_target_start_ctio(ispsoftc_t *, tmd_xact_t *);
static void isp_handle_platform_atio(ispsoftc_t *, at_entry_t *);
static void isp_handle_platform_atio2(ispsoftc_t *, at2_entry_t *);
static void isp_handle_platform_atio7(ispsoftc_t *, at7_entry_t *);
static int isp_terminate_cmd(ispsoftc_t *, tmd_cmd_t *);
static void isp_handle_platform_ctio(ispsoftc_t *, void *);
static int isp_target_putback_atio(ispsoftc_t *, tmd_cmd_t *);
static void isp_complete_ctio(ispsoftc_t *, tmd_xact_t *);
static void isp_tgt_tq(ispsoftc_t *);
#endif

const char *
isplinux_info(struct Scsi_Host *host)
{
    ispsoftc_t *isp = ISP_HOST2ISP(host);
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
        } else if (isp->isp_type == ISP_HA_FC_2500) {
            foo[25] = '5';
            foo[26] = '3';
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
static ISP_INLINE void
isplinux_eh_timer_off(Scsi_Cmnd *Cmnd)
{
    if (Cmnd->eh_timeout.function) {
        del_timer(&Cmnd->eh_timeout);
    }
}

static ISP_INLINE void
isplinux_eh_timer_on(Scsi_Cmnd *Cmnd)
{
    if (Cmnd->eh_timeout.function) {
        mod_timer(&Cmnd->eh_timeout, jiffies + Cmnd->timeout_per_command);
    }
}
#else
static ISP_INLINE void
isplinux_eh_timer_on(Scsi_Cmnd *Cmnd)
{
    Cmnd->SCp.ptr = (void *) jiffies;
    Cmnd->SCp.Message = 1;
}

static ISP_INLINE void
isplinux_eh_timer_off(Scsi_Cmnd *Cmnd)
{
    Cmnd->SCp.Message = 0;
}

static enum blk_eh_timer_return isplinux_eh_timed_out(Scsi_Cmnd *Cmnd)
{
    /*
     * Give us more time if command is on our internal wait queue
     * or if time elapsed after removing from wait queue is too small
     */
    if (Cmnd->SCp.Message == 0) {
        return (BLK_EH_RESET_TIMER);
    } else {
        unsigned long start = (unsigned long) Cmnd->SCp.ptr;

        if (time_before(jiffies, start + Cmnd->request->timeout)) {
            return (BLK_EH_RESET_TIMER);
        }
    }

    /*
     * We do not do any error handling here, instruct scsi layer do it
     */
    return (BLK_EH_NOT_HANDLED);
}
#endif

static ISP_INLINE void
isplinux_append_to_waitq(ispsoftc_t *isp, Scsi_Cmnd *Cmnd)
{
    /*
     * If we're a fibre channel card and we consider the loop to be
     * down, we just finish the command here and now.
     */
    if ((IS_FC(isp) && ISP_DATA(isp, XS_CHANNEL(Cmnd))->deadloop) || isp->isp_dead) {
        XS_INITERR(Cmnd);
        XS_SETERR(Cmnd, DID_NO_CONNECT);
        /*
         * Add back a timer else scsi_done drops this on the floor.
         */
        isplinux_eh_timer_on(Cmnd);
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
    isplinux_eh_timer_off(Cmnd);
}

static ISP_INLINE void
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

static ISP_INLINE Scsi_Cmnd *
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

static ISP_INLINE void
isplinux_runwaitq(ispsoftc_t *isp)
{
    Scsi_Cmnd *f;
    int chan, result;


    for (chan = 0; chan < isp->isp_nchan; chan++) {
        if (ISP_DATA(isp, chan)->blocked || ISP_DATA(isp, chan)->qfdelay) {
            continue;
        }
        f = isp->isp_osinfo.wqnext;
        while (f != NULL) {
            Scsi_Cmnd *nxt = (Scsi_Cmnd *) f->host_scribble;
            if (XS_CHANNEL(f) != chan) {
                f = nxt;
                continue;

            }

            f = isp_remove_from_waitq(f);
            result = isp_start(f);

            /*
             * Restart the timer for this command if it is queued or completing.
             */
            if (result == CMD_QUEUED || result == CMD_COMPLETE) {
                isplinux_eh_timer_on(f);
                if (result == CMD_QUEUED) {
                    if (isp->isp_osinfo.hiwater < isp->isp_nactive) {
                        isp->isp_osinfo.hiwater = isp->isp_nactive;
                    }
                    f = isp->isp_osinfo.wqnext;
                    continue;
                }
            }

            /*
             * If we cannot start a command on a fibre channel card, it means
             * that loop state isn't ready for us to do so. Activate the FC
             * thread to rediscover loop and fabric residency- but not if
             * we consider the loop to be dead. If the loop is considered dead,
             * we wait until a PDB Changed after a Loop UP activates the FC
             * thread.
             */
            if (IS_FC(isp)) {
                if (result == CMD_RQLATER && ISP_DATA(isp, XS_CHANNEL(f))->deadloop == 0) {
                    isp_thread_event(isp, ISP_THREAD_FC_RESCAN, FCPARAM(isp, chan), 0, __func__, __LINE__);
                }
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
                isp_prt(isp, ISP_LOGERR, "isplinux_runwaitq: result %d", result);
            }
            f = isp->isp_osinfo.wqnext;
        }
    }
}

static ISP_INLINE void
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
        isplinux_eh_timer_on(Cmnd);
        ISP_LOCK_SCSI_DONE(isp);
        (*Cmnd->scsi_done)(Cmnd);
        ISP_UNLK_SCSI_DONE(isp);
    } while ((Cmnd = Ncmnd) != NULL);
    ISP_IGET_LK_SOFTC(isp);
}

static ISP_INLINE Scsi_Cmnd *
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
    ispsoftc_t *isp = ISP_HOST2ISP(host);
    int result, chan;
    unsigned long flags;


    chan = XS_CHANNEL(Cmnd);
    Cmnd->scsi_done = donecmd;

    ISP_DRIVER_ENTRY_LOCK(isp);
    ISP_LOCK_SOFTC(isp);

    /*
     * See if we're currently blocked. If we are, just queue up the command to be run later.
     */
    if (ISP_DATA(isp, chan)->blocked || ISP_DATA(isp, chan)->qfdelay) {
        isp_prt(isp, ISP_LOGDEBUG0, "appending cmd to waitq due to %d/%d", ISP_DATA(isp, chan)->blocked, ISP_DATA(isp, chan)->qfdelay);
        isplinux_append_to_waitq(isp, Cmnd);
        ISP_UNLK_SOFTC(isp);
        ISP_DRIVER_EXIT_LOCK(isp);
        return (0);
    }

    /*
     * If we get past the above, and we're not at RUNSTATE, we're broken or out of service.
     */
    if (isp->isp_state != ISP_RUNSTATE) {
        isp_prt(isp, ISP_LOGDEBUG0, "DID_NOCONNECT because isp not at RUNSTATE");
        ISP_UNLK_SOFTC(isp);
        ISP_DRIVER_EXIT_LOCK(isp);
        XS_INITERR(Cmnd);
        XS_SETERR(Cmnd, DID_NO_CONNECT);
        ISP_LOCK_SCSI_DONE(isp);
        (*Cmnd->scsi_done)(Cmnd);
        ISP_UNLK_SCSI_DONE(isp);
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
        if (IS_FC(isp) && ISP_DATA(isp, XS_CHANNEL(Cmnd))->deadloop == 0) {
            isp_thread_event(isp, ISP_THREAD_FC_RESCAN, FCPARAM(isp, XS_CHANNEL(Cmnd)), 0, __func__, __LINE__);
        }
        result = 0;
    } else if (result == CMD_COMPLETE) {
        result = -1;
    } else {
        isp_prt(isp, ISP_LOGERR, "unknown return code %d from isp_start", result);
        XS_INITERR(Cmnd);
        XS_SETERR(Cmnd, DID_ERROR);
        ISP_LOCK_SCSI_DONE(isp);
        (*Cmnd->scsi_done)(Cmnd);
        ISP_UNLK_SCSI_DONE(isp);
        return (0);
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

static ISP_INLINE void
isplinux_scsi_probe_done(Scsi_Cmnd *Cmnd)
{
    ispsoftc_t *isp = XS_ISP(Cmnd);
    isp_data *idp;

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

    idp = ISP_DATA(isp, XS_CHANNEL(Cmnd));

    if ((idp->tgts_tested & (1 << XS_TGT(Cmnd))) == 0) {
        sdparam *sdp;
        caddr_t iqd;

        sdp = SDPARAM(isp, XS_CHANNEL(Cmnd));

        if (Cmnd->cmnd[0] == 0x12 && host_byte(Cmnd->result) == DID_OK) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
            if (Cmnd->use_sg == 0) {
                iqd = (caddr_t) Cmnd->request_buffer;
            } else {
                struct scatterlist *sg = (struct scatterlist *) Cmnd->request_buffer;
                iqd = page_address(sg_page(sg)) + sg->offset;
            }
#else
            {
                struct scatterlist *sg = scsi_sglist(Cmnd);
                iqd = page_address(sg_page(sg)) + sg->offset;
            }
#endif
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
            idp->tgts_tested |= (1 << XS_TGT(Cmnd));
        } else if (host_byte(Cmnd->result) != DID_OK) {
            idp->tgts_tested |= (1 << XS_TGT(Cmnd));
        }
        if ((idp->tgts_tested & ~sdp->isp_initiator_id) == (0xffff & ~sdp->isp_initiator_id)) {
            idp->tgts_tested = 0xffff;
            sdp->update = 1;
        }
    }
}

void
isp_done(Scsi_Cmnd *Cmnd)
{
    ispsoftc_t *isp = XS_ISP(Cmnd);

    if (IS_SCSI(isp) && unlikely(ISP_DATA(isp, XS_CHANNEL(Cmnd))->tgts_tested != 0xffff)) {
        isplinux_scsi_probe_done(Cmnd);
    }

    Cmnd->result &= ~0xff;
    Cmnd->result |= Cmnd->SCp.Status;

    if (Cmnd->SCp.Status != GOOD) {
        isp_prt(isp, ISP_LOGDEBUG0, "%d.%d.%d: cmd 0x%x finishes with status 0x%x", XS_CHANNEL(Cmnd), XS_TGT(Cmnd), XS_LUN(Cmnd), XS_CDBP(Cmnd)[0] & 0xff, Cmnd->SCp.Status);
        if (Cmnd->SCp.Status == SCSI_QFULL) {
            ISP_DATA(isp, XS_CHANNEL(Cmnd))->qfdelay = 2 * ISP_WATCH_TPS;
            /*
             * Too many hangups in the midlayer
             */
            isplinux_append_to_waitq(isp, Cmnd);
            return;
        }
    }

    if (Cmnd->underflow > (XS_XFRLEN(Cmnd) - XS_GET_RESID(Cmnd))) {
        XS_SETERR(Cmnd, DID_ERROR);
    }

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
        ISP_DATA(isp, XS_CHANNEL(Cmnd))->qfdelay = ISP_WATCH_TPS;
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
    isp_prt(isp, ISP_LOGINFO, "Bus Device Reset %successfully sent to %d.%d.%d",
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
    ISP_DATA(isp, XS_CHANNEL(Cmnd))->qfdelay = ISP_WATCH_TPS;
    if (IS_FC(isp) && fcp->isp_fwstate == FW_READY && fcp->isp_loopstate == LOOP_READY && fcp->isp_topo == TOPO_F_PORT) {
        ISP_UNLKU_SOFTC(isp);
        ISP_DRIVER_CTL_EXIT_LOCK(isp);
        isp_prt(isp, ISP_LOGINFO, "SCSI Bus Reset request ignored");
        return (SUCCESS);
    }
    r = isp_control(isp, ISPCTL_RESET_DEV, XS_CHANNEL(Cmnd), XS_TGT(Cmnd));
    ISP_UNLKU_SOFTC(isp);
    ISP_DRIVER_CTL_EXIT_LOCK(isp);
    isp_prt(isp, ISP_LOGINFO, "Chan %d SCSI Bus Reset %successful", XS_CHANNEL(Cmnd), r == 0? "s" : "uns");
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

    (void) isplinux_reinit(isp, 0);

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
    void *pool, *npool;
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
    npool = isp_kzalloc(N_NOTIFIES * sizeof (notify_t), GFP_KERNEL);
    if (npool == NULL) {
        isp_prt(isp, ISP_LOGERR, "cannot allocate TMD NOTIFY structures");
        isp_kfree(pool, NTGT_CMDS * TMD_SIZE);
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
    memset(isp->isp_osinfo.auxbmap, 0, sizeof (isp->isp_osinfo.auxbmap));
    memcpy(isp->isp_osinfo.inqdata, inqdsd, DEFAULT_INQSIZE);
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
    snprintf(hba.r_name, sizeof (hba.r_name), ISP_NAME);
    hba.r_inst = isp->isp_unit;
    hba.r_version = QR_VERSION;
    hba.r_action = isp_taction;
    hba.r_locator = isp->isp_osinfo.device_id;
    hba.r_nchannels = isp->isp_nchan;
    if (IS_FC(isp)) {
        hba.r_type = R_FC;
    } else{
        hba.r_type = R_SPI;
    }
    hba.r_private = NULL;
    ISP_PARENT_TARGET(QOUT_HBA_REG, &hba);
}

void
isp_deinit_target(ispsoftc_t *isp)
{
    void *pool, *npool;
    unsigned long flags;

    ISP_LOCK_SOFTC(isp);
    pool = isp->isp_osinfo.pool;
    isp->isp_osinfo.pool = NULL;
    npool = isp->isp_osinfo.npool;
    isp->isp_osinfo.npool = NULL;
    ISP_UNLK_SOFTC(isp);
    if (pool) {
        isp_kfree(pool, NTGT_CMDS * TMD_SIZE);
    }
    if (npool) {
        isp_kfree(npool, N_NOTIFIES * sizeof (notify_t));
    }
}

void
isp_detach_target(ispsoftc_t *isp)
{
    hba_register_t hba;
    struct semaphore rsem;

    hba.r_identity = isp;
    snprintf(hba.r_name, sizeof (hba.r_name), ISP_NAME);
    hba.r_inst = isp->isp_unit;
    hba.r_version = QR_VERSION;
    hba.r_action = isp_taction;
    hba.r_nchannels = isp->isp_nchan;
    if (IS_FC(isp)) {
        hba.r_type = R_FC;
    } else{
        hba.r_type = R_SPI;
    }
    hba.r_private = &rsem;
    sema_init(&rsem, 0);
    ISP_PARENT_TARGET(QOUT_HBA_UNREG, &hba);
    down(&rsem);
}

static void
isp_tgt_tq(ispsoftc_t *isp)
{
    notify_t *ins;
    tmd_cmd_t *tmd;
    tmd_xact_t *xact;
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
    xact = isp->isp_osinfo.pending_x;
    if (xact) {
        isp->isp_osinfo.pending_x = NULL;
    }
    ISP_UNLK_SOFTC(isp);
    while (ins != NULL) {
        notify_t *next = ins->notify.nt_lreserved;
        ins->notify.nt_lreserved = NULL;
        isp_prt(isp, ISP_LOGTDEBUG2, "isp_tgt_tq -> notify 0x%x", ins->notify.nt_ncode);
        ISP_PARENT_TARGET(QOUT_NOTIFY, ins);
        ins = next;
    }
    while (tmd != NULL) {
        tmd_cmd_t *next = tmd->cd_next;
        tmd->cd_next = NULL;
        isp_prt(isp, ISP_LOGTDEBUG2, "isp_tgt_tq[%llx] -> code 0x%x", (ull) tmd->cd_tagval, tmd->cd_action);
        ISP_PARENT_TARGET(tmd->cd_action, tmd);
        tmd = next;
    }
    while (xact != NULL) {
        tmd_xact_t *next = xact->td_lprivate;
        xact->td_lprivate = NULL;
        ISP_PARENT_TARGET(QOUT_TMD_DONE, xact);
        xact = next;
    }
}

static ISP_INLINE tmd_cmd_t *
isp_find_tmd(ispsoftc_t *isp, uint64_t tagval)
{
    int i;
    tmd_cmd_t *tmd = isp->isp_osinfo.pool;

    if (tmd == NULL || tagval == TAG_ANY) {
        return (NULL);
    }
    for (i = 0; i < NTGT_CMDS; i++) {
        if ((tmd->cd_lflags & CDFL_BUSY) && tmd->cd_tagval == tagval) {
            return (tmd);
        }
        tmd++;
    }
    return (NULL);
}

static void
isp_tgt_dump_pdb(ispsoftc_t *isp, int chan)
{
    fcparam *fcp;
    int i;

    if (chan >= isp->isp_nchan) {
        return;
    }

    fcp = FCPARAM(isp, chan);
    for (i = MAX_FC_TARG-1; i >= 0; i--) {
        fcportdb_t *lp = &fcp->portdb[i];

        if (lp->target_mode == 0) {
            continue;
        }
        isp_prt(isp, ISP_LOGTINFO, "PDB[%d]: Chan %d 0x%016llx Port-ID 0x%06x N-Port Handle 0x%04x", i, chan, (ull) lp->port_wwn, lp->portid, lp->handle);
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
            printk(KERN_ERR "null isp @ %s:%s:%d\n", __FILE__, __func__, __LINE__);
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
        if (ip->i_channel >= isp->isp_nchan) {
            ip->i_error = -ENODEV;
        } else if (IS_FC(isp)) {
            fcparam *fcp = FCPARAM(isp, ip->i_channel);
            ip->i_type = I_FC;
            ip->i_id.fc.wwnn_nvram = fcp->isp_wwnn_nvram;
            ip->i_id.fc.wwpn_nvram = fcp->isp_wwpn_nvram;
            ip->i_id.fc.wwnn = fcp->isp_wwnn;
            ip->i_id.fc.wwpn = fcp->isp_wwpn;
            ip->i_error = 0;
        } else {
            sdparam *sdp = SDPARAM(isp, ip->i_channel);
            ip->i_type = I_SPI;
            ip->i_id.spi.iid = sdp->isp_initiator_id;
            ip->i_error = 0;
        }
        break;
    }
    case QIN_SETINFO:
    {
        info_t *ip = arg;
        isp = ip->i_identity;
        if (ip->i_type == I_FC) {
            FCPARAM(isp, ip->i_channel)->isp_wwnn = ip->i_id.fc.wwnn;
            FCPARAM(isp, ip->i_channel)->isp_wwpn = ip->i_id.fc.wwpn;
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
            rv = isp_control(isp, ISPCTL_GET_NAMES, chan, nph, NULL, &wwpn);
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
            printk(KERN_ERR "null isp @ %s:%s:%d\n", __FILE__, __func__, __LINE__);
            break;
        }
        ep->en_error = isp_enable_lun(isp, ep->en_chan, ep->en_lun);
        ISP_PARENT_TARGET(QOUT_ENABLE, ep);
        break;

    case QIN_DISABLE:
        ep = arg;
        isp = ep->en_hba;
        if (isp == NULL) {
            printk(KERN_ERR "null isp @ %s:%s:%d\n", __FILE__, __func__, __LINE__);
            break;
        }
        ep->en_error = isp_disable_lun(isp, ep->en_chan, ep->en_lun);
        ISP_PARENT_TARGET(QOUT_DISABLE, ep);
        ISP_LOCK_SOFTC(isp);
        if (ep->en_error == 0) {
            (void) isp_target_async(isp, 0, ASYNC_LOOP_DOWN);
        }
        ISP_UNLK_SOFTC(isp);
        break;

    case QIN_TMD_CONT:
    {
        tmd_xact_t *xact = arg;
        tmd = xact->td_cmd;
        isp = tmd->cd_hba;
        isp_target_start_ctio(isp, arg);
        break;
    }
    case QIN_TMD_FIN:
        tmd = (tmd_cmd_t *) arg;
        isp = tmd->cd_hba;
        if (isp == NULL) {
            printk(KERN_ERR "null isp @ %s:%s:%d\n", __FILE__, __func__, __LINE__);
            break;
        }
        ISP_LOCK_SOFTC(isp);
        isp_prt(isp, ISP_LOGTDEBUG1, "freeing tmd %p [%llx]", tmd, (ull) tmd->cd_tagval);
        if (tmd->cd_lflags & CDFL_RESRC_FILL) {
            if (isp_target_putback_atio(isp, tmd)) {
                isp_thread_event(isp, ISP_THREAD_FC_PUTBACK, tmd, 0, __func__, __LINE__);
                ISP_UNLK_SOFTC(isp);
                break;
            }
        }
        if (tmd->cd_lflags & CDFL_NEED_CLNUP) {
            tmd->cd_lflags &= ~CDFL_NEED_CLNUP;
            isp_prt(isp, ISP_LOGTINFO, "Terminating [%llx] on FIN", (ull) tmd->cd_tagval);
            (void) isp_terminate_cmd(isp, tmd);
        }
        tmd->cd_next = NULL;
        if (isp->isp_osinfo.tfreelist) {
            isp->isp_osinfo.bfreelist->cd_next = tmd;
        } else {
            isp->isp_osinfo.tfreelist = tmd;
        }
        isp->isp_osinfo.bfreelist = tmd; /* remember to move the list tail pointer */
        isp_prt(isp, ISP_LOGTDEBUG1, "DONE freeing tmd %p [%llx]", tmd, (ull) tmd->cd_tagval);
        ISP_UNLK_SOFTC(isp);
        break;

    case QIN_NOTIFY_ACK:
    {
        notify_t *ins = (notify_t *) arg;

        isp = ins->notify.nt_hba;
        if (isp == NULL) {
            printk(KERN_ERR "null isp @ %s:%s:%d\n", __FILE__, __func__, __LINE__);
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
            if (ins->notify.nt_failed) {
                isp_prt(isp, ISP_LOGWARN, "[%llx] notify code 0x%x returned back with failure",  (ull) ins->notify.nt_tagval, ins->notify.nt_ncode);
            }
            if (isp->isp_state != ISP_RUNSTATE) {
                isp_prt(isp, ISP_LOGTINFO, "[%llx] Notify Code 0x%x (qevalid=%d) acked- h/w not ready (dropping)",
                    (ull) ins->notify.nt_tagval, ins->notify.nt_ncode, ins->qevalid);
            }

            /*
             * This case is for a Task Management Function, which shows up as an ATIO7 entry.
             */
            if (IS_24XX(isp) && ins->qevalid && ((isphdr_t *)ins->qentry)->rqs_entry_type == RQSTYPE_ATIO) {
                ct7_entry_t local, *cto = &local;
                at7_entry_t *aep = (at7_entry_t *)ins->qentry;
                fcportdb_t *lp;
                uint32_t sid;
                uint16_t nphdl;

                sid = (aep->at_hdr.s_id[0] << 16) | (aep->at_hdr.s_id[1] << 8) | aep->at_hdr.s_id[2];
                if (isp_find_pdb_by_sid(isp, ins->notify.nt_channel, sid, &lp)) {
                    nphdl = lp->handle;
                } else {
                    nphdl = NIL_HANDLE;
                }
                memset(&local, 0, sizeof (local));
                cto->ct_header.rqs_entry_type = RQSTYPE_CTIO7;
                cto->ct_header.rqs_entry_count = 1;
                cto->ct_nphdl = nphdl;
                cto->ct_rxid = aep->at_rxid;
                cto->ct_vpidx = ins->notify.nt_channel;
                cto->ct_iid_lo = sid;
                cto->ct_iid_hi = sid >> 16;
                cto->ct_oxid = aep->at_hdr.ox_id;
                cto->ct_flags = CT7_SENDSTATUS|CT7_NOACK|CT7_NO_DATA|CT7_FLAG_MODE1;
                cto->ct_flags |= (aep->at_ta_len >> 12) << CT7_TASK_ATTR_SHIFT;

		/* set response */
		cto->ct_scsi_status = (FCP_RSPLEN_VALID << 8);
		cto->rsp.m1.ct_resplen = FCP_MAX_RSPLEN;
		ISP_MEMZERO(cto->rsp.m1.ct_resp, FCP_MAX_RSPLEN);
		cto->rsp.m1.ct_resp[3] = ins->tmf_resp;
		isp_prt(isp, ISP_LOGINFO, "[%llx] TMF response. status %d",
			(ull)ins->notify.nt_tagval, ins->tmf_resp);
		WARN_ON(isp_target_put_entry(isp, &local)); /* XXX FIX ME XXX */
		break;
	}

            /*
             * This case is for a responding to an ABTS frame
             */
            if (IS_24XX(isp) && ins->qevalid && ((isphdr_t *)ins->qentry)->rqs_entry_type == RQSTYPE_ABTS_RCVD) {
                uint8_t storage[QENTRY_LEN];
                ct7_entry_t *cto = (ct7_entry_t *) storage;
                abts_t *abts = (abts_t *)ins->qentry;

                ISP_MEMZERO(cto, sizeof (ct7_entry_t));
                isp_prt(isp, ISP_LOGTDEBUG0, "%s: [%x] terminating after ABTS received", __func__, abts->abts_rxid_task);
                cto->ct_header.rqs_entry_type = RQSTYPE_CTIO7;
                cto->ct_header.rqs_entry_count = 1;
                cto->ct_nphdl = ins->notify.nt_nphdl;
                cto->ct_rxid = abts->abts_rxid_task;
                cto->ct_iid_lo = ins->notify.nt_sid;
                cto->ct_iid_hi = ins->notify.nt_sid >> 16;
                cto->ct_oxid = abts->abts_ox_id;
                cto->ct_vpidx = ins->notify.nt_channel;
                cto->ct_flags = CT7_NOACK|CT7_TERMINATE;
                WARN_ON(isp_target_put_entry(isp, cto));
                WARN_ON(isp_acknak_abts(isp, ins->qentry, 0));
                break;
            }

            /*
             * General purpose acknowledgement
             */
            if (ins->notify.nt_need_ack) {
                isp_prt(isp, ISP_LOGTINFO, "[%llx] Notify Code 0x%x (qevalid=%d) being acked", (ull) ins->notify.nt_tagval, ins->notify.nt_ncode, ins->qevalid);
                WARN_ON(isp_notify_ack(isp, ins->qevalid? ins->qentry : NULL));
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
            printk(KERN_ERR "null isp @ %s:%s:%d\n", __FILE__, __func__, __LINE__);
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
        /* force ourselves to not run any queues now */
        isp = NULL;
        break;
    default:
        printk(KERN_ERR "isp_taction: unknown action %x, arg %p\n", action, arg);
        break;
    }
    if (isp) {
        isp_tgt_tq(isp);
    }
}

static int
lunenabled(ispsoftc_t *isp, uint16_t bus, uint16_t lun)
{
    tgt_enalun_t *axl = isp->isp_osinfo.luns;
    while (axl) {
        if (axl->bus == bus && axl->lun == lun) {
            return (1);
        }
        axl = axl->next;
    }
    return (0);
}

static int
nolunsenabled(ispsoftc_t *isp, uint16_t bus)
{
    tgt_enalun_t *axl = isp->isp_osinfo.luns;
    while (axl) {
        if (axl->bus == bus) {
            return (0);
        }
        axl = axl->next;
    }
    return (1);
}

static ISP_INLINE void
addlun(ispsoftc_t *isp, tgt_enalun_t *axl, uint16_t bus, uint16_t lun)
{
    axl->lun = lun;
    axl->bus = bus;
    axl->next = isp->isp_osinfo.luns;
    isp->isp_osinfo.luns = axl;
}

static ISP_INLINE tgt_enalun_t *
remlun(ispsoftc_t *isp, uint16_t bus, uint16_t lun)
{
    tgt_enalun_t *axl, *axy = NULL;
    axl = isp->isp_osinfo.luns;
    if (axl == NULL) {
        return (axy);
    }
    if (axl->lun == lun && axl->bus == bus) {
        isp->isp_osinfo.luns = axl->next;
        axy = axl;
    } else {
        while (axl->next) {
            if (axl->next->lun == lun && axl->next->bus == bus) {
                axy = axl->next;
                axl->next = axy->next;
                break;
            }
            axl = axl->next;
        }
    }
    return (axy);
}

static void
isp_target_start_ctio(ispsoftc_t *isp, tmd_xact_t *xact)
{
    void *qe;
    uint32_t handle, orig_xfrlen = 0;
    uint8_t local[QENTRY_LEN];
    unsigned long flags;
    int32_t resid;
    tmd_cmd_t *tmd = xact->td_cmd;

    xact->td_lflags &= ~TDFL_ERROR;
    xact->td_error = 0;

    /*
     * Use this lock to protect tmd fields
     */
    ISP_LOCK_SOFTC(isp);

    /*
     * Pre-increment cd_moved so we know how many bytes are actually in transit. If we actually fail to move
     * the bytes, we'll subtract things out when we collect status. If we fail to even start the transfer
     * (due to inability to even get queue space), we'll subtract that as well too.
     */
    orig_xfrlen = xact->td_xfrlen;
    tmd->cd_moved += orig_xfrlen;

    /*
     * Set the residual to be equal to the total length less the amount previously moved plus this transfer size
     */
    resid = tmd->cd_totlen - tmd->cd_moved;


    /*
     * Check for commands that are already dead
     */
    if (tmd->cd_lflags & CDFL_ABORTED) {
        isp_prt(isp, ISP_LOGTINFO, "%s: [%llx] already ABORTED- not sending a CTIO", __func__, (ull) tmd->cd_tagval);
        xact->td_error = -ENXIO;
        goto out;
    }

    /*
     * If the transfer length is zero, we have to be sending status.
     * If we're sending data, we have to have one and only one data
     * direction set.
     */
    if (xact->td_xfrlen == 0) {
        if ((xact->td_hflags & TDFH_STSVALID) == 0) {
            isp_prt(isp, ISP_LOGERR, "%s: a CTIO, no data, and no status is wrong", __func__);
            dump_stack();
            xact->td_error = -EINVAL;
            goto out;
        }
    } else {
        if ((xact->td_hflags & TDFH_DATA_MASK) == 0) {
            isp_prt(isp, ISP_LOGERR, "%s: a data CTIO with no direction is wrong", __func__);
            dump_stack();
            xact->td_error = -EINVAL;
            goto out;
        }
        if ((xact->td_hflags & TDFH_DATA_MASK) == TDFH_DATA_MASK) {
            isp_prt(isp, ISP_LOGERR, "%s: a data CTIO with both directions is wrong (for now)", __func__);
            dump_stack();
            xact->td_error = -EINVAL;
            goto out;
        }
    }

    if ((xact->td_hflags & TDFH_STSVALID) && tmd->cd_scsi_status == SCSI_CHECK && (xact->td_hflags & TDFH_SNSVALID) && tmd->cd_sense[0] == 0) {
        isp_prt(isp, ISP_LOGWARN, "%s: [%llx] cdb0 0x%02x CHECK CONDITION but bogus sense 0x%x/0x%x/0x%x", __func__, (ull) tmd->cd_tagval, tmd->cd_cdb[0], tmd->cd_sense[0], tmd->cd_sense[12], tmd->cd_sense[13]);
    }

    memset(local, 0, QENTRY_LEN);

    /*
     * We're either moving data or completing a command here (or both).
     */
    if (IS_24XX(isp)) {
        ct7_entry_t *cto = (ct7_entry_t *) local;
        int tattr;

        cto->ct_header.rqs_entry_type = RQSTYPE_CTIO7;
        cto->ct_header.rqs_entry_count = 1;
        cto->ct_header.rqs_seqno = 1;
        cto->ct_nphdl = tmd->cd_nphdl;
        cto->ct_rxid = tmd->cd_tagval;
        cto->ct_iid_lo = tmd->cd_portid;
        cto->ct_iid_hi = tmd->cd_portid >> 16;
        cto->ct_oxid = tmd->cd_oxid;
        cto->ct_vpidx = tmd->cd_channel;
        cto->ct_scsi_status = tmd->cd_scsi_status;
        cto->ct_timeout = ISP_CT_TIMEOUT;

        switch (tmd->cd_tagtype) {
        case CD_SIMPLE_TAG:
            tattr = FCP_CMND_TASK_ATTR_SIMPLE;
            break;
        case CD_HEAD_TAG:
            tattr = FCP_CMND_TASK_ATTR_HEAD;
            break;
        case CD_ORDERED_TAG:
            tattr = FCP_CMND_TASK_ATTR_ORDERED;
            break;
        case CD_ACA_TAG:
            tattr = FCP_CMND_TASK_ATTR_ACA;
            break;
        default:
            tattr = FCP_CMND_TASK_ATTR_UNTAGGED;
            break;
        }
        cto->ct_flags = tattr << CT7_TASK_ATTR_SHIFT;

        if (xact->td_xfrlen == 0) {
            cto->ct_flags |= CT7_FLAG_MODE1 | CT7_NO_DATA | CT7_SENDSTATUS;
            if ((xact->td_hflags & TDFH_SNSVALID) != 0) {
                cto->rsp.m1.ct_resplen = cto->ct_senselen = min(TMD_SENSELEN, MAXRESPLEN_24XX);
                memcpy(cto->rsp.m1.ct_resp, tmd->cd_sense, cto->ct_senselen);
                cto->ct_scsi_status |= (FCP_SNSLEN_VALID << 8);
            }
        } else {
            cto->rsp.m0.ct_xfrlen = xact->td_xfrlen;
            cto->rsp.m0.reloff = tmd->cd_moved - orig_xfrlen;
            cto->ct_flags |= CT7_FLAG_MODE0;
            if (xact->td_hflags & TDFH_DATA_IN) {
                cto->ct_flags |= CT7_DATA_IN;
            } else {
                cto->ct_flags |= CT7_DATA_OUT;
            }
            if (xact->td_hflags & TDFH_STSVALID) {
                cto->ct_flags |= CT7_SENDSTATUS;
            }
        }

        if ((cto->ct_flags & CT7_SENDSTATUS) && resid) {
            cto->ct_resid = resid;
            if (resid < 0) {
                cto->ct_scsi_status |= (FCP_RESID_OVERFLOW << 8);
            } else {
                cto->ct_scsi_status |= (FCP_RESID_UNDERFLOW << 8);
            }
        }
        isp_prt(isp, ISP_LOGTDEBUG0, "%s: CTIO7[%llx] scsi sts %x flags %x resid %d offset %u", __func__, (ull) tmd->cd_tagval, tmd->cd_scsi_status, cto->ct_flags, resid, xact->td_offset);
    } else if (IS_FC(isp)) {
        ct2_entry_t *cto = (ct2_entry_t *) local;
        uint16_t *ssptr = NULL;

        cto->ct_header.rqs_entry_type = RQSTYPE_CTIO2;
        cto->ct_header.rqs_entry_count = 1;
        cto->ct_header.rqs_seqno = 1;
        if (ISP_CAP_2KLOGIN(isp)) {
            ((ct2e_entry_t *)cto)->ct_iid = tmd->cd_nphdl;
        } else {
            cto->ct_iid = tmd->cd_nphdl;
        }
        if (ISP_CAP_SCCFW(isp)) {
            cto->ct_lun = L0LUN_TO_FLATLUN(tmd->cd_lun);
        }
        cto->ct_rxid = tmd->cd_tagval;
        if (cto->ct_rxid == 0) {
            isp_prt(isp, ISP_LOGERR, "a tagval of zero is not acceptable");
            xact->td_error = -EINVAL;
            goto out;
        }
        cto->ct_timeout = ISP_CT_TIMEOUT;
#if    0
        /*
         * I've had problems with this at varying times- dunno why
         */
        cto->ct_flags = CT2_FASTPOST;
#endif

        if (xact->td_xfrlen == 0) {
            cto->ct_flags |= CT2_FLAG_MODE1 | CT2_NO_DATA | CT2_SENDSTATUS;
            ssptr = &cto->rsp.m1.ct_scsi_status;
            *ssptr = tmd->cd_scsi_status;
            if ((xact->td_hflags & TDFH_SNSVALID) != 0) {
                cto->rsp.m1.ct_senselen = min(TMD_SENSELEN, MAXRESPLEN);
                memcpy(cto->rsp.m1.ct_resp, tmd->cd_sense, cto->rsp.m1.ct_senselen);
                cto->rsp.m1.ct_scsi_status |= CT2_SNSLEN_VALID;
            }
        } else {
            cto->ct_reloff = tmd->cd_moved - orig_xfrlen;
            cto->ct_flags |= CT2_FLAG_MODE0;
            if (xact->td_hflags & TDFH_DATA_IN) {
                cto->ct_flags |= CT2_DATA_IN;
            } else {
                cto->ct_flags |= CT2_DATA_OUT;
            }
            cto->rsp.m0.ct_xfrlen = xact->td_xfrlen;
            if (xact->td_hflags & TDFH_STSVALID) {
                ssptr = &cto->rsp.m0.ct_scsi_status;
                cto->ct_flags |= CT2_SENDSTATUS;
                cto->rsp.m0.ct_scsi_status = tmd->cd_scsi_status;
                /*
                 * It will be up to the low level mapping routine
                 * to check for sense data.
                 */
            }
        }

        if (ssptr && resid) {
            cto->ct_resid = resid;
            if (resid < 0) {
                *ssptr |= CT2_DATA_OVER;
            } else {
                *ssptr |= CT2_DATA_UNDER;
            }
        }
        if (cto->ct_flags & CT2_SENDSTATUS) {
            cto->ct_flags |= CT2_CCINCR;
        }
        isp_prt(isp, ISP_LOGTDEBUG0, "%s: CTIO2[%llx] scsi sts %x flags %x resid %d", __func__, (ull) tmd->cd_tagval, tmd->cd_scsi_status, cto->ct_flags, resid);
    } else {
        ct_entry_t *cto = (ct_entry_t *) local;

        cto->ct_header.rqs_entry_type = RQSTYPE_CTIO;
        cto->ct_header.rqs_entry_count = 1;
        cto->ct_header.rqs_seqno = 1;
        cto->ct_iid = tmd->cd_iid;
        cto->ct_tgt = tmd->cd_tgt;
        cto->ct_lun = L0LUN_TO_FLATLUN(tmd->cd_lun);
        cto->ct_fwhandle = AT_GET_HANDLE(tmd->cd_tagval);
        cto->ct_timeout = ISP_CT_TIMEOUT;
        if (AT_HAS_TAG(tmd->cd_tagval)) {
            cto->ct_tag_val = AT_GET_TAG(tmd->cd_tagval);
            cto->ct_flags |= CT_TQAE;
        }
        if (tmd->cd_flags & CDF_NODISC) {
            cto->ct_flags |= CT_NODISC;
        }
        if (xact->td_xfrlen == 0) {
            cto->ct_flags |= CT_NO_DATA | CT_SENDSTATUS;
            cto->ct_scsi_status = tmd->cd_scsi_status;
        } else {
            if (xact->td_hflags & TDFH_STSVALID) {
                cto->ct_flags |= CT_SENDSTATUS;
            }
            if (xact->td_hflags & TDFH_DATA_IN) {
                cto->ct_flags |= CT_DATA_IN;
            } else {
                cto->ct_flags |= CT_DATA_OUT;
            }
            /*
             * We assume we'll transfer what we say we'll transfer.
             * Otherwise, the command is dead.
             */
            if (xact->td_hflags & TDFH_STSVALID) {
                cto->ct_resid = resid;
            }
        }
        if (cto->ct_flags & CT_SENDSTATUS) {
            cto->ct_flags |= CT_CCINCR;
        }
        isp_prt(isp, ISP_LOGTDEBUG0, "%s: CTIO[%llx] scsi sts %x resid %d cd_lflags %x", __func__, (ull) tmd->cd_tagval, tmd->cd_scsi_status, resid, xact->td_hflags);
    }

    qe = isp_getrqentry(isp);
    if (qe == NULL) {
        isp_prt(isp, ISP_LOGWARN, "%s: request queue overflow", __func__);
        xact->td_error = -ENOMEM;
        goto out;
    }

    if (isp_save_xs_tgt(isp, xact, &handle)) {
        isp_prt(isp, ISP_LOGERR, "%s: No XFLIST pointers", __func__);
        xact->td_error = -ENOMEM;
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

    switch (ISP_DMASETUP(isp, (XS_T *)xact, local)) {
    case CMD_QUEUED:
        tmd->cd_req_cnt += 1;
        ISP_UNLK_SOFTC(isp);
        return;

    case CMD_EAGAIN:
        xact->td_error = -ENOMEM;
        /* FALLTHROUGH */

    case CMD_COMPLETE:
        BUG_ON(xact->td_error == 0);
        isp_destroy_tgt_handle(isp, handle);
        break;

    default:
        BUG();
        break;
    }

out:
    /*
     * XXX: Note that this is different from the vanilla Feral driver
     * XXX: which requires a callback no matter what. SCST requires
     * XXX: synchronous error returns if you can't start a command
     * XXX: and to avoid race conditions and locks we don't do an
     * XXX: upcall in this case.
     */
    if (xact->td_error) {
        xact->td_lflags |= TDFL_ERROR|TDFL_SYNCERROR;
        tmd->cd_moved -= orig_xfrlen;
    } else if ((tmd->cd_lflags & CDFL_LCL) == 0) {
        CALL_PARENT_XFR(isp, xact);
    }
    ISP_UNLK_SOFTC(isp);
}

static void
isp_lcl_respond(ispsoftc_t *isp, void *aep, tmd_cmd_t *tmd)
{
    uint8_t *cdbp;

    if (IS_24XX(isp)) {
        cdbp = ((at7_entry_t *)aep)->at_cmnd.cdb_dl.sf.fcp_cmnd_cdb;
    } else if (IS_FC(isp)) {
        cdbp = ((at2_entry_t *)aep)->at_cdb;
    } else {
        cdbp = ((at_entry_t *)aep)->at_cdb;
    }

    if (cdbp[0] == INQUIRY && L0LUN_TO_FLATLUN(tmd->cd_lun) == 0) {
        if (cdbp[1] == 0 && cdbp[2] == 0 && cdbp[3] == 0 && cdbp[5] == 0) {
            tmd_xact_t *xact;
            struct scatterlist *dp;
            int amt, i;

            for (i = 0; i < N_TGT_AUX; i++) {
                if (ISP_BTST(isp->isp_osinfo.auxbmap, i)) {
                    break;
                }
            }
            if (i == N_TGT_AUX) {
                if (IS_24XX(isp)) {
                    isp_endcmd(isp, aep, tmd->cd_nphdl, tmd->cd_channel, SCSI_BUSY, 0);
                } else {
                    isp_endcmd(isp, aep, SCSI_BUSY, 0);
                }

                return;
            }
            ISP_BSET(isp->isp_osinfo.auxbmap, i);
            xact = &isp->isp_osinfo.auxinfo[i].xact;
            dp = &isp->isp_osinfo.auxinfo[i].sg;
            memset(dp, 0, sizeof (*dp));
            sg_assign_page(dp, virt_to_page(isp->isp_osinfo.inqdata));
            dp->offset = offset_in_page(isp->isp_osinfo.inqdata);
            dp->length = DEFAULT_INQSIZE;

            xact->td_data = dp;
            xact->td_xfrlen = min(DEFAULT_INQSIZE, tmd->cd_totlen);
            if ((amt = cdbp[4]) == 0) {
                amt = 256;
            }
            if (xact->td_xfrlen > amt) {
                xact->td_xfrlen = amt;
            }
            xact->td_hflags |= TDFH_DATA_IN|TDFH_STSVALID;
            xact->td_cmd = tmd;
            xact->td_offset = 0;
            xact->td_error = 0;
            xact->td_lflags = 0;

            tmd->cd_scsi_status = 0;
            tmd->cd_lflags |= CDFL_LCL;
            ISP_DROP_LK_SOFTC(isp);
            isp_target_start_ctio(isp, xact);
            ISP_IGET_LK_SOFTC(isp);
            return;
        }
        /*
         * Illegal field in CDB
         *  0x24 << 24 | 0x5 << 12 | ECMD_SVALID | SCSI_CHECK
         */
        if (IS_24XX(isp)) {
            isp_endcmd(isp, aep, tmd->cd_nphdl, tmd->cd_channel, 0x24005102, 0);
        } else {
            isp_endcmd(isp, aep, 0x24005102, 0);
        }
    } else if (L0LUN_TO_FLATLUN(tmd->cd_lun) == 0) {
        /*
         * Not Ready, Cause Not Reportable
         *
         *  0x4 << 24 | 0x2 << 12 | ECMD_SVALID | SCSI_CHECK
         */
        if (IS_24XX(isp)) {
            isp_endcmd(isp, aep, tmd->cd_nphdl, tmd->cd_channel, 0x04002102, 0);
        } else {
            isp_endcmd(isp, aep, 0x04002102, 0);
        }
    } else {
        /*
         * Logical Unit Not Supported:
         *     0x25 << 24 | 0x5 << 12 | ECMD_SVALID | SCSI_CHECK
         */
        if (IS_24XX(isp)) {
            isp_endcmd(isp, aep, tmd->cd_nphdl, tmd->cd_channel, 0x25005102, 0);
        } else {
            isp_endcmd(isp, aep, 0x25005102, 0);
        }
    }
    memset(tmd, 0, TMD_SIZE);
    if (isp->isp_osinfo.tfreelist) {
        isp->isp_osinfo.bfreelist->cd_next = tmd;
    } else {
        isp->isp_osinfo.tfreelist = tmd;
    }
    isp->isp_osinfo.bfreelist = tmd;
}

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
        if (isp->isp_osinfo.out_of_tmds == 0) {
            isp_prt(isp, ISP_LOGWARN, "out of TMDs");
            isp->isp_osinfo.out_of_tmds = jiffies;
        }
        isp_endcmd(isp, aep, SCSI_BUSY, 0);
        if (jiffies - isp->isp_osinfo.out_of_tmds > 30 * HZ) {
            isp_prt(isp, ISP_LOGERR, "out of TMDs too long: disabling port");
            isp_thread_event(isp, ISP_THREAD_REINIT, NULL, 0, __func__, __LINE__);
        }
        return;
    }
    isp->isp_osinfo.out_of_tmds = 0;
    if ((isp->isp_osinfo.tfreelist = tmd->cd_next) == NULL) {
        isp->isp_osinfo.bfreelist = NULL;
    }
    memset(tmd, 0, TMD_SIZE);

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
        tmd->cd_flags |= CDF_NODISC;
    }
    if (status & QLTM_SVALID) {
        memcpy(tmd->cd_sense, aep->at_sense, QLTM_SENSELEN);
        tmd->cd_flags |= CDF_SNSVALID;
    }
    memcpy(tmd->cd_cdb, aep->at_cdb, min(TMD_CDBLEN, ATIO_CDBLEN));
    AT_MAKE_TAGID(tmd->cd_tagval, aep);
    tmd->cd_tagtype = aep->at_tag_type;
    tmd->cd_hba = isp;
    isp_prt(isp, ISP_LOGTDEBUG0, "ATIO[%llx] CDB=0x%x bus %d iid%d->lun%d ttype 0x%x %s", (ull) tmd->cd_tagval, aep->at_cdb[0] & 0xff,
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
        CALL_PARENT_TMD(isp, tmd, QOUT_TMD_START);
    }
}

static void
isp_handle_platform_atio2(ispsoftc_t *isp, at2_entry_t *aep)
{
    tmd_cmd_t *tmd;
    uint16_t lun, loopid;

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
        loopid = aep2->at_iid;
    } else {
        loopid = aep->at_iid;
        if (ISP_CAP_SCCFW(isp)) {
            lun = aep->at_scclun;
        } else {
            lun = aep->at_lun;
        }
    }

    /*
     * If we're out of resources, just send a BUSY status back.
     */
    if ((tmd = isp->isp_osinfo.tfreelist) == NULL) {
        if (isp->isp_osinfo.out_of_tmds == 0) {
            isp_prt(isp, ISP_LOGWARN, "out of TMDs");
            isp->isp_osinfo.out_of_tmds = jiffies;
        }
        isp_endcmd(isp, aep, SCSI_BUSY, 0);
        if (jiffies - isp->isp_osinfo.out_of_tmds > 30 * HZ) {
            isp_prt(isp, ISP_LOGERR, "out of TMDs too long: disabling port");
            isp_thread_event(isp, ISP_THREAD_REINIT, NULL, 0, __func__, __LINE__);
        }
        return;
    }
    isp->isp_osinfo.out_of_tmds = 0;
    if ((isp->isp_osinfo.tfreelist = tmd->cd_next) == NULL) {
        isp->isp_osinfo.bfreelist = NULL;
    }
    memset(tmd, 0, TMD_SIZE);

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
    tmd->cd_oxid = aep->at_oxid;
    tmd->cd_nphdl = loopid;
    tmd->cd_tgt = FCPARAM(isp, 0)->isp_wwpn;
    FLATLUN_TO_L0LUN(tmd->cd_lun, lun);
    memcpy(tmd->cd_cdb, aep->at_cdb, min(TMD_CDBLEN, ATIO2_CDBLEN));

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
        tmd->cd_flags |= CDF_DATA_OUT;
        break;
    case ATIO2_EX_READ:
        tmd->cd_flags |= CDF_DATA_IN;
        break;
    case ATIO2_EX_WRITE|ATIO2_EX_READ:
        tmd->cd_flags |= CDF_BIDIR;
        isp_prt(isp, ISP_LOGWARN, "ATIO2 with both read/write set");
        break;
    default:
        break;
    }

    tmd->cd_tagval = aep->at_rxid;
    tmd->cd_hba = isp;
    tmd->cd_totlen = aep->at_datalen;
    if ((isp->isp_dblev & ISP_LOGTDEBUG0) || isp->isp_osinfo.hcb == 0) {
        const char *sstr;
        switch (tmd->cd_flags & CDF_BIDIR) {
        default:
            sstr = "nodatadir";
            break;
        case CDF_DATA_OUT:
            sstr = "DATA OUT";
            break;
        case CDF_DATA_IN:
            sstr = "DATA IN";
            break;
        case CDF_DATA_OUT|CDF_DATA_IN:

            sstr = "BIDIR";
            break;
        }
        isp_prt(isp, ISP_LOGALL, "ATIO2[%llx] CDB=0x%x 0x%016llx for lun %d tcode 0x%x dlen %d %s", (ull) tmd->cd_tagval,
            aep->at_cdb[0] & 0xff, tmd->cd_iid, lun, aep->at_taskcodes, aep->at_datalen, sstr);
    }

    if (isp->isp_osinfo.hcb == 0) {
        isp_lcl_respond(isp, aep, tmd);
    } else {
        fcportdb_t *lp;
        if (isp_find_pdb_by_loopid(isp, 0, tmd->cd_nphdl, &lp)) {
            tmd->cd_portid = lp->portid;
            CALL_PARENT_TMD(isp, tmd, QOUT_TMD_START);
        } else {
            tmd->cd_portid = PORT_NONE;
            isp_add_wwn_entry(isp, 0, tmd->cd_iid, tmd->cd_nphdl, PORT_ANY);
            (void) isp_thread_event(isp, ISP_THREAD_FINDPORTID, tmd, 0, __func__, __LINE__);
        }
    }
}

static void
isp_handle_platform_atio7(ispsoftc_t *isp, at7_entry_t *aep)
{
    int tattr, iulen, cdbxlen;
    uint16_t lun, chan, nphdl = NIL_HANDLE;
    uint32_t did, sid;
    uint64_t iid = INI_NONE;
    fcportdb_t *lp;
    fcparam *fcp;
    tmd_cmd_t *tmd;

    isp->isp_osinfo.cmds_started++;
    tattr = aep->at_ta_len >> 12;
    iulen = aep->at_ta_len & 0xffffff;

    did = (aep->at_hdr.d_id[0] << 16) | (aep->at_hdr.d_id[1] << 8) | aep->at_hdr.d_id[2];
    sid = (aep->at_hdr.s_id[0] << 16) | (aep->at_hdr.s_id[1] << 8) | aep->at_hdr.s_id[2];
    lun = (aep->at_cmnd.fcp_cmnd_lun[0] << 8) | aep->at_cmnd.fcp_cmnd_lun[1];

    /*
     * Find the N-port handle, and Virtual Port Index for this command.
     *
     * If we can't, we're somewhat in trouble because we can't actually respond w/o that information.
     * We also, as a matter of course, need to know the WWN of the initiator too.
     */

    /*
     * Find the right channel based upon D_ID
     */
    for (chan = 0; chan < isp->isp_nchan; chan++) {
        fcp = FCPARAM(isp, chan);
        if ((fcp->role & ISP_ROLE_TARGET) == 0 || fcp->isp_fwstate != FW_READY || fcp->isp_loopstate < LOOP_PDB_RCVD) {
            continue;
        }
        if (fcp->isp_portid == did) {
            break;
        }
    }

    if (chan == isp->isp_nchan) {
        /*
         * If this happens, it could be because one of our channels is busy starting up.
         *
         * It's Hackaroni time...
         * It's Hackaroni time...
         * It's Hackaroni time...
         * It's Hackaroni time...
         */
        if ((tmd = isp->isp_osinfo.tfreelist) == NULL || ++aep->at_count == 250) {
            isp_prt(isp, ISP_LOGWARN, "%s: [RX_ID 0x%x] D_ID %x not found on any channel- dropping", __func__, aep->at_rxid, did);
            return;
        }
        if ((isp->isp_osinfo.tfreelist = tmd->cd_next) == NULL) {
            isp->isp_osinfo.bfreelist = NULL;
        }
        memcpy(tmd, aep, sizeof (at7_entry_t));
        /* we should be safe here ... */
        tmd->cd_lflags = CDFL_BUSY;
        tmd->cd_next = isp->isp_osinfo.waiting_t;
        isp->isp_osinfo.waiting_t = tmd;
        tmd->cd_lastoff = 1;
        return;
    }
    isp_prt(isp, ISP_LOGTDEBUG0, "%s: [RX_ID 0x%x] D_ID 0x%06x found on Chan %d for S_ID 0x%06x", __func__, aep->at_rxid, did, chan, sid);

    if (isp_find_pdb_by_sid(isp, chan, sid, &lp)) {
        nphdl = lp->handle;
        iid = lp->port_wwn;
    } else {
        /*
         * If we're not in the port database, do a tentative entry.
         */
        isp_prt(isp, ISP_LOGTINFO, "%s: [RX_ID 0x%x] D_ID 0x%06x found on Chan %d for S_ID 0x%06x wasn't in PDB already", __func__, aep->at_rxid, did, chan, sid);
        isp_add_wwn_entry(isp, chan, INI_NONE, NIL_HANDLE, sid);
    }

    /*
     * If the f/w is out of resources, just send a BUSY status back.
     */
    if (aep->at_rxid == AT7_NORESRC_RXID) {
        isp_endcmd(isp, aep, nphdl, chan, SCSI_BUSY, 0);
        return;
    }

    /*
     * If we're out of resources, just send a BUSY status back.
     */
    if ((tmd = isp->isp_osinfo.tfreelist) == NULL) {
        if (isp->isp_osinfo.out_of_tmds == 0) {
            isp_prt(isp, ISP_LOGWARN, "out of TMDs");
            isp->isp_osinfo.out_of_tmds = jiffies;
        }
        isp_endcmd(isp, aep, chan, SCSI_BUSY, 0);
        if (jiffies - isp->isp_osinfo.out_of_tmds > 30 * HZ) {
            isp_prt(isp, ISP_LOGERR, "out of TMDs too long: disabling port");
            isp_thread_event(isp, ISP_THREAD_REINIT, NULL, 0, __func__, __LINE__);
        }
        return;
    }
    isp->isp_osinfo.out_of_tmds = 0;
    if ((isp->isp_osinfo.tfreelist = tmd->cd_next) == NULL) {
        isp->isp_osinfo.bfreelist = NULL;
    }
    memset(tmd, 0, TMD_SIZE);

    /*
     * Set the local flags to BUSY.
     */
    tmd->cd_lflags = CDFL_BUSY;

    cdbxlen = aep->at_cmnd.fcp_cmnd_alen_datadir >> FCP_CMND_ADDTL_CDBLEN_SHIFT;
    if (cdbxlen) {
        isp_prt(isp, ISP_LOGWARN, "additional CDBLEN ignored");
    }
    cdbxlen = sizeof (aep->at_cmnd.cdb_dl.sf.fcp_cmnd_cdb);
    memcpy(tmd->cd_cdb, aep->at_cmnd.cdb_dl.sf.fcp_cmnd_cdb, cdbxlen);
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
        tmd->cd_flags |= CDF_DATA_OUT;
        break;
    case FCP_CMND_DATA_READ:
        tmd->cd_flags |= CDF_DATA_IN;
        break;
    case FCP_CMND_DATA_READ|FCP_CMND_DATA_WRITE:
        tmd->cd_flags |= CDF_BIDIR;
        isp_prt(isp, ISP_LOGINFO, "FCP_CMND_IU with both read/write set");
        break;
    default:
        break;
    }

    tmd->cd_tgt = FCPARAM(isp, chan)->isp_wwpn;                 /* channel is valid at this point */
    tmd->cd_nphdl = nphdl;                                      /* nphdl is either known or NIL- in either case, we can set it if needed */
    tmd->cd_tagval = aep->at_rxid;                              /* we can construct a tag value at this point */
    tmd->cd_iid = iid;                                          /* iid is either INI_NONE or known */
    memcpy(tmd->cd_lun, aep->at_cmnd.fcp_cmnd_lun, sizeof (tmd->cd_lun));
    tmd->cd_portid = sid;
    tmd->cd_channel = chan;
    tmd->cd_hba = isp;
    tmd->cd_oxid = aep->at_hdr.ox_id;
    if ((isp->isp_dblev & ISP_LOGTDEBUG0) || isp->isp_osinfo.hcb == 0) {
        const char *sstr;
        switch (tmd->cd_flags & CDF_BIDIR) {
        default:
            sstr = "nodatadir";
            break;
        case CDF_DATA_OUT:
            sstr = "DATA OUT";
            break;
        case CDF_DATA_IN:
            sstr = "DATA IN";
            break;
        case CDF_DATA_OUT|CDF_DATA_IN:
            sstr = "BIDIR";
            break;
        }
        isp_prt(isp, ISP_LOGALL, "ATIO7[%llx] cdb0=0x%x from 0x%016llx/0x%06x ox_id 0x%x N-Port Handle 0x%02x for lun %u dlen %d %s", (ull) tmd->cd_tagval,
            tmd->cd_cdb[0] & 0xff, (ull) tmd->cd_iid, tmd->cd_portid, tmd->cd_oxid, tmd->cd_nphdl, lun, tmd->cd_totlen, sstr);
    }

    if (isp->isp_osinfo.hcb == 0) {
        isp_lcl_respond(isp, aep, tmd);
        return;
    }
    if (VALID_INI(tmd->cd_iid)) {
        CALL_PARENT_TMD(isp, tmd, QOUT_TMD_START);
    } else {
        isp_prt(isp, ISP_LOGTDEBUG0, "[0x%llx] asking taskthread to find iid of initiator", (ull) tmd->cd_tagval);
        if (isp_thread_event(isp, ISP_THREAD_FINDIID, tmd, 0, __func__, __LINE__)) {
            isp_endcmd(isp, aep, nphdl, chan, SCSI_BUSY, 0);
            memset(tmd, 0, TMD_SIZE);
            if (isp->isp_osinfo.tfreelist) {
                isp->isp_osinfo.bfreelist->cd_next = tmd;
            } else {
                isp->isp_osinfo.tfreelist = tmd;
            }
            isp->isp_osinfo.bfreelist = tmd;
        }
    }
}

/*
 * Terminate a command
 */
static int
isp_terminate_cmd(ispsoftc_t *isp, tmd_cmd_t *tmd)
{
    ct7_entry_t local, *cto = &local;

    if (IS_24XX(isp)) {
        isp_prt(isp, ISP_LOGTINFO, "isp_terminate_cmd: [%llx] is being terminated", (ull) tmd->cd_tagval);
        memset(&local, 0, sizeof (local));
        cto->ct_header.rqs_entry_type = RQSTYPE_CTIO7;
        cto->ct_header.rqs_entry_count = 1;
        cto->ct_nphdl = tmd->cd_nphdl;
        cto->ct_rxid = tmd->cd_tagval;
        cto->ct_vpidx = tmd->cd_channel;
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
    tmd_xact_t *xact;
    tmd_cmd_t *tmd;
    char *ctstr;
    int sentstatus = 0, ok, resid = 0, id;
    int status, flags;

    /*
     * CTIO, CTIO2, and CTIO7 are close enough....
     */
    if (IS_24XX(isp)) {
        ct7_entry_t *ct = arg;
        xact = (tmd_xact_t *) isp_find_xs_tgt(isp, ct->ct_syshandle);
        if (xact == NULL) {
            isp_prt(isp, ISP_LOGERR, "isp_handle_platform_ctio: null xact");
            return;
        }
        tmd = xact->td_cmd;
        isp_destroy_tgt_handle(isp, ct->ct_syshandle);
        status = ct->ct_nphdl;
        flags = ct->ct_flags;
        sentstatus = (flags & CT7_SENDSTATUS) != 0;
        ok = status == CT7_OK;
        ctstr = "CTIO7";
        if ((ct->ct_flags & CT7_DATAMASK) != CT7_NO_DATA) {
            resid = ct->ct_resid;
        }
        id = ct->ct_iid_lo | (ct->ct_iid_hi << 16);
    } else if (IS_FC(isp)) {
        ct2_entry_t *ct = arg;
        xact = (tmd_xact_t *) isp_find_xs_tgt(isp, ct->ct_syshandle);
        if (xact == NULL) {
            isp_prt(isp, ISP_LOGERR, "isp_handle_platform_ctio: null xact");
            return;
        }
        tmd = xact->td_cmd;
        isp_destroy_tgt_handle(isp, ct->ct_syshandle);
        status = ct->ct_status;
        flags = ct->ct_flags;
        sentstatus = (flags & CT2_SENDSTATUS) != 0;
        ok = (status & ~QLTM_SVALID) == CT_OK;
        ctstr = "CTIO2";
        if ((ct->ct_flags & CT2_DATAMASK) != CT2_NO_DATA) {
            resid = ct->ct_resid;
        }
        id = ct->ct_iid;
    } else {
        ct_entry_t *ct = arg;
        xact = (tmd_xact_t *) isp_find_xs_tgt(isp, ct->ct_syshandle);
        if (xact == NULL) {
            isp_prt(isp, ISP_LOGERR, "isp_handle_platform_ctio: null xact");
            return;
        }
        tmd = xact->td_cmd;
        isp_destroy_tgt_handle(isp, ct->ct_syshandle);
        status = ct->ct_status;
        flags = ct->ct_flags;
        sentstatus = (flags & CT_SENDSTATUS) != 0;
        ok = (status & ~QLTM_SVALID) == CT_OK;
        ctstr = "CTIO";
        if (ct->ct_status & QLTM_SVALID) {
            char *sp = (char *)ct;
            sp += CTIO_SENSE_OFFSET;
            memcpy(tmd->cd_sense, sp, QLTM_SENSELEN);
            tmd->cd_flags |= CDF_SNSVALID;
        }
        if ((ct->ct_flags & CT_DATAMASK) != CT_NO_DATA) {
            resid = ct->ct_resid;
        }
        id = ct->ct_iid;
    }
    if (sentstatus) {
        xact->td_lflags |= TDFL_SENTSTATUS;
    }
    if (ok && sentstatus && (xact->td_hflags & TDFH_SNSVALID)) {
        xact->td_lflags |= TDFL_SENTSENSE;
    }
    tmd->cd_req_cnt -= 1;

    tmd->cd_moved -= resid;

    isp_prt(isp, ISP_LOGTDEBUG0, "%s[%llx] status 0x%x flg 0x%x resid %d %s", ctstr, (ull) tmd->cd_tagval, status, flags, resid, sentstatus? "FIN" : "MID");

    /*
     * We're here either because intermediate data transfers are done
     * and/or the final status CTIO (which may have joined with a
     * Data Transfer) is done.
     *
     * In any case, for this platform, the upper layers figure out
     * what to do next, so all we do here is collect status and
     * pass information along.
     */
    isp_prt(isp, ISP_LOGTDEBUG0, "%s CTIO done (moved %u)", (sentstatus)? "  FINAL " : "MIDTERM ", tmd->cd_moved);

    if (!ok) {
        const char *cx;
        if (IS_24XX(isp)) {
            cx = "O7";
        } else if (IS_FC(isp)) {
            cx = "O2";
        } else {
            cx = "O";
        }
        if ((status & ~QLTM_SVALID) == CT_ABORTED) {
            isp_prt(isp, ISP_LOGINFO, "[%llx] CTI%s aborted", (ull) tmd->cd_tagval, cx);
            tmd->cd_lflags |= CDFL_ABORTED;
        } else if ((status & QLTM_SVALID) == CT_LOGOUT) {
            isp_prt(isp, ISP_LOGINFO, "[%llx] CTI%s killed by Port Logout", (ull) tmd->cd_tagval, cx);
        } else {
            isp_prt(isp, ISP_LOGINFO, "[%llx] CTI%s ended with badstate (0x%x)", (ull) tmd->cd_tagval, cx, status);
        }
        xact->td_error = -EIO;
        xact->td_lflags |= TDFL_ERROR;
        if (isp_target_putback_atio(isp, tmd)) {
            tmd->cd_lflags |= CDFL_RESRC_FILL;
        }
        if ((status & ~QLTM_SVALID) == CT_LOGOUT) {
            int i;
            for (i = 0; i < MAX_FC_TARG; i++) {
                if (FCPARAM(isp, tmd->cd_channel)->portdb[i].target_mode == 0) {
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
                isp_thread_event(isp, ISP_THREAD_LOGOUT, &FCPARAM(isp, tmd->cd_channel)->portdb[i], 0, __func__, __LINE__);
                break;
            }
        }
    }
    isp_complete_ctio(isp, xact);
}

static int
isp_target_putback_atio(ispsoftc_t *isp, tmd_cmd_t *tmd)
{
    uint8_t local[QENTRY_LEN];
    void *qe;

    tmd->cd_lflags &= ~CDFL_RESRC_FILL;
    if (IS_24XX(isp)) {
        return (0);
    }
    qe = isp_getrqentry(isp);
    if (qe == NULL) {
        isp_prt(isp, ISP_LOGWARN, "%s: Request Queue Overflow", __func__);
        return (-ENOMEM);
    }
    isp_prt(isp, ISP_LOGTDEBUG0, "[%llx] resource putback being sent", (ull) tmd->cd_tagval);
    memset(local, 0, sizeof (local));
    if (IS_FC(isp)) {
        at2_entry_t *at = (at2_entry_t *) local;
        at->at_header.rqs_entry_type = RQSTYPE_ATIO2;
        at->at_header.rqs_entry_count = 1;
        at->at_status = CT_OK;
        at->at_rxid = tmd->cd_tagval;
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
    ISP_SYNC_REQUEST(isp);
    return (0);
}

static void
isp_complete_ctio(ispsoftc_t *isp, tmd_xact_t *xact)
{
    tmd_cmd_t *tmd = xact->td_cmd;
    isp->isp_osinfo.cmds_completed++;
    if (isp->isp_osinfo.hcb || (tmd->cd_lflags & CDFL_LCL)) {
        if (isp->isp_osinfo.hcb == 0) {
            isp_prt(isp, ISP_LOGWARN, "nobody to tell about CTIO complete, leaking xact structure");
            memset(tmd, 0, TMD_SIZE);
            if (isp->isp_osinfo.tfreelist) {
                isp->isp_osinfo.bfreelist->cd_next = tmd;
            } else {
                isp->isp_osinfo.tfreelist = tmd;
            }
            isp->isp_osinfo.bfreelist = tmd;
        } else {
            CALL_PARENT_XFR(isp, xact);
        }
    }
}

int
isp_enable_lun(ispsoftc_t *isp, uint16_t bus, uint16_t lun)
{
    struct semaphore rsem;
    tgt_enalun_t *axl;
    uint16_t rstat;
    int cmd, r;
    unsigned long flags;


    /*
     * Validity check the bus argument.
     */
    if (bus >= isp->isp_nchan) {
        return (-ENODEV);
    }

    /*
     * Allocate a sparse lun descriptor
     */
    axl = isp_kzalloc(sizeof (tgt_enalun_t), GFP_KERNEL);
    if (axl == NULL) {
        return (-ENOMEM);
    }

    /*
     * Snag the semaphore on the return state value on enables/disables.
     */
    if (down_interruptible(&isp->isp_osinfo.tgt_inisem)) {
        isp_kfree(axl, sizeof (tgt_enalun_t));
        return (-EINTR);
    }

    /*
     * If this lun is enabled on this bus already, that's an error.
     */
    if (lunenabled(isp, bus, lun)) {
        up(&isp->isp_osinfo.tgt_inisem);
        isp_kfree(axl, sizeof (tgt_enalun_t));
        return (-EEXIST);
    }

    /*
     * Validity check with our enable ruleset.
     * We can't enable busses > 1 without enabling bus 0
     * first in some kind of role.
     */
    if (IS_FC(isp) && bus != 0 && (((FCPARAM(isp, 0)->role & ISP_ROLE_TARGET) && nolunsenabled(isp, 0)) || (FCPARAM(isp, 0)->role == ISP_ROLE_NONE))) {
        isp_prt(isp, ISP_LOGWARN, "%s: must enable Chan 0 before Chan %u", __func__, bus);
        up(&isp->isp_osinfo.tgt_inisem);
        isp_kfree(axl, sizeof (tgt_enalun_t));
        return (-EINVAL);
    }


    /*
     * If this bus is wildcarded, we don't allow any further actions.
     */
    if (lun != LUN_ANY) {
        if (lunenabled(isp, bus, LUN_ANY)) {
            up(&isp->isp_osinfo.tgt_inisem);
            isp_kfree(axl, sizeof (tgt_enalun_t));
            return (-EEXIST);
        }
    }

    /*
     * If this is the first lun being enabled for this bus make sure we're set up for
     * being in target mode.
     */
    if (nolunsenabled(isp, bus)) {
        if (IS_SCSI(isp)) {
            uint16_t tb;

            for (tb = 0; tb < isp->isp_nchan; tb++) {
                if (tb == bus)
                    continue;
                if (nolunsenabled(isp, tb) == 0) {
                    break;
                }
            }

            /*
             * This is the very first bus being enabled.
             */
            if (tb < isp->isp_nchan) {
                mbreg_t mbs;
                memset(&mbs, 0, sizeof (mbs));
                mbs.param[0] = MBOX_ENABLE_TARGET_MODE;
                mbs.param[1] = ENABLE_TARGET_FLAG|ENABLE_TQING_FLAG;
                mbs.param[2] = bus << 7;
                mbs.logval = MBLOGALL;
                ISP_LOCK_SOFTC(isp);
                r = isp_control(isp, ISPCTL_RUN_MBOXCMD, &mbs);
                ISP_UNLK_SOFTC(isp);
                if (r < 0 || mbs.param[0] != MBOX_COMMAND_COMPLETE) {
                    up(&isp->isp_osinfo.tgt_inisem);
                    isp_kfree(axl, sizeof (tgt_enalun_t));
                    return (-EIO);
                }
            }
        } else {
            fcparam *fcp = FCPARAM(isp, bus);
            if ((fcp->role & ISP_ROLE_TARGET) == 0) {
                ISP_LOCK_SOFTC(isp);
                r = isp_fc_change_role(isp, bus, fcp->role | ISP_ROLE_TARGET);
                if (r) {
                    ISP_UNLK_SOFTC(isp);
                    up(&isp->isp_osinfo.tgt_inisem);
                    isp_kfree(axl, sizeof (tgt_enalun_t));
                    return (r);
                }
                ISP_UNLK_SOFTC(isp);
            }
        }
    }

    ISP_LOCK_SOFTC(isp);
    isp->isp_osinfo.rsemap = &rsem;
    sema_init(&rsem, 0);
    if (IS_24XX(isp)) {
        rstat = LUN_OK;
    } else {
        int n, ulun = lun;

        cmd = RQSTYPE_ENABLE_LUN;
        n = DFLT_INOT_CNT;
        if (IS_FC(isp)) {
            if (lun != 0 && lun != LUN_ANY) {
                cmd = RQSTYPE_MODIFY_LUN;
                n = 0;
            } else if (lun == LUN_ANY) {
                /*
                 * For SCC firmware, we only deal with setting
                 * (enabling or modifying) lun 0.
                 */
                ulun = 0;
            }
        }
        rstat = LUN_ERR;
        if (isp_lun_cmd(isp, cmd, bus, ulun, DFLT_CMND_CNT, n)) {
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
    }
out:
    if (rstat != LUN_OK) {
        isp_prt(isp, ISP_LOGERR, "lun %u enable failed", lun);
        ISP_UNLK_SOFTC(isp);
        up(&isp->isp_osinfo.tgt_inisem);
        isp_kfree(axl, sizeof (tgt_enalun_t));
        return (-EIO);
    }
    addlun(isp, axl, bus, lun);
    ISP_UNLK_SOFTC(isp);
    if (lun == LUN_ANY) {
        isp_prt(isp, ISP_LOGINFO, "All luns now enabled for target mode on channel %d", bus);
    } else {
        isp_prt(isp, ISP_LOGINFO, "lun %u now disabled for target mode on channel %d", lun, bus);
    }

    /*
     * Make sure we stay resident while we have a lun enabled
     */
    if (try_module_get(isp->isp_osinfo.host->hostt->module)) {
        isp->isp_osinfo.isget++;
    }
    up(&isp->isp_osinfo.tgt_inisem);
    return (0);
}

int
isp_disable_lun(ispsoftc_t *isp, uint16_t bus, uint16_t lun)
{
    struct semaphore rsem;
    uint16_t rstat;
    tgt_enalun_t *axl;
    int cmd;
    unsigned long flags;

    /*
     * Snag the semaphore on the return state value on enables/disables.
     */
    if (down_interruptible(&isp->isp_osinfo.tgt_inisem)) {
        return (-EINTR);
    }

    if (lunenabled(isp, bus, lun) == 0) {
        up(&isp->isp_osinfo.tgt_inisem);
        return (-ENODEV);
    }

    ISP_LOCK_SOFTC(isp);
    /*
     * Validate this disable based upon our rulesets.
     */
    if (IS_FC(isp)) {
        if (bus == 0 && (FCPARAM(isp, 0)->role & ISP_ROLE_TARGET) != 0) {
            for (rstat = isp->isp_nchan - 1; rstat > 0; rstat--) {
                if (nolunsenabled(isp, rstat) == 0) {
                    break;
                }
            }
            if (rstat > 0) {
                isp_prt(isp, ISP_LOGERR, "%s: must disable Chan %u before Chan 0\n", __func__, rstat);
                ISP_UNLK_SOFTC(isp);
                up(&isp->isp_osinfo.tgt_inisem);
                return (-EINVAL);
            }
        }
    }

    isp->isp_osinfo.rsemap = &rsem;
    sema_init(&rsem, 0);
    if (IS_24XX(isp)) {
        rstat = LUN_OK;
    } else {
        int n, ulun = lun;

        rstat = LUN_ERR;
        cmd = -RQSTYPE_MODIFY_LUN;

        n = DFLT_INOT_CNT;
        if (IS_FC(isp) && lun != 0) {
            n = 0;
            /*
             * For SCC firmware, we only deal with setting
             * (enabling or modifying) lun 0.
             */
            ulun = 0;
        }
        if (isp_lun_cmd(isp, cmd, bus, ulun, DFLT_CMND_CNT, n)) {
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
            /* but proceed anyway */
            isp_prt(isp, ISP_LOGINFO, "MODIFY LUN returned 0x%x", rstat);
            /* but proceed anyway */
            rstat = LUN_OK;
        }
        if (IS_FC(isp) && lun) {
            goto out;
        }
        isp->isp_osinfo.rsemap = &rsem;

        rstat = LUN_ERR;
        cmd = -RQSTYPE_ENABLE_LUN;
        if (isp_lun_cmd(isp, cmd, bus, lun, 0, 0)) {
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
    axl = remlun(isp, bus, lun);
    ISP_UNLK_SOFTC(isp);
    if (axl) {
        isp_kfree(axl, sizeof (tgt_enalun_t));
    } else {
        isp_prt(isp, ISP_LOGWARN, "%s: Chan %d lun %u unable to find axl to delete", __func__, bus, lun);
    }
    if (rstat != LUN_OK) {
        isp_prt(isp, ISP_LOGERR, "lun %u disable failed", lun);
        /* but continue anyway */
    }
    if (lun == LUN_ANY) {
        isp_prt(isp, ISP_LOGINFO, "All luns now disabled for target mode on channel %d", bus);
    } else {
        isp_prt(isp, ISP_LOGINFO, "lun %u now disabled for target mode on channel %d", lun, bus);
    }
    if (isp->isp_osinfo.isget) {
        module_put(isp->isp_osinfo.host->hostt->module);
        isp->isp_osinfo.isget--;
    }
    if (IS_SCSI(isp)) {
        for (bus = 0; bus < isp->isp_nchan; bus++) {
            if (!nolunsenabled(isp, bus)) {
                break;
            }
        }
        if (bus == isp->isp_nchan) {
            int r;
            mbreg_t mbs;
            memset(&mbs, 0, sizeof (mbs));
            mbs.param[0] = MBOX_ENABLE_TARGET_MODE;
            mbs.param[2] = bus << 7;
            mbs.logval = MBLOGNONE;
            ISP_LOCK_SOFTC(isp);
            r = isp_control(isp, ISPCTL_RUN_MBOXCMD, &mbs);
            ISP_UNLK_SOFTC(isp);
            if (r < 0 || mbs.param[0] != MBOX_COMMAND_COMPLETE) {
                isp_prt(isp, ISP_LOGERR, "Chan %d unable to disable target mode", bus);
            }
        }
    } else {
        if (nolunsenabled(isp, bus)) {
            fcparam *fcp = FCPARAM(isp, bus);
            ISP_LOCK_SOFTC(isp);
            if (isp_fc_change_role(isp, bus, fcp->role & ~ISP_ROLE_TARGET)) {
                isp_prt(isp, ISP_LOGERR, "Chan %d unable to disable target mode", bus);
            }
            ISP_UNLK_SOFTC(isp);
        }
    }
    up(&isp->isp_osinfo.tgt_inisem);
    return (0);
}
#endif

void
isp_async(ispsoftc_t *isp, ispasync_t cmd, ...)
{
    static const char prom0[] = "Chan %d PortID 0x%06x handle 0x%x role %s %s WWNN 0x%016llx WWPN 0x%016llx";
    static const char prom2[] = "Chan %d PortID 0x%06x handle 0x%x role %s %s tgt %u WWNN 0x%016llx WWPN 0x%016llx";
    fcportdb_t *lp;
    fcparam *fcp;
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
                isp_prt(isp, ISP_LOGINFO, "Chan %d Target %d at %dMHz Max Offset %d%s", bus, tgt, mhz, sdp->isp_devparam[tgt].actv_offset, wt);
            } else {
                isp_prt(isp, ISP_LOGINFO, "Chan %d Target %d Async Mode%s", bus, tgt, wt);
            }
        }
        break;
    case ISPASYNC_LIP:
        isp_prt(isp, ISP_LOGINFO, "LIP Received");
        break;
    case ISPASYNC_LOOP_RESET:
        va_start(ap, cmd);
        bus = va_arg(ap, int);
        va_end(ap);
        isp_prt(isp, ISP_LOGINFO, "Chan %d Loop Reset Received", bus);
        break;
    case ISPASYNC_BUS_RESET:
        va_start(ap, cmd);
        bus = va_arg(ap, int);
        va_end(ap);
        isp_prt(isp, ISP_LOGINFO, "SCSI bus %d reset detected", bus);
        break;
    case ISPASYNC_LOOP_DOWN:
        va_start(ap, cmd);
        bus = va_arg(ap, int);
        va_end(ap);
        isp_prt(isp, ISP_LOGINFO, "Chan %d Loop DOWN", bus);
        break;
    case ISPASYNC_LOOP_UP:
        va_start(ap, cmd);
        bus = va_arg(ap, int);
        va_end(ap);
        isp_prt(isp, ISP_LOGINFO, "Chan %d Loop UP", bus);
        break;
    case ISPASYNC_DEV_ARRIVED:
        va_start(ap, cmd);
        bus = va_arg(ap, int);
        lp = va_arg(ap, fcportdb_t *);
        va_end(ap);
        fcp = FCPARAM(isp, bus);
        if ((fcp->role & ISP_ROLE_INITIATOR) != 0 && (lp->roles & (SVC3_TGT_ROLE >> SVC3_ROLE_SHIFT))) {
            int dbidx = lp - fcp->portdb;
            int i;

            for (i = 0; i < MAX_FC_TARG; i++) {
                if (i >= FL_ID && i <= SNS_ID) {
                    continue;
                }
                if (fcp->isp_dev_map[i] == 0) {
                    break;
                }
            }
            if (i < MAX_FC_TARG) {
                fcp->isp_dev_map[i] = dbidx + 1;
                lp->dev_map_idx = i + 1;
            } else {
                isp_prt(isp, ISP_LOGWARN, "out of target ids");
                isp_dump_portdb(isp, bus);
            }
        }
        isp_prt(isp, ISP_LOGCONFIG, prom0, bus, lp->portid, lp->handle, isp_class3_roles[lp->roles], "arrived", (ull) lp->node_wwn, (ull) lp->port_wwn);
        if (lp->dev_map_idx) {
            lp->dirty = 0;
            if (isp->isp_osinfo.scan_timeout == 0) {
                isp->isp_osinfo.scan_timeout = ISP_SCAN_TIMEOUT;
            }
        }
        break;
    case ISPASYNC_DEV_CHANGED:
        va_start(ap, cmd);
        bus = va_arg(ap, int);
        lp = va_arg(ap, fcportdb_t *);
        va_end(ap);
        fcp = FCPARAM(isp, bus);
        lp->portid = lp->new_portid;
        lp->roles = lp->new_roles;
        if (lp->dev_map_idx) {
            int t = lp->dev_map_idx - 1;
            fcp->isp_dev_map[t] = (lp - fcp->portdb) + 1;
            tgt = lp->dev_map_idx - 1;
            isp_prt(isp, ISP_LOGCONFIG, prom2, bus, lp->portid, lp->handle, isp_class3_roles[lp->roles], "changed at", tgt, (ull) lp->node_wwn, (ull) lp->port_wwn);
        } else {
            isp_prt(isp, ISP_LOGCONFIG, prom0, bus, lp->portid, lp->handle, isp_class3_roles[lp->roles], "changed", (ull) lp->node_wwn, (ull) lp->port_wwn);
        }
        break;
    case ISPASYNC_DEV_STAYED:
        va_start(ap, cmd);
        bus = va_arg(ap, int);
        lp = va_arg(ap, fcportdb_t *);
        va_end(ap);
        if (lp->dev_map_idx) {
            tgt = lp->dev_map_idx - 1;
            isp_prt(isp, ISP_LOGCONFIG, prom2, bus, lp->portid, lp->handle, isp_class3_roles[lp->roles], "stayed at", tgt, (ull) lp->node_wwn, (ull) lp->port_wwn);
        } else {
            isp_prt(isp, ISP_LOGCONFIG, prom0, bus, lp->portid, lp->handle, isp_class3_roles[lp->roles], "stayed", (ull) lp->node_wwn, (ull) lp->port_wwn);
        }
        break;
    case ISPASYNC_DEV_GONE:
        va_start(ap, cmd);
        bus = va_arg(ap, int);
        lp = va_arg(ap, fcportdb_t *);
        va_end(ap);
        fcp = FCPARAM(isp, bus);
        if (lp->dev_map_idx) {
            lp->reserved = 2;
            if (isp->isp_osinfo.rescan_timeout == 0) {
                isp->isp_osinfo.rescan_timeout = ISP_RESCAN_TIMEOUT;
            }
            isp_prt(isp, ISP_LOGCONFIG, prom0, bus, lp->portid, lp->handle, isp_class3_roles[lp->roles], "zombie", (ull) lp->node_wwn, (ull) lp->port_wwn);
            lp->state = FC_PORTDB_STATE_ZOMBIE;
        } else {
            isp_prt(isp, ISP_LOGCONFIG, prom0, bus, lp->portid, lp->handle, isp_class3_roles[lp->roles], "departed", (ull) lp->node_wwn, (ull) lp->port_wwn);
        }
        break;
    case ISPASYNC_CHANGE_NOTIFY:
    {
        int chg, nphdl, nlstate, reason;

        va_start(ap, cmd);
        bus = va_arg(ap, int);
        chg = va_arg(ap, int);
        if (chg == ISPASYNC_CHANGE_PDB) {
            nphdl = va_arg(ap, int);
            nlstate = va_arg(ap, int);
            reason = va_arg(ap, int);
        } else {
            nphdl = NIL_HANDLE;
            nlstate = reason = 0;
        }
        va_end(ap);
        fcp = FCPARAM(isp, bus);
        if (chg == ISPASYNC_CHANGE_PDB) {
            if (IS_24XX(isp)) {
                isp_prt(isp, ISP_LOGINFO, "Chan %d Port Database Changed, N-Port Handle 0x%04x nlstate %x reason 0x%02x", bus, nphdl, nlstate, reason);
            } else {
                isp_prt(isp, ISP_LOGINFO, "Chan %d Port Database Changed", bus);
            }
        } else if (chg == ISPASYNC_CHANGE_SNS) {
            isp_prt(isp, ISP_LOGINFO, "Chan %d Name Server Database Changed", bus);
        } else {
            isp_prt(isp, ISP_LOGINFO, "Chan %d Other Change Notify occurred", bus);
        }
        if (isp->isp_state >= ISP_INITSTATE) {
            isp_thread_event(isp, ISP_THREAD_FC_RESCAN, fcp, 0, __func__, __LINE__);
        }
        break;
    }
#ifdef    ISP_TARGET_MODE
    case ISPASYNC_TARGET_NOTIFY:
    {
        notify_t *ins;
        isp_notify_t *mp;

        va_start(ap, cmd);
        mp = va_arg(ap, isp_notify_t *);
        va_end(ap);

        if (mp == NULL) {
            break;
        }

        if (FCPARAM(isp, mp->nt_channel) == NULL) {
            break;
        }
        
        if (isp->isp_osinfo.hcb == 0) {
            isp_prt(isp, ISP_LOGWARN, "ISPASYNC_TARGET_NOTIFY with target mode not enabled");
            if (mp->nt_need_ack && mp->nt_lreserved) {
                isp_notify_ack(isp, mp->nt_lreserved);
            }
            break;
        }

        ins = isp->isp_osinfo.nfreelist;
        if (ins == NULL) {
            isp_prt(isp, ISP_LOGERR, "out of TMD NOTIFY structs");
            if (mp->nt_need_ack && mp->nt_lreserved) {
                isp_notify_ack(isp, mp->nt_lreserved);
            }
            break;
        }
        isp->isp_osinfo.nfreelist = ins->notify.nt_lreserved;

        memcpy(&ins->notify, mp, sizeof (isp_notify_t));
        if (mp->nt_lreserved) {
            memcpy(ins->qentry, mp->nt_lreserved, QENTRY_LEN);
            ins->qevalid = 1;
        } else {
            ins->qevalid = 0;
        }
        mp = &ins->notify;

        if (IS_24XX(isp)) {
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
            case NT_DEPARTED:
            case NT_ARRIVED:
                break;
            case NT_LUN_RESET:
            case NT_TARGET_RESET:
                /*
                 * Mark all pertinent commands as dead and needing cleanup.
                 */
                for (i = 0; i < NTGT_CMDS; i++) {
                    tmd_cmd_t *tmd = &isp->isp_osinfo.pool[i];
                    if (tmd->cd_lflags & CDFL_BUSY) {
                        if (mp->nt_channel == tmd->cd_channel && (mp->nt_lun == LUN_ANY || mp->nt_lun == L0LUN_TO_FLATLUN(tmd->cd_lun))) {
                            tmd->cd_lflags |= CDFL_ABORTED|CDFL_NEED_CLNUP;
                        }
                    }
                }
                /* FALLTHROUGH */
            default:
                if (isp_find_pdb_by_sid(isp, mp->nt_channel, sid, &lp)) {
                    mp->nt_wwn = lp->port_wwn;
                }
                break;
            }

            /*
             * Replace target with our port WWN.
             */
            mp->nt_tgt = FCPARAM(isp, mp->nt_channel)->isp_wwpn;
        } else if (IS_FC(isp)) {
            uint16_t loopid;

            /*
             * The outer layer just set the loopid into nt_wwn. We try and find the WWPN.
             */
            loopid = ins->notify.nt_wwn;
            switch (mp->nt_ncode) {
            case NT_HBA_RESET:
            case NT_LINK_UP:
            case NT_LINK_DOWN:
                ins->notify.nt_wwn = INI_NONE;
                break;
            case NT_DEPARTED:
            case NT_ARRIVED:
                break;
            default:
                if (isp_find_pdb_by_loopid(isp, mp->nt_channel, loopid, &lp) == 0) {
                    isp_prt(isp, ISP_LOGTINFO, "cannot find WWN for loopid 0x%x for notify action 0x%x", loopid, mp->nt_ncode);
                    ins->notify.nt_wwn = INI_NONE;
                } else {
                    ins->notify.nt_wwn = lp->port_wwn;
                }
                break;
            }
            /*
             * Replace target with our port WWN.
             */
            mp->nt_tgt = FCPARAM(isp, mp->nt_channel)->isp_wwpn;
        }
        isp_prt(isp, ISP_LOGTINFO, "Notify Code 0x%x iid 0x%016llx tgt 0x%016llx lun %u tag %llx",
            mp->nt_ncode, (ull) mp->nt_wwn, (ull) mp->nt_tgt, mp->nt_lun, mp->nt_tagval);
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
            notify_t *ins = NULL;
            tmd_cmd_t *tmd;
            abts_t *abts = qe;
            int i;
            uint16_t chan, lun;
            uint32_t sid, did;

            if (isp->isp_osinfo.hcb == 0) {
                isp_prt(isp, ISP_LOGTINFO, "RQSTYPE_ABTS_RCVD: with no upstream listener");
                WARN_ON(isp_acknak_abts(isp, qe, 0));
                break;
            }

            did = (abts->abts_did_hi << 16) | abts->abts_did_lo;
            sid = (abts->abts_sid_hi << 16) | abts->abts_sid_lo;

            /*
             * Try to find the original tmd so we can get the lun.
             */
            for (i = 0; i < NTGT_CMDS; i++) {
                tmd = &isp->isp_osinfo.pool[i];
                if (tmd->cd_lflags & CDFL_BUSY) {
                    if (tmd->cd_tagval == abts->abts_rx_id && tmd->cd_oxid == abts->abts_ox_id) {
                        break;
                    }
                }
                tmd = NULL;
            }

            if (tmd == NULL) {
                lun = LUN_ANY;
            } else {
                lun = L0LUN_TO_FLATLUN(tmd->cd_lun);
            }

            if (abts->abts_rxid_task == ISP24XX_NO_TASK) {
                isp_prt(isp, ISP_LOGTINFO, "ABTS from N-Port handle 0x%x Port 0x%06x has no task id (rx_id 0x%04x ox_id 0x%04x)",
                    abts->abts_nphdl, sid, abts->abts_rx_id, abts->abts_ox_id);
                if (tmd) {
                        isp_prt(isp, ISP_LOGTINFO, "... but found tmd to to mark as aborted (active xact count %d)", tmd->cd_req_cnt);
                        tmd->cd_lflags |= CDFL_ABORTED|CDFL_NEED_CLNUP;
                }
                WARN_ON(isp_acknak_abts(isp, qe, 0));
                break;
            }

            ins = isp->isp_osinfo.nfreelist;
            if (ins == NULL) {
                isp_prt(isp, ISP_LOGWARN, "out of TMD NOTIFY structs for RQSTYPE_ABTS_RCVD");
                WARN_ON(isp_acknak_abts(isp, qe, ENOMEM));
                break;
            }
            isp->isp_osinfo.nfreelist = ins->notify.nt_lreserved;
            memset(&ins->notify, 0, sizeof (isp_notify_t));
            lp = NULL;
            for (chan = 0; chan < isp->isp_nchan; chan++) {
                if (isp_find_pdb_by_loopid(isp, chan, abts->abts_nphdl, &lp)) {
                    break;
                }
            }
            if (lp == NULL) {
                if (tmd) {
                    ins->notify.nt_wwn = tmd->cd_iid;
                    chan = tmd->cd_channel;
                } else {
                    isp_prt(isp, ISP_LOGTINFO, "cannot find WWN for N-port handle 0x%x for ABTS", abts->abts_nphdl);
                    ins->notify.nt_wwn = INI_ANY;
                    chan = ISP_GET_VPIDX(isp, ISP_NOCHAN);
                }
            } else {
                ins->notify.nt_wwn = lp->port_wwn;
            }
            memcpy(ins->qentry, qe, QENTRY_LEN);
            ins->qevalid = 1;
            ins->notify.nt_hba = isp;
            ins->notify.nt_tgt = FCPARAM(isp, chan)->isp_wwpn;
            ins->notify.nt_sid = sid;
            ins->notify.nt_did = did;
            ins->notify.nt_nphdl = abts->abts_nphdl;
            ins->notify.nt_lun = lun;
            ins->notify.nt_tagval = abts->abts_rxid_task;
            ins->notify.nt_ncode = NT_ABORT_TASK;
            ins->notify.nt_need_ack = 1;
            ins->notify.nt_channel = chan;
            ins->notify.nt_tmd = NULL;
            /*
             * If we have the command mark it aborted and needing cleanup
             */
            if (tmd) {
                    isp_prt(isp, ISP_LOGTINFO, "[0x%llx] marked as aborted (active xact count %d)", (ull) tmd->cd_tagval, tmd->cd_req_cnt);
                    tmd->cd_lflags |= CDFL_ABORTED|CDFL_NEED_CLNUP;
                    ins->notify.nt_tmd = tmd;
            }
            isp_prt(isp, ISP_LOGTINFO, "ABTS [%llx] from 0x%016llx", (ull) ins->notify.nt_tagval, (ull) ins->notify.nt_wwn);
            CALL_PARENT_NOTIFY(isp, ins);
            break;
        }
        case RQSTYPE_NOTIFY:
        {
            notify_t *ins = NULL;
            uint16_t status, nphdl;
            uint32_t lun, seqid, portid;
            uint8_t *ptr = NULL;

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
                    memset(&ins->notify, 0, sizeof (isp_notify_t));
                    memcpy(ins->qentry, qe, QENTRY_LEN);
                    ins->qevalid = 1;
                    ins->notify.nt_hba = isp;
                    ins->notify.nt_wwn = GET_IID_VAL(inot->in_iid);
                    ins->notify.nt_tgt = inot->in_tgt;
                    ins->notify.nt_lun = inot->in_lun;
                    IN_MAKE_TAGID(ins->notify.nt_tagval, inot);
                    ins->notify.nt_ncode = NT_ABORT_TASK;
                    ins->notify.nt_need_ack = 1;
                    isp_prt(isp, ISP_LOGTINFO, "ABORT TASK [%llx] from iid %u to lun %u", (ull) ins->notify.nt_tagval,
                        (uint32_t) ins->notify.nt_wwn, inot->in_lun);
                    CALL_PARENT_NOTIFY(isp, ins);
                    break;
                } else {
                    isp_notify_ack(isp, qe);
                }
                break;
            } else if (IS_24XX(isp)) {
                in_fcentry_24xx_t *inot = qe;
                uint64_t wwn;

                nphdl = inot->in_nphdl;
                if (nphdl != NIL_HANDLE) {
                    portid = inot->in_portid_hi << 16 | inot->in_portid_lo;
                } else {
                    portid = PORT_ANY;
                }
                status = inot->in_status;
                seqid = inot->in_rxid;
                lun = 0;

                switch (status) {
                case IN24XX_ELS_RCVD:
                {
                    char *msg = NULL;

                    switch (inot->in_status_subcode) {
                    case LOGO:
                        msg = "LOGO";
                        if (ISP_FW_NEWER_THAN(isp, 4, 0, 25)) {
                            ptr = qe;   /* point to unswizzled entry! */
                            wwn =
                                (((uint64_t) ptr[IN24XX_LOGO_WWPN_OFF])   << 56) |
                                (((uint64_t) ptr[IN24XX_LOGO_WWPN_OFF+1]) << 48) |
                                (((uint64_t) ptr[IN24XX_LOGO_WWPN_OFF+2]) << 40) |
                                (((uint64_t) ptr[IN24XX_LOGO_WWPN_OFF+3]) << 32) |
                                (((uint64_t) ptr[IN24XX_LOGO_WWPN_OFF+4]) << 24) |
                                (((uint64_t) ptr[IN24XX_LOGO_WWPN_OFF+5]) << 16) |
                                (((uint64_t) ptr[IN24XX_LOGO_WWPN_OFF+6]) <<  8) |
                                (((uint64_t) ptr[IN24XX_LOGO_WWPN_OFF+7]));
                        } else {
                            wwn = INI_ANY;
                        }
                        isp_del_wwn_entry(isp, ISP_GET_VPIDX(isp, inot->in_vpidx), wwn, nphdl, portid);
                        break;
                    case PRLO:
                        msg = "PRLO";
                        break;
                    case PLOGI:
                        msg = "PLOGI";
                        if (ISP_FW_NEWER_THAN(isp, 4, 0, 25)) {
                            uint8_t *ptr = qe;  /* point to unswizzled entry! */
                            wwn =
                                (((uint64_t) ptr[IN24XX_PLOGI_WWPN_OFF])   << 56) |
                                (((uint64_t) ptr[IN24XX_PLOGI_WWPN_OFF+1]) << 48) |
                                (((uint64_t) ptr[IN24XX_PLOGI_WWPN_OFF+2]) << 40) |
                                (((uint64_t) ptr[IN24XX_PLOGI_WWPN_OFF+3]) << 32) |
                                (((uint64_t) ptr[IN24XX_PLOGI_WWPN_OFF+4]) << 24) |
                                (((uint64_t) ptr[IN24XX_PLOGI_WWPN_OFF+5]) << 16) |
                                (((uint64_t) ptr[IN24XX_PLOGI_WWPN_OFF+6]) <<  8) |
                                (((uint64_t) ptr[IN24XX_PLOGI_WWPN_OFF+7]));
                        } else {
                            wwn = INI_NONE;
                        }
                        isp_add_wwn_entry(isp, ISP_GET_VPIDX(isp, inot->in_vpidx), wwn, nphdl, portid);
                        break;
                    case PRLI:
                        msg = "PRLI";
                        break;
                    case PDISC:
                        isp_prt(isp, ISP_LOGTINFO, "%s: Chan %d IID N-Port Handle 0x%x Port ID 0x%06x PDISC",
                            __func__, ISP_GET_VPIDX(isp, inot->in_vpidx), nphdl, portid);
                        break;
                    default:
                        isp_prt(isp, ISP_LOGTINFO, "ELS CODE 0x%x Received from 0x%06x", inot->in_status_subcode, portid);
                        break;
                    }
                    if (msg) {
                        isp_prt(isp, ISP_LOGTINFO, "%s Chan %d ELS N-port handle %x PortID 0x%06x", msg, ISP_GET_VPIDX(isp, inot->in_vpidx), nphdl, portid);
                    }
                    if ((inot->in_flags & IN24XX_FLAG_PUREX_IOCB) == 0) {
                        isp_notify_ack(isp, qe);
                    }
                    break;
                }
                case IN24XX_PORT_LOGOUT:
                    ptr = "PORT LOGOUT";
                    /* FALLTHROUGH */
                case IN24XX_PORT_CHANGED:
                    if (ptr == NULL) {
                        ptr = "PORT CHANGED";
                    }
                    /* FALLTHROUGH */
                case IN24XX_LIP_RESET: 
                    if (ptr == NULL) {
                        ptr = "LIP RESET";
                    }
                    isp_prt(isp, ISP_LOGINFO, "Chan %d %s (sub-status 0x%x) for N-port handle 0x%x", ISP_GET_VPIDX(isp, inot->in_vpidx), ptr, inot->in_status_subcode, nphdl);

                    /*
                     * All subcodes here are irrelevant. What is relevant
                     * is that we need to terminate all active commands from
                     * this initiator (known by N-port handle).
                     */
                    /* XXX IMPLEMENT XXX */
                    isp_notify_ack(isp, inot);
                    break;
                case IN24XX_LINK_RESET:
                case IN24XX_LINK_FAILED:
                case IN24XX_SRR_RCVD:
                default:
                    isp_notify_ack(isp, qe);
                    break;
                }
            } else if (IS_FC(isp)) {
                if (ISP_CAP_2KLOGIN(isp)) {
                    in_fcentry_e_t *inot = qe;
                    nphdl = inot->in_iid;
                    status = inot->in_status;
                    seqid = inot->in_seqid;
                    lun = inot->in_scclun;
                } else {
                    in_fcentry_t *inot = qe;
                    nphdl = inot->in_iid;
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
                    memset(&ins->notify, 0, sizeof (isp_notify_t));
                    memcpy(ins->qentry, qe, QENTRY_LEN);
                    ins->qevalid = 1;
                    ins->notify.nt_hba = isp;
                } else {
                    isp_prt(isp, ISP_LOGINFO, "skipping handling of Notify Status 0x%x", status);
                    isp_notify_ack(isp, qe);
                    break;
                }

                if (status == IN_ABORT_TASK) {
                    if (isp_find_pdb_by_loopid(isp, 0, nphdl, &lp) == 0) {
                        isp_prt(isp, ISP_LOGINFO, "cannot find WWN for loopid 0x%x for ABORT TASK", nphdl);
                        ins->notify.nt_wwn = INI_NONE;
                    } else {
                        ins->notify.nt_wwn = lp->port_wwn;
                    }
                    ins->notify.nt_channel = 0;
                    ins->notify.nt_tgt = FCPARAM(isp, 0)->isp_wwpn;
                    ins->notify.nt_lun = lun;
                    ins->notify.nt_need_ack = 1;
                    ins->notify.nt_tagval = seqid;
                    ins->notify.nt_ncode = NT_ABORT_TASK;
                    isp_prt(isp, ISP_LOGTINFO, "ABORT TASK [%llx] from 0x%016llx to lun %u", (ull) ins->notify.nt_tagval,
                        (ull) ins->notify.nt_wwn, lun);
                    CALL_PARENT_NOTIFY(isp, ins);
                    break;
                } else if (status == IN_PORT_LOGOUT) {
                    /*
                     * The port specified by the loop id listed in nphdl has logged out. We need to tell our upstream listener about it.
                     */
                    if (isp_find_pdb_by_loopid(isp, 0, nphdl, &lp)) {
                        ins->notify.nt_wwn = lp->port_wwn;
                        ins->notify.nt_ncode = NT_LOGOUT;
                        isp_prt(isp, ISP_LOGTINFO, "%s: isp_del_wwn called for 0x%016llx due to PORT_LOGOUT", __func__, (ull) ins->notify.nt_wwn);
                        isp_del_wwn_entry(isp, 0, ins->notify.nt_wwn, nphdl, PORT_ANY);
                        ins->notify.nt_tagval = seqid;
                        isp_prt(isp, ISP_LOGTINFO, "PORT LOGOUT [%llx] from 0x%016llx", (ull) ins->notify.nt_tagval, (ull) ins->notify.nt_wwn);
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
                    isp_prt(isp, ISP_LOGINFO, "Port Logout at handle 0x%x (seqid 0x%x) but have no WWPN for it- just ACKing", nphdl, seqid);
                    isp_notify_ack(isp, qe);
                } else if (status == IN_GLOBAL_LOGO) {
                    /*
                     * Everyone Logged Out
                     */
                    isp_prt(isp, ISP_LOGTINFO, "%s: isp_del_wwn called for everyone due to GLOBAL PORT_LOGOUT", __func__);
                    isp_del_wwn_entry(isp, 0, INI_ANY, NIL_HANDLE, PORT_ANY);
                    ins->notify.nt_wwn = INI_ANY;
                    ins->notify.nt_ncode = NT_LOGOUT;
                    ins->notify.nt_need_ack = 1;
                    CALL_PARENT_NOTIFY(isp, ins);
                } else {
                    isp_prt(isp, ISP_LOGINFO, "%s: ACKing unknown status 0x%x", __func__, status);
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
        ISP_DATA(isp, mbox6)->blocked = 1;
        ISP_RESET0(isp);
        isp_shutdown(isp);
        isp_thread_event(isp, ISP_THREAD_REINIT, NULL, 0, __func__, __LINE__);
        break;
    }
    case ISPASYNC_FW_RESTARTED:
    {
        if (IS_FC(isp)) {
            int i;
            for (i = 0; i < isp->isp_nchan; i++) {
                isp_thread_event(isp, ISP_THREAD_FC_RESCAN, FCPARAM(isp, i), 0, __func__, __LINE__);
            }
        }
        break;
    }
    default:
        break;
    }
}

int
isplinux_biosparam(struct scsi_device *sdev, struct block_device *n, sector_t capacity, int ip[])
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

int
isplinux_get_default_id(ispsoftc_t *isp, int chan)
{
    if (IS_FC(isp))
        return (isp_fc_id);
    else
        return (isp_spi_id);
}

int
isplinux_get_default_role(ispsoftc_t *isp, int chan)
{
    return (ISP_DATA(isp, chan)->role);
}

void
isplinux_set_default_role(ispsoftc_t *isp, int chan, int role)
{
    ISP_DATA(isp, chan)->role = role;
}

/*
 * When we want to get the 'default' WWNs (when lacking NVRAM), we pick them up
 * from our platform default (defww{p|n}n) and morph them based upon channel.
 *
 * When we want to get the 'active' WWNs, we get NVRAM WWNs and then morph
 * them based upon channel.
 */

uint64_t
isplinux_default_wwn(ispsoftc_t *isp, int chan, int isactive, int iswwnn)
{
    uint64_t seed;
    isp_data *fc = ISP_DATA(isp, chan);

    /*
     * If we're asking for a active WWN, the default overrides get returned,
     * otherwise the NVRAM value is picked.
     *
     * If we're asking for a default WWN, we just pick the default override.
     */
    if (isactive) {
        seed = iswwnn? fc->def_wwnn : fc->def_wwpn;
        if (seed) {
            return (seed);
        }
        seed = iswwnn? FCPARAM(isp, chan)->isp_wwnn_nvram : FCPARAM(isp, chan)->isp_wwpn_nvram;
        if (seed) {
            return (seed);
        }
        return (0x400000007F00000aull);
    } else {
        seed = iswwnn? fc->def_wwnn : fc->def_wwpn;
    }


    /*
     * For channel zero just return what we have. For either ACIIVE or DEFAULT cases,
     * we depend on default override of NVRAM values for channel zero.
     */
    if (chan == 0) {
        return (seed);
    }

    /*
     * For other channels, we are doing one of three things:
     *
     *  1. If what we have now is non-zero, return it. Otherwise
     *     we morph values from channel 0.
     *  2. If we're here for a WWPN we synthesize it if
     *     Channel 0's wwpn has a type 2 NAA.
     *  3. If we're here for a WWNN we synthesize it if
     *     Channel 0's wwnn has a type 2 NAA.
     */

    if (seed) {
        return (seed);
    }
    if (isactive) {
        seed = iswwnn? FCPARAM(isp, 0)->isp_wwnn_nvram : FCPARAM(isp, 0)->isp_wwpn_nvram;
    } else {
        seed = iswwnn? ISP_DATA(isp, 0)->def_wwnn : ISP_DATA(isp, 0)->def_wwpn;
    }

    if (((seed >> 60) & 0xf) == 2) {
        /*
         * The type 2 NAA fields for QLogic cards appear be laid out thusly:
         *
         * bits 63..60  NAA == 2
         * bits 59..57  unused/zero
         * bit  56      port (1) or node (0) WWN distinguishor
         * bit  48      physical port on dual-port chips (23XX/24XX)
         *
         * This is somewhat nutty, particularly since bit 48 is irrelevant
         * as they assign seperate serial numbers to different physical ports
         * anyway.
         *
         * We'll stick our channel number plus one first into bits 57..59 and
         * thence into bits 52..55 which allows for 8 bits of channel which is
         * comfortably more than our maximum (126) now.
         */
        seed &= ~0x0FF0000000000000ULL;
        if (iswwnn == 0) {
            seed |= ((uint64_t) (chan+1) & 0xf) << 56;
            seed |= ((uint64_t) ((chan+1) >> 4) & 0xf) << 52;
        }
    } else {
        seed = 0;
    }
    return (seed);
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
    unsigned long flags;
    int i;

    ISP_ILOCK_SOFTC(isp);
    isp->isp_osinfo.dogcnt++;

    for (i = 0; i < isp->isp_nchan; i++) {
        if (ISP_DATA(isp, i)->qfdelay) {
            ISP_DATA(isp, i)->qfdelay--;
        }
    }

    /*
     * Check to see whether we need to check for loop state
     */
    if (IS_FC(isp) && isp->isp_state == ISP_RUNSTATE) {
        for (i = 0 ; i < isp->isp_nchan; i++) {
            fcparam *fcp = FCPARAM(isp, i);
            if (fcp->role == ISP_ROLE_NONE || ISP_DATA(isp, i)->deadloop || ISP_DATA(isp, i)->nextscan == 0) {
                continue;
            }
            if (jiffies > ISP_DATA(isp, i)->nextscan) {
                ISP_DATA(isp, i)->nextscan = jiffies;
                isp_thread_event(isp, ISP_THREAD_FC_RESCAN, fcp, 0, __func__, __LINE__);
            }
        }
    }

    /*
     * Run any commands that were waitinbg.
     */
    isplinux_runwaitq(isp);

    /*
     * Pick up any commands needing completion...
     */

    if ((Cmnd = isp->isp_osinfo.dqnext) != NULL) {
        isp->isp_osinfo.dqnext = isp->isp_osinfo.dqtail = NULL;
    }

    /*
     * Check for any rescan activity that needs running
     */
    if (isp->isp_osinfo.scan_timeout && --isp->isp_osinfo.scan_timeout == 0) {
            isp_thread_event(isp, ISP_THREAD_SCSI_SCAN, (void *)1, 0, __func__, __LINE__);
    }
    if (isp->isp_osinfo.rescan_timeout && --isp->isp_osinfo.rescan_timeout == 0) {
            isp_thread_event(isp, ISP_THREAD_SCSI_SCAN, (void *)0, 0, __func__, __LINE__);
    }

    /*
     * Set up the timer again
     */
    if (isp->dogactive) {
        isp->isp_osinfo.timer.expires = jiffies + ISP_WATCH_TIME;
        add_timer(&isp->isp_osinfo.timer);
    }

#ifdef  ISP_TARGET_MODE
    /*
     * Fire up any delayed target mode actions based
     * upon whether the dog counter has wrapped to
     * zero.
     */
    if (isp->isp_osinfo.dogcnt == 0) {
        tmd_cmd_t *wt;
        while ((wt = isp->isp_osinfo.waiting_t) != NULL) {
            isp->isp_osinfo.waiting_t = wt->cd_next;
            wt->cd_next = NULL;
            if (wt->cd_lastoff == 0) {
                isp_thread_event(isp, ISP_THREAD_FINDIID, wt, 0, __func__, __LINE__);
            } else {
                isp_thread_event(isp, ISP_THREAD_RESTART_AT7, wt, 0, __func__, __LINE__);
            }
        }
    }
#endif

    ISP_IUNLK_SOFTC(isp);

    /*
     * Complete any commands that had been on the done queue
     */
    if (Cmnd) {
        ISP_LOCK_SCSI_DONE(isp);
        while (Cmnd) {
            Scsi_Cmnd *f = (Scsi_Cmnd *) Cmnd->host_scribble;
            Cmnd->host_scribble = NULL;
            (*Cmnd->scsi_done)(Cmnd);
            Cmnd = f;
        }
        ISP_UNLK_SCSI_DONE(isp);
    }
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#define PTARG                   , struct pt_regs *pt
#else
#define PTARG
#endif

irqreturn_t
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
        return IRQ_NONE;
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
            (*Cmnd->scsi_done)(Cmnd);
            Cmnd = f;
        }
        ISP_UNLK_SCSI_DONE(isp);
    }
#ifdef  ISP_TARGET_MODE
    isp_tgt_tq(isp);
#endif
    return IRQ_HANDLED;
}

/*
 * roles=DEVID=role[,...]
 */
static int
isp_parse_rolearg(ispsoftc_t *isp, int chan, char *roles)
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

/*
 * isp_wwnns=DEVID=[chan:]wwn[,...]
 * isp_wwpns=DEVID=[chan:]wwn[,...]
 */
static uint64_t
isp_parse_wwnarg(ispsoftc_t *isp, int chan, char *wwns)
{
    char *wwnt = wwns;
    uint64_t wwn = 0;

    while (wwn == 0 && wwnt && *wwnt) {
        unsigned int id;
        int thischan;
        char *eqtok, *commatok, *colontok, *wwnstart, *p, *q;

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
        q = wwnt;
        colontok = strchr(eqtok+1, ':');
        thischan = 0;
        if (colontok) {
            *colontok = 0;
            q = eqtok + 1;
            thischan = simple_strtoul(q, &p, 0);
            *colontok = ':';
            if (p == q) {
                thischan = 0;
            }
            q = wwnt;
            wwnstart = colontok + 1;
        } else {
            wwnstart = eqtok + 1;
        }
        if (strncmp(q, "0x", 2) == 0) {
            q += 2;
        }
        id = simple_strtoul(q, &p, 16);
        if (p != q && id == isp->isp_osinfo.device_id && thischan == chan) {
            unsigned long t, t2;
            p = wwnstart;
            while (*p) {
                p++;
            }
            p -= 8;
            if (p > wwnstart) {
                char *q;
                char c;
                q = p;
                t = simple_strtoul(p, &q, 16);
                c = *p;
                *p = 0;
                t2 = simple_strtoul(wwnstart, NULL, 16);
                *p = c;
            } else {
                t = simple_strtoul(wwnstart, NULL, 16);
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
    int retval, chan, i;
    unsigned long flags;

    if (isp_nofwreload & (1 << isp->isp_unit)) {
        isp->isp_confopts |= ISP_CFG_NORELOAD;
    }
    if (isp_nonvram & (1 << isp->isp_unit)) {
        isp->isp_confopts |= ISP_CFG_NONVRAM;
    }

    if (IS_FC(isp)) {
        if (isp_nport_only & (1 << isp->isp_unit)) {
            isp->isp_confopts |= ISP_CFG_NPORT_ONLY;
        } else if (isp_loop_only & (1 << isp->isp_unit)) {
            isp->isp_confopts |= ISP_CFG_LPORT_ONLY;
        } else {
            isp->isp_confopts |= ISP_CFG_NPORT;
        }
        isp->isp_osinfo.host->this_id = MAX_FC_TARG+1;
        if (isp_default_frame_size) {
            if (isp_default_frame_size != 512 && isp_default_frame_size != 1024 && isp_default_frame_size != 2048) {
                isp_prt(isp, ISP_LOGERR, "bad frame size (%d), defaulting to (%d)", isp_default_frame_size, ICB_DFLT_FRMLEN);
                isp_default_frame_size = 0;
            }
        }
        if (isp_default_exec_throttle) {
            if (isp_default_exec_throttle < 1 || isp_default_exec_throttle > 255) {
                isp_prt(isp, ISP_LOGERR, "bad execution throttle size (%d), defaulting to (%d)", isp_default_exec_throttle, ICB_DFLT_THROTTLE);
                isp_default_exec_throttle = 0;
            }
        }
        if (isp_fcduplex & (1 << isp->isp_unit)) {
            isp->isp_confopts |= ISP_CFG_FULL_DUPLEX;
        }
        isp->isp_osinfo.host->max_id = MAX_FC_TARG;
        isp->isp_osinfo.host->max_cmd_len = 16;

        for (chan = 0; chan < isp->isp_nchan; chan++) {
            isp_data *fc = ISP_DATA(isp, chan);

            fc->def_wwnn = isp_parse_wwnarg(isp, chan, isp_wwnns);
            fc->def_wwpn = isp_parse_wwnarg(isp, chan, isp_wwpns);
            if (isp_default_frame_size) {
                isp->isp_confopts |= ISP_CFG_OWNFSZ;
                DEFAULT_FRAMESIZE(isp) = isp_default_frame_size;
            } else {
                DEFAULT_FRAMESIZE(isp) = ICB_DFLT_FRMLEN;
            }
            if (isp_default_exec_throttle) {
                isp->isp_confopts |= ISP_CFG_OWNEXCTHROTTLE;
                DEFAULT_EXEC_THROTTLE(isp) = isp_default_exec_throttle;
            } else {
                DEFAULT_EXEC_THROTTLE(isp) = ICB_DFLT_THROTTLE;
            }
            fc->role = isp_parse_rolearg(isp, chan, isp_roles);
            SET_DEFAULT_ROLE(isp, chan, fc->role);
        }
    } else {
        isp->isp_osinfo.host->max_id = MAX_TARGETS;
        isp->isp_osinfo.host->max_cmd_len = 12;
        isp->isp_osinfo.host->this_id = 7;    /* temp default */
        for (chan = 0; chan < isp->isp_nchan; chan++) {
            SDPARAM(isp, chan)->role = isp_parse_rolearg(isp, chan, isp_roles);
            SET_DEFAULT_ROLE(isp, chan, SDPARAM(isp, chan)->role);
        }
    }

    if (isp_own_id) {
        isp->isp_confopts |= ISP_CFG_OWNLOOPID;
    }

    /*
     * Initialize locks
     */
    ISP_LOCK_INIT(isp);
    ISP_TLOCK_INIT(isp);
    sema_init(&isp->isp_osinfo.mbox_sem, 1);
    init_waitqueue_head(&isp->isp_osinfo.mboxwq);
    init_waitqueue_head(&isp->isp_osinfo.trq);
    for (i = 0; i < MAX_THREAD_ACTION; i++) {
        init_waitqueue_head(&isp->isp_osinfo.t_actions[i].thread_waiter);
        if (i < MAX_THREAD_ACTION - 1) {
            isp->isp_osinfo.t_actions[i].next = &isp->isp_osinfo.t_actions[i+1];
        }
    }
    isp->isp_osinfo.t_busy = NULL;
    isp->isp_osinfo.t_busy_t = NULL;
    isp->isp_osinfo.t_free = isp->isp_osinfo.t_actions;

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
    if (IS_FC(isp)) {
        isp->isp_osinfo.thread_task = kthread_run(isp_task_thread, isp, "isp%d_fc", isp->isp_unit);
        if (IS_ERR(isp->isp_osinfo.thread_task)) {
            isp_prt(isp, ISP_LOGERR, "unable to start FC task thread");
#ifdef ISP_TARGET_MODE
            isp_deinit_target(isp);
#endif
            isp->isp_osinfo.thread_task = NULL;
        }

    }
    ISP_LOCK_SOFTC(isp);
    init_timer(&isp->isp_osinfo.timer);
    isp->isp_osinfo.timer.data = (unsigned long) isp;
    isp->isp_osinfo.timer.function = isplinux_timer;
    isp->isp_osinfo.timer.expires = jiffies + ISP_WATCH_TIME;
    add_timer(&isp->isp_osinfo.timer);
    isp->dogactive = 1;

    retval = isplinux_reinit(isp, 1);

    if (retval) {
        isp_prt(isp, ISP_LOGERR, "failed to init HBA port- skipping it");
        del_timer(&isp->isp_osinfo.timer);
        isp->dogactive = 0;
        ISP_UNLK_SOFTC(isp);
#ifdef ISP_TARGET_MODE
        isp_deinit_target(isp);
#endif
        if (isp->isp_osinfo.thread_task) {
            kthread_stop(isp->isp_osinfo.thread_task);
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
isplinux_reinit(ispsoftc_t *isp, int doset_defaults)
{
    int maxluns = isp_maxluns;

    isp_reset(isp, doset_defaults);

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
     *     If somebody has set isp_maxluns away from the default, we follow that.
     *
     *     We filter any value through the HBA maximum
     */
    if (isp_maxluns == 8) {
        if (IS_FC(isp)) {
            maxluns = 256;
        }
    }
    isp->isp_osinfo.host->max_lun = min(maxluns, ISP_MAX_LUNS(isp));
    isp->isp_osinfo.host->can_queue = 1;
    isp->isp_osinfo.host->cmd_per_lun = 1;
    isp->isp_osinfo.host->this_id = IS_FC(isp)? MAX_FC_TARG : 7;

    isp_init(isp);
    if (isp->isp_state != ISP_INITSTATE) {
        isp_prt(isp, ISP_LOGERR, "failed to enter INIT state");
        return (-1);
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
        ISP_SLEEP(isp, 1 * 1000000);

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
    isp->mbintsok = 1;
    isp->isp_state = ISP_RUNSTATE;
    return (0);
}

int
isp_thread_event(ispsoftc_t *isp, int action, void *a, int dowait, const char *file, const int line)
{
    isp_thread_action_t *tap;
    unsigned long flags;

    spin_lock_irqsave(&isp->isp_osinfo.tlock, flags);
    /*
     * Check for duplicates
     */
    for (tap = isp->isp_osinfo.t_busy; tap != NULL; tap = tap->next) {
        if (tap->thread_action == action && tap->arg == a && dowait == 0) {
            tap->count++;
            spin_unlock_irqrestore(&isp->isp_osinfo.tlock, flags);
            wake_up(&isp->isp_osinfo.trq);
            isp_prt(isp, ISP_LOGDEBUG1, "async thread event %d from %s:%d now has count %d", action, file, line, tap->count);
            return (0);
        }
    }
    if ((tap = isp->isp_osinfo.t_free) == NULL) {
        spin_unlock_irqrestore(&isp->isp_osinfo.tlock, flags);
        isp_prt(isp, ISP_LOGERR, "thread event %d from %s:%d sent with thread overflow", action, file, line);
        return (-1);
    }
    isp->isp_osinfo.t_free = tap->next;
    tap->next = NULL;
    tap->count = 1;
    tap->thread_action = action;
    tap->arg = a;
    tap->done = 0;
    if (dowait) {
        tap->waiting = 1;
        isp_prt(isp, ISP_LOGDEBUG0, "action %d sending from %s:%d and now waiting", action, file, line);
    } else {
        tap->waiting = 0;
        isp_prt(isp, ISP_LOGDEBUG0, "action %d from %s:%d sending", action, file, line);
    }
    if (isp->isp_osinfo.t_busy) {
        isp->isp_osinfo.t_busy_t->next = tap;
    } else {
        isp->isp_osinfo.t_busy = tap;
    }
    isp->isp_osinfo.t_busy_t = tap;
    spin_unlock_irqrestore(&isp->isp_osinfo.tlock, flags);
    wake_up(&isp->isp_osinfo.trq);
    if (dowait) {
        while (wait_event_interruptible_timeout(tap->thread_waiter, (tap->done == 1), 100)) {
            if (kthread_should_stop()) {
                break;
            }
        }
        if (kthread_should_stop()) {
            tap->waiting = 0;
            return (-1);
        }
        spin_lock_irqsave(&isp->isp_osinfo.tlock, flags);
        tap->waiting = 0;
        tap->next = isp->isp_osinfo.t_free;
        isp->isp_osinfo.t_free = tap;
        tap->next = NULL;
        spin_unlock_irqrestore(&isp->isp_osinfo.tlock, flags);
        isp_prt(isp, ISP_LOGDEBUG0, "action %d from %s:%d done", action, file, line);
    }
    return (0);
}

static void
isp_scsi_scan(ispsoftc_t *isp)
{
    unsigned long flags;
    int chan, tgt, i;

    if (!IS_FC(isp)) {
        return;
    }

    ISP_LOCKU_SOFTC(isp);
    for (chan = 0; chan < isp->isp_nchan; chan++) {
        fcparam *fcp = FCPARAM(isp, chan);
        for (i = 0; i < MAX_FC_TARG; i++) {
            fcportdb_t *lp = &fcp->portdb[i];
            if (lp->dev_map_idx == 0) {
                continue;
            }
            tgt = lp->dev_map_idx - 1;
            if (lp->state == FC_PORTDB_STATE_VALID && lp->dirty == 0) {
                ISP_UNLKU_SOFTC(isp);
                scsi_scan_target(&isp->isp_osinfo.host->shost_gendev, chan, tgt, 0, 0);
                ISP_LOCKU_SOFTC(isp);
            } else if (lp->state == FC_PORTDB_STATE_ZOMBIE) {
                struct scsi_device *sdev;
                fcp->isp_dev_map[tgt] = 0;
                lp->state = FC_PORTDB_STATE_NIL;
                lp->dev_map_idx = 0;
                lp->dirty = 0;
                ISP_UNLKU_SOFTC(isp);
                sdev = scsi_device_lookup(isp->isp_osinfo.host, 0, tgt, 0);
                if (sdev) {
                    scsi_remove_device(sdev);
                    scsi_device_put(sdev);
                }
                ISP_LOCKU_SOFTC(isp);
            }
        }
    }
    ISP_UNLKU_SOFTC(isp);
}

static int
isp_task_thread(void *arg)
{
    ispsoftc_t *isp = arg;
    isp_thread_action_t *tap;
    unsigned long flags;
    int i;

    isp_prt(isp, ISP_LOGDEBUG0, "isp_task_thread starting");

    while (!kthread_should_stop()) {
        isp_prt(isp, ISP_LOGDEBUG0, "isp_task_thread sleeping");
        if (wait_event_interruptible(isp->isp_osinfo.trq, (isp->isp_osinfo.t_busy || kthread_should_stop()))) {
            continue;
        }
        isp_prt(isp, ISP_LOGDEBUG0, "isp_task_thread running");
        if (kthread_should_stop()) {
            break;
        }
        spin_lock_irqsave(&isp->isp_osinfo.tlock, flags);
        while ((tap = isp->isp_osinfo.t_busy) != NULL) {
            if ((isp->isp_osinfo.t_busy = tap->next) == NULL) {
                isp->isp_osinfo.t_busy_t = NULL;
            }
            spin_unlock_irqrestore(&isp->isp_osinfo.tlock, flags);
            if (tap == NULL) {
                break;
            }
            isp_prt(isp, ISP_LOGDEBUG0, "isp_task_thread: action %d", tap->thread_action);
            switch (tap->thread_action) {
            case ISP_THREAD_NIL:
                break;
            case ISP_THREAD_SCSI_SCAN:
                isp_scsi_scan(isp);
                break;
            case ISP_THREAD_REINIT:
                ISP_LOCKU_SOFTC(isp);
                if (isp->isp_dead) {
                    isp_prt(isp, ISP_LOGERR, "chip marked dead- not restarting");
                    isp_shutdown(isp);
                    ISP_DISABLE_INTS(isp);
                    ISP_UNLKU_SOFTC(isp);
                    break;
                }
                isp_reinit(isp, 0);
                if (isp->isp_state == ISP_RUNSTATE) {
                    for (i = 0; i < isp->isp_nchan; i++) {
                        ISP_DATA(isp, i)->blocked = 0;
                    }
                    isp_async(isp, ISPASYNC_FW_RESTARTED);
                } else {
                    isp_prt(isp, ISP_LOGERR, "unable to restart chip");
                }
                ISP_UNLKU_SOFTC(isp);
                break;
            case ISP_THREAD_FC_RESCAN:
            {
                fcparam *fcp = tap->arg;
                int chan = fcp - FCPARAM(isp, 0);

                fcp = FCPARAM(isp, chan);
                ISP_LOCKU_SOFTC(isp);
                ISP_DATA(isp, chan)->nextscan = 0;
                if (isp_fc_runstate(isp, chan, 250000) == 0) {
                    ISP_DATA(isp, chan)->deadloop = 0;
                    ISP_DATA(isp, chan)->downcount = 0;
                    ISP_DATA(isp, chan)->blocked = 0;
                    isplinux_runwaitq(isp);
                } else {
                    if (ISP_DATA(isp, chan)->downcount == 0) {
                        ISP_DATA(isp, chan)->downcount = jiffies;
                    }
                    /*
                     * Try again in a little while.
                     */
                    if ((jiffies - ISP_DATA(isp, chan)->downcount) > (isp_deadloop_time * HZ)) {
                        fcp->loop_seen_once = 0;
                        ISP_DATA(isp, chan)->deadloop = 1;
                        ISP_DATA(isp, chan)->downcount = 0;
                        ISP_DATA(isp, chan)->blocked = 0;
                        isp_prt(isp, ISP_LOGWARN, "Chan %d assuming loop is dead", chan);
                        isplinux_flushwaitq(isp);
                        ISP_UNLKU_SOFTC(isp);
                        break;
                    }
                    ISP_DATA(isp, chan)->nextscan = jiffies + HZ;
                }
                ISP_UNLKU_SOFTC(isp);
                break;
            }
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
                    isp_prt(isp, ISP_LOGTINFO, "target mode entry no longer valid");
                    ISP_UNLKU_SOFTC(isp);
                    break;
                }
                memset(&u, 0, sizeof (u));
                u.id = lp->handle;
                isp_prt(isp, ISP_LOGTINFO, "Doing Port Logout repair for 0x%016llx@0x%x (loop id) %u", (ull) lp->port_wwn, lp->portid, lp->handle);
                memset(&mbs, 0, sizeof (mbs));
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
                memset(&mbs, 0, sizeof (mbs));
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
                fcportdb_t *lp = NULL;
                uint64_t iid = INI_NONE;
                uint16_t nphdl = NIL_HANDLE;

                if (tmd->cd_lflags & CDFL_ABORTED) {
                    isp_prt(isp, ISP_LOGTINFO, "[%llx] asking thread to terminate because it was marked aborted", (ull) tmd->cd_tagval);
                    isp_thread_event(isp, ISP_THREAD_TERMINATE, tmd, 0, __func__, __LINE__);
                    break;
                }
                ISP_LOCKU_SOFTC(isp);
                if (isp_find_pdb_by_sid(isp, tmd->cd_channel, tmd->cd_portid, &lp)) {
                    if (!VALID_INI(lp->port_wwn)) {
                        if (lp->handle == NIL_HANDLE) {
                            /*
                             * Ooops- all we have is the port id.
                             */
                            uint16_t nphdl, max;
                            isp_pdb_t pdb;

                            if (IS_24XX(isp)) {
                                max = NPH_MAX_2K;
                            } else {
                                max = NPH_MAX;
                            }
                            for (nphdl = 0; nphdl != max; nphdl++) {
                                if (isp_control(isp, ISPCTL_GET_PDB, tmd->cd_channel, nphdl, &pdb)) {
                                    continue;
                                }
                                isp_prt(isp, ISP_LOGTINFO, "%s: nphdl 0x%04x has portid 0x%06x", __func__, nphdl, pdb.portid);
                                if (pdb.portid == tmd->cd_portid) {
                                    lp->handle = nphdl;
                                    break;
                                }
                            }
                            if (nphdl == max) {
                                ISP_UNLKU_SOFTC(isp);
                                isp_prt(isp, ISP_LOGTINFO, "[0x%llx] asking thread to terminate cmd [0x%02x] because because we can't find the N-Port handle", (ull) tmd->cd_tagval, tmd->cd_cdb[0] & 0xff);
                                isp_tgt_dump_pdb(isp, tmd->cd_channel);
                                isp_thread_event(isp, ISP_THREAD_TERMINATE, tmd, 0, __func__, __LINE__);
                                break;
                            }
                        }
                        if (isp_control(isp, ISPCTL_GET_NAMES, tmd->cd_channel, lp->handle, NULL, &lp->port_wwn) == 0) {
                            nphdl = lp->handle;
                            iid = lp->port_wwn;
                        } else {
                            isp_prt(isp, ISP_LOGALL, "%s: Chan %d [0x%llx] failed to get name for handle 0x%02x for portid 0x%06x", __func__, tmd->cd_channel, (ull) tmd->cd_tagval, lp->handle, tmd->cd_portid);
                        }
                    } else {
                        nphdl = lp->handle;
                        iid = lp->port_wwn;
                    }
                } else {
                    /*
                     * If it's no longer in the port database, then some event between the receipt of the command and now
                     * has cleared it out. The command is probably already dead due to initiator port logout.
                     */
                    ISP_UNLKU_SOFTC(isp);
                    isp_prt(isp, ISP_LOGTINFO, "[0x%llx] asking thread to terminate cmd [0x%02x] because PortID 0x%06x no longer in port database", (ull) tmd->cd_tagval, tmd->cd_cdb[0] & 0xff, tmd->cd_portid);
                    isp_tgt_dump_pdb(isp, tmd->cd_channel);
                    isp_thread_event(isp, ISP_THREAD_TERMINATE, tmd, 0, __func__, __LINE__);
                    break;
                }
                if (iid == INI_NONE) {
                    isp_prt(isp, ISP_LOGTDEBUG0, "%s: [0x%llx] trying to find IID again...", __func__, (ull) tmd->cd_tagval);
                    tmd->cd_next = isp->isp_osinfo.waiting_t;
                    isp->isp_osinfo.waiting_t = tmd;
                    tmd->cd_lastoff = 0;
                    ISP_UNLKU_SOFTC(isp);
                    break;
                }
                tmd->cd_tgt = FCPARAM(isp, tmd->cd_channel)->isp_wwpn;
                tmd->cd_nphdl = nphdl;
                tmd->cd_iid = iid;
                isp_prt(isp, ISP_LOGTINFO, "%s: [0x%llx] Chan %d found initiator @ IID 0x%016llx N-Port Handle 0x%02x Port ID 0x%06x", __func__,
                    (ull) tmd->cd_tagval, tmd->cd_channel, (ull)tmd->cd_iid, tmd->cd_nphdl, tmd->cd_portid);
                CALL_PARENT_TMD(isp, tmd, QOUT_TMD_START);
                ISP_UNLKU_SOFTC(isp);
                isp_tgt_tq(isp);
                break;
            }
            case ISP_THREAD_FINDPORTID:
            {
                tmd_cmd_t *tmd = tap->arg;
                fcportdb_t *lp;

                ISP_LOCKU_SOFTC(isp);
                if (isp_find_pdb_by_loopid(isp, tmd->cd_channel, tmd->cd_nphdl, &lp)) {
                    if (lp->portid == PORT_NONE) {
                        isp_pdb_t pdb;
                        if (isp_control(isp, ISPCTL_GET_PDB, tmd->cd_channel, tmd->cd_nphdl, &pdb) == 0) {
                            tmd->cd_portid = lp->portid = pdb.portid;
                        }
                    } else {
                        tmd->cd_portid = lp->portid;
                    }
                } else {
                    isp_prt(isp, ISP_LOGTINFO, "[0x%llx] not in port database at all any more", (ull) tmd->cd_tagval);
                }
                if (tmd->cd_portid != PORT_NONE) {
                    isp_prt(isp, ISP_LOGTINFO, "%s: [0x%llx] Chan %d found initiator @ IID 0x%016llx N-Port Handle 0x%02x Port ID 0x%06x", __func__,
                        (ull) tmd->cd_tagval, tmd->cd_channel, (ull)tmd->cd_iid, tmd->cd_nphdl, tmd->cd_portid);
                }
                CALL_PARENT_TMD(isp, tmd, QOUT_TMD_START);
                ISP_UNLKU_SOFTC(isp);
                isp_tgt_tq(isp);
                break;
            }
            case ISP_THREAD_TERMINATE:
            {
                fcportdb_t *lp;
                tmd_cmd_t *tmd = tap->arg;

                ISP_LOCKU_SOFTC(isp);
                if (isp_find_pdb_by_sid(isp, tmd->cd_channel, tmd->cd_portid, &lp)) {
                    tmd->cd_iid = lp->port_wwn;
                    tmd->cd_nphdl = lp->handle;
                    CALL_PARENT_TMD(isp, tmd, QOUT_TMD_START);
                    ISP_UNLKU_SOFTC(isp);
                    isp_tgt_tq(isp);
                    isp_prt(isp, ISP_LOGINFO, "Chan %d [%llx] reprieved", tmd->cd_channel, (ull) tmd->cd_tagval);
                    break;
                }

                isp_prt(isp, ISP_LOGTINFO, "%s now terminating [%llx] from 0x%06x", __func__, (ull) tmd->cd_tagval, tmd->cd_portid);
                if (isp_terminate_cmd(isp, tmd)) {
                    ISP_UNLKU_SOFTC(isp);
                    isp_thread_event(isp, ISP_THREAD_TERMINATE, tmd, 0, __func__, __LINE__);
                    break;
                }
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
            case ISP_THREAD_RESTART_AT7:
            {
                at7_entry_t at;
                tmd_cmd_t *tmd = tap->arg;
                memcpy(&at, tmd, sizeof (at7_entry_t));
                ISP_LOCKU_SOFTC(isp);
                memset(tmd, 0, sizeof (tmd_cmd_t));
                if (isp->isp_osinfo.tfreelist) {
                    isp->isp_osinfo.bfreelist->cd_next = tmd;
                } else {
                    isp->isp_osinfo.tfreelist = tmd;
                }
                isp->isp_osinfo.bfreelist = tmd; /* remember to move the list tail pointer */
                isp_handle_platform_atio7(isp, &at);
                ISP_UNLKU_SOFTC(isp);
                break;
            }
            case ISP_THREAD_FC_PUTBACK:
            {
                tmd_cmd_t *tmd = tap->arg;
                ISP_LOCKU_SOFTC(isp);
                isp_prt(isp, ISP_LOGTINFO, "%s: [%llx] calling putback", __func__, (ull) tmd->cd_tagval);
                if (isp_target_putback_atio(isp, tmd)) {
                    ISP_UNLKU_SOFTC(isp);
                    isp_thread_event(isp, ISP_THREAD_FC_PUTBACK, tmd, 0, __func__, __LINE__);
                    break;
                }
                if (tmd->cd_lflags & CDFL_NEED_CLNUP) {
                    tmd->cd_lflags ^= CDFL_NEED_CLNUP;
                    isp_prt(isp, ISP_LOGTINFO, "Terminating %llx too", (ull) tmd->cd_tagval);
                    (void) isp_terminate_cmd(isp, tmd);
                }
                memset(tmd, 0, sizeof (tmd_cmd_t));
                if (isp->isp_osinfo.tfreelist) {
                    isp->isp_osinfo.bfreelist->cd_next = tmd;
                } else {
                    isp->isp_osinfo.tfreelist = tmd;
                }
                isp->isp_osinfo.bfreelist = tmd; /* remember to move the list tail pointer */
                isp_prt(isp, ISP_LOGTDEBUG0, "DONE freeing tmd %p [%llx] after retry", tmd, (ull) tmd->cd_tagval);
                ISP_UNLKU_SOFTC(isp);
                break;
            }
#endif
            default:
                break;
            }
            tap->done = 0;
            if (tap->waiting) {
                isp_prt(isp, ISP_LOGDEBUG0, "isp_task_thread signalling");
                tap->waiting = 0;
                wake_up(&tap->thread_waiter);
                spin_lock_irqsave(&isp->isp_osinfo.tlock, flags);
            } else {
                spin_lock_irqsave(&isp->isp_osinfo.tlock, flags);
                tap->next = isp->isp_osinfo.t_free;
                isp->isp_osinfo.t_free = tap;
            }
        }
        spin_unlock_irqrestore(&isp->isp_osinfo.tlock, flags);
    }
    isp_prt(isp, ISP_LOGDEBUG0, "isp_task_thread exiting");
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
    if (level & (ISP_LOGTINFO|ISP_LOGINFO|ISP_LOGCONFIG|ISP_LOGSANCFG)) {
        prefl = KERN_INFO "%s: ";
    } else if (level & ISP_LOGWARN) {
        prefl = KERN_WARNING "%s: ";
    } else if (level & ISP_LOGERR) {
        prefl = KERN_ERR "%s: ";
    } else if (level & (ISP_LOGTDEBUG0|ISP_LOGTDEBUG1|ISP_LOGTDEBUG2)) {
        prefl = KERN_DEBUG "%s: ";
    } else if (level & (ISP_LOGDEBUG0|ISP_LOGDEBUG1|ISP_LOGDEBUG2|ISP_LOGDEBUG3)) {
        prefl = KERN_DEBUG "%s: ";
    } else {
        prefl = "%s: ";
    }
    printk(prefl, isp->isp_name);
    va_start(ap, fmt);
    vsnprintf(buf, sizeof (buf), fmt, ap);
    va_end(ap);
    printk("%s\n", buf);
}

#ifndef    ISP_LICENSE
#define    ISP_LICENSE    "GPL"
#endif
#ifdef  MODULE
#ifdef    MODULE_LICENSE
MODULE_LICENSE( ISP_LICENSE );
#endif
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
module_param(isp_vports, int, 0);
#else

static int __init isp_roleinit(char *str)
{
    isp_roles = str;
    return 0;
}
__setup("isp_roles=", isp_roleinit);
#endif

static struct scsi_host_template driver_template = {
    .name =                     ISP_NAME,
    .module =                   THIS_MODULE,
    .info =                     isplinux_info,
    .queuecommand =             isplinux_queuecommand,
    .eh_abort_handler =         isplinux_abort,
    .eh_device_reset_handler =  isplinux_bdr,
    .eh_bus_reset_handler =     isplinux_sreset,
    .eh_host_reset_handler =    isplinux_hreset,
    .slave_configure =          isplinux_slave_configure,
    .bios_param =               isplinux_biosparam,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
    .eh_timed_out =             isplinux_eh_timed_out,
#endif
#if defined(CONFIG_PROC_FS)
    .proc_info =                isplinux_proc_info,
    .proc_name =                ISP_NAME,
#endif
    .can_queue =                1,
    .sg_tablesize =             SG_ALL,
    .use_clustering =           ENABLE_CLUSTERING
};
struct scsi_host_template *isp_template = &driver_template;
/*
 * vim:ts=4:sw=4:expandtab
 */
