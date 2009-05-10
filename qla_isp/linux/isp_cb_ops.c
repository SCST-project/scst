/* $Id: isp_cb_ops.c,v 1.101 2009/05/01 22:34:13 mjacob Exp $ */
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
 * Qlogic ISP Host Adapter procfs and open/close entry points
 * proc safe pretty print code courtesy of Gerard Roudier (groudier@free.fr)
 */

#include "isp_linux.h"
#include "isp_ioctl.h"

#ifdef  CONFIG_PROC_FS
/*
 * 'safe' proc pretty print code
 */
struct info_str {
    char *buffer;
    int length;
    off_t offset;
    int pos;
};

static void
copy_mem_info(struct info_str *info, char *data, int len)
{
    if (info->pos + len > info->offset + info->length) {
        len = info->offset + info->length - info->pos;
    }

    if (info->pos + len < info->offset) {
        info->pos += len;
        return;
    }

    if (info->pos < info->offset) {
        off_t partial;

        partial = info->offset - info->pos;
        data += partial;
        info->pos += partial;
        len  -= partial;
    }

    if (len > 0) {
        memcpy(info->buffer, data, len);
        info->pos += len;
        info->buffer += len;
    }
}

static int copy_info(struct info_str *, const char *, ...) __attribute__((__format__(__printf__, 2, 3)));

static int
copy_info(struct info_str *info, const char *fmt, ...)
{
    va_list args;
    char buf[256];
    int len;

    va_start(args, fmt);
    len = vsprintf(buf, fmt, args);
    va_end(args);

    copy_mem_info(info, buf, len);
    return (len);
}


int
isplinux_proc_info(struct Scsi_Host *shp, char *buf, char **st, off_t off, int len, int io)
{
    int i;
    struct info_str info;
    ispsoftc_t *isp = NULL;
    unsigned long flags;

    for (i = 0; i < MAX_ISP; i++) {
        isp = isplist[i];
        if (isp == NULL) {
            continue;
        }
        if (isp->isp_host->host_no == shp->host_no) {
            break;
        }
    }
    if (isp == NULL) {
        return (-ENODEV);
    }

    if (io) {
        buf[len] = 0;
        io = -ENOSYS;
        if (strncmp(buf, "debug=", 6) == 0) {
            unsigned long debug;
            char *p = &buf[6], *q;
            debug = simple_strtoul(p, &q, 16);
            if (q == &buf[6]) {
                isp_prt(isp, ISP_LOGERR, "Garbled Debug Line '%s'", buf);
                return (-EINVAL);
            }
            isp_prt(isp, ISP_LOGINFO, "setting debug level to 0x%lx", debug);
            ISP_LOCKU_SOFTC(isp);
            isp->isp_dblev = debug;
            ISP_UNLKU_SOFTC(isp);
            io = len;
        } else if (strncmp(buf, "rescan", 6) == 0) {
            if (IS_FC(isp)) {
                for (io = 0; io < isp->isp_nchan; io++) {
                    isp_thread_event(isp, ISP_THREAD_FC_RESCAN, FCPARAM(isp, io), 1, __func__, __LINE__);
                }
                io = len;
            }
        } else if (strncmp(buf, "lip", 3) == 0) {
            if (IS_FC(isp)) {
                ISP_LOCKU_SOFTC(isp);
                (void) isp_control(isp, ISPCTL_SEND_LIP, 0);
                ISP_UNLKU_SOFTC(isp);
                io = len;
            }
        } else if (strncmp(buf, "busreset=", 9) == 0) {
            char *p = &buf[6], *q;
            int bus = (int) simple_strtoul(p, &q, 16);
            if (q == &buf[6]) {
                isp_prt(isp, ISP_LOGERR, "Garbled Bus Reset Line '%s'", buf);
                return (-EINVAL);
            }
            ISP_LOCKU_SOFTC(isp);
            (void) isp_control(isp, ISPCTL_RESET_BUS, bus);
            ISP_UNLKU_SOFTC(isp);
            io = len;
        } else if (strncmp(buf, "devreset=", 9) == 0) {
            char *p = &buf[6], *q;
            int dev = (int) simple_strtoul(p, &q, 16);
            if (q == &buf[6]) {
                isp_prt(isp, ISP_LOGERR, "Garbled Dev Reset Line '%s'", buf);
                return (-EINVAL);
            }
            /* always bus 0 */
            ISP_LOCKU_SOFTC(isp);
            (void) isp_control(isp, ISPCTL_RESET_DEV, 0, dev);
            ISP_UNLKU_SOFTC(isp);
            io = len;
        } else if (strncmp(buf, "reset", 5) == 0) {
            ISP_LOCKU_SOFTC(isp);
            isp_reinit(isp, 0);
            ISP_UNLKU_SOFTC(isp);
            io = len;
        } else if (strncmp(buf, "bins", 4) == 0) {
            ISP_LOCKU_SOFTC(isp);
            memset(isp->isp_osinfo.bins, 0, sizeof (isp->isp_osinfo.bins));
            ISP_UNLKU_SOFTC(isp);
            io = len;
        }
        return (io);
    }

    ISP_LOCKU_SOFTC(isp);
    if (st) {
        *st = buf;
    }
    info.buffer = buf;
    info.length = len;
    info.offset = off;
    info.pos    = 0;

    copy_info(&info, (char *)isplinux_info(isp->isp_host));
#ifdef  HBA_VERSION
    copy_info(&info, "\n HBA Version %s, built %s, %s", HBA_VERSION, __DATE__, __TIME__);
#endif
    copy_info(&info, "\n DEVID %x\n", isp->isp_osinfo.device_id);
    copy_info(&info,
        " Interrupt Stats:\n"
        "  total=0x%016llx bogus=0x%016llx\n"
        "  MboxC=0x%016llx async=0x%016llx\n"
        "  CRslt=0x%016llx CPost=0x%016llx\n"
        "  RspnsCHiWater=0x%04x FastPostC_Hiwater=0x%04x\n",
        (ull) isp->isp_intcnt, (ull) isp->isp_intbogus, (ull) isp->isp_intmboxc,
        (ull) isp->isp_intoasync, (ull) isp->isp_rsltccmplt, (ull) isp->isp_fphccmplt,
        isp->isp_rscchiwater, isp->isp_fpcchiwater);
    copy_info(&info,
        " Request In %d Request Out %d Result %d Nactv %d"
        " HiWater %u QAVAIL %d WtQHi %d\n",
        isp->isp_reqidx, isp->isp_reqodx, isp->isp_residx, isp->isp_nactive,
        isp->isp_osinfo.hiwater, ISP_QAVAIL(isp),
        isp->isp_osinfo.wqhiwater);
    for (i = 0; i < isp->isp_maxcmds; i++) {
        if (isp->isp_xflist[i]) {
            copy_info(&info, " %d:%p", i, isp->isp_xflist[i]);
        }
    }
#ifdef  ISP_TARGET_MODE
    copy_info(&info, "\n");
    for (i = 0; i < isp->isp_maxcmds; i++) {
        if (isp->isp_tgtlist[i]) {
            copy_info(&info, " %d:%p", i, isp->isp_tgtlist[i]);
        }
    }
#endif
    copy_info(&info, "\n");
    if (isp->isp_osinfo.wqnext) {
        struct scsi_cmnd *f = isp->isp_osinfo.wqnext;
        copy_info(&info, "WaitQ(%d)", isp->isp_osinfo.wqcnt);
        while (f) {
            copy_info(&info, "->%p", f);
            f = (struct scsi_cmnd *) f->host_scribble;
        }
        copy_info(&info, "\n");
    }
    if (isp->isp_osinfo.dqnext) {
        struct scsi_cmnd *f = isp->isp_osinfo.dqnext;
        copy_info(&info, "DoneQ");
        while (f) {
            copy_info(&info, "->%p", f);
            f = (struct scsi_cmnd *) f->host_scribble;
        }
        copy_info(&info, "\n");
    }
//    copy_info(&info, "blocked %d qfdelay %d\n", isp->isp_blocked, isp->isp_qfdelay);

    copy_info(&info, "\nxfer bins:\n");
    copy_info(&info, " <=1024   4096  32768  65536 131072 262144 524288  >0.5M\n");
/*                     123456 123456 123456 123456 123456 123456 123456 123456 */
    for (i = 0; i < 8; i++) {
        copy_info(&info, "% 7ld", isp->isp_osinfo.bins[i]);
    }
    copy_info(&info, "\n");
#ifdef  ISP_TARGET_MODE
    if (isp->isp_osinfo.cmds_started || isp->isp_osinfo.cmds_completed) {
        copy_info(&info, "\n");
        copy_info(&info, "Target cmds started: %llu; Target cmds completed ok: %llu", isp->isp_osinfo.cmds_started, isp->isp_osinfo.cmds_completed);
        copy_info(&info, "\n");
    }
#endif

    if (IS_FC(isp)) {
        int chan;
        for (chan = 0; chan < isp->isp_nchan; chan++) {
            fcparam *fcp = FCPARAM(isp, chan);
            copy_info(&info, "Self Channel %d:\nHandle ID 0x%x PortID 0x%06x FW State %s Loop State %s Topology %s Link Speed %dGb\n", chan, fcp->isp_loopid, fcp->isp_portid,
                isp_fc_fw_statename(fcp->isp_fwstate), isp_fc_loop_statename(fcp->isp_loopstate), isp_fc_toponame(fcp), fcp->isp_gbspeed);
            copy_info(&info, "Port WWN 0x%016llx Node WWN 0x%016llx\n\n", (ull) fcp->isp_wwpn, (ull)fcp->isp_wwnn);
            copy_info(&info, "FC devices in port database:\n");
            for (i = 0; i < MAX_FC_TARG; i++) {
                if (fcp->portdb[i].state != FC_PORTDB_STATE_VALID) {
                    continue;
                }
                if (fcp->portdb[i].dev_map_idx) {
                    copy_info(&info, "\tdbidx %d handle 0x%x PortID 0x%06x role %s (target %d)\n\tPort WWN 0x%016llx Node WWN 0x%016llx\n\n",
                        i, fcp->portdb[i].handle, fcp->portdb[i].portid, isp_class3_roles[fcp->portdb[i].roles],
                        fcp->portdb[i].dev_map_idx - 1, (ull) fcp->portdb[i].port_wwn, (ull) fcp->portdb[i].node_wwn);
                } else {
                    copy_info(&info, "\tdbidx %d handle 0x%x PortID 0x%06x role %s\n\tPort WWN 0x%016llx Node WWN 0x%016llx\n\n",
                        i, fcp->portdb[i].handle, fcp->portdb[i].portid, isp_class3_roles[fcp->portdb[i].roles],
                        (ull) fcp->portdb[i].port_wwn, (ull) fcp->portdb[i].node_wwn);
                }
            }
        }
    } else {
        sdparam *sdp = (sdparam *)isp->isp_param;

        copy_info(&info, "Initiator ID: %d\n", sdp->isp_initiator_id);
        copy_info(&info, "Target Flag  Period Offset\n");
        for (i = 0; i < MAX_TARGETS; i++) {
            copy_info(&info, "%6d: 0x%04x 0x%04x 0x%x\n", i, sdp->isp_devparam[i].actv_flags, sdp->isp_devparam[i].actv_offset,
                sdp->isp_devparam[i].actv_period);
        }
        if (IS_DUALBUS(isp)) {
            sdp++;
            copy_info(&info, "\nInitiator ID: %d, Channel B\n", sdp->isp_initiator_id);
            copy_info(&info,
                "Target     CurFlag    DevFlag  Period Offset B-Channel\n");
            for (i = 0; i < MAX_TARGETS; i++) {
                copy_info(&info, "%6d: 0x%04x 0x%04x 0x%x\n", i, sdp->isp_devparam[i].actv_flags, sdp->isp_devparam[i].actv_offset,
                    sdp->isp_devparam[i].actv_period);
            }
        }
    }
    ISP_UNLKU_SOFTC(isp);
    return (info.pos > info.offset ? info.pos - info.offset : 0);
}
#endif  /* CONFIG_PROC_FS */

static int isp_open(struct inode *, struct file *);
static int isp_close(struct inode *, struct file *);
static int isp_ioctl(struct inode *, struct file *, unsigned int, unsigned long);

dev_t isp_dev;
struct cdev isp_cdev = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
    .kobj   =   { .k_name = ISP_NAME, },
#endif
    .owner  =   THIS_MODULE
};
ISP_CLASS *isp_class;

struct file_operations isp_ioctl_operations = {
 .owner     =   THIS_MODULE,
 .open      =   isp_open,
 .release   =   isp_close,
 .ioctl     =   isp_ioctl,
};

static int
isp_open(struct inode *ip, struct file *fp)
{
    const int minor = iminor(ip);
    int i;
    ispsoftc_t *isp = NULL;

    for (i = 0; i < MAX_ISP; i++) {
        if (isplist[i] && isplist[i]->isp_unit == minor) {
            isp = isplist[i];
            break;
        }
    }
    if (isp == NULL) {
        return (-ENXIO);
    }
    if (isp->isp_isopen) {
        return (-EBUSY);
    }
    isp->isp_isopen = 1;
    fp->private_data = isp;
    return (0);
}

static int
isp_close(struct inode *ip, struct file *fp)
{
    ispsoftc_t *isp = fp->private_data;
    isp->isp_isopen = 0;
    return (0);
}

static int
isp_ioctl(struct inode *ip, struct file *fp, unsigned int c, unsigned long arg)
{
    ispsoftc_t *isp = fp->private_data;
    int i, rv, inarg, outarg;
    fcparam *fcp;
    uint16_t loopid, chan;
    mbreg_t mbs;
    unsigned long flags;

    if (isp == (ispsoftc_t *)NULL) {
        return -ENXIO;
    }

    if (IS_SCSI(isp)) {
        switch (c) {
        case ISP_SDBLEV:
        case ISP_RESCAN:
        case ISP_GETROLE:
        case ISP_SETROLE:
        case ISP_RESETHBA:
            break;
        default:
            return (-EINVAL);
        }
        fcp = NULL;
    } else {
        fcp = isp->isp_param;
    }

    rv = 0;
    isp_prt(isp, ISP_LOGDEBUG1, "isp_ioctl: cmd=%x", c);

    switch (c) {
    case ISP_GET_STATS:
    {
        isp_stats_t stats;

        memset(&stats, 0, sizeof stats);
        stats.isp_stat_version = ISP_STATS_VERSION;
        stats.isp_type = isp->isp_type;
        stats.isp_revision = isp->isp_revision;
        ISP_LOCK_SOFTC(isp);
        stats.isp_stats[ISP_INTCNT] = isp->isp_intcnt;
        stats.isp_stats[ISP_INTBOGUS] = isp->isp_intbogus;
        stats.isp_stats[ISP_INTMBOXC] = isp->isp_intmboxc;
        stats.isp_stats[ISP_INGOASYNC] = isp->isp_intoasync;
        stats.isp_stats[ISP_RSLTCCMPLT] = isp->isp_rsltccmplt;
        stats.isp_stats[ISP_FPHCCMCPLT] = isp->isp_fphccmplt;
        stats.isp_stats[ISP_RSCCHIWAT] = isp->isp_rscchiwater;
        stats.isp_stats[ISP_FPCCHIWAT] = isp->isp_fpcchiwater;
        ISP_UNLK_SOFTC(isp);
        if (COPYOUT(&stats, (void *)arg, sizeof (stats))) {
            rv = -EFAULT;
        }
        break;
    }
    case ISP_CLR_STATS:
        ISP_LOCK_SOFTC(isp);
        isp->isp_intcnt = 0;
        isp->isp_intbogus = 0;
        isp->isp_intmboxc = 0;
        isp->isp_intoasync = 0;
        isp->isp_rsltccmplt = 0;
        isp->isp_fphccmplt = 0;
        isp->isp_rscchiwater = 0;
        isp->isp_fpcchiwater = 0;
        ISP_UNLK_SOFTC(isp);
        break;

    case ISP_SDBLEV:
        if (COPYIN((void *)arg, &inarg, sizeof (inarg))) {
            rv = -EFAULT;
            break;
        }
        outarg = isp->isp_dblev;
        isp->isp_dblev = inarg;
        if (COPYOUT(&outarg, (void *)arg, sizeof (outarg))) {
            rv = -EFAULT;
            break;
        }
        break;

    case ISP_RESCAN:
        if (IS_FC(isp)) {
            for (i = 0; i < isp->isp_nchan; i++) {
                FCPARAM(isp, i)->isp_loopstate = LOOP_PDB_RCVD;
                isp_thread_event(isp, ISP_THREAD_FC_RESCAN, FCPARAM(isp, i), 0, __func__, __LINE__);
            }
        }
        break;

    case ISP_GETROLE:
        if (COPYIN((void *)arg, &inarg, sizeof (inarg))) {
            rv = -EFAULT;
            break;
        }
        chan = inarg >> 16;
        if (chan >= isp->isp_nchan) {
            rv = -ENXIO;
            break;
        }
        if (IS_FC(isp)) {
            outarg = FCPARAM(isp, chan)->role;
        } else {
            outarg = SDPARAM(isp, chan)->role;
        }
        if (COPYOUT(&outarg, (void *)arg, sizeof (outarg))) {
            rv = -EFAULT;
            break;
        }
        break;
    case ISP_SETROLE:
        if (COPYIN((void *)arg, &inarg, sizeof (inarg))) {
            rv = -EFAULT;
            break;
        }
        chan = inarg >> 16;
        if (chan >= isp->isp_nchan) {
            rv = -ENXIO;
            break;
        }
        inarg &= 0xffff;
        if (inarg & ~(ISP_ROLE_INITIATOR|ISP_ROLE_TARGET)) {
            rv = -EINVAL;
            break;
        }
        /*
         * Check to see if we're already in that role.
         */
        if (IS_FC(isp)) {
            if (FCPARAM(isp, chan)->role == inarg) {
                break;
            }
            outarg = FCPARAM(isp, chan)->role;
            if (COPYOUT(&outarg, (void *)arg, sizeof (outarg))) {
                rv = -EFAULT;
                break;
            }
            FCPARAM(isp, chan)->role = inarg;
            SET_DEFAULT_ROLE(isp, chan, FCPARAM(isp, chan)->role);
        } else {
            if (SDPARAM(isp, chan)->role == inarg) {
                break;
            }
            outarg = SDPARAM(isp, chan)->role;
            if (COPYOUT(&outarg, (void *)arg, sizeof (outarg))) {
                rv = -EFAULT;
                break;
            }
            SDPARAM(isp, chan)->role = inarg;
            SET_DEFAULT_ROLE(isp, chan, SDPARAM(isp, chan)->role);
        }
        break;
    case ISP_RESETHBA:
    {
        ISP_LOCK_SOFTC(isp);
        isp_reset(isp, 0);
        ISP_UNLK_SOFTC(isp);
        break;
    }
    case ISP_FC_LIP:
        if (COPYIN((void *)arg, &chan, sizeof (chan))) {
            chan = 0;
        }
        ISP_LOCK_SOFTC(isp);
        if (isp_control(isp, ISPCTL_SEND_LIP, chan)) {
            rv = -EIO;
        }
        ISP_UNLK_SOFTC(isp);
        break;
    case ISP_FC_GETDINFO:
    {
        struct isp_fc_device local, *ifc = &local;
        fcportdb_t *lp;

        if (IS_SCSI(isp)) {
            rv = -EINVAL;
            break;
        }
        if (COPYIN((void *)arg, ifc, sizeof (*ifc))) {
            rv = -EFAULT;
            break;
        }
        if (ifc->chan >= isp->isp_nchan) {
            rv = -EINVAL;
            break;
        }
        if (ifc->loopid >= MAX_FC_TARG) {
            rv = -EINVAL;
            break;
        }
        ISP_LOCK_SOFTC(isp);
        lp = &FCPARAM(isp, ifc->chan)->portdb[ifc->loopid];
        if (lp->state == FC_PORTDB_STATE_VALID || lp->target_mode) {
            ifc->role = lp->roles;
            ifc->loopid = lp->handle;
            ifc->portid = lp->portid;
            ifc->node_wwn = lp->node_wwn;
            ifc->port_wwn = lp->port_wwn;
        } else {
            rv = -ENODEV;
        }
        ISP_UNLK_SOFTC(isp);
        if (rv == 0) {
            if (COPYOUT((void *)ifc, (void *)arg, sizeof (*ifc))) {
                rv = -EFAULT;
            }
        }
        break;
    }
    case ISP_FC_GETHINFO:
    {
        struct isp_hba_device local, *hba = &local;
        if (COPYIN((void *)arg, hba, sizeof (*hba))) {
            rv = -EFAULT;
            break;
        }
        chan = hba->fc_channel;
        if (chan >= isp->isp_nchan) {
            rv = -EINVAL;
            break;
        }
        ISP_LOCK_SOFTC(isp);
        hba->fc_nchannels = isp->isp_nchan;
        hba->fc_nports = ISP_CAP_2KLOGIN(isp)? 2048 : 256;
        hba->fc_fw_major = ISP_FW_MAJORX(isp->isp_fwrev);
        hba->fc_fw_minor = ISP_FW_MINORX(isp->isp_fwrev);
        hba->fc_fw_micro = ISP_FW_MICROX(isp->isp_fwrev);
        hba->fc_speed = FCPARAM(isp, chan)->isp_gbspeed;
        hba->fc_topology = FCPARAM(isp, chan)->isp_topo + 1;
        hba->fc_loopid = FCPARAM(isp, chan)->isp_loopid;
        hba->nvram_node_wwn = FCPARAM(isp, chan)->isp_wwnn_nvram;
        hba->nvram_port_wwn = FCPARAM(isp, chan)->isp_wwpn_nvram;
        hba->active_node_wwn = FCPARAM(isp, chan)->isp_wwnn;
        hba->active_port_wwn = FCPARAM(isp, chan)->isp_wwpn;
        ISP_UNLK_SOFTC(isp);
        if (COPYOUT(hba, (void *)arg, sizeof (*hba))) {
            rv = -EFAULT;
            break;
        }
        break;
    }
    case ISP_TSK_MGMT:
    {
        int needmarker;
        struct isp_fc_tsk_mgmt local, *fct = (struct isp_fc_tsk_mgmt *) &local;

        if (IS_SCSI(isp)) {
            rv = -EINVAL;
            break;
        }

        if (COPYIN((void *)arg, fct, sizeof (*fct))) {
            rv = -EFAULT;
            break;
        }

        memset(&mbs, 0, sizeof (mbs));
        needmarker = 0;
        loopid = fct->loopid;
        if (ISP_CAP_2KLOGIN(isp) == 0) {
            loopid <<= 8;
        }
        switch (fct->action) {
        case IPT_CLEAR_ACA:
            mbs.param[0] = MBOX_CLEAR_ACA;
            mbs.param[1] = loopid;
            mbs.param[2] = fct->lun;
            break;
        case IPT_TARGET_RESET:
            mbs.param[0] = MBOX_TARGET_RESET;
            mbs.param[1] = loopid;
            needmarker = 1;
            break;
        case IPT_LUN_RESET:
            mbs.param[0] = MBOX_LUN_RESET;
            mbs.param[1] = loopid;
            mbs.param[2] = fct->lun;
            needmarker = 1;
            break;
        case IPT_CLEAR_TASK_SET:
            mbs.param[0] = MBOX_CLEAR_TASK_SET;
            mbs.param[1] = loopid;
            mbs.param[2] = fct->lun;
            needmarker = 1;
            break;
        case IPT_ABORT_TASK_SET:
            mbs.param[0] = MBOX_ABORT_TASK_SET;
            mbs.param[1] = loopid;
            mbs.param[2] = fct->lun;
            needmarker = 1;
            break;
        default:
            rv = -EINVAL;
            break;
        }
        if (rv == 0) {
            mbs.logval = MBLOGALL;
            mbs.timeout = 2000000;
            ISP_LOCKU_SOFTC(isp);
            if (needmarker) {
                ISP_SET_SENDMARKER(isp, 0, 1);
            }
            rv = isp_control(isp, ISPCTL_RUN_MBOXCMD, &mbs);
            ISP_UNLKU_SOFTC(isp);
            if (rv) {
                rv = -EIO;
            }
        }
        break;
    }
    case ISP_FC_GETDLIST:
    {
        isp_dlist_t *ua;
        uint16_t nph, nphe, count, chan, lim;
        struct wwnpair pair, *uptr;

        if (IS_SCSI(isp)) {
            rv = -EINVAL;
            break;
        }

        ua = (isp_dlist_t *)arg;
        uptr = &ua->wwns[0];

        if (COPYIN((void *)&ua->count, &lim, sizeof (lim))) {
            rv = -EFAULT;
            break;
        }

        if (COPYIN((void *)&ua->channel, &chan, sizeof (chan))) {
            rv = -EFAULT;
            break;
        }

        if (ISP_CAP_2KLOGIN(isp)) {
            nphe = NPH_MAX_2K;
        } else {
            nphe = NPH_MAX;
        }
        for (count = 0, nph = 0; count < lim && nph != nphe; nph++) {
            ISP_LOCKU_SOFTC(isp);
            rv = isp_control(isp, ISPCTL_GET_NAMES, chan, nph, &pair.wwnn, &pair.wwpn);
            ISP_UNLKU_SOFTC(isp);
            if (rv || (pair.wwpn == INI_NONE && pair.wwnn == INI_NONE)) {
                rv = 0;
                continue;
            }
            if (COPYOUT(&pair, (void *)uptr++, sizeof (pair))) {
                rv = -EFAULT;
                break;
            }
            count++;
        }
        if (rv == 0) {
            if (COPYOUT(&count, (void *)&ua->count, sizeof (count))) {
                rv = -EFAULT;
            }
        }
        break;
    }
    default:
        rv = -EINVAL;
        break;
    }
    return (rv);
}
/*
 * vim:ts=4:sw=4:expandtab
 */
