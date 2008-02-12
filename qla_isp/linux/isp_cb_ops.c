/* $Id: isp_cb_ops.c,v 1.79 2007/12/11 22:18:05 mjacob Exp $ */
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
 * Qlogic ISP Host Adapter procfs and open/close entry points
 * proc safe pretty print code courtesy of Gerard Roudier (groudier@free.fr)
 */

#include "isp_linux.h"
#include "isp_ioctl.h"
#include "exioct.h"

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
                    ISP_THREAD_EVENT(isp, ISP_THREAD_FC_RESCAN, FCPARAM(isp, io), 1, __FUNCTION__, __LINE__);
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
            isp_reinit(isp);
            ISP_UNLKU_SOFTC(isp);
            io = len;
        } else if (strncmp(buf, "bins", 4) == 0) {
            ISP_LOCKU_SOFTC(isp);
            MEMZERO(isp->isp_osinfo.bins, sizeof (isp->isp_osinfo.bins));
            ISP_UNLKU_SOFTC(isp);
            io = len;
        }
#ifdef  ISP_FW_CRASH_DUMP
        else if (strncmp(buf, "fwcrash", 7) == 0) {
            if (IS_FC(isp)) {
                ISP_LOCKU_SOFTC(isp);
                ISP_THREAD_EVENT(isp, ISP_THREAD_FW_CRASH_DUMP, NULL, 0, __FUNCTION__, __LINE__);
                ISP_UNLKU_SOFTC(isp);
                io = len;
            }
        }
#endif
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
        (unsigned long long) isp->isp_intcnt, (unsigned long long) isp->isp_intbogus, (unsigned long long) isp->isp_intmboxc,
        (unsigned long long) isp->isp_intoasync, (unsigned long long) isp->isp_rsltccmplt, (unsigned long long) isp->isp_fphccmplt,
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
        Scsi_Cmnd *f = isp->isp_osinfo.wqnext;
        copy_info(&info, "WaitQ(%d)", isp->isp_osinfo.wqcnt);
        while (f) {
            copy_info(&info, "->%p", f);
            f = (Scsi_Cmnd *) f->host_scribble;
        }
        copy_info(&info, "\n");
    }
    if (isp->isp_osinfo.dqnext) {
        Scsi_Cmnd *f = isp->isp_osinfo.dqnext;
        copy_info(&info, "DoneQ");
        while (f) {
            copy_info(&info, "->%p", f);
            f = (Scsi_Cmnd *) f->host_scribble;
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
            copy_info(&info,
                "Self Channel %d:\nHandle ID 0x%x PortID 0x%06x FW State 0x%x Loop State 0x%x\n", chan,
                fcp->isp_loopid, fcp->isp_portid, fcp->isp_fwstate, fcp->isp_loopstate);
            copy_info(&info, "Port WWN 0x%016llx Node WWN 0x%016llx\n\n", fcp->isp_wwpn, fcp->isp_wwnn);
            copy_info(&info, "FC devices in port database:\n");
            for (i = 0; i < MAX_FC_TARG; i++) {
                if (fcp->portdb[i].state != FC_PORTDB_STATE_VALID) {
                    continue;
                }
                if (fcp->portdb[i].ini_map_idx) {
                    copy_info(&info, "\tdbidx %d handle 0x%x PortID 0x%06x role %s (target %d)\n\tPort WWN 0x%016llx Node WWN 0x%016llx\n\n",
                        i, fcp->portdb[i].handle, fcp->portdb[i].portid, isp_class3_roles[fcp->portdb[i].roles],
                        fcp->portdb[i].ini_map_idx - 1, fcp->portdb[i].port_wwn, fcp->portdb[i].node_wwn);
                } else {
                    copy_info(&info, "\tdbidx %d handle 0x%x PortID 0x%06x role %s\n\tPort WWN 0x%016llx Node WWN 0x%016llx\n\n",
                        i, fcp->portdb[i].handle, fcp->portdb[i].portid, isp_class3_roles[fcp->portdb[i].roles],
                        fcp->portdb[i].port_wwn, fcp->portdb[i].node_wwn);
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

static int isp_open(struct inode *, struct file *);
static int isp_close(struct inode *, struct file *);
static int isp_ioctl(struct inode *, struct file *, unsigned int, unsigned long);
static int isp_qlogic_ext_ioctl(struct inode *, struct file *, unsigned int, unsigned long);

dev_t isp_dev;
struct cdev isp_cdev = {
    .kobj   =   { .name = ISP_NAME, } ,
    .owner  =   THIS_MODULE
};
ISP_CLASS *isp_class;

struct file_operations isp_ioctl_operations = {
 owner:     THIS_MODULE,
 open:      isp_open,
 release:   isp_close,
 ioctl:     isp_ioctl,
};

struct file_operations hba_api_ioctl_operations = {
 owner:     THIS_MODULE,
 ioctl:     isp_qlogic_ext_ioctl,
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

    if (((c & _IOC_TYPEMASK) >> _IOC_TYPESHIFT) == QLMULTIPATH_MAGIC) {
        return (isp_qlogic_ext_ioctl(ip, fp, c, arg));
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

        MEMZERO(&stats, sizeof stats);
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
#ifdef  ISP_FW_CRASH_DUMP
    case ISP_GET_FW_CRASH_DUMP:
    {
        uint16_t *ptr = fcp->isp_dump_data;
        size_t sz;
        if (IS_2200(isp))
            sz = QLA2200_RISC_IMAGE_DUMP_SIZE;
        else
            sz = QLA2300_RISC_IMAGE_DUMP_SIZE;
        ISP_LOCK_SOFTC(isp);
        if (ptr && *ptr) {
            if (COPYOUT(ptr, (void *)arg, sz)) {
                rv = -EFAULT;
            } else {
                *ptr = 0;
            }
        } else {
            rv = -ENXIO;
        }
        ISP_UNLK_SOFTC(isp);
        break;
    }

    case ISP_FORCE_CRASH_DUMP:
        ISP_LOCK_SOFTC(isp);
        isp_async(isp, ISPASYNC_FW_CRASH, NULL);
        ISP_UNLK_SOFTC(isp);
        break;
#endif
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
            ISP_LOCKU_SOFTC(isp);
            for (i = 0; i < isp->isp_nchan; i++) {
                ISP_THREAD_EVENT(isp, ISP_THREAD_FC_RESCAN, FCPARAM(isp, i), 1, __FUNCTION__, __LINE__);
            }
            ISP_UNLKU_SOFTC(isp);
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
        isp_reset(isp);
        ISP_UNLK_SOFTC(isp);
        break;
    }
    case ISP_FC_LIP:
        ISP_LOCK_SOFTC(isp);
        if (isp_control(isp, ISPCTL_SEND_LIP, 0)) {
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
        if (lp->state == FC_PORTDB_STATE_VALID) {
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

        MEMZERO(&mbs, sizeof (mbs));
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
 * SDMI Routines
 */

static int isp_exti_query(EXT_IOCTL *);
static int isp_exti_setinstance(EXT_IOCTL *);
static int isp_exti_fcct_passthru(EXT_IOCTL *);
static int isp_exti_discover_luns(ispsoftc_t *, int, UINT64, UINT64, UINT16 *);
static void *isp_exti_usrptr(UINT64, UINT16);
static int isp_exti_passthru(EXT_IOCTL *);
static int isp_run_cmd(ispsoftc_t *, isp_xcmd_t *);

int
isp_qlogic_ext_ioctl(struct inode *ip, struct file *fp, unsigned int cmd, unsigned long arg)
{
    EXT_IOCTL ext;
    EXT_IOCTL *uext = (EXT_IOCTL *) arg;
    int rval;

    rval = 0;

    if (COPYIN(uext, &ext, sizeof (ext))) {
        ext.Status = EXT_STATUS_COPY_ERR;
        ext.DetailStatus = 0;
        goto out;
    }

    ext.DetailStatus = EXT_STATUS_OK;
    ext.Status = EXT_STATUS_OK;

    /*
     * Make sure this is a supported command.
     */
    switch (cmd) {
    case EXT_CC_GET_HBA_CNT:
    case EXT_CC_SETINSTANCE:
    case EXT_CC_QUERY:
    case EXT_SC_QUERY_CHIP:
    case EXT_CC_SEND_FCCT_PASSTHRU:
    case EXT_CC_SEND_SCSI_PASSTHRU:
        break;
    default:
        ext.Status = EXT_STATUS_INVALID_REQUEST;
        ext.DetailStatus = 0;
        break;
    }
    if (ext.Status != EXT_STATUS_OK) {
        goto out;
    }

    if (memcmp(&ext.Signature, EXT_DEF_REGULAR_SIGNATURE, strlen(EXT_DEF_REGULAR_SIGNATURE)) != 0) {
        printk("%s: bad signature\n", __FUNCTION__);
        ext.Status = EXT_STATUS_INVALID_PARAM;
        goto out;
    }

    if (ext.Version != EXT_VERSION) {
        printk("%s: bad version %d\n", __FUNCTION__, ext.Version);
        ext.Status = EXT_STATUS_UNSUPPORTED_VERSION;
        goto out;
    }
    /*
     * We only count FC adapters.
     */
    if (cmd == EXT_CC_GET_HBA_CNT) {
        unsigned int i;

        ext.Instance = 0;
        for(i = 0; i < MAX_ISP; i++) {
            if (isplist[i] && IS_FC(isplist[i])) {
                ext.Instance++;
            }
        }
        if (COPYOUT(&ext.Instance, &uext->Instance, sizeof (uext->Instance))) {
            ext.Status = EXT_STATUS_COPY_ERR;
        } else {
            ext.Status = EXT_STATUS_OK;
        }
    } else if (cmd == EXT_CC_SETINSTANCE) {
        rval = isp_exti_setinstance(&ext);
        if (rval) {
            goto out;
        }
        if (COPYOUT(&ext.HbaSelect, &uext->HbaSelect, sizeof (uext->HbaSelect))) {
            ext.Status = EXT_STATUS_COPY_ERR;
        } else {
            ext.Status = EXT_STATUS_OK;
        }
    } else if (cmd == EXT_CC_QUERY) {
        rval = isp_exti_query(&ext);
    } else if (cmd == EXT_CC_SEND_FCCT_PASSTHRU) {
        rval = isp_exti_fcct_passthru(&ext);
    } else if (cmd == EXT_CC_SEND_SCSI_PASSTHRU) {
        rval = isp_exti_passthru(&ext);
    } else {
        ext.Status = EXT_STATUS_INVALID_REQUEST;
    }

out:
    if (COPYOUT(&ext.Status, &uext->Status, sizeof (ext.Status))) {
        rval = -EFAULT;
    } else if (COPYOUT(&ext.DetailStatus, &uext->DetailStatus, sizeof (ext.Status))) {
        rval = -EFAULT;
    }
    return (rval);
}

static int
isp_exti_setinstance(EXT_IOCTL *ext)
{
    unsigned int inst, index;

    for (inst = index = 0; index < MAX_ISP; index++) {
        if (isplist[index] && IS_FC(isplist[index])) {
            if (inst++ == ext->Instance) {
                break;
            }
        }
    }
    if (index >= MAX_ISP) {
        ext->Status = EXT_STATUS_DEV_NOT_FOUND;
        return (-ENXIO);
    }
    api_isp = isplist[index];
    ext->HbaSelect = api_isp->isp_unit;
    api_channel = 0;    /* XXXXXXXXXXXXXXXXXXXXXXX */
    return (0);
}
    
static int
isp_exti_query(EXT_IOCTL *pext)
{
    ispsoftc_t *isp = api_isp;
    int cl, i, rval = 0;
    void *outaddr;
    fcparam *fcp;
    fcportdb_t *lp;
    unsigned long flags;

    if (isp == NULL) {
        pext->Status = EXT_STATUS_DEV_NOT_FOUND;
        return (0);
    }
    ISP_LOCKU_SOFTC(isp);
    fcp = FCPARAM(isp, api_channel);
    if (fcp->isp_fwstate != FW_READY || fcp->isp_loopstate < LOOP_LSCAN_DONE) {
        if (isp_fc_runstate(isp, api_channel, 1000000) < 0) {
            ISP_UNLKU_SOFTC(isp);
            pext->Status = EXT_STATUS_PENDING;
            return (0);
        }
    }

    outaddr = isp_exti_usrptr(pext->ResponseAdr, pext->AddrMode);

    switch (pext->SubCode) {
    case EXT_SC_QUERY_HBA_NODE:
    {
        EXT_HBA_NODE hba;

        MEMZERO(&hba, sizeof (hba));
        MAKE_NODE_NAME_FROM_WWN(hba.WWNN, fcp->isp_wwnn_nvram);
        MEMCPY(hba.SerialNum, &hba.WWNN[5], 3);
        SNPRINTF((char *)hba.DriverVersion, EXT_DEF_MAX_STR_SIZE, "Linux Version %d.%d; Common Core Code Version %d.%d",
            ISP_PLATFORM_VERSION_MAJOR, ISP_PLATFORM_VERSION_MINOR,
            ISP_CORE_VERSION_MAJOR, ISP_CORE_VERSION_MINOR);
        SNPRINTF((char *)hba.FWVersion, EXT_DEF_MAX_STR_SIZE, "%02d.%02d.%02d", isp->isp_fwrev[0], isp->isp_fwrev[1], isp->isp_fwrev[2]);
        hba.OptRomVersion[0] = '0';
        hba.PortCount = 1;
        hba.InterfaceType = EXT_DEF_FC_INTF_TYPE;
        ISP_UNLKU_SOFTC(isp);
        cl = min(pext->ResponseLen, sizeof (hba));
        if (COPYOUT(&hba, outaddr, cl)) {
            pext->Status = EXT_STATUS_COPY_ERR;
            rval = -EFAULT;
        }
        break;
    }
    case EXT_SC_QUERY_HBA_PORT:
    {
        EXT_HBA_PORT hbp;

        MEMZERO(&hbp, sizeof (hbp));
        MAKE_NODE_NAME_FROM_WWN(hbp.WWPN, FCPARAM(isp, 0)->isp_wwpn);
        hbp.Id[1] = (fcp->isp_portid >> 16)  & 0xff;
        hbp.Id[2] = (fcp->isp_portid >> 8) & 0xff;
        hbp.Id[3] = fcp->isp_portid & 0xff;

        if (FCPARAM(isp, 0)->role & ISP_ROLE_TARGET) {
            hbp.Type |= EXT_DEF_TARGET_DEV;
        }

        if (FCPARAM(isp, 0)->role & ISP_ROLE_INITIATOR) {
            hbp.Type |= EXT_DEF_INITIATOR_DEV;
        }

        hbp.State = EXT_DEF_HBA_OK;

        if (fcp->isp_topo == TOPO_NL_PORT || fcp->isp_topo == TOPO_FL_PORT) {
            hbp.Mode = EXT_DEF_LOOP_MODE;
        } else {
            hbp.Mode = EXT_DEF_P2P_MODE;
        }
            hbp.Type |= EXT_DEF_FABRIC_DEV;

        /*
         * Count devices in our port database.
         */
        for (i = 0; i < MAX_FC_TARG; i++) {
            lp = &fcp->portdb[i];
            if (lp->state != FC_PORTDB_STATE_VALID) {
                continue;
            }
            if (lp->portid == fcp->isp_portid) {
                continue;
            }
            hbp.DiscPortCount++;
            if (lp->roles & (SVC3_TGT_ROLE >> SVC3_ROLE_SHIFT)) {
                hbp.DiscTargetCount++;
            }
        }
        ISP_UNLKU_SOFTC(isp);
        hbp.DiscPortNameType = EXT_DEF_USE_PORT_NAME;
        hbp.PortSupportedFC4Types = EXT_DEF_FC4_TYPE_SCSI;
        hbp.PortActiveFC4Types = EXT_DEF_FC4_TYPE_SCSI;
        hbp.PortSupportedSpeed = EXT_DEF_PORTSPEED_1GBIT;
        if (IS_23XX(isp)) {
            hbp.PortSupportedSpeed |= EXT_DEF_PORTSPEED_2GBIT;
        } else if (IS_24XX(isp)) {
            hbp.PortSupportedSpeed |= EXT_DEF_PORTSPEED_2GBIT|EXT_DEF_PORTSPEED_4GBIT;
        }
        cl = min(pext->ResponseLen, sizeof (hbp));
        if (COPYOUT(&hbp, outaddr, cl)) {
            pext->Status = EXT_STATUS_COPY_ERR;
            rval = -EFAULT;
        }
        break;
    }
    case EXT_SC_QUERY_DISC_PORT:
    {
        EXT_DISC_PORT port;
        fcportdb_t *rlp;
        int inst;

        MEMZERO(&port, sizeof (port));
        rlp = NULL;
        for (inst = i = 0; rlp == NULL && i < MAX_FC_TARG; i++) {
            lp = &fcp->portdb[i];
            if (lp->state != FC_PORTDB_STATE_VALID) {
                continue;
            }
            if (lp->portid == fcp->isp_portid) {
                continue;
            }
            if (inst != pext->Instance) {
                inst++;
                continue;
            }
            rlp = lp;
        }
        if (rlp == NULL) {
            ISP_UNLKU_SOFTC(isp);
            pext->Status = EXT_STATUS_DEV_NOT_FOUND;
            break;
        }
        MAKE_NODE_NAME_FROM_WWN(port.WWPN, rlp->port_wwn);
        MAKE_NODE_NAME_FROM_WWN(port.WWNN, rlp->node_wwn);
        port.Id[1] = (rlp->portid >> 16)  & 0xff;
        port.Id[2] = (rlp->portid >> 8) & 0xff;
        port.Id[3] = rlp->portid & 0xff;
        if (fcp->isp_topo == TOPO_F_PORT || fcp->isp_topo == TOPO_FL_PORT) {
            port.Type = EXT_DEF_FABRIC_DEV;
        } else {
            port.Type = 0;
        }
        if (rlp->roles & (SVC3_TGT_ROLE >> SVC3_ROLE_SHIFT)) {
            port.Type |= EXT_DEF_TARGET_DEV;
        }
        if (rlp->roles & (SVC3_INI_ROLE >> SVC3_ROLE_SHIFT)) {
            port.Type |= EXT_DEF_INITIATOR_DEV;
        }
        port.Status = EXT_DEF_HBA_OK;
        port.Bus = isp->isp_host->host_no;
        if (rlp->ini_map_idx) {
            port.TargetId = rlp->ini_map_idx - 1;
        } else {
            port.TargetId = 0;
        }
        ISP_UNLKU_SOFTC(isp);
        cl = min(pext->ResponseLen, sizeof (port));
        if (COPYOUT(&port, outaddr, cl)) {
            pext->Status = EXT_STATUS_COPY_ERR;
            rval = -EFAULT;
        }
        break;
    }
    case EXT_SC_QUERY_DISC_TGT:
    {
        EXT_DISC_TARGET tgt;
        fcportdb_t *rlp;
        UINT64 wwpn, wwnn;
        int inst;

        MEMZERO(&tgt, sizeof (tgt));
        rlp = NULL;
        for (inst = i = 0; rlp == NULL && i < MAX_FC_TARG; i++) {
            lp = &fcp->portdb[i];
            if (lp->state != FC_PORTDB_STATE_VALID) {
                continue;
            }
            if (lp->portid == fcp->isp_portid) {
                continue;
            }
            if ((lp->roles & (SVC3_TGT_ROLE >> SVC3_ROLE_SHIFT)) == 0) {
                continue;
            }
            if (inst != pext->Instance) {
                inst++;
                continue;
            }
            rlp = lp;
        }
        if (rlp == NULL) {
            ISP_UNLKU_SOFTC(isp);
            pext->Status = EXT_STATUS_DEV_NOT_FOUND;
            break;
        }
        MAKE_NODE_NAME_FROM_WWN(tgt.WWPN, rlp->port_wwn);
        MAKE_NODE_NAME_FROM_WWN(tgt.WWNN, rlp->node_wwn);
        tgt.Id[1] = (rlp->portid >> 16)  & 0xff;
        tgt.Id[2] = (rlp->portid >> 8) & 0xff;
        tgt.Id[3] = rlp->portid & 0xff;
        if (fcp->isp_topo == TOPO_F_PORT || fcp->isp_topo == TOPO_FL_PORT) {
            tgt.Type = EXT_DEF_FABRIC_DEV;
        } else {
            tgt.Type = 0;
        }
        if (rlp->roles & (SVC3_TGT_ROLE >> SVC3_ROLE_SHIFT)) {
            tgt.Type |= EXT_DEF_TARGET_DEV;
        }
        if (rlp->roles & (SVC3_INI_ROLE >> SVC3_ROLE_SHIFT)) {
            tgt.Type |= EXT_DEF_INITIATOR_DEV;
        }
        tgt.Status = EXT_DEF_HBA_OK;
        tgt.Bus = isp->isp_host->host_no;
        if (rlp->ini_map_idx) {
            tgt.TargetId = rlp->ini_map_idx - 1;
        } else {
            tgt.TargetId = 0;
        }
        wwpn = rlp->port_wwn;
        wwnn = rlp->node_wwn;
        ISP_UNLKU_SOFTC(isp);
        rval = isp_exti_discover_luns(isp, api_channel, wwpn, wwnn, &tgt.LunCount);
        if (rval) {
            break;
        }
        cl = min(pext->ResponseLen, sizeof (tgt));
        if (COPYOUT(&tgt, outaddr, cl)) {
            pext->Status = EXT_STATUS_COPY_ERR;
            rval = -EFAULT;
        }
        break;
    }
    case EXT_SC_QUERY_CHIP:
    {
        EXT_CHIP xc;
        struct pci_dev *pdev = isp->isp_osinfo.device;

        MEMZERO(&xc, sizeof (xc));
        xc.VendorId = pdev->vendor;
        xc.DeviceId = pdev->device;
        xc.SubVendorId = pdev->subsystem_vendor;
        xc.SubSystemId = pdev->subsystem_device;
        xc.PciBusNumber = pdev->bus->number;
        xc.PciDevFunc = pdev->devfn;
        xc.PciSlotNumber = PCI_SLOT(pdev->devfn);
        xc.DomainNr = pci_domain_nr(pdev->bus);
        xc.InterruptLevel = pdev->irq;
        cl = min(pext->ResponseLen, sizeof (xc));
        if (COPYOUT(&xc, outaddr, cl)) {
            pext->Status = EXT_STATUS_COPY_ERR;
            rval = -EFAULT;
        }
        break;
    }
    case EXT_SC_QUERY_DISC_LUN:
    default:
        ISP_UNLKU_SOFTC(isp);
        pext->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
        break;
    }
    return (rval);
}


#define IGPOFF  0                                   /* place CT Request itself is put */
#define OGPOFF  (ISP_FC_SCRLEN >> 1)                /* place CT Response itself is put */
#define ZTXOFF  (ISP_FC_SCRLEN - (1 * QENTRY_LEN))  /* place where status entry for CT passthru request ends up */
#define CTXOFF  (ISP_FC_SCRLEN - (2 * QENTRY_LEN))  /* place where CT passthru request is put */

static int
isp_exti_fcct_passthru(EXT_IOCTL *pext)
{
    ispsoftc_t *isp = api_isp;
    isp_plcmd_t p;
    fcparam *fcp = FCPARAM(isp, 0);
    mbreg_t mbs;
    uint8_t qe[QENTRY_LEN], *scp;
    uint16_t handle;
    unsigned long flags;
    void *localmem = NULL;
    size_t localamt;
    int r;
    int rval = 0;

    if (isp == NULL) {
        pext->Status = EXT_STATUS_DEV_NOT_FOUND;
        return (0);
    }

    if (pext->RequestLen > (ISP_FC_SCRLEN >> 1)) {
        pext->Status = EXT_STATUS_NO_MEMORY;
        return (0);
    }
    if (pext->ResponseLen > ((ISP_FC_SCRLEN >> 1) - (2 * QENTRY_LEN))) {
        pext->Status = EXT_STATUS_NO_MEMORY;
        return (0);
    }

    localamt = pext->RequestLen;
    if (pext->ResponseLen > localamt) {
        localamt = pext->ResponseLen;
    }
    localmem = isp_kalloc(localamt, GFP_KERNEL);
    if (localmem == NULL) {
        pext->Status = EXT_STATUS_NO_MEMORY;
        return (0);
    }
    pext->Status = EXT_STATUS_OK;
    if (COPYIN(isp_exti_usrptr(pext->RequestAdr, pext->AddrMode), localmem, pext->RequestLen)) {
        pext->Status = EXT_STATUS_COPY_ERR;
        rval = -EFAULT;
        goto out;
    }

    /*
     * First- check to see if topology is right and things are right otherwise.
     */
    ISP_LOCKU_SOFTC(isp);
    if (fcp->isp_topo != TOPO_F_PORT && fcp->isp_topo != TOPO_FL_PORT) {
        ISP_UNLKU_SOFTC(isp);
        pext->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
        goto out;
    }

    /*
     * Login into the Management Server
     */
    p.channel = api_channel;
    p.handle = NIL_HANDLE;
    p.portid = MANAGEMENT_PORT_ID;
    p.flags = PLOGX_FLG_CMD_PLOGI;
    r = isp_control(isp, ISPCTL_PLOGX, &p);
    if (r) {
        ISP_UNLKU_SOFTC(isp);
        isp_prt(isp, ISP_LOGWARN, "failed to log into management server (0x%x)", r);
        pext->Status = EXT_STATUS_MS_NO_RESPONSE;
        goto out;
    }
    handle = p.handle;

    /*
     * Acquire Scratch
     */
    MEMZERO(qe, QENTRY_LEN);
    FC_SCRATCH_ACQUIRE(isp, 0);
    scp = fcp->isp_scratch;

    MEMCPY(&scp[IGPOFF], localmem, pext->RequestLen);
    MEMORYBARRIER(isp, SYNC_SFORDEV, IGPOFF, pext->RequestLen);

    /*
     * Build command we're going to use
     */
    if (IS_24XX(isp)) {
        isp_ct_pt_t *pt;

        /*
         * Build a Passthrough IOCB in memory.
         */
        pt = (isp_ct_pt_t *)qe;
        pt->ctp_header.rqs_entry_count = 1;
        pt->ctp_header.rqs_entry_type = RQSTYPE_CT_PASSTHRU;
        pt->ctp_handle = 0xffffffff;
        pt->ctp_nphdl = handle;
        pt->ctp_cmd_cnt = 1;
        pt->ctp_time = 5;
        pt->ctp_rsp_cnt = 1;
        pt->ctp_rsp_bcnt = pext->ResponseLen;
        pt->ctp_cmd_bcnt = pext->RequestLen;
        pt->ctp_dataseg[0].ds_base = DMA_LO32(fcp->isp_scdma+IGPOFF);
        pt->ctp_dataseg[0].ds_basehi = DMA_HI32(fcp->isp_scdma+IGPOFF);
        pt->ctp_dataseg[0].ds_count = pext->RequestLen;
        pt->ctp_dataseg[1].ds_base = DMA_LO32(fcp->isp_scdma+OGPOFF);
        pt->ctp_dataseg[1].ds_basehi = DMA_HI32(fcp->isp_scdma+OGPOFF);
        pt->ctp_dataseg[1].ds_count = pext->ResponseLen;
        isp_put_ct_pt(isp, pt, (isp_ct_pt_t *) &scp[CTXOFF]);

        /*
         * Build a EXEC IOCB A64 command that points to the CT passthru command
         */
        MEMZERO(&mbs, sizeof (mbs));
        mbs.param[0] = MBOX_EXEC_COMMAND_IOCB_A64;
        mbs.param[1] = QENTRY_LEN;
        mbs.param[2] = DMA_WD1(fcp->isp_scdma + CTXOFF);
        mbs.param[3] = DMA_WD0(fcp->isp_scdma + CTXOFF);
        mbs.param[6] = DMA_WD3(fcp->isp_scdma + CTXOFF);
        mbs.param[7] = DMA_WD2(fcp->isp_scdma + CTXOFF);
        mbs.logval = MBLOGALL;
        MEMORYBARRIER(isp, SYNC_SFORDEV, CTXOFF, 2 * QENTRY_LEN);
        isp_control(isp, ISPCTL_RUN_MBOXCMD, &mbs);
        if (mbs.param[0] != MBOX_COMMAND_COMPLETE) {
            pext->Status = EXT_STATUS_ERR;
            goto out1;
        }
        MEMORYBARRIER(isp, SYNC_SFORCPU, ZTXOFF, QENTRY_LEN);
        pt = (isp_ct_pt_t *)qe;
        isp_get_ct_pt(isp, (isp_ct_pt_t *) &scp[ZTXOFF], pt);
        /*
         * Let the user application parse any errors
         */
    } else {
        isp_ms_t *ms;
        /*
         * Build a Passthrough IOCB in memory.
         */
        ms = (isp_ms_t *)qe;
        ms->ms_header.rqs_entry_count = 1;
        ms->ms_header.rqs_entry_type = RQSTYPE_MS_PASSTHRU;
        ms->ms_handle = 0xffffffff;
        if (ISP_CAP_2KLOGIN(isp)) {
            ms->ms_nphdl = handle;
        } else {
            ms->ms_nphdl = handle << 8;
        }
        ms->ms_cmd_cnt = 1;
        ms->ms_time = 5;
        ms->ms_tot_cnt = 2;
        ms->ms_rsp_bcnt = pext->ResponseLen;
        ms->ms_cmd_bcnt = pext->RequestLen;
        ms->ms_dataseg[0].ds_base = DMA_LO32(fcp->isp_scdma+IGPOFF);
        ms->ms_dataseg[0].ds_basehi = DMA_HI32(fcp->isp_scdma+IGPOFF);
        ms->ms_dataseg[0].ds_count = pext->RequestLen;
        ms->ms_dataseg[1].ds_base = DMA_LO32(fcp->isp_scdma+OGPOFF);
        ms->ms_dataseg[1].ds_basehi = DMA_HI32(fcp->isp_scdma+OGPOFF);
        ms->ms_dataseg[1].ds_count = pext->ResponseLen;
        isp_put_ms(isp, ms, (isp_ms_t *) &scp[CTXOFF]);

        /*
         * Build a EXEC IOCB A64 command that points to the MS passthru command
         */
        MEMZERO(&mbs, sizeof (mbs));
        mbs.param[0] = MBOX_EXEC_COMMAND_IOCB_A64;
        mbs.param[1] = QENTRY_LEN;
        mbs.param[2] = DMA_WD1(fcp->isp_scdma + CTXOFF);
        mbs.param[3] = DMA_WD0(fcp->isp_scdma + CTXOFF);
        mbs.param[6] = DMA_WD3(fcp->isp_scdma + CTXOFF);
        mbs.param[7] = DMA_WD2(fcp->isp_scdma + CTXOFF);
        mbs.logval = MBLOGALL;
        MEMORYBARRIER(isp, SYNC_SFORDEV, CTXOFF, 2 * QENTRY_LEN);
        isp_control(isp, ISPCTL_RUN_MBOXCMD, &mbs);
        if (mbs.param[0] != MBOX_COMMAND_COMPLETE) {
            pext->Status = EXT_STATUS_ERR;
            goto out1;
        }
        MEMORYBARRIER(isp, SYNC_SFORCPU, ZTXOFF, QENTRY_LEN);
        ms = (isp_ms_t *)qe;
        isp_get_ms(isp, (isp_ms_t *) &scp[ZTXOFF], ms);
    }

    MEMORYBARRIER(isp, SYNC_SFORCPU, OGPOFF, pext->ResponseLen);
    MEMCPY(localmem, &scp[OGPOFF], pext->ResponseLen);

out1:

    /*
     * Release Scratch
     */
    FC_SCRATCH_RELEASE(isp, 0);

    /*
     * Log out of the Management Server
     */
    p.channel = api_channel;
    p.handle = handle;
    p.portid = MANAGEMENT_PORT_ID;
    p.flags = PLOGX_FLG_CMD_LOGO|PLOGX_FLG_EXPLICIT_LOGO;
    r = isp_control(isp, ISPCTL_PLOGX, &p);
    if (r) {
        isp_prt(isp, ISP_LOGWARN, "failed to log out of management server (0x%x)", r);
    }
    ISP_UNLKU_SOFTC(isp);

    /*
     * Copy data
     */
out:
    if (rval == 0) {
        if (COPYOUT(localmem, isp_exti_usrptr(pext->ResponseAdr, pext->AddrMode), pext->ResponseLen)) {
            pext->Status = EXT_STATUS_COPY_ERR;
            rval = -EFAULT;
        }
    }
    if (localmem) {
        isp_kfree(localmem, localamt);
    }
    return (rval);
}

static void *
isp_exti_usrptr(UINT64 uaddr, UINT16 mode)
{
    void *ptr = NULL;

#if BITS_PER_LONG == 32
    if (mode == EXT_DEF_ADDR_MODE_32) {
        UINT32 xaddr = uaddr & 0xffffffff;
        ptr = (void *) xaddr;
    }
#elif   BITS_PER_LONG == 64
    ptr = (void *) uaddr;
#endif
    return (ptr);
}

static int
isp_exti_passthru(EXT_IOCTL *pext)
{
    ispsoftc_t *isp = api_isp;
    char *bufp;
    fcportdb_t *lp;
    EXT_FC_SCSI_PASSTHRU fcx;
    uint64_t wwnn = 0LL;
    uint64_t wwpn = 0LL;
    uint32_t portid = (uint32_t) -1;
    isp_xcmd_t cmd;
    int status;
    size_t cpyamt;
    unsigned long flags;

    if (isp == NULL) {
        pext->Status = EXT_STATUS_DEV_NOT_FOUND;
        return (0);
    }
    if (COPYIN(isp_exti_usrptr(pext->RequestAdr, pext->AddrMode), &fcx, sizeof (fcx))) {
        pext->Status = EXT_STATUS_COPY_ERR;
        return (0);
    }

    if (fcx.FCScsiAddr.DestType == EXT_DEF_DESTTYPE_SCSI || fcx.FCScsiAddr.DestType == EXT_DEF_DESTTYPE_FABRIC) {
        pext->Status = EXT_STATUS_INVALID_REQUEST;
        return (0);
    }

    if (isp == NULL) {
        pext->Status = EXT_STATUS_DEV_NOT_FOUND;
        return (0);
    }

    switch (pext->SubCode) {
    case EXT_SC_SEND_FC_SCSI_PASSTHRU:
        break;
    case EXT_SC_SEND_SCSI_PASSTHRU:
    case EXT_SC_SCSI3_PASSTHRU:
    default:
        pext->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
        return (0);
    }

    MEMZERO(&cmd, sizeof (cmd));

    if (pext->ResponseLen) {
        bufp = isp_kalloc(pext->ResponseLen, GFP_KERNEL);
        if (bufp == NULL) {
            pext->Status = EXT_STATUS_NO_MEMORY;
            return (0);
        }
        if (fcx.Direction == EXT_DEF_SCSI_PASSTHRU_DATA_OUT) {
            if (COPYIN(isp_exti_usrptr(pext->ResponseAdr, pext->AddrMode), bufp, pext->ResponseLen)) {
                isp_kfree(bufp, pext->ResponseLen);
                pext->Status = EXT_STATUS_COPY_ERR;
                return (0);
            }
        } else {
            cmd.fcd.beg.do_read = 1;
        }
        cmd.fcd.beg.data_length = pext->ResponseLen;
        cmd.fcd.beg.data_ptr = bufp;
    } else {
        bufp = NULL;
    }

    if (fcx.FCScsiAddr.DestType == EXT_DEF_DESTTYPE_WWNN) {
        MAKE_WWN_FROM_NODE_NAME(wwnn, fcx.FCScsiAddr.DestAddr.WWNN);
    } else if (fcx.FCScsiAddr.DestType == EXT_DEF_DESTTYPE_WWPN) {
        MAKE_WWN_FROM_NODE_NAME(wwpn, fcx.FCScsiAddr.DestAddr.WWPN);
    } else if (fcx.FCScsiAddr.DestType == EXT_DEF_DESTTYPE_PORTID) {
        portid = (fcx.FCScsiAddr.DestAddr.Id[1] << 16) | (fcx.FCScsiAddr.DestAddr.Id[2] << 8) | (fcx.FCScsiAddr.DestAddr.Id[3]);
    }
    /*
     * Make sure we have an entry for this device (handle, portid)
     * so we know how to send the command.
     */
    ISP_LOCKU_SOFTC(isp);
    for (lp = &FCPARAM(isp, api_channel)->portdb[0]; lp < &FCPARAM(isp, api_channel)->portdb[MAX_FC_TARG]; lp++) {
        if (lp->state != FC_PORTDB_STATE_VALID) {
            continue;
        }
        if (fcx.FCScsiAddr.DestType == EXT_DEF_DESTTYPE_WWNN) {
            if (lp->node_wwn == wwnn) {
                break;
            }
        } else if (fcx.FCScsiAddr.DestType == EXT_DEF_DESTTYPE_WWPN) {
            if (lp->port_wwn == wwpn) {
                break;
            }
        } else if (fcx.FCScsiAddr.DestType == EXT_DEF_DESTTYPE_PORTID) {
            if (lp->portid == portid) {
                break;
            }
        }
    }
    if (lp == &FCPARAM(isp, api_channel)->portdb[MAX_FC_TARG]) {
        ISP_UNLKU_SOFTC(isp);
        pext->Status = EXT_STATUS_DEV_NOT_FOUND;
        if (bufp) {
            isp_kfree(bufp, pext->ResponseLen);
        }
        return (0);
    }
    wwnn = lp->node_wwn;
    wwpn = lp->port_wwn;
    cmd.handle = lp->handle;
    cmd.portid = lp->portid;
    cmd.channel = api_channel;
    ISP_UNLKU_SOFTC(isp);

    MEMCPY(cmd.fcd.beg.cdb, fcx.Cdb, min(EXT_DEF_SCSI_PASSTHRU_CDB_LENGTH, sizeof (cmd.fcd.beg.cdb)));
    cmd.lun = fcx.FCScsiAddr.Lun;
    cmd.timeout = fcx.Timeout;
    cpyamt = 0;
    pext->Status = EXT_STATUS_OK;

    status = isp_run_cmd(isp, &cmd);
    if (status == 0) {
        cpyamt = pext->ResponseLen - cmd.fcd.end.data_residual;
        if (cmd.fcd.end.status == SCSI_CHECK && cmd.fcd.end.sense_length) {
            fcx.SenseLength = min(cmd.fcd.end.sense_length, sizeof (fcx.SenseData));
            MEMCPY(fcx.SenseData, cmd.fcd.end.sense_data, fcx.SenseLength);
        }
        if ((pext->DetailStatus = cmd.fcd.end.status) != SCSI_GOOD) {
            pext->Status = EXT_STATUS_SCSI_STATUS;
        } else if (cpyamt != pext->ResponseLen) {
            pext->Status = EXT_STATUS_DATA_UNDERRUN;
        }
    } else {
        cpyamt = 0;
        pext->Status = EXT_STATUS_ERR;
    }

    if (bufp && fcx.Direction == EXT_DEF_SCSI_PASSTHRU_DATA_IN && cpyamt) {
        if (cpyamt) {
            if (COPYOUT(bufp, isp_exti_usrptr(pext->ResponseAdr, pext->AddrMode), cpyamt)) {
                pext->Status = EXT_STATUS_COPY_ERR;
            }
        }
    }
    if (bufp) {
        isp_kfree(bufp, pext->ResponseLen);
    }
    return (0);
}

#define RPT_LUN_SIZE    1024

static int
isp_exti_discover_luns(ispsoftc_t *isp, int chan, UINT64 wwpn, UINT64 wwnn, UINT16 *nluns)
{
    isp_xcmd_t cmd;
    int status, nent, i, hilun;
    unsigned long flags;
    fcparam *fcp = FCPARAM(isp, chan);
    fcportdb_t *lp;
    uint8_t *bufp;

    MEMZERO(&cmd, sizeof (isp_xcmd_t));
    ISP_LOCKU_SOFTC(isp);
    for (lp = &fcp->portdb[0]; lp < &fcp->portdb[MAX_FC_TARG]; lp++) {
        if (lp->state != FC_PORTDB_STATE_VALID) {
            continue;
        }
        if (lp->port_wwn == wwpn && lp->node_wwn == wwnn) {
            break;
        }
    }
    if (lp == &fcp->portdb[MAX_FC_TARG]) {
        ISP_UNLKU_SOFTC(isp);
        return (-ENODEV);
    }
    if ((lp->roles & (SVC3_TGT_ROLE >> SVC3_ROLE_SHIFT)) == 0) {
        ISP_UNLKU_SOFTC(isp);
        *nluns = 0;
        return (0);
    }
    cmd.handle = lp->handle;
    cmd.portid = lp->portid;
    ISP_UNLKU_SOFTC(isp);
    bufp = isp_kzalloc(RPT_LUN_SIZE, GFP_KERNEL);
    if (bufp == NULL) {
        return (-ENOMEM);
    }
    cmd.fcd.beg.data_ptr = bufp;
    cmd.fcd.beg.data_length = RPT_LUN_SIZE;
    cmd.fcd.beg.do_read = 1;
    cmd.fcd.beg.cdb[0] = REPORT_LUNS;
    cmd.fcd.beg.cdb[4] = (RPT_LUN_SIZE >> 24) & 0xff;
    cmd.fcd.beg.cdb[5] = (RPT_LUN_SIZE >> 16) & 0xff;
    cmd.fcd.beg.cdb[6] = (RPT_LUN_SIZE >>  8) & 0xff;
    cmd.fcd.beg.cdb[7] = (RPT_LUN_SIZE) & 0xff;
    cmd.timeout = 30;
    status = isp_run_cmd(isp, &cmd);
    if (status) {
        isp_prt(isp, ISP_LOGWARN, "isp_exti_discover_luns: isp_run_cmd returned %d", status);
        isp_kfree(bufp, RPT_LUN_SIZE);
        return (-EIO);
    }
    nent = (bufp[2] << 8) | bufp[3];


    hilun = 0;
    /*
     * This is not *quite* the right way to do this.
     */
    for (i = 0; i < nent; i++) {
        uint8_t *lunptr = bufp + 8 + (8 * i);
        uint16_t lun;
        lun = lunptr[1];
        if (lunptr[0] & 0x40) {
            lun |= ((lunptr[1] & 0x1f) << 8);
        }
        if (hilun < lun) {
            hilun = lun;
        }
    }
    isp_kfree(bufp, RPT_LUN_SIZE);
    *nluns = hilun + 1;
    return (0);
}

static void
isp_run_cmd_done(struct scsi_cmnd *Cmnd)
{
    struct semaphore *semap = (struct semaphore *) Cmnd->request_buffer;
    up(semap);
}

static int
isp_run_cmd(ispsoftc_t *isp, isp_xcmd_t *cmd)
{
    struct scsi_device *dev = NULL;
    Scsi_Cmnd *Cmnd = NULL;
    struct Scsi_Host *host = NULL;
    uint32_t nxti, optr, handle;
    uint8_t local[QENTRY_LEN];
    ispreq_t *reqp;
    int time, result = 0;
    DECLARE_MUTEX_LOCKED(rsem);
    unsigned long flags;

    time = cmd->timeout / 1000;
    if (time == 0 && cmd->timeout) {
        time = 1;
    }
    if (IS_24XX(isp) && time > 0x1999) {
        time = 0x1999;
    }
    MEMZERO(local, sizeof (local));
    Cmnd = isp_kzalloc(sizeof (Scsi_Cmnd), GFP_KERNEL);
    if (Cmnd == NULL) {
        result = -ENOMEM;
        goto out;
    }
    host = isp->isp_osinfo.host;
    dev = isp_kzalloc(sizeof (struct scsi_device), GFP_KERNEL);
    if (dev == NULL) {
        result = -ENOMEM;
        goto out;
    }
    Cmnd->device = dev;
    dev->host = host;
    Cmnd->scsi_done = isp_run_cmd_done;
    Cmnd->request_buffer = &rsem;

    ISP_LOCKU_SOFTC(isp);
    if (isp_getrqentry(isp, &nxti, &optr, (void *)&reqp)) {
        ISP_UNLKU_SOFTC(isp);
        isp_prt(isp, ISP_LOGDEBUG0, "%s: Request Queue Overflow", __FUNCTION__);
        result = -ENOMEM;
        goto out;
    }
    reqp = (ispreq_t *) local;
    reqp->req_header.rqs_entry_count = 1;

    if (isp_save_xs(isp, Cmnd, &handle)) {
        ISP_UNLKU_SOFTC(isp);
        isp_prt(isp, ISP_LOGDEBUG0, "out of xflist pointers");
        result = -ENOMEM;
        goto out;
    }
    reqp->req_handle = handle;

    /*
     * Now see if we need to synchronize the ISP with respect to anything.
     * We do dual duty here (cough) for synchronizing for busses other
     * than which we got here to send a command to.
     */
    if (IS_24XX(isp)) {
        ispreqt7_t *t7 = (ispreqt7_t *) local;
        reqp->req_header.rqs_entry_type = RQSTYPE_T7RQS;
        t7->req_task_attribute = FCP_CMND_TASK_ATTR_SIMPLE;
        t7->req_nphdl = cmd->handle;
        t7->req_tidlo = cmd->portid;
        t7->req_tidhi = cmd->portid >> 16;
        if (cmd->lun > 256) {
            t7->req_lun[0] = cmd->lun >> 8;
            t7->req_lun[0] |= 0x40;
        }
        t7->req_lun[1] = cmd->lun;
        MEMCPY(t7->req_cdb, cmd->fcd.beg.cdb, min(sizeof (t7->req_cdb), sizeof (cmd->fcd.beg.cdb)));
        Cmnd->cmd_len = sizeof(t7->req_cdb);
        t7->req_time = time;
    } else if (IS_FC(isp)) {
        ispreqt2_t *t2 = (ispreqt2_t *) local;
        reqp->req_header.rqs_entry_type = RQSTYPE_T2RQS;
        t2->req_flags = REQFLAG_STAG;

        if (ISP_CAP_2KLOGIN(isp)) {
            ((ispreqt2e_t *)reqp)->req_target = cmd->handle;
            ((ispreqt2e_t *)reqp)->req_scclun = cmd->lun;
        } else if (ISP_CAP_SCCFW(isp)) {
            t2->req_target = cmd->handle;
            t2->req_scclun = cmd->lun;
        } else {
            t2->req_target = cmd->handle;
            t2->req_lun_trn = cmd->lun;
        }
        MEMCPY(t2->req_cdb, cmd->fcd.beg.cdb, min(sizeof (t2->req_cdb), sizeof (cmd->fcd.beg.cdb)));
        Cmnd->cmd_len = sizeof(t2->req_cdb);
        t2->req_time = time;
    } else {
        reqp->req_header.rqs_entry_type = RQSTYPE_REQUEST;
        reqp->req_flags = REQFLAG_STAG;
        reqp->req_target = cmd->handle;
        reqp->req_lun_trn = cmd->lun;
        reqp->req_cdblen = 12;
        MEMCPY(reqp->req_cdb, cmd->fcd.beg.cdb, min(sizeof (reqp->req_cdb), sizeof (cmd->fcd.beg.cdb)));
        Cmnd->cmd_len = 12;
        reqp->req_time = time;
    }

    MEMCPY(Cmnd->cmnd, cmd->fcd.beg.cdb, Cmnd->cmd_len);
    Cmnd->request_bufflen = cmd->fcd.beg.data_length;
    Cmnd->request_buffer = cmd->fcd.beg.data_ptr;
    if (Cmnd->request_bufflen && Cmnd->request_buffer) {
        if (cmd->fcd.beg.do_read) {
            Cmnd->sc_data_direction = SCSI_DATA_READ;
        } else {
            Cmnd->sc_data_direction =  SCSI_DATA_WRITE;
        }
    } else {
        Cmnd->sc_data_direction =  SCSI_DATA_NONE;
    }

    result = ISP_DMASETUP(isp, Cmnd, reqp, &nxti, optr);
    switch (result) {
    default:
        isp_prt(isp, ISP_LOGWARN, "isp_run_cmd: dma setup returned %d", result);
        result = -EIO;
        break;
    case CMD_EAGAIN:
        result = -ENOMEM;
        break;
    case CMD_QUEUED:
        ISP_ADD_REQUEST(isp, nxti);
        isp->isp_nactive++;
        result = 0;
        break;
    }

    if (result == 0) {
        ISP_UNLKU_SOFTC(isp);
        down(&rsem);
        cmd->fcd.end.data_residual = Cmnd->resid;
        cmd->fcd.end.status = Cmnd->SCp.Status;
        if (cmd->fcd.end.status == SCSI_CHECK) {
            MEMCPY(cmd->fcd.end.sense_data, Cmnd->sense_buffer, min(sizeof(cmd->fcd.end.sense_data), sizeof (Cmnd->sense_buffer)));
        }
        if (host_byte(Cmnd->result) != DID_OK) {
            result = -EIO;
        }
        ISP_LOCKU_SOFTC(isp);
        ISP_DMAFREE(isp, Cmnd, handle);
    }
    isp_destroy_handle(isp, handle);
    ISP_UNLKU_SOFTC(isp);
out:
    if (dev) {
        isp_kfree(dev, sizeof (struct scsi_device));
    }
    isp_kfree(Cmnd, sizeof (Scsi_Cmnd));
    return (result);
}
#endif  /* CONFIG_PROC_FS */
/*
 * vim:ts=4:sw=4:expandtab
 */
