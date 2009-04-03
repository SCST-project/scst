/* $Id: isp_ioctl.h,v 1.30 2009/03/30 04:17:34 mjacob Exp $ */
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
 * ioctl definitions for Qlogic FC/SCSI HBA driver
 */
#define ISP_IOC (0x4D4A5100)    /* 'MJQ' << 8 */

/*
 * This ioctl sets/retrieves the debugging level for this hba instance.
 * Note that this is not a simple integer level- see ispvar.h for definitions.
 *
 * The arguments is a pointer to an integer with the new debugging level.
 * The old value is written into this argument.
 */

#define ISP_SDBLEV  (ISP_IOC | 1)

/*
 * This ioctl resets the HBA. Use with caution.
 */
#define ISP_RESETHBA    (ISP_IOC | 2)

/*
 * This ioctl performs a fibre chanel rescan.
 */
#define ISP_RESCAN  (ISP_IOC | 3)

/*
 * This ioctl performs a reset and then will set the adapter to the
 * role that was passed in (the old role will be returned). It almost
 * goes w/o saying: use with caution.
 *
 * Channel selector stored in bits 8..32 as input to driver.
 */
#define ISP_SETROLE     (ISP_IOC | 4)

#define ISP_ROLE_NONE           0x0
#define ISP_ROLE_TARGET         0x1
#define ISP_ROLE_INITIATOR      0x2
#define ISP_ROLE_BOTH           (ISP_ROLE_TARGET|ISP_ROLE_INITIATOR)
#ifndef ISP_DEFAULT_ROLES
#define ISP_DEFAULT_ROLES       ISP_ROLE_BOTH
#endif

/*
 * Get the current adapter role
 * Channel selector passed in first argument.
 */
#define ISP_GETROLE     (ISP_IOC | 5)

/*
 * Get/Clear Stats
 */
#define ISP_STATS_VERSION   0
typedef struct {
    uint8_t     isp_stat_version;
    uint8_t     isp_type;           /* (ro) reflects chip type */
    uint8_t     isp_revision;       /* (ro) reflects chip version */
    uint8_t     unused1;
    uint32_t    unused2;
    /*
     * Statistics Counters
     */
#define ISP_NSTATS      16
#define ISP_INTCNT      0
#define ISP_INTBOGUS    1
#define ISP_INTMBOXC    2
#define ISP_INGOASYNC   3
#define ISP_RSLTCCMPLT  4
#define ISP_FPHCCMCPLT  5
#define ISP_RSCCHIWAT   6
#define ISP_FPCCHIWAT   7
    uint64_t    isp_stats[ISP_NSTATS];
} isp_stats_t;

#define ISP_GET_STATS   (ISP_IOC | 6)
#define ISP_CLR_STATS   (ISP_IOC | 7)

/*
 * Initiate a LIP
 */
#define ISP_FC_LIP      (ISP_IOC | 8)

/*
 * Return the Port Database structure for the named device, or ENODEV if none.
 * Caller fills in virtual loopid (0..255/2048), aka 'target'. The driver returns
 * ENODEV (if nothing valid there) or the actual loopid (for local loop devices
 * only), 24 bit Port ID and Node and Port WWNs.
 */
struct isp_fc_device {
    uint32_t    loopid;     /* 0..255/2048 */
    uint32_t
            chan    : 6,
            role    : 2,
            portid  : 24;   /* 24 bit Port ID */
    uint64_t    node_wwn;
    uint64_t    port_wwn;
};
#define ISP_FC_GETDINFO (ISP_IOC | 9)

/*
 * Get F/W crash dump
 */
#define ISP_GET_FW_CRASH_DUMP   (ISP_IOC | 10)
#define ISP_FORCE_CRASH_DUMP    (ISP_IOC | 11)

/*
 * Get information about this Host Adapter, including current connection
 * topology and capabilities.
 */
struct isp_hba_device {
    uint32_t                : 8,
        fc_speed            : 4,    /* Gbps */
                            : 1,
        fc_topology         : 3,
        fc_channel          : 8,    /* channel selector */
        fc_loopid           : 16;   /* loop id selector */
    uint8_t     fc_fw_major;    /* firmware major version */
    uint8_t     fc_fw_minor;    /* firmware minor version */
    uint8_t     fc_fw_micro;    /* firmware micro version */
    uint8_t     fc_nchannels;   /* number of supported channels */
    uint16_t    fc_nports;      /* number of supported ports */
    uint64_t    nvram_node_wwn;
    uint64_t    nvram_port_wwn;
    uint64_t    active_node_wwn;
    uint64_t    active_port_wwn;
};

#define ISP_TOPO_UNKNOWN    0   /* connection topology unknown */
#define ISP_TOPO_FCAL       1   /* private or PL_DA */
#define ISP_TOPO_LPORT      2   /* public loop */
#define ISP_TOPO_NPORT      3   /* N-port */
#define ISP_TOPO_FPORT      4   /* F-port */

/* do not use this one any more */
/* #define ISP_FC_GETHINFO     (ISP_IOC|12) */
#define ISP_FC_GETHINFO     (ISP_IOC|13)

/*
 * Set Active WWNN/WWPN
 */
struct isp_wwn {
    uint32_t    _reserved[2];
    uint64_t    node_wwn;
    uint64_t    port_wwn;
};

#define ISP_FC_SET_WWN      (ISP_IOC | 20)

/*
 * Various Reset Goodies
 */
struct isp_fc_tsk_mgmt {
    uint32_t    loopid;		/* 0..255/2048 */
    uint16_t    lun;
    uint16_t    chan;
    enum {
        IPT_CLEAR_ACA,
        IPT_TARGET_RESET,
        IPT_LUN_RESET,
        IPT_CLEAR_TASK_SET,
        IPT_ABORT_TASK_SET
    } action;
};
/* don't use 21 anymore */
/* #define	ISP_TSK_MGMT		(ISP_IOC | 21) */
#define	ISP_TSK_MGMT		(ISP_IOC | 22)

/*
 * Just gimme a list of WWPNs that are logged into us.
 */
typedef struct {
    uint16_t count;
    uint16_t channel;
    struct wwnpair {
        uint64_t wwnn;
        uint64_t wwpn;
    } wwns[1];
} isp_dlist_t;
/* do not recycle 22 */

#define ISP_FC_GETDLIST     (ISP_IOC | 23)
/*
 * vim:ts=4:sw=4:expandtab
 */
