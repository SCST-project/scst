/* $Id: scsi_target.h,v 1.26 2007/03/10 01:56:34 mjacob Exp $ */
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
 * SCSI Target Control Port
 */
#define SCSI_TARGET     "scsi_target"
#define SCSI_TARGET_DEV "/proc/" SCSI_TARGET

/*
 * SCSI Target Stub Driver for Linux for a memory or user agent disk device.
 * Ioctl Definitions File.
 */

#define _SI             ('e' << 8)

/*
 * Set new debugging level (get previous) (int argument).
 */
#define SC_DEBUG        (_SI | 0)

/*
 * Enable/Disable lun
 */
typedef struct {
    char    hba_name_unit[16];  /* e.g., "isp0" */
    uint64_t nbytes;            /* disk size, in bytes */
    uint16_t lun;               /* lun to map it to */
    uint16_t flags;             /* flags */
} sc_enable_t;
#define SC_EF_OVERCOMMIT        0x01    /* allow overcommit */

#define SC_ENABLE_LUN   (_SI | 1)
#define SC_DISABLE_LUN  (_SI | 2)

/*
 * Overcommit disks have to have data written to backing store
 * and read from it.
 */
typedef struct {
    char        hba_name_unit[16];  /* e.g., "isp0" */
    uint16_t    lun;                /* lun */
    uint16_t            :   14,
                sync    :   1,      /* (implied) sync after write */
                read    :   1;      /* read (from target to initiator) flag */
    void *      tag;                /* id tag for this command */
    void *      addr;               /* user buffer address */
    uint32_t    len;                /* user buffer length */
    uint64_t    off;                /* disk offset */
    uint32_t    amt;                /* this command's actual data length */
    int         err;                /* from user app */
} sc_io_t;
#define SC_GET_IO       (_SI | 3)
#define SC_PUT_IO       (_SI | 4)
/*
 * vim:ts=4:sw=4:expandtab
 */
