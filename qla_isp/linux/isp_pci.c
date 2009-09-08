/* $Id: isp_pci.c,v 1.186 2009/09/06 00:37:07 mjacob Exp $ */
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
 * Qlogic ISP Host Adapter PCI specific probe and attach routines
 */
#include "isp_linux.h"
#include <linux/firmware.h>

static int isp_pci_mapmem = 0xffffffff;
#if    defined(__sparc__)
#undef  ioremap_nocache
#define ioremap_nocache    ioremap
#endif
static int isplinux_pci_init_one(struct Scsi_Host *);
static uint32_t isp_pci_rd_reg(ispsoftc_t *, int);
static void isp_pci_wr_reg(ispsoftc_t *, int, uint32_t);
#if !(defined(ISP_DISABLE_1080_SUPPORT) && defined(ISP_DISABLE_12160_SUPPORT))
static uint32_t isp_pci_rd_reg_1080(ispsoftc_t *, int);
static void isp_pci_wr_reg_1080(ispsoftc_t *, int, uint32_t);
#endif
#if !(defined(ISP_DISABLE_1020_SUPPORT) && defined(ISP_DISABLE_1080_SUPPORT) && defined(ISP_DISABLE_12160_SUPPORT) && defined(ISP_DISABLE_2100_SUPPORT) && defined(ISP_DISABLE_2200_SUPPORT))
static int isp_pci_rd_isr(ispsoftc_t *, uint32_t *, uint16_t *, uint16_t *);
#endif
#if !(defined(ISP_DISABLE_2300_SUPPORT) && defined(ISP_DISABLE_2322_SUPPORT))
static int isp_pci_rd_isr_2300(ispsoftc_t *, uint32_t *, uint16_t *, uint16_t *);
#endif
#if !defined(ISP_DISABLE_2400_SUPPORT)
static uint32_t isp_pci_rd_reg_2400(ispsoftc_t *, int);
static void isp_pci_wr_reg_2400(ispsoftc_t *, int, uint32_t);
static int isp_pci_rd_isr_2400(ispsoftc_t *, uint32_t *, uint16_t *, uint16_t *);
#endif
static int isp_pci_mbxdma(ispsoftc_t *);
static int isp_pci_dmasetup(ispsoftc_t *, XS_T *, void *);
static void isp_pci_dmateardown(ispsoftc_t *, XS_T *, uint32_t);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,6)
#define DMA_64BIT_MASK  0xffffffffffffffffULL
#define DMA_32BIT_MASK  0x00000000ffffffffULL
#endif

#define SIXTEENM_SEG(x)             (((u64) (x)) & 0xffffffff00000000ULL)
#define SAME_SIXTEENM(addr, cnt)    (SIXTEENM_SEG(addr) == SIXTEENM_SEG(addr + cnt - 1))

#define FOURG_SEG(x)                (((u64) (x)) & 0xffffffff00000000ULL)
#define SAME_4G(addr, cnt)          (FOURG_SEG(addr) == FOURG_SEG(addr + cnt - 1))


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
#define ISP_IRQ_FLAGS   SA_INTERRUPT | SA_SHIRQ
#else
#define ISP_IRQ_FLAGS   IRQF_SHARED
#endif

static void isp_pci_reset0(ispsoftc_t *);
static void isp_pci_reset1(ispsoftc_t *);
static void isp_pci_dumpregs(ispsoftc_t *, const char *);
static int isplinux_pci_exclude(struct pci_dev *);


#define ISP_1040_RISC_CODE  NULL
#define ISP_1080_RISC_CODE  NULL
#define ISP_12160_RISC_CODE NULL
#define ISP_2100_RISC_CODE  NULL
#define ISP_2200_RISC_CODE  NULL
#define ISP_2300_RISC_CODE  NULL
#define ISP_2322_RISC_CODE  NULL
#define ISP_2400_RISC_CODE  NULL
#define ISP_2500_RISC_CODE  NULL

#if defined(DISABLE_FW_LOADER) || !(defined(CONFIG_FW_LOADER) || defined(CONFIG_FW_LOADER_MODULE))
#ifndef    ISP_DISABLE_1020_SUPPORT
#include "asm_1040.h"
#undef  ISP_1040_RISC_CODE
#define ISP_1040_RISC_CODE  (const uint16_t *) isp_1040_risc_code
#endif
#ifndef    ISP_DISABLE_1080_SUPPORT
#include "asm_1080.h"
#undef  ISP_1080_RISC_CODE
#define ISP_1080_RISC_CODE  (const uint16_t *) isp_1080_risc_code
#endif
#ifndef    ISP_DISABLE_12160_SUPPORT
#include "asm_12160.h"
#undef  ISP_12160_RISC_CODE
#define ISP_12160_RISC_CODE  (const uint16_t *) isp_12160_risc_code
#endif
#ifndef    ISP_DISABLE_2100_SUPPORT
#include "asm_2100.h"
#undef  ISP_2100_RISC_CODE
#define ISP_2100_RISC_CODE  (const uint16_t *) isp_2100_risc_code
#endif
#ifndef    ISP_DISABLE_2200_SUPPORT
#include "asm_2200.h"
#undef  ISP_2200_RISC_CODE
#define ISP_2200_RISC_CODE  (const uint16_t *) isp_2200_risc_code
#endif
#ifndef    ISP_DISABLE_2300_SUPPORT
#include "asm_2300.h"
#undef  ISP_2300_RISC_CODE
#define ISP_2300_RISC_CODE  (const uint16_t *) isp_2300_risc_code
#endif
#ifndef    ISP_DISABLE_2322_SUPPORT
#include "asm_2322.h"
#undef  ISP_2322_RISC_CODE
#define ISP_2322_RISC_CODE  (const uint16_t *) isp_2322_risc_code
#endif
#ifndef    ISP_DISABLE_2400_SUPPORT
#define ISP_2400
#define ISP_2400_MULTI
#define ISP_2500
#define ISP_2500_MULTI
#include "asm_2400.h"
#include "asm_2500.h"
#undef  ISP_2400_RISC_CODE
#undef  ISP_2500_RISC_CODE
#define ISP_2400_RISC_CODE  (const uint32_t *) isp_2400_risc_code
#define ISP_2500_RISC_CODE  (const uint32_t *) isp_2500_risc_code
#define ISP_2400_MULTI_RISC_CODE    (const uint32_t *) isp_2400_multi_risc_code
#define ISP_2500_MULTI_RISC_CODE    (const uint32_t *) isp_2500_multi_risc_code
#endif
#endif

#ifndef    ISP_DISABLE_1020_SUPPORT
static struct ispmdvec mdvec = {
    isp_pci_rd_isr,
    isp_pci_rd_reg,
    isp_pci_wr_reg,
    isp_pci_mbxdma,
    isp_pci_dmasetup,
    isp_pci_dmateardown,
    isp_pci_reset0,
    isp_pci_reset1,
    isp_pci_dumpregs,
    ISP_1040_RISC_CODE,
    BIU_BURST_ENABLE|BIU_PCI_CONF1_FIFO_64
};
#endif

#ifndef    ISP_DISABLE_1080_SUPPORT
static struct ispmdvec mdvec_1080 = {
    isp_pci_rd_isr,
    isp_pci_rd_reg_1080,
    isp_pci_wr_reg_1080,
    isp_pci_mbxdma,
    isp_pci_dmasetup,
    isp_pci_dmateardown,
    isp_pci_reset0,
    isp_pci_reset1,
    isp_pci_dumpregs,
    ISP_1080_RISC_CODE,
    BIU_BURST_ENABLE|BIU_PCI_CONF1_FIFO_128
};
#endif

#ifndef    ISP_DISABLE_12160_SUPPORT
static struct ispmdvec mdvec_12160 = {
    isp_pci_rd_isr,
    isp_pci_rd_reg_1080,
    isp_pci_wr_reg_1080,
    isp_pci_mbxdma,
    isp_pci_dmasetup,
    isp_pci_dmateardown,
    isp_pci_reset0,
    isp_pci_reset1,
    isp_pci_dumpregs,
    ISP_12160_RISC_CODE,
    BIU_BURST_ENABLE|BIU_PCI_CONF1_FIFO_128
};
#endif

#ifndef    ISP_DISABLE_2100_SUPPORT
static struct ispmdvec mdvec_2100 = {
    isp_pci_rd_isr,
    isp_pci_rd_reg,
    isp_pci_wr_reg,
    isp_pci_mbxdma,
    isp_pci_dmasetup,
    isp_pci_dmateardown,
    isp_pci_reset0,
    isp_pci_reset1,
    isp_pci_dumpregs,
    ISP_2100_RISC_CODE
};
#endif

#ifndef    ISP_DISABLE_2200_SUPPORT
static struct ispmdvec mdvec_2200 = {
    isp_pci_rd_isr,
    isp_pci_rd_reg,
    isp_pci_wr_reg,
    isp_pci_mbxdma,
    isp_pci_dmasetup,
    isp_pci_dmateardown,
    isp_pci_reset0,
    isp_pci_reset1,
    isp_pci_dumpregs,
    ISP_2200_RISC_CODE
};
#endif

#ifndef    ISP_DISABLE_2300_SUPPORT
static struct ispmdvec mdvec_2300 = {
    isp_pci_rd_isr_2300,
    isp_pci_rd_reg,
    isp_pci_wr_reg,
    isp_pci_mbxdma,
    isp_pci_dmasetup,
    isp_pci_dmateardown,
    isp_pci_reset0,
    isp_pci_reset1,
    isp_pci_dumpregs,
    ISP_2300_RISC_CODE
};
#endif
#ifndef    ISP_DISABLE_2322_SUPPORT
static struct ispmdvec mdvec_2322 = {
    isp_pci_rd_isr_2300,
    isp_pci_rd_reg,
    isp_pci_wr_reg,
    isp_pci_mbxdma,
    isp_pci_dmasetup,
    isp_pci_dmateardown,
    isp_pci_reset0,
    isp_pci_reset1,
    isp_pci_dumpregs,
    ISP_2322_RISC_CODE
};
#endif
#ifndef ISP_DISABLE_2400_SUPPORT
static struct ispmdvec mdvec_2400 = {
    isp_pci_rd_isr_2400,
    isp_pci_rd_reg_2400,
    isp_pci_wr_reg_2400,
    isp_pci_mbxdma,
    isp_pci_dmasetup,
    isp_pci_dmateardown,
    isp_pci_reset0,
    isp_pci_reset1,
    NULL,
    ISP_2400_RISC_CODE
};
static struct ispmdvec mdvec_2500 = {
    isp_pci_rd_isr_2400,
    isp_pci_rd_reg_2400,
    isp_pci_wr_reg_2400,
    isp_pci_mbxdma,
    isp_pci_dmasetup,
    isp_pci_dmateardown,
    isp_pci_reset0,
    isp_pci_reset1,
    NULL,
    ISP_2500_RISC_CODE
};
#endif

#ifndef    PCI_DEVICE_ID_QLOGIC_ISP1020
#define PCI_DEVICE_ID_QLOGIC_ISP1020    0x1020
#endif

#ifndef    PCI_DEVICE_ID_QLOGIC_ISP1020
#define PCI_DEVICE_ID_QLOGIC_ISP1020    0x1020
#endif

#ifndef    PCI_DEVICE_ID_QLOGIC_ISP1080
#define PCI_DEVICE_ID_QLOGIC_ISP1080    0x1080
#endif

#ifndef    PCI_DEVICE_ID_QLOGIC_ISP10160
#define PCI_DEVICE_ID_QLOGIC_ISP10160    0x1016
#endif

#ifndef    PCI_DEVICE_ID_QLOGIC_ISP12160
#define PCI_DEVICE_ID_QLOGIC_ISP12160    0x1216
#endif

#ifndef    PCI_DEVICE_ID_QLOGIC_ISP1240
#define PCI_DEVICE_ID_QLOGIC_ISP1240    0x1240
#endif

#ifndef    PCI_DEVICE_ID_QLOGIC_ISP1280
#define PCI_DEVICE_ID_QLOGIC_ISP1280    0x1280
#endif

#ifndef    PCI_DEVICE_ID_QLOGIC_ISP2100
#define PCI_DEVICE_ID_QLOGIC_ISP2100    0x2100
#endif

#ifndef    PCI_DEVICE_ID_QLOGIC_ISP2200
#define PCI_DEVICE_ID_QLOGIC_ISP2200    0x2200
#endif

#ifndef    PCI_DEVICE_ID_QLOGIC_ISP2300
#define PCI_DEVICE_ID_QLOGIC_ISP2300    0x2300
#endif

#ifndef    PCI_DEVICE_ID_QLOGIC_ISP2312
#define PCI_DEVICE_ID_QLOGIC_ISP2312    0x2312
#endif

#ifndef    PCI_DEVICE_ID_QLOGIC_ISP2322
#define PCI_DEVICE_ID_QLOGIC_ISP2322    0x2322
#endif

#ifndef    PCI_DEVICE_ID_QLOGIC_ISP2422
#define PCI_DEVICE_ID_QLOGIC_ISP2422    0x2422
#endif

#ifndef    PCI_DEVICE_ID_QLOGIC_ISP2432
#define PCI_DEVICE_ID_QLOGIC_ISP2432    0x2432
#endif

#ifndef    PCI_DEVICE_ID_QLOGIC_ISP2532
#define PCI_DEVICE_ID_QLOGIC_ISP2532    0x2532
#endif

#ifndef    PCI_DEVICE_ID_QLOGIC_ISP6312
#define PCI_DEVICE_ID_QLOGIC_ISP6312    0x6312
#endif

#ifndef    PCI_DEVICE_ID_QLOGIC_ISP6322
#define PCI_DEVICE_ID_QLOGIC_ISP6322    0x6322
#endif

#define PCI_DFLT_LTNCY  0x40
#define PCI_DFLT_LNSZ   0x10
#define PCI_CMD_ISP     (PCI_COMMAND_MASTER|PCI_COMMAND_INVALIDATE|PCI_COMMAND_PARITY|PCI_COMMAND_SERR)

/*
 * Encapsulating softc... Order of elements is important. The tag
 * pci_isp must come first because of multiple structure punning
 * (Scsi_Host == struct isp_pcisoftc == ispsoftc_t).
 */
struct isp_pcisoftc {
    ispsoftc_t          pci_isp;
    struct pci_dev *    pci_dev;
    vm_offset_t         port;       /* I/O port address */
    vm_offset_t         paddr;      /* Physical Memory Address */
    void *              vaddr;      /* Mapped Memory Address */
    vm_offset_t         voff;
    vm_offset_t         poff[_NREG_BLKS];
    u16     msix_vector[3];
    u8                      : 5,
            msix_enabled    : 2,
            msi_enabled     : 1;
};
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
#define pci_enable_msi(x)   -ENXIO
#define pci_enable_msix(x)  -ENXIO
#define pci_disable_msi(x)  do { ; } while(0)
#define pci_disable_msix(x) do { ; } while(0)
#endif

/*
 * Gratefully borrowed from Gerard Roudier's sym53c8xx driver
 */
static ISP_INLINE void *
map_pci_mem(struct isp_pcisoftc *isp_pci, u_long size)
{
    unsigned long page_base;
    unsigned long map_size;
    u8 *page_remapped;

    page_base = isp_pci->paddr & PAGE_MASK;
    isp_pci->voff = isp_pci->paddr - page_base;
    map_size = roundup(isp_pci->voff + size, PAGE_SIZE);
    page_remapped = ioremap_nocache(page_base, map_size);
    if (page_remapped) {
        page_remapped += isp_pci->voff;
    }
    return (page_remapped);
}

static ISP_INLINE
void unmap_pci_mem(struct isp_pcisoftc *isp_pci, unsigned long size)
{
    if (isp_pci->vaddr) {
        u8 *p = isp_pci->vaddr;
        p += isp_pci->voff;
        iounmap(p);
    }
}

static ISP_INLINE int
map_isp_mem(struct isp_pcisoftc *isp_pci, u_short cmd, vm_offset_t mem_base)
{
    if (cmd & PCI_COMMAND_MEMORY) {
        isp_pci->paddr = mem_base;
        isp_pci->paddr &= PCI_BASE_ADDRESS_MEM_MASK;
        isp_pci->vaddr = map_pci_mem(isp_pci, 0xff);
        return (isp_pci->vaddr != (void *) 0);
    }
    return (0);
}

static ISP_INLINE int
map_isp_io(struct isp_pcisoftc *isp_pci, u_short cmd, vm_offset_t io_base)
{
    if ((cmd & PCI_COMMAND_IO) && (io_base & 3) == 1) {
        isp_pci->port = io_base & PCI_BASE_ADDRESS_IO_MASK;
        request_region(isp_pci->port, 0xff, ISP_NAME);
        return (1);
    }
    return (0);
}

static void
isplinux_pci_release(struct Scsi_Host *host)
{
    ispsoftc_t *isp = ISP_HOST2ISP(host);
    struct isp_pcisoftc *isp_pci = (struct isp_pcisoftc *) isp;
    int i;

    if (host->irq) {
        free_irq(host->irq, isp_pci);
        host->irq = 0;
    }
    if (isp_pci->msix_enabled) {
        if (isp_pci->msix_enabled > 1) {
            free_irq(isp_pci->msix_vector[0], isp_pci);
            free_irq(isp_pci->msix_vector[1], isp_pci);
            free_irq(isp_pci->msix_vector[2], isp_pci);
        }
        pci_disable_msix(isp_pci->pci_dev);
        isp_pci->msix_enabled = 0;
    }
    if (isp_pci->msi_enabled) {
        pci_disable_msi(isp_pci->pci_dev);
        isp_pci->msi_enabled = 0;
    }
    if (isp_pci->vaddr != NULL) {
        unmap_pci_mem(isp_pci, 0xff);
        isp_pci->vaddr = NULL;
    } else if (isp_pci->port) {
        release_region(isp_pci->port, 0xff);
        isp_pci->port = 0;
    }
    if (isp->isp_rquest) {
        pci_free_consistent(isp_pci->pci_dev, RQUEST_QUEUE_LEN(isp) * QENTRY_LEN, isp->isp_rquest, isp->isp_rquest_dma);
        isp->isp_rquest = NULL;
    }
    if (isp->isp_xflist) {
        isp_kfree(isp->isp_xflist, isp->isp_osinfo.mcorig * sizeof (XS_T **));
        isp->isp_xflist = NULL;
    }
#ifdef    ISP_TARGET_MODE
    if (isp->isp_tgtlist) {
        isp_kfree(isp->isp_tgtlist, isp->isp_osinfo.mcorig * sizeof (void **));
        isp->isp_tgtlist = NULL;
    }
#endif
    if (isp->isp_result) {
        pci_free_consistent(isp_pci->pci_dev, RESULT_QUEUE_LEN(isp) * QENTRY_LEN, isp->isp_result, isp->isp_result_dma);
        isp->isp_result = NULL;
    }
    if (IS_FC(isp)) {
        for (i = 0; i < isp->isp_nchan; i++) {
            fcparam *fcp = FCPARAM(isp, i);
            if (fcp->isp_scratch) {
                pci_free_consistent(isp_pci->pci_dev, ISP_FC_SCRLEN, fcp->isp_scratch, fcp->isp_scdma);
                fcp->isp_scratch = NULL;
            }
        }
    }
    pci_release_regions(isp_pci->pci_dev);
    if (isp->isp_param) {
        isp_kfree(isp->isp_param, isp->isp_osinfo.param_amt);
        isp->isp_param = NULL;
    }
    if (isp->isp_osinfo.storep) {
        isp_kfree(isp->isp_osinfo.storep, isp->isp_osinfo.storep_amt);
        isp->isp_osinfo.storep = NULL;
    }
    pci_disable_device(isp_pci->pci_dev);

    /*
     * Pull ourselves off the global list
     */
    for (i = 0; i < MAX_ISP; i++) {
        if (isplist[i] == isp) {
            isplist[i] = NULL;
            break;
        }
    }
}


#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,7) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
/**
 * pci_intx - enables/disables PCI INTx for device dev
 * @pdev: the PCI device to operate on
 * @enable: boolean: whether to enable or disable PCI INTx
 *
 * Enables/disables PCI INTx for device dev
 */
static void
pci_intx(struct pci_dev *pdev, int enable)
{
    u16 pci_command, new;
    pci_read_config_word(pdev, PCI_COMMAND, &pci_command);
    if (enable) {
        new = pci_command & ~PCI_COMMAND_INTX_DISABLE;
    } else {
        new = pci_command | PCI_COMMAND_INTX_DISABLE;
    }
    if (new != pci_command) {
        pci_write_config_word(pdev, PCI_COMMAND, new);
    }
}
#endif

static int
isplinux_pci_init_one(struct Scsi_Host *host)
{
    static char *nomap = "cannot map either memory or I/O space";
    unsigned long io_base, mem_base;
    unsigned int bar, rev;
    u16 cmd;
    struct isp_pcisoftc *isp_pci;
    struct pci_dev *pdev;
    ispsoftc_t *isp;
    const char *fwname = NULL;

    isp_pci = (struct isp_pcisoftc *) ISP_HOST2ISP(host);
    pdev = isp_pci->pci_dev;
    isp = (ispsoftc_t *) isp_pci;
    if (isp_debug) {
        isp->isp_dblev = isp_debug;
    } else {
        isp->isp_dblev = ISP_LOGCONFIG|ISP_LOGINFO|ISP_LOGWARN|ISP_LOGERR;
#ifdef  ISP_TARGET_MODE
        isp->isp_dblev |= ISP_LOGTINFO;
#endif
    }

    pci_read_config_word(pdev, PCI_COMMAND, &cmd);
    pci_read_config_dword(pdev, PCI_CLASS_REVISION, &rev);
    rev &= 0xff;

    if (pci_request_regions(pdev, ISP_NAME)) {
        return (1);
    }

    io_base = pci_resource_start(pdev, 0);
    if (pci_resource_flags(pdev, 0) & PCI_BASE_ADDRESS_MEM_TYPE_64) {
        bar = 2;
    } else {
        bar = 1;
    }
    mem_base = pci_resource_start(pdev, bar);
    if (pci_resource_flags(pdev, bar) & PCI_BASE_ADDRESS_MEM_TYPE_64) {
#if    BITS_PER_LONG == 64
        mem_base |= pci_resource_start(pdev, bar+1) << 32;
#else
        isp_pci_mapmem &= ~(1 << isp->isp_unit);
#endif
    }

    isp_pci->poff[BIU_BLOCK >> _BLK_REG_SHFT] = BIU_REGS_OFF;
    isp_pci->poff[MBOX_BLOCK >> _BLK_REG_SHFT] = PCI_MBOX_REGS_OFF;
    isp_pci->poff[SXP_BLOCK >> _BLK_REG_SHFT] = PCI_SXP_REGS_OFF;
    isp_pci->poff[RISC_BLOCK >> _BLK_REG_SHFT] = PCI_RISC_REGS_OFF;
    isp_pci->poff[DMA_BLOCK >> _BLK_REG_SHFT] = DMA_REGS_OFF;
    isp->isp_nchan = 1;

    switch (pdev->device) {
    case PCI_DEVICE_ID_QLOGIC_ISP1020:
        break;
    case PCI_DEVICE_ID_QLOGIC_ISP12160:
    case PCI_DEVICE_ID_QLOGIC_ISP1240:
        isp->isp_nchan = 2;
        /* FALLTHROUGH */
    case PCI_DEVICE_ID_QLOGIC_ISP1080:
    case PCI_DEVICE_ID_QLOGIC_ISP1280:
    case PCI_DEVICE_ID_QLOGIC_ISP10160:
        isp_pci->poff[DMA_BLOCK >> _BLK_REG_SHFT] = ISP1080_DMA_REGS_OFF;
        break;
    case PCI_DEVICE_ID_QLOGIC_ISP2200:
    case PCI_DEVICE_ID_QLOGIC_ISP2100:
        isp_pci->poff[MBOX_BLOCK >> _BLK_REG_SHFT] = PCI_MBOX_REGS2100_OFF;
        break;
    case PCI_DEVICE_ID_QLOGIC_ISP2300:
        pci_clear_mwi(pdev);
        isp_pci->poff[MBOX_BLOCK >> _BLK_REG_SHFT] = PCI_MBOX_REGS2300_OFF;
        break;
    case PCI_DEVICE_ID_QLOGIC_ISP6312:
    case PCI_DEVICE_ID_QLOGIC_ISP2312:
    case PCI_DEVICE_ID_QLOGIC_ISP2322:
        isp->isp_port = PCI_FUNC(pdev->devfn);
        isp_pci->poff[MBOX_BLOCK >> _BLK_REG_SHFT] = PCI_MBOX_REGS2300_OFF;
        break;
    case PCI_DEVICE_ID_QLOGIC_ISP2422:
    case PCI_DEVICE_ID_QLOGIC_ISP2432:
    case PCI_DEVICE_ID_QLOGIC_ISP2532:
        isp->isp_port = PCI_FUNC(pdev->devfn);
        isp_pci->poff[MBOX_BLOCK >> _BLK_REG_SHFT] = PCI_MBOX_REGS2400_OFF;
        isp->isp_nchan += isp_vports;
        break;
    default:
        isp_prt(isp, ISP_LOGERR, "Device ID 0x%04x is not a known Qlogic Device", pdev->device);
        pci_release_regions(pdev);
        return (1);
    }

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,7)
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP2422 || pdev->device == PCI_DEVICE_ID_QLOGIC_ISP2432 || pdev->device == PCI_DEVICE_ID_QLOGIC_ISP2532) {
        struct msix_entry isp_msix[3];
        int reg;

        isp_msix[0].vector = 0;
        isp_msix[0].entry = 0;
        isp_msix[1].vector = 1;
        isp_msix[1].entry = 1;
        isp_msix[2].vector = 2;
        isp_msix[2].entry = 2;

        /* enable PCI-INTX */
        pci_intx(pdev, 1);

        /*
	 * enable MSI-X or MSI-X, but no MSI-X for the 2432
	 */
        if (pdev->device != PCI_DEVICE_ID_QLOGIC_ISP2432 && pci_enable_msix(pdev, isp_msix, 3) == 0) {
            isp_pci->msix_enabled = 1;
            isp_pci->msix_vector[0] = isp_msix[0].vector;
            isp_pci->msix_vector[1] = isp_msix[1].vector;
            isp_pci->msix_vector[2] = isp_msix[2].vector;
        } else if (pci_enable_msi(pdev) == 0) {
            isp_pci->msi_enabled = 1;
        }

        /*
         * Is this a PCI-X card? If so, set max read byte count.
        */
        reg = pci_find_capability(pdev, PCI_CAP_ID_PCIX);
        if (reg) {
            uint16_t pxcmd;
            pci_read_config_word(pdev, reg + PCI_X_CMD, &pxcmd);
            pxcmd |= PCI_X_CMD_MAX_READ;    /* 4K READ BURST */
            pci_write_config_word(pdev, reg + PCI_X_CMD, pxcmd);
        }

        /*
         * Is this a PCI Express card? If so, set max read byte count.
         */
        reg = pci_find_capability(pdev, PCI_CAP_ID_EXP);
        if (reg) {
            uint16_t pectl;

            reg += 0x8;
            pci_read_config_word(pdev, reg + PCI_EXP_DEVCTL, &pectl);
            pectl &= ~PCI_EXP_DEVCTL_READRQ;
            pectl |= (5 << 12); /* 4K READ BURST */
            pci_write_config_word(pdev, reg + PCI_EXP_DEVCTL, pectl);
        }
    } else
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
    if (pci_enable_msi(pdev) == 0) {
        isp_pci->msi_enabled = 1;
    }
#endif

    /*
     * Disable the ROM.
     */
    pci_write_config_dword(pdev, PCI_ROM_ADDRESS, 0);

    /*
     * Set up stuff...
     */
    isp_pci->port = 0;
    isp_pci->vaddr = NULL;

    /*
     * If we prefer to map memory space over I/O, try that first.
     */
    if (isp_pci_mapmem & (1 << isp->isp_unit)) {
        if (map_isp_mem(isp_pci, cmd, mem_base) == 0) {
            if (map_isp_io(isp_pci, cmd, io_base) == 0) {
                isp_prt(isp, ISP_LOGERR, "%s", nomap);
                pci_release_regions(pdev);
                return (1);
            }
        }
    } else {
        if (map_isp_io(isp_pci, cmd, io_base) == 0) {
            if (map_isp_mem(isp_pci, cmd, mem_base) == 0) {
                isp_prt(isp, ISP_LOGERR, "%s", nomap);
                pci_release_regions(pdev);
                return (1);
            }
        }
    }
    if (isp_pci->vaddr) {
        isp_prt(isp, ISP_LOGCONFIG, "mapped memory 0x%lx at %p",  isp_pci->paddr, isp_pci->vaddr);
        host->io_port = isp_pci->paddr;
    } else {
        isp_prt(isp, ISP_LOGCONFIG, "mapped I/O space at 0x%lx", isp_pci->port);
        host->io_port = isp_pci->port;
    }
    host->irq = 0;
    host->max_channel = isp->isp_nchan - 1;
    fwname = NULL;
    isp->isp_revision = rev;
#ifndef    ISP_DISABLE_1020_SUPPORT
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP1020) {
        isp->isp_mdvec = &mdvec;
        isp->isp_type = ISP_HA_SCSI_UNKNOWN;
        if (isp->isp_mdvec->dv_ispfw == NULL) {
            fwname = "ql1040_fw.bin";
        }
    }
#endif
#ifndef    ISP_DISABLE_1080_SUPPORT
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP1080) {
        isp->isp_mdvec = &mdvec_1080;
        isp->isp_type = ISP_HA_SCSI_1080;
        if (isp->isp_mdvec->dv_ispfw == NULL) {
            fwname = "ql1080_fw.bin";
        }
    }
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP1240) {
        isp->isp_mdvec = &mdvec_1080;
        isp->isp_type = ISP_HA_SCSI_1240;
        host->max_channel = 1;
        if (isp->isp_mdvec->dv_ispfw == NULL) {
            fwname = "ql1080_fw.bin";
        }
    }
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP1280) {
        isp->isp_mdvec = &mdvec_1080;
        isp->isp_type = ISP_HA_SCSI_1280;
        host->max_channel = 1;
        if (isp->isp_mdvec->dv_ispfw == NULL) {
            fwname = "ql1080_fw.bin";
        }
    }
#endif
#ifndef    ISP_DISABLE_12160_SUPPORT
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP10160) {
        isp->isp_mdvec = &mdvec_12160;
        isp->isp_type = ISP_HA_SCSI_12160;
        if (isp->isp_mdvec->dv_ispfw == NULL) {
            fwname = "ql12160_fw.bin";
        }
    }
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP12160) {
        isp->isp_mdvec = &mdvec_12160;
        isp->isp_type = ISP_HA_SCSI_12160;
        host->max_channel = 1;
        if (isp->isp_mdvec->dv_ispfw == NULL) {
            fwname = "ql12160_fw.bin";
        }
    }
#endif
#ifndef    ISP_DISABLE_2100_SUPPORT
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP2100) {
        isp->isp_mdvec = &mdvec_2100;
        isp->isp_type = ISP_HA_FC_2100;
        if (isp->isp_mdvec->dv_ispfw == NULL)
            fwname = "ql2100_fw.bin";
    }
#endif
#ifndef    ISP_DISABLE_2200_SUPPORT
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP2200) {
        isp->isp_mdvec = &mdvec_2200;
        isp->isp_type = ISP_HA_FC_2200;
        if (isp->isp_mdvec->dv_ispfw == NULL)
            fwname = "ql2200_fw.bin";
    }
#endif
#ifndef    ISP_DISABLE_2300_SUPPORT
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP2300) {
        isp->isp_mdvec = &mdvec_2300;
        isp->isp_type = ISP_HA_FC_2300;
        if (isp->isp_mdvec->dv_ispfw == NULL)
            fwname = "ql2300_fw.bin";
    }
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP2312) {
        isp->isp_mdvec = &mdvec_2300;
        isp->isp_type = ISP_HA_FC_2312;
        if (isp->isp_mdvec->dv_ispfw == NULL)
            fwname = "ql2300_fw.bin";
    }
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP6312) {
        isp->isp_mdvec = &mdvec_2300;
        isp->isp_type = ISP_HA_FC_2312;
        if (isp->isp_mdvec->dv_ispfw == NULL)
            fwname = "ql2300_fw.bin";
    }
#endif
#ifndef    ISP_DISABLE_2322_SUPPORT
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP2322) {
        isp->isp_mdvec = &mdvec_2322;
        isp->isp_type = ISP_HA_FC_2322;
        if (isp->isp_mdvec->dv_ispfw == NULL)
            fwname = "ql2322_fw.bin";
    }
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP6322) {
        isp->isp_mdvec = &mdvec_2300;
        isp->isp_type = ISP_HA_FC_2322;
        if (isp->isp_mdvec->dv_ispfw == NULL)
            fwname = "ql2322_fw.bin";
    }
#endif
#ifndef    ISP_DISABLE_2400_SUPPORT
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP2422 || pdev->device == PCI_DEVICE_ID_QLOGIC_ISP2432) {
        isp->isp_mdvec = &mdvec_2400;
        isp->isp_type = ISP_HA_FC_2400;
        if (isp->isp_mdvec->dv_ispfw == NULL)
            fwname = "ql2400_fw.bin";
    }
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP2532) {
        isp->isp_mdvec = &mdvec_2500;
        isp->isp_type = ISP_HA_FC_2500;
        if (isp->isp_mdvec->dv_ispfw == NULL)
            fwname = "ql2500_fw.bin";
    }
#endif
    if (isp_pci->msix_enabled) {
        if (request_irq(isp_pci->msix_vector[0], isplinux_intr, 0, "isp_general", isp_pci)) {
            isp_prt(isp, ISP_LOGWARN, "unable to request MSI-X vector 0");
            pci_disable_msix(pdev);
            isp_pci->msix_enabled = 0;
        } else if (request_irq(isp_pci->msix_vector[1], isplinux_intr, 0, "isp_resp_q", isp_pci)) {
            isp_prt(isp, ISP_LOGWARN, "unable to request MSI-X vector 1");
            free_irq(isp_pci->msix_vector[0], isp_pci);
            pci_disable_msix(pdev);
            isp_pci->msix_enabled = 0;
        } else if (request_irq(isp_pci->msix_vector[2], isplinux_intr, 0, "isp_atio_q", isp_pci)) {
            isp_prt(isp, ISP_LOGWARN, "unable to request MSI-X vector 2");
            free_irq(isp_pci->msix_vector[0], isp_pci);
            free_irq(isp_pci->msix_vector[1], isp_pci);
            pci_disable_msix(pdev);
            isp_pci->msix_enabled = 0;
        } else {
            isp_pci->msix_enabled++;
        }
    }
    if (isp_pci->msix_enabled == 0) {
        if (isp_pci->msi_enabled == 0) {
            if (pci_enable_msi(pdev) == 0) {
                isp_pci->msi_enabled = 1;
            }
        }
        if (request_irq(pdev->irq, isplinux_intr, ISP_IRQ_FLAGS, isp->isp_name, isp_pci)) {
            isp_prt(isp, ISP_LOGERR, "could not snag irq %u (0x%x)", pdev->irq, pdev->irq);
            goto bad;
        }
        host->irq = pdev->irq;
    }

    /*
     * Get parameter area set up
     */
    isp->isp_osinfo.storep_amt = sizeof (isp_data) * isp->isp_nchan;
    if (IS_FC(isp)) {
        isp->isp_osinfo.param_amt = sizeof (fcparam) * isp->isp_nchan;
    } else {
        isp->isp_osinfo.param_amt = sizeof (sdparam) * isp->isp_nchan;
    }
    isp->isp_param = isp_kzalloc(isp->isp_osinfo.param_amt, GFP_KERNEL);
    isp->isp_osinfo.storep = isp_kzalloc(isp->isp_osinfo.storep_amt, GFP_KERNEL);
    if (isp->isp_param == NULL || isp->isp_osinfo.storep == NULL) {
        isp_prt(isp, ISP_LOGERR, "unable to allocate data structures");
        goto bad;
    }

    /*
     * All PCI QLogic cards really can do full 32 bit PCI transactions,
     * at least. But the older cards (1020s) have a 24 bit segment limit
     * where the dma address can't cross a 24 bit boundary. Until we get
     * have segment aware midlayer code, we'll set the DMA mask as if
     * we only could do 24 bit I/O for those cards.
     *
     * We can turn on highmem_io for all of them as we use the PCI dma mapping
     * API.
     */

    if (IS_1020(isp)) {
        if (pci_set_dma_mask(pdev, (u64)(0xffffffull))) {
                isp_prt(isp, ISP_LOGERR, "cannot set dma mask");
                goto bad;
        }
    } else if (pci_set_dma_mask(pdev, (u64) (0xffffffffffffffffull))) {
        if (pci_set_dma_mask(pdev, (u64) (0xffffffffull))) {
            isp_prt(isp, ISP_LOGERR, "cannot set dma mask");
            goto bad;
        }
    } else {
        isp->isp_osinfo.is_64bit_dma = 1;
    }

#if !defined(DISABLE_FW_LOADER) && (defined(CONFIG_FW_LOADER) || defined(CONFIG_FW_LOADER_MODULE))
    if (fwname) {
        if (request_firmware(&isp->isp_osinfo.fwp, fwname, &pdev->dev) == 0) {
            isp->isp_mdvec->dv_ispfw = isp->isp_osinfo.fwp->data;
            isp_prt(isp, ISP_LOGCONFIG, "using loaded firmware set \"%s\"", fwname);
            /*
             * On little endian machines convert a byte stream of firmware to native 16 or 32 bit format.
             */
#if BYTE_ORDER == LITTLE_ENDIAN
            if (IS_24XX(isp)) {
                uint32_t *ptr = (uint32_t *)isp->isp_osinfo.fwp->data;
                int i;
                for (i = 0; i < isp->isp_osinfo.fwp->size >> 2; i++) {
                    ptr[i] = ISP_SWAP32(isp, ptr[i]);
                }
            } else {
                uint16_t *ptr = (uint16_t *)isp->isp_osinfo.fwp->data;
                int i;
                for (i = 0; i < isp->isp_osinfo.fwp->size >> 1; i++) {
                    ptr[i] = ISP_SWAP16(isp, ptr[i]);
                }
            }
#endif
        } else {
            isp_prt(isp, ISP_LOGWARN, "unable to load firmware set \"%s\"", fwname);
            isp->isp_osinfo.fwp = NULL;
        }
    }
#else
    if (isp_vports) {
        if (IS_25XX(isp)) {
            isp->isp_mdvec->dv_ispfw = ISP_2500_MULTI_RISC_CODE;
        } else if (IS_24XX(isp)) {
            isp->isp_mdvec->dv_ispfw = ISP_2400_MULTI_RISC_CODE;
        }
    }
#endif

    if (isplinux_common_init(isp)) {
        isp_prt(isp, ISP_LOGERR, "isplinux_common_init failed");
        goto bad;
    }
    CREATE_ISP_DEV(isp, isp_class);
    return (0);
bad:
    if (isp->isp_param) {
        isp_kfree(isp->isp_param, isp->isp_osinfo.param_amt);
        isp->isp_param = NULL;
    }
    if (isp->isp_osinfo.storep) {
        isp_kfree(isp->isp_osinfo.storep, isp->isp_osinfo.storep_amt);
        isp->isp_osinfo.storep = NULL;
    }
#ifdef  CONFIG_FW_LOADER
    if (isp->isp_osinfo.fwp) {
        release_firmware(isp->isp_osinfo.fwp);
        isp->isp_osinfo.fwp = NULL;
    }
#endif
    ISP_DISABLE_INTS(isp);
    if (host->irq) {
        free_irq(host->irq, isp_pci);
        host->irq = 0;
    }
    if (isp_pci->msix_enabled) {
        if (isp_pci->msix_enabled > 1) {
            free_irq(isp_pci->msix_vector[0], isp_pci);
            free_irq(isp_pci->msix_vector[1], isp_pci);
            free_irq(isp_pci->msix_vector[2], isp_pci);
        }
        pci_disable_msix(isp_pci->pci_dev);
        isp_pci->msix_enabled = 0;
    }
    if (isp_pci->msi_enabled) {
        isp_pci->msi_enabled = 0;
        pci_disable_msi(isp_pci->pci_dev);
    }
    if (isp_pci->vaddr != NULL) {
        unmap_pci_mem(isp_pci, 0xff);
        isp_pci->vaddr = NULL;
    } else {
        release_region(isp_pci->port, 0xff);
        isp_pci->port = 0;
    }
    pci_release_regions(pdev);
    return (1);
}

static ISP_INLINE uint32_t
ispregrd(struct isp_pcisoftc *pcs, vm_offset_t offset)
{
    uint32_t rv;
    if (pcs->vaddr) {
        u8 *addr = pcs->vaddr;
        rv = readw(addr+offset);
    } else {
        offset += pcs->port;
        rv = inw(offset);
    }
    return (rv);
}

static ISP_INLINE void
ispregwr(struct isp_pcisoftc *pcs, vm_offset_t offset, uint32_t val)
{
    if (pcs->vaddr) {
        u8 *addr = pcs->vaddr;
        writew(val, addr+offset);
    } else {
        offset += pcs->port;
        outw(val, offset);
    }
}

static ISP_INLINE int
isp_pci_rd_debounced(struct isp_pcisoftc *pcs, vm_offset_t off, uint16_t *rp)
{
    uint16_t val0, val1;
    int i = 0;
    do {
        val0 = ispregrd(pcs, off);
        val1 = ispregrd(pcs, off);
    } while (val0 != val1 && ++i < 1000);
    if (val0 != val1) {
        return (1);
    }
    *rp = val0;
    return (0);
}

#define IspVirt2Off(a, x)   ((a)->poff[((x) & _BLK_REG_MASK) >> _BLK_REG_SHFT] + ((x) & 0xff))

#if !(defined(ISP_DISABLE_1020_SUPPORT) && defined(ISP_DISABLE_1080_SUPPORT) && defined(ISP_DISABLE_12160_SUPPORT) && defined(ISP_DISABLE_2100_SUPPORT) && defined(ISP_DISABLE_2200_SUPPORT))
static int
isp_pci_rd_isr(ispsoftc_t *isp, uint32_t *isrp, uint16_t *semap, uint16_t *mbp)
{
    struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
    uint16_t isr, sema;

    if (IS_2100(isp)) {
        if (isp_pci_rd_debounced(pcs, IspVirt2Off(pcs, BIU_ISR), &isr)) {
            return (0);
        }
        if (isp_pci_rd_debounced(pcs, IspVirt2Off(pcs, BIU_SEMA), &sema)) {
            return (0);
        }
    } else {
        isr = ispregrd(pcs, IspVirt2Off(pcs, BIU_ISR));
        sema = ispregrd(pcs, IspVirt2Off(pcs, BIU_SEMA));
    }
    isp_prt(isp, ISP_LOGDEBUG3, "ISR 0x%x SEMA 0x%x", isr, sema);
    isr &= INT_PENDING_MASK(isp);
    sema &= BIU_SEMA_LOCK;
    if (isr == 0 && sema == 0) {
        return (0);
    }
    *isrp = isr;
    if ((*semap = sema) != 0) {
        if (IS_2100(isp)) {
            if (isp_pci_rd_debounced(pcs, IspVirt2Off(pcs, OUTMAILBOX0), mbp)) {
                return (0);
            }
        } else {
            *mbp = ispregrd(pcs, IspVirt2Off(pcs, OUTMAILBOX0));
        }
    }
    return (1);
}
#endif

#if !(defined(ISP_DISABLE_2300_SUPPORT) && defined(ISP_DISABLE_2322_SUPPORT) && defined(ISP_DISABLE_2400_SUPPORT))
static ISP_INLINE uint32_t
ispregrd32(struct isp_pcisoftc *pcs, vm_offset_t offset)
{
    uint32_t rv;
    if (pcs->vaddr) {
        u8 *addr = pcs->vaddr;
        rv = readl(addr+offset);
    } else {
        offset += pcs->port;
        rv = inl(offset);
    }
    return (rv);
}
#endif

#if !(defined(ISP_DISABLE_2300_SUPPORT) && defined(ISP_DISABLE_2322_SUPPORT))
static int
isp_pci_rd_isr_2300(ispsoftc_t *isp, uint32_t *isrp, uint16_t *semap, uint16_t *mbox0p)
{
    struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
    uint32_t hccr;
    uint32_t r2hisr;

    if ((ispregrd(pcs, IspVirt2Off(pcs, BIU_ISR)) & BIU2100_ISR_RISC_INT) == 0) {
        *isrp = 0;
        return (0);
    }

    r2hisr = ispregrd32(pcs, IspVirt2Off(pcs, BIU_R2HSTSLO));
    isp_prt(isp, ISP_LOGDEBUG3, "RISC2HOST ISR 0x%x", r2hisr);
    if ((r2hisr & BIU_R2HST_INTR) == 0) {
        *isrp = 0;
        return (0);
    }
    switch (r2hisr & BIU_R2HST_ISTAT_MASK) {
    case ISPR2HST_ROM_MBX_OK:
    case ISPR2HST_ROM_MBX_FAIL:
    case ISPR2HST_MBX_OK:
    case ISPR2HST_MBX_FAIL:
    case ISPR2HST_ASYNC_EVENT:
        *isrp = r2hisr & 0xffff;
        *mbox0p = (r2hisr >> 16);
        *semap = 1;
        return (1);
    case ISPR2HST_RIO_16:
        *isrp = r2hisr & 0xffff;
        *mbox0p = ASYNC_RIO1;
        *semap = 1;
        return (1);
    case ISPR2HST_FPOST:
        *isrp = r2hisr & 0xffff;
        *mbox0p = ASYNC_CMD_CMPLT;
        *semap = 1;
        return (1);
    case ISPR2HST_FPOST_CTIO:
        *isrp = r2hisr & 0xffff;
        *mbox0p = ASYNC_CTIO_DONE;
        *semap = 1;
        return (1);
    case ISPR2HST_RSPQ_UPDATE:
        *isrp = r2hisr & 0xffff;
        *mbox0p = 0;
        *semap = 0;
        return (1);
    default:
        hccr = ISP_READ(isp, HCCR);
        if (hccr & HCCR_PAUSE) {
            ISP_WRITE(isp, HCCR, HCCR_RESET);
            isp_prt(isp, ISP_LOGERR, "RISC paused at interrupt (%x->%x)", hccr, ISP_READ(isp, HCCR));
        } else {
            isp_prt(isp, ISP_LOGERR, "unknown interrerupt 0x%x", r2hisr);
        }
        return (0);
    }
}
#endif

#if !defined(ISP_DISABLE_2400_SUPPORT)
static ISP_INLINE void
ispregwr32(struct isp_pcisoftc *pcs, vm_offset_t offset, uint32_t val)
{
    if (pcs->vaddr) {
        u8 *addr = pcs->vaddr;
        writel(val, addr+offset);
    } else {
        offset += pcs->port;
        outl(val, offset);
    }
}

static uint32_t
isp_pci_rd_reg_2400(ispsoftc_t *isp, int regoff)
{
    struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
    uint32_t rv;
    int block = regoff & _BLK_REG_MASK;

    switch (block) {
    case BIU_BLOCK:
        break;
    case MBOX_BLOCK:
        return (ispregrd(pcs, IspVirt2Off(pcs, regoff)));
    case SXP_BLOCK:
        isp_prt(isp, ISP_LOGWARN, "SXP_BLOCK read at 0x%x", regoff);
        return (0xffffffff);
    case RISC_BLOCK:
        isp_prt(isp, ISP_LOGWARN, "RISC_BLOCK read at 0x%x", regoff);
        return (0xffffffff);
    case DMA_BLOCK:
        isp_prt(isp, ISP_LOGWARN, "DMA_BLOCK read at 0x%x", regoff);
        return (0xffffffff);
    default:
        isp_prt(isp, ISP_LOGWARN, "unknown block read at 0x%x", regoff);
        return (0xffffffff);
    }


    switch (regoff) {
    case BIU2400_FLASH_ADDR:
    case BIU2400_FLASH_DATA:
    case BIU2400_ICR:
    case BIU2400_ISR:
    case BIU2400_CSR:
    case BIU2400_REQINP:
    case BIU2400_REQOUTP:
    case BIU2400_RSPINP:
    case BIU2400_RSPOUTP:
    case BIU2400_PRI_REQINP:
    case BIU2400_PRI_REQOUTP:
    case BIU2400_ATIO_RSPINP:
    case BIU2400_ATIO_RSPOUTP:
    case BIU2400_HCCR:
    case BIU2400_GPIOD:
    case BIU2400_GPIOE:
    case BIU2400_HSEMA:
        rv = ispregrd32(pcs, IspVirt2Off(pcs, regoff));
        break;
    case BIU2400_R2HSTSLO:
        rv = ispregrd32(pcs, IspVirt2Off(pcs, regoff));
        break;
    case BIU2400_R2HSTSHI:
        rv = ispregrd32(pcs, IspVirt2Off(pcs, regoff)) >> 16;
        break;
    default:
        isp_prt(isp, ISP_LOGERR, "isp_pci_rd_reg_2400: unknown offset %x", regoff);
        rv = 0xffffffff;
        break;
    }
    return (rv);
}

static void
isp_pci_wr_reg_2400(ispsoftc_t *isp, int regoff, uint32_t val)
{
    struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
    int block = regoff & _BLK_REG_MASK;
    volatile int junk;

    switch (block) {
    case BIU_BLOCK:
        break;
    case MBOX_BLOCK:
        ispregwr(pcs, IspVirt2Off(pcs, regoff), val);
        junk = ispregrd(pcs, IspVirt2Off(pcs, regoff));
        return;
    case SXP_BLOCK:
        isp_prt(isp, ISP_LOGWARN, "SXP_BLOCK write at 0x%x", regoff);
        return;
    case RISC_BLOCK:
        isp_prt(isp, ISP_LOGWARN, "RISC_BLOCK write at 0x%x", regoff);
        return;
    case DMA_BLOCK:
        isp_prt(isp, ISP_LOGWARN, "DMA_BLOCK write at 0x%x", regoff);
        return;
    default:
        break;
    }

    switch (regoff) {
    case BIU2400_FLASH_ADDR:
    case BIU2400_FLASH_DATA:
    case BIU2400_ICR:
    case BIU2400_ISR:
    case BIU2400_CSR:
    case BIU2400_REQINP:
    case BIU2400_REQOUTP:
    case BIU2400_RSPINP:
    case BIU2400_RSPOUTP:
    case BIU2400_PRI_REQINP:
    case BIU2400_PRI_REQOUTP:
    case BIU2400_ATIO_RSPINP:
    case BIU2400_ATIO_RSPOUTP:
    case BIU2400_HCCR:
    case BIU2400_GPIOD:
    case BIU2400_GPIOE:
    case BIU2400_HSEMA:
        ispregwr32(pcs, IspVirt2Off(pcs, regoff), val);
        junk = ispregrd32(pcs, IspVirt2Off(pcs, regoff));
        break;
    default:
        isp_prt(isp, ISP_LOGERR, "isp_pci_wr_reg_2400: bad offset 0x%x", regoff);
        break;
    }
}

static int
isp_pci_rd_isr_2400(ispsoftc_t *isp, uint32_t *isrp, uint16_t *semap, uint16_t *mbox0p)
{
    struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
    uint32_t r2hisr;
    volatile int junk;

    r2hisr = ispregrd32(pcs, IspVirt2Off(pcs, BIU2400_R2HSTSLO));
    isp_prt(isp, ISP_LOGDEBUG3, "RISC2HOST ISR 0x%x", r2hisr);
    if ((r2hisr & BIU2400_R2HST_INTR) == 0) {
        *isrp = 0;
        return (0);
    }
    switch (r2hisr & BIU2400_R2HST_ISTAT_MASK) {
    case ISP2400R2HST_ROM_MBX_OK:
    case ISP2400R2HST_ROM_MBX_FAIL:
    case ISP2400R2HST_MBX_OK:
    case ISP2400R2HST_MBX_FAIL:
    case ISP2400R2HST_ASYNC_EVENT:
        *isrp = r2hisr & 0xffff;
        *mbox0p = (r2hisr >> 16);
        *semap = 1;
        return (1);
    case ISP2400R2HST_RSPQ_UPDATE:
    case ISP2400R2HST_ATIO_RSPQ_UPDATE:
    case ISP2400R2HST_ATIO_RQST_UPDATE:
        *isrp = r2hisr & 0xffff;
        *mbox0p = 0;
        *semap = 0;
        return (1);
    default:
        ispregwr32(pcs, IspVirt2Off(pcs, BIU2400_HCCR), HCCR_2400_CMD_CLEAR_RISC_INT);
        junk = ispregrd32(pcs, IspVirt2Off(pcs, BIU2400_HCCR));
        isp_prt(isp, ISP_LOGERR, "unknown interrupt 0x%x", r2hisr);
        return (0);
    }
}
#endif

static uint32_t
isp_pci_rd_reg(ispsoftc_t *isp, int regoff)
{
    uint32_t rv, oldconf = 0;
    struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
    volatile int junk;

    if ((regoff & _BLK_REG_MASK) == SXP_BLOCK) {
        /*
         * We will assume that someone has paused the RISC processor.
         */
        oldconf = ispregrd(pcs, IspVirt2Off(pcs, BIU_CONF1));
        ispregwr(pcs, IspVirt2Off(pcs, BIU_CONF1), oldconf | BIU_PCI_CONF1_SXP);
        junk = ispregrd(pcs, IspVirt2Off(pcs, BIU_CONF1));
    }
    rv = ispregrd(pcs, IspVirt2Off(pcs, regoff));
    if ((regoff & _BLK_REG_MASK) == SXP_BLOCK) {
        ispregwr(pcs, IspVirt2Off(pcs, BIU_CONF1), oldconf);
        junk = ispregrd(pcs, IspVirt2Off(pcs, BIU_CONF1));
    }
    return (rv);
}

static void
isp_pci_wr_reg(ispsoftc_t *isp, int regoff, uint32_t val)
{
    struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
    uint32_t oldconf = 0;
    volatile int junk;

    if ((regoff & _BLK_REG_MASK) == SXP_BLOCK) {
        /*
         * We will assume that someone has paused the RISC processor.
         */
        oldconf = ispregrd(pcs, IspVirt2Off(pcs, BIU_CONF1));
        ispregwr(pcs, IspVirt2Off(pcs, BIU_CONF1), oldconf | BIU_PCI_CONF1_SXP);
        junk = ispregrd(pcs, IspVirt2Off(pcs, BIU_CONF1));
    }
    ispregwr(pcs, IspVirt2Off(pcs, regoff), val);
    junk = ispregrd(pcs, IspVirt2Off(pcs, regoff));
    if ((regoff & _BLK_REG_MASK) == SXP_BLOCK) {
        ispregwr(pcs, IspVirt2Off(pcs, BIU_CONF1), oldconf);
        junk = ispregrd(pcs, IspVirt2Off(pcs, BIU_CONF1));
    }
}

#if !(defined(ISP_DISABLE_1080_SUPPORT) && defined(ISP_DISABLE_12160_SUPPORT))
static uint32_t
isp_pci_rd_reg_1080(ispsoftc_t *isp, int regoff)
{
    struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
    uint32_t rv, oldconf = 0;
    volatile int junk;

    if ((regoff & _BLK_REG_MASK) == SXP_BLOCK || (regoff & _BLK_REG_MASK) == (SXP_BLOCK|SXP_BANK1_SELECT)) {
        uint32_t tmpconf;
        /*
         * We will assume that someone has paused the RISC processor.
         */
        oldconf = ispregrd(pcs,  IspVirt2Off(pcs, BIU_CONF1));
        tmpconf = oldconf & ~BIU_PCI1080_CONF1_DMA;
        if (IS_1280(isp)) {
            if (regoff & SXP_BANK1_SELECT) {
                tmpconf |= BIU_PCI1080_CONF1_SXP0;
            } else {
                tmpconf |= BIU_PCI1080_CONF1_SXP1;
            }
        } else {
            tmpconf |= BIU_PCI1080_CONF1_SXP0;
        }
        ispregwr(pcs,  IspVirt2Off(pcs, BIU_CONF1), tmpconf);
        junk = ispregrd(pcs, IspVirt2Off(pcs, BIU_CONF1));
    } else if ((regoff & _BLK_REG_MASK) == DMA_BLOCK) {
        oldconf = ispregrd(pcs,  IspVirt2Off(pcs, BIU_CONF1));
        ispregwr(pcs, IspVirt2Off(pcs, BIU_CONF1), oldconf | BIU_PCI1080_CONF1_DMA);
        junk = ispregrd(pcs, IspVirt2Off(pcs, BIU_CONF1));
    }
    rv = ispregrd(pcs, IspVirt2Off(pcs, regoff));
    if (oldconf) {
        ispregwr(pcs, IspVirt2Off(pcs, BIU_CONF1), oldconf);
        junk = ispregrd(pcs, IspVirt2Off(pcs, BIU_CONF1));
    }
    return (rv);
}

static void
isp_pci_wr_reg_1080(ispsoftc_t *isp, int regoff, uint32_t val)
{
    struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
    uint32_t oldconf = 0;
    volatile int junk;

    if ((regoff & _BLK_REG_MASK) == SXP_BLOCK || (regoff & _BLK_REG_MASK) == (SXP_BLOCK|SXP_BANK1_SELECT)) {
        uint32_t tmpconf;
        /*
         * We will assume that someone has paused the RISC processor.
         */
        oldconf = ispregrd(pcs,  IspVirt2Off(pcs, BIU_CONF1));
        tmpconf = oldconf & ~BIU_PCI1080_CONF1_DMA;
        if (IS_1280(isp)) {
            if (regoff & SXP_BANK1_SELECT) {
                tmpconf |= BIU_PCI1080_CONF1_SXP0;
            } else {
                tmpconf |= BIU_PCI1080_CONF1_SXP1;
            }
        } else {
            tmpconf |= BIU_PCI1080_CONF1_SXP0;
        }
        ispregwr(pcs,  IspVirt2Off(pcs, BIU_CONF1), tmpconf);
        junk = ispregrd(pcs, IspVirt2Off(pcs, BIU_CONF1));
    } else if ((regoff & _BLK_REG_MASK) == DMA_BLOCK) {
        oldconf = ispregrd(pcs,  IspVirt2Off(pcs, BIU_CONF1));
        ispregwr(pcs, IspVirt2Off(pcs, BIU_CONF1), oldconf | BIU_PCI1080_CONF1_DMA);
        junk = ispregrd(pcs, IspVirt2Off(pcs, BIU_CONF1));
    }
    ispregwr(pcs, IspVirt2Off(pcs, regoff), val);
    junk = ispregrd(pcs, IspVirt2Off(pcs, regoff));
    if (oldconf) {
        ispregwr(pcs, IspVirt2Off(pcs, BIU_CONF1), oldconf);
        junk = ispregrd(pcs, IspVirt2Off(pcs, BIU_CONF1));
    }
}
#endif

/*
 * We enter with the IRQs disabled.
 *
 * This makes 2.6 unhappy when we try to allocate memory.
 *
 * The only time we need to allocate memory is when we're
 * setting things up, and in that case the chip isn't really
 * quite active yet.
 */
static int
isp_pci_mbxdma(ispsoftc_t *isp)
{
    fcparam *fcp;
    int i;
    struct isp_pcisoftc *pcs;

    if (isp->isp_xflist) {
        return (0);
    }
    isp->isp_osinfo.mcorig = isp->isp_maxcmds;

    pcs = (struct isp_pcisoftc *) isp;

    ISP_DROP_LK_SOFTC(isp);
    if (isp->isp_xflist == NULL) {
        size_t amt = isp->isp_osinfo.mcorig * sizeof (XS_T **);
        isp->isp_xflist = isp_kzalloc(amt, GFP_KERNEL);
        if (isp->isp_xflist == NULL) {
            isp_prt(isp, ISP_LOGERR, "unable to allocate xflist array");
            goto bad;
        }
    }
#ifdef    ISP_TARGET_MODE
    if (isp->isp_tgtlist == NULL) {
        size_t amt = isp->isp_osinfo.mcorig * sizeof (void **);
        isp->isp_tgtlist = isp_kzalloc(amt, GFP_KERNEL);
        if (isp->isp_tgtlist == NULL) {
            isp_prt(isp, ISP_LOGERR, "unable to allocate tgtlist array");
            goto bad;
        }
    }
    if (IS_24XX(isp) && isp->isp_atioq == NULL) {
        dma_addr_t busaddr;
        isp->isp_atioq = pci_alloc_consistent(pcs->pci_dev, RESULT_QUEUE_LEN(isp) * QENTRY_LEN, &busaddr);
        if (isp->isp_atioq == NULL) {
            isp_prt(isp, ISP_LOGERR, "unable to allocate atio queue");
            goto bad;
        }
        isp->isp_atioq_dma = busaddr;
        if (isp->isp_atioq_dma & 0x3f) {
            isp_prt(isp, ISP_LOGERR, "ATIO Queue not on 64 byte boundary");
            goto bad;
        }
        memset(isp->isp_atioq, 0, ISP_QUEUE_SIZE(RESULT_QUEUE_LEN(isp)));
    }
#endif
    if (isp->isp_rquest == NULL) {
        dma_addr_t busaddr;
        isp->isp_rquest = pci_alloc_consistent(pcs->pci_dev, RQUEST_QUEUE_LEN(isp) * QENTRY_LEN, &busaddr);
        if (isp->isp_rquest == NULL) {
            isp_prt(isp, ISP_LOGERR, "unable to allocate request queue");
            goto bad;
        }
        isp->isp_rquest_dma = busaddr;
        if (isp->isp_rquest_dma & 0x3f) {
            isp_prt(isp, ISP_LOGERR, "Request Queue not on 64 byte boundary");
            goto bad;
        }
        memset(isp->isp_rquest, 0, ISP_QUEUE_SIZE(RQUEST_QUEUE_LEN(isp)));
    }

    if (isp->isp_result == NULL) {
        dma_addr_t busaddr;
        isp->isp_result = pci_alloc_consistent(pcs->pci_dev, RESULT_QUEUE_LEN(isp) * QENTRY_LEN, &busaddr);
        if (isp->isp_result == NULL) {
            isp_prt(isp, ISP_LOGERR, "unable to allocate result queue");
            goto bad;
        }
        isp->isp_result_dma = busaddr;
        if (isp->isp_rquest_dma & 0x3f) {
            isp_prt(isp, ISP_LOGERR, "Result Queue not on 64 byte boundary");
            goto bad;
        }
        memset(isp->isp_result, 0, ISP_QUEUE_SIZE(RESULT_QUEUE_LEN(isp)));
    }

    if (IS_FC(isp)) {
        for (i = 0; i < isp->isp_nchan; i++) {
            fcp = FCPARAM(isp, i);
            if (fcp->isp_scratch == NULL) {
                dma_addr_t busaddr;
                fcp->isp_scratch = pci_alloc_consistent(pcs->pci_dev, ISP_FC_SCRLEN, &busaddr);
                if (fcp->isp_scratch == NULL) {
                    isp_prt(isp, ISP_LOGERR, "unable to allocate scratch space");
                    goto bad;
                }
                fcp->isp_scdma = busaddr;
                memset(fcp->isp_scratch, 0, ISP_FC_SCRLEN);
                if (fcp->isp_scdma & 0x7) {
                    isp_prt(isp, ISP_LOGERR, "scratch space not 8 byte aligned");
                    goto bad;
                }
            }
        }
    }
    ISP_IGET_LK_SOFTC(isp);
    return (0);

bad:
    if (isp->isp_xflist) {
        isp_kfree(isp->isp_xflist, isp->isp_osinfo.mcorig * sizeof (XS_T **));
        isp->isp_xflist = NULL;
    }
#ifdef    ISP_TARGET_MODE
    if (isp->isp_tgtlist) {
        isp_kfree(isp->isp_tgtlist, isp->isp_osinfo.mcorig * sizeof (void **));
        isp->isp_tgtlist = NULL;
    }
    if (isp->isp_atioq) {
        pci_free_consistent(pcs->pci_dev, RESULT_QUEUE_LEN(isp) * QENTRY_LEN, isp->isp_atioq, isp->isp_atioq_dma);
        isp->isp_atioq = NULL;
        isp->isp_atioq_dma = 0;
    }
#endif
    if (isp->isp_rquest) {
        pci_free_consistent(pcs->pci_dev, RQUEST_QUEUE_LEN(isp) * QENTRY_LEN, isp->isp_rquest, isp->isp_rquest_dma);
        isp->isp_rquest = NULL;
        isp->isp_rquest_dma = 0;
    }
    if (isp->isp_result) {
        pci_free_consistent(pcs->pci_dev, RESULT_QUEUE_LEN(isp) * QENTRY_LEN, isp->isp_result, isp->isp_result_dma);
        isp->isp_result = NULL;
        isp->isp_result_dma = 0;
    }
    if (IS_FC(isp)) {
        for (i = 0; i < isp->isp_nchan; i++) {
            fcp = FCPARAM(isp, i);
            if (fcp->isp_scratch) {
                    pci_free_consistent(pcs->pci_dev, ISP_FC_SCRLEN, fcp->isp_scratch, fcp->isp_scdma);
                    fcp->isp_scratch = NULL;
                    fcp->isp_scdma = 0;
            }
        }
    }
    ISP_IGET_LK_SOFTC(isp);
    return (1);
}

#ifdef    ISP_TARGET_MODE
static int
isp_pci_dmasetup_tgt(ispsoftc_t *isp, tmd_xact_t *xact, void *fqe)
{
    struct scatterlist *sg = NULL;
    isp_ddir_t ddir;
    uint32_t nseg;
    int ret;

    switch (((isphdr_t *)fqe)->rqs_entry_type) {
    case RQSTYPE_CTIO:
        if ((((ct_entry_t *)fqe)->ct_flags & CT_DATAMASK) == CT_DATA_OUT) {
            ddir = ISP_FROM_DEVICE;
        } else if ((((ct_entry_t *)fqe)->ct_flags & CT_DATAMASK) == CT_DATA_IN) {
            ddir = ISP_TO_DEVICE;
        } else {
            ddir = ISP_NOXFR;
        }
        break;
    case RQSTYPE_CTIO2:
        if ((((ct2_entry_t *)fqe)->ct_flags & CT2_DATAMASK) == CT2_DATA_OUT) {
            ddir = ISP_FROM_DEVICE;
        } else if ((((ct2_entry_t *)fqe)->ct_flags & CT2_DATAMASK) == CT2_DATA_IN) {
            ddir = ISP_TO_DEVICE;
        } else {
            ddir = ISP_NOXFR;
        }
        if (ddir != ISP_NOXFR && isp->isp_osinfo.is_64bit_dma) {
            ((isphdr_t *)fqe)->rqs_entry_type = RQSTYPE_CTIO3;
        }
        break;
    case RQSTYPE_CTIO7:
        if (((ct7_entry_t *)fqe)->ct_flags & CT7_DATA_OUT) {
            ddir = ISP_FROM_DEVICE;
        } else if (((ct7_entry_t *)fqe)->ct_flags & CT7_DATA_IN) {
            ddir = ISP_TO_DEVICE;
        } else {
            ddir = ISP_NOXFR;
        }
        break;
    default:
        xact->td_error = -EINVAL;
        return (CMD_COMPLETE);
    }

    if (ddir != ISP_NOXFR) {
        struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
        uint32_t xfcnt;

        sg = xact->td_data;
        xfcnt = xact->td_xfrlen;
        nseg = 0;
        while (xfcnt > 0) {
            xfcnt -= sg->length;
            sg++;
            nseg++;
        }
        sg = xact->td_data;
        nseg = pci_map_sg(pcs->pci_dev, sg, nseg, ddir == ISP_TO_DEVICE? PCI_DMA_TODEVICE : PCI_DMA_FROMDEVICE);
    } else {
        sg = NULL;
        nseg = 0;
    }
    if (isp->isp_osinfo.is_64bit_dma) {
        if (nseg >= ISP_NSEG64_MAX) {
            isp_prt(isp, ISP_LOGERR, "number of segments (%d) exceed maximum we can support (%d)", nseg, ISP_NSEG64_MAX);
            xact->td_error = -EFAULT;
            return (CMD_COMPLETE);
        }
    } else if (nseg >= ISP_NSEG_MAX) {
        isp_prt(isp, ISP_LOGERR, "number of segments (%d) exceed maximum we can support (%d)", nseg, ISP_NSEG_MAX);
        xact->td_error = -EFAULT;
        return (CMD_COMPLETE);
    }
    ret = isp_send_tgt_cmd(isp, fqe, sg, nseg, xact->td_xfrlen, ddir, xact->td_cmd->cd_sense, TMD_SENSELEN);
    if (ret == CMD_QUEUED) {
        int bin;
        if (xact->td_xfrlen <= 1024) {
            bin = 0;
        } else if (xact->td_xfrlen <= 4096) {
            bin = 1;
        } else if (xact->td_xfrlen <= 32768) {
            bin = 2;
        } else if (xact->td_xfrlen <= 65536) {
            bin = 3;
        } else if (xact->td_xfrlen <= 131372) {
            bin = 4;
        } else if (xact->td_xfrlen <= 262144) {
            bin = 5;
        } else if (xact->td_xfrlen <= 524288) {
            bin = 6;
        } else {
            bin = 7;
        }
        isp->isp_osinfo.bins[bin]++;
    }
    return (ret);
}
#endif

static int
isp_pci_dmasetup(ispsoftc_t *isp, Scsi_Cmnd *Cmnd, void *fqe)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
    struct scatterlist one_shot;
#endif
    struct scatterlist *sg = NULL;
    isphdr_t *hp;
    isp_ddir_t ddir;
    uint32_t nseg;
    int ret;

    hp = fqe;
    switch (hp->rqs_entry_type) {
#ifdef    ISP_TARGET_MODE
    case RQSTYPE_CTIO:
    case RQSTYPE_CTIO2:
    case RQSTYPE_CTIO7:
        return (isp_pci_dmasetup_tgt(isp, (tmd_xact_t *)Cmnd, fqe));
#endif
    case RQSTYPE_REQUEST:
        if (isp->isp_osinfo.is_64bit_dma) {
            hp->rqs_entry_type = RQSTYPE_A64;
        }
        break;
    case RQSTYPE_T2RQS:
        if (isp->isp_osinfo.is_64bit_dma) {
            hp->rqs_entry_type = RQSTYPE_T3RQS;
        }
        break;
    case RQSTYPE_T7RQS:
        break;
    default:
        isp_prt(isp, ISP_LOGERR, "%s: unknwon type 0x%x", __func__, hp->rqs_entry_type);
        return (CMD_COMPLETE);
    }

    if (Cmnd->sc_data_direction == SCSI_DATA_NONE) {
        ddir = ISP_NOXFR;
    } else if (Cmnd->sc_data_direction == SCSI_DATA_WRITE) {
        ddir = ISP_TO_DEVICE;
    } else {
        ddir = ISP_FROM_DEVICE;
    }

    if (ddir != ISP_NOXFR) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
        if ((nseg = Cmnd->use_sg) == 0) {
            struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
            nseg = 1;
            sg = &one_shot;
            sg_dma_address(sg) =  pci_map_single(pcs->pci_dev, Cmnd->request_buffer, XS_XFRLEN(Cmnd), scsi_to_pci_dma_dir(Cmnd->sc_data_direction));
            sg_dma_len(sg) = XS_XFRLEN(Cmnd);
            QLA_HANDLE(Cmnd) = (DMA_HTYPE_T) sg_dma_address(sg);
        } else {
            struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
            sg = (struct scatterlist *) Cmnd->request_buffer;
            nseg = pci_map_sg(pcs->pci_dev, sg, Cmnd->use_sg, scsi_to_pci_dma_dir(Cmnd->sc_data_direction));
        }
        if (nseg == 0) {
            isp_prt(isp, ISP_LOGWARN, "%s: unable to dma map request", __func__);
            XS_SETERR(Cmnd, HBA_BOTCH);
            return (CMD_COMPLETE);
        }
#else
        nseg = scsi_dma_map(Cmnd);
        if (nseg <= 0) {
            isp_prt(isp, ISP_LOGWARN, "%s: unable to dma map request", __func__);
            XS_SETERR(Cmnd, HBA_BOTCH);
            return (CMD_COMPLETE);
        }
        sg = scsi_sglist(Cmnd);
#endif
    } else {
        sg = NULL;
        nseg = 0;
    }
    if (isp->isp_osinfo.is_64bit_dma) {
        if (nseg >= ISP_NSEG64_MAX) {
            isp_prt(isp, ISP_LOGERR, "number of segments (%d) exceed maximum we can support (%d)", nseg, ISP_NSEG64_MAX);
            XS_SETERR(Cmnd, HBA_BOTCH);
            return (CMD_COMPLETE);
        }
    } else if (nseg >= ISP_NSEG_MAX) {
        isp_prt(isp, ISP_LOGERR, "number of segments (%d) exceed maximum we can support (%d)", nseg, ISP_NSEG_MAX);
        XS_SETERR(Cmnd, HBA_BOTCH);
        return (CMD_COMPLETE);
    }
    ret = isp_send_cmd(isp, fqe, sg, nseg, XS_XFRLEN(Cmnd), ddir);
    if (ret == CMD_QUEUED) {
        int bin;
        if (XS_XFRLEN(Cmnd) <= 1024) {
            bin = 0;
        } else if (XS_XFRLEN(Cmnd) <= 4096) {
            bin = 1;
        } else if (XS_XFRLEN(Cmnd) <= 32768) {
            bin = 2;
        } else if (XS_XFRLEN(Cmnd) <= 65536) {
            bin = 3;
        } else if (XS_XFRLEN(Cmnd) <= 131372) {
            bin = 4;
        } else if (XS_XFRLEN(Cmnd) <= 262144) {
            bin = 5;
        } else if (XS_XFRLEN(Cmnd) <= 524288) {
            bin = 6;
        } else {
            bin = 7;
        }
        isp->isp_osinfo.bins[bin]++;
    } else if (ret == CMD_COMPLETE) {
        XS_SETERR(Cmnd, HBA_BOTCH);
    }
    return (ret);
}

static void
isp_pci_dmateardown(ispsoftc_t *isp, Scsi_Cmnd *Cmnd, uint32_t handle)
{
#ifdef    ISP_TARGET_MODE
    /*
     * The argument passed may not be a Cmnd pointer- this is the
     * safest way to keep the two w/o redoing our internal apis.
     */
    if (IS_TARGET_HANDLE(handle)) {
        struct isp_pcisoftc *pcs = (struct isp_pcisoftc *)isp;
        tmd_xact_t *xact = (tmd_xact_t *) Cmnd;
        tmd_cmd_t *tmd = xact? xact->td_cmd : NULL;
        int nseg = tmd? tmd->cd_nseg :  0;
        if (nseg && xact->td_data) {
            isp_prt(isp, ISP_LOGTDEBUG2, "[%llx]: pci_unmap %d segments at %p for handle 0x%x", tmd->cd_tagval, nseg, xact->td_data, handle);
            pci_unmap_sg(pcs->pci_dev, xact->td_data, nseg, (xact->td_hflags & TDFH_DATA_IN)? PCI_DMA_TODEVICE : PCI_DMA_FROMDEVICE);
        }
    } else
#endif
    if (Cmnd->sc_data_direction != SCSI_DATA_NONE) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
        struct isp_pcisoftc *pcs = (struct isp_pcisoftc *)isp;
        if (Cmnd->use_sg) {
            pci_unmap_sg(pcs->pci_dev, (struct scatterlist *)Cmnd->request_buffer, Cmnd->use_sg, scsi_to_pci_dma_dir(Cmnd->sc_data_direction));
        } else if (XS_XFRLEN(Cmnd)) {
            XS_DMA_ADDR_T dhandle = (XS_DMA_ADDR_T) QLA_HANDLE(Cmnd);
            pci_unmap_single(pcs->pci_dev, dhandle, XS_XFRLEN(Cmnd), scsi_to_pci_dma_dir(Cmnd->sc_data_direction));
        }
#else
        scsi_dma_unmap(Cmnd);
#endif
    }
}

static void
isp_pci_reset0(ispsoftc_t *isp)
{
    ISP_DISABLE_INTS(isp);
    isp->mbintsok = 0;
    isp->intsok = 0;
}

static void
isp_pci_reset1(ispsoftc_t *isp)
{
    if (!IS_24XX(isp)) {
        isp_pci_wr_reg(isp, HCCR, PCI_HCCR_CMD_BIOS);
    }
    ISP_ENABLE_INTS(isp);
    isp->intsok = 1;
    /*
     * We used to enable mbintsok here.
     * This seemed to nuke 24XX cards in some, but not all cases.
     */
}

static void
isp_pci_dumpregs(ispsoftc_t *isp, const char *msg)
{
    struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
    uint16_t csr;

    pci_read_config_word(pcs->pci_dev, PCI_COMMAND, &csr);
    printk("%s: ", isp->isp_name);
    if (msg) {
        printk("%s\n", msg);
    }
    if (IS_SCSI(isp)) {
        printk("    biu_conf1=%x", ISP_READ(isp, BIU_CONF1));
    } else {
        printk("    biu_csr=%x", ISP_READ(isp, BIU2100_CSR));
    }
    printk(" biu_icr=%x biu_isr=%x biu_sema=%x ", ISP_READ(isp, BIU_ICR), ISP_READ(isp, BIU_ISR), ISP_READ(isp, BIU_SEMA));
    printk("risc_hccr=%x\n", ISP_READ(isp, HCCR));
    if (IS_SCSI(isp)) {
        ISP_WRITE(isp, HCCR, HCCR_CMD_PAUSE);
        printk("    cdma_conf=%x cdma_sts=%x cdma_fifostat=%x\n", ISP_READ(isp, CDMA_CONF), ISP_READ(isp, CDMA_STATUS), ISP_READ(isp, CDMA_FIFO_STS));
        printk("    ddma_conf=%x ddma_sts=%x ddma_fifostat=%x\n", ISP_READ(isp, DDMA_CONF), ISP_READ(isp, DDMA_STATUS), ISP_READ(isp, DDMA_FIFO_STS));
        printk("    sxp_int=%x sxp_gross=%x sxp(scsi_ctrl)=%x\n", ISP_READ(isp, SXP_INTERRUPT), ISP_READ(isp, SXP_GROSS_ERR), ISP_READ(isp, SXP_PINS_CTRL));
        ISP_WRITE(isp, HCCR, HCCR_CMD_RELEASE);
    }
    printk("    mbox regs: %x %x %x %x %x\n",
       ISP_READ(isp, OUTMAILBOX0), ISP_READ(isp, OUTMAILBOX1),
       ISP_READ(isp, OUTMAILBOX2), ISP_READ(isp, OUTMAILBOX3),
       ISP_READ(isp, OUTMAILBOX4));
    printk("    PCI Status Command/Status=%x\n", csr);
}

static char *isp_pci_exclude = NULL;
static char *isp_pci_include = NULL;

static int
isplinux_pci_exclude(struct pci_dev *dev)
{
    int checking_for_inclusion;
    char *wrk;

    if (isp_pci_include && *isp_pci_include) {
        checking_for_inclusion = 1;
        wrk = isp_pci_include;
    } else {
        checking_for_inclusion = 0;
        wrk = isp_pci_exclude;
    }
    while (wrk && *wrk) {
        unsigned int id;
        char *commatok, *p, *q;

        commatok = strchr(wrk, ',');
        if (commatok) {
            *commatok = 0;
        }
        if (strncmp(wrk, "0x", 2) == 0) {
            q = wrk + 2;
        } else {
            q = wrk;
        }
        id = simple_strtoul(q, &p, 16);
        if (commatok) {
            *commatok = ',';
        }
        if (p != q) {
            /*
             * We have a device id. See if it matches the current device.
             */
            unsigned int exid = ((dev->bus->number) << 16) | (PCI_SLOT(dev->devfn) << 8) | (PCI_FUNC(dev->devfn));
            if (id == exid) {
                if (checking_for_inclusion) {
                    return (0);
                } else {
                    printk(KERN_INFO "%s@<%d,%d,%d>: excluding device\n", ISP_NAME, dev->bus->number, PCI_SLOT(dev->devfn), PCI_FUNC(dev->devfn));
                    return (1);
                }
            }
        }
        if (commatok) {
            wrk = commatok+1;
        } else {
            break;
        }
    }
    /*
     * We didn't find this device on our list and we were checking
     * the list of devices to *include*, so don't attach this device.
     * Otherwise, we can attach this device.
     */
    if (checking_for_inclusion) {
        printk(KERN_INFO "%s@<%d,%d,%d>: excluding device\n", ISP_NAME, dev->bus->number, PCI_SLOT(dev->devfn), PCI_FUNC(dev->devfn));
        return (1);
    } else {
        return (0);
    }
}
#ifdef    MODULE
module_param(isp_pci_mapmem, int, 0);
module_param(isp_pci_exclude, charp, 0);
module_param(isp_pci_include, charp, 0);
#else
static int __init isp_exclude(char *str)
{
    isp_pci_exclude = str;
    return 0;
}
__setup("isp_pci_exclude=", isp_exclude);

static int __init isp_include(char *str)
{
    isp_pci_include = str;
    return 0;
}
__setup("isp_pci_include=", isp_include);
#endif

static struct pci_device_id isp_pci_tbl[] __devinitdata = {
#ifndef    ISP_DISABLE_1020_SUPPORT
        { PCI_DEVICE(PCI_VENDOR_ID_QLOGIC, PCI_DEVICE_ID_QLOGIC_ISP1020) },
#endif
#ifndef    ISP_DISABLE_1080_SUPPORT
        { PCI_DEVICE(PCI_VENDOR_ID_QLOGIC, PCI_DEVICE_ID_QLOGIC_ISP1080) },
#endif
#ifndef    ISP_DISABLE_12160_SUPPORT
        { PCI_DEVICE(PCI_VENDOR_ID_QLOGIC, PCI_DEVICE_ID_QLOGIC_ISP12160) },
#endif
#ifndef    ISP_DISABLE_2100_SUPPORT
        { PCI_DEVICE(PCI_VENDOR_ID_QLOGIC, PCI_DEVICE_ID_QLOGIC_ISP2100) },
#endif
#ifndef    ISP_DISABLE_2200_SUPPORT
        { PCI_DEVICE(PCI_VENDOR_ID_QLOGIC, PCI_DEVICE_ID_QLOGIC_ISP2200) },
#endif
#ifndef    ISP_DISABLE_2300_SUPPORT
        { PCI_DEVICE(PCI_VENDOR_ID_QLOGIC, PCI_DEVICE_ID_QLOGIC_ISP2300) },
        { PCI_DEVICE(PCI_VENDOR_ID_QLOGIC, PCI_DEVICE_ID_QLOGIC_ISP2312) },
#endif
#ifndef    ISP_DISABLE_2322_SUPPORT
        { PCI_DEVICE(PCI_VENDOR_ID_QLOGIC, PCI_DEVICE_ID_QLOGIC_ISP6312) },
        { PCI_DEVICE(PCI_VENDOR_ID_QLOGIC, PCI_DEVICE_ID_QLOGIC_ISP2322) },
        { PCI_DEVICE(PCI_VENDOR_ID_QLOGIC, PCI_DEVICE_ID_QLOGIC_ISP6322) },
#endif
#ifndef    ISP_DISABLE_2400_SUPPORT
        { PCI_DEVICE(PCI_VENDOR_ID_QLOGIC, PCI_DEVICE_ID_QLOGIC_ISP2422) },
        { PCI_DEVICE(PCI_VENDOR_ID_QLOGIC, PCI_DEVICE_ID_QLOGIC_ISP2432) },
        { PCI_DEVICE(PCI_VENDOR_ID_QLOGIC, PCI_DEVICE_ID_QLOGIC_ISP2532) },
#endif
        { 0, 0 }
};
MODULE_DEVICE_TABLE(pci, isp_pci_tbl);

static int __devinit
isplinux_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    struct Scsi_Host *host;
    struct scsi_host_template *tmpt = isp_template;
    ispsoftc_t *isp;
    struct isp_pcisoftc *pci_isp;
    int i, ret;

    if (pdev->subsystem_vendor == PCI_VENDOR_ID_AMI) {
        printk(KERN_INFO "skipping AMI Raid Card that uses QLogic chips\n");
        return (-ENODEV);
    }

    if (isplinux_pci_exclude(pdev)) {
        printk(KERN_INFO "%s: excluding device\n", pci_name(pdev));
        return (-ENODEV);
    }
    if (pci_enable_device(pdev)) {
        printk(KERN_ERR "%s: cannot enable\n", pci_name(pdev));
        return (-ENODEV);
    }
    pci_set_master(pdev);

    tmpt->max_sectors = isp_maxsectors;

    host = scsi_host_alloc(tmpt, sizeof(struct isp_pcisoftc));
    if (host == NULL) {
        pci_disable_device(pdev);
        return (-ENOMEM);
    }
    pci_isp = (struct isp_pcisoftc *) ISP_HOST2ISP(host);
    pci_set_drvdata(pdev, pci_isp);
    pci_isp->pci_dev = pdev;
    isp = (ispsoftc_t *) pci_isp;
    isp->isp_host = host;
    isp->isp_osinfo.device = pdev;
    host->unique_id = isp_unit_seed++;
    sprintf(isp->isp_name, "%s%d", ISP_NAME, isp->isp_unit);
    isp->isp_osinfo.device_id = (pci_domain_nr(pdev->bus) << 16) | ((pdev->bus->number) << 8) | (PCI_SLOT(pdev->devfn) << 3) | (PCI_FUNC(pdev->devfn));
    if (isp_disable & (1 << isp->isp_unit)) {
        printk("%s: disabled at user request\n", isp->isp_name);
        scsi_host_put(host);
        pci_disable_device(pdev);
        return (-ENODEV);
    }
    if (isplinux_pci_init_one(host)) {
        scsi_host_put(host);
        pci_disable_device(pdev);
        return (-ENOMEM);
    }
    ret = scsi_add_host(host, &pdev->dev);
    if (ret) {
        scsi_host_put(host);
        if (pci_isp->msix_enabled) {
            if (pci_isp->msix_enabled > 1) {
                free_irq(pci_isp->msix_vector[0], pci_isp);
                free_irq(pci_isp->msix_vector[1], pci_isp);
                free_irq(pci_isp->msix_vector[2], pci_isp);
            }
            pci_disable_msix(pci_isp->pci_dev);
            pci_isp->msix_enabled = 0;
        }
        if (pci_isp->msi_enabled) {
            pci_isp->msi_enabled = 0;
            pci_disable_msi(pdev);
        }
        pci_disable_device(pdev);
        return (ret);
    }
    for (i = 0; i < MAX_ISP; i++) {
        if (isplist[i] == NULL) {
            isplist[i] = isp;
            break;
        }
    }
    scsi_scan_host(host);
    return (0);
}

static void __devexit
isplinux_pci_remove(struct pci_dev *pdev)
{
    struct isp_pcisoftc *pci_isp = pci_get_drvdata(pdev);
    unsigned long flags;
    ispsoftc_t *isp;
    struct Scsi_Host *host;

    isp = (ispsoftc_t *) pci_isp;
    DESTROY_ISP_DEV(isp);
    host = isp->isp_host;
    scsi_remove_host(host);
#ifdef    ISP_TARGET_MODE
    isp_detach_target(isp);
#endif
    if (isp->isp_osinfo.thread_task) {
        wake_up(&isp->isp_osinfo.trq);
        kthread_stop(isp->isp_osinfo.thread_task);
        isp->isp_osinfo.thread_task = NULL;
    }
    ISP_LOCKU_SOFTC(isp);
    isp_shutdown(isp);
    isp->dogactive = 0;
    del_timer(&isp->isp_osinfo.timer);
    ISP_DISABLE_INTS(isp);
    ISP_UNLKU_SOFTC(isp);
    isplinux_pci_release(host);
#ifdef    ISP_TARGET_MODE
    isp_deinit_target(isp);
#endif
    scsi_host_put(host);
#ifdef  CONFIG_FW_LOADER
    if (isp->isp_osinfo.fwp) {
        release_firmware(isp->isp_osinfo.fwp);
        isp->isp_osinfo.fwp = NULL;
    }
#endif
    pci_set_drvdata(pdev, NULL);
}

static struct pci_driver isplinux_pci_driver = {
        .name           = ISP_NAME,
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9)
        .driver         = {
            .owner      = THIS_MODULE,
        },
#endif
        .id_table       = isp_pci_tbl,
        .probe          = isplinux_pci_probe,
        .remove         = __devexit_p(isplinux_pci_remove),
};

static int __init
isplinux_pci_init(void)
{
    int ret;

    printk(KERN_INFO "Feral Software QLogic SCSI/FC Driver built on %s %s\n", __DATE__, __TIME__);
    ret = alloc_chrdev_region(&isp_dev, 0, MAX_ISP, ISP_NAME);
    if (ret) {
        printk(KERN_ERR "%s: cannot allocate chrdev region\n", __func__);
        return (ret);
    }
    cdev_init(&isp_cdev, &isp_ioctl_operations);
    if (cdev_add(&isp_cdev, isp_dev, MAX_ISP)) {
        printk(KERN_ERR "%s: cannot add cdev\n", __func__);
        kobject_put(&isp_cdev.kobj);
        unregister_chrdev_region(isp_dev, MAX_ISP);
        return (-EIO);
    }
    isp_class = CREATE_ISP_CLASS(THIS_MODULE, ISP_NAME);
    if (IS_ERR(isp_class)) {
        printk(KERN_ERR "%s: unable to add '%s' class\n", ISP_NAME, ISP_NAME);
        cdev_del(&isp_cdev);
        unregister_chrdev_region(isp_dev, MAX_ISP);
        return (PTR_ERR(isp_class));
    }
    ret = pci_register_driver(&isplinux_pci_driver);
    if (ret < 0) {
        printk(KERN_ERR "%s: unable to register driver (return value %d)", __func__, ret);
        DESTROY_ISP_CLASS(isp_class);
        cdev_del(&isp_cdev);
        unregister_chrdev_region(isp_dev, MAX_ISP);
        return (ret);
    }
    return (0);
}

static void __exit
isplinux_pci_exit(void)
{
    pci_unregister_driver(&isplinux_pci_driver);
    DESTROY_ISP_CLASS(isp_class);
    cdev_del(&isp_cdev);
    unregister_chrdev_region(isp_dev, MAX_ISP);
}

module_init(isplinux_pci_init);
module_exit(isplinux_pci_exit);
/*
 * vim:ts=4:sw=4:expandtab
 */
