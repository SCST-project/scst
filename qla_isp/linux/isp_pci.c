/* $Id: isp_pci.c,v 1.161 2008/02/12 00:40:51 mjacob Exp $ */
/*
 *  Copyright (c) 1997-2008 by Matthew Jacob
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
#if !(defined(ISP_DISABLE_1020_SUPPORT) && defined(ISP_DISABLE_1080_SUPPORT) && defined(ISP_DISABLE_12160_SUPPORT) && \
    defined(ISP_DISABLE_2100_SUPPORT) && defined(ISP_DISABLE_2200_SUPPORT))
static int isp_pci_rd_isr(ispsoftc_t *, uint32_t *, uint16_t *, uint16_t *);
#endif
#if !(defined(ISP_DISABLE_2300_SUPPORT) && defined(ISP_DISABLE_2322_SUPPORT))
static int isp_pci_rd_isr_2300(ispsoftc_t *, uint32_t *, uint16_t *, uint16_t *);
#endif
#ifndef    ISP_DISABLE_2400_SUPPORT
static uint32_t isp_pci_rd_reg_2400(ispsoftc_t *, int);
static void isp_pci_wr_reg_2400(ispsoftc_t *, int, uint32_t);
static int isp_pci_rd_isr_2400(ispsoftc_t *, uint32_t *, uint16_t *, uint16_t *);
static int isp_pci_2400_dmasetup(ispsoftc_t *, XS_T *, ispreq_t *, uint32_t *, uint32_t);
#endif
static int isp_pci_mbxdma(ispsoftc_t *);
static int isp_pci_dmasetup(ispsoftc_t *, XS_T *, ispreq_t *, uint32_t *, uint32_t);
static void isp_pci_dmateardown(ispsoftc_t *, XS_T *, uint32_t);

#define FOURG_SEG(x)        (((u64) (x)) & 0xffffffff00000000ULL)
#define SAME_4G(addr, cnt)    (FOURG_SEG(addr) == FOURG_SEG(addr + cnt - 1))

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
#define ISP_IRQ_FLAGS   SA_INTERRUPT | SA_SHIRQ
#else
#define ISP_IRQ_FLAGS   IRQF_SHARED
#endif

#ifdef    ISP_DAC_SUPPORTED
#define ISP_A64                 1
#define HIWD(x)                 ((x) >> 32)
#define IS_HIGH_ISP_ADDR(addr)  ((u64) addr > ((u64) 0xffffffffLL))
#else
#define ISP_A64                 0
#define HIWD(x)                 0
#define IS_HIGH_ISP_ADDR(addr)  0
#endif
#define LOWD(x)                 x

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

#define DISABLE_FW_LOADER 1
#if defined(DISABLE_FW_LOADER) ||  !(defined(CONFIG_FW_LOADER) || defined(CONFIG_FW_LOADER_MODULE))
#ifndef    ISP_DISABLE_1020_SUPPORT
#include "asm_1040.h"
#endif
#ifndef    ISP_DISABLE_1080_SUPPORT
#include "asm_1080.h"
#endif
#ifndef    ISP_DISABLE_12160_SUPPORT
#include "asm_12160.h"
#endif
#ifndef    ISP_DISABLE_2100_SUPPORT
#include "asm_2100.h"
#endif
#ifndef    ISP_DISABLE_2200_SUPPORT
#include "asm_2200.h"
#endif
#ifndef    ISP_DISABLE_2300_SUPPORT
#include "asm_2300.h"
#endif
#ifndef    ISP_DISABLE_2322_SUPPORT
#include "asm_2322.h"
#endif
#ifndef    ISP_DISABLE_2400_SUPPORT
#include "asm_2400.h"
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
    isp_pci_2400_dmasetup,
    isp_pci_dmateardown,
    isp_pci_reset0,
    isp_pci_reset1,
    NULL,
    ISP_2400_RISC_CODE
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
static __inline void *
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

static __inline
void unmap_pci_mem(struct isp_pcisoftc *isp_pci, unsigned long size)
{
    if (isp_pci->vaddr) {
        u8 *p = isp_pci->vaddr;
        p += isp_pci->voff;
        iounmap(p);
    }
}

static __inline int 
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

static __inline int 
map_isp_io(struct isp_pcisoftc *isp_pci, u_short cmd, vm_offset_t io_base)
{
    if ((cmd & PCI_COMMAND_IO) && (io_base & 3) == 1) {
        isp_pci->port = io_base & PCI_BASE_ADDRESS_IO_MASK;
        request_region(isp_pci->port, 0xff, ISP_NAME);
        return (1);
    }
    return (0);
}

void
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
    if (isp_pci->vaddr != 0) {
        unmap_pci_mem(isp_pci, 0xff);
        isp_pci->vaddr = 0;
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


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
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
        isp->isp_port = PCI_FUNC(pdev->devfn);
        isp_pci->poff[MBOX_BLOCK >> _BLK_REG_SHFT] = PCI_MBOX_REGS2400_OFF;
        isp->isp_nchan += isp_vports;
        break;
    default:
        isp_prt(isp, ISP_LOGERR, "Device ID 0x%04x is not a known Qlogic Device", pdev->device);
        pci_release_regions(pdev);
        return (1);
    }

    /* PCI Rev 2.3 changes */
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP6312 || pdev->device == PCI_DEVICE_ID_QLOGIC_ISP2322) {
        /* enable PCI-INTX */
        pci_intx(pdev, 1);
    }


    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP2422 || pdev->device == PCI_DEVICE_ID_QLOGIC_ISP2432) {
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

        /* enable MSI-X or MSI-X */
        if (pci_enable_msix(pdev, isp_msix, 3) == 0) {
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
    }

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
        if (isp->isp_mdvec->dv_ispfw == NULL)
            fwname = "ql1020_fw.bin";
    } 
#endif
#ifndef    ISP_DISABLE_1080_SUPPORT
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP1080) {
        isp->isp_mdvec = &mdvec_1080;
        isp->isp_type = ISP_HA_SCSI_1080;
        if (isp->isp_mdvec->dv_ispfw == NULL)
            fwname = "ql1080_fw.bin";
    }
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP1240) {
        isp->isp_mdvec = &mdvec_1080;
        isp->isp_type = ISP_HA_SCSI_1240;
        host->max_channel = 1;
        if (isp->isp_mdvec->dv_ispfw == NULL)
            fwname = "ql1080_fw.bin";
    }
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP1280) {
        isp->isp_mdvec = &mdvec_1080;
        isp->isp_type = ISP_HA_SCSI_1280;
        host->max_channel = 1;
        if (isp->isp_mdvec->dv_ispfw == NULL)
            fwname = "ql1080_fw.bin";
    }
#endif
#ifndef    ISP_DISABLE_12160_SUPPORT
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP10160) {
        isp->isp_mdvec = &mdvec_12160;
        isp->isp_type = ISP_HA_SCSI_12160;
        if (isp->isp_mdvec->dv_ispfw == NULL)
            fwname = "ql12160_fw.bin";
    }
    if (pdev->device == PCI_DEVICE_ID_QLOGIC_ISP12160) {
        isp->isp_mdvec = &mdvec_12160;
        isp->isp_type = ISP_HA_SCSI_12160;
        host->max_channel = 1;
        if (isp->isp_mdvec->dv_ispfw == NULL)
            fwname = "ql12160_fw.bin";
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
     *
     * We use our synthetic ISP_A64 define here because this allows us to
     * remove code we wouldn't want to try and use if we don't have
     * CONFIG_HIGHMEM64G defined.
     */

    if (isp->isp_type < ISP_HA_SCSI_1240) {
        if (pci_set_dma_mask(pdev, (u64)0x00ffffff)) {
            isp_prt(isp, ISP_LOGERR, "cannot set 24 bit dma mask");
            goto bad;
        }
    } else if (ISP_A64) {
        if (pci_set_dma_mask(pdev, (u64) 0xffffffffffffffffULL)) {
            if (pci_set_dma_mask(pdev, (u64) 0xffffffff)) {
                isp_prt(isp, ISP_LOGERR, "cannot set 32 bit dma mask");
                goto bad;
            }
        } else {
            isp_prt(isp, ISP_LOGCONFIG, "enabling 64 bit DMA");
        }
    } else {
        if (pci_set_dma_mask(pdev, (u64)0xffffffff)) {
            isp_prt(isp, ISP_LOGERR, "cannot set 32 bit dma mask");
            goto bad;
        }
    }

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
            isp_prt(isp, ISP_LOGCONFIG, "unable to load firmware set \"%s\"", fwname);
        }
    }

    if (isplinux_common_init(isp)) {
        isp_prt(isp, ISP_LOGERR, "isplinux_common_init failed");
        goto bad;
    }
    CREATE_ISP_DEV(isp);
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
    if (isp->isp_osinfo.fwp) {
        release_firmware(isp->isp_osinfo.fwp);
        isp->isp_osinfo.fwp = NULL;
    }
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
    if (isp_pci->vaddr != 0) {
        unmap_pci_mem(isp_pci, 0xff);
        isp_pci->vaddr = 0;
    } else {
        release_region(isp_pci->port, 0xff);
        isp_pci->port = 0;
    }
    pci_release_regions(pdev);
    return (1);
}

static __inline uint32_t
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

static __inline void
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

static __inline int
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

#if !(defined(ISP_DISABLE_2300_SUPPORT) && defined(ISP_DISASBLE_2322_SUPPORT) && defined(ISP_DISABLE_2400_SUPPORT))
static __inline uint32_t
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

#ifndef ISP_DISABLE_2400_SUPPORT
static __inline void
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
        MEMZERO(isp->isp_atioq, ISP_QUEUE_SIZE(RESULT_QUEUE_LEN(isp)));
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
        MEMZERO(isp->isp_rquest, ISP_QUEUE_SIZE(RQUEST_QUEUE_LEN(isp)));
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
        MEMZERO(isp->isp_result, ISP_QUEUE_SIZE(RESULT_QUEUE_LEN(isp)));
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
                MEMZERO(fcp->isp_scratch, ISP_FC_SCRLEN);
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
static int tdma_mk(ispsoftc_t *, tmd_xact_t *, ct_entry_t *, uint32_t *, uint32_t);
static int tdma_mkfc(ispsoftc_t *, tmd_xact_t *, ct2_entry_t *, uint32_t *, uint32_t);

#define ALLOW_SYNTHETIC_CTIO    1
#ifndef ALLOW_SYNTHETIC_CTIO
#define cto2    0
#endif

#define STATUS_WITH_DATA        1

/*
 * We need to handle DMA for target mode differently from initiator mode.
 * 
 * DMA mapping and construction and submission of CTIO Request Entries
 * and rendevous for completion are very tightly coupled because we start
 * out by knowing (per platform) how much data we have to move, but we
 * don't know, up front, how many DMA mapping segments will have to be used
 * cover that data, so we don't know how many CTIO and Continuation Request
 * Entries we will end up using. Further, for performance reasons we may want
 * to (on the last CTIO for Fibre Channel), send status too (if all went well).
 *
 * The standard vector still goes through isp_pci_dmasetup, but the callback
 * for the DMA mapping routines comes here instead with a pointer to a
 * partially filled in already allocated request queue entry.
 */
    
static int
tdma_mk(ispsoftc_t *isp, tmd_xact_t *xact, ct_entry_t *cto, uint32_t *nxtip, uint32_t optr)
{
    static const char ctx[] = "CTIO[%x] cdb0 0x%02x lun %u for iid %u flags 0x%x SSTS 0x%02x resid %u <END>";
    static const char mid[] = "CTIO[%x] cdb0 0x%02x lun %u for iid %u flags 0x%x xfr %u moved %u/%u <MID>";
    struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
    struct scatterlist *sg;
    ct_entry_t *qe;
    uint8_t scsi_status;
    uint32_t curi, nxti, handle;
    uint32_t sflags;
    int32_t resid;
    tmd_cmd_t *tmd;
    int nth_ctio, nctios, send_status, nseg, new_seg_cnt;

    tmd = xact->td_cmd;
    curi = isp->isp_reqidx;
    qe = (ct_entry_t *) ISP_QUEUE_ENTRY(isp->isp_rquest, isp->isp_reqidx);

    if (cto->ct_flags & CT_SENDSTATUS) {
        int level;
        if (cto->ct_resid || cto->ct_scsi_status) {
            level = ISP_LOGTINFO;
        } else {
            level = ISP_LOGTDEBUG0;
        }
        isp_prt(isp, level, ctx, cto->ct_fwhandle, tmd->cd_cdb[0], L0LUN_TO_FLATLUN(tmd->cd_lun), cto->ct_iid, cto->ct_flags,
            cto->ct_scsi_status, cto->ct_resid);
    } else {
        isp_prt(isp, ISP_LOGTDEBUG0, mid, tmd->cd_cdb[0], cto->ct_fwhandle, L0LUN_TO_FLATLUN(tmd->cd_lun), cto->ct_iid, cto->ct_flags,
            xact->td_xfrlen, tmd->cd_moved, tmd->cd_totlen);
    }

    cto->ct_xfrlen = 0;
    cto->ct_seg_count = 0;
    cto->ct_header.rqs_entry_count = 1;
    MEMZERO(cto->ct_dataseg, sizeof (cto->ct_dataseg));

    if (xact->td_xfrlen == 0) {
        ISP_TDQE(isp, "tdma_mk[no data]", curi, cto);
        isp_put_ctio(isp, cto, qe);
        if (cto->ct_flags & CT_CCINCR) {
            tmd->cd_lflags &= ~CDFL_RESRC_FILL;
        }
        return (CMD_QUEUED);
    }

    if (xact->td_xfrlen <= 1024) {
        nseg = 0;
    } else if (xact->td_xfrlen <= 4096) {
        nseg = 1;
    } else if (xact->td_xfrlen <= 32768) {
        nseg = 2;
    } else if (xact->td_xfrlen <= 65536) {
        nseg = 3;
    } else if (xact->td_xfrlen <= 131372) {
        nseg = 4;
    } else if (xact->td_xfrlen <= 262144) {
        nseg = 5;
    } else if (xact->td_xfrlen <= 524288) {
        nseg = 6;
    } else {
        nseg = 7;
    }
    isp->isp_osinfo.bins[nseg]++;

    sg = xact->td_data;
    nseg = 0;
    resid = (int32_t) xact->td_xfrlen;
    while (resid > 0) {
        if (sg->length == 0) {
            isp_prt(isp, ISP_LOGWARN, "%s: zero length segment #%d for tag %llx\n", __FUNCTION__, nseg, tmd->cd_tagval);
            cto->ct_resid = -EINVAL;
            return (CMD_COMPLETE);
        }
        nseg++;
        resid -= sg->length;
        sg++;
    }
    sg = xact->td_data;

    new_seg_cnt = pci_map_sg(pcs->pci_dev, sg, nseg, (cto->ct_flags & CT_DATA_IN)? PCI_DMA_TODEVICE : PCI_DMA_FROMDEVICE);

    if (new_seg_cnt == 0) {
        isp_prt(isp, ISP_LOGWARN, "%s: unable to dma map request", __FUNCTION__);
        cto->ct_resid = -ENOMEM;
        return (CMD_COMPLETE);
    }
    tmd->cd_nseg = new_seg_cnt;

    nctios = nseg / ISP_RQDSEG;
    if (nseg % ISP_RQDSEG) {
        nctios++;
    }

    /*
     * Save handle, and potentially any SCSI status, which
     * we'll reinsert on the last CTIO we're going to send.
     */
    handle = cto->ct_syshandle;
    cto->ct_syshandle = 0;
    cto->ct_header.rqs_seqno = 0;
    send_status = (cto->ct_flags & CT_SENDSTATUS) != 0;

    if (send_status) {
        sflags = cto->ct_flags & (CT_SENDSTATUS | CT_CCINCR);
        cto->ct_flags &= ~(CT_SENDSTATUS|CT_CCINCR);
        /*
         * Preserve residual.
         */
        resid = cto->ct_resid;

        /*
         * Save actual SCSI status.
         */
        scsi_status = cto->ct_scsi_status;

#ifndef    STATUS_WITH_DATA
        sflags |= CT_NO_DATA;
        /*
         * We can't do a status at the same time as a data CTIO, so
         * we need to synthesize an extra CTIO at this level.
         */
        nctios++;
#endif
    } else {
        sflags = scsi_status = resid = 0;
    }

    cto->ct_resid = 0;
    cto->ct_scsi_status = 0;

    nxti = *nxtip;

    for (nth_ctio = 0; nth_ctio < nctios; nth_ctio++) {
        int seglim;

        seglim = nseg;
        if (seglim) {
            int seg;

            if (seglim > ISP_RQDSEG)
                seglim = ISP_RQDSEG;

            for (seg = 0; seg < seglim; seg++, nseg--) {
                XS_DMA_ADDR_T addr = sg_dma_address(sg);

                /*
                 * We could actually do the work to support this,
                 * but it's extra code to write and test with things
                 * pretty unlikely to ever be used.
                 */
                if (ISP_A64 && IS_HIGH_ISP_ADDR(addr)) {
                    isp_prt(isp, ISP_LOGERR, "%s: 64 bit tgt mode not supported", __FUNCTION__);
                    cto->ct_resid = -EFAULT;
                    pci_unmap_sg(pcs->pci_dev, xact->td_data, nseg, (cto->ct_flags & CT_DATA_IN)? PCI_DMA_TODEVICE: PCI_DMA_FROMDEVICE);
                    return (CMD_COMPLETE);
                }
                /*
                 * Unlike normal initiator commands, we don't do any swizzling here.
                 */
                cto->ct_dataseg[seg].ds_base = LOWD(addr);
                cto->ct_dataseg[seg].ds_count = (uint32_t) sg_dma_len(sg);
                cto->ct_xfrlen += sg_dma_len(sg);
                sg++;
            }
            cto->ct_seg_count = seg;
        } else {
            /*
             * This case should only happen when we're
             * sending an extra CTIO with final status.
             */
            if (send_status == 0) {
                isp_prt(isp, ISP_LOGERR, "%s: ran out of segments, no status to send", __FUNCTION__);
                return (CMD_EAGAIN);
            }
        }

        /*
         * At this point, the fields ct_lun, ct_iid, ct_tagval, ct_tagtype, and
         * ct_timeout have been carried over unchanged from what our caller had
         * set.
         *
         * The dataseg fields and the seg_count fields we just got through
         * setting. The data direction we've preserved all along and only
         * clear it if we're now sending status.
         */
        if (nth_ctio == nctios - 1) {
            /*
             * We're the last in a sequence of CTIOs, so mark this
             * CTIO and save the handle to the command such that when
             * this CTIO completes we can free dma resources and
             * do whatever else we need to do to finish the rest
             * of the command.
             */
            cto->ct_syshandle = handle;
            cto->ct_header.rqs_seqno = 1;

            if (send_status) {
                cto->ct_scsi_status = scsi_status;
                cto->ct_flags |= sflags;
                cto->ct_resid = resid;
            }
            isp_put_ctio(isp, cto, qe);
            ISP_TDQE(isp, "last tdma_mk", curi, cto);
            if (nctios > 1) {
                MEMORYBARRIER(isp, SYNC_REQUEST, curi, QENTRY_LEN);
            }
        } else {
            ct_entry_t *oqe = qe;

            /*
             * Make sure handle fields are clean
             */
            cto->ct_syshandle = 0;
            cto->ct_header.rqs_seqno = 0;

            isp_prt(isp, ISP_LOGTDEBUG1, "CTIO[%x] lun%d for ID%d ct_flags 0x%x", cto->ct_fwhandle, L0LUN_TO_FLATLUN(tmd->cd_lun), (int) cto->ct_iid, cto->ct_flags);

            /*
             * Get a new CTIO
             */
            qe = (ct_entry_t *) ISP_QUEUE_ENTRY(isp->isp_rquest, nxti);
            nxti = ISP_NXT_QENTRY(nxti, RQUEST_QUEUE_LEN(isp));
            if (nxti == optr) {
                isp_prt(isp, ISP_LOGERR, "%s: request queue overflow", __FUNCTION__);
                return (CMD_EAGAIN);
            }

           /*
            * Now that we're done with the old CTIO,
            * flush it out to the request queue.
            */
            ISP_TDQE(isp, "tdma_mk", curi, cto);
            isp_put_ctio(isp, cto, oqe);
            if (nth_ctio != 0) {
                MEMORYBARRIER(isp, SYNC_REQUEST, curi, QENTRY_LEN);
            }
            curi = ISP_NXT_QENTRY(curi, RQUEST_QUEUE_LEN(isp));

            /*
             * Reset some fields in the CTIO so we can reuse
             * for the next one we'll flush to the request
             * queue.
             */
            cto->ct_header.rqs_entry_type = RQSTYPE_CTIO;
            cto->ct_header.rqs_entry_count = 1;
            cto->ct_header.rqs_flags = 0;
            cto->ct_status = 0;
            cto->ct_scsi_status = 0;
            cto->ct_xfrlen = 0;
            cto->ct_resid = 0;
            cto->ct_seg_count = 0;
            MEMZERO(cto->ct_dataseg, sizeof (cto->ct_dataseg));
        }
    }
    *nxtip = nxti;
    isp_prt(isp, ISP_LOGTDEBUG2, "[%llx]: map %d segments at %p for handle 0x%x", tmd->cd_tagval, new_seg_cnt, xact->td_data, cto->ct_syshandle);
    if (sflags & CT_CCINCR) {
        tmd->cd_lflags &= ~CDFL_RESRC_FILL;
    }
    return (CMD_QUEUED);
}

/*
 * We're passed a pointer to a prototype ct2_entry_t.
 *
 * If it doesn't contain any data movement, it has to be for sending status,
 * possibly with Sense Data as well, so we send a single CTIO2. This should
 * be a Mode 1 CTIO2, and it's up to the caller to set up the Sense Data
 * and flags appropriately.
 *
 * If it does contain data movement, it may *also* be for sending status
 * (possibly with Sense Data also). It's possible to describe to the firmware
 * what we want in one CTIO2. However, under some conditions it is not,
 * so we must also send a *second* CTIO2 after the first one.
 *
 * If the data to be sent is in segments that exceeds that which we can
 * fit into a CTIO2 (likely, as there's only room for 3 segments), we
 * utilize normal continuation entries, which get pushed after the
 * first CTIO2, and possibly are followed by a final CTIO2.
 *
 * In any case, it's up to the caller to send us a Mode 0 CTIO2 describing
 * the data to be moved (if any) and the appropriate flags indicating
 * status. We'll clear and set as appropriate. We'll also check to see
 * whether Sense Data is attempting to be sent and retrieve it as appropriate.
 *
 * In all cases the caller should not assume that the prototype CTIO2
 * has been left unchanged.
 */
#ifndef    ISP_DISABLE_2400_SUPPORT
static int tdma_mk_2400(ispsoftc_t *, tmd_xact_t *, ct7_entry_t *, uint32_t *, uint32_t);
static int
tdma_mk_2400(ispsoftc_t *isp, tmd_xact_t *xact, ct7_entry_t *cto, uint32_t *nxtip, uint32_t optr)
{
    struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
    static const char ctx[] = "CTIO7[%llx] cdb0 0x%02x lun %u nphdl 0x%x flgs 0x%x ssts 0x%x xfr %u moved %u/%u resid %d <END>";
    static const char mid[] = "CTIO7[%llx] cdb0 0x%02x lun %u nphdl 0x%x flgs 0x%x xfr %u moved %u/%u <MID>";
    XS_DMA_ADDR_T addr, last_synthetic_addr;
    tmd_cmd_t *tmd = xact->td_cmd;
    struct scatterlist *sg;
    void *qe;
    uint16_t swd;
    uint32_t curi, nxti;
    uint32_t bc, last_synthetic_count;
    long xfcnt;    /* must be signed */
    int nseg, seg, ovseg, seglim, new_seg_cnt;
#ifdef ALLOW_SYNTHETIC_CTIO
    ct7_entry_t *cto2 = NULL, ct2;
#endif 

    nxti = *nxtip;
    curi = isp->isp_reqidx;
    qe = ISP_QUEUE_ENTRY(isp->isp_rquest, curi);

    if (cto->ct_flags & CT7_SENDSTATUS) {
        int level;
        if (cto->ct_resid || cto->ct_scsi_status) {
            level = ISP_LOGTINFO;
        } else {
            level = ISP_LOGTDEBUG0;
        }
        isp_prt(isp, level, ctx, (unsigned long long) tmd->cd_tagval, tmd->cd_cdb[0], L0LUN_TO_FLATLUN(tmd->cd_lun), cto->ct_nphdl, cto->ct_flags,
            cto->ct_scsi_status, xact->td_xfrlen, tmd->cd_moved, tmd->cd_totlen, cto->ct_resid);
    } else {
        isp_prt(isp, ISP_LOGTDEBUG0, mid, (unsigned long long) tmd->cd_tagval, tmd->cd_cdb[0], L0LUN_TO_FLATLUN(tmd->cd_lun), cto->ct_nphdl, cto->ct_flags,
            xact->td_xfrlen, tmd->cd_moved, tmd->cd_totlen);
    }

    /*
     * Handle commands that transfer no data right away.
     */
    if (xact->td_xfrlen == 0) {
        cto->ct_header.rqs_entry_count = 1;
        cto->ct_header.rqs_seqno = 1;

        /* ct_syshandle contains the synchronization handle set by caller */
        isp_put_ctio7(isp, cto, qe);
        ISP_TDQE(isp, "tdma_mk_2400[no data]", curi, qe);
        return (CMD_QUEUED);
    }

    if (xact->td_xfrlen <= 1024) {
        nseg = 0;
    } else if (xact->td_xfrlen <= 4096) {
        nseg = 1;
    } else if (xact->td_xfrlen <= 32768) {
        nseg = 2;
    } else if (xact->td_xfrlen <= 65536) {
        nseg = 3;
    } else if (xact->td_xfrlen <= 131372) {
        nseg = 4;
    } else if (xact->td_xfrlen <= 262144) {
        nseg = 5;
    } else if (xact->td_xfrlen <= 524288) {
        nseg = 6;
    } else {
        nseg = 7;
    }
    isp->isp_osinfo.bins[nseg]++;

    /*
     * First, count and map all S/G segments
     *
     * The byte counter has to be signed because
     * we can have descriptors that are, in fact,
     * longer than our data transfer count.
     */
    sg = xact->td_data;
    nseg = 0;
    xfcnt = xact->td_xfrlen;
    while (xfcnt > 0) {
        if (sg->length == 0) {
            isp_prt(isp, ISP_LOGWARN, "%s: zero length segment #%d for tag %llx\n", __FUNCTION__, nseg, tmd->cd_tagval);
            cto->ct_resid = -EINVAL;
            return (CMD_COMPLETE);
        }
        nseg++;
        xfcnt -= sg->length;
        sg++;
    }
    sg = xact->td_data;
    new_seg_cnt = pci_map_sg(pcs->pci_dev, sg, nseg, (cto->ct_flags & CT2_DATA_IN)? PCI_DMA_TODEVICE : PCI_DMA_FROMDEVICE);
    if (new_seg_cnt == 0) {
        isp_prt(isp, ISP_LOGWARN, "%s: unable to dma map request", __FUNCTION__);
        cto->ct_resid = -ENOMEM;
        return (CMD_COMPLETE);
    }
    tmd->cd_nseg = new_seg_cnt;

    /*
     * Check for sequential ordering of data frames
     */
    if (tmd->cd_lastoff + tmd->cd_lastsize != xact->td_offset) {
        isp_prt(isp, ISP_LOGWARN, "%s: [0x%llx] lastoff %u lastsize %u but curoff %u (totlen %u)", __FUNCTION__, (unsigned long long) tmd->cd_tagval, tmd->cd_lastoff, tmd->cd_lastsize, xact->td_offset, tmd->cd_totlen);
    }
    tmd->cd_lastsize = xact->td_xfrlen;
    tmd->cd_lastoff = xact->td_offset;

    /*
     * Second, figure out whether we'll need to send a separate status CTIO.
     */
    swd = cto->ct_scsi_status;

    if ((cto->ct_flags & CT7_SENDSTATUS) && ((swd & 0xff) || cto->ct_resid)) {
#ifdef  ALLOW_SYNTHETIC_CTIO
        cto2 = &ct2;
        /*
         * Copy over CTIO2
         */
        MEMCPY(cto2, cto, sizeof (ct7_entry_t));

        /*
         * Clear fields from first CTIO7 that now need to be cleared
         */
        cto->ct_flags &= ~CT7_SENDSTATUS;
        cto->ct_resid = 0;
        cto->ct_syshandle = 0;
        cto->ct_scsi_status = 0;

        /*
         * Reset fields in the second CTIO7 as appropriate.
         */
        cto2->ct_flags &= ~(CT7_FLAG_MMASK|CT7_DATAMASK);
        cto2->ct_flags |= CT7_NO_DATA|CT7_NO_DATA|CT7_FLAG_MODE1;
        cto2->ct_seg_count = 0;
        MEMZERO(&cto2->rsp, sizeof (cto2->rsp));
        cto2->ct_scsi_status = swd;
        if ((swd & 0xff) == SCSI_CHECK && (xact->td_hflags & TDFH_SNSVALID)) {
            cto2->rsp.m1.ct_resplen = min(TMD_SENSELEN, MAXRESPLEN_24XX);
            MEMCPY(cto2->rsp.m1.ct_resp, tmd->cd_sense, cto2->rsp.m1.ct_resplen);
            cto2->ct_scsi_status |= (FCP_SNSLEN_VALID << 8);
        }
#else
        cto->ct_flags &= ~CT7_SENDSTATUS;
        cto->ct_resid = 0;
        cto->ct_scsi_status = 0;
#endif
    }

    /*
     * Third, fill in the data segments in the first CTIO2 itself.
     * This is also a good place to set the relative offset.
     */
    xfcnt = xact->td_xfrlen;

    cto->rsp.m0.reloff = xact->td_offset;

    seglim = 1;

    last_synthetic_count = 0;
    last_synthetic_addr = 0;
    cto->ct_seg_count = 1;
    seg = 1;

    bc = min(sg_dma_len(sg), xfcnt);
    addr = sg_dma_address(sg);
    cto->rsp.m0.ds.ds_base = LOWD(addr);
    cto->rsp.m0.ds.ds_basehi = HIWD(addr);
    if (!SAME_4G(addr, bc)) {
        isp_prt(isp, ISP_LOGTDEBUG1, "seg0[%d]%x%08x:%u (TRUNC'd)", seg, (uint32_t) HIWD(addr), (uint32_t)LOWD(addr), bc);
        cto->rsp.m0.ds.ds_count = (unsigned int) (FOURG_SEG(addr + bc) - addr);
        addr += cto->rsp.m0.ds.ds_count;
        bc -= cto->rsp.m0.ds.ds_count;
        last_synthetic_count = bc;
        last_synthetic_addr = addr;
    } else {
        cto->rsp.m0.ds.ds_count = bc;
        isp_prt(isp, ISP_LOGTDEBUG1, "%s: seg0[%d]%lx%08lx:%u", __FUNCTION__, seg,
            (unsigned long)cto->rsp.m0.ds.ds_basehi, (unsigned long)cto->rsp.m0.ds.ds_base, bc);
    }
    cto->rsp.m0.ct_xfrlen += bc;
    xfcnt -= bc;
    sg++;


    if (seg == nseg && last_synthetic_count == 0) {
        goto mbxsync;
    }

    /*
     * Now do any continuation segments that are required.
     */
    do {
        int lim;
        uint32_t curip;
        ispcontreq_t local, *crq = &local, *qep;

        curip = nxti;
        qep = (ispcontreq_t *) ISP_QUEUE_ENTRY(isp->isp_rquest, curip);
        nxti = ISP_NXT_QENTRY((curip), RQUEST_QUEUE_LEN(isp));
        if (nxti == optr) {
            pci_unmap_sg(pcs->pci_dev, xact->td_data, nseg, (cto->ct_flags & CT2_DATA_IN)? PCI_DMA_TODEVICE : PCI_DMA_FROMDEVICE);
            isp_prt(isp, ISP_LOGTDEBUG0, "%s: out of space for continuations (%d of %d segs done)", __FUNCTION__, cto->ct_seg_count, nseg);
            return (CMD_EAGAIN);
        }
        cto->ct_header.rqs_entry_count++;
        MEMZERO((void *)crq, sizeof (*crq));
        crq->req_header.rqs_entry_count = 1;
        crq->req_header.rqs_entry_type = RQSTYPE_A64_CONT;
        lim = ISP_CDSEG64;

        for (ovseg = 0; (seg < nseg || last_synthetic_count) && ovseg < lim; seg++, ovseg++, sg++) {
            ispcontreq64_t *xrq;
            if (last_synthetic_count) {
                addr = last_synthetic_addr;
                bc = last_synthetic_count;
                last_synthetic_count = 0;
                sg--;
                seg--;
            } else {
                addr = sg_dma_address(sg);
                bc = min(sg_dma_len(sg), xfcnt);
            }
            isp_prt(isp, ISP_LOGTDEBUG1, "%s: seg%d[%d]%llx:%u", __FUNCTION__, cto->ct_header.rqs_entry_count-1, ovseg, (unsigned long long) addr, bc);

            cto->ct_seg_count++;
            cto->rsp.m0.ct_xfrlen += bc;

            xrq = (ispcontreq64_t *) crq;
            xrq->req_dataseg[ovseg].ds_count = bc;
            xrq->req_dataseg[ovseg].ds_base = LOWD(addr);
            xrq->req_dataseg[ovseg].ds_basehi = HIWD(addr);
            /*
             * Make sure we don't cross a 4GB boundary.
             */
            if (!SAME_4G(addr, bc)) {
                isp_prt(isp, ISP_LOGTDEBUG1, "seg%d[%d]%llx:%u (TRUNC'd)", cto->ct_header.rqs_entry_count-1, ovseg, (long long)addr, bc);
                xrq->req_dataseg[ovseg].ds_count = (unsigned int) (FOURG_SEG(addr + bc) - addr);
                addr += xrq->req_dataseg[ovseg].ds_count;
                bc -= xrq->req_dataseg[ovseg].ds_count;
                xfcnt -= xrq->req_dataseg[ovseg].ds_count;
                /*
                 * Do we have space to split it here?
                 */
                if (ovseg == lim - 1) {
                    last_synthetic_count = bc;
                    last_synthetic_addr = addr;
                    cto->ct_seg_count++;
                } else {
                    ovseg++;
                    xrq->req_dataseg[ovseg].ds_count = bc;
                    xrq->req_dataseg[ovseg].ds_base = LOWD(addr);
                    xrq->req_dataseg[ovseg].ds_basehi = HIWD(addr);
                }
            }
        }
        ISP_TDQE(isp, "tdma_mk_2400 cont", curip, crq);
        MEMORYBARRIER(isp, SYNC_REQUEST, curip, QENTRY_LEN);
        if (crq->req_header.rqs_entry_type == RQSTYPE_A64_CONT) {
            isp_put_cont64_req(isp, (ispcontreq64_t *)crq, (ispcontreq64_t *)qep);
        } else {
            isp_put_cont_req(isp, crq, qep);
        }
    } while (seg < nseg || last_synthetic_count);

    isp_prt(isp, ISP_LOGTDEBUG2, "[%llx]: map %d segments at %p for handle 0x%x", tmd->cd_tagval, new_seg_cnt, xact->td_data, cto->ct_syshandle);

mbxsync:

#ifdef  ALLOW_SYNTHETIC_CTIO
    /*
     * If we have a final CTIO2, allocate and push *that*
     * onto the request queue.
     */
    if (cto2) {
        qe = (ct7_entry_t *) ISP_QUEUE_ENTRY(isp->isp_rquest, nxti);
        curi = nxti;
        nxti = ISP_NXT_QENTRY(curi, RQUEST_QUEUE_LEN(isp));
        if (nxti == optr) {
            pci_unmap_sg(pcs->pci_dev, xact->td_data, nseg, (cto->ct_flags & CT7_DATA_IN)? PCI_DMA_TODEVICE : PCI_DMA_FROMDEVICE);
            isp_prt(isp, ISP_LOGTDEBUG0, "%s: request queue overflow", __FUNCTION__);
            cto->ct_resid = -EAGAIN;
            return (CMD_COMPLETE);
        }
        MEMORYBARRIER(isp, SYNC_REQUEST, curi, QENTRY_LEN);
        isp_put_ctio7(isp, cto2, (ct7_entry_t *)qe);
        ISP_TDQE(isp, "tdma_mk_2400:final", curi, cto2);
    }
#endif
    qe = ISP_QUEUE_ENTRY(isp->isp_rquest, isp->isp_reqidx);
    isp_put_ctio7(isp, cto, qe);
    if (cto->ct_flags & CT2_FASTPOST) {
        isp_prt(isp, ISP_LOGTDEBUG1, "[%x] fastpost (0x%x) with entry count %d", cto->ct_rxid, tmd->cd_cdb[0], cto->ct_header.rqs_entry_count);
    }
    ISP_TDQE(isp, "tdma_mk_2400", isp->isp_reqidx, cto);
    *nxtip = nxti;
    return (CMD_QUEUED);
}
#endif

static int
tdma_mkfc(ispsoftc_t *isp, tmd_xact_t *xact, ct2_entry_t *cto, uint32_t *nxtip, uint32_t optr)
{
    struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
    static const char ctx[] = "CTIO2[%x] cdb0 0x%02x lun %u for 0x%016llx flags 0x%x SSTS 0x%04x resid %u <END>";
    static const char mid[] = "CTIO2[%x] cdb0 0x%02x lun %u for 0x%016llx flags 0x%x xfr %u moved %u/%u <MID>";
    XS_DMA_ADDR_T addr, last_synthetic_addr;
    tmd_cmd_t *tmd = xact->td_cmd;
    struct scatterlist *sg;
    void *qe;
    uint16_t swd;
    uint32_t curi, nxti;
    uint32_t bc, last_synthetic_count;
    long xfcnt;    /* must be signed */
    int nseg, seg, ovseg, seglim, new_seg_cnt;
#ifdef ALLOW_SYNTHETIC_CTIO
    ct2_entry_t *cto2 = NULL, ct2;
#endif 

    nxti = *nxtip;
    curi = isp->isp_reqidx;
    qe = ISP_QUEUE_ENTRY(isp->isp_rquest, curi);

    
    if (cto->ct_flags & CT2_SENDSTATUS) {
        int level;
        if ((cto->ct_flags & CT2_FLAG_MMASK) == CT2_FLAG_MODE0) {
            swd = cto->rsp.m0.ct_scsi_status;
        } else if ((cto->ct_flags & CT2_FLAG_MMASK) == CT2_FLAG_MODE1) {
            swd = cto->rsp.m1.ct_scsi_status;
        } else {
            swd = 0;
        }
        if (cto->ct_resid || swd) {
            level = ISP_LOGTINFO;
        } else {
            level = ISP_LOGTDEBUG0;
        }
        isp_prt(isp, level, ctx, cto->ct_rxid, tmd->cd_cdb[0], L0LUN_TO_FLATLUN(tmd->cd_lun), (unsigned long long) tmd->cd_iid, cto->ct_flags, swd, cto->ct_resid);
    } else {
        isp_prt(isp, ISP_LOGTDEBUG0, mid, cto->ct_rxid, tmd->cd_cdb[0], L0LUN_TO_FLATLUN(tmd->cd_lun), (unsigned long long) tmd->cd_iid, cto->ct_flags,
            xact->td_xfrlen, tmd->cd_moved, tmd->cd_totlen);
        swd = 0;
    }

    if (cto->ct_flags & CT2_FASTPOST) {
        if ((xact->td_hflags & (TDFH_STSVALID|TDFH_SNSVALID)) != TDFH_STSVALID) {
            cto->ct_flags &= ~CT2_FASTPOST;
        }
    }

    /*
     * Handle commands that transfer no data right away.
     */
    if (xact->td_xfrlen == 0) {
        cto->ct_header.rqs_entry_count = 1;
        cto->ct_header.rqs_seqno = 1;
        /* ct_syshandle contains the synchronization handle set by caller */
        cto->ct_seg_count = 0;
        cto->ct_reloff = 0;
        isp_put_ctio2(isp, cto, qe);
        if (cto->ct_flags & CT2_FASTPOST) {
            isp_prt(isp, ISP_LOGTDEBUG1, "[%x] faspost (0x%x)", cto->ct_rxid, tmd->cd_cdb[0]);
        }
        ISP_TDQE(isp, "tdma_mkfc[no data]", curi, qe);
        if (cto->ct_flags & CT2_CCINCR) {
            tmd->cd_lflags &= ~CDFL_RESRC_FILL;
        }
        return (CMD_QUEUED);
    }

    if (xact->td_xfrlen <= 1024) {
        nseg = 0;
    } else if (xact->td_xfrlen <= 4096) {
        nseg = 1;
    } else if (xact->td_xfrlen <= 32768) {
        nseg = 2;
    } else if (xact->td_xfrlen <= 65536) {
        nseg = 3;
    } else if (xact->td_xfrlen <= 131372) {
        nseg = 4;
    } else if (xact->td_xfrlen <= 262144) {
        nseg = 5;
    } else if (xact->td_xfrlen <= 524288) {
        nseg = 6;
    } else {
        nseg = 7;
    }
    isp->isp_osinfo.bins[nseg]++;


    /*
     * First, count and map all S/G segments
     *
     * The byte counter has to be signed because
     * we can have descriptors that are, in fact,
     * longer than our data transfer count.
     */
    sg = xact->td_data;
    nseg = 0;
    xfcnt = xact->td_xfrlen;
    while (xfcnt > 0) {
        if (sg->length == 0) {
            isp_prt(isp, ISP_LOGWARN, "%s: zero length segment #%d for tag %llx\n", __FUNCTION__, nseg, tmd->cd_tagval);
            cto->ct_resid = -EINVAL;
            return (CMD_COMPLETE);
        }
        nseg++;
        xfcnt -= sg->length;
        sg++;
    }
    sg = xact->td_data;
    new_seg_cnt = pci_map_sg(pcs->pci_dev, sg, nseg, (cto->ct_flags & CT2_DATA_IN)? PCI_DMA_TODEVICE : PCI_DMA_FROMDEVICE);
    if (new_seg_cnt == 0) {
        isp_prt(isp, ISP_LOGWARN, "%s: unable to dma map request", __FUNCTION__);
        cto->ct_resid = -ENOMEM;
        return (CMD_COMPLETE);
    }
    tmd->cd_nseg = new_seg_cnt;

    /*
     * Second, figure out whether we'll need to send a separate status CTIO.
     */

    if ((cto->ct_flags & CT2_SENDSTATUS) && ((swd & 0xff) || cto->ct_resid)) {
#ifdef  ALLOW_SYNTHETIC_CTIO
        cto2 = &ct2;
        /*
         * Copy over CTIO2
         */
        MEMCPY(cto2, cto, sizeof (ct2_entry_t));

        /*
         * Clear fields from first CTIO2 that now need to be cleared
         */
        cto->ct_flags &= ~(CT2_SENDSTATUS|CT2_CCINCR|CT2_FASTPOST);
        cto->ct_resid = 0;
        cto->ct_syshandle = 0;
        cto->rsp.m0.ct_scsi_status = 0;

        /*
         * Reset fields in the second CTIO2 as appropriate.
         */
        cto2->ct_flags &= ~(CT2_FLAG_MMASK|CT2_DATAMASK|CT2_FASTPOST);
        cto2->ct_flags |= CT2_NO_DATA|CT2_FLAG_MODE1;
        cto2->ct_seg_count = 0;
        cto2->ct_reloff = 0;
        MEMZERO(&cto2->rsp, sizeof (cto2->rsp));
        if ((swd & 0xff) == SCSI_CHECK && (swd & CT2_SNSLEN_VALID)) {
            cto2->rsp.m1.ct_senselen = min(TMD_SENSELEN, MAXRESPLEN);
            MEMCPY(cto2->rsp.m1.ct_resp, tmd->cd_sense, cto2->rsp.m1.ct_senselen);
            swd |= CT2_SNSLEN_VALID;
        }
        if (cto2->ct_resid > 0) {
            swd |= CT2_DATA_UNDER;
        } else if (cto2->ct_resid < 0) {
            swd |= CT2_DATA_OVER;
        }
        cto2->rsp.m1.ct_scsi_status = swd;
        if (cto2->ct_flags & CT2_CCINCR) {
            tmd->cd_lflags &= ~CDFL_RESRC_FILL;
        }
#else
        cto->ct_flags &= ~(CT2_SENDSTATUS|CT2_CCINCR|CT2_FASTPOST);
        cto->ct_resid = 0;
        cto->rsp.m0.ct_scsi_status = 0;
#endif
    } else if ((cto->ct_flags & (CT2_SENDSTATUS|CT2_CCINCR)) == (CT2_SENDSTATUS|CT2_CCINCR)) {
        tmd->cd_lflags &= ~CDFL_RESRC_FILL;
    }

    /*
     * Third, fill in the data segments in the first CTIO2 itself.
     * This is also a good place to set the relative offset.
     */
    xfcnt = xact->td_xfrlen;
    cto->ct_reloff = xact->td_offset;

    /*
     * This is a good place to return to if we need to redo this with
     * 64 bit PCI addressing. We really want to use 32 bit addressing
     * if we can because it's a lot more efficient.
     */
    if (IS_2322(isp)) {
        seglim = ISP_RQDSEG_T3;
        cto->ct_header.rqs_entry_type = RQSTYPE_CTIO3;
        if (cto2) {
            cto2->ct_header.rqs_entry_type = RQSTYPE_CTIO3;
        }
    } else {
        seglim = ISP_RQDSEG_T2;
        cto->ct_header.rqs_entry_type = RQSTYPE_CTIO2;
        if (cto2) {
            cto2->ct_header.rqs_entry_type = RQSTYPE_CTIO2;
        }
    }

again:
    last_synthetic_count = 0;
    last_synthetic_addr = 0;
    cto->ct_seg_count = min(nseg, seglim);

    for (seg = 0; seg < cto->ct_seg_count; seg++) {
        bc = min(sg_dma_len(sg), xfcnt);
        addr = sg_dma_address(sg);
#ifdef    ISP_DAC_SUPPORTED
        if (seglim == ISP_RQDSEG_T2) {
            if (IS_HIGH_ISP_ADDR(addr)) {
                cto->ct_header.rqs_entry_type = RQSTYPE_CTIO3;
                if (cto2) {
                    cto2->ct_header.rqs_entry_type = RQSTYPE_CTIO3;
                }
                xfcnt = xact->td_xfrlen;
                cto->rsp.m0.ct_xfrlen = 0;
                sg = xact->td_data;
                seglim = ISP_RQDSEG_T3;
                isp_prt(isp, ISP_LOGTDEBUG2, "%s: found hi page", __FUNCTION__);
                goto again;
            }
            cto->rsp.m0.u.ct_dataseg[seg].ds_base = LOWD(addr);
            cto->rsp.m0.u.ct_dataseg[seg].ds_count = bc;
            isp_prt(isp, ISP_LOGTDEBUG1, "%s: seg0[%d]%x:%u", __FUNCTION__, seg, cto->rsp.m0.u.ct_dataseg[seg].ds_base, bc);
        } else {
            cto->rsp.m0.u.ct_dataseg64[seg].ds_base = LOWD(addr);
            cto->rsp.m0.u.ct_dataseg64[seg].ds_basehi = HIWD(addr);
            if (!SAME_4G(addr, bc)) {
                isp_prt(isp, ISP_LOGTDEBUG1, "seg0[%d]%x%08x:%u (TRUNC'd)", seg, (uint32_t) HIWD(addr), (uint32_t)LOWD(addr), bc);
                cto->rsp.m0.u.ct_dataseg64[seg].ds_count = (unsigned int) (FOURG_SEG(addr + bc) - addr);
                addr += cto->rsp.m0.u.ct_dataseg64[seg].ds_count;
                bc -= cto->rsp.m0.u.ct_dataseg64[seg].ds_count;
                /*
                 * Do we have space to split it here?
                 */
                if (seg == seglim - 1) {
                    last_synthetic_count = bc;
                    last_synthetic_addr = addr;
                } else {
                    cto->ct_seg_count++;
                    seg++;
                    cto->rsp.m0.u.ct_dataseg64[seg].ds_count = bc;
                    cto->rsp.m0.u.ct_dataseg64[seg].ds_base = LOWD(addr);
                    cto->rsp.m0.u.ct_dataseg64[seg].ds_basehi = HIWD(addr);
                    isp_prt(isp, ISP_LOGALL, "%s: seg0[%d]%lx%08lx:%u", __FUNCTION__, seg,
                        (unsigned long)cto->rsp.m0.u.ct_dataseg64[seg].ds_basehi, (unsigned long)cto->rsp.m0.u.ct_dataseg64[seg].ds_base, bc);
                }
            } else {
                cto->rsp.m0.u.ct_dataseg64[seg].ds_count = bc;
                isp_prt(isp, ISP_LOGTDEBUG1, "%s: seg0[%d]%lx%08lx:%u", __FUNCTION__, seg,
                    (unsigned long)cto->rsp.m0.u.ct_dataseg64[seg].ds_basehi, (unsigned long)cto->rsp.m0.u.ct_dataseg64[seg].ds_base, bc);
            }
        }
#else
        if (seglim == ISP_RQDSEG_T2) {
            cto->rsp.m0.u.ct_dataseg[seg].ds_base = addr;
            cto->rsp.m0.u.ct_dataseg[seg].ds_count = bc;
            isp_prt(isp, ISP_LOGTDEBUG1, "%s: seg0[%d]%x:%u", __FUNCTION__, seg, cto->rsp.m0.u.ct_dataseg[seg].ds_base, bc);
        } else {
            cto->rsp.m0.u.ct_dataseg64[seg].ds_base = addr;
            cto->rsp.m0.u.ct_dataseg64[seg].ds_basehi = 0;
            cto->rsp.m0.u.ct_dataseg64[seg].ds_count = bc;
            isp_prt(isp, ISP_LOGTDEBUG1, "%s: seg0[%d]%lx:%u", __FUNCTION__, seg, (unsigned long) cto->rsp.m0.u.ct_dataseg64[seg].ds_base, bc);
        }
#endif
        cto->rsp.m0.ct_xfrlen += bc;
        xfcnt -= bc;
        sg++;
    }


    if (seg == nseg && last_synthetic_count == 0) {
        goto mbxsync;
    }

    /*
     * Now do any continuation segments that are required.
     */
    do {
        int lim;
        uint32_t curip;
        ispcontreq_t local, *crq = &local, *qep;

        curip = nxti;
        qep = (ispcontreq_t *) ISP_QUEUE_ENTRY(isp->isp_rquest, curip);
        nxti = ISP_NXT_QENTRY((curip), RQUEST_QUEUE_LEN(isp));
        if (nxti == optr) {
            pci_unmap_sg(pcs->pci_dev, xact->td_data, nseg, (cto->ct_flags & CT2_DATA_IN)? PCI_DMA_TODEVICE : PCI_DMA_FROMDEVICE);
            isp_prt(isp, ISP_LOGTDEBUG0, "%s: out of space for continuations (%d of %d segs done)", __FUNCTION__, cto->ct_seg_count, nseg);
            return (CMD_EAGAIN);
        }
        cto->ct_header.rqs_entry_count++;
        MEMZERO((void *)crq, sizeof (*crq));
        crq->req_header.rqs_entry_count = 1;
        if (cto->ct_header.rqs_entry_type == RQSTYPE_CTIO3) {
            crq->req_header.rqs_entry_type = RQSTYPE_A64_CONT;
            lim = ISP_CDSEG64;
        } else {
            crq->req_header.rqs_entry_type = RQSTYPE_DATASEG;
            lim = ISP_CDSEG;
        }

        for (ovseg = 0; (seg < nseg || last_synthetic_count) && ovseg < lim; seg++, ovseg++, sg++) {
            if (last_synthetic_count) {
                addr = last_synthetic_addr;
                bc = last_synthetic_count;
                last_synthetic_count = 0;
                sg--;
                seg--;
            } else {
                addr = sg_dma_address(sg);
                bc = min(sg_dma_len(sg), xfcnt);
            }
            isp_prt(isp, ISP_LOGTDEBUG1, "%s: seg%d[%d]%llx:%u", __FUNCTION__, cto->ct_header.rqs_entry_count-1, ovseg, (unsigned long long) addr, bc);

            cto->ct_seg_count++;
            cto->rsp.m0.ct_xfrlen += bc;

            if (crq->req_header.rqs_entry_type == RQSTYPE_A64_CONT) {
                ispcontreq64_t *xrq = (ispcontreq64_t *) crq;
                xrq->req_dataseg[ovseg].ds_count = bc;
                xrq->req_dataseg[ovseg].ds_base = LOWD(addr);
                xrq->req_dataseg[ovseg].ds_basehi = HIWD(addr);
                /*
                 * Make sure we don't cross a 4GB boundary.
                 */
                if (!SAME_4G(addr, bc)) {
                    isp_prt(isp, ISP_LOGTDEBUG1, "seg%d[%d]%llx:%u (TRUNC'd)", cto->ct_header.rqs_entry_count-1, ovseg, (long long)addr, bc);
                    xrq->req_dataseg[ovseg].ds_count = (unsigned int) (FOURG_SEG(addr + bc) - addr);
                    addr += xrq->req_dataseg[ovseg].ds_count;
                    bc -= xrq->req_dataseg[ovseg].ds_count;
                    xfcnt -= xrq->req_dataseg[ovseg].ds_count;
                    /*
                     * Do we have space to split it here?
                     */
                    if (ovseg == lim - 1) {
                        last_synthetic_count = bc;
                        last_synthetic_addr = addr;
                        cto->ct_seg_count++;
                    } else {
                        ovseg++;
                        xrq->req_dataseg[ovseg].ds_count = bc;
                        xrq->req_dataseg[ovseg].ds_base = LOWD(addr);
                        xrq->req_dataseg[ovseg].ds_basehi = HIWD(addr);
                    }
                }
                continue;
            }
            /*
             * We get here if we're a 32 bit continuation entry.
             * We also check for being over 32 bits with our PCI
             * address. If we are, we set ourselves up to do 64
             * bit addressing and start the whole mapping process
             * all over again- we apparently can't really mix types
             */
            if (ISP_A64 && IS_HIGH_ISP_ADDR(addr)) {
                nxti = *nxtip;
                cto->ct_header.rqs_entry_count = 1;
                xfcnt = xact->td_xfrlen;
                cto->ct_header.rqs_entry_type = RQSTYPE_CTIO3;
                if (cto2) {
                    cto2->ct_header.rqs_entry_type = RQSTYPE_CTIO3;
                }
                cto->rsp.m0.ct_xfrlen = 0;
                sg = xact->td_data;
                seglim = ISP_RQDSEG_T3;
                isp_prt(isp, ISP_LOGTDEBUG1, "%s: found hi page in continuation, restarting", __FUNCTION__);
                goto again;
            }
            crq->req_dataseg[ovseg].ds_count = bc;
            crq->req_dataseg[ovseg].ds_base = addr;
            xfcnt -= bc;
        }

        ISP_TDQE(isp, "tdma_mkfc cont", curip, crq);
        MEMORYBARRIER(isp, SYNC_REQUEST, curip, QENTRY_LEN);
        if (crq->req_header.rqs_entry_type == RQSTYPE_A64_CONT) {
            isp_put_cont64_req(isp, (ispcontreq64_t *)crq, (ispcontreq64_t *)qep);
        } else {
            isp_put_cont_req(isp, crq, qep);
        }
    } while (seg < nseg || last_synthetic_count);

    isp_prt(isp, ISP_LOGTDEBUG2, "[%llx]: map %d segments at %p for handle 0x%x", tmd->cd_tagval, new_seg_cnt, xact->td_data, cto->ct_syshandle);

mbxsync:

#ifdef  ALLOW_SYNTHETIC_CTIO
    /*
     * If we have a final CTIO2, allocate and push *that*
     * onto the request queue.
     */
    if (cto2) {
        qe = (ct2_entry_t *) ISP_QUEUE_ENTRY(isp->isp_rquest, nxti);
        curi = nxti;
        nxti = ISP_NXT_QENTRY(curi, RQUEST_QUEUE_LEN(isp));
        if (nxti == optr) {
            pci_unmap_sg(pcs->pci_dev, xact->td_data, nseg, (cto->ct_flags & CT2_DATA_IN)? PCI_DMA_TODEVICE : PCI_DMA_FROMDEVICE);
            isp_prt(isp, ISP_LOGTDEBUG0, "%s: request queue overflow", __FUNCTION__);
            cto->ct_resid = -EAGAIN;
            return (CMD_COMPLETE);
        }
        MEMORYBARRIER(isp, SYNC_REQUEST, curi, QENTRY_LEN);
        isp_put_ctio2(isp, cto2, (ct2_entry_t *)qe);
        ISP_TDQE(isp, "tdma_mkfc:final", curi, cto2);
    }
#endif
    qe = ISP_QUEUE_ENTRY(isp->isp_rquest, isp->isp_reqidx);
    isp_put_ctio2(isp, cto, qe);
    if (cto->ct_flags & CT2_FASTPOST) {
        isp_prt(isp, ISP_LOGTDEBUG1, "[%x] fastpost (0x%x) with entry count %d", cto->ct_rxid, tmd->cd_cdb[0], cto->ct_header.rqs_entry_count);
    }
    ISP_TDQE(isp, "tdma_mkfc", isp->isp_reqidx, cto);
    *nxtip = nxti;
    return (CMD_QUEUED);
}
#endif

static int
isp_pci_dmasetup(ispsoftc_t *isp, Scsi_Cmnd *Cmnd, ispreq_t *rq, uint32_t *nxi, uint32_t optr)
{
    struct scatterlist *sg, *savesg;
    XS_DMA_ADDR_T one_shot_addr, last_synthetic_addr;
    unsigned int one_shot_length, last_synthetic_count;
    int segcnt, seg, ovseg, seglim;
    void *h;
    uint32_t nxti;

#ifdef    ISP_TARGET_MODE
    if (rq->req_header.rqs_entry_type == RQSTYPE_CTIO || rq->req_header.rqs_entry_type == RQSTYPE_CTIO2 ||
            rq->req_header.rqs_entry_type == RQSTYPE_CTIO3) {
        int s;
        if (IS_FC(isp)) {
            s = tdma_mkfc(isp, (tmd_xact_t *)Cmnd, (ct2_entry_t *)rq, nxi, optr);
        } else {
            s = tdma_mk(isp, (tmd_xact_t *)Cmnd, (ct_entry_t *)rq, nxi, optr);
        }
        return (s);
   }
#endif

    nxti = *nxi;
    h = (void *) ISP_QUEUE_ENTRY(isp->isp_rquest, isp->isp_reqidx);

    if (Cmnd->sc_data_direction == SCSI_DATA_NONE || Cmnd->request_bufflen == 0) {
        rq->req_seg_count = 1;
        goto mbxsync;
    }

    if (Cmnd->request_bufflen <= 1024) {
        seg = 0;
    } else if (Cmnd->request_bufflen <= 4096) {
        seg = 1;
    } else if (Cmnd->request_bufflen <= 32768) {
        seg = 2;
    } else if (Cmnd->request_bufflen <= 65536) {
        seg = 3;
    } else if (Cmnd->request_bufflen <= 131372) {
        seg = 4;
    } else if (Cmnd->request_bufflen <= 262144) {
        seg = 5;
    } else if (Cmnd->request_bufflen <= 524288) {
        seg = 6;
    } else {
        seg = 7;
    }
    isp->isp_osinfo.bins[seg]++;

    if (IS_FC(isp)) {
        seglim = ISP_RQDSEG_T2;
        ((ispreqt2_t *)rq)->req_totalcnt = Cmnd->request_bufflen;
        if (Cmnd->sc_data_direction == SCSI_DATA_WRITE) {
            ((ispreqt2_t *)rq)->req_flags |= REQFLAG_DATA_OUT;
        } else if (Cmnd->sc_data_direction == SCSI_DATA_READ) {
            ((ispreqt2_t *)rq)->req_flags |= REQFLAG_DATA_IN;
        } else {
            isp_prt(isp, ISP_LOGERR, "%s: unkown data direction (%x) for %d byte request (opcode 0x%x)", __FUNCTION__,
                Cmnd->sc_data_direction, Cmnd->request_bufflen, Cmnd->cmnd[0]);
            XS_SETERR(Cmnd, HBA_BOTCH);
            return (CMD_COMPLETE);
        }
    } else {
        if (Cmnd->cmd_len > 12) {
            seglim = 0;
        } else {
            seglim = ISP_RQDSEG;
        }
        if (Cmnd->sc_data_direction == SCSI_DATA_WRITE) {
            rq->req_flags |= REQFLAG_DATA_OUT;
        } else if (Cmnd->sc_data_direction == SCSI_DATA_READ) {
            rq->req_flags |= REQFLAG_DATA_IN;
        } else {
            isp_prt(isp, ISP_LOGERR, "%s: unkown data direction (%x) for %d byte request (opcode 0x%x)", __FUNCTION__,
                Cmnd->sc_data_direction, Cmnd->request_bufflen, Cmnd->cmnd[0]);
            XS_SETERR(Cmnd, HBA_BOTCH);
            return (CMD_COMPLETE);
        }
    }

    one_shot_addr = (XS_DMA_ADDR_T) 0;
    one_shot_length = 0;
    if ((segcnt = Cmnd->use_sg) == 0) {
        struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
        segcnt = 1;
        sg = NULL;
        one_shot_length = Cmnd->request_bufflen;
        one_shot_addr = pci_map_single(pcs->pci_dev, Cmnd->request_buffer, Cmnd->request_bufflen, scsi_to_pci_dma_dir(Cmnd->sc_data_direction));
        QLA_HANDLE(Cmnd) = (DMA_HTYPE_T) one_shot_addr;
    } else {
        struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
        sg = (struct scatterlist *) Cmnd->request_buffer;
        segcnt = pci_map_sg(pcs->pci_dev, sg, Cmnd->use_sg, scsi_to_pci_dma_dir(Cmnd->sc_data_direction));
    }
    if (segcnt == 0) {
        isp_prt(isp, ISP_LOGWARN, "%s: unable to dma map request", __FUNCTION__);
        XS_SETERR(Cmnd, HBA_BOTCH);
        return (CMD_EAGAIN);
    }
    savesg = sg;

again:
    last_synthetic_count = 0;
    last_synthetic_addr = 0;
    for (seg = 0, rq->req_seg_count = 0; seg < segcnt && rq->req_seg_count < seglim; seg++, rq->req_seg_count++) {
        XS_DMA_ADDR_T addr;
        unsigned int length;

        if (sg) {
            length = sg_dma_len(sg);
            addr = sg_dma_address(sg);
            sg++;
        } else {
            length = one_shot_length;
            addr = one_shot_addr;
        }

        if (ISP_A64 && IS_HIGH_ISP_ADDR(addr)) {
            if (IS_FC(isp)) {
                if (rq->req_header.rqs_entry_type != RQSTYPE_T3RQS) {
                    rq->req_header.rqs_entry_type = RQSTYPE_T3RQS;
                    seglim = ISP_RQDSEG_T3;
                    sg = savesg;
                    goto again;
                }
           } else {
                if (rq->req_header.rqs_entry_type != RQSTYPE_A64) {
                    rq->req_header.rqs_entry_type = RQSTYPE_A64;
                    seglim = ISP_RQDSEG_A64;
                    sg = savesg;
                    goto again;
                }
           }
        }

        if (ISP_A64 && rq->req_header.rqs_entry_type == RQSTYPE_T3RQS) {
            ispreqt3_t *rq3 = (ispreqt3_t *)rq;
            rq3->req_dataseg[rq3->req_seg_count].ds_count = length;
            rq3->req_dataseg[rq3->req_seg_count].ds_base = LOWD(addr);
            rq3->req_dataseg[rq3->req_seg_count].ds_basehi = HIWD(addr);
            /*
             * Make sure we don't cross a 4GB boundary.
             */
            if (!SAME_4G(addr, length)) {
                isp_prt(isp, ISP_LOGDEBUG1, "seg0[%d]%08x%08x:%u (TRUNC'd)", rq->req_seg_count, (uint32_t)HIWD(addr), (uint32_t)LOWD(addr), length);
                rq3->req_dataseg[rq3->req_seg_count].ds_count = (unsigned int) (FOURG_SEG(addr + length) - addr);
                addr += rq3->req_dataseg[rq3->req_seg_count].ds_count;
                length -= rq3->req_dataseg[rq3->req_seg_count].ds_count;
                /*
                 * Do we have space to split it here?
                 */
                if (rq3->req_seg_count == seglim - 1) {
                    last_synthetic_count = length;
                    last_synthetic_addr = addr;
                } else {
                    rq3->req_seg_count++;
                    rq3->req_dataseg[rq3->req_seg_count].ds_count = length;
                    rq3->req_dataseg[rq3->req_seg_count].ds_base = LOWD(addr);
                    rq3->req_dataseg[rq3->req_seg_count].ds_basehi = HIWD(addr);
                }
            }
        } else if (ISP_A64 && rq->req_header.rqs_entry_type == RQSTYPE_A64) {
            ispreq64_t *rq6 = (ispreq64_t *)rq;
            rq6->req_dataseg[rq6->req_seg_count].ds_count = length;
            rq6->req_dataseg[rq6->req_seg_count].ds_base = LOWD(addr);
            rq6->req_dataseg[rq6->req_seg_count].ds_basehi = HIWD(addr);
            /*
             * Make sure we don't cross a 4GB boundary.
             */
            if (!SAME_4G(addr, length)) {
                isp_prt(isp, ISP_LOGDEBUG1, "seg0[%d]%llx:%u (TRUNC'd)", rq->req_seg_count, (long long)addr, length);
                rq6->req_dataseg[rq6->req_seg_count].ds_count = (unsigned int) (FOURG_SEG(addr + length) - addr);
                addr += rq6->req_dataseg[rq6->req_seg_count].ds_count;
                length -= rq6->req_dataseg[rq6->req_seg_count].ds_count;
                /*
                 * Do we have space to split it here?
                 */
                if (rq6->req_seg_count == seglim - 1) {
                    last_synthetic_count = length;
                    last_synthetic_addr = LOWD(addr);
                } else {
                    rq6->req_seg_count++;
                    rq6->req_dataseg[rq6->req_seg_count].ds_count = length;
                    rq6->req_dataseg[rq6->req_seg_count].ds_base = LOWD(addr);
                    rq6->req_dataseg[rq6->req_seg_count].ds_basehi = HIWD(addr);
                }
            }
        } else if (rq->req_header.rqs_entry_type == RQSTYPE_T2RQS) {
            ispreqt2_t *rq2 = (ispreqt2_t *)rq;
            rq2->req_dataseg[rq2->req_seg_count].ds_count = length;
            rq2->req_dataseg[rq2->req_seg_count].ds_base = addr;
        } else {
            rq->req_dataseg[rq->req_seg_count].ds_count = length;
            rq->req_dataseg[rq->req_seg_count].ds_base = addr;
        }
        isp_prt(isp, ISP_LOGDEBUG1, "seg0[%d]%llx:%u", rq->req_seg_count, (long long)addr, length);
    }

    if (sg == NULL || (seg == segcnt && last_synthetic_count == 0)) {
        goto mbxsync;
    }

    do {
        int lim;
        uint32_t curip;
        ispcontreq_t local, *crq = &local, *qep;

        curip = nxti;
        qep = (ispcontreq_t *) ISP_QUEUE_ENTRY(isp->isp_rquest, curip);
        nxti = ISP_NXT_QENTRY((curip), RQUEST_QUEUE_LEN(isp));
        if (nxti == optr) {
            isp_pci_dmateardown(isp, Cmnd, 0);
            isp_prt(isp, ISP_LOGDEBUG0, "%s: out of space for continuations (%d of %d done)", __FUNCTION__, seg, segcnt);
            XS_SETERR(Cmnd, HBA_BOTCH);
            return (CMD_EAGAIN);
        }
        rq->req_header.rqs_entry_count++;
        MEMZERO((void *)crq, sizeof (*crq));
        crq->req_header.rqs_entry_count = 1;
        if (rq->req_header.rqs_entry_type == RQSTYPE_T3RQS || rq->req_header.rqs_entry_type == RQSTYPE_A64) {
            crq->req_header.rqs_entry_type = RQSTYPE_A64_CONT;
            lim = ISP_CDSEG64;
        } else {
            crq->req_header.rqs_entry_type = RQSTYPE_DATASEG;
            lim = ISP_CDSEG;
        }

        for (ovseg = 0; (seg < segcnt || last_synthetic_count) && ovseg < lim; rq->req_seg_count++, seg++, ovseg++, sg++) {
            XS_DMA_ADDR_T addr;
            unsigned int length;

            if (last_synthetic_count) {
                addr = last_synthetic_addr;
                length = last_synthetic_count;
                last_synthetic_count = 0;
                sg--;
                seg--;
            } else {
                addr = sg_dma_address(sg);
                length = sg_dma_len(sg);
            }

            if (length == 0) {
                panic("zero length s-g element at line %d", __LINE__);
            }
            isp_prt(isp, ISP_LOGDEBUG1, "seg%d[%d]%llx:%u", rq->req_header.rqs_entry_count-1, ovseg, (unsigned long long) addr, length);

            if (crq->req_header.rqs_entry_type == RQSTYPE_A64_CONT) {
                ispcontreq64_t *xrq = (ispcontreq64_t *) crq;
                xrq->req_dataseg[ovseg].ds_count = length;
                xrq->req_dataseg[ovseg].ds_base = LOWD(addr);
                xrq->req_dataseg[ovseg].ds_basehi = HIWD(addr);
                /*
                 * Make sure we don't cross a 4GB boundary.
                 */
                if (!SAME_4G(addr, length)) {
                    isp_prt(isp, ISP_LOGDEBUG1, "seg%d[%d]%llx:%u (TRUNC'd)", rq->req_header.rqs_entry_count-1, ovseg, (long long)addr, length);
                    xrq->req_dataseg[ovseg].ds_count = (unsigned int) (FOURG_SEG(addr + length) - addr);
                    addr += xrq->req_dataseg[ovseg].ds_count;
                    length -= xrq->req_dataseg[ovseg].ds_count;
                    /*
                     * Do we have space to split it here?
                     */
                    if (ovseg == lim - 1) {
                        last_synthetic_count = length;
                        last_synthetic_addr = addr;
                    } else {
                        ovseg++;
                        xrq->req_dataseg[ovseg].ds_count = length;
                        xrq->req_dataseg[ovseg].ds_base = LOWD(addr);
                        xrq->req_dataseg[ovseg].ds_basehi = HIWD(addr);
                    }
                }
                continue;
            }
            /*
             * We get here if we're a 32 bit continuation entry.
             * We also check for being over 32 bits with our PCI
             * address. If we are, we set ourselves up to do 64
             * bit addressing and start the whole mapping process
             * all over again- we apparently can't really mix types
             */
            if (ISP_A64 && IS_HIGH_ISP_ADDR(addr)) {
                if (IS_FC(isp)) {
                    rq->req_header.rqs_entry_type = RQSTYPE_T3RQS;
                    seglim = ISP_RQDSEG_T3;
                } else {
                    rq->req_header.rqs_entry_type = RQSTYPE_A64;
                    seglim = ISP_RQDSEG_A64;
                }
                sg = savesg;
                nxti = *nxi;
                rq->req_header.rqs_entry_count = 1;
                goto again;
            }
            crq->req_dataseg[ovseg].ds_count = length;
            crq->req_dataseg[ovseg].ds_base = addr;
        }
        if (isp->isp_dblev & ISP_LOGDEBUG1) {
            isp_print_qentry(isp, "tdma_mkfc: continuation", curip, crq);
        }
        MEMORYBARRIER(isp, SYNC_REQUEST, curip, QENTRY_LEN);
        if (crq->req_header.rqs_entry_type == RQSTYPE_A64_CONT) {
            isp_put_cont64_req(isp, (ispcontreq64_t *)crq, (ispcontreq64_t *)qep);
        } else {
            isp_put_cont_req(isp, crq, qep);
        }
    } while (seg < segcnt || last_synthetic_count);
mbxsync:
    if (isp->isp_dblev & ISP_LOGDEBUG1) {
        isp_print_qentry(isp, "isp_pci_dmasetup", isp->isp_reqidx, rq);
    }

    if (rq->req_header.rqs_entry_type == RQSTYPE_T3RQS) {
        if (ISP_CAP_2KLOGIN(isp))
            isp_put_request_t3e(isp, (ispreqt3e_t *) rq, (ispreqt3e_t *) h);
        else
            isp_put_request_t3(isp, (ispreqt3_t *) rq, (ispreqt3_t *) h);
    } else if (rq->req_header.rqs_entry_type == RQSTYPE_T2RQS) {
        if (ISP_CAP_2KLOGIN(isp))
            isp_put_request_t2e(isp, (ispreqt2e_t *) rq, (ispreqt2e_t *) h);
        else
            isp_put_request_t2(isp, (ispreqt2_t *) rq, (ispreqt2_t *) h);
    } else {
        isp_put_request(isp, (ispreq_t *) rq, (ispreq_t *) h);
    }
    *nxi = nxti;
    return (CMD_QUEUED);
}

#ifndef ISP_DISABLE_2400_SUPPORT
static int
isp_pci_2400_dmasetup(ispsoftc_t *isp, Scsi_Cmnd *Cmnd, ispreq_t *orig_rq, uint32_t *nxi, uint32_t optr)
{
    struct scatterlist *sg, *savesg;
    ispreqt7_t *rq;
    XS_DMA_ADDR_T addr, one_shot_addr, last_synthetic_addr;
    unsigned int one_shot_length, last_synthetic_count, length;
    int segcnt, seg, ovseg;
    void *h;
    uint32_t nxti;

#ifdef    ISP_TARGET_MODE
    if (orig_rq->req_header.rqs_entry_type == RQSTYPE_CTIO7) {
        return tdma_mk_2400(isp, (tmd_xact_t *)Cmnd, (ct7_entry_t *)orig_rq, nxi, optr);
   }
#endif
    rq = (ispreqt7_t *) orig_rq;
    nxti = *nxi;
    h = (void *) ISP_QUEUE_ENTRY(isp->isp_rquest, isp->isp_reqidx);

    if (Cmnd->sc_data_direction == SCSI_DATA_NONE || Cmnd->request_bufflen == 0) {
        rq->req_seg_count = 0;
        goto mbxsync;
    }

    if (Cmnd->request_bufflen <= 1024) {
        seg = 0;
    } else if (Cmnd->request_bufflen <= 4096) {
        seg = 1;
    } else if (Cmnd->request_bufflen <= 32768) {
        seg = 2;
    } else if (Cmnd->request_bufflen <= 65536) {
        seg = 3;
    } else if (Cmnd->request_bufflen <= 131372) {
        seg = 4;
    } else if (Cmnd->request_bufflen <= 262144) {
        seg = 5;
    } else if (Cmnd->request_bufflen <= 524288) {
        seg = 6;
    } else {
        seg = 7;
    }
    isp->isp_osinfo.bins[seg]++;

    rq->req_dl = Cmnd->request_bufflen;
    rq->req_seg_count = 1;
    if (Cmnd->sc_data_direction == SCSI_DATA_WRITE) {
        rq->req_alen_datadir = FCP_CMND_DATA_WRITE;
    } else if (Cmnd->sc_data_direction == SCSI_DATA_READ) {
        rq->req_alen_datadir = FCP_CMND_DATA_READ;
    } else {
        isp_prt(isp, ISP_LOGERR, "unknown data direction (%x) for %d byte request (opcode 0x%x)",
            Cmnd->sc_data_direction, Cmnd->request_bufflen, Cmnd->cmnd[0]);
        XS_SETERR(Cmnd, HBA_BOTCH);
        return (CMD_COMPLETE);
    }

    one_shot_addr = (XS_DMA_ADDR_T) 0;
    one_shot_length = 0;
    if ((segcnt = Cmnd->use_sg) == 0) {
        struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
        segcnt = 1;
        sg = NULL;
        one_shot_length = Cmnd->request_bufflen;
        one_shot_addr = pci_map_single(pcs->pci_dev, Cmnd->request_buffer, Cmnd->request_bufflen, scsi_to_pci_dma_dir(Cmnd->sc_data_direction));
        QLA_HANDLE(Cmnd) = (DMA_HTYPE_T) one_shot_addr;
    } else {
        struct isp_pcisoftc *pcs = (struct isp_pcisoftc *) isp;
        sg = (struct scatterlist *) Cmnd->request_buffer;
        segcnt = pci_map_sg(pcs->pci_dev, sg, Cmnd->use_sg, scsi_to_pci_dma_dir(Cmnd->sc_data_direction));
    }

    if (segcnt == 0) {
        isp_prt(isp, ISP_LOGWARN, "unable to dma map request");
        XS_SETERR(Cmnd, HBA_BOTCH);
        return (CMD_EAGAIN);
    }

    savesg = sg;

    last_synthetic_count = 0;
    last_synthetic_addr = 0;

    if (sg) {
        length = sg_dma_len(sg);
        addr = sg_dma_address(sg);
        sg++;
    } else {
        length = one_shot_length;
        addr = one_shot_addr;
    }
    seg = 1;

    rq->req_dataseg.ds_base = LOWD(addr);
    rq->req_dataseg.ds_basehi = HIWD(addr);
    rq->req_dataseg.ds_count = length;

    /*
     * Make sure we don't cross a 4GB boundary.
     */
    if (!SAME_4G(addr, length)) {
        isp_prt(isp, ISP_LOGDEBUG1, "seg0[%d]0x%016llx:%u (TRUNC'd)", rq->req_seg_count, (unsigned long long) addr, length);
        rq->req_dataseg.ds_count = (unsigned int) (FOURG_SEG(addr + length) - addr);
        addr += rq->req_dataseg.ds_count;
        length -= rq->req_dataseg.ds_count;
        last_synthetic_count = length;
        last_synthetic_addr = addr;
    }
    isp_prt(isp, ISP_LOGDEBUG1, "seg0[%d]0x%016llx:%u", rq->req_seg_count, (unsigned long long) addr, length);

    if (sg == NULL || (seg == segcnt && last_synthetic_count == 0)) {
        goto mbxsync;
    }

    do {
        int lim;
        uint32_t curip;
        ispcontreq64_t local, *xrq = &local, *qep;

        curip = nxti;
        qep = (ispcontreq64_t *) ISP_QUEUE_ENTRY(isp->isp_rquest, curip);
        nxti = ISP_NXT_QENTRY((curip), RQUEST_QUEUE_LEN(isp));
        if (nxti == optr) {
            isp_pci_dmateardown(isp, Cmnd, 0);
            isp_prt(isp, ISP_LOGWARN, "out of space for continuations (did %d of %d segments)", seg, segcnt);
            XS_SETERR(Cmnd, HBA_BOTCH);
            return (CMD_EAGAIN);
        }
        rq->req_header.rqs_entry_count++;
        MEMZERO((void *)xrq, sizeof (*xrq));
        xrq->req_header.rqs_entry_count = 1;
        xrq->req_header.rqs_entry_type = RQSTYPE_A64_CONT;
        lim = ISP_CDSEG64;

        for (ovseg = 0; (seg < segcnt || last_synthetic_count) && ovseg < lim; rq->req_seg_count++, seg++, ovseg++, sg++) {
            XS_DMA_ADDR_T addr;
            unsigned int length;

            if (last_synthetic_count) {
                addr = last_synthetic_addr;
                length = last_synthetic_count;
                last_synthetic_count = 0;
                sg--;
                seg--;
            } else {
                addr = sg_dma_address(sg);
                length = sg_dma_len(sg);
            }

            if (length == 0) {
                panic("zero length s-g element at line %d", __LINE__);
            }
            isp_prt(isp, ISP_LOGDEBUG1, "seg%d[%d]0x%016llx:%u", rq->req_header.rqs_entry_count-1, ovseg, (unsigned long long) addr, length);

            xrq->req_dataseg[ovseg].ds_count = length;
            xrq->req_dataseg[ovseg].ds_base = LOWD(addr);
            xrq->req_dataseg[ovseg].ds_basehi = HIWD(addr);
            /*
             * Make sure we don't cross a 4GB boundary.
             */
            if (!SAME_4G(addr, length)) {
                isp_prt(isp, ISP_LOGDEBUG1, "seg%d[%d]%llx:%u (TRUNC'd)", rq->req_header.rqs_entry_count-1, ovseg, (unsigned long long)addr, length);
                xrq->req_dataseg[ovseg].ds_count = (unsigned int) (FOURG_SEG(addr + length) - addr);
                addr += xrq->req_dataseg[ovseg].ds_count;
                length -= xrq->req_dataseg[ovseg].ds_count;
                /*
                 * Do we have space to split it here?
                 */
                if (ovseg == lim - 1) {
                    last_synthetic_count = length;
                    last_synthetic_addr = addr;
                } else {
                    ovseg++;
                    xrq->req_dataseg[ovseg].ds_count = length;
                    xrq->req_dataseg[ovseg].ds_base = LOWD(addr);
                    xrq->req_dataseg[ovseg].ds_basehi = HIWD(addr);
                }
            }
        }
        if (isp->isp_dblev & ISP_LOGDEBUG1) {
            isp_print_qentry(isp, "isp_pci_2400_dmasetup continuation", curip, xrq);
        }
        MEMORYBARRIER(isp, SYNC_REQUEST, curip, QENTRY_LEN);
        isp_put_cont64_req(isp, xrq, qep);
    } while (seg < segcnt || last_synthetic_count);
mbxsync:
    if (isp->isp_dblev & ISP_LOGDEBUG1) {
        isp_print_qentry(isp, "isp_pci_2400_dmasetup", isp->isp_reqidx, rq);
    }
    isp_put_request_t7(isp, rq, (ispreqt7_t *) h);
    *nxi = nxti;
    return (CMD_QUEUED);
}
#endif

static void
isp_pci_dmateardown(ispsoftc_t *isp, Scsi_Cmnd *Cmnd, uint32_t handle)
{
    struct isp_pcisoftc *pcs = (struct isp_pcisoftc *)isp;
#ifdef    ISP_TARGET_MODE
    /*
     * The argument passed may not be a Cmnd pointer- this is the
     * safest way to keep the two w/o redoing our internal apis.
     */
    if (IS_TARGET_HANDLE(handle)) {
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
        if (Cmnd->use_sg) {
            pci_unmap_sg(pcs->pci_dev, (struct scatterlist *)Cmnd->request_buffer,
            Cmnd->use_sg, scsi_to_pci_dma_dir(Cmnd->sc_data_direction));
        } else if (Cmnd->request_bufflen) {
            XS_DMA_ADDR_T dhandle = (XS_DMA_ADDR_T) QLA_HANDLE(Cmnd);
            pci_unmap_single(pcs->pci_dev, dhandle, Cmnd->request_bufflen,
            scsi_to_pci_dma_dir(Cmnd->sc_data_direction));
        }
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
    isp->mbintsok = 1;
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
    isp->isp_osinfo.device_id = ((pdev->bus->number) << 16) | (PCI_SLOT(pdev->devfn) << 8) | (PCI_FUNC(pdev->devfn));
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
    ISP_THREAD_KILL(isp);
    ISP_LOCKU_SOFTC(isp);
    isp_shutdown(isp);
    isp->dogactive = 0;
    del_timer(&isp->isp_osinfo.timer);
    ISP_DISABLE_INTS(isp);
    ISP_UNLKU_SOFTC(isp);
    isplinux_pci_release(host);
#ifdef    ISP_FW_CRASH_DUMP
    if (FCPARAM(isp)->isp_dump_data) {
        size_t amt;
        if (IS_2200(isp)) {
            amt = QLA2200_RISC_IMAGE_DUMP_SIZE;
        } else {
            amt = QLA2200_RISC_IMAGE_DUMP_SIZE;
        }
        isp_prt(isp, ISP_LOGCONFIG, "freeing crash dump area");
        isp_kfree(FCPARAM(isp)->isp_dump_data, amt);
        FCPARAM(isp)->isp_dump_data = 0;
    }
#endif
#ifdef    ISP_TARGET_MODE
    isp_deinit_target(isp);
#endif
    scsi_host_put(host);
    if (isp->isp_osinfo.fwp) {
        release_firmware(isp->isp_osinfo.fwp);
        isp->isp_osinfo.fwp = NULL;
    }
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
        printk(KERN_ERR "%s: cannot allocate chrdev region\n", __FUNCTION__);
        return (ret);
    }
    cdev_init(&isp_cdev, &isp_ioctl_operations);
    if (cdev_add(&isp_cdev, isp_dev, MAX_ISP)) {
        printk(KERN_ERR "%s: cannot add cdev\n", __FUNCTION__);
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
	    printk(KERN_ERR "%s: unable to register driver (return value %d)", __FUNCTION__, ret);
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
