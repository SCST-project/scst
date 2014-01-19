/*
 * Marvell 88SE64xx/88SE94xx main function
 *
 * Copyright 2007 Red Hat, Inc.
 * Copyright 2008 Marvell. <kewei@marvell.com>
 *
 * This file is licensed under GPLv2.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
*/


#ifdef SUPPORT_TARGET
#include "mv_sas.h"
#include "mv_spi.h"

static u8    SPICmd[16];

#ifndef IDENTIFY_SPI
u8 DEFAULT_SPI_CMD[16] = {
	0x06, 0x04, 0x05, 0x01, 0x03, 0x02, 0x52, 0x62, 0x15
};
#else
static u8 ATMEL_SPI_CMD[16] = {
	0x06, 0x04, 0x05, 0x01, 0x03, 0x02, 0x52, 0x62, 0x15
};
static u8 WINBOND_SPI_CMD[16] = {
	0x06, 0x04, 0x05, 0x01, 0x03, 0x02, 0x20, 0xC7, 0xAB
};

static u8 ATMEL_SPI_CMD_41a_021[16] = {
	/* 0     1     2     3     4     5     6     7     8     9    10   11*/
	0x06, 0x04, 0x05, 0x01, 0x03, 0x02, 0xD8, 0x60, 0x9F, 0x36, 0x39, 0x3C
};

static u8 EON_F20_SPI_CMD[16] = {
	0x06, 0x04, 0x05, 0x01, 0x03, 0x02, 0x20, 0x60, 0x90
};
#endif

#ifdef IDENTIFY_SPI
#define SPI_IDENTIFY_TIMER		10000

static int spi_atmelidentify(struct mvs_info *mvi)
{
	u32  dwtmp;
	MVS_CHIP_DISP->spi_buildcmd(mvi, &dwtmp,
		ATMEL_SPI_CMD[SPI_INS_RDID],
		1,
		2,
		0);
	MVS_CHIP_DISP->spi_issuecmd(mvi, dwtmp);
	if (0 == MVS_CHIP_DISP->spi_waitdataready(mvi, SPI_IDENTIFY_TIMER)) {
		dwtmp = MVS_CHIP_DISP->spi_read_data(mvi);
		switch (dwtmp) {
		case 0x631f:
			mvi->flashid = AT25F2048;
			mvi->flashsize = 256L * 1024;
			mvi->flashsectSize = 64L * 1024;
			return 0;
		}
	}
	mv_dprintk("identify failed\n");
	return -1;
}

static int spi_atmelidentify_41a_021(struct mvs_info *mvi)
{
	u32  dwTmp;
	MVS_CHIP_DISP->spi_buildcmd(mvi, &dwTmp,
		(u8)ATMEL_SPI_CMD_41a_021[SPI_INS_RDID],
		1,
		2,
		-1);
	MVS_CHIP_DISP->spi_issuecmd(mvi, dwTmp);

	if (0 == MVS_CHIP_DISP->spi_waitdataready(mvi, SPI_IDENTIFY_TIMER)) {
		dwTmp = MVS_CHIP_DISP->spi_read_data(mvi);
		switch (dwTmp) {
		case 0x441f:
			mvi->flashid = AT25DF041A;
			mvi->flashsize = 256L * 1024;
			mvi->flashsectSize = 64L * 1024;
			return 0;
		case 0x431f:
			mvi->flashid = AT25DF021;
			mvi->flashsize = 256L * 1024;
			mvi->flashsectSize = 64L * 1024;
			return 0;
		}
	}

    return -1;
}


static int spi_winbondidentify(struct mvs_info *mvi)
{
	u32  dwTmp;

	MVS_CHIP_DISP->spi_buildcmd(mvi,  &dwTmp,
		WINBOND_SPI_CMD[SPI_INS_RDID],
		1,
		2,
		0);
	MVS_CHIP_DISP->spi_issuecmd(mvi, dwTmp);

	if (0 == MVS_CHIP_DISP->spi_waitdataready(mvi, SPI_IDENTIFY_TIMER)) {
		dwTmp = MVS_CHIP_DISP->spi_read_data(mvi);
		switch (dwTmp) {
		case 0x1212:
			mvi->flashid = W25X40;
			mvi->flashsize = 256L * 1024;
			mvi->flashsectSize = 64L * 1024;
			return 0;
	    }
	}

	return -1;
}

static int spi_eonidentify_f20(struct mvs_info *mvi)
{
	u32  dwTmp;

	MVS_CHIP_DISP->spi_buildcmd(mvi,  &dwTmp,
		EON_F20_SPI_CMD[SPI_INS_RDID],
		1,
		2,
		0);
	MVS_CHIP_DISP->spi_issuecmd(mvi, dwTmp);

	if (0 == MVS_CHIP_DISP->spi_waitdataready(mvi, SPI_IDENTIFY_TIMER)) {
		dwTmp = MVS_CHIP_DISP->spi_read_data(mvi);
		switch (dwTmp) {
		case 0x111C:
			mvi->flashid = EN25F20;
			mvi->flashsize = 256L * 1024;
			mvi->flashsectSize = 4L * 1024;
			return 0;
		}
	}

	return -1;

}
#endif


static int spi_init(struct mvs_info *mvi)
{
	u32  i;
#ifndef IDENTIFY_SPI
	for (i = 0; i < sizeof(SPICmd); i++)
		SPICmd[i] = DEFAULT_SPI_CMD[i];

	mvi->flashid = 0x11ab;
	mvi->flashsize = 256L * 1024;
	mvi->flashsectSize = 64L * 1024;
	return 0;
#else
	u8   *spivendor;

	spivendor = NULL;
	/* Identify Atmel first. Suppose it's popular.Don't identify Mxic
	 *  since it can use the same instruction set as Atmel.
	 * If cannot identify, by default use Atmel instruction set. */
	if (0 == spi_atmelidentify(mvi))
		spivendor = ATMEL_SPI_CMD;
	else if (0 == spi_atmelidentify_41a_021(mvi))
		spivendor = ATMEL_SPI_CMD_41a_021;
	else if (0 == spi_winbondidentify(mvi))
		spivendor = WINBOND_SPI_CMD;
	else if (0 == spi_eonidentify_f20(mvi))
		spivendor = EON_F20_SPI_CMD;
	else
		spivendor = ATMEL_SPI_CMD;

	if (spivendor) {
		for (i = 0; i < sizeof(SPICmd); i++)
			SPICmd[i] = spivendor[i];
		return 0;
	}
	return -1;
#endif
}

static int spi_read(struct mvs_info *mvi, u32 addr, u8 *data, u8 size)
{
	u32  i, dwTmp;

	if (size > 4)
		size = 4;
	MVS_CHIP_DISP->spi_buildcmd(mvi, &dwTmp,
		(u8)SPICmd[SPI_INS_READ],
		1,
		size,
		addr);
	MVS_CHIP_DISP->spi_issuecmd(mvi, dwTmp);

	if (0 == MVS_CHIP_DISP->spi_waitdataready(mvi, 10000)) {
		dwTmp = MVS_CHIP_DISP->spi_read_data(mvi);
		for (i = 0; i < size; i++)
			data[i] = ((u8 *)&dwTmp)[i];
		return 0;
	} else
	    mv_dprintk("timeout\n");

	return -1;
}

static int spi_readbuf(struct mvs_info *mvi, u32 addr, u8 *data, u32 count)
{
	u32      i, j;
	u32      tmpAddr, tmpdata, addrend;
	u8       *val = data;

	addrend = addr + count;
	tmpAddr = rounding(addr, 4);
	j = (addr & ((1U<<2) - 1));
	if (j > 0) {
		spi_read(mvi, tmpAddr, (u8 *)&tmpdata, 4);
		for (i = j; i < 4; i++)
			*val++ = ((u8 *)&tmpdata)[i];
		tmpAddr += 4;
	}
	j = rounding(addrend, 4);
	for (; tmpAddr < j; tmpAddr += 4) {
		spi_read(mvi, tmpAddr, (u8 *)&tmpdata, 4);
		*((u32 *)val) = tmpdata;
		val += 4;
	}
	if (tmpAddr < addrend) {
		spi_read(mvi, tmpAddr, (u8 *)&tmpdata, 4);
		count = addrend - tmpAddr;
		for (i = 0; i < count; i++)
			*val++ = ((u8 *)&tmpdata)[i];
	}

    return 0;
}

static u8 mvverifychecksum(u8 *address, u32 Size)
{
	u8	checkSum = 0;
	u32	temp = 0;

	for (temp = 0; temp < Size; temp++)
		checkSum += address[temp];

	return	checkSum;
}

static bool mvui_init_param(struct mvs_info *mvi,
			    struct hba_info_main *hba_info_para)
{
	u32	param_flash_addr = PARA_OFF;

	if (!mvi)
		return false;

	if (spi_init(mvi)) {
		mv_dprintk("Init flash rom failed.\n");
		return false;
	}
	mv_dprintk("Init flash rom ok,flash type is 0x%x.\n", mvi->flashid);
	/* step 1 read param from flash offset = 0x3FFF00 */
	spi_readbuf(mvi, param_flash_addr, (u8 *)hba_info_para,
		    FLASH_PARA_SIZE);

	/* step 2 check the signature first */
	if (hba_info_para->signature[0] == 'M' &&
	    hba_info_para->signature[1] == 'R' &&
	    hba_info_para->signature[2] == 'V' &&
	    hba_info_para->signature[3] == 'L' &&
	    (!mvverifychecksum((u8 *)hba_info_para, FLASH_PARA_SIZE))) {
		return true;
	}
	return false;
}

u8 mvs_spi_init(struct mvs_info *mvi)
{
	u8 i;
	u64 sas_addr;
	struct hba_info_main hba_info_para;

	do {
		if (!mvui_init_param(mvi, &hba_info_para)) {
			for (i = 0; i < mvi->chip->n_phy; i++) {
				sas_addr = 0x5005043011ab0000ULL;
				if (mvi->id == 1)
					sas_addr = 0x5005043011ab0001ULL;
				mvi->phy[i].dev_sas_addr =
					cpu_to_be64((u64)(*(u64 *)&sas_addr));
			}
			return -1;
		}
		for (i = 0; i < mvi->chip->n_phy; i++) {
			int vphy = i+mvi->id*mvi->chip->n_phy;
			sas_addr = hba_info_para.sas_address[vphy];
			mvi->phy[i].dev_sas_addr = sas_addr;
			mv_printk("Phy %d SAS ADDRESS %016llx\n", i,
				SAS_ADDR(&mvi->phy[i].dev_sas_addr));
		}
	} while (0);

	memcpy(mvi->sas_addr, &mvi->phy[0].dev_sas_addr, SAS_ADDR_SIZE);

	return 0;
}
#endif   /*SUPPORT_TARGET*/

