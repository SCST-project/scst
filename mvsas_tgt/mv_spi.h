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
#ifndef _MV_SPI_H_
#define _MV_SPI_H_

#define IDENTIFY_SPI		1
#define FLASH_SIZE		0x40000
#define PARA_OFF		(FLASH_SIZE - 0x100)

#define NVRAM_DATA_MAJOR_VERSION		0
#define NVRAM_DATA_MINOR_VERSION		1

#define AT25F2048			0x0101
#define AT25DF041A			0x0102
#define AT25DF021			0x0103

#define MX25L2005               0x0201
#define MX25L4005               0x0202
#define MX25L8005               0x0203
#define W25X40				0x0301
#define EN25F20				0x0401


#define SPI_INS_WREN			0
#define SPI_INS_WRDI			1
#define SPI_INS_RDSR			2
#define SPI_INS_WRSR			3
#define SPI_INS_READ			4
#define SPI_INS_RPOG			5
#define SPI_INS_SERASE			6
#define SPI_INS_CERASE			7
#define SPI_INS_RDID			8
#define SPI_INS_PRSEC			9
#define SPI_INS_UPTSEC			10
#define SPI_INS_RDPT			11


#define MAX_PD_IN_PD_PAGE_FLASH		128
#define FLASH_PARA_SIZE		(sizeof(struct hba_info_main))
#define rounding_mask(x, mask)  (((x)+(mask))&~(mask))
#define rounding(value, align)  rounding_mask(value,   \
						 (typeof(value)) (align-1))
#define offset_of(type, member) offsetof(type, member)

#define PAGE_INTERVAL_DISTANCE		0x100

struct hba_info_main {
	u8	signature[4];
	u8	reserve[52];
	u64	sas_address[8];
	u8	reserved4[135];
	u8	checksum;
};	/* total 256 bytes */
u8 mvs_spi_init(struct mvs_info *mvi);

#endif
#endif	 /*SUPPORT_TARGET*/
