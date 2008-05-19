/*****************************************************************************
*                  QLOGIC LINUX SOFTWARE
*
* QLogic ISP2x00 device driver ioctl definition file
* Copyright (C) 2005 QLogic Corporation
* (www.qlogic.com)
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License as published by the
* Free Software Foundation; either version 2, or (at your option) any
* later version.
*
* This program is distributed in the hope that it will be useful, but
* WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* General Public License for more details.
****************************************************************************/

/*
 * File Name: exioctln.h

   Rev 24    October 06, 2005	RL
	     - Added reserve internal ioctl command code for future use.

   Rev 23    June 22, 2005	RL
	     - Corrected assignment condition of EXT_ADDR_MODE_OS value.

   Rev 22    February 25, 2005	RL
	     - Added reserve internal ioctl command codes.

   Rev 21    February 1, 2005	RL
	     - Deleted AdapterModel field and bit definition for
	       EXT_LN_DRIVER_DATA.

   Rev 20    December 20, 2004	RL
	     - Decreased MAX_HBA_OS value again.

   Rev 19    September 9, 2004	RL
	     - Added AdapterModel field and bit definition for
	       EXT_LN_DRIVER_DATA.

   Rev 18    August 6, 2004	RL
	     - Added 'Flags' field and bit defines for EXT_LN_DRIVER_DATA.
	     - Corrected UINT64 define to real 64 bit.
	     - Corrected ioctl command value definition so it is
	       the same value in both 32bit and 64bit environments.
	     - Added NFO command values.
	     - Changed EXT_CC_STARTIOCTL to EXT_CC_GET_HBA_CNT.

   Rev 17    August 08, 2003	RL
	     - Decreased MAX_HBA_OS value to both decrease wasted space
	       in shared mem so it can be used to store other data, and
	       to decrease unnecesary loops checking through all adapters.

   Rev 16    July 31, 2003	RL
	     - Added definitions for Status field in discovered target
	       structure.
	     - Updated ioctl command value assignment on PPC64 so this
	       file can be shared with API lib.

   Rev 15    June 03, 2003	RL
	     - Modified ioctl command code value assignment so it also
	       works on PPC64.

   Rev 14    February 25, 2003	RL
             - Added EXT_CC_DRIVER_SPECIFIC ioctl command to return
	       some driver specific data that can be used by API library
	       to determine how to maintain backward compatibility
	       of certain features.

   Rev 13    January 31, 2003	RL
             - Changed the value of EXT_DEF_USE_HBASELECT to avoid
               conflicting with older implementation of FO API lib.

   Rev 12    January 20, 2003	RL
             - Added EXT_DEF_USE_HBASELECT definition for use by
               the SETINSTANCE command.

   Rev 11    December 10, 2002	RL
             - Added EXT_CC_SEND_ELS_PASSTHRU_OS definition.

   Rev 10    October 26, 2001	RL
             - Corrected MAX_HBA, MAX_TARGET and MAX_LUN values to 255.

   Rev 9     July 26, 2001	RL
             - Added definition of signed types.

   Rev 8     July 05, 2001	RL
             - Redefined ioctl command values.

   Rev 7     Nov 06, 2000   BN
             - Added EXT_DEF_MAX_AEN_QUEUE_OS define
             - Added define for handle_hba_t

   Rev 6     Oct 25, 2000   BN
             - Added EXT_CC_DRIVER_PROP_OS define

   Rev 5     Oct 25, 2000   BN
             - Redo the copyright header and add AEN details

   Rev 4     Oct 23, 2000   BN
             - Added definition for BOOLEAN

   Rev 3     Oct 23, 2000   BN
             - Added definitions for EXT_ADDR_MODE_OS
               and also include of <linux/ioctl.h>

   Rev 2     Oct 18, 2000   BN
             - Enable API Exention support

   Rev 1     Original version Sep 7, 2000   BN

*/


#ifndef _EXIOCT_LN_H_
#define _EXIOCT_LN_H_

#include <linux/ioctl.h>

#ifdef APILIB
#include <stdint.h>
#include <linux/types.h>
#include <bits/wordsize.h>
#endif


#ifndef INT8
#define	INT8		int8_t
#endif

#ifndef INT16
#define	INT16		int16_t
#endif

#ifndef INT32
#define	INT32		int32_t
#endif

#ifndef UINT8
#define	UINT8		uint8_t
#endif

#ifndef UINT16
#define	UINT16		uint16_t
#endif

#ifndef UINT32
#define	UINT32		uint32_t
#endif

#ifndef UINT64
#define	UINT64		uint64_t
#endif

#ifndef UINT64_O
#define	UINT64_O	void *	/* old define for FC drivers */
#endif

#ifndef BOOLEAN
#define BOOLEAN		uint8_t
#endif

#ifndef HANDLE
#define HANDLE		int
#endif



#if __WORDSIZE == 64
#define EXT_ADDR_MODE_OS  EXT_DEF_ADDR_MODE_64
#else
#define EXT_ADDR_MODE_OS  EXT_DEF_ADDR_MODE_32
#endif


#define QLMULTIPATH_MAGIC 'y'

#define _QLBUILD   /* for exioct.h to enable include of qinsdmgt.h */


#define	EXT_DEF_MAX_HBA_OS		31	/* 0x1F */
#define	EXT_DEF_MAX_HBAS		32	/* 0 - 0x1F */

#define	EXT_DEF_MAX_BUS_OS		1

#define	EXT_DEF_MAX_TARGET_OS		255	/* 0xFE */
#define	EXT_DEF_MAX_TARGETS		256	/* 0 - 0xFE */

#define	EXT_DEF_MAX_LUN_OS		255	/* 0xFE */
#define	EXT_DEF_MAX_LUNS		256	/* 0 - 0xFE */

#define EXT_DEF_MAX_AEN_QUEUE_OS        64
#define EXT_DEF_MAX_TGTEV_QUEUE_OS      256	/* max tgts in driver */
#define	EXT_DEF_MAX_NFOEV_QUEUE_OS	256

#define EXT_DEF_FC_HEADER_LEN		24
#define EXT_DEF_ELS_RJT_LENGTH		0x08	/* 8  */
#define EXT_DEF_ELS_RPS_ACC_LENGTH	0x40	/* 64 */
#define EXT_DEF_ELS_RLS_ACC_LENGTH	0x1C	/* 28 */

#define EXT_DEF_USE_HBASELECT		0x02	/* bit 1: HbaSelect field now
						 * used to specify destination
						 * HBA of each command.
						 * SetInstance cmd is now
						 * issued only once during
						 * API initialization.
						 */

/* target status flags */
#define EXT_DEF_TGTSTAT_OFFLINE		0x01
#define EXT_DEF_TGTSTAT_IN_CFG		0x02

#define EXT_DEF_REGULAR_SIGNATURE	"QLOGIC"


/*****************/
/* Command codes */
/*****************/
#define	QL_IOCTL_BASE(idx)	\
    _IOWR(QLMULTIPATH_MAGIC, idx, EXT_IOCTL)

#define	QL_IOCTL_CMD(idx)	QL_IOCTL_BASE(idx)

/***************************************************************
 * These are regular/external command codes, starting from 0.
 * The regular command code end index must be updated whenever
 * adding new commands.
 ***************************************************************/
#define EXT_DEF_LN_REG_CC_START_IDX	0x00	/* reg cmd start index */

#define EXT_CC_QUERY_OS					/* QUERY */	\
    QL_IOCTL_CMD(0x00)
#define EXT_CC_SEND_FCCT_PASSTHRU_OS			/* FCCT_PASSTHRU */ \
    QL_IOCTL_CMD(0x01)
#define	EXT_CC_REG_AEN_OS				/* REG_AEN */	\
    QL_IOCTL_CMD(0x02)
#define	EXT_CC_GET_AEN_OS				/* GET_AEN */	\
    QL_IOCTL_CMD(0x03)
#define	EXT_CC_SEND_ELS_RNID_OS				/* SEND_ELS_RNID */ \
    QL_IOCTL_CMD(0x04)
#define	EXT_CC_SCSI_PASSTHRU_OS				/* SCSI_PASSTHRU */ \
    QL_IOCTL_CMD(0x05)

#define EXT_CC_GET_DATA_OS				/* GET_DATA */	\
    QL_IOCTL_CMD(0x06)
#define EXT_CC_SET_DATA_OS				/* SET_DATA */	\
    QL_IOCTL_CMD(0x07)

#define EXT_DEF_LN_REG_CC_END_IDX	0x07	/* reg cmd end index */

/*****************************************
 * Following are internal command codes.
 * See inioct.h.
 *****************************************/
#define EXT_DEF_LN_INT_CC_START_IDX	0x08	/* int cmd start index */
#define EXT_CC_RESERVED0A_OS						\
    QL_IOCTL_CMD(0x08)
#define EXT_CC_RESERVED0B_OS						\
    QL_IOCTL_CMD(0x09)

#define EXT_CC_RESERVED0C_OS						\
    QL_IOCTL_CMD(0x0a)
#define EXT_CC_RESERVED0D_OS						\
    QL_IOCTL_CMD(0x0b)

#define EXT_CC_RESERVED0E_OS						\
    QL_IOCTL_CMD(0x0c)
#define EXT_CC_RESERVED0F_OS						\
    QL_IOCTL_CMD(0x0d)

#define EXT_CC_RESERVED0G_OS						\
    QL_IOCTL_CMD(0x0e)
#define EXT_CC_RESERVED0H_OS						\
    QL_IOCTL_CMD(0x0f)

#define EXT_CC_RESERVED0I_OS						\
    QL_IOCTL_CMD(0x10)
#define EXT_CC_RESERVED0J_OS						\
    QL_IOCTL_CMD(0x11)
#define EXT_CC_RESERVED0K_OS						\
    QL_IOCTL_CMD(0x12)
#define EXT_CC_RESERVED0L_OS						\
    QL_IOCTL_CMD(0x13)

#define EXT_CC_RESERVED0Z_OS						\
    QL_IOCTL_CMD(0x21)

#define EXT_DEF_LN_INT_CC_END_IDX	0x21	/* supported int cmd end idx */

/********************************************************/
/* These are additional regular/external command codes. */
/********************************************************/
#define EXT_DEF_LN_ADD_CC_START_IDX	0x30	/* additional cmd start index */
#define EXT_CC_SEND_ELS_PASSTHRU_OS					\
    QL_IOCTL_CMD(0x30)
#define EXT_DEF_LN_ADD_CC_END_IDX	0x30	/* additional cmd end index */


/********************************************************
 * NextGen Failover (NFO) ioctl command codes range from
 * 0x37 to 0x4f.  See qlnfoln.h
 ********************************************************/


/********************************************************
 * Failover ioctl command codes range from 0xc0 to 0xdf.
 * See definition in qlfoln.h.
 ********************************************************/


/*******************************************************************/
/* These are Linux driver implementation specific commands. Values */
/* start from highest possible value and in decreasing order.      */
/*******************************************************************/
#define EXT_DEF_LN_SPC_CC_START_IDX	0xff	/* LN specific cmd start idx */

#define EXT_CC_GET_HBA_CNT				/* GET_HBA_CNT */ \
    QL_IOCTL_CMD(0xff)
#define EXT_CC_SETINSTANCE				/* SETINSTANCE */ \
    QL_IOCTL_CMD(0xfe)
#define	EXT_CC_WWPN_TO_SCSIADDR				/* WWPN_TO_SCSIADDR */ \
    QL_IOCTL_CMD(0xfd)
#define	EXT_CC_DRIVER_SPECIFIC				/* DRIVER_SPECIFIC */ \
    QL_IOCTL_CMD(0xfc)

#define EXT_DEF_LN_SPC_CC_END_IDX	0xfc	/* LN specific cmd end idx */


/*
 * Response struct definition
 */
typedef struct _EXT_LN_DRV_VERSION {
	UINT8	Major;
	UINT8	Minor;
	UINT8	Patch;
	UINT8	Beta;
	UINT8	Reserved[4];
} EXT_LN_DRV_VERSION;				/* 8 */

typedef struct _EXT_LN_DRIVER_DATA {
	EXT_LN_DRV_VERSION  	DrvVer;		/* 8 */
	UINT32	Flags;				/* 4 */
	UINT32	Reserved[13];			/* 52 */
} EXT_LN_DRIVER_DATA, *PEXT_LN_DRIVER_DATA;	/* 64 */

/* Bit defines for the Flags field */
#define EXT_DEF_NGFO_CAPABLE		0x0001	/* bit 0: failover capable */
#define EXT_DEF_NGFO_ENABLED		0x0002	/* bit 1: failover enabled */



/*
 * Overrides for Emacs so that we almost follow Linus's tabbing style.
 * Emacs will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-indent-level: 2
 * c-brace-imaginary-offset: 0
 * c-brace-offset: -2
 * c-argdecl-indent: 2
 * c-label-offset: -2
 * c-continued-statement-offset: 4
 * c-continued-brace-offset: 0
 * indent-tabs-mode: nil
 * tab-width: 8
 * End:
 */

#endif /* _EXIOCT_LN_H_ */

