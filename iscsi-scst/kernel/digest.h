/*
 *  iSCSI digest handling.
 *
 *  Copyright (C) 2004 Xiranet Communications GmbH <arne.redlich@xiranet.com>
 *  Copyright (C) 2007 - 2013 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#ifndef __ISCSI_DIGEST_H__
#define __ISCSI_DIGEST_H__

extern void digest_alg_available(int *val);

extern int digest_init(struct iscsi_conn *conn);

extern int digest_rx_header(struct iscsi_cmnd *cmnd);
extern int digest_rx_data(struct iscsi_cmnd *cmnd);

extern void digest_tx_header(struct iscsi_cmnd *cmnd);
extern void digest_tx_data(struct iscsi_cmnd *cmnd);

#endif /* __ISCSI_DIGEST_H__ */
