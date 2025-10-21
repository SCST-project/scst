/*
 *  iSCSI digest handling.
 *
 *  Copyright (C) 2004 Xiranet Communications GmbH <arne.redlich@xiranet.com>
 *  Copyright (C) 2007 - 2018 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2018 Western Digital Corporation
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

struct iscsi_conn;
struct iscsi_cmnd;

void digest_alg_available(int *val);

int digest_init(struct iscsi_conn *conn);

int digest_rx_header(struct iscsi_cmnd *cmnd);
int digest_rx_data(struct iscsi_cmnd *cmnd);

void digest_tx_header(struct iscsi_cmnd *cmnd);
void digest_tx_data(struct iscsi_cmnd *cmnd);

#endif /* __ISCSI_DIGEST_H__ */
