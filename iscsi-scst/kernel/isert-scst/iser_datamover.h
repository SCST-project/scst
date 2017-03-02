/*
 * This file is part of iser target kernel module.
 *
 * Copyright (c) 2013 - 2014 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2013 - 2014 Yan Burman (yanb@mellanox.com)
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *            - Redistributions of source code must retain the above
 *              copyright notice, this list of conditions and the following
 *              disclaimer.
 *
 *            - Redistributions in binary form must reproduce the above
 *              copyright notice, this list of conditions and the following
 *              disclaimer in the documentation and/or other materials
 *              provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __ISER_DATAMOVER_H__
#define __ISER_DATAMOVER_H__

#include "../iscsi.h"

/* iscsi layer calling iser */
int isert_datamover_init(void);
int isert_datamover_cleanup(void);

void *isert_portal_add(struct sockaddr *sa, size_t addr_len);
int isert_portal_remove(void *portal_h);

struct iscsi_cmnd *isert_alloc_login_rsp_pdu(struct iscsi_conn *iscsi_conn);

int isert_get_peer_addr(struct iscsi_conn *iscsi_conn, struct sockaddr *sa,
			size_t *addr_len);

int isert_get_target_addr(struct iscsi_conn *iscsi_conn, struct sockaddr *sa,
			  size_t *addr_len);

 /* last: if last transition into FF (Fully Featured) state */
int isert_login_rsp_tx(struct iscsi_cmnd *login_rsp,
		       int last, int discovery);
int isert_set_session_params(struct iscsi_conn *iscsi_conn,
			     struct iscsi_sess_params *sess_params,
			     struct iscsi_tgt_params *tgt_params);

struct iscsi_cmnd *isert_alloc_scsi_rsp_pdu(struct iscsi_conn *iscsi_conn);
struct iscsi_cmnd *isert_alloc_scsi_fake_pdu(struct iscsi_conn *iscsi_conn);

int isert_pdu_tx(struct iscsi_cmnd *pdu);

int isert_request_data_out(struct iscsi_cmnd *cmd);
int isert_send_data_in(struct iscsi_cmnd *cmd, struct iscsi_cmnd *rsp);
int isert_send_status(struct iscsi_cmnd *rsp);

int isert_close_connection(struct iscsi_conn *iscsi_conn);
int isert_task_abort(struct iscsi_cmnd *cmnd);
void isert_free_connection(struct iscsi_conn *iscsi_conn);

void isert_release_tx_pdu(struct iscsi_cmnd *iscsi_pdu);
void isert_release_rx_pdu(struct iscsi_cmnd *cmnd);

/* iser calling iscsi layer */
int isert_conn_established(struct iscsi_conn *iscsi_conn,
			   struct sockaddr *from_addr, int addr_len);
int isert_login_req_rx(struct iscsi_cmnd *login_req);
int isert_pdu_rx(struct iscsi_cmnd *pdu);
int isert_data_out_ready(struct iscsi_cmnd *cmd);
int isert_data_in_sent(struct iscsi_cmnd *cmd);
int isert_pdu_sent(struct iscsi_cmnd *pdu);
void isert_pdu_err(struct iscsi_cmnd *pdu);

void isert_connection_closed(struct iscsi_conn *iscsi_conn);
void isert_connection_abort(struct iscsi_conn *iscsi_conn);

void *isert_get_priv(struct iscsi_conn *iscsi_conn);
void isert_set_priv(struct iscsi_conn *iscsi_conn, void *priv);

#endif
