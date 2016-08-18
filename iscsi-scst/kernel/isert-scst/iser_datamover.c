/*
* isert_datamover.c
*
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

#include <linux/kernel.h>

#include "isert_dbg.h"
#include "iser.h"
#include "iser_datamover.h"

int isert_datamover_init(void)
{
	int err;

	err = isert_global_init();
	if (unlikely(err)) {
		PRINT_ERROR("iser datamover init failed, err:%d", err);
		return err;
	}
	return 0;
}

int isert_datamover_cleanup(void)
{
	isert_global_cleanup();
	return 0;
}

int isert_get_peer_addr(struct iscsi_conn *iscsi_conn, struct sockaddr *sa,
			size_t *addr_len)
{
	int ret;
	struct isert_connection *isert_conn = container_of(iscsi_conn,
						struct isert_connection, iscsi);
	struct sockaddr *peer_sa = (struct sockaddr *)&isert_conn->peer_addr;

	ret = isert_get_addr_size(peer_sa, addr_len);
	if (unlikely(ret))
		goto out;

	memcpy(sa, peer_sa, *addr_len);
out:
	return ret;
}

int isert_get_target_addr(struct iscsi_conn *iscsi_conn, struct sockaddr *sa,
			  size_t *addr_len)
{
	int ret;
	struct isert_connection *isert_conn = container_of(iscsi_conn,
						struct isert_connection, iscsi);
	struct sockaddr *self_sa = (struct sockaddr *)&isert_conn->self_addr;

	ret = isert_get_addr_size(self_sa, addr_len);
	if (unlikely(ret))
		goto out;

	memcpy(sa, self_sa, *addr_len);
out:
	return ret;
}

void *isert_portal_add(struct sockaddr *saddr, size_t addr_len)
{
	return isert_portal_start(saddr, addr_len);
}

int isert_portal_remove(void *portal_h)
{
	struct isert_portal *portal = portal_h;

	isert_portal_release(portal);
	return 0;
}

void isert_free_connection(struct iscsi_conn *iscsi_conn)
{
	struct isert_connection *isert_conn = container_of(iscsi_conn,
						struct isert_connection, iscsi);

	isert_post_drain(isert_conn);
	isert_conn_free(isert_conn);
}

struct iscsi_cmnd *isert_alloc_login_rsp_pdu(struct iscsi_conn *iscsi_conn)
{
	struct isert_connection *isert_conn = container_of(iscsi_conn,
						struct isert_connection, iscsi);
	struct isert_cmnd *isert_pdu = isert_conn->login_rsp_pdu;

	isert_tx_pdu_init(isert_pdu, isert_conn);
	return &isert_pdu->iscsi;
}

static struct iscsi_cmnd *isert_alloc_scsi_pdu(struct iscsi_conn *iscsi_conn,
					       int fake)
{
	struct isert_connection *isert_conn = container_of(iscsi_conn,
						struct isert_connection, iscsi);
	struct isert_cmnd *isert_pdu;

again:
	spin_lock(&isert_conn->tx_lock);
	if (list_empty(&isert_conn->tx_free_list)) {
		spin_unlock(&isert_conn->tx_lock);
		goto again;
	}
	isert_pdu = list_first_entry(&isert_conn->tx_free_list,
				     struct isert_cmnd, pool_node);
	list_move(&isert_pdu->pool_node, &isert_conn->tx_busy_list);
	spin_unlock(&isert_conn->tx_lock);

	isert_pdu->is_fake_rx = fake;
	return &isert_pdu->iscsi;
}

struct iscsi_cmnd *isert_alloc_scsi_rsp_pdu(struct iscsi_conn *iscsi_conn)
{
	return isert_alloc_scsi_pdu(iscsi_conn, 0);
}

struct iscsi_cmnd *isert_alloc_scsi_fake_pdu(struct iscsi_conn *iscsi_conn)
{
	return isert_alloc_scsi_pdu(iscsi_conn, 1);
}

void isert_release_tx_pdu(struct iscsi_cmnd *iscsi_pdu)
{
	struct isert_cmnd *isert_pdu = container_of(iscsi_pdu,
						    struct isert_cmnd, iscsi);
	struct isert_connection *isert_conn = container_of(iscsi_pdu->conn,
						struct isert_connection, iscsi);

	isert_tx_pdu_init_iscsi(isert_pdu);

	spin_lock(&isert_conn->tx_lock);
	list_move(&isert_pdu->pool_node, &isert_conn->tx_free_list);
	spin_unlock(&isert_conn->tx_lock);
}

void isert_release_rx_pdu(struct iscsi_cmnd *iscsi_pdu)
{
	struct isert_cmnd *isert_pdu = container_of(iscsi_pdu,
						    struct isert_cmnd, iscsi);

	isert_rx_pdu_done(isert_pdu);
}

/* if last transition into FF (Fully Featured) state */
int isert_login_rsp_tx(struct iscsi_cmnd *login_rsp, int last, int discovery)
{
	struct isert_connection *isert_conn = container_of(login_rsp->conn,
						struct isert_connection, iscsi);
	int err;

	if (last && !discovery) {
		err = isert_alloc_conn_resources(isert_conn);
		if (unlikely(err)) {
			PRINT_ERROR("Failed to init conn resources");
			return err;
		}
		isert_pdu_free(isert_conn->login_req_pdu);
		isert_conn->login_req_pdu = NULL;
	} else {
		err = isert_post_recv(isert_conn,
					  &isert_conn->login_req_pdu->wr[0],
					  1);
		if (unlikely(err)) {
			PRINT_ERROR("Failed to post recv login req rx buf, err:%d", err);
			return err;
		}
	}

	return isert_pdu_tx(login_rsp);
}

int isert_set_session_params(struct iscsi_conn *iscsi_conn,
			     struct iscsi_sess_params *sess_params,
			     struct iscsi_tgt_params *tgt_params)
{
	struct isert_connection *isert_conn = container_of(iscsi_conn,
						struct isert_connection, iscsi);

	isert_conn->queue_depth = tgt_params->queued_cmnds;

	isert_conn->immediate_data = sess_params->immediate_data;
	isert_conn->target_recv_data_length = sess_params->target_recv_data_length;
	isert_conn->initial_r2t = sess_params->initial_r2t;
	isert_conn->first_burst_length = sess_params->first_burst_length;
	isert_conn->initiator_recv_data_length = sess_params->initiator_recv_data_length;

	return 0;
}

int isert_pdu_tx(struct iscsi_cmnd *iscsi_cmnd)
{
	struct isert_cmnd *isert_cmnd = container_of(iscsi_cmnd,
						    struct isert_cmnd, iscsi);
	struct isert_connection *isert_conn = container_of(iscsi_cmnd->conn,
						struct isert_connection, iscsi);
	int err;

	isert_tx_pdu_convert_from_iscsi(isert_cmnd, iscsi_cmnd);
	err = isert_pdu_send(isert_conn, isert_cmnd);

	return err;
}

int isert_request_data_out(struct iscsi_cmnd *iscsi_cmnd)
{
	struct isert_cmnd *isert_cmnd = container_of(iscsi_cmnd,
						    struct isert_cmnd, iscsi);
	struct isert_connection *isert_conn = container_of(iscsi_cmnd->conn,
						struct isert_connection, iscsi);
	int ret;

	ret = isert_prepare_rdma(isert_cmnd, isert_conn, ISER_WR_RDMA_READ);
	if (unlikely(ret < 0))
		return ret;

	ret = isert_pdu_post_rdma_read(isert_conn, isert_cmnd, ret);

	return ret;
}

int isert_send_data_in(struct iscsi_cmnd *iscsi_cmnd,
		       struct iscsi_cmnd *iscsi_rsp)
{
	struct isert_cmnd *isert_cmnd = container_of(iscsi_cmnd,
						    struct isert_cmnd, iscsi);
	struct isert_connection *isert_conn = container_of(iscsi_cmnd->conn,
						struct isert_connection, iscsi);
	struct isert_cmnd *isert_rsp = container_of(iscsi_rsp,
						    struct isert_cmnd, iscsi);
	int ret;

	ret = isert_prepare_rdma(isert_cmnd, isert_conn, ISER_WR_RDMA_WRITE);
	if (unlikely(ret < 0))
		return ret;

	isert_tx_pdu_convert_from_iscsi(isert_rsp, iscsi_rsp);
	ret = isert_pdu_post_rdma_write(isert_conn, isert_cmnd, isert_rsp, ret);

	return ret;
}

int isert_close_connection(struct iscsi_conn *iscsi_conn)
{
	struct isert_connection *isert_conn = container_of(iscsi_conn,
						struct isert_connection, iscsi);

	isert_conn_disconnect(isert_conn);

	return 0;
}

int isert_task_abort(struct iscsi_cmnd *cmnd)
{
	return 0;
}

void *isert_get_priv(struct iscsi_conn *iscsi_conn)
{
	struct isert_connection *isert_conn = container_of(iscsi_conn,
						struct isert_connection, iscsi);

	return isert_conn->priv_data;
}

void isert_set_priv(struct iscsi_conn *iscsi_conn, void *priv)
{
	struct isert_connection *isert_conn = container_of(iscsi_conn,
					struct isert_connection, iscsi);

	isert_conn->priv_data = priv;
}
