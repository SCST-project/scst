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

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/in.h>
#include <linux/in6.h>

#ifdef INSIDE_KERNEL_TREE
#include <scst/iscsit_transport.h>
#else
#include "iscsit_transport.h"
#endif
#include "isert_dbg.h"
#include "isert.h"
#include "iser.h"
#include "iser_datamover.h"

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)
unsigned long isert_trace_flag = ISERT_DEFAULT_LOG_FLAGS;
#endif

static unsigned int isert_nr_devs = ISERT_NR_DEVS;
module_param(isert_nr_devs, uint, S_IRUGO);
MODULE_PARM_DESC(isert_nr_devs,
		 "Maximum concurrent number of connection requests to handle (up to 999).");

static void isert_mark_conn_closed(struct iscsi_conn *conn, int flags)
{
	TRACE_ENTRY();
	if (flags & ISCSI_CONN_ACTIVE_CLOSE)
		conn->active_close = 1;
	if (flags & ISCSI_CONN_DELETING)
		conn->deleting = 1;

	conn->read_state = 0;

	if (!conn->closing) {
		conn->closing = 1;
		schedule_work(&conn->close_work);
	}

	TRACE_EXIT();
}

static void isert_close_conn(struct iscsi_conn *conn, int flags)
{
	struct isert_conn_dev *dev;

	dev = isert_get_priv(conn);
	if (dev)
		dev->state = CS_DISCONNECTED;
}

static int isert_receive_cmnd_data(struct iscsi_cmnd *cmnd)
{
#ifdef CONFIG_SCST_EXTRACHECKS
	if (cmnd->scst_state == ISCSI_CMD_STATE_RX_CMD)
		TRACE_DBG("cmnd %p is still in RX_CMD state",
			  cmnd);
#endif
	EXTRACHECKS_BUG_ON(cmnd->scst_state != ISCSI_CMD_STATE_AFTER_PREPROC);
	return 0;
}

static void isert_update_len_sn(struct iscsi_cmnd *cmnd)
{
	TRACE_ENTRY();

	iscsi_cmnd_set_length(&cmnd->pdu);
	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_NOP_IN:
		if (cmnd->pdu.bhs.itt == ISCSI_RESERVED_TAG)
			cmnd->pdu.bhs.sn = (__force u32)cmnd_set_sn(cmnd, 0);
		else
			cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_SCSI_RSP:
		cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_SCSI_TASK_MGT_RSP:
		cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_TEXT_RSP:
		cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_SCSI_DATA_IN:
	{
		struct iscsi_data_in_hdr *rsp =
			(struct iscsi_data_in_hdr *)&cmnd->pdu.bhs;

		cmnd_set_sn(cmnd, (rsp->flags & ISCSI_FLG_FINAL) ? 1 : 0);
		break;
	}
	case ISCSI_OP_LOGOUT_RSP:
		cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_R2T:
		cmnd->pdu.bhs.sn = (__force u32)cmnd_set_sn(cmnd, 0);
		break;
	case ISCSI_OP_ASYNC_MSG:
		cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_REJECT:
		cmnd_set_sn(cmnd, 1);
		break;
	default:
		PRINT_ERROR("Unexpected cmnd op %x", cmnd_opcode(cmnd));
		break;
	}

	TRACE_EXIT();
}

static int isert_process_all_writes(struct iscsi_conn *conn)
{
	struct iscsi_cmnd *cmnd;
	int res = 0;

	TRACE_ENTRY();

	while ((cmnd = iscsi_get_send_cmnd(conn)) != NULL) {
		isert_update_len_sn(cmnd);
		conn_get(conn);
		isert_pdu_tx(cmnd);
	}

	TRACE_EXIT_RES(res);
	return res;
}

static int isert_send_locally(struct iscsi_cmnd *req, unsigned int cmd_count)
{
	int res = 0;

	TRACE_ENTRY();

	req_cmnd_pre_release(req);
	res = isert_process_all_writes(req->conn);
	cmnd_put(req);

	TRACE_EXIT_RES(res);
	return res;
}

static struct iscsi_cmnd *isert_cmnd_alloc(struct iscsi_conn *conn,
					   struct iscsi_cmnd *parent)
{
	struct iscsi_cmnd *cmnd;

	TRACE_ENTRY();

	if (likely(parent))
		cmnd = isert_alloc_scsi_rsp_pdu(conn);
	else
		cmnd = isert_alloc_scsi_fake_pdu(conn);

	iscsi_cmnd_init(conn, cmnd, parent);

	TRACE_EXIT();
	return cmnd;
}

static void isert_cmnd_free(struct iscsi_cmnd *cmnd)
{
	struct isert_cmnd *isert_cmnd = container_of(cmnd, struct isert_cmnd,
						    iscsi);

	TRACE_ENTRY();

#ifdef CONFIG_SCST_EXTRACHECKS
	if (unlikely(cmnd->on_write_list || cmnd->on_write_timeout_list)) {
		struct iscsi_scsi_cmd_hdr *req = cmnd_hdr(cmnd);

		PRINT_CRIT_ERROR("cmnd %p still on some list?, %x, %x, %x, %x, %x, %x, %x",
			cmnd, req->opcode, req->scb[0],
			req->flags, req->itt, be32_to_cpu(req->data_length),
			req->cmd_sn,
			be32_to_cpu((__force __be32)(cmnd->pdu.datasize)));

		if (unlikely(cmnd->parent_req)) {
			struct iscsi_scsi_cmd_hdr *preq =
					cmnd_hdr(cmnd->parent_req);
			PRINT_CRIT_ERROR("%p %x %u", preq, preq->opcode,
					 preq->scb[0]);
		}
		sBUG();
	}
#endif
	if (cmnd->parent_req || isert_cmnd->is_fake_rx)
		isert_release_tx_pdu(cmnd);
	else
		isert_release_rx_pdu(cmnd);

	TRACE_EXIT();
}

static void isert_preprocessing_done(struct iscsi_cmnd *req)
{
	req->scst_state = ISCSI_CMD_STATE_AFTER_PREPROC;
}

static void isert_set_sense_data(struct iscsi_cmnd *rsp,
	const u8 *sense_buf, int sense_len)
{
	u8 *buf;

	buf = sg_virt(rsp->sg) + ISER_HDRS_SZ;

	memcpy(buf, &rsp->sense_hdr, sizeof(rsp->sense_hdr));
	memcpy(&buf[sizeof(rsp->sense_hdr)], sense_buf, sense_len);
}

static void isert_set_req_data(struct iscsi_cmnd *req, struct iscsi_cmnd *rsp)
{
	memcpy(sg_virt(rsp->sg) + ISER_HDRS_SZ,
	       sg_virt(req->sg) + ISER_HDRS_SZ, req->bufflen);
	rsp->bufflen = req->bufflen;
}

static void isert_send_data_rsp(struct iscsi_cmnd *req, u8 *sense,
				int sense_len, u8 status, int is_send_status)
{
	struct iscsi_cmnd *rsp;

	TRACE_ENTRY();

	sBUG_ON(!is_send_status);

	rsp = create_status_rsp(req, status, sense, sense_len);

	isert_update_len_sn(rsp);

	conn_get(rsp->conn);
	if (status != SAM_STAT_CHECK_CONDITION)
		isert_send_data_in(req, rsp);
	else
		isert_pdu_tx(rsp);

	TRACE_EXIT();
}

static void isert_make_conn_wr_active(struct iscsi_conn *conn)
{
	isert_process_all_writes(conn);
}

static int isert_conn_activate(struct iscsi_conn *conn)
{
	return 0;
}

static void isert_free_conn(struct iscsi_conn *conn)
{
	isert_free_connection(conn);
}

void isert_handle_close_connection(struct iscsi_conn *conn)
{
	isert_mark_conn_closed(conn, 0);
	/*
	 * Take care of case where our connection is being closed without
	 * being connected to a session - if connection allocation failed for
	 * some reason.
	 */
	if (unlikely(!conn->session))
		isert_free_connection(conn);
	else
		start_close_conn(conn);
}

int isert_pdu_rx(struct iscsi_cmnd *cmnd)
{
	int res = 0;
	scst_data_direction dir;

	TRACE_ENTRY();

#ifdef CONFIG_SCST_EXTRACHECKS
	cmnd->conn->rd_task = current;
#endif
	iscsi_cmnd_init(cmnd->conn, cmnd, NULL);
	cmnd_rx_start(cmnd);

	if (unlikely(!cmnd->scst_cmd)) {
		cmnd_rx_end(cmnd);
		goto out;
	}

	if (unlikely(scst_cmd_prelim_completed(cmnd->scst_cmd) ||
		     unlikely(cmnd->prelim_compl_flags != 0))) {
		set_bit(ISCSI_CMD_PRELIM_COMPLETED, &cmnd->prelim_compl_flags);
		cmnd_rx_end(cmnd);
		goto out;
	}

	dir = scst_cmd_get_data_direction(cmnd->scst_cmd);

	if (dir & SCST_DATA_WRITE) {
		res = iscsi_cmnd_set_write_buf(cmnd);
		if (unlikely(res))
			goto out;
		res = isert_request_data_out(cmnd);
		cmnd->r2t_len_to_receive = 0;
		cmnd->r2t_len_to_send = 0;
		cmnd->outstanding_r2t = 0;
	} else {
		cmnd_rx_end(cmnd);
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

int isert_data_out_ready(struct iscsi_cmnd *cmnd)
{
	int res = 0;

	TRACE_ENTRY();
#ifdef CONFIG_SCST_EXTRACHECKS
	cmnd->conn->rd_task = current;
#endif
	cmnd_rx_end(cmnd);

	TRACE_EXIT_RES(res);
	return res;
}

int isert_data_in_sent(struct iscsi_cmnd *din)
{
	return 0;
}

void isert_pdu_err(struct iscsi_cmnd *pdu)
{
	struct iscsi_conn *conn = pdu->conn;

	if (!conn->session) /* we are still in login phase */
		return;

	if (pdu->parent_req) {
		rsp_cmnd_release(pdu);
		conn_put(conn);
	} else {
		/*
		 * we will get multiple pdu errors
		 * for same PDU with multiple RDMAs case
		 */
		if (pdu->on_write_timeout_list)
			req_cmnd_release_force(pdu);
	}
}

int isert_pdu_sent(struct iscsi_cmnd *pdu)
{
	struct iscsi_conn *conn = pdu->conn;
	int res = 0;

	TRACE_ENTRY();

	if (unlikely(pdu->should_close_conn)) {
		if (pdu->should_close_all_conn) {
			struct iscsi_target *target =
				pdu->conn->session->target;

			PRINT_INFO("Closing all connections for target %x at initiator's %s request",
				   target->tid, conn->session->initiator_name);
			mutex_lock(&target->target_mutex);
			target_del_all_sess(target, 0);
			mutex_unlock(&target->target_mutex);
		} else {
			PRINT_INFO("Closing connection %p at initiator's %s request",
				   conn, conn->session->initiator_name);
			mark_conn_closed(conn);
		}
	}

	/* we may get NULL parent req for login response */
	if (likely(pdu->parent_req)) {
		rsp_cmnd_release(pdu);
		conn_put(conn);
	}

	TRACE_EXIT_RES(res);
	return res;
}

static ssize_t isert_get_initiator_ip(struct iscsi_conn *conn,
				      char *buf, int size)
{
	int pos;
	struct sockaddr_storage ss;
	size_t addr_len;

	TRACE_ENTRY();

	isert_get_peer_addr(conn, (struct sockaddr *)&ss, &addr_len);

	switch (ss.ss_family) {
	case AF_INET:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		pos = scnprintf(buf, size,
			 "%u.%u.%u.%u",
			 NIPQUAD(((struct sockaddr_in *)&ss)->sin_addr.s_addr));
#else
		pos = scnprintf(buf, size,
			"%pI4", &((struct sockaddr_in *)&ss)->sin_addr.s_addr);
#endif
		break;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	case AF_INET6:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
		pos = scnprintf(buf, size,
			 "[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]",
			 NIP6(((struct sockaddr_in6 *)&ss)->sin6_addr));
#else
		pos = scnprintf(buf, size, "[%pI6]",
			&((struct sockaddr_in6 *)&ss)->sin6_addr);
#endif
		break;
#endif
	default:
		pos = scnprintf(buf, size, "Unknown family %d",
			ss.ss_family);
		break;
	}

	TRACE_EXIT_RES(pos);
	return pos;
}

static struct iscsit_transport isert_transport = {
	.owner = THIS_MODULE,
	.name = "iSER",
	.transport_type = ISCSI_RDMA,
	.iscsit_conn_alloc = isert_conn_alloc,
	.iscsit_conn_activate = isert_conn_activate,
	.iscsit_conn_free = isert_free_conn,
	.iscsit_alloc_cmd = isert_cmnd_alloc,
	.iscsit_free_cmd = isert_cmnd_free,
	.iscsit_preprocessing_done = isert_preprocessing_done,
	.iscsit_send_data_rsp = isert_send_data_rsp,
	.iscsit_make_conn_wr_active = isert_make_conn_wr_active,
	.iscsit_get_initiator_ip = isert_get_initiator_ip,
	.iscsit_send_locally = isert_send_locally,
	.iscsit_mark_conn_closed = isert_mark_conn_closed,
	.iscsit_conn_close = isert_close_conn,
	.iscsit_set_sense_data = isert_set_sense_data,
	.iscsit_set_req_data = isert_set_req_data,
	.iscsit_receive_cmnd_data = isert_receive_cmnd_data,
	.iscsit_close_all_portals = isert_close_all_portals,
};

static void isert_cleanup_module(void)
{
	iscsit_unreg_transport(&isert_transport);
	isert_cleanup_login_devs();
}

static int __init isert_init_module(void)
{
	int ret;

	if (isert_nr_devs > 999) {
		PRINT_ERROR("Invalid argument for isert_nr_devs provded: %d",
			    isert_nr_devs);
		ret = -EINVAL;
		goto out;
	}

	ret = iscsit_reg_transport(&isert_transport);
	if (unlikely(ret))
		goto out;

	ret = isert_init_login_devs(isert_nr_devs);

out:
	return ret;
}

MODULE_AUTHOR("Yan Burman");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("iSER target transport driver v3.0.1-pre#"
		   __stringify(OFED_FLAVOR));

module_init(isert_init_module);
module_exit(isert_cleanup_module);
