/*
 * Retain the original licensing text; SPDX conversion requires a separate license audit.
 */
/* checkpatch-suppress-file SPDX_LICENSE_TAG ; See the contract above. */
/*
 *  Copyright (C) 2005 FUJITA Tomonori <tomof@acm.org>
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

#include "iscsi_trace_flag.h"
#include "iscsi.h"
#include "digest.h"

static bool iscsi_param_selected(const struct iscsi_kern_params_info *info, unsigned int key)
{
	return !info->partial || (info->partial & (1U << key));
}

static void iscsi_param_check(const struct iscsi_kern_params_info *info, s32 *iparams,
			      unsigned int key, const char *name, s32 min, s32 max)
{
	s32 *value;

	if (!iscsi_param_selected(info, key))
		return;

	value = &iparams[key];
	TRACE_DBG("%s: %d", name, *value);
	if (*value < min) {
		PRINT_WARNING("%s: %d is too small, resetting it to allowed min %d",
			      name, *value, min);
		*value = min;
	} else if (*value > max) {
		PRINT_WARNING("%s: %d is too big, resetting it to allowed max %d",
			      name, *value, max);
		*value = max;
	}
}

#define CHECK_PARAM(info, iparams, word, min, max)			\
	iscsi_param_check(info, iparams, key_##word, #word, min, max)

/*
 * The word parameter is a structure member or a name token, not an expression; parentheses would
 * make its member access invalid.
 */
/* checkpatch-suppress-macro MACRO_ARG_PRECEDENCE ; See the contract above. */
#define SET_PARAM(params, info, iparams, word)				\
do {									\
	if (iscsi_param_selected(info, key_##word)) {			\
		s32 __value = (iparams)[key_##word];			\
									\
		(params)->word = __value;				\
		TRACE_DBG("%s set to %d", #word, __value);		\
	}								\
} while (0)

/*
 * The word parameter is a structure member or a name token, not an expression;
 * parentheses would make its member access invalid.
 */
/* checkpatch-suppress-macro MACRO_ARG_PRECEDENCE ; See the contract above. */
#define	GET_PARAM(params, iparams, word)	\
	((iparams)[key_##word] = (params)->word)

const char *iscsi_get_bool_value(int val)
{
	if (val)
		return "Yes";
	else
		return "No";
}

const char *iscsi_get_digest_name(int val, char *res)
{
	int pos = 0;

	if (val & DIGEST_NONE)
		pos = sprintf(&res[pos], "None");

	if (val & DIGEST_CRC32C)
		pos += sprintf(&res[pos], "%s%s", (pos != 0) ? ", " : "",
			"CRC32C");

	if (pos == 0)
		sprintf(&res[pos], "Unknown");

	return res;
}

static void log_params(struct iscsi_sess_params *params)
{
	char hdigest_name[64], ddigest_name[64];

	PRINT_INFO("Negotiated parameters: InitialR2T %s, ImmediateData %s, MaxConnections %d, MaxRecvDataSegmentLength %d, MaxXmitDataSegmentLength %d, ",
		   iscsi_get_bool_value(params->initial_r2t),
		   iscsi_get_bool_value(params->immediate_data),
		   params->max_connections,
		   params->max_recv_data_length, params->max_xmit_data_length);
	PRINT_INFO("    MaxBurstLength %d, FirstBurstLength %d, DefaultTime2Wait %d, DefaultTime2Retain %d, ",
		   params->max_burst_length, params->first_burst_length,
		   params->default_wait_time, params->default_retain_time);
	PRINT_INFO("    MaxOutstandingR2T %d, DataPDUInOrder %s, DataSequenceInOrder %s, ErrorRecoveryLevel %d, ",
		   params->max_outstanding_r2t,
		   iscsi_get_bool_value(params->data_pdu_inorder),
		   iscsi_get_bool_value(params->data_sequence_inorder),
		   params->error_recovery_level);
	PRINT_INFO("    HeaderDigest %s, DataDigest %s, OFMarker %s, IFMarker %s, OFMarkInt %d, IFMarkInt %d, RDMAExtensions %s",
		   iscsi_get_digest_name(params->header_digest, hdigest_name),
		   iscsi_get_digest_name(params->data_digest, ddigest_name),
		   iscsi_get_bool_value(params->ofmarker),
		   iscsi_get_bool_value(params->ifmarker),
		   params->ofmarkint, params->ifmarkint,
		   iscsi_get_bool_value(params->rdma_extensions));
}

/* target_mutex supposed to be locked */
static void sess_params_check(struct iscsi_kern_params_info *info)
{
	s32 *iparams = info->session_params;
	const int max_len = ISCSI_CONN_IOV_MAX * PAGE_SIZE;

	/*
	 * This is only kernel sanity check. Actual data validity checks
	 * performed in the user space.
	 */

	CHECK_PARAM(info, iparams, initial_r2t, 0, 1);
	CHECK_PARAM(info, iparams, immediate_data, 0, 1);
	CHECK_PARAM(info, iparams, max_connections, 1, 1);
	CHECK_PARAM(info, iparams, max_recv_data_length, 512, max_len);
	CHECK_PARAM(info, iparams, max_xmit_data_length, 512, max_len);
	CHECK_PARAM(info, iparams, max_burst_length, 512, max_len);
	CHECK_PARAM(info, iparams, first_burst_length, 512, max_len);
	CHECK_PARAM(info, iparams, max_outstanding_r2t, 1, 65535);
	CHECK_PARAM(info, iparams, error_recovery_level, 0, 0);
	CHECK_PARAM(info, iparams, data_pdu_inorder, 0, 1);
	CHECK_PARAM(info, iparams, data_sequence_inorder, 0, 1);

	digest_alg_available(&iparams[key_header_digest]);
	digest_alg_available(&iparams[key_data_digest]);

	CHECK_PARAM(info, iparams, ofmarker, 0, 0);
	CHECK_PARAM(info, iparams, ifmarker, 0, 0);

	/* iSER related parameters */
	CHECK_PARAM(info, iparams, rdma_extensions, 0, 1);
	CHECK_PARAM(info, iparams, target_recv_data_length, 512, max_len);
	CHECK_PARAM(info, iparams, initiator_recv_data_length, 512, max_len);
}

/* target_mutex supposed to be locked */
static void sess_params_set(struct iscsi_sess_params *params,
			    const struct iscsi_kern_params_info *info)
{
	const s32 *iparams = info->session_params;

	SET_PARAM(params, info, iparams, initial_r2t);
	SET_PARAM(params, info, iparams, immediate_data);
	SET_PARAM(params, info, iparams, max_connections);
	SET_PARAM(params, info, iparams, max_recv_data_length);
	SET_PARAM(params, info, iparams, max_xmit_data_length);
	SET_PARAM(params, info, iparams, max_burst_length);
	SET_PARAM(params, info, iparams, first_burst_length);
	SET_PARAM(params, info, iparams, default_wait_time);
	SET_PARAM(params, info, iparams, default_retain_time);
	SET_PARAM(params, info, iparams, max_outstanding_r2t);
	SET_PARAM(params, info, iparams, data_pdu_inorder);
	SET_PARAM(params, info, iparams, data_sequence_inorder);
	SET_PARAM(params, info, iparams, error_recovery_level);
	SET_PARAM(params, info, iparams, header_digest);
	SET_PARAM(params, info, iparams, data_digest);
	SET_PARAM(params, info, iparams, ofmarker);
	SET_PARAM(params, info, iparams, ifmarker);
	SET_PARAM(params, info, iparams, ofmarkint);
	SET_PARAM(params, info, iparams, ifmarkint);

	/* iSER related parameters */
	SET_PARAM(params, info, iparams, rdma_extensions);
	SET_PARAM(params, info, iparams, target_recv_data_length);
	SET_PARAM(params, info, iparams, initiator_recv_data_length);
}

static void sess_params_get(const struct iscsi_sess_params *params,
			    struct iscsi_kern_params_info *info)
{
	s32 *iparams = info->session_params;

	GET_PARAM(params, iparams, initial_r2t);
	GET_PARAM(params, iparams, immediate_data);
	GET_PARAM(params, iparams, max_connections);
	GET_PARAM(params, iparams, max_recv_data_length);
	GET_PARAM(params, iparams, max_xmit_data_length);
	GET_PARAM(params, iparams, max_burst_length);
	GET_PARAM(params, iparams, first_burst_length);
	GET_PARAM(params, iparams, default_wait_time);
	GET_PARAM(params, iparams, default_retain_time);
	GET_PARAM(params, iparams, max_outstanding_r2t);
	GET_PARAM(params, iparams, data_pdu_inorder);
	GET_PARAM(params, iparams, data_sequence_inorder);
	GET_PARAM(params, iparams, error_recovery_level);
	GET_PARAM(params, iparams, header_digest);
	GET_PARAM(params, iparams, data_digest);
	GET_PARAM(params, iparams, ofmarker);
	GET_PARAM(params, iparams, ifmarker);
	GET_PARAM(params, iparams, ofmarkint);
	GET_PARAM(params, iparams, ifmarkint);

	/* iSER related parameters */
	GET_PARAM(params, iparams, rdma_extensions);
	GET_PARAM(params, iparams, target_recv_data_length);
	GET_PARAM(params, iparams, initiator_recv_data_length);
}

/* target_mutex supposed to be locked */
static void tgt_params_check(struct iscsi_session *session, struct iscsi_kern_params_info *info)
{
	s32 *iparams = info->target_params;
	unsigned int rsp_timeout, nop_in_timeout;

	/*
	 * This is only kernel sanity check. Actual data validity checks
	 * performed in the user space.
	 */

	CHECK_PARAM(info, iparams, queued_cmnds, MIN_NR_QUEUED_CMNDS, MAX_NR_QUEUED_CMNDS);
	CHECK_PARAM(info, iparams, rsp_timeout, MIN_RSP_TIMEOUT, MAX_RSP_TIMEOUT);
	CHECK_PARAM(info, iparams, nop_in_interval, MIN_NOP_IN_INTERVAL, MAX_NOP_IN_INTERVAL);
	CHECK_PARAM(info, iparams, nop_in_timeout, MIN_NOP_IN_TIMEOUT, MAX_NOP_IN_TIMEOUT);

	/*
	 * We adjust too long timeout in req_add_to_write_timeout_list()
	 * only for NOPs, so check and warn if this assumption isn't honored.
	 */
	if (!info->partial || (info->partial & 1 << key_rsp_timeout))
		rsp_timeout = iparams[key_rsp_timeout];
	else
		rsp_timeout = session->tgt_params.rsp_timeout;
	if (!info->partial || (info->partial & 1 << key_nop_in_timeout))
		nop_in_timeout = iparams[key_nop_in_timeout];
	else
		nop_in_timeout = session->tgt_params.nop_in_timeout;
	if (nop_in_timeout > rsp_timeout)
		PRINT_WARNING("RspTimeout should be >= NopInTimeout, otherwise data transfer failure could take up to NopInTimeout long to detect");
}

/* target_mutex supposed to be locked */
static int iscsi_tgt_params_set(struct iscsi_session *session, struct iscsi_kern_params_info *info,
				int set)
{
	struct iscsi_tgt_params *params = &session->tgt_params;
	s32 *iparams = info->target_params;

	lockdep_assert_held(&session->target->target_mutex);

	if (set) {
		struct iscsi_conn *conn;

		tgt_params_check(session, info);

		SET_PARAM(params, info, iparams, queued_cmnds);
		SET_PARAM(params, info, iparams, rsp_timeout);
		SET_PARAM(params, info, iparams, nop_in_interval);
		SET_PARAM(params, info, iparams, nop_in_timeout);

		PRINT_INFO("Target parameters set for session %llx: QueuedCommands %d, Response timeout %d, Nop-In interval %d, Nop-In timeout %d",
			   session->sid,
			   params->queued_cmnds, params->rsp_timeout,
			   params->nop_in_interval, params->nop_in_timeout);

		list_for_each_entry(conn, &session->conn_list, conn_list_entry) {
			conn->data_rsp_timeout =
				session->tgt_params.rsp_timeout * HZ;
			conn->nop_in_interval =
				session->tgt_params.nop_in_interval * HZ;
			conn->nop_in_timeout =
				session->tgt_params.nop_in_timeout * HZ;
			spin_lock_bh(&conn->conn_thr_pool->rd_lock);
			if (!conn->closing && conn->nop_in_interval > 0) {
				TRACE_DBG("Schedule Nop-In work for conn %p",
					  conn);
				schedule_delayed_work(&conn->nop_in_delayed_work,
						      conn->nop_in_interval + ISCSI_ADD_SCHED_TIME);
			}
			spin_unlock_bh(&conn->conn_thr_pool->rd_lock);
		}
	} else {
		GET_PARAM(params, iparams, queued_cmnds);
		GET_PARAM(params, iparams, rsp_timeout);
		GET_PARAM(params, iparams, nop_in_interval);
		GET_PARAM(params, iparams, nop_in_timeout);
	}

	return 0;
}

/* target_mutex supposed to be locked */
static int iscsi_sess_params_set(struct iscsi_session *session,
				 struct iscsi_kern_params_info *info, int set)
{
	struct iscsi_sess_params *params;

	if (set)
		sess_params_check(info);

	params = &session->sess_params;

	if (set) {
		sess_params_set(params, info);
		log_params(params);
	} else {
		sess_params_get(params, info);
	}

	return 0;
}

/* target_mutex supposed to be locked */
int iscsi_params_set(struct iscsi_target *target, struct iscsi_kern_params_info *info, int set)
{
	int err;
	struct iscsi_session *session;

	lockdep_assert_held(&target->target_mutex);

	if (info->sid == 0) {
		PRINT_ERROR("sid must not be %d", 0);
		err = -EINVAL;
		goto out;
	}

	session = session_lookup(target, info->sid);
	if (!session) {
		PRINT_ERROR("Session for sid %llx not found", info->sid);
		err = -ENOENT;
		goto out;
	}

	if (set && !list_empty(&session->conn_list) && info->params_type != key_target) {
		err = -EBUSY;
		goto out;
	}

	if (info->params_type == key_session)
		err = iscsi_sess_params_set(session, info, set);
	else if (info->params_type == key_target)
		err = iscsi_tgt_params_set(session, info, set);
	else
		err = -EINVAL;

out:
	return err;
}
