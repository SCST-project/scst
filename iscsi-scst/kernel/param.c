/*
 *  Copyright (C) 2005 FUJITA Tomonori <tomof@acm.org>
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

#include "iscsi.h"
#include "digest.h"

#define	CHECK_PARAM(info, iparams, word, min, max)				\
do {										\
	if (!(info)->partial || ((info)->partial & 1 << key_##word)) {		\
		TRACE_DBG("%s: %u", #word, (iparams)[key_##word]);		\
		if ((iparams)[key_##word] < (min) ||				\
			(iparams)[key_##word] > (max)) {			\
			if ((iparams)[key_##word] < (min)) {			\
				(iparams)[key_##word] = (min);			\
				PRINT_WARNING("%s: %u is too small, resetting "	\
					"it to allowed min %u",			\
					#word, (iparams)[key_##word], (min));	\
			} else {						\
				PRINT_WARNING("%s: %u is too big, resetting "	\
					"it to allowed max %u",			\
					#word, (iparams)[key_##word], (max));	\
				(iparams)[key_##word] = (max);			\
			}							\
		}								\
	}									\
} while (0)

#define	SET_PARAM(params, info, iparams, word)					\
({										\
	int changed = 0;							\
	if (!(info)->partial || ((info)->partial & 1 << key_##word)) {		\
		if ((params)->word != (iparams)[key_##word])			\
			changed = 1;						\
		(params)->word = (iparams)[key_##word];				\
		TRACE_DBG("%s set to %u", #word, (params)->word);		\
	}									\
	changed;								\
})

#define	GET_PARAM(params, info, iparams, word)	\
	(iparams)[key_##word] = (params)->word

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
		pos = sprintf(&res[pos], "%s", "None");

	if (val & DIGEST_CRC32C)
		pos += sprintf(&res[pos], "%s%s", (pos != 0) ? ", " : "",
			"CRC32C");

	if (pos == 0)
		sprintf(&res[pos], "%s", "Unknown");

	return res;
}

static void log_params(struct iscsi_sess_params *params)
{
	char hdigest_name[64], ddigest_name[64];

	PRINT_INFO("Negotiated parameters: InitialR2T %s, ImmediateData %s, "
		"MaxConnections %d, MaxRecvDataSegmentLength %d, "
		"MaxXmitDataSegmentLength %d, ",
		iscsi_get_bool_value(params->initial_r2t),
		iscsi_get_bool_value(params->immediate_data), params->max_connections,
		params->max_recv_data_length, params->max_xmit_data_length);
	PRINT_INFO("    MaxBurstLength %d, FirstBurstLength %d, "
		"DefaultTime2Wait %d, DefaultTime2Retain %d, ",
		params->max_burst_length, params->first_burst_length,
		params->default_wait_time, params->default_retain_time);
	PRINT_INFO("    MaxOutstandingR2T %d, DataPDUInOrder %s, "
		"DataSequenceInOrder %s, ErrorRecoveryLevel %d, ",
		params->max_outstanding_r2t,
		iscsi_get_bool_value(params->data_pdu_inorder),
		iscsi_get_bool_value(params->data_sequence_inorder),
		params->error_recovery_level);
	PRINT_INFO("    HeaderDigest %s, DataDigest %s, OFMarker %s, "
		"IFMarker %s, OFMarkInt %d, IFMarkInt %d",
		iscsi_get_digest_name(params->header_digest, hdigest_name),
		iscsi_get_digest_name(params->data_digest, ddigest_name),
		iscsi_get_bool_value(params->ofmarker),
		iscsi_get_bool_value(params->ifmarker),
		params->ofmarkint, params->ifmarkint);
}

/* target_mutex supposed to be locked */
static void sess_params_check(struct iscsi_kern_params_info *info)
{
	int32_t *iparams = info->session_params;
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

	return;
}

/* target_mutex supposed to be locked */
static void sess_params_set(struct iscsi_sess_params *params,
			   struct iscsi_kern_params_info *info)
{
	int32_t *iparams = info->session_params;

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
	return;
}

static void sess_params_get(struct iscsi_sess_params *params,
			   struct iscsi_kern_params_info *info)
{
	int32_t *iparams = info->session_params;

	GET_PARAM(params, info, iparams, initial_r2t);
	GET_PARAM(params, info, iparams, immediate_data);
	GET_PARAM(params, info, iparams, max_connections);
	GET_PARAM(params, info, iparams, max_recv_data_length);
	GET_PARAM(params, info, iparams, max_xmit_data_length);
	GET_PARAM(params, info, iparams, max_burst_length);
	GET_PARAM(params, info, iparams, first_burst_length);
	GET_PARAM(params, info, iparams, default_wait_time);
	GET_PARAM(params, info, iparams, default_retain_time);
	GET_PARAM(params, info, iparams, max_outstanding_r2t);
	GET_PARAM(params, info, iparams, data_pdu_inorder);
	GET_PARAM(params, info, iparams, data_sequence_inorder);
	GET_PARAM(params, info, iparams, error_recovery_level);
	GET_PARAM(params, info, iparams, header_digest);
	GET_PARAM(params, info, iparams, data_digest);
	GET_PARAM(params, info, iparams, ofmarker);
	GET_PARAM(params, info, iparams, ifmarker);
	GET_PARAM(params, info, iparams, ofmarkint);
	GET_PARAM(params, info, iparams, ifmarkint);
	return;
}

/* target_mutex supposed to be locked */
static void tgt_params_check(struct iscsi_session *session,
	struct iscsi_kern_params_info *info)
{
	int32_t *iparams = info->target_params;
	unsigned int rsp_timeout, nop_in_timeout;

	/*
	 * This is only kernel sanity check. Actual data validity checks
	 * performed in the user space.
	 */

	CHECK_PARAM(info, iparams, queued_cmnds, MIN_NR_QUEUED_CMNDS,
		MAX_NR_QUEUED_CMNDS);
	CHECK_PARAM(info, iparams, rsp_timeout, MIN_RSP_TIMEOUT,
		MAX_RSP_TIMEOUT);
	CHECK_PARAM(info, iparams, nop_in_interval, MIN_NOP_IN_INTERVAL,
		MAX_NOP_IN_INTERVAL);
	CHECK_PARAM(info, iparams, nop_in_timeout, MIN_NOP_IN_TIMEOUT,
		MAX_NOP_IN_TIMEOUT);

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
		PRINT_WARNING("%s", "RspTimeout should be >= NopInTimeout, "
			"otherwise data transfer failure could take up to "
			"NopInTimeout long to detect");

	return;
}

/* target_mutex supposed to be locked */
static int iscsi_tgt_params_set(struct iscsi_session *session,
		      struct iscsi_kern_params_info *info, int set)
{
	struct iscsi_tgt_params *params = &session->tgt_params;
	int32_t *iparams = info->target_params;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&session->target->target_mutex);
#endif

	if (set) {
		struct iscsi_conn *conn;

		tgt_params_check(session, info);

		SET_PARAM(params, info, iparams, queued_cmnds);
		SET_PARAM(params, info, iparams, rsp_timeout);
		SET_PARAM(params, info, iparams, nop_in_interval);
		SET_PARAM(params, info, iparams, nop_in_timeout);

		PRINT_INFO("Target parameters set for session %llx: "
			"QueuedCommands %d, Response timeout %d, Nop-In "
			"interval %d, Nop-In timeout %d", session->sid,
			params->queued_cmnds, params->rsp_timeout,
			params->nop_in_interval, params->nop_in_timeout);

		list_for_each_entry(conn, &session->conn_list,
					conn_list_entry) {
			conn->data_rsp_timeout = session->tgt_params.rsp_timeout * HZ;
			conn->nop_in_interval = session->tgt_params.nop_in_interval * HZ;
			conn->nop_in_timeout = session->tgt_params.nop_in_timeout * HZ;
			spin_lock_bh(&conn->conn_thr_pool->rd_lock);
			if (!conn->closing && (conn->nop_in_interval > 0)) {
				TRACE_DBG("Schedule Nop-In work for conn %p", conn);
				schedule_delayed_work(&conn->nop_in_delayed_work,
					conn->nop_in_interval + ISCSI_ADD_SCHED_TIME);
			}
			spin_unlock_bh(&conn->conn_thr_pool->rd_lock);
		}
	} else {
		GET_PARAM(params, info, iparams, queued_cmnds);
		GET_PARAM(params, info, iparams, rsp_timeout);
		GET_PARAM(params, info, iparams, nop_in_interval);
		GET_PARAM(params, info, iparams, nop_in_timeout);
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
	} else
		sess_params_get(params, info);

	return 0;
}

/* target_mutex supposed to be locked */
int iscsi_params_set(struct iscsi_target *target,
	struct iscsi_kern_params_info *info, int set)
{
	int err;
	struct iscsi_session *session;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	lockdep_assert_held(&target->target_mutex);
#endif

	if (info->sid == 0) {
		PRINT_ERROR("sid must not be %d", 0);
		err = -EINVAL;
		goto out;
	}

	session = session_lookup(target, info->sid);
	if (session == NULL) {
		PRINT_ERROR("Session for sid %llx not found", info->sid);
		err = -ENOENT;
		goto out;
	}

	if (set && !list_empty(&session->conn_list) &&
	    (info->params_type != key_target)) {
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
