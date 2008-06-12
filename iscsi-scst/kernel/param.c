/*
 *  Copyright (C) 2005 FUJITA Tomonori <tomof@acm.org>
 *  Copyright (C) 2007 - 2008 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2008 CMS Distribution Limited
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

#define	CHECK_PARAM(info, iparam, word, min, max)				\
do {										\
	if (!(info)->partial || ((info)->partial & 1 << key_##word))		\
		if ((iparam)[key_##word] < (min) ||				\
			(iparam)[key_##word] > (max)) {				\
			PRINT_ERROR("%s: %u is out of range (%u %u)",		\
				#word, (iparam)[key_##word], (min), (max));	\
			if ((iparam)[key_##word] < (min))			\
				(iparam)[key_##word] = (min);			\
			else							\
				(iparam)[key_##word] = (max);			\
		}								\
} while (0)

#define	SET_PARAM(param, info, iparam, word)					\
({										\
	int changed = 0;							\
	if (!(info)->partial || ((info)->partial & 1 << key_##word)) {		\
		if ((param)->word != (iparam)[key_##word])			\
			changed = 1;						\
		(param)->word = (iparam)[key_##word];				\
	}									\
	changed;								\
})

#define	GET_PARAM(param, info, iparam, word)					\
do {										\
	(iparam)[key_##word] = (param)->word;					\
} while (0)

static const char *get_bool_name(int val)
{
	if (val)
		return "Yes";
	else
		return "No";
}

static const char *get_digest_name(int val)
{
	if (val == DIGEST_NONE)
		return "None";
	else if (val == DIGEST_CRC32C)
		return "CRC32C";
	else
		return "Unknown";
}

static void log_params(struct iscsi_sess_param *param)
{
	PRINT_INFO("Negotiated parameters: InitialR2T %s, ImmediateData %s, "
		"MaxConnections %d, MaxRecvDataSegmentLength %d, "
		"MaxXmitDataSegmentLength %d, ", get_bool_name(param->initial_r2t),
		get_bool_name(param->immediate_data), param->max_connections,
		param->max_recv_data_length, param->max_xmit_data_length);
	PRINT_INFO("    MaxBurstLength %d, FirstBurstLength %d, "
		"DefaultTime2Wait %d, DefaultTime2Retain %d, ",
		param->max_burst_length, param->first_burst_length,
		param->default_wait_time, param->default_retain_time);
	PRINT_INFO("    MaxOutstandingR2T %d, DataPDUInOrder %s, "
		"DataSequenceInOrder %s, ErrorRecoveryLevel %d, ",
		param->max_outstanding_r2t, get_bool_name(param->data_pdu_inorder),
		get_bool_name(param->data_sequence_inorder),
		param->error_recovery_level);
	PRINT_INFO("    HeaderDigest %s, DataDigest %s, OFMarker %s, "
		"IFMarker %s, OFMarkInt %d, IFMarkInt %d",
		get_digest_name(param->header_digest),
		get_digest_name(param->data_digest),
		get_bool_name(param->ofmarker), get_bool_name(param->ifmarker),
		param->ofmarkint, param->ifmarkint);
}

/* target_mutex supposed to be locked */
static void sess_param_check(struct iscsi_param_info *info)
{
	u32 *iparam = info->session_param;

	CHECK_PARAM(info, iparam, max_connections, 1, 1);
	CHECK_PARAM(info, iparam, max_recv_data_length, 512,
		    (u32) (ISCSI_CONN_IOV_MAX * PAGE_SIZE));
	CHECK_PARAM(info, iparam, max_xmit_data_length, 512,
		    (u32) (ISCSI_CONN_IOV_MAX * PAGE_SIZE));
	CHECK_PARAM(info, iparam, error_recovery_level, 0, 0);
	CHECK_PARAM(info, iparam, data_pdu_inorder, 0, 1);
	CHECK_PARAM(info, iparam, data_sequence_inorder, 0, 1);

	digest_alg_available(&iparam[key_header_digest]);
	digest_alg_available(&iparam[key_data_digest]);

	CHECK_PARAM(info, iparam, ofmarker, 0, 0);
	CHECK_PARAM(info, iparam, ifmarker, 0, 0);
}

/* target_mutex supposed to be locked */
static void sess_param_set(struct iscsi_sess_param *param, struct iscsi_param_info *info)
{
	u32 *iparam = info->session_param;

	SET_PARAM(param, info, iparam, initial_r2t);
	SET_PARAM(param, info, iparam, immediate_data);
	SET_PARAM(param, info, iparam, max_connections);
	SET_PARAM(param, info, iparam, max_recv_data_length);
	SET_PARAM(param, info, iparam, max_xmit_data_length);
	SET_PARAM(param, info, iparam, max_burst_length);
	SET_PARAM(param, info, iparam, first_burst_length);
	SET_PARAM(param, info, iparam, default_wait_time);
	SET_PARAM(param, info, iparam, default_retain_time);
	SET_PARAM(param, info, iparam, max_outstanding_r2t);
	SET_PARAM(param, info, iparam, data_pdu_inorder);
	SET_PARAM(param, info, iparam, data_sequence_inorder);
	SET_PARAM(param, info, iparam, error_recovery_level);
	SET_PARAM(param, info, iparam, header_digest);
	SET_PARAM(param, info, iparam, data_digest);
	SET_PARAM(param, info, iparam, ofmarker);
	SET_PARAM(param, info, iparam, ifmarker);
	SET_PARAM(param, info, iparam, ofmarkint);
	SET_PARAM(param, info, iparam, ifmarkint);
}

static void sess_param_get(struct iscsi_sess_param *param, struct iscsi_param_info *info)
{
	u32 *iparam = info->session_param;

	GET_PARAM(param, info, iparam, initial_r2t);
	GET_PARAM(param, info, iparam, immediate_data);
	GET_PARAM(param, info, iparam, max_connections);
	GET_PARAM(param, info, iparam, max_recv_data_length);
	GET_PARAM(param, info, iparam, max_xmit_data_length);
	GET_PARAM(param, info, iparam, max_burst_length);
	GET_PARAM(param, info, iparam, first_burst_length);
	GET_PARAM(param, info, iparam, default_wait_time);
	GET_PARAM(param, info, iparam, default_retain_time);
	GET_PARAM(param, info, iparam, max_outstanding_r2t);
	GET_PARAM(param, info, iparam, data_pdu_inorder);
	GET_PARAM(param, info, iparam, data_sequence_inorder);
	GET_PARAM(param, info, iparam, error_recovery_level);
	GET_PARAM(param, info, iparam, header_digest);
	GET_PARAM(param, info, iparam, data_digest);
	GET_PARAM(param, info, iparam, ofmarker);
	GET_PARAM(param, info, iparam, ifmarker);
	GET_PARAM(param, info, iparam, ofmarkint);
	GET_PARAM(param, info, iparam, ifmarkint);
}

/* target_mutex supposed to be locked */
static void trgt_param_check(struct iscsi_param_info *info)
{
	u32 *iparam = info->target_param;

	CHECK_PARAM(info, iparam, queued_cmnds, MIN_NR_QUEUED_CMNDS, MAX_NR_QUEUED_CMNDS);
}

/* target_mutex supposed to be locked */
static void trgt_param_set(struct iscsi_target *target, struct iscsi_param_info *info)
{
	struct iscsi_trgt_param *param = &target->trgt_param;
	u32 *iparam = info->target_param;

	SET_PARAM(param, info, iparam, queued_cmnds);
}

/* target_mutex supposed to be locked */
static void trgt_param_get(struct iscsi_trgt_param *param, struct iscsi_param_info *info)
{
	u32 *iparam = info->target_param;

	GET_PARAM(param, info, iparam, queued_cmnds);
}

/* target_mutex supposed to be locked */
static int trgt_param(struct iscsi_target *target, struct iscsi_param_info *info, int set)
{
	if (set) {
		struct iscsi_trgt_param *prm;
		trgt_param_check(info);
		trgt_param_set(target, info);

		prm = &target->trgt_param;
		PRINT_INFO("Target parameter changed: QueuedCommands %d",
			prm->queued_cmnds);
	} else
		trgt_param_get(&target->trgt_param, info);

	return 0;
}

/* target_mutex supposed to be locked */
static int sess_param(struct iscsi_target *target, struct iscsi_param_info *info, int set)
{
	struct iscsi_session *session = NULL;
	struct iscsi_sess_param *param;
	int err = -ENOENT;

	if (set)
		sess_param_check(info);

	if (info->sid) {
		session = session_lookup(target, info->sid);
		if (!session)
			goto out;
		if (set && !list_empty(&session->conn_list)) {
			err = -EBUSY;
			goto out;
		}
		param = &session->sess_param;
	} else
		param = &target->trgt_sess_param;

	if (set) {
		sess_param_set(param, info);
		if (session != NULL)
			log_params(param);
	} else
		sess_param_get(param, info);

	err = 0;
out:
	return err;
}

/* target_mutex supposed to be locked */
int iscsi_param_set(struct iscsi_target *target, struct iscsi_param_info *info, int set)
{
	int err;

	if (info->param_type == key_session)
		err = sess_param(target, info, set);
	else if (info->param_type == key_target)
		err = trgt_param(target, info, set);
	else
		err = -EINVAL;

	return err;
}
