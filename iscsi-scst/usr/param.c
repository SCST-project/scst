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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>

#include "iscsid.h"

/* Taken from Linux kernel sources */
size_t strlcpy(char *dest, const char *src, size_t size)
{
	size_t ret = strlen(src);

	if (size) {
		size_t len = (ret >= size) ? size - 1 : ret;
		memcpy(dest, src, len);
		dest[len] = '\0';
	}
	return ret;
}

int params_index_by_name(char *name, struct iscsi_key *keys)
{
	int i, err = -ENOENT;

	for (i = 0; keys[i].name; i++) {
		if (!strcasecmp(keys[i].name, name)) {
			err = i;
			break;
		}
	}

	return err;
}

int params_index_by_name_numwild(char *name, struct iscsi_key *keys)
{
	int i, err = -ENOENT;

	for (i = 0; keys[i].name; i++) {
		if (!strncasecmp(keys[i].name, name, strlen(keys[i].name))) {
			int j;
			if (strlen(keys[i].name) > strlen(name))
				continue;
			for (j = strlen(keys[i].name); j < strlen(name); j++) {
				if (!isdigit(name[j]))
					goto next;
			}
			err = i;
			break;
next:
			continue;
		}
	}

	return err;
}

void params_set_defaults(unsigned int *params, struct iscsi_key *keys)
{
	int i;

	for (i = 0; keys[i].name; i++)
		params[i] = keys[i].local_def;

	return;
}

static int range_val_to_str(unsigned int val, char *str, int len)
{
	snprintf(str, len, "%u", val);
	return 0;
}

static int range_str_to_val(char *str, unsigned int *val)
{
	*val = strtol(str, NULL, 0);
	return 0;
}

static int bool_val_to_str(unsigned int val, char *str, int len)
{
	int err = 0;

	switch (val) {
	case 0:
		strlcpy(str, "No", len);
		break;
	case 1:
		strlcpy(str, "Yes", len);
		break;
	default:
		err = -EINVAL;
	}

	return err;
}

static int bool_str_to_val(char *str, unsigned int *val)
{
	int err = 0;

	if (!strcmp(str, "Yes"))
		*val = 1;
	else if (!strcmp(str, "No"))
		*val = 0;
	else
		err = -EINVAL;

	return err;
}

static int or_set_val(struct iscsi_param *param, int idx, unsigned int *val)
{
	*val |= param[idx].val;
	param[idx].val = *val;

	return 0;
}

static int and_set_val(struct iscsi_param *param, int idx, unsigned int *val)
{
	*val &= param[idx].val;
	param[idx].val = *val;

	return 0;
}

static int num_check_val(struct iscsi_key *key, unsigned int *val)
{
	int err = 0;

	if (*val < key->min) {
		*val = key->min;
		err = -EINVAL;
	} else if (*val > key->max) {
		*val = key->max;
		err = -EINVAL;
	}

	return err;
}

static int minimum_set_val(struct iscsi_param *param, int idx, unsigned int *val)
{
	if (*val > param[idx].val)
		*val = param[idx].val;
	param[idx].val = *val;
	return 0;
}

static int maximum_set_val(struct iscsi_param *param, int idx, unsigned int *val)
{
	if (param[idx].val > *val)
		*val = param[idx].val;
	param[idx].val = *val;
	return 0;
}

static int digest_val_to_str(unsigned int val, char *str, int len)
{
	int pos = 0;

	if (val & DIGEST_NONE) {
		len -= pos;
		pos = snprintf(&str[pos], len, "%s", "None");
	}

	if (pos >= len)
		goto out;

	if (val & DIGEST_CRC32C) {
		len -= pos;
		pos = snprintf(&str[pos], len, "%s%s",
			(pos != 0) ? "," : "", "CRC32C");
	}

	if (pos >= len)
		goto out;

	if (pos == 0)
		pos = snprintf(&str[0], len, "%s", "Unknown");

out:
	return 0;
}

static int digest_str_to_val(char *str, unsigned int *val)
{
	int err = 0;
	char *p, *q;
	p = str;

	*val = 0;
	do {
		while ((*p != '\0') && isspace(*p))
			p++;
		if (!strncasecmp(p, "None", strlen("None")))
			*val |= DIGEST_NONE;
		else if (!strncasecmp(p, "CRC32C", strlen("CRC32C")))
			*val |= DIGEST_CRC32C;
		else {
			err = -EINVAL;
			break;
		}

		if ((q = strchr(p, ',')))
			p = q + 1;
	} while (q);

	if (*val == 0)
		*val = DIGEST_NONE;

	return err;
}

static int digest_set_val(struct iscsi_param *param, int idx, unsigned int *val)
{
	if (*val & DIGEST_CRC32C && param[idx].val & DIGEST_CRC32C)
		*val = DIGEST_CRC32C;
	else
		*val = DIGEST_NONE;

	param[idx].val = *val;

	return 0;
}

static int marker_val_to_str(unsigned int val, char *str, int len)
{
	if (val == 0)
		strlcpy(str, "Irrelevant", len);
	else
		strlcpy(str, "Reject", len);

	return 0;
}

static int marker_set_val(struct iscsi_param *params, int idx, unsigned int *val)
{
	if ((idx == key_ofmarkint && params[key_ofmarker].key_state == KEY_STATE_DONE) ||
	    (idx == key_ifmarkint && params[key_ifmarker].key_state == KEY_STATE_DONE))
		*val = 0;
	else
		*val = 1;

	params[idx].val = *val;

	return 0;
}

int params_val_to_str(struct iscsi_key *keys, int idx, unsigned int val, char *str, int len)
{
	if (keys[idx].ops->val_to_str)
		return keys[idx].ops->val_to_str(val, str, len);
	else
		return 0;
}

int params_str_to_val(struct iscsi_key *keys, int idx, char *str, unsigned int *val)
{
	if (keys[idx].ops->str_to_val)
		return keys[idx].ops->str_to_val(str, val);
	else
		return 0;
}

int params_check_val(struct iscsi_key *keys, int idx, unsigned int *val)
{
	if (keys[idx].ops->check_val)
		return keys[idx].ops->check_val(&keys[idx], val);
	else
		return 0;
}

int params_set_val(struct iscsi_key *keys, struct iscsi_param *param,
		  int idx, unsigned int *val)
{
	if (keys[idx].ops->set_val)
		return keys[idx].ops->set_val(param, idx, val);
	else
		return 0;
}

static struct iscsi_key_ops minimum_ops = {
	.val_to_str = range_val_to_str,
	.str_to_val = range_str_to_val,
	.check_val = num_check_val,
	.set_val = minimum_set_val,
};

static struct iscsi_key_ops maximum_ops = {
	.val_to_str = range_val_to_str,
	.str_to_val = range_str_to_val,
	.check_val = num_check_val,
	.set_val = maximum_set_val,
};

static struct iscsi_key_ops or_ops = {
	.val_to_str = bool_val_to_str,
	.str_to_val = bool_str_to_val,
	.set_val = or_set_val,
};

static struct iscsi_key_ops and_ops = {
	.val_to_str = bool_val_to_str,
	.str_to_val = bool_str_to_val,
	.set_val = and_set_val,
};

static struct iscsi_key_ops digest_ops = {
	.val_to_str = digest_val_to_str,
	.str_to_val = digest_str_to_val,
	.set_val = digest_set_val,
};

static struct iscsi_key_ops marker_ops = {
	.val_to_str = marker_val_to_str,
	.set_val = marker_set_val,
};

#define	SET_KEY_VALUES(x)	DEFAULT_##x,DEFAULT_##x,MIN_##x,MAX_##x

/*
 * List of local target keys with initial values.
 * Must match corresponding key_* enum in iscsi_scst.h!!
 *
 * Updating this array don't forget to update tgt_params_check() in
 * the kernel as well!
 */
struct iscsi_key target_keys[] = {
	/* name,  rfc_def, local_def, min, max, show_in_sysfs, ops */
	{"QueuedCommands", SET_KEY_VALUES(NR_QUEUED_CMNDS), 1, &minimum_ops},
	{"RspTimeout", SET_KEY_VALUES(RSP_TIMEOUT), 1, &minimum_ops},
	{"NopInInterval", SET_KEY_VALUES(NOP_IN_INTERVAL), 1, &minimum_ops},
	{"NopInTimeout", SET_KEY_VALUES(NOP_IN_TIMEOUT), 1, &minimum_ops},
	{"MaxSessions", 0, 0, 0, 65535, 1, &minimum_ops},
	{NULL,},
};

/*
 * List of iSCSI RFC specified session keys with initial values.
 * Must match corresponding key_* enum in iscsi_scst.h!!
 *
 * Updating this array don't forget to update sess_params_check() in
 * the kernel as well!
 */
struct iscsi_key session_keys[] = {
	/* name,  rfc_def, local_def, min, max, show_in_sysfs, ops */
	{"InitialR2T", 1, 0, 0, 1, 1, &or_ops},
	{"ImmediateData", 1, 1, 0, 1, 1, &and_ops},
	{"MaxConnections", 1, 1, 1, 1, 0, &minimum_ops},
	{"MaxRecvDataSegmentLength", 8192, -1, 512, -1, 1, &minimum_ops},
	{"MaxXmitDataSegmentLength", 8192, -1, 512, -1, 1, &minimum_ops},
	{"MaxBurstLength", 262144, -1, 512, -1, 1, &minimum_ops},
	{"FirstBurstLength", 65536, 65536, 512, -1, 1, &minimum_ops},
	{"DefaultTime2Wait", 2, 0, 0, 0, 0, &maximum_ops},
	{"DefaultTime2Retain", 20, 0, 0, 0, 0, &minimum_ops},
	{"MaxOutstandingR2T", 1, 32, 1, 65535, 1, &minimum_ops},
	{"DataPDUInOrder", 1, 0, 0, 1, 0, &or_ops},
	{"DataSequenceInOrder", 1, 0, 0, 1, 0, &or_ops},
	{"ErrorRecoveryLevel", 0, 0, 0, 0, 0, &minimum_ops},
	{"HeaderDigest", DIGEST_NONE, DIGEST_NONE, DIGEST_NONE, DIGEST_ALL, 1, &digest_ops},
	{"DataDigest", DIGEST_NONE, DIGEST_NONE, DIGEST_NONE, DIGEST_ALL, 1, &digest_ops},
	{"OFMarker", 0, 0, 0, 0, 0, &and_ops},
	{"IFMarker", 0, 0, 0, 0, 0, &and_ops},
	{"OFMarkInt", 2048, 2048, 1, 65535, 0, &marker_ops},
	{"IFMarkInt", 2048, 2048, 1, 65535, 0, &marker_ops},
	{NULL,},
};
