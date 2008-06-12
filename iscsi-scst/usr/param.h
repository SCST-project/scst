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

#ifndef PARAMS_H
#define PARAMS_H

struct iscsi_key;

struct iscsi_param {
	int state;
	unsigned int exec_val;
	unsigned int local_val;
};

struct iscsi_key_ops {
	int (*val_to_str)(unsigned int, char *);
	int (*str_to_val)(char *, unsigned int *);
	int (*check_val)(struct iscsi_key *, unsigned int *);
	int (*set_val)(struct iscsi_param *, int, unsigned int *);
};

struct iscsi_key {
	char *name;
	unsigned int rfc_def;
	unsigned int local_def;
	unsigned int min;
	unsigned int max;
	struct iscsi_key_ops *ops;
};

extern struct iscsi_key session_keys[];
extern struct iscsi_key target_keys[];

extern void param_set_defaults(struct iscsi_param *, struct iscsi_key *);
extern int param_index_by_name(char *, struct iscsi_key *);
extern int param_val_to_str(struct iscsi_key *, int, unsigned int, char *);
extern int param_str_to_val(struct iscsi_key *, int, char *, unsigned int *);
extern int param_check_val(struct iscsi_key *, int, unsigned int *);
extern int param_set_val(struct iscsi_key *, struct iscsi_param *, int, unsigned int *);

#endif
