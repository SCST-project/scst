/*
 *  Copyright (C) 2007 Vladislav Bolkhovitin
 *  Copyright (C) 2007 CMS Distribution Limited
 * 
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation, version 2
 *  of the License.
 * 
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#ifndef CONFIG_H
#define CONFIG_H

struct config_operations {
	int (*init) (char *, char **, int *);
	int (*default_load) (char *);
	int (*target_add) (u32 *, char *);
	int (*target_stop) (u32);
	int (*target_del) (u32);
	int (*param_set) (u32, u64, int, u32, struct iscsi_param *);
	int (*account_add) (u32, int, char *, char *);
	int (*account_del) (u32, int, char *);
	int (*account_query) (u32, int, char *, char *);
	int (*initiator_access) (u32, int);
};

extern struct config_operations *cops;

#endif
