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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "iscsid.h"

#define BUFSIZE		4096
#define CONFIG_FILE	"/etc/iscsi-scstd.conf"
#define ACCT_CONFIG_FILE	CONFIG_FILE

/*
 * Account configuration code
 */

struct user {
	struct __qelem ulist;

	u32 tid;
	char *name;
	char *password;
};

/* this is the orignal Ardis code. */
static char *target_sep_string(char **pp)
{
	char *p = *pp;
	char *q;

	for (p = *pp; isspace(*p); p++)
		;
	for (q = p; *q && !isspace(*q); q++)
		;
	if (*q)
		*q++ = 0;
	else
		p = NULL;
	*pp = q;
	return p;
}

static struct iscsi_key user_keys[] = {
	{"IncomingUser",},
	{"OutgoingUser",},
	{NULL,},
};

static struct __qelem discovery_users_in = LIST_HEAD_INIT(discovery_users_in);
static struct __qelem discovery_users_out = LIST_HEAD_INIT(discovery_users_out);

#define HASH_ORDER	4
#define acct_hash(x)	((x) & ((1 << HASH_ORDER) - 1))

static struct __qelem trgt_acct_in[1 << HASH_ORDER];
static struct __qelem trgt_acct_out[1 << HASH_ORDER];

static struct __qelem *account_list_get(u32 tid, int dir)
{
	struct __qelem *list = NULL;

	if (tid) {
		list = (dir == AUTH_DIR_INCOMING) ?
			&trgt_acct_in[acct_hash(tid)] : &trgt_acct_out[acct_hash(tid)];
	} else
		list = (dir == AUTH_DIR_INCOMING) ?
			&discovery_users_in : &discovery_users_out;

	return list;
}

static int config_account_init(char *filename)
{
	FILE *fp;
	char buf[BUFSIZE], *p, *q;
	u32 tid;
	int idx, res = 0;

	if (!(fp = fopen(filename, "r"))) {
		return errno == ENOENT ? 0 : -errno;
	}

	tid = 0;
	while (fgets(buf, sizeof(buf), fp)) {
		q = buf;
		p = target_sep_string(&q);
		if (!p || *p == '#')
			continue;

		if (!strcasecmp(p, "Target")) {
			tid = 0;
			if (!(p = target_sep_string(&q)))
				continue;
			tid = target_find_id_by_name(p);
		} else if (!((idx = param_index_by_name(p, user_keys)) < 0)) {
			char *name, *pass;
			name = target_sep_string(&q);
			pass = target_sep_string(&q);

			res = config_account_add(tid, idx, name, pass);
			if (res < 0) {
				log_error("%s %s\n", name, pass);
				break;
			}
		}
	}

	fclose(fp);

	return res;
}

/* Return the first account if the length of name is zero */
static struct user *account_lookup_by_name(u32 tid, int dir, char *name)
{
	struct __qelem *list = account_list_get(tid, dir);
	struct user *user = NULL;

	list_for_each_entry(user, list, ulist) {
		if (user->tid != tid)
			continue;
		if (!strlen(name))
			return user;
		if (!strcmp(user->name, name))
			return user;
	}

	return NULL;
}

int config_account_query(u32 tid, int dir, char *name, char *pass)
{
	struct user *user;

	if (!(user = account_lookup_by_name(tid, dir, name)))
		return -ENOENT;

	if (!strlen(name))
		strncpy(name, user->name, ISCSI_NAME_LEN);

	strncpy(pass, user->password, ISCSI_NAME_LEN);

	return 0;
}

int config_account_list(u32 tid, int dir, u32 *cnt, u32 *overflow,
	char *buf, size_t buf_sz)
{
	struct __qelem *list = account_list_get(tid, dir);
	struct user *user;

	*cnt = *overflow = 0;

	if (!list)
		return -ENOENT;

	list_for_each_entry(user, list, ulist) {
		if (buf_sz >= ISCSI_NAME_LEN) {
			strncpy(buf, user->name, ISCSI_NAME_LEN);
			buf_sz -= ISCSI_NAME_LEN;
			buf += ISCSI_NAME_LEN;
			*cnt += 1;
		} else
			*overflow += 1;
	}

	return 0;
}

static void account_destroy(struct user *user)
{
	if (!user)
		return;
	remque(&user->ulist);
	free(user->name);
	free(user->password);
	free(user);
}

int config_account_del(u32 tid, int dir, char *name)
{
	struct user *user;

	if (!name || !(user = account_lookup_by_name(tid, dir, name)))
		return -ENOENT;

	account_destroy(user);

	/* update the file here. */
	return 0;
}

static struct user *account_create(void)
{
	struct user *user;

	if (!(user = malloc(sizeof(*user))))
		return NULL;

	memset(user, 0, sizeof(*user));
	INIT_LIST_HEAD(&user->ulist);

	return user;
}

int config_account_add(u32 tid, int dir, char *name, char *pass)
{
	int err = -ENOMEM;
	struct user *user;
	struct __qelem *list;

	if (!name || !pass)
		return -EINVAL;

	if (tid) {
		/* check here */
/* 		return -ENOENT; */
	}

	/* Check for minimum RFC defined value */
	if (strlen(pass) < 12) {
		log_error("Secret for user %s is too short. At least 12 bytes "
			"are required\n", name);
		return -EINVAL;
	}

	if (!(user = account_create()) ||
	    !(user->name = strdup(name)) ||
	    !(user->password = strdup(pass)))
		goto out;

	user->tid = tid;
	list = account_list_get(tid, dir);

	if (dir == AUTH_DIR_OUTGOING && !list_empty(list)) {
		struct user *old;
		log_warning("Only one outgoing %s account is supported."
			    " Replacing the old one.\n",
			    tid ? "target" : "discovery");

		old = list_entry(list->q_forw, struct user, ulist);
		account_destroy(old);
	}

	insque(user, list);

	/* update the file here. */
	return 0;
out:
	account_destroy(user);

	return err;
}

/*
 * Access control code
 */

static int netmask_match_v6(struct sockaddr *sa1, struct sockaddr *sa2, uint32_t mbit)
{
	uint16_t mask, a1[8], a2[8];
	int i;

	for (i = 0; i < 8; i++) {
		a1[i] = ntohs(((struct sockaddr_in6 *) sa1)->sin6_addr.s6_addr16[i]);
		a2[i] = ntohs(((struct sockaddr_in6 *) sa2)->sin6_addr.s6_addr16[i]);
	}

	for (i = 0; i < mbit / 16; i++)
		if (a1[i] ^ a2[i])
			return 0;

	if (mbit % 16) {
		mask = ~((1 << (16 - (mbit % 16))) - 1);
		if ((mask & a1[mbit / 16]) ^ (mask & a2[mbit / 16]))
			return 0;
	}

	return 1;
}

static int netmask_match_v4(struct sockaddr *sa1, struct sockaddr *sa2, uint32_t mbit)
{
	uint32_t s1, s2, mask = ~((1 << (32 - mbit)) - 1);

	s1 = htonl(((struct sockaddr_in *) sa1)->sin_addr.s_addr);
	s2 = htonl(((struct sockaddr_in *) sa2)->sin_addr.s_addr);

	if (~mask & s1)
		return 0;

	if (!((mask & s2) ^ (mask & s1)))
		return 1;

	return 0;
}

static int netmask_match(struct sockaddr *sa1, struct sockaddr *sa2, char *buf)
{
	int32_t mbit;
	uint8_t family = sa1->sa_family;

	mbit = strtoul(buf, NULL, 0);
	if (mbit < 0 ||
	    (family == AF_INET && mbit > 31) ||
	    (family == AF_INET6 && mbit > 127))
		return 0;

	if (family == AF_INET)
		return netmask_match_v4(sa1, sa2, mbit);

	return netmask_match_v6(sa1, sa2, mbit);
}

static int address_match(struct sockaddr *sa1, struct sockaddr *sa2)
{
	if (sa1->sa_family == AF_INET)
		return ((struct sockaddr_in *) sa1)->sin_addr.s_addr ==
			((struct sockaddr_in *) sa2)->sin_addr.s_addr;
	else {
		struct in6_addr *a1, *a2;

		a1 = &((struct sockaddr_in6 *) sa1)->sin6_addr;
		a2 = &((struct sockaddr_in6 *) sa2)->sin6_addr;

		return (a1->s6_addr32[0] == a2->s6_addr32[0] &&
			a1->s6_addr32[1] == a2->s6_addr32[1] &&
			a1->s6_addr32[2] == a2->s6_addr32[2] &&
			a1->s6_addr32[3] == a2->s6_addr32[3]);
	}

	return 0;
}

static int __initiator_match(int fd, char *str)
{
	struct sockaddr_storage from;
	struct addrinfo hints, *res;
	socklen_t len;
	char *p, *q;
	int err = 0;

	len = sizeof(from);
	if (getpeername(fd, (struct sockaddr *) &from, &len) < 0)
		return 0;

	while ((p = strsep(&str, ","))) {
		while (isspace(*p))
			p++;

		if (!strcmp(p, "ALL"))
			return 1;

		if (*p == '[') {
			p++;
			if (!(q = strchr(p, ']')))
				return 0;
			*(q++) = '\0';
		} else
			q = p;

		if ((q = strchr(q, '/')))
			*(q++) = '\0';

		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_NUMERICHOST;

		if (getaddrinfo(p, NULL, &hints, &res) < 0)
			return 0;

		if (q)
			err = netmask_match(res->ai_addr,
					    (struct sockaddr *) &from, q);
		else
			err = address_match(res->ai_addr,
					    (struct sockaddr *) &from);

		freeaddrinfo(res);

		if (err)
			break;
	}

	return err;
}

static int initiator_match(u32 tid, int fd, char *filename)
{
	int err = 0;
	FILE *fp;
	char buf[BUFSIZE], *p;

	if (!(fp = fopen(filename, "r")))
		return err;

	/*
	 * Every time we are called, we read the file. So we don't need to
	 * implement 'reload feature'. It's slow, however, it doesn't matter.
	 */
	while ((p = fgets(buf, sizeof(buf), fp))) {
		if (!p || *p == '#')
			continue;

		p = &buf[strlen(buf) - 1];
		if (*p != '\n')
			continue;
		*p = '\0';

		if (!(p = strchr(buf, ' ')))
			continue;
		*(p++) = '\0';

		if (target_find_id_by_name(buf) != tid && strcmp(buf, "ALL"))
			continue;

		err = __initiator_match(fd, p);
		break;
	}

	fclose(fp);
	return err;
}

int config_initiator_access(u32 tid, int fd)
{
	if (initiator_match(tid, fd, "/etc/initiators.deny") &&
	    !initiator_match(tid, fd, "/etc/initiators.allow"))
		return -EPERM;
	else
		return 0;
}

/*
 * Main configuration code
 */

static int __config_target_create(u32 *tid, char *name, int update)
{
	int err;

	if (target_find_by_name(name)) {
		log_error("duplicated target %s", name);
		return -EINVAL;
	}
	if ((err = target_add(tid, name)) < 0)
		return err;

	return err;
}

int config_target_create(u32 *tid, char *name)
{
	return __config_target_create(tid, name, 1);
}

int config_target_destroy(u32 tid)
{
	int err;

	if ((err = target_del(tid)) < 0)
		return err;

	return err;
}

int config_param_set(u32 tid, u64 sid, int type, u32 partial,
	struct iscsi_param *param)
{
	int err;

	err = kernel_param_set(tid, sid, type, partial, param);

	return err;
}

static int iscsi_param_partial_set(u32 tid, u64 sid, int type, int key, u32 val)
{
	struct iscsi_param *param;
	struct iscsi_param session_param[session_key_last];
	struct iscsi_param target_param[target_key_last];

	if (type == key_session)
		param = session_param;
	else
		param = target_param;

	param[key].val = val;

	return config_param_set(tid, sid, type, 1 << key, param);
}

static int config_main_init(char *filename)
{
	FILE *config;
	char buf[BUFSIZE];
	char *p, *q;
	int idx;
	u32 tid, val;
	int res = 0;

	if (!(config = fopen(filename, "r"))) {
		return errno == ENOENT ? 0 : -errno;
	}

	tid = 0;
	while (fgets(buf, BUFSIZE, config)) {
		q = buf;
		p = target_sep_string(&q);
		if (!p || *p == '#')
			continue;
		if (!strcasecmp(p, "Target")) {
			tid = 0;
			if (!(p = target_sep_string(&q)))
				continue;
			if (__config_target_create(&tid, p, 0))
				log_debug(1, "creating target %s", p);
		} else if (!strcasecmp(p, "Alias") && tid) {
			;
		} else if (!((idx = param_index_by_name(p, target_keys)) < 0) && tid) {
			val = strtol(q, &q, 0);
			if (param_check_val(target_keys, idx, &val) < 0) {
				log_error("Wrong value %u for parameter %s\n",
					val, target_keys[idx].name);
				res = -1;
				break;
			}
			iscsi_param_partial_set(tid, 0, key_target, idx, val);
		} else if (!((idx = param_index_by_name(p, session_keys)) < 0) && tid) {
			char *str = target_sep_string(&q);
			if (param_str_to_val(session_keys, idx, str, &val) < 0) {
				log_error("Wrong value %s for parameter %s\n",
					str, session_keys[idx].name);
				res = -1;
				break;
			}
			if (param_check_val(session_keys, idx, &val) < 0) {
				log_error("Wrong value %u for parameter %s\n",
					val, session_keys[idx].name);
				res = -1;
				break;
			}
			iscsi_param_partial_set(tid, 0, key_session, idx, val);
		} else if (param_index_by_name(p, user_keys) < 0) {
			log_warning("Unknown iscsi-scstd.conf param: %s\n", p);
			res = -1;
			break;
		}
	}

	fclose(config);
	return res;
}

int config_load(char *params)
{
	int i, err;

	for (i = 0; i < 1 << HASH_ORDER; i++) {
		INIT_LIST_HEAD(&trgt_acct_in[i]);
		INIT_LIST_HEAD(&trgt_acct_out[i]);
	}

	/* First, we must finish the main configuration. */
	if ((err = config_main_init(params ? params : CONFIG_FILE)))
		return err;

	if ((err = config_account_init(ACCT_CONFIG_FILE)) < 0)
		return err;

	/* TODO: error handling */

	return err;
}

int config_isns_load(char *params, char **isns, int *isns_ac)
{
	FILE *config;
	char buf[BUFSIZE];
	char *p, *q;

	if (!(config = fopen(params ? : CONFIG_FILE, "r")))
		return -errno;

	while (fgets(buf, BUFSIZE, config)) {
		q = buf;
		p = target_sep_string(&q);
		if (!p || *p == '#')
			continue;
		if (!strcasecmp(p, "iSNSServer")) {
			*isns = strdup(target_sep_string(&q));
		} else if (!strcasecmp(p, "iSNSAccessControl")) {
			char *str = target_sep_string(&q);
			if (!strcasecmp(str, "Yes"))
				*isns_ac = 1;
		}
	}

	fclose(config);
	return 0;
}
