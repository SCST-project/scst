/*
 * iSNS functions
 *
 *  Copyright (C) 2006 FUJITA Tomonori <tomof@acm.org>
 *  Copyright (C) 2007 - 2013 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "iscsid.h"
#include "isns_proto.h"
#include "misc.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define BUFSIZE (1 << 18)

struct isns_io {
	char *buf;
	int offset;
};

struct isns_qry_mgmt {
	char name[ISCSI_NAME_LEN];
	uint16_t transaction;
	struct __qelem qlist;
};

struct isns_initiator {
	char name[ISCSI_NAME_LEN];
	struct __qelem ilist;
};

char *isns_server;
int isns_access_control;
char isns_entity_target_name[ISCSI_NAME_LEN];
int isns_timeout = -1;

static LIST_HEAD(qry_list);
static uint16_t scn_listen_port;
static int isns_fd, scn_listen_fd, scn_fd;
static struct isns_io isns_rx, scn_rx;
static char *rxbuf;
static uint16_t transaction;
static uint32_t current_timeout = 30; /* seconds */
static char eid[ISCSI_NAME_LEN];
static uint8_t ip[16]; /* SCST iSCSI supports only one portal */
static struct sockaddr_storage ss;

int isns_scn_access_allowed(uint32_t tid, char *name)
{
	struct isns_initiator *ini;
	struct target *target = target_find_by_id(tid);

	if ((isns_server == NULL) || !isns_access_control)
		return 1;

	if (!target)
		return 0;

	list_for_each_entry(ini, &target->isns_head, ilist) {
		if (!strcmp(ini->name, name))
			return 1;
	}
	return 0;
}

static int isns_get_ip(int fd)
{
	int err, i;
	uint32_t addr;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} lss;
	socklen_t slen = sizeof(lss);

	err = getsockname(fd, &lss.sa, &slen);
	if (err) {
		log_error("getsockname error: %s!", strerror(errno));
		return err;
	}

	err = getnameinfo(&lss.sa, sizeof(lss),
			  eid, sizeof(eid), NULL, 0, 0);
	if (err == EAI_AGAIN)
		err = getnameinfo(&lss.sa, sizeof(lss),
				  eid, sizeof(eid), NULL, 0, NI_NUMERICHOST);
	if (err) {
		log_error("getnameinfo error: %s!", get_error_str(err));
		return err;
	}

	switch (lss.sa.sa_family) {
	case AF_INET:
		addr = lss.sin.sin_addr.s_addr;

		ip[10] = ip[11] = 0xff;
		ip[15] = 0xff & (addr >> 24);
		ip[14] = 0xff & (addr >> 16);
		ip[13] = 0xff & (addr >> 8);
		ip[12] = 0xff & addr;
		break;
	case AF_INET6:
		for (i = 0; i < ARRAY_SIZE(ip); i++)
			ip[i] = lss.sin6.sin6_addr.s6_addr[i];
		break;
	}

	return 0;
}

static int isns_connect(void)
{
	int fd, err;

	log_debug(1, "Going to connect to iSNS server %s", isns_server);

	fd = socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		log_error("unable to create (%s) %d!", strerror(errno),
			  ss.ss_family);
		return -errno;
	}

	/*
	 * ToDo: must be made non-blocking, otherwise for an unreacheable
	 * server it blocks all other events processing until timeout (30 secs).
	 */
	err = connect(fd, (struct sockaddr *)&ss, sizeof(ss));
	if (err < 0) {
		log_error("unable to connect (%s) %d!", strerror(errno),
			  ss.ss_family);
		close(fd);
		return -errno;
	}

	log_info("%s %d: new connection %d", __func__, __LINE__, fd);

	if (!strlen(eid)) {
		err = isns_get_ip(fd);
		if (err) {
			close(fd);
			return err;
		}
	}

	isns_fd = fd;
	isns_set_fd(fd, scn_listen_fd, scn_fd);

	return fd;
}

static void isns_hdr_init(struct isns_hdr *hdr, uint16_t function,
			  uint16_t length, uint16_t flags,
			  uint16_t trans, uint16_t sequence)
{
	hdr->version = htons(0x0001);
	hdr->function = htons(function);
	hdr->length = htons(length);
	hdr->flags = htons(flags);
	hdr->transaction = htons(trans);
	hdr->sequence = htons(sequence);
}

static int isns_tlv_set(struct isns_tlv **tlv, int max_tlv_buflen,
	uint32_t tag, uint32_t length, void *value)
{
	int l = length;
	int res;

	if (l % ISNS_ALIGN)
		l += (ISNS_ALIGN - (l % ISNS_ALIGN));

	if (sizeof(struct isns_tlv) + l > max_tlv_buflen) {
		log_error("Too big tlv len %d (max allowed %d)", l,
			max_tlv_buflen);
		res = -EOVERFLOW;
		goto out;
	}

	(*tlv)->tag = htonl(tag);
	(*tlv)->length = htonl(l);

	if (length)
		memcpy((*tlv)->value, value, length);

	l += sizeof(struct isns_tlv);
	*tlv = (struct isns_tlv *)((char *)*tlv + l);

	res = l;

out:
	return res;
}

static int isns_scn_deregister(char *name)
{
	int err;
	uint16_t flags, length = 0;
	char buf[2048];
	struct isns_hdr *hdr = (struct isns_hdr *)buf;
	struct isns_tlv *tlv;
	int max_buf;

	if (!isns_fd) {
		err = isns_connect();
		if (err < 0)
			goto out;
	}

	memset(buf, 0, sizeof(buf));
	tlv = (struct isns_tlv *)hdr->pdu;
	max_buf = sizeof(buf) - offsetof(struct isns_hdr, pdu);

	err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ISCSI_NAME,
				strlen(name) + 1, name);
	if (err < 0)
		goto out;
	length += err;

	err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ISCSI_NAME,
				strlen(name) + 1, name);
	if (err < 0)
		goto out;
	length += err;

	flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_SCN_DEREG, length, flags,
		      ++transaction, 0);

	err = write(isns_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_error("%s %d: %s", __func__, __LINE__, strerror(errno));

out:
	return err;
}

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define correct_scn_flag_endiannes(x)						\
{								\
	x = (x & 0x55555555) << 1 | (x & 0xaaaaaaaa) >> 1;	\
	x = (x & 0x33333333) << 2 | (x & 0xcccccccc) >> 2;	\
	x = (x & 0x0f0f0f0f) << 4 | (x & 0xf0f0f0f0) >> 4;	\
	x = (x & 0x00ff00ff) << 8 | (x & 0xff00ff00) >> 8;	\
	x = (x & 0x0000ffff) << 16 | (x & 0xffff0000) >> 16;	\
}
#else
#define correct_scn_flag_endiannes(x) { }
#endif

static int isns_scn_register(void)
{
	int err;
	uint16_t flags, length = 0;
	uint32_t scn_flags;
	char buf[4096];
	struct isns_hdr *hdr = (struct isns_hdr *)buf;
	int max_buf;
	struct isns_tlv *tlv;
	struct target *target;

	if (list_empty(&targets_list))
		return 0;

	if (!isns_fd) {
		err = isns_connect();
		if (err < 0)
			goto out;
	}

	memset(buf, 0, sizeof(buf));
	tlv = (struct isns_tlv *)hdr->pdu;
	max_buf = sizeof(buf) - offsetof(struct isns_hdr, pdu);

	if (strlen(isns_entity_target_name) < 1) {
		target = list_entry(targets_list.q_forw, struct target, tlist);
		err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ISCSI_NAME,
			strlen(target->name) + 1, target->name);
	} else {
		err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ISCSI_NAME,
		strlen(isns_entity_target_name) + 1, isns_entity_target_name);
	}

	if (err < 0)
		goto out;
	length += err;

	err = isns_tlv_set(&tlv, max_buf - length, 0, 0, 0);
	if (err < 0)
		goto out;
	length += err;

	scn_flags = ISNS_SCN_FLAG_INITIATOR | ISNS_SCN_FLAG_OBJECT_REMOVE |
			ISNS_SCN_FLAG_OBJECT_ADDED | ISNS_SCN_FLAG_OBJECT_UPDATED;
	correct_scn_flag_endiannes(scn_flags);
	scn_flags = htonl(scn_flags);

	err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ISCSI_SCN_BITMAP,
				sizeof(scn_flags), &scn_flags);
	if (err < 0)
		goto out;
	length += err;

	flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_SCN_REG, length, flags, ++transaction, 0);

	err = write(isns_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_error("%s %d: %s", __func__, __LINE__, strerror(errno));

out:
	return err;
}

static int isns_attr_query(char *name)
{
	int err;
	uint16_t flags, length = 0;
	char buf[4096];
	struct isns_hdr *hdr = (struct isns_hdr *)buf;
	struct isns_tlv *tlv;
	struct target *target;
	uint32_t node = htonl(ISNS_NODE_INITIATOR);
	struct isns_qry_mgmt *mgmt;
	int max_buf;

	if (list_empty(&targets_list))
		return 0;

	if (!isns_fd) {
		err = isns_connect();
		if (err < 0)
			goto out;
	}

	mgmt = malloc(sizeof(*mgmt));
	if (!mgmt)
		return 0;
	list_add_tail(&mgmt->qlist, &qry_list);

	memset(buf, 0, sizeof(buf));
	tlv = (struct isns_tlv *)hdr->pdu;
	max_buf = sizeof(buf) - offsetof(struct isns_hdr, pdu);

	if (name)
		snprintf(mgmt->name, sizeof(mgmt->name), "%s", name);
	else {
		mgmt->name[0] = '\0';
		target = list_entry(targets_list.q_forw, struct target, tlist);
		name = target->name;
	}

	err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ISCSI_NAME,
				strlen(name) + 1, name);
	if (err < 0)
		goto out;
	length += err;

	err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ISCSI_NODE_TYPE,
				sizeof(node), &node);
	if (err < 0)
		goto out;
	length += err;

	err = isns_tlv_set(&tlv, max_buf - length, 0, 0, 0);
	if (err < 0)
		goto out;
	length += err;

	err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ISCSI_NAME, 0, 0);
	if (err < 0)
		goto out;
	length += err;

	err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ISCSI_NODE_TYPE, 0, 0);
	if (err < 0)
		goto out;
	length += err;

	err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_PORTAL_IP_ADDRESS, 0, 0);
	if (err < 0)
		goto out;
	length += err;

	flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_DEV_ATTR_QRY, length, flags,
		      ++transaction, 0);
	mgmt->transaction = transaction;

	err = write(isns_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_error("%s %d: %s", __func__, __LINE__, strerror(errno));

out:
	return err;
}

static int isns_deregister(void)
{
	int err;
	uint16_t flags, length = 0;
	char buf[4096];
	struct isns_hdr *hdr = (struct isns_hdr *)buf;
	struct isns_tlv *tlv;
	struct target *target;
	int max_buf;

	if (list_empty(&targets_list))
		return 0;

	if (!isns_fd) {
		err = isns_connect();
		if (err < 0)
			goto out;
	}

	memset(buf, 0, sizeof(buf));
	tlv = (struct isns_tlv *)hdr->pdu;
	max_buf = sizeof(buf) - offsetof(struct isns_hdr, pdu);

	target = list_entry(targets_list.q_forw, struct target, tlist);

	err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ISCSI_NAME,
				strlen(target->name) + 1, target->name);
	if (err < 0)
		goto out;
	length += err;

	err = isns_tlv_set(&tlv, max_buf - length, 0, 0, 0);
	if (err < 0)
		goto out;
	length += err;

	err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ENTITY_IDENTIFIER,
				strlen(eid) + 1, eid);
	if (err < 0)
		goto out;
	length += err;

	flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_DEV_DEREG, length, flags,
		      ++transaction, 0);

	err = write(isns_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_error("%s %d: %s", __func__, __LINE__, strerror(errno));
out:
	return err;
}

int isns_target_register(char *name)
{
	char buf[4096];
	uint16_t flags = 0, length = 0;
	struct isns_hdr *hdr = (struct isns_hdr *)buf;
	struct isns_tlv *tlv;
	uint32_t port = htonl(server_port);
	uint32_t node = htonl(ISNS_NODE_TARGET);
	uint32_t type = htonl(2);
	struct target *target;
	int err, initial = list_length_is_one(&targets_list);
	int max_buf;

	if (isns_server == NULL)
		return 0;

	if (!isns_fd) {
		err = isns_connect();
		if (err < 0)
			return err;
	}

	memset(buf, 0, sizeof(buf));
	tlv = (struct isns_tlv *)hdr->pdu;
	max_buf = sizeof(buf) - offsetof(struct isns_hdr, pdu);

	if (strlen(isns_entity_target_name) < 1) {
		target = list_entry(targets_list.q_forw, struct target, tlist);
		err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ISCSI_NAME,
				strlen(target->name) + 1, target->name);
	} else {
		err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ISCSI_NAME,
				strlen(isns_entity_target_name) + 1, isns_entity_target_name);
	}
if (err < 0)
		goto out;
        length += err;

	err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ENTITY_IDENTIFIER,
				strlen(eid) + 1, eid);
	if (err < 0)
		goto out;
	length += err;

	err = isns_tlv_set(&tlv, max_buf - length, 0, 0, 0);
	if (err < 0)
		goto out;
	length += err;

	err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ENTITY_IDENTIFIER,
				strlen(eid) + 1, eid);
	if (err < 0)
		goto out;
	length += err;

	if (initial) {
		err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ENTITY_PROTOCOL,
					sizeof(type), &type);
		if (err < 0)
			goto out;
		length += err;

		err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_PORTAL_IP_ADDRESS,
					sizeof(ip), &ip);
		if (err < 0)
			goto out;
		length += err;

		err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_PORTAL_PORT,
					sizeof(port), &port);
		if (err < 0)
			goto out;
		length += err;

		flags = ISNS_FLAG_REPLACE;

		if (scn_listen_port) {
			uint32_t sport = htonl(scn_listen_port);
			err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_SCN_PORT,
						sizeof(sport), &sport);
			if (err < 0)
				goto out;
			length += err;
		}
	}

	err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ISCSI_NAME,
				strlen(name) + 1, name);
	if (err < 0)
		goto out;
	length += err;

	err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ISCSI_NODE_TYPE,
				sizeof(node), &node);
	if (err < 0)
		goto out;
	length += err;

	flags |= ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_DEV_ATTR_REG, length, flags,
		      ++transaction, 0);

	err = write(isns_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_error("%s %d: %s", __func__, __LINE__, strerror(errno));

	if (scn_listen_port)
		isns_scn_register();

	isns_attr_query(name);

out:
	return err;
}

static void free_all_acl(struct target *target)
{
	struct isns_initiator *ini;

	while (!list_empty(&target->isns_head)) {
		ini = list_entry(target->isns_head.q_forw, typeof(*ini), ilist);
		list_del(&ini->ilist);
		free(ini);
	}
}

int isns_target_deregister(char *name)
{
	char buf[4096];
	uint16_t flags, length = 0;
	struct isns_hdr *hdr = (struct isns_hdr *)buf;
	struct isns_tlv *tlv;
	int err, last = list_empty(&targets_list);
	struct target *target;
	int max_buf;

	target = target_find_by_name(name);
	if (target)
		free_all_acl(target);

	if (isns_server == NULL)
		return 0;

	if (!isns_fd) {
		err = isns_connect();
		if (err < 0)
			goto out;
	}

	isns_scn_deregister(name);

	memset(buf, 0, sizeof(buf));
	tlv = (struct isns_tlv *)hdr->pdu;
	max_buf = sizeof(buf) - offsetof(struct isns_hdr, pdu);

	err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ISCSI_NAME,
				strlen(name) + 1, name);
	if (err < 0)
		goto out;
	length += err;

	err = isns_tlv_set(&tlv, max_buf - length, 0, 0, 0);
	if (err < 0)
		goto out;
	length += err;

	if (last) {
		err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ENTITY_IDENTIFIER,
					strlen(eid) + 1, eid);
		if (err < 0)
			goto out;
		length += err;
	} else {
		err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ISCSI_NAME,
					strlen(name) + 1, name);
		if (err < 0)
			goto out;
		length += err;
	}

	flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_DEV_DEREG, length, flags,
		      ++transaction, 0);

	err = write(isns_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_error("%s %d: %s", __func__, __LINE__, strerror(errno));

out:
	return err;
}

static int recv_hdr(int fd, struct isns_io *rx, struct isns_hdr *hdr)
{
	int err;

	if (rx->offset < sizeof(*hdr)) {
		err = read(fd, rx->buf + rx->offset,
			   sizeof(*hdr) - rx->offset);
		if (err < 0) {
			if (errno == EAGAIN || errno == EINTR)
				return -EAGAIN;
			log_error("header read error %d %d %s %d",
				  fd, err, strerror(errno), rx->offset);
			return -1;
		} else if (err == 0)
			return -1;

		log_debug(1, "header %d %d bytes!", fd, err);
		rx->offset += err;

		if (rx->offset < sizeof(*hdr)) {
			log_debug(1, "header wait %d %d", rx->offset, err);
			return -EAGAIN;
		}
	}

	return 0;
}

#define get_hdr_param(hdr, function, length, flags, transaction, sequence)	\
{										\
	function = ntohs(hdr->function);					\
	length = ntohs(hdr->length);						\
	flags = ntohs(hdr->flags);						\
	transaction = ntohs(hdr->transaction);					\
	sequence = ntohs(hdr->sequence);					\
}

static int recv_pdu(int fd, struct isns_io *rx, struct isns_hdr *hdr)
{
	uint16_t function, length, flags, transaction, sequence;
	int err;

	err = recv_hdr(fd, rx, hdr);
	if (err)
		return err;

	/* Now we got a complete header */
	get_hdr_param(hdr, function, length, flags, transaction, sequence);
	log_debug(1, "got a header %x %u %x %u %u", function, length, flags,
		  transaction, sequence);

	if (length + sizeof(*hdr) > BUFSIZE) {
		log_error("ToDo: we cannot handle this yet %u!", length);
		return -1;
	}

	if (rx->offset < length + sizeof(*hdr)) {
		err = read(fd, rx->buf + rx->offset,
			   length + sizeof(*hdr) - rx->offset);
		if (err < 0) {
			if (errno == EAGAIN || errno == EINTR)
				return -EAGAIN;
			log_error("pdu read error %d %d %s %d",
				  fd, err, strerror(errno), rx->offset);
			return -1;
		} else if (err == 0)
			return -1;

		log_debug(1, "pdu %u %u", fd, err);
		rx->offset += err;

		if (rx->offset < length + sizeof(*hdr)) {
			log_error("pdu wait %d %d", rx->offset, err);
			return -EAGAIN;
		}
	}

	/* Now we got everything. */
	rx->offset = 0;

	return 0;
}

#define print_unknown_pdu(hdr)						\
{									\
	uint16_t function, length, flags, transaction, sequence;	\
	get_hdr_param(hdr, function, length, flags, transaction,	\
		      sequence)						\
	log_error("%s %d: unknown function %x %u %x %u %u",		\
		  __func__, __LINE__,				\
		  function, length, flags, transaction, sequence);	\
}

static char *print_scn_pdu(struct isns_hdr *hdr)
{
	struct isns_tlv *tlv = (struct isns_tlv *)hdr->pdu;
	uint16_t function __attribute__((unused));
	uint16_t length;
	uint16_t flags __attribute__((unused));
	uint16_t transaction __attribute__((unused));
	uint16_t sequence __attribute__((unused));
	char *name = NULL;

	get_hdr_param(hdr, function, length, flags, transaction, sequence);

	while (length) {
		uint32_t vlen = ntohl(tlv->length);

		if (vlen + sizeof(*tlv) > length)
			vlen = length - sizeof(*tlv);

		if (vlen < 4)
			goto next;

		switch (ntohl(tlv->tag)) {
		case ISNS_ATTR_ISCSI_NAME:
			((char *)tlv->value)[vlen-1] = '\0';
			log_debug(3, "scn name: %u, %s", vlen, (char *)tlv->value);
			if (!name)
				name = (char *)tlv->value;
			break;
		case ISNS_ATTR_TIMESTAMP:
			if (vlen < 8)
				goto next;
			/* log_debug(3, "%u : %u : %" PRIx64, ntohl(tlv->tag), vlen, */
			/* *((uint64_t *)tlv->value)); */
			break;
		case ISNS_ATTR_ISCSI_SCN_BITMAP:
			log_debug(3, "scn bitmap : %x", *((uint32_t *)tlv->value));
			break;
		}

next:
		length -= (sizeof(*tlv) + vlen);
		tlv = (struct isns_tlv *)((char *)tlv->value + vlen);
	}

	return name;
}

static void qry_rsp_handle(struct isns_hdr *hdr)
{
	struct isns_tlv *tlv;
	uint16_t function __attribute__((unused));
	uint16_t flags __attribute__((unused));
	uint16_t sequence __attribute__((unused));
	uint16_t length, transaction;
	uint32_t status = (uint32_t) (*hdr->pdu);
	struct isns_qry_mgmt *mgmt, *n;
	struct target *target;
	struct isns_initiator *ini;
	char *name = NULL;

	get_hdr_param(hdr, function, length, flags, transaction, sequence);

	list_for_each_entry_safe(mgmt, n, &qry_list, qlist) {
		if (mgmt->transaction == transaction) {
			list_del(&mgmt->qlist);
			goto found;
		}
	}

	log_error("%s %d: transaction not found %u",
		  __func__, __LINE__, transaction);

	return;

found:
	if (status) {
		log_error("%s %d: error response %u",
			  __func__, __LINE__, status);

		goto free_qry_mgmt;
	}

	if (!strlen(mgmt->name)) {
		log_debug(1, "%s %d: skip %u",
			  __func__, __LINE__, transaction);
		goto free_qry_mgmt;
	}

	target = target_find_by_name(mgmt->name);
	if (!target) {
		log_error("%s %d: invalid tid %s",
			  __func__, __LINE__, mgmt->name);
		goto free_qry_mgmt;
	}

	free_all_acl(target);

	/* skip status */
	if (length < 4)
		goto free_qry_mgmt;
	tlv = (struct isns_tlv *)((char *)hdr->pdu + 4);
	length -= 4;

	while (length) {
		uint32_t vlen = ntohl(tlv->length);

		if (vlen + sizeof(*tlv) > length)
			vlen = length - sizeof(*tlv);

		if (vlen < 4)
			goto next;

		switch (ntohl(tlv->tag)) {
		case ISNS_ATTR_ISCSI_NAME:
			((char *)tlv->value)[vlen-1] = '\0';
			name = (char *)tlv->value;
			break;
		case ISNS_ATTR_ISCSI_NODE_TYPE:
			if (ntohl(*(tlv->value)) == ISNS_NODE_INITIATOR && name) {
				log_debug(3, "%s %d: %s", __func__, __LINE__,
					  (char *)name);
				ini = malloc(sizeof(*ini));
				if (!ini)
					goto free_qry_mgmt;
				snprintf(ini->name, sizeof(ini->name), "%s",
					 name);
				list_add_tail(&ini->ilist, &target->isns_head);
			} else
				name = NULL;
			break;
		default:
			name = NULL;
			break;
		}

next:
		length -= (sizeof(*tlv) + vlen);
		tlv = (struct isns_tlv *)((char *)tlv->value + vlen);
	}

free_qry_mgmt:
	free(mgmt);
}

int isns_handle(int is_timeout)
{
	int err;
	struct isns_io *rx = &isns_rx;
	struct isns_hdr *hdr = (struct isns_hdr *)rx->buf;
	uint16_t function;
	uint16_t length __attribute__((unused));
	uint16_t flags __attribute__((unused));
	uint16_t transaction __attribute__((unused));
	uint16_t sequence __attribute__((unused));
	char *name = NULL;

	if (isns_server == NULL)
		return 0;

	if (is_timeout)
		return isns_attr_query(NULL);

	err = recv_pdu(isns_fd, rx, hdr);
	if (err) {
		if (err == -EAGAIN)
			return err;
		log_debug(1, "%s %d: close connection %d", __func__, __LINE__,
			  isns_fd);
		close(isns_fd);
		isns_fd = 0;
		isns_set_fd(0, scn_listen_fd, scn_fd);
		return err;
	}

	get_hdr_param(hdr, function, length, flags, transaction, sequence);

	switch (function) {
	case ISNS_FUNC_DEV_ATTR_REG_RSP:
		break;
	case ISNS_FUNC_DEV_ATTR_QRY_RSP:
		qry_rsp_handle(hdr);
		break;
	case ISNS_FUNC_DEV_DEREG_RSP:
	case ISNS_FUNC_SCN_REG_RSP:
	case ISNS_FUNC_SCN_DEREG_RSP:
		break;
	case ISNS_FUNC_SCN:
		name = print_scn_pdu(hdr);
		if (name) {
			log_debug(3, "%s %d: %s", __func__, __LINE__, name);
			isns_attr_query(name);
		}
		break;
	default:
		print_unknown_pdu(hdr);
	}

	return 0;
}

static int scn_accept_connection(void)
{
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} from;
	socklen_t slen;
	int fd, err, opt = 1;

	if (isns_server == NULL) {
		/*
		 * Sometimes we have (leftover?) events after disable iSNS
		 * server, so ignore them
		 */
		goto out;
	}

	slen = sizeof(from);
	fd = accept(scn_listen_fd, &from.sa, &slen);
	if (fd < 0) {
		log_error("%s %d: accept error: %s", __func__, __LINE__,
			  strerror(errno));
		return -errno;
	}
	log_info("Accept scn connection %d", fd);

	err = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
	if (err)
		log_error("%s %d: %s\n", __func__, __LINE__,
			  strerror(errno));
	/* not critical, so ignore. */

	scn_fd = fd;
	isns_set_fd(isns_fd, scn_listen_fd, scn_fd);

out:
	return 0;
}

static int send_scn_rsp(char *name, uint16_t transaction)
{
	char buf[1024];
	struct isns_hdr *hdr = (struct isns_hdr *)buf;
	struct isns_tlv *tlv;
	uint16_t flags, length = 0;
	int err, max_buf;

	memset(buf, 0, sizeof(buf));
	*((uint32_t *)hdr->pdu) = 0;
	max_buf = sizeof(buf) - offsetof(struct isns_hdr, pdu);
	tlv = (struct isns_tlv *)((char *)hdr->pdu + 4);
	length +=4;

	err = isns_tlv_set(&tlv, max_buf - length, ISNS_ATTR_ISCSI_NAME,
				strlen(name) + 1, name);
	if (err < 0)
		goto out;
	length += err;

	flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_SCN_RSP, length, flags, transaction, 0);

	err = write(scn_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_error("%s %d: %s", __func__, __LINE__, strerror(errno));

out:
	return err;
}

int isns_scn_handle(int is_accept)
{
	int err;
	struct isns_io *rx = &scn_rx;
	struct isns_hdr *hdr = (struct isns_hdr *)rx->buf;
	uint16_t function, transaction;
	uint16_t length __attribute__((unused));
	uint16_t flags __attribute__((unused));
	uint16_t sequence __attribute__((unused));
	char *name = NULL;

	log_debug(3, "%s %d: %d", __func__, __LINE__, is_accept);

	if (is_accept)
		return scn_accept_connection();

	err = recv_pdu(scn_fd, rx, hdr);
	if (err) {
		if (err == -EAGAIN)
			return err;
		log_debug(1, "%s %d: close connection %d", __func__, __LINE__,
			  scn_fd);
		close(scn_fd);
		scn_fd = 0;
		isns_set_fd(isns_fd, scn_listen_fd, 0);
		return err;
	}

	get_hdr_param(hdr, function, length, flags, transaction, sequence);

	switch (function) {
	case ISNS_FUNC_SCN:
		name = print_scn_pdu(hdr);
		break;
	default:
		print_unknown_pdu(hdr);
	}

	if (name) {
		send_scn_rsp(name, transaction);
		isns_attr_query(name);
	}

	return 0;
}

static int scn_init(void)
{
	int fd, opt, err;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} lss;
	socklen_t slen;

	fd = socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		log_error("%s %d: %s\n", __func__, __LINE__, strerror(errno));
		err = -errno;
		goto out;
	}

	opt = 1;
	if (ss.ss_family == AF_INET6) {
		err = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
		if (err) {
			log_error("%s %d: %s\n", __func__, __LINE__,
				  strerror(errno));
			goto out_close;
		}
	}

	err = listen(fd, 5);
	if (err) {
		log_error("%s %d: %s\n", __func__, __LINE__, strerror(errno));
		goto out_close;
	}

	slen = sizeof(lss);
	err = getsockname(fd, (struct sockaddr *)&lss, &slen);
	if (err) {
		log_error("%s %d: %s\n", __func__, __LINE__, strerror(errno));
		goto out_close;
	}

	/* protocol independent way ? */
	if (lss.sa.sa_family == AF_INET6)
		scn_listen_port = ntohs(lss.sin6.sin6_port);
	else
		scn_listen_port = ntohs(lss.sin.sin_port);

	log_info("scn listen port %u %d %d\n", scn_listen_port, fd, err);

out_close:
	if (err)
		close(fd);
	else {
		scn_listen_fd = fd;
		isns_set_fd(isns_fd, scn_listen_fd, scn_fd);
	}

out:
	return err;
}

int isns_init(void)
{
	int err;
	char port[8];
	struct addrinfo hints, *res;

	snprintf(port, sizeof(port), "%d", ISNS_PORT);
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	err = getaddrinfo(isns_server, (char *)&port, &hints, &res);
	if (err) {
		log_error("getaddrinfo error: %s, %s", get_error_str(err),
			isns_server);
		goto out;
	}
	memcpy(&ss, res->ai_addr, sizeof(*res->ai_addr));
	freeaddrinfo(res);

	rxbuf = calloc(2, BUFSIZE);
	if (!rxbuf) {
		log_error("oom!");
		err = -ENOMEM;
		goto out;
	}

	err = scn_init();
	if (err != 0)
		goto out_free;

	isns_rx.buf = rxbuf;
	isns_rx.offset = 0;
	scn_rx.buf = rxbuf + BUFSIZE;
	scn_rx.offset = 0;

	isns_timeout = current_timeout * 1000;

	err = isns_connect();
	if (err > 0)
		err = 0;

out:
	return err;

out_free:
	free(rxbuf);
	goto out;
}

void isns_exit(void)
{
	struct target *target;

	if (isns_server == NULL)
		goto out;

	if (!isns_fd)
		goto close;

	list_for_each_entry(target, &targets_list, tlist)
		isns_scn_deregister(target->name);

	isns_deregister();
	/* we can't receive events any more. */
	isns_set_fd(0, 0, 0);

close:
	if (isns_fd) {
		close(isns_fd);
		isns_fd = 0;
	}
	if (scn_listen_fd) {
		close(scn_listen_fd);
		scn_listen_fd = 0;
	}
	if (scn_fd) {
		close(scn_fd);
		scn_fd = 0;
	}

	free(rxbuf);
	rxbuf = NULL;

	free(isns_server);
	isns_server = NULL;

	isns_timeout = -1;

out:
	return;
}
