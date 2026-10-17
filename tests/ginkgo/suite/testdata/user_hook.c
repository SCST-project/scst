// SPDX-License-Identifier: GPL-2.0-only
/*
 * LD_PRELOAD fault hook for usr/fileio/fileio_tgt. Once the file named by
 * SCST_TEST_HOOK_TRIGGER exists, SCST_TEST_HOOK_ACTION selects one fault:
 *
 * capacity: replace the block length of the next READ CAPACITY reply.
 *
 * Each fault is applied once and logged to stderr.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "scst_user.h"

static int (*next_ioctl)(int fd, unsigned long request, ...);
static int done;
static unsigned int exec_handle;
static unsigned long long exec_pbuf;
static unsigned char exec_cdb[2];

static int armed(const char *action)
{
	const char *want = getenv("SCST_TEST_HOOK_ACTION");
	const char *trigger = getenv("SCST_TEST_HOOK_TRIGGER");

	return !done && want && trigger && strcmp(want, action) == 0 &&
	       access(trigger, F_OK) == 0;
}

static void corrupt_capacity(struct scst_user_get_cmd *cmd)
{
	struct scst_user_reply_cmd *reply;
	unsigned int offset;
	unsigned char *data;

	if (!exec_handle || !cmd->preply || !armed("capacity"))
		return;
	reply = (void *)(uintptr_t)cmd->preply;
	if (reply->cmd_h != exec_handle || reply->subcode != SCST_USER_EXEC ||
	    reply->exec_reply.status != 0)
		return;
	if (exec_cdb[0] == 0x25)
		offset = 4;	/* READ CAPACITY(10) */
	else if (exec_cdb[0] == 0x9e && (exec_cdb[1] & 0x1f) == 0x10)
		offset = 8;	/* READ CAPACITY(16) */
	else
		return;
	if (reply->exec_reply.resp_data_len < offset + 4)
		return;
	/* The reply names a buffer only if the handler allocated it. */
	data = (void *)(uintptr_t)(reply->exec_reply.pbuf ?: exec_pbuf);
	if (!data)
		return;
	done = 1;
	/* 809052976: not a power of two. */
	memcpy(&data[offset], "\x30\x39\x2b\x30", 4);
	fprintf(stderr, "SCST_TEST_HOOK capacity cdb=0x%02x\n", exec_cdb[0]);
}

int ioctl(int fd, unsigned long request, ...)
{
	struct scst_user_get_cmd *cmd;
	va_list args;
	void *arg;
	int ret;

	if (!next_ioctl)
		next_ioctl = dlsym(RTLD_NEXT, "ioctl");
	if (!next_ioctl)
		abort();
	va_start(args, request);
	arg = va_arg(args, void *);
	va_end(args);
	if (request != SCST_USER_REPLY_AND_GET_CMD || !arg)
		return next_ioctl(fd, request, arg);

	cmd = arg;
	corrupt_capacity(cmd);
	ret = next_ioctl(fd, request, arg);
	exec_handle = 0;
	if (ret == 0 && cmd->subcode == SCST_USER_EXEC) {
		exec_handle = cmd->cmd_h;
		exec_pbuf = cmd->exec_cmd.pbuf;
		memcpy(exec_cdb, cmd->exec_cmd.cdb, sizeof(exec_cdb));
	}
	return ret;
}
