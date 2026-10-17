// SPDX-License-Identifier: GPL-2.0-only
/*
 * LD_PRELOAD fault hook for usr/fileio/fileio_tgt. Once the file named by
 * SCST_TEST_HOOK_TRIGGER exists, SCST_TEST_HOOK_ACTION selects one fault:
 *
 * fork:     fork() once before the next scst_user ioctl. The child only
 *           sleeps, like a crash reporter, system() or popen(). A failed
 *           fork() is logged with its errno instead of the success line.
 * capacity: replace the block length of the next READ CAPACITY reply.
 *
 * SCST_TEST_HOOK_DONTFORK=1 protects active data buffers before fork(), as
 * required by scst_user on kernels older than Linux 5.9. The fixture uses
 * one worker, single-command replies and page-aligned cached allocations.
 * Protection is removed before the handler frees a buffer.
 *
 * Each fault is applied once and logged to stderr.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "scst_user.h"

static int (*next_ioctl)(int fd, unsigned long request, ...);
static int done;
static unsigned int exec_handle;
static unsigned long long exec_pbuf;
static unsigned char exec_cdb[2];
static struct scst_user_get_cmd last_cmd;

struct user_buffer {
	struct user_buffer *next;
	void *data;
	size_t length;
	int dontfork;
};

static struct user_buffer *buffers;

static int needs_dontfork(void)
{
	const char *value = getenv("SCST_TEST_HOOK_DONTFORK");

	return value && strcmp(value, "1") == 0;
}

static void fail_fork(const char *operation)
{
	int err = errno;

	fprintf(stderr, "SCST_TEST_HOOK fork failed: %s: errno %d (%s)\n",
		operation, err, strerror(err));
	_exit(EXIT_FAILURE);
}

static void remember_buffer(struct scst_user_get_cmd *cmd)
{
	struct scst_user_reply_cmd *reply;
	struct user_buffer *buffer;
	unsigned long long pbuf;
	int length;
	long page_size;

	if (!needs_dontfork() || done || !cmd->preply || !last_cmd.cmd_h)
		return;
	reply = (void *)(uintptr_t)cmd->preply;
	if (reply->cmd_h != last_cmd.cmd_h || reply->subcode != last_cmd.subcode)
		return;
	if (reply->subcode == SCST_USER_EXEC) {
		pbuf = reply->exec_reply.pbuf;
		length = last_cmd.exec_cmd.alloc_len;
	} else if (reply->subcode == SCST_USER_ALLOC_MEM) {
		pbuf = reply->alloc_reply.pbuf;
		length = last_cmd.alloc_cmd.alloc_len;
	} else {
		return;
	}
	if (!pbuf)
		return;
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0 || length <= 0 || pbuf % page_size || length % page_size) {
		errno = EINVAL;
		fail_fork("expected a whole-page cached allocation");
	}
	/* An interrupted ioctl may resubmit the same reply. */
	for (buffer = buffers; buffer; buffer = buffer->next) {
		if (buffer->data == (void *)(uintptr_t)pbuf)
			return;
	}
	buffer = calloc(1, sizeof(*buffer));
	if (!buffer)
		fail_fork("track buffer");
	buffer->data = (void *)(uintptr_t)pbuf;
	buffer->length = length;
	buffer->next = buffers;
	buffers = buffer;
}

static void forget_buffer(unsigned long long pbuf)
{
	struct user_buffer **link = &buffers;
	struct user_buffer *buffer;

	while ((buffer = *link)) {
		if (buffer->data != (void *)(uintptr_t)pbuf) {
			link = &buffer->next;
			continue;
		}
		/* Do not leave allocator memory excluded from future forks. */
		if (buffer->dontfork && madvise(buffer->data, buffer->length, MADV_DOFORK))
			fail_fork("MADV_DOFORK");
		*link = buffer->next;
		free(buffer);
		return;
	}
}

static void protect_buffers(void)
{
	struct user_buffer *buffer;
	unsigned int count = 0;

	if (!needs_dontfork())
		return;
	if (!buffers) {
		errno = ENOENT;
		fail_fork("no active data buffers");
	}
	for (buffer = buffers; buffer; buffer = buffer->next) {
		if (madvise(buffer->data, buffer->length, MADV_DONTFORK))
			fail_fork("MADV_DONTFORK");
		buffer->dontfork = 1;
		count++;
	}
	fprintf(stderr, "SCST_TEST_HOOK dontfork buffers=%u\n", count);
}

static int armed(const char *action)
{
	const char *want = getenv("SCST_TEST_HOOK_ACTION");
	const char *trigger = getenv("SCST_TEST_HOOK_TRIGGER");

	return !done && want && trigger && strcmp(want, action) == 0 &&
	       access(trigger, F_OK) == 0;
}

static void fork_once(void)
{
	pid_t pid;

	if (!armed("fork"))
		return;
	done = 1;
	protect_buffers();
	pid = fork();
	if (pid < 0) {
		int err = errno;

		fprintf(stderr, "SCST_TEST_HOOK fork failed: errno %d (%s)\n",
			err, strerror(err));
		return;
	}
	if (pid == 0) {
		for (;;)
			pause();
	}
	fprintf(stderr, "SCST_TEST_HOOK fork child=%d\n", (int)pid);
}

static void corrupt_capacity(struct scst_user_get_cmd *cmd)
{
	struct scst_user_reply_cmd *reply;
	int offset;
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
	remember_buffer(cmd);
	fork_once();
	corrupt_capacity(cmd);
	ret = next_ioctl(fd, request, arg);
	last_cmd.cmd_h = 0;
	if (ret == 0) {
		last_cmd = *cmd;
		if (cmd->subcode == SCST_USER_ON_CACHED_MEM_FREE)
			forget_buffer(cmd->on_cached_mem_free.pbuf);
		else if (cmd->subcode == SCST_USER_ON_FREE_CMD &&
			 !cmd->on_free_cmd.buffer_cached)
			forget_buffer(cmd->on_free_cmd.pbuf);
	}
	exec_handle = 0;
	if (ret == 0 && cmd->subcode == SCST_USER_EXEC) {
		exec_handle = cmd->cmd_h;
		exec_pbuf = cmd->exec_cmd.pbuf;
		memcpy(exec_cdb, cmd->exec_cmd.cdb, sizeof(exec_cdb));
	}
	return ret;
}
