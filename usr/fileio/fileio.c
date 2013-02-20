/*
 *  fileio.c
 *
 *  Copyright (C) 2007 - 2013 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <getopt.h>
#include <malloc.h>
#include <inttypes.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/poll.h>
#include <sys/ioctl.h>

#include <pthread.h>

char *app_name;

#include "common.h"

#if defined(DEBUG) || defined(TRACING)

#ifdef DEBUG
/*#define DEFAULT_LOG_FLAGS (TRACE_ALL & ~TRACE_MEMORY & ~TRACE_BUFF \
	 & ~TRACE_FUNCTION)
#define DEFAULT_LOG_FLAGS (TRACE_ALL & ~TRACE_MEMORY & ~TRACE_BUFF & \
	~TRACE_SCSI & ~TRACE_SCSI_SERIALIZING & ~TRACE_DEBUG)
*/
#define DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MINOR | TRACE_PID | \
	TRACE_FUNCTION | TRACE_SPECIAL | TRACE_MGMT | TRACE_MGMT_DEBUG | \
	TRACE_TIME)

#define TRACE_SN(args...)	TRACE(TRACE_SCSI_SERIALIZING, args)

#else /* DEBUG */

# ifdef TRACING
#define DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MGMT | \
	TRACE_TIME | TRACE_SPECIAL)
# else
#define DEFAULT_LOG_FLAGS 0
# endif
#endif /* DEBUG */

unsigned long trace_flag = DEFAULT_LOG_FLAGS;
#endif /* defined(DEBUG) || defined(TRACING) */

#define DEF_BLOCK_SHIFT		9
#define VERSION_STR		"3.0.0-pre2"
#define THREADS			7

#define MAX_VDEVS		10

static void *align_alloc(size_t size);

static struct vdisk_dev devs[MAX_VDEVS];
static int num_devs;

int vdisk_ID;
static int flush_interval;

static int parse_type = SCST_USER_PARSE_STANDARD;
static int on_free_cmd_type = SCST_USER_ON_FREE_CMD_IGNORE;
static int on_free_cmd_type_set;
static int memory_reuse_type = SCST_USER_MEM_REUSE_ALL;
static int threads = THREADS;
static int unreg_before_close;
static int block_size = (1 << DEF_BLOCK_SHIFT);
static int block_shift = DEF_BLOCK_SHIFT;
static int wt_flag, rd_only_flag, o_direct_flag, nullio, nv_cache;
#if defined(DEBUG_TM_IGNORE) || defined(DEBUG_TM_IGNORE_ALL)
static int debug_tm_ignore;
#endif
static int non_blocking, sgv_shared, sgv_single_alloc_pages, sgv_purge_interval;
static int sgv_disable_clustered_pool, prealloc_buffers_num, prealloc_buffer_size;

static void *(*alloc_fn)(size_t size) = align_alloc;

static struct option const long_options[] =
{
	{"block", required_argument, 0, 'b'},
	{"threads", required_argument, 0, 'e'},
	{"write_through", no_argument, 0, 't'},
	{"read_only", no_argument, 0, 'r'},
	{"direct", no_argument, 0, 'o'},
	{"nullio", no_argument, 0, 'n'},
	{"nv_cache", no_argument, 0, 'c'},
	{"parse", required_argument, 0, 'p'},
	{"on_free", required_argument, 0, 'f'},
	{"mem_reuse", required_argument, 0, 'm'},
	{"non_blocking", no_argument, 0, 'l'},
	{"vdisk_id", required_argument, 0, 'I'},
	{"flush", required_argument, 0, 'F'},
	{"unreg_before_close", no_argument, 0, 'u'},
	{"sgv_shared", no_argument, 0, 's'},
	{"sgv_single_cache", required_argument, 0, 'S'},
	{"sgv_purge_interval", required_argument, 0, 'P'},
	{"sgv_disable_clustered_pool", no_argument, 0, 'D'},
	{"prealloc_buffers", required_argument, 0, 'R'},
	{"prealloc_buffer_size", required_argument, 0, 'Z'},
#if defined(DEBUG) || defined(TRACING)
	{"debug", required_argument, 0, 'd'},
#endif
#if defined(DEBUG_TM_IGNORE) || defined(DEBUG_TM_IGNORE_ALL)
	{"debug_tm_ignore", no_argument, 0, 'g'},
#endif
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

static void usage(void)
{
	printf("Usage: %s [OPTIONS] name path [name path] ...\n", app_name);
	printf("\nFILEIO disk target emulator for SCST\n");
	printf("  -b, --block=size	Block size, must be power of 2 and >=512\n");
	printf("  -e, --threads=count	Number of threads, %d by default\n", THREADS);
	printf("  -t, --write_through	Write through mode\n");
	printf("  -r, --read_only	Read only\n");
	printf("  -o, --direct		O_DIRECT mode\n");
	printf("  -n, --nullio		NULLIO mode\n");
	printf("  -c, --nv_cache	NV_CACHE mode\n");
	printf("  -p, --parse=type	Parse type, one of \"std\" "
		"(default), \"call\" or \"excpt\"\n");
	printf("  -f, --on_free=type	On free call type, one of \"ignore\" "
		"(default) or \"call\"\n");
	printf("  -m, --mem_reuse=type	Memory reuse type, one of \"all\" "
		"(default), \"read\", \"write\" or \"none\"\n");
	printf("  -l, --non_blocking	Use non-blocking operations\n");
	printf("  -I, --vdisk_id=ID	Vdisk ID (used in multi-targets setups)\n");
	printf("  -F, --flush=n		Flush SGV cache each n seconds\n");
	printf("  -s, --sgv_shared	Use shared SGV cache\n");
	printf("  -S, --sgv_single_cache=n Use single entry SGV cache with n pages/entry\n");
	printf("  -P, --sgv_purge_interval=n Use SGV cache purge interval n seconds\n");
	printf("  -u, --unreg_before_close Unregister before close\n");
	printf("  -D, --sgv_disable_clustered_pool Disable clustered SGV pool\n");
	printf("  -R, --prealloc_buffers=n Prealloc n buffers\n");
	printf("  -Z, --prealloc_buffer_size=n Sets the size in KB of each prealloced buffer\n");
#if defined(DEBUG) || defined(TRACING)
	printf("  -d, --debug=level	Debug tracing level\n");
#endif
#if defined(DEBUG_TM_IGNORE) || defined(DEBUG_TM_IGNORE_ALL)
	printf("  -g, --debug_tm_ignore	Turn on DEBUG_TM_IGNORE\n");
#endif
	return;
}

static int scst_calc_block_shift(int sector_size)
{
	int block_shift = 0;
	int t = sector_size;

	if (sector_size == 0)
		goto out;

	t = sector_size;
	while(1) {
		if ((t & 1) != 0)
			break;
		t >>= 1;
		block_shift++;
	}
	if (block_shift < 9) {
		PRINT_ERROR("Wrong sector size %d", sector_size);
		block_shift = -1;
	}

out:
	TRACE_EXIT_RES(block_shift);
	return block_shift;
}

static void *align_alloc(size_t size)
{
	TRACE_MEM("Request to alloc %zdKB", size / 1024);
	return memalign(PAGE_SIZE, size);
}

void sigalrm_handler(int signo)
{
	int res, i;

	TRACE_ENTRY();

	TRACE_DBG("%s", "Flushing cache...");

	for (i = 0; i < num_devs; i++) {
		res = ioctl(devs[i].scst_usr_fd, SCST_USER_FLUSH_CACHE, NULL);
		if (res != 0) {
			res = errno;
			PRINT_ERROR("Unable to flush cache: %s", strerror(res));
			goto out;
		}
	}

	TRACE_DBG("%s", "Flushing cache done.");

	res = alarm(flush_interval);
	if (res != 0) {
		res = errno;
		PRINT_ERROR("alarm() failed: %s", strerror(res));
		goto out;
	}

out:
	TRACE_EXIT();
	return;
}

void sigusr1_handler(int signo)
{
	int res, i;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("%s", "Capacity data changed...");

	for (i = 0; i < num_devs; i++) {
		res = ioctl(devs[i].scst_usr_fd, SCST_USER_DEVICE_CAPACITY_CHANGED, NULL);
		if (res != 0) {
			res = errno;
			PRINT_ERROR("Capacity data changed failed: %s", strerror(res));
			goto out;
		}
	}

	TRACE_DBG("%s", "Capacity data changed done.");

out:
	TRACE_EXIT();
	return;
}

int prealloc_buffers(struct vdisk_dev *dev)
{
	int i, c, res = 0;

	if (sgv_disable_clustered_pool)
		c = 0;
	else
		c = 1;

	do {
		for (i = 0; i < prealloc_buffers_num; i++) {
			union scst_user_prealloc_buffer pre;

			memset(&pre, 0, sizeof(pre));
			pre.in.pbuf = (unsigned long)alloc_fn(prealloc_buffer_size);
			pre.in.bufflen = prealloc_buffer_size;
			pre.in.for_clust_pool = c;

			if (pre.in.pbuf == 0) {
				res = errno;
				PRINT_ERROR("Unable to prealloc buffer: %s",
					strerror(res));
				goto out;
			}

			res = ioctl(dev->scst_usr_fd, SCST_USER_PREALLOC_BUFFER, &pre);
			if (res != 0) {
				res = errno;
				PRINT_ERROR("Unable to send prealloced buffer: %s",
					strerror(res));
				free((void *)(unsigned long)pre.in.pbuf);
				goto out;
			}
			TRACE_MEM("Prealloced buffer cmd_h %x", pre.out.cmd_h);
		}
		c--;
	} while (c >= 0);

out:
	return res;
}

int start(int argc, char **argv)
{
	int res = 0;
	int fd;
	int i, rc;
	void *rc1;
	static struct scst_user_dev_desc desc;
	pthread_t thread[MAX_VDEVS][threads];

	memset(thread, 0, sizeof(thread));

	i = 0;
	optind -= 2;
	while (1) {
		int j;

		optind += 2;
		if (optind > (argc-2))
			break;

		devs[i].block_size = block_size;
		devs[i].block_shift = block_shift;
		devs[i].alloc_fn = alloc_fn;

		devs[i].rd_only_flag = rd_only_flag;
		devs[i].wt_flag = wt_flag;
		devs[i].nv_cache = nv_cache;
		devs[i].o_direct_flag = o_direct_flag;
		devs[i].nullio = nullio;
		devs[i].non_blocking = non_blocking;
#if defined(DEBUG_TM_IGNORE) || defined(DEBUG_TM_IGNORE_ALL)
		devs[i].debug_tm_ignore = debug_tm_ignore;
#endif
		devs[i].type = TYPE_DISK;
		devs[i].name = argv[optind];
		devs[i].file_name = argv[optind+1];

		TRACE_DBG("Opening file %s", devs[i].file_name);
		fd = open(devs[i].file_name, O_RDONLY|O_LARGEFILE);
		if (fd < 0) {
			res = -errno;
			PRINT_ERROR("Unable to open file %s (%s)", devs[i].file_name,
				strerror(-res));
			continue;
		}

		devs[i].file_size = lseek64(fd, 0, SEEK_END);
		devs[i].nblocks = devs[i].file_size >> devs[i].block_shift;

		close(fd);

		PRINT_INFO("%s", " ");
		PRINT_INFO("Virtual device \"%s\", path \"%s\", size %"PRId64"MB, "
			"block size %d, nblocks %"PRId64", options:", devs[i].name,
			devs[i].file_name, (uint64_t)devs[i].file_size/1024/1024,
			devs[i].block_size, (uint64_t)devs[i].nblocks);

		snprintf(devs[i].usn, sizeof(devs[i].usn), "%"PRIx64,
			gen_dev_id_num(&devs[i]));
		TRACE_DBG("usn %s", devs[i].usn);

		devs[i].scst_usr_fd = open(DEV_USER_PATH DEV_USER_NAME, O_RDWR |
					(devs[i].non_blocking ? O_NONBLOCK : 0));
		if (devs[i].scst_usr_fd < 0) {
			res = -errno;
			PRINT_ERROR("Unable to open SCST device %s (%s)",
				DEV_USER_PATH DEV_USER_NAME, strerror(-res));
			goto out_unreg;
		}

		memset(&desc, 0, sizeof(desc));
		desc.license_str = (unsigned long)"GPL";
		desc.version_str = (unsigned long)DEV_USER_VERSION;
		strncpy(desc.name, devs[i].name, sizeof(desc.name)-1);
		desc.name[sizeof(desc.name)-1] = '\0';
		if (sgv_shared) {
			desc.sgv_shared = 1;
			strncpy(desc.sgv_name, devs[0].name, sizeof(desc.sgv_name)-1);
			desc.sgv_name[sizeof(desc.sgv_name)-1] = '\0';
		}
		desc.sgv_single_alloc_pages = sgv_single_alloc_pages;
		desc.sgv_purge_interval = sgv_purge_interval;
		desc.sgv_disable_clustered_pool = sgv_disable_clustered_pool;
		desc.type = devs[i].type;
		desc.block_size = devs[i].block_size;

		desc.opt.parse_type = parse_type;
		desc.opt.on_free_cmd_type = on_free_cmd_type;
		desc.opt.memory_reuse_type = memory_reuse_type;

		desc.opt.tst = SCST_CONTR_MODE_SEP_TASK_SETS;
		desc.opt.queue_alg = SCST_CONTR_MODE_QUEUE_ALG_UNRESTRICTED_REORDER;
		desc.opt.d_sense = SCST_CONTR_MODE_FIXED_SENSE;

		res = ioctl(devs[i].scst_usr_fd, SCST_USER_REGISTER_DEVICE, &desc);
		if (res != 0) {
			res = errno;
			PRINT_ERROR("Unable to register device: %s", strerror(res));
			goto out_unreg;
		}

		if ((prealloc_buffers_num > 0) && (prealloc_buffer_size > 0)) {
			res = prealloc_buffers(&devs[i]);
			if (res != 0)
				goto out_unreg;
		}

#if 1
		{
			/* Not needed, added here only as a test */
			struct scst_user_opt opt;

			res = ioctl(devs[i].scst_usr_fd, SCST_USER_GET_OPTIONS, &opt);
			if (res != 0) {
				res = errno;
				PRINT_ERROR("Unable to get options: %s", strerror(res));
				goto out_unreg;
			}

			opt.parse_type = parse_type;
			opt.on_free_cmd_type = on_free_cmd_type;
			opt.memory_reuse_type = memory_reuse_type;

			res = ioctl(devs[i].scst_usr_fd, SCST_USER_SET_OPTIONS, &opt);
			if (res != 0) {
				res = errno;
				PRINT_ERROR("Unable to set options: %s", strerror(res));
				goto out_unreg;
			}
		}
#endif

		res = pthread_mutex_init(&devs[i].dev_mutex, NULL);
		if (res != 0) {
			res = errno;
			PRINT_ERROR("pthread_mutex_init() failed: %s", strerror(res));
			goto out_unreg;
		}

		for (j = 0; j < threads; j++) {
			rc = pthread_create(&thread[i][j], NULL, main_loop, &devs[i]);
			if (rc != 0) {
				res = errno;
				PRINT_ERROR("pthread_create() failed: %s",
					strerror(res));
				break;
			}
		}

		i++;
		num_devs++;
		if (num_devs >= MAX_VDEVS) {
			PRINT_INFO("Max devices limit %d reached", i);
			break;
		}
	}

	for (i = 0; i < num_devs; i++) {
		int j = 0;
		while (thread[i][j] != 0) {
			rc = pthread_join(thread[i][j], &rc1);
			if (rc != 0) {
				res = errno;
				PRINT_ERROR("pthread_join() failed: %s",
					strerror(res));
			} else if (rc1 != NULL) {
				res = (long)rc1;
				PRINT_INFO("Thread %d exited (dev %s), res %lx", j,
					devs[i].name, (long)rc1);
			} else
				PRINT_INFO("Thread %d exited (dev %s)", j,
					devs[i].name);
			j++;
		}
		pthread_mutex_destroy(&devs[i].dev_mutex);
	}

out_unreg:
	alarm(0);
	for (i = 0; i < num_devs; i++) {
		if (unreg_before_close) {
			res = ioctl(devs[i].scst_usr_fd, SCST_USER_UNREGISTER_DEVICE, NULL);
			if (res != 0) {
				res = errno;
				PRINT_ERROR("Unable to unregister device: %s",
					strerror(res));
				/* go through */
			}
		}
		close(devs[i].scst_usr_fd);
	}

	return res;
}

int main(int argc, char **argv)
{
	int res = 0;
	int ch, longindex;
	struct sigaction act;

	setlinebuf(stdout);

	res = debug_init();
	if (res != 0)
		goto out;

	app_name = argv[0];

	memset(devs, 0, sizeof(devs));

	while ((ch = getopt_long(argc, argv, "+b:e:trongluF:I:cp:f:m:d:vsS:P:hDR:Z:",
			long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'b':
			block_size = atoi(optarg);
			PRINT_INFO("block_size %x (%s)", block_size, optarg);
			block_shift = scst_calc_block_shift(block_size);
			if (block_shift < 9) {
				res = -EINVAL;
				goto out_usage;
			}
			break;
		case 'e':
			threads = strtol(optarg, (char **)NULL, 0);
			break;
		case 't':
			wt_flag = 1;
			break;
#if defined(DEBUG) || defined(TRACING)
		case 'd':
			trace_flag = strtol(optarg, (char **)NULL, 0);
			break;
#endif
		case 'r':
			rd_only_flag = 1;
			break;
		case 'o':
			o_direct_flag = 1;
			break;
		case 'n':
			nullio = 1;
			break;
		case 'c':
			nv_cache = 1;
			break;
		case 'p':
			if (strncmp(optarg, "std", 3) == 0)
				parse_type = SCST_USER_PARSE_STANDARD;
			else if (strncmp(optarg, "call", 3) == 0)
				parse_type = SCST_USER_PARSE_CALL;
			else if (strncmp(optarg, "excpt", 5) == 0)
				parse_type = SCST_USER_PARSE_EXCEPTION;
			else
				goto out_usage;
			break;
		case 'f':
			on_free_cmd_type_set = 1;
			if (strncmp(optarg, "ignore", 6) == 0)
				on_free_cmd_type = SCST_USER_ON_FREE_CMD_IGNORE;
			else if (strncmp(optarg, "call", 3) == 0)
				on_free_cmd_type = SCST_USER_ON_FREE_CMD_CALL;
			else
				goto out_usage;
			break;
		case 's':
			sgv_shared = 1;
			break;
		case 'S':
			sgv_single_alloc_pages = atoi(optarg);
			break;
		case 'P':
			sgv_purge_interval = atoi(optarg);
			break;
		case 'D':
			sgv_disable_clustered_pool = 1;
			break;
		case 'R':
			prealloc_buffers_num = atoi(optarg);
			break;
		case 'Z':
			prealloc_buffer_size = atoi(optarg) * 1024;
			break;
		case 'm':
			if (strncmp(optarg, "all", 3) == 0)
				memory_reuse_type = SCST_USER_MEM_REUSE_ALL;
			else if (strncmp(optarg, "read", 4) == 0)
				memory_reuse_type = SCST_USER_MEM_REUSE_READ;
			else if (strncmp(optarg, "write", 5) == 0)
				memory_reuse_type = SCST_USER_MEM_REUSE_WRITE;
			else if (strncmp(optarg, "none", 4) == 0)
				memory_reuse_type = SCST_USER_MEM_NO_REUSE;
			else
				goto out_usage;
			break;
		case 'l':
			non_blocking = 1;
			break;
		case 'I':
			vdisk_ID = strtol(optarg, (char **)NULL, 0);
			break;
		case 'F':
			flush_interval = strtol(optarg, (char **)NULL, 0);
			if (flush_interval < 0) {
				PRINT_ERROR("Wrong flush interval %d",
					flush_interval);
				flush_interval = 0;
			}
			break;
		case 'u':
			unreg_before_close = 1;
			break;
#if defined(DEBUG_TM_IGNORE) || defined(DEBUG_TM_IGNORE_ALL)
		case 'g':
			debug_tm_ignore = 1;
			break;
#endif
		case 'v':
			printf("%s version %s\n", app_name, VERSION_STR);
			goto out_done;
		default:
			goto out_usage;
		}
	}

	if (optind > (argc-2))
		goto out_usage;

	if (!on_free_cmd_type_set &&
	    (memory_reuse_type != SCST_USER_MEM_REUSE_ALL))
		on_free_cmd_type = SCST_USER_ON_FREE_CMD_CALL;

	PRINT_INFO("%s", "Options:");

	if (rd_only_flag)
		PRINT_INFO("	%s", "READ ONLY");
	if (wt_flag)
		PRINT_INFO("	%s", "WRITE THROUGH");
	if (nv_cache)
		PRINT_INFO("	%s", "NV_CACHE");
	if (o_direct_flag)
		PRINT_INFO("	%s", "O_DIRECT");
	if (nullio)
		PRINT_INFO("	%s", "NULLIO");
	if (non_blocking)
		PRINT_INFO("	%s", "NON-BLOCKING");

	switch(parse_type) {
	case SCST_USER_PARSE_STANDARD:
		PRINT_INFO("	%s", "Standard parse");
		break;
	case SCST_USER_PARSE_CALL:
		PRINT_INFO("	%s", "Call parse");
		break;
	case SCST_USER_PARSE_EXCEPTION:
		PRINT_INFO("	%s", "Exception parse");
		break;
	default:
		sBUG();
	}

	switch(on_free_cmd_type) {
	case SCST_USER_ON_FREE_CMD_IGNORE:
		PRINT_INFO("	%s", "Ignore on_free_cmd");
		break;
	case SCST_USER_ON_FREE_CMD_CALL:
		PRINT_INFO("	%s", "Call on_free_cmd");
		break;
	default:
		sBUG();
	}

	switch(memory_reuse_type) {
	case SCST_USER_MEM_REUSE_ALL:
		PRINT_INFO("	%s", "Full memory reuse enabled");
		break;
	case SCST_USER_MEM_REUSE_READ:
		PRINT_INFO("	%s", "READ memory reuse enabled");
		break;
	case SCST_USER_MEM_REUSE_WRITE:
		PRINT_INFO("	%s", "WRITE memory reuse enabled");
		break;
	case SCST_USER_MEM_NO_REUSE:
		PRINT_INFO("	%s", "Memory reuse disabled");
		break;
	default:
		sBUG();
	}

	if (sgv_shared)
		PRINT_INFO("	%s", "SGV shared");

	if (sgv_single_alloc_pages != 0)
		PRINT_INFO("	Use single entry SGV cache with %d pages/entry",
			sgv_single_alloc_pages);

	if (sgv_purge_interval != 0) {
		if (sgv_purge_interval > 0)
			PRINT_INFO("	Use SGV cache purge interval %d seconds",
				sgv_purge_interval);
		else
			PRINT_INFO("	%s", "SGV cache purging disabled");
	}

	if (sgv_disable_clustered_pool)
		PRINT_INFO("	%s", "Disable clustered SGV pool");

	if ((prealloc_buffers_num > 0) && (prealloc_buffer_size > 0))
		PRINT_INFO("	Prealloc %d buffers of %dKB",
			prealloc_buffers_num, prealloc_buffer_size / 1024);

	if (!o_direct_flag && (memory_reuse_type == SCST_USER_MEM_NO_REUSE)) {
		PRINT_INFO("	%s", "Using unaligned buffers");
		alloc_fn = malloc;
	}

#if defined(DEBUG_TM_IGNORE) || defined(DEBUG_TM_IGNORE_ALL)
	if (debug_tm_ignore)
		PRINT_INFO("	%s", "DEBUG_TM_IGNORE");
#endif

#ifdef DEBUG
	PRINT_INFO("trace_flag %lx", trace_flag);
#endif

	memset(&act, 0, sizeof(act));
	act.sa_handler = sigusr1_handler;
	act.sa_flags = SA_RESTART;
	sigemptyset(&act.sa_mask);
	res = sigaction(SIGUSR1, &act, NULL);
	if (res != 0) {
		res = errno;
		PRINT_ERROR("sigaction() failed: %s",
			strerror(res));
		/* don't do anything */
	}

	if (flush_interval != 0) {
		memset(&act, 0, sizeof(act));
		act.sa_handler = sigalrm_handler;
		act.sa_flags = SA_RESTART;
		sigemptyset(&act.sa_mask);
		res = sigaction(SIGALRM, &act, NULL);
		if (res != 0) {
			res = errno;
			PRINT_ERROR("sigaction() failed: %s",
				strerror(res));
			goto out_done;
		}       

		res = alarm(flush_interval);
		if (res != 0) {
			res = errno;
			PRINT_ERROR("alarm() failed: %s",
				strerror(res));
			goto out_done;
		}
	}

	res = start(argc, argv);

out_done:
	debug_done();

out:
	return res;

out_usage:
	usage();
	goto out_done;
}
