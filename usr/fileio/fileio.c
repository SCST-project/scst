/*
 *  fileio.c
 *
 *  Copyright (C) 2007 - 2009 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2007 - 2009 ID7 Ltd.
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
	TRACE_FUNCTION | TRACE_SPECIAL | TRACE_MGMT | TRACE_MGMT_MINOR | \
	TRACE_MGMT_DEBUG | TRACE_TIME)

#define TRACE_SN(args...)	TRACE(TRACE_SCSI_SERIALIZING, args)

#else /* DEBUG */

# ifdef TRACING
#define DEFAULT_LOG_FLAGS (TRACE_OUT_OF_MEM | TRACE_MINOR | TRACE_MGMT | \
	TRACE_TIME | TRACE_SPECIAL)
# else
#define DEFAULT_LOG_FLAGS 0
# endif
#endif /* DEBUG */

unsigned long trace_flag = DEFAULT_LOG_FLAGS;
#endif /* defined(DEBUG) || defined(TRACING) */

#define DEF_BLOCK_SHIFT		9
#define VERSION_STR		"1.0.1.1"
#define THREADS			7

struct vdisk_dev dev;
int vdisk_ID;
int flush_interval;

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
	printf("Usage: %s [OPTION] name path\n", app_name);
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
	printf("  -u, --unreg_before_close Unregister before close\n");
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
	return memalign(PAGE_SIZE, size);
}

void sigalrm_handler(int signo)
{
	int res;

	TRACE_ENTRY();

	TRACE_DBG("%s", "Flushing cache...");

	res = ioctl(dev.scst_usr_fd, SCST_USER_FLUSH_CACHE, NULL);
	if (res != 0) {
		res = errno;
		PRINT_ERROR("Unable to flush cache: %s", strerror(res));
		goto out;
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
	int res;

	TRACE_ENTRY();

	TRACE_MGMT_DBG("%s", "Capacity data changed...");

	res = ioctl(dev.scst_usr_fd, SCST_USER_DEVICE_CAPACITY_CHANGED, NULL);
	if (res != 0) {
		res = errno;
		PRINT_ERROR("Capacity data changed failed: %s", strerror(res));
		goto out;
	}

	TRACE_DBG("%s", "Capacity data changed done.");

out:
	TRACE_EXIT();
	return;
}

int main(int argc, char **argv)
{
	int res = 0;
	int ch, longindex;
	int fd;
	int parse_type = SCST_USER_PARSE_STANDARD;
	int on_free_cmd_type = SCST_USER_ON_FREE_CMD_IGNORE;
	int on_free_cmd_type_set = 0;
	int memory_reuse_type = SCST_USER_MEM_REUSE_ALL;
	int threads = THREADS;
	struct scst_user_dev_desc desc;
	int unreg_before_close = 0;

	setlinebuf(stdout);

	res = debug_init();
	if (res != 0)
		goto out;

	app_name = argv[0];

	memset(&dev, 0, sizeof(dev));
	dev.block_size = (1 << DEF_BLOCK_SHIFT);
	dev.block_shift = DEF_BLOCK_SHIFT;
	dev.type = TYPE_DISK;
	dev.alloc_fn = align_alloc;

	while ((ch = getopt_long(argc, argv, "+b:e:trongluF:I:cp:f:m:d:vh", long_options,
				&longindex)) >= 0) {
		switch (ch) {
		case 'b':
			dev.block_size = atoi(optarg);
			PRINT_INFO("block_size %x (%s)", dev.block_size, optarg);
			dev.block_shift = scst_calc_block_shift(dev.block_size);
			if (dev.block_shift < 9) {
				res = -EINVAL;
				goto out_usage;
			}
			break;
		case 'e':
			threads = strtol(optarg, (char **)NULL, 0);
			break;
		case 't':
			dev.wt_flag = 1;
			break;
#if defined(DEBUG) || defined(TRACING)
		case 'd':
			trace_flag = strtol(optarg, (char **)NULL, 0);
			break;
#endif
		case 'r':
			dev.rd_only_flag = 1;
			break;
		case 'o':
			dev.o_direct_flag = 1;
			dev.alloc_fn = align_alloc;
			break;
		case 'n':
			dev.nullio = 1;
			break;
		case 'c':
			dev.nv_cache = 1;
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
			dev.non_blocking = 1;
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
			dev.debug_tm_ignore = 1;
			break;
#endif
		case 'v':
			printf("%s version %s\n", app_name, VERSION_STR);
			goto out_done;
		default:
			goto out_usage;
		}
	}

	if (optind != (argc-2))
		goto out_usage;

	if (!on_free_cmd_type_set &&
	    (memory_reuse_type != SCST_USER_MEM_REUSE_ALL))
		on_free_cmd_type = SCST_USER_ON_FREE_CMD_CALL;

	dev.name = argv[optind];
	dev.file_name = argv[optind+1];

	TRACE_DBG("Opening file %s", dev.file_name);
	fd = open(dev.file_name, O_RDONLY|O_LARGEFILE);
	if (fd < 0) {
		res = -errno;
		PRINT_ERROR("Unable to open file %s (%s)", dev.file_name,
			strerror(-res));
		goto out_done;
	}

	dev.file_size = lseek64(fd, 0, SEEK_END);
	dev.nblocks = dev.file_size >> dev.block_shift;

	close(fd);

	PRINT_INFO("Virtual device \"%s\", path \"%s\", size %"PRId64"Mb, "
		"block size %d, nblocks %"PRId64", options:", dev.name,
		dev.file_name, (uint64_t)dev.file_size/1024/1024,
		dev.block_size, (uint64_t)dev.nblocks);
	if (dev.rd_only_flag)
		PRINT_INFO("	%s", "READ ONLY");
	if (dev.wt_flag)
		PRINT_INFO("	%s", "WRITE THROUGH");
	if (dev.nv_cache)
		PRINT_INFO("	%s", "NV_CACHE");
	if (dev.o_direct_flag)
		PRINT_INFO("	%s", "O_DIRECT");
	if (dev.nullio)
		PRINT_INFO("	%s", "NULLIO");
	if (dev.non_blocking)
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

	if (!dev.o_direct_flag && (memory_reuse_type == SCST_USER_MEM_NO_REUSE)) {
		PRINT_INFO("	%s", "Using unaligned buffers");
		dev.alloc_fn = malloc;
	}

#if defined(DEBUG_TM_IGNORE) || defined(DEBUG_TM_IGNORE_ALL)
	if (dev.debug_tm_ignore) {
		PRINT_INFO("	%s", "DEBUG_TM_IGNORE");
	}
#endif

#ifdef DEBUG
	PRINT_INFO("trace_flag %lx", trace_flag);
#endif

	snprintf(dev.usn, sizeof(dev.usn), "%llx", gen_dev_id_num(&dev));
	TRACE_DBG("usn %s", dev.usn);

	dev.scst_usr_fd = open(DEV_USER_PATH DEV_USER_NAME, O_RDWR |
		(dev.non_blocking ? O_NONBLOCK : 0));
	if (dev.scst_usr_fd < 0) {
		res = -errno;
		PRINT_ERROR("Unable to open SCST device %s (%s)",
			DEV_USER_PATH DEV_USER_NAME, strerror(-res));
		goto out_done;
	}

	memset(&desc, 0, sizeof(desc));
	desc.version_str = (unsigned long)DEV_USER_VERSION;
	strncpy(desc.name, dev.name, sizeof(desc.name)-1);
	desc.name[sizeof(desc.name)-1] = '\0';
	desc.type = dev.type;
	desc.block_size = dev.block_size;

	desc.opt.parse_type = parse_type;
	desc.opt.on_free_cmd_type = on_free_cmd_type;
	desc.opt.memory_reuse_type = memory_reuse_type;

	desc.opt.tst = SCST_CONTR_MODE_SEP_TASK_SETS;
	desc.opt.queue_alg = SCST_CONTR_MODE_QUEUE_ALG_UNRESTRICTED_REORDER;
	desc.opt.d_sense = SCST_CONTR_MODE_FIXED_SENSE;

	res = ioctl(dev.scst_usr_fd, SCST_USER_REGISTER_DEVICE, &desc);
	if (res != 0) {
		res = errno;
		PRINT_ERROR("Unable to register device: %s", strerror(res));
		goto out_close;
	}

#if 1
	{
		/* Not needed, added here only as a test */
		struct scst_user_opt opt;

		res = ioctl(dev.scst_usr_fd, SCST_USER_GET_OPTIONS, &opt);
		if (res != 0) {
			res = errno;
			PRINT_ERROR("Unable to get options: %s", strerror(res));
			goto out_unreg;
		}

		opt.parse_type = parse_type;
		opt.on_free_cmd_type = on_free_cmd_type;
		opt.memory_reuse_type = memory_reuse_type;

		res = ioctl(dev.scst_usr_fd, SCST_USER_SET_OPTIONS, &opt);
		if (res != 0) {
			res = errno;
			PRINT_ERROR("Unable to set options: %s", strerror(res));
			goto out_unreg;
		}
	}
#endif

	res = pthread_mutex_init(&dev.dev_mutex, NULL);
	if (res != 0) {
		res = errno;
		PRINT_ERROR("pthread_mutex_init() failed: %s", strerror(res));
		goto out_unreg;
	}

	{
		pthread_t thread[threads];
		int i, j, rc;
		void *rc1;
		struct sigaction act;

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

		for(i = 0; i < threads; i++) {
			rc = pthread_create(&thread[i], NULL, main_loop, &dev);
			if (rc != 0) {
				res = errno;
				PRINT_ERROR("pthread_create() failed: %s",
					strerror(res));
				break;
			}
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
				goto join;
			}       

			res = alarm(flush_interval);
			if (res != 0) {
				res = errno;
				PRINT_ERROR("alarm() failed: %s",
					strerror(res));
				goto join;
			}
		}

join:
		j = i;
		for(i = 0; i < j; i++) {
			rc = pthread_join(thread[i], &rc1);
			if (rc != 0) {
				res = errno;
				PRINT_ERROR("pthread_join() failed: %s",
					strerror(res));
			} else if (rc1 != NULL) {
				res = (long)rc1;
				PRINT_INFO("Thread %d exited, res %lx", i,
					(long)rc1);
			} else
				PRINT_INFO("Thread %d exited", i);
		}
	}

	pthread_mutex_destroy(&dev.dev_mutex);

	alarm(0);

out_unreg:
	if (unreg_before_close) {
		res = ioctl(dev.scst_usr_fd, SCST_USER_UNREGISTER_DEVICE, NULL);
		if (res != 0) {
			res = errno;
			PRINT_ERROR("Unable to unregister device: %s",
				strerror(res));
			/* go through */
		}
	}

out_close:
	close(dev.scst_usr_fd);

out_done:
	debug_done();

out:
	return res;

out_usage:
	usage();
	goto out_done;
}
