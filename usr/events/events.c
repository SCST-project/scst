/*
 *  events.c
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
#include <stdbool.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/poll.h>
#include <sys/ioctl.h>

#include <pthread.h>

#include "version.h"
#include "debug.h"
#include "scst_event.h"

char *app_name;

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

bool log_daemon = false; /* needed for the tracing infrastructure */
unsigned long trace_flag = DEFAULT_LOG_FLAGS;
#endif /* defined(DEBUG) || defined(TRACING) */

static struct option const long_options[] = {
	{"allowed_event", required_argument, 0, 'e'},
	{"allowed_issuer", required_argument, 0, 'i'},
	{"non_blocking", no_argument, 0, 'n'},
#if defined(DEBUG) || defined(TRACING)
	{"debug", required_argument, 0, 'd'},
#endif
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

#define MAX_ALLOWED_EVENTS	16
static struct scst_event allowed_events[MAX_ALLOWED_EVENTS];
static int allowed_events_num;
static int non_blocking;

static void usage(void)
{
	printf("Usage: %s [OPTIONS]\n", app_name);
	printf("\nSCST events testing program\n");
	printf("  -e, --allowed_event=code Allowed event code, 0 - any event\n");
	printf("  -i, --allowed_issuer=issuer Allowed issuer, * - any issuer\n");
	printf("  -n, --non_blocking	Use non-blocking operations\n");
#if defined(DEBUG) || defined(TRACING)
	printf("  -d, --debug=level	Debug tracing level\n");
#endif
}

static void handle_tm_received(struct scst_event_user *event_user)
{
	struct scst_event_tm_fn_received_payload *p = (struct scst_event_tm_fn_received_payload *)event_user->out_event.payload;

	printf("fn %d, device %s\n", p->fn, p->device_name);

	return;
}

int main(int argc, char **argv)
{
	int res = 0, i;
	int ch, longindex;
	int event_fd;
	uint8_t event_user_buf[10240];
	struct scst_event_user *event_user = (struct scst_event_user *)event_user_buf;
	struct pollfd pl;

	setlinebuf(stdout);

	res = debug_init();
	if (res != 0)
		goto out;

	app_name = argv[0];

	while ((ch = getopt_long(argc, argv, "+e:i:d:nhv",
			long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'e':
			if (allowed_events[allowed_events_num].event_code != 0) {
				allowed_events_num++;
				if (allowed_events_num >= MAX_ALLOWED_EVENTS) {
					PRINT_ERROR("Too many allowed events %d",
						allowed_events_num);
					exit(1);
				}
			}
			allowed_events[allowed_events_num].event_code = atoi(optarg);
			break;
		case 'i':
			if (allowed_events[allowed_events_num].issuer_name[0] != '\0') {
				allowed_events_num++;
				if (allowed_events_num >= MAX_ALLOWED_EVENTS) {
					PRINT_ERROR("Too many allowed events %d",
						allowed_events_num);
					exit(1);
				}
			}
			strncpy(allowed_events[allowed_events_num].issuer_name,
				optarg, sizeof(allowed_events[allowed_events_num].issuer_name));
			allowed_events[allowed_events_num].issuer_name[
				sizeof(allowed_events[allowed_events_num].issuer_name)-1] = '\0';
			break;
		case 'n':
			non_blocking = 1;
			break;
#if defined(DEBUG) || defined(TRACING)
		case 'd':
			trace_flag = strtol(optarg, (char **)NULL, 0);
			break;
#endif
		case 'v':
			printf("%s version %s\n", app_name, VERSION_STR);
			goto out_done;
		default:
			goto out_usage;
		}
	}

	if (allowed_events_num == 0) {
		if ((allowed_events[0].event_code == 0) &&
		    (allowed_events[0].issuer_name[0] == '\0'))
			allowed_events[0].issuer_name[0] = '*';
	}

	allowed_events_num++;

#ifdef DEBUG
	PRINT_INFO("trace_flag %lx", trace_flag);
#endif

	if (non_blocking)
		PRINT_INFO("%s", "NON-BLOCKING");

	event_fd = open(SCST_EVENT_DEV, O_RDWR | (non_blocking ? O_NONBLOCK : 0));
	if (event_fd < 0) {
		res = -errno;
		PRINT_ERROR("Unable to open SCST event device %s (%s)",
			SCST_EVENT_DEV, strerror(-res));
		goto out_done;
	}

	memset(&pl, 0, sizeof(pl));
	pl.fd = event_fd;
	pl.events = POLLIN;

	for (i = 0; i < allowed_events_num; i++) {
		struct scst_event e;

		PRINT_INFO("Setting allowed event code %d, issuer_name %s",
			allowed_events[i].event_code,
			allowed_events[i].issuer_name);
		memset(&e, 0, sizeof(e));
		e.event_code = allowed_events[i].event_code;
		strncpy(e.issuer_name, allowed_events[i].issuer_name,
			sizeof(e.issuer_name));
		e.issuer_name[sizeof(e.issuer_name)-1] = '\0';

		res = ioctl(event_fd, SCST_EVENT_ALLOW_EVENT, &e);
		if (res != 0) {
			PRINT_ERROR("SCST_EVENT_ALLOW_EVENT failed: %s (res %d)",
				strerror(errno), res);
			goto out_done;
		}
	}

	while (1) {
		memset(event_user_buf, 0, sizeof(event_user_buf));
		event_user->max_event_size = sizeof(event_user_buf);
		res = ioctl(event_fd, SCST_EVENT_GET_NEXT_EVENT, event_user);
		if (res != 0) {
			res = errno;
			switch (res) {
			case ESRCH:
			case EBUSY:
				TRACE_MGMT_DBG("SCST_EVENT_GET_NEXT_EVENT returned "
					"%d (%s)", res, strerror(res));
				/* go through */
			case EINTR:
				continue;
			case EAGAIN:
				TRACE_DBG("SCST_EVENT_GET_NEXT_EVENT, returned "
					"EAGAIN (%d)", res);
				if (non_blocking)
					break;
				else
					continue;
			default:
				PRINT_ERROR("SCST_EVENT_GET_NEXT_EVENT failed: %s (res %d)",
					strerror(errno), res);
				goto out_done;
			}
again_poll:
			res = poll(&pl, 1, 2000);
			if (res > 0)
				continue;
			else if (res == 0)
				goto again_poll;
			else {
				res = errno;
				switch (res) {
				case ESRCH:
				case EBUSY:
				case EAGAIN:
					TRACE_MGMT_DBG("poll() returned %d "
						"(%s)", res, strerror(res));
				case EINTR:
					goto again_poll;
				default:
					PRINT_ERROR("poll() failed: %s", strerror(res));
#if 1
					goto again_poll;
#else
					goto out_close;
#endif
				}
			}

		}

		PRINT_INFO("\nevent_code %d, issuer_name %s",
			event_user->out_event.event_code,
			event_user->out_event.issuer_name);
		if (event_user->out_event.payload_len != 0)
			PRINT_BUFFER("payoad", event_user->out_event.payload,
				event_user->out_event.payload_len);
		PRINT_INFO("%s", "");

		if (event_user->out_event.event_code == 0x12345) {
			struct scst_event_notify_done d;

			PRINT_INFO("%s", "Press any key to send reply to event "
				"0x12345");
			getchar();

			memset(&d, 0, sizeof(d));
			d.event_id = event_user->out_event.event_id;
			d.status = -19;
			res = ioctl(event_fd, SCST_EVENT_NOTIFY_DONE, &d);
			if (res != 0)
				PRINT_ERROR("SCST_EVENT_NOTIFY_DONE failed: %s "
					"(res %d)", strerror(errno), res);
		} else if (event_user->out_event.event_code == SCST_EVENT_TM_FN_RECEIVED)
			handle_tm_received(event_user);
		else if (event_user->out_event.event_code == SCST_EVENT_TM_FN_RECEIVED) {
			struct scst_event_notify_done d;

			memset(&d, 0, sizeof(d));
			d.event_id = event_user->out_event.event_id;
			d.status = -20;
			res = ioctl(event_fd, SCST_EVENT_NOTIFY_DONE, &d);
			if (res != 0)
				PRINT_ERROR("SCST_EVENT_NOTIFY_DONE failed: %s "
					"(res %d)", strerror(errno), res);
		}

#if 0
		{
			struct scst_event e;

			PRINT_INFO("Deleting allowed event code %d, issuer_name %s",
				allowed_events[0].event_code,
				allowed_events[0].issuer_name);
			memset(&e, 0, sizeof(e));
			e.event_code = allowed_events[0].event_code;
			strncpy(e.issuer_name, allowed_events[0].issuer_name,
				sizeof(e.issuer_name));
			e.issuer_name[sizeof(e.issuer_name)-1] = '\0';

			res = ioctl(event_fd, SCST_EVENT_DISALLOW_EVENT, &e);
			if (res != 0) {
				PRINT_ERROR("SCST_EVENT_DISALLOW_EVENT failed: "
					"%s (res %d)", strerror(errno), res);
			}
		}
#endif
	}

out_done:
	debug_done();

out:
	return res;

out_usage:
	usage();
	goto out_done;
}
