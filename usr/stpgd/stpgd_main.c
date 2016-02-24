/*
 *  stpgd_main.c
 */

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <malloc.h>
#include <inttypes.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <syslog.h>

#include "version.h"
#include "debug.h"
#include "scst_event.h"

char *app_name;

#define DEFAULT_TRANSITION_TIME 17

#if defined(DEBUG) || defined(TRACING)

#ifdef DEBUG

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

bool log_daemon = true;
unsigned long trace_flag = DEFAULT_LOG_FLAGS;
#endif /* defined(DEBUG) || defined(TRACING) */

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

int transition_timeout = DEFAULT_TRANSITION_TIME;

static struct option const long_options[] = {
	{"path", required_argument, 0, 'p'},
	{"timeout", required_argument, 0, 't'},
	{"foreground", no_argument, 0, 'f'},
#if defined(DEBUG) || defined(TRACING)
	{"debug", required_argument, 0, 'd'},
#endif
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

int stpg_init_report_pipe[2];
char *stpg_path;

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try '%s --help' for more information.\n", app_name);
	else {
		printf("Usage: %s [OPTIONS]\n", app_name);
		printf("STPG target daemon\n");
		printf("  -f, --foreground	make the program run in the foreground\n");
		printf("  -p, --path		absolute path to the STPG script\n");
		printf("  -t, --timeout		transition timeout\n");
#if defined(DEBUG) || defined(TRACING)
		printf("  -d, --debug=level     debug tracing level\n");
#endif
		printf("  -h, --help		display this help and exit\n");
	}
}

static void stpg_handle_tm_received(struct scst_event_user *event_user)
{
	/*
	 * Put code to abort state transition here, if this STPG cmd,
	 * identified by cmd_to_abort_tag or RESET, requested to be aborted
	 */
}

int invoke_stpg(const uint8_t *device_name,
	const struct scst_event_stpg_descr *descr, pid_t *out_pid)
{
	char *args[7], *env[7];
	int res = 0, ret, i;
	pid_t c_pid;

	args[0] = stpg_path;
	args[1] = (char *)device_name;
	args[2] = (char *)descr->prev_state;
	args[3] = (char *)descr->new_state;
	args[4] = (char *)descr->dg_name;
	args[5] = (char *)descr->tg_name;
	args[6] = NULL;

	env[0] = "PATH=/bin:/usr/bin:/sbin:/usr/sbin";
	ret = asprintf(&env[1], "SCST_DEVICE_NAME=%s", device_name);
	if (ret < 0) {
		res = -errno;
		PRINT_ERROR("asprintf() failed: %d (%s)", res, strerror(-res));
		goto out;
	}
	ret = asprintf(&env[2], "SCST_PREV_ALUA_STATE=%s", descr->prev_state);
	if (ret < 0) {
		res = -errno;
		PRINT_ERROR("asprintf() failed: %d (%s)", res, strerror(-res));
		goto out;
	}
	ret = asprintf(&env[3], "SCST_ALUA_STATE=%s", descr->new_state);
	if (ret < 0) {
		res = -errno;
		PRINT_ERROR("asprintf() failed: %d (%s)", res, strerror(-res));
		goto out;
	}
	ret = asprintf(&env[4], "SCST_DEVICE_GROUP=%s", descr->dg_name);
	if (ret < 0) {
		res = -errno;
		PRINT_ERROR("asprintf() failed: %d (%s)", res, strerror(-res));
		goto out;
	}
	ret = asprintf(&env[5], "SCST_TARGET_GROUP=%s", descr->tg_name);
	if (ret < 0) {
		res = -errno;
		PRINT_ERROR("asprintf() failed: %d (%s)", res, strerror(-res));
		goto out;
	}
	env[6] = NULL;

	PRINT_INFO("Invoking script %s with parameters: %s %s %s %s %s and environment: "
		"%s %s %s %s %s", stpg_path, args[1], args[2], args[3],
		args[4], args[5], env[1], env[2], env[3], env[4], env[5]);

	c_pid = fork();
	if (c_pid == 0) {
		ret = setpgid(getpid(), getpid());
		if (ret < 0) {
			res = -errno;
			PRINT_ERROR("setgid failed %d (%s)", ret, strerror(-ret));
		}
		TRACE_DBG("pgid %d (pid %d)", getpgid(getpid()), getpid());
		ret = execve(stpg_path, args, env);
		if (ret < 0) {
			res = -errno;
			PRINT_ERROR("EXEC failed %d (%s)", ret, strerror(-ret));
		}
		exit(0);
	} else if (c_pid < 0) {
		res = -errno;
		PRINT_ERROR("fork() failed: %d (%s)", res, strerror(-res));
	}

	*out_pid = c_pid;

	for (i = 1; i < (signed)ARRAY_SIZE(env); i++)
		free(env[i]);

out:
	return res;
}

/* Returns 0, if the pid is still running, >0 if it was exited or <0 error code */
int wait_until_finished(pid_t pid, unsigned long deadline, int *status, int child)
{
	int res;
	time_t start, end;
	double elapsed;

	TRACE_ENTRY();

	time(&start);
	do {
		res = waitpid(pid, status, WNOHANG);
		if (res != 0) {
			if (res < 0) {
				res = -errno;
				PRINT_ERROR("Waitpid for pid %d (child %d) "
					"failed: %d (%s)", pid, child,
					errno, strerror(errno));
			}
			break;
		}
		sleep(0.1);
		time(&end);
		elapsed = difftime(end, start);
	} while (elapsed < deadline);

	TRACE_EXIT_RES(res);
	return res;
}

int handle_stpg_received(struct scst_event_user *event_user)
{
	const struct scst_event_stpg_payload *p = (struct scst_event_stpg_payload *)event_user->out_event.payload;
	int num, k;
	int res = 0;
	pid_t pids[p->stpg_descriptors_cnt];

	TRACE_DBG("device name %s, stpg_descriptors_cnt %d", p->device_name,
		p->stpg_descriptors_cnt);

	for (num = 0; num < p->stpg_descriptors_cnt; num++) {
		res = invoke_stpg(p->device_name, &p->stpg_descriptors[num], &pids[num]);
		TRACE_DBG("num %d, res %d, pid %d", num, res, pids[num]);
		if (res != 0)
			break;
	}

	TRACE_DBG("num %d", num);
	for (k = 0; k < num; k++) {
		int status = 0, rc;

		TRACE_DBG("k %d, pid %d", k, pids[k]);

		rc = wait_until_finished(pids[k], transition_timeout, &status, k);
		TRACE_DBG("rc %d, status %d", rc, WEXITSTATUS(status));
		if (rc > 0) {
			if (res == 0)
				res = WEXITSTATUS(status);
			continue;
		} else if (rc < 0) {
			if (res == 0)
				res = rc;
			continue;
		}

		PRINT_WARNING("on_stpg %d (pid %d) did not finish on time - "
			"sending SIGTERM", k, pids[k]);
		if (res == 0)
			res = -ETIMEDOUT;
		rc = killpg(pids[k], SIGTERM);
		if (rc < 0)
			PRINT_ERROR("Failed to send SIGTERM to child %d (pid %d): %d/%s",
				k, pids[k], errno, strerror(errno));

		rc = wait_until_finished(pids[k], 1, &status, k);
		if (rc != 0)
			continue;

		while (1) {
			PRINT_WARNING("on_stpg %d (pid %d) did not finish on time - "
					"sending SIGKILL", k, pids[k]);
			rc = killpg(pids[k], SIGKILL);
			if (rc < 0) {
				PRINT_ERROR("Failed to send SIGKILL to child %d "
					"(pid %d): %d/%s", k, pids[k], errno,
					strerror(errno));
				break;
			}
			rc = wait_until_finished(pids[k], 1, &status, k);
			if (rc != 0)
				break;
		};
	}

	TRACE_EXIT_RES(res);
	return res;
}

static int stpg_event_loop(void)
{
	int res = 0, status;
	int event_fd;
	uint8_t event_user_buf[1024*1024];
	pid_t c_pid = 0;
	struct pollfd pl;
	struct scst_event_user *event_user =
		(struct scst_event_user *)event_user_buf;
	struct scst_event e1;
	bool first_error = true;

	event_fd = open(SCST_EVENT_DEV, O_RDWR);
	if (event_fd < 0) {
		res = -errno;
		PRINT_ERROR("Unable to open SCST event device %s (%s)",
			SCST_EVENT_DEV, strerror(-res));
		goto out;
	}

	close(stpg_init_report_pipe[0]);

	if (log_daemon)
		res = write(stpg_init_report_pipe[1], &res, sizeof(res));

	close(stpg_init_report_pipe[1]);

	memset(&pl, 0, sizeof(pl));
	pl.fd = event_fd;
	pl.events = POLLIN;

	memset(&e1, 0, sizeof(e1));
	e1.event_code = SCST_EVENT_STPG_USER_INVOKE;
	strncpy(e1.issuer_name, SCST_EVENT_SCST_CORE_ISSUER,
		sizeof(e1.issuer_name));
	e1.issuer_name[sizeof(e1.issuer_name)-1] = '\0';
	PRINT_INFO("Setting allowed event code %d, issuer_name %s",
		   e1.event_code, e1.issuer_name);

	res = ioctl(event_fd, SCST_EVENT_ALLOW_EVENT, &e1);
	if (res != 0) {
		res = -errno;
		PRINT_ERROR("SCST_EVENT_ALLOW_EVENT failed: %d (%s)",
			    res, strerror(-res));
		goto out;
	}

	e1.event_code = SCST_EVENT_TM_FN_RECEIVED;
	strncpy(e1.issuer_name, SCST_EVENT_SCST_CORE_ISSUER,
		sizeof(e1.issuer_name));
	e1.issuer_name[sizeof(e1.issuer_name)-1] = '\0';
	PRINT_INFO("Setting allowed event code %d, issuer_name %s",
		   e1.event_code, e1.issuer_name);
	res = ioctl(event_fd, SCST_EVENT_ALLOW_EVENT, &e1);
	if (res != 0) {
		res = -errno;
		PRINT_ERROR("SCST_EVENT_ALLOW_EVENT failed: %d (%s)",
			    res, strerror(-res));
		goto out;
	}

	while (1) {
		memset(event_user_buf, 0, sizeof(event_user_buf));
		event_user->max_event_size = sizeof(event_user_buf);
		res = ioctl(event_fd, SCST_EVENT_GET_NEXT_EVENT, event_user);
		if (res != 0) {
			res = -errno;
			switch (-res) {
			case ESRCH:
			case EBUSY:
				TRACE_MGMT_DBG("SCST_EVENT_GET_NEXT_EVENT "
					"returned %d (%s)", res, strerror(res));
				/* go through */
			case EINTR:
				continue;
			case EAGAIN:
				TRACE_DBG("SCST_EVENT_GET_NEXT_EVENT, "
					"returned EAGAIN (%d)", -res);
				continue;
			default:
				PRINT_ERROR("SCST_EVENT_GET_NEXT_EVENT "
					"failed: %d (%s)", res, strerror(-res));
				if (!first_error)
					goto out;
				first_error = false;
				continue;
			}
			first_error = true;
again_poll:
			res = poll(&pl, 1, c_pid > 0 ? 1 : 0);
			if (res > 0)
				continue;
			else if (res == 0)
				goto again_poll;
			else {
				res = -errno;
				switch (res) {
				case ESRCH:
				case EBUSY:
				case EAGAIN:
					TRACE_MGMT_DBG("poll() returned %d "
						"(%s)", res, strerror(-res));
				case EINTR:
					goto again_poll;
				default:
					PRINT_ERROR("poll() failed: %d (%s)",
						res, strerror(-res));
					goto again_poll;
				}
			}
		}
		first_error = true;
#ifdef DEBUG
		PRINT_INFO("event_code %d, issuer_name %s",
			event_user->out_event.event_code,
			event_user->out_event.issuer_name);
#endif
		if (event_user->out_event.payload_len != 0)
			TRACE_BUFFER("payload", event_user->out_event.payload,
				event_user->out_event.payload_len);

		if (event_user->out_event.event_code == SCST_EVENT_STPG_USER_INVOKE) {
			c_pid = fork();
			if (c_pid == -1)
				PRINT_ERROR("Failed to fork: %d", c_pid);
			else if (c_pid == 0) {
				struct scst_event_notify_done d;

				signal(SIGCHLD, SIG_DFL);

				status = handle_stpg_received(event_user);

				memset(&d, 0, sizeof(d));
				d.event_id = event_user->out_event.event_id;
				d.status = status;
				res = ioctl(event_fd, SCST_EVENT_NOTIFY_DONE, &d);
				if (res != 0) {
					res = -errno;
					PRINT_ERROR("SCST_EVENT_NOTIFY_DONE "
						"failed: %s (res %d)",
						strerror(-res), res);
				} else
					PRINT_INFO("STPG event completed with status %d", status);
				exit(res);
			}
		} else if (event_user->out_event.event_code == SCST_EVENT_TM_FN_RECEIVED)
			stpg_handle_tm_received(event_user);
		else
			PRINT_ERROR("Unknown event %d received", event_user->out_event.event_code);
	}
out:
	return res;
}

void sig_chld(int signal)
{
	/* Check just in case */
	if (signal == SIGCHLD) {
		TRACE_DBG("Cleanup zombie (pid %d)", getpid());
		wait(NULL);
	}
}

int main(int argc, char **argv)
{
	int res = 0, ch, longindex;
	pid_t pid;
	struct sigaction sa;

	setlinebuf(stdout);

	openlog(argv[0], LOG_PID, LOG_USER);

	res = pipe(stpg_init_report_pipe);
	if (res == -1) {
		res = -errno;
		PRINT_ERROR("Pipe failed: %d (%s)", res, strerror(-res));
		goto out;
	}

	sa.sa_handler = &sig_chld;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	if (sigaction(SIGCHLD, &sa, 0) == -1) {
		PRINT_ERROR("sigaction() failed: %d/%s", errno, strerror(errno));
		exit(1);
	}

	/*
	 * Otherwise we could die in some later write() during the event_loop()
	 * instead of getting EPIPE!
	 */
	signal(SIGPIPE, SIG_IGN);

	res = debug_init();
	if (res != 0)
		goto out;

	app_name = argv[0];

	while ((ch = getopt_long(argc, argv, "+d:fp:t:hv",
			long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'p':
			stpg_path = optarg;
			break;
#if defined(DEBUG) || defined(TRACING)
		case 'd':
		       trace_flag = strtol(optarg, (char **)NULL, 0);
		       break;
#endif
		case 'v':
			printf("%s version %s\n", app_name, VERSION_STR);
			goto out_done;
		case 'f':
			log_daemon = false;
			break;
		case 't':
			transition_timeout = strtol(optarg, (char **)NULL, 0);
			if (transition_timeout < 0) {
				printf("Invalid timeout %d\n", transition_timeout);
				res = -EINVAL;
				goto out_done;
			}
			break;
		case 'h':
			usage(0);
			goto out_done;
		default:
			goto out_usage;
		}
	}

	if (!stpg_path)
		stpg_path = "/usr/local/bin/scst/scst_on_stpg";

	if (access(stpg_path, X_OK) == -1) {
		PRINT_ERROR("Script file \" %s \"does not exist or not "
			"executable", stpg_path);
		res = -1;
		goto out_done;
	}

#ifdef DEBUG
	PRINT_INFO("trace_flag %lx", trace_flag);
#endif
	if (log_daemon) {
		trace_flag &= ~TRACE_TIME;
		trace_flag &= ~TRACE_PID;

		pid = fork();
		if (pid < 0) {
			PRINT_ERROR("starting daemon failed(%d)", pid);
			res = pid;
			goto out_done;
		} else if (pid) {
			int res1 = -1;

			close(stpg_init_report_pipe[1]);
			if ((unsigned)read(stpg_init_report_pipe[0], &res1, sizeof(res1)) < sizeof(res1)) {
				res = -1;
				goto out_done;
			} else {
				res = res1;
				goto out_done;
			}
		}

		close(0);
		open("/dev/null", O_RDWR);
		dup2(0, 1);
		dup2(0, 2);
		setsid();
	}

	res = stpg_event_loop();

out_done:
	debug_done();

out:
	closelog();
	return res;

out_usage:
	usage(1);
	goto out_done;
}
