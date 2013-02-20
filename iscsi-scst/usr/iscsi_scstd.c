/*
 *  Copyright (C) 2002 - 2003 Ardis Technolgies <roman@ardistech.com>
 *  Copyright (C) 2007 - 2013 Vladislav Bolkhovitin
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
#include <getopt.h>
#include <netdb.h>
#include <signal.h>

#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "iscsid.h"
#include "iscsi_adm.h"

static char* server_address;
uint16_t server_port = ISCSI_LISTEN_PORT;

struct pollfd poll_array[POLL_MAX];

static struct connection *incoming[INCOMING_MAX];
static int incoming_cnt;
int ctrl_fd, ipc_fd, nl_fd;
int conn_blocked;

struct iscsi_init_params iscsi_init_params;

static char program_name[] = "iscsi-scstd";

static struct option const long_options[] =
{
	{"config", required_argument, 0, 'c'},
	{"foreground", no_argument, 0, 'f'},
	{"debug", required_argument, 0, 'd'},
	{"uid", required_argument, 0, 'u'},
	{"gid", required_argument, 0, 'g'},
	{"address", required_argument, 0, 'a'},
	{"port", required_argument, 0, 'p'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

int init_report_pipe[2];

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	else {
		printf("Usage: %s [OPTION]\n", program_name);
		printf("\
iSCSI target daemon.\n\
  -c, --config=[path]     Execute in the config file.\n");
		printf("\
  -f, --foreground        make the program run in the foreground\n\
  -d, --debug debuglevel  print debugging information\n\
  -u, --uid=uid           run as uid, default is current user\n\
  -g, --gid=gid           run as gid, default is current user group\n\
  -a, --address=address   listen on specified local address instead of all\n\
  -p, --port=port         listen on specified port instead of 3260\n\
  -h, --help              display this help and exit\n\
");
	}
	exit(1);
}

const char *get_error_str(int error)
{
	if (error == EAI_SYSTEM)
		return strerror(errno);
	else
		return gai_strerror(error);
}

static void create_listen_socket(struct pollfd *array)
{
	struct addrinfo hints, *res, *res0;
	char servname[64];
	int i, sock, opt, rc;

	memset(servname, 0, sizeof(servname));
	snprintf(servname, sizeof(servname), "%d", server_port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	rc = getaddrinfo(server_address, servname, &hints, &res0);
	if (rc != 0) {
		log_error("Unable to get address info (%s)!",
			get_error_str(rc));
		exit(1);
	}

	i = 0;
	for (res = res0; res && i < LISTEN_MAX; res = res->ai_next) {
		sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sock < 0) {
			log_error("Unable to create server socket (%s) %d %d %d!",
				  strerror(errno), res->ai_family,
				  res->ai_socktype, res->ai_protocol);
			continue;
		}

		sock_set_keepalive(sock, 50);

		opt = 1;
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
			log_warning("Unable to set SO_REUSEADDR on server socket (%s)!",
				    strerror(errno));
		opt = 1;
		if (res->ai_family == AF_INET6 &&
		    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt))) {
			log_error("Unable to restrict IPv6 socket (%s)", strerror(errno));
			close(sock);
			continue;
		}

		if (bind(sock, res->ai_addr, res->ai_addrlen)) {
			log_error("Unable to bind server socket (%s)!", strerror(errno));
			close(sock);
			continue;
		}

		if (listen(sock, INCOMING_MAX)) {
			log_error("Unable to listen to server socket (%s)!", strerror(errno));
			close(sock);
			continue;
		}

		set_non_blocking(sock);

		array[i].fd = sock;
		array[i].events = POLLIN;

		i++;
	}

	freeaddrinfo(res0);

	if (i == 0)
		exit(1);
}

static void accept_connection(int listen)
{
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} from, to;
	socklen_t namesize;
	struct pollfd *pollfd;
	struct connection *conn;
	int fd, i, rc;
	char initiator_addr[ISCSI_PORTAL_LEN], initiator_port[NI_MAXSERV];
	char target_portal[ISCSI_PORTAL_LEN], target_portal_port[NI_MAXSERV];

	namesize = sizeof(from);
	if ((fd = accept(listen, &from.sa, &namesize)) < 0) {
		switch (errno) {
		case EINTR:
		case EAGAIN:
		case ENETDOWN:
		case EPROTO:
		case ENOPROTOOPT:
		case EHOSTDOWN:
		case ENONET:
		case EHOSTUNREACH:
		case EOPNOTSUPP:
		case ENETUNREACH:
			break;
		default:
			log_error("accept(incoming_socket) failed: %s",
				strerror(errno));
			exit(1);
		}
		goto out;
	}

	namesize = sizeof(to);
	rc = getsockname(fd, &to.sa, &namesize);
	if (rc != 0) {
		log_error("getsockname() failed: %s", strerror(errno));
		goto out_close;
	}

	rc = getnameinfo(&to.sa, sizeof(to), target_portal, sizeof(target_portal),
		target_portal_port, sizeof(target_portal_port),
		NI_NUMERICHOST | NI_NUMERICSERV);
	if (rc != 0) {
		log_error("Target portal getnameinfo() failed: %s!",
			get_error_str(rc));
		goto out_close;
	}

	rc = getnameinfo(&from.sa, sizeof(from), initiator_addr,
		 sizeof(initiator_addr), initiator_port,
		 sizeof(initiator_port), NI_NUMERICHOST | NI_NUMERICSERV);
	if (rc != 0) {
		log_error("Initiator getnameinfo() failed: %s!",
			get_error_str(rc));
		goto out_close;
	}

	log_info("Connect from %s:%s to %s:%s", initiator_addr, initiator_port,
		target_portal, target_portal_port);

	if (conn_blocked) {
		log_warning("Connection refused due to blocking\n");
		goto out_close;
	}

	for (i = 0; i < INCOMING_MAX; i++) {
		if (!incoming[i])
			break;
	}
	if (i >= INCOMING_MAX) {
		log_error("Unable to find incoming slot? %d\n", i);
		goto out_close;
	}

	if (!(conn = conn_alloc())) {
		log_error("Fail to allocate %s", "conn\n");
		goto out_close;
	}

	conn->fd = fd;
	conn->target_portal = strdup(target_portal);
	if (conn->target_portal == NULL) {
		log_error("Unable to duplicate target portal %s", target_portal);
		goto out_free;
	}

	incoming[i] = conn;
	conn_read_pdu(conn);

	set_non_blocking(fd);
	pollfd = &poll_array[POLL_INCOMING + i];
	pollfd->fd = fd;
	pollfd->events = POLLIN;
	pollfd->revents = 0;

	incoming_cnt++;

out:
	return;

out_free:
	conn_free(conn);

out_close:
	close(fd);
	goto out;
}

static void __set_fd(int idx, int fd)
{
	poll_array[idx].fd = fd;
	poll_array[idx].events = fd ? POLLIN : 0;
}

void isns_set_fd(int isns, int scn_listen, int scn)
{
	__set_fd(POLL_ISNS, isns);
	__set_fd(POLL_SCN_LISTEN, scn_listen);
	__set_fd(POLL_SCN, scn);
}

static void event_conn(struct connection *conn, struct pollfd *pollfd)
{
	int res, opt;

again:
	switch (conn->iostate) {
	case IOSTATE_READ_BHS:
	case IOSTATE_READ_AHS_DATA:
	      read_again:
		res = read(pollfd->fd, conn->buffer, conn->rwsize);
		if (res <= 0) {
			if (res == 0 || (errno != EINTR && errno != EAGAIN)) {
				conn->state = STATE_DROP;
				goto out;
			} else if (errno == EINTR)
				goto read_again;
			break;
		}
		conn->rwsize -= res;
		conn->buffer += res;
		if (conn->rwsize)
			break;

		switch (conn->iostate) {
		case IOSTATE_READ_BHS:
			conn->iostate = IOSTATE_READ_AHS_DATA;
			conn->req.ahssize = conn->req.bhs.ahslength * 4;
			conn->req.datasize = ((conn->req.bhs.datalength[0] << 16) +
					      (conn->req.bhs.datalength[1] << 8) +
					      conn->req.bhs.datalength[2]);
			conn->rwsize = (conn->req.ahssize + conn->req.datasize + 3) & -4;
			if (conn->rwsize > INCOMING_BUFSIZE) {
				log_warning("Recv PDU with invalid size %d "
					"(max: %d)", conn->rwsize,
					INCOMING_BUFSIZE);
				conn->state = STATE_DROP;
				goto out;
			}
			if (conn->rwsize) {
				if (!conn->req_buffer) {
					conn->req_buffer = malloc(INCOMING_BUFSIZE);
					if (!conn->req_buffer) {
						log_error("Failed to alloc recv buffer");
						conn->state = STATE_DROP;
						goto out;
					}
				}
				conn->buffer = conn->req_buffer;
				conn->req.ahs = conn->buffer;
				conn->req.data = conn->buffer + conn->req.ahssize;
				goto read_again;
			}

		case IOSTATE_READ_AHS_DATA:
			conn_write_pdu(conn);
			pollfd->events = POLLOUT;

			log_pdu(2, &conn->req);
			if (!cmnd_execute(conn))
				conn->state = STATE_EXIT;

			if (conn->state == STATE_EXIT) {
				/* We need to send response */
				goto again;
			}
			break;
		}
		break;

	case IOSTATE_WRITE_BHS:
	case IOSTATE_WRITE_AHS:
	case IOSTATE_WRITE_DATA:
	      write_again:
		opt = 1;
		setsockopt(pollfd->fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
		res = write(pollfd->fd, conn->buffer, conn->rwsize);
		if (res < 0) {
			if (errno != EINTR && errno != EAGAIN) {
				conn->state = STATE_DROP;
				goto out;
			} else if (errno == EINTR)
				goto write_again;
			break;
		}

		conn->rwsize -= res;
		conn->buffer += res;
		if (conn->rwsize)
			goto write_again;

		switch (conn->iostate) {
		case IOSTATE_WRITE_BHS:
			if (conn->rsp.ahssize) {
				conn->iostate = IOSTATE_WRITE_AHS;
				conn->buffer = conn->rsp.ahs;
				conn->rwsize = conn->rsp.ahssize;
				goto write_again;
			}
		case IOSTATE_WRITE_AHS:
			if (conn->rsp.datasize) {
				int o;

				conn->iostate = IOSTATE_WRITE_DATA;
				conn->buffer = conn->rsp.data;
				conn->rwsize = conn->rsp.datasize;
				o = conn->rwsize & 3;
				if (o) {
					for (o = 4 - o; o; o--)
						*((u8 *) conn->buffer + conn->rwsize++) =
						    0;
				}
				goto write_again;
			}
		case IOSTATE_WRITE_DATA:
			opt = 0;
			setsockopt(pollfd->fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
			cmnd_finish(conn);

			switch (conn->state) {
			case STATE_KERNEL:
				conn_pass_to_kern(conn, pollfd->fd);
				if(conn->passed_to_kern)
					conn->state = STATE_CLOSE;
				else
					conn->state = STATE_EXIT;
				break;
			case STATE_EXIT:
			case STATE_CLOSE:
			case STATE_DROP:
				break;
			default:
				conn_read_pdu(conn);
				pollfd->events = POLLIN;
				break;
			}
			break;
		}

		break;
	default:
		log_error("illegal iostate %d for port %d!\n", conn->iostate,
			pollfd->fd);
		exit(1);
	}
out:
	return;
}

static void event_loop(void)
{
	int res, i;

	create_listen_socket(poll_array + POLL_LISTEN);

	poll_array[POLL_IPC].fd = ipc_fd;
	poll_array[POLL_IPC].events = POLLIN;
	poll_array[POLL_NL].fd = nl_fd;
	poll_array[POLL_NL].events = POLLIN;

	for (i = 0; i < INCOMING_MAX; i++) {
		poll_array[POLL_INCOMING + i].fd = -1;
		poll_array[POLL_INCOMING + i].events = 0;
		incoming[i] = NULL;
	}

	close(init_report_pipe[0]);
	res = 0;

	if (log_daemon)
		res = write(init_report_pipe[1], &res, sizeof(res));

	close(init_report_pipe[1]);

	while (1) {
		if (!iscsi_enabled) {
			handle_iscsi_events(nl_fd, true);
			continue;
		}
		res = poll(poll_array, POLL_MAX, isns_timeout);
		if (res == 0) {
			isns_handle(1);
			continue;
		} else if (res < 0) {
			if (errno == EINTR)
				continue;
			else if (errno == EINVAL)
				log_error("%s: poll() failed with EINVAL. Should "
					"you increase RLIMIT_NOFILE (ulimit -n)? "
					"Or upgrade your kernel? Kernels below 2.6.19 "
					"have a bug, which doesn't allow poll() "
					"to work with >256 file descriptors. See "
					"http://sourceforge.net/mailarchive/forum.php?"
					"thread_name=9392A06CB0FDC847B3A530B3DC174E7B0"
					"55F1EF3%40mse10be1.mse10.exchange.ms&forum_"
					"name=scst-devel for more details. Alternatively, "
					"you can decrease iscsi_scstd.c::INCOMING_MAX "
					"constant to a lower value, e.g. 128, then "
					"recompile and reinstall the user space part "
					"of iSCSI-SCST.", __FUNCTION__);
			else
				log_error("%s: poll() failed: %s", __FUNCTION__,
					strerror(errno));
			exit(1);
		}

		for (i = 0; i < LISTEN_MAX; i++) {
			if (poll_array[POLL_LISTEN + i].revents
			    && incoming_cnt < INCOMING_MAX)
				accept_connection(poll_array[POLL_LISTEN + i].fd);
		}

		if (poll_array[POLL_NL].revents)
			handle_iscsi_events(nl_fd, false);

		if (poll_array[POLL_IPC].revents)
			iscsi_adm_request_handle(ipc_fd);

		if (poll_array[POLL_ISNS].revents)
			isns_handle(0);

		if (poll_array[POLL_SCN_LISTEN].revents)
			isns_scn_handle(1);

		if (poll_array[POLL_SCN].revents)
			isns_scn_handle(0);

		for (i = 0; i < INCOMING_MAX; i++) {
			struct connection *conn = incoming[i];
			struct pollfd *pollfd = &poll_array[POLL_INCOMING + i];

			if (!conn || !pollfd->revents)
				continue;

			pollfd->revents = 0;

			event_conn(conn, pollfd);

			if ((conn->state == STATE_CLOSE) ||
			    (conn->state == STATE_EXIT) ||
			    (conn->state == STATE_DROP)) {
				struct session *sess = conn->sess;
				log_debug(1, "closing conn %p", conn);
				conn_free_pdu(conn);
				close(pollfd->fd);
				pollfd->fd = -1;
				incoming[i] = NULL;
				incoming_cnt--;
				if (conn->state != STATE_CLOSE) {
					if (conn->passed_to_kern) {
						kernel_conn_destroy(conn->tid,
							conn->sess->sid.id64,
							conn->cid);
					} else {
						/*
						 * Check if session could not be established,
						 * but sessions count was already incremented
						 */
						if (!sess && conn->sessions_count_incremented)
							conn->target->sessions_count--;
						conn_free(conn);
						log_debug(1, "conn %p freed (sess %p, empty %d)",
							conn, sess,
							sess ? list_empty(&sess->conn_list) : -1);
						if (sess && list_empty(&sess->conn_list))
							session_free(sess);
					}
				}
			}
		}
	}
}

static void init_max_params(void)
{
	if ((session_keys[key_max_recv_data_length].local_def != -1) ||
	    (session_keys[key_max_recv_data_length].max != -1) ||
	    (session_keys[key_max_xmit_data_length].local_def != -1) ||
	    (session_keys[key_max_xmit_data_length].max != -1) ||
	    (session_keys[key_max_burst_length].local_def != -1) ||
	    (session_keys[key_max_burst_length].max != -1) ||
	    (session_keys[key_first_burst_length].max != -1)) {
		log_error("Wrong session_keys initialization");
		exit(-1);
	}

	/* QueuedCommands */
	target_keys[key_queued_cmnds].local_def = min((int)target_keys[key_queued_cmnds].local_def,
						      iscsi_init_params.max_queued_cmds);
	target_keys[key_queued_cmnds].max = min((int)target_keys[key_queued_cmnds].max,
						iscsi_init_params.max_queued_cmds);
	target_keys[key_queued_cmnds].min = min((int)target_keys[key_queued_cmnds].min,
						iscsi_init_params.max_queued_cmds);

	/* MaxRecvDataSegmentLength */
	session_keys[key_max_recv_data_length].local_def = iscsi_init_params.max_data_seg_len;
	session_keys[key_max_recv_data_length].max = iscsi_init_params.max_data_seg_len;

	/* MaxXmitDataSegmentLength */
	session_keys[key_max_xmit_data_length].local_def = iscsi_init_params.max_data_seg_len;
	session_keys[key_max_xmit_data_length].max = iscsi_init_params.max_data_seg_len;

	/* MaxBurstLength */
	session_keys[key_max_burst_length].local_def = iscsi_init_params.max_data_seg_len;
	session_keys[key_max_burst_length].max = iscsi_init_params.max_data_seg_len;

	/* FirstBurstLength */
	session_keys[key_first_burst_length].local_def =
		min((int)session_keys[key_first_burst_length].local_def,
		    iscsi_init_params.max_data_seg_len);
	session_keys[key_first_burst_length].max = iscsi_init_params.max_data_seg_len;

	return;
}

int main(int argc, char **argv)
{
	int ch, longindex;
	char *config = NULL;
	uid_t uid = 0;
	gid_t gid = 0;
	int err;

#ifdef CONFIG_SCST_PROC
	iscsi_enabled = 1;
#endif

	if (pipe(init_report_pipe) == -1) {
		perror("pipe failed");
		exit(-1);
	}

	/*
	 * Otherwise we could die in some later write() during the event_loop()
	 * instead of getting EPIPE!
	 */
	signal(SIGPIPE, SIG_IGN);

	while ((ch = getopt_long(argc, argv, "c:fd:s:u:g:a:p:vh", long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'c':
			config = optarg;
			break;
		case 'f':
			log_daemon = 0;
			break;
		case 'd':
			log_level = strtol(optarg, NULL, 0);
			break;
		case 'u':
			uid = strtoul(optarg, NULL, 0);
			break;
		case 'g':
			gid = strtoul(optarg, NULL, 0);
			break;
		case 'a':
			server_address = strdup(optarg);
			if (server_address == NULL) {
				perror("strdup failed");
				exit(-1);
			}
			break;
		case 'p':
			server_port = (uint16_t)strtoul(optarg, NULL, 0);
			break;
		case 'v':
			printf("%s version %s\n", program_name, ISCSI_VERSION_STRING);
			exit(0);
			break;
		case 'h':
			usage(0);
			break;
		default:
			usage(1);
			break;
		}
	}

	if ((ctrl_fd = kernel_open()) < 0)
		exit(-1);

	init_max_params();

	if ((nl_fd = nl_open()) < 0) {
		perror("netlink open failed");
		exit(-1);
	};

#ifndef CONFIG_SCST_PROC
	err = kernel_attr_add(NULL, ISCSI_ISNS_SERVER_ATTR_NAME,
			S_IRUSR|S_IRGRP|S_IROTH|S_IWUSR, 0);
	if (err != 0)
		exit(err);

	err = kernel_attr_add(NULL, ISCSI_ENABLED_ATTR_NAME,
			S_IRUSR|S_IRGRP|S_IROTH|S_IWUSR, 0);
	if (err != 0)
		exit(err);
	err = kernel_attr_add(NULL, ISCSI_ISNS_ENTITY_ATTR_NAME,
			S_IRUSR|S_IRGRP|S_IROTH|S_IWUSR, 0);
	if (err != 0)
		exit(err);
#endif

	if ((ipc_fd = iscsi_adm_request_listen()) < 0) {
		perror("Opening AF_LOCAL socket failed");
		exit(-1);
	}

	log_init();
	if (log_daemon) {
		char buf[64];
		pid_t pid;
		int fd;

		fd = open("/var/run/iscsi-scstd.pid", O_WRONLY|O_CREAT, 0644);
		if (fd < 0) {
			log_error("unable to create pid file");
			exit(1);
		}
		pid = fork();
		if (pid < 0) {
			log_error("starting daemon failed");
			exit(1);
		} else if (pid) {
			int res = -1;
			close(init_report_pipe[1]);
			if (read(init_report_pipe[0], &res, sizeof(res)) < sizeof(res))
				exit(-1);
			else
				exit(res);
		}

		if (chdir("/") < 0) {
			log_error("failed to set working dir to /: %m");
			exit(1);
		}

		if (lockf(fd, F_TLOCK, 0) < 0) {
			log_error("unable to lock pid file");
			exit(1);
		}
		if (ftruncate(fd, 0) < 0) {
			log_error("failed to ftruncate the PID file: %m");
			exit(1);
		}

		sprintf(buf, "%d\n", getpid());
		if (write(fd, buf, strlen(buf)) < strlen(buf)) {
			log_error("failed to write PID to PID file: %m");
			exit(1);
		}

		close(0);
		open("/dev/null", O_RDWR);
		dup2(0, 1);
		dup2(0, 2);
		setsid();
	}

	err = config_load(config);
	if (err != 0)
		exit(1);

	if (gid && setgid(gid) < 0)
		log_error("setgid failed: %s", strerror(errno));

	if (uid && setuid(uid) < 0)
		log_error("setuid failed: %s", strerror(errno));

	event_loop();

	return 0;
}
