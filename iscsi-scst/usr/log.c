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
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/time.h>
#include <string.h>

#include "iscsid.h"

int log_daemon = 1;
int log_level = 0;

void log_init(void)
{
	if (log_daemon)
		openlog("iscsi-scstd", 0, LOG_DAEMON);
}

static void dolog_nofunc(int prio, const char *fmt, va_list ap)
{
	if (log_daemon) {
		int len = strlen(fmt);
		char f[len+1+1];
		if (fmt[len] != '\n')
			sprintf(f, "%s\n", fmt);
		else
			sprintf(f, "%s", fmt);
		vsyslog(prio, f, ap);
	} else {
		struct timeval time;

		gettimeofday(&time, NULL);
		fprintf(stderr, "%ld.%06ld: ", time.tv_sec, time.tv_usec);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		fflush(stderr);
	}
}

static void dolog(int prio, const char *func, int line, const char *fmt, va_list ap)
{
	if (log_level == 0) {
		dolog_nofunc(prio, fmt, ap);
		return;
	}

	if (log_daemon) {
		int len = strlen(func) + strlen(fmt);
		char f[len+1+1];
		if (fmt[len] != '\n')
			sprintf(f, "%s:%d: %s %s\n", func, line,
				(prio == LOG_ERR) ? "ERROR:" : "", fmt);
		else
			sprintf(f, "%s:%d: %s %s", func, line,
				(prio == LOG_ERR) ? "ERROR: " : "", fmt);
		vsyslog(prio, f, ap);
	} else {
		struct timeval time;

		gettimeofday(&time, NULL);
		fprintf(stderr, "%ld.%06ld: %s:%d: ", time.tv_sec, time.tv_usec, func, line);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		fflush(stderr);
	}
}

void __log(const char *func, int line, int prio, int level, const char *fmt, ...)
{
	if (level) {
		prio = LOG_DEBUG;
		if (log_level < level)
			return;
	}

	va_list ap;
	va_start(ap, fmt);
	dolog(prio, func, line, fmt, ap);
	va_end(ap);
}

/* Definition for __log_pdu buffer */
#define BUFFER_SIZE 16

/*
 * size required for a hex dump of BUFFER_SIZE bytes (' ' + 2 chars = 3 chars
 * per byte) with a ' |' separator each 4th byte:
 */
#define LINE_SIZE (BUFFER_SIZE * 3 + BUFFER_SIZE / 4 * 2 + 1)

static void __dump_line(const char *func, int line_num, int level, unsigned char *buf, int *cp)
{
	char line[LINE_SIZE], *lp = line;
	int i, cnt;

	cnt = *cp;
	if (!cnt)
		return;
	for (i = 0; i < BUFFER_SIZE; i++) {
		if (i < cnt)
			lp += sprintf(lp, " %02x", buf[i]);
		else
			lp += sprintf(lp, "   ");
		if ((i % 4) == 3)
			lp += sprintf(lp, " |");
		if (i >= cnt || !isprint(buf[i]))
			buf[i] =  ' ';
	}

	/* buf is not \0-terminated! */
	__log(func, line_num, LOG_DEBUG, level, "%s %.*s |", line, BUFFER_SIZE, buf);
	*cp = 0;
}

static void __dump_char(const char *func, int line, int level, unsigned char *buf, int *cp, int ch)
{
	int cnt = (*cp)++;

	buf[cnt] = ch;
	if (cnt == BUFFER_SIZE - 1)
		__dump_line(func, line, level, buf, cp);
}

#define dump_line() __dump_line(func, line, level, char_buf, &char_cnt)
#define dump_char(ch) __dump_char(func, line, level, char_buf, &char_cnt, ch)

void __log_pdu(const char *func, int line, int level, struct PDU *pdu)
{
	unsigned char char_buf[BUFFER_SIZE];
	int char_cnt = 0;
	unsigned char *buf;
	int i;

	if (log_level < level)
		return;

	buf = (void *)&pdu->bhs;
	__log(func, line, LOG_DEBUG, level, "BHS: (%p)", buf);
	for (i = 0; i < BHS_SIZE; i++)
		dump_char(*buf++);
	dump_line();

	buf = (void *)pdu->ahs;
	__log(func, line, LOG_DEBUG, level, "AHS: (%p)", buf);
	for (i = 0; i < pdu->ahssize; i++)
		dump_char(*buf++);
	dump_line();

	buf = (void *)pdu->data;
	__log(func, line, LOG_DEBUG, level, "Data: (%p)", buf);
	for (i = 0; i < pdu->datasize; i++)
		dump_char(*buf++);
	dump_line();
}
