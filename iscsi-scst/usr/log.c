/*
 *  Copyright (C) 2002 - 2003 Ardis Technolgies <roman@ardistech.com>
 *  Copyright (C) 2007 - 2008 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2008 CMS Distribution Limited
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

static void dolog(int prio, const char *fmt, va_list ap)
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

void log_info(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	dolog(LOG_INFO, fmt, ap);
	va_end(ap);
}

void log_warning(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	dolog(LOG_WARNING, fmt, ap);
	va_end(ap);
}

void log_error(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	dolog(LOG_ERR, fmt, ap);
	va_end(ap);
}

void log_debug(int level, const char *fmt, ...)
{
	if (log_level > level) {
		va_list ap;
		va_start(ap, fmt);
		dolog(LOG_DEBUG, fmt, ap);
		va_end(ap);
	}
}

/* Definition for log_pdu buffer */
#define BUFFER_SIZE 16

/*
 * size required for a hex dump of BUFFER_SIZE bytes (' ' + 2 chars = 3 chars
 * per byte) with a ' |' separator each 4th byte:
 */
#define LINE_SIZE (BUFFER_SIZE * 3 + BUFFER_SIZE / 4 * 2 + 1)

static void __dump_line(int level, unsigned char *buf, int *cp)
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
	log_debug(level, "%s %.*s |", line, BUFFER_SIZE, buf);
	*cp = 0;
}

static void __dump_char(int level, unsigned char *buf, int *cp, int ch)
{
	int cnt = (*cp)++;

	buf[cnt] = ch;
	if (cnt == BUFFER_SIZE - 1)
		__dump_line(level, buf, cp);
}

#define dump_line() __dump_line(level, char_buf, &char_cnt)
#define dump_char(ch) __dump_char(level, char_buf, &char_cnt, ch)

void log_pdu(int level, struct PDU *pdu)
{
	unsigned char char_buf[BUFFER_SIZE];
	int char_cnt = 0;
	unsigned char *buf;
	int i;

	if (log_level < level)
		return;

	buf = (void *)&pdu->bhs;
	log_debug(level, "BHS: (%p)", buf);
	for (i = 0; i < BHS_SIZE; i++)
		dump_char(*buf++);
	dump_line();

	buf = (void *)pdu->ahs;
	log_debug(level, "AHS: (%p)", buf);
	for (i = 0; i < pdu->ahssize; i++)
		dump_char(*buf++);
	dump_line();

	buf = (void *)pdu->data;
	log_debug(level, "Data: (%p)", buf);
	for (i = 0; i < pdu->datasize; i++)
		dump_char(*buf++);
	dump_line();
}
