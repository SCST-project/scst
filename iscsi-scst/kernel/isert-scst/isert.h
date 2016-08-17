/*
* This file is part of iser target kernel module.
*
* Copyright (c) 2013 - 2014 Mellanox Technologies. All rights reserved.
* Copyright (c) 2013 - 2014 Yan Burman (yanb@mellanox.com)
*
* This software is available to you under a choice of one of two
* licenses.  You may choose to be licensed under the terms of the GNU
* General Public License (GPL) Version 2, available from the file
* COPYING in the main directory of this source tree, or the
* OpenIB.org BSD license below:
*
*     Redistribution and use in source and binary forms, with or
*     without modification, are permitted provided that the following
*     conditions are met:
*
*            - Redistributions of source code must retain the above
*              copyright notice, this list of conditions and the following
*              disclaimer.
*
*            - Redistributions in binary form must reproduce the above
*              copyright notice, this list of conditions and the following
*              disclaimer in the documentation and/or other materials
*              provided with the distribution.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
* BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
* ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
* CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

#ifndef __ISERT_H__
#define __ISERT_H__

#include <linux/list.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/types.h>	/* size_t, dev_t */
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/init.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)
#include <asm/atomic.h>
#else
#include <linux/atomic.h>
#endif

#ifdef INSIDE_KERNEL_TREE
#include <scst/isert_scst.h>
#include <scst/iscsi_scst.h>
#else
#include "isert_scst.h"
#include "iscsi_scst.h"
#endif
#include "../iscsi.h"

#include "iser_hdr.h"

struct iscsi_conn;

#define ISERT_NR_DEVS 128

struct isert_listener_dev {
	struct device *dev;
	struct cdev cdev;
	dev_t devno;
	wait_queue_head_t waitqueue;
	struct mutex conn_lock;
	struct list_head new_conn_list;
	struct list_head curr_conn_list;
	struct isert_addr_info info;
	atomic_t available;
	void *portal_h[ISERT_MAX_PORTALS];
	int free_portal_idx;
};

enum isert_conn_dev_state {
	CS_INIT,
	CS_REQ_BHS,
	CS_REQ_DATA,
	CS_REQ_FINISHED,
	CS_RSP_BHS,
	CS_RSP_DATA,
	CS_RSP_FINISHED,
	CS_DISCONNECTED,
};

#define ISERT_CONN_PASSED	0

struct isert_conn_dev {
	struct device *dev;
	struct cdev cdev;
	dev_t devno;
	wait_queue_head_t waitqueue;
	struct list_head conn_list_entry;
	struct iscsi_conn *conn;
	unsigned int idx;
	int occupied;
	spinlock_t pdu_lock;
	struct iscsi_cmnd *login_req;
	struct iscsi_cmnd *login_rsp;
	atomic_t available;
	size_t read_len;
	char *read_buf;
	size_t write_len;
	char *write_buf;
	void *sg_virt;
	struct page *pages[DIV_ROUND_UP(ISER_MAX_LOGIN_RDSL, PAGE_SIZE)];
	enum isert_conn_dev_state state;
	int is_discovery;
	struct timer_list tmo_timer;
	int timer_active;
	struct kref kref;
	unsigned long flags;
};

#define ISER_CONN_DEV_PREFIX "isert/conn"

/* isert_login.c */
int __init isert_init_login_devs(unsigned int ndevs);
void isert_cleanup_login_devs(void);
int isert_conn_alloc(struct iscsi_session *session,
		     struct iscsi_kern_conn_info *info,
		     struct iscsi_conn **new_conn,
		     struct iscsit_transport *t);
void isert_handle_close_connection(struct iscsi_conn *conn);
void isert_close_all_portals(void);
void isert_del_timer(struct isert_conn_dev *dev);

#endif /* __ISERT_H__ */
