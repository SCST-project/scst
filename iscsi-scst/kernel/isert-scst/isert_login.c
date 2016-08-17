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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>		/* everything... */
#include <linux/errno.h>	/* error codes */
#include <linux/poll.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
#include <linux/freezer.h>
#else
#define wait_event_freezable(wq, cond) ({ wait_event(wq, cond); 0; })
#endif
#include <linux/file.h>
#include "isert_dbg.h"
#include "../iscsi.h"
#include "isert.h"
#include "iser.h"
#include "iser_datamover.h"

static DEFINE_MUTEX(conn_mgmt_mutex);

static unsigned int n_devs;

static int isert_major;

static struct isert_conn_dev *isert_conn_devices;

static struct isert_listener_dev isert_listen_dev;

static struct class *isert_class;

static struct isert_conn_dev *get_available_dev(struct isert_listener_dev *dev,
						struct iscsi_conn *conn)
{
	unsigned int i;
	struct isert_conn_dev *res = NULL;

	mutex_lock(&dev->conn_lock);
	for (i = 0; i < n_devs; ++i) {
		if (!isert_conn_devices[i].occupied) {
			res = &isert_conn_devices[i];
			res->occupied = 1;
			res->conn = conn;
			isert_set_priv(conn, res);
			list_add_tail(&res->conn_list_entry, &dev->new_conn_list);
			break;
		}
	}
	mutex_unlock(&dev->conn_lock);

	return res;
}

void isert_del_timer(struct isert_conn_dev *dev)
{
	if (dev->timer_active) {
		dev->timer_active = 0;
		del_timer_sync(&dev->tmo_timer);
	}
}

static void isert_kref_release_dev(struct kref *kref)
{
	struct isert_conn_dev *dev = container_of(kref,
						  struct isert_conn_dev,
						  kref);
	kref_init(&dev->kref);
	dev->occupied = 0;
	dev->state = CS_INIT;
	atomic_set(&dev->available, 1);
	list_del_init(&dev->conn_list_entry);
	dev->flags = 0;
	dev->conn = NULL;
}

static void isert_dev_release(struct isert_conn_dev *dev)
{
	sBUG_ON(atomic_read(&dev->kref.refcount) == 0);
	mutex_lock(&isert_listen_dev.conn_lock);
	kref_put(&dev->kref, isert_kref_release_dev);
	mutex_unlock(&isert_listen_dev.conn_lock);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void isert_close_conn_fn(void *ctx)
#else
static void isert_close_conn_fn(struct work_struct *work)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct iscsi_conn *conn = ctx;
#else
	struct iscsi_conn *conn = container_of(work,
		struct iscsi_conn, close_work);
#endif

	isert_close_connection(conn);
}

static void isert_conn_timer_fn(unsigned long arg)
{
	struct isert_conn_dev *conn_dev = (struct isert_conn_dev *)arg;
	struct iscsi_conn *conn = conn_dev->conn;

	TRACE_ENTRY();

	conn_dev->timer_active = 0;

	PRINT_ERROR("Timeout on connection %p", conn_dev->conn);

	schedule_work(&conn->close_work);

	TRACE_EXIT();
}

static int add_new_connection(struct isert_listener_dev *dev,
			      struct iscsi_conn *conn)
{
	struct isert_conn_dev *conn_dev = get_available_dev(dev, conn);
	int res = 0;

	TRACE_ENTRY();

	if (!conn_dev) {
		PRINT_WARNING("Unable to allocate new connection");
		res = -ENOSPC;
		goto out;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	INIT_WORK(&conn->close_work, isert_close_conn_fn, conn);
#else
	INIT_WORK(&conn->close_work, isert_close_conn_fn);
#endif

	init_timer(&conn_dev->tmo_timer);
	conn_dev->tmo_timer.function = isert_conn_timer_fn;
	conn_dev->tmo_timer.expires = jiffies + 60 * HZ;
	conn_dev->tmo_timer.data = (unsigned long)conn_dev;
	add_timer(&conn_dev->tmo_timer);
	conn_dev->timer_active = 1;
	wake_up(&dev->waitqueue);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static bool have_new_connection(struct isert_listener_dev *dev)
{
	bool ret;

	mutex_lock(&dev->conn_lock);
	ret = !list_empty(&dev->new_conn_list);
	mutex_unlock(&dev->conn_lock);

	return ret;
}

int isert_conn_alloc(struct iscsi_session *session,
		     struct iscsi_kern_conn_info *info,
		     struct iscsi_conn **new_conn,
		     struct iscsit_transport *t)
{
	int res = 0;
	struct isert_conn_dev *dev;
	struct iscsi_conn *conn;
	struct iscsi_cmnd *cmnd;
	struct file *filp = fget(info->fd);

	TRACE_ENTRY();

	lockdep_assert_held(&session->target->target_mutex);

	mutex_lock(&conn_mgmt_mutex);

	if (unlikely(!filp)) {
		res = -EBADF;
		goto out;
	}

	dev = filp->private_data;

	if (unlikely(dev->state == CS_DISCONNECTED)) {
		res = -EBADF;
		goto out;
	}

	sBUG_ON(dev->state != CS_RSP_FINISHED);

	cmnd = dev->login_rsp;

	sBUG_ON(cmnd == NULL);
	dev->login_rsp = NULL;

	*new_conn = dev->conn;
	res = isert_set_session_params(dev->conn, &session->sess_params,
				       &session->tgt_params);

	if (!res)
		set_bit(ISERT_CONN_PASSED, &dev->flags);

	fput(filp);

	conn = *new_conn;

	if (unlikely(res))
		goto cleanup_conn;

	conn->transport = t;

	res = iscsi_init_conn(session, info, conn);
	if (unlikely(res))
		goto cleanup_conn;

	conn->rd_state = 1;
	isert_del_timer(dev);
	isert_dev_release(dev);
	isert_set_priv(conn, NULL);

	res = isert_login_rsp_tx(cmnd, true, false);
	vunmap(dev->sg_virt);
	dev->sg_virt = NULL;

	if (unlikely(res))
		goto cleanup_iscsi_conn;

#ifndef CONFIG_SCST_PROC
	res = conn_sysfs_add(conn);
	if (unlikely(res))
		goto cleanup_iscsi_conn;
#endif

	list_add_tail(&conn->conn_list_entry, &session->conn_list);

	goto out;

cleanup_iscsi_conn:
	conn->rd_state = 0;
	if (conn->nop_in_interval > 0)
		cancel_delayed_work_sync(&conn->nop_in_delayed_work);
cleanup_conn:
	conn->session = NULL;
	isert_close_connection(conn);
out:
	mutex_unlock(&conn_mgmt_mutex);
	TRACE_EXIT_RES(res);
	return res;
}

static unsigned int isert_listen_poll(struct file *filp,
				      struct poll_table_struct *wait)
{
	struct isert_listener_dev *dev = filp->private_data;
	unsigned int mask = 0;

	poll_wait(filp, &dev->waitqueue, wait);

	if (have_new_connection(dev))
		mask |= POLLIN | POLLRDNORM;

	return mask;
}

static int isert_listen_open(struct inode *inode, struct file *filp)
{
	struct isert_listener_dev *dev;

	dev = container_of(inode->i_cdev, struct isert_listener_dev, cdev);

	if (!atomic_dec_and_test(&dev->available)) {
		atomic_inc(&dev->available);
		return -EBUSY; /* already open */
	}

	filp->private_data = dev; /* for other methods */

	return 0;
}

static void isert_delete_conn_dev(struct isert_conn_dev *conn_dev)
{
	isert_del_timer(conn_dev);

	if (!test_and_set_bit(ISERT_CONN_PASSED, &conn_dev->flags)) {
		if (conn_dev->conn)
			isert_close_connection(conn_dev->conn);
	}
}

static int isert_listen_release(struct inode *inode, struct file *filp)
{
	struct isert_listener_dev *dev = filp->private_data;
	struct isert_conn_dev *conn_dev;

	mutex_lock(&isert_listen_dev.conn_lock);
	list_for_each_entry(conn_dev, &dev->new_conn_list, conn_list_entry)
		isert_delete_conn_dev(conn_dev);

	list_for_each_entry(conn_dev, &dev->curr_conn_list, conn_list_entry)
		isert_delete_conn_dev(conn_dev);
	mutex_unlock(&isert_listen_dev.conn_lock);

	atomic_inc(&dev->available);
	return 0;
}

static ssize_t isert_listen_read(struct file *filp, char __user *buf,
				 size_t count, loff_t *f_pos)
{
	struct isert_listener_dev *dev = filp->private_data;
	struct isert_conn_dev *conn_dev;
	int res = 0;
	char k_buff[sizeof("/dev/") + sizeof(ISER_CONN_DEV_PREFIX) + 3 + 1];
	size_t to_write;

	TRACE_ENTRY();

	if (!have_new_connection(dev)) {
wait_for_connection:
		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;
		res = wait_event_freezable(dev->waitqueue,
			!have_new_connection(dev));
		if (res < 0)
			goto out;
	}

	mutex_lock(&dev->conn_lock);
	if (list_empty(&dev->new_conn_list)) {
		/* could happen if we got disconnect */
		mutex_unlock(&dev->conn_lock);
		goto wait_for_connection;
	}
	conn_dev = list_first_entry(&dev->new_conn_list, struct isert_conn_dev,
				    conn_list_entry);
	list_move(&conn_dev->conn_list_entry, &dev->curr_conn_list);
	mutex_unlock(&dev->conn_lock);

	to_write = min_t(size_t, sizeof(k_buff), count);
	res = scnprintf(k_buff, to_write, "/dev/"ISER_CONN_DEV_PREFIX"%d",
			conn_dev->idx);
	++res; /* copy trailing \0 as well */

	if (unlikely(copy_to_user(buf, k_buff, res)))
		res = -EFAULT;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static long isert_listen_ioctl(struct file *filp, unsigned int cmd,
			       unsigned long arg)
{
	struct isert_listener_dev *dev = filp->private_data;
	int res = 0, rc;
	void __user *ptr = (void __user *)arg;
	void *portal;

	TRACE_ENTRY();

	switch (cmd) {
	case SET_LISTEN_ADDR:
		rc = copy_from_user(&dev->info, ptr, sizeof(dev->info));
		if (unlikely(rc != 0)) {
			PRINT_ERROR("Failed to copy %d user's bytes", rc);
			res = -EFAULT;
			goto out;
		}

		if (unlikely(dev->free_portal_idx >= ISERT_MAX_PORTALS)) {
			PRINT_ERROR("Maximum number of portals exceeded: %d",
				    ISERT_MAX_PORTALS);
			res = -EINVAL;
			goto out;
		}

		if (unlikely(dev->info.addr_len > sizeof(dev->info.addr))) {
			PRINT_ERROR("Invalid address length %zd > %zd",
				    dev->info.addr_len, sizeof(dev->info.addr));
			res = -EINVAL;
			goto out;
		}

		portal = isert_portal_add((struct sockaddr *)&dev->info.addr,
					  dev->info.addr_len);
		if (IS_ERR(portal)) {
			PRINT_ERROR("Unable to add portal of size %zu",
				    dev->info.addr_len);
			res = PTR_ERR(portal);
			goto out;
		}
		dev->portal_h[dev->free_portal_idx++] = portal;
		break;

	default:
		PRINT_ERROR("Invalid ioctl cmd %x", cmd);
		res = -EINVAL;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

int isert_conn_established(struct iscsi_conn *iscsi_conn,
			   struct sockaddr *from_addr, int addr_len)
{
	return add_new_connection(&isert_listen_dev, iscsi_conn);
}

static void isert_dev_disconnect(struct iscsi_conn* iscsi_conn)
{
	struct isert_conn_dev* dev = isert_get_priv(iscsi_conn);

	if (dev) {
		isert_del_timer(dev);
		dev->state = CS_DISCONNECTED;
		if (dev->login_req) {
			isert_task_abort(dev->login_req);
			spin_lock(&dev->pdu_lock);
			dev->login_req = NULL;
			spin_unlock(&dev->pdu_lock);
		}
		wake_up(&dev->waitqueue);
		isert_dev_release(dev);
		isert_set_priv(iscsi_conn, NULL);
	}
}

void isert_connection_closed(struct iscsi_conn *iscsi_conn)
{
	TRACE_ENTRY();

	mutex_lock(&conn_mgmt_mutex);

	if (iscsi_conn->rd_state) {
		mutex_unlock(&conn_mgmt_mutex);
		isert_handle_close_connection(iscsi_conn);
	} else {
		isert_dev_disconnect(iscsi_conn);
		mutex_unlock(&conn_mgmt_mutex);
		isert_free_connection(iscsi_conn);
	}

	TRACE_EXIT();
}

void isert_connection_abort(struct iscsi_conn *iscsi_conn)
{
	struct isert_connection *isert_conn = (struct isert_connection *)iscsi_conn;

	TRACE_ENTRY();

	mutex_lock(&conn_mgmt_mutex);

	if (!iscsi_conn->rd_state) {
		if (!test_and_set_bit(ISERT_DISCON_CALLED, &isert_conn->flags)) {
			isert_dev_disconnect(iscsi_conn);
			isert_free_connection(iscsi_conn);
		}
	}
	mutex_unlock(&conn_mgmt_mutex);

	TRACE_EXIT();
}

static bool will_read_block(struct isert_conn_dev *dev)
{
	bool res = true;

	spin_lock(&dev->pdu_lock);
	if (dev->login_req != NULL) {
		switch (dev->state) {
		case CS_REQ_BHS:
		case CS_REQ_DATA:
			res = false;
			break;
		default:
			break;
		}
	}
	spin_unlock(&dev->pdu_lock);

	return res;
}

static int isert_open(struct inode *inode, struct file *filp)
{
	struct isert_conn_dev *dev; /* device information */
	int res = 0;

	TRACE_ENTRY();

	dev = container_of(inode->i_cdev, struct isert_conn_dev, cdev);

	mutex_lock(&isert_listen_dev.conn_lock);
	if (unlikely(dev->occupied == 0)) {
		mutex_unlock(&isert_listen_dev.conn_lock);
		res = -ENODEV; /* already closed */
		goto out;
	}
	mutex_unlock(&isert_listen_dev.conn_lock);

	if (unlikely(!atomic_dec_and_test(&dev->available))) {
		atomic_inc(&dev->available);
		res = -EBUSY; /* already open */
		goto out;
	}

	mutex_lock(&isert_listen_dev.conn_lock);
	kref_get(&dev->kref);
	mutex_unlock(&isert_listen_dev.conn_lock);

	filp->private_data = dev; /* for other methods */

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int isert_release(struct inode *inode, struct file *filp)
{
	struct isert_conn_dev *dev = filp->private_data;
	int res = 0;

	TRACE_ENTRY();

	vunmap(dev->sg_virt);
	dev->sg_virt = NULL;
	dev->is_discovery = 0;

	isert_delete_conn_dev(dev);
	isert_dev_release(dev);

	TRACE_EXIT_RES(res);
	return res;
}

static char *isert_vmap_sg(struct page **pages, struct scatterlist *sgl,
			   int n_ents)
{
	unsigned int i;
	struct scatterlist *sg;
	void *vaddr;

	for_each_sg(sgl, sg, n_ents, i)
		pages[i] = sg_page(sg);

	vaddr = vmap(pages, n_ents, 0, PAGE_KERNEL);

	return vaddr;
}

static ssize_t isert_read(struct file *filp, char __user *buf, size_t count,
			  loff_t *f_pos)
{
	struct isert_conn_dev *dev = filp->private_data;
	size_t to_read;

	mutex_lock(&conn_mgmt_mutex);

	if (dev->state == CS_DISCONNECTED) {
		mutex_unlock(&conn_mgmt_mutex);
		return -EPIPE;
	}

	if (will_read_block(dev)) {
		int ret;

		if (filp->f_flags & O_NONBLOCK) {
			mutex_unlock(&conn_mgmt_mutex);
			return -EAGAIN;
		}
		ret = wait_event_freezable(dev->waitqueue,
			!will_read_block(dev));
		if (ret < 0) {
			mutex_unlock(&conn_mgmt_mutex);
			return ret;
		}
	}

	to_read = min(count, dev->read_len);
	if (copy_to_user(buf, dev->read_buf, to_read)) {
		mutex_unlock(&conn_mgmt_mutex);
		return -EFAULT;
	}

	dev->read_len -= to_read;
	dev->read_buf += to_read;

	switch (dev->state) {
	case CS_REQ_BHS:
		if (dev->read_len == 0) {
			dev->read_len = dev->login_req->bufflen;
			dev->sg_virt = isert_vmap_sg(dev->pages,
						     dev->login_req->sg,
						     dev->login_req->sg_cnt);
			if (!dev->sg_virt) {
				mutex_unlock(&conn_mgmt_mutex);
				return -ENOMEM;
			}
			dev->read_buf = dev->sg_virt + ISER_HDRS_SZ;
			dev->state = CS_REQ_DATA;
		}
		break;

	case CS_REQ_DATA:
		if (dev->read_len == 0) {
			vunmap(dev->sg_virt);
			dev->sg_virt = NULL;

			spin_lock(&dev->pdu_lock);
			dev->login_req = NULL;
			dev->state = CS_REQ_FINISHED;
			spin_unlock(&dev->pdu_lock);
		}
		break;

	default:
		PRINT_ERROR("Invalid state %d", dev->state);
		to_read = 0;
	}

	mutex_unlock(&conn_mgmt_mutex);

	return to_read;
}

static ssize_t isert_write(struct file *filp, const char __user *buf,
			   size_t count, loff_t *f_pos)
{
	struct isert_conn_dev *dev = filp->private_data;
	size_t to_write;

	mutex_lock(&conn_mgmt_mutex);

	if (dev->state == CS_DISCONNECTED) {
		mutex_unlock(&conn_mgmt_mutex);
		return -EPIPE;
	}

	to_write = min(count, dev->write_len);
	if (copy_from_user(dev->write_buf, buf, to_write)) {
		mutex_unlock(&conn_mgmt_mutex);
		return -EFAULT;
	}

	dev->write_len -= to_write;
	dev->write_buf += to_write;

	switch (dev->state) {
	case CS_RSP_BHS:
		if (dev->write_len == 0) {
			dev->state = CS_RSP_DATA;
			dev->sg_virt = isert_vmap_sg(dev->pages,
						     dev->login_rsp->sg,
						     dev->login_rsp->sg_cnt);
			if (!dev->sg_virt) {
				mutex_unlock(&conn_mgmt_mutex);
				return -ENOMEM;
			}
			dev->write_buf = dev->sg_virt + ISER_HDRS_SZ;
			dev->write_len = dev->login_rsp->bufflen -
					 sizeof(dev->login_rsp->pdu.bhs);
			iscsi_cmnd_get_length(&dev->login_rsp->pdu);
		}
		break;

	case CS_RSP_DATA:
		break;

	default:
		PRINT_ERROR("Invalid state %d", dev->state);
		to_write = 0;
	}

	mutex_unlock(&conn_mgmt_mutex);

	return to_write;
}

static bool is_last_login_rsp(struct iscsi_login_rsp_hdr *rsp)
{
	return (rsp->flags & ISCSI_FLG_TRANSIT) &&
	       ((rsp->flags & ISCSI_FLG_NSG_MASK) == ISCSI_FLG_NSG_FULL_FEATURE);
}

static long isert_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct isert_conn_dev *dev = filp->private_data;
	int res = 0, rc;
	int val;
	void __user *ptr = (void __user *)arg;
	struct iscsi_cmnd *cmnd;

	TRACE_ENTRY();

	mutex_lock(&conn_mgmt_mutex);

	if (dev->state == CS_DISCONNECTED) {
		res = -EPIPE;
		goto out;
	}

	switch (cmd) {
	case RDMA_CORK:
		rc = copy_from_user(&val, ptr, sizeof(val));
		if (unlikely(rc != 0)) {
			PRINT_ERROR("Failed to copy %d user's bytes", rc);
			res = -EFAULT;
			goto out;
		}
		if (val) {
			if (!dev->login_rsp) {
				cmnd = isert_alloc_login_rsp_pdu(dev->conn);
				if (unlikely(!cmnd)) {
					res = -ENOMEM;
					goto out;
				}
				dev->login_rsp = cmnd;
				dev->write_buf = (char *)&cmnd->pdu.bhs;
				dev->write_len = sizeof(cmnd->pdu.bhs);
				dev->state = CS_RSP_BHS;
			}
		} else {
			struct iscsi_login_rsp_hdr *rsp;
			bool last;

			if (unlikely(!dev->login_rsp)) {
				res = -EINVAL;
				goto out;
			}

			dev->state = CS_RSP_FINISHED;
			rsp = (struct iscsi_login_rsp_hdr *)(&dev->login_rsp->pdu.bhs);
			last = is_last_login_rsp(rsp);

			dev->login_rsp->bufflen -= dev->write_len;

			if (!last || dev->is_discovery) {
				spin_lock(&dev->pdu_lock);
				dev->login_req = NULL;
				spin_unlock(&dev->pdu_lock);
				res = isert_login_rsp_tx(dev->login_rsp,
							last,
							dev->is_discovery);
				vunmap(dev->sg_virt);
				dev->sg_virt = NULL;
				dev->login_rsp = NULL;
			}
		}
		break;

	case GET_PORTAL_ADDR:
		{
			struct isert_addr_info addr;

			res = isert_get_target_addr(dev->conn,
						   (struct sockaddr *)&addr.addr,
						   &addr.addr_len);
			if (unlikely(res))
				goto out;

			rc = copy_to_user(ptr, &addr, sizeof(addr));
			if (unlikely(rc != 0))
				res = -EFAULT;
		}
		break;

	case DISCOVERY_SESSION:
		rc = copy_from_user(&val, ptr, sizeof(val));
		if (unlikely(rc != 0)) {
			PRINT_ERROR("Failed to copy %d user's bytes", rc);
			res = -EFAULT;
			goto out;
		}
		dev->is_discovery = val;
		break;

	default:
		PRINT_ERROR("Invalid ioctl cmd %x", cmd);
		res = -EINVAL;
	}

out:
	mutex_unlock(&conn_mgmt_mutex);
	TRACE_EXIT_RES(res);
	return res;
}

static unsigned int isert_poll(struct file *filp,
			       struct poll_table_struct *wait)
{
	struct isert_conn_dev *dev = filp->private_data;
	unsigned int mask = 0;

	poll_wait(filp, &dev->waitqueue, wait);

	if (!dev->conn || dev->state == CS_DISCONNECTED)
		mask |= POLLHUP | POLLIN;
	else {
		if (!will_read_block(dev))
			mask |= POLLIN | POLLRDNORM;

		mask |= POLLOUT | POLLWRNORM;
	}

	return mask;
}

int isert_login_req_rx(struct iscsi_cmnd *login_req)
{
	struct isert_conn_dev *dev = isert_get_priv(login_req->conn);
	int res = 0;

	TRACE_ENTRY();

	if (!dev) {
		PRINT_ERROR("Received PDU %p on invalid connection",
			    login_req);
		res = -EINVAL;
		goto out;
	}

	switch (dev->state) {
	case CS_INIT:
	case CS_RSP_FINISHED:
		if (unlikely(dev->login_req != NULL))
			sBUG();
		break;

	case CS_REQ_BHS: /* Got login request before done handling old one */
		break;

	case CS_REQ_DATA:
	case CS_REQ_FINISHED:
	case CS_RSP_BHS:
	case CS_RSP_DATA:
		PRINT_WARNING("Received login PDU while handling previous one. State:%d",
			      dev->state);
		res = -EINVAL;
		goto out;

	default:
		sBUG();
	}


	spin_lock(&dev->pdu_lock);
	dev->login_req = login_req;
	dev->read_len = sizeof(login_req->pdu.bhs);
	dev->read_buf = (char *)&login_req->pdu.bhs;
	dev->state = CS_REQ_BHS;
	spin_unlock(&dev->pdu_lock);

	wake_up(&dev->waitqueue);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static dev_t devno;

static const struct file_operations listener_fops = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.read		= isert_listen_read,
	.unlocked_ioctl	= isert_listen_ioctl,
	.compat_ioctl	= isert_listen_ioctl,
	.poll		= isert_listen_poll,
	.open		= isert_listen_open,
	.release	= isert_listen_release,
};

static const struct file_operations conn_fops = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.read		= isert_read,
	.write		= isert_write,
	.unlocked_ioctl	= isert_ioctl,
	.compat_ioctl	= isert_ioctl,
	.poll		= isert_poll,
	.open		= isert_open,
	.release	= isert_release,
};

static void __init isert_setup_cdev(struct isert_conn_dev *dev,
				    unsigned int index)
{
	int err;

	TRACE_ENTRY();

	dev->devno = MKDEV(isert_major, index + 1);

	cdev_init(&dev->cdev, &conn_fops);
	dev->cdev.owner = THIS_MODULE;
	dev->cdev.ops = &conn_fops;
	dev->idx = index;
	init_waitqueue_head(&dev->waitqueue);
	dev->login_req = NULL;
	dev->login_rsp = NULL;
	spin_lock_init(&dev->pdu_lock);
	atomic_set(&dev->available, 1);
	kref_init(&dev->kref);
	dev->state = CS_INIT;
	err = cdev_add(&dev->cdev, dev->devno, 1);
	/* Fail gracefully if need be */
	if (unlikely(err))
		PRINT_ERROR("Error %d adding "ISER_CONN_DEV_PREFIX"%d", err,
			    index);

	dev->dev = device_create(isert_class, NULL, dev->devno,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
				 NULL,
#endif
				 ISER_CONN_DEV_PREFIX"%d", index);

	TRACE_EXIT();
}

static void __init isert_setup_listener_cdev(struct isert_listener_dev *dev)
{
	int err;

	TRACE_ENTRY();

	dev->devno = MKDEV(isert_major, 0);

	cdev_init(&dev->cdev, &listener_fops);
	dev->cdev.owner = THIS_MODULE;
	dev->cdev.ops = &listener_fops;
	init_waitqueue_head(&dev->waitqueue);
	INIT_LIST_HEAD(&dev->new_conn_list);
	INIT_LIST_HEAD(&dev->curr_conn_list);
	mutex_init(&dev->conn_lock);
	atomic_set(&dev->available, 1);
	err = cdev_add(&dev->cdev, dev->devno, 1);
	/* Fail gracefully if need be */
	if (unlikely(err))
		PRINT_ERROR("Error %d adding isert_scst", err);

	dev->dev = device_create(isert_class, NULL, dev->devno,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
				 NULL,
#endif
				 "isert_scst");

	TRACE_EXIT();
}

int __init isert_init_login_devs(unsigned int ndevs)
{
	int res;
	unsigned int i;

	TRACE_ENTRY();

	n_devs = ndevs;

	res = alloc_chrdev_region(&devno, 0, n_devs,
			"isert_scst");
	isert_major = MAJOR(devno);

	if (unlikely(res < 0)) {
		PRINT_ERROR("can't get major %d", isert_major);
		goto out;
	}

	/*
	 * allocate the devices -- we can't have them static, as the number
	 * can be specified at load time
	 */
	isert_conn_devices = kcalloc(n_devs, sizeof(struct isert_conn_dev),
				     GFP_KERNEL);
	if (unlikely(!isert_conn_devices)) {
		res = -ENOMEM;
		goto fail;  /* Make this more graceful */
	}

	isert_class = class_create(THIS_MODULE, "isert_scst");

	isert_setup_listener_cdev(&isert_listen_dev);

	/* Initialize each device. */
	for (i = 0; i < n_devs; i++)
		isert_setup_cdev(&isert_conn_devices[i], i);

	res = isert_datamover_init();
	if (unlikely(res)) {
		PRINT_ERROR("Unable to initialize datamover: %d", res);
		goto fail;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
fail:
	isert_cleanup_login_devs();
	goto out;
}

void isert_close_all_portals(void)
{
	int i;

	for (i = 0; i < isert_listen_dev.free_portal_idx; ++i)
		isert_portal_remove(isert_listen_dev.portal_h[i]);
	isert_listen_dev.free_portal_idx = 0;
}

void isert_cleanup_login_devs(void)
{
	int i;

	TRACE_ENTRY();

	isert_close_all_portals();

	isert_datamover_cleanup();

	if (isert_conn_devices) {
		for (i = 0; i < n_devs; i++) {
			device_destroy(isert_class,
				       isert_conn_devices[i].devno);
			cdev_del(&isert_conn_devices[i].cdev);
		}
		kfree(isert_conn_devices);
	}

	device_destroy(isert_class, isert_listen_dev.devno);
	cdev_del(&isert_listen_dev.cdev);

	if (isert_class)
		class_destroy(isert_class);

	unregister_chrdev_region(devno, n_devs);

	TRACE_EXIT();
}
