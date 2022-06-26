/*
 *  Event notification code.
 *
 *  Copyright (C) 2005 FUJITA Tomonori <tomof@acm.org>
 *  Copyright (C) 2007 - 2018 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2018 Western Digital Corporation
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 */

#include <linux/module.h>
#ifdef INSIDE_KERNEL_TREE
#include <scst/iscsi_scst.h>
#else
#include "iscsi_scst.h"
#endif
#include "iscsi_trace_flag.h"
#include "iscsi.h"

struct net *iscsi_net_ns;
EXPORT_SYMBOL(iscsi_net_ns);

/* See also commit 2d4bc93368f5 ("netlink: extended ACK reporting") */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
struct netlink_ext_ack;

static inline void netlink_ack_backport(struct sk_buff *in_skb,
					struct nlmsghdr *nlh, int err,
					const struct netlink_ext_ack *extack)
{
	WARN_ON_ONCE(extack);
	netlink_ack(in_skb, nlh, err);
}
#define netlink_ack netlink_ack_backport
#endif

static struct sock *nl;
static u32 iscsid_pid;

static int event_recv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	u32 pid;

	pid = NETLINK_CB(skb).portid;
	WARN_ON(pid == 0);

	iscsid_pid = pid;

	return 0;
}

static void event_recv_skb(struct sk_buff *skb)
{
	int err;
	struct nlmsghdr	*nlh;
	u32 rlen;

	while (skb->len >= NLMSG_SPACE(0)) {
		nlh = (struct nlmsghdr *)skb->data;
		if (nlh->nlmsg_len < sizeof(*nlh) || skb->len < nlh->nlmsg_len)
			goto out;
		rlen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (rlen > skb->len)
			rlen = skb->len;
		err = event_recv_msg(skb, nlh);
		if (err)
			netlink_ack(skb, nlh, -err, NULL);
		else if (nlh->nlmsg_flags & NLM_F_ACK)
			netlink_ack(skb, nlh, 0, NULL);
		skb_pull(skb, rlen);
	}

out:
	return;
}

/* event_mutex supposed to be held */
static int __event_send(const void *buf, int buf_len)
{
	int res = 0, len;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	static u32 seq; /* protected by event_mutex */

	TRACE_ENTRY();

	if (ctr_open_state != ISCSI_CTR_OPEN_STATE_OPEN)
		goto out;

	len = NLMSG_SPACE(buf_len);

	skb = alloc_skb(len, GFP_KERNEL);
	if (skb == NULL) {
		PRINT_ERROR("alloc_skb() failed (len %d)", len);
		res =  -ENOMEM;
		goto out;
	}

	nlh = __nlmsg_put(skb, iscsid_pid, seq++, NLMSG_DONE, buf_len, 0);

	memcpy(NLMSG_DATA(nlh), buf, buf_len);
	res = netlink_unicast(nl, skb, iscsid_pid, 0);
	if (res <= 0) {
		if (res != -ECONNREFUSED)
			PRINT_ERROR("netlink_unicast() failed: %d", res);
		else
			TRACE(TRACE_MINOR,
			      "netlink_unicast() failed: %s. Not functioning user space?",
			      "Connection refused");
		goto out;
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

int event_send(u32 tid, u64 sid, u32 cid, u32 cookie,
	enum iscsi_kern_event_code code,
	const char *param1, const char *param2)
{
	int err;
	static DEFINE_MUTEX(event_mutex);
	struct iscsi_kern_event event = {};
	int param1_size, param2_size;

	param1_size = (param1 != NULL) ? strlen(param1) : 0;
	param2_size = (param2 != NULL) ? strlen(param2) : 0;

	event.tid = tid;
	event.sid = sid;
	event.cid = cid;
	event.code = code;
	event.cookie = cookie;
	event.param1_size = param1_size;
	event.param2_size = param2_size;

	mutex_lock(&event_mutex);

	err = __event_send(&event, sizeof(event));
	if (err <= 0)
		goto out_unlock;

	if (param1_size > 0) {
		err = __event_send(param1, param1_size);
		if (err <= 0)
			goto out_unlock;
	}

	if (param2_size > 0) {
		err = __event_send(param2, param2_size);
		if (err <= 0)
			goto out_unlock;
	}

out_unlock:
	mutex_unlock(&event_mutex);
	return err;
}

int __init event_init(void)
{
	iscsi_net_ns = kobj_ns_grab_current(KOBJ_NS_TYPE_NET);

	{
		struct netlink_kernel_cfg cfg = {
			.input = event_recv_skb,
			.groups = 1,
		};
		nl = netlink_kernel_create(iscsi_net_ns, NETLINK_ISCSI_SCST,
					   &cfg);
	}
	if (!nl)
		goto drop_ns;

	return 0;

drop_ns:
	PRINT_ERROR("%s", "netlink_kernel_create() failed");
	kobj_ns_drop(KOBJ_NS_TYPE_NET, iscsi_net_ns);
	iscsi_net_ns = NULL;
	return -ENOMEM;
}

void event_exit(void)
{
	netlink_kernel_release(nl);
	kobj_ns_drop(KOBJ_NS_TYPE_NET, iscsi_net_ns);
	iscsi_net_ns = NULL;
}
