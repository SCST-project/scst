/*
 *  Event notification code.
 *
 *  Copyright (C) 2005 FUJITA Tomonori <tomof@acm.org>
 *  Copyright (C) 2007 Vladislav Bolkhovitin
 *  Copyright (C) 2007 CMS Distribution Limited
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
 *  Some functions are based on audit code.
 */

#include <net/tcp.h>
#include "iscsi_u.h"
#include "iscsi.h"

static struct sock *nl;
static u32 iscsid_pid;

static int event_recv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	u32 uid, pid, seq;
	char *data;

	pid  = NETLINK_CREDS(skb)->pid;
	uid  = NETLINK_CREDS(skb)->uid;
	seq  = nlh->nlmsg_seq;
	data = NLMSG_DATA(nlh);

	iscsid_pid = pid;

	return 0;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
static int event_recv_skb(struct sk_buff *skb)
#else
static void event_recv_skb(struct sk_buff *skb)
#endif
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
		if ((err = event_recv_msg(skb, nlh))) {
			netlink_ack(skb, nlh, -err);
		} else if (nlh->nlmsg_flags & NLM_F_ACK)
			netlink_ack(skb, nlh, 0);
		skb_pull(skb, rlen);
	}

out:
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
	return 0;
#else
	return;
#endif
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
static void event_recv(struct sock *sk, int length)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&sk->sk_receive_queue))) {
		if (event_recv_skb(skb) && skb->len)
			skb_queue_head(&sk->sk_receive_queue, skb);
		else
			kfree_skb(skb);
	}
}
#endif

static int notify(void *data, int len, int gfp_mask)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	static u32 seq = 0;

	if (!(skb = alloc_skb(NLMSG_SPACE(len), gfp_mask)))
		return -ENOMEM;

	nlh = __nlmsg_put(skb, iscsid_pid, seq++, NLMSG_DONE, len - sizeof(*nlh), 0);

	memcpy(NLMSG_DATA(nlh), data, len);

	return netlink_unicast(nl, skb, iscsid_pid, 0);
}

int event_send(u32 tid, u64 sid, u32 cid, u32 state, int atomic)
{
	int err;
	struct iscsi_event event;

	event.tid = tid;
	event.sid = sid;
	event.cid = cid;
	event.state = state;

	err = notify(&event, NLMSG_SPACE(sizeof(struct iscsi_event)), 0);

	return err;
}

int __init event_init(void)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
	nl = netlink_kernel_create(NETLINK_ISCSI_SCST, 1, event_recv,
		THIS_MODULE);
#else
  #if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
  	nl = netlink_kernel_create(NETLINK_ISCSI_SCST, 1, event_recv, NULL,
		THIS_MODULE);
  #else
	nl = netlink_kernel_create(&init_net, NETLINK_ISCSI_SCST, 1,
		event_recv_skb, NULL, THIS_MODULE);
  #endif
#endif
	if (!nl) {
		PRINT_ERROR("%s", "netlink_kernel_create() failed");
		return -ENOMEM;
	} else
		return 0;
}

void event_exit(void)
{
	if (nl)
		sock_release(nl->sk_socket);
}
