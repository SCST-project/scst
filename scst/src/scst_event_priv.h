/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_EVENT_PRIV_H
#define SCST_EVENT_PRIV_H

#define SCST_MAX_EVENTS			2048
#define SCST_MAX_PAYLOAD		(3 * 1024)
#define SCST_DEFAULT_EVENT_TIMEOUT	(60 * HZ)

struct scst_event_priv {
	struct list_head privs_list_entry;
	int allowed_events_cnt;
	int queued_events_cnt;
	unsigned int going_to_exit:1;
	unsigned int blocking:1;
	pid_t owner_pid;
	/*
	 * WARNING: payloads in events in the allowed list queued AS IS from the
	 * user space, so they are UNTRUSTED and can NOT be used in any other
	 * way, except as BLOBs for comparison!
	 */
	struct list_head allowed_events_list;
	struct list_head queued_events_list;
	wait_queue_head_t queued_events_waitQ;
	struct list_head processing_events_list;
};

#endif /* SCST_EVENT_PRIV_H */
