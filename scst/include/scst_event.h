/*
 *  include/scst_event.h
 *
 *  Copyright (C) 2014 - 2017 SanDisk Corporation
 *
 *  Contains constants and data structures for scst_event module.
 */

#ifndef __SCST_EVENT_H
#define __SCST_EVENT_H

#ifdef __KERNEL__
#include <linux/types.h>
#endif

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst_const.h>
#else
#include "scst_const.h"
#endif

#define SCST_EVENT_NAME			"scst_event"
#define SCST_EVENT_PATH			"/dev/"
#define SCST_EVENT_DEV			SCST_EVENT_PATH SCST_EVENT_NAME
#define SCST_EVENT_VERSION_NAME		SCST_VERSION_NAME
#define SCST_EVENT_VERSION		\
	SCST_EVENT_VERSION_NAME "$Revision: 2454 $" SCST_CONST_VERSION

#ifndef aligned_u64
#define aligned_u64 uint64_t __attribute__((aligned(8)))
#endif

/*
 * Due to variable size, this structure must always be last in any outer
 * structure!
 */
struct scst_event {
	int32_t payload_len;

	uint32_t event_code;

	uint32_t event_id; /* ID uniquely identifying this event */

	/*
	 * Event's issuer's name, i.e. SCST name of the corresponding module
	 * (target driver or dev handler). SCST_EVENT_SCST_CORE_ISSUER for SCST
	 * core.
	 */
	char issuer_name[SCST_MAX_NAME];

	uint8_t payload[]; /* event's payload */
};

#ifdef __KERNEL__
typedef void (*scst_event_done_notify_fn) (struct scst_event *event,
	void *priv, int status);

struct scst_event_entry {
	struct list_head events_list_entry;
	scst_event_done_notify_fn event_notify_fn;
	void *notify_fn_priv;
	unsigned long event_timeout; /* in jiffies */
	int *pqueued_events_cnt;
	union {
		struct work_struct scst_event_queue_work;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
		struct work_struct event_timeout_work;
#else
		struct delayed_work event_timeout_work;
#endif
	};

	struct scst_event event;
	/* event's payload */
};
#endif

struct scst_event_user {
	int32_t max_event_size;
	struct scst_event out_event;
};

struct scst_event_notify_done {
	uint32_t event_id;
	int status;
};

/* IOCTLs */
#define SCST_EVENT_ALLOW_EVENT		_IOW('u', 1, struct scst_event)
#define SCST_EVENT_DISALLOW_EVENT	_IOW('u', 2, struct scst_event)
#define SCST_EVENT_GET_NEXT_EVENT	_IOWR('u', 3, struct scst_event_user)
#define SCST_EVENT_NOTIFY_DONE		_IOW('u', 4, struct scst_event_notify_done)

#ifdef __KERNEL__
void scst_event_queue(uint32_t event_code, const char *issuer_name,
	struct scst_event_entry *e);
#endif

/*************************************************************
 ** SCST events
 *************************************************************/

/* SCST core issuer name */
#define SCST_EVENT_SCST_CORE_ISSUER	"SCST core"

/** SCST core's events **/

#define SCST_EVENT_LUN_NOT_FOUND	1
struct scst_event_lun_not_found_payload {
	aligned_u64 lun;
	uint8_t initiator_name[SCST_MAX_EXTERNAL_NAME];
	uint8_t target_name[SCST_MAX_EXTERNAL_NAME];
};

#define SCST_EVENT_NEGATIVE_LUNS_INQUIRY 2
struct scst_event_negative_luns_inquiry_payload {
	uint8_t initiator_name[SCST_MAX_EXTERNAL_NAME];
	uint8_t target_name[SCST_MAX_EXTERNAL_NAME];
};

#define SCST_EVENT_EXT_BLOCKING_DONE	3
struct scst_event_ext_blocking_done_payload {
	uint8_t device_name[SCST_MAX_EXTERNAL_NAME];
	uint32_t data_len;
	uint8_t data[];
};

#define SCST_EVENT_TM_FN_RECEIVED	4
struct scst_event_tm_fn_received_payload {
	uint32_t fn; /* TM fn */
	aligned_u64 lun;
	uint8_t device_name[SCST_MAX_EXTERNAL_NAME];
	uint8_t initiator_name[SCST_MAX_EXTERNAL_NAME];
	uint8_t target_name[SCST_MAX_EXTERNAL_NAME];
	uint8_t session_sysfs_name[SCST_MAX_EXTERNAL_NAME];
	struct { /* if ABORT TASK, then tag and CDB of cmd to abort */
		aligned_u64 cmd_to_abort_tag;
		uint8_t cdb[SCST_MAX_CDB_SIZE];
	};
};

#define SCST_EVENT_STPG_USER_INVOKE    5
struct scst_event_stpg_descr {
	uint16_t group_id;
	/*
	 * Better to keep below fields as small as possible to fit
	 * in single page as many descriptors as possible.
	 */
	uint8_t prev_state[32];
	uint8_t new_state[32];
	uint8_t dg_name[64];
	uint8_t tg_name[64];
};
struct scst_event_stpg_payload {
	aligned_u64 stpg_cmd_tag;
	uint8_t device_name[64];
	uint16_t stpg_descriptors_cnt;
	struct scst_event_stpg_descr stpg_descriptors[0];
};

#endif /* __SCST_EVENT_H */
