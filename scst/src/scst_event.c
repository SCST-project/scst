/*
 *  scst_event.c
 *
 *  Copyright (C) 2014 - 2016 SanDisk Corporation
 *
 */

#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/poll.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include <linux/module.h>

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#include <scst/scst_event.h>
#else
#include "scst.h"
#include "scst_event.h"
#endif

#include "scst_priv.h"

static struct class *scst_event_sysfs_class;

static int scst_event_major;

#define SCST_MAX_EVENTS			2048
#define SCST_MAX_PAYLOAD		3*1024
#define SCST_DEFAULT_EVENT_TIMEOUT	(60*HZ)

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

static DEFINE_MUTEX(scst_event_mutex);
static LIST_HEAD(scst_event_privs_list);

/*
 * Compares events e1_wild and e2, where e1_wild can have wildcard matching,
 * i.e.:
 *   - event_code 0 - any event code
 *   - issuer_name "*" - any issuer name
 *   - payload_len 0 - any payload
 */
static bool scst_event_cmp(const struct scst_event *e1_wild,
	const struct scst_event *e2)
{
	int res = false;

	TRACE_ENTRY();

	if ((e1_wild->event_code != e2->event_code) &&
	    (e1_wild->event_code != 0))
		goto out;

	if ((strcmp(e1_wild->issuer_name, e2->issuer_name) != 0) &&
	    (strcmp(e1_wild->issuer_name, "*") != 0))
		goto out;

	if (e1_wild->payload_len == 0)
		goto out_true;

	if ((e1_wild->payload_len != e2->payload_len) ||
	    (memcmp(e1_wild->payload, e2->payload, e1_wild->payload_len) != 0))
		goto out;

out_true:
	res = true;

out:
	TRACE_EXIT_RES(res);
	return res;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void scst_event_timeout_fn(void *p)
{
	struct scst_event_entry *event_entry = p;
#else
static void scst_event_timeout_fn(struct work_struct *work)
{
	struct scst_event_entry *event_entry = container_of(work,
		struct scst_event_entry, event_timeout_work.work);
#endif

	TRACE_ENTRY();

	TRACE_MGMT_DBG("Timeout of event %d (issuer %s, id %u, entry %p)",
		event_entry->event.event_code, event_entry->event.issuer_name,
		event_entry->event.event_id, event_entry);

	mutex_lock(&scst_event_mutex);

	if (list_empty(&event_entry->events_list_entry)) {
		/* It's done already and about to be freed */
		mutex_unlock(&scst_event_mutex);
		goto out;
	}
	list_del_init(&event_entry->events_list_entry);

	(*event_entry->pqueued_events_cnt)--;

	mutex_unlock(&scst_event_mutex);

	TRACE_DBG("Calling notify_fn of event_entry %p", event_entry);
	event_entry->event_notify_fn(&event_entry->event,
		 event_entry->notify_fn_priv, -ETIMEDOUT);

	TRACE_MEM("Freeing event entry %p", event_entry);
	kfree(event_entry);

out:
	TRACE_EXIT();
	return;
}

static int scst_clone_event(const struct scst_event_entry *orig_entry,
	struct scst_event_entry **new_event_entry)
{
	int res = 0;
	const struct scst_event *event = &orig_entry->event;
	struct scst_event_entry *event_entry;
	int event_entry_len = sizeof(*event_entry) + event->payload_len;

	TRACE_ENTRY();

	event_entry = kzalloc(event_entry_len, GFP_KERNEL);
	if (event_entry == NULL) {
		PRINT_ERROR("Unable to clone event entry (size %d, event %d, "
			"issuer %s", event_entry_len, event->event_code,
			event->issuer_name);
		res = -ENOMEM;
		goto out;
	}

	TRACE_MEM("event_entry %p (len %d) allocated", event_entry, event_entry_len);

	memcpy(&event_entry->event, event, sizeof(*event) + event->payload_len);

	WARN_ON(orig_entry->event_notify_fn != NULL);

	*new_event_entry = event_entry;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void __scst_event_queue(struct scst_event_entry *event_entry)
{
	const struct scst_event *event = &event_entry->event;
	struct scst_event_priv *priv;
	struct scst_event_entry *allowed_entry;
	bool queued = false;
	int rc = 0;
	static atomic_t base_event_id = ATOMIC_INIT(0);

	TRACE_ENTRY();

	mutex_lock(&scst_event_mutex);

	list_for_each_entry(priv, &scst_event_privs_list, privs_list_entry) {
		list_for_each_entry(allowed_entry, &priv->allowed_events_list,
				events_list_entry) {
			if (scst_event_cmp(&allowed_entry->event, event)) {
				struct scst_event_entry *new_event_entry;

				if (priv->queued_events_cnt >= SCST_MAX_EVENTS) {
					PRINT_ERROR("Too many queued events %d, "
						"event %d, issuer %s is lost.",
						priv->queued_events_cnt,
						event->event_code,
						event->issuer_name);
					rc = -EMFILE;
					break;
				}

				if (!queued)
					new_event_entry = event_entry;
				else if (event_entry->event_notify_fn == NULL) {
					rc = scst_clone_event(event_entry, &new_event_entry);
					if (rc != 0)
						goto done;
				} else {
					PRINT_WARNING("Event %d can be queued only once, "
						"dublicated receiver pid %d will miss it!",
						event->event_code, priv->owner_pid);
					break;
				}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
				INIT_WORK(&new_event_entry->event_timeout_work,
					  scst_event_timeout_fn,
					  new_event_entry);
#else
				INIT_DELAYED_WORK(&new_event_entry->event_timeout_work,
						  scst_event_timeout_fn);
#endif
				if (new_event_entry->event_notify_fn != NULL) {
					new_event_entry->event.event_id = atomic_inc_return(&base_event_id);
					if (new_event_entry->event_timeout == 0)
						new_event_entry->event_timeout = SCST_DEFAULT_EVENT_TIMEOUT;
					schedule_delayed_work(&new_event_entry->event_timeout_work,
						new_event_entry->event_timeout);
				}

				list_add_tail(&new_event_entry->events_list_entry,
					&priv->queued_events_list);
				priv->queued_events_cnt++;
				new_event_entry->pqueued_events_cnt = &priv->queued_events_cnt;
				queued = true;

				TRACE_DBG("event %d queued (issuer %s, id %u, "
					"entry %p)", new_event_entry->event.event_code,
					new_event_entry->event.issuer_name,
					new_event_entry->event.event_id, new_event_entry);

				wake_up_all(&priv->queued_events_waitQ);
				break;
			}
		}
	}
done:
	mutex_unlock(&scst_event_mutex);

	if (!queued) {
		if (event_entry->event_notify_fn != NULL) {
			if (rc == 0)
				rc = -ENOENT;
			TRACE_DBG("Calling notify_fn of event_entry %p (rc %d)",
				event_entry, rc);
			event_entry->event_notify_fn(&event_entry->event,
				event_entry->notify_fn_priv, rc);
		}

		TRACE_MEM("Freeing orphan event entry %p", event_entry);
		kfree(event_entry);
	}

	TRACE_EXIT();
	return;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void scst_event_queue_work_fn(void *p)
{
	struct scst_event_entry *e = p;
#else
static void scst_event_queue_work_fn(struct work_struct *work)
{
	struct scst_event_entry *e = container_of(work,
		struct scst_event_entry, scst_event_queue_work);
#endif

	TRACE_ENTRY();

	__scst_event_queue(e);

	TRACE_EXIT();
	return;
}

/* Can be called on IRQ with any lock held */
void scst_event_queue(uint32_t event_code, const char *issuer_name,
	struct scst_event_entry *e)
{
	TRACE_ENTRY();

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	INIT_WORK(&e->scst_event_queue_work, scst_event_queue_work_fn, e);
#else
	INIT_WORK(&e->scst_event_queue_work, scst_event_queue_work_fn);
#endif

	TRACE_DBG("Scheduling event entry %p", e);

	e->event.event_code = event_code;
	strlcpy(e->event.issuer_name, issuer_name, sizeof(e->event.issuer_name));

	schedule_work(&e->scst_event_queue_work);

	TRACE_EXIT();
	return;
}
EXPORT_SYMBOL_GPL(scst_event_queue);

/* Might be called on IRQ with any lock held */
int scst_event_queue_lun_not_found(const struct scst_cmd *cmd)
{
	int res = 0, event_entry_len;
	struct scst_event_entry *event_entry;
	struct scst_event *event;
	struct scst_event_lun_not_found_payload *payload;

	TRACE_ENTRY();

	event_entry_len = sizeof(*event_entry) + sizeof(*payload);
	event_entry = kzalloc(event_entry_len, GFP_ATOMIC);
	if (event_entry == NULL) {
		PRINT_ERROR("Unable to allocate event (size %d). LUN not found "
			"event is lost (LUN %lld, initiator %s, target %s)!",
			event_entry_len, (unsigned long long int)cmd->lun,
			cmd->sess->initiator_name, cmd->tgt->tgt_name);
		res = -ENOMEM;
		goto out;
	}

	TRACE_MEM("event_entry %p (len %d) allocated", event_entry,
		event_entry_len);

	event = &event_entry->event;

	event->payload_len = sizeof(*payload);
	payload = (struct scst_event_lun_not_found_payload *)event->payload;

	payload->lun = cmd->lun;
	strlcpy(payload->initiator_name, cmd->sess->initiator_name,
		sizeof(payload->initiator_name));
	strlcpy(payload->target_name, cmd->tgt->tgt_name,
		sizeof(payload->target_name));

	scst_event_queue(SCST_EVENT_LUN_NOT_FOUND,
		SCST_EVENT_SCST_CORE_ISSUER, event_entry);

out:
	TRACE_EXIT_RES(res);
	return res;
}

int scst_event_queue_negative_luns_inquiry(const struct scst_tgt *tgt,
	const char *initiator_name)
{
	int res = 0, event_entry_len;
	struct scst_event_entry *event_entry;
	struct scst_event *event;
	struct scst_event_negative_luns_inquiry_payload *payload;

	TRACE_ENTRY();

	event_entry_len = sizeof(*event_entry) + sizeof(*payload);
	event_entry = kzalloc(event_entry_len, GFP_ATOMIC);
	if (event_entry == NULL) {
		PRINT_ERROR("Unable to allocate event (size %d). NEGATIVE LUNS "
			"INQUIRY event is lost (initiator %s, target %s)!",
			event_entry_len, initiator_name, tgt->tgt_name);
		res = -ENOMEM;
		goto out;
	}

	TRACE_MEM("event_entry %p (len %d) allocated", event_entry,
		event_entry_len);

	event = &event_entry->event;

	event->payload_len = sizeof(*payload);
	payload = (struct scst_event_negative_luns_inquiry_payload *)event->payload;

	strlcpy(payload->initiator_name, initiator_name,
		sizeof(payload->initiator_name));
	strlcpy(payload->target_name, tgt->tgt_name,
		sizeof(payload->target_name));

	scst_event_queue(SCST_EVENT_NEGATIVE_LUNS_INQUIRY,
		SCST_EVENT_SCST_CORE_ISSUER, event_entry);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* No locks */
int scst_event_queue_ext_blocking_done(struct scst_device *dev, void *data, int len)
{
	int res, event_entry_len;
	struct scst_event_entry *event_entry;
	struct scst_event *event;
	struct scst_event_ext_blocking_done_payload *payload;

	TRACE_ENTRY();

	event_entry_len = sizeof(*event_entry) + sizeof(*payload) + len;
	event_entry = kzalloc(event_entry_len, GFP_ATOMIC);
	if (event_entry == NULL) {
		PRINT_CRIT_ERROR("Unable to allocate event. Ext blocking "
			"done event is lost (device %s, size %zd)!", dev->virt_name,
			sizeof(*event_entry) + sizeof(*payload) + len);
		res = -ENOMEM;
		goto out;
	}

	TRACE_MEM("event_entry %p (len %d) allocated", event_entry,
		event_entry_len);

	event = &event_entry->event;

	event->payload_len = sizeof(*payload) + len;
	payload = (struct scst_event_ext_blocking_done_payload *)event->payload;

	strlcpy(payload->device_name, dev->virt_name, sizeof(payload->device_name));
	if (len > 0)
		memcpy(payload->data, data, len);

	scst_event_queue(SCST_EVENT_EXT_BLOCKING_DONE,
		SCST_EVENT_SCST_CORE_ISSUER, event_entry);
	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* No locks */
int scst_event_queue_tm_fn_received(struct scst_mgmt_cmd *mcmd)
{
	int res = 0, event_entry_len;
	struct scst_event_entry *event_entry;
	struct scst_event *event;
	struct scst_event_tm_fn_received_payload *payload;

	TRACE_ENTRY();

	event_entry_len = sizeof(*event_entry) + sizeof(*payload);
	event_entry = kzalloc(event_entry_len, GFP_KERNEL);
	if (event_entry == NULL) {
		PRINT_CRIT_ERROR("Unable to allocate event (size %d). External "
			"TM fn received event is lost!", event_entry_len);
		res = -ENOMEM;
		goto out;
	}

	TRACE_MEM("event_entry %p (len %d) allocated", event_entry,
		event_entry_len);

	event = &event_entry->event;

	event->payload_len = sizeof(*payload);
	payload = (struct scst_event_tm_fn_received_payload *)event->payload;

	payload->fn = mcmd->fn;
	payload->lun = mcmd->lun;
	if (mcmd->mcmd_tgt_dev != NULL)
		strlcpy(payload->device_name, mcmd->mcmd_tgt_dev->dev->virt_name,
			sizeof(payload->device_name));
	strlcpy(payload->initiator_name, mcmd->sess->initiator_name,
		sizeof(payload->initiator_name));
	strlcpy(payload->target_name, mcmd->sess->tgt->tgt_name,
		sizeof(payload->target_name));
	strlcpy(payload->session_sysfs_name, mcmd->sess->sess_name,
		sizeof(payload->session_sysfs_name));
	if (mcmd->cmd_to_abort != NULL) {
		payload->cmd_to_abort_tag = mcmd->cmd_to_abort->tag;
		strlcpy(payload->cdb, mcmd->cmd_to_abort->cdb,
			sizeof(payload->cdb));
	}

	scst_event_queue(SCST_EVENT_TM_FN_RECEIVED,
		SCST_EVENT_SCST_CORE_ISSUER, event_entry);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* scst_event_mutex supposed to be held. Can release/reacquire it inside */
static void scst_release_event_entry(struct scst_event_entry *e)
{
	TRACE_ENTRY();

	TRACE_DBG("Deleting event entry %p", e);
	list_del(&e->events_list_entry);

	if (e->event_notify_fn != NULL) {
		mutex_unlock(&scst_event_mutex);

		cancel_delayed_work_sync(&e->event_timeout_work);

		TRACE_DBG("Calling notify_fn of event_entry %p", e);
		e->event_notify_fn(&e->event, e->notify_fn_priv, -EFAULT);

		mutex_lock(&scst_event_mutex);
	}

	TRACE_MEM("Freeing notified event entry %p", e);
	kfree(e);

	TRACE_EXIT();
	return;
}

static int scst_event_release(struct inode *inode, struct file *file)
{
	struct scst_event_priv *priv;
	struct scst_event_entry *e, *et;

	TRACE_ENTRY();

	mutex_lock(&scst_event_mutex);

	priv = file->private_data;
	if (priv == NULL) {
		mutex_unlock(&scst_event_mutex);
		goto out;
	}
	file->private_data = NULL;

	list_del(&priv->privs_list_entry);

	mutex_unlock(&scst_event_mutex);

	TRACE_DBG("Going to release event priv %p", priv);

	priv->going_to_exit = 1;
	wake_up_all(&priv->queued_events_waitQ);

	list_for_each_entry_safe(e, et, &priv->allowed_events_list,
					events_list_entry) {
		TRACE_MEM("Deleting allowed event entry %p", e);
		list_del(&e->events_list_entry);
		kfree(e);
	}

	mutex_lock(&scst_event_mutex); /* to sync with timeout_work */
	while (!list_empty(&priv->queued_events_list)) {
		e = list_entry(priv->queued_events_list.next,
				typeof(*e), events_list_entry);
		scst_release_event_entry(e);
	}
	while (!list_empty(&priv->processing_events_list)) {
		e = list_entry(priv->processing_events_list.next,
				typeof(*e), events_list_entry);
		scst_release_event_entry(e);
	}
	mutex_unlock(&scst_event_mutex);

	TRACE_MEM("Deleting priv %p", priv);
	kfree(priv);

	module_put(THIS_MODULE);

out:
	TRACE_EXIT();
	return 0;
}

/*
 * scst_event_mutex supposed to be held. Caller supposed to free returned
 * out_event_entry using kfree(). This function returnes event_entry, not
 * plain event, because this entry can then be queued in some list.
 */
static int scst_event_get_event_from_user(void __user *arg,
	struct scst_event_entry **out_event_entry)
{
	int res, rc, event_entry_len;
	uint32_t payload_len;
	struct scst_event_entry *event_entry;

	TRACE_ENTRY();

	res = get_user(payload_len, (uint32_t __user *)arg);
	if (res != 0) {
		PRINT_ERROR("Failed to get payload len: %d", res);
		goto out;
	}

	if (payload_len > SCST_MAX_PAYLOAD) {
		PRINT_ERROR("Payload len %d is too big (max %d)", payload_len,
			SCST_MAX_PAYLOAD);
		res = -EINVAL;
		goto out;
	}

	TRACE_DBG("payload_len %d", payload_len);

	event_entry_len = sizeof(*event_entry) + payload_len;

	event_entry = kzalloc(event_entry_len, GFP_KERNEL);
	if (event_entry == NULL) {
		PRINT_ERROR("Unable to allocate event entry (size %d)",
			event_entry_len);
		res = -ENOMEM;
		goto out;
	}

	TRACE_MEM("Allocated event entry %p", event_entry);

	rc = copy_from_user(&event_entry->event, arg,
		sizeof(event_entry->event) + payload_len);
	if (rc != 0) {
		PRINT_ERROR("Failed to copy %d user's bytes", rc);
		res = -EFAULT;
		goto out_free;
	}

	event_entry->event.issuer_name[sizeof(event_entry->event.issuer_name)-1] = '\0';

	TRACE_DBG("user event: event_code %d, issuer_name %s",
		event_entry->event.event_code, event_entry->event.issuer_name);

	*out_event_entry = event_entry;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	TRACE_MEM("Deleting event entry %p", event_entry);
	kfree(event_entry);
	goto out;
}

/* scst_event_mutex supposed to be held */
static int scst_event_allow_event(struct scst_event_priv *priv, void __user *arg)
{
	int res;
	struct scst_event_entry *event_entry, *e;

	TRACE_ENTRY();

	res = scst_event_get_event_from_user(arg, &event_entry);
	if (res != 0)
		goto out;

	list_for_each_entry(e, &priv->allowed_events_list, events_list_entry) {
		if (scst_event_cmp(&event_entry->event, &e->event)) {
			PRINT_WARNING("Allowed event (event_code %d, "
				"issuer_name %s) already exists",
				e->event.event_code, e->event.issuer_name);
			res = -EEXIST;
			goto out_free;
		}
	}

	if (priv->allowed_events_cnt >= SCST_MAX_EVENTS) {
		PRINT_ERROR("Too many allowed events %d",
			priv->allowed_events_cnt);
		res = -EMFILE;
		goto out_free;
	}

	list_add_tail(&event_entry->events_list_entry,
		&priv->allowed_events_list);
	priv->allowed_events_cnt++;
	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free:
	TRACE_MEM("Deleting event entry %p", event_entry);
	kfree(event_entry);
	goto out;
}

/* scst_event_mutex supposed to be held */
static int scst_event_disallow_event(struct scst_event_priv *priv,
	void __user *arg)
{
	int res;
	struct scst_event_entry *event_entry, *e, *et;
	bool found = false;

	TRACE_ENTRY();

	res = scst_event_get_event_from_user(arg, &event_entry);
	if (res != 0)
		goto out;

	/* For wildcard events we might delete several events */
	list_for_each_entry_safe(e, et, &priv->allowed_events_list,
					events_list_entry) {
		if (scst_event_cmp(&event_entry->event, &e->event)) {
			PRINT_INFO("Deleting allowed event (event_code %d, "
				"issuer_name %s)", e->event.event_code,
				e->event.issuer_name);
			TRACE_MEM("Deleting event entry %p", e);
			list_del(&e->events_list_entry);
			kfree(e);
			priv->allowed_events_cnt--;
			found = true;
		}
	}
	if (!found) {
		PRINT_WARNING("Allowed event (event_code %d, issuer_name %s) "
			"not found", event_entry->event.event_code,
			event_entry->event.issuer_name);
		res = -ENOENT;
	} else
		res = 0;

	TRACE_MEM("Deleting event entry %p", e);
	kfree(event_entry);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* scst_event_mutex supposed to be held. Might drop it, then get back. */
static int scst_event_user_next_event(struct scst_event_priv *priv,
	void __user *arg)
{
	int res, rc;
	int32_t max_event_size, needed_size;
	struct scst_event_entry *event_entry;
	struct scst_event_user __user *event_user = arg;

	TRACE_ENTRY();

	res = get_user(max_event_size, (int32_t __user *)arg);
	if (res != 0) {
		PRINT_ERROR("Failed to get max event size: %d", res);
		goto out;
	};

	/* Waiting for at least one event, if blocking */
	while (list_empty(&priv->queued_events_list)) {
		mutex_unlock(&scst_event_mutex);
		wait_event_interruptible(priv->queued_events_waitQ,
			(!list_empty(&priv->queued_events_list) || priv->going_to_exit ||
			 !priv->blocking || signal_pending(current)));
		mutex_lock(&scst_event_mutex);
		if (priv->going_to_exit || signal_pending(current)) {
			res = -EINTR;
			TRACE_DBG("Signal pending or going_to_exit (%d), returning",
				priv->going_to_exit);
			goto out;
		} else if (list_empty(&priv->queued_events_list) && !priv->blocking) {
			res = -EAGAIN;
			TRACE_DBG("Nothing pending, returning %d", res);
			goto out;
		}
	}

	EXTRACHECKS_BUG_ON(list_empty(&priv->queued_events_list));

	event_entry = list_entry(priv->queued_events_list.next,
			struct scst_event_entry, events_list_entry);

	needed_size = sizeof(event_entry->event) + event_entry->event.payload_len;

	if (needed_size > max_event_size) {
		TRACE_DBG("Too big event (size %d, max size %d)", needed_size,
			max_event_size);
		res = put_user(needed_size, (int32_t __user *)arg);
		if (res == 0)
			res = -ENOSPC;
		goto out;
	}

	rc = copy_to_user(&event_user->out_event, &event_entry->event, needed_size);
	if (rc != 0) {
		PRINT_ERROR("Copy to user failed (%d)", rc);
		res = -EFAULT;
		goto out;
	}

	if (event_entry->event_notify_fn) {
		TRACE_DBG("Moving event entry %p to processing events list",
			event_entry);
		list_move_tail(&event_entry->events_list_entry,
			&priv->processing_events_list);
	} else {
		TRACE_MEM("Deleting event entry %p", event_entry);
		list_del(&event_entry->events_list_entry);
		kfree(event_entry);
	}

	priv->queued_events_cnt--;

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* scst_event_mutex supposed to be held. Might drop it, then get back. */
static int scst_event_user_notify_done(struct scst_event_priv *priv,
	void __user *arg)
{
	int res, rc;
	struct scst_event_notify_done n;
	struct scst_event_entry *e;
	bool found = false;

	TRACE_ENTRY();

	rc = copy_from_user(&n, arg, sizeof(n));
	if (rc != 0) {
		PRINT_ERROR("Failed to copy %d user's bytes of notify done", rc);
		res = -EFAULT;
		goto out;
	}

	res = 0;

	list_for_each_entry(e, &priv->processing_events_list, events_list_entry) {
		if (e->event.event_id == n.event_id) {
			found = true;
			break;
		}
	}
	if (!found) {
		PRINT_ERROR("Waiting event for id %u not found", n.event_id);
		res = -ENOENT;
		goto out;
	}

	list_del_init(&e->events_list_entry);

	mutex_unlock(&scst_event_mutex);

	cancel_delayed_work_sync(&e->event_timeout_work);

	if (e->event_notify_fn != NULL) {
		TRACE_DBG("Calling notify_fn of event_entry %p", e);
		e->event_notify_fn(&e->event, e->notify_fn_priv, n.status);
	}

	TRACE_MEM("Freeing event entry %p", e);
	kfree(e);

	/* Lock it back, because we expected to do so */
	mutex_lock(&scst_event_mutex);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/* scst_event_mutex supposed to be held */
static int scst_event_create_priv(struct file *file)
{
	int res;
	struct scst_event_priv *priv;

	TRACE_ENTRY();

	EXTRACHECKS_BUG_ON(file->private_data != NULL);

	if (!try_module_get(THIS_MODULE)) {
		PRINT_ERROR("Fail to get module");
		res = -ETXTBSY;
		goto out;
	}

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (priv == NULL) {
		PRINT_ERROR("Unable to allocate priv (size %zd)",
			sizeof(*priv));
		res = -ENOMEM;
		goto out_put;
	}

	TRACE_MEM("priv %p allocated", priv);

	priv->owner_pid = current->pid;
	INIT_LIST_HEAD(&priv->allowed_events_list);
	init_waitqueue_head(&priv->queued_events_waitQ);
	INIT_LIST_HEAD(&priv->queued_events_list);
	INIT_LIST_HEAD(&priv->processing_events_list);
	if (file->f_flags & O_NONBLOCK) {
		TRACE_DBG("%s", "Non-blocking operations");
		priv->blocking = 0;
	} else
		priv->blocking = 1;

	list_add_tail(&priv->privs_list_entry, &scst_event_privs_list);

	file->private_data = priv;

	res = 0;

out:
	TRACE_EXIT_RES(res);
	return res;

out_put:
	module_put(THIS_MODULE);
	goto out;
}

static long scst_event_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg)
{
	long res;
	struct scst_event_priv *priv;

	TRACE_ENTRY();

	mutex_lock(&scst_event_mutex);

	priv = file->private_data;
	if (unlikely(priv == NULL)) {
		/* This is the first time we are here */
		res = scst_event_create_priv(file);
		if (res != 0)
			goto out_unlock;
		priv = file->private_data;
	}

	TRACE_DBG("priv %p", priv);

	/*
	 * Handler functions called under scst_event_mutex for their
	 * convenience only, because they would need to reacquire it back again
	 * anyway. It has nothing common with protecting private_data, which
	 * protected from release() by the file reference counting.
	 */

	switch (cmd) {
	case SCST_EVENT_ALLOW_EVENT:
		TRACE_DBG("%s", "ALLOW_EVENT");
		res = scst_event_allow_event(priv, (void __user *)arg);
		break;

	case SCST_EVENT_DISALLOW_EVENT:
		TRACE_DBG("%s", "DISALLOW_EVENT");
		res = scst_event_disallow_event(priv, (void __user *)arg);
		break;

	case SCST_EVENT_GET_NEXT_EVENT:
		TRACE_DBG("%s", "GET_NEXT_EVENT");
		res = scst_event_user_next_event(priv, (void __user *)arg);
		break;

	case SCST_EVENT_NOTIFY_DONE:
		TRACE_DBG("%s", "NOTIFY_DONE");
		res = scst_event_user_notify_done(priv, (void __user *)arg);
		break;

	default:
		PRINT_ERROR("Invalid ioctl cmd %x", cmd);
		res = -EINVAL;
		goto out_unlock;
	}

out_unlock:
	mutex_unlock(&scst_event_mutex);

	TRACE_EXIT_RES(res);
	return res;
}

static unsigned int scst_event_poll(struct file *file, poll_table *wait)
{
	int res = 0;
	struct scst_event_priv *priv;

	TRACE_ENTRY();

	mutex_lock(&scst_event_mutex);

	priv = file->private_data;
	if (unlikely(priv == NULL)) {
		PRINT_ERROR("At least one allowed event must be set");
		res = -EINVAL;
		goto out_unlock;
	}

	if (!list_empty(&priv->queued_events_list)) {
		res |= POLLIN | POLLRDNORM;
		goto out_unlock;
	}

	mutex_unlock(&scst_event_mutex);

	TRACE_DBG("Before poll_wait() (priv %p)", priv);
	poll_wait(file, &priv->queued_events_waitQ, wait);
	TRACE_DBG("After poll_wait() (priv %p)", priv);

	mutex_lock(&scst_event_mutex);

	if (!list_empty(&priv->queued_events_list)) {
		res |= POLLIN | POLLRDNORM;
		goto out_unlock;
	}

out_unlock:
	mutex_unlock(&scst_event_mutex);

	TRACE_EXIT_HRES(res);
	return res;
}

#if 0
#define CONFIG_EVENTS_WAIT_TEST
#endif

#ifdef CONFIG_EVENTS_WAIT_TEST
static void scst_event_test_notify_fn(struct scst_event *event,
	void *priv, int status)
{
	TRACE_ENTRY();

	PRINT_INFO("Notification for event %u (id %d) received with status %d "
		"(priv %p)", event->event_code, event->event_id, status,
		priv);

	TRACE_EXIT();
	return;
}

static ssize_t event_wait_test_store(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	int res = 0, event_entry_len;
	struct scst_event_entry *event_entry;

	TRACE_ENTRY();

	event_entry_len = sizeof(*event_entry);
	event_entry = kzalloc(event_entry_len, GFP_KERNEL);
	if (event_entry == NULL) {
		PRINT_ERROR("Unable to allocate event (size %d). Test "
			"event is lost!", event_entry_len);
		res = -ENOMEM;
		goto out;
	}

	TRACE_MEM("event_entry %p (len %d) allocated", event_entry,
		event_entry_len);

	event_entry->event_notify_fn = scst_event_test_notify_fn;
	event_entry->event_timeout = 10*HZ;

	scst_event_queue(0x12345, SCST_EVENT_SCST_CORE_ISSUER, event_entry);

	if (res == 0)
		res = count;

out:
	TRACE_EXIT_RES(res);
	return res;
}

static struct kobj_attribute event_wait_test_attr =
	__ATTR(event_wait_test, S_IWUSR, NULL, event_wait_test_store);

#endif /* #ifdef CONFIG_EVENTS_WAIT_TEST */

static const struct file_operations scst_event_fops = {
	.poll		= scst_event_poll,
	.unlocked_ioctl	= scst_event_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= scst_event_ioctl,
#endif
	.release	= scst_event_release,
};

int scst_event_init(void)
{
	int res = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 21)
	struct class_device *class_member;
#else
	struct device *dev;
#endif

	TRACE_ENTRY();

	scst_event_sysfs_class = class_create(THIS_MODULE, SCST_EVENT_NAME);
	if (IS_ERR(scst_event_sysfs_class)) {
		PRINT_ERROR("%s", "Unable create sysfs class for SCST event");
		res = PTR_ERR(scst_event_sysfs_class);
		goto out;
	}

	scst_event_major = register_chrdev(0, SCST_EVENT_NAME, &scst_event_fops);
	if (scst_event_major < 0) {
		PRINT_ERROR("register_chrdev() failed: %d", res);
		res = scst_event_major;
		goto out_class;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 21)
	class_member = class_device_create(scst_event_sysfs_class, NULL,
					   MKDEV(scst_event_major, 0), NULL,
					   SCST_EVENT_NAME);
	if (IS_ERR(class_member)) {
		res = PTR_ERR(class_member);
		goto out_chrdev;
	}
#else
	dev = device_create(scst_event_sysfs_class, NULL,
			    MKDEV(scst_event_major, 0),
				NULL,
				SCST_EVENT_NAME);
	if (IS_ERR(dev)) {
		res = PTR_ERR(dev);
		goto out_chrdev;
	}
#endif

#ifdef CONFIG_EVENTS_WAIT_TEST
	sysfs_create_file(kernel_kobj, &event_wait_test_attr.attr);
#endif

out:
	TRACE_EXIT_RES(res);
	return res;


out_chrdev:
	unregister_chrdev(scst_event_major, SCST_EVENT_NAME);

out_class:
	class_destroy(scst_event_sysfs_class);
	goto out;
}

void scst_event_exit(void)
{
	TRACE_ENTRY();

#ifdef CONFIG_EVENTS_WAIT_TEST
	sysfs_remove_file(kernel_kobj, &event_wait_test_attr.attr);
#endif

	unregister_chrdev(scst_event_major, SCST_EVENT_NAME);

	device_destroy(scst_event_sysfs_class, MKDEV(scst_event_major, 0));
	class_destroy(scst_event_sysfs_class);

	/* Wait for all pending being queued events to process */
	flush_scheduled_work();

	TRACE_EXIT();
	return;
}
