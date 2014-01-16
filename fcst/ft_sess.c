/*
 * Copyright (c) 2010 Cisco Systems, Inc.
 *
 * This program is free software; you may redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
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
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/hash.h>
#include <asm/unaligned.h>
#include <scsi/libfc.h>
#include <scsi/fc/fc_els.h>
#include "fcst.h"

static void ft_sess_put(struct ft_sess *sess);

static int ft_tport_count;

static ssize_t ft_format_wwn(char *buf, size_t len, u64 wwn)
{
	u8 b[8];

	put_unaligned_be64(wwn, b);
	return snprintf(buf, len,
		 "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
		 b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
}

/*
 * Lookup or allocate target local port.
 * Caller holds ft_lport_lock.
 */
static struct ft_tport *ft_tport_create(struct fc_lport *lport)
{
	struct ft_tport *tport;
	char name[FT_NAMELEN];
	int i;

	ft_format_wwn(name, sizeof(name), lport->wwpn);
	FT_SESS_DBG("create %s\n", name);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	tport = rcu_dereference_protected(lport->prov[FC_TYPE_FCP],
					  lockdep_is_held(&ft_lport_lock));
#else
	tport = rcu_dereference(lport->prov[FC_TYPE_FCP]);
#endif
	if (tport) {
		FT_SESS_DBG("tport alloc %s - already setup\n", name);
		return tport;
	}

	tport = kzalloc(sizeof(*tport), GFP_KERNEL);
	if (!tport) {
		FT_SESS_DBG("tport alloc %s failed\n", name);
		return NULL;
	}

	tport->tgt = scst_register_target(&ft_scst_template, name);
	if (!tport->tgt) {
		FT_SESS_DBG("register_target %s failed\n", name);
		kfree(tport);
		return NULL;
	}
	scst_tgt_set_tgt_priv(tport->tgt, tport);
	ft_tport_count++;

	tport->lport = lport;
	for (i = 0; i < FT_SESS_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&tport->hash[i]);

	rcu_assign_pointer(lport->prov[FC_TYPE_FCP], tport);
	FT_SESS_DBG("register_target %s succeeded\n", name);
	return tport;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
/*
 * Free tport via RCU.
 */
static void ft_tport_rcu_free(struct rcu_head *rcu)
{
	struct ft_tport *tport = container_of(rcu, struct ft_tport, rcu);

	kfree(tport);
}
#endif

/*
 * Delete target local port, if any, associated with the local port.
 * Caller holds ft_lport_lock.
 */
static void ft_tport_delete(struct ft_tport *tport)
{
	struct fc_lport *lport;
	struct scst_tgt *tgt;

	tgt = tport->tgt;
	BUG_ON(!tgt);
	FT_SESS_DBG("delete %s\n", scst_get_tgt_name(tgt));
	scst_unregister_target(tgt);
	lport = tport->lport;
	BUG_ON(tport != lport->prov[FC_TYPE_FCP]);
	rcu_assign_pointer(lport->prov[FC_TYPE_FCP], NULL);
	tport->lport = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
	kfree_rcu(tport, rcu);
#else
	call_rcu(&tport->rcu, ft_tport_rcu_free);
#endif
	ft_tport_count--;
}

/*
 * Add local port.
 * Called thru fc_lport_iterate().
 */
void ft_lport_add(struct fc_lport *lport, void *arg)
{
	mutex_lock(&ft_lport_lock);
	ft_tport_create(lport);
	mutex_unlock(&ft_lport_lock);
}

/*
 * Delete local port.
 * Called thru fc_lport_iterate().
 */
void ft_lport_del(struct fc_lport *lport, void *arg)
{
	struct ft_tport *tport;

	mutex_lock(&ft_lport_lock);
	tport = lport->prov[FC_TYPE_FCP];
	if (tport)
		ft_tport_delete(tport);
	mutex_unlock(&ft_lport_lock);
}

/*
 * Notification of local port change from libfc.
 * Create or delete local port and associated tport.
 */
int ft_lport_notify(struct notifier_block *nb, unsigned long event, void *arg)
{
	struct fc_lport *lport = arg;

	switch (event) {
	case FC_LPORT_EV_ADD:
		ft_lport_add(lport, NULL);
		break;
	case FC_LPORT_EV_DEL:
		ft_lport_del(lport, NULL);
		break;
	}
	return NOTIFY_DONE;
}

/*
 * Hash function for FC_IDs.
 */
static u32 ft_sess_hash(u32 port_id)
{
	return hash_32(port_id, FT_SESS_HASH_BITS);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0) &&		      \
	! (LINUX_VERSION_CODE >> 8 == KERNEL_VERSION(3, 4, 0) >> 8 && \
	   LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 41)) &&	      \
	! (LINUX_VERSION_CODE >> 8 == KERNEL_VERSION(3, 2, 0) >> 8 && \
	   LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 44)) &&	      \
	!defined(CONFIG_SUSE_KERNEL)
/*
 * See also commit 4b20db3 (kref: Implement kref_get_unless_zero v3 -- v3.8).
 * See also commit e3a5505 in branch stable/linux-3.4.y (v3.4.41).
 * See also commit 3fa8ee5 in branch stable/linux-3.2.y (v3.2.44).
 */
static inline int __must_check kref_get_unless_zero(struct kref *kref)
{
	return atomic_add_unless(&kref->refcount, 1, 0);
}
#endif

/*
 * Find session in local port.
 * Sessions and hash lists are RCU-protected.
 * A reference is taken which must be eventually freed.
 */
static struct ft_sess *ft_sess_get(struct fc_lport *lport, u32 port_id)
{
	struct ft_tport *tport;
	struct hlist_head *head;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *pos;
#endif
	struct ft_sess *sess;

	rcu_read_lock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	tport = rcu_dereference_protected(lport->prov[FC_TYPE_FCP], true);
#else
	tport = rcu_dereference(lport->prov[FC_TYPE_FCP]);
#endif
	if (!tport)
		goto out;

	head = &tport->hash[ft_sess_hash(port_id)];
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry_rcu(sess, pos, head, hash) {
#else
	hlist_for_each_entry_rcu(sess, head, hash) {
#endif
		if (sess->port_id == port_id) {
			if (!kref_get_unless_zero(&sess->kref))
				sess = NULL;
			rcu_read_unlock();
			FT_SESS_DBG("port_id %x found %p\n", port_id, sess);
			return sess;
		}
	}
out:
	rcu_read_unlock();
	FT_SESS_DBG("port_id %x not found\n", port_id);
	return NULL;
}

/*
 * Allocate session and enter it in the hash for the local port.
 * Caller holds ft_lport_lock.
 */
static int ft_sess_create(struct ft_tport *tport, struct fc_rport_priv *rdata,
			  u32 fcp_parm)
{
	struct ft_sess *sess;
	struct scst_session *scst_sess;
	struct hlist_head *head;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *pos;
#endif
	u32 port_id;
	char name[FT_NAMELEN];

	port_id = rdata->ids.port_id;
	if (!rdata->maxframe_size) {
		FT_SESS_DBG("port_id %x maxframe_size 0\n", port_id);
		return FC_SPP_RESP_CONF;
	}

	head = &tport->hash[ft_sess_hash(port_id)];
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry_rcu(sess, pos, head, hash) {
#else
	hlist_for_each_entry_rcu(sess, head, hash) {
#endif
		if (sess->port_id == port_id) {
			sess->params = fcp_parm;
			return 0;
		}
	}

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess)
		return FC_SPP_RESP_RES;		/* out of resources */

	sess->port_name = rdata->ids.port_name;
	sess->max_payload = rdata->maxframe_size;
	sess->max_lso_payload = rdata->maxframe_size;
	if (tport->lport->seq_offload)
		sess->max_lso_payload = tport->lport->lso_max;
	sess->params = fcp_parm;
	sess->tport = tport;
	sess->port_id = port_id;
	kref_init(&sess->kref);			/* ref for table entry */

	ft_format_wwn(name, sizeof(name), rdata->ids.port_name);
	FT_SESS_DBG("register %s\n", name);
	scst_sess = scst_register_session(tport->tgt, 0, name, sess, NULL,
					  NULL);
	if (!scst_sess) {
		kfree(sess);
		return FC_SPP_RESP_RES;		/* out of resources */
	}
	sess->scst_sess = scst_sess;
	hlist_add_head_rcu(&sess->hash, head);
	tport->sess_count++;

	FT_SESS_DBG("port_id %x sess %p\n", port_id, sess);

	rdata->prli_count++;
	return 0;
}

/*
 * Unhash the session.
 * Caller holds ft_lport_lock.
 */
static void ft_sess_unhash(struct ft_sess *sess)
{
	struct ft_tport *tport = sess->tport;

	hlist_del_rcu(&sess->hash);
	BUG_ON(!tport->sess_count);
	tport->sess_count--;
	sess->port_id = -1;
	sess->params = 0;
}

/*
 * Delete session from hash.
 * Caller holds ft_lport_lock.
 */
static struct ft_sess *ft_sess_delete(struct ft_tport *tport, u32 port_id)
{
	struct hlist_head *head;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *pos;
#endif
	struct ft_sess *sess;

	head = &tport->hash[ft_sess_hash(port_id)];
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry_rcu(sess, pos, head, hash) {
#else
	hlist_for_each_entry_rcu(sess, head, hash) {
#endif
		if (sess->port_id == port_id) {
			ft_sess_unhash(sess);
			return sess;
		}
	}
	return NULL;
}

/*
 * Remove session and send PRLO.
 * This is called when the target is being deleted.
 * Caller holds ft_lport_lock.
 */
static void ft_sess_close(struct ft_sess *sess)
{
	struct fc_lport *lport;
	u32 port_id;

	lport = sess->tport->lport;
	port_id = sess->port_id;
	if (port_id == -1)
		return;
	FT_SESS_DBG("port_id %x\n", port_id);
	ft_sess_unhash(sess);
	ft_sess_put(sess);
	/* XXX should send LOGO or PRLO to rport */
}

/*
 * Allocate and fill in the SPC Transport ID for persistent reservations.
 */
int ft_get_transport_id(struct scst_tgt *tgt, struct scst_session *scst_sess,
	uint8_t **result)
{
	struct ft_sess *sess;
	struct {
		u8	format_proto;	/* format and protocol ID (0 for FC) */
		u8	__resv1[7];
		__be64	port_name;	/* N_Port Name */
		u8	__resv2[8];
	} __attribute__((__packed__)) *id;

	if (!scst_sess)
		return SCSI_TRANSPORTID_PROTOCOLID_FCP2;

	id = kzalloc(sizeof(*id), GFP_KERNEL);
	if (!id)
		return -ENOMEM;

	sess = scst_sess_get_tgt_priv(scst_sess);
	id->port_name = cpu_to_be64(sess->port_name);
	id->format_proto = SCSI_TRANSPORTID_PROTOCOLID_FCP2;
	*result = (uint8_t *)id;
	return 0;
}

/*
 * libfc ops involving sessions.
 */

/*
 * Handle PRLI (process login) request.
 * This could be a PRLI we're sending or receiving.
 * Caller holds ft_lport_lock.
 */
static int ft_prli_locked(struct fc_rport_priv *rdata, u32 spp_len,
			  const struct fc_els_spp *rspp, struct fc_els_spp *spp)
{
	struct ft_tport *tport;
	u32 fcp_parm;
	int ret;

	if (!rspp)
		goto fill;

	if (rspp->spp_flags & (FC_SPP_OPA_VAL | FC_SPP_RPA_VAL))
		return FC_SPP_RESP_NO_PA;

	/*
	 * If both target and initiator bits are off, the SPP is invalid.
	 */
	fcp_parm = ntohl(rspp->spp_params);
	if (!(fcp_parm & (FCP_SPPF_INIT_FCN | FCP_SPPF_TARG_FCN)))
		return FC_SPP_RESP_INVL;

	/*
	 * Create session (image pair) only if requested by
	 * EST_IMG_PAIR flag and if the requestor is an initiator.
	 */
	if (rspp->spp_flags & FC_SPP_EST_IMG_PAIR) {
		spp->spp_flags |= FC_SPP_EST_IMG_PAIR;

		if (!(fcp_parm & FCP_SPPF_INIT_FCN))
			return FC_SPP_RESP_CONF;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
		tport = rcu_dereference_protected(
					rdata->local_port->prov[FC_TYPE_FCP],
					lockdep_is_held(&ft_lport_lock));
#else
		tport = rcu_dereference(rdata->local_port->prov[FC_TYPE_FCP]);
#endif
		if (!tport) {
			/* not a target for this local port */
			return FC_SPP_RESP_CONF;
		}
		if (!tport->enabled) {
			pr_err("Refused login from %#x because target port %s"
			       " not yet enabled", rdata->ids.port_id,
			       tport->tgt->tgt_name);
			return FC_SPP_RESP_CONF;
		}
		ret = ft_sess_create(tport, rdata, fcp_parm);
		if (ret)
			return ret;
	}

	/*
	 * OR in our service parameters with other provider (initiator), if any.
	 * If the initiator indicates RETRY, we must support that, too.
	 * Don't force RETRY on the initiator, though.
	 */
fill:
	fcp_parm = ntohl(spp->spp_params);
	spp->spp_params = htonl(fcp_parm | FCP_SPPF_TARG_FCN);
	return FC_SPP_RESP_ACK;
}

/**
 * tcm_fcp_prli() - Handle incoming or outgoing PRLI for the FCP target
 * @rdata: remote port private
 * @spp_len: service parameter page length
 * @rspp: received service parameter page (NULL for outgoing PRLI)
 * @spp: response service parameter page
 *
 * Returns spp response code.
 */
static int ft_prli(struct fc_rport_priv *rdata, u32 spp_len,
		   const struct fc_els_spp *rspp, struct fc_els_spp *spp)
{
	int ret;

	mutex_lock(&ft_lport_lock);
	ret = ft_prli_locked(rdata, spp_len, rspp, spp);
	mutex_unlock(&ft_lport_lock);
	FT_SESS_DBG("port_id %x flags %x ret %x\n",
	       rdata->ids.port_id, rspp ? rspp->spp_flags : 0, ret);
	return ret;
}

static void ft_sess_rcu_free(struct rcu_head *rcu)
{
	struct ft_sess *sess = container_of(rcu, struct ft_sess, rcu);

	kfree(sess);
}

static void ft_sess_free(struct kref *kref)
{
	struct ft_sess *sess = container_of(kref, struct ft_sess, kref);
	struct scst_session *scst_sess;

	scst_sess = sess->scst_sess;
	FT_SESS_DBG("unregister %s\n", scst_sess->initiator_name);
	scst_unregister_session(scst_sess, 0, NULL);
	call_rcu(&sess->rcu, ft_sess_rcu_free);
}

static void ft_sess_put(struct ft_sess *sess)
{
	BUG_ON(!sess);
	BUG_ON(atomic_read(&sess->kref.refcount) <= 0);
	kref_put(&sess->kref, ft_sess_free);
}

static void ft_prlo(struct fc_rport_priv *rdata)
{
	struct ft_sess *sess;
	struct ft_tport *tport;

	mutex_lock(&ft_lport_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	tport = rcu_dereference_protected(rdata->local_port->prov[FC_TYPE_FCP],
					  lockdep_is_held(&ft_lport_lock));
#else
	tport = rcu_dereference(rdata->local_port->prov[FC_TYPE_FCP]);
#endif
	if (!tport) {
		mutex_unlock(&ft_lport_lock);
		return;
	}
	sess = ft_sess_delete(tport, rdata->ids.port_id);
	if (!sess) {
		mutex_unlock(&ft_lport_lock);
		return;
	}
	mutex_unlock(&ft_lport_lock);

	ft_sess_put(sess);		/* release from table */
	rdata->prli_count--;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36) && !defined(RHEL_MAJOR)
static inline u32 fc_frame_sid(const struct fc_frame *fp)
{
	return ntoh24(fc_frame_header_get(fp)->fh_s_id);
}
#endif

/*
 * Handle incoming FCP request.
 * Caller has verified that the frame is type FCP.
 * Note that this may be called directly from the softirq context.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36) \
	&& (!defined(RHEL_MAJOR) || RHEL_MAJOR -0 <= 5)
static void ft_recv(struct fc_lport *lport, struct fc_seq *sp,
		    struct fc_frame *fp)
#else
static void ft_recv(struct fc_lport *lport, struct fc_frame *fp)
#endif
{
	struct ft_sess *sess;
	u32 sid = fc_frame_sid(fp);

	FT_SESS_DBG("sid %x preempt %x\n", sid, preempt_count());

	sess = ft_sess_get(lport, sid);
	if (!sess) {
		FT_SESS_DBG("sid %x sess lookup failed\n", sid);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36) \
	&& (!defined(RHEL_MAJOR) || RHEL_MAJOR -0 <= 5)
		lport->tt.exch_done(sp);
#endif
		/* TBD XXX - if FCP_CMND, send LOGO */
		fc_frame_free(fp);
		return;
	}
	FT_SESS_DBG("sid %x sess lookup returned %p preempt %x\n",
			sid, sess, preempt_count());
	ft_recv_req(sess, fp);
	ft_sess_put(sess);
}

/*
 * Release all sessions for a target.
 * Called through scst_unregister_target() as well as directly.
 * Caller holds ft_lport_lock.
 */
int ft_tgt_release(struct scst_tgt *tgt)
{
	struct ft_tport *tport;
	struct hlist_head *head;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *pos;
#endif
	struct ft_sess *sess;

	tport = scst_tgt_get_tgt_priv(tgt);
	tport->enabled = 0;
	tport->lport->service_params &= ~FCP_SPPF_TARG_FCN;

	for (head = tport->hash; head < &tport->hash[FT_SESS_HASH_SIZE]; head++)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
		hlist_for_each_entry_rcu(sess, pos, head, hash)
#else
		hlist_for_each_entry_rcu(sess, head, hash)
#endif
			ft_sess_close(sess);

	synchronize_rcu();
	return 0;
}

/* Caller must hold a reference on tgt->tgt_kobj. */
int ft_tgt_enable(struct scst_tgt *tgt, bool enable)
{
	struct ft_tport *tport;
	int ret = 0;

	if (enable) {
		FT_SESS_DBG("enable tgt %s\n", tgt->tgt_name);
		tport = scst_tgt_get_tgt_priv(tgt);
		if (tport == NULL) {
			ret = -E_TGT_PRIV_NOT_YET_SET;
			goto out;
		}
		tport->enabled = 1;
		tport->lport->service_params |= FCP_SPPF_TARG_FCN;
	} else {
		FT_SESS_DBG("disable tgt %s\n", tgt->tgt_name);
		ft_tgt_release(tgt);
	}

out:
	return ret;
}

bool ft_tgt_enabled(struct scst_tgt *tgt)
{
	struct ft_tport *tport;

	if (tgt == NULL)
		return false;

	tport = scst_tgt_get_tgt_priv(tgt);
	return tport->enabled;
}

int ft_tgt_detect(struct scst_tgt_template *tt)
{
	return ft_tport_count;
}

/*
 * Report AEN (Asynchronous Event Notification) from device to initiator.
 * See notes in scst.h.
 */
int ft_report_aen(struct scst_aen *aen)
{
	struct ft_sess *sess;

	sess = scst_sess_get_tgt_priv(scst_aen_get_sess(aen));
	FT_SESS_DBG("AEN event %d sess to %x lun %lld\n",
		    aen->event_fn, sess->port_id, scst_aen_get_lun(aen));
	return SCST_AEN_RES_FAILED;	/* XXX TBD */
}

/*
 * Provider ops for libfc.
 */
struct fc4_prov ft_prov = {
	.prli = ft_prli,
	.prlo = ft_prlo,
	.recv = ft_recv,
	.module = THIS_MODULE,
};
