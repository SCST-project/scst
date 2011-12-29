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
 *
 * $Id$
 */
#ifndef __SCSI_FCST_H__
#define __SCSI_FCST_H__

#ifdef INSIDE_KERNEL_TREE
#include <scst/scst.h>
#else
#include <linux/version.h>
#include "scst.h"
#endif

#define FT_VERSION	"0.3"
#define FT_MODULE	"fcst"

#define FT_MAX_HW_PENDING_TIME	20	/* max I/O time in seconds */

/*
 * Debug options.
 */
#define FT_DEBUG_CONF	0x01	/* configuration messages */
#define FT_DEBUG_SESS	0x02	/* session messages */
#define FT_DEBUG_IO	0x04	/* I/O operations */

extern unsigned int ft_debug_logging;	/* debug options */

#define FT_ERR(fmt, args...)						\
	printk(KERN_ERR FT_MODULE ": %s: " fmt, __func__, ##args)

#define FT_DEBUG(mask, fmt, args...)					\
	do {								\
		if (ft_debug_logging & (mask))				\
			printk(KERN_INFO FT_MODULE ": %s: " fmt,	\
			       __func__, ##args);			\
	} while (0)

#define FT_CONF_DBG(fmt, args...)	FT_DEBUG(FT_DEBUG_CONF, fmt, ##args)
#define FT_SESS_DBG(fmt, args...)	FT_DEBUG(FT_DEBUG_SESS, fmt, ##args)
#define FT_IO_DBG(fmt, args...)		FT_DEBUG(FT_DEBUG_IO, fmt, ##args)

#define FT_NAMELEN	32		/* length of ASCI WWPNs including pad */

/*
 * Session (remote port).
 */
struct ft_sess {
	u32 port_id;			/* for hash lookup use only */
	u32 params;
	u16 max_payload;		/* max transmitted payload size */
	u32 max_lso_payload;		/* max offloaded payload size */
	u64 port_name;			/* port name for transport ID */
	struct ft_tport *tport;
	struct hlist_node hash;		/* linkage in ft_sess_hash table */
	struct rcu_head rcu;
	struct kref kref;		/* ref for hash and outstanding I/Os */
	struct scst_session *scst_sess;
};

/*
 * Hash table of sessions per local port.
 * Hash lookup by remote port FC_ID.
 */
#define FT_SESS_HASH_BITS	6
#define FT_SESS_HASH_SIZE	(1 << FT_SESS_HASH_BITS)

/*
 * Per local port data.
 * This is created when the first session logs into the local port.
 * Deleted when tpg is deleted or last session is logged off.
 */
struct ft_tport {
	u32	sess_count;		/* number of sessions in hash */
	u8	enabled:1;
	struct rcu_head rcu;
	struct hlist_head hash[FT_SESS_HASH_SIZE];	/* list of sessions */
	struct fc_lport *lport;
	struct scst_tgt *tgt;
};

/*
 * Commands
 */
struct ft_cmd {
	int serial;			/* order received, for debugging */
	struct fc_seq *seq;		/* sequence in exchange mgr */
	struct fc_frame *req_frame;	/* original request frame */
	u32 write_data_len;		/* data received from initiator */
	u32 read_data_len;		/* data sent to initiator */
	u32 xfer_rdy_len;		/* max xfer ready offset */
	u32 max_lso_payload;		/* max offloaded (LSO) data payload */
	u16 max_payload;		/* max transmitted data payload */
	struct scst_cmd *scst_cmd;
};

extern struct list_head ft_lport_list;
extern struct mutex ft_lport_lock;
extern struct scst_tgt_template ft_scst_template;

/*
 * libfc interface.
 */
int ft_prli(struct fc_rport_priv *, u32 spp_len,
	    const struct fc_els_spp *, struct fc_els_spp *);
void ft_prlo(struct fc_rport_priv *);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36) \
	&& (!defined(RHEL_MAJOR) || RHEL_MAJOR -0 <= 5)
void ft_recv(struct fc_lport *, struct fc_seq *, struct fc_frame *);
#else
void ft_recv(struct fc_lport *, struct fc_frame *);
#endif

/*
 * SCST interface.
 */
int ft_send_response(struct scst_cmd *);
int ft_send_xfer_rdy(struct scst_cmd *);
void ft_cmd_timeout(struct scst_cmd *);
void ft_cmd_free(struct scst_cmd *);
void ft_cmd_tm_done(struct scst_mgmt_cmd *);
int ft_tgt_detect(struct scst_tgt_template *);
int ft_tgt_release(struct scst_tgt *);
int ft_tgt_enable(struct scst_tgt *, bool);
bool ft_tgt_enabled(struct scst_tgt *);
int ft_report_aen(struct scst_aen *);
int ft_get_transport_id(struct scst_tgt *, struct scst_session *, uint8_t **);

/*
 * Session interface.
 */
int ft_lport_notify(struct notifier_block *, unsigned long, void *);
void ft_lport_add(struct fc_lport *, void *);
void ft_lport_del(struct fc_lport *, void *);

/*
 * other internal functions.
 */
int ft_thread(void *);
void ft_recv_req(struct ft_sess *, struct fc_frame *);
void ft_recv_write_data(struct scst_cmd *, struct fc_frame *);
int ft_send_read_data(struct scst_cmd *);
struct ft_tpg *ft_lport_find_tpg(struct fc_lport *);
struct ft_node_acl *ft_acl_get(struct ft_tpg *, struct fc_rport_priv *);
void ft_cmd_dump(struct scst_cmd *, const char *);

#endif /* __SCSI_FCST_H__ */
