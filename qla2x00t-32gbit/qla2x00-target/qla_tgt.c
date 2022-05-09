/*
 *  qla_target.c SCSI LLD infrastructure for Cavium 22xx/23xx/24xx/25xx
 *
 *  based on qla2x00t.c code:
 *
 *  Copyright (C) 2004 - 2010 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2006 Nathaniel Clark <nate@misrule.us>
 *  Copyright (C) 2006 - 2010 ID7 Ltd.
 *
 *  Forward port and refactoring to modern qla2xxx and target/configfs
 *
 *  Copyright (C) 2010-2013 Nicholas A. Bellinger <nab@kernel.org>
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

/* NOTE: this file is mean to hold any symbol/routine that's SCST
 *  specific where upstream community would not accept.  Upstream
 *  would view these symbols as dead code.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/workqueue.h>
#include <asm/unaligned.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tcq.h>

#include "qla_def.h"
#include "scst_qla2xxx.h"

size_t qlt_add_vtarget(u64 port_name, u64 node_name, u64 parent_host)
{
	struct fc_vport *vport;
	struct Scsi_Host *shost = NULL;
	scsi_qla_host_t *vha = NULL, *npiv_vha;
	struct qla_tgt *tgt;
	struct fc_vport_identifiers vid;
	uint8_t parent_wwn[WWN_SIZE];

	memset(&vid, 0, sizeof(vid));

	u64_to_wwn(parent_host, parent_wwn);

	mutex_lock(&qla_tgt_mutex);
	list_for_each_entry(tgt, &qla_tgt_glist, tgt_list_entry) {
		vha = tgt->vha;

		if (!memcmp(parent_wwn, vha->port_name, WWN_SIZE)) {
			shost = vha->host;
			break;
		}
	}
	mutex_unlock(&qla_tgt_mutex);
	if (!vha || !shost)
		return -ENODEV;

	vid.port_name = port_name;
	vid.node_name = node_name;
	vid.roles = FC_PORT_ROLE_FCP_INITIATOR;
	vid.vport_type = FC_PORTTYPE_NPIV;
	/* vid.symbolic_name is already zero/NULL's */
	vid.disable = false;            /* always enabled */

	/* We only allow support on Channel 0 !!! */
	vport = fc_vport_create(shost, 0, &vid);
	if (!vport) {
		pr_err("fc_vport_create failed for qla2xxx_npiv\n");
		return -EINVAL;
	}

	npiv_vha = (struct scsi_qla_host *) vport->dd_data;
	scsi_host_get(npiv_vha->host);

	return 0;
}
EXPORT_SYMBOL(qlt_add_vtarget);

size_t qlt_del_vtarget(u64 port_name)
{
	struct qla_tgt *tgt, *t;
	scsi_qla_host_t *vha = NULL;
	struct Scsi_Host *shost;
	struct fc_host_attrs *fc_host;
	struct fc_vport *vport;
	unsigned long flags;
	int match = 0;

	pr_info("%s: %llx", __func__, port_name);
	mutex_lock(&qla_tgt_mutex);
	list_for_each_entry_safe(tgt, t, &qla_tgt_glist, tgt_list_entry) {
		vha = tgt->vha;
		shost = vha->host;
		fc_host = shost_to_fc_host(shost);
		spin_lock_irqsave(shost->host_lock, flags);
		/* We only allow support on Channel 0 !!! */
		list_for_each_entry(vport, &fc_host->vports, peers) {
			if ((vport->channel == 0) &&
			    (vport->port_name == port_name)) {
				match = 1;
				dev_info(&vha->hw->pdev->dev,
				    "%s: port_name %llx\n",
				    __func__, port_name);
				break;
			}
		}
		spin_unlock_irqrestore(shost->host_lock, flags);
		if (match)
			break;
	}
	mutex_unlock(&qla_tgt_mutex);

	if (!match)
		return -ENODEV;

	return fc_vport_terminate(vport);
}
EXPORT_SYMBOL(qlt_del_vtarget);
