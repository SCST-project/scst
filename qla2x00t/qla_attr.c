/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2008 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#include "qla_def.h"

#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/delay.h>
#include <linux/version.h>

#include "qla2x_tgt.h"
#include <linux/ctype.h>

#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(maj, min) 0
#endif

static int qla24xx_vport_disable(struct fc_vport *, bool);

/* SYSFS attributes --------------------------------------------------------- */

static ssize_t
qla2x00_show_class2_enabled(struct device *dev,
	struct device_attribute *attr, char *buffer)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));
	ulong max_size = PAGE_SIZE;
	ulong size;

	size = scnprintf(buffer, max_size, "%d\n", ha->enable_class_2);

	return size;
}

static ssize_t
qla2x00_store_class2_enabled(struct device *dev,
	struct device_attribute *attr, const char *buffer, size_t size)
{
	struct scsi_qla_host *ha = shost_priv(class_to_shost(dev));
	scsi_qla_host_t *pha = to_qla_parent(ha);
	int reset = 0;
	unsigned long flags;
	int res = size;

	if (buffer == NULL)
		goto out;

	spin_lock_irqsave(&pha->hardware_lock, flags);

	switch (buffer[0]) {
	case '0':
		if (ha->enable_class_2) {
			ha->enable_class_2 = 0;
			reset = 1;
		}
		break;
	case '1':
		if (!ha->enable_class_2) {
			if (ha->fw_attributes & __constant_cpu_to_le32(BIT_0)) {
				qla_printk(KERN_INFO, ha, "Enabling class 2 "
					"operations.\n");
				ha->enable_class_2 = 1;
				reset = 1;
			} else {
				qla_printk(KERN_INFO, ha, "Firmware doesn't "
					"support class 2 operations.\n");
				res = -EINVAL;
				goto out_unlock;
			}
		}
		break;
	default:
#if defined(QL_DEBUG_LEVEL_9) || defined(QL_DEBUG_LEVEL_11)
		qla_printk(KERN_ERR, ha, "%s: Requested action not understood: "
			"%s\n", __func__, buffer);
#endif
		res = -EINVAL;
		goto out_unlock;
	}

	spin_unlock_irqrestore(&pha->hardware_lock, flags);

	if (reset)
		set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);

out:
	return size;

out_unlock:
	spin_unlock_irqrestore(&pha->hardware_lock, flags);
	goto out;
}

static DEVICE_ATTR(class2_enabled,
		   S_IRUGO|S_IWUSR,
		   qla2x00_show_class2_enabled,
		   qla2x00_store_class2_enabled);

#ifdef CONFIG_SCSI_QLA2XXX_TARGET

/* #define CONFIG_SCST_PROC */

#ifdef CONFIG_SCST_PROC

static ssize_t
qla2x00_show_tgt_enabled(struct device *dev,
	struct device_attribute *attr, char *buffer)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));
	ssize_t size;

	size = scnprintf(buffer, PAGE_SIZE, "%d\n", qla_tgt_mode_enabled(ha));

	return size;
}

static ssize_t
qla2x00_store_tgt_enabled(struct device *dev,
	struct device_attribute *attr, const char *buffer, size_t size)
{
	struct scsi_qla_host *ha = shost_priv(class_to_shost(dev));
	int res = size;

	if ((buffer == NULL) || (size == 0))
		goto out;

	if (qla_target.tgt_host_action == NULL) {
		qla_printk(KERN_INFO, ha, "%s: not acting for lack of target "
			"driver\n", __func__);
		res = -EINVAL;
		goto out;
	}

	switch (buffer[0]) {
	case '0':
		res = qla_target.tgt_host_action(ha, DISABLE_TARGET_MODE);
		break;
	case '1':
		res = qla_target.tgt_host_action(ha, ENABLE_TARGET_MODE);
		break;
	default:
		qla_printk(KERN_ERR, ha, "%s: Requested action not "
			"understood: %s\n", __func__, buffer);
		res = -EINVAL;
		goto out;
	}

	if (res == 0)
		res = size;

	if ((size > 1) && (buffer[1] == 'r'))
		set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);

out:
	return res;
}

static DEVICE_ATTR(target_mode_enabled,
		   S_IRUGO|S_IWUSR,
		   qla2x00_show_tgt_enabled,
		   qla2x00_store_tgt_enabled);

static ssize_t
qla2x00_show_expl_conf_enabled(struct device *dev,
	struct device_attribute *attr, char *buffer)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));
	ulong max_size = PAGE_SIZE;
	ulong size;

	size = scnprintf(buffer, max_size, "%d\n", ha->enable_explicit_conf);

	return size;
}

static ssize_t
qla2x00_store_expl_conf_enabled(struct device *dev,
	struct device_attribute *attr, const char *buffer, size_t size)
{
	struct scsi_qla_host *ha = shost_priv(class_to_shost(dev));
	scsi_qla_host_t *pha = to_qla_parent(ha);
	unsigned long flags;

	if (buffer == NULL)
		return size;

	spin_lock_irqsave(&pha->hardware_lock, flags);

	switch (buffer[0]) {
	case '0':
		ha->enable_explicit_conf = 0;
		qla_printk(KERN_INFO, ha, "qla2xxx(%ld): explicit conformation "
			"disabled\n", ha->instance);
		break;
	case '1':
		ha->enable_explicit_conf = 1;
		qla_printk(KERN_INFO, ha, "qla2xxx(%ld): explicit conformation "
			"enabled\n", ha->instance);
		break;
	default:
#if defined(QL_DEBUG_LEVEL_9) || defined(QL_DEBUG_LEVEL_11)
		qla_printk(KERN_ERR, ha, "%s: Requested action not understood: "
			"%s\n", __func__, buffer);
#endif
		break;
	}

	spin_unlock_irqrestore(&pha->hardware_lock, flags);

	return size;
}

static DEVICE_ATTR(explicit_conform_enabled,
		   S_IRUGO|S_IWUSR,
		   qla2x00_show_expl_conf_enabled,
		   qla2x00_store_expl_conf_enabled);

#endif /* CONFIG_SCST_PROC */

static ssize_t
qla2x00_show_ini_mode_force_reverse(struct device *dev,
	struct device_attribute *attr, char *buffer)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));
	ulong max_size = PAGE_SIZE;
	ulong size;

	size = scnprintf(buffer, max_size, "%x\n", ha->ini_mode_force_reverse);

	return size;
}

static ssize_t
qla2x00_store_ini_mode_force_reverse(struct device *dev,
	struct device_attribute *attr, const char *buffer, size_t size)
{
	struct scsi_qla_host *ha = shost_priv(class_to_shost(dev));
	scsi_qla_host_t *pha = to_qla_parent(ha);
	unsigned long flags;

	if (buffer == NULL)
		return size;

	spin_lock_irqsave(&pha->hardware_lock, flags);

	switch (buffer[0]) {
	case '0':
		if (!ha->ini_mode_force_reverse)
			goto out_unlock;
		ha->ini_mode_force_reverse = 0;
		qla_printk(KERN_INFO, ha, "qla2xxx(%ld): initiator mode force "
			"reverse disabled\n", ha->instance);
		qla_reverse_ini_mode(ha);
		break;
	case '1':
		if (ha->ini_mode_force_reverse)
			goto out_unlock;
		ha->ini_mode_force_reverse = 1;
		qla_printk(KERN_INFO, ha, "qla2xxx(%ld): initiator mode force "
			"reverse enabled\n", ha->instance);
		qla_reverse_ini_mode(ha);
		break;
	default:
#if defined(QL_DEBUG_LEVEL_9) || defined(QL_DEBUG_LEVEL_11)
		qla_printk(KERN_ERR, ha, "%s: Requested action not understood: "
			"%s\n", __func__, buffer);
#endif
		break;
	}

	spin_unlock_irqrestore(&pha->hardware_lock, flags);

	set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
	qla2xxx_wake_dpc(ha);
	qla2x00_wait_for_hba_online(ha);

out:
	return size;

out_unlock:
	spin_unlock_irqrestore(&pha->hardware_lock, flags);
	goto out;
}

static DEVICE_ATTR(ini_mode_force_reverse,
		   S_IRUGO|S_IWUSR,
		   qla2x00_show_ini_mode_force_reverse,
		   qla2x00_store_ini_mode_force_reverse);

static ssize_t
qla2x00_show_resource_counts(struct device *dev,
	struct device_attribute *attr, char *buffer)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));
	ulong max_size = PAGE_SIZE;
	ulong size;
	mbx_cmd_t mc;
	int rval;

	mc.mb[0] = MBC_GET_RESOURCE_COUNTS;
	mc.out_mb = MBX_0;
	mc.in_mb = MBX_0|MBX_1|MBX_2;
	mc.tov = 30;
	mc.flags = 0;

	rval = qla2x00_mailbox_command(ha, &mc);

	if (rval != QLA_SUCCESS) {
		size = scnprintf(buffer, max_size,
			"Mailbox Command failed %d, mb %#x",
			rval, mc.mb[0]);
	} else {
		size = scnprintf(buffer, max_size,
			"immed_notify\t%d\ncommand\t\t%d\n",
			mc.mb[2], mc.mb[1]);
	}

	return size;
}

static DEVICE_ATTR(resource_counts,
		   S_IRUGO,
		   qla2x00_show_resource_counts,
		   NULL);

static ssize_t
qla2x00_show_port_database(struct device *dev,
	struct device_attribute *attr, char *buffer)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));
	ulong max_size = PAGE_SIZE;
	ulong size = 0;
	int rval, i;
	uint16_t entries;
	void *pmap;
	int pmap_len;

	rval = qla2x00_get_node_name_list(ha, &pmap, &pmap_len);
	if (rval != QLA_SUCCESS) {
		size = scnprintf(buffer, max_size,
				"qla2x00_get_node_name_list() failed %d\n",
				rval);
		goto next;
	}

	size += scnprintf(buffer+size, max_size-size,
			 "Port Name List returned %d bytes\nL_ID WWPN\n",
			 pmap_len);

	if (IS_FWI2_CAPABLE(ha)) {
		struct qla_port24_data *pmap24 = pmap;

		entries = pmap_len/sizeof(*pmap24);

		for (i = 0; (i < entries) && (size < max_size); ++i) {
			uint64_t *wwn = (uint64_t *)pmap24[i].port_name;
			if (*wwn == 0)
				continue;
			size += scnprintf(buffer+size, max_size-size,
					 "%04x %02x%02x%02x%02x%02x%02x%02x%02x\n",
					 le16_to_cpu(pmap24[i].loop_id),
					 pmap24[i].port_name[7],
					 pmap24[i].port_name[6],
					 pmap24[i].port_name[5],
					 pmap24[i].port_name[4],
					 pmap24[i].port_name[3],
					 pmap24[i].port_name[2],
					 pmap24[i].port_name[1],
					 pmap24[i].port_name[0]);
		}
	} else {
		struct qla_port23_data *pmap2x = pmap;

		entries = pmap_len/sizeof(*pmap2x);

		for (i = 0; (i < entries) && (size < max_size); ++i) {
			size += scnprintf(buffer+size, max_size-size,
					 "%04x %02x%02x%02x%02x%02x%02x%02x%02x\n",
					 le16_to_cpu(pmap2x[i].loop_id),
					 pmap2x[i].port_name[7],
					 pmap2x[i].port_name[6],
					 pmap2x[i].port_name[5],
					 pmap2x[i].port_name[4],
					 pmap2x[i].port_name[3],
					 pmap2x[i].port_name[2],
					 pmap2x[i].port_name[1],
					 pmap2x[i].port_name[0]);
		}
	}

	kfree(pmap);

next:
	if (size < max_size) {
		dma_addr_t gid_list_dma;
		struct gid_list_info *gid_list;
		char *id_iter;
		struct gid_list_info *gid;

		gid_list = dma_alloc_coherent(&ha->pdev->dev, GID_LIST_SIZE,
				&gid_list_dma, GFP_KERNEL);
		if (gid_list == NULL) {
			size += scnprintf(buffer+size, max_size-size,
					"Unable to allocate gid_list");
			goto out_id_list_failed;
		}

		/* Get list of logged in devices. */
		rval = qla2x00_get_id_list(ha, gid_list, gid_list_dma,
						&entries);
		if (rval != QLA_SUCCESS) {
			size += scnprintf(buffer+size, max_size-size,
					"qla2x00_get_id_list failed: %d",
					rval);
			goto out_free_id_list;
		}

		size += scnprintf(buffer+size, max_size-size,
				 "\nGet ID List (0x007C) returned %d entries\n"
				 "L_ID PortID\n",
				 entries);

		id_iter = (char *)gid_list;
		for (i = 0; (i < entries) && (size < max_size); ++i) {
			gid = (struct gid_list_info *)id_iter;
			if (IS_QLA2100(ha) || IS_QLA2200(ha)) {
				size += scnprintf(buffer+size, max_size-size,
						 "%02x %02x%02x%02x\n",
						 gid->loop_id_2100,
						 gid->domain,
						 gid->area,
						 gid->al_pa);

			} else {
				size += scnprintf(buffer+size, max_size-size,
						 "%04x %02x%02x%02x\n",
						 le16_to_cpu(gid->loop_id),
						 gid->domain,
						 gid->area,
						 gid->al_pa);

			}
			id_iter += ha->gid_list_info_size;
		}
out_free_id_list:
		dma_free_coherent(&ha->pdev->dev, GID_LIST_SIZE, gid_list,
					gid_list_dma);
	}

out_id_list_failed:
	if (size < max_size) {
		fc_port_t *fcport;
		char *state;
		char port_type[] = "URSBIT";

		size += scnprintf(buffer+size, max_size-size,
				 "\nfc_ports database\n");

		list_for_each_entry_rcu(fcport, &ha->fcports, list) {
			if (size >= max_size)
				goto out;
			switch (atomic_read(&fcport->state)) {
			case FCS_UNCONFIGURED : state = "Unconfigured"; break;
			case FCS_DEVICE_DEAD : state = "Dead"; break;
			case FCS_DEVICE_LOST : state = "Lost"; break;
			case FCS_ONLINE	: state = "Online"; break;
			case FCS_NOT_SUPPORTED : state = "Not Supported"; break;
			case FCS_FAILOVER : state = "Failover"; break;
			case FCS_FAILOVER_FAILED : state = "Failover Failed"; break;
			default: state = "Unknown"; break;
			}

			size += scnprintf(buffer+size, max_size-size,
					 "%04x %02x%02x%02x "
					 "%02x%02x%02x%02x%02x%02x%02x%02x "
					 "%c %s\n",
					 fcport->loop_id,
					 fcport->d_id.b.domain,
					 fcport->d_id.b.area,
					 fcport->d_id.b.al_pa,
					 fcport->port_name[0], fcport->port_name[1],
					 fcport->port_name[2], fcport->port_name[3],
					 fcport->port_name[4], fcport->port_name[5],
					 fcport->port_name[6], fcport->port_name[7],
					 port_type[fcport->port_type], state);
		}
	}
out:
	return size;
}

static ssize_t
qla2x00_update_portdb(struct device *dev,
	struct device_attribute *attr, const char *buffer, size_t size)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));

	if ((buffer == NULL) || (size == 0))
		goto out;

	switch (buffer[0]) {
	case '2':
		qla_printk(KERN_INFO, ha, "Reconfiguring loop on %ld\n",
			ha->host_no);
		qla2x00_configure_loop(ha);
		break;

	case 'l':
	case 'L':
		qla_printk(KERN_INFO, ha, "Reconfiguring local loop on %ld\n",
			ha->host_no);
		qla2x00_configure_local_loop(ha);
		break;

	case 'f':
	case 'F':
		qla_printk(KERN_INFO, ha, "Reconfiguring fabric on %ld\n",
			ha->host_no);
		qla2x00_configure_fabric(ha);

	default:
		qla_printk(KERN_INFO, ha, "Resyncing loop on %ld\n",
			ha->host_no);
		set_bit(LOOP_RESYNC_NEEDED, &ha->dpc_flags);
		break;
	}

out:
	return size;
}


static DEVICE_ATTR(port_database,
		   S_IRUGO|S_IWUSR,
		   qla2x00_show_port_database,
		   qla2x00_update_portdb);

#endif /* CONFIG_SCSI_QLA2XXX_TARGET */

static ssize_t
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35) && \
	(!defined(RHEL_RELEASE_CODE) || \
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(6, 1))
qla2x00_sysfs_read_fw_dump(
#else
qla2x00_sysfs_read_fw_dump(struct file *file,
#endif
			   struct kobject *kobj,
			   struct bin_attribute *bin_attr,
			   char *buf, loff_t off, size_t count)
{
	struct scsi_qla_host *ha = shost_priv(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	char *rbuf = (char *)ha->fw_dump;

	if (ha->fw_dump_reading == 0)
		return 0;
	if (off > ha->fw_dump_len)
                return 0;
	if (off + count > ha->fw_dump_len)
		count = ha->fw_dump_len - off;

	memcpy(buf, &rbuf[off], count);

	return (count);
}

static ssize_t
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35) && \
	(!defined(RHEL_RELEASE_CODE) || \
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(6, 1))
qla2x00_sysfs_write_fw_dump(
#else
qla2x00_sysfs_write_fw_dump(struct file *file,
#endif
			    struct kobject *kobj,
			    struct bin_attribute *bin_attr,
			    char *buf, loff_t off, size_t count)
{
	struct scsi_qla_host *ha = shost_priv(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	int reading;

	if (off != 0)
		return (0);

	reading = simple_strtol(buf, NULL, 10);
	switch (reading) {
	case 0:
		if (!ha->fw_dump_reading)
			break;

		qla_printk(KERN_INFO, ha,
		    "Firmware dump cleared on (%ld).\n", ha->host_no);

		ha->fw_dump_reading = 0;
		ha->fw_dumped = 0;
		break;
	case 1:
		if (ha->fw_dumped && !ha->fw_dump_reading) {
			ha->fw_dump_reading = 1;

			qla_printk(KERN_INFO, ha,
			    "Raw firmware dump ready for read on (%ld).\n",
			    ha->host_no);
		}
		break;
	case 2:
		qla2x00_alloc_fw_dump(ha);
		break;
	case 3:
		qla2x00_system_error(ha);
		break;
	}
	return (count);
}

static struct bin_attribute sysfs_fw_dump_attr = {
	.attr = {
		.name = "fw_dump",
		.mode = S_IRUSR | S_IWUSR,
	},
	.size = 0,
	.read = qla2x00_sysfs_read_fw_dump,
	.write = qla2x00_sysfs_write_fw_dump,
};

static ssize_t
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35) && \
	(!defined(RHEL_RELEASE_CODE) || \
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(6, 1))
qla2x00_sysfs_read_nvram(
#else
qla2x00_sysfs_read_nvram(struct file *file,
#endif
			 struct kobject *kobj,
			 struct bin_attribute *bin_attr,
			 char *buf, loff_t off, size_t count)
{
	struct scsi_qla_host *ha = shost_priv(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	int		size = ha->nvram_size;
	char		*nvram_cache = ha->nvram;

	if (!capable(CAP_SYS_ADMIN) || off > size || count == 0)
		return 0;
	if (off + count > size) {
		size -= off;
		count = size;
	}

	/* Read NVRAM data from cache. */
	memcpy(buf, &nvram_cache[off], count);

	return count;
}

static ssize_t
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35) && \
	(!defined(RHEL_RELEASE_CODE) || \
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(6, 1))
qla2x00_sysfs_write_nvram(
#else
qla2x00_sysfs_write_nvram(struct file *file,
#endif
			  struct kobject *kobj,
			  struct bin_attribute *bin_attr,
			  char *buf, loff_t off, size_t count)
{
	struct scsi_qla_host *ha = shost_priv(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	uint16_t	cnt;

	if (!capable(CAP_SYS_ADMIN) || off != 0 || count != ha->nvram_size)
		return 0;

	/* Checksum NVRAM. */
	if (IS_FWI2_CAPABLE(ha)) {
		uint32_t *iter;
		uint32_t chksum;

		iter = (uint32_t *)buf;
		chksum = 0;
		for (cnt = 0; cnt < ((count >> 2) - 1); cnt++)
			chksum += le32_to_cpu(*iter++);
		chksum = ~chksum + 1;
		*iter = cpu_to_le32(chksum);
	} else {
		uint8_t *iter;
		uint8_t chksum;

		iter = (uint8_t *)buf;
		chksum = 0;
		for (cnt = 0; cnt < count - 1; cnt++)
			chksum += *iter++;
		chksum = ~chksum + 1;
		*iter = chksum;
	}

	/* Write NVRAM. */
	ha->isp_ops->write_nvram(ha, (uint8_t *)buf, ha->nvram_base, count);
	ha->isp_ops->read_nvram(ha, (uint8_t *)ha->nvram, ha->nvram_base,
	    count);

	set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);

	return (count);
}

static struct bin_attribute sysfs_nvram_attr = {
	.attr = {
		.name = "nvram",
		.mode = S_IRUSR | S_IWUSR,
	},
	.size = 512,
	.read = qla2x00_sysfs_read_nvram,
	.write = qla2x00_sysfs_write_nvram,
};

static ssize_t
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35) && \
	(!defined(RHEL_RELEASE_CODE) || \
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(6, 1))
qla2x00_sysfs_read_optrom(
#else
qla2x00_sysfs_read_optrom(struct file *file,
#endif
			  struct kobject *kobj,
			  struct bin_attribute *bin_attr,
			  char *buf, loff_t off, size_t count)
{
	struct scsi_qla_host *ha = shost_priv(dev_to_shost(container_of(kobj,
	    struct device, kobj)));

	if (ha->optrom_state != QLA_SREADING)
		return 0;
	if (off > ha->optrom_region_size)
		return 0;
	if (off + count > ha->optrom_region_size)
		count = ha->optrom_region_size - off;

	memcpy(buf, &ha->optrom_buffer[off], count);

	return count;
}

static ssize_t
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35) && \
	(!defined(RHEL_RELEASE_CODE) || \
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(6, 1))
qla2x00_sysfs_write_optrom(
#else
qla2x00_sysfs_write_optrom(struct file *file,
#endif
			   struct kobject *kobj,
			   struct bin_attribute *bin_attr,
			   char *buf, loff_t off, size_t count)
{
	struct scsi_qla_host *ha = shost_priv(dev_to_shost(container_of(kobj,
	    struct device, kobj)));

	if (ha->optrom_state != QLA_SWRITING)
		return -EINVAL;
	if (off > ha->optrom_region_size)
		return -ERANGE;
	if (off + count > ha->optrom_region_size)
		count = ha->optrom_region_size - off;

	memcpy(&ha->optrom_buffer[off], buf, count);

	return count;
}

static struct bin_attribute sysfs_optrom_attr = {
	.attr = {
		.name = "optrom",
		.mode = S_IRUSR | S_IWUSR,
	},
	.size = 0,
	.read = qla2x00_sysfs_read_optrom,
	.write = qla2x00_sysfs_write_optrom,
};

static ssize_t
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35) && \
	(!defined(RHEL_RELEASE_CODE) || \
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(6, 1))
qla2x00_sysfs_write_optrom_ctl(
#else
qla2x00_sysfs_write_optrom_ctl(struct file *file,
#endif
			       struct kobject *kobj,
			       struct bin_attribute *bin_attr,
			       char *buf, loff_t off, size_t count)
{
	struct scsi_qla_host *ha = shost_priv(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	uint32_t start = 0;
	uint32_t size = ha->optrom_size;
	int val, valid;

	if (off)
		return 0;

	if (sscanf(buf, "%d:%x:%x", &val, &start, &size) < 1)
		return -EINVAL;
	if (start > ha->optrom_size)
		return -EINVAL;

	switch (val) {
	case 0:
		if (ha->optrom_state != QLA_SREADING &&
		    ha->optrom_state != QLA_SWRITING)
			break;

		ha->optrom_state = QLA_SWAITING;

		DEBUG2(qla_printk(KERN_INFO, ha,
		    "Freeing flash region allocation -- 0x%x bytes.\n",
		    ha->optrom_region_size));

		vfree(ha->optrom_buffer);
		ha->optrom_buffer = NULL;
		break;
	case 1:
		if (ha->optrom_state != QLA_SWAITING)
			break;

		if (start & 0xfff) {
			qla_printk(KERN_WARNING, ha,
			    "Invalid start region 0x%x/0x%x.\n", start, size);
			return -EINVAL;
		}

		ha->optrom_region_start = start;
		ha->optrom_region_size = start + size > ha->optrom_size ?
		    ha->optrom_size - start : size;

		ha->optrom_state = QLA_SREADING;
		ha->optrom_buffer = vmalloc(ha->optrom_region_size);
		if (ha->optrom_buffer == NULL) {
			qla_printk(KERN_WARNING, ha,
			    "Unable to allocate memory for optrom retrieval "
			    "(%x).\n", ha->optrom_region_size);

			ha->optrom_state = QLA_SWAITING;
			return count;
		}

		DEBUG2(qla_printk(KERN_INFO, ha,
		    "Reading flash region -- 0x%x/0x%x.\n",
		    ha->optrom_region_start, ha->optrom_region_size));

		memset(ha->optrom_buffer, 0, ha->optrom_region_size);
		ha->isp_ops->read_optrom(ha, ha->optrom_buffer,
		    ha->optrom_region_start, ha->optrom_region_size);
		break;
	case 2:
		if (ha->optrom_state != QLA_SWAITING)
			break;

		/*
		 * We need to be more restrictive on which FLASH regions are
		 * allowed to be updated via user-space.  Regions accessible
		 * via this method include:
		 *
		 * ISP21xx/ISP22xx/ISP23xx type boards:
		 *
		 * 	0x000000 -> 0x020000 -- Boot code.
		 *
		 * ISP2322/ISP24xx type boards:
		 *
		 * 	0x000000 -> 0x07ffff -- Boot code.
		 * 	0x080000 -> 0x0fffff -- Firmware.
		 *
		 * ISP25xx type boards:
		 *
		 * 	0x000000 -> 0x07ffff -- Boot code.
		 * 	0x080000 -> 0x0fffff -- Firmware.
		 * 	0x120000 -> 0x12ffff -- VPD and HBA parameters.
		 */
		valid = 0;
		if (ha->optrom_size == OPTROM_SIZE_2300 && start == 0)
			valid = 1;
		else if (start == (FA_BOOT_CODE_ADDR*4) ||
		    start == (FA_RISC_CODE_ADDR*4))
			valid = 1;
		else if (IS_QLA25XX(ha) && start == (FA_VPD_NVRAM_ADDR*4))
		    valid = 1;
		if (!valid) {
			qla_printk(KERN_WARNING, ha,
			    "Invalid start region 0x%x/0x%x.\n", start, size);
			return -EINVAL;
		}

		ha->optrom_region_start = start;
		ha->optrom_region_size = start + size > ha->optrom_size ?
		    ha->optrom_size - start : size;

		ha->optrom_state = QLA_SWRITING;
		ha->optrom_buffer = vmalloc(ha->optrom_region_size);
		if (ha->optrom_buffer == NULL) {
			qla_printk(KERN_WARNING, ha,
			    "Unable to allocate memory for optrom update "
			    "(%x).\n", ha->optrom_region_size);

			ha->optrom_state = QLA_SWAITING;
			return count;
		}

		DEBUG2(qla_printk(KERN_INFO, ha,
		    "Staging flash region write -- 0x%x/0x%x.\n",
		    ha->optrom_region_start, ha->optrom_region_size));

		memset(ha->optrom_buffer, 0, ha->optrom_region_size);
		break;
	case 3:
		if (ha->optrom_state != QLA_SWRITING)
			break;

		DEBUG2(qla_printk(KERN_INFO, ha,
		    "Writing flash region -- 0x%x/0x%x.\n",
		    ha->optrom_region_start, ha->optrom_region_size));

		ha->isp_ops->write_optrom(ha, ha->optrom_buffer,
		    ha->optrom_region_start, ha->optrom_region_size);
		break;
	default:
		count = -EINVAL;
	}
	return count;
}

static struct bin_attribute sysfs_optrom_ctl_attr = {
	.attr = {
		.name = "optrom_ctl",
		.mode = S_IWUSR,
	},
	.size = 0,
	.write = qla2x00_sysfs_write_optrom_ctl,
};

static ssize_t
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35) && \
	(!defined(RHEL_RELEASE_CODE) || \
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(6, 1))
qla2x00_sysfs_read_vpd(
#else
qla2x00_sysfs_read_vpd(struct file *file,
#endif
		       struct kobject *kobj,
		       struct bin_attribute *bin_attr,
		       char *buf, loff_t off, size_t count)
{
	struct scsi_qla_host *ha = shost_priv(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	int           size = ha->vpd_size;
	char          *vpd_cache = ha->vpd;

	if (!capable(CAP_SYS_ADMIN) || off > size || count == 0)
		return 0;
	if (off + count > size) {
		size -= off;
		count = size;
	}

	/* Read NVRAM data from cache. */
	memcpy(buf, &vpd_cache[off], count);

	return count;
}

static ssize_t
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35) && \
	(!defined(RHEL_RELEASE_CODE) || \
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(6, 1))
qla2x00_sysfs_write_vpd(
#else
qla2x00_sysfs_write_vpd(struct file *file,
#endif
			struct kobject *kobj,
			struct bin_attribute *bin_attr,
			char *buf, loff_t off, size_t count)
{
	struct scsi_qla_host *ha = shost_priv(dev_to_shost(container_of(kobj,
	    struct device, kobj)));

	if (!capable(CAP_SYS_ADMIN) || off != 0 || count != ha->vpd_size)
		return 0;

	/* Write NVRAM. */
	ha->isp_ops->write_nvram(ha, (uint8_t *)buf, ha->vpd_base, count);
	ha->isp_ops->read_nvram(ha, (uint8_t *)ha->vpd, ha->vpd_base, count);

	return count;
}

static struct bin_attribute sysfs_vpd_attr = {
	.attr = {
		.name = "vpd",
		.mode = S_IRUSR | S_IWUSR,
	},
	.size = 0,
	.read = qla2x00_sysfs_read_vpd,
	.write = qla2x00_sysfs_write_vpd,
};

static ssize_t
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35) && \
	(!defined(RHEL_RELEASE_CODE) || \
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(6, 1))
qla2x00_sysfs_read_sfp(
#else
qla2x00_sysfs_read_sfp(struct file *file,
#endif
		       struct kobject *kobj,
		       struct bin_attribute *bin_attr,
		       char *buf, loff_t off, size_t count)
{
	struct scsi_qla_host *ha = shost_priv(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	uint16_t iter, addr, offset;
	int rval;

	if (!capable(CAP_SYS_ADMIN) || off != 0 || count != SFP_DEV_SIZE * 2)
		return 0;

	if (ha->sfp_data)
		goto do_read;

	ha->sfp_data = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL,
	    &ha->sfp_data_dma);
	if (!ha->sfp_data) {
		qla_printk(KERN_WARNING, ha,
		    "Unable to allocate memory for SFP read-data.\n");
		return 0;
	}

do_read:
	memset(ha->sfp_data, 0, SFP_BLOCK_SIZE);
	addr = 0xa0;
	for (iter = 0, offset = 0; iter < (SFP_DEV_SIZE * 2) / SFP_BLOCK_SIZE;
	    iter++, offset += SFP_BLOCK_SIZE) {
		if (iter == 4) {
			/* Skip to next device address. */
			addr = 0xa2;
			offset = 0;
		}

		rval = qla2x00_read_sfp(ha, ha->sfp_data_dma, addr, offset,
		    SFP_BLOCK_SIZE);
		if (rval != QLA_SUCCESS) {
			qla_printk(KERN_WARNING, ha,
			    "Unable to read SFP data (%x/%x/%x).\n", rval,
			    addr, offset);
			count = 0;
			break;
		}
		memcpy(buf, ha->sfp_data, SFP_BLOCK_SIZE);
		buf += SFP_BLOCK_SIZE;
	}

	return count;
}

static struct bin_attribute sysfs_sfp_attr = {
	.attr = {
		.name = "sfp",
		.mode = S_IRUSR | S_IWUSR,
	},
	.size = SFP_DEV_SIZE * 2,
	.read = qla2x00_sysfs_read_sfp,
};

static void
qla2x00_wait_for_passthru_completion(struct scsi_qla_host *ha)
{
	unsigned long timeout;

	if (unlikely(pci_channel_offline(ha->pdev)))
		return;

	timeout = ((ha->r_a_tov / 10 * 2) + 5) * HZ;
	if (!wait_for_completion_timeout(&ha->pass_thru_intr_comp, timeout)) {
		DEBUG2(qla_printk(KERN_WARNING, ha,
		    "Passthru request timed out.\n"));
		if (IS_QLA82XX(ha))
			set_bit(FCOE_CTX_RESET_NEEDED, &ha->dpc_flags);
		else {
			ha->isp_ops->fw_dump(ha, 0);
			set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
		}
		qla2xxx_wake_dpc(ha);
		ha->pass_thru_cmd_result = 0;
		ha->pass_thru_cmd_in_process = 0;
	}
}

static ssize_t
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35) && \
	(!defined(RHEL_RELEASE_CODE) || \
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(6, 2))
qla2x00_sysfs_read_ct(
#else
qla2x00_sysfs_read_ct(struct file *file,
#endif
		      struct kobject *kobj,
		      struct bin_attribute *bin_attr,
		      char *buf,
		      loff_t off, size_t count)
{
	struct scsi_qla_host *ha = shost_priv(dev_to_shost(container_of(kobj,
					    struct device, kobj)));

	if (!ha->pass_thru_cmd_in_process || !ha->pass_thru_cmd_result) {
		DEBUG3(qla_printk(KERN_WARNING, ha,
		    "Passthru CT response is not available.\n"));
		return 0;
	}

	memcpy(buf, ha->pass_thru, count);

	ha->pass_thru_cmd_result = 0;
	ha->pass_thru_cmd_in_process = 0;

	return count;
}

static ssize_t
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35) && \
	(!defined(RHEL_RELEASE_CODE) || \
	 RHEL_RELEASE_CODE -0 < RHEL_RELEASE_VERSION(6, 2))
qla2x00_sysfs_write_ct(
#else
qla2x00_sysfs_write_ct(struct file *file,
#endif
		       struct kobject *kobj,
		       struct bin_attribute *bin_attr,
		       char *buf,
		       loff_t off, size_t count)
{
	struct scsi_qla_host *ha = shost_priv(dev_to_shost(container_of(kobj,
					    struct device, kobj)));
	fc_ct_request_t *request = (void *)buf;
	struct ct_entry_24xx *ct_iocb = NULL;
	ms_iocb_entry_t *ct_iocb_2G = NULL;
	unsigned long flags;

	if (test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags) ||
	    test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags) ||
	    test_bit(ISP_ABORT_RETRY, &ha->dpc_flags)) {
		DEBUG2_3_11(qla_printk(KERN_INFO, ha,
		    "%s(%ld): isp reset in progress.\n",
		    __func__, ha->host_no));
		goto ct_error0;
	}
	if (atomic_read(&ha->loop_state) != LOOP_READY)
		goto ct_error0;
	if (count < sizeof(request->ct_iu)) {
		DEBUG2(qla_printk(KERN_WARNING, ha,
		    "Passthru CT buffer insufficient size %zu...\n", count));
		goto ct_error0;
	}
	if (ha->pass_thru_cmd_in_process || ha->pass_thru_cmd_result) {
		DEBUG2(qla_printk(KERN_WARNING, ha,
		    "Passthru CT request is already progress\n"));
		goto ct_error0;
	}
	if (qla2x00_mgmt_svr_login(ha)) {
		DEBUG2(qla_printk(KERN_WARNING, ha,
		    "Passthru CT request failed to login management server\n"));
		goto ct_error0;
	}

	ha->pass_thru_cmd_in_process = 1;
	spin_lock_irqsave(&ha->hardware_lock, flags);

	if (count > PAGE_SIZE) {
		DEBUG2(qla_printk(KERN_INFO, ha,
		    "Passthru CT request excessive size %d...\n",
		    (int)count));
		count = PAGE_SIZE;
	}

	memset(ha->pass_thru, 0, PAGE_SIZE);
	memcpy(ha->pass_thru, &request->ct_iu, count);

	if (IS_FWI2_CAPABLE(ha)) {
		ct_iocb = (void *)qla2x00_req_pkt(ha);

		if (ct_iocb == NULL) {
			DEBUG2(qla_printk(KERN_WARNING, ha,
			    "Passthru CT request failed to get request "
			    "packet\n"));
			goto ct_error1;
		}

		ct_iocb->entry_type = CT_IOCB_TYPE;
		ct_iocb->entry_count = 1;
		ct_iocb->entry_status = 0;
		ct_iocb->comp_status = __constant_cpu_to_le16(0);
		if (*(buf+4) & 0xfc)
			ct_iocb->nport_handle = __constant_cpu_to_le16(NPH_SNS);
		else
			ct_iocb->nport_handle = cpu_to_le16(ha->mgmt_svr_loop_id);
		ct_iocb->cmd_dsd_count = __constant_cpu_to_le16(1);
		ct_iocb->vp_index = ha->vp_idx;
		ct_iocb->timeout = (cpu_to_le16(ha->r_a_tov / 10 * 2) + 2);
		ct_iocb->rsp_dsd_count = __constant_cpu_to_le16(1);
		ct_iocb->rsp_byte_count = cpu_to_le32(PAGE_SIZE);
		ct_iocb->cmd_byte_count = cpu_to_le32(count);

		ct_iocb->dseg_0_address[0] = cpu_to_le32(LSD(ha->pass_thru_dma));
		ct_iocb->dseg_0_address[1] = cpu_to_le32(MSD(ha->pass_thru_dma));
		ct_iocb->dseg_0_len = ct_iocb->cmd_byte_count;

		ct_iocb->dseg_1_address[0] = cpu_to_le32(LSD(ha->pass_thru_dma));
		ct_iocb->dseg_1_address[1] = cpu_to_le32(MSD(ha->pass_thru_dma));
		ct_iocb->dseg_1_len = ct_iocb->rsp_byte_count;
	} else {
		ct_iocb_2G = (void *)qla2x00_req_pkt(ha);

		if (ct_iocb_2G == NULL) {
			DEBUG2(qla_printk(KERN_WARNING, ha,
			    "Passthru CT request failed to get request "
			    "packet\n"));
			goto ct_error1;
		}

		ct_iocb_2G->entry_type = CT_IOCB_TYPE;
		ct_iocb_2G->entry_count = 1;
		ct_iocb_2G->entry_status = 0;
		SET_TARGET_ID(ha, ct_iocb_2G->loop_id, ha->mgmt_svr_loop_id);
		ct_iocb_2G->status = __constant_cpu_to_le16(0);
		ct_iocb_2G->control_flags = __constant_cpu_to_le16(0);
		ct_iocb_2G->timeout = (cpu_to_le16(ha->r_a_tov / 10 * 2) + 2);
		ct_iocb_2G->cmd_dsd_count = __constant_cpu_to_le16(1);
		ct_iocb_2G->total_dsd_count = __constant_cpu_to_le16(2);
		ct_iocb_2G->rsp_bytecount = cpu_to_le32(PAGE_SIZE);
		ct_iocb_2G->req_bytecount = cpu_to_le32(count);

		ct_iocb_2G->dseg_req_address[0] = cpu_to_le32(LSD(ha->pass_thru_dma));
		ct_iocb_2G->dseg_req_address[1] = cpu_to_le32(MSD(ha->pass_thru_dma));
		ct_iocb_2G->dseg_req_length = ct_iocb_2G->req_bytecount;

		ct_iocb_2G->dseg_rsp_address[0] = cpu_to_le32(LSD(ha->pass_thru_dma));
		ct_iocb_2G->dseg_rsp_address[1] = cpu_to_le32(MSD(ha->pass_thru_dma));
		ct_iocb_2G->dseg_rsp_length = ct_iocb_2G->rsp_bytecount;
	}

	wmb();
	qla2x00_isp_cmd(ha);

	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	qla2x00_wait_for_passthru_completion(ha);

	return count;

ct_error1:
	ha->pass_thru_cmd_in_process = 0;
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

ct_error0:
	DEBUG3(qla_printk(KERN_WARNING, ha,
	    "Passthru CT failed on scsi(%ld)\n", ha->host_no));
	return 0;
}

static struct bin_attribute sysfs_ct_attr = {
	.attr = {
		.name = "ct",
		.mode = S_IRUSR | S_IWUSR,
	},
	.size = 0,
	.read = qla2x00_sysfs_read_ct,
	.write = qla2x00_sysfs_write_ct,
};


static struct sysfs_entry {
	char *name;
	struct bin_attribute *attr;
	int is4GBp_only;
} bin_file_entries[] = {
	{ "fw_dump", &sysfs_fw_dump_attr, },
	{ "nvram", &sysfs_nvram_attr, },
	{ "optrom", &sysfs_optrom_attr, },
	{ "optrom_ctl", &sysfs_optrom_ctl_attr, },
	{ "vpd", &sysfs_vpd_attr, 1 },
	{ "sfp", &sysfs_sfp_attr, 1 },
	{ "ct", &sysfs_ct_attr, },
	{ NULL },
};

void
qla2x00_alloc_sysfs_attr(scsi_qla_host_t *ha)
{
	struct Scsi_Host *host = ha->host;
	struct sysfs_entry *iter;
	int ret;

	for (iter = bin_file_entries; iter->name; iter++) {
		if (iter->is4GBp_only && !IS_FWI2_CAPABLE(ha))
			continue;

		ret = sysfs_create_bin_file(&host->shost_gendev.kobj,
		    iter->attr);
		if (ret)
			qla_printk(KERN_INFO, ha,
			    "Unable to create sysfs %s binary attribute "
			    "(%d).\n", iter->name, ret);
	}
}

void
qla2x00_free_sysfs_attr(scsi_qla_host_t *ha)
{
	struct Scsi_Host *host = ha->host;
	struct sysfs_entry *iter;

	for (iter = bin_file_entries; iter->name; iter++) {
		if (iter->is4GBp_only && !IS_FWI2_CAPABLE(ha))
			continue;

		sysfs_remove_bin_file(&host->shost_gendev.kobj,
		    iter->attr);
	}

	if (ha->beacon_blink_led == 1)
		ha->isp_ops->beacon_off(ha);
}

/* Scsi_Host attributes. */

static ssize_t
qla2x00_drvr_version_show(struct device *dev,
			  struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%s\n", qla2x00_version_str);
}

static ssize_t
qla2x00_fw_version_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));
	char fw_str[128];

	return scnprintf(buf, PAGE_SIZE, "%s\n",
	    ha->isp_ops->fw_version_str(ha, fw_str, sizeof(fw_str)));
}

static ssize_t
qla2x00_serial_num_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));
	uint32_t sn;

	if (IS_FWI2_CAPABLE(ha))
		return scnprintf(buf, PAGE_SIZE, "\n");

	sn = ((ha->serial0 & 0x1f) << 16) | (ha->serial2 << 8) | ha->serial1;
	return scnprintf(buf, PAGE_SIZE, "%c%05d\n", 'A' + sn / 100000,
	    sn % 100000);
}

static ssize_t
qla2x00_isp_name_show(struct device *dev, struct device_attribute *attr,
		      char *buf)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));
	return scnprintf(buf, PAGE_SIZE, "ISP%04X\n", ha->pdev->device);
}

static ssize_t
qla2x00_isp_id_show(struct device *dev, struct device_attribute *attr,
		    char *buf)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));
	return scnprintf(buf, PAGE_SIZE, "%04x %04x %04x %04x\n",
	    ha->product_id[0], ha->product_id[1], ha->product_id[2],
	    ha->product_id[3]);
}

static ssize_t
qla2x00_model_name_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));
	return scnprintf(buf, PAGE_SIZE, "%s\n", ha->model_number);
}

static ssize_t
qla2x00_model_desc_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));
	return scnprintf(buf, PAGE_SIZE, "%s\n",
	    ha->model_desc ? ha->model_desc: "");
}

static ssize_t
qla2x00_pci_info_show(struct device *dev, struct device_attribute *attr,
		      char *buf)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));
	char pci_info[30];

	return scnprintf(buf, PAGE_SIZE, "%s\n",
	    ha->isp_ops->pci_info_str(ha, pci_info, sizeof(pci_info)));
}

static ssize_t
qla2x00_link_state_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));
	int len = 0;

	if (atomic_read(&ha->loop_state) == LOOP_DOWN ||
	    atomic_read(&ha->loop_state) == LOOP_DEAD)
		len = scnprintf(buf, PAGE_SIZE, "Link Down\n");
	else if (atomic_read(&ha->loop_state) != LOOP_READY ||
	    test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags))
		len = scnprintf(buf, PAGE_SIZE, "Unknown Link State\n");
	else {
		len = scnprintf(buf, PAGE_SIZE, "Link Up - ");

		switch (ha->current_topology) {
		case ISP_CFG_NL:
			len += scnprintf(buf + len, PAGE_SIZE-len, "Loop\n");
			break;
		case ISP_CFG_FL:
			len += scnprintf(buf + len, PAGE_SIZE-len, "FL_Port\n");
			break;
		case ISP_CFG_N:
			len += scnprintf(buf + len, PAGE_SIZE-len,
			    "N_Port to N_Port\n");
			break;
		case ISP_CFG_F:
			len += scnprintf(buf + len, PAGE_SIZE-len, "F_Port\n");
			break;
		default:
			len += scnprintf(buf + len, PAGE_SIZE-len, "Loop\n");
			break;
		}
	}
	return len;
}

static ssize_t
qla2x00_zio_show(struct device *dev, struct device_attribute *attr,
		 char *buf)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));
	int len = 0;

	switch (ha->zio_mode) {
	case QLA_ZIO_MODE_6:
		len += scnprintf(buf + len, PAGE_SIZE-len, "Mode 6\n");
		break;
	case QLA_ZIO_DISABLED:
		len += scnprintf(buf + len, PAGE_SIZE-len, "Disabled\n");
		break;
	}
	return len;
}

static ssize_t
qla2x00_zio_store(struct device *dev, struct device_attribute *attr,
		  const char *buf, size_t count)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));
	int val = 0;
	uint16_t zio_mode;

	if (!IS_ZIO_SUPPORTED(ha))
		return -ENOTSUPP;

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;

	if (val)
		zio_mode = QLA_ZIO_MODE_6;
	else
		zio_mode = QLA_ZIO_DISABLED;

	/* Update per-hba values and queue a reset. */
	if (zio_mode != QLA_ZIO_DISABLED || ha->zio_mode != QLA_ZIO_DISABLED) {
		ha->zio_mode = zio_mode;
		set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
	}
	return strlen(buf);
}

static ssize_t
qla2x00_zio_timer_show(struct device *dev, struct device_attribute *attr,
		       char *buf)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));

	return scnprintf(buf, PAGE_SIZE, "%d us\n", ha->zio_timer * 100);
}

static ssize_t
qla2x00_zio_timer_store(struct device *dev, struct device_attribute *attr,
			const char *buf, size_t count)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));
	int val = 0;
	uint16_t zio_timer;

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;
	if (val > 25500 || val < 100)
		return -ERANGE;

	zio_timer = (uint16_t)(val / 100);
	ha->zio_timer = zio_timer;

	return strlen(buf);
}

static ssize_t
qla2x00_beacon_show(struct device *dev, struct device_attribute *attr,
		    char *buf)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));
	int len = 0;

	if (ha->beacon_blink_led)
		len += scnprintf(buf + len, PAGE_SIZE-len, "Enabled\n");
	else
		len += scnprintf(buf + len, PAGE_SIZE-len, "Disabled\n");
	return len;
}

static ssize_t
qla2x00_beacon_store(struct device *dev, struct device_attribute *attr,
		     const char *buf, size_t count)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));
	int val = 0;
	int rval;

	if (IS_QLA2100(ha) || IS_QLA2200(ha))
		return -EPERM;

	if (test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags)) {
		qla_printk(KERN_WARNING, ha,
		    "Abort ISP active -- ignoring beacon request.\n");
		return -EBUSY;
	}

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;

	if (val)
		rval = ha->isp_ops->beacon_on(ha);
	else
		rval = ha->isp_ops->beacon_off(ha);

	if (rval != QLA_SUCCESS)
		count = 0;

	return count;
}

static ssize_t
qla2x00_optrom_bios_version_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));

	return scnprintf(buf, PAGE_SIZE, "%d.%02d\n", ha->bios_revision[1],
	    ha->bios_revision[0]);
}

static ssize_t
qla2x00_optrom_efi_version_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));

	return scnprintf(buf, PAGE_SIZE, "%d.%02d\n", ha->efi_revision[1],
	    ha->efi_revision[0]);
}

static ssize_t
qla2x00_optrom_fcode_version_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));

	return scnprintf(buf, PAGE_SIZE, "%d.%02d\n", ha->fcode_revision[1],
	    ha->fcode_revision[0]);
}

static ssize_t
qla2x00_optrom_fw_version_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	scsi_qla_host_t *ha = shost_priv(class_to_shost(dev));

	return scnprintf(buf, PAGE_SIZE, "%d.%02d.%02d %d\n",
	    ha->fw_revision[0], ha->fw_revision[1], ha->fw_revision[2],
	    ha->fw_revision[3]);
}

static DEVICE_ATTR(driver_version, S_IRUGO, qla2x00_drvr_version_show, NULL);
static DEVICE_ATTR(fw_version, S_IRUGO, qla2x00_fw_version_show, NULL);
static DEVICE_ATTR(serial_num, S_IRUGO, qla2x00_serial_num_show, NULL);
static DEVICE_ATTR(isp_name, S_IRUGO, qla2x00_isp_name_show, NULL);
static DEVICE_ATTR(isp_id, S_IRUGO, qla2x00_isp_id_show, NULL);
static DEVICE_ATTR(model_name, S_IRUGO, qla2x00_model_name_show, NULL);
static DEVICE_ATTR(model_desc, S_IRUGO, qla2x00_model_desc_show, NULL);
static DEVICE_ATTR(pci_info, S_IRUGO, qla2x00_pci_info_show, NULL);
static DEVICE_ATTR(link_state, S_IRUGO, qla2x00_link_state_show, NULL);
static DEVICE_ATTR(zio, S_IRUGO | S_IWUSR, qla2x00_zio_show, qla2x00_zio_store);
static DEVICE_ATTR(zio_timer, S_IRUGO | S_IWUSR, qla2x00_zio_timer_show,
		   qla2x00_zio_timer_store);
static DEVICE_ATTR(beacon, S_IRUGO | S_IWUSR, qla2x00_beacon_show,
		   qla2x00_beacon_store);
static DEVICE_ATTR(optrom_bios_version, S_IRUGO,
		   qla2x00_optrom_bios_version_show, NULL);
static DEVICE_ATTR(optrom_efi_version, S_IRUGO,
		   qla2x00_optrom_efi_version_show, NULL);
static DEVICE_ATTR(optrom_fcode_version, S_IRUGO,
		   qla2x00_optrom_fcode_version_show, NULL);
static DEVICE_ATTR(optrom_fw_version, S_IRUGO, qla2x00_optrom_fw_version_show,
		   NULL);

struct device_attribute *qla2x00_host_attrs[] = {
	&dev_attr_driver_version,
	&dev_attr_fw_version,
	&dev_attr_serial_num,
	&dev_attr_isp_name,
	&dev_attr_isp_id,
	&dev_attr_model_name,
	&dev_attr_model_desc,
	&dev_attr_pci_info,
	&dev_attr_link_state,
	&dev_attr_zio,
	&dev_attr_zio_timer,
	&dev_attr_beacon,
	&dev_attr_optrom_bios_version,
	&dev_attr_optrom_efi_version,
	&dev_attr_optrom_fcode_version,
	&dev_attr_optrom_fw_version,
	&dev_attr_class2_enabled,
#ifdef CONFIG_SCSI_QLA2XXX_TARGET
#ifdef CONFIG_SCST_PROC
	&dev_attr_target_mode_enabled,
	&dev_attr_explicit_conform_enabled,
#endif
	&dev_attr_ini_mode_force_reverse,
	&dev_attr_resource_counts,
	&dev_attr_port_database,
#endif
	NULL,
};

/* Host attributes. */

static void
qla2x00_get_host_port_id(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = shost_priv(shost);

	fc_host_port_id(shost) = ha->d_id.b.domain << 16 |
	    ha->d_id.b.area << 8 | ha->d_id.b.al_pa;
}

static void
qla2x00_get_host_speed(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = to_qla_parent(shost_priv(shost));
	u32 speed = FC_PORTSPEED_UNKNOWN;

	switch (ha->link_data_rate) {
	case PORT_SPEED_1GB:
		speed = FC_PORTSPEED_1GBIT;
		break;
	case PORT_SPEED_2GB:
		speed = FC_PORTSPEED_2GBIT;
		break;
	case PORT_SPEED_4GB:
		speed = FC_PORTSPEED_4GBIT;
		break;
	case PORT_SPEED_8GB:
		speed = FC_PORTSPEED_8GBIT;
		break;
	}
	fc_host_speed(shost) = speed;
}

static void
qla2x00_get_host_port_type(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = shost_priv(shost);
	uint32_t port_type = FC_PORTTYPE_UNKNOWN;

	if (ha->parent) {
		fc_host_port_type(shost) = FC_PORTTYPE_NPIV;
		return;
	}
	switch (ha->current_topology) {
	case ISP_CFG_NL:
		port_type = FC_PORTTYPE_LPORT;
		break;
	case ISP_CFG_FL:
		port_type = FC_PORTTYPE_NLPORT;
		break;
	case ISP_CFG_N:
		port_type = FC_PORTTYPE_PTP;
		break;
	case ISP_CFG_F:
		port_type = FC_PORTTYPE_NPORT;
		break;
	}
	fc_host_port_type(shost) = port_type;
}

static void
qla2x00_get_starget_node_name(struct scsi_target *starget)
{
	struct Scsi_Host *host = dev_to_shost(starget->dev.parent);
	scsi_qla_host_t *ha = shost_priv(host);
	fc_port_t *fcport;
	u64 node_name = 0;

	list_for_each_entry_rcu(fcport, &ha->fcports, list) {
		if (fcport->rport &&
		    starget->id == fcport->rport->scsi_target_id) {
			node_name = wwn_to_u64(fcport->node_name);
			break;
		}
	}

	fc_starget_node_name(starget) = node_name;
}

static void
qla2x00_get_starget_port_name(struct scsi_target *starget)
{
	struct Scsi_Host *host = dev_to_shost(starget->dev.parent);
	scsi_qla_host_t *ha = shost_priv(host);
	fc_port_t *fcport;
	u64 port_name = 0;

	list_for_each_entry_rcu(fcport, &ha->fcports, list) {
		if (fcport->rport &&
		    starget->id == fcport->rport->scsi_target_id) {
			port_name = wwn_to_u64(fcport->port_name);
			break;
		}
	}

	fc_starget_port_name(starget) = port_name;
}

static void
qla2x00_get_starget_port_id(struct scsi_target *starget)
{
	struct Scsi_Host *host = dev_to_shost(starget->dev.parent);
	scsi_qla_host_t *ha = shost_priv(host);
	fc_port_t *fcport;
	uint32_t port_id = ~0U;

	list_for_each_entry_rcu(fcport, &ha->fcports, list) {
		if (fcport->rport &&
		    starget->id == fcport->rport->scsi_target_id) {
			port_id = fcport->d_id.b.domain << 16 |
			    fcport->d_id.b.area << 8 | fcport->d_id.b.al_pa;
			break;
		}
	}

	fc_starget_port_id(starget) = port_id;
}

static void
qla2x00_set_rport_loss_tmo(struct fc_rport *rport, uint32_t timeout)
{
	if (timeout)
		rport->dev_loss_tmo = timeout;
	else
		rport->dev_loss_tmo = 1;
}

static void
qla2x00_dev_loss_tmo_callbk(struct fc_rport *rport)
{
	struct Scsi_Host *host = rport_to_shost(rport);
	fc_port_t *fcport = *(fc_port_t **)rport->dd_data;

	if (!fcport)
		return;

	qla2x00_abort_fcport_cmds(fcport);

	/*
	 * Transport has effectively 'deleted' the rport, clear
	 * all local references.
	 */
#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	if (qla_target.tgt_fc_port_deleted)
		qla_target.tgt_fc_port_deleted(fcport->ha, fcport);
#endif
	spin_lock_irq(host->host_lock);
	fcport->rport = NULL;
	*((fc_port_t **)rport->dd_data) = NULL;
	spin_unlock_irq(host->host_lock);
}

static void
qla2x00_terminate_rport_io(struct fc_rport *rport)
{
	fc_port_t *fcport = *(fc_port_t **)rport->dd_data;

	if (!fcport)
		return;

	qla2x00_abort_fcport_cmds(fcport);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0) && !defined(CONFIG_SUSE_KERNEL)
	scsi_target_unblock(&rport->dev);
#else
	/*
	 * It is not needed here, because the caller (fc_terminate_rport_io())
	 * calls it.
	 */
#endif
}

static int
qla2x00_issue_lip(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = shost_priv(shost);

	qla2x00_loop_reset(ha);
	return 0;
}

static struct fc_host_statistics *
qla2x00_get_fc_host_stats(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = to_qla_parent(shost_priv(shost));
	int rval;
	struct link_statistics *stats;
	dma_addr_t stats_dma;
	struct fc_host_statistics *pfc_host_stat;

	pfc_host_stat = &ha->fc_host_stat;
	memset(pfc_host_stat, -1, sizeof(struct fc_host_statistics));

	stats = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &stats_dma);
	if (stats == NULL) {
		DEBUG2_3_11(printk("%s(%ld): Failed to allocate memory.\n",
		    __func__, ha->host_no));
		goto done;
	}
	memset(stats, 0, DMA_POOL_SIZE);

	rval = QLA_FUNCTION_FAILED;
	if (IS_FWI2_CAPABLE(ha)) {
		rval = qla24xx_get_isp_stats(ha, stats, stats_dma);
	} else if (atomic_read(&ha->loop_state) == LOOP_READY &&
		    !test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags) &&
		    !test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags) &&
		    !ha->dpc_active) {
		/* Must be in a 'READY' state for statistics retrieval. */
		rval = qla2x00_get_link_status(ha, ha->loop_id, stats,
		    stats_dma);
	}

	if (rval != QLA_SUCCESS)
		goto done_free;

	pfc_host_stat->link_failure_count = stats->link_fail_cnt;
	pfc_host_stat->loss_of_sync_count = stats->loss_sync_cnt;
	pfc_host_stat->loss_of_signal_count = stats->loss_sig_cnt;
	pfc_host_stat->prim_seq_protocol_err_count = stats->prim_seq_err_cnt;
	pfc_host_stat->invalid_tx_word_count = stats->inval_xmit_word_cnt;
	pfc_host_stat->invalid_crc_count = stats->inval_crc_cnt;
	if (IS_FWI2_CAPABLE(ha)) {
		pfc_host_stat->tx_frames = stats->tx_frames;
		pfc_host_stat->rx_frames = stats->rx_frames;
		pfc_host_stat->dumped_frames = stats->dumped_frames;
		pfc_host_stat->nos_count = stats->nos_rcvd;
	}

done_free:
        dma_pool_free(ha->s_dma_pool, stats, stats_dma);
done:
	return pfc_host_stat;
}

static void
qla2x00_get_host_symbolic_name(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = shost_priv(shost);

	qla2x00_get_sym_node_name(ha, fc_host_symbolic_name(shost));
}

static void
qla2x00_set_host_system_hostname(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = shost_priv(shost);

	set_bit(REGISTER_FDMI_NEEDED, &ha->dpc_flags);
}

static void
qla2x00_get_host_fabric_name(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = shost_priv(shost);
	u64 node_name;

	if (ha->device_flags & SWITCH_FOUND)
		node_name = wwn_to_u64(ha->fabric_node_name);
	else
		node_name = wwn_to_u64(ha->node_name);

	fc_host_fabric_name(shost) = node_name;
}

static void
qla2x00_get_host_port_state(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = to_qla_parent(shost_priv(shost));

	if (!ha->flags.online)
		fc_host_port_state(shost) = FC_PORTSTATE_OFFLINE;
	else if (atomic_read(&ha->loop_state) == LOOP_TIMEOUT)
		fc_host_port_state(shost) = FC_PORTSTATE_UNKNOWN;
	else
		fc_host_port_state(shost) = FC_PORTSTATE_ONLINE;
}

static int
qla24xx_vport_create(struct fc_vport *fc_vport, bool disable)
{
	int	ret = 0;
	scsi_qla_host_t *ha = shost_priv(fc_vport->shost);
	scsi_qla_host_t *vha;

	ret = qla24xx_vport_create_req_sanity_check(fc_vport);
	if (ret) {
		DEBUG15(printk("qla24xx_vport_create_req_sanity_check failed, "
		    "status %x\n", ret));
		return (ret);
	}

	vha = qla24xx_create_vhost(fc_vport);
	if (vha == NULL) {
		DEBUG15(printk ("qla24xx_create_vhost failed, vha = %p\n",
		    vha));
		return FC_VPORT_FAILED;
	}
	if (disable) {
		atomic_set(&vha->vp_state, VP_OFFLINE);
		fc_vport_set_state(fc_vport, FC_VPORT_DISABLED);
	} else
		atomic_set(&vha->vp_state, VP_FAILED);

	/* ready to create vport */
	qla_printk(KERN_INFO, vha, "VP entry id %d assigned.\n", vha->vp_idx);

	/* initialized vport states */
	atomic_set(&vha->loop_state, LOOP_DOWN);
	vha->vp_err_state=  VP_ERR_PORTDWN;
	vha->vp_prev_err_state=  VP_ERR_UNKWN;
	/* Check if physical ha port is Up */
	if (atomic_read(&ha->loop_state) == LOOP_DOWN ||
	    atomic_read(&ha->loop_state) == LOOP_DEAD) {
		/* Don't retry or attempt login of this virtual port */
		DEBUG15(printk ("scsi(%ld): pport loop_state is not UP.\n",
		    vha->host_no));
		atomic_set(&vha->loop_state, LOOP_DEAD);
		if (!disable)
			fc_vport_set_state(fc_vport, FC_VPORT_LINKDOWN);
	}

	if (scsi_add_host(vha->host, &fc_vport->dev)) {
		DEBUG15(printk("scsi(%ld): scsi_add_host failure for VP[%d].\n",
			vha->host_no, vha->vp_idx));
		goto vport_create_failed_2;
	}

	/* initialize attributes */
	fc_host_node_name(vha->host) = wwn_to_u64(vha->node_name);
	fc_host_port_name(vha->host) = wwn_to_u64(vha->port_name);
	fc_host_supported_classes(vha->host) =
		fc_host_supported_classes(ha->host);
	fc_host_supported_speeds(vha->host) =
		fc_host_supported_speeds(ha->host);

#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	vha->tgt = NULL;
	vha->q2t_tgt = NULL;
	mutex_init(&vha->tgt_mutex);
	mutex_init(&vha->tgt_host_action_mutex);
	qla_clear_tgt_mode(vha);
	qla2x00_send_enable_lun(vha, false);
	if (IS_QLA24XX_TYPE(vha))
		vha->atio_q_length = ATIO_ENTRY_CNT_24XX;
	else if (IS_QLA25XX(vha))
		vha->atio_q_length = ATIO_ENTRY_CNT_24XX;

	if (qla_target.tgt_host_action != NULL)
		qla_target.tgt_host_action(vha, ADD_TARGET);

	/*
	 * Must be after tgt_host_action() to not race with
	 * qla2xxx_add_targets().
	 */
#endif
	qla24xx_vport_disable(fc_vport, disable);

	return 0;
vport_create_failed_2:
	qla24xx_disable_vp(vha);
	qla24xx_deallocate_vp_id(vha);
	kfree(vha->port_name);
	kfree(vha->node_name);
	scsi_host_put(vha->host);
	return FC_VPORT_FAILED;
}

static int
qla24xx_vport_delete(struct fc_vport *fc_vport)
{
	scsi_qla_host_t *ha = shost_priv(fc_vport->shost);
	scsi_qla_host_t *vha = fc_vport->dd_data;

#ifdef CONFIG_SCSI_QLA2XXX_TARGET
	if (qla_target.tgt_host_action != NULL)
		qla_target.tgt_host_action(vha, REMOVE_TARGET);
#endif

	qla24xx_disable_vp(vha);
	qla24xx_deallocate_vp_id(vha);

	mutex_lock(&ha->vport_lock);
	ha->cur_vport_count--;
	clear_bit(vha->vp_idx, ha->vp_idx_map);
	mutex_unlock(&ha->vport_lock);

	kfree(vha->node_name);
	kfree(vha->port_name);

	if (vha->timer_active) {
		qla2x00_vp_stop_timer(vha);
		DEBUG15(printk ("scsi(%ld): timer for the vport[%d] = %p "
		    "has stopped\n",
		    vha->host_no, vha->vp_idx, vha));
        }

	fc_remove_host(vha->host);

	scsi_remove_host(vha->host);

	scsi_host_put(vha->host);

	return 0;
}

static int
qla24xx_vport_disable(struct fc_vport *fc_vport, bool disable)
{
	scsi_qla_host_t *vha = fc_vport->dd_data;

	if (disable)
		qla24xx_disable_vp(vha);
	else
		qla24xx_enable_vp(vha);

	return 0;
}

struct fc_function_template qla2xxx_transport_functions = {

	.show_host_node_name = 1,
	.show_host_port_name = 1,
	.show_host_supported_classes = 1,
	.show_host_supported_speeds = 1,

	.get_host_port_id = qla2x00_get_host_port_id,
	.show_host_port_id = 1,
	.get_host_speed = qla2x00_get_host_speed,
	.show_host_speed = 1,
	.get_host_port_type = qla2x00_get_host_port_type,
	.show_host_port_type = 1,
	.get_host_symbolic_name = qla2x00_get_host_symbolic_name,
	.show_host_symbolic_name = 1,
	.set_host_system_hostname = qla2x00_set_host_system_hostname,
	.show_host_system_hostname = 1,
	.get_host_fabric_name = qla2x00_get_host_fabric_name,
	.show_host_fabric_name = 1,
	.get_host_port_state = qla2x00_get_host_port_state,
	.show_host_port_state = 1,

	.dd_fcrport_size = sizeof(struct fc_port *),
	.show_rport_supported_classes = 1,

	.get_starget_node_name = qla2x00_get_starget_node_name,
	.show_starget_node_name = 1,
	.get_starget_port_name = qla2x00_get_starget_port_name,
	.show_starget_port_name = 1,
	.get_starget_port_id  = qla2x00_get_starget_port_id,
	.show_starget_port_id = 1,

	.set_rport_dev_loss_tmo = qla2x00_set_rport_loss_tmo,
	.show_rport_dev_loss_tmo = 1,

	.issue_fc_host_lip = qla2x00_issue_lip,
	.dev_loss_tmo_callbk = qla2x00_dev_loss_tmo_callbk,
	.terminate_rport_io = qla2x00_terminate_rport_io,
	.get_fc_host_stats = qla2x00_get_fc_host_stats,

	.vport_create = qla24xx_vport_create,
	.vport_disable = qla24xx_vport_disable,
	.vport_delete = qla24xx_vport_delete,
};

struct fc_function_template qla2xxx_transport_vport_functions = {

	.show_host_node_name = 1,
	.show_host_port_name = 1,
	.show_host_supported_classes = 1,

	.get_host_port_id = qla2x00_get_host_port_id,
	.show_host_port_id = 1,
	.get_host_speed = qla2x00_get_host_speed,
	.show_host_speed = 1,
	.get_host_port_type = qla2x00_get_host_port_type,
	.show_host_port_type = 1,
	.get_host_symbolic_name = qla2x00_get_host_symbolic_name,
	.show_host_symbolic_name = 1,
	.set_host_system_hostname = qla2x00_set_host_system_hostname,
	.show_host_system_hostname = 1,
	.get_host_fabric_name = qla2x00_get_host_fabric_name,
	.show_host_fabric_name = 1,
	.get_host_port_state = qla2x00_get_host_port_state,
	.show_host_port_state = 1,

	.dd_fcrport_size = sizeof(struct fc_port *),
	.show_rport_supported_classes = 1,

	.get_starget_node_name = qla2x00_get_starget_node_name,
	.show_starget_node_name = 1,
	.get_starget_port_name = qla2x00_get_starget_port_name,
	.show_starget_port_name = 1,
	.get_starget_port_id  = qla2x00_get_starget_port_id,
	.show_starget_port_id = 1,

	.set_rport_dev_loss_tmo = qla2x00_set_rport_loss_tmo,
	.show_rport_dev_loss_tmo = 1,

	.issue_fc_host_lip = qla2x00_issue_lip,
	.dev_loss_tmo_callbk = qla2x00_dev_loss_tmo_callbk,
	.terminate_rport_io = qla2x00_terminate_rport_io,
	.get_fc_host_stats = qla2x00_get_fc_host_stats,
};

void
qla2x00_init_host_attr(scsi_qla_host_t *ha)
{
	u32 speed = FC_PORTSPEED_UNKNOWN;

	fc_host_node_name(ha->host) = wwn_to_u64(ha->node_name);
	fc_host_port_name(ha->host) = wwn_to_u64(ha->port_name);
	fc_host_supported_classes(ha->host) = ha->enable_class_2 ?
		(FC_COS_CLASS2|FC_COS_CLASS3) : FC_COS_CLASS3;
	fc_host_max_npiv_vports(ha->host) = ha->max_npiv_vports;;
	fc_host_npiv_vports_inuse(ha->host) = ha->cur_vport_count;

	if (IS_QLA25XX(ha))
		speed = FC_PORTSPEED_8GBIT | FC_PORTSPEED_4GBIT |
		    FC_PORTSPEED_2GBIT | FC_PORTSPEED_1GBIT;
	else if (IS_QLA24XX_TYPE(ha))
		speed = FC_PORTSPEED_4GBIT | FC_PORTSPEED_2GBIT |
		    FC_PORTSPEED_1GBIT;
	else if (IS_QLA23XX(ha))
		speed = FC_PORTSPEED_2GBIT | FC_PORTSPEED_1GBIT;
	else
		speed = FC_PORTSPEED_1GBIT;
	fc_host_supported_speeds(ha->host) = speed;
}
