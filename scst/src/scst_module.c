/*
 *  scst_module.c
 *
 *  Copyright (C) 2004 - 2013 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
 *
 *  Support for loading target modules. The usage is similar to scsi_module.c
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

#include <linux/module.h>
#include <linux/init.h>

#include <scst.h>

static int __init init_this_scst_driver(void)
{
	int res;

	TRACE_ENTRY();

	res = scst_register_target_template(&driver_target_template);
	TRACE_DBG("scst_register_target_template() returned %d", res);
	if (res < 0)
		goto out;

#ifdef SCST_REGISTER_INITIATOR_DRIVER
	driver_template.module = THIS_MODULE;
	scsi_register_module(MODULE_SCSI_HA, &driver_template);
	TRACE_DBG("driver_template.present=%d",
	      driver_template.present);
	if (driver_template.present == 0) {
		res = -ENODEV;
		MOD_DEC_USE_COUNT;
		goto out;
	}
#endif

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void __exit exit_this_scst_driver(void)
{
	TRACE_ENTRY();

#ifdef SCST_REGISTER_INITIATOR_DRIVER
	scsi_unregister_module(MODULE_SCSI_HA, &driver_template);
#endif

	scst_unregister_target_template(&driver_target_template);

	TRACE_EXIT();
	return;
}

module_init(init_this_scst_driver);
module_exit(exit_this_scst_driver);
