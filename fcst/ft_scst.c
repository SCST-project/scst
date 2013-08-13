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
#include <linux/module.h>
#include <linux/types.h>
#include <scsi/libfc.h>
#include "fcst.h"

unsigned int ft_debug_logging;
module_param_named(debug_logging, ft_debug_logging, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug_logging, "log levels bigmask");

DEFINE_MUTEX(ft_lport_lock);

static struct notifier_block ft_notifier = {
	.notifier_call = ft_lport_notify
};

/*
 * SCST target ops and configuration.
 * XXX - re-check uninitialized fields
 */
struct scst_tgt_template ft_scst_template = {
	.sg_tablesize = 128,		/* XXX get true limit from libfc */
	.xmit_response_atomic = 1,
	.rdy_to_xfer_atomic = 1,
	.xmit_response =	ft_send_response,
	.rdy_to_xfer =		ft_send_xfer_rdy,
	.on_hw_pending_cmd_timeout = ft_cmd_timeout,
	.on_free_cmd =		ft_cmd_free,
	.task_mgmt_fn_done =	ft_cmd_tm_done,
	.detect =		ft_tgt_detect,
	.release =		ft_tgt_release,
	.report_aen =		ft_report_aen,
	.enable_target =	ft_tgt_enable,
	.is_target_enabled =	ft_tgt_enabled,
	.get_initiator_port_transport_id = ft_get_transport_id,
	.max_hw_pending_time =	FT_MAX_HW_PENDING_TIME,
	.name =			FT_MODULE,
};

static int __init ft_module_init(void)
{
	int err;

	err = scst_register_target_template(&ft_scst_template);
	if (err)
		return err;
	err = fc_fc4_register_provider(FC_TYPE_FCP, &ft_prov);
	if (err) {
		scst_unregister_target_template(&ft_scst_template);
		return err;
	}
	blocking_notifier_chain_register(&fc_lport_notifier_head, &ft_notifier);
	fc_lport_iterate(ft_lport_add, NULL);
	return 0;
}

static void __exit ft_module_exit(void)
{
	blocking_notifier_chain_unregister(&fc_lport_notifier_head,
					   &ft_notifier);
	fc_fc4_deregister_provider(FC_TYPE_FCP, &ft_prov);
	fc_lport_iterate(ft_lport_del, NULL);
	scst_unregister_target_template(&ft_scst_template);
	synchronize_rcu();
}

MODULE_AUTHOR("Joe Eykholt <jeykholt@cisco.com>");
MODULE_DESCRIPTION("SCST FCoE target driver v" FT_VERSION);
MODULE_LICENSE("GPL v2");
module_init(ft_module_init);
module_exit(ft_module_exit);
