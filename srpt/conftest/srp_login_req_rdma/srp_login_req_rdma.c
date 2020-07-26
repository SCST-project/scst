#include <linux/module.h>
#include <scsi/srp.h>

static int __init modinit(void)
{
	return sizeof(struct srp_login_req_rdma);
}

module_init(modinit);

MODULE_LICENSE("GPL");
