#include <linux/module.h>
#include <scsi/srp.h>

static int modinit(void)
{
	return sizeof(struct srp_login_req_rdma);
}

module_init(modinit);
