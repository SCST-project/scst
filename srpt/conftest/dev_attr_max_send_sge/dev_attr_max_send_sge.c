#include <linux/module.h>
#include <linux/stddef.h>
#include <rdma/ib_verbs.h>

static int modinit(void)
{
	return offsetof(struct ib_device_attr, max_send_sge);
}

module_init(modinit);
