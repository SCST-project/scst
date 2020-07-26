#include <linux/module.h>
#include <rdma/ib_verbs.h>

static int __init modinit(void)
{
	struct ib_send_wr wr = { };

	return wr.wr.rdma.rkey;
}

module_init(modinit);

MODULE_LICENSE("GPL");
