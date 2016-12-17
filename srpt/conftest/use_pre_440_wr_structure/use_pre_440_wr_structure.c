#include <linux/module.h>
#include <rdma/ib_verbs.h>

static int modinit(void)
{
	struct ib_send_wr wr = { };

	return wr.wr.rdma.rkey;
}

module_init(modinit);
