#include <linux/module.h>
#include <rdma/ib_cm.h>

static int modinit(void)
{
	struct ib_qp qp = { };
	const struct ib_recv_wr recv_wr = { };
	const struct ib_recv_wr *bad_recv_wr;

	return ib_post_recv(&qp, &recv_wr, &bad_recv_wr);
}

module_init(modinit);
