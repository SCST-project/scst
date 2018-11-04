#include <linux/module.h>
#include <rdma/ib_cm.h>

static int modinit(void)
{
	struct ib_qp *qp = NULL;
	const struct ib_recv_wr *recv_wr = NULL;
	const struct ib_recv_wr **bad_recv_wr = NULL;

	return ib_post_recv(qp, recv_wr, bad_recv_wr);
}

module_init(modinit);
