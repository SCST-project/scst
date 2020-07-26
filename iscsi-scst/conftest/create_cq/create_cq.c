#include <linux/module.h>
#include <rdma/ib_verbs.h>

static int __init modinit(void)
{
	struct ib_cq *q;

	q = ib_create_cq(NULL, NULL, NULL, NULL, NULL);

	return q != 0;
}

module_init(modinit);

MODULE_LICENSE("GPL");
