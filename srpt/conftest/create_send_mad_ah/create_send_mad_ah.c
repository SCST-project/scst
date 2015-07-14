#include <linux/module.h>
#include <rdma/ib_mad.h>

static int modinit(void)
{
	struct ib_mad_send_buf *b;

	b = ib_create_send_mad(NULL, 0, 0, NULL, 0, 0, 0, 0);

	return b != 0;
}

module_init(modinit);
