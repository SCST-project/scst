#include <linux/module.h>
#include <rdma/ib_mad.h>

static void imrh(struct ib_mad_agent *mad_agent,
		 struct ib_mad_send_buf *send_buf,
		 struct ib_mad_recv_wc *mad_recv_wc)
{
}

static int modinit(void)
{
	ib_mad_recv_handler h = imrh;

	return !!h;
}

module_init(modinit);
