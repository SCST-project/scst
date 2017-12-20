#include <linux/module.h>
#include <linux/net.h>

static int modinit(void)
{
	int (*f)(struct socket *, struct msghdr *, size_t, int) = sock_recvmsg;

	return f != NULL;
}

module_init(modinit);
