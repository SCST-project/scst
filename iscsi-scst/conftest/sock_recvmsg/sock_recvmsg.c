#include <linux/module.h>
#include <linux/net.h>

static int __init modinit(void)
{
	int (*f)(struct socket *, struct msghdr *, size_t, int) = sock_recvmsg;

	return f != NULL;
}

module_init(modinit);

MODULE_LICENSE("GPL");
