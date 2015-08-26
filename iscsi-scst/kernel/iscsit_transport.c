
#include <linux/spinlock.h>
#include "iscsi_trace_flag.h"
#ifdef INSIDE_KERNEL_TREE
#include <scst/iscsit_transport.h>
#else
#include "iscsit_transport.h"
#endif
#include "iscsi.h"

static LIST_HEAD(transport_list);
static DEFINE_MUTEX(transport_mutex);

static struct iscsit_transport *__iscsit_get_transport(enum iscsit_transport_type type)
{
	struct iscsit_transport *t;

	list_for_each_entry(t, &transport_list, transport_list_entry) {
		if (t->transport_type == type)
			return t;
	}

	return NULL;
}

struct iscsit_transport *iscsit_get_transport(enum iscsit_transport_type type)
{
	struct iscsit_transport *t;

	mutex_lock(&transport_mutex);
	t = __iscsit_get_transport(type);
	mutex_unlock(&transport_mutex);

	return t;
}

int iscsit_reg_transport(struct iscsit_transport *t)
{
	struct iscsit_transport *tmp;
	int ret = 0;

	INIT_LIST_HEAD(&t->transport_list_entry);

	mutex_lock(&transport_mutex);
	tmp = __iscsit_get_transport(t->transport_type);
	if (tmp) {
		PRINT_ERROR("Unable to register transport type %d - Already registered",
			    t->transport_type);
		ret = -EEXIST;
	} else {
		list_add_tail(&t->transport_list_entry, &transport_list);
		PRINT_INFO("Registered iSCSI transport: %s", t->name);
	}
	mutex_unlock(&transport_mutex);

	return ret;
}
EXPORT_SYMBOL(iscsit_reg_transport);

void iscsit_unreg_transport(struct iscsit_transport *t)
{
	mutex_lock(&transport_mutex);
	list_del(&t->transport_list_entry);
	mutex_unlock(&transport_mutex);

	PRINT_INFO("Unregistered iSCSI transport: %s", t->name);
}
EXPORT_SYMBOL(iscsit_unreg_transport);

