/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCST_ISCSI_NTHREAD_TEST_H
#define SCST_ISCSI_NTHREAD_TEST_H

#ifdef INSIDE_KERNEL_TREE
#include "../scst_test.h"
#else
#include "../../scst/src/scst_test.h"
#endif

#ifdef SCST_KUNIT_ENABLED

int write_data(struct iscsi_conn *conn);
int iscsi_tx_sendmsg(struct socket *sock, struct msghdr *msg,
		     struct kvec *iov, size_t size);
void iscsi_tx_complete(struct iscsi_cmnd *cmnd);
bool iscsi_shutdown_timed_out(bool deleting, unsigned long started, unsigned long now);

#endif /* SCST_KUNIT_ENABLED */
#endif /* SCST_ISCSI_NTHREAD_TEST_H */
