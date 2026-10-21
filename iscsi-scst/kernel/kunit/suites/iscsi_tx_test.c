// SPDX-License-Identifier: GPL-2.0-only
#ifdef INSIDE_KERNEL_TREE
#include "../../../kunit/scst_kunit.h"
#else
#include "../../../../scst/src/kunit/scst_kunit.h"
#endif
#include "../../iscsi_trace_flag.h"
#include "../../iscsi.h"
#include "../../nthread.h"
#include "../../nthread_test.h"

struct iscsi_tx_fixture {
	struct iscsi_conn conn;
	struct iscsi_session session;
	struct iscsi_cmnd rsp;
	struct iscsit_transport transport;
	struct socket socket;
	int send_result;
	unsigned int sends;
	unsigned int closes;
	unsigned int completions;
};

static int iscsi_tx_write_stub(struct iscsi_conn *conn)
{
	struct kunit *test = kunit_get_current_test();
	struct iscsi_tx_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, conn, &f->conn);
	f->sends++;
	if (f->send_result > 0)
		conn->write_size -= f->send_result;
	return f->send_result;
}

static int iscsi_tx_send_stub(struct socket *sock, struct msghdr *msg,
			      struct kvec *iov, size_t size)
{
	struct kunit *test = kunit_get_current_test();
	struct iscsi_tx_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, sock, &f->socket);
	KUNIT_EXPECT_EQ(test, msg->msg_flags, MSG_NOSIGNAL | MSG_DONTWAIT);
	KUNIT_EXPECT_EQ(test, size, (size_t)f->conn.write_size);
	KUNIT_EXPECT_EQ(test, iov->iov_len, size);
	if (f->conn.write_state == TX_PADDING) {
		unsigned int i;

		for (i = 0; i < size; i++)
			KUNIT_EXPECT_EQ(test, ((u8 *)iov->iov_base)[i], (u8)0);
	} else {
		KUNIT_EXPECT_EQ(test, f->conn.write_state, TX_DDIGEST);
		KUNIT_EXPECT_PTR_EQ(test, iov->iov_base,
				    (u8 *)&f->rsp.ddigest + sizeof(u32) - size);
	}
	f->sends++;
	return f->send_result;
}

static void iscsi_tx_close_stub(struct iscsi_conn *conn, int flags)
{
	struct kunit *test = kunit_get_current_test();
	struct iscsi_tx_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, conn, &f->conn);
	KUNIT_EXPECT_EQ(test, flags, ISCSI_CONN_ACTIVE_CLOSE);
	KUNIT_EXPECT_EQ(test, conn->write_state, TX_END);
	KUNIT_EXPECT_EQ(test, conn->write_size, 0);
	KUNIT_EXPECT_EQ(test, f->completions, 0U);
	conn->closing = 1;
	f->closes++;
}

static void iscsi_tx_complete_stub(struct iscsi_cmnd *cmnd)
{
	struct kunit *test = kunit_get_current_test();
	struct iscsi_tx_fixture *f = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, cmnd, &f->rsp);
	KUNIT_EXPECT_EQ(test, f->conn.write_state, TX_END);
	KUNIT_EXPECT_EQ(test, f->conn.write_size, 0);
	KUNIT_EXPECT_PTR_EQ(test, f->conn.write_cmnd, cmnd);
	f->completions++;
}

static int iscsi_tx_test_init(struct kunit *test)
{
	struct iscsi_tx_fixture *f;

	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;
	test->priv = f;
	f->conn.session = &f->session;
	f->session.initiator_name = "kunit-private-initiator";
	f->conn.transport = &f->transport;
	f->transport.iscsit_mark_conn_closed = iscsi_tx_close_stub;
	f->conn.sock = &f->socket;
	f->conn.write_cmnd = &f->rsp;
	f->conn.ddigest_type = DIGEST_NONE;
	f->conn.wr_state = ISCSI_CONN_WR_STATE_PROCESSING;
#ifdef CONFIG_SCST_EXTRACHECKS
	f->conn.wr_task = current;
#endif
	f->rsp.conn = &f->conn;
	f->rsp.ddigest = (__force __be32)cpu_to_le32(0x12345678);
	kunit_activate_static_stub(test, write_data, iscsi_tx_write_stub);
	kunit_activate_static_stub(test, iscsi_tx_sendmsg, iscsi_tx_send_stub);
	kunit_activate_static_stub(test, iscsi_tx_complete, iscsi_tx_complete_stub);
	return 0;
}

struct iscsi_tx_result_case {
	const char *name;
	int state;
	int result;
};

#define TX_RESULTS(phase, state) \
	{ phase "-closed", state, 0 }, \
	{ phase "-io-error", state, -EIO }, \
	{ phase "-broken-pipe", state, -EPIPE }, \
	{ phase "-retry", state, -EAGAIN }, \
	{ phase "-interrupted", state, -ERESTARTSYS }, \
	{ phase "-short-write", state, 1 }, \
	{ phase "-complete", state, 3 }

static const struct iscsi_tx_result_case iscsi_tx_results[] = {
	TX_RESULTS("data", TX_BHS_DATA),
	TX_RESULTS("padding", TX_PADDING),
	TX_RESULTS("digest", TX_DDIGEST),
};

#undef TX_RESULTS

static void iscsi_tx_result_desc(const struct iscsi_tx_result_case *p, char *desc)
{
	strscpy(desc, p->name, KUNIT_PARAM_DESC_SIZE);
}

KUNIT_ARRAY_PARAM(iscsi_tx_result, iscsi_tx_results, iscsi_tx_result_desc);

static void iscsi_tx_result_test(struct kunit *test)
{
	const struct iscsi_tx_result_case *p = test->param_value;
	struct iscsi_tx_fixture *f = test->priv;
	bool fatal = p->result <= 0 && p->result != -EAGAIN && p->result != -ERESTARTSYS;
	bool done = fatal || p->result == 3;

	f->conn.write_state = p->state;
	f->conn.write_size = 3;
	f->send_result = p->result;
	KUNIT_EXPECT_EQ(test, iscsi_send(&f->conn), p->result);
	KUNIT_EXPECT_EQ(test, f->sends, 1U);
	KUNIT_EXPECT_EQ(test, f->closes, (unsigned int)fatal);
	KUNIT_EXPECT_EQ(test, f->completions, (unsigned int)done);
	KUNIT_EXPECT_EQ(test, f->conn.write_state, done ? TX_INIT : p->state);
	KUNIT_EXPECT_EQ(test, f->conn.write_size, done ? 0 : (p->result > 0 ? 2 : 3));
	if (done)
		KUNIT_EXPECT_PTR_EQ(test, f->conn.write_cmnd, NULL);
	else
		KUNIT_EXPECT_PTR_EQ(test, f->conn.write_cmnd, &f->rsp);

	if (!done) {
		/* Retry continues the same response, including the digest offset. */
		f->send_result = f->conn.write_size;
		KUNIT_EXPECT_GT(test, iscsi_send(&f->conn), 0);
		KUNIT_EXPECT_EQ(test, f->completions, 1U);
		KUNIT_EXPECT_EQ(test, f->closes, 0U);
		KUNIT_EXPECT_EQ(test, f->conn.write_state, TX_INIT);
		KUNIT_EXPECT_PTR_EQ(test, f->conn.write_cmnd, NULL);
	}
}

struct iscsi_tx_padding_case {
	const char *name;
	unsigned int data_size;
	bool digest;
};

static const struct iscsi_tx_padding_case iscsi_tx_paddings[] = {
	{ "aligned", 4, false },
	{ "one-byte", 3, false },
	{ "two-bytes", 2, false },
	{ "three-bytes", 1, false },
	{ "aligned-digest", 4, true },
	{ "one-byte-digest", 3, true },
	{ "two-bytes-digest", 2, true },
	{ "three-bytes-digest", 1, true },
};

static void iscsi_tx_padding_desc(const struct iscsi_tx_padding_case *p, char *desc)
{
	strscpy(desc, p->name, KUNIT_PARAM_DESC_SIZE);
}

KUNIT_ARRAY_PARAM(iscsi_tx_padding_case, iscsi_tx_paddings, iscsi_tx_padding_desc);

static void iscsi_tx_padding_test(struct kunit *test)
{
	const struct iscsi_tx_padding_case *p = test->param_value;
	struct iscsi_tx_fixture *f = test->priv;
	unsigned int padding = (4 - p->data_size) & 3;

	f->conn.write_state = TX_BHS_DATA;
	f->conn.write_size = 1;
	f->rsp.pdu.datasize = p->data_size;
	f->conn.ddigest_type = p->digest ? DIGEST_CRC32C : DIGEST_NONE;
	f->send_result = 1;
	KUNIT_EXPECT_EQ(test, iscsi_send(&f->conn), 1);
	KUNIT_EXPECT_EQ(test, f->conn.write_state,
			padding ? TX_PADDING : (p->digest ? TX_INIT_DDIGEST : TX_INIT));
	KUNIT_EXPECT_EQ(test, f->completions, (unsigned int)(!padding && !p->digest));
	if (padding) {
		f->send_result = -EAGAIN;
		KUNIT_EXPECT_EQ(test, iscsi_send(&f->conn), -EAGAIN);
		KUNIT_EXPECT_EQ(test, f->conn.write_size, (int)padding);
		/* With a digest, the same call also makes a short digest write. */
		f->send_result = padding;
		KUNIT_EXPECT_EQ(test, iscsi_send(&f->conn), (int)padding);
	}
	if (p->digest) {
		f->send_result = padding ? sizeof(u32) - padding : sizeof(u32);
		KUNIT_EXPECT_GT(test, iscsi_send(&f->conn), 0);
	}
	KUNIT_EXPECT_EQ(test, f->completions, 1U);
	KUNIT_EXPECT_EQ(test, f->closes, 0U);
	KUNIT_EXPECT_EQ(test, f->conn.write_size, 0);
	KUNIT_EXPECT_EQ(test, f->conn.write_state, TX_INIT);
	KUNIT_EXPECT_PTR_EQ(test, f->conn.write_cmnd, NULL);
}

static struct kunit_case iscsi_tx_cases[] = {
	KUNIT_CASE_PARAM(iscsi_tx_result_test, iscsi_tx_result_gen_params),
	KUNIT_CASE_PARAM(iscsi_tx_padding_test, iscsi_tx_padding_case_gen_params),
	{}
};

scst_kunit_suite(iscsi_tx_suite, "ISCSI", "-tx",
		 .init = iscsi_tx_test_init,
		 .test_cases = iscsi_tx_cases,
);
