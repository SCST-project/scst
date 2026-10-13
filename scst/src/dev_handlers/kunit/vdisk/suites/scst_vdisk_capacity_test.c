// SPDX-License-Identifier: GPL-2.0-only
#include "../../../../kunit/scst_kunit.h"
#include "../../../scst_vdisk_priv.h"
#include "../../../scst_vdisk_test.h"

struct capacity_fixture {
	struct scst_cmd cmd;
	struct scst_device dev;
	struct scst_session sess;
	struct scst_vdisk_dev vdev;
	struct vdisk_cmd_params params;
	struct block_device bdev;
	struct request_queue queue;
	struct gendisk disk;
	struct scatterlist sg[2];
	u8 sense[SCST_SENSE_BUFFERSIZE];
	u8 buffer[65];
};

/* Last LBA 0x12345678, 512-byte logical blocks, remaining fields clear. */
static const u8 capacity_wire[32] = {
	0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78,
	0, 0, 2, 0,
};

static int capacity_init(struct kunit *test)
{
	struct capacity_fixture *f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);

	if (!f)
		return -ENOMEM;
	test->priv = f;
	f->dev.dh_priv = &f->vdev;
	f->dev.block_size = 512;
	f->dev.block_shift = 9;
	f->vdev.dev = &f->dev;
	f->vdev.nblocks = 0x12345679;
	f->cmd.dev = &f->dev;
	f->cmd.sess = &f->sess;
	f->cmd.cmd_gfp_mask = GFP_KERNEL;
	f->cmd.cdb = f->cmd.cdb_buf;
	f->cmd.cdb[0] = SERVICE_ACTION_IN_16;
	f->cmd.cdb[1] = SAI_READ_CAPACITY_16;
	f->cmd.data_direction = SCST_DATA_READ;
	f->cmd.sense = f->sense;
	f->cmd.sense_buflen = sizeof(f->sense);
	f->params.cmd = &f->cmd;
	atomic_set(&f->sess.sess_cmd_count, 1);
	f->sess.initiator_name = "kunit";
	f->sess.init_phase = SCST_SESS_IPH_READY;
	return 0;
}

static void capacity_buffer(struct capacity_fixture *f, unsigned int length,
			    unsigned int split)
{
	memset(f->buffer, 0xa5, sizeof(f->buffer));
	put_unaligned_be32(length, &f->cmd.cdb[10]);
	f->cmd.bufflen = length;
	f->cmd.resp_data_len = length;
	if (!length)
		return;
	if (split) {
		sg_init_table(f->sg, 2);
		sg_set_buf(&f->sg[0], f->buffer, split);
		sg_set_buf(&f->sg[1], f->buffer + split, length - split);
		f->cmd.sg_cnt = 2;
	} else {
		sg_init_one(f->sg, f->buffer, length);
		f->cmd.sg_cnt = 1;
	}
	f->cmd.sg = f->sg;
}

struct capacity_format_case {
	const char *name;
	u32 block_size;
	u32 physical_size;
	bool nullio;
	bool exponent;
	bool thin;
	bool zeroes;
	u8 dif_type;
	u8 expected_exponent;
	u8 expected_provisioning;
	u8 expected_protection;
};

static const struct capacity_format_case capacity_format_cases[] = {
	{ .name = "fileio_512", .block_size = 512, .exponent = true,
	  .expected_exponent = 3 },
	{ .name = "fileio_4096", .block_size = 4096, .exponent = true },
	{ .name = "fileio_exponent_disabled", .block_size = 512 },
	{ .name = "nullio_512", .block_size = 512, .nullio = true,
	  .exponent = true, .expected_exponent = 3 },
	{ .name = "blockio_512_4096", .block_size = 512, .physical_size = 4096,
	  .exponent = true, .expected_exponent = 3 },
	{ .name = "blockio_512_512", .block_size = 512, .physical_size = 512,
	  .exponent = true },
	{ .name = "blockio_512_8192", .block_size = 512, .physical_size = 8192,
	  .exponent = true, .expected_exponent = 4 },
	{ .name = "blockio_4096_512", .block_size = 4096, .physical_size = 512,
	  .exponent = true },
	{ .name = "blockio_exponent_disabled", .block_size = 512, .physical_size = 8192 },
	{ .name = "thin_without_zeroes", .block_size = 512, .thin = true,
	  .expected_provisioning = 0x80 },
	{ .name = "thin_with_zeroes", .block_size = 512, .thin = true, .zeroes = true,
	  .expected_provisioning = 0xc0 },
	{ .name = "zeroes_without_thin", .block_size = 512, .zeroes = true },
	{ .name = "dif_type_1", .block_size = 512, .dif_type = 1,
	  .expected_protection = 1 },
	{ .name = "dif_type_2", .block_size = 512, .dif_type = 2,
	  .expected_protection = 3 },
	{ .name = "dif_type_3", .block_size = 512, .dif_type = 3,
	  .expected_protection = 5 },
};

static void capacity_format_desc(const struct capacity_format_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(capacity_format, capacity_format_cases, capacity_format_desc);

static void capacity_format(struct kunit *test)
{
	const struct capacity_format_case *p = test->param_value;
	struct capacity_fixture *f = test->priv;
	u8 expected[32];

	memcpy(expected, capacity_wire, sizeof(expected));
	if (p->block_size == 4096)
		expected[10] = 0x10;
	expected[12] = p->expected_protection;
	expected[13] = p->expected_exponent;
	expected[14] = p->expected_provisioning;
	f->dev.block_size = p->block_size;
	f->dev.block_shift = ilog2(p->block_size);
	f->vdev.nullio = p->nullio;
	f->vdev.lb_per_pb_exp = p->exponent;
	f->vdev.thin_provisioned = p->thin;
	f->vdev.discard_zeroes_data = p->zeroes;
	if (p->physical_size) {
		/* Only queue geometry is consumed; no device is opened or registered. */
		f->vdev.blockio = true;
		f->vdev.bdev_desc.bdev = &f->bdev;
		f->bdev.bd_disk = &f->disk;
		f->bdev.bd_queue = &f->queue;
		f->disk.queue = &f->queue;
		f->queue.limits.physical_block_size = p->physical_size;
	}
	if (p->dif_type) {
		f->dev.dev_dif_mode = SCST_DIF_MODE_TGT;
		f->dev.dev_dif_type = p->dif_type;
	}
	capacity_buffer(f, 32, 0);
	KUNIT_EXPECT_EQ(test, vdisk_exec_sai_16(&f->params), CMD_SUCCEEDED);
	KUNIT_EXPECT_EQ(test, f->cmd.status, SAM_STAT_GOOD);
	KUNIT_EXPECT_EQ(test, f->cmd.resp_data_len, 32);
	KUNIT_EXPECT_EQ(test, memcmp(f->buffer, expected, sizeof(expected)), 0);
	KUNIT_EXPECT_EQ(test, f->buffer[32], 0xa5);
}

struct capacity_length_case {
	const char *name;
	u32 length;
	u32 split;
	u32 expected_length;
};

static const struct capacity_length_case capacity_length_cases[] = {
	{ "no_buffer", 0, 0, 0 },
	{ "one_byte", 1, 0, 1 },
	{ "lba_only", 8, 0, 8 },
	{ "through_block_size", 12, 0, 12 },
	{ "through_exponent", 14, 0, 14 },
	{ "short_response", 31, 0, 31 },
	{ "full_response", 32, 0, 32 },
	{ "oversized_buffer", 64, 0, 32 },
	{ "lba_across_sg", 32, 3, 32 },
	{ "flags_across_sg", 32, 13, 32 },
	{ "short_scatterlist", 15, 7, 15 },
};

static void capacity_length_desc(const struct capacity_length_case *p, char *desc)
{
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "%s", p->name);
}

KUNIT_ARRAY_PARAM(capacity_length, capacity_length_cases, capacity_length_desc);

static void capacity_length(struct kunit *test)
{
	const struct capacity_length_case *p = test->param_value;
	struct capacity_fixture *f = test->priv;
	unsigned int i;

	capacity_buffer(f, p->length, p->split);
	KUNIT_EXPECT_EQ(test, vdisk_exec_sai_16(&f->params), CMD_SUCCEEDED);
	KUNIT_EXPECT_EQ(test, f->cmd.status, SAM_STAT_GOOD);
	KUNIT_EXPECT_EQ(test, f->cmd.resp_data_len, (int)p->expected_length);
	KUNIT_EXPECT_FALSE(test, f->cmd.sg_buff_vmallocated);
	KUNIT_EXPECT_EQ(test, memcmp(f->buffer, capacity_wire, p->expected_length), 0);
	for (i = p->expected_length; i < sizeof(f->buffer); i++)
		KUNIT_EXPECT_EQ_MSG(test, f->buffer[i], 0xa5, "byte %u", i);
}

static void capacity_large_lba(struct kunit *test)
{
	struct capacity_fixture *f = test->priv;
	const u8 expected_lba[] = { 0, 0, 0, 1, 0, 0, 0, 1 };

	f->vdev.nblocks = 0x100000002ULL;
	capacity_buffer(f, 32, 0);
	KUNIT_ASSERT_EQ(test, vdisk_exec_sai_16(&f->params), CMD_SUCCEEDED);
	KUNIT_EXPECT_EQ(test, f->cmd.status, SAM_STAT_GOOD);
	KUNIT_EXPECT_EQ(test, memcmp(f->buffer, expected_lba, sizeof(expected_lba)), 0);
}

static void capacity_invalid_lba(struct kunit *test)
{
	struct capacity_fixture *f = test->priv;
	unsigned int i;

	f->cmd.cdb[2] = 1;
	capacity_buffer(f, 32, 0);
	KUNIT_EXPECT_EQ(test, vdisk_exec_sai_16(&f->params), CMD_SUCCEEDED);
	KUNIT_EXPECT_EQ(test, f->cmd.status, SAM_STAT_CHECK_CONDITION);
	KUNIT_EXPECT_EQ(test, f->cmd.resp_data_len, 0);
	KUNIT_EXPECT_EQ(test, f->sense[2], ILLEGAL_REQUEST);
	KUNIT_EXPECT_EQ(test, f->sense[12], 0x24);
	KUNIT_EXPECT_EQ(test, f->sense[15], 0xc0);
	KUNIT_EXPECT_EQ(test, get_unaligned_be16(f->sense + 16), 2);
	for (i = 0; i < sizeof(f->buffer); i++)
		KUNIT_EXPECT_EQ(test, f->buffer[i], 0xa5);
}

static struct kunit_case scst_vdisk_capacity_cases[] = {
	KUNIT_CASE_PARAM(capacity_format, capacity_format_gen_params),
	KUNIT_CASE_PARAM(capacity_length, capacity_length_gen_params),
	KUNIT_CASE(capacity_large_lba),
	KUNIT_CASE(capacity_invalid_lba),
	{}
};

scst_kunit_suite(scst_vdisk_capacity_suite, "VDISK", "-capacity",
		 .init = capacity_init,
		 .test_cases = scst_vdisk_capacity_cases,
);
