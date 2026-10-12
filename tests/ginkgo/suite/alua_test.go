// SPDX-License-Identifier: GPL-2.0-only
package suite

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ALUA configuration", Label("basic", "alua"), func() {
	var f *fixture
	BeforeEach(func() { f = newFixture() })

	It("manages device groups, target groups and remote target entries", func(ctx SpecContext) {
		d, dg := f.device(ctx, "disk"), f.deviceGroup(ctx, "devices")
		tg, entry := f.name("ports"), f.name("remote")
		f.do(ctx, "-add_dgrp_dev", d, "-dev_group", dg)
		f.do(ctx, "-add_tgrp", tg, "-dev_group", dg)
		f.do(ctx, "-set_tgrp_attr", tg, "-dev_group", dg, "-attributes", "group_id=7")
		f.do(ctx, "-add_tgrp_tgt", entry, "-dev_group", dg, "-tgt_group", tg)
		f.do(ctx, "-set_ttgt_attr", entry, "-dev_group", dg, "-tgt_group", tg, "-attributes", "rel_tgt_id=8")
		members := must(cli.DeviceGroup(ctx, dg))
		Expect(members["Devices"]).To(ConsistOf(d))
		Expect(members["Target Groups"]).To(ConsistOf(tg))
		Expect(must(cli.Names(ctx, "Targets", "-list_tgrp", tg, "-dev_group", dg))).To(ConsistOf(entry))
		Expect(must(cli.Scalar(ctx, "group_id", "-list_tgrp_attr", tg, "-dev_group", dg))).To(Equal("7"))
		Expect(must(cli.Scalar(ctx, "rel_tgt_id", "-list_ttgt_attr", entry, "-dev_group", dg, "-tgt_group", tg))).To(Equal("8"))
		f.do(ctx, "-rem_tgrp_tgt", entry, "-dev_group", dg, "-tgt_group", tg)
		Expect(must(cli.Names(ctx, "Targets", "-list_tgrp", tg, "-dev_group", dg))).To(BeEmpty())
		f.do(ctx, "-rem_tgrp", tg, "-dev_group", dg)
		Expect(must(cli.DeviceGroup(ctx, dg))["Target Groups"]).To(BeEmpty())
		f.do(ctx, "-rem_dgrp_dev", d, "-dev_group", dg)
		Expect(must(cli.DeviceGroup(ctx, dg))["Devices"]).To(BeEmpty())
		f.do(ctx, "-rem_dgrp", dg)
		Expect(must(cli.Names(ctx, "Device Group", "-list_dgrp"))).NotTo(ContainElement(dg))
		Expect(must(cli.Devices(ctx))).To(HaveKey(d))
	})

	It("rejects duplicate and conflicting device membership", Label("negative"), func(ctx SpecContext) {
		d, first, second := f.device(ctx, "disk"), f.deviceGroup(ctx, "first"), f.deviceGroup(ctx, "second")
		f.do(ctx, "-add_dgrp_dev", d, "-dev_group", first)
		f.reject(ctx, "-add_dgrp_dev", d, "-dev_group", first)
		Expect(must(cli.DeviceGroup(ctx, first))["Devices"]).To(ConsistOf(d))
		f.reject(ctx, "-add_dgrp_dev", d, "-dev_group", second)
		Expect(must(cli.DeviceGroup(ctx, first))["Devices"]).To(ConsistOf(d))
		Expect(must(cli.DeviceGroup(ctx, second))["Devices"]).To(BeEmpty())
	})
})
