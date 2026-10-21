// SPDX-License-Identifier: GPL-2.0-only
package suite

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"scst-component-tests/internal/testcfg"
)

var _ = Describe("Device management", Label("basic", "devices"), func() {
	var f *fixture
	BeforeEach(func() { f = newFixture() })

	It("opens and closes a device without removing its neighbor", Label("pr"), func(ctx SpecContext) {
		d, neighbor := f.device(ctx, "disk"), f.device(ctx, "neighbor")
		Expect(must(cli.Devices(ctx))).To(Equal(map[string]string{d: "vdisk_nullio", neighbor: "vdisk_nullio"}))
		Expect(must(cli.Scalar(ctx, "dummy", "-list_device", d))).To(Equal("1"))
		f.do(ctx, "-close_dev", d, "-handler", "vdisk_nullio")
		Expect(must(cli.Devices(ctx))).To(Equal(map[string]string{neighbor: "vdisk_nullio"}))
	})

	It("rejects a duplicate name and preserves the existing device", Label("negative", "pr"), func(ctx SpecContext) {
		d := f.device(ctx, "disk")
		before := must(cli.Scalar(ctx, "size_mb", "-list_device", d))
		f.reject(ctx, "-open_dev", d, "-handler", "vdisk_nullio", "-attributes", "dummy=1,size_mb=16")
		Expect(must(cli.Devices(ctx))).To(Equal(map[string]string{d: "vdisk_nullio"}))
		Expect(must(cli.Scalar(ctx, "size_mb", "-list_device", d))).To(Equal(before))
	})

	DescribeTable("refuses to close an assigned device until it is unmapped", Label("negative"),
		func(ctx SpecContext, inGroup bool) {
			d, t := f.device(ctx, "disk"), f.target(ctx, "target")
			g := ""
			if inGroup {
				g = f.name("group")
				f.at(ctx, t, "", "-add_group", g)
			}
			f.at(ctx, t, g, "-add_lun", "0", "-device", d)
			f.reject(ctx, "-close_dev", d, "-handler", "vdisk_nullio")
			Expect(must(cli.Devices(ctx))).To(HaveKey(d))
			Expect(f.luns(ctx, t, g)).To(Equal(map[int]string{0: d}))
			f.at(ctx, t, g, "-rem_lun", "0")
			Expect(f.luns(ctx, t, g)).To(BeEmpty())
			f.do(ctx, "-close_dev", d, "-handler", "vdisk_nullio")
			Expect(must(cli.Devices(ctx))).NotTo(HaveKey(d))
		}, Entry("in the default LUN map", false), Entry("in an initiator group", true))
})

var _ = Describe("Local targets", Label("basic", "targets"), func() {
	var f *fixture
	BeforeEach(func() { f = newFixture() })

	It("creates a target with a session and removes only that target", Label("pr"), func(ctx SpecContext) {
		session := f.name("session")
		t, neighbor := f.target(ctx, "target", "session_name="+session), f.target(ctx, "neighbor")
		Expect(must(cli.Targets(ctx))).To(Equal(map[string]string{t: "scst_local", neighbor: "scst_local"}))
		Eventually(func(g Gomega) {
			sessions, err := cli.Sessions(ctx)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(sessions["scst_local/"+t]).To(ConsistOf(session))
		}, testcfg.Duration(cfg.SettleTimeout), testcfg.Duration(cfg.PollInterval)).WithContext(ctx).Should(Succeed())
		f.do(ctx, "-rem_target", t, "-driver", "scst_local")
		Expect(must(cli.Targets(ctx))).To(Equal(map[string]string{neighbor: "scst_local"}))
		Expect(must(cli.Sessions(ctx))).NotTo(HaveKey("scst_local/" + t))
	})

	It("rejects a duplicate target and preserves its mappings", Label("negative"), func(ctx SpecContext) {
		t, d := f.target(ctx, "target"), f.device(ctx, "disk")
		f.at(ctx, t, "", "-add_lun", "0", "-device", d)
		f.reject(ctx, "-add_target", t, "-driver", "scst_local")
		Expect(must(cli.Targets(ctx))).To(Equal(map[string]string{t: "scst_local"}))
		Expect(f.state(ctx, t).LUNs).To(Equal(map[int]string{0: d}))
	})
})

var _ = Describe("LUN mappings", Label("basic", "luns"), func() {
	var f *fixture
	BeforeEach(func() { f = newFixture() })

	It("adds and removes a read-only LUN without changing its neighbor", Label("pr"), func(ctx SpecContext) {
		t, d, neighbor := f.target(ctx, "target"), f.device(ctx, "disk"), f.device(ctx, "neighbor")
		f.at(ctx, t, "", "-add_lun", "0", "-device", d, "-attributes", "read_only=1")
		f.at(ctx, t, "", "-add_lun", "1", "-device", neighbor)
		Expect(f.state(ctx, t).LUNs).To(Equal(map[int]string{0: d, 1: neighbor}))
		Expect(f.lunReadOnly(ctx, t, "", "0")).To(Equal("1"))
		Expect(f.lunReadOnly(ctx, t, "", "1")).To(Equal("0"))
		f.at(ctx, t, "", "-rem_lun", "0")
		Expect(f.state(ctx, t).LUNs).To(Equal(map[int]string{1: neighbor}))
	})

	It("replaces a LUN's device without changing another LUN", func(ctx SpecContext) {
		t, a, b := f.target(ctx, "target"), f.device(ctx, "first"), f.device(ctx, "second")
		f.at(ctx, t, "", "-add_lun", "0", "-device", a)
		f.at(ctx, t, "", "-add_lun", "1", "-device", a)
		f.at(ctx, t, "", "-replace_lun", "0", "-device", b)
		Expect(f.state(ctx, t).LUNs).To(Equal(map[int]string{0: b, 1: a}))
	})

	It("rejects a duplicate LUN and preserves its original device", Label("negative"), func(ctx SpecContext) {
		t, a, b := f.target(ctx, "target"), f.device(ctx, "first"), f.device(ctx, "second")
		f.at(ctx, t, "", "-add_lun", "0", "-device", a)
		f.reject(ctx, append([]string{"-add_lun", "0", "-device", b}, scope(t, "")...)...)
		Expect(f.state(ctx, t).LUNs).To(Equal(map[int]string{0: a}))
	})

	It("rejects a missing device without adding a LUN", Label("negative"), func(ctx SpecContext) {
		t, d := f.target(ctx, "target"), f.device(ctx, "disk")
		f.at(ctx, t, "", "-add_lun", "0", "-device", d)
		f.reject(ctx, append([]string{"-add_lun", "1", "-device", f.name("missing")}, scope(t, "")...)...)
		Expect(f.state(ctx, t).LUNs).To(Equal(map[int]string{0: d}))
	})
})

var _ = Describe("Initiator groups", Label("basic", "groups"), func() {
	var f *fixture
	BeforeEach(func() { f = newFixture() })

	It("creates groups, moves an initiator and removes empty groups", Label("pr"), func(ctx SpecContext) {
		t, a, b, init := f.target(ctx, "target"), f.name("group_a"), f.name("group_b"), f.name("initiator")
		f.at(ctx, t, "", "-add_group", a)
		f.at(ctx, t, "", "-add_group", b)
		f.at(ctx, t, a, "-add_init", init)
		Expect(f.state(ctx, t).Groups[a].Initiators).To(ConsistOf(init))
		f.at(ctx, t, a, "-move_init", init, "-to", b)
		state := f.state(ctx, t)
		Expect(state.Groups[a].Initiators).To(BeEmpty())
		Expect(state.Groups[b].Initiators).To(ConsistOf(init))
		f.at(ctx, t, b, "-rem_init", init)
		Expect(f.state(ctx, t).Groups[b].Initiators).To(BeEmpty())
		f.at(ctx, t, "", "-rem_group", a)
		Expect(f.state(ctx, t).Groups).To(HaveLen(1))
		Expect(f.state(ctx, t).Groups).To(HaveKey(b))
		f.at(ctx, t, "", "-rem_group", b)
		Expect(f.state(ctx, t).Groups).To(BeEmpty())
	})

	It("clears one group's LUNs while preserving default and sibling mappings", func(ctx SpecContext) {
		t, a, b := f.target(ctx, "target"), f.name("group_a"), f.name("group_b")
		d, da, db := f.device(ctx, "default"), f.device(ctx, "first"), f.device(ctx, "second")
		f.at(ctx, t, "", "-add_group", a)
		f.at(ctx, t, "", "-add_group", b)
		f.at(ctx, t, "", "-add_lun", "0", "-device", d)
		f.at(ctx, t, a, "-add_lun", "0", "-device", da)
		f.at(ctx, t, b, "-add_lun", "0", "-device", db)
		state := f.state(ctx, t)
		Expect(state.LUNs).To(Equal(map[int]string{0: d}))
		Expect(state.Groups[a].LUNs).To(Equal(map[int]string{0: da}))
		Expect(state.Groups[b].LUNs).To(Equal(map[int]string{0: db}))
		f.at(ctx, t, a, "-clear_luns")
		state = f.state(ctx, t)
		Expect(state.LUNs).To(Equal(map[int]string{0: d}))
		Expect(state.Groups[a].LUNs).To(BeEmpty())
		Expect(state.Groups[b].LUNs).To(Equal(map[int]string{0: db}))
	})
})

var _ = Describe("Global attributes", Label("basic", "attributes"), func() {
	It("sets and reads measure_latency, rejecting an invalid value without changing it", Label("negative"), func(ctx SpecContext) {
		f := newFixture()
		original := must(cli.Scalar(ctx, "measure_latency", "-list_scst_attr"))
		Expect(original).To(BeElementOf("0", "1"))
		deferSpecCleanup(func(ctx SpecContext) {
			if err := cli.Blocked(); err != nil {
				AbortSuite("cannot restore measure_latency: " + err.Error())
			}
			r, err := cli.Execute(ctx, "-set_scst_attr", "-attributes", "measure_latency="+original)
			if err != nil || r.ExitCode != 0 || r.ReportedError() {
				AbortSuite("cannot restore measure_latency: " + r.String())
			}
			actual, err := cli.Scalar(ctx, "measure_latency", "-list_scst_attr")
			if err != nil || actual != original {
				AbortSuite("measure_latency restoration could not be verified")
			}
		})
		value := "1"
		if original == value {
			value = "0"
		}
		f.do(ctx, "-set_scst_attr", "-attributes", "measure_latency="+value)
		Expect(must(cli.Scalar(ctx, "measure_latency", "-list_scst_attr"))).To(Equal(value))
		f.reject(ctx, "-set_scst_attr", "-attributes", "measure_latency=.")
		Expect(must(cli.Scalar(ctx, "measure_latency", "-list_scst_attr"))).To(Equal(value))
	})
})
