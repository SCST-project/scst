// SPDX-License-Identifier: GPL-2.0-only
package suite

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func (f *fixture) targetGroup(ctx context.Context, dg, suffix, target, id string) string {
	GinkgoHelper()
	tg := f.name(suffix)
	f.do(ctx, "-add_tgrp", tg, "-dev_group", dg)
	f.do(ctx, "-set_tgrp_attr", tg, "-dev_group", dg, "-attributes", "group_id="+id)
	f.do(ctx, "-add_tgrp_tgt", target, "-dev_group", dg, "-tgt_group", tg)
	return tg
}

func (f *fixture) aluaState(ctx context.Context, dg, tg, state string) {
	GinkgoHelper()
	f.do(ctx, "-set_tgrp_attr", tg, "-dev_group", dg, "-attributes", "state="+state)
	Expect(must(cli.Scalar(ctx, "state", "-list_tgrp_attr", tg, "-dev_group", dg))).To(Equal(state))
}

var _ = Describe("ALUA device activation", Label("basic", "alua", "fileio", "issue-55"), func() {
	var f *fixture
	BeforeEach(func() { f = newFixture() })

	DescribeTable("deactivates and reopens devices for local target-group transitions", Label("negative"),
		func(ctx SpecContext, mapped bool) {
			d := f.fileDevice(ctx, "disk", f.backingFile("disk"), "bind_alua_state=1")
			neighbor := f.fileDevice(ctx, "neighbor", f.backingFile("neighbor"), "bind_alua_state=1")
			session := f.name("session")
			t, dg := f.target(ctx, "target", "session_name="+session), f.deviceGroup(ctx, "devices")
			f.detachCopyManager(ctx, d)
			if mapped {
				f.at(ctx, t, "", "-add_group", "access")
				f.at(ctx, t, "access", "-add_lun", "0", "-device", d)
				f.at(ctx, t, "access", "-add_init", session)
				f.sessionLUNs(ctx, t, session, map[int]string{0: d})
			}
			f.do(ctx, "-add_dgrp_dev", d, "-dev_group", dg)
			tg := f.targetGroup(ctx, dg, "local", t, "11")
			f.aluaState(ctx, dg, tg, "active")
			Expect(f.deviceAttr(ctx, d, "active")).To(Equal("1"))
			f.aluaState(ctx, dg, tg, "transitioning")
			Expect(f.deviceAttr(ctx, d, "active")).To(Equal("0"))
			f.reject(ctx, "-set_dev_attr", d, "-attributes", "sync=1")
			Expect(f.deviceAttr(ctx, neighbor, "active")).To(Equal("1"))
			path := f.backingFile("replacement")
			f.setDevice(ctx, d, "filename="+path)
			Expect(f.deviceAttr(ctx, d, "filename")).To(Equal(path))
			f.aluaState(ctx, dg, tg, "nonoptimized")
			Expect(f.deviceAttr(ctx, d, "active")).To(Equal("1"))
			if mapped {
				f.setDevice(ctx, d, "sync=1")
			} else {
				f.reject(ctx, "-set_dev_attr", d, "-attributes", "sync=1")
			}
			f.aluaState(ctx, dg, tg, "standby")
			Expect(f.deviceAttr(ctx, d, "active")).To(Equal("0"))
			f.reject(ctx, "-set_dev_attr", d, "-attributes", "sync=1")
			f.aluaState(ctx, dg, tg, "active")
			Expect(f.deviceAttr(ctx, d, "active")).To(Equal("1"))
			f.reject(ctx, "-set_tgrp_attr", tg, "-dev_group", dg, "-attributes", "state=invalid_state")
			Expect(must(cli.Scalar(ctx, "state", "-list_tgrp_attr", tg, "-dev_group", dg))).To(Equal("active"))
			Expect(f.deviceAttr(ctx, d, "active")).To(Equal("1"))
			Expect(f.deviceAttr(ctx, neighbor, "active")).To(Equal("1"))
			if mapped {
				Expect(f.luns(ctx, t, "access")).To(Equal(map[int]string{0: d}))
			}
		}, Entry("with a LUN mapping", true), Entry("without a LUN mapping", false))

	It("keeps local devices active when only a remote group changes", func(ctx SpecContext) {
		d := f.fileDevice(ctx, "disk", f.backingFile("disk"), "bind_alua_state=1")
		t, _ := f.attachFileio(ctx, d)
		dg := f.deviceGroup(ctx, "devices")
		f.do(ctx, "-add_dgrp_dev", d, "-dev_group", dg)
		local := f.targetGroup(ctx, dg, "local", t, "11")
		remote := f.targetGroup(ctx, dg, "remote", f.name("remote_target"), "12")
		f.aluaState(ctx, dg, local, "active")
		f.aluaState(ctx, dg, remote, "transitioning")
		Expect(f.deviceAttr(ctx, d, "active")).To(Equal("1"))
		Expect(must(cli.Scalar(ctx, "state", "-list_tgrp_attr", local, "-dev_group", dg))).To(Equal("active"))
		f.aluaState(ctx, dg, remote, "standby")
		Expect(f.deviceAttr(ctx, d, "active")).To(Equal("1"))
		f.setDevice(ctx, d, "sync=1")
	})

	It("leaves unbound fileio active during a local ALUA transition", func(ctx SpecContext) {
		d := f.fileDevice(ctx, "disk", f.backingFile("disk"), "bind_alua_state=0")
		t, _ := f.attachFileio(ctx, d)
		dg := f.deviceGroup(ctx, "devices")
		f.do(ctx, "-add_dgrp_dev", d, "-dev_group", dg)
		tg := f.targetGroup(ctx, dg, "local", t, "11")
		f.aluaState(ctx, dg, tg, "active")
		f.aluaState(ctx, dg, tg, "transitioning")
		Expect(f.deviceAttr(ctx, d, "active")).To(Equal("1"))
		f.aluaState(ctx, dg, tg, "active")
		Expect(f.deviceAttr(ctx, d, "active")).To(Equal("1"))
	})
})
