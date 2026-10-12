// SPDX-License-Identifier: GPL-2.0-only
package suite

import (
	"context"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"scst-component-tests/internal/admin"
	"scst-component-tests/internal/testcfg"
)

func (f *fixture) sessionLUNs(ctx context.Context, target, session string, expected map[int]string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		sessions, err := cli.SessionDetails(ctx)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(sessions).To(HaveKey("scst_local/" + target))
		g.Expect(sessions["scst_local/"+target]).To(HaveKey(session))
		g.Expect(sessions["scst_local/"+target][session].LUNs).To(Equal(expected))
	}, testcfg.Duration(cfg.SettleTimeout), testcfg.Duration(cfg.PollInterval)).WithContext(ctx).Should(Succeed())
}

var _ = Describe("Relative target IDs", Label("basic", "targets", "negative", "issue-230"), func() {
	It("rejects conflicts and invalid IDs, then reuses an ID after target removal", func(ctx SpecContext) {
		f := newFixture()
		a, b, d := f.target(ctx, "first"), f.target(ctx, "second"), f.device(ctx, "disk")
		f.at(ctx, b, "", "-add_lun", "0", "-device", d)
		// Account for the internal copy-manager target as well as local targets.
		targets := must(admin.Pairs(must(cli.Query(ctx, "-list_target")), "Driver", "Target"))
		used := map[string]bool{}
		for name, driver := range targets {
			used[must(cli.Scalar(ctx, "rel_tgt_id", "-list_tgt_attr", name, "-driver", driver))] = true
		}
		var ids []string
		for n := 60000; len(ids) < 2; n++ {
			id := strconv.Itoa(n)
			if !used[id] {
				ids = append(ids, id)
			}
		}
		set := func(target, id string) {
			f.do(ctx, "-set_tgt_attr", target, "-driver", "scst_local", "-attributes", "rel_tgt_id="+id)
		}
		get := func(target string) string {
			return must(cli.Scalar(ctx, "rel_tgt_id", "-list_tgt_attr", target, "-driver", "scst_local"))
		}
		set(a, ids[0])
		set(b, ids[1])
		for _, invalid := range []string{ids[0], "0", "65536"} {
			f.reject(ctx, "-set_tgt_attr", b, "-driver", "scst_local", "-attributes", "rel_tgt_id="+invalid)
			Expect(get(a)).To(Equal(ids[0]))
			Expect(get(b)).To(Equal(ids[1]))
			Expect(f.luns(ctx, b, "")).To(Equal(map[int]string{0: d}))
		}
		f.do(ctx, "-rem_target", a, "-driver", "scst_local")
		set(b, ids[0])
		Expect(get(b)).To(Equal(ids[0]))
		Expect(f.luns(ctx, b, "")).To(Equal(map[int]string{0: d}))
	})
})

// The CLI's session LUN table reports the selected group's mapping. It cannot
// prove SCSI command routing or inspect the lifetime of each kernel tgt_dev.
func (f *fixture) exerciseGroups(ctx context.Context, iterations int) {
	GinkgoHelper()
	session := f.name("session")
	t := f.target(ctx, "target", "session_name="+session)
	a, b := f.name("first"), f.name("second")
	da, db := f.device(ctx, "first"), f.device(ctx, "second")
	f.at(ctx, t, "", "-add_group", b)
	f.at(ctx, t, b, "-add_lun", "0", "-device", db)
	for i := 0; i < iterations; i++ {
		f.at(ctx, t, "", "-add_group", a)
		f.at(ctx, t, a, "-add_lun", "0", "-device", da)
		f.at(ctx, t, a, "-add_init", session)
		f.sessionLUNs(ctx, t, session, map[int]string{0: da})
		f.at(ctx, t, a, "-move_init", session, "-to", b)
		f.sessionLUNs(ctx, t, session, map[int]string{0: db})
		Expect(f.state(ctx, t).Groups[a].Initiators).To(BeEmpty())
		Expect(f.state(ctx, t).Groups[b].Initiators).To(ConsistOf(session))
		f.at(ctx, t, b, "-move_init", session, "-to", a)
		f.sessionLUNs(ctx, t, session, map[int]string{0: da})
		before := f.state(ctx, t)
		for _, force := range []bool{false, true} {
			args := []string{"-rem_group", a}
			if force {
				args = append(args, "-force")
			}
			f.reject(ctx, append(args, scope(t, "")...)...)
			Expect(f.state(ctx, t)).To(Equal(before))
			f.sessionLUNs(ctx, t, session, map[int]string{0: da})
		}
		// -force bypasses the CLI's populated-group check, not the kernel's
		// live-session check with forcibly_close_sessions disabled. Move the
		// session away before deleting the group and its remaining LUNs.
		f.at(ctx, t, a, "-move_init", session, "-to", b)
		f.sessionLUNs(ctx, t, session, map[int]string{0: db})
		f.at(ctx, t, "", "-rem_group", a, "-force")
		Expect(f.state(ctx, t).Groups).NotTo(HaveKey(a))
		Expect(must(cli.Sessions(ctx))["scst_local/"+t]).To(ConsistOf(session))
		f.sessionLUNs(ctx, t, session, map[int]string{0: db})
		f.at(ctx, t, b, "-rem_init", session)
		Expect(f.state(ctx, t).Groups[b].Initiators).To(BeEmpty())
	}
	f.do(ctx, "-rem_target", t, "-driver", "scst_local")
	Expect(must(cli.Sessions(ctx))).NotTo(HaveKey("scst_local/" + t))
	Expect(must(cli.Devices(ctx))).To(HaveLen(2))
}

var _ = It("rejects deletion of a live session's group and removes it after moving the session", Label("basic", "groups", "sessions", "negative", "issue-179"), func(ctx SpecContext) {
	newFixture().exerciseGroups(ctx, 1)
})

var _ = It("repeatedly recreates groups while keeping a local session alive", Label("stress", "groups", "sessions", "issue-179"), func(ctx SpecContext) {
	newFixture().exerciseGroups(ctx, cfg.StressIterations)
})

func copyManagerLUNs(ctx context.Context) map[int]string {
	GinkgoHelper()
	return must(cli.DriverAssignments(ctx, "copy_manager", "copy_manager_tgt")).LUNs
}

var _ = It("rolls back a rejected read-only copy-manager mapping and permits a valid retry", Label("basic", "copy-manager", "negative", "issue-204"), func(ctx SpecContext) {
	f := newFixture()
	d, neighbor := f.device(ctx, "disk"), f.device(ctx, "neighbor")
	original := copyManagerLUNs(ctx)
	Expect(original).To(HaveLen(2))
	lun := -1
	for n, device := range original {
		if device == d {
			lun = n
		}
	}
	Expect(lun).To(BeNumerically(">=", 0))
	args := []string{"-driver", "copy_manager", "-target", "copy_manager_tgt"}
	f.do(ctx, append([]string{"-rem_lun", strconv.Itoa(lun)}, args...)...)
	delete(original, lun)
	Expect(copyManagerLUNs(ctx)).To(Equal(original))
	// This reaches the management rollback path with nullio. The original
	// issue's stale per-LUN thread_pid node is not observable via scstadmin.
	f.reject(ctx, append([]string{"-add_lun", strconv.Itoa(lun), "-device", d, "-attributes", "read_only=1"}, args...)...)
	Expect(copyManagerLUNs(ctx)).To(Equal(original))
	Expect(must(cli.Devices(ctx))).To(Equal(map[string]string{d: "vdisk_nullio", neighbor: "vdisk_nullio"}))
	Expect(must(cli.Sessions(ctx))["copy_manager/copy_manager_tgt"]).To(ConsistOf("copy_manager_sess"))
	f.do(ctx, append([]string{"-add_lun", strconv.Itoa(lun), "-device", d}, args...)...)
	original[lun] = d
	Expect(copyManagerLUNs(ctx)).To(Equal(original))
	f.do(ctx, append([]string{"-rem_lun", strconv.Itoa(lun)}, args...)...)
	f.do(ctx, "-close_dev", d, "-handler", "vdisk_nullio")
	delete(original, lun)
	Expect(copyManagerLUNs(ctx)).To(Equal(original))
	Expect(must(cli.Devices(ctx))).To(Equal(map[string]string{neighbor: "vdisk_nullio"}))
})
