// SPDX-License-Identifier: GPL-2.0-only
package iscsi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"scst-component-tests/internal/admin"
	"scst-component-tests/internal/dataio"
	"scst-component-tests/internal/initiator"
	"scst-component-tests/internal/testcfg"
)

type fixture struct {
	Backend                                         dataio.Backend
	LUNs                                            map[int]string
	BackingFiles                                    []string
	Target, Initiator, Iface, Device                string
	ifaceOwned, nodeOwned, targetOwned, deviceOwned bool
}

var sequence int

func newFixture(ctx context.Context) *fixture { return newProfileFixture(ctx, nil) }

func newProfileFixture(ctx context.Context, profile *dataio.Profile) *fixture {
	GinkgoHelper()
	if pending.Load() != 0 {
		AbortSuite("previous cleanup failed; inspect both hosts")
	}
	if err := peer.Blocked(); err != nil {
		AbortSuite(err.Error())
	}
	if err := cli.Blocked(); err != nil {
		AbortSuite(err.Error())
	}
	Expect(daemon.Running()).To(Succeed())
	Expect(empty(ctx)).To(Succeed())
	expectNoSessions(ctx)
	sequence++
	f := &fixture{
		Target:    fmt.Sprintf("iqn.2026-10.test.scst:%s.%s.%d", strings.ReplaceAll(cfg.NamePrefix, "_", "-"), runID, sequence),
		Initiator: fmt.Sprintf("iqn.2026-10.test.scst:init.%s.%d", runID, sequence),
		Iface:     fmt.Sprintf("scst_%s_%d", runID, sequence),
		Device:    fmt.Sprintf("%s_%s_%d", cfg.NamePrefix, runID, sequence),
	}
	f.Backend.Handler = "vdisk_nullio"
	if profile != nil {
		f.Backend.Handler = profile.Handler
	}
	f.LUNs = map[int]string{0: f.Device}
	data := must(json.MarshalIndent(f, "", "  "))
	Expect(os.WriteFile(filepath.Join(artifactDir, f.Device+".json"), data, 0600)).To(Succeed())
	pending.Add(1)
	DeferCleanup(func(ctx SpecContext) {
		f.cleanup(ctx)
		if ctx.Err() == nil {
			pending.Add(-1)
		}
	}, NodeTimeout(testcfg.Duration(cfg.CleanupTimeout)))

	// Check names before claiming ownership, then record before each mutation.
	Expect(ifaces(ctx)).NotTo(ContainElement(f.Iface))
	f.ifaceOwned = true
	remoteOK(ctx, "iscsiadm", "-m", "iface", "-I", f.Iface, "-o", "new")
	for _, setting := range [][2]string{{"iface.transport_name", "tcp"}, {"iface.initiatorname", f.Initiator}} {
		remoteOK(ctx, "iscsiadm", "-m", "iface", "-I", f.Iface, "-o", "update", "-n", setting[0], "-v", setting[1])
	}
	Expect(f.nodeExists(ctx)).To(BeFalse())
	f.nodeOwned = true
	f.nodeOK(ctx, "-o", "new")
	for _, setting := range [][2]string{
		{"node.startup", "manual"}, {"node.conn[0].startup", "manual"},
		{"node.session.auth.authmethod", "None"},
		{"node.session.auth.username_in", ""}, {"node.session.auth.password_in", ""},
		{"node.session.initial_login_retry_max", "1"},
		{"node.conn[0].timeo.login_timeout", strconv.Itoa(int(testcfg.Duration(cfg.ISCSI.LoginTimeout).Seconds()))},
		{"node.session.timeo.replacement_timeout", "5"},
	} {
		f.update(ctx, setting[0], setting[1])
	}
	attrs := "dummy=1,size_mb=8"
	if profile != nil {
		f.Backend = must(dataio.PrepareBackend(ctx, cfg, artifactDir, dataio.DeviceID(f.Device), *profile,
			cli.RunProgram, func(path string) { f.BackingFiles = append(f.BackingFiles, path) }))
		attrs = f.Backend.Attributes
	}
	f.deviceOwned = true
	do(ctx, "-open_dev", f.Device, "-handler", f.Backend.Handler, "-attributes", attrs)
	if profile != nil {
		do(ctx, "-set_dev_attr", f.Device, "-attributes", "usn="+f.Backend.Serial+",vend_specific_id="+f.Backend.Serial)
	}
	f.targetOwned = true
	do(ctx, "-add_target", f.Target, "-driver", "iscsi")
	do(ctx, "-set_tgt_attr", f.Target, "-driver", "iscsi", "-attributes", "per_portal_acl=0")
	f.at(ctx, "", "-add_group", "access")
	lunAttrs := "read_only=0"
	if profile != nil && profile.ReadOnly {
		lunAttrs = "read_only=1"
	}
	f.at(ctx, "access", "-add_lun", "0", "-device", f.Device, "-attributes", lunAttrs)
	if profile != nil && profile.ExtraLUNs {
		f.at(ctx, "access", "-add_lun", "7", "-device", f.Device)
		f.LUNs[7] = f.Device
		f.at(ctx, "", "-add_group", "hidden")
		f.at(ctx, "hidden", "-add_lun", "13", "-device", f.Device)
	}
	f.at(ctx, "access", "-add_init", f.Initiator)
	do(ctx, "-enable_target", f.Target, "-driver", "iscsi")
	data = must(json.MarshalIndent(f, "", "  "))
	Expect(os.WriteFile(filepath.Join(artifactDir, f.Device+".json"), data, 0600)).To(Succeed())
	return f
}

func ifaces(ctx context.Context) []string {
	GinkgoHelper()
	return must(initiator.Ifaces(remoteOK(ctx, "iscsiadm", "-m", "iface").Stdout))
}

func (f *fixture) at(ctx context.Context, group string, args ...string) {
	GinkgoHelper()
	args = append(args, "-driver", "iscsi", "-target", f.Target)
	if group != "" {
		args = append(args, "-group", group)
	}
	do(ctx, args...)
}

func (f *fixture) node(ctx context.Context, args ...string) admin.Result {
	GinkgoHelper()
	return remoteRun(ctx, append([]string{"iscsiadm", "-m", "node", "-T", f.Target, "-p", portal(), "-I", f.Iface}, args...)...)
}
func (f *fixture) nodeOK(ctx context.Context, args ...string) admin.Result {
	GinkgoHelper()
	r := f.node(ctx, args...)
	Expect(r.ExitCode).To(BeZero(), r.String())
	return r
}
func (f *fixture) nodeExists(ctx context.Context) bool {
	GinkgoHelper()
	r := f.node(ctx)
	Expect(r.ExitCode).To(BeElementOf(0, 21), r.String())
	return r.ExitCode == 0
}
func (f *fixture) update(ctx context.Context, name, value string) {
	GinkgoHelper()
	f.nodeOK(ctx, "-o", "update", "-n", name, "-v", value)
}
func (f *fixture) discover(ctx context.Context) map[string]string {
	GinkgoHelper()
	r := remoteRun(ctx, "iscsiadm", "-m", "discovery", "-t", "sendtargets", "-p", portal(), "-I", f.Iface, "-o", "nonpersistent")
	Expect(r.ExitCode).To(BeElementOf(0, 21), r.String())
	entries := must(initiator.Discovery(r.Stdout))
	if r.ExitCode == 21 {
		Expect(entries).To(BeEmpty())
	}
	return entries
}
func (f *fixture) login(ctx context.Context) {
	GinkgoHelper()
	f.nodeOK(ctx, "--login")
	r := remoteOK(ctx, "iscsiadm", "-m", "session")
	sessions := must(initiator.Sessions(r.Stdout))
	Expect(sessions).To(HaveLen(1))
	Expect(sessions[0].Target).To(Equal(f.Target))
	Expect(sessions[0].Portal).To(Equal(portal()))
	Eventually(func(g Gomega) {
		sessions, err := cli.SessionDetails(ctx)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(sessions["iscsi/"+f.Target]).To(HaveLen(1))
		// The public CLI shows the group's LUN map; this is not a data I/O check.
		for _, s := range sessions["iscsi/"+f.Target] {
			g.Expect(s.LUNs).To(Equal(f.LUNs))
		}
	}, testcfg.Duration(cfg.SettleTimeout), testcfg.Duration(cfg.PollInterval)).WithContext(ctx).Should(Succeed())
}
func (f *fixture) noTargetSession(ctx context.Context) {
	GinkgoHelper()
	Eventually(func() []string { return must(cli.Sessions(ctx))["iscsi/"+f.Target] },
		testcfg.Duration(cfg.SettleTimeout), testcfg.Duration(cfg.PollInterval)).WithContext(ctx).Should(BeEmpty())
}
func (f *fixture) logout(ctx context.Context) {
	GinkgoHelper()
	f.nodeOK(ctx, "--logout")
	expectNoSessions(ctx)
	f.noTargetSession(ctx)
}

func (f *fixture) cleanup(ctx context.Context) {
	GinkgoHelper()
	Expect(peer.Blocked()).NotTo(HaveOccurred(), "preserving target while initiator state is uncertain")
	Expect(cli.Blocked()).NotTo(HaveOccurred())
	Expect(daemon.Running()).To(Succeed())
	if f.nodeOwned && f.nodeExists(ctx) {
		// Attempt logout even when a failed login returned an ordinary nonzero code.
		r := f.node(ctx, "--logout")
		Expect(r.ExitCode).To(BeElementOf(0, 21), r.String())
		expectNoSessions(ctx)
		f.noTargetSession(ctx)
		f.nodeOK(ctx, "-o", "delete")
		Expect(f.nodeExists(ctx)).To(BeFalse())
	}
	if f.ifaceOwned {
		for _, name := range ifaces(ctx) {
			if name == f.Iface {
				remoteOK(ctx, "iscsiadm", "-m", "iface", "-I", f.Iface, "-o", "delete")
			}
		}
		Expect(ifaces(ctx)).NotTo(ContainElement(f.Iface))
	}
	expectNoSessions(ctx)
	if f.targetOwned {
		if _, present := must(cli.DriverTargets(ctx, "iscsi"))[f.Target]; present {
			f.noTargetSession(ctx)
			do(ctx, "-rem_target", f.Target, "-driver", "iscsi")
		}
	}
	if f.deviceOwned {
		if handler, present := must(cli.Devices(ctx))[f.Device]; present {
			Expect(handler).To(Equal(f.Backend.Handler))
			do(ctx, "-close_dev", f.Device, "-handler", handler)
		}
	}
	Expect(empty(ctx)).To(Succeed())
	for _, path := range f.BackingFiles {
		Expect(os.Remove(path)).To(Succeed())
	}
}
