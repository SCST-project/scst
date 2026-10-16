// SPDX-License-Identifier: GPL-2.0-only
package iscsi

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"scst-component-tests/internal/admin"
	"scst-component-tests/internal/initiator"
	"scst-component-tests/internal/testcfg"
	"scst-component-tests/internal/testhost"
)

const (
	alternateACG = "alternate"
	// Both directions replace tgt_devs while retaining the bootstrapping LUN 0.
	reassignLUNs = 16
)

func (f *fixture) expectLUNs(ctx context.Context, luns map[int]string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		sessions, err := cli.SessionDetails(ctx)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(sessions["iscsi/"+f.Target]).To(HaveLen(1))
		for _, s := range sessions["iscsi/"+f.Target] {
			g.Expect(s.LUNs).To(Equal(luns))
		}
	}, testcfg.Duration(cfg.SettleTimeout), testcfg.Duration(cfg.PollInterval)).WithContext(ctx).Should(Succeed())
}

func fixtureSocket(ctx context.Context) string {
	GinkgoHelper()
	r := remoteOK(ctx, "ss", "-Hnt4", "state", "established", "dst", cfg.ISCSI.TargetAddress,
		"dport", "=", fmt.Sprint(cfg.ISCSI.Port))
	return must(initiator.TCPConnection(r.Stdout, portal()))
}

type acgMoveResult struct {
	command admin.Result
	err     error
}

// No Ginkgo assertions run in the worker. Its caller always joins it before
// asserting or cleaning up, including when the initiator command failed.
func (f *fixture) raceACG(ctx context.Context, kernel *testhost.KernelLog, from, to string, argv []string, resetSocket string) {
	GinkgoHelper()
	watch := must(kernel.Watch(fmt.Sprintf("(initiator %s) will be reassigned from acg %s to acg %s", f.Initiator, from, to)))
	defer watch.Close()
	done := make(chan acgMoveResult, 1)
	go func() {
		r, err := cli.Execute(ctx, "-move_init", f.Initiator, "-driver", "iscsi", "-target", f.Target,
			"-group", from, "-to", to)
		done <- acgMoveResult{command: r, err: err}
	}()
	// Starting both userspace commands together mostly measures CLI/SSH startup.
	// Wait for this session to enter reassignment before requesting teardown.
	waitCtx, cancel := context.WithTimeout(ctx, testcfg.Duration(cfg.CommandTimeout))
	message, waitErr := watch.Wait(waitCtx)
	cancel()
	var r admin.Result
	var err error
	if waitErr == nil {
		r, err = peer.Run(ctx, testcfg.Duration(cfg.CommandTimeout), argv...)
	}
	move := <-done
	Expect(kernel.Check()).To(Succeed())
	Expect(move.err).NotTo(HaveOccurred(), move.command.String())
	Expect(move.command.ExitCode).To(BeZero(), move.command.String())
	Expect(move.command.ReportedError()).To(BeFalse(), move.command.String())
	Expect(waitErr).NotTo(HaveOccurred(), "no fresh reassignment message for the fixture; teardown was not requested")
	AddReportEntry("reassignment", fmt.Sprintf("%s -> %s; kernel sequence=%d time_us=%d; move=%s; teardown=%s",
		from, to, message.Sequence, message.Microseconds, move.command.Duration, r.Duration))
	Expect(err).NotTo(HaveOccurred(), r.String())
	Expect(r.ExitCode).To(BeZero(), r.String())
	if argv[0] == "ss" {
		// ss -K may exit zero without destroying a socket, e.g. if the kernel
		// lacks SOCK_DESTROY support. Its output must identify our exact tuple.
		Expect(r.Stderr).To(BeEmpty(), r.String())
		local := must(initiator.TCPConnection(r.Stdout, portal()))
		Expect(local).To(Equal(resetSocket))
	}
	Expect(r.Started.Before(move.command.Started.Add(move.command.Duration))).To(BeTrue(),
		"ACG move completed before teardown started; this round is inconclusive")
}

var _ = DescribeTable("ACG reassignment during iSCSI teardown", Label("iscsi", "stress", "race", "sessions", "issue-367"),
	func(ctx SpecContext, recoverTCP bool) {
		path := filepath.Join(artifactDir, fmt.Sprintf("issue-367-%t-kernel.log", recoverTCP))
		kernel := must(testhost.StartKernelLog(path))
		AddReportEntry("kernel log", path)
		// Registered before the fixture: capture remains active throughout its
		// cleanup. On diagnostic/error, prevent suite-level module unloading.
		DeferCleanup(func() {
			if err := kernel.Close(); err != nil {
				pending.Add(1)
				AbortSuite("kernel evidence failed; preserve target stack: " + err.Error())
			}
		})
		f := newFixture(ctx)
		f.beforeCleanup = kernel.Check
		f.at(ctx, "", "-add_group", alternateACG)
		// Disjoint nonzero LUN maps exercise allocation AND removal on every
		// round. A single extra LUN only exercises removal in one direction.
		f.at(ctx, alternateACG, "-add_lun", "0", "-device", f.Device)
		alternateLUNs := map[int]string{0: f.Device}
		for lun := 1; lun <= reassignLUNs; lun++ {
			f.at(ctx, "access", "-add_lun", strconv.Itoa(lun), "-device", f.Device)
			f.LUNs[lun] = f.Device
			f.at(ctx, alternateACG, "-add_lun", strconv.Itoa(lun+reassignLUNs), "-device", f.Device)
			alternateLUNs[lun+reassignLUNs] = f.Device
		}
		maps := map[string]map[int]string{"access": f.LUNs, alternateACG: alternateLUNs}
		AddReportEntry("ACG maps", maps)
		f.login(ctx)
		f.at(ctx, "access", "-move_init", f.Initiator, "-to", alternateACG)
		f.expectLUNs(ctx, alternateLUNs)
		f.at(ctx, alternateACG, "-move_init", f.Initiator, "-to", "access")
		f.expectLUNs(ctx, f.LUNs)
		f.logout(ctx)

		from, to := "access", alternateACG
		for i := 0; i < cfg.StressIterations; i++ {
			By(fmt.Sprintf("round %d: %s -> %s, TCP recovery=%t", i+1, from, to, recoverTCP))
			Expect(kernel.Check()).To(Succeed())
			f.login(ctx)
			argv := []string{"iscsiadm", "-m", "node", "-T", f.Target, "-p", portal(), "-I", f.Iface, "--logout"}
			var before string
			var sessionID string
			if recoverTCP {
				before = fixtureSocket(ctx)
				sessions := must(initiator.Sessions(remoteOK(ctx, "iscsiadm", "-m", "session").Stdout))
				Expect(sessions).To(HaveLen(1))
				Expect(sessions[0].Target).To(Equal(f.Target))
				sessionID = sessions[0].ID
				host, port, err := net.SplitHostPort(before)
				Expect(err).NotTo(HaveOccurred())
				argv = []string{"ss", "-K", "-Hnt4", "state", "established", "src", host, "sport", "=", port,
					"dst", cfg.ISCSI.TargetAddress, "dport", "=", fmt.Sprint(cfg.ISCSI.Port)}
			}
			f.raceACG(ctx, kernel, from, to, argv, before)
			f.LUNs = maps[to]
			if recoverTCP {
				Eventually(func(g Gomega) {
					g.Expect(kernel.Check()).To(Succeed())
					r := remoteOK(ctx, "ss", "-Hnt4", "state", "established", "dst", cfg.ISCSI.TargetAddress,
						"dport", "=", fmt.Sprint(cfg.ISCSI.Port))
					local, err := initiator.TCPConnection(r.Stdout, portal())
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(local).NotTo(Equal(before), "require a replacement TCP connection")
					r = remoteOK(ctx, "iscsiadm", "-m", "session", "-r", sessionID, "-P", "1")
					g.Expect(r.Stdout).To(MatchRegexp(`(?m)^\s*iSCSI Connection State: LOGGED IN\s*$`))
				}, testcfg.Duration(cfg.CommandTimeout), testcfg.Duration(cfg.PollInterval)).WithContext(ctx).Should(Succeed())
				f.expectLUNs(ctx, f.LUNs)
				f.logout(ctx)
			} else {
				expectNoSessions(ctx)
				f.noTargetSession(ctx)
			}
			assignments := must(cli.DriverAssignments(ctx, "iscsi", f.Target))
			Expect(assignments.Groups[to].Initiators).To(ConsistOf(f.Initiator))
			Expect(assignments.Groups[from].Initiators).To(BeEmpty())
			Expect(kernel.Check()).To(Succeed())
			from, to = to, from
		}
		// Successful commands and clean logs cannot establish that the TM
		// reader entered the short NULL-ACG window on any particular round.
		AddReportEntry("issue #367 outcome", fmt.Sprintf("not reproduced in %d kernel-observed reassignments; TM/NULL-ACG overlap was not observed directly", cfg.StressIterations))
	},
	Entry("with logout", false),
	Entry("with TCP connection recovery", true),
)
