// SPDX-License-Identifier: GPL-2.0-only
package iscsi

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"scst-component-tests/internal/admin"
	"scst-component-tests/internal/remote"
	"scst-component-tests/internal/testcfg"
	"scst-component-tests/internal/testhost"
	"scst-component-tests/internal/testrun"
)

var cfg testcfg.Config
var cli *admin.Client
var peer *remote.Session
var daemon *testhost.Process
var artifactDir, runID string
var pending atomic.Int64

func TestISCSI(t *testing.T) {
	testrun.Run(t, "SCST iSCSI over SSH", true, func(env testrun.Environment) {
		cfg, cli, artifactDir, runID = env.Config, env.Client, env.ArtifactDir, env.RunID
	})
}

func must[T any](value T, err error) T {
	GinkgoHelper()
	Expect(err).NotTo(HaveOccurred())
	return value
}

func journal(name string) *os.File {
	GinkgoHelper()
	f := must(os.OpenFile(filepath.Join(artifactDir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600))
	DeferCleanup(func() { Expect(f.Close()).To(Succeed()) })
	return f
}

func empty(ctx context.Context) error { return cli.RequireEmptyDriver(ctx, "iscsi") }
func portal() string                  { return net.JoinHostPort(cfg.ISCSI.TargetAddress, strconv.Itoa(cfg.ISCSI.Port)) }

func beforeReplace(ctx context.Context) error {
	if err := empty(ctx); err != nil {
		return err
	}
	drivers, err := cli.Names(ctx, "Driver", "-list_driver")
	if err != nil {
		return err
	}
	for _, driver := range drivers {
		if driver == "iscsi" {
			state, err := cli.Scalar(ctx, "open_state", "-list_drv_attr", "iscsi")
			if err != nil {
				return err
			}
			if state != "closed" {
				return fmt.Errorf("existing iSCSI control daemon is still attached: %s", state)
			}
		}
	}
	return nil
}

var _ = BeforeSuite(func(ctx SpecContext) {
	// Binding a temporary socket verifies address ownership and port availability.
	listener := must(net.Listen("tcp4", portal()))
	Expect(listener.Close()).To(Succeed())
	r, err := cli.RunProgram(ctx, testcfg.Duration(cfg.CommandTimeout), "pgrep", "-x", "iscsi-scstd")
	Expect(err).NotTo(HaveOccurred())
	Expect(r.ExitCode).To(Equal(1), "stop the existing target daemon before this suite: %s", r.String())
	sshLog, commandLog := journal("ssh.log"), journal("initiator.jsonl")
	connectCtx, cancel := context.WithTimeout(ctx, testcfg.Duration(cfg.CommandTimeout))
	peer, err = remote.Connect(connectCtx, cfg.ISCSI.Initiator, commandLog, sshLog)
	cancel()
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { Expect(peer.Close()).To(Succeed()) })
	r = remoteRun(ctx, "iscsiadm", "--version")
	Expect(r.ExitCode).To(BeZero(), r.String())
	r = remoteRun(ctx, "pgrep", "-x", "iscsid")
	Expect(r.ExitCode).To(BeZero(), "start iscsid on the initiator before running: %s", r.String())
	// Use a disposable initiator with no sessions; existing node/iface records
	// are preserved. Kernel TCP initiator support must already be loaded.
	expectNoSessions(ctx)
	r = remoteRun(ctx, "lsmod")
	Expect(r.ExitCode).To(BeZero(), r.String())
	Expect(r.Stdout).To(MatchRegexp(`(?m)^iscsi_tcp\s`), "load iscsi_tcp on the initiator before running")

	modules := new(testhost.Modules)
	source := os.Getenv("SCST_TEST_SOURCE_DIR")
	if source == "" {
		source = must(filepath.Abs("../../.."))
	}
	err = modules.Prepare(ctx, testhost.Options{
		SourceDir: source, KernelDir: os.Getenv("SCST_TEST_KDIR"), ISCSI: true,
		Build: os.Getenv("SCST_TEST_BUILD") == "1", Jobs: cfg.BuildJobs,
		BuildTimeout: testcfg.Duration(cfg.BuildTimeout), CommandTimeout: testcfg.Duration(cfg.CommandTimeout),
	}, cli.RunProgram, beforeReplace, GinkgoWriter)
	DeferCleanup(func(ctx SpecContext) {
		Expect(pending.Load()).To(BeZero(), "spec cleanup incomplete; preserving target stack")
		Expect(peer.Blocked()).NotTo(HaveOccurred(), "initiator state uncertain; preserving target stack")
		Expect(cli.Blocked()).NotTo(HaveOccurred(), "target state uncertain; preserving target stack")
		expectNoSessions(ctx)
		if daemon != nil {
			Expect(empty(ctx)).To(Succeed())
			fmt.Fprintf(GinkgoWriter, "Stopping owned iscsi-scstd (PID %d)\n", daemon.PID())
			Expect(daemon.Stop(ctx)).To(Succeed())
			Eventually(func() string { return must(cli.Scalar(ctx, "open_state", "-list_drv_attr", "iscsi")) },
				testcfg.Duration(cfg.SettleTimeout), testcfg.Duration(cfg.PollInterval)).WithContext(ctx).Should(Equal("closed"))
		}
		Expect(modules.Unload(ctx, testcfg.Duration(cfg.CommandTimeout), cli.RunProgram, empty, GinkgoWriter)).To(Succeed())
	}, NodeTimeout(testcfg.Duration(cfg.CleanupTimeout)))
	Expect(err).To(Succeed())
	Expect(empty(ctx)).To(Succeed())
	config := filepath.Join(artifactDir, "iscsi-scstd.conf")
	Expect(os.WriteFile(config, nil, 0600)).To(Succeed())
	log := journal("iscsi-scstd.log")
	fmt.Fprintf(GinkgoWriter, "Starting checkout iscsi-scstd on %s\n", portal())
	daemon, err = testhost.StartProcess(log, filepath.Join(source, "iscsi-scst/usr/iscsi-scstd"),
		"-f", "-d", "1", "-c", config, "-a", cfg.ISCSI.TargetAddress, "-p", strconv.Itoa(cfg.ISCSI.Port))
	Expect(err).NotTo(HaveOccurred())
	Expect(os.WriteFile(filepath.Join(artifactDir, "iscsi-scstd.pid"), []byte(fmt.Sprintln(daemon.PID())), 0600)).To(Succeed())
	Eventually(func() bool {
		Expect(daemon.Running()).To(Succeed())
		attrs := must(cli.Attributes(ctx, "-list_drv_attr", "iscsi"))
		return len(attrs["enabled"].Values) == 1
	}, testcfg.Duration(cfg.SettleTimeout), testcfg.Duration(cfg.PollInterval)).WithContext(ctx).Should(BeTrue())
	do(ctx, "-set_drv_attr", "iscsi", "-attributes", "enabled=1")
	// Opening the listener can follow attribute registration in the daemon.
	Eventually(func() error {
		if err := daemon.Running(); err != nil {
			return err
		}
		c, err := net.DialTimeout("tcp4", portal(), time.Second)
		if err == nil {
			c.Close()
		}
		return err
	}, testcfg.Duration(cfg.SettleTimeout), testcfg.Duration(cfg.PollInterval)).WithContext(ctx).Should(Succeed())
})

func do(ctx context.Context, args ...string) {
	GinkgoHelper()
	r, err := cli.Execute(ctx, args...)
	Expect(err).NotTo(HaveOccurred(), r.String())
	Expect(r.ExitCode).To(BeZero(), r.String())
	Expect(r.ReportedError()).To(BeFalse(), r.String())
}

func remoteRun(ctx context.Context, args ...string) admin.Result {
	GinkgoHelper()
	r, err := peer.Run(ctx, testcfg.Duration(cfg.CommandTimeout), args...)
	Expect(err).NotTo(HaveOccurred(), "remote execution failure is not an expected rejection: %s", r.String())
	return r
}

func remoteOK(ctx context.Context, args ...string) admin.Result {
	GinkgoHelper()
	r := remoteRun(ctx, args...)
	Expect(r.ExitCode).To(BeZero(), r.String())
	return r
}

func expectNoSessions(ctx context.Context) {
	GinkgoHelper()
	r := remoteRun(ctx, "iscsiadm", "-m", "session")
	Expect(r.ExitCode).To(Equal(21), "expected no initiator sessions: %s", r.String())
	Expect(r.Stdout).To(BeEmpty(), r.String())
}
