// SPDX-License-Identifier: GPL-2.0-only
package iscsi

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"scst-component-tests/internal/admin"
	"scst-component-tests/internal/testcfg"
)

//go:embed credential_probe.py
var credentialProbe string

func addTestCHAPUser(ctx SpecContext, f *fixture) (string, admin.Result) {
	GinkgoHelper()
	secretBytes := make([]byte, 16)
	_, err := rand.Read(secretBytes)
	Expect(err).NotTo(HaveOccurred())
	secret := hex.EncodeToString(secretBytes)
	value := "tester " + secret
	r, err := cli.Execute(ctx, "-add_tgt_attr", f.Target, "-driver", "iscsi", "-attributes", "IncomingUser="+value)
	Expect(err).NotTo(HaveOccurred(), r.String())
	Expect(r.ExitCode).To(BeZero(), r.String())
	Expect(r.ReportedError()).To(BeFalse(), r.String())
	Expect(must(cli.Scalar(ctx, "IncomingUser", "-list_tgt_attr", f.Target, "-driver", "iscsi"))).To(Equal(value))
	return secret, r
}

func runCredentialProbe(ctx SpecContext, args ...string) admin.Result {
	GinkgoHelper()
	argv := append([]string{"python3", "-c", credentialProbe}, args...)
	r, err := cli.RunProgram(ctx, testcfg.Duration(cfg.CommandTimeout), argv...)
	Expect(err).NotTo(HaveOccurred(), "probe execution failure is not evidence of access denial: %s", r.String())
	Expect(r.ExitCode).To(BeZero(), r.String())
	Expect(r.ReportedError()).To(BeFalse(), r.String())
	return r
}

var _ = Describe("CHAP credential confidentiality", Label("basic", "iscsi", "chap", "security", "issue-91"), func() {
	DescribeTable("denies unprivileged reads of a saved configuration with umask 022", Label("config"), func(ctx SpecContext, initialMode os.FileMode) {
		// The normal artifact directory is private and would hide a readable
		// config. Use an owned, traversable directory with no untrusted writers.
		dir := must(os.MkdirTemp("/tmp", "scst-chap-"))
		AddReportEntry("credential probe directory", dir)
		// Register before the SCST fixture so its cleanup runs first. Preserve
		// the files on uncertain completion, but close access to the directory.
		DeferCleanup(func() {
			if err := os.Chmod(dir, 0700); err != nil {
				AbortSuite("cannot protect credential probe directory: " + err.Error())
			}
			if pending.Load() != 0 || cli.Blocked() != nil {
				fmt.Fprintf(GinkgoWriter, "Preserving credential probe directory: %s\n", dir)
				return
			}
			if err := os.RemoveAll(dir); err != nil {
				AbortSuite("cannot remove credential probe directory: " + err.Error())
			}
		})
		Expect(os.Chmod(dir, 0755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "private-control"), []byte("private\n"), 0600)).To(Succeed())

		f := newFixture(ctx)
		secret, _ := addTestCHAPUser(ctx, f)
		saved := filepath.Join(dir, "saved.conf")
		if initialMode == 0 {
			_, err := os.Lstat(saved)
			Expect(os.IsNotExist(err)).To(BeTrue(), "the output must not be pre-created with safe permissions")
		} else {
			Expect(os.WriteFile(saved, []byte("old configuration\n"), initialMode)).To(Succeed())
			Expect(os.Chmod(saved, initialMode)).To(Succeed())
		}
		// Only the child changes umask. The helper then execs the configured
		// real scstadmin, preserving the shared runner's journal and timeout.
		args := append([]string{"save", dir}, cli.Command...)
		args = append(args, "-noprompt", "-no_lip", "-write_config", saved)
		runCredentialProbe(ctx, args...)
		info := must(os.Stat(saved))
		Expect(info.Mode().IsRegular()).To(BeTrue())
		contents := must(os.ReadFile(saved))
		// Check the synthetic secret, without implementing a config parser.
		Expect(string(contents)).To(ContainSubstring(secret), "the saved config must actually contain the configured secret")
		Expect(os.WriteFile(filepath.Join(artifactDir, f.Device+"-saved.conf"), contents, 0600)).To(Succeed())
		AddReportEntry("saved configuration mode", fmt.Sprintf("%04o", info.Mode().Perm()))
		r := runCredentialProbe(ctx, "read", dir, secret)
		Expect(r.Stdout).To(Equal("denied\n"), "unprivileged reader recovered the secret from a config with mode %04o", info.Mode().Perm())
		Expect(info.Mode().Perm()&0077).To(BeZero(), "saved credentials must not grant group or other access")
	},
		Entry("new file", os.FileMode(0)),
		Entry("existing world-readable file", os.FileMode(0644)),
		Entry("existing group-readable file", os.FileMode(0640)),
		Entry("existing private file", os.FileMode(0600)),
	)

	It("does not print secrets during dynamic attribute updates or debug output", func(ctx SpecContext) {
		f := newFixture(ctx)
		secret, r := addTestCHAPUser(ctx, f)
		// Inspect only the management operation's output, not argv in the
		// command journal or the explicit privileged attribute query.
		Expect(r.Stdout + "\n" + r.Stderr).NotTo(ContainSubstring(secret))
		for _, operation := range []struct {
			name  string
			debug bool
		}{
			{"-add_tgt_attr", false}, // Duplicate value.
			{"-rem_tgt_attr", true},  // Debug must not remove the value.
			{"-rem_tgt_attr", false},
			{"-rem_tgt_attr", false}, // Missing value.
			{"-add_tgt_attr", true},
		} {
			args := []string{operation.name, f.Target, "-driver", "iscsi", "-attributes", "IncomingUser=tester " + secret}
			if operation.debug {
				args = append(args, "-debug")
			}
			r, err := cli.Execute(ctx, args...)
			Expect(err).NotTo(HaveOccurred(), r.String())
			Expect(r.ExitCode).To(BeZero(), r.String())
			Expect(r.ReportedError()).To(BeFalse(), r.String())
			Expect(r.Stdout + "\n" + r.Stderr).NotTo(ContainSubstring(secret))
		}
	})

	It("rejects a symlink output without changing its referent", Label("config"), func(ctx SpecContext) {
		f := newFixture(ctx)
		dir := filepath.Join(artifactDir, f.Device+"-output-link")
		Expect(os.Mkdir(dir, 0700)).To(Succeed())
		referent := filepath.Join(dir, "original")
		saved := filepath.Join(dir, "saved.conf")
		original := []byte("do not overwrite\n")
		Expect(os.WriteFile(referent, original, 0600)).To(Succeed())
		Expect(os.Symlink(referent, saved)).To(Succeed())
		r, err := cli.Execute(ctx, "-write_config", saved)
		Expect(err).NotTo(HaveOccurred(), "execution failure is not output rejection: %s", r.String())
		Expect(r.ExitCode).NotTo(BeZero(), r.String())
		Expect(r.Stdout + r.Stderr).To(ContainSubstring("Failed to save configuration"))
		Expect(must(os.ReadFile(referent))).To(Equal(original))
		Expect(must(os.Lstat(saved)).Mode() & os.ModeSymlink).NotTo(BeZero())
	})
})
