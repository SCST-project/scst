// SPDX-License-Identifier: GPL-2.0-only
package iscsi

import (
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"scst-component-tests/internal/testcfg"
)

var _ = It("rejects an invalid portal list and logs the intact offending token", Label("basic", "iscsi", "negative"), func(ctx SpecContext) {
	attrs := must(cli.Attributes(ctx, "-list_drv_attr", "iscsi"))
	before, ok := attrs["internal_portal"]
	Expect(ok).To(BeTrue())
	restoreValue := strings.Join(before.Values, " ")
	// scstadmin displays an empty attribute as <not set>.
	if restoreValue == "<not set>" {
		restoreValue = ""
	}
	DeferCleanup(func(ctx SpecContext) {
		if cli.Blocked() != nil || daemon.Running() != nil {
			AbortSuite("cannot verify or restore the internal portal setting")
		}
		do(ctx, "-set_drv_attr", "iscsi", "-attributes", "internal_portal="+restoreValue)
	}, NodeTimeout(testcfg.Duration(cfg.CleanupTimeout)))

	logPath := filepath.Join(artifactDir, "iscsi-scstd.log")
	logStart := len(must(os.ReadFile(logPath)))
	bad := "invalid-portal-" + runID
	// A second token selects the list-validation path. The invalid first
	// token is at the start of the allocation that used to be freed before
	// logging, making allocator metadata corruption observable in the log.
	r, err := cli.Execute(ctx, "-set_drv_attr", "iscsi", "-attributes", "internal_portal="+bad+" 127.0.0.1")
	Expect(err).NotTo(HaveOccurred(), r.String())
	Expect(r.ExitCode != 0 || r.ReportedError()).To(BeTrue(), r.String())
	Expect(r.Stderr).To(ContainSubstring("(EINVAL)"), r.String())
	Eventually(func() string {
		Expect(daemon.Running()).To(Succeed())
		log := must(os.ReadFile(logPath))
		Expect(len(log)).To(BeNumerically(">=", logStart))
		return string(log[logStart:])
	}, testcfg.Duration(cfg.SettleTimeout), testcfg.Duration(cfg.PollInterval)).WithContext(ctx).
		Should(ContainSubstring("Invalid address supplied " + bad))
	after := must(cli.Attributes(ctx, "-list_drv_attr", "iscsi"))
	Expect(after["internal_portal"]).To(Equal(before))
})
