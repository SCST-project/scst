// SPDX-License-Identifier: GPL-2.0-only
package suite

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"scst-component-tests/internal/admin"
	"scst-component-tests/internal/testcfg"
	"scst-component-tests/internal/testhost"
	"scst-component-tests/internal/testrun"
)

var cfg testcfg.Config
var cli *admin.Client
var artifactDir, runID string
var pendingCleanups atomic.Int64

func TestSCST(t *testing.T) {
	testrun.Run(t, "SCST through scstadmin", false, func(env testrun.Environment) {
		cfg, cli, artifactDir, runID = env.Config, env.Client, env.ArtifactDir, env.RunID
	})
}

var _ = BeforeSuite(func(ctx SpecContext) {
	modules := new(testhost.Modules)
	sourceDir := os.Getenv("SCST_TEST_SOURCE_DIR")
	if sourceDir == "" {
		// Direct go test invocation runs in tests/ginkgo/suite.
		sourceDir = must(filepath.Abs("../../.."))
	}
	err := modules.Prepare(ctx, testhost.Options{
		SourceDir: sourceDir, KernelDir: os.Getenv("SCST_TEST_KDIR"),
		Build: os.Getenv("SCST_TEST_BUILD") == "1",
		Jobs:  cfg.BuildJobs, BuildTimeout: testcfg.Duration(cfg.BuildTimeout),
		CommandTimeout: testcfg.Duration(cfg.CommandTimeout),
	}, cli.RunProgram, cli.RequireEmpty, GinkgoWriter)
	// Register after Prepare returns, including partial failure, so unloading
	// cannot race with module loading if Ginkgo interrupts suite setup.
	DeferCleanup(func(ctx SpecContext) {
		Expect(pendingCleanups.Load()).To(BeZero(), "refusing to unload modules: spec cleanup did not complete")
		Expect(cli.Blocked()).NotTo(HaveOccurred(), "refusing to unload modules after an execution failure")
		Expect(modules.Unload(ctx, testcfg.Duration(cfg.CommandTimeout),
			cli.RunProgram, cli.RequireEmpty, GinkgoWriter)).To(Succeed())
	}, NodeTimeout(testcfg.Duration(cfg.CleanupTimeout)))
	Expect(err).To(Succeed())
	drivers, err := cli.Names(ctx, "Driver", "-list_driver")
	Expect(err).NotTo(HaveOccurred(), "scstadmin must be able to query the modules loaded by the suite")
	Expect(drivers).To(ContainElement("scst_local"), "prepare scst_local with add_default_tgt=0")
	Expect(must(cli.Names(ctx, "Handler", "-list_handler"))).To(ContainElements("vdisk_nullio", "vdisk_fileio"))
	Expect(cli.RequireEmpty(ctx)).To(Succeed())
})

// Keep failed, interrupted, or unfinished spec cleanup visible to suite cleanup.
func deferSpecCleanup(body func(SpecContext)) {
	GinkgoHelper()
	pendingCleanups.Add(1)
	DeferCleanup(func(ctx SpecContext) {
		body(ctx)
		if ctx.Err() == nil {
			pendingCleanups.Add(-1)
		}
	}, NodeTimeout(testcfg.Duration(cfg.CleanupTimeout)))
}

func must[T any](value T, err error) T {
	GinkgoHelper()
	Expect(err).NotTo(HaveOccurred())
	return value
}
