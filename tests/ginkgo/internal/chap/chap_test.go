// SPDX-License-Identifier: GPL-2.0-only
package chap

import (
	_ "embed"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"scst-component-tests/internal/admin"
	"scst-component-tests/internal/cprobe"
)

//go:embed testdata/random_probe.c
var randomProbe string

func TestCHAP(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SCST CHAP randomness")
}

var _ = Describe("CHAP entropy failures", Label("unit", "userspace", "chap"), func() {
	var probe string
	var client *admin.Client

	BeforeEach(func(ctx SpecContext) {
		client = &admin.Client{Log: GinkgoWriter}
		dir, err := os.MkdirTemp("", "scst-chap-probe-")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() {
			if client.Blocked() != nil {
				AddReportEntry("preserved CHAP probe", dir)
				return
			}
			Expect(os.RemoveAll(dir)).To(Succeed())
		})
		source := os.Getenv("SCST_TEST_SOURCE_DIR")
		if source == "" {
			_, file, _, ok := runtime.Caller(0)
			Expect(ok).To(BeTrue())
			source = filepath.Clean(filepath.Join(filepath.Dir(file), "../../../.."))
		}
		Expect(cprobe.PrepareISCSIHeaders(source, dir)).To(Succeed())
		input := filepath.Join(dir, "random_probe.c")
		Expect(os.WriteFile(input, []byte(randomProbe), 0600)).To(Succeed())
		probe = filepath.Join(dir, "random-probe")
		// Dead-section removal keeps this unit probe independent of the
		// daemon's unrelated authentication and transport dependencies.
		r, err := client.RunProgram(ctx, 30*time.Second,
			"cc", "-D_GNU_SOURCE", "-O2", "-ffunction-sections", "-fdata-sections",
			"-I"+dir,
			"-I"+filepath.Join(source, "iscsi-scst/usr"),
			"-I"+filepath.Join(source, "iscsi-scst/include"),
			"-I"+filepath.Join(source, "scst/include"),
			input, "-Wl,--gc-sections", "-o", probe)
		Expect(err).NotTo(HaveOccurred(), r.String())
		Expect(r.ExitCode).To(BeZero(), r.String())
	})

	DescribeTable("publishes only complete challenges from successful reads", func(ctx SpecContext, scenario string) {
		r, err := client.RunProgram(ctx, 10*time.Second, probe, scenario)
		Expect(err).NotTo(HaveOccurred(), r.String())
		Expect(r.ExitCode).To(BeZero(), r.String())
		Expect(r.Stdout).To(Equal("ok\n"), r.String())
	},
		Entry("zero entropy value retains the lower length bound", "zero"),
		Entry("a set sign bit cannot shorten the challenge", "high-bit"),
		Entry("interrupted and short reads complete the value", "interrupted-short"),
		Entry("open failure rejects authentication", "open-error"),
		Entry("read failure rejects authentication", "read-error"),
		Entry("EOF rejects authentication", "eof"),
		Entry("EOF after a short read rejects authentication", "partial-eof"),
		Entry("payload failure discards the partial challenge", "payload-error"),
	)
})
