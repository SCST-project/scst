// SPDX-License-Identifier: GPL-2.0-only
package param

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

//go:embed testdata/string_probe.c
var stringProbe string

func TestStringCopy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SCST daemon string copies")
}

var _ = Describe("Bounded daemon string copies", Label("unit", "userspace", "param"), func() {
	var probe string
	var client *admin.Client

	BeforeEach(func(ctx SpecContext) {
		client = &admin.Client{Log: GinkgoWriter}
		dir, err := os.MkdirTemp("", "scst-param-probe-")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() {
			if client.Blocked() != nil {
				AddReportEntry("preserved string-copy probe", dir)
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
		input := filepath.Join(dir, "string_probe.c")
		Expect(os.WriteFile(input, []byte(stringProbe), 0600)).To(Succeed())
		probe = filepath.Join(dir, "string-probe")
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

	DescribeTable("bounds source reads and destination writes", func(ctx SpecContext, scenario string) {
		r, err := client.RunProgram(ctx, 10*time.Second, probe, scenario)
		Expect(err).NotTo(HaveOccurred(), r.String())
		Expect(r.ExitCode).To(BeZero(), r.String())
		Expect(r.Stdout).To(Equal("ok\n"), r.String())
	},
		Entry("zero capacity touches neither pointer", "zero"),
		Entry("an empty source writes only its terminator", "empty"),
		Entry("a fitting string leaves the tail untouched", "fits"),
		Entry("an exact fit retains its terminator", "exact-fit"),
		Entry("a one-byte destination is terminated", "one-byte"),
		Entry("a full source stops before the guard page", "truncated"),
	)
})
