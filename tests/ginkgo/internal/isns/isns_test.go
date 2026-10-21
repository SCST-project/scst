// SPDX-License-Identifier: GPL-2.0-only
package isns

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

//go:embed testdata/tlv_probe.c
var tlvProbe string

func TestISNS(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SCST iSNS payload bounds")
}

var _ = Describe("iSNS payload validation", Label("unit", "userspace", "isns"), func() {
	var probe string
	var client *admin.Client

	BeforeEach(func(ctx SpecContext) {
		client = &admin.Client{Log: GinkgoWriter}
		dir, err := os.MkdirTemp("", "scst-isns-probe-")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() {
			if client.Blocked() != nil {
				AddReportEntry("preserved iSNS probe", dir)
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
		input := filepath.Join(dir, "tlv_probe.c")
		Expect(os.WriteFile(input, []byte(tlvProbe), 0600)).To(Succeed())
		probe = filepath.Join(dir, "tlv-probe")
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

	DescribeTable("checks bounds before reading or replacing ACLs", func(ctx SpecContext, scenario string) {
		r, err := client.RunProgram(ctx, 10*time.Second, probe, scenario)
		Expect(err).NotTo(HaveOccurred(), r.String())
		Expect(r.ExitCode).To(BeZero(), r.String())
		Expect(r.Stdout).To(Equal("ok\n"), r.String())
	},
		Entry("empty and short SCN payloads stop at the guard page", "scn-short"),
		Entry("oversized SCN value length is rejected", "scn-oversized"),
		Entry("truncated SCN value is rejected", "scn-truncated"),
		Entry("unaligned SCN value is rejected", "scn-unaligned"),
		Entry("malformed SCN tail does not modify the earlier name", "scn-tail"),
		Entry("valid SCN name and bitmap are accepted", "scn-valid"),
		Entry("zero-length delimiter advances to the next attribute", "scn-delimiter"),
		Entry("short query status preserves the ACL", "query-short"),
		Entry("short query TLV header preserves the ACL", "query-short-tlv"),
		Entry("oversized query value preserves the ACL", "query-oversized"),
		Entry("malformed query tail preserves the complete ACL", "query-tail"),
		Entry("error status preserves the ACL", "query-error"),
		Entry("valid query replaces the ACL", "query-valid"),
	)
})
