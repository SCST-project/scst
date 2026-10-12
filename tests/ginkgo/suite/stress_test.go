// SPDX-License-Identifier: GPL-2.0-only
package suite

import (
	"context"
	"fmt"
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func (f *fixture) exerciseIdentifiers(ctx context.Context, iterations int) {
	GinkgoHelper()
	neighbor := f.device(ctx, "neighbor")
	neighborID := f.deviceAttr(ctx, neighbor, "t10_dev_id")
	neighborUSN := f.deviceAttr(ctx, neighbor, "usn")
	for i := 0; i < iterations; i++ {
		a, b := f.device(ctx, "first"), f.device(ctx, "second")
		before := copyManagerLUNs(ctx)
		Expect(before).To(HaveLen(3))
		// Updating separate devices schedules independent inquiry work. CLI
		// calls are serialized; this is not a deterministic race reproducer.
		for j, d := range []string{a, b} {
			id := fmt.Sprintf("%s%03x%d", runID, i, j)
			f.setDevice(ctx, d, "t10_dev_id="+id+",usn="+id)
		}
		for j, d := range []string{a, b} {
			id := fmt.Sprintf("%s%03x%d", runID, i, j)
			Expect(f.deviceAttr(ctx, d, "t10_dev_id")).To(Equal(id))
			Expect(f.deviceAttr(ctx, d, "usn")).To(Equal(id))
		}
		Expect(copyManagerLUNs(ctx)).To(Equal(before))
		for _, d := range []string{a, b} {
			f.do(ctx, "-close_dev", d, "-handler", "vdisk_nullio")
		}
		Expect(must(cli.Devices(ctx))).To(Equal(map[string]string{neighbor: "vdisk_nullio"}))
		remaining := copyManagerLUNs(ctx)
		Expect(remaining).To(HaveLen(1))
		for _, d := range remaining {
			Expect(d).To(Equal(neighbor))
		}
		Expect(f.deviceAttr(ctx, neighbor, "t10_dev_id")).To(Equal(neighborID))
		Expect(f.deviceAttr(ctx, neighbor, "usn")).To(Equal(neighborUSN))
	}
}

var _ = It("updates device identifiers without changing neighboring devices or copy-manager mappings", Label("basic", "devices", "copy-manager", "issue-99"), func(ctx SpecContext) {
	newFixture().exerciseIdentifiers(ctx, 1)
})

var _ = It("repeatedly updates identifiers and recreates copy-manager devices", Label("stress", "devices", "copy-manager", "issue-99"), func(ctx SpecContext) {
	newFixture().exerciseIdentifiers(ctx, cfg.StressIterations)
})

var _ = It("removes a local session with many LUNs and reuses its target name", Label("stress", "scale", "sessions", "issue-229"), func(ctx SpecContext) {
	f := newFixture()
	d, neighbor := f.device(ctx, "disk"), f.device(ctx, "neighbor")
	session := f.name("session")
	t := f.target(ctx, "target", "session_name="+session)
	g := f.name("group")
	var config strings.Builder
	fmt.Fprintf(&config, "HANDLER vdisk_nullio {\n DEVICE %s {\n  dummy 1\n  size_mb 8\n }\n}\n", d)
	fmt.Fprintf(&config, "TARGET_DRIVER scst_local {\n TARGET %s {\n  GROUP %s {\n   INITIATOR %s\n", t, g, session)
	expected := map[int]string{}
	for n := 0; n < cfg.ScaleLUNs; n++ {
		fmt.Fprintf(&config, "   LUN %d %s\n", n, d)
		expected[n] = d
	}
	config.WriteString("  }\n }\n}\n")
	path := f.file("many-luns.conf")
	Expect(os.WriteFile(path, []byte(config.String()), 0600)).To(Succeed())
	f.do(ctx, "-config", path)
	Expect(f.luns(ctx, t, g)).To(Equal(expected))
	f.sessionLUNs(ctx, t, session, expected)
	r, err := cli.Execute(ctx, "-rem_target", t, "-driver", "scst_local")
	Expect(err).NotTo(HaveOccurred(), r.String())
	Expect(r.ExitCode).To(BeZero(), r.String())
	Expect(r.ReportedError()).To(BeFalse(), r.String())
	AddReportEntry("session teardown", fmt.Sprintf("%d LUNs: %s (includes scstadmin overhead)", cfg.ScaleLUNs, r.Duration))
	Expect(must(cli.Targets(ctx))).NotTo(HaveKey(t))
	Expect(must(cli.Sessions(ctx))).NotTo(HaveKey("scst_local/" + t))
	Expect(must(cli.Devices(ctx))).To(Equal(map[string]string{d: "vdisk_nullio", neighbor: "vdisk_nullio"}))
	// Reusing the name and attaching a fresh session exposes lingering state.
	f.target(ctx, "target", "session_name="+session)
	f.at(ctx, t, "", "-add_group", g)
	f.at(ctx, t, g, "-add_lun", "0", "-device", neighbor)
	f.at(ctx, t, g, "-add_init", session)
	f.sessionLUNs(ctx, t, session, map[int]string{0: neighbor})
})
