// SPDX-License-Identifier: GPL-2.0-only
package suite

import (
	"context"
	"fmt"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// A small input configuration, written independently for this suite. Output
// configurations are consumed only by scstadmin, never by a test-side parser.
func (f *fixture) configuration() string {
	GinkgoHelper()
	d, t, g, init := f.name("disk"), f.name("target"), f.name("group"), f.name("initiator")
	f.devices = append(f.devices, d)
	f.targets = append(f.targets, t)
	path := f.file("input.conf")
	text := fmt.Sprintf(`HANDLER vdisk_nullio {
    DEVICE %s {
        dummy 1
        size_mb 8
    }
}
TARGET_DRIVER scst_local {
    TARGET %s {
        LUN 0 %s
        GROUP %s {
            LUN 1 %s {
                read_only 1
            }
            INITIATOR %s
        }
    }
}
`, d, t, d, g, d, init)
	Expect(os.WriteFile(path, []byte(text), 0600)).To(Succeed())
	return path
}

func (f *fixture) expectConfiguration(ctx context.Context) {
	GinkgoHelper()
	d, t, g := f.name("disk"), f.name("target"), f.name("group")
	Expect(must(cli.Devices(ctx))).To(Equal(map[string]string{d: "vdisk_nullio"}))
	Expect(must(cli.Targets(ctx))).To(Equal(map[string]string{t: "scst_local"}))
	Expect(must(cli.Scalar(ctx, "dummy", "-list_device", d))).To(Equal("1"))
	Expect(must(cli.Scalar(ctx, "size_mb", "-list_device", d))).To(Equal("8"))
	state := f.state(ctx, t)
	Expect(state.LUNs).To(Equal(map[int]string{0: d}))
	Expect(state.Groups).To(HaveLen(1))
	Expect(state.Groups).To(HaveKey(g))
	Expect(state.Groups[g].LUNs).To(Equal(map[int]string{1: d}))
	Expect(state.Groups[g].Initiators).To(ConsistOf(f.name("initiator")))
	Expect(f.lunReadOnly(ctx, t, "", "0")).To(Equal("0"))
	Expect(f.lunReadOnly(ctx, t, g, "1")).To(Equal("1"))
}

var _ = Describe("Configuration files", Label("basic", "config"), func() {
	var f *fixture
	BeforeEach(func() { f = newFixture() })

	It("checks a valid configuration without applying it or changing existing objects", Label("issue-296"), func(ctx SpecContext) {
		path := f.configuration()
		d, t := f.device(ctx, "neighbor_disk"), f.target(ctx, "neighbor_target")
		f.at(ctx, t, "", "-add_lun", "0", "-device", d)
		f.do(ctx, "-check_config", path)
		Expect(must(cli.Devices(ctx))).To(Equal(map[string]string{d: "vdisk_nullio"}))
		Expect(must(cli.Targets(ctx))).To(Equal(map[string]string{t: "scst_local"}))
		Expect(f.luns(ctx, t, "")).To(Equal(map[int]string{0: d}))
	})

	It("applies the same configuration twice without changing its graph", func(ctx SpecContext) {
		path := f.configuration()
		f.do(ctx, "-config", path)
		f.expectConfiguration(ctx)
		f.do(ctx, "-config", path)
		f.expectConfiguration(ctx)
	})

	It("saves, clears and restores the configuration through scstadmin", Label("clear-config"), func(ctx SpecContext) {
		f.do(ctx, "-config", f.configuration())
		f.expectConfiguration(ctx)
		saved := f.file("saved.conf")
		f.do(ctx, "-write_config", saved)
		f.do(ctx, "-clear_config", "-force")
		Expect(must(cli.Devices(ctx))).To(BeEmpty())
		Expect(must(cli.Targets(ctx))).To(BeEmpty())
		Expect(must(cli.Names(ctx, "Device Group", "-list_dgrp"))).To(BeEmpty())
		f.do(ctx, "-config", saved)
		f.expectConfiguration(ctx)
	})
})
