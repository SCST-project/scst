// SPDX-License-Identifier: GPL-2.0-only
package suite

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"scst-component-tests/internal/dataio"
	"scst-component-tests/internal/testcfg"
)

var _ = dataio.Register(func(ctx SpecContext, profile dataio.Profile) *dataio.Endpoint {
	timeout := testcfg.Duration(cfg.CommandTimeout)
	Expect(dataio.RequireTools(ctx, cli.RunProgram, timeout, profile.FIO)).To(Succeed())
	f := newFixture()
	backend := must(dataio.PrepareBackend(ctx, cfg, artifactDir, dataio.DeviceID(f.prefix), profile,
		cli.RunProgram, func(path string) { f.backingFiles = append(f.backingFiles, path) }))
	d := f.openDevice(ctx, "io", backend.Handler, backend.Attributes)
	f.setDevice(ctx, d, "usn="+backend.Serial+",vend_specific_id="+backend.Serial)
	session := f.name("session")
	target := f.target(ctx, "target", "session_name="+session)
	f.at(ctx, target, "", "-add_group", "access")
	attrs := "read_only=0"
	if profile.ReadOnly {
		attrs = "read_only=1"
	}
	f.at(ctx, target, "access", "-add_lun", "0", "-device", d, "-attributes", attrs)
	if profile.ExtraLUNs {
		f.at(ctx, target, "access", "-add_lun", "7", "-device", d)
		f.at(ctx, target, "", "-add_group", "hidden")
		f.at(ctx, target, "hidden", "-add_lun", "13", "-device", d)
	}
	f.at(ctx, target, "access", "-add_init", session)
	e := &dataio.Endpoint{Run: cli.RunProgram, Timeout: timeout, IOTimeout: testcfg.Duration(cfg.IO.Timeout),
		Backend: backend, ReadOnly: profile.ReadOnly, RegionMB: cfg.IO.RegionMB, Artifacts: artifactDir, Name: f.name("io")}
	Eventually(func() error { return e.Discover(ctx) }, testcfg.Duration(cfg.SettleTimeout),
		testcfg.Duration(cfg.PollInterval)).WithContext(ctx).Should(Succeed())
	return e
})
