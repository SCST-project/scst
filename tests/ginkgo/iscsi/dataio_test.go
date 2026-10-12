// SPDX-License-Identifier: GPL-2.0-only
package iscsi

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"scst-component-tests/internal/dataio"
	"scst-component-tests/internal/testcfg"
)

var _ = dataio.Register(func(ctx SpecContext, profile dataio.Profile) *dataio.Endpoint {
	timeout := testcfg.Duration(cfg.CommandTimeout)
	Expect(dataio.RequireTools(ctx, peer.Run, timeout)).To(Succeed())
	f := newProfileFixture(ctx, &profile)
	f.login(ctx)
	e := &dataio.Endpoint{Run: peer.Run, Timeout: timeout,
		Backend: f.Backend, ReadOnly: profile.ReadOnly, Artifacts: artifactDir, Name: f.Device}
	Eventually(func() error { return e.Discover(ctx) }, testcfg.Duration(cfg.SettleTimeout),
		testcfg.Duration(cfg.PollInterval)).WithContext(ctx).Should(Succeed())
	return e
})
