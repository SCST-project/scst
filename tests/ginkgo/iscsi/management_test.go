// SPDX-License-Identifier: GPL-2.0-only
package iscsi

import (
	"crypto/rand"
	"encoding/hex"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = It("discovers a target, logs in with its own IQN and logs out", Label("basic", "iscsi", "sessions"), func(ctx SpecContext) {
	f := newFixture(ctx)
	Expect(f.discover(ctx)).To(Equal(map[string]string{f.Target: portal()}))
	f.login(ctx)
	f.logout(ctx)
})

var _ = It("can log in again after a complete logout", Label("basic", "iscsi", "sessions"), func(ctx SpecContext) {
	f := newFixture(ctx)
	for i := 0; i < 2; i++ {
		f.login(ctx)
		f.logout(ctx)
	}
})

var _ = It("repeatedly logs in and out without leaking sessions", Label("stress", "iscsi", "sessions"), func(ctx SpecContext) {
	f := newFixture(ctx)
	for i := 0; i < cfg.StressIterations; i++ {
		f.login(ctx)
		f.logout(ctx)
	}
})

var _ = DescribeTable("CHAP authentication", Label("basic", "iscsi", "chap", "negative", "issue-318"),
	func(ctx SpecContext, algorithm string) {
		f := newFixture(ctx)
		secretBytes := make([]byte, 8)
		_, err := rand.Read(secretBytes)
		Expect(err).NotTo(HaveOccurred())
		secret := hex.EncodeToString(secretBytes)
		do(ctx, "-add_tgt_attr", f.Target, "-driver", "iscsi", "-attributes", "IncomingUser=tester "+secret)
		f.update(ctx, "node.session.auth.authmethod", "CHAP")
		// Offer exactly one algorithm. A fallback would hide SHA256/SHA3 failures.
		f.update(ctx, "node.session.auth.chap_algs", algorithm)
		f.update(ctx, "node.session.auth.username", "tester")
		f.update(ctx, "node.session.auth.password", "incorrect-secret")
		before := must(cli.DriverAssignments(ctx, "iscsi", f.Target))
		r := f.node(ctx, "--login")
		Expect(r.ExitCode).To(Equal(24), "expected authentication failure, not transport/setup failure: %s", r.String())
		expectNoSessions(ctx)
		f.noTargetSession(ctx)
		Expect(must(cli.DriverAssignments(ctx, "iscsi", f.Target))).To(Equal(before))
		f.update(ctx, "node.session.auth.password", secret)
		f.login(ctx)
		f.logout(ctx)
	},
	Entry("MD5", "MD5"),
	Entry("SHA1", "SHA1"),
	Entry("SHA256", "SHA256"),
	Entry("SHA3-256", "SHA3-256"),
)

var _ = It("filters discovery by the target portal address and permits the matching portal", Label("basic", "iscsi", "discovery", "issue-103", "issue-126"), func(ctx SpecContext) {
	f := newFixture(ctx)
	Expect(f.discover(ctx)).To(HaveKeyWithValue(f.Target, portal()))
	// The daemon listens only on target_address. Loopback cannot match it.
	do(ctx, "-add_tgt_attr", f.Target, "-driver", "iscsi", "-attributes", "allowed_portal=127.0.0.1")
	Expect(f.discover(ctx)).To(BeEmpty())
	do(ctx, "-rem_tgt_attr", f.Target, "-driver", "iscsi", "-attributes", "allowed_portal=127.0.0.1")
	do(ctx, "-add_tgt_attr", f.Target, "-driver", "iscsi", "-attributes", "allowed_portal="+cfg.ISCSI.TargetAddress)
	Expect(f.discover(ctx)).To(HaveKeyWithValue(f.Target, portal()))
	f.login(ctx)
	f.logout(ctx)
})
