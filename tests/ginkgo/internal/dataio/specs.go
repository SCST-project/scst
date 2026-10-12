// SPDX-License-Identifier: GPL-2.0-only
package dataio

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Register shares protocol assertions across transports;
// each suite owns its target/session lifecycle and supplies the exported disk.
func Register(create func(SpecContext, Profile) *Endpoint) bool {
	return Describe("Exported SCSI devices", func() {
		It("returns INQUIRY and VPD identity", Label("scsi"), func(ctx SpecContext) {
			Expect(create(ctx, Profile{Handler: "vdisk_fileio"}).Identity(ctx)).To(Succeed())
		})
		It("reports matching READ CAPACITY(10) and (16) geometry", Label("scsi"), func(ctx SpecContext) {
			Expect(create(ctx, Profile{Handler: "vdisk_fileio"}).Capacity(ctx)).To(Succeed())
		})
		It("reports only the initiator's accessible LUNs", Label("scsi"), func(ctx SpecContext) {
			Expect(create(ctx, Profile{Handler: "vdisk_fileio", ExtraLUNs: true}).LUNs(ctx)).To(Succeed())
		})
		It("rejects a read-only WRITE with DATA PROTECT and preserves data", Label("scsi", "negative"), func(ctx SpecContext) {
			Expect(create(ctx, Profile{Handler: "vdisk_fileio", ReadOnly: true}).ReadOnlyWrite(ctx)).To(Succeed())
		})
		It("rejects an out-of-range READ with ILLEGAL REQUEST and remains usable", Label("scsi", "negative"), func(ctx SpecContext) {
			Expect(create(ctx, Profile{Handler: "vdisk_fileio"}).OutOfRange(ctx)).To(Succeed())
		})
	})
}
