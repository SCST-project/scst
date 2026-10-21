// SPDX-License-Identifier: GPL-2.0-only
package dataio

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Register shares protocol assertions and the fio profile across transports;
// each suite owns its target/session lifecycle and supplies the exported disk.
func Register(create func(SpecContext, Profile) *Endpoint) bool {
	return Describe("Exported SCSI devices", func() {
		It("returns INQUIRY and VPD identity", Label("scsi", "smoke"), func(ctx SpecContext) {
			Expect(create(ctx, Profile{Handler: "vdisk_fileio"}).Identity(ctx)).To(Succeed())
		})
		It("reports matching READ CAPACITY(10) and (16) geometry", Label("scsi", "smoke", "pr"), func(ctx SpecContext) {
			Expect(create(ctx, Profile{Handler: "vdisk_fileio"}).Capacity(ctx)).To(Succeed())
		})
		It("reports only the initiator's accessible LUNs", Label("scsi", "smoke"), func(ctx SpecContext) {
			Expect(create(ctx, Profile{Handler: "vdisk_fileio", ExtraLUNs: true}).LUNs(ctx)).To(Succeed())
		})
		It("rejects a read-only WRITE with DATA PROTECT and preserves data", Label("scsi", "negative", "smoke", "pr"), func(ctx SpecContext) {
			Expect(create(ctx, Profile{Handler: "vdisk_fileio", ReadOnly: true}).ReadOnlyWrite(ctx)).To(Succeed())
		})
		It("rejects an out-of-range READ with ILLEGAL REQUEST and remains usable", Label("scsi", "negative", "smoke"), func(ctx SpecContext) {
			Expect(create(ctx, Profile{Handler: "vdisk_fileio"}).OutOfRange(ctx)).To(Succeed())
		})
		DescribeTable("bounds UNMAP descriptors and preserves surrounding data", Label("scsi", "fileio", "unmap"),
			func(ctx SpecContext, tc unmapCase) {
				e := create(ctx, Profile{Handler: "vdisk_fileio", Fileio: FileioOptions{ThinProvisioned: true}})
				Expect(e.UNMAP(ctx, tc)).To(Succeed())
			},
			Entry("zero parameter length is a no-op", unmapCase{}),
			Entry("short header returns PARAMETER LIST LENGTH ERROR", Label("negative"),
				unmapCase{parameterLength: 7, lengthError: true}),
			Entry("empty descriptor list is a no-op", unmapCase{parameterLength: 8}),
			Entry("header alone cannot supply a descriptor", unmapCase{parameterLength: 8, descriptorLength: 16}),
			Entry("15-byte descriptor is ignored", unmapCase{parameterLength: 23, descriptorLength: 15}),
			Entry("one complete descriptor unmaps its range", unmapCase{parameterLength: 24, descriptorLength: 16, unmapped: 1}),
			Entry("unaligned descriptor length keeps the complete descriptor", unmapCase{parameterLength: 25, descriptorLength: 17, unmapped: 1}),
			Entry("CDB length excludes a partial second descriptor", unmapCase{parameterLength: 39, descriptorLength: 32, unmapped: 1}),
			Entry("CDB length bounds an oversized descriptor list", Label("smoke"), unmapCase{parameterLength: 24, descriptorLength: 32, unmapped: 1}),
			Entry("descriptor length excludes a complete trailing descriptor", unmapCase{parameterLength: 40, descriptorLength: 16, unmapped: 1}),
			Entry("two complete descriptors unmap both ranges", unmapCase{parameterLength: 40, descriptorLength: 32, unmapped: 2}),
			Entry("maximum descriptor length is bounded by the transfer", unmapCase{parameterLength: 24, descriptorLength: 0xffff, unmapped: 1}))
		DescribeTable("handles FUA writes and explicit cache commands", Label("scsi", "fileio", "issue-395"),
			func(ctx SpecContext, options FileioOptions) {
				e := create(ctx, Profile{Handler: "vdisk_fileio", Fileio: options})
				Expect(e.Capacity(ctx)).To(Succeed())
				Expect(e.CacheCommands(ctx, !options.WriteThrough && !options.NVCache)).To(Succeed())
			},
			Entry("buffered synchronous 512", FileioOptions{BlockSize: 512}),
			Entry("buffered asynchronous 512", Label("smoke"), FileioOptions{Async: true, BlockSize: 512}),
			Entry("buffered synchronous 4096", FileioOptions{BlockSize: 4096}),
			Entry("direct asynchronous 4096", FileioOptions{Async: true, Direct: true, BlockSize: 4096}),
			Entry("asynchronous write-through FUA control", FileioOptions{Async: true, WriteThrough: true}),
			Entry("asynchronous nonvolatile-cache FUA control", FileioOptions{Async: true, NVCache: true}))
		DescribeTable("verifies concurrent 4K, 64K and 128K fio jobs", Label("io", "fio", "smoke"), func(ctx SpecContext, handler string) {
			e := create(ctx, Profile{Handler: handler, FIO: true})
			Expect(e.Capacity(ctx)).To(Succeed())
			Expect(e.FIO(ctx)).To(Succeed())
		},
			Entry("buffered fileio with 512-byte sectors", Label("fileio", "pr"), "vdisk_fileio"),
			Entry("direct blockio with 4096-byte sectors", Label("blockio", "pr"), "vdisk_blockio"))
	})
}
