// SPDX-License-Identifier: GPL-2.0-only
package suite

import (
	"context"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Drop only this fixture's copy-manager mappings. Without this, a device can
// retain an open backend after the last external LUN has been removed.
func (f *fixture) detachCopyManager(ctx context.Context, device string) {
	GinkgoHelper()
	for lun, d := range copyManagerLUNs(ctx) {
		if d == device {
			f.do(ctx, "-rem_lun", strconv.Itoa(lun), "-driver", "copy_manager", "-target", "copy_manager_tgt")
		}
	}
	Expect(copyManagerLUNs(ctx)).NotTo(ContainElement(device))
}

func (f *fixture) attachFileio(ctx context.Context, device string) (string, string) {
	GinkgoHelper()
	session := f.name("session")
	target := f.target(ctx, "target", "session_name="+session)
	// scstadmin reports session LUNs only for explicit initiator groups.
	f.at(ctx, target, "", "-add_group", "access")
	f.at(ctx, target, "access", "-add_lun", "0", "-device", device)
	f.at(ctx, target, "access", "-add_init", session)
	f.sessionLUNs(ctx, target, session, map[int]string{0: device})
	return target, session
}

var _ = Describe("File-backed devices", Label("basic", "fileio"), func() {
	var f *fixture
	BeforeEach(func() { f = newFixture() })

	It("syncs an active device and keeps its configuration across reactivation", func(ctx SpecContext) {
		path := f.backingFile("disk")
		d := f.fileDevice(ctx, "disk", path)
		f.attachFileio(ctx, d)
		Expect(f.deviceAttr(ctx, d, "active")).To(Equal("1"))
		f.setDevice(ctx, d, "sync=1")
		f.setDevice(ctx, d, "active=0")
		Expect(f.deviceAttr(ctx, d, "active")).To(Equal("0"))
		f.setDevice(ctx, d, "active=1")
		Expect(f.deviceAttr(ctx, d, "active")).To(Equal("1"))
		Expect(f.deviceAttr(ctx, d, "filename")).To(Equal(path))
		Expect(f.deviceAttr(ctx, d, "size_mb")).To(Equal("16"))
		f.setDevice(ctx, d, "sync=1")
	})

	It("rejects an active backing change and recovers from a failed activation", Label("negative"), func(ctx SpecContext) {
		first, second := f.backingFile("first"), f.backingFile("second")
		d := f.fileDevice(ctx, "disk", first, "thin_provisioned=0")
		f.attachFileio(ctx, d)
		f.reject(ctx, "-set_dev_attr", d, "-attributes", "filename="+second)
		Expect(f.deviceAttr(ctx, d, "filename")).To(Equal(first))
		Expect(f.deviceAttr(ctx, d, "active")).To(Equal("1"))
		f.reject(ctx, "-set_dev_attr", d, "-attributes", "active=2")
		Expect(f.deviceAttr(ctx, d, "active")).To(Equal("1"))
		f.setDevice(ctx, d, "active=0")
		f.setDevice(ctx, d, "filename="+f.file("missing.img"))
		f.reject(ctx, "-set_dev_attr", d, "-attributes", "active=1")
		Expect(f.deviceAttr(ctx, d, "active")).To(Equal("0"))
		f.setDevice(ctx, d, "filename="+second)
		f.setDevice(ctx, d, "active=1")
		Expect(f.deviceAttr(ctx, d, "filename")).To(Equal(second))
		Expect(f.deviceAttr(ctx, d, "active")).To(Equal("1"))
		Expect(f.deviceAttr(ctx, d, "thin_provisioned")).To(Equal("0"))
		Expect(f.deviceAttr(ctx, d, "size_mb")).To(Equal("16"))
		f.setDevice(ctx, d, "sync=1")
	})

	It("rejects a missing backing file without leaving a device behind", Label("negative"), func(ctx SpecContext) {
		neighbor := f.fileDevice(ctx, "neighbor", f.backingFile("neighbor"))
		d := f.name("missing")
		f.devices = append(f.devices, d)
		f.reject(ctx, "-open_dev", d, "-handler", "vdisk_fileio", "-attributes", "filename="+f.file("missing.img"))
		Expect(must(cli.Devices(ctx))).To(Equal(map[string]string{neighbor: "vdisk_fileio"}))
		Expect(f.deviceAttr(ctx, neighbor, "active")).To(Equal("1"))
		// A failed create must not reserve the name.
		f.fileDevice(ctx, "missing", f.backingFile("recovered"))
		Expect(f.deviceAttr(ctx, d, "active")).To(Equal("1"))
	})

	// Issue #13: the explicit TP setting must remain a configuration key even
	// when equal to the default. This does not reproduce the reported I/O CRC.
	DescribeTable("preserves explicit thin provisioning through save and restore", Label("config", "clear-config", "issue-13"),
		func(ctx SpecContext, tp string) {
			if tp == "1" && !cfg.FileioThinProvisioning {
				Skip("fileio_thin_provisioning=false: TP-enabled coverage explicitly disabled for this filesystem")
			}
			path := f.backingFile("disk")
			d := f.fileDevice(ctx, "disk", path, "thin_provisioned="+tp, "bind_alua_state=1")
			attrs := must(cli.Attributes(ctx, "-list_device", d))
			Expect(attrs).To(HaveKey("thin_provisioned"))
			Expect(attrs["thin_provisioned"].Key).To(BeTrue())
			Expect(f.deviceAttr(ctx, d, "thin_provisioned")).To(Equal(tp), "TP-enabled coverage requires a capable backing filesystem; see backing_dir and fileio_thin_provisioning")
			// Exercise backend reactivation before persisting the setting.
			f.setDevice(ctx, d, "active=0")
			path = f.backingFile("replacement")
			f.setDevice(ctx, d, "filename="+path)
			f.setDevice(ctx, d, "active=1")
			Expect(f.deviceAttr(ctx, d, "thin_provisioned")).To(Equal(tp))
			saved := f.file("fileio.conf")
			f.do(ctx, "-write_config", saved)
			f.do(ctx, "-check_config", saved)
			f.do(ctx, "-clear_config", "-force")
			Expect(cli.RequireEmpty(ctx)).To(Succeed())
			f.do(ctx, "-config", saved)
			Expect(must(cli.Devices(ctx))).To(Equal(map[string]string{d: "vdisk_fileio"}))
			Expect(f.deviceAttr(ctx, d, "filename")).To(Equal(path))
			Expect(f.deviceAttr(ctx, d, "active")).To(Equal("1"))
			Expect(f.deviceAttr(ctx, d, "thin_provisioned")).To(Equal(tp))
			Expect(must(cli.Attributes(ctx, "-list_device", d))["thin_provisioned"].Key).To(BeTrue())
			Expect(f.deviceAttr(ctx, d, "bind_alua_state")).To(Equal("1"))
		}, Entry("disabled", "0"), Entry("enabled on a capable filesystem", "1"))
})

var _ = It("handles sync on an inactive fileio device without losing manageability", Label("basic", "fileio", "negative", "issue-394"), func(ctx SpecContext) {
	f := newFixture()
	path := f.backingFile("disk")
	d := f.fileDevice(ctx, "disk", path)
	f.attachFileio(ctx, d)
	f.setDevice(ctx, d, "active=0")
	Expect(f.deviceAttr(ctx, d, "active")).To(Equal("0"))
	f.reject(ctx, "-set_dev_attr", d, "-attributes", "sync=1")
	Expect(f.deviceAttr(ctx, d, "active")).To(Equal("0"))
	Expect(f.deviceAttr(ctx, d, "filename")).To(Equal(path))
	Expect(f.deviceAttr(ctx, d, "size_mb")).To(Equal("16"))
	f.setDevice(ctx, d, "active=1")
	Expect(f.deviceAttr(ctx, d, "active")).To(Equal("1"))
	f.setDevice(ctx, d, "sync=1")
})

var _ = It("rejects sync after the last attachment and reopens on a new attachment", Label("basic", "fileio", "negative", "issue-394"), func(ctx SpecContext) {
	f := newFixture()
	path := f.backingFile("disk")
	d := f.fileDevice(ctx, "disk", path)
	f.detachCopyManager(ctx, d)
	Expect(f.deviceAttr(ctx, d, "active")).To(Equal("1"))
	f.reject(ctx, "-set_dev_attr", d, "-attributes", "sync=1")
	// Reactivation alone must not invent a backend attachment.
	f.setDevice(ctx, d, "active=0")
	f.setDevice(ctx, d, "active=1")
	f.reject(ctx, "-set_dev_attr", d, "-attributes", "sync=1")
	target, session := f.attachFileio(ctx, d)
	f.setDevice(ctx, d, "sync=1")
	f.at(ctx, target, "access", "-rem_lun", "0")
	f.sessionLUNs(ctx, target, session, map[int]string{})
	f.reject(ctx, "-set_dev_attr", d, "-attributes", "sync=1")
	Expect(f.deviceAttr(ctx, d, "active")).To(Equal("1"))
	Expect(f.deviceAttr(ctx, d, "filename")).To(Equal(path))
	Expect(f.deviceAttr(ctx, d, "size_mb")).To(Equal("16"))
	f.at(ctx, target, "access", "-add_lun", "0", "-device", d)
	f.sessionLUNs(ctx, target, session, map[int]string{0: d})
	f.setDevice(ctx, d, "sync=1")
})
