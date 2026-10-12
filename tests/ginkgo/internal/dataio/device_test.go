// SPDX-License-Identifier: GPL-2.0-only
package dataio

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"scst-component-tests/internal/admin"
)

func TestDeviceIDFitsVDiskUSN(t *testing.T) {
	seen := make(map[string]string)
	for _, name := range []string{
		"scsttest_0123456789abcdef_1",
		"scsttest_0123456789abcdef_2",
		"scsttest_0123456789abcdef_1_io",
	} {
		id := DeviceID(name)
		if len(id) == 0 || len(id) > 20 {
			t.Fatalf("fixture identifier %q exceeds the 20-character vdisk USN limit", id)
		}
		if previous, exists := seen[id]; exists {
			t.Fatalf("fixtures %q and %q share identifier %q", previous, name, id)
		}
		seen[id] = name
	}
}

func TestRejectUnsafeDisk(t *testing.T) {
	mounted, fs := "/mnt/data", "xfs"
	for _, b := range []block{
		{Type: "part"}, {Type: "disk", Children: []block{{Type: "part"}}},
		{Type: "disk", Mountpoints: []*string{&mounted}}, {Type: "disk", Filesystem: &fs},
	} {
		if unused(b) == nil {
			t.Fatalf("accepted disk in use: %+v", b)
		}
	}
	if err := unused(block{Type: "disk", Mountpoints: []*string{nil}}); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverRejectsAmbiguousOrWrongDiskBeforeSG(t *testing.T) {
	good := block{Path: "/dev/sdz", Type: "disk", HCTL: "1:0:0:0", Serial: "owned", Size: 192 << 20, Logical: 512}
	for name, disks := range map[string][]block{
		"absent": {}, "duplicate": {good, good},
		"wrong LUN":    {func() block { b := good; b.HCTL = "1:0:0:7"; return b }()},
		"wrong size":   {func() block { b := good; b.Size--; return b }()},
		"wrong sector": {func() block { b := good; b.Logical = 4096; return b }()},
		"readonly":     {func() block { b := good; b.ReadOnly = true; return b }()},
		"other serial": {func() block { b := good; b.Serial = "other"; return b }()},
	} {
		t.Run(name, func(t *testing.T) {
			run := func(_ context.Context, _ time.Duration, argv ...string) (admin.Result, error) {
				if argv[0] != "lsblk" {
					t.Fatalf("unsafe device reached SCSI utility: %v", argv)
				}
				data, err := json.Marshal(map[string]any{"blockdevices": disks})
				return admin.Result{Stdout: string(data)}, err
			}
			e := Endpoint{Run: run, Backend: Backend{Serial: "owned", Bytes: 192 << 20, BlockSize: 512}}
			if e.Discover(context.Background()) == nil {
				t.Fatal("accepted wrong disk")
			}
		})
	}
}
