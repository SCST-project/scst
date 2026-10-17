// SPDX-License-Identifier: GPL-2.0-only
package dataio

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"scst-component-tests/internal/admin"
)

func TestFindModelRejectsAmbiguousOrWrongDiskBeforeSG(t *testing.T) {
	model, other, lun0, lun7 := "u0123456789abcde", "other", "1:0:0:0", "1:0:0:7"
	good := modelBlock{Path: "/dev/sdz", Type: "disk", Size: 16 << 20, Logical: 4096, Model: &model, HCTL: &lun0}
	for name, disks := range map[string][]modelBlock{
		"absent": {}, "duplicate": {good, good},
		"no model":     {func() modelBlock { b := good; b.Model = nil; return b }()},
		"other model":  {func() modelBlock { b := good; b.Model = &other; return b }()},
		"wrong LUN":    {func() modelBlock { b := good; b.HCTL = &lun7; return b }()},
		"no HCTL":      {func() modelBlock { b := good; b.HCTL = nil; return b }()},
		"wrong size":   {func() modelBlock { b := good; b.Size--; return b }()},
		"wrong sector": {func() modelBlock { b := good; b.Logical = 512; return b }()},
		"not a disk":   {func() modelBlock { b := good; b.Type = "rom"; return b }()},
	} {
		t.Run(name, func(t *testing.T) {
			run := func(_ context.Context, _ time.Duration, argv ...string) (admin.Result, error) {
				if argv[0] != "lsblk" {
					t.Fatalf("wrong device reached SCSI utility: %v", argv)
				}
				data, err := json.Marshal(map[string]any{"blockdevices": disks})
				return admin.Result{Stdout: string(data)}, err
			}
			e := Endpoint{Run: run, Backend: Backend{Bytes: 16 << 20, BlockSize: 4096}}
			if e.FindModel(context.Background(), model) == nil {
				t.Fatal("accepted wrong disk")
			}
		})
	}
}

func TestFindModelSelectsOwnedDisk(t *testing.T) {
	model, lun0 := "u0123456789abcde", "1:0:0:0"
	var turs []string
	run := func(_ context.Context, _ time.Duration, argv ...string) (admin.Result, error) {
		if argv[0] == "lsblk" {
			data, err := json.Marshal(map[string]any{"blockdevices": []modelBlock{
				{Path: "/dev/sdy", Type: "disk", Size: 1 << 30, Logical: 512},
				{Path: "/dev/sdz", Type: "disk", Size: 16 << 20, Logical: 4096, Model: &model, HCTL: &lun0},
			}})
			return admin.Result{Stdout: string(data)}, err
		}
		if argv[0] != "python3" {
			t.Fatalf("unexpected command: %v", argv)
		}
		turs = append(turs, argv[len(argv)-1])
		return admin.Result{Stdout: `{"exit_code":0,"data":"","stderr":""}`}, nil
	}
	e := Endpoint{Run: run, Backend: Backend{Bytes: 16 << 20, BlockSize: 4096}}
	if err := e.FindModel(context.Background(), model); err != nil {
		t.Fatal(err)
	}
	if e.Path != "/dev/sdz" || len(turs) != 1 {
		t.Fatalf("selected %q after %d commands", e.Path, len(turs))
	}
}
