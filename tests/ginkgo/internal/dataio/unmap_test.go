// SPDX-License-Identifier: GPL-2.0-only
package dataio

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"scst-component-tests/internal/admin"
	"scst-component-tests/internal/testcfg"
)

func TestUNMAPWireFormat(t *testing.T) {
	cdb, data, err := unmapCDB(unmapCase{parameterLength: 39, descriptorLength: 32, unmapped: 1})
	if err != nil || hex.EncodeToString(cdb) != "42000000000000002700" {
		t.Fatalf("UNMAP CDB %x: %v", cdb, err)
	}
	// The partial second descriptor must still contain a valid LBA and count:
	// processing it would corrupt the second range, rather than be a no-op.
	want := "0025002000000000" + "00000000000000180000000800000000" + "000000000000002800000008000000"
	if hex.EncodeToString(data) != want {
		t.Fatalf("UNMAP parameters %x, want %s", data, want)
	}
	cdb, data, err = unmapCDB(unmapCase{})
	if err != nil || len(data) != 0 || hex.EncodeToString(cdb) != "42000000000000000000" {
		t.Fatalf("zero-length UNMAP: %x %x %v", cdb, data, err)
	}
}

func TestUNMAPReadbackAndRejection(t *testing.T) {
	for _, mode := range []string{"good", "no-op", "extra descriptor", "guard corruption", "short read", "execution", "length error", "wrong sense", "missing sense"} {
		t.Run(mode, func(t *testing.T) {
			tc := unmapCase{parameterLength: 24, descriptorLength: 32, unmapped: 1}
			negative := mode == "length error" || mode == "wrong sense" || mode == "missing sense"
			if negative {
				tc = unmapCase{parameterLength: 7, lengthError: true}
			}
			var disk []byte
			unmapped := false
			run := func(_ context.Context, _ time.Duration, argv ...string) (admin.Result, error) {
				var request struct {
					Args  []string `json:"argv"`
					Input []byte   `json:"input"`
				}
				if err := json.Unmarshal([]byte(argv[3]), &request); err != nil {
					t.Fatal(err)
				}
				_, cdb, ok := strings.Cut(strings.Join(request.Args, " "), "/dev/fixture ")
				if !ok {
					t.Fatalf("unexpected command %v", request.Args)
				}
				r := Reply{Data: []byte{}}
				switch strings.Fields(cdb)[0] {
				case "8a":
					disk = bytes.Clone(request.Input)
				case "88":
					r.Data = disk
					if unmapped && mode == "short read" {
						r.Data = disk[:len(disk)-1]
					}
				case "42":
					unmapped = true
					if mode == "execution" {
						return admin.Result{}, errors.New("timeout")
					}
					if negative {
						r.ExitCode = 5
						r.Stderr = "SCSI Status: Check Condition\n Raw sense data (in hex), sb_len=8, calculated_len=8\n        72 05 1a 00 00 00 00 00\n"
						if mode == "wrong sense" {
							r.Stderr = strings.ReplaceAll(r.Stderr, "05 1a", "05 24")
						}
						if mode == "missing sense" {
							r.Stderr = "device open failed"
						}
					} else if mode != "no-op" {
						clear(disk[4096:8192])
						if mode == "extra descriptor" {
							clear(disk[12288:16384])
						}
						if mode == "guard corruption" {
							disk[0] = 0
						}
					}
				default:
					t.Fatalf("unexpected CDB %s", cdb)
				}
				wire, err := json.Marshal(r)
				return admin.Result{Stdout: string(wire)}, err
			}
			e := Endpoint{Run: run, Path: "/dev/fixture", Backend: Backend{Handler: "vdisk_fileio", Bytes: 1 << 20, BlockSize: 512}}
			err := e.unmapCommand(context.Background(), tc)
			wantSuccess := mode == "good" || mode == "length error"
			if (err == nil) != wantSuccess {
				t.Fatalf("success=%t, want %t: %v", err == nil, wantSuccess, err)
			}
		})
	}
}

func TestThinFileioRequiresWorkingHolePunch(t *testing.T) {
	for _, mode := range []string{"good", "unsupported", "no-op"} {
		t.Run(mode, func(t *testing.T) {
			var owned []string
			run := func(_ context.Context, _ time.Duration, argv ...string) (admin.Result, error) {
				if len(owned) != 1 || argv[len(argv)-1] != owned[0] {
					t.Fatal("hole punch attempted before recording file ownership")
				}
				if mode == "unsupported" {
					return admin.Result{ExitCode: 1, Stderr: "Operation not supported"}, nil
				}
				if mode == "good" {
					f, err := os.OpenFile(owned[0], os.O_RDWR, 0)
					if err != nil {
						t.Fatal(err)
					}
					_, err = f.WriteAt(make([]byte, 4096), 0)
					closeErr := f.Close()
					if err != nil || closeErr != nil {
						t.Fatalf("fake hole punch: %v, close: %v", err, closeErr)
					}
				}
				return admin.Result{}, nil
			}
			cfg := testcfg.Config{CommandTimeout: "1s", IO: testcfg.IO{RegionMB: 1}}
			b, err := PrepareBackend(context.Background(), cfg, t.TempDir(), "unmap",
				Profile{Handler: "vdisk_fileio", Fileio: FileioOptions{ThinProvisioned: true}}, run,
				func(path string) { owned = append(owned, path) })
			if (err == nil) != (mode == "good") {
				t.Fatalf("unexpected backend preparation result: %v", err)
			}
			if err == nil && !strings.Contains(b.Attributes, ",thin_provisioned=1,") {
				t.Fatalf("lost thin provisioning: %s", b.Attributes)
			}
		})
	}
}
