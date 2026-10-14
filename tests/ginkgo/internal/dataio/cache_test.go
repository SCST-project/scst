// SPDX-License-Identifier: GPL-2.0-only
package dataio

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"scst-component-tests/internal/admin"
	"scst-component-tests/internal/testcfg"
)

func TestCacheCDBWireFormat(t *testing.T) {
	cases := []struct {
		name  string
		build func() ([]byte, error)
		want  string
	}{
		{"WRITE10 FUA", func() ([]byte, error) { return readWriteCDB(false, true, true, 0x12345678, 0x1234) }, "2a081234567800123400"},
		{"WRITE16 FUA", func() ([]byte, error) { return readWriteCDB(true, true, true, 0x100000002, 9) }, "8a080000000100000002000000090000"},
		{"READ16", func() ([]byte, error) { return readWriteCDB(true, false, false, 31, 9) }, "8800000000000000001f000000090000"},
		{"CACHE10 range", func() ([]byte, error) { return synchronizeCacheCDB(false, false, 16, 2) }, "35000000001000000200"},
		{"CACHE10 IMMED to end", func() ([]byte, error) { return synchronizeCacheCDB(false, true, 16, 0) }, "35020000001000000000"},
		{"CACHE16 range", func() ([]byte, error) { return synchronizeCacheCDB(true, false, 0x100000002, 9) }, "91000000000100000002000000090000"},
		{"CACHE16 IMMED to end", func() ([]byte, error) { return synchronizeCacheCDB(true, true, 16, 0) }, "91020000000000000010000000000000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.build()
			if err != nil || hex.EncodeToString(got) != tc.want {
				t.Fatalf("CDB %x, want %s: %v", got, tc.want, err)
			}
		})
	}
	for _, r := range []struct {
		lba    uint64
		blocks uint32
	}{{0x100000000, 1}, {1, 0x10000}} {
		if _, err := readWriteCDB(false, true, true, r.lba, r.blocks); err == nil {
			t.Fatal("truncated WRITE10 range")
		}
		if _, err := synchronizeCacheCDB(false, false, r.lba, r.blocks); err == nil {
			t.Fatal("truncated CACHE10 range")
		}
	}
}

func TestCacheCommandSequence(t *testing.T) {
	for _, fua := range []bool{false, true} {
		t.Run(fmt.Sprintf("fua=%t", fua), func(t *testing.T) {
			var ops []string
			var payload []byte
			run := func(_ context.Context, _ time.Duration, argv ...string) (admin.Result, error) {
				var request struct {
					Args  []string `json:"argv"`
					Input []byte   `json:"input"`
				}
				if err := json.Unmarshal([]byte(argv[3]), &request); err != nil {
					t.Fatal(err)
				}
				args := request.Args
				if args[0] != "sg_raw" {
					t.Fatalf("unexpected command %v", args)
				}
				cdb := args[len(args)-16:]
				ops = append(ops, cdb[0])
				var data []byte
				switch cdb[0] {
				case "8a":
					wantFlag := "00"
					if fua {
						wantFlag = "08"
					}
					if cdb[1] != wantFlag || !strings.Contains(strings.Join(args, " "), "--send=4608") {
						t.Fatalf("WRITE flags/size: %v", args)
					}
					payload = append([]byte(nil), request.Input...)
					if len(payload) != 4608 {
						t.Fatalf("payload: %d", len(payload))
					}
				case "91":
					if cdb[1] != "02" || strings.Join(cdb[10:14], "") != "00000000" {
						t.Fatalf("CACHE IMMED/to-end: %v", cdb)
					}
					if len(request.Input) != 0 || strings.Contains(strings.Join(args, " "), "--request=") {
						t.Fatal("CACHE has a data phase")
					}
				case "88":
					if cdb[1] != "00" || !strings.Contains(strings.Join(args, " "), "--request=4608") {
						t.Fatalf("READ flags/size: %v", args)
					}
					data = payload
				default:
					t.Fatalf("unexpected CDB %v", cdb)
				}
				if data == nil {
					data = []byte{}
				}
				wire, err := json.Marshal(Reply{Data: data})
				return admin.Result{Stdout: string(wire)}, err
			}
			e := Endpoint{Run: run, Path: "/dev/fixture", Backend: Backend{Bytes: 1 << 20, BlockSize: 512}}
			err := e.cacheCommand(context.Background(), cacheOperation{sixteen: true, fua: fua, immed: true, toEnd: true, lba: 31, blocks: 9})
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"8a", "91", "88"}
			if fua {
				want = []string{"8a", "88"}
			}
			if !reflect.DeepEqual(ops, want) {
				t.Fatalf("command sequence %v, want %v", ops, want)
			}
		})
	}
}

func TestCacheCommandRejectsFailureAndCorruptReadback(t *testing.T) {
	for _, failure := range []string{"execution", "check condition", "short read", "wrong data"} {
		t.Run(failure, func(t *testing.T) {
			calls := 0
			run := func(_ context.Context, _ time.Duration, _ ...string) (admin.Result, error) {
				calls++
				if failure == "execution" {
					return admin.Result{}, errors.New("timeout")
				}
				r := Reply{Data: []byte{}}
				if failure == "check condition" {
					r.ExitCode = 3
					r.Stderr = "SCSI Status: Check Condition"
				}
				if calls == 2 && failure == "wrong data" {
					r.Data = make([]byte, 512)
				}
				wire, err := json.Marshal(r)
				return admin.Result{Stdout: string(wire)}, err
			}
			e := Endpoint{Run: run, Path: "/dev/fixture", Backend: Backend{Bytes: 1 << 20, BlockSize: 512}}
			if e.cacheCommand(context.Background(), cacheOperation{fua: true, lba: 16, blocks: 1}) == nil {
				t.Fatal("accepted failed command or invalid data")
			}
			if (failure == "execution" || failure == "check condition") && calls != 1 {
				t.Fatal("continued after failed WRITE")
			}
		})
	}
}

func TestFileioCacheProfiles(t *testing.T) {
	for _, options := range []FileioOptions{
		{}, {Async: true}, {BlockSize: 4096},
		{Async: true, Direct: true, BlockSize: 4096},
		{Async: true, WriteThrough: true}, {Async: true, NVCache: true},
	} {
		var cfg testcfg.Config
		cfg.IO.RegionMB = 1
		var owned []string
		b, err := PrepareBackend(context.Background(), cfg, t.TempDir(), "cache", Profile{Handler: "vdisk_fileio", Fileio: options}, nil, func(path string) { owned = append(owned, path) })
		if err != nil {
			t.Fatal(err)
		}
		if len(owned) != 1 {
			t.Fatalf("unowned backing: %v", owned)
		}
		for name, on := range map[string]bool{"async": options.Async, "o_direct": options.Direct, "write_through": options.WriteThrough, "nv_cache": options.NVCache} {
			bit := 0
			if on {
				bit = 1
			}
			if !strings.Contains(b.Attributes, fmt.Sprintf(",%s=%d", name, bit)) {
				t.Fatalf("lost %s in %s", name, b.Attributes)
			}
		}
		want := options.BlockSize
		if want == 0 {
			want = 512
		}
		if b.BlockSize != want || !strings.Contains(b.Attributes, fmt.Sprintf(",blocksize=%d,", want)) {
			t.Fatalf("geometry: %+v", b)
		}
	}
}

func TestFileioDirectRequiresAsync(t *testing.T) {
	var cfg testcfg.Config
	cfg.IO.RegionMB = 1
	owned := false
	_, err := PrepareBackend(context.Background(), cfg, t.TempDir(), "invalid",
		Profile{Handler: "vdisk_fileio", Fileio: FileioOptions{Direct: true}}, nil,
		func(string) { owned = true })
	if err == nil {
		t.Fatal("accepted direct fileio without asynchronous I/O")
	}
	if owned {
		t.Fatal("created a backing file for an unsupported profile")
	}
}
