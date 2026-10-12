// SPDX-License-Identifier: GPL-2.0-only
package dataio

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFIOProfile(t *testing.T) {
	job := renderFIO("/dev/sdz", 67108864, false, false)
	for _, want := range []string{"filename=/dev/sdz\n", "direct=0\n", "verify_only=0\n", "size=67108864\n", "offset=0\n", "offset=67108864\n", "offset=134217728\n", "bs=4k\n", "bs=64k\n", "bs=128k\n", "verify=crc32c\n", "force_async=1\n"} {
		if !strings.Contains(job, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(job, "@") || strings.Contains(job, "stonewall") {
		t.Fatal("unrendered or serialized jobs")
	}
	verify := renderFIO("/dev/sdz", 67108864, true, true)
	if !strings.Contains(verify, "direct=1\n") || !strings.Contains(verify, "verify_only=1\n") {
		t.Fatal("cache-bypassing pass not configured")
	}
}

func TestFIORejectsIncompleteIO(t *testing.T) {
	jobs := []map[string]any{}
	for _, name := range []string{"small", "medium", "large"} {
		jobs = append(jobs, map[string]any{"jobname": name, "error": 0, "read": map[string]any{"io_bytes": 65536}, "write": map[string]any{"io_bytes": 65536}})
	}
	report := func() []byte {
		b, err := json.Marshal(map[string]any{"jobs": jobs})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if err := fioReport(report(), 65536, false); err != nil {
		t.Fatal(err)
	}
	jobs[0]["write"] = map[string]any{"io_bytes": 0}
	if err := fioReport(report(), 65536, true); err != nil {
		t.Fatal(err)
	}
	if fioReport(report(), 65536, false) == nil {
		t.Fatal("accepted missing writes")
	}
	jobs[0]["write"] = map[string]any{"io_bytes": 65536}
	for _, mutate := range []func(){
		func() { jobs[0]["read"] = map[string]any{"io_bytes": 65535} },
		func() { jobs[0]["read"] = map[string]any{"io_bytes": 65536}; jobs[1]["error"] = 84 },
		func() { jobs[1]["error"] = 0; jobs[1]["jobname"] = "small" },
		func() { jobs[1]["jobname"] = "medium"; delete(jobs[2], "error") },
		func() { jobs = jobs[:2] },
	} {
		mutate()
		if fioReport(report(), 65536, false) == nil {
			t.Fatal("accepted incomplete fio report")
		}
	}
	for _, data := range []string{"{}", "null", "", `{"jobs":[]}`} {
		if fioReport([]byte(data), 65536, false) == nil {
			t.Fatal("accepted empty report")
		}
	}
}
