// SPDX-License-Identifier: GPL-2.0-only
package testrun

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"scst-component-tests/internal/testcfg"
)

func TestReadSelection(t *testing.T) {
	for _, tc := range []struct {
		name               string
		local, iscsi, want int
	}{
		{"local", 31, 0, 1}, {"iscsi", 0, 8, 1}, {"both", 31, 7, 2}, {"empty", 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, s := range []Selection{{"local", tc.local}, {"iscsi", tc.iscsi}} {
				data, _ := json.Marshal(s)
				if err := os.WriteFile(filepath.Join(dir, s.Group+".json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := ReadSelection(dir)
			if tc.want == 0 {
				if err == nil {
					t.Fatal("empty selection succeeded")
				}
				return
			}
			if err != nil || len(got) != tc.want {
				t.Fatalf("selection=%v err=%v", got, err)
			}
			if tc.want == 2 && (got[0].Group != "local" || got[1].Group != "iscsi") {
				t.Fatal("unstable transport order")
			}
		})
	}
	if _, err := ReadSelection(t.TempDir()); err == nil {
		t.Fatal("missing discovery reports succeeded")
	}
}

func TestValidateSelectedGroups(t *testing.T) {
	local, both := []Selection{{"local", 31}}, []Selection{{"local", 31}, {"iscsi", 7}}
	cfg := testcfg.Config{DisposableHost: true}
	if err := ValidateSelection(cfg, local); err != nil {
		t.Fatal(err)
	}
	if ValidateSelection(cfg, both) == nil {
		t.Fatal("iSCSI selection accepted without its configuration")
	}
	cfg.ISCSI = &testcfg.ISCSI{}
	if err := ValidateSelection(cfg, local); err != nil {
		t.Fatal("unselected initiator required approval:", err)
	}
	if ValidateSelection(cfg, both) == nil {
		t.Fatal("selected initiator lacks disposable_host")
	}
	cfg.ISCSI.Initiator.DisposableHost = true
	if err := ValidateSelection(cfg, both); err != nil {
		t.Fatal(err)
	}
}
