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
		name        string
		local, want int
	}{
		{"local", 31, 1}, {"empty", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, s := range []Selection{{"local", tc.local}} {
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
		})
	}
	if _, err := ReadSelection(t.TempDir()); err == nil {
		t.Fatal("missing discovery reports succeeded")
	}
}

func TestValidateSelectedGroups(t *testing.T) {
	local := []Selection{{"local", 31}}
	if ValidateSelection(testcfg.Config{}, local) == nil {
		t.Fatal("selected host lacks disposable_host")
	}
	if err := ValidateSelection(testcfg.Config{DisposableHost: true}, local); err != nil {
		t.Fatal(err)
	}
}
