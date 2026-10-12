// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scst-component-tests/internal/testrun"
)

// Stand in for the Go tool so these tests never launch a live component suite.
func TestMain(m *testing.M) {
	if os.Getenv("SCST_LAUNCHER_STUB") == "1" {
		if dir := os.Getenv("SCST_TEST_PLAN_DIR"); dir != "" {
			var selections []testrun.Selection
			if json.Unmarshal([]byte(os.Getenv("SCST_STUB_SELECTION")), &selections) != nil {
				os.Exit(2)
			}
			for _, s := range selections {
				data, _ := json.Marshal(s)
				if os.WriteFile(filepath.Join(dir, s.Group+".json"), data, 0600) != nil {
					os.Exit(2)
				}
			}
			os.Exit(0)
		}
		file, err := os.OpenFile(os.Getenv("SCST_STUB_CALLS"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			os.Exit(2)
		}
		for _, arg := range os.Args[1:] {
			if arg == "./suite" || arg == "./iscsi" {
				if _, err := file.WriteString(arg + "\n"); err != nil {
					os.Exit(2)
				}
				file.Close()
				if arg == "./suite" && os.Getenv("SCST_STUB_FAIL_LOCAL") == "1" {
					os.Exit(1)
				}
				os.Exit(0)
			}
		}
		os.Exit(2)
	}
	os.Exit(m.Run())
}

func TestSelectedPackagesRunInOrder(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		local, iscsi         int
		failLocal, wantError bool
		want                 string
	}{
		{name: "local", local: 31, want: "./suite\n"},
		{name: "iscsi", iscsi: 8, want: "./iscsi\n"},
		{name: "both", local: 31, iscsi: 7, want: "./suite\n./iscsi\n"},
		{name: "failed cleanup stops next group", local: 31, iscsi: 7, failLocal: true, wantError: true, want: "./suite\n"},
		{name: "empty filter", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := stub(t, tc.local, tc.iscsi)
			if tc.failLocal {
				t.Setenv("SCST_STUB_FAIL_LOCAL", "1")
			}
			// Listing skips host config but follows the same package selection/order.
			err := run(true)
			if (err != nil) != tc.wantError {
				t.Fatalf("unexpected result: %v", err)
			}
			got, err := os.ReadFile(calls)
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("calls=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestConfigurationRejectedBeforeAnySuiteRuns(t *testing.T) {
	calls := stub(t, 31, 7)
	config := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(config, []byte(`{"disposable_host":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCST_TEST_CONFIG", config)
	err := run(false)
	if err == nil || !strings.Contains(err.Error(), "iscsi section") {
		t.Fatalf("missing iSCSI preflight: %v", err)
	}
	if _, err := os.Stat(calls); !os.IsNotExist(err) {
		t.Fatal("launched a suite before validating all selected groups")
	}
}

func stub(t *testing.T, local, iscsi int) string {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GO", binary)
	t.Setenv("SCST_LAUNCHER_STUB", "1")
	t.Setenv("SCST_STUB_FAIL_LOCAL", "0")
	t.Setenv("SCST_TEST_CONFIG", "/must/not/read/in/list/mode")
	data, _ := json.Marshal([]testrun.Selection{{Group: "local", Specs: local}, {Group: "iscsi", Specs: iscsi}})
	t.Setenv("SCST_STUB_SELECTION", string(data))
	calls := filepath.Join(t.TempDir(), "calls")
	t.Setenv("SCST_STUB_CALLS", calls)
	return calls
}
