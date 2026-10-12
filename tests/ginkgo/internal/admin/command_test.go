// SPDX-License-Identifier: GPL-2.0-only
package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A subprocess exercises the actual exec path without invoking scstadmin.
func TestCommandProcess(t *testing.T) {
	if os.Getenv("SCST_COMMAND_TEST_HELPER") != "1" {
		return
	}
	i := 0
	for i < len(os.Args) && os.Args[i] != "--" {
		i++
	}
	mode := os.Args[i+1]
	switch mode {
	case "reject":
		_ = json.NewEncoder(os.Stdout).Encode(os.Args[i+2:])
		fmt.Fprint(os.Stderr, "expected rejection")
		os.Exit(23)
	case "wait":
		time.Sleep(time.Minute)
	case "signal":
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	case "overflow":
		fmt.Print(strings.Repeat("x", outputLimit+1))
	case "warning":
		fmt.Print(attributeWriteError)
		fmt.Fprint(os.Stderr, "(EINVAL) ")
	case "query":
		var outputs map[string]string
		if err := json.Unmarshal([]byte(os.Getenv("SCST_QUERY_TEST_OUTPUTS")), &outputs); err != nil {
			os.Exit(2)
		}
		for _, arg := range os.Args[i+2:] {
			if out, found := outputs[arg]; found {
				fmt.Print(out)
				os.Exit(0)
			}
		}
		os.Exit(2)
	default:
		os.Exit(2)
	}
	os.Exit(0)
}

// A failed attribute write: the CLI says "done" and exits zero, but
// issueWarning reports the operation error. State checks remain in the specs.
const attributeWriteError = `
Collecting current configuration: done.

-> Making requested changes.
    -> Setting SCST attribute 'measure_latency' to value '.': done.

WARNING: Received the following error:

    Failed to set a SCST attribute. See "dmesg" for more information.

    -> Done, 0 change(s) made.

All done.
`

func TestReportedError(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		want         bool
	}{
		{"failed attribute write", attributeWriteError, true},
		{"fatal error", "FATAL: Received the following error:\nA fatal error occurred.\n", true},
		{"indented error", "\tWARNING: Received the following error:\r\n", true},
		{"success", "-> Done, 1 change(s) made.\nAll done.\n", false},
		{"idempotent success", "-> Attribute 'measure_latency' already set to value '0', ignoring.\n-> Done, 0 change(s) made.\n", false},
		{"configuration advisory", "-> WARNING: No LUN 0 defined for driver/target/group 'local/t/g'.\n-> Done, 1 warnings found.\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := (Result{Stdout: tc.output}).ReportedError(); got != tc.want {
				t.Fatalf("ReportedError() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestWarningWithZeroExit(t *testing.T) {
	c := helperClient(t, "warning")
	r, err := c.Execute(context.Background(), "-set_scst_attr", "-attributes", "measure_latency=.")
	if err != nil || r.ExitCode != 0 || !r.ReportedError() || c.Blocked() != nil {
		t.Fatalf("lost operation rejection or treated it as execution failure: %v / %s", err, r)
	}
	if _, err := c.Query(context.Background(), "-list_scst_attr"); err == nil {
		t.Fatal("query accepted explicit error with zero exit")
	}
}

func helperClient(t *testing.T, mode string) *Client {
	t.Helper()
	t.Setenv("SCST_COMMAND_TEST_HELPER", "1")
	return &Client{Command: []string{os.Args[0], "-test.run=^TestCommandProcess$", "--", mode}, Timeout: 5 * time.Second}
}

func TestRejectionAndLiteralArguments(t *testing.T) {
	c := helperClient(t, "reject")
	var log bytes.Buffer
	c.Log = &log
	args := []string{"-device", "value with spaces; $(not-a-command)"}
	r, err := c.Execute(context.Background(), args...)
	if err != nil || r.ExitCode != 23 || c.Blocked() != nil {
		t.Fatalf("ordinary rejection treated as execution failure: %v / %s", err, r)
	}
	var actual []string
	if err := json.Unmarshal([]byte(r.Stdout), &actual); err != nil {
		t.Fatal(err)
	}
	want := append([]string{"-noprompt", "-no_lip"}, args...)
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("argv got %q, want %q", actual, want)
	}
	var recorded Result
	if err := json.Unmarshal(log.Bytes(), &recorded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(recorded.Args, r.Args) || recorded.Stderr != "expected rejection" {
		t.Fatalf("incomplete command log: %+v", recorded)
	}
	if _, err := c.Query(context.Background(), "-list_device"); err == nil {
		t.Fatal("query accepted nonzero exit")
	}
}

func TestExecutionFailuresBlockFurtherCommands(t *testing.T) {
	for _, mode := range []string{"wait", "signal", "overflow", "missing"} {
		t.Run(mode, func(t *testing.T) {
			c := helperClient(t, mode)
			if mode == "wait" {
				c.Timeout = 50 * time.Millisecond
			}
			if mode == "missing" {
				c.Command = []string{t.TempDir() + "/missing"}
			}
			_, err := c.Execute(context.Background())
			if err == nil || c.Blocked() == nil {
				t.Fatalf("%s did not block: %v", mode, err)
			}
			c.Command = []string{os.Args[0]}
			r, err := c.Execute(context.Background())
			if err == nil || len(r.Args) != 0 {
				t.Fatalf("executed another command after %s", mode)
			}
		})
	}
}

func TestHostProgramSharesJournalAndFailureLatch(t *testing.T) {
	c := helperClient(t, "reject")
	var log bytes.Buffer
	c.Log = &log
	args := append(append([]string{}, c.Command...), "path with spaces")
	r, err := c.RunProgram(context.Background(), time.Second, args...)
	if err != nil || r.ExitCode != 23 {
		t.Fatalf("host program: %v / %s", err, r)
	}
	var actual []string
	if err := json.Unmarshal([]byte(r.Stdout), &actual); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, []string{"path with spaces"}) {
		t.Fatalf("host program received CLI flags or split arguments: %q", actual)
	}
	var recorded Result
	if err := json.Unmarshal(log.Bytes(), &recorded); err != nil || !reflect.DeepEqual(recorded.Args, args) {
		t.Fatalf("host program missing from journal: %+v, %v", recorded, err)
	}
	// A failed preparation command must also prevent subsequent SCST access.
	_, err = c.RunProgram(context.Background(), time.Second, t.TempDir()+"/missing")
	if err == nil || c.Blocked() == nil {
		t.Fatalf("missing host program did not block: %v", err)
	}
	r, err = c.Execute(context.Background(), "-list_device")
	if err == nil || len(r.Args) != 0 {
		t.Fatal("SCST command executed after host preparation failure")
	}
}
