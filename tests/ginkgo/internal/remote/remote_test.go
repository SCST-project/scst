// SPDX-License-Identifier: GPL-2.0-only
package remote

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func localWorker(t *testing.T, lock string) *Session {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is needed to exercise the SSH worker protocol locally")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, _, err := start(ctx, exec.Command(python, "-u", "-c", worker, lock), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestWorkerArgvAndOrdinaryFailure(t *testing.T) {
	s := localWorker(t, filepath.Join(t.TempDir(), "host.lock"))
	var log bytes.Buffer
	s.log = &log
	input := "a 'quote'\n$(do-not-execute); `literal`"
	r, err := s.Run(context.Background(), time.Second, "python3", "-c", "import sys; print(sys.argv[1]); sys.exit(24)", input)
	if err != nil || r.ExitCode != 24 || r.Stdout != input+"\n" || s.Blocked() != nil {
		t.Fatalf("ordinary result lost: %+v %v", r, err)
	}
	r, err = s.Run(context.Background(), time.Second, "true")
	if err != nil || r.ExitCode != 0 || strings.Count(log.String(), "\n") != 2 {
		t.Fatalf("follow-up/log: %+v %v", r, err)
	}
}

func TestWorkerLockAndSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host.lock")
	s := localWorker(t, path)
	for _, lock := range []string{path, filepath.Join(dir, "link")} {
		if lock != path {
			if err := os.Symlink(path, lock); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		other, _, err := start(ctx, exec.Command("python3", "-u", "-c", worker, lock), io.Discard, io.Discard)
		cancel()
		if err == nil {
			other.Close()
			t.Fatal("accepted locked/symlink lock file")
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// The lock inode remains, but the lock itself is released on connection close.
	localWorker(t, path)
}

func TestWorkerUncertainResultsBlockFurtherCommands(t *testing.T) {
	for name, argv := range map[string][]string{
		"timeout":         {"python3", "-c", "import time; time.sleep(5)"},
		"signal":          {"python3", "-c", "import os,signal; os.kill(os.getpid(),signal.SIGKILL)"},
		"output limit":    {"python3", "-c", "print('x' * (2 * 1024 * 1024))"},
		"missing program": {"/no/such/scst-test-program"},
	} {
		t.Run(name, func(t *testing.T) {
			s := localWorker(t, filepath.Join(t.TempDir(), "host.lock"))
			_, err := s.Run(context.Background(), 100*time.Millisecond, argv...)
			if err == nil || s.Blocked() == nil {
				t.Fatal("uncertain result accepted")
			}
			marker := filepath.Join(t.TempDir(), "must-not-exist")
			if _, err := s.Run(context.Background(), time.Second, "touch", marker); err == nil {
				t.Fatal("follow-up allowed")
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("follow-up executed")
			}
		})
	}
}

func TestLostConnectionAndBadReply(t *testing.T) {
	for name, code := range map[string]string{
		"EOF":       "import json; print(json.dumps({'uid':0,'boot_id':'test'}),flush=True)",
		"bad reply": "import json,sys; print(json.dumps({'uid':0,'boot_id':'test'}),flush=True); sys.stdin.readline(); print('{}',flush=True)",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := exec.LookPath("python3"); err != nil {
				t.Skip("python3 unavailable")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			s, _, err := start(ctx, exec.Command("python3", "-u", "-c", code), io.Discard, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if _, err := s.Run(ctx, time.Second, "true"); err == nil || s.Blocked() == nil {
				t.Fatal("lost/malformed response accepted")
			}
		})
	}
}

func TestSSHCommandQuoting(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	lock := filepath.Join(t.TempDir(), "lock ' with $ and ` and\nnewline")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, _, err := start(ctx, exec.Command("sh", "-c", "exec python3 -u -c "+quote(worker)+" "+quote(lock)), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := os.Stat(lock); err != nil {
		t.Fatal("remote shell quoting changed the lock path:", err)
	}
	r, err := s.Run(ctx, time.Second, "true")
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("worker command: %+v %v", r, err)
	}
}
