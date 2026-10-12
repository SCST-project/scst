// SPDX-License-Identifier: GPL-2.0-only
package dataio

import (
	"bytes"
	"context"
	"os/exec"
	"testing"
	"time"

	"scst-component-tests/internal/admin"
)

func TestBinaryCommandPreservesOutputAndExit(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	run := func(ctx context.Context, _ time.Duration, argv ...string) (admin.Result, error) {
		out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).Output()
		return admin.Result{Stdout: string(out)}, err
	}
	payload := []byte{0, 0xff, 0x80, '\n'}
	r, err := command(context.Background(), run, time.Second, payload, "python3", "-c",
		"import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); sys.stderr.write('sense'); sys.exit(7)")
	if err != nil || r.ExitCode != 7 || r.Stderr != "sense" || !bytes.Equal(r.Data, payload) {
		t.Fatalf("binary response: %+v %v", r, err)
	}
	for _, output := range []string{"null", "{}", `{"exit_code":0,"stderr":""}`} {
		fake := func(context.Context, time.Duration, ...string) (admin.Result, error) {
			return admin.Result{Stdout: output}, nil
		}
		if _, err := command(context.Background(), fake, time.Second, nil, "unused"); err == nil {
			t.Fatal("accepted missing reply")
		}
	}
}

func TestChildInterruptionBlocksFurtherCommands(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	for name, script := range map[string]string{
		"signal":  "import os,signal; os.kill(os.getpid(), signal.SIGTERM)",
		"timeout": "import time; time.sleep(5)",
	} {
		t.Run(name, func(t *testing.T) {
			client := &admin.Client{}
			_, err := command(context.Background(), client.RunProgram, 500*time.Millisecond, nil, "python3", "-c", script)
			if err == nil || client.Blocked() == nil {
				t.Fatalf("lost supervision failure: %v, latch %v", err, client.Blocked())
			}
		})
	}
}
