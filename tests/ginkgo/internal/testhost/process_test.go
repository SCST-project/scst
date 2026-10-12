// SPDX-License-Identifier: GPL-2.0-only
package testhost

import (
	"context"
	"io"
	"testing"
	"time"
)

func TestForegroundProcess(t *testing.T) {
	p, err := StartProcess(io.Discard, "sleep", "30")
	if err != nil {
		t.Fatal(err)
	}
	defer p.cmd.Process.Kill()
	if err := p.Running(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if p.Running() == nil {
		t.Fatal("stopped daemon appears running")
	}
}

func TestEarlyDaemonExit(t *testing.T) {
	p, err := StartProcess(io.Discard, "false")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.done:
	case <-time.After(time.Second):
		t.Fatal("child did not exit")
	}
	if p.Running() == nil || p.Stop(context.Background()) == nil {
		t.Fatal("early exit accepted as normal teardown")
	}
}
