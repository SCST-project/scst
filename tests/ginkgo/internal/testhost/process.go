// SPDX-License-Identifier: GPL-2.0-only
package testhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"syscall"
)

// Process owns a foreground daemon. A failed spec deliberately leaves it alive
// if session cleanup cannot establish a safe teardown order.
type Process struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

func StartProcess(log io.Writer, argv ...string) (*Process, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("missing daemon command")
	}
	p := &Process{cmd: exec.Command(argv[0], argv[1:]...), done: make(chan struct{})}
	p.cmd.Stdout, p.cmd.Stderr = log, log
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := p.cmd.Start(); err != nil {
		return nil, err
	}
	go func() { p.err = p.cmd.Wait(); close(p.done) }()
	return p, nil
}

func (p *Process) Running() error {
	select {
	case <-p.done:
		return fmt.Errorf("target daemon exited unexpectedly: %v", p.err)
	default:
		return nil
	}
}

func (p *Process) PID() int { return p.cmd.Process.Pid }

func (p *Process) Stop(ctx context.Context) error {
	if err := p.Running(); err != nil {
		return err
	}
	if err := syscall.Kill(-p.PID(), syscall.SIGTERM); err != nil {
		return err
	}
	select {
	case <-p.done:
		var exit *exec.ExitError
		if p.err == nil || errors.As(p.err, &exit) && exit.Sys().(syscall.WaitStatus).Signal() == syscall.SIGTERM {
			return nil
		}
		return fmt.Errorf("target daemon stop: %w", p.err)
	case <-ctx.Done():
		// Do not escalate to SIGKILL or unload modules beneath a stuck daemon.
		return fmt.Errorf("target daemon did not stop: %w", ctx.Err())
	}
}
