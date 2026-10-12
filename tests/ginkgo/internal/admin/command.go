// SPDX-License-Identifier: GPL-2.0-only
package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Result struct {
	Args     []string      `json:"argv"`
	Started  time.Time     `json:"started"`
	Duration time.Duration `json:"duration_ns"`
	ExitCode int           `json:"exit_code"`
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	Failure  string        `json:"execution_error,omitempty"`
}

func (r Result) String() string {
	return fmt.Sprintf("%q: exit %d\nstdout:\n%s\nstderr:\n%s\nexecution error: %s",
		r.Args, r.ExitCode, r.Stdout, r.Stderr, r.Failure)
}

// ReportedError recognizes scstadmin's operation-error banners. In particular,
// issueWarning can report a failed attribute write while the process exits 0.
// Configuration advisories (such as a missing LUN 0) are not these errors.
func (r Result) ReportedError() bool {
	for _, stream := range []string{r.Stdout, r.Stderr} {
		for _, line := range strings.Split(stream, "\n") {
			switch strings.TrimSpace(line) {
			case "WARNING: Received the following error:", "FATAL: Received the following error:":
				return true
			}
		}
	}
	return false
}

// Client invokes the public CLI without a shell. Execute separates ordinary
// command results from failures to execute or supervise the process. Callers
// must check both ExitCode and ReportedError for scstadmin operations.
type Client struct {
	Command []string
	Timeout time.Duration
	Log     io.Writer
	mu      sync.Mutex
	blocked error
}

func (c *Client) Blocked() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.blocked
}

const outputLimit = 1024 * 1024

type limitedOutput struct {
	buffer    bytes.Buffer
	truncated bool
}

func (b *limitedOutput) String() string { return b.buffer.String() }

func (b *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if len(p) > outputLimit-b.buffer.Len() {
		p = p[:outputLimit-b.buffer.Len()]
		b.truncated = true
	}
	_, _ = b.buffer.Write(p)
	return n, nil
}

func (c *Client) Execute(ctx context.Context, args ...string) (Result, error) {
	if len(c.Command) == 0 {
		return Result{ExitCode: -1}, fmt.Errorf("missing scstadmin command")
	}
	argv := append(append([]string{}, c.Command...), "-noprompt", "-no_lip")
	return c.RunProgram(ctx, c.Timeout, append(argv, args...)...)
}

// RunProgram is used for host setup and teardown. It shares the command journal
// and failure latch with Execute, but does not add scstadmin arguments.
func (c *Client) RunProgram(ctx context.Context, timeout time.Duration, argv ...string) (Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := Result{ExitCode: -1, Started: time.Now().UTC()}
	if c.blocked != nil {
		return r, fmt.Errorf("further commands disabled: %w", c.blocked)
	}
	if len(argv) == 0 {
		return r, fmt.Errorf("missing program")
	}
	r.Args = append([]string{}, argv...)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.Args[0], r.Args[1:]...)
	// Terminate the command's process group on cancellation. Privilege wrappers
	// may prevent this; a timeout always blocks subsequent management operations.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	var out, stderr limitedOutput
	cmd.Stdout, cmd.Stderr = &out, &stderr
	err := cmd.Run()
	r.Duration, r.Stdout, r.Stderr = time.Since(r.Started), out.String(), stderr.String()
	if cmd.ProcessState != nil {
		r.ExitCode = cmd.ProcessState.ExitCode()
	}
	var executionError error
	var exitError *exec.ExitError
	switch {
	case ctx.Err() != nil:
		executionError = fmt.Errorf("command interrupted: %w; kernel work may still be running", ctx.Err())
		c.blocked = executionError
	case out.truncated || stderr.truncated:
		executionError = fmt.Errorf("command output exceeded %d bytes", outputLimit)
		c.blocked = executionError
	case err != nil && (!errors.As(err, &exitError) || r.ExitCode < 0):
		executionError = err
		c.blocked = executionError
	}
	if executionError != nil {
		r.Failure = executionError.Error()
	}
	if c.Log != nil {
		if err := json.NewEncoder(c.Log).Encode(r); err != nil {
			c.blocked = fmt.Errorf("cannot record command: %w", err)
			return r, errors.Join(executionError, c.blocked)
		}
	}
	return r, executionError
}

func (c *Client) Query(ctx context.Context, args ...string) (string, error) {
	r, err := c.Execute(ctx, args...)
	if err != nil {
		return "", fmt.Errorf("scstadmin query could not complete: %w\n%s", err, r.String())
	}
	if r.ExitCode != 0 || r.ReportedError() {
		return "", fmt.Errorf("scstadmin query failed: %s", r.String())
	}
	return r.Stdout, nil
}
