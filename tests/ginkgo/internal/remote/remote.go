// SPDX-License-Identifier: GPL-2.0-only
package remote

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"scst-component-tests/internal/admin"
	"scst-component-tests/internal/testcfg"
)

//go:embed worker.py
var worker string

type response struct {
	ExitCode *int   `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Failure  string `json:"execution_error"`
	UID      int    `json:"uid"`
	BootID   string `json:"boot_id"`
}

type message struct {
	payload response
	err     error
}

// Session retains one SSH connection and one remote lock for the entire suite.
// Commands travel as JSON argv arrays, not interpolated remote shell commands.
// A lost response is never retried: its remote effects may already have occurred.
type Session struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	input    io.WriteCloser
	messages chan message
	done     chan struct{}
	waitErr  error
	log      io.Writer
	blocked  error
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func Connect(ctx context.Context, cfg testcfg.Initiator, log, stderr io.Writer) (*Session, error) {
	args := []string{"-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
		"-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
		"-p", strconv.Itoa(cfg.Port), "-l", cfg.User}
	if cfg.IdentityFile != "" {
		args = append(args, "-o", "IdentitiesOnly=yes", "-i", cfg.IdentityFile)
	}
	args = append(args, "--", cfg.Host, "exec python3 -u -c "+quote(worker)+" "+quote(cfg.LockFile))
	s, hello, err := start(ctx, exec.Command("ssh", args...), log, stderr)
	if err != nil {
		return nil, err
	}
	localID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err == nil && (hello.UID != 0 || hello.BootID == "" || hello.BootID == strings.TrimSpace(string(localID))) {
		err = fmt.Errorf("initiator must be root on a different Linux host")
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func start(ctx context.Context, cmd *exec.Cmd, log, stderr io.Writer) (*Session, response, error) {
	s := &Session{cmd: cmd, log: log, messages: make(chan message, 1), done: make(chan struct{})}
	var err error
	s.input, err = cmd.StdinPipe()
	if err != nil {
		return nil, response{}, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		s.input.Close()
		return nil, response{}, err
	}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		s.input.Close()
		out.Close()
		return nil, response{}, err
	}
	go func() {
		defer close(s.messages)
		scanner := bufio.NewScanner(out)
		scanner.Buffer(make([]byte, 4096), 16*1024*1024)
		for scanner.Scan() {
			var r response
			err := json.Unmarshal(scanner.Bytes(), &r)
			s.messages <- message{r, err}
			if err != nil {
				break
			}
		}
		if err := scanner.Err(); err != nil {
			s.messages <- message{err: err}
		}
		s.waitErr = cmd.Wait()
		close(s.done)
	}()
	r, err := s.receive(ctx)
	if err == nil && r.Failure != "" {
		err = errors.New(r.Failure)
	}
	if err != nil {
		s.Close()
		return nil, r, fmt.Errorf("SSH initiator setup: %w", err)
	}
	return s, r, nil
}

func (s *Session) receive(ctx context.Context) (response, error) {
	select {
	case m, ok := <-s.messages:
		if !ok {
			return response{}, fmt.Errorf("SSH connection ended; inspect ssh.log and remote state")
		}
		return m.payload, m.err
	case <-ctx.Done():
		return response{}, ctx.Err()
	}
}

func (s *Session) Blocked() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blocked
}

func (s *Session) Run(ctx context.Context, timeout time.Duration, argv ...string) (admin.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := admin.Result{Args: argv, Started: time.Now().UTC(), ExitCode: -1}
	if s.blocked != nil {
		return r, fmt.Errorf("remote commands disabled: %w", s.blocked)
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < timeout {
		timeout = time.Until(deadline)
	}
	request := struct {
		Args    []string `json:"argv"`
		Timeout float64  `json:"timeout"`
	}{argv, timeout.Seconds()}
	err := ctx.Err()
	if err == nil {
		err = json.NewEncoder(s.input).Encode(request)
	}
	if err == nil {
		// The worker gets the first opportunity to kill and reap a timed-out command.
		waitCtx, cancel := context.WithTimeout(ctx, timeout+3*time.Second)
		var reply response
		reply, err = s.receive(waitCtx)
		cancel()
		r.Stdout, r.Stderr = reply.Stdout, reply.Stderr
		if reply.ExitCode != nil {
			r.ExitCode = *reply.ExitCode
		} else if err == nil {
			err = fmt.Errorf("remote response lacks exit_code")
		}
		if err == nil && reply.Failure != "" {
			err = errors.New(reply.Failure)
		}
	}
	r.Duration = time.Since(r.Started)
	if err != nil {
		r.Failure = err.Error()
		s.blocked = err
	}
	if s.log != nil {
		if logErr := json.NewEncoder(s.log).Encode(r); logErr != nil {
			s.blocked = errors.Join(err, logErr)
			err = s.blocked
		}
	}
	return r, err
}

// Close releases the connection, never performs implicit iSCSI cleanup.
func (s *Session) Close() error {
	s.input.Close()
	select {
	case <-s.done:
		return s.waitErr
	case <-time.After(2 * time.Second):
		s.cmd.Process.Kill()
		return fmt.Errorf("SSH worker did not exit; remote state may require inspection")
	}
}
