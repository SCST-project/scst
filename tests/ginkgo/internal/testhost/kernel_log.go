// SPDX-License-Identifier: GPL-2.0-only
package testhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var kernelFault = regexp.MustCompile(`(?i)WARNING:|BUG:|Oops:|Kernel panic|KASAN:|KCSAN:|UBSAN:|kernel BUG at|general protection fault|Unable to handle kernel|Call [Tt]race:|Backtrace:|(?:soft|hard) LOCKUP|blocked for more than|rcu:.*stall`)

// KernelLog captures new records only. A read/sequence error or diagnostic is
// sticky: callers must preserve the target instead of starting teardown.
type KernelLog struct {
	mu       sync.Mutex
	read     func([]byte) (int, error)
	output   io.Writer
	sequence uint64
	seen     bool
	err      error
	stop     chan struct{}
	done     chan struct{}
	close    func() error
	watches  map[*KernelWatch]struct{}
}

// KernelMessage identifies a LOG_KERN record in the raw capture. Microseconds
// is the kernel timestamp, not a wall-clock time comparable to command logs.
type KernelMessage struct {
	Sequence     uint64
	Microseconds uint64
	Text         string
}

// KernelWatch matches only new messages after Watch drained the existing log.
// Its fields are protected by the capture's mutex, including background reads.
type KernelWatch struct {
	kernel   *KernelLog
	contains string
	match    *KernelMessage
}

func (k *KernelLog) Watch(contains string) (*KernelWatch, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if contains == "" {
		return nil, fmt.Errorf("empty kernel message filter")
	}
	if err := k.check(); err != nil {
		return nil, err
	}
	w := &KernelWatch{kernel: k, contains: contains}
	if k.watches == nil {
		k.watches = make(map[*KernelWatch]struct{})
	}
	k.watches[w] = struct{}{}
	return w, nil
}

func (w *KernelWatch) Close() {
	w.kernel.mu.Lock()
	defer w.kernel.mu.Unlock()
	delete(w.kernel.watches, w)
}

// Wait checks the whole batch before accepting a match: a diagnostic or lost
// record in that batch must not authorize another test operation.
func (w *KernelWatch) Wait(ctx context.Context) (KernelMessage, error) {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return KernelMessage{}, err
		}
		w.kernel.mu.Lock()
		err := w.kernel.check()
		match := w.match
		w.kernel.mu.Unlock()
		if err != nil {
			return KernelMessage{}, err
		}
		if match != nil {
			return *match, nil
		}
		select {
		case <-ctx.Done():
			return KernelMessage{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func StartKernelLog(path string) (*KernelLog, error) {
	fd, err := syscall.Open("/dev/kmsg", syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if _, err := syscall.Seek(fd, 0, io.SeekEnd); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	log, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	k := &KernelLog{
		read: func(p []byte) (int, error) { return syscall.Read(fd, p) }, output: log,
		stop: make(chan struct{}), done: make(chan struct{}),
		close: func() error { return errors.Join(syscall.Close(fd), log.Close()) },
	}
	go func() {
		defer close(k.done)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				k.Check()
			case <-k.stop:
				k.Check()
				return
			}
		}
	}()
	return k, nil
}

// Check drains a bounded batch even after a fault, retaining subsequent trace
// records. The bound also prevents a noisy kernel from delaying test deadlines.
func (k *KernelLog) Check() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.check()
}

// check requires mu; Watch uses it to drain and arm without an intervening read.
func (k *KernelLog) check() error {
	buffer := make([]byte, 64*1024)
	for i := 0; i < 256; i++ {
		n, err := k.read(buffer)
		if errors.Is(err, syscall.EAGAIN) {
			return k.err
		}
		if err == nil && n == 0 {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			if k.err == nil {
				k.err = err
			}
			return k.err
		}
		if err := k.accept(buffer[:n]); err != nil && k.err == nil {
			k.err = err
		}
	}
	if k.err == nil {
		k.err = fmt.Errorf("kernel log backlog exceeds capture limit; evidence incomplete")
	}
	return k.err
}

func (k *KernelLog) accept(record []byte) error {
	if n, err := k.output.Write(record); err != nil {
		return err
	} else if n != len(record) {
		return io.ErrShortWrite
	}
	header, body, ok := strings.Cut(string(record), ";")
	fields := strings.Split(header, ",")
	if !ok || len(fields) < 4 {
		return fmt.Errorf("malformed /dev/kmsg record")
	}
	priority, pErr := strconv.ParseUint(fields[0], 10, 32)
	sequence, sErr := strconv.ParseUint(fields[1], 10, 64)
	microseconds, tErr := strconv.ParseUint(fields[2], 10, 64)
	if pErr != nil || sErr != nil || tErr != nil {
		return fmt.Errorf("invalid /dev/kmsg metadata")
	}
	lost := k.seen && sequence != k.sequence+1
	k.sequence, k.seen = sequence, true
	if lost {
		return fmt.Errorf("lost kernel records before sequence %d", sequence)
	}
	// Userspace records remain in the artifact but cannot supply LOG_KERN
	// diagnostics. Ignore dictionary properties following the message line.
	message, _, _ := strings.Cut(body, "\n")
	if priority>>3 == 0 {
		if kernelFault.MatchString(message) {
			return fmt.Errorf("kernel diagnostic: %s", message)
		}
		for w := range k.watches {
			if strings.Contains(message, w.contains) {
				w.match = &KernelMessage{Sequence: sequence, Microseconds: microseconds, Text: message}
				delete(k.watches, w)
			}
		}
	}
	return nil
}

func (k *KernelLog) Close() error {
	close(k.stop)
	<-k.done
	return errors.Join(k.err, k.close())
}
