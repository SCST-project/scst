// SPDX-License-Identifier: GPL-2.0-only
package testhost

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestKernelLogEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows []string
		want string
	}{
		{"normal", []string{"6,41,100,-;scst session reassigned\n", "6,42,101,-;done\n"}, ""},
		{"userspace", []string{"14,1,1,-;BUG: userspace text\n"}, ""},
		{"oops", []string{"3,1,1,-;BUG: kernel NULL pointer dereference\n", "3,2,2,-;Call Trace:\n", "3,3,3,-; scst_tm_thread+0x10\n"}, "kernel diagnostic"},
		{"warning", []string{"4,1,1,-;WARNING: CPU: 0\n"}, "kernel diagnostic"},
		{"gap", []string{"6,1,1,-;a\n", "6,3,2,-;b\n"}, "lost kernel records"},
		{"malformed", []string{"bad record\n"}, "malformed"},
		{"metadata", []string{"6,x,1,-;bad\n"}, "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			rows := append([]string(nil), tc.rows...)
			k := &KernelLog{output: &output, read: func(p []byte) (int, error) {
				if len(rows) == 0 {
					return 0, syscall.EAGAIN
				}
				n := copy(p, rows[0])
				rows = rows[1:]
				return n, nil
			}}
			err := k.Check()
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("Check() = %v, wanted %q", err, tc.want)
			}
			if k.Check() != err {
				t.Fatal("failure was not retained")
			}
			if output.String() != strings.Join(tc.rows, "") {
				t.Fatal("raw evidence lost")
			}
		})
	}
}

func TestKernelLogReadFailures(t *testing.T) {
	for _, readErr := range []error{syscall.EPIPE, io.ErrUnexpectedEOF} {
		k := &KernelLog{output: io.Discard, read: func([]byte) (int, error) { return 0, readErr }}
		if !errors.Is(k.Check(), readErr) {
			t.Fatal("read failure was accepted")
		}
	}
}

func kernelWatchFixture() (*KernelLog, chan string) {
	rows := make(chan string, 16)
	k := &KernelLog{output: io.Discard, read: func(p []byte) (int, error) {
		select {
		case row := <-rows:
			return copy(p, row), nil
		default:
			return 0, syscall.EAGAIN
		}
	}}
	return k, rows
}

func TestKernelWatchFreshKernelMessage(t *testing.T) {
	k, rows := kernelWatchFixture()
	const message = "(initiator iqn.test:ours) will be reassigned from acg access to acg alternate"
	rows <- "6,1,100,-;scst: " + message + "\n"
	w, err := k.Watch(message)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	rows <- "14,2,101,-;scst: " + message + "\n"
	rows <- "6,3,102,-;scst: (initiator iqn.test:other) will be reassigned from acg access to acg alternate\n"
	rows <- "6,4,103,-;unrelated\n PROPERTY=" + message + "\n"
	rows <- "6,5,104,-;scst: " + message + "\n"
	rows <- "6,6,105,-;scst: " + message + "\n"
	// The background collector may see the message before Wait starts.
	if err := k.Check(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := w.Wait(ctx)
	if err != nil || got.Sequence != 5 || got.Microseconds != 104 || got.Text != "scst: "+message {
		t.Fatalf("Wait() = %+v, %v; want first fresh kernel message at sequence 5", got, err)
	}
}

func TestKernelWatchRejectsIncompleteEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows []string
		want string
	}{
		{"fault after match", []string{"6,1,1,-;ready\n", "4,2,2,-;WARNING: CPU: 0\n"}, "kernel diagnostic"},
		{"fault before match", []string{"3,1,1,-;BUG: kernel NULL pointer dereference\n", "6,2,2,-;ready\n"}, "kernel diagnostic"},
		{"lost records", []string{"6,1,1,-;unrelated\n", "6,3,3,-;ready\n"}, "lost kernel records"},
		{"malformed after match", []string{"6,1,1,-;ready\n", "bad record\n"}, "malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k, rows := kernelWatchFixture()
			w, err := k.Watch("ready")
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			for _, row := range tc.rows {
				rows <- row
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := w.Wait(ctx); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Wait() = %v, want %s", err, tc.want)
			}
			if _, err := k.Watch("another operation"); err == nil {
				t.Fatal("armed another watch after incomplete evidence")
			}
		})
	}
}

func TestKernelWatchDeadlineAndCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		k, rows := kernelWatchFixture()
		w, err := k.Watch("ready")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		want := context.DeadlineExceeded
		if canceled {
			rows <- "6,1,1,-;ready\n"
			cancel()
			want = context.Canceled
		}
		_, err = w.Wait(ctx)
		cancel()
		w.Close()
		if !errors.Is(err, want) {
			t.Fatalf("Wait() = %v, want %v", err, want)
		}
		if len(k.watches) != 0 {
			t.Fatal("closed watch still registered")
		}
	}
}

func TestKernelWatchConcurrentCapture(t *testing.T) {
	k, rows := kernelWatchFixture()
	w, err := k.Watch("ready")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	done := make(chan error, 1)
	go func() {
		rows <- "6,1,1,-;ready\n"
		done <- k.Check()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := w.Wait(ctx)
	captureErr := <-done
	if err != nil || captureErr != nil || got.Sequence != 1 {
		t.Fatalf("Wait() = %+v, %v; capture error = %v", got, err, captureErr)
	}
}
