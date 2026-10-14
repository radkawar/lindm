// SPDX-License-Identifier: Apache-2.0

package labhost

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

func TestSlotsConcurrentCapacity(t *testing.T) {
	host := fixtureHost("local", t.TempDir())
	host.MaxGuests = 3
	slots, err := openFixtureSlots(host)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ready := make(chan chan struct{}, 12)
	results := make(chan error, 12)
	var active atomic.Int32
	for range 12 {
		go func() {
			lease, err := slots.Acquire(ctx)
			if err != nil {
				results <- err
				return
			}
			if active.Add(1) > 3 {
				active.Add(-1)
				results <- errors.Join(errors.New("slot capacity exceeded"), lease.Close())
				return
			}
			release := make(chan struct{})
			ready <- release
			select {
			case <-release:
			case <-ctx.Done():
			}
			active.Add(-1)
			results <- lease.Close()
		}()
	}
	for range 4 {
		var held [3]chan struct{}
		for index := range held {
			select {
			case held[index] = <-ready:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
		if count, err := slots.Count(); err != nil || count != 3 {
			t.Fatalf("held slots: %d, %v", count, err)
		}
		for _, release := range held {
			close(release)
		}
	}
	for range 12 {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	if count, err := slots.Count(); err != nil || count != 0 {
		t.Fatalf("released slots: %d, %v", count, err)
	}
	entries, err := os.ReadDir(slots.directory)
	entries = slices.DeleteFunc(entries, func(entry os.DirEntry) bool { return entry.Name() == capacityFile })
	if err != nil || len(entries) != 4 {
		t.Fatalf("persistent lock identities: %d, %v", len(entries), err)
	}
}

func TestSlotsCancelAndWake(t *testing.T) {
	host := fixtureHost("local", t.TempDir())
	host.MaxGuests = 1
	slots, err := openFixtureSlots(host)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lease, err := slots.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	})
	deadline, stop := context.WithTimeout(ctx, 25*time.Millisecond)
	defer stop()
	if extra, err := slots.Acquire(deadline); !errors.Is(err, context.DeadlineExceeded) {
		if extra != nil {
			t.Cleanup(func() {
				if err := extra.Close(); err != nil {
					t.Error(err)
				}
			})
		}
		t.Fatalf("full slot cancellation: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		next, err := slots.Acquire(ctx)
		if err == nil {
			err = next.Close()
		}
		result <- err
	}()
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatalf("waiter after release: %v", err)
	}
	canceled, cancelNow := context.WithCancel(ctx)
	cancelNow()
	if extra, err := slots.Acquire(canceled); !errors.Is(err, context.Canceled) {
		if extra != nil {
			t.Cleanup(func() {
				if err := extra.Close(); err != nil {
					t.Error(err)
				}
			})
		}
		t.Fatalf("already-canceled admission: %v", err)
	}
	if count, err := slots.Count(); err != nil || count != 0 {
		t.Fatalf("canceled admission retained a lock: %d, %v", count, err)
	}
}

func TestSlotsCrashRelease(t *testing.T) {
	host := fixtureHost("local", t.TempDir())
	host.MaxGuests = 1
	slots, err := openFixtureSlots(host)
	if err != nil {
		t.Fatal(err)
	}
	child := startLeaseHelper(t, host.WorkDirectory, nil)
	if count, err := slots.Count(); err != nil || count != 1 {
		t.Fatalf("child lock: %d, %v", count, err)
	}
	killLeaseHelper(t, child)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lease, err := slots.Acquire(ctx)
	if err != nil {
		t.Fatalf("crashed child did not release slot: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLeaseInheritedLifetime(t *testing.T) {
	host := fixtureHost("local", t.TempDir())
	host.MaxGuests = 1
	slots, err := openFixtureSlots(host)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lease, err := slots.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	})
	child := startLeaseHelper(t, host.WorkDirectory, lease)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if count, err := slots.Count(); err != nil || count != 1 {
		t.Fatalf("parent close released live child's capacity: %d, %v", count, err)
	}
	if err := lease.Inherit(exec.Command("unused")); err == nil {
		t.Fatal("closed lease inherited")
	}
	killLeaseHelper(t, child)
	if count, err := slots.Count(); err != nil || count != 0 {
		t.Fatalf("last child close retained capacity: %d, %v", count, err)
	}
}

func TestSlotsRejectSymlink(t *testing.T) {
	host := fixtureHost("local", t.TempDir())
	host.MaxGuests = 1
	slots, err := openFixtureSlots(host)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(slots.directory, "slot-0000.lock")); err != nil {
		t.Fatal(err)
	}
	if _, err := slots.Count(); err == nil {
		t.Fatal("symlink accepted as slot identity")
	}
}

// TestLeaseHelperProcess is re-executed to exercise kernel process and exec
// semantics rather than a mock of flock or PID-based liveness.
func TestLeaseHelperProcess(t *testing.T) {
	mode := os.Getenv("LINDM_LAB_LEASE_TEST")
	if mode == "" {
		return
	}
	switch mode {
	case "acquire":
		host := fixtureHost("local", os.Getenv("LINDM_LAB_LEASE_DIRECTORY"))
		host.MaxGuests = 1
		slots, err := openFixtureSlots(host)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		lease, err := slots.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := lease.Close(); err != nil {
				t.Error(err)
			}
		}()
	case "inherit":
		file := os.NewFile(3, "inherited-lease")
		defer func() {
			if err := file.Close(); err != nil {
				t.Error(err)
			}
		}()
	default:
		t.Fatalf("unexpected helper mode %q", mode)
	}
	if _, err := fmt.Fprintln(os.Stdout, "ready"); err != nil {
		t.Fatal(err)
	}
	var input [1]byte
	if _, err := os.Stdin.Read(input[:]); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func startLeaseHelper(t *testing.T, directory string, lease *Lease) *exec.Cmd {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLeaseHelperProcess$")
	mode := "acquire"
	if lease != nil {
		mode = "inherit"
		if err := lease.Inherit(cmd); err != nil {
			t.Fatal(err)
		}
	}
	cmd.Env = append(os.Environ(), "LINDM_LAB_LEASE_TEST="+mode, "LINDM_LAB_LEASE_DIRECTORY="+directory)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stdin.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error(err)
		}
	})
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			killLeaseHelper(t, cmd)
		}
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("lease child readiness: %q, %v", line, err)
	}
	return cmd
}

func killLeaseHelper(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Error(err)
	}
	var exit *exec.ExitError
	if err := cmd.Wait(); err != nil && !errors.As(err, &exit) {
		t.Error(err)
	}
}
