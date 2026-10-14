// SPDX-License-Identifier: Apache-2.0

package filelock

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLockFileReportsEachHolderChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	unlock, err := LockFile(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	reports := make(chan string, 8)
	acquired := make(chan error, 1)
	go func() {
		release, err := LockFile(context.Background(), path, func(holder string) { reports <- holder })
		if err == nil {
			err = release()
		}
		acquired <- err
	}()
	if first := <-reports; !strings.HasPrefix(first, "pid ") {
		t.Fatalf("first holder report %q", first)
	}
	if err := os.WriteFile(path, []byte("pid 1 test: [3/9] ok pkg\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if progress := <-reports; progress != "pid 1 test: [3/9] ok pkg" {
		t.Fatalf("progress report %q", progress)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	if err := <-acquired; err != nil {
		t.Fatal(err)
	}
}

func TestLockFileCrossProcessAndExitRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLockFileProcessHelper$")
	child.Env = append(os.Environ(), "LINDM_FILELOCK_TEST_PATH="+path)
	child.Stderr = os.Stderr
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = input.Close() }()
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	scanner := bufio.NewScanner(output)
	if !scanner.Scan() || scanner.Text() != "locked" {
		t.Fatalf("child lock startup: %q, %v", scanner.Text(), scanner.Err())
	}
	if release, ok, err := TryLockFile(path); err != nil || ok || release != nil {
		t.Fatalf("admitted while child holds lock: ok=%v err=%v", ok, err)
	}
	short, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	defer stop()
	if _, err := LockFile(short, path, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter did not respect cancellation: %v", err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err == nil {
		t.Fatal("killed child exited successfully")
	}
	release, ok, err := TryLockFile(path)
	if err != nil || !ok {
		t.Fatalf("process exit did not release lock: ok=%v err=%v", ok, err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

func TestLockFileProcessHelper(t *testing.T) {
	path := os.Getenv("LINDM_FILELOCK_TEST_PATH")
	if path == "" {
		return
	}
	// Deliberately leave cleanup to process exit, as a crashed holder would.
	if _, err := LockFile(t.Context(), path, nil); err != nil {
		t.Fatal(err)
	}
	fmt.Println("locked")
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal(err)
	}
}
