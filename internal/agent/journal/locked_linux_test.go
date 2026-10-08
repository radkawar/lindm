package journal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

func TestJournalLockedDirectoryLifecycle(t *testing.T) {
	directory := protectedDirectory(t)
	locked := lockDirectoryForTest(t, directory)
	if _, err := OpenLocked(t.Context(), directory, locked); !errors.Is(err, ErrUnprovisioned) {
		t.Fatalf("fresh locked directory: %v", err)
	}
	assertDirectoryLockHeld(t, directory)
	initial := pendingState(t)
	store, err := InitializeLocked(t.Context(), directory, locked, initial)
	if err != nil {
		t.Fatalf("initialize under retained lock: %v", err)
	}
	defer func() {
		if store != nil {
			_ = store.Close()
		}
	}()
	flags, err := unix.FcntlInt(store.dir.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("journal lock duplicate can escape exec: flags=%d err=%v", flags, err)
	}
	assertDirectoryLockHeld(t, directory)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	assertDirectoryLockHeld(t, directory)
	store, err = OpenLocked(t.Context(), directory, locked)
	if err != nil {
		t.Fatalf("reopen under original lock: %v", err)
	}
	state, _, err := store.Load(t.Context())
	if err != nil || !proto.Equal(state, initial) {
		t.Fatalf("locked reopen changed authority: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	assertDirectoryLockHeld(t, directory)
	if err := locked.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(t.Context(), directory)
	if err != nil {
		t.Fatalf("final lock owner did not release directory: %v", err)
	}
}

func TestJournalLockedDirectoryRejectsUnsafeBinding(t *testing.T) {
	for _, failure := range []string{"different directory", "unsafe mode", "replaceable ancestor", "missing lock"} {
		t.Run(failure, func(t *testing.T) {
			parent := protectedDirectory(t)
			directory := filepath.Join(parent, "state")
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			locked := lockDirectoryForTest(t, directory)
			supplied := locked
			path := directory
			switch failure {
			case "different directory":
				path = protectedDirectory(t)
			case "unsafe mode":
				if err := os.Chmod(directory, 0750); err != nil {
					t.Fatal(err)
				}
			case "replaceable ancestor":
				if err := os.Chmod(parent, 0777); err != nil {
					t.Fatal(err)
				}
			case "missing lock":
				supplied = nil
			}
			if store, err := OpenLocked(t.Context(), path, supplied); !errors.Is(err, ErrRecoveryHold) {
				if store != nil {
					_ = store.Close()
				}
				t.Fatalf("unsafe locked open was not rejected: %v", err)
			}
			if store, err := InitializeLocked(t.Context(), path, supplied, pendingState(t)); !errors.Is(err, ErrRecoveryHold) {
				if store != nil {
					_ = store.Close()
				}
				t.Fatalf("unsafe locked initialization was not rejected: %v", err)
			}
			for _, candidate := range []string{path, directory} {
				if _, err := os.Lstat(filepath.Join(candidate, markerName)); !os.IsNotExist(err) {
					t.Fatalf("failed boundary check wrote provisioning authority: %v", err)
				}
			}
			assertDirectoryLockHeld(t, directory)
		})
	}
}

func TestJournalLockedCancellationPreservesOwner(t *testing.T) {
	directory := protectedDirectory(t)
	locked := lockDirectoryForTest(t, directory)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := OpenLocked(ctx, directory, locked); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled open classified as damage: %v", err)
	}
	if _, err := InitializeLocked(ctx, directory, locked, pendingState(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled initialization classified as damage: %v", err)
	}
	assertDirectoryLockHeld(t, directory)
	if _, err := os.Lstat(filepath.Join(directory, markerName)); !os.IsNotExist(err) {
		t.Fatalf("canceled initialization wrote authority: %v", err)
	}
}

func lockDirectoryForTest(t *testing.T, directory string) *os.File {
	t.Helper()
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "external-journal-owner")
	t.Cleanup(func() { _ = file.Close() })
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	return file
}

func assertDirectoryLockHeld(t *testing.T, directory string) {
	t.Helper()
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("independent descriptor acquired the live directory lock: %v", err)
	}
}
