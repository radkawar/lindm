//go:build linux

package packageprovider

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// A child holds the POSIX write lock the way dpkg's frontend protocol (and
// ubuntu-release-upgrader through python-apt) does; POSIX locks are per process.
func TestMain(m *testing.M) {
	if path := os.Getenv("LINDM_DPKG_LOCK_HOLDER"); path != "" {
		os.Exit(holdDPKGLock(path))
	}
	os.Exit(m.Run())
}

func holdDPKGLock(path string) int {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return 2
	}
	if err := unix.FcntlFlock(uintptr(fd), unix.F_SETLK, &unix.Flock_t{Type: unix.F_WRLCK}); err != nil {
		return 3
	}
	fmt.Println("locked")
	// Hold until the parent closes stdin.
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	return 0
}

func TestDPKGFrontendHeldReportsAnotherFrontendAndClassifiesBusy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock-frontend")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if held, err := dpkgFrontendHeld(path); err != nil || held {
		t.Fatalf("free lock reported held=%t: %v", held, err)
	}
	if held, err := dpkgFrontendHeld(filepath.Join(t.TempDir(), "absent")); err != nil || held {
		t.Fatalf("absent dpkg database reported held=%t: %v", held, err)
	}
	child := exec.Command(os.Args[0], "-test.run=^$")
	child.Env = append(os.Environ(), "LINDM_DPKG_LOCK_HOLDER="+path)
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "locked\n" {
		_ = child.Process.Kill()
		t.Fatalf("lock holder did not start: %q %v", line, err)
	}
	held, err := dpkgFrontendHeld(path)
	if err != nil || !held {
		t.Errorf("another frontend's lock reported held=%t: %v", held, err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	if held, err := dpkgFrontendHeld(path); err != nil || held {
		t.Fatalf("released lock reported held=%t: %v", held, err)
	}
	if !errors.Is(classifyDPKGBusy(ErrBusy), ErrBusy) || classifyDPKGBusy(nil) != nil {
		t.Fatal("busy classification changed nil or an existing busy error")
	}
}

// Pop!_OS's pop-upgrade and PackageKit can take dpkg's frontend lock between
// staging and apply (observed natively: resources-executor exact-v2-upgrade).
// A busy database before the final authority gate changed nothing and stays
// ErrBusy for the server to retry; after the gate the outcome is unknown.
func TestApplyBusyBeforeAuthorityGateStaysBusy(t *testing.T) {
	busy := fmt.Errorf("%w: package_apply_native_busy", ErrBusy)
	if err := nativeTransactionError(busy, false); !errors.Is(err, ErrBusy) || errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("busy before the gate = %v", err)
	}
	if err := nativeTransactionError(busy, true); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("busy after the gate = %v", err)
	}
	if err := nativeTransactionError(errors.New("native package helper did not complete: x"), false); !errors.Is(err, ErrOutcomeUnknown) || errors.Is(err, ErrBusy) {
		t.Fatalf("other failure = %v", err)
	}
}
