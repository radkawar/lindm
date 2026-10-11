//go:build linux

package osupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

// The shipped layout on Ubuntu, Fedora and RHEL: /etc/os-release is a
// symlink to the regular /usr/lib/os-release.
func TestDetectReadsUsrLibOSReleaseBeforeTheEtcSymlink(t *testing.T) {
	root := t.TempDir()
	usrLib := filepath.Join(root, "usr", "lib", "os-release")
	etc := filepath.Join(root, "etc", "os-release")
	for _, dir := range []string{filepath.Dir(usrLib), filepath.Dir(etc)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(usrLib, []byte("NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../usr/lib/os-release", etc); err != nil {
		t.Fatal(err)
	}
	owner := uint32(os.Getuid())
	native, err := detect([]string{usrLib, etc}, owner)
	if err != nil || native.kind() != resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES {
		t.Fatalf("detect = %v, %v", native, err)
	}
	// The symlink itself is never followed.
	if _, err := detect([]string{etc}, owner); err == nil {
		t.Fatal("detect followed the /etc/os-release symlink")
	}
	// /etc/os-release is the fallback only when /usr/lib/os-release is absent.
	if err := os.Remove(etc); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(usrLib, etc); err != nil {
		t.Fatal(err)
	}
	if native, err := detect([]string{usrLib, etc}, owner); err != nil || native.kind() != resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES {
		t.Fatalf("fallback detect = %v, %v", native, err)
	}
	if _, err := detect([]string{usrLib}, owner); err == nil {
		t.Fatal("missing os-release detected a platform")
	}
}

// A mutating native step at its deadline gets SIGTERM, never SIGKILL: the
// shell's TERM trap runs and its exit status is reported. Queries are
// group-killed instead.
func TestRunCommandTerminatesMutatingStepsWithSIGTERMOnly(t *testing.T) {
	started := time.Now()
	trap := `trap 'echo terminated; exit 7' TERM; while :; do sleep 0.05; done`
	result, err := runCommand(context.Background(), step{timeout: 300 * time.Millisecond, mutating: true}, "/usr/bin/sh", "-c", trap)
	if !errors.Is(err, context.DeadlineExceeded) || result.exitCode != 7 {
		t.Fatalf("runCommand = exit %d, %v", result.exitCode, err)
	}
	if got := result.stdoutTail.buf.String(); got != "terminated\n" {
		t.Fatalf("trap output = %q", got)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("termination took %v", elapsed)
	}
	result, err = runCommand(context.Background(), step{timeout: 300 * time.Millisecond}, "/usr/bin/sh", "-c", trap)
	if !errors.Is(err, context.DeadlineExceeded) || result.exitCode == 7 {
		t.Fatalf("query was not killed: exit %d, %v", result.exitCode, err)
	}
	if _, err := runCommand(context.Background(), step{timeout: time.Minute, stdoutLimit: 4}, "/usr/bin/sh", "-c", "echo 0123456789"); !errors.Is(err, errNativeOutput) {
		t.Fatalf("overflowing listing = %v", err)
	}
	// Verbose output of an unparsed successful step is not a failure.
	if _, err := runCommand(context.Background(), step{timeout: time.Minute}, "/usr/bin/sh", "-c", "head -c 100000 /dev/zero; head -c 100000 /dev/zero >&2"); err != nil {
		t.Fatalf("verbose successful step failed: %v", err)
	}
}

// Every bound of a full run fits the overall run budget, which leaves the
// unit's TimeoutStartSec a grace period after SIGTERM.
func TestRunStepBoundsFitTheUnitTimeout(t *testing.T) {
	worst := runLockWait + refreshTimeout +
		2*listTimeout + // pending (two repoqueries on DNF)
		2*snapshotTimeout + installTimeout + restartTimeout + oracleTimeout +
		2*listTimeout + oracleTimeout + // post-run status listing and oracle
		logindTimeout + notifyBudget + logindTimeout // schedule, notify, pending reboot
	if worst >= runBudget || runBudget+runTermGrace > unitRunTimeout || unitRunTimeout != 6*time.Hour {
		t.Fatalf("worst case %v, budget %v, unit %v", worst, runBudget, unitRunTimeout)
	}
	rollingWorst := runLockWait + refreshTimeout + listTimeout +
		3*snapshotTimeout + oracleTimeout + installTimeout +
		3*oracleTimeout + logindTimeout + notifyBudget // reboot and two native hold queries
	if rollingWorst >= runBudget {
		t.Fatalf("rolling transaction and snapper budget %v exceeds %v", rollingWorst, runBudget)
	}
	const unitStatusTimeout = 5 * time.Minute
	if statusBudget >= unitStatusTimeout || statusLockWait >= statusBudget {
		t.Fatalf("status budget %v exceeds unit timeout", statusBudget)
	}
}

func TestAcquireLockRefusesSharedDirectories(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns every directory created here")
	}
	// A directory not owned by root (such as anything a user can create) is
	// refused before any lock file is created in it.
	dir := t.TempDir()
	if _, err := acquireLock(context.Background(), filepath.Join(dir, "run.lock"), time.Second); !errors.Is(err, errFileUnsafe) {
		t.Fatalf("acquireLock in a user directory = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "run.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock file created in an untrusted directory: %v", err)
	}
}
