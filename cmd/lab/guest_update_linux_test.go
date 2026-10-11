//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestGuestUpdateUnpackDistinguishesRenameFromObservationFailure(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "lindm-agent")
	partial := binary + ";1234"
	if err := os.WriteFile(partial, []byte("native partial bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if size, err := partialNativeFile(partial); err != nil || size != 20 {
		t.Fatalf("actual partial file not observed: size=%d err=%v", size, err)
	}
	if err := os.Rename(partial, binary); err != nil {
		t.Fatal(err)
	}
	if size, err := partialNativeFile(partial); err != nil || size != 0 {
		t.Fatalf("atomic native rename became an error/witness: size=%d err=%v", size, err)
	}
	if _, err := partialNativeFile(filepath.Join(binary, "not-a-directory")); err == nil {
		t.Fatal("non-disappearance stat failure was suppressed")
	}
	if err := os.Symlink(binary, partial); err != nil {
		t.Fatal(err)
	}
	if _, err := partialNativeFile(partial); err == nil {
		t.Fatal("symlink accepted as native partial-file evidence")
	}
}

func TestGuestUpdateUnpackCannotWitnessWithoutOwnedCgroup(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "lindm-agent")
	if err := os.WriteFile(binary+".dpkg-new", []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	witness, err := freezeNativeUnpack(context.Background(), filepath.Join(root, "absent-cgroup"), binary, nil)
	if err == nil || witness != "" {
		t.Fatalf("unowned partial file became frozen native evidence: %q %v", witness, err)
	}
}

// libalpm writes the final path in place after unlinking it: only a replaced
// inode is a pacman unpack candidate, never the untouched installed binary.
func TestGuestUpdateUnpackPacmanInPlaceCandidate(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "lindm-agent")
	if err := os.WriteFile(binary, []byte("installed agent"), 0700); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	var original unix.Stat_t
	if err := unix.Fstat(int(held.Fd()), &original); err != nil {
		t.Fatal(err)
	}
	if files, err := nativeUnpackFiles(binary, &original); err != nil || slices.Contains(files, binary) {
		t.Fatalf("unchanged installed binary became an unpack candidate: %v %v", files, err)
	}
	if err := os.Remove(binary); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("partial"), 0700); err != nil {
		t.Fatal(err)
	}
	if files, err := nativeUnpackFiles(binary, &original); err != nil || !slices.Contains(files, binary) {
		t.Fatalf("replaced inode is not a pacman candidate: %v %v", files, err)
	}
	if witness, err := freezeNativeUnpack(context.Background(), filepath.Join(t.TempDir(), "absent-cgroup"), binary, &original); err == nil || witness != "" {
		t.Fatalf("unowned in-place write became frozen native evidence: %q %v", witness, err)
	}
}

func TestGuestUpdateUnpackStopsOnTerminalProductState(t *testing.T) {
	for _, phase := range []string{"recovery_required", "rejected", "installed"} {
		status := &agentv1.AgentUpdateStatus{Phase: phase, Reason: "native_transaction_incomplete"}
		err := guestUpdateUnpackTerminal(status)
		if err == nil || !strings.Contains(err.Error(), phase) || !strings.Contains(err.Error(), status.GetReason()) {
			t.Fatalf("terminal %s hidden behind unpack deadline: %v", phase, err)
		}
	}
	for _, phase := range []string{"idle", "checking", "staged", "applying", "installing"} {
		if err := guestUpdateUnpackTerminal(&agentv1.AgentUpdateStatus{Phase: phase}); err != nil {
			t.Fatalf("pending %s treated as terminal: %v", phase, err)
		}
	}
}

func TestGuestUpdateUnpackResolvesActualUnitCgroup(t *testing.T) {
	unit := "lindm-agent-update-550b704e-e362-45c7-b55e-8bd588deee86.service"
	for _, group := range []string{"/lindm.slice/lindm-updates.slice/" + unit, "/custom.slice/" + unit} {
		got, err := parseNativeUpdateCgroup(unit, []byte("LoadState=loaded\nControlGroup="+group+"\n"))
		if err != nil || got != "/sys/fs/cgroup"+group {
			t.Fatalf("actual systemd binding lost: %q %v", got, err)
		}
	}
	for _, group := range []string{"relative/" + unit, "/x/../" + unit, "/other.service"} {
		if _, err := parseNativeUpdateCgroup(unit, []byte("ControlGroup="+group+"\n")); err == nil {
			t.Fatalf("unbound cgroup accepted: %q", group)
		}
	}
	if got, err := parseNativeUpdateCgroup(unit, []byte("LoadState=not-found\nControlGroup=\n")); err != nil || got != "" {
		t.Fatalf("unit launch race treated as failure: %q %v", got, err)
	}
}
