//go:build linux

package osupdate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRollingHoldSurvivesRestoredRootAndMalformedReceipt(t *testing.T) {
	dir := t.TempDir()
	state, root := filepath.Join(dir, "state-hold"), filepath.Join(dir, "root-hold")
	paths := []string{state, root}
	owner := uint32(os.Getuid())
	if err := rollingHoldFiles(paths, owner); err != nil {
		t.Fatal(err)
	}
	// A restored pre-snapshot contains the root marker even when /var was
	// excluded and its successful current receipt has already cleared state.
	if err := os.WriteFile(root, []byte("malformed or interrupted protobuf"), 0600); err != nil {
		t.Fatal(err)
	}
	var failure *nativeFailure
	if err := rollingHoldFiles(paths, owner); !errors.As(err, &failure) || failure.reason != "rolling_recovery_hold" {
		t.Fatalf("restored root did not hold automatic replay: %v", err)
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := rollingHoldFiles(paths, owner); !errors.As(err, &failure) {
		t.Fatalf("empty retained state marker was discarded: %v", err)
	}
}

func TestRollingHoldRefusesReplaceableMarkers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hold")
	if err := os.Symlink(filepath.Join(dir, "missing"), path); err != nil {
		t.Fatal(err)
	}
	if err := rollingHoldFiles([]string{path}, uint32(os.Getuid())); err == nil {
		t.Fatal("symlinked marker bypassed recovery hold")
	}
}

func TestSnapshotReplayGuardRequiresActualSavedBytes(t *testing.T) {
	dir := t.TempDir()
	current, saved := filepath.Join(dir, "current"), filepath.Join(dir, "snapshot")
	owner := uint32(os.Getuid())
	content := []byte("durable transaction replay guard")
	if err := os.WriteFile(current, content, 0600); err != nil {
		t.Fatal(err)
	}
	// A nested Btrfs subvolume omitted by a nonrecursive snapshot leaves no
	// saved marker. This tests the required postcondition, not Btrfs itself.
	if err := verifySnapshotReplayMarker(current, saved, owner); err == nil {
		t.Fatal("missing saved marker accepted from mount identity alone")
	}
	if err := os.WriteFile(saved, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifySnapshotReplayMarker(current, saved, owner); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(saved, []byte("older transaction"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifySnapshotReplayMarker(current, saved, owner); err == nil {
		t.Fatal("snapshot containing another transaction's guard accepted")
	}
	if err := os.Remove(saved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(current, saved); err != nil {
		t.Fatal(err)
	}
	if err := verifySnapshotReplayMarker(current, saved, owner); err == nil {
		t.Fatal("live guard symlink accepted as saved snapshot evidence")
	}
	ancestor := filepath.Join(dir, "redirect")
	if err := os.Symlink(dir, ancestor); err != nil {
		t.Fatal(err)
	}
	if err := verifySnapshotReplayMarker(current, filepath.Join(ancestor, "current"), owner); err == nil {
		t.Fatal("snapshot ancestor symlink accepted as retained replay guard")
	}
}
