//go:build linux

package vmlab

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This tests command ordering and failure propagation over SSH, not a native
// package installation. The real demo smoke must exercise the customer /repo
// installer and provisioning path in clean encrypted guests.
func TestDemoProbeDirectoryPrecedesUploadAndReadiness(t *testing.T) {
	var calls atomic.Int32
	guest, _ := updateSSHFixture(t, false, func(call int) (string, uint32, bool) {
		calls.Store(int32(call))
		if call == 1 {
			return "", 0, false
		}
		return "directory setup refused", 73, false
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// A nonexistent observer binary distinguishes directory preparation from an
	// attempted upload. No package transaction or lab probe is actually executed.
	err := installDemoAgent(ctx, &EncryptedVM{guest: guest}, &DemoDeviceInput{}, filepath.Join(t.TempDir(), "missing-lab-binary"))
	if err == nil || !strings.Contains(err.Error(), "guest operation exited with status 73") {
		t.Fatalf("directory setup did not precede probe upload/readiness: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("commands after directory failure: got %d, want installer then directory setup", got)
	}
}

// Ubuntu 24.04 has no /etc/motd.d: the owner's opt-in creates an absent
// approved root (and its parents) but never changes an existing directory.
func TestDemoFileRootsScriptCreatesOnlyAbsentRoots(t *testing.T) {
	base := t.TempDir()
	existing, absent := filepath.Join(base, "existing"), filepath.Join(base, "etc", "motd.d")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		command := exec.CommandContext(t.Context(), "sh", "-eu", "-c", demoFileRootsScript, "sh", existing, absent)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("roots script: %v: %s", err, output)
		}
	}
	for path, want := range map[string]os.FileMode{existing: 0o700, absent: 0o755, filepath.Dir(absent): 0o755} {
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != want {
			t.Fatalf("%s: %v %v, want directory %v", path, info, err, want)
		}
	}
}
