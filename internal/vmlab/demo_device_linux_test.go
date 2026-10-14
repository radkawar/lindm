// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
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
