//go:build linux && integration

package vmlab

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCancelledSeedCreationContainsSecretsAndStopsDescendants(t *testing.T) {
	if _, err := exec.LookPath("cloud-localds"); err != nil {
		t.Fatal("cloud-image-utils is required for the seed cancellation regression")
	}
	inheritedTemp, runDir, tools := t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("TMPDIR", inheritedTemp)
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	// Keep the real seed tool and its staging behavior. Pause only its ISO
	// builder, after it has copied private user-data, to make cancellation exact.
	shim := "#!/bin/sh\nprintf '%s' \"$$\" > helper.pid\nexec sleep 600\n"
	if err := os.WriteFile(filepath.Join(tools, "genisoimage"), []byte(shim), 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"user-data": "#cloud-config\nssh_keys:\n  ed25519_private: test-only-private-key-sentinel\n", "meta-data": "instance-id: cancellation-regression\n"} {
		if err := os.WriteFile(filepath.Join(runDir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := hostCommand(ctx, runDir, "cloud-localds", nil, "seed.img", "user-data", "meta-data")
		done <- err
	}()
	var helperPID int
	t.Cleanup(func() {
		if helperPID > 0 {
			_ = syscall.Kill(helperPID, syscall.SIGKILL)
		}
	})
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for helperPID == 0 {
		select {
		case err := <-done:
			t.Fatalf("seed tool exited before staging: %v", err)
		case <-deadline.C:
			t.Fatal("seed staging did not reach ISO builder")
		case <-ticker.C:
			data, err := os.ReadFile(filepath.Join(runDir, "helper.pid"))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(string(data))
			if err == nil && pid > 0 {
				helperPID = pid
			}
		}
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled seed creation succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("seed helper did not stop within cancellation bound")
	}
	if err := (&guestVM{dir: runDir}).close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(inheritedTemp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("cancelled seed leaked %d private staging entries outside owned cleanup", len(entries))
	}
	if _, err := os.Stat(runDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("owned seed directory survived cleanup: %v", err)
	}
	// A killed orphan may briefly remain as a zombie until its adopter reaps
	// it; a running/sleeping helper can still write after directory cleanup.
	status, err := os.ReadFile("/proc/" + strconv.Itoa(helperPID) + "/status")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err == nil && !strings.Contains(string(status), "State:\tZ") && !strings.Contains(string(status), "State:\tX") {
		t.Error("seed helper descendant remained alive after cancellation")
	}
}
