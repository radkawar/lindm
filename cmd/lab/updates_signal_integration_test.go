//go:build linux && integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"lindm/internal/vmlab"
)

// Exercise the real update staging/signing path, not a simulated update. Stop
// before package compilation/guest admission: no QEMU slot or fixture is used.
func TestVMUpdatesSignalsCleanOwnedStaging(t *testing.T) {
	for _, name := range []string{"gpg", "gpgconf", "gpg-connect-agent"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatalf("native cancellation regression requires %s: %v", name, err)
		}
	}
	manifest, err := filepath.Abs("../../lab/images/ubuntu-noble-amd64.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			// GnuPG sockets require short paths, unlike testing's nested TempDir.
			parent, err := os.MkdirTemp("", "update-signal-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(parent) })
			source, work := filepath.Join(parent, "source"), filepath.Join(parent, "work")
			for _, dir := range []string{work, source, filepath.Join(source, "cmd"), filepath.Join(source, "internal"), filepath.Join(source, "db"), filepath.Join(source, "gen"), filepath.Join(source, "web")} {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			for name, contents := range map[string]string{"go.mod": "module lindm\n", "go.sum": ""} {
				if err := os.WriteFile(filepath.Join(source, name), []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			record := filepath.Join(parent, "cancelled.json")
			child := exec.Command(os.Args[0], "-test.run=^TestVMUpdatesSignalChild$", "-test.count=1")
			child.Env = append(os.Environ(), "LINDM_UPDATE_SIGNAL_CHILD=1", "LINDM_UPDATE_SIGNAL_SOURCE="+source, "LINDM_UPDATE_SIGNAL_WORK="+work, "LINDM_UPDATE_SIGNAL_RECORD="+record, "LINDM_UPDATE_SIGNAL_MANIFEST="+manifest)
			log, err := os.Create(filepath.Join(parent, "child.log"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := log.Close(); err != nil {
					t.Error(err)
				}
			})
			child.Stdout, child.Stderr = log, log
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = child.Process.Kill() })
			done := make(chan error, 1)
			go func() { done <- child.Wait() }()
			deadline := time.NewTimer(15 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			staged := false
			for !staged {
				select {
				case err := <-done:
					data, _ := os.ReadFile(log.Name())
					t.Fatalf("update exited before signing material was staged: %v\n%s", err, data)
				case <-deadline.C:
					t.Fatal("update did not reach owned signing staging")
				case <-tick.C:
					matches, err := filepath.Glob(filepath.Join(work, "lindm-update-lab-*", "package-signing.pass"))
					if err != nil {
						t.Fatal(err)
					}
					staged = len(matches) == 1
				}
			}
			if err := child.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					data, _ := os.ReadFile(log.Name())
					t.Fatalf("signal cleanup failed: %v\n%s", err, data)
				}
			case <-time.After(20 * time.Second):
				t.Fatal("signal cleanup exceeded signer teardown bound")
			}
			entries, err := os.ReadDir(work)
			if err != nil || len(entries) != 0 {
				t.Fatalf("owned sources/signing material survived cancellation: entries=%v err=%v", entries, err)
			}
			data, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			var result vmlab.VMUpdateResult
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
			if result.Outcome != "cancelled" || result.Passed || result.Failure != "" || result.CancellationReason == "" || result.FinishedAt.Before(result.StartedAt) {
				t.Fatalf("missing explicit cancelled evidence: %+v", result)
			}
			processes, err := filepath.Glob("/proc/[0-9]*/cmdline")
			if err != nil {
				t.Fatal(err)
			}
			for _, process := range processes {
				command, readErr := os.ReadFile(process)
				if readErr != nil && !errors.Is(readErr, os.ErrNotExist) && !errors.Is(readErr, os.ErrPermission) && !errors.Is(readErr, syscall.ESRCH) {
					t.Fatal(readErr)
				}
				if bytes.Contains(command, []byte(work+"/lindm-update-lab-")) {
					t.Fatalf("owned signing process survived cancellation: %s", process)
				}
			}
		})
	}
}

func TestVMUpdatesSignalChild(t *testing.T) {
	if os.Getenv("LINDM_UPDATE_SIGNAL_CHILD") != "1" {
		return
	}
	// Same signal context as main, bypassing only host scheduling: this test
	// cancels while signing, before any guest/authority fixture can be admitted.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := runVMUpdates(ctx, []string{"-repo", os.Getenv("LINDM_UPDATE_SIGNAL_SOURCE"), "-manifest", os.Getenv("LINDM_UPDATE_SIGNAL_MANIFEST"), "-work-dir", os.Getenv("LINDM_UPDATE_SIGNAL_WORK"), "-record", os.Getenv("LINDM_UPDATE_SIGNAL_RECORD")}, os.Stdout, os.Stderr)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("update did not preserve signal cancellation: %v", err)
	}
}
