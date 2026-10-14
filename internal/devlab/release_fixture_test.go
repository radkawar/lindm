// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"lindm/internal/releaseupdate"
)

func TestReleaseFixtureSeparatesOnlineCustody(t *testing.T) {
	root := t.TempDir()
	custody := filepath.Join(root, "release-custody")
	online := filepath.Join(root, "release-online-custody")
	if err := releaseupdate.GenerateDevelopmentKeys(custody); err != nil {
		t.Fatal(err)
	}
	if err := createReleaseOnlineCustody(custody, online); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(online)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"rollout.pem", "snapshot.pem", "timestamp.pem"}
	if len(entries) != len(want) {
		t.Fatalf("server custody contains %d entries, want only online roles", len(entries))
	}
	for i, entry := range entries {
		if entry.Name() != want[i] {
			t.Fatalf("unexpected online key %q", entry.Name())
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("unprotected online key %q: %v", entry.Name(), err)
		}
		source, err := os.ReadFile(filepath.Join(custody, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		copied, err := os.ReadFile(filepath.Join(online, entry.Name()))
		if err != nil {
			clear(source)
			t.Fatal(err)
		}
		equal := bytes.Equal(source, copied)
		clear(source)
		clear(copied)
		if !equal {
			t.Fatalf("online role %q does not match delegated fixture authority", entry.Name())
		}
	}
	for _, name := range []string{"root.pem", "targets.pem"} {
		if _, err := os.Stat(filepath.Join(custody, name)); err != nil {
			t.Fatalf("offline fixture custody was removed: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(online, name)); !os.IsNotExist(err) {
			t.Fatalf("offline role exposed to server: %s (%v)", name, err)
		}
	}
	if err := createReleaseOnlineCustody(custody, online); err == nil {
		t.Fatal("existing online custody silently replaced")
	}
}
