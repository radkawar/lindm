// SPDX-License-Identifier: Apache-2.0

package worktree

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lindm/internal/filelock"
)

func TestOwnNodeModulesReplacesSymlinkWithoutTouchingTarget(t *testing.T) {
	repo := fixtureRepository(t)
	ctx := context.Background()
	path, err := repo.Add(ctx, "legacy", "HEAD", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate the retired layout: node_modules linked to the main checkout.
	if err := os.RemoveAll(filepath.Join(path, "node_modules")); err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(repo.Main, "node_modules")
	if err := os.Symlink(shared, filepath.Join(path, "node_modules")); err != nil {
		t.Fatal(err)
	}
	if state := NodeModulesState(path); !strings.HasPrefix(state, "symlink -> ") {
		t.Fatalf("legacy state %q", state)
	}
	if err := repo.InstallNodeModules(ctx, path, io.Discard); err != nil {
		t.Fatal(err)
	}
	if state := NodeModulesState(path); state != "own" {
		t.Fatalf("migrated state %q", state)
	}
	if data, err := os.ReadFile(filepath.Join(path, "node_modules", "pkg", "index.js")); err != nil || string(data) != "shared\n" {
		t.Fatalf("migrated content %q %v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(shared, "pkg", "index.js")); err != nil || string(data) != "shared\n" {
		t.Fatalf("migration damaged the link target: %q %v", data, err)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(path, ".node_modules-staging-*")); len(leftovers) != 0 {
		t.Fatalf("staging left behind: %v", leftovers)
	}
}

func TestPublishNodeModulesKeepsOldTreeOnFailure(t *testing.T) {
	checkout := t.TempDir()
	old := filepath.Join(checkout, "node_modules", "pkg")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "v"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("install failed")
	if err := PublishNodeModules(checkout, func(staging string) error {
		if err := os.MkdirAll(filepath.Join(staging, "node_modules", "partial"), 0o755); err != nil {
			return err
		}
		return failure
	}); !errors.Is(err, failure) {
		t.Fatalf("failure not reported: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(old, "v")); err != nil || string(data) != "old" {
		t.Fatalf("failed install changed the published tree: %q %v", data, err)
	}
	if err := PublishNodeModules(checkout, func(staging string) error {
		return os.MkdirAll(filepath.Join(staging, "node_modules", "new"), 0o755)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(checkout, "node_modules", "new")); err != nil {
		t.Fatalf("new tree not published: %v", err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("previous tree not removed: %v", err)
	}
}

func TestLockHoldersNamesTheRealHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	unlock, err := filelock.LockFile(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A stale record must not hide the actual holder.
	if err := os.WriteFile(path, []byte("pid 1 someone long gone\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	holders, err := LockHolders(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(holders) != 1 || holders[0].PID != os.Getpid() || holders[0].Waiting {
		t.Fatalf("holders %+v, want pid %d", holders, os.Getpid())
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	if holders, err := LockHolders(path); err != nil || len(holders) != 0 {
		t.Fatalf("holders after unlock %+v %v", holders, err)
	}
}
