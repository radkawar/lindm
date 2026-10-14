// SPDX-License-Identifier: Apache-2.0
//go:build linux

package releasebuild

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	releasev1 "lindm/gen/lindm/release/v1"
)

func TestCrossFilesystemMismatchMovesReadonlyEvidenceWithoutFollowingLinks(t *testing.T) {
	work := t.TempDir()
	if err := os.Chmod(work, 0700); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(work, "first", "go-mod", "module@v1")
	if err := os.MkdirAll(cache, 0700); err != nil {
		t.Fatal(err)
	}
	payload := []byte("observed unsigned dependency bytes")
	if err := os.WriteFile(filepath.Join(cache, "source.go"), payload, 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cache, 0500); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("link target must never be copied or counted"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(work, "dependency-link")); err != nil {
		t.Fatal(err)
	}
	owned, err := os.Lstat(work)
	if err != nil {
		t.Fatal(err)
	}
	parent := crossFilesystemParent(t, work)
	first := &buildOutput{observation: &releasev1.BuildObservation{SourceSha256: "first"}}
	second := &buildOutput{observation: &releasev1.BuildObservation{SourceSha256: "second"}}
	cause := errors.New("unsigned source differs")
	moved, err := retainMismatch(t.Context(), work, owned, parent, first, second, cause)
	if !moved || !errors.Is(err, cause) {
		t.Fatalf("mismatch evidence not retained: %v", err)
	}
	if _, err := os.Lstat(work); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cross-filesystem original work not removed")
	}
	entries, readErr := os.ReadDir(parent)
	if readErr != nil || len(entries) != 1 {
		t.Fatalf("unexpected retained evidence: %v %v", entries, readErr)
	}
	retained := filepath.Join(parent, entries[0].Name())
	link, readErr := os.Readlink(filepath.Join(retained, "dependency-link"))
	if readErr != nil || link != outside {
		t.Fatal("dependency link followed or lost")
	}
	data, readErr := os.ReadFile(filepath.Join(retained, "first", "go-mod", "module@v1", "source.go"))
	if readErr != nil || string(data) != string(payload) {
		t.Fatal("readonly module evidence lost")
	}
	evidence, readErr := os.ReadFile(filepath.Join(retained, "reproducibility-failure.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("(%d regular-file bytes)", len(payload)+len(evidence))) {
		t.Fatal("retained size included link target or excluded evidence")
	}
}

func TestCanceledMismatchDoesNotCreateRetainedEvidence(t *testing.T) {
	work := t.TempDir()
	if err := os.Chmod(work, 0700); err != nil {
		t.Fatal(err)
	}
	owned, err := os.Lstat(work)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	moved, err := retainMismatch(ctx, work, owned, parent, nil, nil, errors.New("mismatch"))
	if moved || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled mismatch retained: %v", err)
	}
	if err := cleanupBuildWork(work, owned); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("interrupted mismatch left diagnostic staging")
	}
}
