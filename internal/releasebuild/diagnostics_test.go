// SPDX-License-Identifier: Apache-2.0

//go:build linux

package releasebuild

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	releasev1 "lindm/gen/lindm/release/v1"
)

func TestBuildFailurePreservesBothDiagnosticStreams(t *testing.T) {
	_, err := command(t.Context(), t.TempDir(), nil, "/bin/sh", "-c", "printf 'compiler error on stdout\\n'; printf 'dependency warning on stderr\\n' >&2; exit 2")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 {
		t.Fatalf("build failure lost exit status: %v", err)
	}
	for _, diagnostic := range []string{"stdout:\ncompiler error on stdout", "stderr:\ndependency warning on stderr"} {
		if !strings.Contains(err.Error(), diagnostic) {
			t.Fatalf("build failure lost diagnostic %q: %v", diagnostic, err)
		}
	}
}

func TestCleanupOwnReadonlyModulesNeverFollowsExternalLink(t *testing.T) {
	work := filepath.Join(t.TempDir(), "private-build")
	module := filepath.Join(work, "first", "go-mod", "module@v1")
	if err := os.MkdirAll(module, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(module, "PATENTS"), []byte("module input"), 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(module, 0555); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "shared-cache")
	if err := os.Mkdir(external, 0555); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(work, "external")); err != nil {
		t.Fatal(err)
	}
	owned, err := os.Lstat(work)
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanupBuildWork(work, owned); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(work); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private work survived cleanup: %v", err)
	}
	info, err := os.Stat(external)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0555 {
		t.Fatal("cleanup changed external shared-cache permissions")
	}
}

func TestCleanupRejectsReplacedWorkInode(t *testing.T) {
	parent := t.TempDir()
	work := filepath.Join(parent, "work")
	if err := os.Mkdir(work, 0700); err != nil {
		t.Fatal(err)
	}
	owned, err := os.Lstat(work)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(work, filepath.Join(parent, "original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(work, 0700); err != nil {
		t.Fatal(err)
	}
	if err := cleanupBuildWork(work, owned); err == nil {
		t.Fatal("cleanup accepted replacement work inode")
	}
	if _, err := os.Stat(work); err != nil {
		t.Fatal("cleanup removed unrelated replacement")
	}
}

func TestMismatchEvidenceRetainsBothObservedInputs(t *testing.T) {
	work := t.TempDir()
	observations := []*releasev1.BuildObservation{
		{SourceSha256: "source", UnsignedSha256: map[string]string{"artifact": "first"}, BinarySha256: map[string]string{"lindmd/amd64": "binary-first"}, ConsoleSha256: map[string]string{"index.html": "console-first"}, ToolVersions: map[string]string{"go": "observed-go"}},
		{SourceSha256: "source", UnsignedSha256: map[string]string{"artifact": "second"}, BinarySha256: map[string]string{"lindmd/amd64": "binary-second"}, ConsoleSha256: map[string]string{"index.html": "console-second"}, ToolVersions: map[string]string{"go": "observed-go"}},
	}
	cause := errors.New("unsigned payload differs")
	err := retainFailure(work, &buildOutput{observation: observations[0]}, &buildOutput{observation: observations[1]}, cause)
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "reproducibility-failure.json") {
		t.Fatalf("missing retained failure location: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(work, "reproducibility-failure.json"))
	if err != nil {
		t.Fatal(err)
	}
	var evidence releasev1.ReleaseBuildFailure
	if err := protojson.Unmarshal(data, &evidence); err != nil {
		t.Fatal(err)
	}
	if len(evidence.Builds) != 2 || evidence.Builds[0].BinarySha256["lindmd/amd64"] != "binary-first" || evidence.Builds[1].ConsoleSha256["index.html"] != "console-second" || evidence.Builds[0].ToolVersions["go"] != "observed-go" || evidence.RetainedWorkDirectory != work {
		t.Fatal("failure evidence lost actual build observations")
	}
}
