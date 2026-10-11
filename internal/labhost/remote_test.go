package labhost

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestReturnedEvidenceDoesNotOverwriteExistingRecord(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "downloaded.json")
	destination := filepath.Join(root, "evidence.json")
	if err := os.WriteFile(source, []byte("new record\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("retained record\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := publishRecord(source, destination); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing evidence not refused: %v", err)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "retained record\n" {
		t.Fatal("existing record was changed")
	}
	fresh := filepath.Join(root, "fresh.json")
	if err := publishRecord(source, fresh); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("evidence mode = %v", info.Mode())
	}
}

func TestRemotePackageRelocationPreservesRepositoryBasename(t *testing.T) {
	root := t.TempDir()
	name := "lindm-agent_0.7.0_arm64.deb"
	build := filepath.Join(root, "build", name)
	repository := filepath.Join(root, "repository")
	pool := filepath.Join(repository, "pool", "main", "l", "lindm-agent", name)
	for _, path := range []string{build, pool} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("unchanged artifact bytes"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	stage := &remoteStage{ctx: t.Context(), local: t.TempDir(), remote: t.TempDir(), stderr: io.Discard, copied: make(map[string]string)}
	stagedBuild, err := stage.input(build)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(stagedBuild) != name {
		t.Fatalf("package basename changed: %s", stagedBuild)
	}
	record := filepath.Join(root, "record.json")
	input := map[string]any{"artifact": map[string]string{"path": build}, "apt": map[string]string{"root": repository}}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, data, 0600); err != nil {
		t.Fatal(err)
	}
	stagedRecord, err := stage.record(record)
	if err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(stagedRecord)
	if err != nil {
		t.Fatal(err)
	}
	var relocated struct {
		Artifact struct{ Path string }
		APT      struct{ Root string }
	}
	if err := json.Unmarshal(data, &relocated); err != nil {
		t.Fatal(err)
	}
	// The lifecycle validator derives this path from the artifact basename.
	poolArtifact := filepath.Join(relocated.APT.Root, "pool", "main", "l", "lindm-agent", filepath.Base(relocated.Artifact.Path))
	data, err = os.ReadFile(poolArtifact)
	if err != nil || string(data) != "unchanged artifact bytes" {
		t.Fatalf("relocated repository artifact unavailable or changed: %q, %v", data, err)
	}
	other := filepath.Join(root, "other", name)
	if err := os.MkdirAll(filepath.Dir(other), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("distinct artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	stagedOther, err := stage.input(other)
	if err != nil || stagedOther == stagedBuild || filepath.Base(stagedOther) != name {
		t.Fatalf("same-named inputs collide or lose basename: %s, %v", stagedOther, err)
	}
	data, err = os.ReadFile(stagedBuild)
	if err != nil || string(data) != "unchanged artifact bytes" {
		t.Fatalf("earlier artifact overwritten: %q, %v", data, err)
	}
}

func TestAssistanceEvidenceReturnKeepsOwnerCredentialsRemote(t *testing.T) {
	source, destination := t.TempDir(), filepath.Join(t.TempDir(), "returned")
	for name, data := range map[string]string{"assistance.json": "record", "guest.png": "screenshot", "owner-access": "secret"} {
		if err := os.WriteFile(filepath.Join(source, name), []byte(data), 0400); err != nil {
			t.Fatal(err)
		}
	}
	if err := collectAssistanceEvidence(t.Context(), "", source, destination, io.Discard); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"assistance.json": "record", "guest.png": "screenshot"} {
		got, err := os.ReadFile(filepath.Join(destination, name))
		if err != nil || string(got) != want {
			t.Fatalf("returned %s = %q, %v", name, got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(destination, "owner-access")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owner credentials were returned: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(source, "owner-access")); err != nil || string(got) != "secret" {
		t.Fatalf("remote owner credentials changed: %q, %v", got, err)
	}
	if err := collectAssistanceEvidence(t.Context(), "", source, destination, io.Discard); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing qualification was not refused: %v", err)
	}
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("returned evidence directory is not private: %v, %v", info, err)
	}
}
