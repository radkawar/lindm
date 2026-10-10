package server

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"lindm/internal/config"
	"lindm/internal/releaseupdate"
)

func TestRecoveryArtifactsRequirePinnedBootstrapAndPrivateState(t *testing.T) {
	directory := t.TempDir()
	keys := filepath.Join(directory, "keys")
	if err := releaseupdate.GenerateDevelopmentKeys(keys); err != nil {
		t.Fatal(err)
	}
	signers, err := releaseupdate.LoadRoleSigners(keys, true)
	if err != nil {
		t.Fatal(err)
	}
	repository := filepath.Join(directory, "repository")
	publisher, err := releaseupdate.CreateRepository(t.Context(), releaseupdate.PublisherConfig{Directory: repository, Signers: signers})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("exact offline-authorized recovery bytes")
	digest := sha256.Sum256(payload)
	name, err := releaseupdate.RecoveryTargetPath(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "recovery.efi")
	if err := os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := publisher.PublishArtifact(t.Context(), name, source); err != nil {
		t.Fatal(err)
	}
	resources := &config.Resources{ReleaseRepositoryDirectory: repository, ReleaseVerificationStateDirectory: filepath.Join(directory, "private-state")}
	if _, err := newRecoveryArtifacts(resources); err == nil {
		t.Fatal("untrusted repository root accepted without installation anchor")
	}
	root, err := os.ReadFile(filepath.Join(repository, "metadata/1.root.json"))
	if err != nil {
		t.Fatal(err)
	}
	resources.ExecutionBootstrap = &config.ExecutionBootstrap{ReleaseRootJSON: root}
	resources.ReleaseVerificationStateDirectory = filepath.Join(repository, "verification")
	if _, err := newRecoveryArtifacts(resources); err == nil {
		t.Fatal("public verification state accepted")
	}
	resources.ReleaseVerificationStateDirectory = filepath.Join(directory, "private-state")
	client, err := newRecoveryArtifacts(resources)
	if err != nil {
		t.Fatal(err)
	}
	info, err := client.Artifact(t.Context(), name)
	if err != nil || info.Length != int64(len(payload)) || !bytes.Equal(info.SHA256, digest[:]) {
		t.Fatalf("pinned exact signed artifact refused: %v %v", info, err)
	}
}
