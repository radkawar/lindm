//go:build linux

package config

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestPackageProviderSigningKeyCustody(t *testing.T) {
	base := t.TempDir()
	// The test umask may leave the fixture directory group-writable.
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("public package signing material")
	digest := sha256.Sum256(content)
	path := filepath.Join(base, "signer.asc")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	source := &agentv1.NativePackageSource{SigningKeyFile: "signer.asc", SigningKeySha256: digest[:]}
	cfg := &agentv1.NativePackageProviderConfig{Sources: []*agentv1.NativePackageSource{source}}
	if err := resolvePackageProvider(base, cfg, false); err != nil {
		t.Fatal(err)
	}
	if source.GetSigningKeyFile() != path {
		t.Fatalf("relative signing key not resolved: %q", source.GetSigningKeyFile())
	}
	if err := os.WriteFile(path, []byte("changed public key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := resolvePackageProvider(base, cfg, false); err == nil {
		t.Fatal("changed source signing key accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(base, "other.asc")
	if err := os.WriteFile(other, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, path); err != nil {
		t.Fatal(err)
	}
	if err := resolvePackageProvider(base, cfg, false); err == nil {
		t.Fatal("symlink source signing key accepted")
	}
	if err := resolvePackageProvider(base, nil, false); err != nil {
		t.Fatalf("absent opt-in must need no signing files: %v", err)
	}
}
