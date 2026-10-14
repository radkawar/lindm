// SPDX-License-Identifier: Apache-2.0

//go:build linux

package config

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/platform"
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

func TestRPMMetadataTrusted(t *testing.T) {
	fedora, ok := platform.Lookup("fedora-44")
	if !ok {
		t.Fatal("fedora-44 missing")
	}
	fedoraLink := "https://mirrors.fedoraproject.org/metalink?repo=fedora-44&arch=x86_64"
	updatesLink := "https://mirrors.fedoraproject.org/metalink?repo=updates-released-f44&arch=x86_64"
	metalink := func(link string) *resourcev1.RpmRepository_Metalink {
		return &resourcev1.RpmRepository_Metalink{Metalink: link}
	}
	baseURLs := &resourcev1.RpmRepository_BaseUrls{BaseUrls: &resourcev1.RepositoryURLs{Urls: []string{"https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Everything/x86_64/os/"}}}
	for name, tc := range map[string]struct {
		rpm  *resourcev1.RpmRepository
		want bool
	}{
		"signed metadata base URL": {&resourcev1.RpmRepository{RequireMetadataSignature: true, Location: baseURLs}, true},
		"pinned metalinks": {&resourcev1.RpmRepository{Location: metalink(fedoraLink), AdditionalRepositories: []*resourcev1.RpmAdditionalRepository{
			{NativeId: "updates", Location: &resourcev1.RpmAdditionalRepository_Metalink{Metalink: updatesLink}}}}, true},
		"unsigned base URL": {&resourcev1.RpmRepository{Location: baseURLs}, false},
		"unpinned metalink": {&resourcev1.RpmRepository{Location: metalink("https://mirror.example.com/metalink?repo=fedora-44&arch=x86_64")}, false},
		"additional base URL": {&resourcev1.RpmRepository{Location: metalink(fedoraLink), AdditionalRepositories: []*resourcev1.RpmAdditionalRepository{
			{NativeId: "updates", Location: &resourcev1.RpmAdditionalRepository_BaseUrls{BaseUrls: baseURLs.BaseUrls}}}}, false},
	} {
		if got := RPMMetadataTrusted(fedora, tc.rpm); got != tc.want {
			t.Errorf("%s: RPMMetadataTrusted = %v, want %v", name, got, tc.want)
		}
	}
	ubuntu, _ := platform.Lookup("ubuntu-24.04")
	if RPMMetadataTrusted(ubuntu, &resourcev1.RpmRepository{Location: metalink(fedoraLink)}) {
		t.Fatal("a release without pinned metalinks trusted unsigned metadata")
	}
}
