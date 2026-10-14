// SPDX-License-Identifier: Apache-2.0

package offlinebundle

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"testing"

	releasev1 "lindm/gen/lindm/release/v1"
)

// A server release embeds its attested agent repository subset
// (agent-repository/), and every release signs its redistribution documents
// (license_sha256); releasebuild.Verify requires both. The export copied only
// release.json and artifact base names, so every bundle of a release built
// after either change failed import ("release/agent-repository/release.json",
// then "release/LICENSE": no such file or directory).
func TestCopyReleaseKeepsTheServerReleaseAgentRepository(t *testing.T) {
	artifact := func(product, name string) *releasev1.ReleaseArtifact {
		return &releasev1.ReleaseArtifact{Product: product, Path: name, SbomPath: name + ".sbom", ProvenancePath: name + ".provenance", SignaturePath: name + ".signature"}
	}
	legal := map[string]string{"LICENSE": "license text", "NOTICE": "notice text", "THIRD-PARTY-LICENSES": "third-party text"}
	server := &releasev1.ReleaseManifest{Artifacts: []*releasev1.ReleaseArtifact{artifact("lindm-agent", "agent.deb"), artifact("lindmd", "lindmd.deb")}, LicenseSha256: map[string]string{}}
	for name, content := range legal {
		server.LicenseSha256[name] = digestOf(content)
	}
	embedded := map[string]string{
		"agent-repository/release.json":                         `{"version":"0.1.0"}`,
		"agent-repository/attestation.pub":                      "public key bytes",
		"agent-repository/repo/apt/dists/stable/InRelease":      "signed metadata",
		"agent-repository/repo/apt/pool/main/l/lindm-agent.deb": "package bytes",
	}
	source := func(t *testing.T, tree map[string]string) string {
		t.Helper()
		directory := t.TempDir()
		files := map[string]string{"release.json": `{"version":"0.1.0"}`, "release.json.dsse": "{}"}
		maps.Copy(files, legal)
		for _, a := range server.GetArtifacts() {
			for _, name := range []string{a.GetPath(), a.GetSbomPath(), a.GetProvenancePath(), a.GetSignaturePath()} {
				files[name] = name + " bytes"
			}
		}
		for name, content := range tree {
			files[name] = content
		}
		for name, content := range files {
			path := filepath.Join(directory, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
		}
		return directory
	}

	src := source(t, embedded)
	destination := filepath.Join(t.TempDir(), "release")
	if _, err := copyRelease(src, destination, server); err != nil {
		t.Fatal(err)
	}
	want := maps.Clone(embedded)
	maps.Copy(want, legal)
	for name, content := range want {
		got, err := os.ReadFile(filepath.Join(destination, filepath.FromSlash(name)))
		if err != nil || !bytes.Equal(got, []byte(content)) {
			t.Fatalf("%s not exported byte for byte: %q, %v", name, got, err)
		}
	}
	files, err := listFiles(t.Context(), filepath.Dir(destination))
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, f := range files {
		listed[f.GetPath()] = true
	}
	for name := range want {
		if !listed["release/"+name] {
			t.Fatalf("signed bundle file list omits release/%s", name)
		}
	}

	if _, err := copyRelease(source(t, nil), filepath.Join(t.TempDir(), "release"), server); err == nil {
		t.Fatal("exported a server release without its embedded agent repository")
	}
	agentOnly := &releasev1.ReleaseManifest{Artifacts: server.GetArtifacts()[:1]}
	if _, err := copyRelease(source(t, nil), filepath.Join(t.TempDir(), "release"), agentOnly); err != nil {
		t.Fatalf("agent-only release: %v", err)
	}
	unlicensed := source(t, embedded)
	if err := os.Remove(filepath.Join(unlicensed, "NOTICE")); err != nil {
		t.Fatal(err)
	}
	if _, err := copyRelease(unlicensed, filepath.Join(t.TempDir(), "release"), server); err == nil {
		t.Fatal("exported a release without a signed redistribution document")
	}

	linked := source(t, embedded)
	if err := os.Symlink("/etc/hostname", filepath.Join(linked, "agent-repository", "repo", "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := copyRelease(linked, filepath.Join(t.TempDir(), "release"), server); err == nil {
		t.Fatal("exported a symlink inside the embedded agent repository")
	}
}
