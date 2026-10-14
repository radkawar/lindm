// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serverdeps

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	serverdepsv1 "lindm/gen/lindm/serverdeps/v1"
)

// Protects the consumer from unsigned, mixed-signer and failed native checks,
// even when the native process exits successfully or a payload digest matches.
func TestRPMSignatureMatchesExactVendor(t *testing.T) {
	for _, test := range []struct {
		name, output string
		want         bool
	}{
		{"native-good", "Header V4 RSA/SHA256 Signature, key ID fd431d51: OK\nPayload SHA256 digest: OK\n", true},
		{"package-name-not-status", "/private/libadwaita.rpm:\nHeader V4 RSA/SHA256 Signature, key ID fd431d51: OK\nPayload SHA256 digest: OK\n", true},
		{"native-full-key", "Header V4 RSA/SHA256 Signature, key ID 199e2f91fd431d51: OK\n", true},
		{"unsigned-digest-only", "Payload SHA256 digest: OK\n", false},
		{"wrong-signer", "Header V4 RSA/SHA256 Signature, key ID deadbeef: OK\n", false},
		{"missing-key", "Header V4 RSA/SHA256 Signature, key ID fd431d51: NOKEY\n", false},
		{"bad-payload", "Header V4 RSA/SHA256 Signature, key ID fd431d51: OK\nPayload SHA256 digest: BAD\n", false},
		{"mixed-signatures", "Header V4 RSA/SHA256 Signature, key ID fd431d51: OK\nHeader V4 RSA/SHA256 Signature, key ID deadbeef: OK\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := rpmSignatureMatches(test.output, redHatRelease2); got != test.want {
				t.Fatalf("signature accepted=%t, want %t", got, test.want)
			}
		})
	}
}

func TestRPMVendorAcquisitionBoundary(t *testing.T) {
	id := "rhel-9-for-x86_64-baseos-rpms"
	origin := "https://cdn.redhat.com/content/dist/rhel9/9/x86_64/baseos/os"
	if !rpmSourceURL(origin, id) {
		t.Fatal("official entitled BaseOS origin refused")
	}
	for _, source := range []string{
		"http://cdn.redhat.com/content/dist/rhel9/9/x86_64/baseos/os",
		"https://user@cdn.redhat.com/content/dist/rhel9/9/x86_64/baseos/os",
		origin + "?token=private",
		origin + "#fragment",
		"https://cdn.redhat.com.evil.example/content/dist/rhel9/9/x86_64/baseos/os",
		"https://cdn.redhat.com/content/dist/rhel10/10/x86_64/baseos/os",
	} {
		if rpmSourceURL(source, id) {
			t.Fatalf("unauthenticated or wrong vendor origin admitted: %s", source)
		}
	}
	if rpmSourceURL(origin, "epel") || rpmVendorKeyDigest("199E2F91FD431D51") != "" || rpmVendorKeyDigest(redHatRelease2) == "" {
		t.Fatal("source or full vendor key pin boundary weakened")
	}
}

func TestRPMPrimaryBindsExactPayloadIdentityAndBytes(t *testing.T) {
	payload := []byte("native-package-fixture")
	digest := sha256.Sum256(payload)
	sha := hex.EncodeToString(digest[:])
	primary := fmt.Sprintf(`<metadata xmlns="http://linux.duke.edu/metadata/common"><package type="rpm"><name>postgresql-server</name><arch>x86_64</arch><version epoch="0" ver="13.20" rel="1.el9"/><checksum type="sha256">%s</checksum><size package="%d"/></package></metadata>`, sha, len(payload))
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(primary)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	item := rpmTestRetained(t, dir, "primary.xml.gz", compressed.Bytes())
	root, err := openSnapshotRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	identity := "postgresql-server-0:13.20-1.el9.x86_64"
	selected := map[string]*serverdepsv1.File{identity: {Sha256: sha, SizeBytes: uint64(len(payload))}}
	if err := checkRPMPrimary(root, item, selected); err != nil {
		t.Fatal(err)
	}
	selected[identity].SizeBytes++
	if err := checkRPMPrimary(root, item, selected); err == nil {
		t.Fatal("wrong vendor package size accepted")
	}
	delete(selected, identity)
	selected["postgresql-server-0:13.21-1.el9.x86_64"] = &serverdepsv1.File{Sha256: sha, SizeBytes: uint64(len(payload))}
	if err := checkRPMPrimary(root, item, selected); err == nil {
		t.Fatal("wrong native package version accepted")
	}
}

func TestRPMMetadataRejectsChangedRetainedBytes(t *testing.T) {
	dir := t.TempDir()
	original := []byte(`<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><checksum type="sha256">aaaa</checksum><location href="repodata/primary.xml.gz"/><size>10</size></data></repomd>`)
	item := rpmTestRetained(t, dir, "repomd.xml", original)
	root, err := openSnapshotRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	changed := bytes.Replace(original, []byte("aaaa"), []byte("bbbb"), 1)
	if err := os.WriteFile(filepath.Join(dir, item.Path), changed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRPMIndex(root, item); err == nil {
		t.Fatal("mutated metadata accepted under original acquisition digest")
	}
}

func rpmTestRetained(t *testing.T, dir, name string, content []byte) *serverdepsv1.File {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), content, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return &serverdepsv1.File{Path: name, Sha256: hex.EncodeToString(digest[:]), SizeBytes: uint64(len(content)), Kind: serverdepsv1.FileKind_FILE_KIND_METADATA}
}

func TestRPMReplayEvidenceRefusesSymlinksAndOverwrite(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "evidence")); err != nil {
		t.Fatal(err)
	}
	if err := writeRPMReplayEvidence(root, []byte("confirmed")); err == nil {
		t.Fatal("replay evidence followed a symlink directory")
	}
	safe := t.TempDir()
	if err := os.Mkdir(filepath.Join(safe, "evidence"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeRPMReplayEvidence(safe, []byte("confirmed")); err != nil {
		t.Fatal(err)
	}
	if err := writeRPMReplayEvidence(safe, []byte("replacement")); err == nil {
		t.Fatal("replay evidence overwrote an existing record")
	}
}
