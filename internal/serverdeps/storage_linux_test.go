// SPDX-License-Identifier: Apache-2.0

package serverdeps

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	serverdepsv1 "lindm/gen/lindm/serverdeps/v1"
)

func testManifest() *serverdepsv1.Manifest {
	hash := strings.Repeat("a", 64)
	return &serverdepsv1.Manifest{Distribution: "ubuntu", Version: "24.04", Architecture: "amd64", Backend: serverdepsv1.Backend_BACKEND_DEB, BaseImageSha256: hash, RequestedPackages: []string{"postgresql-16"}, BasePackages: []string{"apt=2.8.3 amd64 installed"}, SolverVersion: "apt 2.8.3", MaxBytes: 100, MaxPackages: 10, TotalBytes: 5, PackageCount: 1, Custody: "development-lab", AcquiredAt: "2026-10-13T00:00:00Z", CaptureEvidencePath: "evidence/capture", ReplayEvidencePath: "evidence/replay", Repositories: []*serverdepsv1.Repository{{Id: "noble", SourceUrl: "https://archive.ubuntu.com/ubuntu/", Authentication: "apt-inrelease", MetadataPath: "archive/dists/noble/InRelease", SigningKeyPath: "keys/archive.gpg", SignerFingerprint: UbuntuArchiveFingerprint}}, Files: []*serverdepsv1.File{{Path: "archive/dists/noble/InRelease", Sha256: hash, SizeBytes: 1, Kind: serverdepsv1.FileKind_FILE_KIND_METADATA}, {Path: "archive/pool/p.deb", Sha256: hash, SizeBytes: 1, Kind: serverdepsv1.FileKind_FILE_KIND_PACKAGE}, {Path: "evidence/capture", Sha256: hash, SizeBytes: 1, Kind: serverdepsv1.FileKind_FILE_KIND_EVIDENCE}, {Path: "evidence/replay", Sha256: hash, SizeBytes: 1, Kind: serverdepsv1.FileKind_FILE_KIND_EVIDENCE}, {Path: "keys/archive.gpg", Sha256: hash, SizeBytes: 1, Kind: serverdepsv1.FileKind_FILE_KIND_KEY}}}
}

func TestTransferRejectsUnsafeNativeClosure(t *testing.T) {
	cases := []struct {
		name   string
		change func(*serverdepsv1.Manifest)
	}{
		{"traversal", func(m *serverdepsv1.Manifest) { m.Files[0].Path = "../escape" }},
		{"backend_confusion", func(m *serverdepsv1.Manifest) { m.Backend = serverdepsv1.Backend_BACKEND_RPM }},
		{"count_mismatch", func(m *serverdepsv1.Manifest) { m.PackageCount = 2 }},
		{"byte_bound", func(m *serverdepsv1.Manifest) { m.MaxBytes = 4 }},
		{"missing_replay", func(m *serverdepsv1.Manifest) { m.ReplayEvidencePath = "evidence/absent" }},
		{"missing_key", func(m *serverdepsv1.Manifest) { m.Repositories[0].SigningKeyPath = "keys/absent" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			m := testManifest()
			test.change(m)
			digest, err := identity(m)
			if err != nil {
				t.Fatal(err)
			}
			m.ManifestSha256 = digest
			data, err := protojson.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			var transfer bytes.Buffer
			if err := binary.Write(&transfer, binary.BigEndian, uint32(len(data))); err != nil {
				t.Fatal(err)
			}
			if _, err := transfer.Write(data); err != nil {
				t.Fatal(err)
			}
			if _, _, err := readTransferManifest(&transfer, digest); err == nil {
				t.Fatal("unsafe transfer manifest accepted")
			}
		})
	}
}

func TestSnapshotTargetKeepsNativeIdentityAndScope(t *testing.T) {
	for _, test := range []struct {
		distribution, version, architecture string
		backend                             serverdepsv1.Backend
		want                                bool
	}{
		{"ubuntu", "24.04", "amd64", serverdepsv1.Backend_BACKEND_DEB, true},
		{"rhel", "9", "amd64", serverdepsv1.Backend_BACKEND_RPM, true},
		{"ubuntu", "24.04", "amd64", serverdepsv1.Backend_BACKEND_RPM, false},
		{"rhel", "9", "amd64", serverdepsv1.Backend_BACKEND_DEB, false},
		{"ubuntu", "26.04", "amd64", serverdepsv1.Backend_BACKEND_DEB, false},
		{"ubuntu", "22.04", "amd64", serverdepsv1.Backend_BACKEND_DEB, false},
		{"debian", "12", "amd64", serverdepsv1.Backend_BACKEND_DEB, false},
		{"debian", "13", "amd64", serverdepsv1.Backend_BACKEND_DEB, false},
		{"ubuntu", "9", "amd64", serverdepsv1.Backend_BACKEND_DEB, false},
		{"rhel", "10", "amd64", serverdepsv1.Backend_BACKEND_RPM, false},
		{"rhel", "9.8", "amd64", serverdepsv1.Backend_BACKEND_RPM, false},
		{"rocky", "9", "amd64", serverdepsv1.Backend_BACKEND_RPM, false},
		{"rocky", "10", "amd64", serverdepsv1.Backend_BACKEND_RPM, false},
		{"almalinux", "9", "amd64", serverdepsv1.Backend_BACKEND_RPM, false},
		{"almalinux", "10", "amd64", serverdepsv1.Backend_BACKEND_RPM, false},
		{"linuxmint", "22.3", "amd64", serverdepsv1.Backend_BACKEND_DEB, false},
		{"pop", "24.04", "amd64", serverdepsv1.Backend_BACKEND_DEB, false},
		{"ubuntu", "24.04", "arm64", serverdepsv1.Backend_BACKEND_DEB, false},
		{"rhel", "9", "x86_64", serverdepsv1.Backend_BACKEND_RPM, false},
	} {
		t.Run(test.distribution+"/"+test.version+"/"+test.architecture+"/"+test.backend.String(), func(t *testing.T) {
			m := &serverdepsv1.Manifest{Distribution: test.distribution, Version: test.version, Architecture: test.architecture, Backend: test.backend}
			_, err := snapshotTarget(m)
			if (err == nil) != test.want {
				t.Fatalf("target accepted=%t, want %t: %v", err == nil, test.want, err)
			}
			if m.Distribution != test.distribution || m.Version != test.version || m.Architecture != test.architecture || m.Backend != test.backend {
				t.Fatal("admission rewrote captured native identity")
			}
		})
	}
}

func TestSafeDescriptorRejectsIntermediateSymlink(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "real"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "real", "file"), []byte("payload"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(directory, "link")); err != nil {
		t.Fatal(err)
	}
	linkedRoot, err := openSnapshotRoot(directory + "/link/.")
	if err == nil {
		if err := linkedRoot.Close(); err != nil {
			t.Error(err)
		}
		t.Fatal("intermediate symlink in snapshot root accepted")
	}
	root, err := openSnapshotRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	file, err := OpenRelative(root, "link/file", false)
	if err == nil {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
		t.Fatal("linked path accepted")
	}
}

func TestAPTIndexCarriesOriginalVendorPackageDigest(t *testing.T) {
	hash := strings.Repeat("b", 64)
	input := "Package: postgresql-16\nVersion: 16.10-0ubuntu0.24.04.1\nArchitecture: amd64\nFilename: pool/main/p/postgresql-16/postgresql-16.deb\nSize: 1234\nSHA256: " + hash + "\n\n"
	values, err := packageDigests(strings.NewReader(input), "archive", "archive/dists/noble/main/binary-amd64/Packages.gz")
	if err != nil {
		t.Fatal(err)
	}
	value := values["archive/pool/main/p/postgresql-16/postgresql-16.deb"]
	if value.hash != hash || value.size != 1234 || value.identity != "postgresql-16=16.10-0ubuntu0.24.04.1:amd64" {
		t.Fatalf("wrong vendor provenance: %+v", value)
	}
	for _, bad := range []string{strings.Replace(input, hash, "invalid", 1), strings.Replace(input, "pool/main", "../pool/main", 1), strings.Replace(input, "Size: 1234", "Size: 0", 1)} {
		if _, err := packageDigests(strings.NewReader(bad), "archive", "index"); err == nil {
			t.Fatal("malformed signed package index accepted")
		}
	}
}

func TestAPTMetadataRejectsOtherTargetOrExpiredVendorValidity(t *testing.T) {
	now := time.Date(2026, time.October, 13, 12, 0, 0, 0, time.UTC)
	valid := "Origin: Ubuntu\nCodename: noble\nSuite: noble-updates\nArchitectures: amd64 arm64\nDate: Mon, 12 Oct 2026 12:00:00 UTC\nValid-Until: Wed, 14 Oct 2026 12:00:00 UTC\n"
	if err := aptReleaseTarget([]byte(valid), "noble-updates", now); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		strings.Replace(valid, "Codename: noble", "Codename: jammy", 1),
		strings.Replace(valid, "Wed, 14 Oct 2026", "Mon, 12 Oct 2026", 1),
		strings.Replace(valid, "Date: Mon, 12 Oct 2026", "Date: Wed, 14 Oct 2026", 1),
	} {
		if err := aptReleaseTarget([]byte(input), "noble-updates", now); err == nil {
			t.Fatal("wrong target or invalid vendor time accepted")
		}
	}
}

func TestCaptureEvidenceCannotOverwriteRetainedBytes(t *testing.T) {
	capture := &APTCapture{Staging: t.TempDir(), Manifest: &serverdepsv1.Manifest{MaxBytes: 100}}
	if err := capture.Add("evidence/capture", []byte("native output"), serverdepsv1.FileKind_FILE_KIND_EVIDENCE); err != nil {
		t.Fatal(err)
	}
	if err := capture.Add("evidence/capture", []byte("replacement"), serverdepsv1.FileKind_FILE_KIND_EVIDENCE); err == nil {
		t.Fatal("capture overwrote retained evidence")
	}
	data, err := os.ReadFile(filepath.Join(capture.Staging, "repository", "evidence", "capture"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "native output" || len(capture.Manifest.Files) != 1 {
		t.Fatal("failed evidence write changed retained content or manifest")
	}
}

func TestAPTReleaseBoundsOnlyRetainedClosureFiles(t *testing.T) {
	hash := strings.Repeat("a", 64)
	release := "SHA256:\n " + hash + " 829119597 Contents-amd64\n " + hash + " 0 main/debian-installer/binary-amd64/Packages\n " + hash + " 35517 main/dep11/icons-128x128@2.tar.gz\n " + hash + " 1808488 main/binary-amd64/Packages.gz\n"
	values, err := releaseDigests([]byte(release), "archive/dists/noble")
	if err != nil {
		t.Fatal(err)
	}
	if values["archive/dists/noble/Contents-amd64"].size != 829119597 || values["archive/dists/noble/main/binary-amd64/Packages.gz"].size != 1808488 || values["archive/dists/noble/main/dep11/icons-128x128@2.tar.gz"].size != 35517 {
		t.Fatal("signed digest table lost original vendor sizes")
	}
	for _, name := range []string{"../escape", "/absolute", "main/../escape", "main//index", "main/\x00index"} {
		invalid := "SHA256:\n " + hash + " 123 " + name + "\n"
		if _, err := releaseDigests([]byte(invalid), "archive/dists/noble"); err == nil {
			t.Fatalf("noncanonical vendor index path accepted: %q", name)
		}
	}
}

func TestAPTSolverPathsDecodeOnlyWithinCapturedOrigin(t *testing.T) {
	origin := "http://127.0.0.1:42000"
	path := "archive/pool/main/g/gcc-14/libstdc++6_14.2.0-4ubuntu2~24.04_amd64.deb"
	for _, encoded := range []string{path, strings.ReplaceAll(path, "+", "%2b"), strings.ReplaceAll(path, "+", "%2B")} {
		name, err := aptSolverPath(origin+"/"+encoded, origin)
		if err != nil || name != path {
			t.Fatalf("native URI did not recover exact signed filename: %q %v", name, err)
		}
	}
	for _, uri := range []string{
		"https://archive.ubuntu.com/ubuntu/" + path,
		origin + ".outside/" + path,
		origin + "/archive/%2e%2e/escape.deb",
		origin + "/archive/%252e%252e/escape.deb",
		origin + "/archive/%00escape.deb",
		origin + "/archive/bad%escape.deb",
		origin + "/archive/not-a-package.gz",
	} {
		if _, err := aptSolverPath(uri, origin); err == nil {
			t.Fatalf("unadmitted native package URI accepted: %q", uri)
		}
	}
}

func TestAPTScriptUsesOwnedEmptyConfigurationPaths(t *testing.T) {
	script, err := APTScript("/private/repository", "/private/native", testManifest(), false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`Dir::Etc::parts "/private/native/config-parts";`,
		`Dir::Etc::main "/private/native/empty-main.conf";`,
		`Dir::Etc::sourceparts "/private/native/source-parts";`,
		": > '/private/native/empty-main.conf'",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("native APT isolation missing %q", expected)
		}
	}
	if strings.Contains(script, `"-"`) {
		t.Fatal("native APT can resolve configuration under ambient /etc/apt/-")
	}
}
