//go:build linux

package packaging

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// Bundle contents here are serialization fixtures, not a release-authentication
// proof. Real package/repository signing uses the guarded development signer.
func repositoryPayloadFixture(t *testing.T) string {
	t.Helper()
	bundle := t.TempDir()
	for _, format := range []string{"apt", "rpm", "arch"} {
		if err := os.MkdirAll(filepath.Join(bundle, "repo", format), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"release.json", "release.json.dsse", "attestation.pub", "package-signing.asc", "repo/apt/package.deb", "repo/rpm/package.rpm", "repo/arch/package.pkg.tar.zst"} {
		if err := os.WriteFile(filepath.Join(bundle, name), []byte("unchanged bundled bytes: "+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return bundle
}

func TestRepositoryStagingPreservesBytesAndRejectsLinks(t *testing.T) {
	for _, attack := range []string{"none", "link", "missing-manifest"} {
		t.Run(attack, func(t *testing.T) {
			bundle := repositoryPayloadFixture(t)
			if attack == "link" {
				if err := os.Symlink("release.json", filepath.Join(bundle, "linked")); err != nil {
					t.Fatal(err)
				}
			}
			if attack == "missing-manifest" {
				if err := os.Remove(filepath.Join(bundle, "release.json.dsse")); err != nil {
					t.Fatal(err)
				}
			}
			payload := t.TempDir()
			files, err := stageAgentRepository(payload, bundle, DefaultSourceDateEpoch)
			if attack != "none" {
				if !errors.Is(err, ErrArtifact) {
					t.Fatalf("unsafe/incomplete bundle staged: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != 7 {
				t.Fatalf("lost bundled files: %d", len(files))
			}
			for _, file := range files {
				source, err := os.ReadFile(filepath.Join(bundle, strings.TrimPrefix(file.Rel, AgentRepositoryPath[1:]+"/")))
				if err != nil {
					t.Fatal(err)
				}
				installed := filepath.Join(payload, file.Rel)
				body, err := os.ReadFile(installed)
				if err != nil || !bytes.Equal(body, source) {
					t.Fatalf("bundle bytes changed: %s: %v", file.Rel, err)
				}
				info, err := os.Stat(installed)
				if err != nil || info.Mode().Perm() != 0444 || info.ModTime().Unix() != DefaultSourceDateEpoch || file.Conf {
					t.Fatalf("bundle is mutable/operator-owned or nondeterministic: %s: %v", file.Rel, err)
				}
			}
		})
	}
}

func TestServerNativeArchivesCarryIdenticalReadOnlyBundle(t *testing.T) {
	requireNativeTools(t, "dpkg-deb", "rpmbuild", "rpmsign", "rpm", "rpmkeys", "rpm2cpio", "cpio", "gpg", "gpgconf", "gpg-connect-agent", "gpgv")
	work, err := os.MkdirTemp("", "pkg-bundle-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(work); err != nil {
			t.Error(err)
		}
	})
	key, err := GenerateDevelopmentSigner(t.Context(), work)
	if err != nil {
		t.Fatal(err)
	}
	bundle := repositoryPayloadFixture(t)
	arch := Architecture{GOARCH: "amd64", Debian: "amd64", RPM: "x86_64", Arch: "x86_64"}
	for _, format := range []Format{FormatDEB, FormatRPM, FormatArch} {
		t.Run(string(format), func(t *testing.T) {
			var previous string
			for iteration := range 2 {
				build := filepath.Join(work, fmt.Sprintf("%s-%d", format, iteration))
				if err := os.Mkdir(build, 0700); err != nil {
					t.Fatal(err)
				}
				payload, staged, digest := stageProductFixture(t, build, serverProduct())
				bundleFiles, err := stageAgentRepository(payload, bundle, DefaultSourceDateEpoch)
				if err != nil {
					t.Fatal(err)
				}
				staged = append(staged, bundleFiles...)
				validated, guard, err := validateSigner(t.Context(), build, *key)
				if err != nil {
					t.Fatal(err)
				}
				artifacts, buildErr := buildArtifacts(t.Context(), build, []Format{format}, payload, "0.1.0", arch, DefaultSourceDateEpoch, validated, digest, staged, serverProduct())
				closeErr := guard.close(t.Context(), build)
				if buildErr != nil || closeErr != nil {
					t.Fatalf("native archive: %v; signer cleanup: %v", buildErr, closeErr)
				}
				artifact := artifacts[0]
				if previous != "" && artifact.UnsignedSHA256 != previous {
					t.Fatal("server unsigned archives differ despite identical canonical agent bundle")
				}
				previous = artifact.UnsignedSHA256
				if format != FormatArch {
					// Production DEB/RPM verification compares every bundled file's
					// digest during the real native archive build above.
					continue
				}
				info, err := readArchInfo(artifact.Path)
				if err != nil || info["pkgname"][0] != ServerPackageName || len(info["backup"]) != 0 {
					t.Fatalf("Arch server identity/config ownership: %v", err)
				}
				assertServerArchBundle(t, artifact.Path, bundleFiles)
			}
		})
	}
}

func assertServerArchBundle(t *testing.T, path string, files []stagedFile) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	reader, err := zstd.NewReader(file, zstd.WithDecoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	archive := tar.NewReader(reader)
	want := map[string]string{}
	for _, entry := range files {
		want[entry.Rel] = entry.SHA256
	}
	seen := 0
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if sum := want[header.Name]; sum != "" {
			hash := sha256.New()
			if _, err := io.Copy(hash, archive); err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(hash.Sum(nil)) != sum || header.Mode != 0444 {
				t.Fatalf("Arch bundle changed or mutable: %s", header.Name)
			}
			seen++
		}
		if header.Name == ".INSTALL" {
			body, err := io.ReadAll(archive)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(body, []byte("upgrade-stop")) || bytes.Contains(body, []byte("lindm/lifecycle")) || !bytes.Contains(body, []byte("lindmd/lifecycle configure")) {
				t.Fatal("Arch server uses agent lifecycle or stops services on upgrade")
			}
		}
	}
	if seen != len(want) {
		t.Fatal("Arch server omitted canonical agent bundle files")
	}
}
