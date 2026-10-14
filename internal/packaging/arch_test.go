// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packaging

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"lindm/internal/platform"
)

// These tests cover archive bytes and real GPG trust boundaries. The payload is
// deliberately not an agent executable; real install/upgrade belongs to the VM.
func TestArchReproducibilityRepositoryAndRejection(t *testing.T) {
	requireNativeTools(t, "gpg", "gpgv", "gpgconf", "gpg-connect-agent")
	work, err := os.MkdirTemp("", "pkg-arch-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(work); err != nil {
			t.Error(err)
		}
	})
	ctx := context.Background()
	key, err := GenerateDevelopmentSigner(ctx, work)
	if err != nil {
		t.Fatal(err)
	}
	var first Artifact
	var firstRepo *ArchRepository
	for iteration := range 2 {
		buildDir := filepath.Join(work, fmt.Sprintf("build-%d", iteration))
		if err := os.Mkdir(buildDir, 0o700); err != nil {
			t.Fatal(err)
		}
		payload, staged, digest := stageProductFixture(t, buildDir, agentProduct())
		validated, guard, err := validateSigner(ctx, buildDir, *key)
		if err != nil {
			t.Fatal(err)
		}
		artifact, buildErr := buildArch(ctx, buildDir, payload, "0.1.0", Architecture{GOARCH: "amd64", Debian: "amd64", RPM: "x86_64", Arch: "x86_64"}, DefaultSourceDateEpoch, validated, digest, staged, agentProduct())
		closeErr := guard.close(ctx, buildDir)
		if buildErr != nil || closeErr != nil {
			t.Fatalf("build: %v; signer cleanup: %v", buildErr, closeErr)
		}
		if artifact.Format != FormatArch || !artifact.Signed || artifact.SignaturePath != artifact.Path+".sig" || artifact.UnsignedSHA256 != artifact.SHA256 {
			t.Fatalf("incorrect artifact evidence: %+v", artifact)
		}
		assertArchArchive(t, artifact, staged)
		repoDir := filepath.Join(work, fmt.Sprintf("repo-%d", iteration))
		if err := os.Mkdir(repoDir, 0o700); err != nil {
			t.Fatal(err)
		}
		repo, err := PublishArch(ctx, ArchRequest{OutputDir: repoDir, Packages: []string{artifact.Path}, Signer: *key})
		if err != nil {
			t.Fatal(err)
		}
		if !repo.RepoMetadataSigned || !repo.PackagesVerified || repo.Fingerprint != key.Fingerprint {
			t.Fatalf("unsigned repository evidence: %+v", repo)
		}
		assertArchDatabase(t, repo, artifact)
		if iteration == 0 {
			first, firstRepo = artifact, repo
		} else {
			for _, pair := range [][2]string{{first.Path, artifact.Path}, {first.SignaturePath, artifact.SignaturePath}, {firstRepo.Database, repo.Database}, {firstRepo.DatabaseSignature, repo.DatabaseSignature}} {
				a, _, err := hashFile(pair[0])
				if err != nil {
					t.Fatal(err)
				}
				b, _, err := hashFile(pair[1])
				if err != nil {
					t.Fatal(err)
				}
				if a != b {
					t.Fatalf("two clean builds differ: %s", filepath.Base(pair[0]))
				}
			}
		}
	}
	negativeDir := filepath.Join(work, "negative")
	if err := os.Mkdir(negativeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fixtures, err := BuildRejectionFixtures(ctx, RejectionRequest{Arch: first, Signer: *key, OutputDir: negativeDir})
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures.Cases) != 3 || fixtures.WrongSignerFingerprint == key.Fingerprint {
		t.Fatalf("incorrect rejection cases: %+v", fixtures)
	}
	for _, c := range fixtures.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if c.Artifact.Signed {
				t.Fatal("negative fixture claims a verified signature")
			}
			out := filepath.Join(work, "reject-"+c.Name)
			if err := os.Mkdir(out, 0o700); err != nil {
				t.Fatal(err)
			}
			if _, err := PublishArch(ctx, ArchRequest{OutputDir: out, Packages: []string{c.Artifact.Path}, Signer: *key}); err == nil {
				t.Fatal("published unauthenticated Arch package")
			}
			if _, err := os.Stat(filepath.Join(out, "arch")); !os.IsNotExist(err) {
				t.Fatalf("failed publication exposed repository: %v", err)
			}
		})
	}
	// A database signature must authenticate the actual downloadable bytes.
	if err := rejectionFlipByte(firstRepo.Database, 20); err != nil {
		t.Fatal(err)
	}
	if err := verifyArchSignature(ctx, work, firstRepo.Database, firstRepo.PublicKey); err == nil {
		t.Fatal("accepted tampered sync database")
	}
}

func assertArchArchive(t *testing.T, artifact Artifact, staged []stagedFile) {
	t.Helper()
	file, err := os.Open(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	zr, err := zstd.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	data := make(map[string][]byte)
	headers := make(map[string]tar.Header)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimSuffix(h.Name, "/")
		if _, exists := headers[name]; exists {
			t.Fatalf("duplicate member %s", name)
		}
		if h.Uid != 0 || h.Gid != 0 || h.ModTime.Unix() != DefaultSourceDateEpoch || (h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir) {
			t.Fatalf("noncanonical member: %+v", h)
		}
		headers[name] = *h
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		data[name] = body
	}
	for _, s := range staged {
		if h, ok := headers[s.Rel]; !ok || h.Mode != int64(s.Mode.Perm()) {
			t.Fatalf("missing/wrong-mode payload %s", s.Rel)
		}
	}
	if fmt.Sprintf("%x", sha256.Sum256(data[BinaryPath[1:]])) != artifact.PayloadSHA256 {
		t.Fatal("payload digest changed")
	}
	info, err := parseArchInfo(data[".PKGINFO"])
	if err != nil {
		t.Fatal(err)
	}
	if info["pkgver"][0] != "0.1.0-1" || info["arch"][0] != "x86_64" || strings.Join(info["backup"], ",") != "etc/xdg/autostart/lindm-session.desktop,etc/lindm/executor.json,etc/lindm/agent.json" {
		t.Fatalf("incorrect package identity/config preservation: %+v", info)
	}
	if strings.Join(info["license"], ",") != "Apache-2.0" || len(info["url"]) != 0 {
		t.Fatalf("incorrect project license or invented project URL: %+v", info)
	}
	for _, dependency := range platform.BackendPacman.ResourceDependencies() {
		if !slices.Contains(info["depend"], dependency) {
			t.Fatalf("advertised native resource runtime is only optional: %s", dependency)
		}
	}
	buildinfo := string(data[".BUILDINFO"])
	for _, required := range []string{"format = 2\n", "pkgarch = x86_64\n", "buildtool = go\n", "buildtoolver = " + strings.TrimPrefix(runtime.Version(), "go") + "-1-any\n", fmt.Sprintf("pkgbuild_sha256sum = %x\n", sha256.Sum256(data[".PKGBUILD"]))} {
		if !strings.Contains(buildinfo, required) {
			t.Fatalf("incomplete .BUILDINFO: %s", required)
		}
	}
	// Validate mtree against every archived member rather than echoing its generator.
	gz, err := gzip.NewReader(bytes.NewReader(data[".MTREE"]))
	if err != nil {
		t.Fatal(err)
	}
	mtree, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(mtree), "\n") {
		if !strings.HasPrefix(line, "./") {
			continue
		}
		parts := strings.Fields(line)
		name := strings.TrimPrefix(parts[0], "./")
		h, ok := headers[name]
		if !ok || seen[name] {
			t.Fatalf("unexpected mtree member %s", name)
		}
		seen[name] = true
		attrs := make(map[string]string)
		for _, attr := range parts[1:] {
			k, v, _ := strings.Cut(attr, "=")
			attrs[k] = v
		}
		if attrs["mode"] != strconv.FormatInt(h.Mode, 8) || attrs["time"] != fmt.Sprintf("%d.0", DefaultSourceDateEpoch) {
			t.Fatalf("mtree metadata differs: %s", name)
		}
		if h.Typeflag == tar.TypeReg && (attrs["size"] != strconv.FormatInt(h.Size, 10) || attrs["sha256digest"] != fmt.Sprintf("%x", sha256.Sum256(data[name]))) {
			t.Fatalf("mtree file digest differs: %s", name)
		}
	}
	if len(seen) != len(headers)-1 {
		t.Fatal("mtree omitted archive members")
	}
}

func assertArchDatabase(t *testing.T, repo *ArchRepository, artifact Artifact) {
	t.Helper()
	file, err := os.Open(repo.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := gz.Close(); err != nil {
			t.Error(err)
		}
	}()
	tr := tar.NewReader(gz)
	h, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if h.Name != PackageName+"-0.1.0-1/desc" {
		t.Fatalf("wrong repository coordinate %s", h.Name)
	}
	desc, err := io.ReadAll(tr)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(artifact.SignaturePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"%NAME%\n" + PackageName + "\n", "%VERSION%\n0.1.0-1\n", "%FILENAME%\n" + filepath.Base(artifact.Path) + "\n", "%SHA256SUM%\n" + artifact.SHA256 + "\n", "%PGPSIG%\n" + base64.StdEncoding.EncodeToString(sig) + "\n", "%DEPENDS%\nsystemd\nglibc\ncoreutils\nsh\n"} {
		if !bytes.Contains(desc, []byte(required)) {
			t.Fatalf("sync DB omitted field %q", required)
		}
	}
	if _, err := tr.Next(); err != io.EOF {
		t.Fatalf("unexpected extra DB entry: %v", err)
	}
}

func TestArchMetadataAndRepositoryBoundaries(t *testing.T) {
	formats, err := normalizeFormats([]Format{FormatArch, FormatArch})
	if err != nil || len(formats) != 1 || formats[0] != FormatArch {
		t.Fatalf("Arch selection: %v, %v", formats, err)
	}
	for _, input := range []string{"relative", "/tmp/repo\nSigLevel = Never", "/tmp/repo#comment", "/tmp/$repo"} {
		if _, err := ArchRepoConfig(input); err == nil {
			t.Fatalf("accepted unsafe pacman config path %q", input)
		}
	}
	config, err := ArchRepoConfig("/var/lib/lindm-lab/repo")
	if err != nil || !strings.Contains(config, "PackageRequired DatabaseRequired TrustedOnly") {
		t.Fatalf("weak repository policy: %q %v", config, err)
	}
	for _, input := range []string{"", "pkgname = lindm-agent\npkgname = other\n", "pkgname = lindm-agent\npkgver = ../../escape\n", "pkgname = lindm-agent\x00injected\n"} {
		if _, err := parseArchInfo([]byte(input)); err == nil {
			t.Fatalf("accepted malformed metadata %q", input)
		}
	}
	for _, name := range []string{"../escape", "/etc/escape", "a/../../escape"} {
		t.Run(name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "bad.pkg.tar.zst")
			if err := writeArchArchive(t.Context(), filename, []archMember{archMemoryMember(name, []byte("bad"))}, DefaultSourceDateEpoch); err != nil {
				t.Fatal(err)
			}
			if _, err := readArchInfo(filename); err == nil {
				t.Fatal("accepted archive traversal")
			}
		})
	}
}
