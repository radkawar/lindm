// SPDX-License-Identifier: Apache-2.0
//go:build linux

package vmlab

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/releasebuild"
)

func productionSigningManifestFixture() *labv1.ImageManifest {
	signature := "https://cloud-images.ubuntu.com/noble/20260926/SHA256SUMS.gpg"
	return &labv1.ImageManifest{
		Distribution: "ubuntu", Version: "24.04", Architecture: "amd64", Edition: "server-cloudimg",
		ImageUrl:    "https://cloud-images.ubuntu.com/noble/20260926/noble-server-cloudimg-amd64.img",
		ChecksumUrl: "https://cloud-images.ubuntu.com/noble/20260926/SHA256SUMS", SignatureUrl: &signature,
		ChecksumMode:      labv1.ChecksumMode_CHECKSUM_MODE_DETACHED,
		SignerFingerprint: "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81",
	}
}

func TestProductionSigningHardwareRequiresMaintainedVendorGuest(t *testing.T) {
	for _, architecture := range []string{"amd64", "x86_64"} {
		manifest := productionSigningManifestFixture()
		manifest.Architecture = architecture
		options := &VMHardwareOptions{Accelerator: "tcg"}
		hardware, err := productionSigningHardware(manifest, options)
		if err != nil || hardware.MemoryMiB != 8192 || hardware.CPUs != 2 || !hardware.AllowNetwork || hardware.Accelerator != "tcg" {
			t.Fatalf("maintained guest hardware=%+v error=%v", hardware, err)
		}
		if options.MemoryMiB != 0 || options.CPUs != 0 || options.AllowNetwork {
			t.Fatal("mutated caller hardware")
		}
	}
	for _, mutate := range []func(*labv1.ImageManifest){
		func(m *labv1.ImageManifest) { m.Distribution = "debian" },
		func(m *labv1.ImageManifest) { m.Version = "26.04" },
		func(m *labv1.ImageManifest) { m.Architecture = "arm64" },
		func(m *labv1.ImageManifest) { m.Edition = "desktop" },
		func(m *labv1.ImageManifest) {
			digest := strings.Repeat("a", 64)
			m.RepositorySnapshotManifestSha256 = &digest
		},
		func(m *labv1.ImageManifest) { m.ChecksumMode = labv1.ChecksumMode_CHECKSUM_MODE_VENDOR_AUTHENTICATED },
		func(m *labv1.ImageManifest) { m.ImageUrl = "https://example.test/noble/image.img" },
		func(m *labv1.ImageManifest) { m.SignerFingerprint = strings.Repeat("A", 40) },
	} {
		manifest := productionSigningManifestFixture()
		mutate(manifest)
		if _, err := productionSigningHardware(manifest, nil); err == nil {
			t.Fatalf("accepted unmaintained/unverified guest: %+v", manifest)
		}
	}
	smaller := &VMHardwareOptions{MemoryMiB: 4096, CPUs: 1}
	if hardware, err := productionSigningHardware(productionSigningManifestFixture(), smaller); err != nil || hardware.MemoryMiB != 4096 || hardware.CPUs != 1 {
		t.Fatalf("did not retain bounded explicit lane resources: hardware=%+v error=%v", hardware, err)
	}
	for _, hardware := range []VMHardwareOptions{{MemoryMiB: 255}, {MemoryMiB: 8193}, {CPUs: 3}} {
		if _, err := productionSigningHardware(productionSigningManifestFixture(), &hardware); err == nil {
			t.Fatalf("accepted unbounded lane resources: %+v", hardware)
		}
	}
}

func TestProductionSigningProviderResourceDefaultsAndBounds(t *testing.T) {
	firmware := &EncryptedFirmwareOptions{Code: "/code", Vars: "/vars", Package: "fixture", Version: "1"}
	for _, options := range []*VMHardwareOptions{nil, {MemoryMiB: 8192, CPUs: 2}, {Architecture: "aarch64", Firmware: firmware, MemoryMiB: 4096, CPUs: 4}} {
		hardware, err := resolveVMHardware(options, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		memory, cpus := "2048", "2"
		if options != nil && options.MemoryMiB == 8192 {
			memory = "8192"
		}
		if options != nil && options.Architecture == "aarch64" {
			memory, cpus = "4096", "4"
		}
		args, err := configuredVMArguments(hardware, t.TempDir(), "12345", false)
		if err != nil {
			t.Fatal(err)
		}
		for flag, expected := range map[string]string{"-m": memory, "-smp": cpus} {
			index := slices.Index(args, flag)
			if index < 0 || index+1 >= len(args) || args[index+1] != expected {
				t.Fatalf("QEMU %s does not match bounded guest resources: %v", flag, args)
			}
		}
	}
	for _, hardware := range []VMHardwareOptions{{MemoryMiB: 255}, {MemoryMiB: 65537}, {CPUs: 65}} {
		if _, err := resolveVMHardware(&hardware, "amd64"); err == nil {
			t.Fatalf("accepted unbounded provider resources: %+v", hardware)
		}
	}
}

func TestProductionSigningRequiresHeaderOnlyNoSwapEvidence(t *testing.T) {
	for _, header := range []string{"Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n", "Filename Type Size Used Priority\n"} {
		if !productionSigningSwapHeaderOnly([]byte(header)) {
			t.Fatal("rejected kernel header-only no-swap observation")
		}
	}
	for _, data := range []string{"", "Filename\n", "Filename Type Size Used Priority\n/swapfile file 100 0 -2\n", "Filename Type Size Used Priority\n/dev/zram0 partition 100 0 5\n"} {
		if productionSigningSwapHeaderOnly([]byte(data)) {
			t.Fatalf("accepted non-header-only swap: %q", data)
		}
	}
}

func TestProductionSigningSourceSelectionMatchesCanonicalExclusions(t *testing.T) {
	paths, err := productionSigningSourcePaths([]byte("web/src/main.tsx\x00.go-version\x00artifacts/key\x00.cache/cache\x00.tools/go\x00node_modules/key\x00web/dist/file\x00.git/key\x00a/file.go\x00a.c\x00a-/file.go\x00a/file.go\x00"))
	want := []string{".go-version", "a/file.go", "a-/file.go", "a.c", "web/src/main.tsx"}
	if err != nil || !reflect.DeepEqual(paths, want) {
		t.Fatalf("canonical source paths=%v error=%v", paths, err)
	}
	for _, listed := range []string{"", "go.mod", "../outside\x00", "/outside\x00", "a/../outside\x00", "release-keys/custody.age\x00", ".ssh/id_ed25519\x00", ".gnupg/private-keys-v1.d/key\x00", "operator/passphrase.txt\x00", ".env\x00", "operator/key.p12\x00"} {
		if _, err := productionSigningSourcePaths([]byte(listed)); err == nil {
			t.Fatalf("accepted invalid/private source selection %q", listed)
		}
	}
	if _, err := productionSigningSourcePaths([]byte("internal/packaging/passphrase_linux.go\x00internal/advisory/keys/vendor.asc\x00")); err != nil {
		t.Fatalf("refused public source/public vendor keys: %v", err)
	}
}

func productionSigningSourceFixture(t *testing.T) string {
	t.Helper()
	repository := t.TempDir()
	if output, err := exec.CommandContext(t.Context(), "git", "init", "--quiet", repository).CombinedOutput(); err != nil {
		t.Fatalf("initialize capture fixture: %v: %s", err, output)
	}
	for name, data := range map[string]string{
		"go.mod": "module fixture\n\ngo 1.26.9\n", ".node-version": "24.21.0\n",
		"a/file.go": "package source\n", "a.c": "public C source\n", "a-/file.go": "package source\n",
		"web/src/main.tsx": "public console source\n", "web/dist/generated.js": "excluded generated output\n",
		".cache/host-cache": "excluded maintainer cache\n", "artifacts/release-keys/private": "excluded artifact tree\n",
	} {
		path := filepath.Join(repository, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return repository
}

func TestProductionSigningCaptureHashesActualOnceCapturedPublicBytes(t *testing.T) {
	repository := productionSigningSourceFixture(t)
	expected, err := releasebuild.SourceDigest(t.Context(), repository)
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "source.tar")
	sourceSHA, archiveSHA, err := captureProductionSigningSource(t.Context(), repository, archive)
	if err != nil || sourceSHA != expected {
		t.Fatalf("captured digest=%s canonical=%s error=%v", sourceSHA, expected, err)
	}
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if archiveSHA != hex.EncodeToString(sum[:]) {
		t.Fatal("source transfer archive digest differs from actual captured bytes")
	}
	if err := os.WriteFile(filepath.Join(repository, "a/file.go"), []byte("changed checkout after capture\n"), 0644); err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(bytes.NewReader(data))
	var names []string
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, header.Name)
		captured, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if header.Name == "a/file.go" && string(captured) != "package source\n" {
			t.Fatal("captured source followed later checkout mutation")
		}
		if header.Typeflag != tar.TypeReg {
			t.Fatal("source archive includes nonregular input")
		}
	}
	for _, name := range names {
		for _, prefix := range productionSigningSourceExclusions {
			if strings.HasPrefix(name, prefix) {
				t.Fatalf("transferred excluded cache/artifact: %s", name)
			}
		}
	}
}

func TestProductionSigningCaptureRefusesPrivateLinksWrongPinsAndCancellation(t *testing.T) {
	for _, mutate := range []func(string) error{
		func(root string) error {
			return os.WriteFile(filepath.Join(root, "private.pem"), []byte("-----BEGIN PRIVATE KEY-----\noperator secret\n"), 0600)
		},
		func(root string) error { return os.Symlink("go.mod", filepath.Join(root, "linked.go")) },
		func(root string) error {
			return os.WriteFile(filepath.Join(root, ".node-version"), []byte("24.20.0\n"), 0600)
		},
		func(root string) error {
			return os.WriteFile(filepath.Join(root, "go.mod"), []byte("module fixture\n\ngo 1.26.8\n"), 0600)
		},
	} {
		repository := productionSigningSourceFixture(t)
		if err := mutate(repository); err != nil {
			t.Fatal(err)
		}
		if _, _, err := captureProductionSigningSource(t.Context(), repository, filepath.Join(t.TempDir(), "source.tar")); err == nil {
			t.Fatal("captured private/symlinked/wrong-pin input")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := captureProductionSigningSource(ctx, productionSigningSourceFixture(t), filepath.Join(t.TempDir(), "source.tar")); err == nil {
		t.Fatal("ignored cancelled capture context")
	}
	if productionSigningPrivateMaterial([]byte("package fixture\nvar marker = `-----BEGIN PRIVATE KEY-----`\n")) {
		t.Fatal("classified source-code marker literal as operator secret")
	}
}

func productionSigningPassLogFixture(t *testing.T) []byte {
	t.Helper()
	var data bytes.Buffer
	appendEvent := func(action, pkg, test string) {
		encoded, err := json.Marshal(map[string]string{"Action": action, "Package": pkg, "Test": test})
		if err != nil {
			t.Fatal(err)
		}
		data.Write(encoded)
		data.WriteByte('\n')
	}
	for pkg, names := range productionSigningRequiredTests {
		for _, name := range names {
			appendEvent("run", pkg, name)
			appendEvent("pass", pkg, name)
		}
	}
	for _, pkg := range productionSigningPackages {
		appendEvent("pass", pkg, "")
	}
	return data.Bytes()
}

func TestProductionSigningPassEvidenceRequiresEveryPackageAndProductionTest(t *testing.T) {
	passed := productionSigningPassLogFixture(t)
	if err := productionSigningTestPasses(passed); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{
		nil,
		[]byte("not genuine test JSON\n"),
		bytes.Replace(passed, []byte(`"Package":"lindm/cmd/release"`), []byte(`"Package":"unrelated/package"`), 1),
		bytes.Replace(passed, []byte(`"Action":"run"`), []byte(`"Action":"output"`), 1),
		bytes.Replace(passed, []byte(`"Action":"pass"`), []byte(`"Action":"skip"`), 1),
		append(append([]byte(nil), passed...), []byte("{\"Action\":\"fail\",\"Package\":\"lindm/cmd/release\"}\n")...),
	} {
		if err := productionSigningTestPasses(data); err == nil {
			t.Fatal("accepted incomplete/skipped/failed production test evidence")
		}
	}
}

func TestProductionSigningEvidenceIsPrivateHashedAndTestsOnly(t *testing.T) {
	root := t.TempDir()
	result := &VMProductionReleaseSigningResult{Scope: productionSigningScope, EvidenceDir: root, StartedAt: time.Now().UTC()}
	data := []byte("actual fixture command output\n")
	if err := productionSigningEvidence(result, "go-test.stdout.jsonl", data); err != nil {
		t.Fatal(err)
	}
	evidence := result.TestEvidence[0]
	sum := sha256.Sum256(data)
	info, err := os.Stat(evidence.Path)
	if err != nil || info.Mode().Perm() != 0600 || evidence.SHA256 != hex.EncodeToString(sum[:]) || evidence.Size != int64(len(data)) {
		t.Fatalf("evidence metadata=%+v info=%v error=%v", evidence, info, err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"scope":"production-signing-tests-only"`, `"lifecycle_qualified":false`, `"passed":false`, `"owned_cleanup_complete":false`, `"source_sha256":`, `"image_sha256":`, `"guest_no_swap":false`, `"tool_versions":`, `"test_evidence":`, `"sha256":`, `"size":`} {
		if !bytes.Contains(encoded, []byte(field)) {
			t.Fatalf("missing contract field %s", field)
		}
	}
	if err := productionSigningEvidence(result, "go-test.stdout.jsonl", []byte("replacement")); err == nil {
		t.Fatal("overwrote previously attested evidence")
	}
	if _, err := RunVMProductionReleaseSigning(t.Context(), nil, VMProductionReleaseSigningOptions{}); err == nil {
		t.Fatal("accepted absent runner prerequisites")
	}
}

func TestProductionSigningRecipesRetainRealSafeGuestBoundaries(t *testing.T) {
	for _, token := range []string{"env -i", "HOME=", "GOCACHE=", "GOMODCACHE=", "GOPATH=", "npm_config_cache=", "GOTOOLCHAIN=local", "GOSUMDB=sum.golang.org"} {
		if !strings.Contains(productionSigningEnvironment(), token) {
			t.Fatalf("missing independent guest environment %s", token)
		}
	}
	for _, token := range []string{"go1.26.9", "v24.21.0", "https://go.dev/dl/", "https://nodejs.org/dist/", "sha256sum --check --strict", "--proto '=https'"} {
		if !strings.Contains(productionSigningInstallTools, token) {
			t.Fatalf("missing actual public pinned install %s", token)
		}
	}
	for _, token := range []string{"'test'", "'-race'", "'-count=1'", "'-tags=integration,production_signing'", "'/proc/swaps'", "stdout_truncated", "stderr_truncated"} {
		if !strings.Contains(productionSigningRunTests, token) {
			t.Fatalf("missing genuine bounded test recipe %s", token)
		}
	}
	if !strings.Contains(productionSigningBuildPrerequisites, "make generate-licenses") || !strings.Contains(productionSigningNativeSetup, "AllowUnauthenticated=false") {
		t.Fatal("missing maintained license build or signed native prerequisites")
	}
	for _, marker := range []string{"-----BEGIN PRIVATE KEY-----", "-----BEGIN PGP PRIVATE KEY BLOCK-----", "AGE-SECRET-KEY-"} {
		if !strings.Contains(productionSigningExportGuard, marker) {
			t.Fatalf("missing guest-side private log export refusal %s", marker)
		}
	}
}
