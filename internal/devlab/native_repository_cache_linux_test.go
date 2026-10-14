// SPDX-License-Identifier: Apache-2.0

//go:build linux

package devlab

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/sigstore/sigstore/pkg/signature"
	sigstoredsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"google.golang.org/protobuf/encoding/protojson"

	releasev1 "lindm/gen/lindm/release/v1"
	"lindm/internal/packaging"
	"lindm/internal/releasebuild"
)

func stockCacheSource(t *testing.T) string {
	t.Helper()
	source := t.TempDir()
	if output, err := exec.CommandContext(t.Context(), "git", "init", "--quiet", source).CombinedOutput(); err != nil {
		t.Fatalf("initialize source: %v: %s", err, output)
	}
	if err := os.WriteFile(filepath.Join(source, "source.go"), []byte("package sample\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return source
}

// This fixture exercises real DSSE/cache admission, not native packaging or VM
// qualification. The artifact payload deliberately identifies that boundary.
func stockCacheSignedFixture(t *testing.T, directory, sourceDigest string) *releasev1.ReleaseManifest {
	t.Helper()
	if err := os.Mkdir(directory, 0755); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	stockCacheWrite(t, directory, "attestation.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	stockCacheWrite(t, directory, "package-signing.asc", stockCacheNativePublic(t))
	signer, err := signature.LoadSignerVerifier(private, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	sign := func(body []byte, kind string) []byte {
		envelope, err := sigstoredsse.WrapSignerVerifier(signer, kind).SignMessage(bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	name, payload := "cache-boundary.deb", []byte("real attestation admission; not a native package")
	digest := stockCacheDigest(payload)
	stockCacheWrite(t, directory, name, payload)
	artifact := &releasev1.ReleaseArtifact{Path: name, Product: "lindm-agent", Architecture: "amd64", Format: "deb", Sha256: digest, Size: int64(len(payload)), UnsignedSha256: digest, SecondUnsignedSha256: digest, SbomPath: name + ".sbom", ProvenancePath: name + ".provenance", SignaturePath: name + ".signature"}
	for _, item := range []struct{ name, kind string }{{artifact.SbomPath, "https://cyclonedx.org/bom"}, {artifact.ProvenancePath, "https://slsa.dev/provenance/v1"}, {artifact.SignaturePath, "https://lindm.invalid/release/artifact/v1"}} {
		statement, err := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v1", "subject": []any{map[string]any{"name": name, "digest": map[string]string{"sha256": digest}}}, "predicateType": item.kind, "predicate": map[string]string{"test": "cache admission only"}})
		if err != nil {
			t.Fatal(err)
		}
		stockCacheWrite(t, directory, item.name, sign(statement, "application/vnd.in-toto+json"))
	}
	observation := &releasev1.BuildObservation{SourceSha256: sourceDigest, StartedAt: "2026-10-13T00:00:00Z", FinishedAt: "2026-10-13T00:00:01Z", UnsignedSha256: map[string]string{name: digest}}
	manifest := &releasev1.ReleaseManifest{Version: "0.1.0", Revision: "console-enrollment-lab", SourceSha256: sourceDigest, SourceDateEpoch: packaging.DefaultSourceDateEpoch, Artifacts: []*releasev1.ReleaseArtifact{artifact}, AttestationKeyId: stockCacheDigest(der), Custody: "development", Builds: []*releasev1.BuildObservation{observation, observation}}
	body, err := protojson.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	stockCacheWrite(t, directory, "release.json", body)
	stockCacheWrite(t, directory, "release.json.dsse", sign(body, "application/vnd.lindm.release.v1+json"))
	return manifest
}

func stockCacheWrite(t *testing.T, directory, name string, body []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), body, 0444); err != nil {
		t.Fatal(err)
	}
}

func stockCacheDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func stockCacheNativePublic(t *testing.T) []byte {
	t.Helper()
	key, err := openpgp.NewEntity("Stock cache admission", "", "", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	armored, err := armor.Encode(&buffer, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Serialize(armored); err != nil {
		t.Fatal(err)
	}
	if err := armored.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestStockRepositoryCacheReusesSourceAndRefusesTamper(t *testing.T) {
	source, cache := stockCacheSource(t), stockCacheDirectory(t)
	builds := 0
	build := func(ctx context.Context, source, bundle, _ string) (*releasev1.ReleaseManifest, error) {
		builds++
		digest, err := releasebuild.SourceDigest(ctx, source)
		if err != nil {
			return nil, err
		}
		return stockCacheSignedFixture(t, bundle, digest), nil
	}
	first, err := cachedNativeEnrollmentRepository(t.Context(), source, cache, releasebuild.SourceDigest, build)
	if err != nil || first.hit {
		t.Fatalf("cold cache: %v", err)
	}
	second, err := cachedNativeEnrollmentRepository(t.Context(), source, cache, releasebuild.SourceDigest, build)
	if err != nil || !second.hit || second.directory != first.directory || builds != 1 {
		t.Fatalf("cache did not reuse authenticated source: %v; builds=%d", err, builds)
	}
	if err := os.WriteFile(filepath.Join(source, "source.go"), []byte("changed source\n"), 0644); err != nil {
		t.Fatal(err)
	}
	changed, err := cachedNativeEnrollmentRepository(t.Context(), source, cache, releasebuild.SourceDigest, build)
	if err != nil || changed.hit || changed.directory == first.directory || builds != 2 {
		t.Fatalf("source change did not invalidate cache: %v", err)
	}
	manifest := filepath.Join(changed.directory, "release.json")
	if err := os.Chmod(manifest, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("tampered signed manifest"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := cachedNativeEnrollmentRepository(t.Context(), source, cache, releasebuild.SourceDigest, build); err == nil || builds != 2 {
		t.Fatal("tampered cache was admitted or silently rebuilt")
	}
}

func TestStockRepositoryCacheSingleFlightAndCancellation(t *testing.T) {
	source, cache := stockCacheSource(t), stockCacheDirectory(t)
	digest, err := releasebuild.SourceDigest(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(t.TempDir(), "fixture")
	manifest := stockCacheSignedFixture(t, fixture, digest)
	var builds atomic.Int32
	build := func(ctx context.Context, _, bundle, _ string) (*releasev1.ReleaseManifest, error) {
		builds.Add(1)
		return manifest, materializeNativeRepository(ctx, fixture, bundle)
	}
	results := make(chan error, 4)
	for range 4 {
		go func() {
			_, err := cachedNativeEnrollmentRepository(t.Context(), source, cache, releasebuild.SourceDigest, build)
			results <- err
		}()
	}
	for range 4 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if builds.Load() != 1 {
		t.Fatalf("concurrent fixtures built %d identical matrices", builds.Load())
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := cachedNativeEnrollmentRepository(ctx, source, cache, releasebuild.SourceDigest, build); err == nil {
		t.Fatal("cache ignored canceled preparation")
	}
}

func TestStockRepositoryCopiesHaveIndependentImmutableInodes(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	stockCacheWrite(t, source, "package.deb", []byte("cache inode regression"))
	first := filepath.Join(t.TempDir(), "first")
	if err := materializeNativeRepository(t.Context(), source, first); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(filepath.Join(first, "package.deb"))
	if err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(t.TempDir(), "second")
	if err := materializeNativeRepository(t.Context(), source, second); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(filepath.Join(first, "package.deb"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := os.Stat(filepath.Join(second, "package.deb"))
	if err != nil {
		t.Fatal(err)
	}
	firstStat, firstOK := before.Sys().(*syscall.Stat_t)
	afterStat, afterOK := after.Sys().(*syscall.Stat_t)
	if !firstOK || !afterOK || os.SameFile(before, other) || firstStat.Ctim != afterStat.Ctim {
		t.Fatal("second fixture changed or shared the first daemon's immutable inode")
	}
	if err := os.RemoveAll(source); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(first, "package.deb"))
	if err != nil || string(body) != "cache inode regression" {
		t.Fatalf("cache pruning invalidated a running fixture: %v", err)
	}
}

func TestStockRepositoryCacheRefusesSharedDirectoryAndSourceRace(t *testing.T) {
	source, cache := stockCacheSource(t), stockCacheDirectory(t)
	if err := os.Mkdir(cache, 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cache, 0770); err != nil {
		t.Fatal(err)
	}
	if err := ensureNativeRepositoryCache(cache); err == nil {
		t.Fatal("accepted a shared cache directory")
	}
	if err := os.Chmod(cache, 0700); err != nil {
		t.Fatal(err)
	}
	build := func(context.Context, string, string, string) (*releasev1.ReleaseManifest, error) {
		return &releasev1.ReleaseManifest{SourceSha256: stockCacheDigest([]byte("a different captured source"))}, nil
	}
	if _, err := cachedNativeEnrollmentRepository(t.Context(), source, cache, releasebuild.SourceDigest, build); err == nil {
		t.Fatal("published a cache entry after its source changed")
	}
	entries, err := os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatal("retained failed build output or published a changed-source entry")
		}
	}
}

func stockCacheDirectory(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, "cache")
}

func TestStockCacheRefusesReplaceableAncestorAndUsesOSCache(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0775); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(parent, "cache")
	if err := ensureNativeRepositoryCache(cache); err == nil {
		t.Fatal("accepted private signing cache beneath a replaceable ancestor")
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := ensureNativeRepositoryCache(cache); err != nil {
		t.Fatalf("protected cache remained unusable: %v", err)
	}
	t.Setenv("XDG_CACHE_HOME", parent)
	actual, err := nativeRepositoryCacheDirectory()
	expected := filepath.Join(parent, "lindm", "lab", "agent-repositories")
	if err != nil || actual != expected {
		t.Fatalf("cache is not independent of worktree ancestry: got %q, want %q: %v", actual, expected, err)
	}
}

// The cache key follows the artifact inputs, not the tree: a change outside
// them reuses the entry whose manifest names the tree it was built from, and
// an entry no longer bound to its input digest is refused, never rebuilt.
func TestStockRepositoryCacheKeysOnArtifactInputs(t *testing.T) {
	source, cache := stockCacheSource(t), stockCacheDirectory(t)
	inputs := func(_ context.Context, source string) (string, error) {
		body, err := os.ReadFile(filepath.Join(source, "source.go"))
		return stockCacheDigest(body), err
	}
	builds := 0
	build := func(ctx context.Context, source, bundle, _ string) (*releasev1.ReleaseManifest, error) {
		builds++
		digest, err := releasebuild.SourceDigest(ctx, source)
		if err != nil {
			return nil, err
		}
		return stockCacheSignedFixture(t, bundle, digest), nil
	}
	first, err := cachedNativeEnrollmentRepository(t.Context(), source, cache, inputs, build)
	if err != nil || first.hit {
		t.Fatalf("cold cache: %v", err)
	}
	if err := os.WriteFile(filepath.Join(source, "console.tsx"), []byte("console-only change\n"), 0644); err != nil {
		t.Fatal(err)
	}
	reused, err := cachedNativeEnrollmentRepository(t.Context(), source, cache, inputs, build)
	if err != nil || !reused.hit || reused.directory != first.directory || builds != 1 {
		t.Fatalf("non-input change rebuilt the artifact: %v; builds=%d", err, builds)
	}
	if reused.manifest.GetSourceSha256() != first.manifest.GetSourceSha256() {
		t.Fatal("reused manifest does not name the tree it was built from")
	}
	if err := os.WriteFile(first.directory+".inputs", []byte(stockCacheDigest([]byte("other inputs"))), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := cachedNativeEnrollmentRepository(t.Context(), source, cache, inputs, build); err == nil || builds != 1 {
		t.Fatal("entry bound to other inputs was admitted or silently rebuilt")
	}
	if err := os.Remove(first.directory + ".inputs"); err != nil {
		t.Fatal(err)
	}
	if _, err := cachedNativeEnrollmentRepository(t.Context(), source, cache, inputs, build); err == nil || builds != 1 {
		t.Fatal("unbound entry was admitted or silently rebuilt")
	}
}
