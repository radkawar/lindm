// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
)

// imageSignature is a detached OpenPGP signature over the image bytes, as
// Omarchy publishes beside each ISO.
func (f signingFixture) imageSignature(t *testing.T, image []byte) []byte {
	t.Helper()
	return f.gpg(t, image, "--local-user", f.primary, "--digest-algo", "SHA512", "--output", "-", "--detach-sign")
}

func sidecarText(m *labv1.ImageManifest) []byte {
	return fmt.Appendf(nil, "%s  %s\n", m.Sha256, m.ImageFilename)
}

func TestVerifyArtifactsDetachedImageSignature(t *testing.T) {
	fixture := newSigningFixture(t)
	other := newSigningFixture(t)
	image := []byte("installer iso fixture bytes signed directly\n")
	original := testManifest(image, fixture.primary, labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_IMAGE)
	signature := fixture.imageSignature(t, image)
	t.Run("good signature over exact bytes", func(t *testing.T) {
		result, err := VerifyArtifacts(context.Background(), original, writeArtifacts(t, image, sidecarText(original), signature, fixture.key))
		if err != nil {
			t.Fatal(err)
		}
		if result.SigningFingerprint != fixture.subkey || result.PrimaryFingerprint != fixture.primary || result.SHA256 != original.Sha256 || result.Size != int64(len(image)) {
			t.Fatalf("incorrect verified image evidence: %+v", result)
		}
	})
	for _, failure := range []string{"bad signature", "wrong signer", "unrelated keyring", "truncated image", "truncated image with matching pin", "tampered image with matching pin", "missing signature", "sidecar disagrees", "sidecar names other file", "wrong pinned digest"} {
		t.Run(failure, func(t *testing.T) {
			m := proto.CloneOf(original)
			payload, sidecar, sig, key := bytes.Clone(image), sidecarText(m), bytes.Clone(signature), bytes.Clone(fixture.key)
			repin := func() {
				digest := sha256.Sum256(payload)
				m.Sha256, m.ImageSizeBytes = hex.EncodeToString(digest[:]), uint64(len(payload))
				sidecar = sidecarText(m)
			}
			switch failure {
			case "bad signature":
				sig = fixture.imageSignature(t, []byte("other bytes\n"))
			case "wrong signer":
				sig = other.imageSignature(t, image)
				key = append(key, other.key...)
			case "unrelated keyring":
				key = other.key
			case "truncated image":
				payload = payload[:len(payload)-1]
			case "truncated image with matching pin":
				payload = payload[:len(payload)-1]
				repin()
			case "tampered image with matching pin":
				payload[0] ^= 1
				repin()
			case "missing signature":
				sig = nil
			case "sidecar disagrees":
				sidecar = fmt.Appendf(nil, "%s  %s\n", strings.Repeat("0", 64), m.ImageFilename)
			case "sidecar names other file":
				sidecar = fmt.Appendf(nil, "%s  other.iso\n", m.Sha256)
			case "wrong pinned digest":
				m.Sha256 = strings.Repeat("0", 64)
				sidecar = sidecarText(m)
			}
			if _, err := VerifyArtifacts(context.Background(), m, writeArtifacts(t, payload, sidecar, sig, key)); err == nil {
				t.Fatal("unauthenticated image was accepted")
			}
		})
	}
}

func TestDetachedImageManifestRequiresExplicitTrust(t *testing.T) {
	original := testManifest([]byte("image"), strings.Repeat("A", 40), labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_IMAGE)
	if err := validateManifest(original); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*labv1.ImageManifest){
		"signature":   func(m *labv1.ImageManifest) { m.SignatureUrl = nil },
		"key":         func(m *labv1.ImageManifest) { m.KeyUrl = "" },
		"fingerprint": func(m *labv1.ImageManifest) { m.SignerFingerprint = "" },
		"provenance":  func(m *labv1.ImageManifest) { m.SignerProvenanceUrl = "" },
	} {
		t.Run(name, func(t *testing.T) {
			m := proto.CloneOf(original)
			change(m)
			if err := validateManifest(m); err == nil {
				t.Fatal("image-signature mode admitted missing trust input")
			}
		})
	}
}

// The cache reauthenticates the image signature offline on every reuse, not
// just the stored SHA-256 pin.
func TestFetchDetachedImageReauthenticatesCache(t *testing.T) {
	fixture := newSigningFixture(t)
	image := []byte("signed installer fetched once\n")
	m := testManifest(image, fixture.primary, labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_IMAGE)
	signature := fixture.imageSignature(t, image)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/image.qcow2":
			_, _ = w.Write(image)
		case "/checksums":
			_, _ = w.Write(sidecarText(m))
		case "/signature":
			_, _ = w.Write(signature)
		case "/key":
			_, _ = w.Write(fixture.key)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	setSources(m, server.URL)
	cache := filepath.Join(t.TempDir(), "images")
	fetched, err := (Fetcher{transport: server.Client().Transport}).Fetch(context.Background(), m, cache)
	if err != nil {
		t.Fatal(err)
	}
	if fetched.PrimaryFingerprint != fixture.primary {
		t.Fatalf("fetch did not report the image signer: %+v", fetched)
	}
	server.Close()
	if _, err := VerifyCache(context.Background(), m, cache); err != nil {
		t.Fatalf("offline reuse: %v", err)
	}
	stored := filepath.Join(cache, "sha256-"+m.Sha256, "signature")
	if err := os.Chmod(stored, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stored, fixture.imageSignature(t, []byte("different bytes\n")), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCache(context.Background(), m, cache); err == nil || !strings.Contains(err.Error(), "gpgv") {
		t.Fatalf("cache reuse trusted a signature over other bytes: %v", err)
	}
}
