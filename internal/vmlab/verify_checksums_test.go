// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
)

func sha512ChecksumText(m *labv1.ImageManifest, image []byte) string {
	digest := sha512.Sum512(image)
	return fmt.Sprintf("%x  %s\n", digest, m.ImageFilename)
}

func TestVerifyArtifactsSHA512AuthenticatesImageNotJustPin(t *testing.T) {
	fixture := newSigningFixture(t)
	image := []byte("Debian image fixture\n")
	original := testManifest(image, fixture.primary, labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_SHA512)
	text := sha512ChecksumText(original, image)
	for _, test := range []struct {
		name string
		text string
		want string
	}{
		{"text mode", text, ""},
		{"binary mode", strings.Replace(text, "  ", " *", 1), ""},
		{"CRLF", strings.ReplaceAll(text, "\n", "\r\n"), ""},
		{"wrong signed digest", strings.Repeat("0", 128) + "  " + original.ImageFilename + "\n", "signed SHA-512"},
		{"SHA256 downgrade", original.Sha256 + "  " + original.ImageFilename + "\n", "malformed SHA512SUMS"},
		{"nonhex digest", strings.Repeat("z", 128) + "  " + original.ImageFilename + "\n", "invalid SHA512 digest"},
		{"bad separator", strings.Replace(text, "  ", " x", 1), "malformed SHA512SUMS"},
		{"malformed unrelated record", text + "bad metadata\n", "malformed SHA512SUMS"},
		{"conflicting duplicate", text + strings.Repeat("0", 128) + "  " + original.ImageFilename + "\n", "exactly one record"},
	} {
		t.Run(test.name, func(t *testing.T) {
			checksum, signature := fixture.signed(t, original, test.text)
			_, err := VerifyArtifacts(context.Background(), original, writeArtifacts(t, image, checksum, signature, fixture.key))
			if test.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("want rejection %q, got %v", test.want, err)
			}
		})
	}
	t.Run("attacker repins replacement image", func(t *testing.T) {
		payload := bytes.Clone(image)
		payload[0] ^= 1
		m := proto.CloneOf(original)
		digest := sha256.Sum256(payload)
		m.Sha256 = hex.EncodeToString(digest[:])
		checksum, signature := fixture.signed(t, m, text)
		if _, err := VerifyArtifacts(context.Background(), m, writeArtifacts(t, payload, checksum, signature, fixture.key)); err == nil || !strings.Contains(err.Error(), "signed SHA-512") {
			t.Fatalf("SHA256 pin bypassed vendor SHA512 authentication: %v", err)
		}
	})
}

func TestSHA512ManifestRequiresExplicitTrust(t *testing.T) {
	original := testManifest([]byte("image"), strings.Repeat("A", 40), labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_SHA512)
	if err := validateManifest(original); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*labv1.ImageManifest)
	}{
		{"signature", func(m *labv1.ImageManifest) { m.SignatureUrl = nil }},
		{"key", func(m *labv1.ImageManifest) { m.KeyUrl = "" }},
		{"fingerprint", func(m *labv1.ImageManifest) { m.SignerFingerprint = "" }},
		{"provenance", func(m *labv1.ImageManifest) { m.SignerProvenanceUrl = "" }},
		{"SHA256 pin", func(m *labv1.ImageManifest) { m.Sha256 = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := proto.CloneOf(original)
			test.change(m)
			if err := validateManifest(m); err == nil {
				t.Fatal("incomplete SHA512 trust accepted")
			}
		})
	}
}

func TestVerifyArtifactsDetachedBSDChecksum(t *testing.T) {
	fixture := newSigningFixture(t)
	image := []byte("Rocky image fixture\n")
	m := testManifest(image, fixture.primary, labv1.ChecksumMode_CHECKSUM_MODE_DETACHED)
	text := fmt.Sprintf("# %s: %d bytes\nSHA256 (%s) = %s\n", m.ImageFilename, len(image), m.ImageFilename, m.Sha256)
	for _, test := range []struct {
		name string
		text string
		pass bool
	}{
		{"signed BSD", text, true},
		{"wrong digest", strings.Replace(text, m.Sha256, strings.Repeat("0", 64), 1), false},
		{"duplicate formats", text + checksumText(m), false},
		{"wrong algorithm", strings.Replace(text, "SHA256 (", "SHA512 (", 1), false},
		{"malformed separator", strings.Replace(text, ") = ", ")=", 1), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			checksum, signature := fixture.signed(t, m, test.text)
			_, err := VerifyArtifacts(context.Background(), m, writeArtifacts(t, image, checksum, signature, fixture.key))
			if (err == nil) != test.pass {
				t.Fatalf("pass=%t: %v", test.pass, err)
			}
		})
	}
}

func TestFetchSHA512PublishesOnlyAuthenticatedSHA256Cache(t *testing.T) {
	fixture := newSigningFixture(t)
	image := []byte("cached Debian image fixture\n")
	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("signed_digest_mismatch=%t", mismatch), func(t *testing.T) {
			m := testManifest(image, fixture.primary, labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_SHA512)
			signedImage := bytes.Clone(image)
			if mismatch {
				signedImage[0] ^= 1
			}
			checksums, signature := fixture.signed(t, m, sha512ChecksumText(m, signedImage))
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/image.qcow2":
					_, _ = w.Write(image)
				case "/checksums":
					_, _ = w.Write(checksums)
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
			fetcher := Fetcher{transport: server.Client().Transport}
			cache := filepath.Join(t.TempDir(), "images")
			entry := "sha256-" + m.Sha256
			result, err := fetcher.Fetch(context.Background(), m, cache)
			if mismatch {
				if err == nil || !strings.Contains(err.Error(), "signed SHA-512") {
					t.Fatalf("unauthenticated image accepted: %v", err)
				}
				for _, name := range []string{entry, "." + entry + ".partial"} {
					if _, err := os.Stat(filepath.Join(cache, name)); !errors.Is(err, fs.ErrNotExist) {
						t.Fatalf("unauthenticated image left %s: %v", name, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.Path != filepath.Join(cache, entry, "image") || result.SHA256 != m.Sha256 || result.SigningFingerprint != fixture.subkey {
				t.Fatalf("incorrect cache identity/evidence: %+v", result)
			}
			server.Close()
			for _, verify := range []func() (*VerifiedImage, error){
				func() (*VerifiedImage, error) { return VerifyCache(context.Background(), m, cache) },
				func() (*VerifiedImage, error) { return fetcher.Fetch(context.Background(), m, cache) },
			} {
				if cached, err := verify(); err != nil || cached.Path != result.Path {
					t.Fatalf("offline signed SHA512 cache reuse: %v", err)
				}
			}
			// A valid new signature for the same filename must still match image bytes.
			changed := bytes.Clone(image)
			changed[0] ^= 1
			checksums, signature = fixture.signed(t, m, sha512ChecksumText(m, changed))
			for name, data := range map[string][]byte{"checksums": checksums, "signature": signature} {
				path := filepath.Join(cache, entry, name)
				if err := os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := VerifyCache(context.Background(), m, cache); err == nil || !strings.Contains(err.Error(), "signed SHA-512") {
				t.Fatalf("offline verification ignored signed SHA512: %v", err)
			}
		})
	}
}
