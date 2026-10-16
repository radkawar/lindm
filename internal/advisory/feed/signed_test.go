// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func TestRetainedVendorDetachedSignatures(t *testing.T) {
	trust, err := newVendorTrust()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 10, 23, 59, 59, 0, time.UTC)
	for _, test := range []struct {
		file, basename, fingerprint, digest string
	}{
		{"redhat-rhsa-2024_6783.json", "rhsa-2024_6783.json", redHatFingerprint, "a1b1b6751e159378b0ccf5a96c3e4ccee2d36e36dfd5de156e479a72274cbe92"},
		{"redhat-cve-2024-6119.json", "cve-2024-6119.json", redHatFingerprint, "a488c851437a9eb0616c3103787e1372e9cac1f3f7ea79ab2cadc7336c8f91be"},
		{"redhat-rhsa-2024_7846.json", "rhsa-2024_7846.json", redHatFingerprint, "2aa634dc4055d4966b63f5389bfbd46f0c554ba6abff9e994e4da660c14b8388"},
		{"redhat-rhsa-2024_1880.json", "rhsa-2024_1880.json", redHatFingerprint, "10fc03ff1284b4de59d03761b1d573c6028184b9ce1f7882554937c05be844bf"},
		{"redhat-cve-2024-21892.json", "cve-2024-21892.json", redHatFingerprint, "01061605d2ea43fe8c982e1e0a5092ee59edcc84ef52cad1c1de594f22dc43a8"},
		{"suse-suse-su-2024_2275-1.json", "suse-su-2024_2275-1.json", suseFingerprint, "066aadd6f0472b23a2025c3f69ebfe4c0ba8dac9c550905ad029cbd929cff71c"},
		{"suse-opensuse-su-2024_11460-1.json", "opensuse-su-2024_11460-1.json", suseFingerprint, "0de87daf06b54274658b2dfafb20f8e42066a6fbc67eaa1eeef0d2fde4b28166"},
	} {
		t.Run(test.file, func(t *testing.T) {
			raw := fixture(t, test.file)
			signature := fixture(t, test.file+".asc")
			checksum, err := vendorChecksum(fixture(t, test.file+".sha256"), "https://mirror.example/"+test.basename)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(raw)
			if !bytes.Equal(checksum, digest[:]) || hex.EncodeToString(digest[:]) != test.digest {
				t.Fatal("retained vendor checksum does not match exact source bytes")
			}
			signer, signedAt, err := trust.verify(t.Context(), test.fingerprint, bytes.NewReader(raw), signature, now)
			if err != nil {
				t.Fatal(err)
			}
			if signer != test.fingerprint || !signedAt.Equal(signatureCreation(t, signature)) || signedAt.IsZero() || !signedAt.Before(now) {
				t.Fatalf("incorrect signature provenance: signer=%s time=%s", signer, signedAt)
			}
			wrong := redHatFingerprint
			if test.fingerprint == redHatFingerprint {
				wrong = suseFingerprint
			}
			for _, invalid := range []struct {
				name        string
				payload     []byte
				proof       []byte
				fingerprint string
				now         time.Time
			}{
				{"changed-payload", append(bytes.Clone(raw), '\n'), signature, test.fingerprint, now},
				{"truncated-payload", raw[:len(raw)-1], signature, test.fingerprint, now},
				{"signature-bitflip", raw, flippedSignature(t, signature), test.fingerprint, now},
				{"truncated-signature", raw, signature[:len(signature)/2], test.fingerprint, now},
				{"extra-signature", raw, append(bytes.Clone(signature), signature...), test.fingerprint, now},
				{"wrong-vendor", raw, signature, wrong, now},
				{"future-time", raw, signature, test.fingerprint, signedAt.Add(-time.Second)},
				{"missing-time", raw, signature, test.fingerprint, time.Time{}},
				{"oversized-proof", raw, bytes.Repeat([]byte("a"), maxProofBytes+1), test.fingerprint, now},
			} {
				t.Run(invalid.name, func(t *testing.T) {
					_, _, err := trust.verify(t.Context(), invalid.fingerprint, bytes.NewReader(invalid.payload), invalid.proof, invalid.now)
					if err == nil {
						t.Fatal("unauthenticated bytes accepted")
					}
					if invalid.name == "signature-bitflip" && !strings.Contains(err.Error(), "verify vendor signature") {
						t.Fatalf("signature mutation did not reach cryptographic verification: %v", err)
					}
				})
			}
		})
	}
}

func signatureCreation(t *testing.T, proof []byte) time.Time {
	t.Helper()
	block, err := armor.Decode(bytes.NewReader(proof))
	if err != nil {
		t.Fatal(err)
	}
	p, err := packet.Read(block.Body)
	if err != nil {
		t.Fatal(err)
	}
	signature, ok := p.(*packet.Signature)
	if !ok {
		t.Fatal("fixture is not a signature packet")
	}
	return signature.CreationTime
}

func TestVendorTrustRejectsCryptographicRevocation(t *testing.T) {
	// This ephemeral key exercises revocation policy, not a fabricated vendor
	// feed. It is never inserted into New's embedded production trust roots.
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	cryptoConfig := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: func() time.Time { return now.Add(-time.Hour) }}
	key, err := openpgp.NewEntity("Revocation policy test", "", "test@example.invalid", cryptoConfig)
	if err != nil {
		t.Fatal(err)
	}
	var signature bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&signature, []*openpgp.Entity{key}, strings.NewReader("revocation policy"), &openpgp.SignParams{Config: cryptoConfig}); err != nil {
		t.Fatal(err)
	}
	trust := &vendorTrust{redHat: openpgp.EntityList{key}}
	_, _, err = trust.verify(t.Context(), redHatFingerprint, strings.NewReader("revocation policy"), signature.Bytes(), now)
	if err == nil || !strings.Contains(err.Error(), "wrong vendor signer") {
		t.Fatalf("valid but unpinned test key was not refused: %v", err)
	}
	if err := key.Revoke(packet.KeyCompromised, "test revocation", cryptoConfig); err != nil {
		t.Fatal(err)
	}
	_, _, err = trust.verify(t.Context(), redHatFingerprint, strings.NewReader("revocation policy"), signature.Bytes(), now)
	if !errors.Is(err, pgperrors.ErrKeyRevoked) {
		t.Fatalf("cryptographically revoked key not rejected by verifier: %v", err)
	}
}

func TestSignedCSAFTLSAcquisition(t *testing.T) {
	for _, test := range []struct {
		file, basename, distro, release, fingerprint string
		format                                       advisoryv1.FeedFormat
	}{
		{"redhat-rhsa-2024_6783.json", "rhsa-2024_6783.json", "rhel", "9.4", redHatFingerprint, advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF},
		{"suse-suse-su-2024_2275-1.json", "suse-su-2024_2275-1.json", "sles", "15.6", suseFingerprint, advisoryv1.FeedFormat_FEED_FORMAT_SUSE_CSAF},
	} {
		t.Run(test.distro, func(t *testing.T) {
			raw := fixture(t, test.file)
			checksum := fixture(t, test.file+".sha256")
			signature := fixture(t, test.file+".asc")
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Header.Get("Accept-Encoding") != "identity" {
					t.Error("signed bytes requested with content transformation")
				}
				var response []byte
				switch r.URL.Path {
				case "/" + test.basename:
					response = raw
				case "/" + test.basename + ".sha256":
					response = checksum
				case "/" + test.basename + ".asc":
					response = signature
				default:
					http.NotFound(w, r)
					return
				}
				if _, err := w.Write(response); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			client, err := New(server.Client())
			if err != nil {
				t.Fatal(err)
			}
			config := source(test.distro, test.release, test.format)
			config.Url = server.URL + "/" + test.basename
			acquire := func() ([]byte, *advisoryv1.FeedArtifact, time.Time, error) {
				if config.GetFormat() != advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF {
					return client.fetchSignedCSAF(t.Context(), config)
				}
				var got []byte
				artifact, signedAt, err := client.consumeSignedCSAF(t.Context(), config, func(file *os.File) error {
					var err error
					got, err = boundedRead(file, redHatRecordBytes)
					return err
				})
				return got, artifact, signedAt, err
			}
			got, artifact, signedAt, err := acquire()
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(raw)
			if !bytes.Equal(got, raw) || artifact.GetUrl() != config.GetUrl() || !bytes.Equal(artifact.GetSha256(), digest[:]) || artifact.GetSignerFingerprint() != test.fingerprint || !signedAt.Equal(signatureCreation(t, signature)) || requests.Load() != 3 {
				t.Fatalf("lost authenticated source provenance: %v %s requests=%d", artifact, signedAt, requests.Load())
			}
			if test.distro == "rhel" {
				t.Run("separate ownership", func(t *testing.T) {
					assertSeparateSignedCSAF(t, client, config.GetUrl(), raw, signedAt)
				})
			}
			config.ExpectedSha256 = make([]byte, sha256.Size)
			if _, _, _, err := acquire(); err == nil {
				t.Fatal("incorrect out-of-band pin accepted")
			}
			config.Url = strings.Replace(config.Url, "https://", "http://", 1)
			before := requests.Load()
			if _, _, _, err := acquire(); err == nil || requests.Load() != before {
				t.Fatal("HTTP source bypassed signing/TLS policy")
			}
		})
	}
}

func assertSeparateSignedCSAF(t *testing.T, client *Client, location string, raw []byte, signedAt time.Time) {
	t.Helper()
	directory := t.TempDir()
	t.Setenv("TMPDIR", directory)
	config := source("rhel", "9.4", advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF)
	config.Url = location
	var verified verifiedCSAF
	t.Cleanup(func() {
		if err := verified.close(); err != nil {
			t.Error(err)
		}
	})
	if err := client.acquireSignedCSAF(t.Context(), config, &verified); err != nil {
		t.Fatal(err)
	}
	if verified.file == nil || verified.artifact.GetUrl() != location || !verified.signedAt.Equal(signedAt) {
		t.Fatal("separate acquisition lost authenticated ownership or provenance")
	}
	name := verified.file.Name()
	got, err := boundedRead(verified.file, redHatRecordBytes)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("authenticated payload was not rewound: %v", err)
	}
	if err := verified.close(); err != nil {
		t.Fatal(err)
	}
	if verified.file != nil || verified.artifact != nil || !verified.signedAt.IsZero() {
		t.Fatal("closed acquisition retained ownership or usable provenance")
	}
	if err := verified.close(); err != nil {
		t.Fatalf("close is not idempotent: %v", err)
	}
	if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("closed acquisition retained its private file: %v", err)
	}

	parseFailure := errors.New("normalization refused")
	artifact, at, err := client.consumeSignedCSAF(t.Context(), config, func(*os.File) error { return parseFailure })
	if !errors.Is(err, parseFailure) || artifact != nil || !at.IsZero() {
		t.Fatalf("normalization failure retained usable provenance: %v", err)
	}
	artifact, at, err = client.consumeSignedCSAF(t.Context(), config, func(file *os.File) error { return file.Close() })
	if err == nil || artifact != nil || !at.IsZero() {
		t.Fatalf("cleanup failure retained usable provenance: %v", err)
	}
	config.ExpectedSha256 = make([]byte, sha256.Size)
	if err := client.acquireSignedCSAF(t.Context(), config, &verified); err == nil || verified.file != nil || verified.artifact != nil || !verified.signedAt.IsZero() {
		t.Fatalf("rejected pin retained private ownership: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := client.acquireSignedCSAF(ctx, config, &verified); !errors.Is(err, context.Canceled) || verified.file != nil {
		t.Fatalf("canceled acquisition retained private ownership: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed acquisitions leaked private staging files: entries=%d error=%v", len(entries), err)
	}
}

func TestSignedProofAndPublisherRefusals(t *testing.T) {
	checksum := fixture(t, "redhat-rhsa-2024_6783.json.sha256")
	location := "https://mirror.example/rhsa-2024_6783.json"
	for _, bad := range [][]byte{
		nil,
		append(bytes.Clone(checksum), checksum...),
		bytes.Replace(checksum, []byte("rhsa-2024_6783.json"), []byte("../rhsa-2024_6783.json"), 1),
		bytes.Replace(checksum, []byte("rhsa-2024_6783.json"), []byte("cve-2024-6119.json"), 1),
		bytes.Replace(checksum, []byte("a1b1"), []byte("zzzz"), 1),
		bytes.Repeat([]byte("a"), maxProofBytes+1),
	} {
		if _, err := vendorChecksum(bad, location); err == nil {
			t.Fatal("invalid vendor checksum record accepted")
		}
	}
	for _, config := range []*advisoryv1.FeedSource{
		nil,
		source("sles", "15.6", advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF),
		source("rhel", "9", advisoryv1.FeedFormat_FEED_FORMAT_SUSE_CSAF),
		source("rocky", "9", advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF_ARCHIVES),
		source("rhel", "9", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON),
	} {
		if _, err := signedPublisher(config); err == nil {
			t.Fatal("source selected an unrelated vendor trust root")
		}
	}
}

func TestRedHatArchivePointerConfinement(t *testing.T) {
	for _, distribution := range []string{"advisories", "vex"} {
		name := "csaf_" + distribution + "_2026-10-04.tar.zst"
		if got, err := redHatArchiveName([]byte(name+"\n"), distribution); err != nil || got != name {
			t.Fatalf("valid archive basename rejected: %q %v", got, err)
		}
		for _, bad := range []string{"", "../" + name, "/" + name, "https://evil.example/" + name, name + "?x=1", name + "\n" + name, " " + name, strings.Replace(name, "10-04", "02-31", 1), strings.Replace(name, distribution, "other", 1), strings.Replace(name, "2026", "%2e%2e", 1)} {
			if _, err := redHatArchiveName([]byte(bad), distribution); err == nil {
				t.Fatalf("unconfined archive pointer accepted: %q", bad)
			}
		}
	}
}

func TestArchiveStreamingBoundAndCancellation(t *testing.T) {
	for _, test := range []struct {
		input string
		ok    bool
	}{
		{"abc", true},
		{"abcd", true},
		{"abcde", false},
		{"abcdef", false},
	} {
		var output bytes.Buffer
		err := copyArchive(t.Context(), &output, strings.NewReader(test.input), 4)
		if (err == nil) != test.ok || output.Len() > 4 {
			t.Fatalf("archive bound failed for %q: bytes=%d err=%v", test.input, output.Len(), err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var output bytes.Buffer
	if err := copyArchive(ctx, &output, strings.NewReader("archive"), 4); !errors.Is(err, context.Canceled) || output.Len() != 0 {
		t.Fatalf("canceled stream wrote bytes: %d %v", output.Len(), err)
	}
}

func TestRedHatArchiveAcquisitionAndCleanup(t *testing.T) {
	// Genuine vendor-signed JSON is served under archive-shaped transport names
	// solely to exercise acquisition. The callback compares exact bytes rather
	// than pretending this fixture is a vendor tar.zst or testing the parser.
	raw := fixture(t, "redhat-rhsa-2024_6783.json")
	vex := fixture(t, "redhat-cve-2024-6119.json")
	signature := fixture(t, "redhat-rhsa-2024_6783.json.asc")
	vexSignature := fixture(t, "redhat-cve-2024-6119.json.asc")
	signedAt := signatureCreation(t, signature)
	vexSignedAt := signatureCreation(t, vexSignature)
	oldest := signedAt
	if vexSignedAt.Before(oldest) {
		oldest = vexSignedAt
	}
	consumerFailure := errors.New("archive consumer failure")
	for _, mode := range []string{"success", "checksum", "signature", "second-signature", "payload", "consumer", "canceled", "oversized", "encoding", "missing-proof", "oversized-proof", "truncated", "http-error"} {
		t.Run(mode, func(t *testing.T) {
			tempDir := t.TempDir()
			t.Setenv("TMPDIR", tempDir)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var retryCounter atomic.Int64
			ctx = WithRetryCounter(ctx, &retryCounter)
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				distribution := "advisories"
				payload, proof := raw, signature
				if strings.HasPrefix(r.URL.Path, "/provider/vex/") {
					distribution = "vex"
					payload, proof = vex, vexSignature
				}
				name := "csaf_" + distribution + "_2026-10-04.tar.zst"
				var response []byte
				switch r.URL.Path {
				case "/provider/" + distribution + "/archive_latest.txt":
					response = []byte(name + "\n")
				case "/provider/" + distribution + "/" + name + ".sha256":
					digest := sha256.Sum256(payload)
					if mode == "checksum" {
						digest[0] ^= 1
					}
					// Only the transport basename differs from the original
					// published checksum; payload and signature stay genuine.
					response = fmt.Appendf(nil, "%x  %s\n", digest, name)
				case "/provider/" + distribution + "/" + name + ".asc":
					if mode == "missing-proof" {
						http.NotFound(w, r)
						return
					}
					response = proof
					if mode == "signature" || (mode == "second-signature" && distribution == "vex") {
						response = flippedSignature(t, proof)
					}
					if mode == "oversized-proof" {
						response = bytes.Repeat([]byte("a"), maxProofBytes+1)
					}
				case "/provider/" + distribution + "/" + name:
					response = payload
					switch mode {
					case "payload":
						response = append(bytes.Clone(payload), '\n')
					case "oversized":
						w.Header().Set("Content-Length", fmt.Sprint(maxArchiveBytes+1))
						w.WriteHeader(http.StatusOK)
						return
					case "encoding":
						w.Header().Set("Content-Encoding", "gzip")
					case "canceled":
						cancel()
						return
					case "truncated":
						w.Header().Set("Content-Length", fmt.Sprint(len(payload)+10))
					case "http-error":
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
				default:
					t.Errorf("unexpected archive request %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				// Refusal cases may close transport before the handler finishes.
				if _, err := w.Write(response); err != nil && mode == "success" {
					t.Error(err)
				}
			}))
			defer server.Close()
			client, err := New(server.Client())
			if err != nil {
				t.Fatal(err)
			}
			clock := &redHatHTTPTestClock{time: time.Now()}
			client.httpRetry = &httpRetryPolicy{
				now: clock.now,
				wait: func(ctx context.Context, delay time.Duration) error {
					if err := ctx.Err(); err != nil {
						return err
					}
					clock.advance(delay)
					return nil
				},
			}
			config := source("rhel", "9.4", advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF_ARCHIVES)
			config.Url = server.URL + "/provider/"
			consumed := 0
			var heldReader io.Reader
			manifest, gotOldest, err := client.fetchRedHatArchives(ctx, config, func(reader io.Reader, location string, _ time.Time) error {
				consumed++
				heldReader = reader
				entries, err := os.ReadDir(tempDir)
				if err != nil {
					return err
				}
				if len(entries) != 1 {
					return fmt.Errorf("expected one owned staged archive, got %d", len(entries))
				}
				info, err := entries[0].Info()
				if err != nil {
					return err
				}
				if info.Mode().Perm() != 0600 {
					return fmt.Errorf("unsafe staged archive permissions: %v", info.Mode())
				}
				if mode == "consumer" {
					return consumerFailure
				}
				got, err := io.ReadAll(reader)
				if err != nil {
					return err
				}
				want := raw
				if strings.Contains(location, "/vex/") {
					want = vex
				}
				if !bytes.Equal(got, want) {
					return errors.New("callback did not receive rewound original signed bytes")
				}
				return nil
			})
			wantRetries := int64(0)
			if mode == "truncated" || mode == "http-error" {
				wantRetries = 4
				if requests.Load() != 8 {
					t.Fatalf("transient archive failure did not exhaust exactly five payload attempts: requests=%d", requests.Load())
				}
			}
			if retryCounter.Load() != wantRetries {
				t.Fatalf("archive retry attribution: mode=%s got=%d want=%d", mode, retryCounter.Load(), wantRetries)
			}
			if mode == "success" {
				if err != nil || consumed != 2 || len(manifest.GetArtifacts()) != 2 || requests.Load() != 8 || !gotOldest.Equal(oldest) {
					t.Fatalf("archive acquisition failed: %v consumed=%d requests=%d oldest=%s", err, consumed, requests.Load(), gotOldest)
				}
				for index, artifact := range manifest.GetArtifacts() {
					payload, distribution := raw, "advisories"
					if index == 1 {
						payload, distribution = vex, "vex"
					}
					digest := sha256.Sum256(payload)
					if !bytes.Equal(artifact.GetSha256(), digest[:]) || artifact.GetSignerFingerprint() != redHatFingerprint || path.Base(artifact.GetUrl()) != "csaf_"+distribution+"_2026-10-04.tar.zst" {
						t.Fatalf("incorrect archive provenance: %v", artifact)
					}
				}
			} else {
				if err == nil || manifest != nil || !gotOldest.IsZero() {
					t.Fatalf("failed archive published provenance: %v %s %v", manifest, gotOldest, err)
				}
				if mode == "consumer" {
					if !errors.Is(err, consumerFailure) || consumed != 1 {
						t.Fatalf("consumer failure lost: %v consumed=%d", err, consumed)
					}
				} else if mode == "second-signature" {
					if consumed != 1 {
						t.Fatalf("second archive failure consumed %d artifacts", consumed)
					}
				} else if consumed != 0 {
					t.Fatal("unauthenticated archive reached consumer")
				}
			}
			entries, readErr := os.ReadDir(tempDir)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("owned archive was not removed: %v %v", entries, readErr)
			}
			if heldReader != nil {
				if _, err := heldReader.Read(make([]byte, 1)); err == nil {
					t.Fatal("staged archive reader remained usable after return")
				}
			}
		})
	}
}

// Mutate the RSA signature integer, not OpenPGP framing. Changing iQIc to iQId
// only changes the packet's declared length (540 to 541); the signed body and
// signature integer remain identical, so that is not an authentication test.
func flippedSignature(t *testing.T, proof []byte) []byte {
	t.Helper()
	block, err := armor.Decode(bytes.NewReader(proof))
	if err != nil {
		t.Fatal(err)
	}
	binary, err := io.ReadAll(block.Body)
	if err != nil {
		t.Fatal(err)
	}
	packetReader := bytes.NewReader(binary)
	p, err := packet.Read(packetReader)
	if err != nil {
		t.Fatal(err)
	}
	signature, ok := p.(*packet.Signature)
	if !ok || signature.PubKeyAlgo != packet.PubKeyAlgoRSA || packetReader.Len() != 0 {
		t.Fatal("fixture must contain exactly one RSA signature packet")
	}
	binary[len(binary)-1] ^= 1
	var out bytes.Buffer
	writer, err := armor.Encode(&out, openpgp.SignatureType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(binary); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(proof, out.Bytes()) {
		t.Fatal("signature mutation changed no bytes")
	}
	return out.Bytes()
}
