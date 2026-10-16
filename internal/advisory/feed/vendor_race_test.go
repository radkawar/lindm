// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

type vendorRaceTestSet struct {
	payload, checksum, signature []byte
}

func vendorRaceTestSets(t *testing.T) (good, checksumRace, signatureRace vendorRaceTestSet) {
	t.Helper()
	good = vendorRaceTestSet{
		payload:   fixture(t, "redhat-rhsa-2024_6783.json"),
		checksum:  fixture(t, "redhat-rhsa-2024_6783.json.sha256"),
		signature: fixture(t, "redhat-rhsa-2024_6783.json.asc"),
	}
	// Inconsistent sets mix retained, authentic vendor publications. Recovery
	// serves the intact original fixture, never a fabricated repaired signature.
	checksumRace = vendorRaceTestSet{
		payload:   fixture(t, "redhat-rhsa-2024_7846.json"),
		checksum:  good.checksum,
		signature: fixture(t, "redhat-rhsa-2024_7846.json.asc"),
	}
	signatureRace = good
	signatureRace.signature = checksumRace.signature
	return good, checksumRace, signatureRace
}

func vendorRaceTestResource(request *http.Request) int {
	switch {
	case strings.HasSuffix(request.URL.Path, ".sha256"):
		return 0
	case strings.HasSuffix(request.URL.Path, ".asc"):
		return 1
	default:
		return 2
	}
}

func vendorRaceTestClient(t *testing.T, sets []vendorRaceTestSet, hook func(*http.Request, *http.Response)) (*Client, *[3]atomic.Int64) {
	t.Helper()
	var requests [3]atomic.Int64
	client, _, _ := httpRetryTestClient(t, func(request *http.Request) (*http.Response, error) {
		resource := vendorRaceTestResource(request)
		index := int(requests[resource].Add(1) - 1)
		if index >= len(sets) {
			t.Errorf("unexpected extra resource acquisition: resource=%d set=%d", resource, index)
			return nil, errors.New("unexpected resource acquisition")
		}
		set := sets[index]
		raw := [3][]byte{set.checksum, set.signature, set.payload}[resource]
		response := httpRetryTestResponse(request, raw, nil)
		if hook != nil {
			hook(request, response)
		}
		return response, nil
	})
	return client, &requests
}

func vendorRaceTestSource() *advisoryv1.FeedSource {
	config := redHatSource("9.4", "standard")
	config.Url = "https://mirror.example/rhsa-2024_6783.json"
	return config
}

func assertVendorRaceRequests(t *testing.T, requests *[3]atomic.Int64, want [3]int64) {
	t.Helper()
	for resource, count := range want {
		if got := requests[resource].Load(); got != count {
			t.Errorf("resource %d fetched %d times, want %d", resource, got, count)
		}
	}
}

func assertVendorRaceCleanup(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Errorf("staged files leaked: entries=%d err=%v", len(entries), err)
	}
}

func TestVendorRaceFreshSets(t *testing.T) {
	good, checksumRace, signatureRace := vendorRaceTestSets(t)
	for _, test := range []struct {
		name    string
		sets    []vendorRaceTestSet
		failure string
	}{
		{"initial-checksum-race", []vendorRaceTestSet{checksumRace, good}, ""},
		{"initial-signature-race", []vendorRaceTestSet{signatureRace, good}, ""},
		{"first-and-second-inconsistent", []vendorRaceTestSet{checksumRace, signatureRace, good}, ""},
		{"persistent-checksum-mismatch", []vendorRaceTestSet{checksumRace, checksumRace, checksumRace}, "vendor CSAF checksum mismatch"},
		{"persistent-signature-mismatch", []vendorRaceTestSet{signatureRace, signatureRace, signatureRace}, "verify vendor signature"},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			t.Setenv("TMPDIR", directory)
			client, requests := vendorRaceTestClient(t, test.sets, nil)
			var refetches, retries atomic.Int64
			ctx := WithRetryCounter(WithVendorRaceRefetchCounter(t.Context(), &refetches), &retries)
			calls := 0
			artifact, signedAt, err := client.consumeSignedCSAF(ctx, vendorRaceTestSource(), func(file *os.File) error {
				calls++
				offset, err := file.Seek(0, io.SeekCurrent)
				if err != nil || offset != 0 {
					return fmt.Errorf("verified file not rewound: offset=%d err=%v", offset, err)
				}
				raw, err := io.ReadAll(file)
				if err == nil && !bytes.Equal(raw, good.payload) {
					return errors.New("stale or mixed-set payload reached parser")
				}
				return err
			})
			sets := int64(len(test.sets))
			assertVendorRaceRequests(t, requests, [3]int64{sets, sets, sets})
			if refetches.Load() != sets-1 || retries.Load() != 0 {
				t.Fatalf("wrong accounting: refetches=%d HTTP retries=%d", refetches.Load(), retries.Load())
			}
			if test.failure != "" {
				if err == nil || !strings.Contains(err.Error(), test.failure) || artifact != nil || !signedAt.IsZero() || calls != 0 {
					t.Fatalf("rejected set reached normalization/publication: calls=%d artifact=%v time=%s err=%v", calls, artifact, signedAt, err)
				}
			} else {
				digest := sha256.Sum256(good.payload)
				if err != nil || calls != 1 || !bytes.Equal(artifact.GetSha256(), digest[:]) || artifact.GetSignerFingerprint() != redHatFingerprint || !signedAt.Equal(signatureCreation(t, good.signature)) {
					t.Fatalf("verified set lost provenance: calls=%d artifact=%v time=%s err=%v", calls, artifact, signedAt, err)
				}
			}
			assertVendorRaceCleanup(t, directory)
		})
	}
}

func TestVendorRaceTerminalFailures(t *testing.T) {
	good, checksumRace, _ := vendorRaceTestSets(t)
	parseFailure := errors.New("document validation refused")
	for _, name := range []string{"operator-pin", "pin-and-vendor-checksum", "TLS-identity", "already-canceled", "cancel-after-payload", "deadline", "watchdog", "overall-ceiling", "storage", "document-validation", "malformed-proof", "untrusted-signer", "invalid-source"} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			t.Setenv("TMPDIR", directory)
			config := vendorRaceTestSource()
			set := good
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var transportErr error
			var wantErr error
			wantRequests := [3]int64{1, 1, 1}
			wantParses := 0
			switch name {
			case "operator-pin", "pin-and-vendor-checksum":
				config.ExpectedSha256 = make([]byte, sha256.Size)
				if name == "pin-and-vendor-checksum" {
					set = checksumRace
				}
			case "TLS-identity":
				transportErr = x509.UnknownAuthorityError{Cert: &x509.Certificate{}}
				wantErr = transportErr
				wantRequests = [3]int64{1, 0, 0}
			case "already-canceled":
				cancel()
				wantErr = context.Canceled
				wantRequests = [3]int64{}
			case "cancel-after-payload":
				set = checksumRace
				wantErr = context.Canceled
			case "deadline":
				var expired context.CancelFunc
				ctx, expired = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer expired()
				wantErr = context.DeadlineExceeded
				wantRequests = [3]int64{}
			case "watchdog":
				transportErr = ErrRefreshStalled
				wantErr = transportErr
				wantRequests = [3]int64{1, 0, 0}
			case "overall-ceiling":
				transportErr = ErrRefreshCeiling
				wantErr = transportErr
				wantRequests = [3]int64{1, 0, 0}
			case "storage":
				t.Setenv("TMPDIR", directory+"/missing")
				wantRequests = [3]int64{1, 1, 0}
			case "document-validation":
				wantParses = 1
				wantErr = parseFailure
			case "malformed-proof":
				set.signature = good.signature[:len(good.signature)/2]
			case "untrusted-signer":
				set.signature = fixture(t, "suse-suse-su-2024_2275-1.json.asc")
			case "invalid-source":
				config.Distro = "sles"
				wantRequests = [3]int64{}
			}
			client, requests := vendorRaceTestClient(t, []vendorRaceTestSet{set}, func(request *http.Request, response *http.Response) {
				if name == "cancel-after-payload" && vendorRaceTestResource(request) == 2 {
					httpRetryTestResponseBody(t, response).close = func() error { cancel(); return nil }
				}
			})
			if transportErr != nil {
				client.http.Transport = redHatHTTPTestTransport(func(*http.Request) (*http.Response, error) {
					requests[0].Add(1)
					return nil, transportErr
				})
			}
			var refetches, retries atomic.Int64
			ctx = WithRetryCounter(WithVendorRaceRefetchCounter(ctx, &refetches), &retries)
			parses := 0
			artifact, signedAt, err := client.consumeSignedCSAF(ctx, config, func(*os.File) error {
				parses++
				return parseFailure
			})
			if err == nil || artifact != nil || !signedAt.IsZero() || parses != wantParses || (wantErr != nil && !errors.Is(err, wantErr)) {
				t.Fatalf("terminal failure accepted: parses=%d artifact=%v time=%s err=%v", parses, artifact, signedAt, err)
			}
			if refetches.Load() != 0 || retries.Load() != 0 {
				t.Fatalf("terminal failure retried: refetches=%d HTTP retries=%d", refetches.Load(), retries.Load())
			}
			assertVendorRaceRequests(t, requests, wantRequests)
			assertVendorRaceCleanup(t, directory)
		})
	}
}

func TestVendorRaceUntrustedRevokedOrExpiredKeyNeverRefetches(t *testing.T) {
	good, _, _ := vendorRaceTestSets(t)
	for _, mode := range []string{"untrusted", "revoked", "expired"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().Add(-time.Hour)
			config := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: func() time.Time { return now }}
			if mode == "expired" {
				config.KeyLifetimeSecs = 60
			}
			key, err := openpgp.NewEntity("Trust policy test", "", "test@example.invalid", config)
			if err != nil {
				t.Fatal(err)
			}
			var proof bytes.Buffer
			if err := openpgp.ArmoredDetachSign(&proof, []*openpgp.Entity{key}, bytes.NewReader(good.payload), &openpgp.SignParams{Config: config}); err != nil {
				t.Fatal(err)
			}
			if mode == "revoked" {
				if err := key.Revoke(packet.KeyCompromised, "test revocation", config); err != nil {
					t.Fatal(err)
				}
			}
			set := good
			set.signature = proof.Bytes()
			client, requests := vendorRaceTestClient(t, []vendorRaceTestSet{set}, nil)
			// This ephemeral key tests rejection only; it cannot satisfy the
			// embedded production fingerprint and never repairs a vendor set.
			client.signedTrust = &vendorTrust{redHat: openpgp.EntityList{key}}
			var counter atomic.Int64
			artifact, at, err := client.consumeSignedCSAF(WithVendorRaceRefetchCounter(t.Context(), &counter), vendorRaceTestSource(), func(*os.File) error {
				t.Fatal("untrusted key reached normalization")
				return nil
			})
			if err == nil || artifact != nil || !at.IsZero() || counter.Load() != 0 {
				t.Fatalf("untrusted/revoked/expired key was retried or accepted: artifact=%v time=%s refetches=%d err=%v", artifact, at, counter.Load(), err)
			}
			assertVendorRaceRequests(t, requests, [3]int64{1, 1, 1})
			// Exercise current-key eligibility with this key's real identity,
			// independently of production's earlier pinned-root rejection.
			block, err := armor.Decode(bytes.NewReader(proof.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			p, err := packet.Read(block.Body)
			if err != nil {
				t.Fatal(err)
			}
			sig, ok := p.(*packet.Signature)
			if !ok {
				t.Fatalf("unexpected signature packet %T", p)
			}
			fingerprint := strings.ToUpper(hex.EncodeToString(key.PrimaryKey.Fingerprint))
			changed := bytes.NewReader(append(bytes.Clone(good.payload), '\n'))
			mismatch, err := vendorCryptoMismatch(t.Context(), openpgp.EntityList{key}, fingerprint, changed, sig, time.Now(), &packet.Config{})
			if err != nil || mismatch != (mode == "untrusted") {
				t.Fatalf("invalid current key became a refetchable crypto mismatch: mode=%s mismatch=%t err=%v", mode, mismatch, err)
			}
		})
	}
}

func TestVendorRaceHTTPRetriesHaveSeparateBudgets(t *testing.T) {
	good, checksumRace, _ := vendorRaceTestSets(t)
	sets := []vendorRaceTestSet{checksumRace, good}
	var requests [3]int
	client, _, _ := httpRetryTestClient(t, func(request *http.Request) (*http.Response, error) {
		resource := vendorRaceTestResource(request)
		attempt := requests[resource]
		requests[resource]++
		if attempt >= 4 {
			t.Fatal("extra set or HTTP attempt")
		}
		set := sets[attempt/2]
		raw := [3][]byte{set.checksum, set.signature, set.payload}[resource]
		response := httpRetryTestResponse(request, raw, nil)
		if attempt%2 == 0 {
			response.StatusCode = http.StatusServiceUnavailable
		}
		return response, nil
	})
	var refetches, retries atomic.Int64
	ctx := WithRetryCounter(WithVendorRaceRefetchCounter(t.Context(), &refetches), &retries)
	if _, _, err := client.consumeSignedCSAF(ctx, vendorRaceTestSource(), func(*os.File) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if requests != [3]int{4, 4, 4} || refetches.Load() != 1 || retries.Load() != 6 {
		t.Fatalf("conflated retry budgets: requests=%v sets=%d HTTP=%d", requests, refetches.Load(), retries.Load())
	}

	var failedRequests atomic.Int64
	client, _, _ = httpRetryTestClient(t, func(request *http.Request) (*http.Response, error) {
		failedRequests.Add(1)
		response := httpRetryTestResponse(request, nil, nil)
		response.StatusCode = http.StatusServiceUnavailable
		return response, nil
	})
	refetches.Store(0)
	retries.Store(0)
	if _, _, err := client.consumeSignedCSAF(ctx, vendorRaceTestSource(), func(*os.File) error {
		t.Fatal("failed HTTP reached parser")
		return nil
	}); err == nil {
		t.Fatal("persistent HTTP error accepted")
	}
	if failedRequests.Load() != 5 || retries.Load() != 4 || refetches.Load() != 0 {
		t.Fatalf("HTTP failure consumed vendor set budget: requests=%d HTTP=%d sets=%d", failedRequests.Load(), retries.Load(), refetches.Load())
	}
}

func TestVendorRaceCounterRefreshIsolation(t *testing.T) {
	good, checksumRace, _ := vendorRaceTestSets(t)
	base := t.Context()
	if WithVendorRaceRefetchCounter(base, nil) != base || VendorRaceRefetchCounter(base) != nil {
		t.Fatal("nil counter altered context or created accounting")
	}
	var first, second atomic.Int64
	firstCtx := WithVendorRaceRefetchCounter(base, &first)
	secondCtx := WithVendorRaceRefetchCounter(firstCtx, &second)
	if VendorRaceRefetchCounter(firstCtx) != &first || VendorRaceRefetchCounter(secondCtx) != &second || WithVendorRaceRefetchCounter(firstCtx, nil) != firstCtx {
		t.Fatal("counter crossed refresh context boundaries")
	}
	clients := make([]*Client, 2)
	for index := range clients {
		clients[index], _ = vendorRaceTestClient(t, []vendorRaceTestSet{checksumRace, good}, nil)
	}
	results := make(chan error, len(clients))
	for _, client := range clients {
		go func() {
			ctx, cancel := context.WithCancel(firstCtx)
			defer cancel()
			_, _, err := client.consumeSignedCSAF(ctx, vendorRaceTestSource(), func(*os.File) error { return nil })
			results <- err
		}()
	}
	for range clients {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if first.Load() != 2 || second.Load() != 0 {
		t.Fatalf("parallel child tasks lost refresh accounting: first=%d second=%d", first.Load(), second.Load())
	}
	client, _ := vendorRaceTestClient(t, []vendorRaceTestSet{good}, nil)
	if _, _, err := client.consumeSignedCSAF(secondCtx, vendorRaceTestSource(), func(*os.File) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if first.Load() != 2 || second.Load() != 0 {
		t.Fatal("initial set changed either refresh's refetch count")
	}
}

func TestVendorRaceDoesNotRefetchSUSEOrImmutableArchives(t *testing.T) {
	good, checksumRace, signatureRace := vendorRaceTestSets(t)
	for _, kind := range []string{"suse", "immutable-archive"} {
		for _, mismatch := range []string{"checksum", "signature"} {
			t.Run(kind+"/"+mismatch, func(t *testing.T) {
				directory := t.TempDir()
				t.Setenv("TMPDIR", directory)
				set := checksumRace
				if mismatch == "signature" {
					set = signatureRace
				}
				if kind == "suse" {
					set = vendorRaceTestSet{
						payload:   fixture(t, "suse-suse-su-2024_2275-1.json"),
						checksum:  fixture(t, "suse-suse-su-2024_2275-1.json.sha256"),
						signature: fixture(t, "suse-suse-su-2024_2275-1.json.asc"),
					}
					if mismatch == "checksum" {
						set.payload = good.payload
					} else {
						set.signature = fixture(t, "suse-opensuse-su-2024_11460-1.json.asc")
					}
				} else {
					// As in the existing archive transport tests, only the
					// checksum basename changes; this is not a tar parser test.
					set.checksum = bytes.Replace(set.checksum, []byte("rhsa-2024_6783.json"), []byte("csaf_advisories_2026-10-04.tar.zst"), 1)
				}
				client, requests := vendorRaceTestClient(t, []vendorRaceTestSet{set}, nil)
				var counter atomic.Int64
				ctx := WithVendorRaceRefetchCounter(t.Context(), &counter)
				var err error
				if kind == "suse" {
					config := source("sles", "15.6", advisoryv1.FeedFormat_FEED_FORMAT_SUSE_CSAF)
					config.Url = "https://mirror.example/suse-su-2024_2275-1.json"
					_, _, _, err = client.fetchSignedCSAF(ctx, config)
				} else {
					_, _, err = client.consumeSignedArchive(ctx, "https://mirror.example/csaf_advisories_2026-10-04.tar.zst", redHatFingerprint, func(io.Reader, string, time.Time) error {
						t.Fatal("inconsistent immutable archive reached parser")
						return nil
					})
				}
				if err == nil || counter.Load() != 0 {
					t.Fatalf("nonmutable/non-Red-Hat source was retried or accepted: refetches=%d err=%v", counter.Load(), err)
				}
				assertVendorRaceRequests(t, requests, [3]int64{1, 1, 1})
				assertVendorRaceCleanup(t, directory)
			})
		}
	}
}

func TestVendorRaceSignatureMismatchIsStructural(t *testing.T) {
	good, _, signatureRace := vendorRaceTestSets(t)
	trust, err := newVendorTrust()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		proof []byte
		now   time.Time
		want  bool
	}{
		{"cryptographic-mismatch", signatureRace.signature, time.Now(), true},
		{"signature-bitflip", flippedSignature(t, good.signature), time.Now(), true},
		{"malformed-proof", good.signature[:len(good.signature)/2], time.Now(), false},
		{"wrong-vendor", fixture(t, "suse-suse-su-2024_2275-1.json.asc"), time.Now(), false},
		{"future-signature", good.signature, signatureCreation(t, good.signature).Add(-time.Second), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := trust.verifySignature(t.Context(), redHatFingerprint, bytes.NewReader(good.payload), test.proof, test.now, true)
			var mismatch *vendorSignatureMismatch
			if err == nil || errors.As(err, &mismatch) != test.want {
				t.Fatalf("wrong typed mismatch classification: mismatch=%t want=%t err=%v", mismatch != nil, test.want, err)
			}
		})
	}
}
