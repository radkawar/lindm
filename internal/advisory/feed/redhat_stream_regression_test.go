package feed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func redHatSemanticClaims(t *testing.T, records []*advisoryv1.Advisory) []string {
	t.Helper()
	keys := make([]string, 0, len(records))
	for _, record := range records {
		raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, string(raw))
	}
	slices.Sort(keys)
	return keys
}

func TestRedHatStreamMatchesPinnedFixtureSemantics(t *testing.T) {
	validator := redHatValidator(t)
	for _, test := range []struct {
		fixture, release, stream, name, cve, fixed, module string
	}{
		{"rhsa-2024_6783", "9.4", "standard", "openssl-libs", "CVE-2024-6119", "1:3.0.7-28.el9_4", ""},
		{"rhsa-2024_6783", "9.8", "standard", "openssl-libs", "CVE-2024-6119", "1:3.0.7-28.el9_4", ""},
		{"rhsa-2024_7846", "8.6", "e4s", "openssl-libs", "CVE-2024-5535", "1:1.1.1k-14.el8_6", ""},
		{"rhsa-2024_1880", "8.8", "eus", "nodejs", "CVE-2023-46809", "1:18.19.1-1.module+el8.8.0+21592+14a8b93e", "18"},
		{"cve-2024-6119", "9.4", "standard", "openssl-libs", "CVE-2024-6119", "1:3.0.7-28.el9_4", ""},
		{"cve-2024-21892", "8.8", "eus", "nodejs", "CVE-2024-21892", "1:18.19.1-1.module+el8.8.0+21592+14a8b93e", "18"},
	} {
		t.Run(test.fixture+"/"+test.release, func(t *testing.T) {
			config := redHatSource(test.release, test.stream)
			raw := redHatFixture(t, test.fixture)
			want, err := parseRedHat(config, raw, validator)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(raw)
			config.ExpectedSha256 = digest[:]
			var records []*advisoryv1.Advisory
			got, err := stageRedHatStream(t.Context(), config, validator, bytes.NewReader(raw), func(record *advisoryv1.Advisory) error {
				records = append(records, record)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(records) == 0 || !slices.Equal(redHatSemanticClaims(t, records), redHatSemanticClaims(t, want.Advisories)) {
				t.Fatalf("stream changed pinned package/CVE/status/module/source semantics: got=%d want=%d", len(records), len(want.Advisories))
			}
			if len(got.Advisories) != 0 || got.CompleteSnapshot != want.CompleteSnapshot || !bytes.Equal(got.SourceSha256, digest[:]) {
				t.Fatalf("stream retained claims or changed metadata: %v", got)
			}
			// Keep independent pinned expectations even when the materialized
			// compatibility API delegates to the same streaming implementation.
			claims := &advisoryv1.FeedDocument{Advisories: records}
			record := redHatRecord(t, claims, test.name, test.cve, test.module, false)
			if record.FixedVersion != test.fixed || record.Architecture != "x86_64" || record.PlatformRelease != test.release || record.PlatformStream != test.stream || record.AssessmentUnknown || record.NotAffected || (test.module != "" && record.ModuleName != "nodejs") {
				t.Fatalf("stream changed pinned backport/module authority: %v", record)
			}
			if test.fixture == "cve-2024-6119" {
				negative := redHatRecord(t, claims, "compat-openssl11", "CVE-2024-6119", "", false)
				if !negative.NotAffected || negative.AssessmentUnknown || negative.FixedVersion != "" {
					t.Fatalf("stream changed genuine VEX negative status: %v", negative)
				}
			}
		})
	}
}

func TestRedHatStreamTopLevelKeyOrder(t *testing.T) {
	validator := redHatValidator(t)
	config := redHatSource("9.4", "standard")
	raw := redHatFixture(t, "rhsa-2024_6783")
	want, err := parseRedHat(config, raw, validator)
	if err != nil {
		t.Fatal(err)
	}
	var parts map[string]json.RawMessage
	if err := json.Unmarshal(raw, &parts); err != nil {
		t.Fatal(err)
	}
	for _, order := range [][]string{
		{"document", "product_tree", "vulnerabilities"},
		{"document", "vulnerabilities", "product_tree"},
		{"product_tree", "document", "vulnerabilities"},
		{"product_tree", "vulnerabilities", "document"},
		{"vulnerabilities", "document", "product_tree"},
		{"vulnerabilities", "product_tree", "document"},
	} {
		t.Run(strings.Join(order, "/"), func(t *testing.T) {
			var reordered bytes.Buffer
			reordered.WriteByte('{')
			for i, key := range order {
				if i != 0 {
					reordered.WriteByte(',')
				}
				fmt.Fprintf(&reordered, "%q:", key)
				reordered.Write(parts[key])
			}
			reordered.WriteByte('}')
			var records []*advisoryv1.Advisory
			_, err := stageRedHatStream(t.Context(), config, validator, &reordered, func(record *advisoryv1.Advisory) error {
				records = append(records, record)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(redHatSemanticClaims(t, records), redHatSemanticClaims(t, want.Advisories)) {
				t.Fatalf("CSAF object key order changed normalized claims: got=%d want=%d", len(records), len(want.Advisories))
			}
		})
	}
}

func TestRedHatStreamRejectsTruncatedAndInvalidJSON(t *testing.T) {
	validator := redHatValidator(t)
	config := redHatSource("9.4", "standard")
	raw := bytes.TrimSpace(redHatFixture(t, "rhsa-2024_6783"))
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{"empty", nil},
		{"null", []byte("null")},
		{"array", []byte("[]")},
		{"missing-fields", []byte("{}")},
		{"invalid-value", []byte(`{"document":}`)},
		{"truncated-metadata", raw[:len(raw)/4]},
		{"truncated-products", raw[:len(raw)/2]},
		{"truncated-vulnerabilities", raw[:len(raw)-1]},
		{"second-document", append(bytes.Clone(raw), []byte("{}")...)},
		{"invalid-utf8", bytes.Replace(raw, []byte("Red Hat Security Advisory"), []byte{0xff}, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			doc, err := stageRedHatStream(t.Context(), config, validator, bytes.NewReader(test.raw), func(*advisoryv1.Advisory) error {
				calls++
				return nil
			})
			if err == nil || doc != nil || calls != 0 {
				t.Fatalf("invalid original accepted or emitted claims: doc=%v calls=%d err=%v", doc, calls, err)
			}
		})
	}
}

func TestRedHatStreamRejectsMalformedCVEWithoutRepairOrPartialClaims(t *testing.T) {
	raw := bytes.ReplaceAll(redHatFixture(t, "rhsa-2024_6783"), []byte("CVE-2024-6119"), []byte("CVE-2024-6119oops"))
	calls := 0
	doc, err := stageRedHatStream(t.Context(), redHatSource("9.4", "standard"), redHatValidator(t), bytes.NewReader(raw), func(*advisoryv1.Advisory) error {
		calls++
		return nil
	})
	if err != nil || doc == nil || calls != 0 || len(doc.RejectedRecords) != 1 || !doc.RejectedRecords[0].Unscoped || doc.RejectedRecords[0].Id != "RHSA-2024:6783" {
		t.Fatalf("malformed CVE was repaired or retained valid prefix claims: doc=%v calls=%d err=%v", doc, calls, err)
	}
}

type redHatFailingReader struct {
	err error
}

func (r redHatFailingReader) Read([]byte) (int, error) {
	return 0, r.err
}

type redHatCancelReader struct {
	input  io.Reader
	cancel context.CancelFunc
	reads  int
}

func (r *redHatCancelReader) Read(p []byte) (int, error) {
	r.reads++
	n, err := r.input.Read(p)
	r.cancel()
	return n, err
}

func TestRedHatStreamCancellationAndConsumerErrors(t *testing.T) {
	validator := redHatValidator(t)
	config := redHatSource("9.4", "standard")
	raw := redHatFixture(t, "rhsa-2024_6783")
	t.Run("already-canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		input := &redHatCancelReader{input: bytes.NewReader(raw), cancel: cancel}
		calls := 0
		doc, err := stageRedHatStream(ctx, config, validator, input, func(*advisoryv1.Advisory) error { calls++; return nil })
		if !errors.Is(err, context.Canceled) || doc != nil || calls != 0 || input.reads != 0 {
			t.Fatalf("canceled import did work: reads=%d calls=%d doc=%v err=%v", input.reads, calls, doc, err)
		}
	})
	t.Run("canceled-during-read", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		input := &redHatCancelReader{input: bytes.NewReader(raw), cancel: cancel}
		calls := 0
		doc, err := stageRedHatStream(ctx, config, validator, input, func(*advisoryv1.Advisory) error { calls++; return nil })
		if !errors.Is(err, context.Canceled) || doc != nil || calls != 0 || input.reads != 1 {
			t.Fatalf("read cancellation lost: reads=%d calls=%d doc=%v err=%v", input.reads, calls, doc, err)
		}
	})
	t.Run("canceled-by-consumer", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		calls := 0
		doc, err := stageRedHatStream(ctx, config, validator, bytes.NewReader(raw), func(*advisoryv1.Advisory) error {
			calls++
			cancel()
			return nil
		})
		if !errors.Is(err, context.Canceled) || doc != nil || calls != 1 {
			t.Fatalf("emission continued after cancellation: calls=%d doc=%v err=%v", calls, doc, err)
		}
	})
	t.Run("consumer-error", func(t *testing.T) {
		failure := errors.New("generation writer unavailable")
		calls := 0
		doc, err := stageRedHatStream(t.Context(), config, validator, bytes.NewReader(raw), func(*advisoryv1.Advisory) error { calls++; return failure })
		if !errors.Is(err, failure) || doc != nil || calls != 1 {
			t.Fatalf("consumer error lost or emission continued: calls=%d doc=%v err=%v", calls, doc, err)
		}
	})
	t.Run("reader-error", func(t *testing.T) {
		failure := errors.New("original source read failed")
		input := io.MultiReader(bytes.NewReader(raw[:len(raw)/2]), redHatFailingReader{err: failure})
		calls := 0
		doc, err := stageRedHatStream(t.Context(), config, validator, input, func(*advisoryv1.Advisory) error { calls++; return nil })
		if !errors.Is(err, failure) || doc != nil || calls != 0 {
			t.Fatalf("source read failure lost: calls=%d doc=%v err=%v", calls, doc, err)
		}
	})
	t.Run("source-pin-mismatch", func(t *testing.T) {
		pinned := proto.CloneOf(config)
		pinned.ExpectedSha256 = make([]byte, sha256.Size)
		calls := 0
		doc, err := stageRedHatStream(t.Context(), pinned, validator, bytes.NewReader(raw), func(*advisoryv1.Advisory) error { calls++; return nil })
		if err == nil || doc != nil || calls != 0 {
			t.Fatalf("unverified source claims escaped: calls=%d doc=%v err=%v", calls, doc, err)
		}
	})
}
