// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func replacementTestBatch(names ...string) []redHatReplacement {
	batch := make([]redHatReplacement, len(names))
	for i, name := range names {
		batch[i] = redHatReplacement{name: name, config: &advisoryv1.FeedSource{Url: name}, done: make(chan error, 1)}
	}
	return batch
}

// Synthetic originals exercise ownership and scheduling only. Signature trust is
// exercised separately below using genuine retained publisher-signed originals.
func replacementTestOriginal(directory string, result *verifiedCSAF, raw []byte, signedAt time.Time) (err error) {
	file, err := os.CreateTemp(directory, "replacement-*")
	if err != nil {
		return err
	}
	result.file = file
	defer func() {
		if err != nil {
			err = errors.Join(err, result.close())
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	result.artifact = &advisoryv1.FeedArtifact{Sha256: digest[:]}
	result.signedAt = signedAt
	return nil
}

func replacementTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func replacementTestResult(t *testing.T, ctx context.Context, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		t.Fatal("replacement pipeline did not join before its deadline")
		return ctx.Err()
	}
}

func replacementTestEmpty(t *testing.T, directory string, files []*os.File) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("owned originals leaked: entries=%v err=%v", entries, err)
	}
	for _, file := range files {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Errorf("owned file was not closed: %s: %v", file.Name(), err)
		}
	}
	if got := len(redHatReplacementSlots); got != 0 {
		t.Fatalf("global replacement permits leaked: %d", got)
	}
}

func replacementTestCheckpoint(t *testing.T, stager *redHatStager, distribution string, names ...string) *redHatCheckpoint {
	t.Helper()
	directory, err := url.Parse("https://example.test/provider/" + distribution + "/")
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := &redHatCheckpoint{
		distribution: distribution,
		directory:    directory,
		index:        []byte(strings.Join(names, "\n") + "\n"),
		changes:      fmt.Appendf(nil, "\"%s\",\"2026-10-01T00:00:00Z\"\n", names[0]),
	}
	if err := checkpoint.stage(t.Context(), stager); err != nil {
		t.Fatal(err)
	}
	return checkpoint
}

func TestRedHatReplacementGlobalAcquisitionsAndOwnedFilesAcrossStreams(t *testing.T) {
	ctx := replacementTestContext(t)
	directory := t.TempDir()
	started := make(chan string, 8)
	release := make(chan struct{})
	var active, peak atomic.Int32
	var mu sync.Mutex
	var files []*os.File
	acquire := func(ctx context.Context, config *advisoryv1.FeedSource, result *verifiedCSAF) error {
		if err := replacementTestOriginal(directory, result, []byte(config.Url), time.Now()); err != nil {
			return err
		}
		mu.Lock()
		files = append(files, result.file)
		entries, err := os.ReadDir(directory)
		mu.Unlock()
		if err != nil || len(entries) > redHatReplacementLimit {
			return errors.Join(fmt.Errorf("owned file budget exceeded: %d", len(entries)), err)
		}
		count := active.Add(1)
		defer active.Add(-1)
		for previous := peak.Load(); count > previous && !peak.CompareAndSwap(previous, count); previous = peak.Load() {
		}
		started <- config.Url
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return errors.Join(ctx.Err(), result.close())
		}
	}
	consume := func(context.Context, *redHatReplacement) error { return nil }
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	go func() {
		firstDone <- runRedHatReplacementBatch(ctx, replacementTestBatch("first-a", "first-b"), acquire, consume)
	}()
	for range 2 {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("first stream failed to overlap acquisitions")
		}
	}
	go func() {
		secondDone <- runRedHatReplacementBatch(ctx, replacementTestBatch("second-a", "second-b", "second-c", "second-d"), acquire, consume)
	}()
	for range 2 {
		select {
		case name := <-started:
			if !strings.HasPrefix(name, "second-") {
				t.Fatalf("unexpected second stream submission %q", name)
			}
		case <-ctx.Done():
			t.Fatal("streams deadlocked while sharing the global budget")
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != redHatReplacementLimit || active.Load() != redHatReplacementLimit {
		t.Fatalf("expected four overlapping owned files: entries=%v active=%d err=%v", entries, active.Load(), err)
	}
	close(release)
	if err := replacementTestResult(t, ctx, firstDone); err != nil {
		t.Fatal(err)
	}
	if err := replacementTestResult(t, ctx, secondDone); err != nil {
		t.Fatal(err)
	}
	if peak.Load() != redHatReplacementLimit || active.Load() != 0 {
		t.Fatalf("unexpected acquisition overlap: peak=%d remaining=%d", peak.Load(), active.Load())
	}
	replacementTestEmpty(t, directory, files)
}

func TestRedHatReplacementLexicalNormalizationAndExactCheckpointClosure(t *testing.T) {
	ctx := replacementTestContext(t)
	stager := snapshotStager(t)
	names := []string{"2024/cve-2024-1001.json", "2024/cve-2024-1002.json", "2024/cve-2024-1003.json", "2024/cve-2024-1004.json", "2024/cve-2024-1005.json", "2024/cve-2024-1006.json"}
	archived := "2024/cve-2024-1000.json"
	inventory := slices.Clone(names)
	slices.Reverse(inventory)
	inventory = append(inventory, archived)
	checkpoint := replacementTestCheckpoint(t, stager, "vex", inventory...)
	archivedDigest := sha256.Sum256([]byte(archived))
	if err := checkpoint.record(ctx, stager, archived, archivedDigest[:]); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	started, completed := make(chan string, 4), make(chan string, 4)
	gates := make(map[string]chan struct{}, len(names))
	for _, name := range names {
		gates[name] = make(chan struct{})
	}
	var order []string
	done := make(chan error, 1)
	go func() {
		batch := replacementTestBatch("", "", "", "")
		for {
			count, err := checkpoint.replacementBatch(ctx, stager, batch)
			if err != nil || count == 0 {
				done <- err
				return
			}
			for i := range count {
				batch[i].config.Url = batch[i].name
			}
			err = runRedHatReplacementBatch(ctx, batch[:count], func(ctx context.Context, config *advisoryv1.FeedSource, result *verifiedCSAF) error {
				if err := replacementTestOriginal(directory, result, []byte(config.Url), time.Now()); err != nil {
					return err
				}
				started <- config.Url
				select {
				case <-gates[config.Url]:
					completed <- config.Url
					return nil
				case <-ctx.Done():
					return errors.Join(ctx.Err(), result.close())
				}
			}, func(ctx context.Context, replacement *redHatReplacement) error {
				order = append(order, replacement.name)
				return checkpoint.recordReplacement(ctx, stager, replacement.name, replacement.verified.artifact.Sha256, replacement.modified, replacement.verified.signedAt)
			})
			if err != nil {
				done <- err
				return
			}
		}
	}()
	for _, group := range [][]string{names[:4], names[4:]} {
		for range group {
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("bounded SQLite batch failed to acquire concurrently")
			}
		}
		for i := len(group) - 1; i >= 0; i-- {
			close(gates[group[i]])
			select {
			case name := <-completed:
				if name != group[i] {
					t.Fatalf("completion not reversed: got %s want %s", name, group[i])
				}
			case <-ctx.Done():
				t.Fatal("replacement acquisition failed to complete")
			}
		}
	}
	if err := replacementTestResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(order, names) {
		t.Fatalf("normalization followed completion instead of indexed path order: %v", order)
	}
	summary, err := checkpoint.summary(ctx, stager)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.New()
	for _, name := range append([]string{archived}, names...) {
		digest := sha256.Sum256([]byte(name))
		_, _ = io.WriteString(expected, name)
		_, _ = expected.Write([]byte{0})
		_, _ = expected.Write(digest[:])
	}
	if summary.DocumentCount != 7 || !bytes.Equal(summary.DocumentManifestSha256, expected.Sum(nil)) {
		t.Fatalf("captured index closure/hash changed: %v", summary)
	}
	replacementTestEmpty(t, directory, nil)
}

func TestRedHatReplacementErrorsCancelJoinAndReleaseEveryOwner(t *testing.T) {
	for _, mode := range []string{"acquisition", "parent-cancellation", "normalization", "timestamp"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(replacementTestContext(t))
			defer cancel()
			directory := t.TempDir()
			batch := replacementTestBatch("a", "b", "c", "d")
			if mode == "timestamp" {
				batch[0].modified = time.Now().Add(time.Hour).UnixNano()
			}
			failure := errors.New("replacement acquisition failed")
			parseFailure := errors.New("replacement normalization failed")
			started := make(chan struct{}, 4)
			release := make(chan struct{})
			var active atomic.Int32
			var mu sync.Mutex
			var files []*os.File
			var parsed int
			done := make(chan error, 1)
			go func() {
				done <- runRedHatReplacementBatch(ctx, batch, func(ctx context.Context, config *advisoryv1.FeedSource, result *verifiedCSAF) error {
					active.Add(1)
					defer active.Add(-1)
					if err := replacementTestOriginal(directory, result, []byte(config.Url), time.Now()); err != nil {
						return err
					}
					mu.Lock()
					files = append(files, result.file)
					mu.Unlock()
					started <- struct{}{}
					if mode == "acquisition" && config.Url == "b" {
						select {
						case <-release:
							return errors.Join(failure, result.close())
						case <-ctx.Done():
							return errors.Join(ctx.Err(), result.close())
						}
					}
					if config.Url == "a" && (mode == "normalization" || mode == "timestamp") {
						select {
						case <-release:
							return nil
						case <-ctx.Done():
							return errors.Join(ctx.Err(), result.close())
						}
					}
					<-ctx.Done()
					return errors.Join(ctx.Err(), result.close())
				}, func(context.Context, *redHatReplacement) error {
					parsed++
					return parseFailure
				})
			}()
			for range 4 {
				select {
				case <-started:
				case <-ctx.Done():
					t.Fatal("did not acquire four originals before failure")
				}
			}
			// An independent stream waiting on the full global budget must not
			// inherit this stream's cancellation or deadlock during its cleanup.
			peerCtx := replacementTestContext(t)
			peerDone := make(chan error, 1)
			go func() {
				peerDone <- runRedHatReplacementBatch(peerCtx, replacementTestBatch("peer-a", "peer-b", "peer-c", "peer-d"), func(_ context.Context, config *advisoryv1.FeedSource, result *verifiedCSAF) error {
					return replacementTestOriginal(directory, result, []byte(config.Url), time.Now())
				}, func(context.Context, *redHatReplacement) error { return nil })
			}()
			if mode == "parent-cancellation" {
				cancel()
			} else {
				close(release)
			}
			err := replacementTestResult(t, replacementTestContext(t), done)
			if peerErr := replacementTestResult(t, peerCtx, peerDone); peerErr != nil {
				t.Fatalf("independent stream failed after sibling cleanup: %v", peerErr)
			}
			switch mode {
			case "acquisition":
				if !errors.Is(err, failure) {
					t.Fatalf("lost original acquisition error: %v", err)
				}
			case "parent-cancellation":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("lost parent cancellation: %v", err)
				}
			case "normalization":
				if !errors.Is(err, parseFailure) || parsed != 1 {
					t.Fatalf("lost normalization error: parses=%d err=%v", parsed, err)
				}
			case "timestamp":
				if err == nil || !strings.Contains(err.Error(), "predates captured change checkpoint") || parsed != 0 {
					t.Fatalf("stale signed original reached normalization: parses=%d err=%v", parsed, err)
				}
			}
			if active.Load() != 0 {
				t.Fatalf("acquisition workers outlived return: %d", active.Load())
			}
			replacementTestEmpty(t, directory, files)
			for _, replacement := range batch {
				if replacement.verified.file != nil || replacement.verified.artifact != nil || !replacement.verified.signedAt.IsZero() {
					t.Fatal("closed replacement retained ownership fields")
				}
			}
		})
	}
}

func TestRedHatReplacementVerifiedAcquisitionAndPreparseWatermark(t *testing.T) {
	raw := fixture(t, "redhat-cve-2024-6119.json")
	proof := fixture(t, "redhat-cve-2024-6119.json.asc")
	signedAt := signatureCreation(t, proof)
	invalidProof := flippedSignature(t, proof)
	for _, mode := range []string{"success", "timestamp", "signature", "checksum"} {
		t.Run(mode, func(t *testing.T) {
			ctx := replacementTestContext(t)
			stager := snapshotStager(t)
			checkpoint := replacementTestCheckpoint(t, stager, "vex", "2024/cve-2024-6119.json")
			modified := signedAt.UnixNano()
			if mode == "timestamp" {
				modified++
			}
			if _, err := stager.db.ExecContext(ctx, `UPDATE snapshot_documents SET modified=?`, modified); err != nil {
				t.Fatal(err)
			}
			directory := t.TempDir()
			t.Setenv("TMPDIR", directory)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var response []byte
				switch r.URL.Path {
				case "/provider/vex/2024/cve-2024-6119.json.sha256":
					digest := sha256.Sum256(raw)
					if mode == "checksum" {
						digest[0] ^= 1
					}
					response = fmt.Appendf(nil, "%x  cve-2024-6119.json\n", digest)
				case "/provider/vex/2024/cve-2024-6119.json.asc":
					response = proof
					if mode == "signature" {
						response = invalidProof
					}
				case "/provider/vex/2024/cve-2024-6119.json":
					response = raw
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
			checkpoint.directory, err = url.Parse(server.URL + "/provider/vex/")
			if err != nil {
				t.Fatal(err)
			}
			source := redHatSource("9.4", "standard")
			doc := new(advisoryv1.FeedDocument)
			err = client.fetchRedHatReplacements(ctx, source, checkpoint, stager, doc, nil)
			if mode == "success" {
				if err != nil || stager.count == 0 {
					t.Fatalf("authenticated original was not normalized: count=%d err=%v", stager.count, err)
				}
				if _, err := checkpoint.summary(ctx, stager); err != nil {
					t.Fatal(err)
				}
			} else {
				if err == nil || stager.count != 0 || len(doc.RejectedRecords) != 0 {
					t.Fatalf("unauthenticated or stale original reached normalization: count=%d doc=%v err=%v", stager.count, doc, err)
				}
				if _, err := checkpoint.summary(ctx, stager); err == nil {
					t.Fatal("failed acquisition established exact checkpoint closure")
				}
			}
			replacementTestEmpty(t, directory, nil)
		})
	}
}

func TestRedHatReplacementBoundedUnusableDocumentQuarantine(t *testing.T) {
	raw := bytes.ReplaceAll(redHatFixture(t, "rhsa-2024_6783"), []byte("CVE-2024-6119"), []byte("CVE-2024-6119oops"))
	for _, rejectLimit := range []uint32{0, 1} {
		t.Run(fmt.Sprint(rejectLimit), func(t *testing.T) {
			ctx := replacementTestContext(t)
			stager := snapshotStager(t)
			checkpoint := replacementTestCheckpoint(t, stager, "advisories", "2024/rhsa-2024_6783.json")
			batch := replacementTestBatch("2024/rhsa-2024_6783.json")
			count, err := checkpoint.replacementBatch(ctx, stager, batch)
			if err != nil || count != 1 {
				t.Fatalf("load replacement: count=%d err=%v", count, err)
			}
			source := redHatSource("9.4", "standard")
			source.MaxRejectedRecords = &rejectLimit
			client := &Client{validator: redHatValidator(t)}
			doc := new(advisoryv1.FeedDocument)
			directory := t.TempDir()
			progress := 0
			err = runRedHatReplacementBatch(ctx, batch, func(_ context.Context, _ *advisoryv1.FeedSource, result *verifiedCSAF) error {
				return replacementTestOriginal(directory, result, raw, time.Now())
			}, func(ctx context.Context, replacement *redHatReplacement) error {
				return client.normalizeRedHatReplacement(ctx, source, checkpoint, stager, doc, replacement, func() error { progress++; return nil })
			})
			if rejectLimit == 0 {
				if err == nil || !strings.Contains(err.Error(), "rejected record limit exceeded") || stager.count != 0 || len(doc.RejectedRecords) != 0 || progress != 0 {
					t.Fatalf("unusable original bypassed rejection bound: count=%d progress=%d doc=%v err=%v", stager.count, progress, doc, err)
				}
				if _, err := checkpoint.summary(ctx, stager); err == nil {
					t.Fatal("rejection-bound failure established closure")
				}
			} else {
				if err != nil || len(doc.RejectedRecords) != 1 || doc.RejectedRecords[0].Unscoped || progress != 1 {
					t.Fatalf("bounded quarantine was not preserved: progress=%d doc=%v err=%v", progress, doc, err)
				}
				var claims []*advisoryv1.Advisory
				if err := stager.emit(ctx, func(claim *advisoryv1.Advisory) error { claims = append(claims, claim); return nil }); err != nil {
					t.Fatal(err)
				}
				redHatRequireOnlyQuarantine(t, doc.RejectedRecords[0], claims)
				if _, err := checkpoint.summary(ctx, stager); err != nil {
					t.Fatalf("bounded unusable original lost inventory digest: %v", err)
				}
			}
			replacementTestEmpty(t, directory, nil)
		})
	}
}
