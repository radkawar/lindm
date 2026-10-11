package devlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/advisory/feed"
)

var (
	benchmarkFeedCache    = flag.String("feed-cache", "", "explicit real acceptance cache directory for BenchmarkRecordedFeed")
	benchmarkFeedManifest = flag.String("feed-manifest", "", "immutable recorded URL/SHA-256/size JSON array for BenchmarkRecordedFeed")
	benchmarkFeedSources  = flag.String("feed-sources", "", "strict protobuf JSON AdvisoryConfig for BenchmarkRecordedFeed")
	benchmarkFeedBudget   = flag.Int64("feed-byte-budget", 4<<30, "per-source/per-iteration replay byte ceiling")
	benchmarkFeedTimeout  = flag.Duration("feed-timeout", 2*time.Hour, "per-source/per-iteration replay deadline")
)

// BenchmarkRecordedFeed replays actual recorded vendor archives through the
// production fetch/verification/parser path with serial claim callbacks. It is
// acquisition+decode+deterministic-encoding throughput, NOT database publication
// or vendor freshness. Use lab feeds replay for the real full-refresh timing.
//
// go test ./internal/devlab -run '^$' -bench '^BenchmarkRecordedFeed$' -benchtime=1x -count=1 -timeout=3h -args -feed-cache DIR -feed-manifest FILE -feed-sources FILE
func BenchmarkRecordedFeed(b *testing.B) {
	if *benchmarkFeedCache == "" || *benchmarkFeedManifest == "" || *benchmarkFeedSources == "" {
		b.Skip("real-recording benchmark requires -feed-cache, -feed-manifest and -feed-sources; no synthetic fallback")
	}
	if *benchmarkFeedTimeout <= 0 || *benchmarkFeedBudget <= 0 {
		b.Fatal("positive feed byte/time budgets required")
	}
	replay, err := LoadFeedReplay(*benchmarkFeedCache, *benchmarkFeedManifest, *benchmarkFeedSources)
	if err != nil {
		b.Fatal(err)
	}
	b.Logf("offline replay (not freshness): manifest=%s sources=%s", replay.ManifestSHA256, replay.ConfigSHA256)
	for _, source := range replay.Config.GetFeeds() {
		b.Run(source.GetId(), func(b *testing.B) {
			b.ReportAllocs()
			var expectedDigest string
			for range b.N {
				ctx, cancel := context.WithTimeout(b.Context(), *benchmarkFeedTimeout)
				client, closeClient, err := replay.openClient(*benchmarkFeedBudget)
				if err != nil {
					cancel()
					b.Fatal(err)
				}
				fetcher, err := feed.New(client)
				if err != nil {
					closeClient()
					cancel()
					b.Fatal(err)
				}
				h := sha256.New()
				var encoded []byte
				var count int64
				doc, err := fetcher.FetchStream(ctx, source, func(claim *advisoryv1.Advisory) error {
					var err error
					encoded, err = (proto.MarshalOptions{Deterministic: true}).MarshalAppend(encoded[:0], claim)
					if err != nil {
						return err
					}
					hashReplayField(h, encoded)
					count++
					return nil
				}, nil)
				closeClient()
				cancel()
				if err != nil {
					b.Fatal(err)
				}
				encoded, err = (proto.MarshalOptions{Deterministic: true}).MarshalAppend(encoded[:0], doc)
				if err != nil {
					b.Fatal(err)
				}
				hashReplayField(h, encoded)
				digest := hex.EncodeToString(h.Sum(nil))
				if expectedDigest != "" && expectedDigest != digest {
					b.Fatal("non-deterministic ordered claims/metadata digest")
				}
				expectedDigest = digest
				b.ReportMetric(float64(count), "claims/op")
			}
			b.Logf("ordered_claims_and_metadata_sha256=%s", expectedDigest)
		})
	}
}
