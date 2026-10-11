package devlab

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/internal/advisory"
	"lindm/internal/config"
)

// FeedTimingOptions identifies explicit reproducible inputs. An empty manifest
// selects connected recording; a manifest selects strictly local replay.
type FeedTimingOptions struct {
	CacheDirectory string
	SourcesPath    string
	ManifestPath   string
	ByteBudget     int64
	Timeout        time.Duration
}

// FeedPublicationDigest hashes stable committed publication content, excluding
// random generation UUIDs and local attempt/check/expiry times. Framed fields
// include source config, manifest/rejections, signed time, completeness and all
// matching rows in deterministic record-ID order. V1 names this digest contract.
type FeedPublicationDigest struct {
	FeedID  string `json:"feed_id"`
	Records int64  `json:"records"`
	SHA256  string `json:"publication_sha256_v1"`
}

// FeedTimingResult separates actual Refresh wall time from the untimed digest
// pass. Replay never establishes vendor freshness even if production status
// fields reflect the deliberately replayed successful acquisition path.
type FeedTimingResult struct {
	Mode                   string                  `json:"mode"`
	VendorHTTPSAcquisition bool                    `json:"vendor_https_acquisition"`
	FreshnessClaim         string                  `json:"freshness_claim"`
	ManifestSHA256         string                  `json:"manifest_sha256,omitempty"`
	SourcesSHA256          string                  `json:"sources_sha256"`
	Refresh                *AcceptanceFeedResult   `json:"refresh,omitempty"`
	Publications           []FeedPublicationDigest `json:"publications"`
	TotalSeconds           float64                 `json:"refresh_and_digest_seconds"`
	DigestSeconds          float64                 `json:"digest_seconds"`
	AllocatedBytes         uint64                  `json:"allocated_bytes_refresh_and_digest"`
	GCCycles               uint32                  `json:"gc_cycles_refresh_and_digest"`
	HeapInUseBytes         uint64                  `json:"heap_in_use_bytes_after_digest"`
}

// TimeFeedRefresh exercises the real stage/reconcile/fenced publication pipeline
// only in this already-disposable authority database. It never changes the
// server's persistent config or enables background refresh/evaluation workers.
func (f *AuthorityFixture) TimeFeedRefresh(ctx context.Context, options FeedTimingOptions) (result *FeedTimingResult, resultErr error) {
	if options.CacheDirectory == "" || options.SourcesPath == "" || options.ByteBudget <= 0 || options.Timeout <= 0 {
		return nil, errors.New("feed timing requires cache, sources and positive byte/time budgets")
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	cfg, err := LoadFeedSources(options.SourcesPath)
	if err != nil {
		return nil, err
	}
	encoded, err := readFeedReplayFile(options.SourcesPath)
	if err != nil {
		return nil, err
	}
	configDigest := sha256.Sum256(encoded)
	result = &FeedTimingResult{Mode: "connected-recording", VendorHTTPSAcquisition: true, FreshnessClaim: "not_asserted", SourcesSHA256: hex.EncodeToString(configDigest[:])}
	started := time.Now()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	defer func() {
		result.TotalSeconds = time.Since(started).Seconds()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		result.AllocatedBytes = after.TotalAlloc - before.TotalAlloc
		result.GCCycles = after.NumGC - before.NumGC
		result.HeapInUseBytes = after.HeapInuse
	}()
	document, err := config.Load(f.configPath())
	if err != nil {
		return result, err
	}
	resources, err := document.Resolve()
	if err != nil {
		return result, err
	}
	defer resources.HTTPClient.CloseIdleConnections()
	pool, err := pgxpool.NewWithConfig(ctx, resources.Database)
	if err != nil {
		return result, err
	}
	defer pool.Close()
	if options.ManifestPath == "" {
		result.Refresh, resultErr = f.RefreshVendorFeeds(ctx, options.CacheDirectory, options.ByteBudget, options.Timeout, cfg.GetFeeds())
	} else {
		result.Mode, result.VendorHTTPSAcquisition = "offline-recording-replay", false
		replay, err := LoadFeedReplay(options.CacheDirectory, options.ManifestPath, options.SourcesPath)
		if err != nil {
			return result, err
		}
		result.ManifestSHA256 = replay.ManifestSHA256
		client, closeClient, err := replay.openClient(options.ByteBudget)
		if err != nil {
			return result, err
		}
		defer closeClient()
		service, err := advisory.New(ctx, pool, replay.Config, client)
		if err != nil {
			return result, err
		}
		refreshStarted := time.Now().UTC()
		result.Refresh = &AcceptanceFeedResult{StartedAt: refreshStarted, ByteBudget: options.ByteBudget, DurationBudgetSeconds: options.Timeout.Seconds(), Artifacts: replay.Artifacts}
		resultErr = service.Refresh(ctx)
		result.Refresh.DurationSeconds = time.Since(refreshStarted).Seconds()
		result.Refresh.Feeds, err = service.Feeds(ctx)
		resultErr = errors.Join(resultErr, err)
	}
	if resultErr != nil {
		return result, resultErr
	}
	digestStarted := time.Now()
	for _, source := range cfg.GetFeeds() {
		digest, err := digestFeedPublication(ctx, pool, source.GetId())
		if err != nil {
			return result, err
		}
		result.Publications = append(result.Publications, digest)
	}
	result.DigestSeconds = time.Since(digestStarted).Seconds()
	return result, nil
}

func digestFeedPublication(ctx context.Context, pool *pgxpool.Pool, feedID string) (FeedPublicationDigest, error) {
	result := FeedPublicationDigest{FeedID: feedID}
	var revision uuid.UUID
	var expected int64
	var sourceConfig, sourceHash, manifest []byte
	var complete bool
	var signedAt pgtype.Timestamptz
	err := pool.QueryRow(ctx, `SELECT revision,advisory_count,config_bytes,source_sha256,source_manifest,complete_snapshot,snapshot_at
FROM advisory_feeds WHERE id=$1 AND enabled AND error='' AND checked_at IS NOT NULL`, feedID).Scan(&revision, &expected, &sourceConfig, &sourceHash, &manifest, &complete, &signedAt)
	if err != nil {
		return result, fmt.Errorf("read committed feed %s: %w", feedID, err)
	}
	h := sha256.New()
	hashReplayField(h, []byte("lindm-feed-publication-v1"))
	hashReplayField(h, []byte(feedID))
	hashReplayField(h, sourceConfig)
	hashReplayField(h, sourceHash)
	hashReplayField(h, manifest)
	if complete {
		hashReplayField(h, []byte{1})
	} else {
		hashReplayField(h, []byte{0})
	}
	if signedAt.Valid {
		hashReplayField(h, []byte(signedAt.Time.UTC().Format(time.RFC3339Nano)))
	} else {
		hashReplayField(h, nil)
	}
	// The primary index supplies deterministic order without an in-memory
	// publication-sized sort. pgx streams at most one bounded row at a time.
	rows, err := pool.Query(ctx, `SELECT id::text,advisory_id,package_name,source_package::text,architecture,record_bytes
FROM advisory_record_generations WHERE feed_id=$1 AND generation=$2 ORDER BY id`, feedID, revision)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		for _, field := range rows.RawValues() {
			hashReplayField(h, field)
		}
		result.Records++
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	if result.Records != expected {
		return result, fmt.Errorf("publication count mismatch for %s: %d != %d", feedID, result.Records, expected)
	}
	result.SHA256 = hex.EncodeToString(h.Sum(nil))
	return result, nil
}

func hashReplayField(h hash.Hash, field []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(field)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(field)
}
