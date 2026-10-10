// Package advisory owns vendor advisory publication, native package matching and
// expiring risk acceptance. It never installs software or treats absent evidence
// as proof that a device is healthy.
package advisory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/advisory/advisorydb"
	"lindm/internal/advisory/feed"
)

var (
	ErrConflict = errors.New("advisory_conflict")
	ErrNotFound = errors.New("advisory_not_found")
	ErrInvalid  = errors.New("advisory_invalid")
	ErrCapacity = errors.New("advisory_capacity")
)

// Service holds checked dependencies. The protobuf configuration is copied at
// construction so callers cannot change feed authority while a refresh is running.
type Service struct {
	pool            *pgxpool.Pool
	config          *configv1.AdvisoryConfig
	client          *feed.Client
	rules           protovalidate.Validator
	clock           func() time.Time
	inventoryAge    time.Duration
	refreshInterval time.Duration
}

func New(ctx context.Context, pool *pgxpool.Pool, cfg *configv1.AdvisoryConfig, client *http.Client) (*Service, error) {
	if pool == nil || client == nil {
		return nil, errors.New("advisory: database and HTTP client are required")
	}
	if cfg == nil {
		cfg = &configv1.AdvisoryConfig{}
	}
	rules, err := protovalidate.New(protovalidate.WithMessages(cfg, &adminv1.AcceptAdvisoryFindingRequest{}), protovalidate.WithDisableLazy())
	if err != nil {
		return nil, fmt.Errorf("compile advisory validation: %w", err)
	}
	if err := rules.Validate(cfg); err != nil {
		return nil, fmt.Errorf("validate advisory configuration: %w", err)
	}
	fetcher, err := feed.New(client)
	if err != nil {
		return nil, err
	}
	s := &Service{pool: pool, config: proto.CloneOf(cfg), client: fetcher, rules: rules, clock: time.Now, inventoryAge: 24 * time.Hour, refreshInterval: 6 * time.Hour}
	if cfg.InventoryMaxAgeSeconds != nil {
		s.inventoryAge = time.Duration(cfg.GetInventoryMaxAgeSeconds()) * time.Second
	}
	if cfg.RefreshIntervalSeconds != nil {
		s.refreshInterval = time.Duration(cfg.GetRefreshIntervalSeconds()) * time.Second
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := advisorydb.New(tx)
	ids := make([]string, 0, len(cfg.GetFeeds()))
	for _, source := range cfg.GetFeeds() {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(source)
		if err != nil {
			return nil, err
		}
		ids = append(ids, source.GetId())
		if err := q.ConfigureAdvisoryFeed(ctx, advisorydb.ConfigureAdvisoryFeedParams{ID: source.GetId(), Distro: source.GetDistro(), Release: source.GetRelease(), PlatformStream: source.GetPlatformStream(), SourceUrl: source.GetUrl(), ConfigBytes: encoded, Revision: uuid.New()}); err != nil {
			return nil, fmt.Errorf("configure advisory feed: %w", err)
		}
	}
	if err := q.DisableAdvisoryFeeds(ctx, ids); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Refresh explicitly refreshes all configured feeds even when scheduled egress is
// disabled. Each feed has an independent bounded fetch and atomic publication.
func (s *Service) Refresh(ctx context.Context) error {
	var result error
	for _, source := range s.config.GetFeeds() {
		if err := ctx.Err(); err != nil {
			return errors.Join(result, err)
		}
		started := s.clock().UTC()
		bounded, cancel := context.WithTimeout(ctx, 5*time.Minute)
		doc, err := s.client.Fetch(bounded, source)
		if err == nil {
			err = s.publish(bounded, source, doc, started)
		}
		cancel()
		if err != nil {
			result = errors.Join(result, fmt.Errorf("refresh feed %s: %w", source.GetId(), err))
			failureCtx, stop := context.WithTimeout(ctx, 5*time.Second)
			storeErr := advisorydb.New(s.pool).FailAdvisoryFeed(failureCtx, advisorydb.FailAdvisoryFeedParams{ID: source.GetId(), AttemptedAt: timestamp(started), Error: "refresh_failed"})
			stop()
			result = errors.Join(result, storeErr)
		}
	}
	return result
}

// Import uses the same checked parser/publication path. Offline bytes require an
// out-of-band configured digest; a filename or an embedded digest is not authority.
func (s *Service) Import(ctx context.Context, id string, input io.Reader) error {
	for _, source := range s.config.GetFeeds() {
		if source.GetId() != id {
			continue
		}
		if len(source.GetExpectedSha256()) != sha256.Size {
			return errors.New("advisory: offline import requires configured expected_sha256")
		}
		doc, err := feed.Parse(source, input)
		if err != nil {
			return err
		}
		// A byte pin establishes integrity, not when the vendor last served the
		// snapshot. Until bundle custody binds acquisition time, imported files
		// can contribute findings but cannot establish current complete coverage.
		doc.CompleteSnapshot = false
		return s.publish(ctx, source, doc, s.clock().UTC())
	}
	return ErrNotFound
}

func (s *Service) publish(ctx context.Context, source *advisoryv1.FeedSource, doc *advisoryv1.FeedDocument, started time.Time) error {
	if doc == nil || len(doc.GetSourceSha256()) != sha256.Size {
		return ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := advisorydb.New(tx)
	current, err := q.LockAdvisoryFeed(ctx, source.GetId())
	if err != nil {
		return err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(source)
	if err != nil {
		return err
	}
	if !current.Enabled || !bytes.Equal(current.ConfigBytes, encoded) {
		return ErrConflict
	}
	if current.CheckedAt.Valid && current.CheckedAt.Time.After(started) {
		return nil
	}
	revision := current.Revision
	recordsChanged := !bytes.Equal(current.SourceSha256, doc.GetSourceSha256())
	if recordsChanged || current.CompleteSnapshot != doc.GetCompleteSnapshot() {
		revision = uuid.New()
	}
	if recordsChanged {
		if err := q.DeleteAdvisoryRecords(ctx, source.GetId()); err != nil {
			return err
		}
		batch := make([]advisorydb.InsertAdvisoryRecordsParams, 0, 500)
		seen := make(map[uuid.UUID]struct{}, len(doc.GetAdvisories()))
		namespace := uuid.NewSHA1(uuid.NameSpaceOID, []byte(source.GetId()))
		flush := func() error {
			if len(batch) == 0 {
				return nil
			}
			_, err := q.InsertAdvisoryRecords(ctx, batch)
			clear(batch)
			batch = batch[:0]
			return err
		}
		for _, record := range doc.GetAdvisories() {
			payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(record)
			if err != nil {
				return err
			}
			id := uuid.NewSHA1(namespace, payload)
			if _, exists := seen[id]; exists {
				continue
			}
			seen[id] = struct{}{}
			batch = append(batch, advisorydb.InsertAdvisoryRecordsParams{ID: id, FeedID: source.GetId(), AdvisoryID: record.GetId(), PackageName: record.GetPackageName(), SourcePackage: record.GetSourcePackage(), Architecture: record.GetArchitecture(), RecordBytes: payload})
			if len(batch) == cap(batch) {
				if err := flush(); err != nil {
					return err
				}
			}
		}
		if err := flush(); err != nil {
			return err
		}
	}
	artifacts := doc.GetArtifacts()
	if len(artifacts) == 0 {
		artifacts = []*advisoryv1.FeedArtifact{{Url: source.GetUrl(), Sha256: doc.GetSourceSha256()}}
	}
	manifest, err := proto.MarshalOptions{Deterministic: true}.Marshal(&advisoryv1.FeedManifest{Artifacts: artifacts})
	if err != nil {
		return err
	}
	expires := started.Add(time.Duration(source.GetMaxAgeSeconds()) * time.Second)
	var snapshotAt pgtype.Timestamptz
	if doc.GetSnapshotAt() != nil {
		if err := doc.GetSnapshotAt().CheckValid(); err != nil || doc.GetSnapshotAt().AsTime().After(s.clock().UTC()) {
			return ErrInvalid
		}
		snapshotAt = timestamp(doc.GetSnapshotAt().AsTime())
		if until := snapshotAt.Time.Add(time.Duration(source.GetMaxAgeSeconds()) * time.Second); until.Before(expires) {
			expires = until
		}
	}
	if err := q.PublishAdvisoryFeed(ctx, advisorydb.PublishAdvisoryFeedParams{ID: source.GetId(), Revision: revision, SourceSha256: doc.GetSourceSha256(), SourceManifest: manifest, SnapshotAt: snapshotAt, CheckedAt: timestamp(started), ExpiresAt: timestamp(expires), AdvisoryCount: int64(len(doc.GetAdvisories())), CompleteSnapshot: doc.GetCompleteSnapshot()}); err != nil {
		return err
	}
	if err := q.InsertAdvisoryAudit(ctx, advisorydb.InsertAdvisoryAuditParams{ID: uuid.New(), Action: "advisory.feed.ingested", ResourceID: source.GetId(), Reason: "Vendor advisory revision published"}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Run owns no detached goroutines. The caller cancels and joins it before closing
// the pool. Inventory matching continues with egress disabled, preserving unknown
// freshness instead of pretending an air-gapped feed is current.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	var nextRefresh time.Time
	var after uuid.UUID
	for {
		if s.config.GetRefreshEnabled() && !s.clock().Before(nextRefresh) {
			if err := s.Refresh(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("advisory refresh failed", "error", err)
			}
			nextRefresh = s.clock().Add(s.refreshInterval)
		}
		bounded, cancel := context.WithTimeout(ctx, 45*time.Second)
		q := advisorydb.New(s.pool)
		if err := q.PruneAdvisoryExceptionRequests(bounded); err != nil && ctx.Err() == nil {
			slog.Warn("advisory receipt retention failed", "error", err)
		}
		if err := q.PruneAdvisoryExceptions(bounded); err != nil && ctx.Err() == nil {
			slog.Warn("advisory exception retention failed", "error", err)
		}
		if len(s.config.GetFeeds()) == 0 {
			cancel()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				continue
			}
		}
		ids, err := advisorydb.New(s.pool).ListAdvisoryDeviceIDs(bounded, after)
		if err == nil {
			for _, id := range ids {
				if _, err := s.Evaluate(bounded, id); err != nil && bounded.Err() == nil {
					slog.Warn("advisory evaluation failed", "device_id", id, "error", err)
				}
				after = id
				if bounded.Err() != nil {
					break
				}
			}
			if len(ids) < 100 {
				after = uuid.Nil
			}
		} else if ctx.Err() == nil {
			slog.Warn("advisory scan failed", "error", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func timestamp(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: !t.IsZero()}
}
