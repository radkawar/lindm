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
	"github.com/jackc/pgx/v5"
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
	var retired []advisoryGeneration
	for _, source := range cfg.GetFeeds() {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(source)
		if err != nil {
			return nil, err
		}
		ids = append(ids, source.GetId())
		current, err := q.LockAdvisoryFeed(ctx, source.GetId())
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		if err == nil && !bytes.Equal(current.ConfigBytes, encoded) {
			retired = append(retired, advisoryGeneration{feedID: source.GetId(), revision: current.Revision})
			if err := q.QueueAdvisoryGenerationCleanup(ctx, advisorydb.QueueAdvisoryGenerationCleanupParams{FeedID: source.GetId(), Generation: current.Revision}); err != nil {
				return nil, err
			}
		}
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
	s.cleanupAdvisoryGenerations(ctx, retired)
	return s, nil
}

// Refresh explicitly refreshes all configured feeds even when scheduled egress is
// disabled. Each feed has an independent bounded fetch and atomic publication.
func (s *Service) Refresh(ctx context.Context) error {
	// Maintenance also runs when egress is disabled or no sources are configured.
	s.cleanupAdvisoryGenerations(ctx, nil)
	var result error
	for _, source := range s.config.GetFeeds() {
		if err := ctx.Err(); err != nil {
			return errors.Join(result, err)
		}
		started := s.clock().UTC()
		bounded, cancel := context.WithTimeout(ctx, 5*time.Minute)
		err := s.publishStream(bounded, source, started, func(emit func(*advisoryv1.Advisory) error) (*advisoryv1.FeedDocument, error) {
			return s.client.FetchStream(bounded, source, emit)
		})
		cancel()
		if err != nil {
			result = errors.Join(result, fmt.Errorf("refresh feed %s: %w", source.GetId(), err))
			encoded, encodeErr := proto.MarshalOptions{Deterministic: true}.Marshal(source)
			result = errors.Join(result, encodeErr)
			if encodeErr == nil {
				failureCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				storeErr := advisorydb.New(s.pool).FailAdvisoryFeed(failureCtx, advisorydb.FailAdvisoryFeedParams{ID: source.GetId(), AttemptedAt: timestamp(started), Error: "refresh_failed", ConfigBytes: encoded})
				stop()
				result = errors.Join(result, storeErr)
			}
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
		started := s.clock().UTC()
		bounded, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		return s.publishStream(bounded, source, started, func(emit func(*advisoryv1.Advisory) error) (*advisoryv1.FeedDocument, error) {
			doc, err := feed.ParseStream(bounded, source, input, emit)
			if err != nil {
				return nil, err
			}
			// A byte pin establishes integrity, not when the vendor served the
			// snapshot. Imports cannot establish current complete coverage.
			doc.CompleteSnapshot = false
			return doc, nil
		})
	}
	return ErrNotFound
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
		cleanupCtx, cleanupCancel := context.WithTimeout(ctx, 30*time.Second)
		if err := s.drainAdvisoryGenerationCleanup(cleanupCtx); err != nil && ctx.Err() == nil {
			slog.Warn("advisory generation cleanup deferred", "error", err)
		}
		cleanupCancel()
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
