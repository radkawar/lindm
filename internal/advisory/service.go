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
		err := s.publishStream(ctx, source, started, func(producerCtx context.Context, emit func(*advisoryv1.Advisory) error, progress func() error) (*advisoryv1.FeedDocument, error) {
			return s.client.FetchStream(producerCtx, source, emit, progress)
		})
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
		return s.publishStream(ctx, source, started, func(producerCtx context.Context, emit func(*advisoryv1.Advisory) error, progress func() error) (*advisoryv1.FeedDocument, error) {
			doc, err := feed.ParseStream(producerCtx, source, input, emit, progress)
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

const (
	// evaluationBatch bounds one pending-device query; each device is matched
	// in its own bounded transaction.
	evaluationBatch = 32
	// evaluationPoll is the latency between a published snapshot/feed
	// generation and its persisted evaluation; reads never match inline.
	evaluationPoll = 5 * time.Second
	// evaluationBudget bounds one evaluation pass before the loop yields to
	// its ticker again.
	evaluationBudget = 45 * time.Second
)

// RunMaintenance is the exclusive refresh, publication-cleanup and retention
// job. It returns only on cancellation. The refresh schedule derives from each
// feed's durable attempted_at, so a leadership change or rolling restart does
// not repeat a vendor fetch. Inventory matching continues with egress disabled
// in RunEvaluations, which runs beside, not behind, a long feed refresh.
func (s *Service) RunMaintenance(ctx context.Context) error {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	// The local floor keeps the previous per-process cadence even if recording
	// an attempt fails; durable attempts add the cross-instance schedule.
	var nextLocalRefresh time.Time
	for {
		cleanupCtx, cleanupCancel := context.WithTimeout(ctx, 30*time.Second)
		if err := s.drainAdvisoryGenerationCleanup(cleanupCtx); err != nil && ctx.Err() == nil {
			slog.Warn("advisory generation cleanup deferred", "error", err)
		}
		cleanupCancel()
		if s.config.GetRefreshEnabled() && !s.clock().Before(nextLocalRefresh) {
			due, err := s.refreshDue(ctx)
			if err != nil && ctx.Err() == nil {
				slog.Warn("advisory refresh schedule unavailable", "error", err)
			}
			if due {
				if err := s.Refresh(ctx); err != nil && ctx.Err() == nil {
					slog.Warn("advisory refresh failed", "error", err)
				}
				nextLocalRefresh = s.clock().Add(s.refreshInterval)
			}
		}
		bounded, cancel := context.WithTimeout(ctx, 45*time.Second)
		q := advisorydb.New(s.pool)
		if err := q.PruneAdvisoryExceptionRequests(bounded); err != nil && ctx.Err() == nil {
			slog.Warn("advisory receipt retention failed", "error", err)
		}
		if err := q.PruneAdvisoryExceptions(bounded); err != nil && ctx.Err() == nil {
			slog.Warn("advisory exception retention failed", "error", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// refreshDue reports whether any configured feed lacks an attempt within the
// refresh interval. Every attempt, successful or failed, records attempted_at.
func (s *Service) refreshDue(ctx context.Context) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	feeds, err := advisorydb.New(s.pool).ListAdvisoryFeeds(ctx)
	if err != nil {
		return false, fmt.Errorf("list advisory feeds: %w", err)
	}
	attempted := make(map[string]time.Time, len(feeds))
	for _, row := range feeds {
		if row.AttemptedAt.Valid {
			attempted[row.ID] = row.AttemptedAt.Time
		}
	}
	now := s.clock()
	for _, source := range s.config.GetFeeds() {
		last, ok := attempted[source.GetId()]
		if !ok || !now.Before(last.Add(s.refreshInterval)) {
			return true, nil
		}
	}
	return false, nil
}

// RunEvaluations is the exclusive evaluation job and returns only on
// cancellation. It does not gate on this process's configured feeds: feeds are
// configured and published in the shared database, possibly by another
// process, and reads depend on this job alone for evaluation.
func (s *Service) RunEvaluations(ctx context.Context) error {
	ticker := time.NewTicker(evaluationPoll)
	defer ticker.Stop()
	for {
		pass, cancel := context.WithTimeout(ctx, evaluationBudget)
		for pass.Err() == nil {
			attempted, err := s.EvaluatePending(pass, evaluationBatch)
			if err != nil && ctx.Err() == nil {
				slog.Warn("advisory evaluation failed", "error", err)
			}
			// A failing batch is retried on the next tick, not spun on.
			if err != nil || attempted < evaluationBatch {
				break
			}
		}
		cancel()
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// EvaluatePending persists fresh evaluations for at most limit active devices
// whose stored evaluation no longer binds their current snapshot, host
// observation or feed generation. It returns the number of devices attempted.
// Device reads serve only these persisted evaluations.
func (s *Service) EvaluatePending(ctx context.Context, limit int32) (int, error) {
	ids, err := advisorydb.New(s.pool).ListAdvisoryEvaluationsPending(ctx, limit)
	if err != nil {
		return 0, fmt.Errorf("list pending advisory evaluations: %w", err)
	}
	var failed error
	for i, id := range ids {
		if err := ctx.Err(); err != nil {
			return i, err
		}
		if _, err := s.Evaluate(ctx, id); err != nil {
			if ctx.Err() != nil {
				return i, ctx.Err()
			}
			failed = errors.Join(failed, fmt.Errorf("evaluate device %s: %w", id, err))
		}
	}
	return len(ids), failed
}

func timestamp(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: !t.IsZero()}
}
