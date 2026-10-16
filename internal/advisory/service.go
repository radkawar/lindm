// SPDX-License-Identifier: Apache-2.0

// Package advisory owns vendor advisory publication, native package matching and
// expiring risk acceptance. It never installs software or treats absent evidence
// as proof that a device is healthy.
package advisory

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/singleflight"
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
	pool              *pgxpool.Pool
	config            *configv1.AdvisoryConfig
	client            *feed.Client
	rules             protovalidate.Validator
	clock             func() time.Time
	inventoryAge      time.Duration
	refreshInterval   time.Duration
	automaticRevision []byte
	streamIDs         []string
	// setBuilds deduplicates concurrent cold builds of one finding set.
	setBuilds singleflight.Group
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
	if cfg.GetAutomaticInventoryFeeds() {
		s.automaticRevision, s.streamIDs, err = automaticProjectionRegistryRevision()
		if err != nil {
			return nil, err
		}
	}
	if err := s.reconcileFeeds(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Refresh explicitly refreshes all configured feeds even when scheduled egress is
// disabled. Each feed has an independent bounded fetch and atomic publication.
func (s *Service) Refresh(ctx context.Context) error {
	// Maintenance also runs when egress is disabled or no sources are configured.
	s.cleanupAdvisoryGenerations(ctx, nil)
	sources, err := s.configuredSources(ctx)
	if err != nil {
		return err
	}
	return s.refreshSources(ctx, sources)
}

func (s *Service) refreshSources(ctx context.Context, sources []*advisoryv1.FeedSource) error {
	results := make([]error, len(sources)+1)
	var next atomic.Int64
	var workers sync.WaitGroup
	// One maintenance leader owns this call. Its cancellation joins all source
	// workers before returning, including on leadership loss.
	for range min(2, len(sources)) {
		workers.Go(func() {
			for {
				index := int(next.Add(1)) - 1
				if index >= len(sources) || ctx.Err() != nil {
					return
				}
				results[index] = s.refreshSource(ctx, sources[index])
			}
		})
	}
	workers.Wait()
	results[len(sources)] = ctx.Err()
	return errors.Join(results...)
}

func (s *Service) refreshSource(ctx context.Context, source *advisoryv1.FeedSource) error {
	var retries atomic.Int64
	ctx = feed.WithRetryCounter(ctx, &retries)
	started := s.clock().UTC()
	err := s.publishStream(ctx, source, started, func(producerCtx context.Context, emit func(*advisoryv1.Advisory) error, progress func() error) (*advisoryv1.FeedDocument, error) {
		return s.client.FetchStream(producerCtx, source, emit, progress)
	})
	if err != nil {
		return fmt.Errorf("refresh feed %s: %w", source.GetId(), err)
	}
	return nil
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
	// evaluationBatch bounds one claimed batch of pending devices; each device
	// is matched in its own bounded transaction.
	evaluationBatch = 64
	// evaluationPoll is the latency between a published snapshot/feed
	// generation and its persisted evaluation; reads never match inline.
	evaluationPoll = 5 * time.Second
	// evaluationBudget bounds one evaluation pass before the loop yields to
	// its ticker again.
	evaluationBudget = 45 * time.Second
	// evaluationClaimLease bounds how long a crashed instance's claimed batch
	// stays hidden from other instances: one pass plus a cold finding-set
	// build, which outlives its pass. Live instances release claims per batch.
	evaluationClaimLease = evaluationBudget + findingSetBuildTimeout
	// evaluationWorkers bounds concurrent device evaluations (and therefore
	// database connections taken from the shared pool by this job).
	evaluationWorkers = 4
	// findingSetPruneBatch bounds unbound shared finding sets removed per
	// minute; each cascades to its findings (tens of thousands for a stock
	// Ubuntu image).
	findingSetPruneBatch = 20
)

// RunMaintenance is the exclusive refresh, publication-cleanup and retention
// job. It returns only on cancellation. The refresh schedule derives from each
// feed's durable attempted_at, so a leadership change or rolling restart does
// not repeat a vendor fetch. Inventory matching continues with egress disabled
// in RunEvaluations, which runs beside, not behind, a long feed refresh.
func (s *Service) RunMaintenance(ctx context.Context) error {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	// Discovery runs even with refresh disabled, without making network requests.
	for {
		cleanupCtx, cleanupCancel := context.WithTimeout(ctx, 30*time.Second)
		if err := s.drainAdvisoryGenerationCleanup(cleanupCtx); err != nil && ctx.Err() == nil {
			slog.Warn("advisory generation cleanup deferred", "error", err)
		}
		cleanupCancel()
		var err error
		if s.config.GetAutomaticInventoryFeeds() {
			discover, stopDiscovery := context.WithTimeout(ctx, 15*time.Second)
			err = s.reconcileFeeds(discover)
			stopDiscovery()
		}
		if err != nil && ctx.Err() == nil {
			slog.Warn("advisory feed activation deferred", "error", err)
		}
		if err == nil && s.config.GetRefreshEnabled() {
			sources, err := s.dueSources(ctx)
			if err != nil && ctx.Err() == nil {
				slog.Warn("advisory refresh schedule unavailable", "error", err)
			}
			if err == nil {
				if err := s.refreshSources(ctx, sources); err != nil && ctx.Err() == nil {
					slog.Warn("advisory refresh failed", "error", err)
				}
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
		if _, err := q.PruneAdvisoryFindingSets(bounded, findingSetPruneBatch); err != nil && ctx.Err() == nil {
			slog.Warn("advisory finding set retention failed", "error", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// RunEvaluations is the replicated evaluation job and returns only on
// cancellation. Every instance claims disjoint batches of pending devices, so
// evaluation throughput scales with replicas; a claim only distributes work,
// while each device's row lock and exact revision bindings keep a repeated or
// overlapping evaluation coherent. It does not gate on this process's
// configured feeds: feeds are configured and published in the shared database,
// possibly by another process, and reads depend on this job alone.
func (s *Service) RunEvaluations(ctx context.Context) error {
	ticker := time.NewTicker(evaluationPoll)
	defer ticker.Stop()
	for {
		pass, cancel := context.WithTimeout(ctx, evaluationBudget)
		for pass.Err() == nil {
			attempted, failures, err := s.evaluatePending(pass, evaluationBatch)
			if err != nil && ctx.Err() == nil {
				slog.Warn("advisory evaluation failed", "error", err)
			}
			// Isolated device failures (still pending) are retried by later
			// batches; a wholly failing batch is retried on the next tick, not
			// spun on.
			if attempted < evaluationBatch || failures == attempted {
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
// Device reads serve only these persisted evaluations. Devices are evaluated by
// a few concurrent workers, each in its own bounded transaction: a device
// evaluation mostly waits on its row lock and short queries, so one serial
// worker cannot keep up with a fleet's inventory arrivals.
func (s *Service) EvaluatePending(ctx context.Context, limit int32) (int, error) {
	attempted, _, err := s.evaluatePending(ctx, limit)
	return attempted, err
}

func (s *Service) evaluatePending(ctx context.Context, limit int32) (attempted, failures int, resultErr error) {
	q := advisorydb.New(s.pool)
	token := uuid.New()
	ids, err := q.ClaimAdvisoryEvaluations(ctx, advisorydb.ClaimAdvisoryEvaluationsParams{LeaseToken: token, LeaseSeconds: int32(evaluationClaimLease / time.Second), RowLimit: limit})
	if err != nil {
		return 0, 0, fmt.Errorf("claim pending advisory evaluations: %w", err)
	}
	if len(ids) == 0 {
		return 0, 0, nil
	}
	defer func() {
		// Busy or failed devices become claimable again by any instance's next
		// batch; an unreleased claim expires after evaluationClaimLease.
		release, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := q.ReleaseAdvisoryEvaluationClaims(release, token); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("release advisory evaluation claims: %w", err))
		}
	}()
	var (
		mu   sync.Mutex
		next atomic.Int64
		wg   sync.WaitGroup
		busy int
	)
	for range min(evaluationWorkers, len(ids)) {
		wg.Go(func() {
			for {
				i := int(next.Add(1)) - 1
				if i >= len(ids) || ctx.Err() != nil {
					return
				}
				_, err := s.Evaluate(ctx, ids[i])
				if ctx.Err() != nil {
					return
				}
				mu.Lock()
				attempted++
				if errors.Is(err, ErrDeviceBusy) {
					busy++
				} else if err != nil {
					failures++
					resultErr = errors.Join(resultErr, fmt.Errorf("evaluate device %s: %w", ids[i], err))
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return attempted, failures, err
	}
	// A batch of only busy devices is retried on the next tick, not spun on.
	if busy == attempted {
		failures = attempted
	}
	return attempted, failures, resultErr
}

func timestamp(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: !t.IsZero()}
}
