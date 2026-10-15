// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/advisory/advisorydb"
	"lindm/internal/advisory/feed"
	"lindm/internal/auditkind"
)

const (
	advisoryPublicationBatchSize  = 4096
	advisoryPublicationBatchBytes = 8 << 20
)

type advisoryGeneration struct {
	feedID   string
	revision uuid.UUID
}

const vendorPublicationReason = "Vendor advisory revision published"

// publishStream commits bounded batches under a private generation. Only the
// final fenced feed update exposes them, after the producer has verified its
// entire input (including the digest). The producer must call emit serially.
func (s *Service) publishStream(ctx context.Context, source *advisoryv1.FeedSource, started time.Time, producer func(context.Context, func(*advisoryv1.Advisory) error, func() error) (*advisoryv1.FeedDocument, error)) error {
	return s.publishStreamReason(ctx, source, started, vendorPublicationReason, producer)
}

// publishStreamReason records publication provenance in structured audit context;
// an older started time than the current checked_at is a no-op.
func (s *Service) publishStreamReason(ctx context.Context, source *advisoryv1.FeedSource, started time.Time, reason string, producer func(context.Context, func(*advisoryv1.Advisory) error, func() error) (*advisoryv1.FeedDocument, error)) (err error) {
	if source == nil || producer == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, progress := feed.NewRefreshProgress(ctx, source)
	defer progress.Close()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(source)
	if err != nil {
		return err
	}
	elapsed := time.Now()
	generation := advisoryGeneration{feedID: source.GetId(), revision: uuid.New()}
	if err := advisorydb.New(s.pool).StartAdvisoryGeneration(ctx, advisorydb.StartAdvisoryGenerationParams{FeedID: generation.feedID, Generation: generation.revision, StartedAt: timestamp(started), ConfigBytes: encoded}); err != nil {
		return err
	}
	// Include only generations owned by this call or retired by its switch.
	// Never sweep all inactive rows: another producer may still be staging them.
	cleanup := []advisoryGeneration{generation}
	defer func() { s.cleanupAdvisoryGenerations(ctx, cleanup) }()
	limit := source.GetTotalClaimsLimit()
	if source.TotalClaimsLimit == nil {
		limit = 5000000
	}
	stager := &publicationStager{
		s: s, progress: progress, generation: generation.revision, feedID: source.GetId(), limit: limit,
		namespace: uuid.NewSHA1(uuid.NameSpaceOID, []byte(source.GetId())),
		batch:     make([]advisorydb.InsertAdvisoryPublicationBatchParams, 0, advisoryPublicationBatchSize),
		payloads:  make([]byte, 0, advisoryPublicationBatchBytes+(64<<10)),
	}
	ctx, stopHeartbeat := s.startAdvisoryLeaseHeartbeat(ctx, generation.revision, time.Minute, &stager.lease)
	defer stopHeartbeat()
	emit := func(record *advisoryv1.Advisory) error { return stager.emit(ctx, record) }
	doc, err := producer(ctx, emit, progress.Mark)
	if err != nil || stager.err != nil {
		return errors.Join(err, stager.err, context.Cause(ctx))
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	revisionData, err := s.describeFeedRevision(source, doc, started)
	if err != nil {
		return err
	}
	if err := stager.flush(ctx); err != nil {
		return err
	}
	// Stop and join before removing the lease in the switch transaction. A
	// successful publication must not race a heartbeat observing its removed key.
	stopHeartbeat()
	if err := context.Cause(ctx); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			err = errors.Join(err, rollbackAdvisoryPublication(ctx, tx))
		}
	}()
	q := advisorydb.New(tx)
	current, err := q.LockAdvisoryFeed(ctx, source.GetId())
	if err != nil {
		return err
	}
	if !current.Enabled || !bytes.Equal(current.ConfigBytes, encoded) {
		return ErrConflict
	}
	if current.CheckedAt.Valid && current.CheckedAt.Time.After(started) {
		return nil
	}
	renewed, err := q.RenewAdvisoryGeneration(ctx, generation.revision)
	if err != nil {
		return err
	}
	if renewed != 1 {
		return ErrConflict
	}
	revision := current.Revision
	// Rejection/coverage changes invalidate evaluations even for identical raw
	// vendor bytes. A genuinely identical refresh only extends freshness.
	if !bytes.Equal(current.SourceSha256, doc.GetSourceSha256()) || !bytes.Equal(current.SourceManifest, revisionData.manifest) || current.CompleteSnapshot != revisionData.complete || current.AdvisoryCount != stager.unique {
		revision = generation.revision
		if err := q.QueueAdvisoryGenerationCleanup(ctx, advisorydb.QueueAdvisoryGenerationCleanupParams{FeedID: source.GetId(), Generation: current.Revision}); err != nil {
			return err
		}
		if err := q.FinishAdvisoryGeneration(ctx, advisorydb.FinishAdvisoryGenerationParams{FeedID: generation.feedID, Generation: generation.revision}); err != nil {
			return err
		}
		cleanup = append(cleanup, advisoryGeneration{feedID: source.GetId(), revision: current.Revision})
	}
	updated, err := q.PublishAdvisoryFeed(ctx, advisorydb.PublishAdvisoryFeedParams{ID: source.GetId(), Revision: revision, SourceSha256: doc.GetSourceSha256(), SourceManifest: revisionData.manifest, SnapshotAt: revisionData.snapshotAt, CheckedAt: timestamp(started), ExpiresAt: timestamp(revisionData.expires), AdvisoryCount: stager.unique, CompleteSnapshot: revisionData.complete, ConfigBytes: encoded})
	if err != nil {
		return err
	}
	if updated != 1 {
		return ErrConflict
	}
	if err := q.InsertAdvisoryAudit(ctx, advisorydb.InsertAdvisoryAuditParams{ID: uuid.New(), Action: auditkind.AdvisoryFeedIngested.String(), ResourceID: source.GetId(), Context: reason}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	if revision == generation.revision {
		cleanup = cleanup[1:]
	}
	slog.Info("advisory feed published", "feed_id", source.GetId(), "emitted_count", stager.emitted, "unique_count", stager.unique, "rejected_count", len(doc.GetRejectedRecords()), "elapsed", time.Since(elapsed))
	return nil
}

// publicationStager stages one generation's emitted advisories in bounded
// batches. A sink error is sticky: every later emit returns it.
type publicationStager struct {
	s          *Service
	lease      sync.Mutex
	progress   *feed.RefreshProgress
	generation uuid.UUID
	feedID     string
	namespace  uuid.UUID
	limit      uint64
	batch      []advisorydb.InsertAdvisoryPublicationBatchParams
	payloads   []byte
	emitted    uint64
	unique     int64
	err        error
}

func (p *publicationStager) flush(ctx context.Context) error {
	if len(p.batch) == 0 {
		return nil
	}
	// The batch renews and locks its own lease until commit. A heartbeat must
	// wait outside its SQL timeout rather than cancel that same transaction.
	p.lease.Lock()
	inserted, err := p.s.stageAdvisoryBatch(ctx, p.generation, p.batch)
	p.lease.Unlock()
	clear(p.batch)
	p.batch = p.batch[:0]
	p.payloads = p.payloads[:0]
	if err != nil {
		return err
	}
	p.unique += inserted
	return p.progress.Mark()
}

func (p *publicationStager) emit(ctx context.Context, record *advisoryv1.Advisory) error {
	if p.err != nil {
		return p.err
	}
	if p.err = ctx.Err(); p.err != nil {
		return p.err
	}
	if p.emitted >= p.limit {
		p.err = ErrCapacity
		return p.err
	}
	p.emitted++
	if record == nil {
		p.err = ErrInvalid
		return p.err
	}
	if size := proto.Size(record); size == 0 || size > 64<<10 {
		p.err = ErrCapacity
		return p.err
	}
	start := len(p.payloads)
	encoded, marshalErr := proto.MarshalOptions{Deterministic: true}.MarshalAppend(p.payloads, record)
	if marshalErr != nil {
		p.err = marshalErr
		return p.err
	}
	p.payloads = encoded
	payload := encoded[start:]
	p.batch = append(p.batch, advisorydb.InsertAdvisoryPublicationBatchParams{
		PublicationID: p.generation,
		Position:      int16(len(p.batch)),
		ID:            uuid.NewSHA1(p.namespace, payload),
		FeedID:        p.feedID,
		AdvisoryID:    record.GetId(),
		PackageName:   record.GetPackageName(),
		SourcePackage: record.GetSourcePackage(),
		Architecture:  record.GetArchitecture(),
		RecordBytes:   payload,
	})
	if len(p.batch) == advisoryPublicationBatchSize || len(p.payloads) >= advisoryPublicationBatchBytes {
		p.err = p.flush(ctx)
	}
	return p.err
}

// feedRevision is the verified feed-level metadata a publication records.
type feedRevision struct {
	manifest   []byte
	complete   bool
	snapshotAt pgtype.Timestamptz
	expires    time.Time
}

// describeFeedRevision validates the producer's document and derives its
// bounded manifest, completeness, snapshot time and expiry. Any unscoped
// rejection makes the snapshot incomplete; expiry never outlives the snapshot.
func (s *Service) describeFeedRevision(source *advisoryv1.FeedSource, doc *advisoryv1.FeedDocument, started time.Time) (feedRevision, error) {
	if doc == nil || len(doc.GetSourceSha256()) != sha256.Size {
		return feedRevision{}, ErrInvalid
	}
	artifacts := doc.GetArtifacts()
	if len(artifacts) == 0 {
		artifacts = []*advisoryv1.FeedArtifact{{Url: source.GetUrl(), Sha256: doc.GetSourceSha256()}}
	}
	publication := &advisoryv1.FeedManifest{Artifacts: artifacts, RejectedRecords: doc.GetRejectedRecords(), RedhatSnapshot: doc.GetRedhatSnapshot()}
	if proto.Size(publication) > 64<<10 {
		return feedRevision{}, ErrCapacity
	}
	manifest, err := proto.MarshalOptions{Deterministic: true}.Marshal(publication)
	if err != nil {
		return feedRevision{}, err
	}
	revision := feedRevision{manifest: manifest, complete: doc.GetCompleteSnapshot()}
	for _, rejected := range doc.GetRejectedRecords() {
		if rejected.GetUnscoped() || len(rejected.GetPackageNames()) == 0 {
			revision.complete = false
			break
		}
	}
	revision.expires = started.Add(time.Duration(source.GetMaxAgeSeconds()) * time.Second)
	if doc.GetSnapshotAt() != nil {
		if err := doc.GetSnapshotAt().CheckValid(); err != nil || doc.GetSnapshotAt().AsTime().After(s.clock().UTC()) {
			return feedRevision{}, ErrInvalid
		}
		revision.snapshotAt = timestamp(doc.GetSnapshotAt().AsTime())
		if until := revision.snapshotAt.Time.Add(time.Duration(source.GetMaxAgeSeconds()) * time.Second); until.Before(revision.expires) {
			revision.expires = until
		}
	}
	return revision, nil
}

// stageAdvisoryBatch uses one short transaction, not a connection held while the
// vendor is downloading. Database conflict handling deduplicates within and across
// batches without retaining a feed-sized map in the server.
func (s *Service) stageAdvisoryBatch(ctx context.Context, publicationID uuid.UUID, batch []advisorydb.InsertAdvisoryPublicationBatchParams) (inserted int64, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			err = errors.Join(err, rollbackAdvisoryPublication(ctx, tx))
		}
	}()
	q := advisorydb.New(tx)
	renewed, err := q.RenewAdvisoryGeneration(ctx, publicationID)
	if err != nil {
		return 0, err
	}
	if renewed != 1 {
		return 0, ErrConflict
	}
	if _, err := q.InsertAdvisoryPublicationBatch(ctx, batch); err != nil {
		return 0, fmt.Errorf("copy advisory publication batch: %w", err)
	}
	inserted, err = q.MergeAdvisoryPublicationBatch(ctx, publicationID)
	if err != nil {
		return 0, fmt.Errorf("merge advisory publication batch: %w", err)
	}
	if err := q.DeleteAdvisoryPublicationBatch(ctx, publicationID); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	committed = true
	return inserted, nil
}

func rollbackAdvisoryPublication(ctx context.Context, tx pgx.Tx) error {
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := tx.Rollback(bounded); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("rollback advisory publication: %w", err)
	}
	return nil
}

// Cleanup records exact owned generations before draining. Staging leases already
// exist durably if cancellation, a crash, or a transient failure prevents marking
// them due immediately. A cleanup failure never changes publication success.
func (s *Service) cleanupAdvisoryGenerations(ctx context.Context, generations []advisoryGeneration) {
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	q := advisorydb.New(s.pool)
	for _, generation := range generations {
		if err := q.QueueAdvisoryGenerationCleanup(bounded, advisorydb.QueueAdvisoryGenerationCleanupParams{FeedID: generation.feedID, Generation: generation.revision}); err != nil {
			slog.Warn("advisory cleanup scheduling failed", "feed_id", generation.feedID, "generation", generation.revision, "error", err)
			return
		}
	}
	if err := s.drainAdvisoryGenerationCleanup(bounded); err != nil {
		slog.Warn("advisory generation cleanup deferred", "error", err)
	}
}

// drainAdvisoryGenerationCleanup resumes durable work, including expired staging
// leases. Each transaction locks one queue key and removes at most 5000 records.
// The same key serializes producer renewal, publication and cleanup; a producer
// that lost its lease cannot recreate deleted rows or publish a partial snapshot.
// Publishers lock the feed before this key. Cleanup never takes a feed row lock:
// its active-revision check is an MVCC read, avoiding the reverse lock order.
// If cleanup wins an expired staging key, renewal fails before publication.
func (s *Service) drainAdvisoryGenerationCleanup(ctx context.Context) error {
	for {
		more, err := s.cleanupAdvisoryGenerationBatch(ctx)
		if err != nil || !more {
			return err
		}
	}
}

func (s *Service) cleanupAdvisoryGenerationBatch(ctx context.Context) (more bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	committed := false
	defer func() {
		if !committed {
			err = errors.Join(err, rollbackAdvisoryPublication(ctx, tx))
		}
	}()
	q := advisorydb.New(tx)
	generation, err := q.LockAdvisoryGenerationCleanup(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := q.DeleteAdvisoryPublicationBatch(ctx, generation.Generation); err != nil {
		return false, err
	}
	deleted, err := q.DeleteInactiveAdvisoryGenerationBatch(ctx, advisorydb.DeleteInactiveAdvisoryGenerationBatchParams(generation))
	if err != nil {
		return false, err
	}
	if deleted < 5000 {
		if err := q.FinishAdvisoryGeneration(ctx, advisorydb.FinishAdvisoryGenerationParams(generation)); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	committed = true
	return true, nil
}
