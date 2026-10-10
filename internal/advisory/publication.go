package advisory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/advisory/advisorydb"
)

const advisoryPublicationBatchSize = 500

type advisoryGeneration struct {
	feedID   string
	revision uuid.UUID
}

// publishStream commits bounded batches under a private generation. Only the
// final fenced feed update exposes them, after the producer has verified its
// entire input (including the digest). The producer must call emit serially.
func (s *Service) publishStream(ctx context.Context, source *advisoryv1.FeedSource, started time.Time, producer func(func(*advisoryv1.Advisory) error) (*advisoryv1.FeedDocument, error)) (err error) {
	if source == nil || producer == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(source)
	if err != nil {
		return err
	}
	elapsed := time.Now()
	generation := advisoryGeneration{feedID: source.GetId(), revision: uuid.New()}
	if err := advisorydb.New(s.pool).StartAdvisoryGeneration(ctx, advisorydb.StartAdvisoryGenerationParams{FeedID: generation.feedID, Generation: generation.revision}); err != nil {
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
	var emitted uint64
	var unique int64
	var sinkErr error
	batch := make([]advisorydb.InsertAdvisoryPublicationBatchParams, 0, advisoryPublicationBatchSize)
	namespace := uuid.NewSHA1(uuid.NameSpaceOID, []byte(source.GetId()))
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		inserted, err := s.stageAdvisoryBatch(ctx, generation.revision, batch)
		clear(batch)
		batch = batch[:0]
		if err != nil {
			return err
		}
		unique += inserted
		return nil
	}
	emit := func(record *advisoryv1.Advisory) error {
		if sinkErr != nil {
			return sinkErr
		}
		if sinkErr = ctx.Err(); sinkErr != nil {
			return sinkErr
		}
		if emitted >= limit {
			sinkErr = ErrCapacity
			return sinkErr
		}
		emitted++
		if record == nil {
			sinkErr = ErrInvalid
			return sinkErr
		}
		if size := proto.Size(record); size == 0 || size > 64<<10 {
			sinkErr = ErrCapacity
			return sinkErr
		}
		payload, marshalErr := proto.MarshalOptions{Deterministic: true}.Marshal(record)
		if marshalErr != nil {
			sinkErr = marshalErr
			return sinkErr
		}
		batch = append(batch, advisorydb.InsertAdvisoryPublicationBatchParams{
			PublicationID: generation.revision,
			Position:      int16(len(batch)),
			ID:            uuid.NewSHA1(namespace, payload),
			FeedID:        source.GetId(),
			AdvisoryID:    record.GetId(),
			PackageName:   record.GetPackageName(),
			SourcePackage: record.GetSourcePackage(),
			Architecture:  record.GetArchitecture(),
			RecordBytes:   payload,
		})
		if len(batch) == advisoryPublicationBatchSize {
			sinkErr = flush()
		}
		return sinkErr
	}
	doc, err := producer(emit)
	if err != nil || sinkErr != nil {
		return errors.Join(err, sinkErr)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if doc == nil || len(doc.GetSourceSha256()) != sha256.Size {
		return ErrInvalid
	}
	artifacts := doc.GetArtifacts()
	if len(artifacts) == 0 {
		artifacts = []*advisoryv1.FeedArtifact{{Url: source.GetUrl(), Sha256: doc.GetSourceSha256()}}
	}
	publication := &advisoryv1.FeedManifest{Artifacts: artifacts, RejectedRecords: doc.GetRejectedRecords()}
	if proto.Size(publication) > 64<<10 {
		return ErrCapacity
	}
	manifest, err := proto.MarshalOptions{Deterministic: true}.Marshal(publication)
	if err != nil {
		return err
	}
	complete := doc.GetCompleteSnapshot()
	for _, rejected := range doc.GetRejectedRecords() {
		if rejected.GetUnscoped() || len(rejected.GetPackageNames()) == 0 {
			complete = false
			break
		}
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
	if err := flush(); err != nil {
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
	if !bytes.Equal(current.SourceSha256, doc.GetSourceSha256()) || !bytes.Equal(current.SourceManifest, manifest) || current.CompleteSnapshot != complete || current.AdvisoryCount != unique {
		revision = generation.revision
		if err := q.QueueAdvisoryGenerationCleanup(ctx, advisorydb.QueueAdvisoryGenerationCleanupParams{FeedID: source.GetId(), Generation: current.Revision}); err != nil {
			return err
		}
		if err := q.FinishAdvisoryGeneration(ctx, advisorydb.FinishAdvisoryGenerationParams{FeedID: generation.feedID, Generation: generation.revision}); err != nil {
			return err
		}
		cleanup = append(cleanup, advisoryGeneration{feedID: source.GetId(), revision: current.Revision})
	}
	updated, err := q.PublishAdvisoryFeed(ctx, advisorydb.PublishAdvisoryFeedParams{ID: source.GetId(), Revision: revision, SourceSha256: doc.GetSourceSha256(), SourceManifest: manifest, SnapshotAt: snapshotAt, CheckedAt: timestamp(started), ExpiresAt: timestamp(expires), AdvisoryCount: unique, CompleteSnapshot: complete, ConfigBytes: encoded})
	if err != nil {
		return err
	}
	if updated != 1 {
		return ErrConflict
	}
	if err := q.InsertAdvisoryAudit(ctx, advisorydb.InsertAdvisoryAuditParams{ID: uuid.New(), Action: "advisory.feed.ingested", ResourceID: source.GetId(), Reason: "Vendor advisory revision published"}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	if revision == generation.revision {
		cleanup = cleanup[1:]
	}
	slog.Info("advisory feed published", "feed_id", source.GetId(), "emitted_count", emitted, "unique_count", unique, "rejected_count", len(doc.GetRejectedRecords()), "elapsed", time.Since(elapsed))
	return nil
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
