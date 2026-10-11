package advisory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/advisory/feed"
)

// ErrStale reports an offline snapshot acquired in the future or already past
// its feed's max_age.
var ErrStale = errors.New("advisory_snapshot_stale")

const maxSnapshotArtifacts = 16

// Snapshot is one signed offline-bundle feed snapshot; the caller has already
// authenticated Input's bytes against the bundle signature.
type Snapshot struct {
	Source     *advisoryv1.FeedSource
	Input      io.Reader
	AcquiredAt time.Time
	Artifacts  []*advisoryv1.FeedArtifact
	SnapshotAt *time.Time
}

// ImportSnapshot publishes a signed offline-bundle snapshot. Unlike Import, the
// bundle signature authenticates the acquisition time, so freshness is
// AcquiredAt+max_age and coverage stays what the parser established. An older
// AcquiredAt than the current publication's checked_at is a no-op.
func (s *Service) ImportSnapshot(ctx context.Context, snapshot Snapshot) error {
	if snapshot.Source == nil || snapshot.Input == nil {
		return ErrInvalid
	}
	if err := validateSnapshotArtifacts(snapshot.Artifacts); err != nil {
		return err
	}
	source, err := s.configuredFeed(snapshot.Source)
	if err != nil {
		return err
	}
	acquired := snapshot.AcquiredAt.UTC()
	now := s.clock().UTC()
	if acquired.IsZero() || acquired.After(now) || !now.Before(acquired.Add(time.Duration(source.GetMaxAgeSeconds())*time.Second)) {
		return ErrStale
	}
	var snapshotAt *timestamppb.Timestamp
	if snapshot.SnapshotAt != nil {
		snapshotAt = timestamppb.New(*snapshot.SnapshotAt)
	}
	return s.publishStreamReason(ctx, source, acquired, "Vendor advisory revision published from signed offline bundle", func(producerCtx context.Context, emit func(*advisoryv1.Advisory) error, progress func() error) (*advisoryv1.FeedDocument, error) {
		doc, err := feed.ParseStream(producerCtx, source, snapshot.Input, emit, progress)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(snapshot.Artifacts[0].GetSha256(), doc.GetSourceSha256()) {
			return nil, fmt.Errorf("%w: primary artifact digest differs from snapshot bytes", ErrInvalid)
		}
		doc.Artifacts = snapshot.Artifacts
		if snapshotAt != nil {
			doc.SnapshotAt = snapshotAt
		}
		return doc, nil
	})
}

// configuredFeed returns the configured source byte-identical to source.
func (s *Service) configuredFeed(source *advisoryv1.FeedSource) (*advisoryv1.FeedSource, error) {
	want, err := proto.MarshalOptions{Deterministic: true}.Marshal(source)
	if err != nil {
		return nil, fmt.Errorf("%w: encode snapshot source: %w", ErrInvalid, err)
	}
	for _, configured := range s.config.GetFeeds() {
		if configured.GetId() != source.GetId() {
			continue
		}
		got, err := proto.MarshalOptions{Deterministic: true}.Marshal(configured)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(got, want) {
			return nil, ErrConflict
		}
		return configured, nil
	}
	return nil, ErrNotFound
}

func validateSnapshotArtifacts(artifacts []*advisoryv1.FeedArtifact) error {
	if len(artifacts) == 0 || len(artifacts) > maxSnapshotArtifacts {
		return fmt.Errorf("%w: snapshot requires 1..%d artifacts", ErrInvalid, maxSnapshotArtifacts)
	}
	for _, artifact := range artifacts {
		if artifact == nil || len(artifact.GetSha256()) != sha256.Size {
			return fmt.Errorf("%w: snapshot artifact requires a SHA-256 digest", ErrInvalid)
		}
	}
	return nil
}
