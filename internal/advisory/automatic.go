// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/advisory/advisorydb"
	"lindm/internal/advisory/feed"
	"lindm/internal/platform"
)

func (s *Service) selectedSources(ctx context.Context, q *advisorydb.Queries) ([]*advisoryv1.FeedSource, error) {
	sources := append([]*advisoryv1.FeedSource(nil), s.config.GetFeeds()...)
	if !s.config.GetAutomaticInventoryFeeds() {
		return sources, nil
	}
	if err := s.resolveAutomaticIdentities(ctx, q); err != nil {
		return nil, err
	}
	identities, err := q.ListAutomaticAdvisoryInventory(ctx, s.automaticRevision)
	if err != nil {
		return nil, err
	}
	for _, identity := range identities {
		release := platform.Identify(platform.OSRelease{ID: identity.OsID, VersionID: identity.OsVersion})
		registered, err := s.automaticSources(release, identity.OsVersion, identity.Architecture)
		if err != nil {
			continue // Unknown, derivative and partial products remain unchecked.
		}
		stream := identity.AdvisoryPlatformStream
		for _, source := range registered {
			if release.Advisory.PlatformStreams && (stream == "" || stream != source.GetPlatformStream()) {
				continue
			}
			exists := false
			for _, current := range sources {
				if current.GetId() == source.GetId() || feed.Applies(current, identity.OsID, identity.OsVersion, identity.Architecture) && current.GetPlatformStream() == source.GetPlatformStream() {
					exists = true
					break
				}
			}
			if !exists && len(sources) < 32 {
				sources = append(sources, source)
			}
		}
	}
	return sources, nil
}

// automaticSources validates the complete inventory-derived message before it
// can become feed eligibility. Invalid observed identities remain unresolved
// coverage, not an error that blocks other devices' source reconciliation.
func (s *Service) automaticSources(release *platform.Release, version, architecture string) ([]*advisoryv1.FeedSource, error) {
	sources, err := RegisteredSources(release.Key, architecture, "auto")
	if err != nil {
		return nil, err
	}
	for _, source := range sources {
		// Complete archives must be acquired before the first parser publication.
		// Keep the validated idle allowance within the existing overall/byte caps.
		source.ProgressTimeoutSeconds = proto.Uint32(3600)
		if release.Advisory.PlatformStreams {
			source.Release = release.FeedRelease(version)
			source.Id += "-" + source.Release
		}
		if err := s.rules.Validate(source); err != nil {
			return nil, err
		}
	}
	return sources, nil
}

func (s *Service) resolveAutomaticIdentities(ctx context.Context, q *advisorydb.Queries) error {
	rows, err := q.PendingAutomaticAdvisoryIdentity(ctx, advisorydb.PendingAutomaticAdvisoryIdentityParams{StreamIds: s.streamIDs, RegistryRevision: s.automaticRevision})
	if err != nil {
		return err
	}
	for _, row := range rows {
		release := platform.Identify(platform.OSRelease{ID: row.OsID, VersionID: row.OsVersion})
		sources, sourceErr := s.automaticSources(release, row.OsVersion, row.Architecture)
		eligible := sourceErr == nil && row.OsIDStatus == 1 && row.ArchitectureStatus == 1 && (row.OsVersionStatus == 1 || release.Version.Rule == platform.VersionAbsent && row.OsVersionStatus == 2)
		stream := ""
		if eligible && release.Advisory.PlatformStreams {
			stream, err = rhelStream(row.Details, row.OsVersion, row.Architecture)
			if err != nil {
				return err
			}
			eligible = false
			for _, source := range sources {
				eligible = eligible || stream != "" && source.GetPlatformStream() == stream
			}
		}
		if err := q.ResolveAutomaticAdvisoryIdentity(ctx, advisorydb.ResolveAutomaticAdvisoryIdentityParams{GenerationID: row.GenerationID, Sequence: row.Sequence, AdvisoryRegistryRevision: s.automaticRevision, AdvisoryEligible: eligible, AdvisoryPlatformStream: stream}); err != nil {
			return err
		}
	}
	return nil
}

// reconcileFeeds uses the same configuration fence for explicit and automatic
// sources. Configuration protobufs are immutable; the shared feed rows remain
// the sole mutable authority. Identical rows retain publications and schedules.
func (s *Service) reconcileFeeds(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := advisorydb.New(tx)
	if err := q.LockAdvisoryFeedConfiguration(ctx); err != nil {
		return err
	}
	sources, err := s.selectedSources(ctx, q)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(sources))
	var retired []advisoryGeneration
	for _, source := range sources {
		if err := s.rules.Validate(source); err != nil {
			return fmt.Errorf("validate registered advisory source: %w", err)
		}
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(source)
		if err != nil {
			return err
		}
		ids = append(ids, source.GetId())
		current, err := q.LockAdvisoryFeed(ctx, source.GetId())
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil && current.Enabled && current.Architecture == source.GetArchitecture() && bytes.Equal(current.ConfigBytes, encoded) {
			continue
		}
		if err == nil && !bytes.Equal(current.ConfigBytes, encoded) {
			retired = append(retired, advisoryGeneration{feedID: source.GetId(), revision: current.Revision})
			if err := q.QueueAdvisoryGenerationCleanup(ctx, advisorydb.QueueAdvisoryGenerationCleanupParams{FeedID: source.GetId(), Generation: current.Revision}); err != nil {
				return err
			}
		}
		if err := q.ConfigureAdvisoryFeed(ctx, advisorydb.ConfigureAdvisoryFeedParams{ID: source.GetId(), Distro: source.GetDistro(), Release: source.GetRelease(), PlatformStream: source.GetPlatformStream(), Architecture: source.GetArchitecture(), SourceUrl: source.GetUrl(), ConfigBytes: encoded, Revision: uuid.New()}); err != nil {
			return fmt.Errorf("configure advisory feed: %w", err)
		}
	}
	if err := q.DisableAdvisoryFeeds(ctx, ids); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.cleanupAdvisoryGenerations(ctx, retired)
	return nil
}

func (s *Service) configuredSources(ctx context.Context) ([]*advisoryv1.FeedSource, error) {
	rows, err := advisorydb.New(s.pool).ListAdvisoryFeeds(ctx)
	if err != nil {
		return nil, err
	}
	sources := make([]*advisoryv1.FeedSource, 0, len(rows))
	for _, row := range rows {
		source := new(advisoryv1.FeedSource)
		if err := proto.Unmarshal(row.ConfigBytes, source); err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	return sources, nil
}

// dueSources never puts a newly activated feed behind another feed's interval.
func (s *Service) dueSources(ctx context.Context) ([]*advisoryv1.FeedSource, error) {
	rows, err := advisorydb.New(s.pool).ListAdvisoryFeeds(ctx)
	if err != nil {
		return nil, err
	}
	var sources []*advisoryv1.FeedSource
	for _, row := range rows {
		if row.AttemptedAt.Valid && s.clock().Before(row.AttemptedAt.Time.Add(s.refreshInterval)) {
			continue
		}
		source := new(advisoryv1.FeedSource)
		if err := proto.Unmarshal(row.ConfigBytes, source); err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	return sources, nil
}
