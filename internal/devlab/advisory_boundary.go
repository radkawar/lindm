package devlab

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/advisory"
	"lindm/internal/config"
)

// PublishedAdvisoryBoundary is a version-only oracle input drawn from an actual
// publication. It is never an assertion that either version is installed.
type PublishedAdvisoryBoundary struct {
	Claim             *advisoryv1.Advisory `json:"claim"`
	ComparisonClaim   *advisoryv1.Advisory `json:"comparison_claim,omitempty"`
	VulnerableVersion string               `json:"vulnerable_version"`
	VersionOrigin     string               `json:"version_origin"`
}

// ReadPublishedAdvisoryBoundary reads only this fixture's digest-bound active
// publication. No synthetic feed or package is inserted into the server. Bounded
// streaming avoids loading an entire vendor export for a two-version oracle.
func (f *AuthorityFixture) ReadPublishedAdvisoryBoundary(ctx context.Context, feedID, sourceSHA256, manager string) (*PublishedAdvisoryBoundary, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	digest, err := hex.DecodeString(sourceSHA256)
	if err != nil || len(digest) != 32 {
		return nil, errors.New("advisory boundary requires a publication SHA256")
	}
	document, err := config.Load(f.configPath())
	if err != nil {
		return nil, err
	}
	resources, err := document.Resolve()
	if err != nil {
		return nil, err
	}
	defer resources.HTTPClient.CloseIdleConnections()
	pool, err := pgxpool.NewWithConfig(ctx, resources.Database)
	if err != nil {
		return nil, err
	}
	defer pool.Close()
	rows, err := pool.Query(ctx, `SELECT r.record_bytes FROM advisory_records r JOIN advisory_feeds f ON f.id=r.feed_id WHERE f.id=$1 AND f.source_sha256=$2 ORDER BY r.package_name,r.id LIMIT 100000`, feedID, digest)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var previous []*advisoryv1.Advisory
	var packageName string
	remaining := 64 << 20
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		remaining -= len(data)
		if remaining < 0 || len(data) > 64<<10 {
			return nil, errors.New("advisory boundary exceeded bounded publication scan")
		}
		record := new(advisoryv1.Advisory)
		if err := proto.Unmarshal(data, record); err != nil {
			return nil, err
		}
		if record.GetPackageName() != packageName {
			previous = previous[:0]
			packageName = record.GetPackageName()
		}
		if !boundaryClaim(record) {
			continue
		}
		for _, candidate := range []struct{ version, origin string }{
			{record.GetIntroducedVersion(), "claim.introduced_version"},
			{record.GetLastAffectedVersion(), "claim.last_affected_version"},
		} {
			if candidate.version != "" && candidate.version != "0" && versionInsideBoundary(manager, candidate.version, record) {
				return &PublishedAdvisoryBoundary{Claim: record, VulnerableVersion: candidate.version, VersionOrigin: candidate.origin}, nil
			}
		}
		for _, earlier := range previous {
			if boundary := publishedBoundaryPair(manager, record, earlier); boundary != nil {
				return boundary, nil
			}
			if boundary := publishedBoundaryPair(manager, earlier, record); boundary != nil {
				return boundary, nil
			}
		}
		if len(previous) < 256 {
			previous = append(previous, record)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("no real vendor vulnerable/fixed version pair in bounded publication scan")
}

func boundaryClaim(record *advisoryv1.Advisory) bool {
	return record.GetFixedVersion() != "" && !record.GetAssessmentUnknown() && !record.GetSourceRecordRejected() && !record.GetNotAffected()
}

func versionInsideBoundary(manager, version string, record *advisoryv1.Advisory) bool {
	inside, err := advisory.MatchesVersion(manager, version, record)
	if err != nil || !inside {
		return false
	}
	fixedInside, err := advisory.MatchesVersion(manager, record.GetFixedVersion(), record)
	return err == nil && !fixedInside
}

func publishedBoundaryPair(manager string, target, other *advisoryv1.Advisory) *PublishedAdvisoryBoundary {
	if !boundaryClaim(target) || !boundaryClaim(other) || target.GetPackageName() != other.GetPackageName() || target.GetArchitecture() != other.GetArchitecture() || target.GetSourcePackage() != other.GetSourcePackage() || !versionInsideBoundary(manager, other.GetFixedVersion(), target) {
		return nil
	}
	return &PublishedAdvisoryBoundary{Claim: target, ComparisonClaim: other, VulnerableVersion: other.GetFixedVersion(), VersionOrigin: "comparison_claim.fixed_version"}
}
