package advisory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/advisory/advisorydb"
	"lindm/internal/advisory/feed"
	"lindm/internal/auditkind"
	"lindm/internal/platform"
)

// candidatePage bounds one candidate query: at most 500 records of at most
// 64 KiB each are held while matching.
const candidatePage = 500

// maxFindings is the per-device admission bound. Ubuntu's OSV export lists
// thousands of open kernel CVEs against the source package, and each installed
// binary of that source is a separate finding: the stock 24.04 cloud image with
// one kernel (6.8.0-142) has 28,821 findings against the 2026-10-10 export, and
// desktops keep several kernels. Exceeding the bound is UNKNOWN, never a
// truncated result.
const maxFindings = 100000

// ErrDeviceBusy reports that the device row is being updated; the device stays
// pending and is evaluated by a later pass.
var ErrDeviceBusy = errors.New("advisory_device_busy")

// evaluationAttempts bounds retries of transaction conflicts and concurrent
// finding-set creation. Retries back off with jitter so workers do not
// re-collide; every attempt rereads the locked device's current inputs.
const evaluationAttempts = 8

// Evaluate publishes one bounded evaluation of the device's current immutable
// snapshot under its device-row lock. Publication of a new snapshot or feed
// immediately makes the previous evaluation UNKNOWN through the shared SQL view.
func (s *Service) Evaluate(ctx context.Context, deviceID uuid.UUID) (advisorydb.AdvisoryEvaluation, error) {
	for attempt := 1; ; attempt++ {
		evaluation, err := s.evaluateOnce(ctx, deviceID)
		if missing, ok := errors.AsType[*missingFindingSet](err); ok && attempt < evaluationAttempts {
			if err := s.buildFindingSet(ctx, missing.feedID, missing.snapshotID, missing.digest, missing.coverage); err != nil {
				return advisorydb.AdvisoryEvaluation{}, err
			}
			continue
		}
		var database *pgconn.PgError
		if attempt < evaluationAttempts && errors.As(err, &database) && (database.Code == "40001" || database.Code == "40P01" || database.ConstraintName == "advisory_finding_sets_feed_id_feed_revision_package_digest_key") && ctx.Err() == nil {
			backoff := time.NewTimer(time.Duration(attempt) * time.Duration(5+rand.IntN(20)) * time.Millisecond)
			select {
			case <-ctx.Done():
				backoff.Stop()
				return advisorydb.AdvisoryEvaluation{}, ctx.Err()
			case <-backoff.C:
			}
			continue
		}
		return evaluation, err
	}
}

func (s *Service) evaluateOnce(ctx context.Context, deviceID uuid.UUID) (advisorydb.AdvisoryEvaluation, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// Inventory publication and retention share this device lock. Finding sets
	// bind an exact immutable package digest and feed revision. READ COMMITTED
	// lets the audit-head lock observe its latest committed predecessor rather
	// than aborting a coherent device binding when an unrelated audit commits.
	// Cold matching keeps its separate REPEATABLE READ snapshot below.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return advisorydb.AdvisoryEvaluation{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := advisorydb.New(tx)
	locked, err := q.TryLockAdvisoryDevice(ctx, deviceID)
	if err != nil {
		return advisorydb.AdvisoryEvaluation{}, err
	}
	if len(locked) == 0 {
		return advisorydb.AdvisoryEvaluation{}, ErrDeviceBusy
	}
	d, err := q.GetAdvisoryDevice(ctx, deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return advisorydb.AdvisoryEvaluation{}, ErrNotFound
	}
	if err != nil {
		return advisorydb.AdvisoryEvaluation{}, err
	}
	dbNow, err := q.AdvisoryDatabaseTime(ctx)
	if err != nil {
		return advisorydb.AdvisoryEvaluation{}, err
	}
	now := dbNow.Time
	feeds, err := q.ListAdvisoryFeeds(ctx)
	if err != nil {
		return advisorydb.AdvisoryEvaluation{}, err
	}
	host := platform.Identify(platform.OSRelease{ID: d.OsID, VersionID: d.OsVersion})
	// An exact derivative row selects its base release's feed, restricted to
	// verified base-archive packages; every other release keeps its own
	// identity and unrestricted matching.
	coverage := derivativeCoverage(host)
	feedOS, feedVersion := feedIdentity(coverage, d.OsID, d.OsVersion)
	platformStream := ""
	if host.Advisory.PlatformStreams {
		platformStream, err = rhelStream(d.HostDetails, d.OsVersion, d.Architecture)
		if err != nil {
			return advisorydb.AdvisoryEvaluation{}, err
		}
	}
	var selected *advisorydb.AdvisoryFeed
	var selectedSource *advisoryv1.FeedSource
	for i := range feeds {
		var source advisoryv1.FeedSource
		if err := proto.Unmarshal(feeds[i].ConfigBytes, &source); err != nil {
			return advisorydb.AdvisoryEvaluation{}, err
		}
		if feed.Applies(&source, feedOS, feedVersion, d.Architecture) && (!host.Advisory.PlatformStreams || platformStream != "" && source.GetPlatformStream() == platformStream) {
			selected = &feeds[i]
			selectedSource = &source
			break
		}
	}
	e := advisorydb.StoreAdvisoryEvaluationParams{DeviceID: deviceID, ID: uuid.New(), SnapshotID: d.CurrentSnapshotID, EvaluatedAt: dbNow, InventoryAt: d.InventoryAt, HostReceivedAt: d.HostReceivedAt, ExpiresAt: timestamp(now.Add(s.inventoryAge)), State: "evaluated"}
	unknown := func(reason string) {
		if e.State != "unknown" {
			e.State = "unknown"
			e.Reason = reason
		}
	}
	if d.State != "active" {
		unknown("device_not_active")
	}
	if d.CurrentSnapshotID == nil || !d.InventoryAt.Valid {
		unknown("inventory_unavailable")
	} else {
		e.ExpiresAt = timestamp(d.InventoryAt.Time.Add(s.inventoryAge))
		if d.InventoryAt.Time.After(now) || !now.Before(e.ExpiresAt.Time) {
			unknown("inventory_stale")
		}
	}
	// A rolling release without VERSION_ID (official Arch) is identified by
	// explicit native absence; failed collection and stale host evidence are not.
	releaseUsable := d.OsVersionStatus.Int16 == 1 || (host.Version.Rule == platform.VersionAbsent && d.OsVersionStatus.Int16 == int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE))
	if !d.HostFinishedAt.Valid || d.HostFinishedAt.Time.After(now) || !now.Before(d.HostFinishedAt.Time.Add(s.inventoryAge)) || d.OsIDStatus.Int16 != 1 || !releaseUsable || d.ArchitectureStatus.Int16 != 1 {
		unknown("host_inventory_stale_or_failed")
	}
	if d.HostFinishedAt.Valid && d.HostFinishedAt.Time.Add(s.inventoryAge).Before(e.ExpiresAt.Time) {
		e.ExpiresAt = timestamp(d.HostFinishedAt.Time.Add(s.inventoryAge))
	}
	if !d.PackageStatus.Valid || d.PackageStatus.Int16 != 1 {
		unknown("package_collection_failed")
	}
	if selected == nil {
		if host.Advisory.PlatformStreams && platformStream == "" {
			unknown("rhel_platform_stream_unavailable")
		} else {
			unknown("feed_unavailable")
		}
	} else {
		e.FeedID = selected.ID
		e.FeedRevision = &selected.Revision
		if !selected.CheckedAt.Valid || selected.CheckedAt.Time.After(now) || !selected.ExpiresAt.Valid || !now.Before(selected.ExpiresAt.Time) {
			unknown("feed_stale")
		}
		if !selected.CompleteSnapshot {
			unknown("feed_partial_coverage")
		}
	}
	previous, previousErr := q.GetAdvisoryEvaluation(ctx, deviceID)
	if previousErr != nil && !errors.Is(previousErr, pgx.ErrNoRows) {
		return advisorydb.AdvisoryEvaluation{}, previousErr
	}
	if previousErr == nil && sameID(previous.SnapshotID, e.SnapshotID) && sameID(previous.FeedRevision, e.FeedRevision) && previous.HostReceivedAt == e.HostReceivedAt && previous.State == e.State && previous.Reason == e.Reason && previous.ExpiresAt == e.ExpiresAt {
		if previous.FeedID != "" {
			return previous, nil
		}
		// Mark the feed-less recheck against the current configuration so the
		// background job does not select this unchanged device again.
		if err := q.TouchAdvisoryEvaluation(ctx, advisorydb.TouchAdvisoryEvaluationParams{DeviceID: deviceID, EvaluatedAt: dbNow, ID: previous.ID}); err != nil {
			return advisorydb.AdvisoryEvaluation{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return advisorydb.AdvisoryEvaluation{}, err
		}
		previous.EvaluatedAt = dbNow
		return previous, nil
	}
	e.FindingDigest = emptyFindingDigest()
	if selected != nil && d.CurrentSnapshotID != nil {
		missing, err := q.AdvisorySourceMappingMissing(ctx, *d.CurrentSnapshotID)
		if err != nil {
			return advisorydb.AdvisoryEvaluation{}, err
		}
		if missing {
			unknown("source_package_identity_missing")
		}
		architectures, err := q.AdvisoryArchitectures(ctx, *d.CurrentSnapshotID)
		if err != nil {
			return advisorydb.AdvisoryEvaluation{}, err
		}
		for _, arch := range architectures {
			if arch == "" || (arch != "all" && arch != "noarch" && (host.Native().Packages.Backend.PackageDB() != platform.PackageDBPacman || arch != "any") && !feed.Applies(selectedSource, feedOS, feedVersion, arch)) {
				unknown("package_architecture_uncovered")
			}
		}
		// Matching depends only on the feed generation and the exact package
		// rows, so identical package sets share one persisted finding set.
		digest, err := q.AdvisoryPackageDigest(ctx, *d.CurrentSnapshotID)
		if err != nil {
			return advisorydb.AdvisoryEvaluation{}, err
		}
		if coverage != nil {
			origins, err := q.AdvisoryOriginDigest(ctx, *d.CurrentSnapshotID)
			if err != nil {
				return advisorydb.AdvisoryEvaluation{}, err
			}
			digest = coverage.setDigest(digest, origins)
		}
		set, err := q.GetAdvisoryFindingSet(ctx, advisorydb.GetAdvisoryFindingSetParams{FeedID: selected.ID, FeedRevision: selected.Revision, PackageDigest: digest})
		if errors.Is(err, pgx.ErrNoRows) {
			// Release the connection and device row lock before waiting on a
			// shared build; retaining them would starve the device pool.
			return advisorydb.AdvisoryEvaluation{}, &missingFindingSet{feedID: selected.ID, snapshotID: *d.CurrentSnapshotID, digest: digest, coverage: coverage}
		}
		if err != nil {
			return advisorydb.AdvisoryEvaluation{}, err
		}
		if set.State != "evaluated" {
			unknown(set.Reason)
		}
		if coverage != nil {
			// No verified base-archive package at all (historical snapshots,
			// failed or empty APT lists) establishes no exposure.
			if d.PackageCount.Valid && set.UncoveredPackages >= d.PackageCount.Int32 {
				unknown("package_origin_unavailable")
			}
			if e.State == "evaluated" {
				e.State, e.Reason, e.UncoveredPackages = "partial", coverage.reason, set.UncoveredPackages
			}
		}
		e.FindingDigest = set.FindingDigest
		e.FindingSetID = &set.ID
	}
	// Candidate-level uncertainty (including a rejected source record) is
	// discovered after the fast path above. Reuse its evaluation identity when
	// evidence is unchanged so pagination does not invalidate itself.
	if previousErr == nil && sameID(previous.SnapshotID, e.SnapshotID) && sameID(previous.FeedRevision, e.FeedRevision) && previous.HostReceivedAt == e.HostReceivedAt && previous.State == e.State && previous.Reason == e.Reason && previous.ExpiresAt == e.ExpiresAt && previous.UncoveredPackages == e.UncoveredPackages && bytes.Equal(previous.FindingDigest, e.FindingDigest) && sameID(previous.FindingSetID, e.FindingSetID) {
		return previous, nil
	}
	if err := q.StoreAdvisoryEvaluation(ctx, e); err != nil {
		return advisorydb.AdvisoryEvaluation{}, err
	}
	result, err := q.GetAdvisoryEvaluation(ctx, deviceID)
	if err != nil {
		return advisorydb.AdvisoryEvaluation{}, err
	}
	// The audit append takes the deployment-wide chain head lock until commit,
	// so it is the transaction's last statement.
	if previousErr != nil || !bytes.Equal(previous.FindingDigest, e.FindingDigest) || previous.State != e.State || previous.Reason != e.Reason {
		if err := q.InsertAdvisoryAudit(ctx, advisorydb.InsertAdvisoryAuditParams{ID: uuid.New(), Action: auditkind.AdvisoryFindingsChanged.String(), ResourceID: deviceID.String(), Context: "Device advisory evidence changed"}); err != nil {
			return advisorydb.AdvisoryEvaluation{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return advisorydb.AdvisoryEvaluation{}, err
	}
	return result, nil
}

// missingFindingSet ends a device evaluation whose finding set does not exist
// yet; Evaluate builds it after the device transaction is released and
// re-evaluates in a fresh snapshot that can see it.
type missingFindingSet struct {
	feedID     string
	snapshotID uuid.UUID
	digest     []byte
	// coverage restricts a derivative's base feed to verified-origin
	// packages; its policy is already bound into digest.
	coverage *originCoverage
}

func (*missingFindingSet) Error() string { return "advisory finding set missing" }

// findingSetBuildTimeout bounds one cold match of a full package set against a
// feed generation; it is separate from the short per-device evaluation budget.
const findingSetBuildTimeout = 2 * time.Minute

// buildFindingSet matches and commits one missing finding set. Concurrent
// workers needing the same (feed, generation, package digest) share a single
// build instead of each matching identical content under row locks; another
// instance's build in progress defers the device as busy.
func (s *Service) buildFindingSet(ctx context.Context, feedID string, snapshotID uuid.UUID, digest []byte, coverage *originCoverage) error {
	key := feedID + "\x00" + string(digest)
	_, err, _ := s.setBuilds.Do(key, func() (any, error) {
		build, cancel := context.WithTimeout(context.WithoutCancel(ctx), findingSetBuildTimeout)
		defer cancel()
		tx, err := s.pool.BeginTx(build, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
		if err != nil {
			return nil, err
		}
		defer func() { _ = tx.Rollback(build) }()
		q := advisorydb.New(tx)
		locked, err := q.TryLockAdvisoryFindingSetBuild(build, findingSetBuildKey(feedID, digest))
		if err != nil {
			return nil, err
		}
		if !locked {
			return nil, fmt.Errorf("finding set built by another instance: %w", ErrDeviceBusy)
		}
		selected, err := q.GetAdvisoryFeed(build, feedID)
		if err != nil {
			return nil, err
		}
		if _, err := q.GetAdvisoryFindingSet(build, advisorydb.GetAdvisoryFindingSetParams{FeedID: selected.ID, FeedRevision: selected.Revision, PackageDigest: digest}); err == nil {
			return nil, nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		var source advisoryv1.FeedSource
		if err := proto.Unmarshal(selected.ConfigBytes, &source); err != nil {
			return nil, err
		}
		if _, err := matchFindingSet(build, q, &selected, &source, snapshotID, digest, coverage); err != nil {
			return nil, err
		}
		return nil, tx.Commit(build)
	})
	var database *pgconn.PgError
	if errors.As(err, &database) && database.ConstraintName == "advisory_finding_sets_feed_id_feed_revision_package_digest_key" {
		return nil // another instance committed the same content first
	}
	return err
}

// findingSetBuildKey names one cross-instance build: the fixed-length hex digest
// precedes the feed ID, so distinct (feed, digest) pairs never share a key.
func findingSetBuildKey(feedID string, digest []byte) string {
	return hex.EncodeToString(digest) + "/" + feedID
}

func emptyFindingDigest() []byte {
	digest := sha256.Sum256(nil)
	return digest[:]
}

// matchFindingSet matches one published snapshot against one feed generation
// and persists the device-independent result. Deterministic record/capacity
// failures persist an UNKNOWN set instead of failing the background job forever
// on unchanged evidence. Candidates arrive in bounded keyset pages; memory never
// holds more than one page of record bytes plus the admitted findings.
func matchFindingSet(ctx context.Context, q *advisorydb.Queries, selected *advisorydb.AdvisoryFeed, selectedSource *advisoryv1.FeedSource, snapshotID uuid.UUID, packageDigest []byte, coverage *originCoverage) (advisorydb.AdvisoryFindingSet, error) {
	set := advisorydb.AdvisoryFindingSet{ID: uuid.New(), FeedID: selected.ID, FeedRevision: selected.Revision, PackageDigest: packageDigest, State: "evaluated"}
	unknown := func(reason string) {
		if set.State != "unknown" {
			set.State = "unknown"
			set.Reason = reason
		}
	}
	// Uncovered packages are excluded from matching, so a vendor rebuild can
	// never appear affected or clear by base advisories.
	var uncovered []bool
	if coverage != nil {
		var err error
		if uncovered, set.UncoveredPackages, err = coverage.uncovered(ctx, q, snapshotID); err != nil {
			return set, err
		}
	}
	findings := make(map[uuid.UUID]advisorydb.InsertAdvisorySetFindingsParams)
	// Per-stream vendor feeds bind native module name/stream identity.
	modules := platform.ForFeed(selectedSource.GetDistro(), selectedSource.GetRelease()).Advisory.PlatformStreams
	var nativePredicates map[string]nativePredicateResult
	afterPosition, afterRecord := int32(-1), uuid.Nil
matching:
	for {
		rows, err := q.AdvisoryCandidates(ctx, advisorydb.AdvisoryCandidatesParams{FeedID: selected.ID, Generation: selected.Revision, SnapshotID: snapshotID, AfterPosition: afterPosition, AfterRecord: afterRecord, RowLimit: candidatePage})
		if err != nil {
			return set, err
		}
		for _, row := range rows {
			if uncovered != nil && row.Position >= 0 && row.Position < maxSnapshotPositions && uncovered[row.Position] {
				continue
			}
			var record advisoryv1.Advisory
			if err := proto.Unmarshal(row.RecordBytes, &record); err != nil {
				unknown("advisory_record_invalid")
				break matching
			}
			// OVAL architecture predicates constrain native instances exactly;
			// unlike repository noarch claims, they are not wildcard joins.
			if record.GetPrerequisitePackage() != "" && (row.Manager != "rpm" || record.GetArchitecture() != "" && row.Architecture != record.GetArchitecture()) {
				continue
			}
			if nativePredicates == nil && (record.GetPrerequisitePackage() != "" || record.GetAllInstalledInstances()) {
				nativePredicates = make(map[string]nativePredicateResult)
			}
			applicable, err := nativeApplicability(ctx, q, snapshotID, &record, nativePredicates)
			if err != nil {
				return set, err
			}
			if !applicable.applies {
				if applicable.reason != "" {
					unknown(applicable.reason)
				}
				continue
			}
			if modules && !record.GetSourceRecordRejected() {
				if row.ModuleStatus != 1 {
					unknown("native_module_identity_unavailable")
					continue
				}
				if row.ModuleName != record.GetModuleName() || row.ModuleStream != record.GetModuleStream() {
					if record.GetAssessmentUnknown() && record.GetModuleName() == "" && row.ModuleName != "" {
						unknown("vendor_module_binding_ambiguous")
					}
					continue
				}
			}
			version := row.Version
			if record.GetSourcePackage() {
				version = row.SourceVersion
			}
			affected, err := MatchesVersion(row.Manager, version, &record)
			if err != nil {
				unknown("package_version_unrecognized")
				continue
			}
			if !affected {
				continue
			}
			if record.GetSourceRecordRejected() {
				unknown("source_record_rejected")
			} else if record.GetAssessmentUnknown() {
				unknown("vendor_assessment_unknown")
			}
			key := findingKey(selected.ID, record.GetId(), row.Name, row.Version, row.Architecture)
			f := advisorydb.InsertAdvisorySetFindingsParams{SetID: set.ID, FindingKey: key, AdvisoryID: record.GetId(), PackageName: row.Name, InstalledVersion: row.Version, FixedVersion: record.GetFixedVersion(), Architecture: row.Architecture, Severity: record.GetSeverity(), Cves: record.GetCves(), SourceUrl: record.GetSourceUrl()}
			if f.Cves == nil {
				f.Cves = []string{}
			}
			if record.GetPublishedAt() != nil {
				f.PublishedAt = timestamp(record.GetPublishedAt().AsTime())
			}
			if previous, exists := findings[key]; exists {
				// A CSAF advisory can emit one matching record per CVE.
				// They are one accepted-risk identity, not last-row-wins.
				f.Cves = append(previous.Cves, f.Cves...)
				slices.Sort(f.Cves)
				f.Cves = slices.Compact(f.Cves)
				if len(f.Cves) > 2048 {
					unknown("matching_capacity_exceeded")
					break matching
				}
				if feed.SeverityRank(previous.Severity) > feed.SeverityRank(f.Severity) {
					f.Severity = previous.Severity
				}
				if previous.FixedVersion == "" || f.FixedVersion == "" {
					f.FixedVersion = ""
				} else {
					comparison, err := feed.Compare(row.Manager, previous.FixedVersion, f.FixedVersion)
					if err != nil {
						unknown("advisory_record_invalid")
						break matching
					}
					if comparison > 0 {
						f.FixedVersion = previous.FixedVersion
					}
				}
				if previous.PublishedAt.Valid && (!f.PublishedAt.Valid || previous.PublishedAt.Time.Before(f.PublishedAt.Time)) {
					f.PublishedAt = previous.PublishedAt
				}
				if previous.SourceUrl < f.SourceUrl {
					f.SourceUrl = previous.SourceUrl
				}
			}
			if _, exists := findings[key]; !exists && len(findings) == maxFindings {
				unknown("matching_capacity_exceeded")
				break matching
			}
			findings[key] = f
		}
		if len(rows) < candidatePage {
			break
		}
		afterPosition, afterRecord = rows[len(rows)-1].Position, rows[len(rows)-1].RecordID
	}
	keys := make([]uuid.UUID, 0, len(findings))
	for key := range findings {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })
	hash := sha256.New()
	ordered := make([]advisorydb.InsertAdvisorySetFindingsParams, 0, len(keys))
	type advisoryKey struct{ id, severity string }
	rollup := make(map[advisoryKey]int32)
	for _, key := range keys {
		f := findings[key]
		_, _ = hash.Write(key[:])
		_, _ = hash.Write([]byte(strings.Join([]string{f.FixedVersion, f.Severity, f.PublishedAt.Time.UTC().Format(time.RFC3339Nano), strings.Join(f.Cves, ","), f.SourceUrl}, "\x00")))
		ordered = append(ordered, f)
		rollup[advisoryKey{f.AdvisoryID, f.Severity}]++
		switch f.Severity {
		case "critical":
			set.CriticalCount++
		case "high":
			set.HighCount++
		case "medium":
			set.MediumCount++
		case "low":
			set.LowCount++
		default:
			set.OtherCount++
		}
	}
	set.FindingDigest = hash.Sum(nil)
	set.FindingCount = int32(len(ordered))
	if err := q.InsertAdvisoryFindingSet(ctx, advisorydb.InsertAdvisoryFindingSetParams{ID: set.ID, FeedID: set.FeedID, FeedRevision: set.FeedRevision, PackageDigest: set.PackageDigest, State: set.State, Reason: set.Reason, FindingDigest: set.FindingDigest, FindingCount: set.FindingCount, CriticalCount: set.CriticalCount, HighCount: set.HighCount, MediumCount: set.MediumCount, LowCount: set.LowCount, OtherCount: set.OtherCount, UncoveredPackages: set.UncoveredPackages}); err != nil {
		return set, err
	}
	if _, err := q.InsertAdvisorySetFindings(ctx, ordered); err != nil {
		return set, err
	}
	advisories := make([]advisorydb.InsertAdvisorySetAdvisoriesParams, 0, len(rollup))
	for key, count := range rollup {
		advisories = append(advisories, advisorydb.InsertAdvisorySetAdvisoriesParams{SetID: set.ID, AdvisoryID: key.id, Severity: key.severity, Findings: count})
	}
	if _, err := q.InsertAdvisorySetAdvisories(ctx, advisories); err != nil {
		return set, err
	}
	return set, nil
}

func sameID(a, b *uuid.UUID) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

// findingKey is device-independent and SQL-reproducible (migration 00019):
// the first 16 bytes of SHA-256 over the NUL-joined identity parts. The API
// finding ID is this key within the device's context.
func findingKey(parts ...string) uuid.UUID {
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	var key uuid.UUID
	copy(key[:], digest[:16])
	return key
}

// MatchesVersion evaluates only a normalized native version range. Callers must
// separately bind product, package, architecture and installed-product predicates.
// A true unknown/rejected assessment is not a claim of known vulnerability.
func MatchesVersion(manager, installed string, record *advisoryv1.Advisory) (bool, error) {
	// A rejected source record supplies no trustworthy version or module
	// boundary. Its exact candidate package identity alone requires UNKNOWN.
	if record.GetSourceRecordRejected() {
		return true, nil
	}
	if record.GetNotAffected() {
		return false, nil
	}
	if _, err := feed.Compare(manager, installed, installed); err != nil {
		return false, err
	}
	if introduced := record.GetIntroducedVersion(); introduced != "" && introduced != "0" {
		cmp, err := feed.Compare(manager, installed, introduced)
		if err != nil {
			return false, err
		}
		if cmp < 0 {
			return false, nil
		}
	}
	if fixed := record.GetFixedVersion(); fixed != "" {
		cmp, err := feed.Compare(manager, installed, fixed)
		if err != nil {
			return false, err
		}
		if cmp >= 0 {
			return false, nil
		}
	}
	if last := record.GetLastAffectedVersion(); last != "" {
		cmp, err := feed.Compare(manager, installed, last)
		if err != nil {
			return false, err
		}
		if cmp > 0 {
			return false, nil
		}
	}
	return true, nil
}
