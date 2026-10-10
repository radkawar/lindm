package advisory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/advisory/advisorydb"
	"lindm/internal/advisory/feed"
)

// Evaluate publishes one bounded, repeatable-read evaluation of the device's
// current immutable snapshot. Publication of a new snapshot or feed immediately
// makes the previous evaluation UNKNOWN through the shared SQL view.
func (s *Service) Evaluate(ctx context.Context, deviceID uuid.UUID) (advisorydb.AdvisoryEvaluation, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return advisorydb.AdvisoryEvaluation{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := advisorydb.New(tx)
	if err := q.LockAdvisoryDevice(ctx, deviceID); err != nil {
		return advisorydb.AdvisoryEvaluation{}, err
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
	platformStream := ""
	if d.OsID == "rhel" {
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
		if feed.Applies(&source, d.OsID, d.OsVersion, d.Architecture) && (d.OsID != "rhel" || platformStream != "" && source.GetPlatformStream() == platformStream) {
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
	// Official Arch has no VERSION_ID. Explicit native absence identifies the
	// rolling product; failed collection and stale host evidence do not.
	releaseUsable := d.OsVersionStatus.Int16 == 1 || (d.OsID == "arch" && d.OsVersion == "" && d.OsVersionStatus.Int16 == int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE))
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
		if d.OsID == "rhel" && platformStream == "" {
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
		return previous, nil
	}
	findings := make(map[uuid.UUID]advisorydb.InsertAdvisoryFindingParams)
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
			if arch == "" || (arch != "all" && arch != "noarch" && (d.OsID != "arch" || arch != "any") && !feed.Applies(selectedSource, d.OsID, d.OsVersion, arch)) {
				unknown("package_architecture_uncovered")
			}
		}
		for start := int32(0); start < d.PackageCount.Int32; start += 500 {
			rows, err := q.AdvisoryCandidates(ctx, advisorydb.AdvisoryCandidatesParams{FeedID: selected.ID, SnapshotID: *d.CurrentSnapshotID, FirstPosition: start, EndPosition: start + 500})
			if err != nil {
				return advisorydb.AdvisoryEvaluation{}, err
			}
			if len(rows) > 10000 {
				unknown("matching_capacity_exceeded")
				break
			}
			for _, row := range rows {
				var record advisoryv1.Advisory
				if err := proto.Unmarshal(row.RecordBytes, &record); err != nil {
					return advisorydb.AdvisoryEvaluation{}, err
				}
				if selectedSource.GetDistro() == "rhel" && !record.GetSourceRecordRejected() {
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
				affected, err := matches(row.Manager, version, &record)
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
				id := findingID(deviceID, selected.ID, record.GetId(), row.Name, row.Version, row.Architecture)
				f := advisorydb.InsertAdvisoryFindingParams{ID: id, DeviceID: deviceID, AdvisoryID: record.GetId(), PackageName: row.Name, InstalledVersion: row.Version, FixedVersion: record.GetFixedVersion(), Architecture: row.Architecture, Severity: record.GetSeverity(), Cves: record.GetCves(), FeedID: selected.ID, SourceUrl: record.GetSourceUrl()}
				if f.Cves == nil {
					f.Cves = []string{}
				}
				if record.GetPublishedAt() != nil {
					f.PublishedAt = timestamp(record.GetPublishedAt().AsTime())
				}
				if previous, exists := findings[id]; exists {
					// A CSAF advisory can emit one matching record per CVE.
					// They are one accepted-risk identity, not last-row-wins.
					f.Cves = append(previous.Cves, f.Cves...)
					slices.Sort(f.Cves)
					f.Cves = slices.Compact(f.Cves)
					if len(f.Cves) > 2048 {
						return advisorydb.AdvisoryEvaluation{}, ErrCapacity
					}
					if feed.SeverityRank(previous.Severity) > feed.SeverityRank(f.Severity) {
						f.Severity = previous.Severity
					}
					if previous.FixedVersion == "" || f.FixedVersion == "" {
						f.FixedVersion = ""
					} else {
						comparison, err := feed.Compare(row.Manager, previous.FixedVersion, f.FixedVersion)
						if err != nil {
							return advisorydb.AdvisoryEvaluation{}, err
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
				findings[id] = f
				if len(findings) > 10000 {
					return advisorydb.AdvisoryEvaluation{}, ErrCapacity
				}
			}
		}
	}
	ids := make([]uuid.UUID, 0, len(findings))
	for id := range findings {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	hash := sha256.New()
	for _, id := range ids {
		f := findings[id]
		_, _ = hash.Write(id[:])
		_, _ = hash.Write([]byte(strings.Join([]string{f.FixedVersion, f.Severity, f.PublishedAt.Time.UTC().Format(time.RFC3339Nano), strings.Join(f.Cves, ","), f.SourceUrl}, "\x00")))
	}
	e.FindingDigest = hash.Sum(nil)
	// Candidate-level uncertainty (including a rejected source record) is
	// discovered after the fast path above. Reuse its evaluation identity when
	// evidence is unchanged so pagination does not invalidate itself.
	if previousErr == nil && sameID(previous.SnapshotID, e.SnapshotID) && sameID(previous.FeedRevision, e.FeedRevision) && previous.HostReceivedAt == e.HostReceivedAt && previous.State == e.State && previous.Reason == e.Reason && previous.ExpiresAt == e.ExpiresAt && bytes.Equal(previous.FindingDigest, e.FindingDigest) {
		return previous, nil
	}
	if err := q.DeleteAdvisoryFindings(ctx, deviceID); err != nil {
		return advisorydb.AdvisoryEvaluation{}, err
	}
	for _, id := range ids {
		if err := q.InsertAdvisoryFinding(ctx, findings[id]); err != nil {
			return advisorydb.AdvisoryEvaluation{}, err
		}
	}
	if err := q.StoreAdvisoryEvaluation(ctx, e); err != nil {
		return advisorydb.AdvisoryEvaluation{}, err
	}
	if previousErr != nil || !bytes.Equal(previous.FindingDigest, e.FindingDigest) || previous.State != e.State || previous.Reason != e.Reason {
		if err := q.InsertAdvisoryAudit(ctx, advisorydb.InsertAdvisoryAuditParams{ID: uuid.New(), Action: "advisory.findings.changed", ResourceID: deviceID.String(), Reason: "Device advisory evidence changed"}); err != nil {
			return advisorydb.AdvisoryEvaluation{}, err
		}
	}
	result, err := q.GetAdvisoryEvaluation(ctx, deviceID)
	if err != nil {
		return advisorydb.AdvisoryEvaluation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return advisorydb.AdvisoryEvaluation{}, err
	}
	return result, nil
}

func sameID(a, b *uuid.UUID) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func findingID(device uuid.UUID, parts ...string) uuid.UUID {
	return uuid.NewSHA1(device, []byte(strings.Join(parts, "\x00")))
}

func matches(manager, installed string, record *advisoryv1.Advisory) (bool, error) {
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
