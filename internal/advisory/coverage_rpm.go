// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/advisory/advisorydb"
	"lindm/internal/advisory/feed"
	"lindm/internal/rpmauthority"
)

const rhelMembershipUnproved = "rhel_product_membership_unproved"

// rhelCoverage proves two independent facts: an installed identity is signed by
// a pinned Red Hat package key, AND the closed selected RHEL product snapshot
// explicitly declares that exact binary NEVRA in this module/architecture.
// A Red Hat signature alone also covers add-ons and other products. Neither a
// familiar package name nor an .elN suffix is a RHEL product declaration.
func rhelCoverage(ctx context.Context, q *advisorydb.Queries, selected *advisorydb.AdvisoryFeed, source *advisoryv1.FeedSource, snapshot uuid.UUID, setID uuid.UUID) ([]bool, []advisorydb.InsertAdvisorySetUncoveredParams, error) {
	packages := make([]advisorydb.ListAdvisoryRpmPackagesRow, 0)
	reasons := make([]string, maxSnapshotPositions)
	eligible := make([]bool, maxSnapshotPositions)
	_, rootValid := rpmauthority.PolicyIdentity()
	after := int32(-1)
	for {
		rows, err := q.ListAdvisoryRpmPackages(ctx, advisorydb.ListAdvisoryRpmPackagesParams{SnapshotID: snapshot, AfterPosition: after, RowLimit: uncoveredPage})
		if err != nil {
			return nil, nil, err
		}
		for _, row := range rows {
			if row.Position < 0 || row.Position >= maxSnapshotPositions {
				return nil, nil, errSnapshotPosition
			}
			eligible[row.Position], reasons[row.Position] = rhelPackagePrerequisite(source, &row, rootValid)
		}
		packages = append(packages, rows...)
		if len(rows) < uncoveredPage {
			break
		}
		after = rows[len(rows)-1].Position
	}
	// Candidate scans are keyset-bounded, including source aliases. A scoped
	// rejection overrides every otherwise valid claim for its matched package,
	// but never changes any unrelated package's coverage or device-wide state.
	afterPosition, afterRecord := int32(-1), uuid.Nil
	// Source and binary claims are contiguous by installed position across
	// keyset pages. Keep only this package's assessment identities in memory.
	type assessmentKey struct{ advisory, cves string }
	keyFor := func(record *advisoryv1.Advisory) assessmentKey {
		cves := record.GetCves()
		if !slices.IsSorted(cves) {
			cves = slices.Clone(cves)
			slices.Sort(cves)
		}
		return assessmentKey{record.GetId(), strings.Join(cves, "\x00")}
	}
	binaryClaims := make(map[assessmentKey]bool)
	sourceClaims := make(map[assessmentKey]bool)
	position := int32(-1)
	finishPackage := func() {
		if position >= 0 && reasons[position] == "" {
			for key := range sourceClaims {
				if !binaryClaims[key] {
					reasons[position] = "rpm_source_epoch_unavailable"
					break
				}
			}
		}
		clear(binaryClaims)
		clear(sourceClaims)
	}
	for {
		rows, err := q.AdvisoryCandidates(ctx, advisorydb.AdvisoryCandidatesParams{FeedID: selected.ID, Generation: selected.Revision, SnapshotID: snapshot, AfterPosition: afterPosition, AfterRecord: afterRecord, RowLimit: candidatePage})
		if err != nil {
			return nil, nil, err
		}
		for _, row := range rows {
			if position != row.Position {
				finishPackage()
				position = row.Position
			}
			if row.Position < 0 || row.Position >= maxSnapshotPositions {
				return nil, nil, errSnapshotPosition
			}
			if !eligible[row.Position] {
				continue
			}
			var record advisoryv1.Advisory
			if err := proto.Unmarshal(row.RecordBytes, &record); err != nil {
				return nil, nil, errors.New("advisory: invalid RHEL product declaration")
			}
			if record.GetSourceRecordRejected() {
				reasons[row.Position] = "source_record_rejected"
				eligible[row.Position] = false
				continue
			}
			if !rhelCandidateScopeMatches(source, &record, row.Architecture, row.SourceArchitecture, row.ModuleName, row.ModuleStream) {
				continue
			}
			if record.GetAssessmentUnknown() {
				reasons[row.Position] = "vendor_assessment_unknown"
				eligible[row.Position] = false
				continue
			}
			if rhelSourceEpochRequired(&record) {
				if !rhelSourceFixedRangeCleared(row.SourceVersion, &record) {
					sourceClaims[keyFor(&record)] = true
				}
			} else if !record.GetSourcePackage() && record.GetArchitecture() == row.Architecture {
				// A negative scoped to another build is not an assessment of
				// this installed binary and cannot discharge source uncertainty.
				if rhelBinaryAssessmentApplies(row.Manager, row.Version, &record) {
					binaryClaims[keyFor(&record)] = true
				}
			}
			if len(binaryClaims)+len(sourceClaims) > maxFindings {
				reasons[row.Position] = "matching_capacity_exceeded"
				eligible[row.Position] = false
				clear(binaryClaims)
				clear(sourceClaims)
				continue
			}
			if exactRhelDeclaration(source, &record, row.Version, row.Architecture, row.SourceArchitecture, row.ModuleName, row.ModuleStream) {
				reasons[row.Position] = ""
			}
		}
		if len(rows) < candidatePage {
			break
		}
		afterPosition, afterRecord = rows[len(rows)-1].Position, rows[len(rows)-1].RecordID
	}
	finishPackage()
	uncovered := make([]bool, maxSnapshotPositions)
	var projection []advisorydb.InsertAdvisorySetUncoveredParams
	for _, row := range packages {
		if reason := reasons[row.Position]; reason != "" {
			uncovered[row.Position] = true
			projection = append(projection, advisorydb.InsertAdvisorySetUncoveredParams{SetID: setID, Position: row.Position, Name: row.Name, Version: row.Version, Architecture: row.Architecture, Reason: reason})
		}
	}
	return uncovered, projection, nil
}

func rhelPackagePrerequisite(source *advisoryv1.FeedSource, row *advisorydb.ListAdvisoryRpmPackagesRow, rootValid bool) (bool, string) {
	switch {
	case row.Manager != "rpm" || row.RpmSigner != rpmauthority.Fingerprint:
		if row.RpmAuthorityReason != "" {
			return false, row.RpmAuthorityReason
		}
		return false, "rpm_authority_unavailable"
	case !rootValid:
		return false, "rpm_signature_unverified"
	case row.SourceName == "" || row.SourceVersion == "" || row.SourceArchitecture == "":
		return false, "rpm_source_identity_unavailable"
	case row.ModuleStatus != 1:
		return false, "native_module_identity_unavailable"
	case row.Architecture == "" || row.Architecture != "noarch" && !feed.Applies(source, source.GetDistro(), source.GetRelease(), row.Architecture):
		return false, "package_architecture_uncovered"
	default:
		return true, rhelMembershipUnproved
	}
}

func rhelBinaryAssessmentApplies(manager, installed string, record *advisoryv1.Advisory) bool {
	if record.GetSourcePackage() || record.GetSourceRecordRejected() || record.GetAssessmentUnknown() {
		return false
	}
	if record.GetNotAffected() {
		if exact := record.GetComponentVersion(); exact != "" {
			comparison, err := feed.Compare(manager, installed, exact)
			if err != nil || comparison != 0 {
				return false
			}
		}
		// MatchesVersion intentionally suppresses negatives before range
		// evaluation. Check their applicability with just the normalized range,
		// without changing the original claim or inventing a positive finding.
		scope := &advisoryv1.Advisory{
			IntroducedVersion:   record.GetIntroducedVersion(),
			FixedVersion:        record.GetFixedVersion(),
			LastAffectedVersion: record.GetLastAffectedVersion(),
		}
		applies, err := MatchesVersion(manager, installed, scope)
		return err == nil && applies
	}
	_, err := MatchesVersion(manager, installed, record)
	return err == nil
}

// SOURCERPM proves source name/VR/architecture but never its epoch (not even
// zero). It cannot establish exact product membership. Versioned source
// assessments or source EVR predicates remain package-scoped coverage gaps
// unless resolved by a same-document/CVE binary assessment or a safe bound.
// Unversioned statuses need no invented epoch after binary membership is proved.
func rhelSourceEpochRequired(record *advisoryv1.Advisory) bool {
	return record.GetSourcePackage() && (record.GetComponentVersion() != "" || record.GetFixedVersion() != "" || record.GetLastAffectedVersion() != "" || record.GetIntroducedVersion() != "" && record.GetIntroducedVersion() != "0")
}

// Zero is a lower bound, NOT an inferred source epoch. For a fixed-only range,
// minimum possible EVR >= fixed proves every possible source epoch is clear.
func rhelSourceFixedRangeCleared(sourceVR string, record *advisoryv1.Advisory) bool {
	if !record.GetSourcePackage() || record.GetAssessmentUnknown() || record.GetSourceRecordRejected() || record.GetNotAffected() || record.GetFixedVersion() == "" || record.GetLastAffectedVersion() != "" || record.GetIntroducedVersion() != "" && record.GetIntroducedVersion() != "0" {
		return false
	}
	comparison, err := feed.Compare("rpm", "0:"+sourceVR, record.GetFixedVersion())
	return err == nil && comparison >= 0
}

func rhelCandidateScopeMatches(source *advisoryv1.FeedSource, record *advisoryv1.Advisory, architecture, sourceArchitecture, moduleName, moduleStream string) bool {
	arch := record.GetArchitecture()
	archMatches := arch == "" || arch == architecture || record.GetSourcePackage() && arch == sourceArchitecture
	return record.GetPlatformRelease() == source.GetRelease() && record.GetPlatformStream() == source.GetPlatformStream() && archMatches && record.GetModuleName() == moduleName && record.GetModuleStream() == moduleStream
}

func exactRhelDeclaration(source *advisoryv1.FeedSource, record *advisoryv1.Advisory, version, architecture, sourceArchitecture, moduleName, moduleStream string) bool {
	if record.GetSourcePackage() || record.GetSourceRecordRejected() || record.GetArchitecture() == "" || !rhelCandidateScopeMatches(source, record, architecture, sourceArchitecture, moduleName, moduleStream) {
		return false
	}
	equal := func(want string) bool {
		if want == "" {
			return false
		}
		comparison, err := feed.Compare("rpm", version, want)
		return err == nil && comparison == 0
	}
	// An exact binary component PURL is product membership, not an affected
	// bound. Legacy fixed builds/exact ranges also declare a binary NEVRA;
	// an arbitrary affected interval alone never proves product membership.
	return equal(record.GetComponentVersion()) || equal(record.GetFixedVersion()) || equal(record.GetIntroducedVersion()) && equal(record.GetLastAffectedVersion())
}
