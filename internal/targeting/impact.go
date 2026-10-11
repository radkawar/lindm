package targeting

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/identity"
	"lindm/internal/targeting/targetingdb"
)

// ImpactResolver reads the actual effective server resource head and resolves
// proposed candidates. Neither result is a native plan or proof of execution.
type ImpactResolver func(context.Context, pgx.Tx, *uuid.UUID, []*policyv1.TargetCandidate) (current, proposed *policyv1.TargetResolution, err error)

const maxImpactDevices = 10000
const maxImpactBytes = 64 << 20

func impactProposalEqual(report *adminv1.PreviewTargetAssignmentImpactResponse, assignment *policyv1.TargetAssignment, expected uint64) bool {
	return report.ExpectedRevision == expected && proto.Equal(report.Assignment, assignment)
}

// Impact requires READ COMMITTED: table locks are acquired before the first
// input read, and held until the caller commits. Only expiring evidence is written.
func (s *Store) Impact(ctx context.Context, tx pgx.Tx, p identity.Principal, r *adminv1.PreviewTargetAssignmentImpactRequest, resolve ImpactResolver) (*adminv1.PreviewTargetAssignmentImpactResponse, error) {
	if err := s.validate(r); err != nil {
		return nil, err
	}
	q, err := begin(ctx, tx, p, identity.PermissionAssignResources, true)
	if err != nil {
		return nil, err
	}
	isolation, err := q.ImpactIsolation(ctx)
	if err != nil {
		return nil, err
	}
	if isolation != "read committed" {
		return nil, ErrRejected
	}
	if err := q.LockTargetImpactInputs(ctx); err != nil {
		return nil, err
	}
	if r.PreviewId != nil {
		report, _, err := loadImpactReport(ctx, q, p, *r.PreviewId)
		if err != nil {
			return nil, err
		}
		if !impactProposalEqual(report, r.Assignment, r.ExpectedRevision) {
			return nil, ErrConflict
		}
		return impactPage(ctx, q, p, report, r.PageSize, r.GetAfterDeviceId())
	}
	if err := q.PruneImpactReports(ctx, p.ID); err != nil {
		return nil, err
	}
	id := uuid.New()
	report, input, err := s.evaluateImpact(ctx, tx, q, p, r.Assignment, r.ExpectedRevision, resolve, &id)
	if err != nil {
		return nil, err
	}
	report.PreviewId = id.String()
	b, err := encoded(report)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	_, _ = h.Write(input)
	_, _ = h.Write(b)
	report.ReviewSha256 = h.Sum(nil)
	b, err = encoded(report)
	if err != nil {
		return nil, err
	}
	if err := q.InsertImpactReport(ctx, targetingdb.InsertImpactReportParams{ID: id, ActorID: p.ID, Document: b, InputDigest: input, ExpiresAt: pgtype.Timestamptz{Time: report.ValidUntil.AsTime(), Valid: true}}); err != nil {
		return nil, err
	}
	return impactPage(ctx, q, p, report, r.PageSize, "")
}

func loadImpactReport(ctx context.Context, q *targetingdb.Queries, p identity.Principal, id string) (*adminv1.PreviewTargetAssignmentImpactResponse, []byte, error) {
	row, err := q.GetImpactReport(ctx, targetingdb.GetImpactReportParams{ID: uuid.MustParse(id), ActorID: p.ID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	report := new(adminv1.PreviewTargetAssignmentImpactResponse)
	if err := proto.Unmarshal(row.Document, report); err != nil {
		return nil, nil, err
	}
	return report, row.InputDigest, nil
}

func impactPage(ctx context.Context, q *targetingdb.Queries, p identity.Principal, report *adminv1.PreviewTargetAssignmentImpactResponse, size uint32, after string) (*adminv1.PreviewTargetAssignmentImpactResponse, error) {
	u, scopes, err := scope(p, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	visible, err := q.ImpactDevicesVisible(ctx, targetingdb.ImpactDevicesVisibleParams{ReportID: uuid.MustParse(report.PreviewId), Unrestricted: u, Scopes: scopes})
	if err != nil {
		return nil, err
	}
	// Do not disclose retained rows or aggregate counts after scope revocation.
	if !visible.Valid || !visible.Bool {
		return nil, ErrNotFound
	}
	cursor := uuid.Nil
	if after != "" {
		cursor = uuid.MustParse(after)
	}
	rows, err := q.ListImpactDevices(ctx, targetingdb.ListImpactDevicesParams{ReportID: uuid.MustParse(report.PreviewId), AfterID: cursor, RowLimit: int32(size) + 1})
	if err != nil {
		return nil, err
	}
	for i, row := range rows {
		if uint32(i) == size {
			break
		}
		item := new(adminv1.TargetAssignmentDeviceImpact)
		if err := proto.Unmarshal(row.Document, item); err != nil {
			return nil, err
		}
		report.Devices = append(report.Devices, item)
		// Reserve the actual continuation field while testing both wire encodings.
		report.NextAfterDeviceId = proto.String(item.DeviceId)
		if err := ValidateResponse(report); err != nil {
			report.Devices = report.Devices[:len(report.Devices)-1]
			if len(report.Devices) == 0 {
				return nil, err
			}
			break
		}
	}
	report.NextAfterDeviceId = nil
	if len(rows) > len(report.Devices) && len(report.Devices) > 0 {
		report.NextAfterDeviceId = proto.String(report.Devices[len(report.Devices)-1].DeviceId)
	}
	return report, nil
}

// SaveImpact checks exact durable replay before looking up the ephemeral report.
// It never activates resources, even when all server resolutions are ready.
func (s *Store) SaveImpact(ctx context.Context, tx pgx.Tx, p identity.Principal, r *adminv1.SaveTargetAssignmentImpactRequest, resolve ImpactResolver) (*adminv1.PutTargetAssignmentResponse, error) {
	if err := s.validate(r); err != nil {
		return nil, err
	}
	q, err := begin(ctx, tx, p, identity.PermissionAssignResources, true)
	if err != nil {
		return nil, err
	}
	out := new(adminv1.PutTargetAssignmentResponse)
	const method = "targeting.assignment.save_reviewed"
	if ok, err := receipt(ctx, q, p, r.RequestId, method, r, out); ok || err != nil {
		return out, err
	}
	report, input, err := loadImpactReport(ctx, q, p, r.PreviewId)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrImpactStale
	}
	if err != nil {
		return nil, err
	}
	if !report.Complete || !bytes.Equal(report.ReviewSha256, r.ReviewSha256) || !impactProposalEqual(report, r.Assignment, r.ExpectedRevision) {
		return nil, ErrImpactStale
	}
	if err := q.LockTargetImpactInputs(ctx); err != nil {
		return nil, err
	}
	now, err := q.TargetingClock(ctx)
	if err != nil {
		return nil, err
	}
	isolation, err := q.ImpactIsolation(ctx)
	if err != nil {
		return nil, err
	}
	if isolation != "read committed" {
		return nil, ErrRejected
	}
	if !now.Time.Before(report.ValidUntil.AsTime()) {
		return nil, ErrImpactStale
	}
	current, currentInput, err := s.evaluateImpact(ctx, tx, q, p, r.Assignment, r.ExpectedRevision, resolve, nil)
	if errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) {
		return nil, ErrImpactStale
	}
	if err != nil {
		return nil, err
	}
	if !current.Complete || !bytes.Equal(input, currentInput) {
		return nil, ErrImpactStale
	}
	now, err = q.TargetingClock(ctx)
	if err != nil {
		return nil, err
	}
	if !now.Time.Before(report.ValidUntil.AsTime()) || !now.Time.Before(current.ValidUntil.AsTime()) {
		return nil, ErrImpactStale
	}
	return s.putAssignment(ctx, q, p, &adminv1.PutTargetAssignmentRequest{RequestId: r.RequestId, Assignment: r.Assignment, ExpectedRevision: r.ExpectedRevision, Reason: r.Reason}, method, r)
}

func (s *Store) evaluateImpact(ctx context.Context, tx pgx.Tx, q *targetingdb.Queries, p identity.Principal, proposal *policyv1.TargetAssignment, expected uint64, resolve ImpactResolver, retain *uuid.UUID) (*adminv1.PreviewTargetAssignmentImpactResponse, []byte, error) {
	if resolve == nil {
		return nil, nil, ErrRejected
	}
	catalog, previous, err := s.prepareImpactCatalog(ctx, q, proposal, expected)
	if err != nil {
		return nil, nil, err
	}
	u, scopes, err := scope(p, identity.PermissionReadFleet)
	if err != nil {
		return nil, nil, err
	}
	params := targetingdb.ListImpactCandidatesParams{Unrestricted: u, Scopes: scopes, AfterID: uuid.Nil, DeviceIds: []uuid.UUID{}, GroupIds: []uuid.UUID{}}
	addImpactScope(&params, proposal.Target)
	if previous != nil {
		addImpactScope(&params, previous.Target)
	}
	now, err := q.TargetingClock(ctx)
	if err != nil {
		return nil, nil, err
	}
	report := &adminv1.PreviewTargetAssignmentImpactResponse{Assignment: proto.CloneOf(proposal), ExpectedRevision: expected, EvaluatedAt: timestamppb.New(now.Time), ValidUntil: timestamppb.New(now.Time.Add(15 * time.Minute)), Complete: true}
	// Reserve maximum final counts and every completeness reason before accepting
	// a row: late report metadata must not make an earlier row unreviewable.
	envelope := &adminv1.PreviewTargetAssignmentImpactResponse{
		PreviewId: uuid.Nil.String(), Assignment: proposal, ExpectedRevision: expected,
		EvaluatedAt: report.EvaluatedAt, ValidUntil: report.ValidUntil, Complete: true,
		ReviewSha256: make([]byte, sha256.Size), CandidateCount: maxImpactDevices,
		EvaluatedDeviceCount: maxImpactDevices, TargetCount: maxImpactDevices,
		IncludedCount: maxImpactDevices, ExcludedCount: maxImpactDevices, UnknownCount: maxImpactDevices,
		Reasons: []string{"candidate_limit", "report_byte_limit", "device_visibility_incomplete", "response_envelope_reserve"},
		Devices: make([]*adminv1.TargetAssignmentDeviceImpact, 1),
	}
	h := sha256.New()
	_, _ = h.Write(catalog.digest)
	totalBytes, scanned := 0, 0
	for {
		rows, err := q.ListImpactCandidates(ctx, params)
		if err != nil {
			return nil, nil, err
		}
		stop := false
		for _, candidate := range rows {
			params.AfterID = candidate.ID
			if scanned == maxImpactDevices {
				report.Complete = false
				report.Reasons = append(report.Reasons, "candidate_limit")
				stop = true
				break
			}
			scanned++
			if !candidate.Visible {
				if report.Complete {
					report.Reasons = append(report.Reasons, "device_visibility_incomplete")
				}
				report.Complete = false
				continue
			}
			report.CandidateCount++
			// TargetingDevice already locks the scoped row; the report uses one
			// pinned evaluation clock rather than querying the clock per member.
			device, err := q.TargetingDevice(ctx, targetingdb.TargetingDeviceParams{DeviceID: candidate.ID, Unrestricted: u, Scopes: scopes})
			if err != nil {
				return nil, nil, err
			}
			e, err := evaluationFromDevice(q, device, now.Time)
			if err != nil {
				return nil, nil, err
			}
			e.catalog = catalog
			e.timeLimit = report.ValidUntil.AsTime()
			rawMatch, err := e.target(ctx, proposal.Target)
			if err != nil {
				return nil, nil, err
			}
			match, err := s.collectImpact(ctx, e, proposal, expected, p.ID.String())
			if err != nil {
				return nil, nil, err
			}
			current, proposed, err := resolve(ctx, tx, e.input.Device.CurrentGenerationID, e.input.Assignments)
			if err != nil {
				return nil, nil, err
			}
			if current == nil || proposed == nil {
				return nil, nil, ErrRejected
			}
			d := e.input.Device
			b, err := encodeImpactDevice(e, current, proposed, match, envelope)
			if err != nil {
				return nil, nil, err
			}
			if totalBytes+len(b) > maxImpactBytes {
				report.Complete = false
				report.Reasons = append(report.Reasons, "report_byte_limit")
				stop = true
				break
			}
			totalBytes += len(b)
			input, err := inputDigest(e)
			if err != nil {
				return nil, nil, err
			}
			_, _ = h.Write(input)
			_, _ = h.Write(digest("impact.device", b))
			if retain != nil {
				if err := q.InsertImpactDevice(ctx, targetingdb.InsertImpactDeviceParams{ReportID: *retain, DeviceID: d.ID, Document: b}); err != nil {
					return nil, nil, err
				}
			}
			countImpactDevice(report, rawMatch, match, e.timeLimit)
		}
		if stop || len(rows) < 200 {
			break
		}
	}
	dependencies, err := json.Marshal(struct {
		Groups      map[string]targetingdb.DynamicTargetGroup
		Definitions map[string]impactDefinitions
		Rollouts    map[string]*rolloutInput
	}{catalog.groups, catalog.definitions, catalog.rollouts})
	if err != nil {
		return nil, nil, err
	}
	_, _ = h.Write(digest("impact.dependencies", dependencies))
	return report, h.Sum(nil), nil
}

func (s *Store) prepareImpactCatalog(ctx context.Context, q *targetingdb.Queries, proposal *policyv1.TargetAssignment, expected uint64) (*impactCatalog, *policyv1.TargetAssignment, error) {
	if _, err := encodedCatalog(proposal); err != nil {
		return nil, nil, err
	}
	exists, err := q.TargetProfileRevisionExists(ctx, uuid.MustParse(proposal.ProfileRevisionId))
	if err != nil {
		return nil, nil, err
	}
	if !exists {
		return nil, nil, ErrNotFound
	}
	if err := checkTarget(ctx, q, proposal.Target); err != nil {
		return nil, nil, err
	}
	for _, target := range proposal.Exclusions {
		if err := checkTarget(ctx, q, target); err != nil {
			return nil, nil, err
		}
	}
	catalog, err := loadImpactCatalog(ctx, q)
	if err != nil {
		return nil, nil, err
	}
	// Bind proposal dependencies even for an empty cohort.
	if err := s.warmImpactProposal(ctx, q, catalog, proposal); err != nil {
		return nil, nil, err
	}
	var previous *policyv1.TargetAssignment
	if index, ok := catalog.assignmentIndex[uuid.MustParse(proposal.AssignmentId)]; ok {
		candidate := catalog.assignments[index]
		if candidate.Revision != expected {
			return nil, nil, ErrConflict
		}
		previous = candidate.Assignment
	}
	if previous == nil && expected != 0 {
		return nil, nil, ErrConflict
	}
	return catalog, previous, nil
}

func encodeImpactDevice(e *evaluation, current, proposed *policyv1.TargetResolution, match policyv1.TargetMatch, envelope *adminv1.PreviewTargetAssignmentImpactResponse) ([]byte, error) {
	d := e.input.Device
	item := &adminv1.TargetAssignmentDeviceImpact{DeviceId: d.ID.String(), Hostname: d.Hostname, OsId: d.OsID, OsVersion: d.OsVersion, Architecture: d.Architecture, State: d.State, Match: match, CurrentResolution: current, ProposedResolution: proposed, Changed: impactChanged(current, proposed), Reasons: []string{"native_capabilities_unknown"}}
	if d.HostReceivedAt.Valid {
		item.HostReceivedAt = timestamppb.New(d.HostReceivedAt.Time)
		if !e.now.Before(d.HostReceivedAt.Time.Add(24 * time.Hour)) {
			item.Reasons = append(item.Reasons, "host_inventory_stale")
		} else {
			e.limit(d.HostReceivedAt.Time.Add(24 * time.Hour))
		}
	} else {
		item.Reasons = append(item.Reasons, "host_inventory_unknown")
	}
	if d.CurrentGenerationID == nil || d.State != "active" {
		item.Reasons = append(item.Reasons, "device_not_active")
	}
	if match == unknown {
		item.Reasons = append(item.Reasons, "membership_unknown")
	}
	for _, group := range e.input.Groups {
		definition := e.catalog.decodedGroups[group.ID.String()]
		if definition != nil && d.HostReceivedAt.Valid && !e.now.Before(d.HostReceivedAt.Time.Add(time.Duration(definition.Expression.InventoryMaxAgeSeconds)*time.Second)) {
			item.Reasons = append(item.Reasons, "membership_inventory_stale")
			break
		}
	}
	for _, c := range e.input.Assignments {
		if c.Match == unknown {
			item.Reasons = append(item.Reasons, "resolution_has_unknown_membership")
			break
		}
	}
	// Every retained row must be individually reviewable with full metadata.
	envelope.Devices[0] = item
	envelope.NextAfterDeviceId = &item.DeviceId
	if err := ValidateResponse(envelope); err != nil {
		return nil, err
	}
	return encoded(item)
}

func countImpactDevice(report *adminv1.PreviewTargetAssignmentImpactResponse, rawMatch, match policyv1.TargetMatch, limit time.Time) {
	report.EvaluatedDeviceCount++
	if rawMatch != excluded {
		report.TargetCount++
	}
	switch match {
	case included:
		report.IncludedCount++
	case excluded:
		report.ExcludedCount++
	default:
		report.UnknownCount++
	}
	if limit.Before(report.ValidUntil.AsTime()) {
		report.ValidUntil = timestamppb.New(limit)
	}
}

func addImpactScope(params *targetingdb.ListImpactCandidatesParams, target *policyv1.TargetRef) {
	switch {
	case target.GetDeviceId() != "":
		params.DeviceIds = append(params.DeviceIds, uuid.MustParse(target.GetDeviceId()))
	case target.GetStaticGroupId() != "":
		params.GroupIds = append(params.GroupIds, uuid.MustParse(target.GetStaticGroupId()))
	default:
		params.AllDevices = true
	}
}

func impactChanged(current, proposed *policyv1.TargetResolution) bool {
	if len(current.Resources) != len(proposed.Resources) {
		return true
	}
	type key struct {
		kind int32
		name string
	}
	existing := make(map[key]*policyv1.ResolvedResource, len(current.Resources))
	for _, item := range current.Resources {
		existing[key{int32(item.GetRef().GetKind()), item.GetRef().GetCanonicalKey()}] = item
	}
	for _, next := range proposed.Resources {
		before := existing[key{int32(next.GetRef().GetKind()), next.GetRef().GetCanonicalKey()}]
		if before == nil || before.Disposition != next.Disposition {
			return true
		}
		// Compare every setting, not record-local resource UUIDs or provenance.
		a, b := before.Resource, next.Resource
		if a == nil || b == nil {
			if a != b {
				return true
			}
			continue
		}
		if !proto.Equal(a.Desired, b.Desired) || !proto.Equal(a.Applicability, b.Applicability) ||
			!proto.Equal(a.Ownership, b.Ownership) || !proto.Equal(a.Verification, b.Verification) ||
			len(a.DependsOn) != len(b.DependsOn) {
			return true
		}
		for i, dependency := range a.DependsOn {
			if !proto.Equal(dependency, b.DependsOn[i]) {
				return true
			}
		}
	}
	return false
}
