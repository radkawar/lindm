// SPDX-License-Identifier: Apache-2.0

package targeting

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
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
	report, input, err := s.evaluateImpact(ctx, tx, q, p, r.Assignment, r.ExpectedRevision, resolve, &id, nil)
	if err != nil {
		return nil, err
	}
	// A rollout of this exact report needs one independent approval when any
	// included change adopts native state or policy requires approval.
	report.ApprovalRequired = report.AdoptingCount > 0 || p.ApprovalRequired(identity.PermissionAssignResources)
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
	if !visible {
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
	if err := impactLabels(ctx, q, report); err != nil {
		return nil, err
	}
	// Labels are display aids; a page that only fits without them drops them.
	if ValidateResponse(report) != nil {
		report.RevisionLabels = nil
	}
	return report, nil
}

// plannedDevice is one evaluated device's reviewed change, captured while a
// StartRollout re-evaluates the exact report inputs.
type plannedDevice struct {
	id         uuid.UUID
	generation *uuid.UUID
	state      string
	match      policyv1.TargetMatch
	proposed   *policyv1.TargetResolution
	changed    bool
	head       string
}

func (s *Store) evaluateImpact(ctx context.Context, tx pgx.Tx, q *targetingdb.Queries, p identity.Principal, proposal *policyv1.TargetAssignment, expected uint64, resolve ImpactResolver, retain *uuid.UUID, plan func(plannedDevice) error) (*adminv1.PreviewTargetAssignmentImpactResponse, []byte, error) {
	if resolve == nil {
		return nil, nil, ErrRejected
	}
	catalog, previous, err := s.prepareImpactCatalog(ctx, q, proposal, expected)
	if err != nil {
		return nil, nil, err
	}
	params, err := impactCandidates(p, proposal, previous)
	if err != nil {
		return nil, nil, err
	}
	now, err := q.TargetingClock(ctx)
	if err != nil {
		return nil, nil, err
	}
	report := &adminv1.PreviewTargetAssignmentImpactResponse{Assignment: proto.CloneOf(proposal), ExpectedRevision: expected, EvaluatedAt: timestamppb.New(now.Time), ValidUntil: timestamppb.New(now.Time.Add(15 * time.Minute)), Complete: true}
	envelope, err := newImpactRowBudget(impactEnvelope(proposal, expected, report))
	if err != nil {
		return nil, nil, err
	}
	h := sha256.New()
	_, _ = h.Write(catalog.digest)
	totalBytes, scanned := 0, 0
	page := impactDevicePage{ids: make([]uuid.UUID, 0, 200)}
	batch := impactDeviceBatch{report: retain}
	for {
		rows, devices, err := page.load(ctx, q, params, maxImpactDevices-scanned)
		if err != nil {
			return nil, nil, err
		}
		deviceIndex := 0
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
			// The bounded preload locks the same scoped inputs in device-ID
			// order. Keep one pinned evaluation clock for the whole report.
			device := targetingdb.TargetingDeviceRow(devices[deviceIndex])
			deviceIndex++
			if device.ID != candidate.ID {
				return nil, nil, ErrRejected
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
			changed, direct, err := deviceImpactChange(ctx, q, device, current, proposed, match, proposal.AssignmentId)
			if err != nil {
				return nil, nil, err
			}
			b, err := encodeImpactDevice(e, current, proposed, match, changed, direct, envelope)
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
			if err := batch.append(ctx, q, device.ID, b); err != nil {
				return nil, nil, err
			}
			countImpactDevice(report, rawMatch, match, e.timeLimit)
			countPlannableImpact(report, device, proposed, match, changed, direct)
			if plan != nil {
				if err := plan(plannedDevice{id: device.ID, generation: device.CurrentGenerationID, state: device.State, match: match, proposed: proposed, changed: changed, head: device.ResourceAssignmentID}); err != nil {
					return nil, nil, err
				}
			}
		}
		if err := batch.flush(ctx, q); err != nil {
			return nil, nil, err
		}
		if stop || len(rows) < 200 {
			break
		}
	}
	dependencies, err := catalog.dependencyDigest()
	if err != nil {
		return nil, nil, err
	}
	_, _ = h.Write(dependencies)
	return report, h.Sum(nil), nil
}

// impactDevicePage reuses the candidate-ID buffer while loading the same scoped,
// locked inputs in bounded device-ID order.
type impactDevicePage struct {
	ids []uuid.UUID
}

func (page *impactDevicePage) load(ctx context.Context, q *targetingdb.Queries, params targetingdb.ListImpactCandidatesParams, remaining int) ([]targetingdb.ListImpactCandidatesRow, []targetingdb.ListImpactDevicePageRow, error) {
	rows, err := q.ListImpactCandidates(ctx, params)
	if err != nil {
		return nil, nil, err
	}
	page.ids = page.ids[:0]
	for _, candidate := range rows[:min(len(rows), remaining)] {
		if candidate.Visible {
			page.ids = append(page.ids, candidate.ID)
		}
	}
	if len(page.ids) == 0 {
		return rows, nil, nil
	}
	devices, err := q.ListImpactDevicePage(ctx, targetingdb.ListImpactDevicePageParams{DeviceIds: page.ids, Unrestricted: params.Unrestricted, Scopes: params.Scopes})
	if err != nil {
		return nil, nil, err
	}
	if len(devices) != len(page.ids) {
		return nil, nil, pgx.ErrNoRows
	}
	return rows, devices, nil
}

// impactDeviceBatch replaces per-member insert round trips with COPY, retaining
// at most 200 rows and 1 MiB of documents. Reevaluation without retention never
// allocates a row buffer.
type impactDeviceBatch struct {
	report *uuid.UUID
	rows   []targetingdb.InsertImpactDeviceParams
	bytes  int
}

func (batch *impactDeviceBatch) append(ctx context.Context, q *targetingdb.Queries, device uuid.UUID, document []byte) error {
	if batch.report == nil {
		return nil
	}
	if batch.rows == nil {
		batch.rows = make([]targetingdb.InsertImpactDeviceParams, 0, 200)
	}
	if batch.bytes+len(document) > maxDocumentBytes {
		if err := batch.flush(ctx, q); err != nil {
			return err
		}
	}
	batch.rows = append(batch.rows, targetingdb.InsertImpactDeviceParams{ReportID: *batch.report, DeviceID: device, Document: document})
	batch.bytes += len(document)
	if len(batch.rows) == cap(batch.rows) {
		return batch.flush(ctx, q)
	}
	return nil
}

func (batch *impactDeviceBatch) flush(ctx context.Context, q *targetingdb.Queries) error {
	if len(batch.rows) == 0 {
		return nil
	}
	if _, err := q.InsertImpactDevice(ctx, batch.rows); err != nil {
		return err
	}
	clear(batch.rows)
	batch.rows = batch.rows[:0]
	batch.bytes = 0
	return nil
}

// Change and adoption counts cover only devices a rollout plans. A device without
// an active generation keeps its reviewed row, but no rollout would change it.
func countPlannableImpact(report *adminv1.PreviewTargetAssignmentImpactResponse, device targetingdb.TargetingDeviceRow, proposed *policyv1.TargetResolution, match policyv1.TargetMatch, changed, direct bool) {
	if device.CurrentGenerationID == nil || device.State != "active" {
		return
	}
	if match == included {
		countAdoption(report, proposed)
	}
	countImpactChange(report, match, changed, direct)
}

// dependencyDigest binds the groups, definitions and rollouts the report read.
func (c *impactCatalog) dependencyDigest() ([]byte, error) {
	dependencies, err := json.Marshal(struct {
		Groups      map[string]targetingdb.DynamicTargetGroup
		Definitions map[string]impactDefinitions
		Rollouts    map[string]*rolloutInput
	}{c.groups, c.definitions, c.rollouts})
	if err != nil {
		return nil, err
	}
	return digest("impact.dependencies", dependencies), nil
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

// impactEnvelope reserves maximum final counts and every completeness reason
// before a row is accepted: late report metadata must not make an earlier row
// unreviewable.
func impactEnvelope(proposal *policyv1.TargetAssignment, expected uint64, report *adminv1.PreviewTargetAssignmentImpactResponse) *adminv1.PreviewTargetAssignmentImpactResponse {
	envelope := &adminv1.PreviewTargetAssignmentImpactResponse{
		PreviewId: uuid.Nil.String(), Assignment: proposal, ExpectedRevision: expected,
		EvaluatedAt: report.EvaluatedAt, ValidUntil: report.ValidUntil, Complete: true,
		ReviewSha256: make([]byte, sha256.Size), CandidateCount: maxImpactDevices,
		EvaluatedDeviceCount: maxImpactDevices, TargetCount: maxImpactDevices,
		IncludedCount: maxImpactDevices, ExcludedCount: maxImpactDevices, UnknownCount: maxImpactDevices,
		Reasons:           []string{"candidate_limit", "report_byte_limit", "device_visibility_incomplete", "response_envelope_reserve"},
		NextAfterDeviceId: proto.String(uuid.Nil.String()),
		AdoptingCount:     maxImpactDevices, ApprovalRequired: true, ChangedCount: maxImpactDevices, RemovingCount: maxImpactDevices, ReplacingDirectCount: maxImpactDevices, Adopted: make([]*resourcev1.ResourceRef, maxAdoptedRefs),
	}
	for i := range envelope.Adopted {
		envelope.Adopted[i] = &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL, CanonicalKey: strings.Repeat("k", 1024)}
	}
	return envelope
}

// The metadata reserve is identical for every row. Serialize it once rather
// than serializing the 64 maximum-length adoption references for every device.
type impactRowBudget struct {
	protobuf int
	json     int
	row      *adminv1.PreviewTargetAssignmentImpactResponse
}

func newImpactRowBudget(envelope *adminv1.PreviewTargetAssignmentImpactResponse) (*impactRowBudget, error) {
	b, err := protojson.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	return &impactRowBudget{
		protobuf: proto.Size(envelope), json: len(b),
		row: &adminv1.PreviewTargetAssignmentImpactResponse{Devices: make([]*adminv1.TargetAssignmentDeviceImpact, 1)},
	}, nil
}

func (budget *impactRowBudget) validate(item *adminv1.TargetAssignmentDeviceImpact) error {
	budget.row.Devices[0] = item
	if budget.protobuf+proto.Size(budget.row) > maxDocumentBytes {
		return ErrCapacity
	}
	b, err := protojson.Marshal(budget.row)
	if err != nil {
		return err
	}
	// Adding the two JSON object sizes conservatively reserves their joining
	// comma and its optional space as well as the devices field and brackets.
	if budget.json+len(b) > maxDocumentBytes {
		return ErrCapacity
	}
	return nil
}

func encodeImpactDevice(e *evaluation, current, proposed *policyv1.TargetResolution, match policyv1.TargetMatch, changed, direct bool, envelope *impactRowBudget) ([]byte, error) {
	d := e.input.Device
	item := &adminv1.TargetAssignmentDeviceImpact{DeviceId: d.ID.String(), Hostname: d.Hostname, OsId: d.OsID, OsVersion: d.OsVersion, Architecture: d.Architecture, State: d.State, Match: match, CurrentResolution: current, ProposedResolution: proposed, Changed: changed, ReplacesDirectAssignment: direct, Reasons: []string{"native_capabilities_unknown"}}
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
	if err := envelope.validate(item); err != nil {
		return nil, err
	}
	return encoded(item)
}

// headHasAssignment reports whether the device's active execution head included
// the assignment.
func headHasAssignment(ctx context.Context, q *targetingdb.Queries, head, assignment string) (bool, error) {
	id, err := uuid.Parse(head)
	if err != nil {
		return false, nil
	}
	row, err := q.GetTargetPreview(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	preview := new(policyv1.TargetPreview)
	if err := proto.Unmarshal(row.Document, preview); err != nil {
		return false, err
	}
	for _, c := range preview.Candidates {
		if c.Match == included && strings.EqualFold(c.GetAssignment().GetAssignmentId(), assignment) {
			return true, nil
		}
	}
	return false, nil
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

// adoptedRefs lists the resources whose ownership adopts existing native state;
// such a change needs the rollout's independent approval.
func adoptedRefs(resolution *policyv1.TargetResolution) []*resourcev1.ResourceRef {
	var refs []*resourcev1.ResourceRef
	for _, item := range resolution.GetResources() {
		if item.GetResource().GetOwnership().GetMode() == resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION {
			refs = append(refs, item.GetRef())
		}
	}
	return refs
}

const maxAdoptedRefs = 64

func countAdoption(report *adminv1.PreviewTargetAssignmentImpactResponse, proposed *policyv1.TargetResolution) {
	refs := adoptedRefs(proposed)
	if len(refs) == 0 {
		return
	}
	report.AdoptingCount++
	for _, ref := range refs {
		if len(report.Adopted) == maxAdoptedRefs {
			return
		}
		if !slices.ContainsFunc(report.Adopted, func(known *resourcev1.ResourceRef) bool { return proto.Equal(known, ref) }) {
			report.Adopted = append(report.Adopted, proto.CloneOf(ref))
		}
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

// deviceImpactChange reports whether the proposal changes the device and, if
// so, whether the change replaces a direct per-device assignment (a resource
// head that is not the device's execution preview).
func deviceImpactChange(ctx context.Context, q *targetingdb.Queries, d targetingdb.TargetingDeviceRow, current, proposed *policyv1.TargetResolution, match policyv1.TargetMatch, assignmentID string) (changed, direct bool, err error) {
	changed = impactChanged(current, proposed)
	if changed && match != included {
		// A device the proposal does not include changes because of it only
		// when its active head was built with this assignment (a removal);
		// otherwise the difference belongs to other assignments' rollouts.
		changed, err = headHasAssignment(ctx, q, d.PreviousPreviewID, assignmentID)
		if err != nil {
			return false, false, err
		}
	}
	return changed, changed && d.ResourceAssignmentID != "" && d.ResourceAssignmentID != d.PreviousPreviewID, nil
}

func countImpactChange(report *adminv1.PreviewTargetAssignmentImpactResponse, match policyv1.TargetMatch, changed, direct bool) {
	if !changed {
		return
	}
	switch match {
	case included:
		report.ChangedCount++
	case excluded:
		report.RemovingCount++
	}
	if direct && match != unknown {
		report.ReplacingDirectCount++
	}
}

// impactCandidates scans devices the proposal or its previous revision targets,
// within the principal's fleet read scope.
func impactCandidates(p identity.Principal, proposal, previous *policyv1.TargetAssignment) (targetingdb.ListImpactCandidatesParams, error) {
	u, scopes, err := scope(p, identity.PermissionReadFleet)
	if err != nil {
		return targetingdb.ListImpactCandidatesParams{}, err
	}
	params := targetingdb.ListImpactCandidatesParams{Unrestricted: u, Scopes: scopes, AfterID: uuid.Nil, DeviceIds: []uuid.UUID{}, GroupIds: []uuid.UUID{}}
	addImpactScope(&params, proposal.Target)
	if previous != nil {
		addImpactScope(&params, previous.Target)
	}
	return params, nil
}
