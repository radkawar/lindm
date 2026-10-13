package targeting

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/auditkind"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
	"lindm/internal/targeting/targetingdb"
)

// Plan statuses persisted in resource_rollout_plans.status.
const (
	planAwaitingApproval  int16 = 1
	planActive            int16 = 2
	planRejected          int16 = 3
	planApprovalExpired   int16 = 4
	planAssignmentChanged int16 = 5
	planSuperseded        int16 = 6
)

// Device plan states persisted in resource_rollout_device_plans.state.
const (
	devicePending     int16 = 1
	deviceActivated   int16 = 2
	deviceNeedsReview int16 = 3
)

const (
	awaitingApprovalReason = "awaiting_approval"
	// ApprovalWindow bounds how long a rollout waits for its approval request.
	// It equals the longest approval lifetime the approval API accepts.
	ApprovalWindow = time.Hour
)

// PlanActivator writes the device head for an exact preview. adoptionApprovalID
// is the rollout's consumed approval when the reviewed change adopts state.
type PlanActivator func(ctx context.Context, tx pgx.Tx, preview *policyv1.TargetPreview, adoptionApprovalID, reason string) error

func validateRolloutPlan(r *adminv1.StartRolloutRequest) error {
	rings := r.Rollout.Rings
	for i, ring := range rings {
		if !proto.Equal(ring.Cohort, r.Assignment.Target) {
			return ErrRejected
		}
		if i > 0 && ring.CumulativeBasisPoints < rings[i-1].CumulativeBasisPoints {
			return ErrRejected
		}
	}
	if rings[len(rings)-1].CumulativeBasisPoints != 10000 {
		return ErrRejected
	}
	return nil
}

func resolutionReady(resolution *policyv1.TargetResolution) bool {
	for _, item := range resolution.GetResources() {
		if item.GetDisposition() != policyv1.ResourceResolutionDisposition_RESOURCE_RESOLUTION_DISPOSITION_READY || item.GetResource() == nil {
			return false
		}
	}
	return true
}

// StartRollout records one reviewed rollout: the exact request (the payload of
// its single approval), the stage plan and every included device's reviewed
// resolution digest. Without a required approval it starts immediately: the
// assignment is saved with this rollout and the first stage is frozen. The
// promoter activates admitted devices; this call never activates a device.
// Like the impact review, it requires READ COMMITTED with input-table locks.
func (s *Store) StartRollout(ctx context.Context, tx pgx.Tx, p identity.Principal, r *adminv1.StartRolloutRequest, resolve ImpactResolver) (*adminv1.StartRolloutResponse, error) {
	if err := s.validate(r); err != nil {
		return nil, err
	}
	if err := validateRolloutPlan(r); err != nil {
		return nil, err
	}
	perm := identity.PermissionAssignResources
	q, err := begin(ctx, tx, p, perm, true)
	if err != nil {
		return nil, err
	}
	out := new(adminv1.StartRolloutResponse)
	if ok, err := receipt(ctx, q, p, r.RequestId, auditkind.TargetingRolloutStart, r, out); ok || err != nil {
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
	isolation, err := q.ImpactIsolation(ctx)
	if err != nil {
		return nil, err
	}
	if isolation != "read committed" {
		return nil, ErrRejected
	}
	now, err := q.TargetingClock(ctx)
	if err != nil {
		return nil, err
	}
	if !now.Time.Before(report.ValidUntil.AsTime()) {
		return nil, ErrImpactStale
	}
	var planned []plannedDevice
	current, currentInput, err := s.evaluateImpact(ctx, tx, q, p, r.Assignment, r.ExpectedRevision, resolve, nil, func(d plannedDevice) error {
		// Included devices move onto this assignment; a device the proposal no
		// longer includes is planned only when its settings change (removal).
		if (d.match == included || (d.match == excluded && d.changed)) && d.generation != nil && d.state == "active" {
			planned = append(planned, d)
		}
		return nil
	})
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
	// An empty plan would be a rollout that can never change a device.
	if len(planned) == 0 {
		return nil, ErrNotReady
	}
	approvalRequired := current.AdoptingCount > 0 || p.ApprovalRequired(perm)
	definition, err := encodedCatalog(r.Rollout)
	if err != nil {
		return nil, err
	}
	started, err := s.rolloutClock(ctx, q)
	if err != nil {
		return nil, err
	}
	id := uuid.MustParse(r.Rollout.RolloutId)
	count, err := q.InsertPlannedRollout(ctx, targetingdb.InsertPlannedRolloutParams{ID: id, Definition: definition, CreatorID: p.ID, StageStartedAt: pgtype.Timestamptz{Time: started, Valid: true}, Paused: true, PauseReason: awaitingApprovalReason, Name: rolloutName(r.Rollout)})
	if err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, ErrConflict
	}
	request, err := encoded(r)
	if err != nil {
		return nil, err
	}
	adopted, err := encoded(&adminv1.RolloutState{Adopted: current.Adopted})
	if err != nil {
		return nil, err
	}
	if err := q.InsertRolloutPlan(ctx, targetingdb.InsertRolloutPlanParams{RolloutID: id, AssignmentID: uuid.MustParse(r.Assignment.AssignmentId), ExpectedRevision: int64(r.ExpectedRevision), RequestID: uuid.MustParse(r.RequestId), Request: request, ApprovalRequired: approvalRequired, Status: planAwaitingApproval, Reason: r.Reason, Adopted: adopted}); err != nil {
		return nil, err
	}
	for _, d := range planned {
		b, err := encoded(d.proposed)
		if err != nil {
			return nil, err
		}
		state, reason := devicePending, ""
		if !resolutionReady(d.proposed) {
			state, reason = deviceNeedsReview, "resolution_not_ready"
		}
		if err := q.InsertRolloutDevicePlan(ctx, targetingdb.InsertRolloutDevicePlanParams{RolloutID: id, DeviceID: d.id, GenerationID: *d.generation, ResolutionSha256: digest("resolution", b), AdoptsExisting: len(adoptedRefs(d.proposed)) > 0, Included: d.match == included, ReviewedHead: parseHead(d.head), State: state, Reason: reason}); err != nil {
			return nil, err
		}
	}
	if !approvalRequired {
		if err := s.startPlan(ctx, q, p, perm, id, nil, false); err != nil {
			return nil, err
		}
	}
	out.Rollout, err = s.rolloutState(ctx, q, id)
	if err != nil {
		return nil, err
	}
	return out, saveReceipt(ctx, q, p, r.RequestId, auditkind.TargetingRolloutStart, id.String(), r.Reason, "", r, out)
}

// startPlan saves the reviewed assignment under its reviewed expected revision
// and freezes the first stage. A changed assignment ends the rollout instead;
// the caller still commits that terminal status. Earlier active or waiting
// rollouts of the same assignment are superseded.
func (s *Store) startPlan(ctx context.Context, q *targetingdb.Queries, p identity.Principal, perm identity.Permission, id uuid.UUID, approval *uuid.UUID, audit bool) error {
	plan, err := q.LockRolloutPlan(ctx, id)
	if err != nil {
		return err
	}
	if plan.Status != planAwaitingApproval {
		return ErrConflict
	}
	request := new(adminv1.StartRolloutRequest)
	if err := proto.Unmarshal(plan.Request, request); err != nil {
		return err
	}
	row, err := q.GetRollout(ctx, id)
	if err != nil {
		return err
	}
	previous, err := q.ActiveRolloutPlansForAssignment(ctx, plan.AssignmentID)
	if err != nil {
		return err
	}
	assignment := proto.CloneOf(request.Assignment)
	assignment.RolloutId = proto.String(id.String())
	if _, err := s.storeAssignment(ctx, q, p, assignment, uint64(plan.ExpectedRevision)); errors.Is(err, ErrConflict) {
		return s.endPlan(ctx, q, row, planAwaitingApproval, planAssignmentChanged, "assignment_changed")
	} else if err != nil {
		return err
	}
	for _, other := range previous {
		if other.RolloutID == id {
			continue
		}
		otherRow, err := q.GetRollout(ctx, other.RolloutID)
		if err != nil {
			return err
		}
		if err := s.endPlan(ctx, q, otherRow, other.Status, planSuperseded, "superseded"); err != nil {
			return err
		}
	}
	if err := s.freezeStage(ctx, q, p, perm, request.Rollout, 0); err != nil {
		return err
	}
	now, err := s.rolloutClock(ctx, q)
	if err != nil {
		return err
	}
	stamp := pgtype.Timestamptz{Time: now, Valid: true}
	count, err := q.UpdateRollout(ctx, targetingdb.UpdateRolloutParams{ID: id, RingIndex: 0, Paused: false, PauseReason: "", StageStartedAt: stamp, ExpectedRevision: row.Revision})
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrConflict
	}
	actor := p.ID
	if err := q.InsertRolloutEvent(ctx, targetingdb.InsertRolloutEventParams{ID: uuid.New(), RolloutID: id, Revision: row.Revision + 1, ActorID: &actor, Reason: plan.Reason}); err != nil {
		return err
	}
	count, err = q.UpdateRolloutPlanStatus(ctx, targetingdb.UpdateRolloutPlanStatusParams{RolloutID: id, Status: planActive, StatusReason: "", ApprovalID: approval, StartedAt: stamp, ExpectedStatus: planAwaitingApproval})
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrConflict
	}
	if !audit {
		return nil
	}
	context := ""
	if approval != nil {
		context = "approval " + approval.String()
	}
	return q.TargetingAudit(ctx, targetingdb.TargetingAuditParams{ID: uuid.New(), ActorID: &actor, Action: auditkind.TargetingRolloutStart.String(), ResourceID: id.String(), Reason: plan.Reason, Context: context})
}

// endPlan records a terminal plan status and withdraws the rollout's authority
// to admit or activate anything further. It never undoes applied devices.
func (s *Store) endPlan(ctx context.Context, q *targetingdb.Queries, row targetingdb.ResourceRollout, expected, status int16, reason string) error {
	count, err := q.UpdateRolloutPlanStatus(ctx, targetingdb.UpdateRolloutPlanStatusParams{RolloutID: row.ID, Status: status, StatusReason: reason, ExpectedStatus: expected})
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrConflict
	}
	if row.Paused && row.PauseReason == reason {
		return nil
	}
	return pauseRollout(ctx, q, row, reason)
}

// StartApproved starts a rollout whose single approval the caller has consumed
// in tx under the creator's fresh authorization (the principal p).
func (s *Store) StartApproved(ctx context.Context, tx pgx.Tx, p identity.Principal, id, approval uuid.UUID) error {
	perm := identity.PermissionAssignResources
	q, err := begin(ctx, tx, p, perm, true)
	if err != nil {
		return err
	}
	return s.startPlan(ctx, q, p, perm, id, &approval, true)
}

// endAwaiting records the outcome of a rollout still awaiting approval:
// rejected, withdrawn, or expired without a decision. Nothing was saved or admitted.
func (s *Store) endAwaiting(ctx context.Context, tx pgx.Tx, id uuid.UUID, status int16, reason string) error {
	q := targetingdb.New(tx)
	if err := q.LockTargeting(ctx); err != nil {
		return err
	}
	row, err := q.GetRollout(ctx, id)
	if err != nil {
		return err
	}
	return s.endPlan(ctx, q, row, planAwaitingApproval, status, reason)
}

// RolloutApprovalScope admits a CreateApproval only for a rollout still awaiting
// approval whose retained request equals the payload byte for byte.
func (s *Store) RolloutApprovalScope(ctx context.Context, tx pgx.Tx, r *adminv1.StartRolloutRequest) error {
	if err := s.validate(r); err != nil {
		return err
	}
	q := targetingdb.New(tx)
	plan, err := q.GetRolloutPlan(ctx, uuid.MustParse(r.Rollout.RolloutId))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	b, err := encoded(r)
	if err != nil {
		return err
	}
	if plan.Status != planAwaitingApproval || !plan.ApprovalRequired || !bytes.Equal(plan.Request, b) {
		return ErrRejected
	}
	return nil
}

// PlanRequest returns the exact retained StartRollout request of a rollout.
func (s *Store) PlanRequest(ctx context.Context, tx pgx.Tx, rolloutID string) (*adminv1.StartRolloutRequest, error) {
	id, err := uuid.Parse(rolloutID)
	if err != nil {
		return nil, ErrRejected
	}
	plan, err := targetingdb.New(tx).GetRolloutPlan(ctx, id)
	if err != nil {
		return nil, err
	}
	request := new(adminv1.StartRolloutRequest)
	return request, proto.Unmarshal(plan.Request, request)
}

// RolloutForApproval projects the retained rollout for an approval reviewer.
func (s *Store) RolloutForApproval(ctx context.Context, tx pgx.Tx, p identity.Principal, r *adminv1.StartRolloutRequest) (*adminv1.RolloutState, error) {
	q, err := beginRead(tx, p, identity.PermissionAssignResources, true)
	if err != nil {
		return nil, err
	}
	id, err := uuid.Parse(r.GetRollout().GetRolloutId())
	if err != nil {
		return nil, ErrRejected
	}
	state, err := s.rolloutState(ctx, q, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return state, err
}

// ActivatePlanned activates one admitted device's reviewed change through the
// normal Preview and Activate fences, or records why the device needs review.
// A fresh preview is applied only when its generation and resolution digest
// equal the reviewed plan; it is never silently applied otherwise.
func (s *Store) ActivatePlanned(ctx context.Context, tx pgx.Tx, p identity.Principal, rolloutID, deviceID uuid.UUID, resolve Resolver, activate PlanActivator) error {
	perm := identity.PermissionAssignResources
	q, err := begin(ctx, tx, p, perm, false)
	if err != nil {
		return err
	}
	plan, err := q.GetRolloutPlan(ctx, rolloutID)
	if err != nil {
		return err
	}
	row, err := q.GetRollout(ctx, rolloutID)
	if err != nil {
		return err
	}
	if plan.Status != planActive || row.Paused {
		return nil
	}
	device, err := q.LockRolloutDevicePlan(ctx, targetingdb.LockRolloutDevicePlanParams{RolloutID: rolloutID, DeviceID: deviceID})
	if err != nil {
		return err
	}
	if device.State != devicePending {
		return nil
	}
	if device.Included {
		if _, err := q.GetRolloutMember(ctx, targetingdb.GetRolloutMemberParams{RolloutID: rolloutID, RingIndex: row.RingIndex, DeviceID: deviceID}); errors.Is(err, pgx.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
	}
	mark := func(state int16, reason string, preview *uuid.UUID) error {
		count, err := q.UpdateRolloutDevicePlan(ctx, targetingdb.UpdateRolloutDevicePlanParams{RolloutID: rolloutID, DeviceID: deviceID, State: state, Reason: reason, PreviewID: preview})
		if err != nil {
			return err
		}
		if count != 1 {
			return ErrConflict
		}
		return nil
	}
	preview, err := s.Preview(ctx, tx, p, perm, &adminv1.PreviewTargetAssignmentsRequest{DeviceId: deviceID.String()}, resolve)
	if errors.Is(err, ErrNotReady) {
		return mark(deviceNeedsReview, "device_not_active", nil)
	}
	if err != nil {
		return err
	}
	previewID := uuid.MustParse(preview.PreviewId)
	if preview.GenerationId != device.GenerationID.String() {
		return mark(deviceNeedsReview, "device_reenrolled", &previewID)
	}
	// A direct assignment made on the device after the review is an
	// administrator's newer decision; never replace it silently.
	direct, err := q.GetDeviceDirectHead(ctx, deviceID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil && (device.ReviewedHead == nil || *device.ReviewedHead != direct) {
		return mark(deviceNeedsReview, "assigned_directly", &previewID)
	}
	for _, c := range preview.Candidates {
		if c.Match == unknown {
			// Membership must be known before any exact activation; retry later.
			return mark(devicePending, "membership_unknown", nil)
		}
	}
	// The resolution digest binds what the reviewer approved for this device,
	// whether it adds this assignment's settings or removes them.
	if !bytes.Equal(preview.ResolutionSha256, device.ResolutionSha256) {
		// Rollouts of different assignments on one device are reviewed one after
		// another, so the later review includes the earlier assignment. That
		// later rollout applies the combined change; this one never does.
		applied, err := headIncludes(ctx, q, deviceID, preview, plan.AssignmentID)
		if err != nil {
			return err
		}
		if applied != nil {
			return mark(deviceActivated, "applied_with_another_rollout", applied)
		}
		pending, err := q.OtherRolloutPlansResolution(ctx, targetingdb.OtherRolloutPlansResolutionParams{DeviceID: deviceID, RolloutID: rolloutID, ResolutionSha256: preview.ResolutionSha256})
		if err != nil {
			return err
		}
		if pending {
			return mark(devicePending, "waiting_for_another_rollout", nil)
		}
		return mark(deviceNeedsReview, "preview_changed", &previewID)
	}
	approval := ""
	if device.AdoptsExisting {
		if plan.ApprovalID == nil {
			return mark(deviceNeedsReview, "adoption_not_approved", &previewID)
		}
		approval = plan.ApprovalID.String()
	}
	// The device records the reviewed rollout's human reason.
	reason := plan.Reason
	_, err = s.Activate(ctx, tx, p, perm, &adminv1.ActivateTargetPreviewRequest{RequestId: uuid.NewString(), PreviewId: preview.PreviewId, PreviewSha256: preview.PreviewSha256, Reason: reason, DeviceId: deviceID.String()}, func(ctx context.Context, tx pgx.Tx, preview *policyv1.TargetPreview) error {
		return activate(ctx, tx, preview, approval, reason)
	})
	switch reason := rpcreason.Get(err); {
	case err == nil:
	case reason == "resource_resolution_conflict":
		return mark(deviceNeedsReview, "resolution_not_ready", &previewID)
	case reason == "approval_required" || reason == "approval_invalid":
		return mark(deviceNeedsReview, "adoption_not_approved", &previewID)
	default:
		return err
	}
	return mark(deviceActivated, "", &previewID)
}

// headIncludes returns the device's current execution head when it already
// includes the fresh preview's candidate for assignment at the same revision.
func headIncludes(ctx context.Context, q *targetingdb.Queries, deviceID uuid.UUID, fresh *policyv1.TargetPreview, assignment uuid.UUID) (*uuid.UUID, error) {
	var want *policyv1.TargetCandidate
	for _, c := range fresh.Candidates {
		if c.GetAssignment().GetAssignmentId() == assignment.String() && c.Match == included {
			want = c
		}
	}
	if want == nil {
		return nil, nil
	}
	document, err := q.TargetExecutionHead(ctx, deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	head := new(policyv1.TargetPreview)
	if err := proto.Unmarshal(document, head); err != nil {
		return nil, err
	}
	if head.GenerationId != fresh.GenerationId {
		return nil, nil
	}
	for _, c := range head.Candidates {
		if c.Match == included && proto.Equal(c.GetAssignment(), want.GetAssignment()) && c.Revision == want.Revision {
			id := uuid.MustParse(head.PreviewId)
			return &id, nil
		}
	}
	return nil, nil
}

func rolloutStatus(status int16) adminv1.RolloutStatus {
	switch status {
	case planAwaitingApproval:
		return adminv1.RolloutStatus_ROLLOUT_STATUS_AWAITING_APPROVAL
	case planActive:
		return adminv1.RolloutStatus_ROLLOUT_STATUS_ACTIVE
	case planRejected:
		return adminv1.RolloutStatus_ROLLOUT_STATUS_REJECTED
	case planApprovalExpired:
		return adminv1.RolloutStatus_ROLLOUT_STATUS_APPROVAL_EXPIRED
	case planAssignmentChanged:
		return adminv1.RolloutStatus_ROLLOUT_STATUS_ASSIGNMENT_CHANGED
	case planSuperseded:
		return adminv1.RolloutStatus_ROLLOUT_STATUS_SUPERSEDED
	default:
		return adminv1.RolloutStatus_ROLLOUT_STATUS_UNSPECIFIED
	}
}

// planState adds the reviewed plan, its status and per-device progress.
func planState(ctx context.Context, q *targetingdb.Queries, row targetingdb.ResourceRollout, state *adminv1.RolloutState) error {
	state.CreatorId = row.CreatorID.String()
	name, err := q.RolloutCreator(ctx, row.CreatorID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	state.CreatorDisplayName = name
	plan, err := q.GetRolloutPlan(ctx, row.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		state.Status = adminv1.RolloutStatus_ROLLOUT_STATUS_UNPLANNED
		if rings := state.GetRollout().GetRings(); len(rings) > 0 {
			state.TargetName, err = targetName(ctx, q, rings[0].Cohort)
		}
		return err
	}
	if err != nil {
		return err
	}
	request := new(adminv1.StartRolloutRequest)
	if err := proto.Unmarshal(plan.Request, request); err != nil {
		return err
	}
	adopted := new(adminv1.RolloutState)
	if err := proto.Unmarshal(plan.Adopted, adopted); err != nil {
		return err
	}
	state.Adopted = adopted.Adopted
	state.Status = rolloutStatus(plan.Status)
	state.StatusReason = plan.StatusReason
	state.Assignment = request.Assignment
	if plan.Status != planAwaitingApproval {
		state.Assignment.RolloutId = proto.String(row.ID.String())
	}
	state.CreatedAt = timestamppb.New(plan.CreatedAt.Time)
	if state.TargetName, err = targetName(ctx, q, request.Assignment.Target); err != nil {
		return err
	}
	labels, err := revisionLabels(ctx, q, []uuid.UUID{uuid.MustParse(request.Assignment.ProfileRevisionId)})
	if err != nil {
		return err
	}
	if len(labels) == 1 {
		state.ProfileVersion = labels[0]
	}
	state.ApprovalRequired = plan.ApprovalRequired
	state.Reason = plan.Reason
	if plan.ApprovalID != nil {
		state.ApprovalId = plan.ApprovalID.String()
	}
	counts, err := q.RolloutPlanCounts(ctx, targetingdb.RolloutPlanCountsParams{RolloutID: row.ID, RingIndex: row.RingIndex})
	if err != nil {
		return err
	}
	if plan.Status == planAwaitingApproval {
		// Nothing is admitted before approval: every pending device waits.
		counts.Waiting += counts.Starting
		counts.Starting = 0
	}
	state.PlannedCount, state.WaitingCount, state.StartingCount = uint32(counts.Planned), uint32(counts.Waiting), uint32(counts.Starting)
	state.ActivatedCount, state.NeedsReviewCount, state.AdoptingCount = uint32(counts.Activated), uint32(counts.NeedsReview), uint32(counts.Adopting)
	return nil
}

// ListRolloutDevices pages the reviewed device plan with live progress.
func (s *Store) ListRolloutDevices(ctx context.Context, tx pgx.Tx, p identity.Principal, perm identity.Permission, r *adminv1.ListRolloutDevicesRequest) (*adminv1.ListRolloutDevicesResponse, error) {
	if err := s.validate(r); err != nil {
		return nil, err
	}
	q, err := beginRead(tx, p, perm, true)
	if err != nil {
		return nil, err
	}
	id := uuid.MustParse(r.RolloutId)
	row, err := q.GetRollout(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	plan, err := q.GetRolloutPlan(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return &adminv1.ListRolloutDevicesResponse{}, nil
	}
	if err != nil {
		return nil, err
	}
	after := uuid.Nil
	if r.AfterDeviceId != nil {
		after = uuid.MustParse(*r.AfterDeviceId)
	}
	out := new(adminv1.ListRolloutDevicesResponse)
	// A state filter scans at most one plan's 10,000 rows in bounded pages.
	for scanned := 0; scanned <= maxImpactDevices; {
		rows, err := q.ListRolloutDevicePlans(ctx, targetingdb.ListRolloutDevicePlansParams{RolloutID: id, RingIndex: row.RingIndex, AfterID: after, RowLimit: 200})
		if err != nil {
			return nil, err
		}
		for _, item := range rows {
			after = item.DeviceID
			scanned++
			device := &adminv1.RolloutDevice{DeviceId: item.DeviceID.String(), Hostname: item.Hostname, State: rolloutDeviceState(item, plan.Status), Reason: item.Reason, AdoptsExisting: item.AdoptsExisting, UpdatedAt: timestamppb.New(item.UpdatedAt.Time)}
			if r.State != adminv1.RolloutDeviceState_ROLLOUT_DEVICE_STATE_UNSPECIFIED && device.State != r.State {
				continue
			}
			out.Devices = append(out.Devices, device)
			if uint32(len(out.Devices)) == r.PageSize {
				return out, nil
			}
		}
		if len(rows) < 200 {
			break
		}
	}
	return out, nil
}

func rolloutDeviceState(item targetingdb.ListRolloutDevicePlansRow, status int16) adminv1.RolloutDeviceState {
	switch item.State {
	case deviceNeedsReview:
		return adminv1.RolloutDeviceState_ROLLOUT_DEVICE_STATE_NEEDS_REVIEW
	case devicePending:
		if item.Admitted && status == planActive {
			return adminv1.RolloutDeviceState_ROLLOUT_DEVICE_STATE_STARTING
		}
		return adminv1.RolloutDeviceState_ROLLOUT_DEVICE_STATE_WAITING
	}
	if !item.Current {
		return adminv1.RolloutDeviceState_ROLLOUT_DEVICE_STATE_UNAVAILABLE
	}
	switch item.Health {
	case 1:
		return adminv1.RolloutDeviceState_ROLLOUT_DEVICE_STATE_APPLIED
	case 2:
		return adminv1.RolloutDeviceState_ROLLOUT_DEVICE_STATE_FAILED
	case 4:
		return adminv1.RolloutDeviceState_ROLLOUT_DEVICE_STATE_UNAVAILABLE
	default:
		return adminv1.RolloutDeviceState_ROLLOUT_DEVICE_STATE_APPLYING
	}
}

// planControlAllowed refuses operator control of a rollout that is not running
// its reviewed plan: resuming one awaiting approval would bypass the approval.
func planControlAllowed(ctx context.Context, q *targetingdb.Queries, id uuid.UUID) error {
	plan, err := q.GetRolloutPlan(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if plan.Status != planActive {
		return fmt.Errorf("rollout plan status %d: %w", plan.Status, ErrNotReady)
	}
	return nil
}

// parseHead is the review's resource head id, absent when the device had none.
func parseHead(id string) *uuid.UUID {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return nil
	}
	return &parsed
}
