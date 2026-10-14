// SPDX-License-Identifier: Apache-2.0

//go:build integration

package targeting

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/identity"
	"lindm/internal/targeting/targetingdb"
)

// candidateResolution is a deterministic stand-in for policy resolution: one
// resource per included assignment, so another assignment changes the digest.
func candidateResolution(candidates []*policyv1.TargetCandidate, mode resourcev1.OwnershipMode) *policyv1.TargetResolution {
	out := &policyv1.TargetResolution{}
	for _, c := range candidates {
		if c.Match != included {
			continue
		}
		key := c.Assignment.ProfileRevisionId + "/" + c.Assignment.AssignmentId
		out.Resources = append(out.Resources, &policyv1.ResolvedResource{
			Ref:         &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL, CanonicalKey: key},
			Resource:    &policyv1.ProfileResource{ResourceId: uuid.NewSHA1(uuid.NameSpaceOID, []byte(key)).String(), Ownership: &resourcev1.OwnershipPolicy{Mode: mode}},
			Disposition: policyv1.ResourceResolutionDisposition_RESOURCE_RESOLUTION_DISPOSITION_READY,
		})
	}
	return out
}

type planHooks struct {
	mode        resourcev1.OwnershipMode
	activations []string
}

func (h *planHooks) resolve(_ context.Context, _ pgx.Tx, candidates []*policyv1.TargetCandidate) (*policyv1.TargetResolution, error) {
	return candidateResolution(candidates, h.mode), nil
}
func (h *planHooks) impact(_ context.Context, _ pgx.Tx, _ *uuid.UUID, candidates []*policyv1.TargetCandidate) (*policyv1.TargetResolution, *policyv1.TargetResolution, error) {
	return &policyv1.TargetResolution{}, candidateResolution(candidates, h.mode), nil
}
func (h *planHooks) hooks() RolloutHooks {
	return RolloutHooks{
		Resolve: h.resolve,
		Activate: func(_ context.Context, _ pgx.Tx, preview *policyv1.TargetPreview, _ uuid.UUID, _ uint64, approval, _ string) error {
			h.activations = append(h.activations, preview.PreviewId+"|"+approval)
			return nil
		},
		ApprovalScope: func(context.Context, pgx.Tx, identity.Principal, identity.Permission, uuid.UUID) error { return nil },
	}
}

// testRolloutHooks serves promotion tests whose rollouts have no reviewed plan.
func testRolloutHooks(*targetingFixture) RolloutHooks {
	return (&planHooks{mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY}).hooks()
}

func newPlanFixture(t *testing.T, mode resourcev1.OwnershipMode) (*targetingFixture, *planHooks, *Promoter, context.Context) {
	t.Helper()
	f, auth, _, ctx := newPromoterFixture(t)
	h := &planHooks{mode: mode}
	promoter, err := NewPromoter(f.pool, auth, f.store, h.hooks())
	if err != nil {
		t.Fatal(err)
	}
	return f, h, promoter, ctx
}

func (f *targetingFixture) startReviewed(t *testing.T, h *planHooks) *adminv1.StartRolloutResponse {
	t.Helper()
	var report *adminv1.PreviewTargetAssignmentImpactResponse
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		var err error
		report, err = f.store.Impact(t.Context(), tx, f.actor, f.impactRequest(impactDevice(f.device)), h.impact)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if report.IncludedCount != 1 || (report.AdoptingCount == 1) != (h.mode == resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION) || report.ApprovalRequired != (report.AdoptingCount == 1) {
		t.Fatalf("impact did not summarize the reviewed adoption: %v", report)
	}
	var out *adminv1.StartRolloutResponse
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		var err error
		out, err = f.store.StartRollout(t.Context(), tx, f.actor, reviewedStart(report), h.impact)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *targetingFixture) rolloutState(t *testing.T, id string) *adminv1.RolloutState {
	t.Helper()
	state, err := f.store.rolloutState(t.Context(), targetingdb.New(f.pool), uuid.MustParse(id))
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func (f *targetingFixture) devicePlan(t *testing.T, rollout string) (int16, string) {
	t.Helper()
	var state int16
	var reason string
	if err := f.pool.QueryRow(t.Context(), "SELECT state,reason FROM resource_rollout_device_plans WHERE rollout_id=$1 AND device_id=$2", uuid.MustParse(rollout), f.device).Scan(&state, &reason); err != nil {
		t.Fatal(err)
	}
	return state, reason
}

func TestStartRolloutActivatesReviewedChangeThroughPromoter(t *testing.T) {
	f, h, promoter, ctx := newPlanFixture(t, resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY)
	started := f.startReviewed(t, h)
	state := started.Rollout
	if state.Status != adminv1.RolloutStatus_ROLLOUT_STATUS_ACTIVE || state.Paused || state.PlannedCount != 1 || state.StartingCount != 1 || state.ApprovalRequired || state.Rollout.Name != "Cohort baseline" || state.Assignment.GetRolloutId() != state.Rollout.RolloutId {
		t.Fatalf("unapproved rollout did not start with its reviewed plan: %v", state)
	}
	if len(h.activations) != 0 {
		t.Fatal("starting a rollout activated a device inside the request")
	}
	if err := promoter.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(h.activations) != 1 || h.activations[0][len(h.activations[0])-1] != '|' {
		t.Fatalf("promoter did not activate exactly one unapproved change: %v", h.activations)
	}
	if got, _ := f.devicePlan(t, state.Rollout.RolloutId); got != deviceActivated {
		t.Fatalf("device plan state=%d, want activated", got)
	}
	var head uuid.UUID
	if err := f.pool.QueryRow(ctx, "SELECT preview_id FROM target_execution_heads WHERE device_id=$1", f.device).Scan(&head); err != nil {
		t.Fatal(err)
	}
	if h.activations[0] != head.String()+"|" {
		t.Fatal("execution head is not the exact activated preview")
	}
	after := f.rolloutState(t, state.Rollout.RolloutId)
	if after.ActivatedCount != 1 || after.StartingCount != 0 || after.NeedsReviewCount != 0 {
		t.Fatalf("progress did not come from the device plan: %v", after)
	}
	// A second pass never repeats an activated device.
	if err := promoter.RunOnce(ctx); err != nil || len(h.activations) != 1 {
		t.Fatalf("activation repeated: %v %v", h.activations, err)
	}
	var devices *adminv1.ListRolloutDevicesResponse
	if err := f.transaction(t, func(tx pgx.Tx) error {
		var err error
		devices, err = f.store.ListRolloutDevices(ctx, tx, f.actor, identity.PermissionAssignResources, &adminv1.ListRolloutDevicesRequest{RolloutId: state.Rollout.RolloutId, PageSize: 10})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(devices.Devices) != 1 || devices.Devices[0].Hostname != "canary" || devices.Devices[0].State != adminv1.RolloutDeviceState_ROLLOUT_DEVICE_STATE_APPLYING {
		t.Fatalf("device progress row: %v", devices)
	}
}

func TestStartRolloutDriftedDeviceNeedsReviewAndIsNeverApplied(t *testing.T) {
	f, h, promoter, ctx := newPlanFixture(t, resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY)
	state := f.startReviewed(t, h).Rollout
	// Another administrator's assignment changes this device's resolution after review.
	f.putAssignment(t, impactDevice(f.device), 5)
	if err := promoter.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(h.activations) != 0 {
		t.Fatal("a drifted preview was activated")
	}
	if got, reason := f.devicePlan(t, state.Rollout.RolloutId); got != deviceNeedsReview || reason != "preview_changed" {
		t.Fatalf("drifted device plan state=%d reason=%q", got, reason)
	}
	var heads int
	if err := f.pool.QueryRow(ctx, "SELECT count(*) FROM target_execution_heads WHERE device_id=$1", f.device).Scan(&heads); err != nil || heads != 0 {
		t.Fatalf("drift moved the execution head: %d %v", heads, err)
	}
	if after := f.rolloutState(t, state.Rollout.RolloutId); after.NeedsReviewCount != 1 || after.Paused {
		t.Fatalf("needs-review device was not reported, or paused the whole rollout: %v", after)
	}
}

func TestStartRolloutAdoptionWaitsForOneApprovalAndSavesNothing(t *testing.T) {
	f, h, promoter, ctx := newPlanFixture(t, resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION)
	state := f.startReviewed(t, h).Rollout
	if state.Status != adminv1.RolloutStatus_ROLLOUT_STATUS_AWAITING_APPROVAL || !state.ApprovalRequired || !state.Paused || state.AdoptingCount != 1 || state.WaitingCount != 1 {
		t.Fatalf("adoption did not wait for approval: %v", state)
	}
	var assignments, members int
	if err := f.pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM target_assignments),(SELECT count(*) FROM resource_rollout_members)").Scan(&assignments, &members); err != nil {
		t.Fatal(err)
	}
	if assignments != 0 || members != 0 {
		t.Fatal("awaiting rollout saved its assignment or admitted devices")
	}
	// Resuming would bypass the approval.
	if err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.ControlRollout(ctx, tx, f.actor, identity.PermissionAssignResources, &adminv1.ControlRolloutRequest{RequestId: uuid.NewString(), RolloutId: state.Rollout.RolloutId, ExpectedRevision: state.Revision, Operation: adminv1.ControlRolloutRequest_OPERATION_RESUME, Reason: "Skip the approval"})
		return err
	}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("resume bypassed the rollout approval: %v", err)
	}
	if err := promoter.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(h.activations) != 0 {
		t.Fatal("awaiting rollout activated a device")
	}
	// Without an approval request for longer than the approval window, it ends.
	if _, err := f.pool.Exec(ctx, "UPDATE resource_rollout_plans SET created_at=created_at-interval '2 hours' WHERE rollout_id=$1", uuid.MustParse(state.Rollout.RolloutId)); err != nil {
		t.Fatal(err)
	}
	if err := promoter.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if after := f.rolloutState(t, state.Rollout.RolloutId); after.Status != adminv1.RolloutStatus_ROLLOUT_STATUS_APPROVAL_EXPIRED || after.StatusReason != "approval_expired" || !after.Paused {
		t.Fatalf("unapproved rollout did not expire visibly: %v", after)
	}
}

func TestStartRolloutRejectsMismatchedStagePlan(t *testing.T) {
	f, h, _, _ := newPlanFixture(t, resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY)
	var report *adminv1.PreviewTargetAssignmentImpactResponse
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		var err error
		report, err = f.store.Impact(t.Context(), tx, f.actor, f.impactRequest(impactDevice(f.device)), h.impact)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*adminv1.StartRolloutRequest){
		"other cohort": func(r *adminv1.StartRolloutRequest) {
			r.Rollout.Rings[0].Cohort = impactDevice(uuid.New())
		},
		"partial final stage": func(r *adminv1.StartRolloutRequest) { r.Rollout.Rings[0].CumulativeBasisPoints = 5000 },
		"bound rollout":       func(r *adminv1.StartRolloutRequest) { r.Assignment.RolloutId = proto.String(uuid.NewString()) },
	} {
		t.Run(name, func(t *testing.T) {
			r := reviewedStart(report)
			change(r)
			if err := f.impactTransaction(t, func(tx pgx.Tx) error {
				_, err := f.store.StartRollout(t.Context(), tx, f.actor, r, h.impact)
				return err
			}); !errors.Is(err, ErrRejected) {
				t.Fatalf("mismatched rollout plan accepted: %v", err)
			}
		})
	}
}
