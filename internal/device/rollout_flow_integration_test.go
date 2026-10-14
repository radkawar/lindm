// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/targeting"
)

// rolloutFixture reviews one profile version for the fixture device through the
// real RPCs, with a real promoter running the device-domain activation hooks.
type rolloutFixture struct {
	*dispatchFixture
	promoter *targeting.Promoter
}

func newRolloutFixture(t *testing.T, mode resourcev1.OwnershipMode) *rolloutFixture {
	t.Helper()
	f := newDispatchFixture(t)
	if _, err := f.service.ReportHostObservation(f.deviceCtx, connect.NewRequest(hostObservation(f.principal.GenerationID.String(), 1, "rollout-laptop"))); err != nil {
		t.Fatal(err)
	}
	item := proto.CloneOf(f.revision.GetSpec().GetResources()[1])
	item.DependsOn = nil
	item.Ownership.Mode = mode
	item.Ownership.AdoptionApprovalId = nil
	publishDispatchResources(t, f, item)
	promoter, err := targeting.NewPromoter(f.pool, f.service.Identity, f.service.Targeting, f.service.RolloutHooks())
	if err != nil {
		t.Fatal(err)
	}
	return &rolloutFixture{dispatchFixture: f, promoter: promoter}
}

func (f *rolloutFixture) review(t *testing.T) *adminv1.PreviewTargetAssignmentImpactResponse {
	t.Helper()
	target := &policyv1.TargetRef{Target: &policyv1.TargetRef_DeviceId{DeviceId: f.principal.DeviceID.String()}}
	review, err := f.service.PreviewTargetAssignmentImpact(f.adminCtx, connect.NewRequest(&adminv1.PreviewTargetAssignmentImpactRequest{Assignment: &policyv1.TargetAssignment{AssignmentId: uuid.NewString(), ProfileRevisionId: f.revision.RevisionId, Target: target}, PageSize: 20}))
	if err != nil {
		t.Fatal(err)
	}
	return review.Msg
}

func (f *rolloutFixture) head(t *testing.T) (string, *string) {
	t.Helper()
	var head string
	var approval *string
	err := f.pool.QueryRow(t.Context(), "SELECT a.id::text, a.adoption_approval_id::text FROM resource_assignment_heads h JOIN resource_assignments a ON a.id=h.assignment_id WHERE h.generation_id=$1", f.principal.GenerationID).Scan(&head, &approval)
	if err != nil {
		return "", nil
	}
	return head, approval
}

func TestRolloutActivatesReviewedDeviceWithoutPerDeviceSteps(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newRolloutFixture(t, resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY)
	review := f.review(t)
	if review.ApprovalRequired || review.AdoptingCount != 0 || review.IncludedCount != 1 {
		t.Fatalf("create-only review: %v", review)
	}
	started, err := f.service.StartRollout(f.adminCtx, connect.NewRequest(reviewedRollout(review, "Roll out the baseline service")))
	if err != nil {
		t.Fatal(err)
	}
	if len(review.RevisionLabels) != 1 || review.RevisionLabels[0].RevisionId != f.revision.RevisionId || review.RevisionLabels[0].ProfileName == "" {
		t.Fatalf("review does not name its profile version: %v", review.RevisionLabels)
	}
	if state := started.Msg.Rollout; state.GetProfileVersion().GetProfileName() != f.revision.GetSpec().GetName() || state.TargetName != "rollout-laptop" {
		t.Fatalf("rollout does not name what it delivers where: %v %q", state.GetProfileVersion(), state.TargetName)
	}
	if state := started.Msg.Rollout; state.Status != adminv1.RolloutStatus_ROLLOUT_STATUS_ACTIVE || state.StartingCount != 1 {
		t.Fatalf("approval-free rollout did not start: %v", state)
	}
	if head, _ := f.head(t); head != "" {
		t.Fatal("StartRollout activated a device inside the request")
	}
	if err := f.promoter.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	state, err := f.service.GetDeviceResourceState(f.adminCtx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: f.principal.DeviceID.String()}))
	if err != nil {
		t.Fatal(err)
	}
	active := state.Msg.GetActiveTargetPreview()
	if active == nil || state.Msg.GetAssignment().GetAssignmentId() != active.GetPreviewId() || len(active.GetResolution().GetResources()) != 1 {
		t.Fatalf("promoter did not activate the exact reviewed preview: %v", state.Msg)
	}
	if head := state.Msg.GetAssignment(); head.GetReason() != "Roll out the baseline service" || len(head.GetSources()) != 1 || head.GetSources()[0].GetProfileName() != f.revision.GetSpec().GetName() {
		t.Fatalf("rollout head does not name its reason and profile: %q %v", head.GetReason(), head.GetSources())
	}
	devices, err := f.service.ListRolloutDevices(f.adminCtx, connect.NewRequest(&adminv1.ListRolloutDevicesRequest{RolloutId: started.Msg.Rollout.Rollout.RolloutId, PageSize: 10}))
	if err != nil {
		t.Fatal(err)
	}
	if len(devices.Msg.Devices) != 1 || devices.Msg.Devices[0].Hostname != "rollout-laptop" || devices.Msg.Devices[0].State != adminv1.RolloutDeviceState_ROLLOUT_DEVICE_STATE_APPLYING {
		t.Fatalf("rollout device progress: %v", devices.Msg)
	}
}

// A direct assignment made on the device after the review is the newer
// decision: the promoter marks the device for review instead of replacing it.
func TestRolloutNeverReplacesDirectAssignmentMadeAfterReview(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newRolloutFixture(t, resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY)
	review := f.review(t)
	if review.ReplacingDirectCount != 0 {
		t.Fatalf("fresh device reported a direct assignment: %v", review)
	}
	started, err := f.service.StartRollout(f.adminCtx, connect.NewRequest(reviewedRollout(review, "Roll out the baseline service")))
	if err != nil {
		t.Fatal(err)
	}
	direct := f.assign(t, nil)
	if err := f.promoter.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if head, _ := f.head(t); head != direct.GetAssignmentId() {
		t.Fatalf("rollout replaced the newer direct assignment: head %s, direct %s", head, direct.GetAssignmentId())
	}
	devices, err := f.service.ListRolloutDevices(f.adminCtx, connect.NewRequest(&adminv1.ListRolloutDevicesRequest{RolloutId: started.Msg.Rollout.Rollout.RolloutId, PageSize: 10}))
	if err != nil {
		t.Fatal(err)
	}
	if len(devices.Msg.Devices) != 1 || devices.Msg.Devices[0].State != adminv1.RolloutDeviceState_ROLLOUT_DEVICE_STATE_NEEDS_REVIEW || devices.Msg.Devices[0].Reason != "assigned_directly" {
		t.Fatalf("directly assigned device is not held for review: %v", devices.Msg)
	}
}

func TestRolloutAdoptionNeedsOneIndependentApproval(t *testing.T) {
	parallelDeviceIntegration(t)
	for _, decision := range []string{"approve", "reject"} {
		t.Run(decision, func(t *testing.T) {
			f := newRolloutFixture(t, resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION)
			review := f.review(t)
			if !review.ApprovalRequired || review.AdoptingCount != 1 || len(review.Adopted) != 1 {
				t.Fatalf("review hid the adoption: %v", review)
			}
			request := reviewedRollout(review, "Adopt the existing service")
			started, err := f.service.StartRollout(f.adminCtx, connect.NewRequest(request))
			if err != nil {
				t.Fatal(err)
			}
			state := started.Msg.Rollout
			if state.Status != adminv1.RolloutStatus_ROLLOUT_STATUS_AWAITING_APPROVAL || state.ApprovalId != "" || state.AdoptingCount != 1 || len(state.Adopted) != 1 {
				t.Fatalf("adoption did not wait for approval: %v", state)
			}
			var assignments int
			if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM target_assignments").Scan(&assignments); err != nil || assignments != 0 {
				t.Fatalf("awaiting rollout saved its assignment: %d %v", assignments, err)
			}
			tampered := proto.CloneOf(request)
			tampered.Reason = "A different request"
			if _, err := f.service.CreateApproval(f.adminCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 3600, Payload: &adminv1.CreateApprovalRequest_StartRollout{StartRollout: tampered}})); err == nil {
				t.Fatal("approval bound a request other than the retained rollout")
			}
			created, err := f.service.CreateApproval(f.adminCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 3600, Payload: &adminv1.CreateApprovalRequest_StartRollout{StartRollout: request}}))
			if err != nil {
				t.Fatal(err)
			}
			approval := created.Msg.GetApproval()
			if approval.GetAction() != "resources.rollout" || approval.GetDeviceId() != "" || approval.GetRollout().GetPlannedCount() != 1 {
				t.Fatalf("rollout approval lost its plan: %v", approval)
			}
			if _, err := f.service.ApproveApproval(f.adminCtx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: approval.GetId(), Reason: "Approve my own rollout"})); err == nil {
				t.Fatal("requester approved their own rollout")
			}
			listed, err := f.service.ListRollouts(f.adminCtx, connect.NewRequest(&adminv1.ListRolloutsRequest{PageSize: 10}))
			if err != nil || len(listed.Msg.Rollouts) != 1 || listed.Msg.Rollouts[0].ApprovalId != approval.GetId() {
				t.Fatalf("rollout list did not name its pending approval: %v %v", listed, err)
			}
			reviewer := f.directory.reviewer(t, f.pool)
			if decision == "approve" {
				_, err = f.service.ApproveApproval(reviewer, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: approval.GetId(), Reason: "Reviewed the adopted service on one device"}))
			} else {
				_, err = f.service.RejectApproval(reviewer, connect.NewRequest(&adminv1.RejectApprovalRequest{ApprovalId: approval.GetId(), Reason: "Do not adopt this service"}))
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := f.promoter.RunOnce(t.Context()); err != nil {
				t.Fatal(err)
			}
			listed, err = f.service.ListRollouts(f.adminCtx, connect.NewRequest(&adminv1.ListRolloutsRequest{PageSize: 10}))
			if err != nil {
				t.Fatal(err)
			}
			got := listed.Msg.Rollouts[0]
			if decision == "reject" {
				if got.Status != adminv1.RolloutStatus_ROLLOUT_STATUS_REJECTED {
					t.Fatalf("rejected rollout status: %v", got)
				}
				if head, _ := f.head(t); head != "" {
					t.Fatal("rejected rollout changed the device")
				}
				return
			}
			if got.Status != adminv1.RolloutStatus_ROLLOUT_STATUS_ACTIVE || got.ApprovalId != approval.GetId() || got.ActivatedCount != 1 {
				t.Fatalf("approved rollout did not start and activate: %v", got)
			}
			head, adoption := f.head(t)
			if head == "" || adoption == nil || *adoption != approval.GetId() {
				t.Fatalf("device head is not bound to the rollout approval: head=%s approval=%v", head, adoption)
			}
			var consumed string
			if err := f.pool.QueryRow(t.Context(), "SELECT state FROM approval_requests WHERE id=$1", approval.GetId()).Scan(&consumed); err != nil || consumed != "consumed" {
				t.Fatalf("rollout approval not consumed: %s %v", consumed, err)
			}
		})
	}
}
