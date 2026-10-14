// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestResourceAdoptionConsumesIndependentExactAssignmentApproval(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixture(t)
	item := proto.CloneOf(f.revision.GetSpec().GetResources()[1])
	item.DependsOn = nil
	item.Ownership.Mode = resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION
	item.Ownership.AdoptionApprovalId = nil
	publishDispatchResources(t, f, item)
	request := f.assignmentRequest(nil)
	_, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(request))
	dispatchError(t, err, connect.CodePermissionDenied, "approval_required")
	created, err := f.service.CreateApproval(f.adminCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_SetResourceAssignment{SetResourceAssignment: proto.CloneOf(request)}}))
	if err != nil {
		t.Fatal(err)
	}
	approvalID := created.Msg.GetApproval().GetId()
	request.ApprovalId = approvalID
	if _, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("pending approval admitted adoption: %v", err)
	}
	if _, err := f.service.ApproveApproval(f.directory.reviewer(t, f.pool), connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: approvalID, Reason: "independently reviewed exact resource adoption"})); err != nil {
		t.Fatal(err)
	}
	changed := proto.CloneOf(request)
	changed.RequestId = uuid.NewString()
	if _, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("different request reused adoption approval: %v", err)
	}
	response, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(request)); err != nil {
		t.Fatalf("exact approved retry failed: %v", err)
	}
	var state, persisted string
	if err := f.pool.QueryRow(t.Context(), "SELECT p.state, a.adoption_approval_id::text FROM resource_assignments a JOIN approval_requests p ON p.id=a.adoption_approval_id WHERE a.id=$1", response.Msg.GetAssignment().GetAssignmentId()).Scan(&state, &persisted); err != nil || state != "consumed" || persisted != approvalID {
		t.Fatalf("missing independently consumed approval: %s %s %v", state, persisted, err)
	}
	// Admit only the signed-binding fixture; production native adoption remains
	// independently gated until the native owner supplies qualification evidence.
	if _, err := f.pool.Exec(t.Context(), "UPDATE resource_assignment_resources SET disposition=1, reason='' WHERE assignment_id=$1", response.Msg.GetAssignment().GetAssignmentId()); err != nil {
		t.Fatal(err)
	}
	intent := f.intent(t, f.work(t))
	if intent.GetOwnership().GetPolicy().GetAdoptionApprovalId() != approvalID || intent.GetOwnership().GetSources()[0].GetProfileRevision() != f.revision.GetRevisionId() {
		t.Fatal("signed ownership lost approved immutable revision binding")
	}
	profile, err := f.service.GetProfileRevision(f.adminCtx, connect.NewRequest(&adminv1.GetProfileRevisionRequest{ProfileId: f.revision.GetProfileId(), RevisionId: proto.String(f.revision.GetRevisionId())}))
	if err != nil || profile.Msg.GetRevision().GetSpec().GetResources()[0].GetOwnership().GetAdoptionApprovalId() != "" {
		t.Fatalf("signed approval mutated immutable profile: %v", err)
	}
}

func TestProfileCannotSupplyAdoptionApprovalMarker(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixture(t)
	spec := proto.CloneOf(f.revision.GetSpec())
	spec.Resources[0].Ownership.Mode = resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION
	spec.Resources[0].Ownership.AdoptionApprovalId = proto.String(uuid.NewString())
	_, err := f.service.PublishProfileRevision(f.adminCtx, connect.NewRequest(&adminv1.PublishProfileRevisionRequest{RequestId: uuid.NewString(), ProfileId: uuid.NewString(), Spec: spec, Reason: "reject unbound adoption marker"}))
	dispatchError(t, err, connect.CodeInvalidArgument, "profile_adoption_approval_must_be_assignment_bound")
}
