//go:build integration

package device

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestHeterogeneousResourceAssignmentDispatchAndRelease(t *testing.T) {
	f := newDispatchFixture(t)
	service := proto.CloneOf(f.revision.GetSpec().GetResources()[1])
	service.DependsOn = nil
	group := dispatchProfileResource(&resourcev1.ResourceDesiredState{
		Ref:   &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP, CanonicalKey: "operators"},
		State: &resourcev1.ResourceDesiredState_LocalGroup{LocalGroup: &resourcev1.LocalGroupDesired{Name: "operators", Presence: resourcev1.Presence_PRESENCE_PRESENT}},
	})
	publishDispatchResources(t, f, service, group)
	assignment := f.assign(t, nil)
	work := f.work(t)
	intent := f.intent(t, work)
	if intent.GetDesired().GetUnit() != service.GetDesired().GetSystemdService().GetUnit() {
		t.Fatal("heterogeneous assignment dispatched a different native service")
	}
	f.start(t, work)
	if _, err := f.service.ReportServiceResult(f.deviceCtx, connect.NewRequest(f.result(t, work, 1, agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED, true))); err != nil {
		t.Fatal(err)
	}
	state := complianceState(t, f)
	if len(state.GetResources()) != 2 {
		t.Fatalf("heterogeneous assignment lost resources: %v", state)
	}
	for _, item := range state.GetResources() {
		switch item.GetResourceId() {
		case service.GetResourceId():
			if item.GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_SUCCEEDED || item.GetLatestAction().GetActionId() != work.GetActionId() {
				t.Fatalf("service did not retain verified dispatch history: %v", item)
			}
		case group.GetResourceId():
			if item.GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_UNSUPPORTED || item.GetReason() != "resource_executor_not_available" || item.GetLatestAction() != nil || !proto.Equal(item.GetDesired(), group.GetDesired()) {
				t.Fatalf("nonservice resource lost explicit unsupported state: %v", item)
			}
		default:
			t.Fatalf("unexpected resource: %v", item)
		}
	}
	assertNoResourceWork(t, f)
	clear := f.assignmentRequest(proto.String(assignment.GetAssignmentId()))
	clear.Target, clear.Clear = nil, true
	cleared, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(clear))
	if err != nil {
		t.Fatal(err)
	}
	state = complianceState(t, f)
	if len(state.GetResources()) != 0 || len(state.GetReleases()) != 2 {
		t.Fatalf("clear did not retain resource release visibility: %v", state)
	}
	refs := map[string]bool{service.GetDesired().GetRef().GetCanonicalKey(): true, group.GetDesired().GetRef().GetCanonicalKey(): true}
	for _, release := range state.GetReleases() {
		key := release.GetRef().GetCanonicalKey()
		if !refs[key] || release.GetState() != "baseline_unknown" || release.GetReason() != "ownership_baseline_unavailable" || release.GetCompletedAt() != nil || release.GetRequestedAt() == nil || release.GetSourceAssignmentId() != assignment.GetAssignmentId() || release.GetSupersedingAssignmentId() != cleared.Msg.GetAssignment().GetAssignmentId() {
			t.Fatalf("release fabricated native cleanup or lost provenance: %v", release)
		}
		delete(refs, key)
	}
	assertNoResourceWork(t, f)
	var count int
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM resource_actions WHERE generation_id=$1", f.principal.GenerationID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("unsupported resource or release minted a native action: count=%d err=%v", count, err)
	}
}

func TestCrossKindResourceClaimConflictNeverDispatches(t *testing.T) {
	f := newDispatchFixture(t)
	service := proto.CloneOf(f.revision.GetSpec().GetResources()[1])
	service.DependsOn = nil
	group := dispatchProfileResource(&resourcev1.ResourceDesiredState{
		Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP, CanonicalKey: "operators"},
		State: &resourcev1.ResourceDesiredState_LocalGroup{LocalGroup: &resourcev1.LocalGroupDesired{
			Name: "operators", Presence: resourcev1.Presence_PRESENCE_PRESENT,
			Members: &resourcev1.MemberSet{LocalUserNames: []string{"alice"}, Mode: resourcev1.SetMode_SET_MODE_EXACT},
		}},
	})
	group.Ownership.CompleteMembershipDimension = true
	user := dispatchProfileResource(&resourcev1.ResourceDesiredState{
		Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, CanonicalKey: "bob"},
		State: &resourcev1.ResourceDesiredState_LocalUser{LocalUser: &resourcev1.LocalUserDesired{
			Name: "bob", Presence: resourcev1.Presence_PRESENCE_PRESENT,
			SupplementaryGroups: &resourcev1.MemberSet{LocalUserNames: []string{"operators"}, Mode: resourcev1.SetMode_SET_MODE_ADDITIVE},
		}},
	})
	publishDispatchResources(t, f, service, group, user)
	_, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(f.assignmentRequest(nil)))
	dispatchError(t, err, connect.CodeFailedPrecondition, "resource_resolution_conflict")
	assertNoResourceWork(t, f)
	state := complianceState(t, f)
	if state.GetAssignment() != nil || len(state.GetResources()) != 0 || len(state.GetRecentActions()) != 0 {
		t.Fatalf("conflicted assignment retained executable state: %v", state)
	}
	var count int
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM resource_actions WHERE generation_id=$1", f.principal.GenerationID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("cross-kind conflict minted an intent: count=%d err=%v", count, err)
	}
}

func dispatchProfileResource(desired *resourcev1.ResourceDesiredState) *policyv1.ProfileResource {
	return &policyv1.ProfileResource{
		ResourceId: uuid.NewString(), Desired: desired,
		Ownership:    &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN},
		Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 1800, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}},
	}
}

func publishDispatchResources(t *testing.T, f *dispatchFixture, resources ...*policyv1.ProfileResource) {
	t.Helper()
	published, err := f.service.PublishProfileRevision(f.adminCtx, connect.NewRequest(&adminv1.PublishProfileRevisionRequest{
		RequestId: uuid.NewString(), ProfileId: uuid.NewString(), Reason: "exercise heterogeneous resource dispatch",
		Spec: &policyv1.ResourceProfile{Name: "Heterogeneous dispatch", Resources: resources},
	}))
	if err != nil {
		t.Fatal(err)
	}
	f.revision = published.Msg.GetRevision()
}

func assertNoResourceWork(t *testing.T, f *dispatchFixture) {
	t.Helper()
	response, err := f.service.GetServiceWork(f.deviceCtx, connect.NewRequest(&devicev1.GetServiceWorkRequest{SessionEpoch: 1}))
	if err != nil || response.Msg.GetWork() != nil {
		t.Fatalf("unexpected resource work: response=%v err=%v", response, err)
	}
}
