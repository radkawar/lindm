//go:build integration

package device

import (
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
)

func TestServiceComplianceRechecksFreshnessAndDependencies(t *testing.T) {
	f := newDispatchFixture(t)
	request := f.assignmentRequest(nil)
	request.ReconcileIntervalSeconds = proto.Uint32(300)
	assigned, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if assigned.Msg.GetAssignment().GetReconcileIntervalSeconds() != 300 {
		t.Fatal("assignment lost its requested interval")
	}
	state := complianceState(t, f)
	if state.GetResources()[0].GetCompliance() != adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_UNKNOWN {
		t.Fatal("unobserved resource reported compliant")
	}
	var last *devicev1.ReportResourceResultRequest
	for range 2 {
		work := f.work(t)
		last = f.result(t, work, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, false)
		if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(last)); err != nil {
			t.Fatal(err)
		}
	}
	if f.work(t) != nil {
		t.Fatal("fresh compliance scheduled an immediate check")
	}
	state = complianceState(t, f)
	for _, resource := range state.GetResources() {
		if resource.GetCompliance() != adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_COMPLIANT || resource.GetLastVerifiedAt() == nil || resource.GetObservedAt() == nil || !resource.GetLastVerifiedAt().AsTime().After(resource.GetObservedAt().AsTime()) {
			t.Fatalf("missing distinct server/native verification: %v", resource)
		}
	}
	ageCompliance(t, f, 11*time.Minute)
	// A retry acknowledges retained evidence; it cannot turn old evidence fresh.
	if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(last)); err != nil {
		t.Fatal(err)
	}
	for _, resource := range complianceState(t, f).GetResources() {
		if resource.GetCompliance() != adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_STALE {
			t.Fatal("offline evidence or exact replay reported fresh")
		}
	}
	work := f.work(t)
	intent := f.intent(t, work)
	if intent.GetDesired().GetRef().GetCanonicalKey() != "zzz-first.service" || intent.GetResourceSequence() != 2 || len(work.GetStartGrantEnvelope()) != 0 {
		t.Fatal("recheck lost dependency order, fresh sequence or read-only preparation")
	}
	if f.work(t).GetActionId() != work.GetActionId() {
		t.Fatal("periodic check minted concurrent work")
	}
	// GetResourceWork rotates the nonce; use the currently issued one.
	work = f.work(t)
	if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(f.result(t, work, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, false))); err != nil {
		t.Fatal(err)
	}
	dependent := f.work(t)
	if f.intent(t, dependent).GetDesired().GetRef().GetCanonicalKey() != "aaa-dependent.service" {
		t.Fatal("reverified dependency did not release due dependent")
	}
	f.start(t, dependent)
	if complianceState(t, f).GetResources()[1].GetCompliance() != adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_ATTENTION {
		t.Fatal("known drift remained compliant during remediation")
	}
	if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(f.result(t, dependent, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, true))); err != nil {
		t.Fatal(err)
	}
	if complianceState(t, f).GetResources()[1].GetCompliance() != adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_DRIFT_REMEDIATED {
		t.Fatal("successful granted recheck did not expose remediation")
	}
}

func TestServiceComplianceRecheckAuthorizationFence(t *testing.T) {
	f := newDispatchFixture(t)
	f.assign(t, nil)
	for range 2 {
		work := f.work(t)
		if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(f.result(t, work, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, false))); err != nil {
			t.Fatal(err)
		}
	}
	ageCompliance(t, f, 16*time.Minute)
	work := f.work(t)
	f.directory.membership(t, false)
	_, err := f.service.AuthorizeResourceStart(f.deviceCtx, connect.NewRequest(&devicev1.AuthorizeResourceStartRequest{SessionEpoch: 1, ActionId: work.GetActionId(), ChallengeProof: f.sign(t, f.challenge(t, work), f.key)}))
	dispatchError(t, err, connect.CodePermissionDenied, "authority_changed")
	assertDispatchClosure(t, f, work.GetActionId(), "authority_changed")
	if f.work(t) != nil {
		t.Fatal("revoked actor minted another periodic action")
	}
	if complianceState(t, f).GetResources()[0].GetCompliance() != adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_ATTENTION {
		t.Fatal("blocked remediation was reported compliant")
	}
}

func TestServiceComplianceReadOnlyHistoryBound(t *testing.T) {
	f := newDispatchFixture(t)
	f.assign(t, nil)
	// Retain a genuine granted success and a non-success without a grant.
	granted := f.work(t)
	f.start(t, granted)
	if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(f.result(t, granted, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, true))); err != nil {
		t.Fatal(err)
	}
	expired := f.work(t)
	if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(f.result(t, expired, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED, false))); err != nil {
		t.Fatal(err)
	}
	var firstReadOnly string
	for i := range 259 {
		ageCompliance(t, f, 16*time.Minute)
		work := f.work(t)
		if i == 0 {
			firstReadOnly = work.GetActionId()
		}
		if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(f.result(t, work, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, false))); err != nil {
			t.Fatal(err)
		}
	}
	var count, protected int
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FILTER (WHERE read_only_success), count(*) FILTER (WHERE NOT read_only_success) FROM resource_actions WHERE generation_id=$1", f.principal.GenerationID).Scan(&count, &protected); err != nil || count != 256 || protected != 2 {
		t.Fatalf("history bound: read-only=%d protected=%d err=%v", count, protected, err)
	}
	capacity, err := devicedb.New(f.pool).ServiceDispatchCapacity(t.Context(), f.principal.GenerationID)
	if err != nil || capacity.Actions != 2 {
		t.Fatalf("periodic read-only successes consumed protected action capacity: %v %v", capacity, err)
	}
	var exists bool
	if err := f.pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM resource_actions WHERE id=$1)", firstReadOnly).Scan(&exists); err != nil || exists {
		t.Fatalf("old read-only history retained: exists=%v err=%v", exists, err)
	}
	assertDispatchClosure(t, f, granted.GetActionId(), "result")
	assertDispatchClosure(t, f, expired.GetActionId(), "result")
	ageCompliance(t, f, 16*time.Minute)
	work := f.work(t)
	if f.intent(t, work).GetResourceSequence() <= 259 {
		t.Fatal("pruning reset monotonic sequence")
	}
}

func TestServiceComplianceIntervalValidation(t *testing.T) {
	f := newDispatchFixture(t)
	for _, seconds := range []uint32{0, 299, 86401} {
		request := f.assignmentRequest(nil)
		request.ReconcileIntervalSeconds = &seconds
		_, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(request))
		dispatchError(t, err, connect.CodeInvalidArgument, "invalid_service_assignment")
	}
	if f.assign(t, nil).GetReconcileIntervalSeconds() != 900 {
		t.Fatal("missing interval did not receive default")
	}
}

func complianceState(t *testing.T, f *dispatchFixture) *adminv1.GetDeviceResourceStateResponse {
	t.Helper()
	state, err := f.service.GetDeviceResourceState(f.adminCtx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: f.principal.DeviceID.String()}))
	if err != nil {
		t.Fatal(err)
	}
	return state.Msg
}

func ageCompliance(t *testing.T, f *dispatchFixture, age time.Duration) {
	t.Helper()
	if _, err := f.pool.Exec(t.Context(), "UPDATE resource_assignment_resources SET last_verified_at=clock_timestamp()-($1::bigint * interval '1 second') WHERE last_verified_at IS NOT NULL", int64(age/time.Second)); err != nil {
		t.Fatal(err)
	}
}
