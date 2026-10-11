//go:build integration

package device

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

func TestServiceFreshDelegationIntentWindow(t *testing.T) {
	f := newDispatchFixtureWithDelegationAge(t, time.Second)
	f.assign(t, nil)
	intent := f.intent(t, f.work(t))
	if !intent.GetNotBefore().AsTime().Equal(f.delegation.GetNotBefore().AsTime()) {
		t.Fatal("fresh delegation did not bound intent not-before")
	}
	if !intent.GetExpiresAt().AsTime().Equal(intent.GetNotBefore().AsTime().Add(12 * time.Minute)) {
		t.Fatal("fresh delegation changed the bounded intent lifetime")
	}
	if !intent.GetExpiresAt().AsTime().After(time.Now()) || intent.GetExpiresAt().AsTime().After(f.delegation.GetExpiresAt().AsTime()) {
		t.Fatal("minted unusable or out-of-delegation execution window")
	}
}

func TestServiceAssignmentCASAndLeaseReplay(t *testing.T) {
	f := newDispatchFixture(t)
	request := f.assignmentRequest(nil)
	first, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(request))
	if err != nil || !proto.Equal(first.Msg, replay.Msg) {
		t.Fatalf("exact assignment retry: %v", err)
	}
	changed := proto.CloneOf(request)
	changed.Reason = "different request content"
	_, err = f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(changed))
	dispatchError(t, err, connect.CodeAlreadyExists, "idempotency_conflict")
	_, err = f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(f.assignmentRequest(nil)))
	dispatchError(t, err, connect.CodeAborted, "resource_assignment_conflict")
	unknown := f.assignmentRequest(nil)
	unknown.DeviceId = uuid.NewString()
	_, err = f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(unknown))
	dispatchError(t, err, connect.CodeNotFound, "not_found")
	work := f.work(t)
	intent := f.intent(t, work)
	if intent.GetDesired().GetRef().GetCanonicalKey() != "zzz-first.service" || intent.GetResourceSequence() != 1 {
		t.Fatalf("dependency order/initial sequence: %v", intent)
	}
	ownership := intent.GetOwnership()
	if intent.GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE || ownership.GetAssignmentId() != first.Msg.GetAssignment().GetAssignmentId() || len(ownership.GetSources()) != 1 {
		t.Fatal("intent lost exact operation, assignment or ownership source")
	}
	source := ownership.GetSources()[0]
	if source.GetProfileId() != first.Msg.GetAssignment().GetProfileId() || source.GetProfileRevision() != first.Msg.GetAssignment().GetRevisionId() || source.GetResourceId() != ownership.GetResourceId() || ownership.GetPolicy().GetRelease() != resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN {
		t.Fatal("intent ownership differs from assigned immutable profile resource")
	}
	replayWork := f.work(t)
	if replayWork.GetActionId() != work.GetActionId() || !bytes.Equal(replayWork.GetIntentEnvelope(), work.GetIntentEnvelope()) || bytes.Equal(replayWork.GetResultNonce(), work.GetResultNonce()) {
		t.Fatal("replay did not retain exact intent and rotate nonce")
	}
	var count int
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM resource_actions WHERE device_id=$1", f.principal.DeviceID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("minted more than once: %d %v", count, err)
	}
	oldHead := first.Msg.GetAssignment().GetAssignmentId()
	second := f.assign(t, &oldHead)
	next := f.work(t)
	nextIntent := f.intent(t, next)
	if next.GetActionId() == work.GetActionId() || nextIntent.GetResourceSequence() <= intent.GetResourceSequence() {
		t.Fatal("assignment replacement reused action/sequence")
	}
	assertDispatchClosure(t, f, work.GetActionId(), "assignment_changed")
	state, err := f.service.GetDeviceResourceState(f.adminCtx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: f.principal.DeviceID.String()}))
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Msg.GetRecentActions()) != 2 || state.Msg.GetRecentActions()[0].GetAction().GetActionId() != next.GetActionId() || state.Msg.GetRecentActions()[1].GetAction().GetClosedReason() != "assignment_changed" || state.Msg.GetRecentActions()[1].GetAssignmentId() != oldHead {
		t.Fatal("recent action history lost prior-head closure")
	}
	historical, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(request))
	if err != nil || !proto.Equal(historical.Msg, first.Msg) {
		t.Fatalf("historical receipt changed after reassignment: %v", err)
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE resource_actions SET issued_at=clock_timestamp()-interval '11 minutes', expires_at=clock_timestamp()-interval '1 minute' WHERE id=$1", next.GetActionId()); err != nil {
		t.Fatal(err)
	}
	expiredReplacement := f.work(t)
	if f.intent(t, expiredReplacement).GetResourceSequence() <= nextIntent.GetResourceSequence() {
		t.Fatal("expired lease reused sequence")
	}
	assertDispatchClosure(t, f, next.GetActionId(), "expired_unstarted")
	head := second.GetAssignmentId()
	clearRequest := &adminv1.SetResourceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: f.principal.DeviceID.String(), ExpectedAssignmentId: &head, Clear: true, Reason: "stop management without restoring native state"}
	cleared, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(clearRequest))
	if err != nil {
		t.Fatal(err)
	}
	for range len(f.revision.GetSpec().GetResources()) {
		release := f.work(t)
		if f.intent(t, release).GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
			t.Fatal("clear did not issue exact release work")
		}
		if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(resourceRefusalResult(t, f, release))); err != nil {
			t.Fatal(err)
		}
	}
	assertNoResourceWork(t, f)
	saved := f.service.signing
	f.service.signing = nil
	clearedID := cleared.Msg.GetAssignment().GetAssignmentId()
	f.assign(t, &clearedID)
	_, err = f.service.GetResourceWork(f.deviceCtx, connect.NewRequest(&devicev1.GetResourceWorkRequest{SessionEpoch: 1}))
	dispatchError(t, err, connect.CodeFailedPrecondition, "execution_signing_unconfigured")
	f.service.signing = saved
	if f.work(t) == nil {
		t.Fatal("configured signer did not resume pending assignment")
	}
}

func TestServiceStartResultNonceAndDependencyGates(t *testing.T) {
	f := newDispatchFixture(t)
	head := f.assign(t, nil)
	work := f.work(t)
	challenge := f.challenge(t, work)
	challenge.IntentSha256 = make([]byte, sha256.Size)
	_, err := f.service.AuthorizeResourceStart(f.deviceCtx, connect.NewRequest(&devicev1.AuthorizeResourceStartRequest{SessionEpoch: 1, ActionId: work.GetActionId(), ChallengeProof: f.sign(t, challenge, f.key)}))
	dispatchError(t, err, connect.CodePermissionDenied, "resource_challenge_binding_rejected")
	for _, change := range []func(*agentv1.ResourceExecutionChallenge){
		func(c *agentv1.ResourceExecutionChallenge) { c.Ref.CanonicalKey = "different.service" },
		func(c *agentv1.ResourceExecutionChallenge) {
			c.Operation = resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE
		},
	} {
		mismatch := f.challenge(t, work)
		change(mismatch)
		_, err := f.service.AuthorizeResourceStart(f.deviceCtx, connect.NewRequest(&devicev1.AuthorizeResourceStartRequest{SessionEpoch: 1, ActionId: work.GetActionId(), ChallengeProof: f.sign(t, mismatch, f.key)}))
		dispatchError(t, err, connect.CodePermissionDenied, "resource_challenge_binding_rejected")
	}
	startRequest, grant := f.start(t, work)
	replay, err := f.service.AuthorizeResourceStart(f.deviceCtx, connect.NewRequest(startRequest))
	if err != nil || !bytes.Equal(replay.Msg.GetStartGrantEnvelope(), grant) {
		t.Fatalf("exact start retry: %v", err)
	}
	other := f.challenge(t, work)
	_, err = f.service.AuthorizeResourceStart(f.deviceCtx, connect.NewRequest(&devicev1.AuthorizeResourceStartRequest{SessionEpoch: 1, ActionId: work.GetActionId(), ChallengeProof: f.sign(t, other, f.key)}))
	dispatchError(t, err, connect.CodeAlreadyExists, "resource_start_conflict")
	running := f.result(t, work, 2, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING, true)
	admitted, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(running))
	if err != nil || admitted.Msg.GetClosed() {
		t.Fatalf("nonterminal report closed action: %v", err)
	}
	again, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(running))
	if err != nil || again.Msg.GetClosed() {
		t.Fatalf("exact consumed-nonce retry: %v", err)
	}
	consumed := f.result(t, work, 3, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING, true)
	_, err = f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(consumed))
	dispatchError(t, err, connect.CodePermissionDenied, "resource_result_nonce_rejected")
	state, err := f.service.GetDeviceResourceState(f.adminCtx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: f.principal.DeviceID.String()}))
	if err != nil {
		t.Fatal(err)
	}
	if state.Msg.GetResources()[0].GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_IN_PROGRESS || state.Msg.GetResources()[1].GetReason() != "dependency_pending" {
		t.Fatal("running history or dependency disposition is wrong")
	}
	work = f.work(t)
	if !bytes.Equal(work.GetStartGrantEnvelope(), grant) {
		t.Fatal("poll lost exact start grant")
	}
	for _, revision := range []uint64{1, 2} {
		stale := f.result(t, work, revision, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING, true)
		_, err = f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(stale))
		dispatchError(t, err, connect.CodeAlreadyExists, "resource_result_conflict")
	}
	success := f.result(t, work, 3, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, true)
	admitted, err = f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(success))
	if err != nil || !admitted.Msg.GetClosed() {
		t.Fatalf("terminal report not closed: %v", err)
	}
	dependent := f.work(t)
	if f.intent(t, dependent).GetDesired().GetRef().GetCanonicalKey() != "aaa-dependent.service" {
		t.Fatal("verified dependency success did not release dependent")
	}
	f.start(t, dependent)
	// A changed head and expired signed lease cannot replace a granted action.
	old := head.GetAssignmentId()
	replacement := f.assign(t, &old)
	if _, err := f.pool.Exec(t.Context(), "UPDATE resource_actions SET issued_at=clock_timestamp()-interval '11 minutes', expires_at=clock_timestamp()-interval '1 minute' WHERE id=$1", dependent.GetActionId()); err != nil {
		t.Fatal(err)
	}
	held := f.work(t)
	if held.GetActionId() != dependent.GetActionId() || len(held.GetStartGrantEnvelope()) == 0 {
		t.Fatal("granted action was replaced before terminal evidence")
	}
	terminal := f.result(t, held, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED, true)
	if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(terminal)); err != nil {
		t.Fatal(err)
	}
	fresh := f.work(t)
	if f.intent(t, fresh).GetDesiredRevision() != replacement.GetAssignmentId() {
		t.Fatal("new head did not run after prior granted action terminated")
	}
}

func TestServiceAssignmentActorAuthorityChanges(t *testing.T) {
	f := newDispatchFixture(t)
	head := f.assign(t, nil)
	f.directory.membership(t, false)
	if f.work(t) != nil {
		t.Fatal("revoked assigning actor minted work")
	}
	state, err := f.service.GetDeviceResourceState(f.adminCtx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: f.principal.DeviceID.String()}))
	if err != nil {
		t.Fatal(err)
	}
	if state.Msg.GetResources()[0].GetReason() != "assignment_authority_changed" {
		t.Fatal("denied assignment head was not blocked")
	}
	f.directory.membership(t, true)
	old := head.GetAssignmentId()
	head = f.assign(t, &old)
	// Removing then restoring the role changes its version even when the next
	// fetch observes the original role. Reauthorization never revives that head.
	f.directory.membership(t, false)
	if _, err := f.service.identity.AuthorizeFresh(t.Context(), f.actor.ID, identity.PermissionAssignResources); err == nil {
		t.Fatal("removed membership still authorized")
	}
	f.directory.membership(t, true)
	if f.work(t) != nil {
		t.Fatal("changed authorization version revived desired head")
	}
	old = head.GetAssignmentId()
	f.assign(t, &old)
	work := f.work(t)
	f.directory.membership(t, false)
	request := &devicev1.AuthorizeResourceStartRequest{SessionEpoch: 1, ActionId: work.GetActionId(), ChallengeProof: f.sign(t, f.challenge(t, work), f.key)}
	_, err = f.service.AuthorizeResourceStart(f.deviceCtx, connect.NewRequest(request))
	dispatchError(t, err, connect.CodePermissionDenied, "authority_changed")
	assertDispatchClosure(t, f, work.GetActionId(), "authority_changed")
}

func TestServiceResultRegisteredCertificateAndNoEffect(t *testing.T) {
	f := newDispatchFixture(t)
	f.assign(t, nil)
	work := f.work(t)
	unknownKey := ed25519Key(t)
	unknown, err := issueCertificate(f.service.ca, f.service.caKey, unknownKey.Public(), f.service.deploymentID, f.principal.DeviceID, f.principal.GenerationID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	request := f.result(t, work, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED, false)
	message := new(agentv1.ResourceExecutionAttestation)
	if err := f.service.authority.Verify(t.Context(), request.GetAttestationEnvelope(), message, 1, f.principal.PublicKey); err != nil {
		t.Fatal(err)
	}
	request.CertificatePem = unknown.PEM
	request.AttestationEnvelope = f.sign(t, message, unknownKey)
	_, err = f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(request))
	dispatchError(t, err, connect.CodePermissionDenied, "certificate_rejected")
	// Renew transport identity, then explicitly revoke the old overlapping signer.
	newKey := ed25519Key(t)
	renewed, err := f.service.RenewIdentity(f.deviceCtx, connect.NewRequest(signedRenewalRequest(t, f.service, f.principal, f.key, 1, mustCSR(t, newKey, &x509.CertificateRequest{}))))
	if err != nil {
		t.Fatal(err)
	}
	newPrincipal, err := f.service.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, renewed.Msg.GetCertificatePem()))
	if err != nil {
		t.Fatal(err)
	}
	f.deviceCtx = withDevicePrincipal(t.Context(), newPrincipal)
	request = f.result(t, work, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED, false)
	// An overlapping registered certificate is accepted, not just the TLS key.
	if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	replacement := f.work(t)
	if replacement.GetActionId() == work.GetActionId() || f.intent(t, replacement).GetResourceSequence() <= f.intent(t, work).GetResourceSequence() {
		t.Fatal("no-effect terminal result did not requeue with higher sequence")
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE device_certificates SET status='revoked', revoked_at=clock_timestamp(), revoke_reason='test signer revocation', overlap_until=NULL WHERE id=$1", f.principal.CertificateID); err != nil {
		t.Fatal(err)
	}
	request = f.result(t, replacement, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED, false)
	_, err = f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(request))
	dispatchError(t, err, connect.CodePermissionDenied, "certificate_rejected")
	f.key, f.certificate, f.principal = newKey, renewed.Msg.GetCertificatePem(), newPrincipal
	request = f.result(t, replacement, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED, true)
	if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	if f.work(t) != nil {
		t.Fatal("failed resource automatically retried or released dependent")
	}
	state, err := f.service.GetDeviceResourceState(f.adminCtx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: f.principal.DeviceID.String()}))
	if err != nil {
		t.Fatal(err)
	}
	if state.Msg.GetResources()[0].GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_ATTENTION || state.Msg.GetResources()[1].GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_BLOCKED {
		t.Fatal("failure did not retain attention and dependency block")
	}
}

func dispatchError(t *testing.T, err error, code connect.Code, reason string) {
	t.Helper()
	if connect.CodeOf(err) != code {
		t.Fatalf("got %v want %v (%s)", err, code, reason)
	}
	rpc, ok := err.(*connect.Error)
	if !ok || rpcreason.Get(rpc) != reason {
		t.Fatalf("got %v want reason %s", err, reason)
	}
}
func assertDispatchClosure(t *testing.T, f *dispatchFixture, id, expected string) {
	t.Helper()
	var reason string
	if err := f.pool.QueryRow(t.Context(), "SELECT closed_reason FROM resource_actions WHERE id=$1", id).Scan(&reason); err != nil || reason != expected {
		t.Fatalf("closure=%s want=%s err=%v", reason, expected, err)
	}
}

func TestResourceResultBindsExactDesiredEvidence(t *testing.T) {
	f := newDispatchFixture(t)
	f.assign(t, nil)
	work := f.work(t)
	valid := f.result(t, work, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, false)
	for _, change := range []func(*agentv1.ResourceExecutionStatus){
		func(status *agentv1.ResourceExecutionStatus) {
			status.Before.Ref.CanonicalKey = "different.service"
			status.Before.GetSystemdService().Unit = "different.service"
		},
		func(status *agentv1.ResourceExecutionStatus) {
			status.Verification.DesiredSha256[0] ^= 1
		},
	} {
		attestation := new(agentv1.ResourceExecutionAttestation)
		if err := f.service.authority.Verify(t.Context(), valid.GetAttestationEnvelope(), attestation, 1, f.principal.PublicKey); err != nil {
			t.Fatal(err)
		}
		change(attestation.Status)
		request := proto.CloneOf(valid)
		request.AttestationEnvelope = f.sign(t, attestation, f.key)
		_, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(request))
		dispatchError(t, err, connect.CodePermissionDenied, "resource_result_binding_rejected")
	}
	if response, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(valid)); err != nil || !response.Msg.GetClosed() {
		t.Fatalf("binding denials consumed valid result authority: %v", err)
	}
}
