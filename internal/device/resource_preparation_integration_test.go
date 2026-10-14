// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	"lindm/internal/device/dispatch"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// These tests exercise signed dispatch, cancellation and PostgreSQL fences, not
// native package qualification. The fixture explicitly admits its resource row;
// production keeps the independent native qualification gate closed.
func newPreparationDispatchFixture(t *testing.T) (*dispatchFixture, *adminv1.ResourceAssignment) {
	t.Helper()
	f := newDispatchFixtureWithDelegationAge(t, time.Hour, "systemd.service.v1", "package.native.v1")
	item := dispatchProfileResource(&resourcev1.ResourceDesiredState{
		Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: "deb/proof/amd64"},
		State: &resourcev1.ResourceDesiredState_NativePackage{NativePackage: &resourcev1.NativePackageDesired{
			Package:    &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, NativeName: "proof", Architecture: "amd64"},
			Presence:   resourcev1.Presence_PRESENCE_PRESENT,
			Version:    &resourcev1.NativePackageDesired_Exact{Exact: &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Deb{Deb: "1.0"}}},
			Repository: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY, CanonicalKey: "apt/11111111-1111-4111-8111-111111111111"},
			Removal:    resourcev1.PackageRemovalPolicy_PACKAGE_REMOVAL_POLICY_PRESERVE_DATA,
		}},
	})
	publishDispatchResources(t, f, item)
	head := f.assign(t, nil)
	if _, err := f.pool.Exec(t.Context(), "UPDATE resource_assignment_resources SET disposition=1, reason='' WHERE assignment_id=$1", head.GetAssignmentId()); err != nil {
		t.Fatal(err)
	}
	return f, head
}

func preparationResult(t *testing.T, f *dispatchFixture, work *devicev1.ResourceWork, revision uint64, state agentv1.ResourceExecutionState) *devicev1.ReportResourceResultRequest {
	t.Helper()
	intent := f.intent(t, work)
	digest := sha256.Sum256(work.GetIntentEnvelope())
	now := time.Now().UTC().Add(-time.Second)
	status := &agentv1.ResourceExecutionStatus{ActionId: work.GetActionId(), IntentSha256: digest[:], State: state, Failure: agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE, AcceptedAt: timestamppb.New(now)}
	if dispatch.ResourceExecutionTerminal(state) {
		status.CompletedAt = timestamppb.New(now)
		switch state {
		case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED:
			status.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_EXPIRED
		case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED:
			status.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_SUPERSEDED
		default:
			status.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE
		}
		status.PreparationOutcome = &agentv1.ResourcePreparationOutcome{Preparation: proto.CloneOf(intent.GetPreparation()), Failure: status.GetFailure()}
	}
	attestation := &agentv1.ResourceExecutionAttestation{
		DeploymentId: intent.GetDeploymentId(), DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(),
		SessionEpoch: 1, ActionRevision: revision, Nonce: work.GetResultNonce(), IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second)), Status: status,
	}
	return &devicev1.ReportResourceResultRequest{SessionEpoch: 1, ActionId: work.GetActionId(), AttestationEnvelope: f.sign(t, attestation, f.key), CertificatePem: f.certificate}
}

func TestResourcePreparationRetainsLeaseWithoutCompliance(t *testing.T) {
	parallelDeviceIntegration(t)
	f, _ := newPreparationDispatchFixture(t)
	first := f.work(t)
	intent := f.intent(t, first)
	if !proto.Equal(intent.GetPreparation().GetDeadline(), intent.GetExpiresAt()) || intent.GetPreparation().GetMaxCacheBytes() != 512<<20 {
		t.Fatal("staging did not bind its independent signed deadline and byte budget")
	}
	pending := preparationResult(t, f, first, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING)
	history := new(agentv1.ResourceExecutionAttestation)
	if err := f.service.Authority.Verify(t.Context(), pending.GetAttestationEnvelope(), history, 1, f.principal.PublicKey); err != nil {
		t.Fatal(err)
	}
	for cycle := range 3 {
		work := f.work(t)
		if work.GetActionId() != first.GetActionId() || !bytes.Equal(work.GetIntentEnvelope(), first.GetIntentEnvelope()) || len(work.GetStartGrantEnvelope()) != 0 {
			t.Fatal("pending staging replaced the exact intent or minted start authority")
		}
		attestation := proto.CloneOf(history)
		attestation.Nonce = work.GetResultNonce()
		request := proto.CloneOf(pending)
		if cycle != 0 {
			changed := proto.CloneOf(attestation)
			changed.Status.AcceptedAt = timestamppb.New(changed.Status.GetAcceptedAt().AsTime().Add(time.Millisecond))
			request.AttestationEnvelope = f.sign(t, changed, f.key)
			_, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(request))
			dispatchError(t, err, connect.CodeAlreadyExists, "resource_result_conflict")
		}
		request.AttestationEnvelope = f.sign(t, attestation, f.key)
		for range 2 {
			response, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(request))
			if err != nil || response.Msg.GetClosed() {
				t.Fatalf("pending result or exact retry closed its action: %v", err)
			}
		}
		state := complianceState(t, f).GetResources()[0]
		status := state.GetLatestAction().GetStatus()
		if state.GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_IN_PROGRESS || state.GetCompliance() != adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_UNKNOWN || state.GetLastVerifiedAt() != nil || state.GetObservedAt() != nil || status.GetBefore() != nil || status.GetVerification() != nil || status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING || state.GetLatestAction().GetClosedAt() != nil {
			t.Fatalf("pending state invented native proof or completion: %v", state)
		}
	}
}

func TestResourcePreparationResultBindsExactIntentAndLimits(t *testing.T) {
	parallelDeviceIntegration(t)
	f, _ := newPreparationDispatchFixture(t)
	work := f.work(t)
	valid := preparationResult(t, f, work, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED)
	for _, change := range []string{"intent", "limits"} {
		attestation := new(agentv1.ResourceExecutionAttestation)
		if err := f.service.Authority.Verify(t.Context(), valid.GetAttestationEnvelope(), attestation, 1, f.principal.PublicKey); err != nil {
			t.Fatal(err)
		}
		reason := "resource_result_binding_rejected"
		if change == "intent" {
			attestation.Status.IntentSha256[0] ^= 1
			reason = "resource_result_rejected"
		} else {
			attestation.Status.PreparationOutcome.Preparation.MaxCacheBytes--
		}
		request := proto.CloneOf(valid)
		request.AttestationEnvelope = f.sign(t, attestation, f.key)
		_, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(request))
		dispatchError(t, err, connect.CodePermissionDenied, reason)
	}
	if response, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(valid)); err != nil || !response.Msg.GetClosed() {
		t.Fatalf("binding denials consumed exact terminal preparation evidence: %v", err)
	}
	state := complianceState(t, f).GetResources()[0]
	if state.GetCompliance() != adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_ATTENTION || state.GetLastVerifiedAt() != nil {
		t.Fatal("failed staging became native compliance")
	}
}

func TestResourcePreparationRejectsMissingSystemdEvidence(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixture(t)
	f.assign(t, nil)
	work := f.work(t)
	_, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(f.result(t, work, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING, false)))
	dispatchError(t, err, connect.CodePermissionDenied, "resource_result_binding_rejected")
}

func TestResourcePreparationCancellationRetainsFenceUntilTerminal(t *testing.T) {
	parallelDeviceIntegration(t)
	for _, mode := range []string{"expired", "superseded", "cleared", "authority"} {
		t.Run(mode, func(t *testing.T) {
			f, head := newPreparationDispatchFixture(t)
			work := f.work(t)
			actionID := work.GetActionId()
			if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(preparationResult(t, f, work, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING))); err != nil {
				t.Fatal(err)
			}
			reason := "assignment_changed"
			terminal := agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED
			switch mode {
			case "expired":
				reason = "expired_unstarted"
				terminal = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED
				if _, err := f.pool.Exec(t.Context(), "UPDATE resource_actions SET issued_at=clock_timestamp()-interval '11 minutes', expires_at=clock_timestamp()-interval '1 minute' WHERE id=$1", work.GetActionId()); err != nil {
					t.Fatal(err)
				}
			case "authority":
				reason = "authority_changed"
				f.directory.membership(t, false)
				_, err := f.service.AuthorizeResourceStart(f.deviceCtx, connect.NewRequest(&devicev1.AuthorizeResourceStartRequest{SessionEpoch: 1, ActionId: work.GetActionId(), ChallengeProof: f.sign(t, f.challenge(t, work), f.key)}))
				dispatchError(t, err, connect.CodePermissionDenied, reason)
				f.directory.membership(t, true)
			default:
				request := f.assignmentRequest(proto.String(head.GetAssignmentId()))
				if mode == "cleared" {
					request.Target, request.Clear = nil, true
				}
				if _, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(request)); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				work = f.work(t)
				if work.GetActionId() != actionID || !work.GetCancelPreparation() || len(work.GetStartGrantEnvelope()) != 0 {
					t.Fatal("pending owned staging was replaced instead of cancelled")
				}
				var open bool
				if err := f.pool.QueryRow(t.Context(), "SELECT closed_at IS NULL FROM resource_actions WHERE id=$1", work.GetActionId()).Scan(&open); err != nil || !open {
					t.Fatalf("cancellation dropped the one-open-effect fence: %v", err)
				}
			}
			_, err := f.service.AuthorizeResourceStart(f.deviceCtx, connect.NewRequest(&devicev1.AuthorizeResourceStartRequest{SessionEpoch: 1, ActionId: work.GetActionId(), ChallengeProof: f.sign(t, f.challenge(t, work), f.key)}))
			dispatchError(t, err, connect.CodePermissionDenied, reason)
			response, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(preparationResult(t, f, work, 2, terminal)))
			if err != nil || !response.Msg.GetClosed() {
				t.Fatalf("terminal owned cleanup was not accepted: %v", err)
			}
			assertDispatchClosure(t, f, work.GetActionId(), reason)
			for _, recent := range complianceState(t, f).GetRecentActions() {
				if action := recent.GetAction(); action.GetActionId() == work.GetActionId() {
					if action.GetClosedAt() == nil || action.GetStatus().GetState() != terminal || action.GetStatus().GetBefore() != nil || action.GetStatus().GetVerification() != nil || action.GetStatus().GetPreparationOutcome() == nil {
						t.Fatal("cancelled preparation lost visible terminal history or invented native proof")
					}
				}
			}
		})
	}
}

func TestResourcePreparationReadyGrantBindsExactDigest(t *testing.T) {
	parallelDeviceIntegration(t)
	f, _ := newPreparationDispatchFixture(t)
	work := f.work(t)
	if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(preparationResult(t, f, work, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING))); err != nil {
		t.Fatal(err)
	}
	work = f.work(t)
	challenge := f.challenge(t, work)
	digest := sha256.Sum256([]byte("ready exact native transaction"))
	challenge.NativePlanSha256 = digest[:]
	request := &devicev1.AuthorizeResourceStartRequest{SessionEpoch: 1, ActionId: work.GetActionId(), ChallengeProof: f.sign(t, challenge, f.key)}
	response, err := f.service.AuthorizeResourceStart(f.deviceCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	grant := new(agentv1.ResourceExecutionStartGrant)
	public, ok := f.service.Signing.StartKey.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("dispatch fixture requires an Ed25519 start key")
	}
	if err := f.service.Authority.Verify(t.Context(), response.Msg.GetStartGrantEnvelope(), grant, 1, public); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(grant.GetChallenge(), challenge) || grant.GetExpiresAt().AsTime().Sub(grant.GetNotBefore().AsTime()) > 30*time.Second {
		t.Fatal("staging widened or changed exact ready challenge authority")
	}
	replay, err := f.service.AuthorizeResourceStart(f.deviceCtx, connect.NewRequest(request))
	if err != nil || !bytes.Equal(replay.Msg.GetStartGrantEnvelope(), response.Msg.GetStartGrantEnvelope()) {
		t.Fatalf("ready grant did not replay exact signed bytes: %v", err)
	}
	challenge.NativePlanSha256[0] ^= 1
	request.ChallengeProof = f.sign(t, challenge, f.key)
	_, err = f.service.AuthorizeResourceStart(f.deviceCtx, connect.NewRequest(request))
	dispatchError(t, err, connect.CodeAlreadyExists, "resource_start_conflict")
	pending := preparationResult(t, f, f.work(t), 2, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING)
	_, err = f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(pending))
	dispatchError(t, err, connect.CodePermissionDenied, "resource_result_binding_rejected")
}

func TestResourcePreparationNeverPreparedAckIsBoundAndNotProof(t *testing.T) {
	parallelDeviceIntegration(t)
	f, head := newPreparationDispatchFixture(t)
	work := f.work(t)
	digest := sha256.Sum256(work.GetIntentEnvelope())
	request := &devicev1.ReportResourceResultRequest{SessionEpoch: 1, ActionId: work.GetActionId(), NeverPrepared: &devicev1.ResourcePreparationCancellation{IntentSha256: digest[:], ResultNonce: work.GetResultNonce()}}
	_, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(request))
	dispatchError(t, err, connect.CodePermissionDenied, "resource_cancellation_not_requested")
	clear := f.assignmentRequest(proto.String(head.GetAssignmentId()))
	clear.Target, clear.Clear = nil, true
	if _, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(clear)); err != nil {
		t.Fatal(err)
	}
	work = f.work(t)
	if !work.GetCancelPreparation() {
		t.Fatal("never-delivered staging was not fenced for cancellation")
	}
	request.NeverPrepared.ResultNonce = work.GetResultNonce()
	for _, field := range []string{"intent", "nonce"} {
		changed := proto.CloneOf(request)
		if field == "intent" {
			changed.NeverPrepared.IntentSha256[0] ^= 1
		} else {
			changed.NeverPrepared.ResultNonce[0] ^= 1
		}
		_, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(changed))
		dispatchError(t, err, connect.CodePermissionDenied, "resource_cancellation_binding_rejected")
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE resource_actions SET nonce_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", work.GetActionId()); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(request))
	dispatchError(t, err, connect.CodePermissionDenied, "resource_result_nonce_rejected")
	request.NeverPrepared.ResultNonce = f.work(t).GetResultNonce()
	for range 2 {
		response, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(request))
		if err != nil || !response.Msg.GetClosed() {
			t.Fatalf("never-prepared acknowledgment or exact retry: %v", err)
		}
	}
	// The cancelled action is closed. Clearing a natively qualified kind may
	// request a separate signed release, never a replay of the cancelled work.
	response, err := f.service.GetResourceWork(f.deviceCtx, connect.NewRequest(&devicev1.GetResourceWorkRequest{SessionEpoch: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if next := response.Msg.GetWork(); next != nil && (next.GetActionId() == work.GetActionId() || f.intent(t, next).GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE) {
		t.Fatal("never-prepared acknowledgment did not close the cancelled action")
	}
	var action *adminv1.ResourceActionSummary
	for _, recent := range complianceState(t, f).GetRecentActions() {
		if recent.GetAction().GetActionId() == work.GetActionId() {
			action = recent.GetAction()
		}
	}
	if action.GetActionId() != work.GetActionId() || action.GetClosedAt() == nil || action.GetClosedReason() != "assignment_changed_never_prepared" || action.GetStatus() != nil || action.GetAttestedAt() != nil || action.GetActionRevision() != 0 {
		t.Fatal("cancellation acknowledgment fabricated signed native history")
	}
}

func TestResourcePreparationNeverPreparedCannotReplaceProtectedHistory(t *testing.T) {
	parallelDeviceIntegration(t)
	for _, granted := range []bool{false, true} {
		name := "preparing"
		if granted {
			name = "granted"
		}
		t.Run(name, func(t *testing.T) {
			f, head := newPreparationDispatchFixture(t)
			work := f.work(t)
			if granted {
				f.start(t, work)
			} else if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(preparationResult(t, f, work, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING))); err != nil {
				t.Fatal(err)
			}
			clear := f.assignmentRequest(proto.String(head.GetAssignmentId()))
			clear.Target, clear.Clear = nil, true
			if _, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(clear)); err != nil {
				t.Fatal(err)
			}
			work = f.work(t)
			digest := sha256.Sum256(work.GetIntentEnvelope())
			_, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(&devicev1.ReportResourceResultRequest{SessionEpoch: 1, ActionId: work.GetActionId(), NeverPrepared: &devicev1.ResourcePreparationCancellation{IntentSha256: digest[:], ResultNonce: work.GetResultNonce()}}))
			reason := "resource_cancellation_not_requested"
			if granted {
				reason = "resource_cancellation_binding_rejected"
			}
			dispatchError(t, err, connect.CodePermissionDenied, reason)
		})
	}
}
