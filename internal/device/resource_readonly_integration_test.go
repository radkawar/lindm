//go:build integration

package device

import (
	"crypto/sha256"
	"testing"
	"time"

	"lindm/internal/device/dispatch"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/resource"
	"lindm/internal/targeting/targetingdb"
)

// This admits only a protocol fixture, not the production native qualification
// gate. Evidence is device-signed fixture data, not a real encryption observation.
func newReadOnlyDispatchFixture(t *testing.T, release bool) (*dispatchFixture, *devicev1.ResourceWork) {
	t.Helper()
	f := newDispatchFixtureWithDelegationAge(t, time.Hour, "systemd.service.v1", "encryption.compliance.v1")
	publishDispatchResources(t, f, dispatchProfileResource(&resourcev1.ResourceDesiredState{
		Ref:   &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_ENCRYPTION_COMPLIANCE, CanonicalKey: "system/root"},
		State: &resourcev1.ResourceDesiredState_EncryptionCompliance{EncryptionCompliance: &resourcev1.EncryptionComplianceDesired{RequireLuksRoot: true}},
	}))
	head := f.assign(t, nil)
	if _, err := f.pool.Exec(t.Context(), "UPDATE resource_assignment_resources SET disposition=1, reason='' WHERE assignment_id=$1", head.GetAssignmentId()); err != nil {
		t.Fatal(err)
	}
	work := f.work(t)
	if release {
		// Obtain the real removal/head/release association, then admit only the
		// release protocol fixture across the still-closed qualification gate.
		intent := f.intent(t, work)
		if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(readOnlyResult(t, f, work, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED))); err != nil {
			t.Fatal(err)
		}
		clear := f.assignmentRequest(proto.String(head.GetAssignmentId()))
		clear.Target, clear.Clear = nil, true
		cleared, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(clear))
		if err != nil {
			t.Fatal(err)
		}
		q := devicedb.New(f.pool)
		resourceID := uuid.MustParse(intent.GetOwnership().GetResourceId())
		var releaseID uuid.UUID
		if err := f.pool.QueryRow(t.Context(), "SELECT id FROM resource_releases WHERE source_assignment_id=$1 AND resource_id=$2 AND superseding_assignment_id=$3", head.GetAssignmentId(), resourceID, cleared.Msg.GetAssignment().GetAssignmentId()).Scan(&releaseID); err != nil {
			t.Fatal(err)
		}
		sequence, err := q.NextResourceSequence(t.Context(), devicedb.NextResourceSequenceParams{GenerationID: f.principal.GenerationID, ResourceKind: int16(intent.GetDesired().GetRef().GetKind()), CanonicalKey: intent.GetDesired().GetRef().GetCanonicalKey()})
		if err != nil {
			t.Fatal(err)
		}
		actionID := uuid.New()
		intent.ActionId, intent.ResourceSequence = actionID.String(), uint64(sequence)
		intent.Operation = resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE
		intent.DesiredRevision = cleared.Msg.GetAssignment().GetAssignmentId()
		intent.Ownership.AssignmentId = intent.GetDesiredRevision()
		envelope := f.sign(t, intent, f.service.Signing.PlanKey)
		document, err := proto.Marshal(intent)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		if err := q.InsertResourceAction(t.Context(), devicedb.InsertResourceActionParams{ID: actionID, DeviceID: f.principal.DeviceID, GenerationID: f.principal.GenerationID, AssignmentID: uuid.MustParse(head.GetAssignmentId()), ResourceID: resourceID, ResourceSequence: sequence, IntentEnvelope: envelope, IntentDocument: document, IssuedAt: core.Timestamptz(now), ExpiresAt: core.Timestamptz(intent.GetExpiresAt().AsTime())}); err != nil {
			t.Fatal(err)
		}
		if err := q.BindResourceReleaseAction(t.Context(), devicedb.BindResourceReleaseActionParams{ID: actionID, ReleaseID: &releaseID}); err != nil {
			t.Fatal(err)
		}
		action, err := q.GetResourceAction(t.Context(), actionID)
		if err != nil {
			t.Fatal(err)
		}
		work, err = dispatch.IssueResourceNonce(t.Context(), q, action, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	return f, work
}

func readOnlyResult(t *testing.T, f *dispatchFixture, work *devicev1.ResourceWork, disposition resourcev1.VerificationDisposition) *devicev1.ReportResourceResultRequest {
	t.Helper()
	intent := f.intent(t, work)
	desiredDigest, err := resource.DesiredDigest(intent.GetDesired())
	if err != nil {
		t.Fatal(err)
	}
	intentDigest := sha256.Sum256(work.GetIntentEnvelope())
	planDigest := sha256.Sum256([]byte("device-signed readonly native plan fixture"))
	now := time.Now().UTC().Add(-time.Second)
	stamp := timestamppb.New(now)
	observation := &resourcev1.ResourceObservation{
		Ref: proto.CloneOf(intent.GetDesired().GetRef()),
		Metadata: &resourcev1.ObservationMetadata{
			BootId: uuid.NewString(), ExecutorIncarnation: uuid.NewString(), ObservedAt: stamp,
			Backend:        &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_LUKS_COMPLIANCE, NativeVersion: "2", ProviderVersion: "fixture", Product: &resourcev1.PlatformProduct{OsId: "ubuntu", Product: "readonly dispatch fixture", Version: "24.04", Architecture: "amd64"}},
			NativeRevision: planDigest[:], ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK,
		},
		Observed: &resourcev1.ResourceObservation_EncryptionCompliance{EncryptionCompliance: &resourcev1.EncryptionComplianceObservation{LuksRoot: proto.Bool(false), EvidenceSha256: planDigest[:]}},
	}
	checks := &resourcev1.EncryptionComplianceChecks{EscrowRequirementMet: true, TpmRequirementMet: true, EvidenceComplete: true}
	state := agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED
	failure := agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_POSTCONDITION
	switch disposition {
	case resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_UNKNOWN:
		observation.Metadata.ObservationStatus = resourcev1.ObservationStatus_OBSERVATION_STATUS_UNAVAILABLE
		observation.GetEncryptionCompliance().LuksRoot = nil
		checks.EvidenceComplete = false
	case resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED:
		observation.GetEncryptionCompliance().LuksRoot = proto.Bool(true)
		observation.GetEncryptionCompliance().RootLuksUuid = proto.String(uuid.NewString())
		observation.GetEncryptionCompliance().RootIdentityBasis = resourcev1.RootStorageIdentityBasis_ROOT_STORAGE_IDENTITY_BASIS_WWN_SERIAL
		observation.GetEncryptionCompliance().RootWwn = "fixture-root-wwn"
		observation.GetEncryptionCompliance().RootSerial = "fixture-root-serial"
		observation.GetEncryptionCompliance().RootSizeBytes = 1024 * 1024 * 1024
		checks.LuksRootRequirementMet, checks.Converged = true, true
		state, failure = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE
	case resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE:
		state, failure = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE
	}
	status := &agentv1.ResourceExecutionStatus{
		ActionId: work.GetActionId(), IntentSha256: intentDigest[:], State: state, Failure: failure, AcceptedAt: stamp, CompletedAt: stamp, Before: observation, ReadOnly: true,
		Verification: &resourcev1.ResourceVerification{Ref: proto.CloneOf(observation.GetRef()), DesiredSha256: desiredDigest[:], PlanSha256: planDigest[:], After: proto.CloneOf(observation), Disposition: disposition, Checks: &resourcev1.ResourceVerification_EncryptionCompliance{EncryptionCompliance: checks}},
	}
	attestation := &agentv1.ResourceExecutionAttestation{DeploymentId: intent.GetDeploymentId(), DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), SessionEpoch: 1, ActionRevision: 1, Nonce: work.GetResultNonce(), IssuedAt: stamp, ExpiresAt: timestamppb.New(now.Add(30 * time.Second)), Status: status}
	return &devicev1.ReportResourceResultRequest{SessionEpoch: 1, ActionId: work.GetActionId(), AttestationEnvelope: f.sign(t, attestation, f.key), CertificatePem: f.certificate}
}

func TestResourceReadOnlyNativeFindingsPersistWithoutStartAuthority(t *testing.T) {
	for _, disposition := range []resourcev1.VerificationDisposition{
		resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED,
		resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_UNKNOWN,
	} {
		t.Run(disposition.String(), func(t *testing.T) {
			f, work := newReadOnlyDispatchFixture(t, false)
			_, err := f.service.AuthorizeResourceStart(f.deviceCtx, connect.NewRequest(&devicev1.AuthorizeResourceStartRequest{SessionEpoch: 1, ActionId: work.GetActionId(), ChallengeProof: f.sign(t, f.challenge(t, work), f.key)}))
			dispatchError(t, err, connect.CodeFailedPrecondition, "resource_read_only")
			request := readOnlyResult(t, f, work, disposition)
			for range 2 {
				response, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(request))
				if err != nil || !response.Msg.GetClosed() {
					t.Fatalf("read-only native finding was discarded or left open: %v", err)
				}
			}
			state := complianceState(t, f).GetResources()[0]
			status := state.GetLatestAction().GetStatus()
			reason := "verification_drifted"
			if disposition == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_UNKNOWN {
				reason = "verification_unknown"
			}
			if status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED || status.GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_POSTCONDITION || !status.GetReadOnly() || status.GetVerification().GetDisposition() != disposition || status.GetBefore() == nil || status.GetStartedAt() != nil || state.GetLatestAction().GetStartAuthorizedAt() != nil || state.GetCompliance() != adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_ATTENTION || state.GetReason() != reason || state.GetLastVerifiedAt() != nil {
				t.Fatalf("read-only finding lost evidence or fabricated effect/compliance: %v", state)
			}
			assertNoResourceWork(t, f)
		})
	}
}

func TestResourceReadOnlyReleaseDoesNotContributeCompliance(t *testing.T) {
	f, work := newReadOnlyDispatchFixture(t, true)
	action, err := devicedb.New(f.pool).GetResourceAction(t.Context(), uuid.MustParse(work.GetActionId()))
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	if _, err := f.pool.Exec(t.Context(), "UPDATE resource_assignment_resources SET last_verified_at=$2, observed_at=$2 WHERE assignment_id=$1", action.AssignmentID, old); err != nil {
		t.Fatal(err)
	}
	request := readOnlyResult(t, f, work, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE)
	for range 2 {
		response, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(request))
		if err != nil || !response.Msg.GetClosed() {
			t.Fatalf("read-only release acknowledgment or exact retry was not terminal: %v", err)
		}
	}
	state := complianceState(t, f)
	if len(state.GetResources()) != 0 || len(state.GetReleases()) != 1 {
		t.Fatal("released source remained an active compliance resource")
	}
	release := state.GetReleases()[0]
	if release.GetState() != "released" || release.GetCompletedAt() == nil || release.GetSourceAssignmentId() != action.AssignmentID.String() || release.GetSupersedingAssignmentId() != f.intent(t, work).GetDesiredRevision() {
		t.Fatalf("read-only release lost its source/head association or completion: %v", release)
	}
	var result *adminv1.ResourceActionSummary
	for _, recent := range state.GetRecentActions() {
		if recent.GetAction().GetActionId() == work.GetActionId() {
			result = recent.GetAction()
		}
	}
	if result == nil || result.GetClosedAt() == nil || result.GetStatus().GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED || !result.GetStatus().GetReadOnly() || result.GetStatus().GetVerification().GetDisposition() != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE {
		t.Fatal("release acknowledgment lost terminal read-only native history")
	}
	var disposition int16
	var reason string
	var verifiedAt, observedAt time.Time
	if err := f.pool.QueryRow(t.Context(), "SELECT disposition, reason, last_verified_at, observed_at FROM resource_assignment_resources WHERE assignment_id=$1 AND resource_id=$2", action.AssignmentID, action.ResourceID).Scan(&disposition, &reason, &verifiedAt, &observedAt); err != nil {
		t.Fatal(err)
	}
	if disposition != int16(adminv1.ResourceDisposition_RESOURCE_DISPOSITION_SUCCEEDED) || reason != "" || !verifiedAt.Equal(old) || !observedAt.Equal(old) {
		t.Fatal("release rewrote the source disposition or refreshed its historical convergence evidence")
	}
	assertNoResourceWork(t, f)
}

func TestResourceReadOnlyNotApplicableRequiresSignedRelease(t *testing.T) {
	f, work := newReadOnlyDispatchFixture(t, false)
	request := readOnlyResult(t, f, work, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE)
	_, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(request))
	dispatchError(t, err, connect.CodePermissionDenied, "resource_result_binding_rejected")
	valid := readOnlyResult(t, f, work, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED)
	if response, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(valid)); err != nil || !response.Msg.GetClosed() {
		t.Fatalf("release binding denial consumed valid read-only evidence: %v", err)
	}
}

func TestReadOnlyNativeHealthDistinguishesUnknownFromDrift(t *testing.T) {
	f, work := newReadOnlyDispatchFixture(t, false)
	assignment := uuid.MustParse(f.intent(t, work).GetDesiredRevision())
	// Rollout health is projected only for active devices; the fixture device
	// is otherwise still pending its first inventory.
	if _, err := f.pool.Exec(t.Context(), "UPDATE devices SET state='active' WHERE id=$1", f.principal.DeviceID); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		reason      string
		disposition int16
		want        policyv1.RolloutHealth
	}{
		{"verification_drifted", 4, policyv1.RolloutHealth_ROLLOUT_HEALTH_FAILED},
		{"verification_unknown", 4, policyv1.RolloutHealth_ROLLOUT_HEALTH_UNKNOWN},
		{"not_applicable", 5, policyv1.RolloutHealth_ROLLOUT_HEALTH_UNKNOWN},
		{"outcome_unknown", 4, policyv1.RolloutHealth_ROLLOUT_HEALTH_UNKNOWN},
	} {
		t.Run(test.reason, func(t *testing.T) {
			// Even still-fresh prior convergence cannot make a negative,
			// uncertain or not-applicable current result healthy.
			if _, err := f.pool.Exec(t.Context(), "UPDATE resource_assignment_resources SET disposition=$2, reason=$3, last_verified_at=clock_timestamp()-interval '1 minute' WHERE assignment_id=$1", assignment, test.disposition, test.reason); err != nil {
				t.Fatal(err)
			}
			health, err := targetingdb.New(f.pool).CurrentExecutionHealth(t.Context(), targetingdb.CurrentExecutionHealthParams{
				AssignmentID: assignment, DeviceID: f.principal.DeviceID, GenerationID: f.principal.GenerationID,
				FreshAfter: core.Timestamptz(time.Now().Add(-time.Hour)),
			})
			if err != nil || health.Health != int16(test.want) {
				t.Fatalf("native uncertainty/drift classified as %d, want %s: %v", health.Health, test.want, err)
			}
		})
	}
}

func TestResourceReadOnlyEvidenceCannotHideIssuedGrant(t *testing.T) {
	f := newDispatchFixture(t)
	f.assign(t, nil)
	work := f.work(t)
	f.start(t, work)
	_, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(f.result(t, work, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, false)))
	dispatchError(t, err, connect.CodePermissionDenied, "resource_result_binding_rejected")
	response, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(f.result(t, work, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, true)))
	if err != nil || !response.Msg.GetClosed() {
		t.Fatalf("read-only denial lost real granted execution history: %v", err)
	}
}
