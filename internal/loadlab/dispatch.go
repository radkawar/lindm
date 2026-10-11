package loadlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

// One action is in flight per device, just as on the server. Retain the prepared
// challenge and terminal history until a report is acknowledged, not just until
// the RPC returns: admission failures and lost replies do not undo execution.
type pendingService struct {
	work      *devicev1.ResourceWork
	intent    *agentv1.ResourceExecutionIntent
	challenge *agentv1.ResourceExecutionChallenge
	proof     []byte
	grant     []byte
	deadline  time.Time
	status    *agentv1.ResourceExecutionStatus
	report    *devicev1.ReportResourceResultRequest
	reportEnd time.Time
}

// dispatch emulates the protected executor's protocol, not its native effects.
// Only keys for this disposable fixture's freshly enrolled identities are used.
func (r *runner) dispatch(ctx context.Context, d *simulatedDevice) error {
	p := d.pending
	// An admitted report remains exactly replayable after nonce/proof expiry.
	// While both windows are current, avoid even fetching replacement work.
	if p != nil && p.report != nil && time.Now().Before(p.reportEnd) && time.Now().Before(p.work.GetResultNonceExpiresAt().AsTime()) {
		return r.reportService(ctx, d)
	}
	response, err := d.client.GetResourceWork(ctx, connect.NewRequest(&devicev1.GetResourceWorkRequest{SessionEpoch: d.epoch}))
	if err != nil {
		return err
	}
	work := response.Msg.GetWork()
	if p != nil {
		if work == nil || work.GetActionId() != p.work.GetActionId() {
			if p.report != nil {
				// A terminal report may have closed the action before its reply
				// was lost. Only its exact receipt can confirm completion.
				return r.reportService(ctx, d)
			}
			return errors.New("server replaced pending simulated action")
		}
		if !bytes.Equal(work.GetIntentEnvelope(), p.work.GetIntentEnvelope()) {
			return errors.New("server changed the intent of an existing simulated action")
		}
		p.work = work
		// The same still-open action proves the terminal report was not
		// admitted. Refresh only its attestation, never the signed history.
		p.report = nil
	} else {
		if work == nil {
			return nil
		}
		if d.completed[work.GetActionId()] {
			return errors.New("server redelivered completed simulated action")
		}
		p, err = r.prepareService(ctx, d, work)
		if err != nil {
			return err
		}
		d.pending = p
	}
	if p.status.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED {
		if err := r.startService(ctx, d, p); err != nil {
			return err
		}
	}
	now := time.Now().UTC()
	attestation := &agentv1.ResourceExecutionAttestation{DeploymentId: p.intent.GetDeploymentId(), DeviceId: d.id, EnrollmentGeneration: d.generation, SessionEpoch: d.epoch, ActionRevision: 1, Nonce: p.work.GetResultNonce(), IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second)), Status: p.status}
	envelope, err := r.authority.Sign(ctx, attestation, d.key)
	if err != nil {
		return err
	}
	p.report = &devicev1.ReportResourceResultRequest{SessionEpoch: d.epoch, ActionId: p.intent.GetActionId(), AttestationEnvelope: envelope, CertificatePem: d.certificate}
	p.reportEnd = attestation.GetExpiresAt().AsTime()
	return r.reportService(ctx, d)
}

func (r *runner) prepareService(ctx context.Context, d *simulatedDevice, work *devicev1.ResourceWork) (*pendingService, error) {
	intent, err := r.verifier.VerifyResourceIntent(ctx, d.root, d.delegation, work.GetIntentEnvelope(), time.Now())
	if err != nil {
		return nil, err
	}
	if intent.GetDeviceId() != d.id || intent.GetEnrollmentGeneration() != d.generation || intent.GetActionId() != work.GetActionId() {
		return nil, errors.New("service intent identity mismatch")
	}
	// Each resource's monotonic sequence rejects old actions without retaining
	// every periodic action ID.
	if intent.GetResourceSequence() <= d.serviceSequences[serviceKey(intent.GetDesired().GetRef())] {
		return nil, errors.New("server redelivered completed simulated service sequence")
	}
	now := time.Now()
	accepted := timestamppb.New(now)
	digest := sha256.Sum256(work.GetIntentEnvelope())
	native := &resourcev1.SystemdServiceObservation{Unit: intent.GetDesired().GetRef().GetCanonicalKey(), BootId: d.boot, ObservedAt: accepted, LoadState: "loaded", ActiveState: "inactive", DefinitionSha256: digest[:], FingerprintSha256: digest[:]}
	before := &resourcev1.ResourceObservation{
		Ref: intent.GetDesired().GetRef(),
		Metadata: &resourcev1.ObservationMetadata{
			BootId: d.boot, ExecutorIncarnation: d.incarnation, ObservedAt: accepted, NativeRevision: digest[:],
			ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK,
			Backend:           &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_SYSTEMD, NativeVersion: "synthetic", ProviderVersion: "loadlab-synthetic", Product: &resourcev1.PlatformProduct{OsId: "synthetic", Product: "protocol load fixture", Version: "1", Architecture: "synthetic"}},
		},
		Observed: &resourcev1.ResourceObservation_SystemdService{SystemdService: native},
	}
	if d.demo != nil {
		status, err := d.demo.immediateResult(intent, digest[:], before)
		if err != nil {
			return nil, err
		}
		if status != nil {
			return &pendingService{work: work, intent: intent, status: status}, nil
		}
	}
	desiredDigest, err := resource.DesiredDigest(intent.GetDesired())
	if err != nil {
		return nil, err
	}
	observedDigest, err := resource.ObservationDigest(before)
	if err != nil {
		return nil, err
	}
	plan := &resourcev1.ResourcePlan{
		Ref: intent.GetDesired().GetRef(), Operation: intent.GetOperation(), DesiredSha256: desiredDigest[:],
		ObservationSha256: observedDigest[:], Backend: before.GetMetadata().GetBackend(), Before: before, OwnershipRevisionSha256: digest[:],
		Safety: &resourcev1.PlanSafety{LockDomains: []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_SERVICE_RUNTIME}, Reversibility: resourcev1.Reversibility_REVERSIBILITY_PARTIAL, RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_NONE, Confirmation: resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_NOT_REQUIRED},
		Plan:   &resourcev1.ResourcePlan_SystemdService{SystemdService: &resourcev1.SystemdServicePlan{Desired: intent.GetDesired().GetSystemdService(), Before: native, ChangeRuntime: true}},
	}
	planDigest, err := resource.PlanDigest(plan)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	deadline := now.Add(min(30*time.Second, intent.GetExpiresAt().AsTime().Sub(now)))
	challenge := &agentv1.ResourceExecutionChallenge{DeploymentId: intent.GetDeploymentId(), DeviceId: d.id, EnrollmentGeneration: d.generation, ActionId: intent.GetActionId(), DesiredRevision: intent.GetDesiredRevision(), Ref: intent.GetDesired().GetRef(), Operation: intent.GetOperation(), ResourceSequence: intent.GetResourceSequence(), RecoveryEpoch: intent.GetRecoveryEpoch(), IntentSha256: digest[:], NativePlanSha256: planDigest[:], Nonce: nonce, BootId: d.boot, ExecutorIncarnation: d.incarnation, IssuedAt: accepted, ExpiresAt: timestamppb.New(deadline)}
	proof, err := r.authority.Sign(ctx, challenge, d.key)
	if err != nil {
		return nil, err
	}
	status := &agentv1.ResourceExecutionStatus{ActionId: intent.GetActionId(), IntentSha256: digest[:], State: agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED, Failure: agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE, AcceptedAt: accepted, Before: before}
	return &pendingService{work: work, intent: intent, challenge: challenge, proof: proof, deadline: deadline, status: status}, nil
}

func (r *runner) startService(ctx context.Context, d *simulatedDevice, p *pendingService) error {
	if !time.Now().Before(p.deadline) {
		p.status.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED
		p.status.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_EXPIRED
		p.status.CompletedAt = stamp()
		return nil
	}
	p.grant = p.work.GetStartGrantEnvelope()
	if len(p.grant) == 0 {
		started, err := d.client.AuthorizeResourceStart(ctx, connect.NewRequest(&devicev1.AuthorizeResourceStartRequest{SessionEpoch: d.epoch, ActionId: p.intent.GetActionId(), ChallengeProof: p.proof}))
		if err != nil {
			return err
		}
		p.grant = started.Msg.GetStartGrantEnvelope()
	}
	now := time.Now()
	// A delayed authorization does not extend the executor's challenge window.
	if !now.Before(p.deadline) {
		p.status.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED
		p.status.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_EXPIRED
		p.status.CompletedAt = timestamppb.New(now)
		return nil
	}
	_, err := r.verifier.VerifyResourceStart(ctx, d.root, d.delegation, p.grant, p.intent, p.challenge, now)
	if err != nil {
		return err
	}
	if r.effects != nil {
		if err := r.effects(d.id, p.intent.GetActionId(), p.intent.GetResourceSequence()); err != nil {
			return err
		}
	}
	if d.demo != nil && d.demo.service == serviceFails {
		p.status.State, p.status.Failure = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE
		p.status.StartedAt, p.status.CompletedAt = timestamppb.New(now), stamp()
		return nil
	}
	after := proto.CloneOf(p.status.GetBefore())
	after.GetSystemdService().ActiveState = "active"
	after.Metadata.ObservedAt = stamp()
	after.GetSystemdService().ObservedAt = after.Metadata.ObservedAt
	p.status.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED
	p.status.StartedAt = timestamppb.New(now)
	p.status.CompletedAt = after.GetMetadata().GetObservedAt()
	desiredDigest, err := resource.DesiredDigest(p.intent.GetDesired())
	if err != nil {
		return err
	}
	p.status.Verification = &resourcev1.ResourceVerification{
		Ref: p.intent.GetDesired().GetRef(), DesiredSha256: desiredDigest[:], PlanSha256: p.challenge.GetNativePlanSha256(),
		After: after, Disposition: resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED,
		Checks: &resourcev1.ResourceVerification_SystemdService{SystemdService: &resourcev1.SystemdServiceChecks{Observation: after.GetSystemdService(), RuntimeMatches: true, EnablementMatches: true, DefinitionMatches: true, JobCompleted: true, Converged: true}},
	}
	return nil
}

func (r *runner) reportService(ctx context.Context, d *simulatedDevice) error {
	p := d.pending
	reported, err := d.client.ReportResourceResult(ctx, connect.NewRequest(p.report))
	if err != nil {
		return err
	}
	if !reported.Msg.GetClosed() {
		return errors.New("terminal simulated action was not closed")
	}
	d.serviceSequences[serviceKey(p.intent.GetDesired().GetRef())] = p.intent.GetResourceSequence()
	d.serviceReports++
	if p.status.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED {
		if len(d.completed) == 0 {
			r.completedDevices.Add(1)
		}
		clear(d.completed)
		d.completed[p.intent.GetActionId()] = true
		r.completed.Add(1)
	}
	d.pending = nil
	return nil
}

func serviceKey(ref *resourcev1.ResourceRef) string {
	return ref.GetKind().String() + "/" + ref.GetCanonicalKey()
}
