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
)

// One action is in flight per device, just as on the server. Retain the prepared
// challenge and terminal history until a report is acknowledged, not just until
// the RPC returns: admission failures and lost replies do not undo execution.
type pendingService struct {
	work      *devicev1.ServiceWork
	intent    *agentv1.ServiceExecutionIntent
	challenge *agentv1.ServiceExecutionChallenge
	proof     []byte
	grant     []byte
	deadline  time.Time
	status    *agentv1.ServiceExecutionStatus
	report    *devicev1.ReportServiceResultRequest
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
	response, err := d.client.GetServiceWork(ctx, connect.NewRequest(&devicev1.GetServiceWorkRequest{SessionEpoch: d.epoch}))
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
	if p.status.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_PREPARED {
		if err := r.startService(ctx, d, p); err != nil {
			return err
		}
	}
	now := time.Now().UTC()
	attestation := &agentv1.ServiceExecutionAttestation{DeploymentId: p.intent.GetDeploymentId(), DeviceId: d.id, EnrollmentGeneration: d.generation, SessionEpoch: d.epoch, ActionRevision: 1, Nonce: p.work.GetResultNonce(), IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second)), Status: p.status}
	envelope, err := r.authority.Sign(ctx, attestation, d.key)
	if err != nil {
		return err
	}
	p.report = &devicev1.ReportServiceResultRequest{SessionEpoch: d.epoch, ActionId: p.intent.GetActionId(), AttestationEnvelope: envelope, CertificatePem: d.certificate}
	p.reportEnd = attestation.GetExpiresAt().AsTime()
	return r.reportService(ctx, d)
}

func (r *runner) prepareService(ctx context.Context, d *simulatedDevice, work *devicev1.ServiceWork) (*pendingService, error) {
	intent, err := r.verifier.VerifyServiceIntent(ctx, d.root, d.delegation, work.GetIntentEnvelope(), time.Now())
	if err != nil {
		return nil, err
	}
	if intent.GetDeviceId() != d.id || intent.GetEnrollmentGeneration() != d.generation || intent.GetActionId() != work.GetActionId() {
		return nil, errors.New("service intent identity mismatch")
	}
	// The fixture assigns one resource to each selected device. Its monotonic
	// sequence rejects old actions without retaining every periodic action ID.
	if intent.GetResourceSequence() <= d.serviceSequence {
		return nil, errors.New("server redelivered completed simulated service sequence")
	}
	now := time.Now()
	accepted := timestamppb.New(now)
	digest := sha256.Sum256(work.GetIntentEnvelope())
	before := &agentv1.ServiceObservation{Unit: intent.GetDesired().GetUnit(), BootId: d.boot, ObservedAt: accepted, LoadState: "loaded", ActiveState: "inactive", DefinitionSha256: digest[:], FingerprintSha256: digest[:]}
	plan := &agentv1.ServicePlan{Desired: intent.GetDesired(), Before: before, ChangeRuntime: true}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(plan)
	if err != nil {
		return nil, err
	}
	planDigest := sha256.Sum256(encoded)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	deadline := now.Add(min(30*time.Second, intent.GetExpiresAt().AsTime().Sub(now)))
	challenge := &agentv1.ServiceExecutionChallenge{DeploymentId: intent.GetDeploymentId(), DeviceId: d.id, EnrollmentGeneration: d.generation, ActionId: intent.GetActionId(), DesiredRevision: intent.GetDesiredRevision(), ResourceSequence: intent.GetResourceSequence(), RecoveryEpoch: intent.GetRecoveryEpoch(), IntentSha256: digest[:], NativePlanSha256: planDigest[:], Nonce: nonce, BootId: d.boot, ExecutorIncarnation: d.incarnation, IssuedAt: accepted, ExpiresAt: timestamppb.New(deadline)}
	proof, err := r.authority.Sign(ctx, challenge, d.key)
	if err != nil {
		return nil, err
	}
	status := &agentv1.ServiceExecutionStatus{ActionId: intent.GetActionId(), IntentSha256: digest[:], State: agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_PREPARED, Failure: agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_NONE, AcceptedAt: accepted, Before: before}
	return &pendingService{work: work, intent: intent, challenge: challenge, proof: proof, deadline: deadline, status: status}, nil
}

func (r *runner) startService(ctx context.Context, d *simulatedDevice, p *pendingService) error {
	if !time.Now().Before(p.deadline) {
		p.status.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_EXPIRED
		p.status.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_EXPIRED
		p.status.CompletedAt = stamp()
		return nil
	}
	p.grant = p.work.GetStartGrantEnvelope()
	if len(p.grant) == 0 {
		started, err := d.client.AuthorizeServiceStart(ctx, connect.NewRequest(&devicev1.AuthorizeServiceStartRequest{SessionEpoch: d.epoch, ActionId: p.intent.GetActionId(), ChallengeProof: p.proof}))
		if err != nil {
			return err
		}
		p.grant = started.Msg.GetStartGrantEnvelope()
	}
	now := time.Now()
	// A delayed authorization does not extend the executor's challenge window.
	if !now.Before(p.deadline) {
		p.status.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_EXPIRED
		p.status.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_EXPIRED
		p.status.CompletedAt = timestamppb.New(now)
		return nil
	}
	_, err := r.verifier.VerifyServiceStart(ctx, d.root, d.delegation, p.grant, p.intent, p.challenge, now)
	if err != nil {
		return err
	}
	after := proto.CloneOf(p.status.GetBefore())
	after.ActiveState = "active"
	after.ObservedAt = stamp()
	p.status.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED
	p.status.StartedAt = timestamppb.New(now)
	p.status.CompletedAt = after.ObservedAt
	p.status.Verification = &agentv1.ServiceVerification{Observation: after, RuntimeMatches: true, EnablementMatches: true, DefinitionMatches: true, Converged: true}
	return nil
}

func (r *runner) reportService(ctx context.Context, d *simulatedDevice) error {
	p := d.pending
	reported, err := d.client.ReportServiceResult(ctx, connect.NewRequest(p.report))
	if err != nil {
		return err
	}
	if !reported.Msg.GetClosed() {
		return errors.New("terminal simulated action was not closed")
	}
	d.serviceSequence = p.intent.GetResourceSequence()
	if p.status.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED {
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
