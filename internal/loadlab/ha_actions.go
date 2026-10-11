package loadlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
)

// errProtocolViolation marks evidence of duplicate or replaced work. RPC errors
// are retryable laboratory faults; these are lane failures.
var errProtocolViolation = errors.New("ha: protocol violation")

// pendingDeviceAction is the simulated executor journal entry for one device
// action. The challenge and proof are retained before start so a lost reply
// never causes a second challenge, and execution is recorded before the report
// so a lost report never causes a second effect.
type pendingDeviceAction struct {
	work      *devicev1.DeviceActionWork
	intent    *agentv1.DeviceActionIntent
	challenge *agentv1.DeviceActionChallenge
	proof     []byte
	plan      *agentv1.DeviceActionPlan
	executed  bool
	newBoot   string
	startedAt time.Time
	reportAt  time.Time
	report    *devicev1.ReportDeviceActionResultRequest
	reportEnd time.Time
}

// restartAction emulates the protected executor's restart protocol; the
// "restart" itself is a ledger entry and a new boot identity, never a host effect.
func (h *haRun) restartAction(ctx context.Context, d *haDevice) error {
	p := d.restart
	if p != nil && p.report != nil && time.Now().Before(p.reportEnd) {
		return h.reportRestart(ctx, d)
	}
	response, err := d.client.GetDeviceActionWork(ctx, connect.NewRequest(&devicev1.GetDeviceActionWorkRequest{SessionEpoch: d.epoch}))
	if err != nil {
		return err
	}
	work := response.Msg.GetWork()
	if p != nil {
		if work == nil || work.GetActionId() != p.work.GetActionId() {
			if p.report != nil {
				// The report may have closed the action before its reply was
				// lost; only the exact admitted attestation can confirm it.
				return h.reportRestart(ctx, d)
			}
			if p.executed {
				return errors.Join(errProtocolViolation, errors.New("server closed or replaced an executed restart before its report"))
			}
			return errors.Join(errProtocolViolation, errors.New("server closed or replaced a prepared restart before its report"))
		}
		if !bytes.Equal(work.GetIntentEnvelope(), p.work.GetIntentEnvelope()) {
			return errors.Join(errProtocolViolation, errors.New("server changed the intent of an open restart"))
		}
		// The same open action proves the terminal report was not admitted.
		// Re-attest the unchanged journal state with the fresh nonce.
		p.work = work
		p.report = nil
	} else {
		if work == nil {
			return nil
		}
		if h.ledger.restartSeen(work.GetActionId()) {
			return errors.Join(errProtocolViolation, errors.New("server redelivered a finished restart"))
		}
		p, err = h.prepareRestart(ctx, d, work)
		if err != nil {
			return err
		}
		d.restart = p
	}
	if !p.executed {
		// The executor never starts after its challenge deadline; it reports the
		// unexecuted action as expired instead of requesting new authority.
		if !time.Now().Before(p.challenge.GetExpiresAt().AsTime()) {
			return h.finishRestart(ctx, d, agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED)
		}
		grant := p.work.GetStartGrantEnvelope()
		if len(grant) == 0 {
			started, err := d.client.AuthorizeDeviceActionStart(ctx, connect.NewRequest(&devicev1.AuthorizeDeviceActionStartRequest{SessionEpoch: d.epoch, ActionId: p.intent.GetActionId(), ChallengeProof: p.proof}))
			if err != nil {
				return err
			}
			grant = started.Msg.GetStartGrantEnvelope()
		}
		now := time.Now()
		if !now.Before(p.challenge.GetExpiresAt().AsTime()) {
			return h.finishRestart(ctx, d, agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED)
		}
		if _, err := h.verifier.VerifyDeviceActionStart(ctx, d.root, d.delegation, grant, p.intent, p.challenge, now); err != nil {
			return errors.Join(errProtocolViolation, err)
		}
		// Journal first, then "reboot": the effect is never repeated.
		if err := h.ledger.executeRestart(d.id, p.intent.GetActionId()); err != nil {
			return err
		}
		p.executed, p.startedAt = true, now
		p.newBoot = uuid.NewString()
		d.boot = p.newBoot
		p.reportAt = now.Add(h.executionDelay())
	}
	if time.Now().Before(p.reportAt) {
		// The device is "rebooting": the action is in flight on the server.
		return nil
	}
	return h.finishRestart(ctx, d, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED)
}

// finishRestart attests the terminal journal state with the current nonce.
func (h *haRun) finishRestart(ctx context.Context, d *haDevice, state agentv1.DeviceActionState) error {
	p := d.restart
	completed := stamp()
	digest := sha256.Sum256(p.work.GetIntentEnvelope())
	status := &agentv1.DeviceActionStatus{ActionId: p.intent.GetActionId(), IntentSha256: digest[:], State: state, Failure: agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NONE,
		AcceptedAt: p.plan.GetBefore().GetObservedAt(), CompletedAt: completed, Before: p.plan.GetBefore()}
	if state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED {
		status.StartedAt = timestamppb.New(p.startedAt)
		status.Verification = &agentv1.DeviceActionVerification{Verified: true, BootId: p.newBoot, After: &agentv1.DeviceActionObservation{ObservedAt: completed, Supported: true, BootId: p.newBoot}}
	} else {
		status.Failure = agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_EXPIRED
	}
	if err := h.attestDeviceAction(ctx, d.simulatedDevice, p, status, 1); err != nil {
		return err
	}
	return h.reportRestart(ctx, d)
}

// attestDeviceAction signs status with the current work nonce as the exact
// replayable report; revisions advance only for a later journal state.
func (r *runner) attestDeviceAction(ctx context.Context, d *simulatedDevice, p *pendingDeviceAction, status *agentv1.DeviceActionStatus, revision uint64) error {
	now := time.Now().UTC()
	attestation := &agentv1.DeviceActionAttestation{DeploymentId: p.intent.GetDeploymentId(), DeviceId: d.id, EnrollmentGeneration: d.generation, SessionEpoch: d.epoch, ActionRevision: revision,
		Nonce: p.work.GetResultNonce(), IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second)), Status: status}
	envelope, err := r.authority.Sign(ctx, attestation, d.key)
	if err != nil {
		return err
	}
	p.report = &devicev1.ReportDeviceActionResultRequest{SessionEpoch: d.epoch, ActionId: p.intent.GetActionId(), AttestationEnvelope: envelope, CertificatePem: d.certificate}
	p.reportEnd = attestation.GetExpiresAt().AsTime()
	return nil
}

func (h *haRun) prepareRestart(ctx context.Context, d *haDevice, work *devicev1.DeviceActionWork) (*pendingDeviceAction, error) {
	return h.prepareDeviceAction(ctx, d.simulatedDevice, work, func(intent *agentv1.DeviceActionIntent, _ *agentv1.DeviceActionPlan) bool {
		return intent.GetSpec().GetRestart() != nil
	})
}

// prepareDeviceAction verifies the signed intent, lets plan record the
// simulated native preflight (false rejects the intent), and signs the
// executor's challenge over it.
func (r *runner) prepareDeviceAction(ctx context.Context, d *simulatedDevice, work *devicev1.DeviceActionWork, plan func(*agentv1.DeviceActionIntent, *agentv1.DeviceActionPlan) bool) (*pendingDeviceAction, error) {
	intent, err := r.verifier.VerifyDeviceActionIntent(ctx, d.root, d.delegation, work.GetIntentEnvelope(), time.Now())
	if err != nil {
		return nil, errors.Join(errProtocolViolation, err)
	}
	now := time.Now().UTC().Add(-time.Second)
	native := &agentv1.DeviceActionPlan{ActionId: intent.GetActionId(), Spec: intent.GetSpec(), Before: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(now), Supported: true, BootId: d.boot}}
	if intent.GetDeviceId() != d.id || intent.GetEnrollmentGeneration() != d.generation || intent.GetActionId() != work.GetActionId() || !plan(intent, native) {
		return nil, errors.Join(errProtocolViolation, errors.New("device action intent identity mismatch"))
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(native)
	if err != nil {
		return nil, err
	}
	planDigest := sha256.Sum256(encoded)
	intentDigest := sha256.Sum256(work.GetIntentEnvelope())
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	challenge := &agentv1.DeviceActionChallenge{DeploymentId: intent.GetDeploymentId(), DeviceId: d.id, EnrollmentGeneration: d.generation, ActionId: intent.GetActionId(),
		ActionSequence: intent.GetActionSequence(), RecoveryEpoch: intent.GetRecoveryEpoch(), IntentSha256: intentDigest[:], SpecSha256: intent.GetSpecSha256(),
		NativePlanSha256: planDigest[:], NativePlan: native, Nonce: nonce, BootId: d.boot, ExecutorIncarnation: d.incarnation,
		IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second))}
	proof, err := r.authority.Sign(ctx, challenge, d.key)
	if err != nil {
		return nil, err
	}
	return &pendingDeviceAction{work: work, intent: intent, challenge: challenge, proof: proof, plan: native}, nil
}

func (h *haRun) reportRestart(ctx context.Context, d *haDevice) error {
	p := d.restart
	reported, err := d.client.ReportDeviceActionResult(ctx, connect.NewRequest(p.report))
	if err != nil {
		return err
	}
	if !reported.Msg.GetClosed() {
		return errors.Join(errProtocolViolation, errors.New("terminal restart report was not closed"))
	}
	h.ledger.finishRestart(p.intent.GetActionId(), p.executed, p.newBoot)
	d.restart = nil
	return nil
}
