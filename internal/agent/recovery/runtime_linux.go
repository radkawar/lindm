// SPDX-License-Identifier: Apache-2.0

//go:build linux

package recovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
	recoveryv1connect "lindm/gen/lindm/recovery/v1/recoveryv1connect"
	"lindm/internal/protodata"
	"lindm/internal/trust"
)

// Provider is the existing native action provider. It independently re-resolves
// exact media and off-target state and invokes the gate at its native boundary.
type Provider interface {
	Observe(context.Context, *agentv1.DeviceActionSpec) (*agentv1.DeviceActionObservation, error)
	Plan(context.Context, *agentv1.DeviceActionSpec, *agentv1.DeviceActionObservation) (*agentv1.DeviceActionPlan, error)
	Apply(context.Context, *agentv1.DeviceActionPlan, []byte, func(context.Context) error) (*agentv1.DeviceActionVerification, error)
	Verify(context.Context, *agentv1.DeviceActionPlan, *agentv1.DeviceActionVerification) (*agentv1.DeviceActionVerification, error)
}

// StateStore is independently durable custody outside the erased scope: either
// a protected off-target filesystem or a qualified TPM NV-anchored journal.
// Consume is irreversible and must survive loss of the full journal payload.
type StateStore interface {
	Load(proto.Message) (bool, error)
	Save(proto.Message) error
	Consume() error
	Consumed() (bool, error)
}

// Options contains trusted local composition, never remote request fields.
// BootID/ImageSHA256 must come from recoveryboot.VerifyBoot; Bootstrap comes from
// the authenticated root/bundle embedded in the qualified signed recovery image.
// Client is TLS-server-authenticated and carries no ordinary device certificate.
// Run borrows Journal and Key; the owner closes the former and clears the latter.
type Options struct {
	Journal       StateStore
	Key           ed25519.PrivateKey
	Bootstrap     *trust.Bootstrap
	Client        recoveryv1connect.RecoveryServiceClient
	Provider      Provider
	BootID        string
	ImageSHA256   []byte
	Clock         *Clock
	ProvisionedAt time.Time
	// Attest quotes the measured boot with the handoff's TPM attestation key.
	// Required exactly for measured-BLS handoffs; the server verifies it.
	Attest func(ctx context.Context, qualifyingData []byte) (*recoveryv1.RecoveryAttestation, error)
}

type runner struct {
	journal             StateStore
	key                 ed25519.PrivateKey
	client              recoveryv1connect.RecoveryServiceClient
	provider            Provider
	bootID, incarnation string
	clock               *Clock
	boottime            func() (time.Duration, error)
	authority           *trust.Authority
	verifier            *trust.ExecutionVerifier
	validator           protovalidate.Validator
	record              *agentv1.RecoveryJournal
	credential          *agentv1.DeviceActionRecoveryCredential
	delegation          *agentv1.ExecutionDelegation
	attest              func(context.Context, []byte) (*recoveryv1.RecoveryAttestation, error)
}

// Run performs at most one effect, synchronously, with a 24-hour operation bound.
// Any durable local/server evidence of a prior attempt prohibits a fresh start.
// Network errors and lost responses are returned, never retried automatically.
func Run(ctx context.Context, options Options) error {
	if options.Journal == nil || options.Provider == nil {
		return errors.New("recovery_dependencies_required")
	}
	record := new(agentv1.RecoveryJournal)
	found, err := options.Journal.Load(record)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("recovery_handoff_missing")
	}
	consumed, err := options.Journal.Consumed()
	if err != nil {
		return err
	}
	var historical *time.Time
	if consumed || len(record.GetStartGrantEnvelope()) != 0 {
		if record.GetChallenge() == nil {
			return errors.New("recovery_consumed_history_missing")
		}
		at := record.GetChallenge().GetIssuedAt().AsTime()
		historical = &at
	}
	r, err := authenticateRunner(ctx, options, record, historical)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 24*time.Hour)
	defer cancel()
	return r.run(ctx)
}

// authenticateRunner is shared by execution and read-only TPM snapshot recovery.
// A historical timestamp authenticates retained credentials, never a new effect;
// every actual start still passes the current-time grant and durable effect gate.
func authenticateRunner(ctx context.Context, options Options, record *agentv1.RecoveryJournal, historical *time.Time) (*runner, error) {
	if len(options.Key) != ed25519.PrivateKeySize || options.Bootstrap == nil || options.Client == nil {
		return nil, errors.New("recovery_dependencies_required")
	}
	if id, err := uuid.Parse(options.BootID); err != nil || id == uuid.Nil || id.String() != options.BootID {
		return nil, errors.New("recovery_boot_identity_required")
	}
	authority, err := trust.New()
	if err != nil {
		return nil, err
	}
	verifier, err := authority.NewExecutionVerifier(options.Bootstrap)
	if err != nil {
		return nil, err
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(&agentv1.RecoveryJournal{}, &recoveryv1.AcquireRecoveryWorkResponse{}, &recoveryv1.AuthorizeRecoveryStartResponse{}, &recoveryv1.CheckpointRecoveryActionResponse{}, &recoveryv1.ReportRecoveryResultResponse{}), protovalidate.WithDisableLazy())
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, errors.New("recovery_handoff_missing")
	}
	if err := protodata.ValidateClosed(record.ProtoReflect()); err != nil {
		return nil, err
	}
	if err := validator.Validate(record); err != nil {
		return nil, err
	}
	r := &runner{journal: options.Journal, key: options.Key, client: options.Client, provider: options.Provider, bootID: options.BootID, incarnation: uuid.NewString(), clock: options.Clock, boottime: bootTime, authority: authority, verifier: verifier, validator: validator, record: record, attest: options.Attest}
	handoff := record.GetHandoff()
	if len(options.Key) != ed25519.PrivateKeySize || handoff.GetOriginalBootId() == r.bootID || !bytes.Equal(handoff.GetRecoveryImageSha256(), options.ImageSHA256) || !bytes.Equal(handoff.GetRecoveryPublicKey(), options.Key[ed25519.SeedSize:]) {
		return nil, errors.New("recovery_boot_or_key_binding_rejected")
	}
	if (handoff.GetMeasuredBoot() != nil) != (options.Attest != nil) {
		return nil, errors.New("recovery_attestation_binding_rejected")
	}
	if record.GetAcceptedRoot().GetDeploymentId() != options.Bootstrap.Root.GetDeploymentId() || record.GetCredentialRoot().GetDeploymentId() != options.Bootstrap.Root.GetDeploymentId() || record.GetCredentialRoot().GetVersion() < options.Bootstrap.Root.GetVersion() || record.GetAcceptedRoot().GetVersion() < record.GetCredentialRoot().GetVersion() {
		return nil, errors.New("recovery_root_rollback")
	}
	// Restore protected trust at its original acceptance time only to select the
	// bootstrap signer. No request proof or effect uses this historical time.
	retainedAt := record.GetTrustAcceptedAt().AsTime()
	retainedDelegation, err := verifier.VerifyDelegation(ctx, record.GetAcceptedRoot(), record.GetDelegationEnvelope(), 0, 0, retainedAt)
	if err != nil {
		return nil, err
	}
	minimum := retainedAt
	if options.ProvisionedAt.After(minimum) {
		minimum = options.ProvisionedAt
	}
	if err := r.clock.bootstrap(ctx, verifier, options.Client, record, retainedDelegation, r.bootID, minimum); err != nil {
		return nil, err
	}
	now, latest, err := r.now()
	if err != nil {
		return nil, err
	}
	credentialTime, currentTrustTime := now, now
	if historical != nil {
		credentialTime = *historical
		currentTrustTime = record.GetTrustAcceptedAt().AsTime()
	}
	r.delegation, err = verifier.VerifyDelegation(ctx, record.GetAcceptedRoot(), record.GetDelegationEnvelope(), 0, 0, currentTrustTime)
	if err != nil {
		return nil, err
	}
	credentialDelegation, err := verifier.VerifyDelegation(ctx, record.GetCredentialRoot(), record.GetCredentialDelegationEnvelope(), 0, 0, credentialTime)
	if err != nil {
		return nil, err
	}
	r.credential, err = verifier.VerifyDeviceActionRecoveryCredential(ctx, record.GetCredentialRoot(), credentialDelegation, record.GetCredentialEnvelope(), handoff, credentialTime)
	if err != nil {
		return nil, err
	}
	intent, err := verifier.VerifyDeviceActionIntent(ctx, record.GetCredentialRoot(), credentialDelegation, record.GetIntentEnvelope(), credentialTime)
	if err != nil {
		return nil, err
	}
	if !proto.Equal(intent, handoff.GetIntent()) {
		return nil, errors.New("recovery_intent_binding_rejected")
	}
	intentDigest := sha256.Sum256(record.GetIntentEnvelope())
	if !bytes.Equal(intentDigest[:], handoff.GetIntentSha256()) {
		return nil, errors.New("recovery_intent_digest_rejected")
	}
	if historical == nil {
		if err := unexpiredThrough(latest, record.GetAcceptedRoot().GetExpiresAt().AsTime(), r.delegation.GetExpiresAt().AsTime(), record.GetCredentialRoot().GetExpiresAt().AsTime(), credentialDelegation.GetExpiresAt().AsTime(), r.credential.GetExpiresAt().AsTime(), intent.GetExpiresAt().AsTime()); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *runner) run(ctx context.Context) error {
	work, err := r.acquire(ctx)
	if err != nil {
		return err
	}
	if !bytes.Equal(work.GetIntentEnvelope(), r.record.GetIntentEnvelope()) {
		return errors.New("recovery_server_changed_intent")
	}
	if work.GetClosed() {
		return nil
	}
	if err := r.updateTrust(ctx, work.GetTrustUpdate()); err != nil {
		return err
	}
	consumed, err := r.journal.Consumed()
	if err != nil {
		return err
	}
	// A prior grant is itself a no-restart fence even when power failed before
	// the irreversible marker. Reconciliation never creates replacement work.
	if consumed || r.record.GetCompletedAt() != nil || len(r.record.GetStartGrantEnvelope()) != 0 || len(work.GetStartGrantEnvelope()) != 0 || work.GetCheckpoint().GetPhase() >= agentv1.RecoveryPhase_RECOVERY_PHASE_EFFECT_COMMITTED {
		if r.record.GetCompletedAt() == nil {
			r.record.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
			r.record.Failure = agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_INTERRUPTED
		}
		if r.record.GetCompletedAt() == nil {
			now, _, err := r.now()
			if err != nil {
				return err
			}
			r.record.CompletedAt = timestamppb.New(now)
		}
		if err := r.journal.Save(r.record); err != nil {
			return err
		}
		return r.report(ctx, work.GetResultNonce())
	}
	if r.record.GetCheckpoint() != nil || work.GetCheckpoint() != nil {
		return errors.New("recovery_prior_boot_checkpoint_requires_reconciliation")
	}
	if err := r.checkpoint(ctx, agentv1.RecoveryPhase_RECOVERY_PHASE_BOOTED); err != nil {
		return err
	}
	intent := r.record.GetHandoff().GetIntent()
	observation, err := r.provider.Observe(ctx, intent.GetSpec())
	if err != nil {
		return r.reject(ctx, err, work.GetResultNonce())
	}
	if !observation.GetSupported() || !observation.GetRecoveryEnvironment() || !observation.GetOffTargetJournal() || observation.GetEncrypted() {
		return r.reject(ctx, errors.New("recovery_media_not_eligible"), work.GetResultNonce())
	}
	plan, err := r.provider.Plan(ctx, intent.GetSpec(), observation)
	if err != nil {
		return r.reject(ctx, err, work.GetResultNonce())
	}
	plan.ActionId = intent.GetActionId()
	canonical, err := trust.RecoveryPlanDigest(plan)
	if err != nil {
		return r.reject(ctx, err, work.GetResultNonce())
	}
	if !bytes.Equal(canonical[:], r.record.GetHandoff().GetNativePlanSha256()) {
		return r.reject(ctx, errors.New("recovery_native_plan_changed"), work.GetResultNonce())
	}
	challenge, started, err := r.challenge(plan)
	if err != nil {
		return r.reject(ctx, err, work.GetResultNonce())
	}
	r.record.Challenge = challenge
	if err := r.journal.Save(r.record); err != nil {
		return err
	}
	envelope, err := r.authorize(ctx, challenge)
	if err != nil {
		return r.unknown(ctx, err, work.GetResultNonce())
	}
	grant, err := r.verifyStart(ctx, envelope, intent, challenge)
	if err != nil {
		return r.unknown(ctx, err, work.GetResultNonce())
	}
	r.record.StartGrantEnvelope = envelope
	r.record.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_QUEUED
	if err := r.journal.Save(r.record); err != nil {
		return err
	}
	gate := &effectGate{journal: r.journal, started: started, expires: grant.GetExpiresAt().AsTime(), clock: r.clock.Bounds, boottime: r.boottime,
		verify: func(ctx context.Context) error {
			_, err := r.verifyStart(ctx, envelope, intent, challenge)
			return err
		},
		checkpoint: func(ctx context.Context) error {
			now, _, err := r.now()
			if err != nil {
				return err
			}
			r.record.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING
			r.record.StartedAt = timestamppb.New(now)
			return r.checkpoint(ctx, agentv1.RecoveryPhase_RECOVERY_PHASE_EFFECT_COMMITTED)
		},
	}
	verification, effectErr := r.provider.Apply(ctx, plan, nil, gate.consume)
	consumed, consumeErr := r.journal.Consumed()
	if consumeErr != nil {
		return errors.Join(effectErr, consumeErr)
	}
	if effectErr == nil && !consumed {
		effectErr = errors.New("recovery_provider_bypassed_effect_gate")
	}
	if effectErr == nil {
		verification, effectErr = r.provider.Verify(ctx, plan, verification)
	}
	if effectErr == nil && (verification == nil || !verification.GetVerified()) {
		effectErr = errors.New("recovery_native_verification_missing")
	}
	now, _, clockErr := r.now()
	if clockErr != nil {
		return errors.Join(effectErr, clockErr)
	}
	r.record.CompletedAt = timestamppb.New(now)
	r.record.Verification = verification
	r.record.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED
	if effectErr != nil {
		r.record.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED
		r.record.Failure = agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_PRECONDITION
		if consumed {
			r.record.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
			r.record.Failure = agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NATIVE
		}
	}
	if err := r.journal.Save(r.record); err != nil {
		return errors.Join(effectErr, err)
	}
	// A long native operation may outlive the original credential or signer.
	// Reacquisition is read-only and obtains current receipt trust/result nonce.
	freshWork, err := r.acquire(ctx)
	if err != nil {
		return errors.Join(effectErr, err)
	}
	if !bytes.Equal(freshWork.GetIntentEnvelope(), r.record.GetIntentEnvelope()) {
		return errors.Join(effectErr, errors.New("recovery_server_changed_intent"))
	}
	if err := r.updateTrust(ctx, freshWork.GetTrustUpdate()); err != nil {
		return errors.Join(effectErr, err)
	}
	if err := r.checkpoint(ctx, agentv1.RecoveryPhase_RECOVERY_PHASE_TERMINAL); err != nil {
		return errors.Join(effectErr, err)
	}
	return errors.Join(effectErr, r.report(ctx, freshWork.GetResultNonce()))
}

func (r *runner) challenge(plan *agentv1.DeviceActionPlan) (*agentv1.DeviceActionChallenge, time.Duration, error) {
	intent := r.record.GetHandoff().GetIntent()
	digest, err := trust.DeviceActionDigest(plan)
	if err != nil {
		return nil, 0, err
	}
	now, latest, err := r.now()
	if err != nil {
		return nil, 0, err
	}
	expires := now.Add(30 * time.Second)
	for _, limit := range []time.Time{intent.GetExpiresAt().AsTime(), r.credential.GetExpiresAt().AsTime()} {
		if limit.Before(expires) {
			expires = limit
		}
	}
	if !latest.Before(expires) {
		return nil, 0, ErrAuthorityExpired
	}
	started, err := r.boottime()
	if err != nil {
		return nil, 0, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, 0, err
	}
	return &agentv1.DeviceActionChallenge{DeploymentId: intent.GetDeploymentId(), DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), ActionId: intent.GetActionId(), ActionSequence: intent.GetActionSequence(), RecoveryEpoch: intent.GetRecoveryEpoch(), IntentSha256: r.record.GetHandoff().GetIntentSha256(), SpecSha256: intent.GetSpecSha256(), NativePlanSha256: digest[:], Nonce: nonce, BootId: r.bootID, ExecutorIncarnation: r.incarnation, IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(expires), NativePlan: plan}, started, nil
}

func (r *runner) updateTrust(ctx context.Context, update *agentv1.UpdateExecutionTrustRequest) error {
	root, delegation, err := r.verifyTrustUpdate(ctx, update)
	if err != nil {
		return err
	}
	now, _, err := r.now()
	if err != nil {
		return err
	}
	r.record.AcceptedRoot = root
	r.record.DelegationEnvelope = update.GetDelegationEnvelope()
	r.record.TrustAcceptedAt = timestamppb.New(now)
	r.delegation = delegation
	return r.journal.Save(r.record)
}

func (r *runner) verifyTrustUpdate(ctx context.Context, update *agentv1.UpdateExecutionTrustRequest) (*agentv1.ExecutionRoot, *agentv1.ExecutionDelegation, error) {
	if update == nil {
		return nil, nil, errors.New("recovery_current_trust_missing")
	}
	if err := protodata.ValidateClosed(update.ProtoReflect()); err != nil {
		return nil, nil, err
	}
	now, latest, err := r.now()
	if err != nil {
		return nil, nil, err
	}
	if err := unexpiredThrough(latest, r.record.GetAcceptedRoot().GetExpiresAt().AsTime()); err != nil {
		return nil, nil, err
	}
	root := r.record.GetAcceptedRoot()
	if err := r.clock.checkRootContinuity(root); err != nil {
		return nil, nil, err
	}
	skip := root.GetVersion() - r.record.GetCredentialRoot().GetVersion()
	if uint64(len(update.GetRootTransitions())) < skip {
		return nil, nil, errors.New("recovery_incomplete_root_history")
	}
	for _, transition := range update.GetRootTransitions()[skip:] {
		next, err := r.verifier.VerifyRootTransition(ctx, root, transition, now)
		if err != nil {
			return nil, nil, err
		}
		if err := unexpiredThrough(latest, next.GetExpiresAt().AsTime()); err != nil {
			return nil, nil, err
		}
		if err := r.clock.checkRootContinuity(next); err != nil {
			return nil, nil, err
		}
		root = next
	}
	previous := r.delegation.GetVersion()
	if bytes.Equal(update.GetDelegationEnvelope(), r.record.GetDelegationEnvelope()) && root.GetVersion() == r.record.GetAcceptedRoot().GetVersion() {
		previous = 0
	}
	delegation, err := r.verifier.VerifyDelegation(ctx, root, update.GetDelegationEnvelope(), previous, r.delegation.GetMinimumRecoveryEpoch(), now)
	if err != nil {
		return nil, nil, fmt.Errorf("recovery current delegation: %w", err)
	}
	if err := unexpiredThrough(latest, delegation.GetExpiresAt().AsTime()); err != nil {
		return nil, nil, err
	}
	if err := r.clock.acceptTrust(root, delegation, update.GetDelegationEnvelope()); err != nil {
		return nil, nil, err
	}
	return root, delegation, nil
}

func (r *runner) reject(ctx context.Context, cause error, nonce []byte) error {
	now, _, err := r.now()
	if err != nil {
		return errors.Join(cause, err)
	}
	r.record.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED
	r.record.Failure = agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_PRECONDITION
	r.record.CompletedAt = timestamppb.New(now)
	if err := r.checkpoint(ctx, agentv1.RecoveryPhase_RECOVERY_PHASE_TERMINAL); err != nil {
		return errors.Join(cause, err)
	}
	return errors.Join(cause, r.report(ctx, nonce))
}

func (r *runner) unknown(ctx context.Context, cause error, nonce []byte) error {
	now, _, err := r.now()
	if err != nil {
		return errors.Join(cause, err)
	}
	r.record.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
	r.record.Failure = agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_AUTHORITY
	r.record.CompletedAt = timestamppb.New(now)
	if err := r.journal.Save(r.record); err != nil {
		return errors.Join(cause, err)
	}
	return errors.Join(cause, r.report(ctx, nonce))
}

func (r *runner) verifyStart(ctx context.Context, envelope []byte, intent *agentv1.DeviceActionIntent, challenge *agentv1.DeviceActionChallenge) (*agentv1.DeviceActionStartGrant, error) {
	now, _, err := r.now()
	if err != nil {
		return nil, err
	}
	grant, err := r.verifier.VerifyRecoveryStart(ctx, r.record.GetAcceptedRoot(), r.delegation, envelope, intent, challenge, r.credential, now)
	if err != nil {
		return nil, err
	}
	_, latest, err := r.now()
	if err != nil {
		return nil, err
	}
	if err := unexpiredThrough(latest, r.record.GetAcceptedRoot().GetExpiresAt().AsTime(), r.delegation.GetExpiresAt().AsTime(), r.credential.GetExpiresAt().AsTime(), intent.GetExpiresAt().AsTime(), challenge.GetExpiresAt().AsTime(), grant.GetExpiresAt().AsTime()); err != nil {
		return nil, err
	}
	return grant, nil
}
