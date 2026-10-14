// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// Recovery proof diagnostics are disclosed only after signature verification.
var (
	ErrRecoveryRequestPayloadMismatch = errors.New("recovery_request_payload_mismatch")
	ErrRecoveryRequestClockAhead      = errors.New("recovery_request_clock_ahead")
	ErrRecoveryRequestExpired         = errors.New("recovery_request_expired")
)

// RecoveryPlanDigest removes only observation time and execution placement from
// the frozen plan. Media identity, controller scope, metadata and policy stay
// byte-bound across the original and recovery boots.
func RecoveryPlanDigest(plan *agentv1.DeviceActionPlan) ([32]byte, error) {
	if plan == nil || plan.GetBefore() == nil {
		return [32]byte{}, errors.New("missing recovery native plan")
	}
	canonical := proto.CloneOf(plan)
	canonical.Before.ObservedAt = nil
	canonical.Before.RecoveryEnvironment = false
	canonical.Before.OffTargetJournal = false
	return DeviceActionDigest(canonical)
}

func (a *Authority) validateRecoveryHandoff(handoff *agentv1.DeviceActionRecoveryHandoff) error {
	if err := a.validateExecutionMessage(handoff); err != nil {
		return err
	}
	intent, challenge := handoff.GetIntent(), handoff.GetChallenge()
	if challenge.GetBootId() != handoff.GetOriginalBootId() || challenge.GetDeploymentId() != intent.GetDeploymentId() || challenge.GetDeviceId() != intent.GetDeviceId() || challenge.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || challenge.GetActionId() != intent.GetActionId() || challenge.GetActionSequence() != intent.GetActionSequence() || challenge.GetRecoveryEpoch() != intent.GetRecoveryEpoch() || !bytes.Equal(challenge.GetIntentSha256(), handoff.GetIntentSha256()) || !bytes.Equal(challenge.GetSpecSha256(), intent.GetSpecSha256()) || !proto.Equal(challenge.GetNativePlan().GetSpec(), intent.GetSpec()) || challenge.GetNativePlan().GetActionId() != intent.GetActionId() {
		return errors.New("recovery handoff identity or challenge rejected")
	}
	media, err := DeviceActionDigest(intent.GetSpec().GetSanitize().GetTarget())
	if err != nil || !bytes.Equal(media[:], handoff.GetMediaSha256()) {
		return errors.New("recovery handoff media digest rejected")
	}
	plan, err := RecoveryPlanDigest(challenge.GetNativePlan())
	if err != nil || !bytes.Equal(plan[:], handoff.GetNativePlanSha256()) {
		return errors.New("recovery handoff native plan rejected")
	}
	rawPlan, err := DeviceActionDigest(challenge.GetNativePlan())
	if err != nil || !bytes.Equal(rawPlan[:], challenge.GetNativePlanSha256()) {
		return errors.New("recovery handoff challenge plan rejected")
	}
	spec, err := DeviceActionDigest(intent.GetSpec())
	if err != nil || !bytes.Equal(spec[:], intent.GetSpecSha256()) {
		return errors.New("recovery handoff action spec rejected")
	}
	return nil
}

// VerifyDeviceActionRecoveryHandoff authenticates the original device identity
// and exact retained intent. It grants neither reboot nor storage destruction.
func (a *Authority) VerifyDeviceActionRecoveryHandoff(ctx context.Context, envelope, certificatePEM []byte, deviceCA *x509.Certificate, expectedIntent *agentv1.DeviceActionIntent, intentSHA256 [32]byte, now time.Time, clockSkew time.Duration) (*agentv1.DeviceActionRecoveryHandoff, error) {
	if clockSkew < 0 || expectedIntent == nil || len(envelope) == 0 || len(envelope) > 65536 {
		return nil, errors.New("invalid recovery handoff input")
	}
	deployment, err := uuid.Parse(expectedIntent.GetDeploymentId())
	if err != nil || deployment == uuid.Nil {
		return nil, errors.New("invalid recovery deployment")
	}
	device, err := uuid.Parse(expectedIntent.GetDeviceId())
	if err != nil || device == uuid.Nil {
		return nil, errors.New("invalid recovery device")
	}
	generation, err := uuid.Parse(expectedIntent.GetEnrollmentGeneration())
	if err != nil || generation == uuid.Nil {
		return nil, errors.New("invalid recovery generation")
	}
	cert, public, err := verifyDeviceProofCertificate(certificatePEM, deviceCA, deployment, device, generation, now)
	if err != nil {
		return nil, err
	}
	handoff := new(agentv1.DeviceActionRecoveryHandoff)
	if err := a.Verify(ctx, envelope, handoff, 1, public); err != nil {
		return nil, err
	}
	if err := a.validateRecoveryHandoff(handoff); err != nil {
		return nil, err
	}
	if !proto.Equal(handoff.GetIntent(), expectedIntent) || !bytes.Equal(handoff.GetIntentSha256(), intentSHA256[:]) {
		return nil, errors.New("recovery handoff intent rejected")
	}
	challenge := handoff.GetChallenge()
	if challenge.GetIssuedAt().AsTime().After(now.Add(clockSkew)) || !now.Add(-clockSkew).Before(challenge.GetExpiresAt().AsTime()) {
		return nil, ErrDeviceClockSkew
	}
	if !now.Before(handoff.GetExpiresAt().AsTime()) || handoff.GetExpiresAt().AsTime().After(cert.NotAfter) {
		return nil, errors.New("recovery handoff validity rejected")
	}
	return handoff, nil
}

// VerifyDeviceActionRecoveryCredential authenticates the purpose-limited online
// credential against current trust and an independently authenticated handoff.
func (v *ExecutionVerifier) VerifyDeviceActionRecoveryCredential(ctx context.Context, root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, envelope []byte, handoff *agentv1.DeviceActionRecoveryHandoff, now time.Time) (*agentv1.DeviceActionRecoveryCredential, error) {
	keys, err := v.capabilityKeys(root, delegation, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, "device.sanitize.v1", now)
	if err != nil {
		return nil, err
	}
	if err := v.authority.validateRecoveryHandoff(handoff); err != nil {
		return nil, err
	}
	if len(envelope) == 0 || len(envelope) > 65536 {
		return nil, errors.New("invalid recovery credential size")
	}
	credential := new(agentv1.DeviceActionRecoveryCredential)
	if err := v.authority.Verify(ctx, envelope, credential, 1, keys...); err != nil {
		return nil, err
	}
	if !proto.Equal(credential.GetHandoff(), handoff) || handoff.GetIntent().GetDeploymentId() != v.deploymentID || credential.GetRootVersion() != root.GetVersion() || credential.GetDelegationVersion() != delegation.GetVersion() || handoff.GetIntent().GetRecoveryEpoch() < delegation.GetMinimumRecoveryEpoch() {
		return nil, errors.New("recovery credential binding rejected")
	}
	if !validServiceInterval(now, credential.GetIssuedAt().AsTime(), credential.GetExpiresAt().AsTime(), delegation.GetNotBefore().AsTime(), delegation.GetExpiresAt().AsTime()) {
		return nil, errors.New("recovery credential validity rejected")
	}
	return credential, nil
}

// VerifyDeviceActionRecoveryBoot checks a fresh two-human BOOT grant. Its domain
// and full handoff digest prevent use as either an ordinary or recovery erase.
func (v *ExecutionVerifier) VerifyDeviceActionRecoveryBoot(ctx context.Context, root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, envelope []byte, handoff *agentv1.DeviceActionRecoveryHandoff, now time.Time) (*agentv1.DeviceActionRecoveryBootGrant, error) {
	keys, err := v.capabilityKeys(root, delegation, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, "device.sanitize.v1", now)
	if err != nil {
		return nil, err
	}
	if err := v.authority.validateRecoveryHandoff(handoff); err != nil {
		return nil, err
	}
	if len(envelope) == 0 || len(envelope) > 65536 {
		return nil, errors.New("invalid recovery boot grant size")
	}
	boot := new(agentv1.DeviceActionRecoveryBootGrant)
	if err := v.authority.Verify(ctx, envelope, boot, 1, keys...); err != nil {
		return nil, err
	}
	digest, err := DeviceActionDigest(handoff)
	if err != nil || !bytes.Equal(digest[:], boot.GetHandoffSha256()) {
		return nil, errors.New("recovery boot handoff substitution rejected")
	}
	if _, err := v.verifyDeviceActionGrant(root, delegation, handoff.GetIntent(), handoff.GetChallenge(), boot.GetGrant(), now, actionRecoveryBoot); err != nil {
		return nil, err
	}
	return boot, nil
}

// VerifyRecoveryStart accepts only a fresh recovery-boot grant for the original
// frozen media and plan. The credential must already be signature-verified.
func (v *ExecutionVerifier) VerifyRecoveryStart(ctx context.Context, root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, envelope []byte, intent *agentv1.DeviceActionIntent, challenge *agentv1.DeviceActionChallenge, credential *agentv1.DeviceActionRecoveryCredential, now time.Time) (*agentv1.DeviceActionStartGrant, error) {
	keys, err := v.capabilityKeys(root, delegation, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, "device.sanitize.v1", now)
	if err != nil {
		return nil, err
	}
	if err := v.authority.validateExecutionMessage(credential); err != nil {
		return nil, err
	}
	handoff := credential.GetHandoff()
	if err := v.authority.validateRecoveryHandoff(handoff); err != nil {
		return nil, err
	}
	if !proto.Equal(intent, handoff.GetIntent()) || challenge.GetBootId() == handoff.GetOriginalBootId() || challenge.GetExecutorIncarnation() == handoff.GetChallenge().GetExecutorIncarnation() || !bytes.Equal(challenge.GetIntentSha256(), handoff.GetIntentSha256()) || !now.Before(credential.GetExpiresAt().AsTime()) || now.Before(credential.GetIssuedAt().AsTime()) || credential.GetRootVersion() != root.GetVersion() || credential.GetDelegationVersion() != delegation.GetVersion() {
		return nil, errors.New("recovery start credential or boot binding rejected")
	}
	digest, err := RecoveryPlanDigest(challenge.GetNativePlan())
	if err != nil || !bytes.Equal(digest[:], handoff.GetNativePlanSha256()) {
		return nil, errors.New("recovery start native plan changed")
	}
	if len(envelope) == 0 || len(envelope) > 65536 {
		return nil, errors.New("invalid recovery start size")
	}
	grant := new(agentv1.DeviceActionStartGrant)
	if err := v.authority.Verify(ctx, envelope, grant, 1, keys...); err != nil {
		return nil, err
	}
	return v.verifyDeviceActionGrant(root, delegation, intent, challenge, grant, now, actionRecoveryEffect)
}

// VerifyRecoveryCheckpointReceipt authenticates durable server acknowledgment;
// the runtime still must persist the receipt and refuse repeated consumption.
func (v *ExecutionVerifier) VerifyRecoveryCheckpointReceipt(ctx context.Context, root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, envelope []byte, checkpoint *agentv1.RecoveryCheckpoint, now time.Time) (*agentv1.RecoveryCheckpointReceipt, error) {
	keys, err := v.capabilityKeys(root, delegation, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, "device.sanitize.v1", now)
	if err != nil {
		return nil, err
	}
	if err := v.authority.validateExecutionMessage(checkpoint); err != nil {
		return nil, err
	}
	if len(envelope) == 0 || len(envelope) > 16384 {
		return nil, errors.New("invalid recovery checkpoint receipt size")
	}
	receipt := new(agentv1.RecoveryCheckpointReceipt)
	if err := v.authority.Verify(ctx, envelope, receipt, 1, keys...); err != nil {
		return nil, err
	}
	digest, err := DeviceActionDigest(checkpoint)
	if err != nil {
		return nil, err
	}
	if receipt.GetCredentialId() != checkpoint.GetCredentialId() || receipt.GetActionId() != checkpoint.GetActionId() || receipt.GetSequence() != checkpoint.GetSequence() || !bytes.Equal(receipt.GetCheckpointSha256(), digest[:]) || receipt.GetRootVersion() != root.GetVersion() || receipt.GetDelegationVersion() != delegation.GetVersion() {
		return nil, errors.New("recovery checkpoint receipt binding rejected")
	}
	if stored := receipt.GetStoredAt().AsTime(); stored.After(now) {
		return nil, fmt.Errorf("recovery_checkpoint_clock_behind: signed_stored_at=%s observed_at=%s", stored.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano))
	}
	return receipt, nil
}

// VerifyRecoveryRequestProof authenticates a fresh purpose-separated request.
// The caller supplies an independently authenticated retained credential and a
// typed request with envelope/proof fields cleared, then transactionally consumes
// the returned RequestId/Nonce and enforces credential lifecycle (including the
// stricter unexpired-credential requirement before any new effect).
func (a *Authority) VerifyRecoveryRequestProof(ctx context.Context, envelope, credentialEnvelope []byte, credential *agentv1.DeviceActionRecoveryCredential, operation agentv1.RecoveryOperation, payload proto.Message, now time.Time) (*agentv1.RecoveryRequestProof, error) {
	if credential == nil || operation == agentv1.RecoveryOperation_RECOVERY_OPERATION_UNSPECIFIED || len(envelope) == 0 || len(envelope) > 16384 {
		return nil, errors.New("invalid recovery request input")
	}
	if err := a.validateExecutionMessage(credential); err != nil {
		return nil, err
	}
	proof := new(agentv1.RecoveryRequestProof)
	if err := a.Verify(ctx, envelope, proof, 1, ed25519.PublicKey(credential.GetHandoff().GetRecoveryPublicKey())); err != nil {
		return nil, err
	}
	credentialDigest := sha256.Sum256(credentialEnvelope)
	payloadDigest, err := DeviceActionDigest(payload)
	if err != nil {
		return nil, err
	}
	if proof.GetCredentialId() != credential.GetCredentialId() || !bytes.Equal(proof.GetCredentialSha256(), credentialDigest[:]) || proof.GetOperation() != operation || proof.GetBootId() == credential.GetHandoff().GetOriginalBootId() || proof.GetExecutorIncarnation() == credential.GetHandoff().GetChallenge().GetExecutorIncarnation() {
		return nil, errors.New("recovery request binding rejected")
	}
	if !bytes.Equal(proof.GetPayloadSha256(), payloadDigest[:]) {
		return nil, ErrRecoveryRequestPayloadMismatch
	}
	if now.Before(proof.GetIssuedAt().AsTime()) {
		return nil, ErrRecoveryRequestClockAhead
	}
	if !now.Before(proof.GetExpiresAt().AsTime()) {
		return nil, ErrRecoveryRequestExpired
	}
	return proof, nil
}
