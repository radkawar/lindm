// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"bytes"
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// Historical evidence is authenticated at its original acceptance times. Current
// revocations gate new effects, never rewrite the past or authorize replay.
func (s *Service) verifyDeviceActionRecord(ctx context.Context, loaded *bound, r *agentv1.DeviceActionRecord) error {
	if s.admit(r) != nil || r.GetInstallationId() != loaded.state.GetInstallationId() || !deviceActionTarget(loaded, r.GetIntent()) || !bytes.Equal(digestBytes(r.GetIntentEnvelope()), r.GetIntentSha256()) || !proto.Equal(r.GetIntent().GetSpec(), r.GetNativePlan().GetSpec()) || !r.GetNativePlan().GetBefore().GetSupported() || r.GetNativePlan().GetActionId() != r.GetIntent().GetActionId() {
		return errRecoveryHold
	}
	accepted := r.GetAcceptedAt().AsTime()
	delegation, err := loaded.execution.verifier.VerifyDelegation(ctx, r.GetAcceptedRoot(), r.GetAcceptedDelegationEnvelope(), 0, 0, accepted)
	if err != nil {
		return historicalResourceError(ctx)
	}
	intent, err := loaded.execution.verifier.VerifyDeviceActionIntent(ctx, r.GetAcceptedRoot(), delegation, r.GetIntentEnvelope(), accepted)
	if err != nil || !proto.Equal(intent, r.GetIntent()) {
		return historicalResourceError(ctx)
	}
	if err := s.verifyDeviceActionChallenge(ctx, loaded, r); err != nil {
		return err
	}
	if len(r.GetStartGrantEnvelope()) != 0 {
		if !bytes.Equal(digestBytes(r.GetStartGrantEnvelope()), r.GetStartGrantSha256()) || r.GetStartedAt() == nil || !proto.Equal(r.GetGrantAcceptedAt(), r.GetStartedAt()) {
			return errRecoveryHold
		}
		if _, err := loaded.execution.verifier.VerifyDeviceActionStart(ctx, r.GetAcceptedRoot(), delegation, r.GetStartGrantEnvelope(), intent, r.GetChallenge(), r.GetStartedAt().AsTime()); err != nil {
			return historicalResourceError(ctx)
		}
	}
	if err := s.verifyRecoveryBootHistory(ctx, loaded, r, delegation); err != nil {
		return err
	}
	if len(r.GetEscrowReceiptEnvelope()) != 0 {
		if r.GetReceiptRoot() == nil || r.GetEscrowConfirmedAt() == nil {
			return errRecoveryHold
		}
		receiptAt := r.GetEscrowConfirmedAt().AsTime()
		receiptDelegation, err := loaded.execution.verifier.VerifyDelegation(ctx, r.GetReceiptRoot(), r.GetReceiptDelegationEnvelope(), 0, 0, receiptAt)
		if err != nil {
			return historicalResourceError(ctx)
		}
		if _, err := loaded.execution.verifier.VerifyDeviceActionEscrowReceipt(ctx, r.GetReceiptRoot(), receiptDelegation, r.GetEscrowReceiptEnvelope(), r, receiptAt); err != nil {
			return historicalResourceError(ctx)
		}
	}
	return s.verifyInventoryRefreshHistory(ctx, loaded, r)
}

func (s *Service) verifyDeviceActionChallenge(ctx context.Context, loaded *bound, r *agentv1.DeviceActionRecord) error {
	c, i := r.GetChallenge(), r.GetIntent()
	planDigest, err := digestMessage(r.GetNativePlan())
	if err != nil || c.GetDeploymentId() != i.GetDeploymentId() || c.GetDeviceId() != i.GetDeviceId() || c.GetEnrollmentGeneration() != i.GetEnrollmentGeneration() || c.GetActionId() != i.GetActionId() || c.GetActionSequence() != i.GetActionSequence() || c.GetRecoveryEpoch() != i.GetRecoveryEpoch() || !bytes.Equal(c.GetIntentSha256(), r.GetIntentSha256()) || !bytes.Equal(c.GetSpecSha256(), i.GetSpecSha256()) || !bytes.Equal(c.GetNativePlanSha256(), planDigest) || !proto.Equal(c.GetNativePlan(), r.GetNativePlan()) || !proto.Equal(c.GetIssuedAt(), r.GetAcceptedAt()) {
		return errRecoveryHold
	}
	public, err := verifyChallengeCustody(ctx, s, loaded, r, new(agentv1.DeviceActionChallenge))
	if err != nil {
		return err
	}
	if len(r.GetHandoffProof()) != 0 {
		_, err := s.verifyRecoveryHandoff(ctx, r, public)
		return err
	}
	return nil
}

func (s *Service) loadDeviceAction(ctx context.Context, loaded *bound, actionID string) (*agentv1.DeviceActionRecord, int64, error) {
	return deviceAction.loadAction(ctx, s, loaded, actionID)
}

func (s *Service) updateDeviceAction(ctx context.Context, loaded *bound, revision int64, next *agentv1.DeviceActionRecord) error {
	return deviceAction.update(ctx, s, loaded, revision, next)
}

// AttestDeviceAction signs only protected historical facts with current device
// identity/session and the caller's fresh nonce. The relay cannot invent status.
func (s *Service) AttestDeviceAction(ctx context.Context, req *connect.Request[agentv1.AttestDeviceActionRequest]) (*connect.Response[agentv1.AttestDeviceActionResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil || s.admit(req.Msg) != nil {
		return nil, mapError(errInvalid)
	}
	if _, err := canonicalUUID(req.Msg.GetActionId()); err != nil {
		return nil, mapError(errInvalid)
	}
	if err := s.lock(ctx); err != nil {
		return nil, mapError(err)
	}
	defer s.mu.Unlock()
	if s.liveRoot != nil {
		return s.attestLiveRoot(ctx, req.Msg)
	}
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	envelope, certificate, err := deviceAction.attest(ctx, s, loaded, req.Msg.GetActionId(), req.Msg.GetNonce(), func(h attestationHeader, record *agentv1.DeviceActionRecord) proto.Message {
		return &agentv1.DeviceActionAttestation{DeploymentId: h.deploymentID, DeviceId: h.deviceID, EnrollmentGeneration: h.generation, SessionEpoch: h.sessionEpoch, ActionRevision: h.revision, Nonce: h.nonce, IssuedAt: h.issued, ExpiresAt: h.expires, Status: deviceActionStatus(record)}
	})
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(&agentv1.AttestDeviceActionResponse{AttestationEnvelope: envelope, CertificatePem: certificate}), nil
}
