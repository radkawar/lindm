//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/pem"
	"time"

	"connectrpc.com/connect"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// AttestServiceExecution authenticates a protected snapshot, not a new native
// observation. The relay selects only an existing action and opaque nonce; all
// signed facts, identity, session and key material come from protected state.
func (s *Service) AttestServiceExecution(ctx context.Context, req *connect.Request[agentv1.AttestServiceExecutionRequest]) (*connect.Response[agentv1.AttestServiceExecutionResponse], error) {
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
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	if err := s.serviceIdentitySession(loaded); err != nil {
		return nil, mapError(err)
	}
	record, revision, err := s.loadServiceAction(ctx, loaded, req.Msg.GetActionId())
	if err != nil {
		return nil, mapError(err)
	}
	if revision <= 0 {
		s.noteTrustDamage()
		return nil, mapError(errRecoveryHold)
	}
	// Historical validation can outlast the current credential. Recheck it at
	// issuance; an expired execution delegation does not invalidate history.
	now := s.now()
	if !certUsable(loaded.cert, now) {
		return nil, mapError(errIdentityExpired)
	}
	expires := now.Add(30 * time.Second)
	if loaded.cert.NotAfter.Before(expires) {
		expires = loaded.cert.NotAfter
	}
	attestation := &agentv1.ServiceExecutionAttestation{
		DeploymentId:         loaded.bootstrap.Root.GetDeploymentId(),
		DeviceId:             loaded.state.GetDeviceId(),
		EnrollmentGeneration: loaded.state.GetEnrollmentGeneration(),
		SessionEpoch:         loaded.state.GetSessionEpoch(),
		ActionRevision:       uint64(revision),
		Nonce:                bytes.Clone(req.Msg.GetNonce()),
		IssuedAt:             protoTimestamp(now), ExpiresAt: protoTimestamp(expires),
		Status: serviceStatus(record),
	}
	envelope, err := s.authority.Sign(ctx, attestation, loaded.identityKey)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(&agentv1.AttestServiceExecutionResponse{
		AttestationEnvelope: envelope,
		CertificatePem:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: loaded.cert.Raw}),
	}), nil
}
