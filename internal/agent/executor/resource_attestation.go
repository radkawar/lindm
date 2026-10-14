// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// AttestResourceExecution authenticates a protected snapshot, not a new native
// observation. The relay selects only an existing action and opaque nonce; all
// signed facts, identity, session and key material come from protected state.
func (s *Service) AttestResourceExecution(ctx context.Context, req *connect.Request[agentv1.AttestResourceExecutionRequest]) (*connect.Response[agentv1.AttestResourceExecutionResponse], error) {
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
	envelope, certificate, err := resourceAction.attest(ctx, s, loaded, req.Msg.GetActionId(), req.Msg.GetNonce(), func(h attestationHeader, record *agentv1.ResourceExecutionRecord) proto.Message {
		return &agentv1.ResourceExecutionAttestation{DeploymentId: h.deploymentID, DeviceId: h.deviceID, EnrollmentGeneration: h.generation, SessionEpoch: h.sessionEpoch, ActionRevision: h.revision, Nonce: h.nonce, IssuedAt: h.issued, ExpiresAt: h.expires, Status: resourceStatus(record)}
	})
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(&agentv1.AttestResourceExecutionResponse{AttestationEnvelope: envelope, CertificatePem: certificate}), nil
}
