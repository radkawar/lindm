//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	"lindm/internal/trust"
)

func (s *Service) verifyOfflineAuthorization(ctx context.Context, bootstrap *trust.Bootstrap, file *agentv1.OfflineEnrollmentAuthorizationFile, now time.Time) (*agentv1.OfflineEnrollmentAuthorization, error) {
	verifier, err := s.authority.NewExecutionVerifier(bootstrap)
	if err != nil {
		return nil, err
	}
	root, delegation, err := verifier.VerifyOfflineChain(ctx, bootstrap.Root, file.GetRootTransitions(), file.GetDelegationEnvelope(), now)
	if err != nil {
		return nil, err
	}
	return verifier.VerifyOfflineAuthorization(ctx, root, delegation, file.GetAuthorizationEnvelope(), now)
}

func (s *Service) enrollmentMaterial(ctx context.Context, loaded *bound, resumed bool) (*agentv1.PrepareBootstrapResponse, error) {
	result := bootstrapResponse(loaded, resumed)
	result.ProvisioningToken = loaded.state.GetProvisioningToken()
	csrDigest := sha256.Sum256(loaded.state.GetEnrollmentCsrPem())
	if result.ProvisioningToken {
		proof := &enrollmentv1.ProvisioningRetrieval{DeploymentId: result.GetDeploymentId(), TransactionId: result.GetEnrollmentTransactionId(), InstallationId: result.GetInstallationId(), CsrSha256: csrDigest[:]}
		encoded, err := s.authority.Sign(ctx, proof, loaded.identityKey)
		if err != nil {
			return nil, err
		}
		result.ProvisioningRetrievalProof = encoded
	}
	if file := loaded.state.GetOfflineAuthorization(); file != nil {
		authorization, err := s.verifyOfflineAuthorization(ctx, loaded.bootstrap, file, s.now())
		if err != nil {
			return nil, errBootstrapRejected
		}
		digest := sha256.Sum256(file.GetAuthorizationEnvelope())
		claim := &agentv1.OfflineEnrollmentRequestProof{DeploymentId: result.GetDeploymentId(), TransactionId: result.GetEnrollmentTransactionId(), InstallationId: result.GetInstallationId(), CsrSha256: csrDigest[:], AuthorizationSha256: digest[:], NotBefore: loaded.state.GetBootstrapVerifiedAt(), ExpiresAt: authorization.GetExpiresAt()}
		encoded, err := s.authority.Sign(ctx, claim, loaded.identityKey)
		if err != nil {
			return nil, err
		}
		result.OfflineRequest = &agentv1.OfflineEnrollmentRequestFile{Authorization: proto.CloneOf(file), CsrPem: bytes.Clone(result.GetCsrPem()), RequestProof: encoded}
	}
	return result, nil
}

func (s *Service) ImportOfflineEnrollment(ctx context.Context, request *connect.Request[agentv1.ImportOfflineEnrollmentRequest]) (*connect.Response[agentv1.ImportOfflineEnrollmentResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if request == nil {
		return nil, mapError(errInvalid)
	}
	if err := s.admit(request.Msg); err != nil {
		return nil, mapError(err)
	}
	if err := s.lock(ctx); err != nil {
		return nil, mapError(err)
	}
	defer s.mu.Unlock()
	loaded, err := s.load(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	if loaded.cert != nil {
		return nil, mapError(errAlreadyEnrolled)
	}
	if loaded.state.GetOfflineAuthorization() == nil {
		return nil, mapError(errCertificateRejected)
	}
	material, err := s.enrollmentMaterial(ctx, loaded, true)
	if err != nil {
		return nil, mapError(err)
	}
	expected := new(agentv1.OfflineEnrollmentRequestProof)
	if err := s.authority.Verify(ctx, material.GetOfflineRequest().GetRequestProof(), expected, 1, loaded.identityPublic); err != nil {
		return nil, mapError(errCertificateRejected)
	}
	verifier, err := s.authority.NewExecutionVerifier(loaded.bootstrap)
	if err != nil {
		return nil, mapError(errCertificateRejected)
	}
	file := request.Msg.GetResponse()
	root, delegation, err := verifier.VerifyOfflineChain(ctx, loaded.bootstrap.Root, file.GetRootTransitions(), file.GetDelegationEnvelope(), s.now())
	if err != nil {
		return nil, mapError(errCertificateRejected)
	}
	response, err := verifier.VerifyOfflineResponse(ctx, root, delegation, file.GetResponseEnvelope(), s.now())
	if err != nil || !proto.Equal(response.GetRequest(), expected) {
		return nil, mapError(errCertificateRejected)
	}
	authorization, err := s.verifyOfflineAuthorization(ctx, loaded.bootstrap, loaded.state.GetOfflineAuthorization(), s.now())
	if err != nil || root.GetVersion() < authorization.GetRootVersion() || delegation.GetVersion() < authorization.GetDelegationVersion() {
		return nil, mapError(errCertificateRejected)
	}
	installed, err := s.installEnrollmentLocked(ctx, loaded, &agentv1.InstallEnrollmentRequest{DeviceId: response.GetDeviceId(), EnrollmentGeneration: response.GetEnrollmentGeneration(), CertificatePem: response.GetCertificatePem()})
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(&agentv1.ImportOfflineEnrollmentResponse{Enrollment: installed}), nil
}
