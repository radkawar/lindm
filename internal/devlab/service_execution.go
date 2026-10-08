package devlab

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/pki"
)

// ServiceExecutionProbeUnit belongs exclusively to a disposable lab guest.
const ServiceExecutionProbeUnit = "lab-signed-service-proof.service"

func (f *ExecutionTrustExercise) Close() {
	if f == nil {
		return
	}
	clear(f.planKey)
	clear(f.startKey)
	f.planKey, f.startKey = nil, nil
}

// SignServiceIntent is deliberately limited to the sacrificial fixture resource
// and the exercise's second root/delegation. It is not a control-plane signer.
func (f *ExecutionTrustExercise) SignServiceIntent(ctx context.Context, intent *agentv1.ServiceExecutionIntent) ([]byte, error) {
	if f == nil || len(f.planKey) != ed25519.PrivateKeySize || intent.GetDeploymentId() != f.deploymentID || intent.GetRootVersion() != 2 || intent.GetDelegationVersion() != 2 || intent.GetRecoveryEpoch() != 1 || intent.GetDesired().GetUnit() != ServiceExecutionProbeUnit {
		return nil, errors.New("service intent is outside the disposable signing fixture")
	}
	return f.authority.Sign(ctx, intent, f.planKey)
}

// SignServiceStart authenticates the root-generated proof and exact native plan
// against the separately pinned development device CA before signing. The lab
// owner is the actor; this must never substitute for production reauthorization.
func (f *ExecutionTrustExercise) SignServiceStart(ctx context.Context, intent *agentv1.ServiceExecutionIntent, intentEnvelope, certificatePEM []byte, prepared *agentv1.PrepareServiceExecutionResponse) (*agentv1.ServiceExecutionStartGrant, []byte, error) {
	if f == nil || len(f.startKey) != ed25519.PrivateKeySize || intent.GetDeploymentId() != f.deploymentID || intent.GetRootVersion() != 2 || intent.GetDelegationVersion() != 2 || intent.GetDesired().GetUnit() != ServiceExecutionProbeUnit {
		return nil, nil, errors.New("service start is outside the disposable signing fixture")
	}
	certificate, err := serviceExerciseCertificate(certificatePEM)
	if err != nil {
		return nil, nil, err
	}
	public, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, nil, errors.New("device challenge certificate is not Ed25519")
	}
	deployment, err := uuid.Parse(intent.GetDeploymentId())
	if err != nil {
		return nil, nil, err
	}
	device, err := uuid.Parse(intent.GetDeviceId())
	if err != nil {
		return nil, nil, err
	}
	generation, err := uuid.Parse(intent.GetEnrollmentGeneration())
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	if _, err := pki.VerifyDeviceCertificatePEM(certificatePEM, public, f.deviceCA, deployment, device, generation, now); err != nil {
		return nil, nil, err
	}
	challenge := new(agentv1.ServiceExecutionChallenge)
	if err := f.authority.Verify(ctx, prepared.GetChallengeProof(), challenge, 1, public); err != nil {
		return nil, nil, err
	}
	encodedPlan, err := proto.MarshalOptions{Deterministic: true}.Marshal(prepared.GetNativePlan())
	if err != nil {
		return nil, nil, err
	}
	planHash, intentHash := sha256.Sum256(encodedPlan), sha256.Sum256(intentEnvelope)
	if challenge.GetDeploymentId() != intent.GetDeploymentId() || challenge.GetDeviceId() != intent.GetDeviceId() || challenge.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || challenge.GetActionId() != intent.GetActionId() || challenge.GetDesiredRevision() != intent.GetDesiredRevision() || challenge.GetResourceSequence() != intent.GetResourceSequence() || challenge.GetRecoveryEpoch() != intent.GetRecoveryEpoch() || !bytes.Equal(challenge.GetIntentSha256(), intentHash[:]) || !bytes.Equal(challenge.GetNativePlanSha256(), planHash[:]) || !proto.Equal(prepared.GetNativePlan().GetDesired(), intent.GetDesired()) {
		return nil, nil, errors.New("device challenge does not bind the requested intent and native plan")
	}
	if now.Before(challenge.GetIssuedAt().AsTime()) || !now.Before(challenge.GetExpiresAt().AsTime()) || challenge.GetIssuedAt().AsTime().Before(intent.GetNotBefore().AsTime()) || challenge.GetExpiresAt().AsTime().After(intent.GetExpiresAt().AsTime()) {
		return nil, nil, errors.New("device challenge is outside the signing window")
	}
	grant := &agentv1.ServiceExecutionStartGrant{
		Challenge: challenge, ActorId: intent.GetActorId(), AuthorizationVersion: intent.GetAuthorizationVersion(), RootVersion: 2, DelegationVersion: 2,
		NotBefore: challenge.GetIssuedAt(), ExpiresAt: challenge.GetExpiresAt(),
	}
	envelope, err := f.authority.Sign(ctx, grant, f.startKey)
	return grant, envelope, err
}

func serviceExerciseCertificate(encoded []byte) (*x509.Certificate, error) {
	if len(encoded) == 0 || len(encoded) > 16384 {
		return nil, errors.New("invalid fixture certificate size")
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one fixture certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}
