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
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/pki"
	"lindm/internal/resource"
	"lindm/internal/trust"
)

// ResourceExecutionProbeUnit belongs exclusively to a disposable lab guest.
const ResourceExecutionProbeUnit = "lab-signed-service-proof.service"

func (f *ExecutionTrustExercise) Close() {
	if f == nil {
		return
	}
	clear(f.planKey)
	clear(f.startKey)
	f.planKey, f.startKey = nil, nil
}

// SignResourceIntent is deliberately limited to the sacrificial fixture resource
// and the exercise's second root/delegation. It is not a control-plane signer.
func (f *ExecutionTrustExercise) SignResourceIntent(ctx context.Context, intent *agentv1.ResourceExecutionIntent) ([]byte, error) {
	if f == nil || len(f.planKey) != ed25519.PrivateKeySize || intent.GetDeploymentId() != f.deploymentID || intent.GetRootVersion() != 2 || intent.GetDelegationVersion() != 2 || intent.GetRecoveryEpoch() != 1 || !fixtureResourceIntent(intent) {
		return nil, errors.New("resource intent is outside the disposable signing fixture")
	}
	return f.authority.Sign(ctx, intent, f.planKey)
}

// SignResourceStart authenticates the root-generated proof and exact native plan
// against the separately pinned development device CA before signing. The lab
// owner is the actor; this must never substitute for production reauthorization.
func (f *ExecutionTrustExercise) SignResourceStart(ctx context.Context, intent *agentv1.ResourceExecutionIntent, intentEnvelope, certificatePEM []byte, prepared *agentv1.PrepareResourceExecutionResponse) (*agentv1.ResourceExecutionStartGrant, []byte, error) {
	if f == nil || len(f.startKey) != ed25519.PrivateKeySize || intent.GetDeploymentId() != f.deploymentID || intent.GetRootVersion() != 2 || intent.GetDelegationVersion() != 2 || intent.GetRecoveryEpoch() != 1 || !fixtureResourceIntent(intent) {
		return nil, nil, errors.New("resource start is outside the disposable signing fixture")
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
	challenge := new(agentv1.ResourceExecutionChallenge)
	if err := f.authority.Verify(ctx, prepared.GetChallengeProof(), challenge, 1, public); err != nil {
		return nil, nil, err
	}
	planHash, err := resource.PlanDigest(prepared.GetNativePlan())
	if err != nil {
		return nil, nil, err
	}
	intentHash := sha256.Sum256(intentEnvelope)
	if challenge.GetDeploymentId() != intent.GetDeploymentId() || challenge.GetDeviceId() != intent.GetDeviceId() || challenge.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || challenge.GetActionId() != intent.GetActionId() || challenge.GetDesiredRevision() != intent.GetDesiredRevision() || challenge.GetResourceSequence() != intent.GetResourceSequence() || challenge.GetRecoveryEpoch() != intent.GetRecoveryEpoch() || !bytes.Equal(challenge.GetIntentSha256(), intentHash[:]) || !bytes.Equal(challenge.GetNativePlanSha256(), planHash[:]) || !proto.Equal(resource.PlanDesired(prepared.GetNativePlan()), intent.GetDesired()) || !resource.RefEqual(challenge.GetRef(), intent.GetDesired().GetRef()) || challenge.GetOperation() != intent.GetOperation() || prepared.GetNativePlan().GetOperation() != intent.GetOperation() {
		return nil, nil, errors.New("device challenge does not bind the requested intent and native plan")
	}
	if !serviceChallengeWindow(now, intent, challenge) {
		return nil, nil, errors.New("device challenge is outside the signing window")
	}
	grant := &agentv1.ResourceExecutionStartGrant{
		Challenge: challenge, ActorId: intent.GetActorId(), AuthorizationVersion: intent.GetAuthorizationVersion(), RootVersion: 2, DelegationVersion: 2,
		NotBefore: challenge.GetIssuedAt(), ExpiresAt: challenge.GetExpiresAt(),
	}
	envelope, err := f.authority.Sign(ctx, grant, f.startKey)
	return grant, envelope, err
}

func fixtureResourceIntent(intent *agentv1.ResourceExecutionIntent) bool {
	if resource.ValidateDesired(intent.GetDesired()) != nil {
		return false
	}
	if intent.GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE && intent.GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		return false
	}
	desired := intent.GetDesired()
	switch desired.GetRef().GetKind() {
	case resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE:
		return desired.GetSystemdService().GetUnit() == ResourceExecutionProbeUnit
	case resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE:
		pkg := desired.GetNativePackage().GetPackage()
		if pkg.GetNativeName() != "lindm-resource-proof" && pkg.GetNativeName() != "lindm-resource-crash" {
			return false
		}
		repository := desired.GetNativePackage().GetRepository().GetCanonicalKey()
		switch pkg.GetEcosystem() {
		case resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB:
			return pkg.GetArchitecture() == "amd64" && repository == "apt/d06a3d03-3118-4779-a00f-a5544ff095ad"
		case resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM:
			return pkg.GetArchitecture() == "x86_64" && repository == "rpm/d06a3d03-3118-4779-a00f-a5544ff095ad"
		}
	case resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE:
		switch desired.GetManagedFile().GetPath() {
		case "/etc/lindm-resource-lab/direct", "/etc/lindm-resource-lab/created", "/etc/lindm-resource-lab/adopted", "/etc/lindm-resource-lab/external":
			return true
		}
	}
	return false
}

func serviceChallengeWindow(now time.Time, intent *agentv1.ResourceExecutionIntent, challenge *agentv1.ResourceExecutionChallenge) bool {
	issued, expires := challenge.GetIssuedAt().AsTime(), challenge.GetExpiresAt().AsTime()
	notBefore, intentExpires := intent.GetNotBefore().AsTime(), intent.GetExpiresAt().AsTime()
	// Guest timestamps use the production tolerance. The host-issued intent
	// remains valid on host time; tolerance never extends its authority window.
	return !issued.After(now.Add(trust.MaxDeviceClockSkew)) &&
		now.Add(-trust.MaxDeviceClockSkew).Before(expires) &&
		!now.Before(notBefore) && now.Before(intentExpires) &&
		!issued.Before(notBefore) && !expires.After(intentExpires)
}

// VerifyResourceAttestation uses the fixture's independently pinned device CA,
// never trust supplied by the relay. Close removes signing keys but deliberately
// retains this public verifier for the reboot/reinstall history checks.
// A verified receipt authenticates retained history, not current compliance.
func (f *ExecutionTrustExercise) VerifyResourceAttestation(ctx context.Context, envelope, certificatePEM []byte, expected *trust.ResourceAttestationBinding, now time.Time) (*agentv1.ResourceExecutionAttestation, error) {
	if f == nil || f.authority == nil || expected == nil || expected.DeploymentID.String() != f.deploymentID {
		return nil, errors.New("service attestation is outside the disposable verification fixture")
	}
	return f.authority.VerifyResourceAttestation(ctx, envelope, certificatePEM, f.deviceCA, expected, now, trust.MaxDeviceClockSkew)
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
