package resource

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

func serviceEvidence(t *testing.T) (*resourcev1.ResourceDesiredState, *resourcev1.ResourceObservation, *resourcev1.ResourcePlan) {
	t.Helper()
	desired := desiredJSON(t, `{"systemdService":{"unit":"example.service","runtime":2,"enablement":1}}`)
	observedAt := timestamppb.New(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	backend := &resourcev1.BackendSelection{
		Backend:         resourcev1.Backend_BACKEND_SYSTEMD,
		NativeVersion:   "257",
		ProviderVersion: "1",
		Product:         &resourcev1.PlatformProduct{OsId: "debian", Product: "debian", Version: "13", Architecture: "amd64"},
	}
	service := &resourcev1.SystemdServiceObservation{
		Unit: "example.service", BootId: fixtureID, ObservedAt: observedAt,
		LoadState: "loaded", ActiveState: "active", SubState: "running", UnitFileState: "enabled", ServiceType: "simple",
		DefinitionSha256: make([]byte, 32), FingerprintSha256: make([]byte, 32),
	}
	observation := &resourcev1.ResourceObservation{
		Ref: proto.CloneOf(desired.GetRef()),
		Metadata: &resourcev1.ObservationMetadata{
			BootId: fixtureID, ExecutorIncarnation: fixtureGeneration, ObservedAt: observedAt,
			Backend: backend, NativeRevision: make([]byte, 32), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK,
		},
		Observed: &resourcev1.ResourceObservation_SystemdService{SystemdService: service},
	}
	digest, err := DesiredDigest(desired)
	if err != nil {
		t.Fatal(err)
	}
	plan := &resourcev1.ResourcePlan{
		Ref: proto.CloneOf(desired.GetRef()), Operation: resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE,
		DesiredSha256: digest[:], ObservationSha256: make([]byte, 32), Backend: backend,
		OwnershipRevisionSha256: make([]byte, 32),
		Safety: &resourcev1.PlanSafety{
			LockDomains:   []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_SERVICE_RUNTIME},
			Reversibility: resourcev1.Reversibility_REVERSIBILITY_REVERSIBLE,
			RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_OWNED_DIMENSIONS,
			Confirmation:  resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_NOT_REQUIRED,
		},
		Plan: &resourcev1.ResourcePlan_SystemdService{SystemdService: &resourcev1.SystemdServicePlan{Desired: desired.GetSystemdService(), Before: service}},
	}
	return desired, observation, plan
}

func TestEvidenceBindsDesiredObservationAndFreshConvergence(t *testing.T) {
	_, observation, plan := serviceEvidence(t)
	if err := ValidateObservation(observation); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlan(plan); err != nil {
		t.Fatal(err)
	}
	verification := &resourcev1.ResourceVerification{
		Ref: observation.GetRef(), DesiredSha256: plan.GetDesiredSha256(), PlanSha256: make([]byte, 32), After: observation,
		Disposition: resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED,
		Checks: &resourcev1.ResourceVerification_SystemdService{SystemdService: &resourcev1.SystemdServiceChecks{
			Observation: observation.GetSystemdService(), RuntimeMatches: true, EnablementMatches: true,
			DefinitionMatches: true, Converged: true, JobCompleted: true,
		}},
	}
	if err := ValidateVerification(verification); err != nil {
		t.Fatal(err)
	}
	verification.GetAfter().Metadata.ObservationStatus = resourcev1.ObservationStatus_OBSERVATION_STATUS_UNAVAILABLE
	if err := ValidateVerification(verification); err == nil {
		t.Fatal("unavailable observation became converged")
	}
	verification.GetAfter().Metadata.ObservationStatus = resourcev1.ObservationStatus_OBSERVATION_STATUS_OK
	verification.GetSystemdService().JobCompleted = false
	if err := ValidateVerification(verification); err == nil {
		t.Fatal("pending native job became converged")
	}
	plan.DesiredSha256[0] ^= 1
	if err := ValidatePlan(plan); err == nil {
		t.Fatal("plan with substituted desired digest accepted")
	}
}

func TestReleaseRequiresLedgerBoundInverse(t *testing.T) {
	_, _, plan := serviceEvidence(t)
	plan.Operation = resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE
	if err := ValidatePlan(plan); err == nil {
		t.Fatal("release without a ledger-bound inverse accepted")
	}
	plan.GetSystemdService().Inverse = &resourcev1.OwnershipInverseBinding{
		LedgerRevisionSha256: make([]byte, 32), LastAppliedSha256: make([]byte, 32),
		NativeIdentitySha256: make([]byte, 32), InverseSha256: make([]byte, 32),
	}
	if err := ValidatePlan(plan); err != nil {
		t.Fatal(err)
	}
	plan.GetSystemdService().Inverse.LedgerRevisionSha256[0] = 1
	if err := ValidatePlan(plan); err == nil {
		t.Fatal("inverse from another ledger revision accepted")
	}
}

func TestObservationAndPlanRejectCrossKindSubstitution(t *testing.T) {
	_, observation, plan := serviceEvidence(t)
	observation.Ref.Kind = resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP
	if err := ValidateObservation(observation); err == nil {
		t.Fatal("observation kind/arm mismatch accepted")
	}
	plan.Ref.CanonicalKey = "other.service"
	if err := ValidatePlan(plan); err == nil {
		t.Fatal("plan ref/desired mismatch accepted")
	}
}
