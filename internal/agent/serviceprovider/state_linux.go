//go:build linux

package serviceprovider

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sync"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/protodata"
	"lindm/internal/resource"
)

var validator = sync.OnceValues(func() (protovalidate.Validator, error) {
	return protovalidate.New(protovalidate.WithMessages(
		&resourcev1.SystemdServiceDesired{}, &resourcev1.SystemdServiceObservation{},
		&resourcev1.ResourcePlan{}, &resourcev1.ResourceVerification{},
		&agentv1.ResourceOwnershipBinding{},
	), protovalidate.WithDisableLazy())
})

func validateMessage(message proto.Message) error {
	if message == nil || !message.ProtoReflect().IsValid() {
		return fmt.Errorf("%w: absent service message", ErrUnsupported)
	}
	if err := protodata.ValidateClosed(message.ProtoReflect()); err != nil {
		return fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	v, err := validator()
	if err != nil {
		return err
	}
	if err := v.Validate(message); err != nil {
		return fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	return nil
}

func validateUnit(unit string) error {
	return validateMessage(&resourcev1.SystemdServiceDesired{
		Unit:       unit,
		Runtime:    resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE,
		Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED,
	})
}

// fingerprint hashes the entire closed observation except its timestamp and the
// fingerprint itself. New native preconditions must become observation fields.
func fingerprint(observation *resourcev1.SystemdServiceObservation) []byte {
	bound := proto.CloneOf(observation)
	bound.ObservedAt = nil
	bound.FingerprintSha256 = nil
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(bound)
	if err != nil {
		// All fields have primitive/timestamp types and no required wire fields.
		// Invalid UTF-8 remains an input error, never an empty valid fingerprint.
		return nil
	}
	digest := sha256.Sum256(encoded)
	return digest[:]
}

func supportedObservation(o *resourcev1.SystemdServiceObservation) error {
	if o.GetLoadState() != "loaded" || o.GetTransient() || o.GetNeedDaemonReload() {
		return fmt.Errorf("%w: unit must be loaded, persistent and not need daemon reload", ErrUnsupported)
	}
	if o.GetJobPending() {
		return fmt.Errorf("%w: unit has a pending job", ErrConflict)
	}
	switch o.GetActiveState() {
	case "activating", "deactivating", "reloading", "refreshing":
		return fmt.Errorf("%w: unit is %s", ErrConflict, o.GetActiveState())
	case "inactive":
		if o.GetSubState() != "dead" {
			return fmt.Errorf("%w: inactive substate %q", ErrUnsupported, o.GetSubState())
		}
	case "active":
		if o.GetSubState() != "running" && (o.GetSubState() != "exited" || !o.GetRemainAfterExit()) {
			return fmt.Errorf("%w: active substate %q", ErrUnsupported, o.GetSubState())
		}
	default:
		return fmt.Errorf("%w: active state %q", ErrUnsupported, o.GetActiveState())
	}
	switch o.GetServiceType() {
	case "simple", "exec", "forking", "oneshot", "dbus", "notify", "notify-reload", "idle":
	default:
		return fmt.Errorf("%w: service type %q", ErrUnsupported, o.GetServiceType())
	}
	switch o.GetUnitFileState() {
	case "enabled", "disabled", "static", "indirect":
	default:
		return fmt.Errorf("%w: unit file state %q", ErrUnsupported, o.GetUnitFileState())
	}
	return nil
}

func drift(desired *resourcev1.SystemdServiceDesired, before *resourcev1.SystemdServiceObservation) (runtime, enablement bool, err error) {
	if desired.GetUnit() != before.GetUnit() {
		return false, false, fmt.Errorf("%w: plan unit mismatch", ErrConflict)
	}
	if err := supportedObservation(before); err != nil {
		return false, false, err
	}
	switch desired.GetRuntime() {
	case resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_UNMANAGED:
	case resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE:
		if before.GetServiceType() == "oneshot" && !before.GetRemainAfterExit() {
			return false, false, fmt.Errorf("%w: nonpersistent oneshot cannot promise active", ErrUnsupported)
		}
		runtime = before.GetActiveState() != "active"
		if runtime && before.GetRefuseManualStart() {
			return false, false, fmt.Errorf("%w: RefuseManualStart", ErrUnsupported)
		}
	case resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE:
		runtime = before.GetActiveState() != "inactive"
		if runtime && before.GetRefuseManualStop() {
			return false, false, fmt.Errorf("%w: RefuseManualStop", ErrUnsupported)
		}
	default:
		return false, false, fmt.Errorf("%w: unknown desired runtime", ErrUnsupported)
	}
	switch desired.GetEnablement() {
	case resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED:
	case resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED, resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_DISABLED:
		if before.GetUnitFileState() != "enabled" && before.GetUnitFileState() != "disabled" {
			return false, false, fmt.Errorf("%w: cannot manage enablement %q", ErrUnsupported, before.GetUnitFileState())
		}
		enablement = !enablementMatches(desired, before)
	default:
		return false, false, fmt.Errorf("%w: unknown desired enablement", ErrUnsupported)
	}
	return runtime, enablement, nil
}

func planFor(desired *resourcev1.ResourceDesiredState, before *resourcev1.ResourceObservation, ownershipRevision []byte) (*resourcev1.ResourcePlan, error) {
	if err := resource.ValidateDesired(desired); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	if desired.GetSystemdService() == nil {
		return nil, fmt.Errorf("%w: non-systemd resource", ErrUnsupported)
	}
	if err := resource.ValidateObservation(before); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	runtime, enablement, err := drift(desired.GetSystemdService(), before.GetSystemdService())
	if err != nil {
		return nil, err
	}
	desiredDigest, err := resource.DesiredDigest(desired)
	if err != nil {
		return nil, err
	}
	observationDigest, err := resource.ObservationDigest(before)
	if err != nil {
		return nil, err
	}
	claims, err := resource.Claims(desired)
	if err != nil {
		return nil, err
	}
	plan := &resourcev1.ResourcePlan{
		Ref:           proto.CloneOf(desired.GetRef()),
		Operation:     resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE,
		DesiredSha256: desiredDigest[:], ObservationSha256: observationDigest[:],
		Backend: proto.CloneOf(before.GetMetadata().GetBackend()),
		Claims:  claims, OwnershipRevisionSha256: bytes.Clone(ownershipRevision),
		Before: before,
		Safety: serviceSafety(),
		Plan: &resourcev1.ResourcePlan_SystemdService{SystemdService: &resourcev1.SystemdServicePlan{
			Desired: proto.CloneOf(desired.GetSystemdService()), Before: before.GetSystemdService(),
			ChangeRuntime: runtime, ChangeEnablement: enablement,
		}},
	}
	if err := ValidatePlan(plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func serviceSafety() *resourcev1.PlanSafety {
	return &resourcev1.PlanSafety{
		LockDomains:   []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_SERVICE_RUNTIME},
		Reversibility: resourcev1.Reversibility_REVERSIBILITY_IRREVERSIBLE,
		RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_NONE,
		Confirmation:  resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_NOT_REQUIRED,
	}
}

// ValidatePlan checks closed schema, native support, observation fingerprint and
// recomputed drift. It establishes evidence consistency, not execution authority.
func ValidatePlan(plan *resourcev1.ResourcePlan) error {
	if err := resource.ValidatePlan(plan); err != nil {
		return fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	if plan.GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE {
		return ErrBaselineUnknown
	}
	native := plan.GetSystemdService()
	if native == nil || native.GetInverse() != nil || len(native.GetInstallProjection()) != 0 || len(native.GetRelatedUnits()) != 0 ||
		!proto.Equal(plan.GetSafety(), serviceSafety()) || plan.GetBackend().GetBackend() != resourcev1.Backend_BACKEND_SYSTEMD {
		return fmt.Errorf("%w: unsupported systemd plan", ErrUnsupported)
	}
	if err := resource.ValidateObservation(plan.GetBefore()); err != nil {
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
	if !proto.Equal(plan.GetBefore().GetSystemdService(), native.GetBefore()) ||
		!proto.Equal(plan.GetBefore().GetMetadata().GetBackend(), plan.GetBackend()) ||
		!bytes.Equal(plan.GetBefore().GetMetadata().GetNativeRevision(), native.GetBefore().GetFingerprintSha256()) {
		return fmt.Errorf("%w: mismatched native observation", ErrConflict)
	}
	observationDigest, err := resource.ObservationDigest(plan.GetBefore())
	if err != nil || !bytes.Equal(observationDigest[:], plan.GetObservationSha256()) {
		return fmt.Errorf("%w: fabricated observation digest", ErrConflict)
	}
	claims, err := resource.Claims(&resourcev1.ResourceDesiredState{
		Ref: plan.GetRef(), State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: native.GetDesired()},
	})
	if err != nil || len(claims) != len(plan.GetClaims()) {
		return fmt.Errorf("%w: fabricated resource claims", ErrConflict)
	}
	for i, claim := range claims {
		if !proto.Equal(claim, plan.GetClaims()[i]) {
			return fmt.Errorf("%w: fabricated resource claims", ErrConflict)
		}
	}
	if !bytes.Equal(fingerprint(plan.GetSystemdService().GetBefore()), plan.GetSystemdService().GetBefore().GetFingerprintSha256()) {
		return fmt.Errorf("%w: fabricated observation fingerprint", ErrConflict)
	}
	runtime, enablement, err := drift(plan.GetSystemdService().GetDesired(), plan.GetSystemdService().GetBefore())
	if err != nil {
		return err
	}
	if plan.GetSystemdService().GetChangeRuntime() != runtime || plan.GetSystemdService().GetChangeEnablement() != enablement {
		return fmt.Errorf("%w: fabricated plan drift", ErrConflict)
	}
	return nil
}

// ValidateVerification checks retained native evidence without reading the host.
// A consistent nonconverged result is valid evidence, not a successful operation.
func ValidateVerification(plan *resourcev1.ResourcePlan, result *resourcev1.ResourceVerification) error {
	if err := ValidatePlan(plan); err != nil {
		return err
	}
	if err := resource.ValidateVerification(result); err != nil {
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
	after := result.GetAfter().GetSystemdService()
	if after.GetUnit() != plan.GetSystemdService().GetDesired().GetUnit() || !bytes.Equal(fingerprint(after), after.GetFingerprintSha256()) {
		return fmt.Errorf("%w: invalid verification observation", ErrConflict)
	}
	expected, err := verification(plan, after, result.GetAfter().GetMetadata().GetExecutorIncarnation())
	if err != nil || !proto.Equal(expected, result) {
		return fmt.Errorf("%w: fabricated verification result", ErrConflict)
	}
	return nil
}

func checkFresh(plan *resourcev1.ResourcePlan, current *resourcev1.SystemdServiceObservation) error {
	if !bytes.Equal(plan.GetSystemdService().GetBefore().GetFingerprintSha256(), current.GetFingerprintSha256()) {
		return fmt.Errorf("%w: stale service plan", ErrConflict)
	}
	return nil
}

func runtimeMatches(desired *resourcev1.SystemdServiceDesired, o *resourcev1.SystemdServiceObservation) bool {
	switch desired.GetRuntime() {
	case resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_UNMANAGED:
		return true
	case resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE:
		return o.GetActiveState() == "active" && (o.GetServiceType() != "oneshot" || o.GetRemainAfterExit())
	case resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE:
		return o.GetActiveState() == "inactive"
	default:
		return false
	}
}

func enablementMatches(desired *resourcev1.SystemdServiceDesired, o *resourcev1.SystemdServiceObservation) bool {
	switch desired.GetEnablement() {
	case resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED:
		return true
	case resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED:
		return o.GetUnitFileState() == "enabled"
	case resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_DISABLED:
		return o.GetUnitFileState() == "disabled"
	default:
		return false
	}
}

func verification(plan *resourcev1.ResourcePlan, after *resourcev1.SystemdServiceObservation, incarnation string) (*resourcev1.ResourceVerification, error) {
	native := plan.GetSystemdService()
	checks := &resourcev1.SystemdServiceChecks{
		Observation:       after,
		RuntimeMatches:    runtimeMatches(native.GetDesired(), after),
		EnablementMatches: enablementMatches(native.GetDesired(), after),
		DefinitionMatches: bytes.Equal(native.GetBefore().GetDefinitionSha256(), after.GetDefinitionSha256()),
		// The fresh observation has no queued or running systemd job: any job
		// this plan enqueued has finished, not merely been accepted.
		JobCompleted: !after.GetJobPending(),
	}
	checks.Converged = checks.GetRuntimeMatches() && checks.GetEnablementMatches() && checks.GetDefinitionMatches() && checks.GetJobCompleted() &&
		after.GetUnit() == native.GetDesired().GetUnit() && after.GetBootId() == native.GetBefore().GetBootId() &&
		supportedObservation(after) == nil
	disposition := resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED
	if checks.GetConverged() {
		disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED
	}
	digest, err := resource.PlanDigest(plan)
	if err != nil {
		return nil, err
	}
	return &resourcev1.ResourceVerification{
		Ref: proto.CloneOf(plan.GetRef()), DesiredSha256: bytes.Clone(plan.GetDesiredSha256()),
		PlanSha256: digest[:], Disposition: disposition,
		After:  observationEnvelope(after, incarnation, plan.GetBackend()),
		Checks: &resourcev1.ResourceVerification_SystemdService{SystemdService: checks},
	}, nil
}

func observationEnvelope(native *resourcev1.SystemdServiceObservation, incarnation string, backend *resourcev1.BackendSelection) *resourcev1.ResourceObservation {
	return &resourcev1.ResourceObservation{
		Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: native.GetUnit()},
		Metadata: &resourcev1.ObservationMetadata{
			BootId: native.GetBootId(), ExecutorIncarnation: incarnation,
			ObservedAt: native.GetObservedAt(), Backend: proto.CloneOf(backend),
			NativeRevision:    bytes.Clone(native.GetFingerprintSha256()),
			ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK,
		},
		Observed: &resourcev1.ResourceObservation_SystemdService{SystemdService: native},
	}
}
