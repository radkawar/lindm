package resource

import (
	"bytes"
	"errors"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

// ErrPreparing reports bounded, effect-free native artifact staging. It never
// implies that a start grant exists or that any managed state has changed.
var ErrPreparing = errors.New("resource: native preparation pending")

// ErrNotConverged distinguishes a valid native verification finding from a
// failed or unavailable observation. Providers may wrap it with native context.
var ErrNotConverged = errors.New("resource: native state not converged")

// PlanDesired returns the canonical desired envelope retained by the typed plan.
// The returned envelope shares immutable message fields with the plan.
func PlanDesired(plan *resourcev1.ResourcePlan) *resourcev1.ResourceDesiredState {
	if plan == nil {
		return nil
	}
	message := plan.ProtoReflect()
	arm := message.WhichOneof(message.Descriptor().Oneofs().ByName("plan"))
	if arm == nil {
		return nil
	}
	native := message.Get(arm).Message()
	field := native.Descriptor().Fields().ByName("desired")
	if field == nil || !native.Has(field) {
		return nil
	}
	desired := &resourcev1.ResourceDesiredState{Ref: plan.GetRef()}
	wrapped := desired.ProtoReflect()
	wrapped.Set(wrapped.Descriptor().Fields().ByNumber(arm.Number()), native.Get(field))
	return desired
}

// PlanBefore returns the complete retained observation, including native metadata.
func PlanBefore(plan *resourcev1.ResourcePlan) *resourcev1.ResourceObservation {
	return plan.GetBefore()
}

// ValidatePlanVerification binds verified evidence to the exact admitted plan.
// Convergence alone is not sufficient: kind, identity and both digests must match.
func ValidatePlanVerification(plan *resourcev1.ResourcePlan, verification *resourcev1.ResourceVerification) error {
	if err := ValidateVerification(verification); err != nil {
		return err
	}
	digest, err := PlanDigest(plan)
	if err != nil {
		return err
	}
	if !RefEqual(plan.GetRef(), verification.GetRef()) || !bytes.Equal(plan.GetDesiredSha256(), verification.GetDesiredSha256()) || !bytes.Equal(digest[:], verification.GetPlanSha256()) {
		return errors.New("resource: verification_plan_binding_mismatch")
	}
	return nil
}

// PlanRequiresEffect is conservative: only a proven native no-change plan can
// bypass the separately signed start grant. Unrecognized kinds never get a
// read-only success merely because their operation fields were not understood.
func PlanRequiresEffect(plan *resourcev1.ResourcePlan) bool {
	if plan.GetEncryptionCompliance() != nil {
		return false
	}
	if plan.GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE {
		return true
	}
	if service := plan.GetSystemdService(); service != nil {
		return service.GetChangeRuntime() || service.GetChangeEnablement()
	}
	if group := plan.GetLocalGroup(); group != nil {
		return group.GetChange() != resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE
	}
	if user := plan.GetLocalUser(); user != nil {
		return user.GetChange() != resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE
	}
	if file := plan.GetManagedFile(); file != nil {
		return file.GetChange() != resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE
	}
	if sysctl := plan.GetSysctl(); sysctl != nil {
		return sysctl.GetChange() != resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE
	}
	if definition := plan.GetSystemdDefinition(); definition != nil {
		return definition.GetChange() != resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE
	}
	if firewall := plan.GetFirewallZone(); firewall != nil {
		return firewall.GetChange() != resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE
	}
	if password := plan.GetPasswordPolicy(); password != nil {
		return len(password.GetFields()) != 0
	}
	if packages := plan.GetNativePackage(); packages != nil {
		return packages.GetChangePackages() || packages.GetChangePin()
	}
	return true
}
