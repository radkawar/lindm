// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"errors"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

// ValidateReadOnlyVerification admits evidence, not permission to apply a plan.
// Nonconvergence remains a terminal finding, including module boot/built-in state.
func ValidateReadOnlyVerification(plan *resourcev1.ResourcePlan, verification *resourcev1.ResourceVerification) error {
	if PlanRequiresEffect(plan) {
		return errors.New("resource: verification_requires_effect")
	}
	if err := ValidatePlanVerification(plan, verification); err != nil {
		return err
	}
	switch verification.GetDisposition() {
	case resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED,
		resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED,
		resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_UNKNOWN:
		return nil
	case resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE:
		if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
			return nil
		}
		if PlanDesired(plan).GetManagedFile().GetKernelModuleBlocklist() != nil {
			return nil
		}
	case resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_PENDING_REBOOT:
		if PlanDesired(plan).GetManagedFile().GetKernelModuleBlocklist() != nil {
			return nil
		}
	}
	return errors.New("resource: invalid_read_only_disposition")
}
