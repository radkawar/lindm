//go:build linux

package executor

import (
	"errors"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

func validateReadOnlyResourceResult(plan *resourcev1.ResourcePlan, verification *resourcev1.ResourceVerification, operationErr error) error {
	if operationErr != nil && !errors.Is(operationErr, resource.ErrNotConverged) {
		return operationErr
	}
	if validateResourceVerification(plan, verification) != nil || resource.ValidateReadOnlyVerification(plan, verification) != nil {
		return errInternal
	}
	if operationErr != nil && verification.GetDisposition() != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED && verification.GetDisposition() != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_UNKNOWN {
		return errInternal
	}
	return nil
}

func recordReadOnlyResourceResult(record *agentv1.ResourceExecutionRecord, verification *resourcev1.ResourceVerification) {
	record.Verification = verification
	record.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED
	record.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE
	if verification.GetDisposition() == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED || verification.GetDisposition() == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_UNKNOWN {
		record.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED
		record.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_POSTCONDITION
	}
}
