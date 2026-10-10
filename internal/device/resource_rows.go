package device

import (
	"context"
	"errors"
	"strconv"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/resource"
)

// resourceRefKey is an internal map key only. Wire/storage hashes retain typed
// kind and key fields; the numeric prefix cannot contain the delimiter.
func resourceRefKey(ref *resourcev1.ResourceRef) string {
	return strconv.FormatInt(int64(ref.GetKind()), 10) + ":" + ref.GetCanonicalKey()
}

func insertResourceRows(ctx context.Context, q *devicedb.Queries, assignment uuid.UUID, resources []*policyv1.ProfileResource) error {
	ids := make(map[string]uuid.UUID, len(resources))
	for _, item := range resources {
		if err := resource.ValidateDesired(item.GetDesired()); err != nil {
			return err
		}
		id, err := uuid.Parse(item.GetResourceId())
		if err != nil {
			return err
		}
		key := resourceRefKey(item.GetDesired().GetRef())
		if _, exists := ids[key]; exists {
			return errors.New("duplicate_resource_ref")
		}
		ids[key] = id
	}
	for position, item := range resources {
		ref := item.GetDesired().GetRef()
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(item)
		if err != nil {
			return err
		}
		dependencies := make([]uuid.UUID, len(item.GetDependsOn()))
		for i, dep := range item.GetDependsOn() {
			id, ok := ids[resourceRefKey(dep.GetRef())]
			if !ok {
				return errors.New("resource_dependency_missing")
			}
			dependencies[i] = id
		}
		id := ids[resourceRefKey(ref)]
		if err := q.InsertServiceResource(ctx, devicedb.InsertServiceResourceParams{AssignmentID: assignment, ResourceID: id, ResourceKind: int16(ref.GetKind()), CanonicalKey: ref.GetCanonicalKey(), Position: int32(position), Document: encoded, DependsOn: dependencies, VerificationMaxAgeSeconds: int32(item.GetVerification().GetMaxAgeSeconds())}); err != nil {
			return err
		}
		if reason := resourceDispatchUnsupported(item); reason != "" {
			if err := q.SetServiceResourceDisposition(ctx, devicedb.SetServiceResourceDispositionParams{AssignmentID: assignment, ResourceID: id, Disposition: 6, Reason: reason}); err != nil {
				return err
			}
		}
	}
	return nil
}

// Phase 1 preserves the signed service protocol. Only this adapter may translate
// a generic desired arm into its existing execution payload. Unknown kinds never
// fall through to systemd, and Phase 2 removes this boundary at atomic cutover.
func serviceExecutionDesired(desired *resourcev1.ResourceDesiredState) (*agentv1.ServiceDesiredState, error) {
	if err := resource.ValidateDesired(desired); err != nil {
		return nil, err
	}
	if desired.GetRef().GetKind() != resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE || desired.GetSystemdService() == nil {
		return nil, errors.New("resource_executor_not_available")
	}
	service := desired.GetSystemdService()
	return &agentv1.ServiceDesiredState{Unit: service.GetUnit(), Runtime: agentv1.ServiceRuntimeState(service.GetRuntime()), Enablement: agentv1.ServiceEnablement(service.GetEnablement())}, nil
}

func resourceRefKeyFromRow(row devicedb.ResourceAssignmentResource) string {
	return strconv.FormatInt(int64(row.ResourceKind), 10) + ":" + row.CanonicalKey
}

func resourceDependencySatisfied(item *policyv1.ProfileResource, condition policyv1.DependencyCondition) bool {
	if item == nil || item.GetDesired().GetSystemdService() == nil {
		return false
	}
	switch condition {
	case policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_PRESENT, policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_CONFIGURED:
		return true
	case policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_ACTIVE:
		return agentv1.ServiceRuntimeState(item.GetDesired().GetSystemdService().GetRuntime()) == agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE
	default:
		return false
	}
}

// Metadata cannot silently promise checks or ownership operations that the
// retained Phase 1 service wire cannot express to the privileged executor.
func resourceDispatchUnsupported(item *policyv1.ProfileResource) string {
	if item.GetDesired().GetRef().GetKind() != resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE {
		return "resource_executor_not_available"
	}
	if len(item.GetApplicability().GetProducts()) != 0 || len(item.GetApplicability().GetFeatures()) != 0 {
		return "resource_capability_evidence_unavailable"
	}
	if item.GetOwnership().GetMode() == resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION || item.GetOwnership().GetRelease() != resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN {
		return "resource_ownership_operation_unavailable"
	}
	for _, check := range item.GetVerification().GetChecks() {
		if check != resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE {
			return "resource_verification_not_available"
		}
	}
	return ""
}
