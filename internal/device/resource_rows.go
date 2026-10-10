package device

import (
	"context"
	"errors"
	"slices"
	"strconv"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

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

func resourceRefKeyFromRow(row devicedb.ResourceAssignmentResource) string {
	return strconv.FormatInt(int64(row.ResourceKind), 10) + ":" + row.CanonicalKey
}

func resourceDependencySatisfied(item *policyv1.ProfileResource, condition policyv1.DependencyCondition) bool {
	desired := item.GetDesired()
	if desired == nil {
		return false
	}
	switch condition {
	case policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_CONFIGURED:
		return true
	case policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_PRESENT:
		return resourceDesiresPresence(desired)
	case policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_ACTIVE:
		return desired.GetSystemdService().GetRuntime() == resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE
	default:
		return false
	}
}

// resourceDesiresPresence reports whether verified convergence means the native
// object exists. Kinds without a presence dimension are configured, not present.
func resourceDesiresPresence(desired *resourcev1.ResourceDesiredState) bool {
	switch {
	case desired.GetSystemdService() != nil:
		return true
	case desired.GetNativePackage() != nil:
		return desired.GetNativePackage().GetPresence() == resourcev1.Presence_PRESENCE_PRESENT
	case desired.GetManagedFile() != nil:
		return desired.GetManagedFile().GetPresence() == resourcev1.Presence_PRESENCE_PRESENT
	case desired.GetLocalUser() != nil:
		return desired.GetLocalUser().GetPresence() == resourcev1.Presence_PRESENCE_PRESENT
	case desired.GetLocalGroup() != nil:
		return desired.GetLocalGroup().GetPresence() == resourcev1.Presence_PRESENCE_PRESENT
	case desired.GetSystemdDefinition() != nil:
		return desired.GetSystemdDefinition().GetPresence() == resourcev1.Presence_PRESENCE_PRESENT
	default:
		return false
	}
}

// resourceQualification is the native evidence recorded for one kind: native
// Ubuntu 24.04 and Fedora 44 lanes exercised exactly these ownership operations.
// docs/verification.md lists the records. Absent kinds are never dispatched.
type resourceQualification struct {
	adoption bool
	releases []resourcev1.ReleaseBehavior
}

var qualifiedResourceKinds = map[resourcev1.ResourceKind]resourceQualification{
	// Services have no ownership baseline: release is retained, or refused by
	// the agent as baseline_unknown without any native effect.
	resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE: {releases: []resourcev1.ReleaseBehavior{resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN}},
}

// The generic wire is not native qualification. Keep unqualified kinds and
// unsupported ownership, applicability and verification operations blocked.
func resourceDispatchUnsupported(item *policyv1.ProfileResource) string {
	qualification, ok := qualifiedResourceKinds[item.GetDesired().GetRef().GetKind()]
	if !ok {
		return "resource_executor_not_available"
	}
	if len(item.GetApplicability().GetProducts()) != 0 || len(item.GetApplicability().GetFeatures()) != 0 {
		return "resource_capability_evidence_unavailable"
	}
	if reason := resourceOwnershipUnsupported(qualification, item.GetOwnership()); reason != "" {
		return reason
	}
	for _, check := range item.GetVerification().GetChecks() {
		if check != resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE {
			return "resource_verification_not_available"
		}
	}
	return ""
}

const resourceOwnershipUnavailable = "resource_ownership_operation_unavailable"

func resourceOwnershipUnsupported(qualification resourceQualification, ownership *resourcev1.OwnershipPolicy) string {
	if ownership.GetMode() == resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION && !qualification.adoption {
		return resourceOwnershipUnavailable
	}
	if !slices.Contains(qualification.releases, ownership.GetRelease()) {
		return resourceOwnershipUnavailable
	}
	return ""
}

func resourceAdoptionRequired(resources []*policyv1.ProfileResource) bool {
	for _, item := range resources {
		if item.GetOwnership().GetMode() == resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION {
			return true
		}
	}
	return false
}
