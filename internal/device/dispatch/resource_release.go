package dispatch

import (
	"context"
	"errors"

	"lindm/internal/device/core"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/device/devicedb"
)

// Release selects the original immutable desired resource, never caller-supplied
// inverse values. Reverse dependency order lets native owners release dependents
// first. The executor alone decides whether a retained baseline is safe to undo.
func pendingResourceRelease(ctx context.Context, q *devicedb.Queries, head devicedb.ResourceAssignment, current []devicedb.ResourceAssignmentResource) (*devicedb.ResourceRelease, *policyv1.ProfileResource, devicedb.ResourceAssignment, error) {
	releases, err := q.PendingResourceReleases(ctx, head.GenerationID)
	if err != nil {
		return nil, nil, devicedb.ResourceAssignment{}, err
	}
	for _, release := range releases {
		active := false
		for _, row := range current {
			if row.ResourceKind == release.ResourceKind && row.CanonicalKey == release.CanonicalKey {
				active = true
				break
			}
		}
		if active {
			if err := q.SetResourceReleaseState(ctx, devicedb.SetResourceReleaseStateParams{ID: release.ID, State: "release_conflict", Reason: "resource_reassigned"}); err != nil {
				return nil, nil, devicedb.ResourceAssignment{}, err
			}
			continue
		}
		source, err := q.GetResourceAssignmentByID(ctx, release.SourceAssignmentID)
		if err != nil {
			return nil, nil, devicedb.ResourceAssignment{}, err
		}
		if source.DeviceID != head.DeviceID || source.GenerationID != head.GenerationID {
			return nil, nil, devicedb.ResourceAssignment{}, core.ErrInternalState
		}
		rows, err := q.ListAssignmentResources(ctx, source.ID)
		if err != nil {
			return nil, nil, devicedb.ResourceAssignment{}, err
		}
		for _, row := range rows {
			if row.ResourceID != release.ResourceID {
				continue
			}
			item := new(policyv1.ProfileResource)
			if err := proto.Unmarshal(row.Document, item); err != nil {
				return nil, nil, devicedb.ResourceAssignment{}, core.ErrInternalState
			}
			if row.ResourceKind != release.ResourceKind || row.CanonicalKey != release.CanonicalKey || item.GetResourceId() != release.ResourceID.String() || int16(item.GetDesired().GetRef().GetKind()) != release.ResourceKind || item.GetDesired().GetRef().GetCanonicalKey() != release.CanonicalKey {
				return nil, nil, devicedb.ResourceAssignment{}, core.ErrInternalState
			}
			if item.GetOwnership().GetMode() == resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION && source.AdoptionApprovalID == nil {
				if err := q.SetResourceReleaseState(ctx, devicedb.SetResourceReleaseStateParams{ID: release.ID, State: "release_conflict", Reason: "adoption_approval_required"}); err != nil {
					return nil, nil, devicedb.ResourceAssignment{}, err
				}
				break
			}
			// Native qualification remains an independent gate. A typed release
			// is not permission to run an unqualified provider.
			if reason := ResourceDispatchUnsupported(item); reason != "" && reason != ResourceOwnershipUnavailable {
				if err := q.SetResourceReleaseState(ctx, devicedb.SetResourceReleaseStateParams{ID: release.ID, State: "release_conflict", Reason: reason}); err != nil {
					return nil, nil, devicedb.ResourceAssignment{}, err
				}
				break
			}
			return &release, item, source, nil
		}
	}
	return nil, nil, devicedb.ResourceAssignment{}, nil
}

func ResourceActionHead(action devicedb.ResourceAction, intent *agentv1.ResourceExecutionIntent) (uuid.UUID, error) {
	if action.ReleaseID == nil {
		if intent.GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE || intent.GetDesiredRevision() != action.AssignmentID.String() {
			return uuid.Nil, core.ErrInternalState
		}
		return action.AssignmentID, nil
	}
	if intent.GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		return uuid.Nil, core.ErrInternalState
	}
	head, err := uuid.Parse(intent.GetDesiredRevision())
	if err != nil || head == uuid.Nil || intent.GetOwnership().GetAssignmentId() != head.String() {
		return uuid.Nil, core.ErrInternalState
	}
	return head, nil
}

func ReleaseResultState(status *agentv1.ResourceExecutionStatus) (string, string) {
	if status.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED {
		return "released", ""
	}
	refusal := status.GetAdmissionRefusal()
	// An earlier effect's unknown outcome refuses the release too; nothing
	// is restored until that exact effect is explicitly resolved.
	if refusal.GetReason() == agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_OWNERSHIP_UNKNOWN {
		return "release_conflict", "outcome_unknown"
	}
	if refusal.GetDetail() != "" && refusal.GetReason() != agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_BASELINE_UNKNOWN && refusal.GetReason() != agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_CAPABILITY_NOT_ENABLED {
		return "release_conflict", refusal.GetDetail()
	}
	if detail := status.GetPreparationOutcome().GetDetail(); detail != "" && status.GetStartedAt() == nil {
		return "release_conflict", detail
	}
	switch status.GetAdmissionRefusal().GetReason() {
	case agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_BASELINE_UNKNOWN:
		return "baseline_unknown", "ownership_baseline_unavailable"
	case agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_UNSUPPORTED_NATIVE:
		return "release_conflict", "native_unsupported"
	case agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_PRECONDITION:
		return "release_conflict", "precondition_failed"
	case agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_UNSAFE_NATIVE_TOOL_PATH:
		return "release_conflict", ResourceReasonUnsafeToolPath
	case agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_CAPABILITY_NOT_ENABLED:
		// Retried (state pending again) when the device's capabilities change.
		return "release_conflict", core.CapabilityNotEnabledReason(status.GetAdmissionRefusal().GetCapability())
	}
	if status.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN {
		return "release_conflict", "outcome_unknown"
	}
	if status.GetFailure() == agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE_BUSY {
		return "release_conflict", ResourceReasonNativeBusy
	}
	return "release_conflict", "release_failed"
}

func validateReleaseAction(release devicedb.ResourceRelease, action devicedb.ResourceAction, intent *agentv1.ResourceExecutionIntent) error {
	if action.ReleaseID == nil || *action.ReleaseID != release.ID || action.AssignmentID != release.SourceAssignmentID || action.ResourceID != release.ResourceID || action.GenerationID != release.GenerationID || int16(intent.GetDesired().GetRef().GetKind()) != release.ResourceKind || intent.GetDesired().GetRef().GetCanonicalKey() != release.CanonicalKey {
		return errors.New("resource_release_binding_rejected")
	}
	return nil
}
