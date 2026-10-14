// SPDX-License-Identifier: Apache-2.0

//go:build linux

package journal

import (
	"bytes"
	"crypto/sha256"
	"strings"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func definitionOwnershipSnapshotValid(snapshot *agentv1.ResourceOwnershipSnapshot) bool {
	o := snapshot.GetObservation().GetSystemdDefinition()
	f := snapshot.GetDefinitionFile()
	if o == nil {
		return f == nil
	}
	if f == nil || f.GetState() == nil || !proto.Equal(f.GetState(), o.GetFileState()) || o.GetExists() != f.GetState().GetExists() || !proto.Equal(o.GetOwnedFile(), f.GetState().GetFile()) || len(f.GetParentIdentitySha256()) != 32 {
		return false
	}
	if len(f.GetNativeRevisionSha256()) != 32 {
		return false
	}
	if f.GetState().GetExists() != (f.Content != nil) || (f.GetParentMissing() && f.GetState().GetExists()) {
		return false
	}
	if f.GetState().GetExists() {
		digest := sha256.Sum256(f.GetContent())
		if !bytes.Equal(digest[:], o.GetOwnedFile().GetSha256()) {
			return false
		}
	}
	path := "/etc/systemd/system/"
	key := o.GetCanonicalKey()
	if unit, ok := strings.CutPrefix(key, "timer/"); ok {
		path += unit
		if !o.GetTimerInstallProjectionComplete() || o.TimerEnabled == nil || o.TimerActive == nil {
			return false
		}
	} else if unit, ok := strings.CutPrefix(key, "drop-in/"); ok {
		path += unit + ".d/50-lindm.conf"
		if o.GetEffectiveOptions() == nil || o.TimerEnabled != nil || o.TimerActive != nil || len(o.GetTimerInstallLinks()) != 0 {
			return false
		}
	} else {
		return false
	}
	return path == f.GetState().GetPath()
}

func definitionOwnershipDimensionKind(kind resourcev1.ResourceKind, dimension agentv1.ResourceOwnedDimension) bool {
	return kind == resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION && (dimension == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_DEFINITION_FILE || dimension == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_DEFINITION_ENABLEMENT || dimension == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_DEFINITION_RUNTIME)
}

func definitionOwnershipDimensionAllowed(action *agentv1.ResourceExecutionRecord, dimension agentv1.ResourceOwnedDimension) bool {
	plan := action.GetNativePlan().GetSystemdDefinition()
	if plan == nil {
		return false
	}
	if dimension == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_DEFINITION_FILE {
		return true
	}
	return plan.GetDesired().GetTimer() != nil && (dimension == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_DEFINITION_ENABLEMENT || dimension == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_DEFINITION_RUNTIME)
}

func definitionOwnershipDimensionMatches(left, right *agentv1.ResourceOwnershipSnapshot, dimension agentv1.ResourceOwnedDimension) bool {
	a, b := left.GetObservation().GetSystemdDefinition(), right.GetObservation().GetSystemdDefinition()
	if a == nil || b == nil || a.GetCanonicalKey() != b.GetCanonicalKey() || !bytes.Equal(a.GetTargetDefinitionSha256(), b.GetTargetDefinitionSha256()) || a.GetDaemonReloadPending() || b.GetDaemonReloadPending() {
		return false
	}
	switch dimension {
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_DEFINITION_FILE:
		return proto.Equal(left.GetDefinitionFile(), right.GetDefinitionFile()) && bytes.Equal(a.GetDefinitionSha256(), b.GetDefinitionSha256()) && proto.Equal(a.GetEffectiveOptions(), b.GetEffectiveOptions()) && bytes.Equal(a.GetTimerScheduleSha256(), b.GetTimerScheduleSha256())
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_DEFINITION_ENABLEMENT:
		if !a.GetTimerInstallProjectionComplete() || !b.GetTimerInstallProjectionComplete() || a.TimerEnabled == nil || b.TimerEnabled == nil || a.GetTimerEnabled() != b.GetTimerEnabled() || a.GetTimerUnitFileState() != b.GetTimerUnitFileState() || len(a.GetTimerInstallLinks()) != len(b.GetTimerInstallLinks()) {
			return false
		}
		for i, link := range a.GetTimerInstallLinks() {
			if !proto.Equal(link, b.GetTimerInstallLinks()[i]) {
				return false
			}
		}
		return true
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_DEFINITION_RUNTIME:
		return left.GetObservation().GetMetadata().GetBootId() == right.GetObservation().GetMetadata().GetBootId() && a.TimerActive != nil && b.TimerActive != nil && a.GetTimerActive() == b.GetTimerActive() && bytes.Equal(a.GetTimerInvocationId(), b.GetTimerInvocationId()) && !a.GetTimerJobPending() && !b.GetTimerJobPending()
	default:
		return false
	}
}

func definitionOwnershipAcquisitionAllowed(intent *agentv1.ResourceExecutionIntent, snapshot *agentv1.ResourceOwnershipSnapshot) bool {
	if !definitionOwnershipSnapshotValid(snapshot) {
		return false
	}
	o := snapshot.GetObservation().GetSystemdDefinition()
	if o == nil {
		return false
	}
	if intent.GetOwnership().GetPolicy().GetMode() == resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION {
		return intent.GetOwnership().GetPolicy().GetAdoptionApprovalId() != ""
	}
	return !o.GetExists() && !o.GetTimerEnabled() && !o.GetTimerActive() && len(o.GetTimerInstallLinks()) == 0
}

// DefinitionOwnershipMatches compares only captured ownership dimensions. An
// inode/link/invocation replacement is drift even if its visible values match.
func DefinitionOwnershipMatches(left, right *agentv1.ResourceOwnershipSnapshot, dimensions []agentv1.ResourceOwnedDimension) bool {
	if left == nil || right == nil || len(dimensions) == 0 {
		return false
	}
	for _, dimension := range dimensions {
		if !definitionOwnershipDimensionMatches(left, right, dimension) {
			return false
		}
	}
	return true
}
