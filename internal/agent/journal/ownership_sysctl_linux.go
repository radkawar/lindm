// SPDX-License-Identifier: Apache-2.0

//go:build linux

package journal

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativefile"
)

func sysctlOwnershipSnapshotValid(snapshot *agentv1.ResourceOwnershipSnapshot) bool {
	o := snapshot.GetObservation().GetSysctl()
	private := snapshot.GetSysctlPersistence()
	if o == nil || o.Value == nil || len(o.GetNativeIdentitySha256()) != 32 || private == nil {
		return false
	}
	file := private.GetState()
	path := sysctlStanzaPath(o.GetKey())
	if file == nil || file.GetPath() != path || !proto.Equal(file, o.GetPersistenceFileState()) || !proto.Equal(file.GetFile(), o.GetOwnedPersistenceFile()) || file.GetExists() != (private.Content != nil) || file.GetExists() != (file.GetFile() != nil) || len(file.GetAncestrySha256()) != 32 || len(file.GetNativeIdentitySha256()) != 32 || !bytes.Equal(file.GetSecurityMetadataSha256(), nativefile.XattrDigest(private.GetXattrs())) {
		return false
	}
	if file.GetExists() {
		digest := sha256.Sum256(private.GetContent())
		if file.GetFile().GetPath() != path || !bytes.Equal(digest[:], file.GetFile().GetSha256()) {
			return false
		}
	} else if len(private.GetXattrs()) != 0 {
		return false
	}
	return true
}
func sysctlOwnershipDimensionKind(kind resourcev1.ResourceKind, dimension agentv1.ResourceOwnedDimension) bool {
	return kind == resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL && (dimension == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_VALUE || dimension == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_PERSISTENCE)
}
func sysctlOwnershipDimensionAllowed(action *agentv1.ResourceExecutionRecord, dimension agentv1.ResourceOwnedDimension) bool {
	d := action.GetIntent().GetDesired().GetSysctl()
	if d == nil {
		return false
	}
	switch dimension {
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_VALUE:
		return true
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_PERSISTENCE:
		return d.GetPersistent()
	default:
		return false
	}
}
func sysctlOwnershipDimensionMatches(left, right *agentv1.ResourceOwnershipSnapshot, dimension agentv1.ResourceOwnedDimension) bool {
	if !sysctlOwnershipSnapshotValid(left) || !sysctlOwnershipSnapshotValid(right) {
		return false
	}
	a, b := left.GetObservation().GetSysctl(), right.GetObservation().GetSysctl()
	if a.GetKey() != b.GetKey() {
		return false
	}
	switch dimension {
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_VALUE:
		return a.GetValue() == b.GetValue() && SysctlValueIdentityMatches(left, right)
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_PERSISTENCE:
		return proto.Equal(left.GetSysctlPersistence(), right.GetSysctlPersistence())
	default:
		return false
	}
}
func sysctlOwnershipAcquisitionAllowed(intent *agentv1.ResourceExecutionIntent, snapshot *agentv1.ResourceOwnershipSnapshot) bool {
	return intent.GetDesired().GetSysctl() != nil && intent.GetOwnership().GetPolicy().GetMode() == resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION && sysctlOwnershipSnapshotValid(snapshot)
}

func sysctlStanzaPath(key string) string {
	return fmt.Sprintf("/etc/sysctl.d/60-lindm-%x.conf", sha256.Sum256([]byte(key)))
}

// SysctlValueIdentityMatches reports whether two observations of a live sysctl
// value name the same owned kernel setting. Within one boot its native identity
// (boot, key and, for net.* keys, the network namespace) must be equal. A
// reboot necessarily changes that identity; the value then remains the owner's
// only if the owned stanza systemd-sysctl applies at boot is byte-identical
// (content, inode, metadata) and is still the effective persistent source.
// Callers compare the values themselves.
func SysctlValueIdentityMatches(left, right *agentv1.ResourceOwnershipSnapshot) bool {
	a, b := left.GetObservation().GetSysctl(), right.GetObservation().GetSysctl()
	if a == nil || b == nil || a.GetKey() != b.GetKey() {
		return false
	}
	if bytes.Equal(a.GetNativeIdentitySha256(), b.GetNativeIdentitySha256()) {
		return true
	}
	before, after := left.GetObservation().GetMetadata().GetBootId(), right.GetObservation().GetMetadata().GetBootId()
	path := sysctlStanzaPath(a.GetKey())
	return before != "" && after != "" && before != after &&
		left.GetSysctlPersistence().GetState().GetExists() && proto.Equal(left.GetSysctlPersistence(), right.GetSysctlPersistence()) &&
		a.GetPersistentSource() == path && b.GetPersistentSource() == path && !a.GetPersistenceConflict() && !b.GetPersistenceConflict() &&
		a.PersistentValue != nil && a.GetPersistentValue() == b.GetPersistentValue()
}
