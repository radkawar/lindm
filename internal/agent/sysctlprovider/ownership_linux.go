//go:build linux

package sysctlprovider

import (
	"bytes"
	"crypto/sha256"
	"slices"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
)

func acquisitionAllowed(owner *agentv1.ResourceOwnershipBinding, ledger *agentv1.ResourceOwnershipLedger, operation resourcev1.ResourceOperation) error {
	if ledger == nil || ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
		if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
			return ErrConflict
		}
		// Every live sysctl already exists; a root allowlist does not replace the
		// signed resource owner's explicit adoption approval.
		if owner.GetPolicy().GetMode() != resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION {
			return ErrConflict
		}
		return nil
	}
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return ErrOutcomeUnknown
	}
	if len(owner.GetSources()) != len(ledger.GetOwner().GetSources()) {
		return ErrConflict
	}
	for _, source := range owner.GetSources() {
		found := false
		for _, other := range ledger.GetOwner().GetSources() {
			if source.GetProfileId() == other.GetProfileId() && source.GetResourceId() == other.GetResourceId() {
				found = true
			}
		}
		if !found {
			return ErrConflict
		}
	}
	return nil
}
func owned(ledger *agentv1.ResourceOwnershipLedger, dimension agentv1.ResourceOwnedDimension) bool {
	return slices.Contains(ledger.GetOwnedDimensions(), dimension)
}
func releaseMatches(current, last *agentv1.ResourceOwnershipSnapshot, dimensions []agentv1.ResourceOwnedDimension) bool {
	if current == nil || last == nil {
		return false
	}
	a, b := current.GetObservation().GetSysctl(), last.GetObservation().GetSysctl()
	if a == nil || b == nil || a.GetKey() != b.GetKey() {
		return false
	}
	for _, dimension := range dimensions {
		switch dimension {
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_VALUE:
			if a.Value == nil || b.Value == nil || a.GetValue() != b.GetValue() || !journal.SysctlValueIdentityMatches(current, last) {
				return false
			}
		case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_PERSISTENCE:
			if !proto.Equal(current.GetSysctlPersistence(), last.GetSysctlPersistence()) {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func targetSnapshot(d *resourcev1.SysctlDesired, before *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger, operation resourcev1.ResourceOperation) (*agentv1.ResourceOwnershipSnapshot, error) {
	target := proto.CloneOf(before)
	o := target.GetObservation().GetSysctl()
	if o == nil || o.Value == nil || before.GetSysctlPersistence() == nil {
		return nil, ErrUnsupported
	}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		if ledger.GetLastApplied() == nil || len(ledger.GetOwnedDimensions()) == 0 {
			return nil, ErrConflict
		}
		if !releaseMatches(before, ledger.GetLastApplied(), ledger.GetOwnedDimensions()) {
			return nil, ErrConflict
		}
		if ledger.GetOwner().GetPolicy().GetRelease() == resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN {
			return target, nil
		}
		baseline := ledger.GetBaseline()
		if owned(ledger, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_VALUE) {
			if baseline.GetObservation().GetSysctl().Value == nil {
				return nil, ErrConflict
			}
			o.Value = proto.String(baseline.GetObservation().GetSysctl().GetValue())
		}
		if owned(ledger, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_PERSISTENCE) {
			target.SysctlPersistence = proto.CloneOf(baseline.GetSysctlPersistence())
			if target.SysctlPersistence == nil {
				return nil, ErrConflict
			}
			o.PersistenceFileState = proto.CloneOf(target.SysctlPersistence.GetState())
			o.OwnedPersistenceFile = proto.CloneOf(o.PersistenceFileState.GetFile())
		}
		return target, nil
	}
	o.Value = proto.String(d.GetValue())
	if d.GetPersistent() {
		file := target.GetSysctlPersistence()
		content := stanza(d.GetKey(), d.GetValue())
		digest := sha256.Sum256(content)
		file.Content = content
		file.State.Exists = true
		if file.State.File == nil {
			file.State.File = &resourcev1.FileIdentity{Path: StanzaPath(d.GetKey())}
		}
		file.State.File.Mode = 0644
		file.State.File.Uid = 0
		file.State.File.Gid = 0
		file.State.File.Sha256 = digest[:]
		o.PersistenceFileState = proto.CloneOf(file.State)
		o.OwnedPersistenceFile = proto.CloneOf(file.State.File)
		o.PersistentValue = proto.String(normalizeValue(d.GetValue()))
		o.PersistentSource = proto.String(StanzaPath(d.GetKey()))
		o.PersistenceConflict = false
	}
	return target, nil
}
func fileTargetMatches(actual, target *agentv1.SysctlPersistenceSnapshot) bool {
	if actual == nil || target == nil || actual.GetState().GetExists() != target.GetState().GetExists() {
		return false
	}
	if !target.GetState().GetExists() {
		return true
	}
	a, b := actual.GetState().GetFile(), target.GetState().GetFile()
	return a != nil && b != nil && a.GetMode() == b.GetMode() && a.GetUid() == b.GetUid() && a.GetGid() == b.GetGid() && bytes.Equal(actual.GetContent(), target.GetContent()) && proto.Equal(&agentv1.ResourceOwnershipSnapshot{ManagedFileXattrs: actual.GetXattrs()}, &agentv1.ResourceOwnershipSnapshot{ManagedFileXattrs: target.GetXattrs()})
}
func targetMatches(actual, target *agentv1.ResourceOwnershipSnapshot) bool {
	return normalizeValue(actual.GetObservation().GetSysctl().GetValue()) == normalizeValue(target.GetObservation().GetSysctl().GetValue()) && fileTargetMatches(actual.GetSysctlPersistence(), target.GetSysctlPersistence())
}
func inverseBinding(ledger *agentv1.ResourceOwnershipLedger, before, target *agentv1.ResourceOwnershipSnapshot) (*resourcev1.OwnershipInverseBinding, error) {
	ledgerDigest, err := journal.ResourceOwnershipDigest(ledger)
	if err != nil {
		return nil, err
	}
	last, err := messageDigest(ledger.GetLastApplied())
	if err != nil {
		return nil, err
	}
	image := &agentv1.ResourceOwnershipSnapshot{Observation: &resourcev1.ResourceObservation{Observed: &resourcev1.ResourceObservation_Sysctl{Sysctl: target.GetObservation().GetSysctl()}}, SysctlPersistence: target.GetSysctlPersistence()}
	inverse, err := messageDigest(image)
	if err != nil {
		return nil, err
	}
	return &resourcev1.OwnershipInverseBinding{LedgerRevisionSha256: ledgerDigest[:], LastAppliedSha256: last, NativeIdentitySha256: bytes.Clone(before.GetObservation().GetSysctl().GetNativeIdentitySha256()), InverseSha256: inverse}, nil
}
func fileSnapshot(source *agentv1.ResourceOwnershipSnapshot) *agentv1.ResourceOwnershipSnapshot {
	file := source.GetSysctlPersistence()
	o := proto.CloneOf(source.GetObservation())
	o.Ref = &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, CanonicalKey: file.GetState().GetPath()}
	o.Observed = &resourcev1.ResourceObservation_ManagedFile{ManagedFile: proto.CloneOf(file.GetState())}
	return &agentv1.ResourceOwnershipSnapshot{Observation: o, ManagedFileContent: bytes.Clone(file.GetContent()), ManagedFileXattrs: file.GetXattrs()}
}
