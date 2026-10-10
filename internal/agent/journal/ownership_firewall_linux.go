//go:build linux

package journal

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativefile"
)

// FirewallNativeIdentity excludes volatile handles and global ruleset generation.
// It includes every dedicated chain, rule order, expression and ownership marker.
// Raw kernel expression identity is checked separately on ownership/release.
func FirewallNativeIdentity(snapshot *agentv1.FirewallNativeSnapshot) ([]byte, error) {
	image := &agentv1.FirewallNativeSnapshot{Table: snapshot.GetTable(), Userdata: snapshot.GetUserdata(), Conflict: snapshot.GetConflict(), Chains: slices.Clone(snapshot.GetChains()), Rules: make([]*agentv1.FirewallNativeRule, len(snapshot.GetRules()))}
	for i, r := range snapshot.GetRules() {
		image.Rules[i] = &agentv1.FirewallNativeRule{Chain: r.GetChain(), Userdata: r.GetUserdata(), ExpressionsSha256: r.GetExpressionsSha256()}
	}
	slices.SortFunc(image.Chains, func(a, b *agentv1.FirewallNativeChain) int { return strings.Compare(a.GetName(), b.GetName()) })
	slices.SortStableFunc(image.Rules, func(a, b *agentv1.FirewallNativeRule) int { return strings.Compare(a.GetChain(), b.GetChain()) })
	data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(image)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	return digest[:], nil
}
func firewallOwnershipSnapshotValid(snapshot *agentv1.ResourceOwnershipSnapshot) bool {
	o, f := snapshot.GetObservation().GetFirewallZone(), snapshot.GetFirewall()
	if o == nil || f == nil || o.GetConflict() || f.GetConflict() || f.GetTable() != "lindm_z_"+strings.ReplaceAll(o.GetZoneId(), "-", "") || o.GetTable() != f.GetTable() || o.GetExists() != (len(f.GetUserdata()) != 0) || !bytes.Equal(o.GetOwnershipUserdata(), f.GetUserdata()) || !bytes.Equal(o.GetNetworkNamespaceSha256(), f.GetNetworkNamespaceSha256()) {
		return false
	}
	digest, err := FirewallNativeIdentity(f)
	if err != nil || !bytes.Equal(digest, o.GetNativeIdentitySha256()) || !bytes.Equal(digest, o.GetKernelRulesSha256()) {
		return false
	}
	for _, r := range f.GetRules() {
		if len(r.GetRawExpressionsSha256()) != 32 || len(r.GetUserdata()) == 0 || !bytes.HasPrefix(r.GetUserdata(), f.GetUserdata()) {
			return false
		}
	}
	for _, c := range f.GetChains() {
		if len(c.GetUserdata()) == 0 || !bytes.HasPrefix(c.GetUserdata(), f.GetUserdata()) {
			return false
		}
	}
	file := f.GetPersistenceFile()
	path := "/var/lib/lindm/firewall/" + o.GetZoneId() + ".pb"
	if file == nil || file.GetPath() != path || file.GetExists() != (f.PersistenceContent != nil) || file.GetExists() != (f.GetPersistent() != nil) || !bytes.Equal(file.GetSecurityMetadataSha256(), nativefile.XattrDigest(f.GetPersistenceXattrs())) {
		return false
	}
	contentDigest := sha256.Sum256(f.GetPersistenceContent())
	if !bytes.Equal(o.GetPersistentSha256(), contentDigest[:]) {
		return false
	}
	if file.GetExists() {
		identity := file.GetFile()
		if identity.GetPath() != path || identity.GetUid() != 0 || identity.GetGid() != 0 || identity.GetMode() != 0600 || !bytes.Equal(identity.GetSha256(), contentDigest[:]) || f.GetPersistent().GetPhase() != agentv1.FirewallPersistencePhase_FIREWALL_PERSISTENCE_PHASE_COMMITTED {
			return false
		}
		state := &agentv1.FirewallPersistentState{}
		if proto.Unmarshal(f.GetPersistenceContent(), state) != nil || !proto.Equal(state, f.GetPersistent()) || state.GetDesired().GetZoneId() != o.GetZoneId() {
			return false
		}
	} else if o.GetExists() || len(f.GetChains()) != 0 || len(f.GetRules()) != 0 || len(f.GetPersistenceXattrs()) != 0 {
		return false
	}
	return true
}
func firewallOwnershipDimensionKind(kind resourcev1.ResourceKind, dimension agentv1.ResourceOwnedDimension) bool {
	return kind == resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE && (dimension == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_FIREWALL_RULESET || dimension == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_FIREWALL_PERSISTENCE)
}
func firewallOwnershipDimensionAllowed(action *agentv1.ResourceExecutionRecord, dimension agentv1.ResourceOwnedDimension) bool {
	return action.GetIntent().GetDesired().GetFirewallZone() != nil && firewallOwnershipDimensionKind(resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE, dimension)
}
func firewallOwnershipDimensionMatches(left, right *agentv1.ResourceOwnershipSnapshot, dimension agentv1.ResourceOwnedDimension) bool {
	if !firewallOwnershipSnapshotValid(left) || !firewallOwnershipSnapshotValid(right) || !proto.Equal(left.GetObservation().GetRef(), right.GetObservation().GetRef()) {
		return false
	}
	a, b := left.GetFirewall(), right.GetFirewall()
	switch dimension {
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_FIREWALL_RULESET:
		if !bytes.Equal(left.GetObservation().GetFirewallZone().GetNativeIdentitySha256(), right.GetObservation().GetFirewallZone().GetNativeIdentitySha256()) || len(a.GetRules()) != len(b.GetRules()) {
			return false
		}
		for i, r := range a.GetRules() {
			if r.GetChain() != b.GetRules()[i].GetChain() || !bytes.Equal(r.GetRawExpressionsSha256(), b.GetRules()[i].GetRawExpressionsSha256()) {
				return false
			}
		}
		return true
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_FIREWALL_PERSISTENCE:
		if left.GetObservation().GetMetadata().GetBootId() == right.GetObservation().GetMetadata().GetBootId() {
			return bytes.Equal(a.GetPersistenceContent(), b.GetPersistenceContent()) && proto.Equal(a.GetPersistenceFile(), b.GetPersistenceFile()) && slices.EqualFunc(a.GetPersistenceXattrs(), b.GetPersistenceXattrs(), func(x, y *agentv1.NativeFileXattr) bool { return proto.Equal(x, y) })
		}
		// The installed boot helper records its new boot after exact replay, so
		// only that receipt and the atomically replaced inode may differ.
		x, y := proto.CloneOf(a.GetPersistent()), proto.CloneOf(b.GetPersistent())
		if x == nil || y == nil {
			return x == nil && y == nil
		}
		if y.GetAppliedBootId() != right.GetObservation().GetMetadata().GetBootId() {
			return false
		}
		x.AppliedBootId = ""
		y.AppliedBootId = ""
		af, bf := a.GetPersistenceFile(), b.GetPersistenceFile()
		return proto.Equal(x, y) && bytes.Equal(af.GetAncestrySha256(), bf.GetAncestrySha256()) && bytes.Equal(af.GetSecurityMetadataSha256(), bf.GetSecurityMetadataSha256()) && af.GetFile().GetMode() == bf.GetFile().GetMode() && af.GetFile().GetUid() == bf.GetFile().GetUid() && af.GetFile().GetGid() == bf.GetFile().GetGid()
	default:
		return false
	}
}

// FirewallOwnershipMatches is the provider's dimension-safe release predicate.
func FirewallOwnershipMatches(left, right *agentv1.ResourceOwnershipSnapshot) bool {
	return firewallOwnershipDimensionMatches(left, right, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_FIREWALL_RULESET) && firewallOwnershipDimensionMatches(left, right, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_FIREWALL_PERSISTENCE)
}
func firewallOwnershipAcquisitionAllowed(intent *agentv1.ResourceExecutionIntent, snapshot *agentv1.ResourceOwnershipSnapshot) bool {
	if intent.GetDesired().GetFirewallZone() == nil || !firewallOwnershipSnapshotValid(snapshot) {
		return false
	}
	if !snapshot.GetObservation().GetFirewallZone().GetExists() && !snapshot.GetFirewall().GetPersistenceFile().GetExists() {
		return true
	}
	return intent.GetOwnership().GetPolicy().GetMode() == resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION && intent.GetOwnership().GetPolicy().GetAdoptionApprovalId() != ""
}
