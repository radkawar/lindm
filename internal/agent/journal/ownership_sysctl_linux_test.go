//go:build linux

package journal

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativefile"
)

func sysctlOwnershipFixture() *agentv1.ResourceOwnershipSnapshot {
	key := "vm.swappiness"
	path := fmt.Sprintf("/etc/sysctl.d/60-lindm-%x.conf", sha256.Sum256([]byte(key)))
	file := &resourcev1.ManagedFileObservation{Path: path, AncestrySha256: make([]byte, 32), NativeIdentitySha256: make([]byte, 32), SecurityMetadataSha256: nativefile.XattrDigest(nil)}
	return &agentv1.ResourceOwnershipSnapshot{Observation: &resourcev1.ResourceObservation{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL, CanonicalKey: key}, Observed: &resourcev1.ResourceObservation_Sysctl{Sysctl: &resourcev1.SysctlObservation{Key: key, Value: proto.String("60"), NativeIdentitySha256: make([]byte, 32), PersistenceFileState: proto.CloneOf(file)}}}, SysctlPersistence: &agentv1.SysctlPersistenceSnapshot{State: file}}
}
func TestSysctlJournalRejectsInventedPersistenceBaseline(t *testing.T) {
	good := sysctlOwnershipFixture()
	if !sysctlOwnershipSnapshotValid(good) {
		t.Fatal("complete absent baseline rejected")
	}
	for _, change := range []func(*agentv1.ResourceOwnershipSnapshot){
		func(s *agentv1.ResourceOwnershipSnapshot) { s.SysctlPersistence = nil },
		func(s *agentv1.ResourceOwnershipSnapshot) { s.GetObservation().GetSysctl().Value = nil },
		func(s *agentv1.ResourceOwnershipSnapshot) { s.SysctlPersistence.State.Path = "/etc/shadow" },
		func(s *agentv1.ResourceOwnershipSnapshot) { s.SysctlPersistence.Content = []byte("invented") },
		func(s *agentv1.ResourceOwnershipSnapshot) { s.GetObservation().GetSysctl().NativeIdentitySha256 = nil },
		func(s *agentv1.ResourceOwnershipSnapshot) {
			s.SysctlPersistence.Xattrs = []*agentv1.NativeFileXattr{{Name: "user.test", Value: []byte("changed")}}
		},
	} {
		bad := proto.CloneOf(good)
		change(bad)
		if sysctlOwnershipSnapshotValid(bad) {
			t.Fatal("incomplete or mismatched private baseline accepted")
		}
	}
}
func TestSysctlJournalComparesOnlyOwnedDimensions(t *testing.T) {
	before := sysctlOwnershipFixture()
	after := proto.CloneOf(before)
	after.GetObservation().GetSysctl().Value = proto.String("20")
	if sysctlOwnershipDimensionMatches(before, after, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_VALUE) {
		t.Fatal("changed live value still owned")
	}
	if !sysctlOwnershipDimensionMatches(before, after, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_PERSISTENCE) {
		t.Fatal("unowned live change contaminated file dimension")
	}
	after = proto.CloneOf(before)
	after.GetObservation().GetSysctl().NativeIdentitySha256[0]++
	if sysctlOwnershipDimensionMatches(before, after, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_VALUE) {
		t.Fatal("recreated proc key retained ownership")
	}
	if sysctlOwnershipDimensionKind(resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_VALUE) {
		t.Fatal("cross-kind dimension admitted")
	}
}
func TestSysctlJournalRequiresAdoptionAndPersistentIntent(t *testing.T) {
	before := sysctlOwnershipFixture()
	intent := &agentv1.ResourceExecutionIntent{Desired: &resourcev1.ResourceDesiredState{Ref: before.GetObservation().GetRef(), State: &resourcev1.ResourceDesiredState_Sysctl{Sysctl: &resourcev1.SysctlDesired{Key: "vm.swappiness", Value: "20"}}}, Ownership: &agentv1.ResourceOwnershipBinding{Policy: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY}}}
	if sysctlOwnershipAcquisitionAllowed(intent, before) {
		t.Fatal("existing kernel value acquired through create-only policy")
	}
	intent.Ownership.Policy.Mode = resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION
	if !sysctlOwnershipAcquisitionAllowed(intent, before) {
		t.Fatal("approved complete baseline rejected")
	}
	action := &agentv1.ResourceExecutionRecord{Intent: intent}
	if sysctlOwnershipDimensionAllowed(action, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_PERSISTENCE) {
		t.Fatal("runtime-only intent acquired persistent ownership")
	}
	intent.GetDesired().GetSysctl().Persistent = true
	if !sysctlOwnershipDimensionAllowed(action, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_PERSISTENCE) {
		t.Fatal("persistent desired dimension rejected")
	}
}
