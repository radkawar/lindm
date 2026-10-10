//go:build linux

package journal

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func definitionSnapshotFixture() *agentv1.ResourceOwnershipSnapshot {
	data := []byte("managed public definition\n")
	digest := sha256.Sum256(data)
	file := &resourcev1.ManagedFileObservation{Path: "/etc/systemd/system/example.timer", Exists: true, File: &resourcev1.FileIdentity{Path: "/etc/systemd/system/example.timer", Device: 1, Inode: 2, Mode: 0644, Sha256: digest[:]}, AncestrySha256: bytes.Repeat([]byte{1}, 32), NativeIdentitySha256: bytes.Repeat([]byte{2}, 32), SecurityMetadataSha256: bytes.Repeat([]byte{3}, 32)}
	o := &resourcev1.SystemdDefinitionObservation{CanonicalKey: "timer/example.timer", Exists: true, OwnedFile: proto.CloneOf(file.File), FileState: proto.CloneOf(file), DefinitionSha256: bytes.Repeat([]byte{4}, 32), TargetDefinitionSha256: bytes.Repeat([]byte{5}, 32), TimerScheduleSha256: bytes.Repeat([]byte{6}, 32), TimerEnabled: proto.Bool(true), TimerActive: proto.Bool(true), TimerInvocationId: bytes.Repeat([]byte{7}, 16), TimerInstallProjectionComplete: true, TimerUnitFileState: "enabled", TimerInstallLinks: []*resourcev1.InstallLink{{Path: "/etc/systemd/system/timers.target.wants/example.timer", Target: file.GetPath(), Device: 1, Inode: 3, AncestrySha256: bytes.Repeat([]byte{8}, 32)}}}
	return &agentv1.ResourceOwnershipSnapshot{Observation: &resourcev1.ResourceObservation{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION, CanonicalKey: o.GetCanonicalKey()}, Metadata: &resourcev1.ObservationMetadata{BootId: "11111111-1111-4111-8111-111111111111"}, Observed: &resourcev1.ResourceObservation_SystemdDefinition{SystemdDefinition: o}}, DefinitionFile: &agentv1.DefinitionFileSnapshot{State: file, Content: data, ParentIdentitySha256: bytes.Repeat([]byte{9}, 32), NativeRevisionSha256: bytes.Repeat([]byte{10}, 32)}}
}
func TestDefinitionSnapshotRequiresMatchingPrivateCustody(t *testing.T) {
	s := definitionSnapshotFixture()
	if !definitionOwnershipSnapshotValid(s) {
		t.Fatal("complete definition snapshot refused")
	}
	for _, mutate := range []func(*agentv1.ResourceOwnershipSnapshot){func(s *agentv1.ResourceOwnershipSnapshot) { s.DefinitionFile = nil }, func(s *agentv1.ResourceOwnershipSnapshot) { s.DefinitionFile.Content = []byte("different") }, func(s *agentv1.ResourceOwnershipSnapshot) { s.DefinitionFile.State.Path = "/etc/passwd" }, func(s *agentv1.ResourceOwnershipSnapshot) {
		s.Observation.GetSystemdDefinition().TimerInstallProjectionComplete = false
	}, func(s *agentv1.ResourceOwnershipSnapshot) { s.DefinitionFile.ParentMissing = true }} {
		bad := proto.CloneOf(s)
		mutate(bad)
		if definitionOwnershipSnapshotValid(bad) {
			t.Fatal("incomplete or substituted native evidence accepted")
		}
	}
}
func TestDefinitionOwnedDimensionsRejectABA(t *testing.T) {
	base := definitionSnapshotFixture()
	for dimension, mutate := range map[agentv1.ResourceOwnedDimension]func(*agentv1.ResourceOwnershipSnapshot){
		agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_DEFINITION_FILE: func(s *agentv1.ResourceOwnershipSnapshot) {
			s.DefinitionFile.State.NativeIdentitySha256 = bytes.Repeat([]byte{99}, 32)
		},
		agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_DEFINITION_ENABLEMENT: func(s *agentv1.ResourceOwnershipSnapshot) {
			s.Observation.GetSystemdDefinition().TimerInstallLinks[0].Inode++
		},
		agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_DEFINITION_RUNTIME: func(s *agentv1.ResourceOwnershipSnapshot) {
			s.Observation.GetSystemdDefinition().TimerInvocationId = bytes.Repeat([]byte{99}, 16)
		},
	} {
		if !definitionOwnershipDimensionMatches(base, proto.CloneOf(base), dimension) {
			t.Fatalf("unchanged dimension %s refused", dimension)
		}
		other := proto.CloneOf(base)
		mutate(other)
		if definitionOwnershipDimensionMatches(base, other, dimension) {
			t.Fatalf("ABA dimension %s accepted", dimension)
		}
		if definitionOwnershipDimensionKind(resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, dimension) {
			t.Fatal("definition authority widened service ownership")
		}
	}
}
