//go:build linux

package accountprovider

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func testProvider() *Provider {
	return &Provider{config: Config{ActionID: uuid.NewString(), ExecutorIncarnation: uuid.NewString(), Native: &agentv1.NativeAccountProviderConfig{MinUid: 1000, MaxUid: 60000, MinGid: 1000, MaxGid: 60000}, Ownership: &agentv1.ResourceOwnershipBinding{Policy: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION, AdoptionApprovalId: proto.String(uuid.NewString()), Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED}}}, boot: uuid.NewString(), backend: &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_SHADOW, NativeVersion: "4.15", ProviderVersion: "1", Product: &resourcev1.PlatformProduct{OsId: "debian", Product: "Debian GNU/Linux", Version: "13", Architecture: "x86_64"}}}
}
func fixtureSnapshot(group bool) *agentv1.ResourceOwnershipSnapshot {
	name := "engineers"
	kind := resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP
	if !group {
		name = "alice"
		kind = resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER
	}
	generation := uuid.NewString()
	s := &agentv1.ResourceOwnershipSnapshot{Observation: &resourcev1.ResourceObservation{Ref: &resourcev1.ResourceRef{Kind: kind, CanonicalKey: name}, Metadata: &resourcev1.ObservationMetadata{BootId: uuid.NewString(), ExecutorIncarnation: uuid.NewString(), ObservedAt: timestamppb.Now(), Backend: testProvider().backend, NativeRevision: bytes.Repeat([]byte{1}, 32), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}}, AccountPrivate: &agentv1.ResourceAccountPrivate{NativeGeneration: generation, IdentityAnchorSha256: bytes.Repeat([]byte{2}, 32)}}
	if group {
		s.Observation.Observed = &resourcev1.ResourceObservation_LocalGroup{LocalGroup: &resourcev1.LocalGroupObservation{Name: name, Exists: true, Origin: resourcev1.NSSOrigin_NSS_ORIGIN_LOCAL_FILES, Gid: proto.Uint32(2000), Members: []string{"external"}, LocalFileRevision: bytes.Repeat([]byte{1}, 32), IdentitySha256: bytes.Repeat([]byte{3}, 32)}}
	} else {
		s.AccountPrivate.PasswordToken = proto.String("$6$private-baseline")
		s.Observation.Observed = &resourcev1.ResourceObservation_LocalUser{LocalUser: &resourcev1.LocalUserObservation{Name: name, Exists: true, Origin: resourcev1.NSSOrigin_NSS_ORIGIN_LOCAL_FILES, Uid: proto.Uint32(2001), Gid: proto.Uint32(2000), Groups: []string{"external"}, Home: &resourcev1.HomeMetadata{Path: "/home/alice", Exists: true, OwnerUid: 2001, OwnerGid: 2000, Mode: 0700, Device: 1, Inode: 2}, Shell: "/bin/sh", PasswordLocked: proto.Bool(false), Aging: &resourcev1.PasswordAging{MinDays: proto.Uint32(0), MaxDays: proto.Uint32(99999), WarnDays: proto.Uint32(7), AccountNeverExpires: proto.Bool(true), AccountLocked: proto.Bool(false)}, LocalFileRevision: bytes.Repeat([]byte{1}, 32), IdentitySha256: bytes.Repeat([]byte{3}, 32), UidGeneration: &generation, HasExternalData: true}}
	}
	return s
}
func fixtureDB() *localDB {
	return &localDB{users: map[string][]string{"alice": strings.Split("alice:x:2001:2000::/home/alice:/bin/sh", ":"), "external": strings.Split("external:x:2002:2003::/home/external:/bin/sh", ":"), "root": strings.Split("root:x:0:0::/root:/bin/sh", ":")}, groups: map[string][]string{"engineers": strings.Split("engineers:x:2000:external", ":"), "external": strings.Split("external:x:2003:alice", ":"), "root": strings.Split("root:x:0:", ":")}, revision: bytes.Repeat([]byte{1}, 32)}
}
func groupDesired(members *resourcev1.MemberSet) *resourcev1.ResourceDesiredState {
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP, CanonicalKey: "engineers"}, State: &resourcev1.ResourceDesiredState_LocalGroup{LocalGroup: &resourcev1.LocalGroupDesired{Name: "engineers", Presence: resourcev1.Presence_PRESENCE_PRESENT, Members: members}}}
}
func userDesired() *resourcev1.ResourceDesiredState {
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, CanonicalKey: "alice"}, State: &resourcev1.ResourceDesiredState_LocalUser{LocalUser: &resourcev1.LocalUserDesired{Name: "alice", Presence: resourcev1.Presence_PRESENCE_PRESENT}}}
}
func appliedLedger(baseline, last *agentv1.ResourceOwnershipSnapshot, dims ...agentv1.ResourceOwnedDimension) *agentv1.ResourceOwnershipLedger {
	return &agentv1.ResourceOwnershipLedger{State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED, Baseline: proto.CloneOf(baseline), LastApplied: proto.CloneOf(last), OwnedDimensions: dims, Owner: testProvider().config.Ownership}
}
func requireError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("unsafe state unexpectedly accepted")
	}
}
