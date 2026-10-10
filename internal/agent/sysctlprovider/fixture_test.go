//go:build linux

package sysctlprovider

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/nativefile"
)

const fixtureID = "6cc7fca6-0947-4b20-86e1-4cc705c58191"
const fixtureNextBoot = "8e4209ed-dc38-4b12-aef6-53c036375682"

type memoryOwnership struct {
	ledger        *agentv1.ResourceOwnershipLedger
	owner         *agentv1.ResourceOwnershipBinding
	complete      int
	releasing     bool
	completionErr error
}

func (s *memoryOwnership) LoadResourceOwnership(context.Context, string, string, string, *resourcev1.ResourceRef) (*agentv1.ResourceOwnershipLedger, error) {
	if s.ledger == nil {
		return nil, journal.ErrResourceOwnershipNotFound
	}
	return proto.CloneOf(s.ledger), nil
}
func (s *memoryOwnership) ClaimResourceOwnership(_ context.Context, action string, revision int64, before *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error) {
	s.ledger = &agentv1.ResourceOwnershipLedger{Ref: proto.CloneOf(before.GetObservation().GetRef()), Owner: proto.CloneOf(s.owner), Baseline: proto.CloneOf(before), Revision: uint64(revision + 1), State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_CLAIMED, ClaimActionId: action}
	return proto.CloneOf(s.ledger), nil
}
func (s *memoryOwnership) BeginResourceOwnershipEffect(_ context.Context, action string, revision int64, before *agentv1.ResourceOwnershipSnapshot, dimensions []agentv1.ResourceOwnedDimension) (*agentv1.ResourceOwnershipLedger, error) {
	s.ledger.BeforeEffect = proto.CloneOf(before)
	s.ledger.EffectActionId = proto.String(action)
	s.ledger.Revision = uint64(revision + 1)
	s.ledger.State = agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN
	s.ledger.OwnedDimensions = dimensions
	return proto.CloneOf(s.ledger), nil
}
func (s *memoryOwnership) CompleteResourceOwnershipEffect(_ context.Context, _ string, revision int64, after *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error) {
	if s.completionErr != nil {
		return nil, s.completionErr
	}
	s.complete++
	s.ledger.LastApplied = proto.CloneOf(after)
	s.ledger.Revision = uint64(revision + 1)
	s.ledger.State = agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED
	if s.releasing {
		s.ledger.State = agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED
	}
	return proto.CloneOf(s.ledger), nil
}

func fixtureProvider(t *testing.T) (*Provider, *memoryOwnership, **agentv1.ResourceOwnershipSnapshot, *resourcev1.ResourceDesiredState) {
	t.Helper()
	owner := &agentv1.ResourceOwnershipBinding{AssignmentId: fixtureID, ResourceId: fixtureID, Sources: []*agentv1.ResourceOwnershipSource{{ProfileId: fixtureID, ProfileRevision: fixtureID, ResourceId: fixtureID}}, Policy: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED, AdoptionApprovalId: proto.String(fixtureID)}}
	platform := &resourcev1.PlatformProduct{OsId: "ubuntu", Product: "Ubuntu", Version: "24.04", Architecture: "x86_64"}
	backend := &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_PROC_SYSCTL, NativeVersion: "6.8.0", ProviderVersion: "1", Product: platform}
	desired := desiredState(&resourcev1.SysctlDesired{Key: "vm.swappiness", Value: "20"})
	file := &resourcev1.ManagedFileObservation{Path: StanzaPath(desired.GetSysctl().GetKey()), AncestrySha256: make([]byte, 32), NativeIdentitySha256: make([]byte, 32), SecurityMetadataSha256: nativefile.XattrDigest(nil)}
	o := &resourcev1.ResourceObservation{Ref: proto.CloneOf(desired.GetRef()), Metadata: &resourcev1.ObservationMetadata{BootId: fixtureID, ExecutorIncarnation: fixtureID, ObservedAt: timestamppb.New(time.Unix(1700000000, 0)), Backend: backend, NativeRevision: make([]byte, 32), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}, Observed: &resourcev1.ResourceObservation_Sysctl{Sysctl: &resourcev1.SysctlObservation{Key: desired.GetSysctl().GetKey(), Value: proto.String("60"), PersistenceGraphSha256: make([]byte, 32), NativeIdentitySha256: make([]byte, 32), PersistenceFileState: proto.CloneOf(file)}}}
	current := &agentv1.ResourceOwnershipSnapshot{Observation: o, SysctlPersistence: &agentv1.SysctlPersistenceSnapshot{State: file}}
	store := &memoryOwnership{owner: owner}
	p := &Provider{config: Config{Native: &agentv1.NativeSysctlProviderConfig{AllowedKeys: []string{"vm.swappiness"}}, Ownership: owner, Platform: platform, ExecutorIncarnation: fixtureID, ActionID: fixtureID}, store: store, backend: backend}
	p.observe = func(context.Context, *resourcev1.SysctlDesired) (*agentv1.ResourceOwnershipSnapshot, error) {
		return proto.CloneOf(current), nil
	}
	p.config.NativeApply = func(ctx context.Context, request *agentv1.NativeResourceTransactionRequest, gate func(context.Context) error) error {
		if err := gate(ctx); err != nil {
			return err
		}
		current = proto.CloneOf(request.GetTarget())
		return nil
	}
	return p, store, &current, desired
}
func persistentFixture(source *agentv1.ResourceOwnershipSnapshot, value string) *agentv1.ResourceOwnershipSnapshot {
	s := proto.CloneOf(source)
	o := s.GetObservation().GetSysctl()
	content := stanza(o.GetKey(), value)
	digest := sha256.Sum256(content)
	file := s.SysctlPersistence
	file.Content = content
	file.State.Exists = true
	file.State.File = &resourcev1.FileIdentity{Path: file.State.GetPath(), Device: 1, Inode: 2, Mode: 0644, Sha256: digest[:]}
	o.Value = proto.String(value)
	o.PersistentValue = proto.String(value)
	o.PersistentSource = proto.String(file.State.GetPath())
	o.PersistenceFileState = proto.CloneOf(file.State)
	o.OwnedPersistenceFile = proto.CloneOf(file.State.File)
	return s
}
