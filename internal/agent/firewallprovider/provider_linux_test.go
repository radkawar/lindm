//go:build linux

package firewallprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/nativefile"
)

// These seams exercise signed-plan/ownership ordering and refusal, not native
// application success. Actual kernel behavior is covered in the isolated test;
// installed persistence and packet proof are separate VM qualification fixtures.
type memoryOwnership struct {
	ledger *agentv1.ResourceOwnershipLedger
	owner  *agentv1.ResourceOwnershipBinding
	action string
}

func (m *memoryOwnership) LoadResourceOwnership(context.Context, string, string, string, *resourcev1.ResourceRef) (*agentv1.ResourceOwnershipLedger, error) {
	if m.ledger == nil {
		return nil, journal.ErrResourceOwnershipNotFound
	}
	return proto.CloneOf(m.ledger), nil
}
func (m *memoryOwnership) ClaimResourceOwnership(_ context.Context, action string, revision int64, before *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error) {
	m.ledger = &agentv1.ResourceOwnershipLedger{FormatVersion: 1, InstallationId: uuid.NewString(), DeploymentId: uuid.NewString(), DeviceId: uuid.NewString(), EnrollmentGeneration: uuid.NewString(), Ref: proto.CloneOf(before.GetObservation().GetRef()), Owner: proto.CloneOf(m.owner), Revision: uint64(revision) + 1, State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_CLAIMED, Baseline: proto.CloneOf(before), OwnerIntentEnvelope: []byte("ordering-test-only"), ClaimActionId: action}
	return proto.CloneOf(m.ledger), nil
}
func (m *memoryOwnership) BeginResourceOwnershipEffect(_ context.Context, action string, _ int64, before *agentv1.ResourceOwnershipSnapshot, dimensions []agentv1.ResourceOwnedDimension) (*agentv1.ResourceOwnershipLedger, error) {
	m.ledger.State = agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN
	m.ledger.BeforeEffect = proto.CloneOf(before)
	m.ledger.EffectActionId = proto.String(action)
	m.ledger.OwnedDimensions = dimensions
	m.ledger.Revision++
	m.action = action
	return proto.CloneOf(m.ledger), nil
}
func (m *memoryOwnership) CompleteResourceOwnershipEffect(_ context.Context, _ string, _ int64, after *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error) {
	m.ledger.State = agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED
	m.ledger.LastApplied = proto.CloneOf(after)
	m.ledger.Revision++
	return proto.CloneOf(m.ledger), nil
}
func providerFixture(t *testing.T) (*Provider, *memoryOwnership, *agentv1.ResourceOwnershipSnapshot, *resourcev1.ResourceDesiredState) {
	t.Helper()
	state, config := compilerFixture(t)
	platform := &resourcev1.PlatformProduct{OsId: "ubuntu", Product: "Ubuntu", Version: "24.04", Architecture: "x86_64"}
	backend := &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_NFTABLES, NativeVersion: "test-kernel", ProviderVersion: "1", Product: platform}
	incarnation := uuid.NewString()
	ref := &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE, CanonicalKey: state.GetDesired().GetZoneId()}
	native := &agentv1.FirewallNativeSnapshot{Table: tableName(ref.GetCanonicalKey()), RulesetGeneration: 1, NetworkNamespaceSha256: bytes.Repeat([]byte{4}, 32), PersistenceFile: &resourcev1.ManagedFileObservation{Path: StatePath(ref.GetCanonicalKey()), AncestrySha256: bytes.Repeat([]byte{1}, 32), NativeIdentitySha256: bytes.Repeat([]byte{2}, 32), SecurityMetadataSha256: nativefile.XattrDigest(nil)}}
	digest, err := nativeDigest(native)
	if err != nil {
		t.Fatal(err)
	}
	empty := sha256.Sum256(nil)
	observation := &resourcev1.FirewallZoneObservation{ZoneId: ref.GetCanonicalKey(), NativeOwner: "lindm-dedicated-nftables", NativeVersion: "test-kernel", Table: native.GetTable(), PersistentSha256: empty[:], KernelRulesSha256: digest, NativeIdentitySha256: digest, NetworkNamespaceSha256: native.GetNetworkNamespaceSha256(), DefaultIngress: resourcev1.FirewallVerdict_FIREWALL_VERDICT_ACCEPT, DefaultEgress: resourcev1.FirewallVerdict_FIREWALL_VERDICT_ACCEPT, PersistentReady: true}
	snapshot := &agentv1.ResourceOwnershipSnapshot{Observation: &resourcev1.ResourceObservation{Ref: ref, Metadata: &resourcev1.ObservationMetadata{BootId: state.GetAppliedBootId(), ExecutorIncarnation: incarnation, ObservedAt: timestamppb.Now(), Backend: backend, NativeRevision: digest, ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}, Observed: &resourcev1.ResourceObservation_FirewallZone{FirewallZone: observation}}, Firewall: native}
	store := &memoryOwnership{owner: state.GetOwner()}
	p := &Provider{config: Config{Native: config, Platform: platform, Ownership: state.GetOwner(), ActionID: state.GetGeneration(), DeploymentID: state.GetDeploymentId(), DeviceID: state.GetDeviceId(), EnrollmentGeneration: state.GetEnrollmentGeneration(), ExecutorIncarnation: incarnation}, store: store, backend: backend}
	p.config.NativeRead = func(context.Context, *resourcev1.ResourceObservation) (*agentv1.ResourceOwnershipSnapshot, error) {
		result := proto.CloneOf(snapshot)
		result.Observation.Metadata.ObservedAt = timestamppb.Now()
		return result, nil
	}
	return p, store, snapshot, &resourcev1.ResourceDesiredState{Ref: proto.CloneOf(ref), State: &resourcev1.ResourceDesiredState_FirewallZone{FirewallZone: state.GetDesired()}}
}
func TestDurableUnknownPrecedesFinalAuthorityAndPreventsReplay(t *testing.T) {
	p, store, _, desired := providerFixture(t)
	plan, err := p.Plan(t.Context(), desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	p.config.NativeApply = func(ctx context.Context, _ *agentv1.NativeResourceTransactionRequest, gate func(context.Context) error) error {
		calls++
		if store.ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
			t.Fatal("native helper invoked before durable uncertainty")
		}
		if err := gate(ctx); err != nil {
			return err
		}
		return errors.New("lost netlink acknowledgment")
	}
	gates := 0
	if _, err := p.Apply(t.Context(), plan, func(context.Context) error { gates++; return nil }); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("lost ack outcome: %v", err)
	}
	if calls != 1 || gates != 1 {
		t.Fatal("native final gate cardinality")
	}
	if _, err := p.Plan(t.Context(), desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal("uncertain transaction was replayable")
	}
	if calls != 1 {
		t.Fatal("planning retried native transaction")
	}
}
func TestChangedNativeStateRejectsBeforeAuthority(t *testing.T) {
	p, _, snapshot, desired := providerFixture(t)
	plan, err := p.Plan(t.Context(), desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Observation.GetFirewallZone().ForeignTables = []string{"new-firewalld-generation"}
	p.config.NativeApply = func(context.Context, *agentv1.NativeResourceTransactionRequest, func(context.Context) error) error {
		t.Fatal("stale plan reached native helper")
		return nil
	}
	if _, err := p.Apply(t.Context(), plan, func(context.Context) error { t.Fatal("stale plan consumed authority"); return nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale plan: %v", err)
	}
}
func appliedSnapshot(t *testing.T, p *Provider, before *agentv1.ResourceOwnershipSnapshot, desired *resourcev1.ResourceDesiredState) *agentv1.ResourceOwnershipSnapshot {
	t.Helper()
	target, err := targetSnapshot(desired.GetFirewallZone(), before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, p.config.Ownership, p.config.Native, p.config.ActionID, p.config.DeploymentID, p.config.DeviceID, p.config.EnrollmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range target.Firewall.Rules {
		r.Handle = uint64(i + 1)
		r.RawExpressionsSha256 = bytes.Clone(r.GetExpressionsSha256())
	}
	sortNative(target.Firewall)
	target.Firewall.PersistenceFile.File.Device = 1
	target.Firewall.PersistenceFile.File.Inode = 123
	target.Firewall.PersistenceFile.NativeIdentitySha256 = bytes.Repeat([]byte{9}, 32)
	digest, err := nativeDigest(target.Firewall)
	if err != nil {
		t.Fatal(err)
	}
	target.Observation.Metadata.NativeRevision = bytes.Clone(digest)
	o := target.Observation.GetFirewallZone()
	o.Exists = true
	o.KernelRulesSha256 = digest
	o.NativeIdentitySha256 = digest
	o.OwnershipUserdata = bytes.Clone(target.Firewall.GetUserdata())
	persistent := sha256.Sum256(target.Firewall.GetPersistenceContent())
	o.PersistentSha256 = persistent[:]
	o.PersistentRules = desired.GetFirewallZone().GetRules()
	o.ActiveRules = desired.GetFirewallZone().GetRules()
	o.BoundInterfaces = desired.GetFirewallZone().GetInterfaces()
	o.DefaultIngress = desired.GetFirewallZone().GetDefaultIngress()
	o.DefaultEgress = desired.GetFirewallZone().GetDefaultEgress()
	return target
}
func TestOwnershipReleaseRequiresExactGenerationAndExpression(t *testing.T) {
	p, _, before, desired := providerFixture(t)
	applied := appliedSnapshot(t, p, before, desired)
	ledger := &agentv1.ResourceOwnershipLedger{State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED, Owner: p.config.Ownership, Baseline: before, LastApplied: applied}
	target, err := targetSnapshot(desired.GetFirewallZone(), applied, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE, p.config.Ownership, p.config.Native, p.config.ActionID, p.config.DeploymentID, p.config.DeviceID, p.config.EnrollmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if len(target.GetFirewall().GetUserdata()) != 0 || target.GetFirewall().GetPersistenceFile().GetExists() {
		t.Fatal("owned creation did not restore absence")
	}
	for _, change := range []func(*agentv1.ResourceOwnershipSnapshot){func(s *agentv1.ResourceOwnershipSnapshot) { s.Firewall.Userdata[0] ^= 1 }, func(s *agentv1.ResourceOwnershipSnapshot) { s.Firewall.Rules[0].RawExpressionsSha256[0] ^= 1 }, func(s *agentv1.ResourceOwnershipSnapshot) { s.Firewall.PersistenceContent[0] ^= 1 }, func(s *agentv1.ResourceOwnershipSnapshot) { s.Firewall.PersistenceFile.File.Mode = 0644 }} {
		drift := proto.CloneOf(applied)
		change(drift)
		if _, err := targetSnapshot(desired.GetFirewallZone(), drift, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE, p.config.Ownership, p.config.Native, p.config.ActionID, p.config.DeploymentID, p.config.DeviceID, p.config.EnrollmentGeneration); !errors.Is(err, ErrConflict) {
			t.Fatal("release removed operator-modified owned dimension")
		}
	}
}
func TestExistingDedicatedStateRequiresApprovedAdoption(t *testing.T) {
	p, _, before, desired := providerFixture(t)
	applied := appliedSnapshot(t, p, before, desired)
	if err := acquisitionAllowed(p.config.Ownership, applied, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrConflict) {
		t.Fatal("unapproved dedicated object acquired")
	}
	owner := proto.CloneOf(p.config.Ownership)
	owner.Policy.Mode = resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION
	owner.Policy.AdoptionApprovalId = proto.String(uuid.NewString())
	if err := acquisitionAllowed(owner, applied, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); err != nil {
		t.Fatal(err)
	}
	applied.Firewall.Conflict = true
	if err := acquisitionAllowed(owner, applied, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrConflict) {
		t.Fatal("approval adopted foreign/unmodelled table")
	}
}
func TestKernelOnlyStateNeverClaimsPersistentConvergence(t *testing.T) {
	p, _, before, desired := providerFixture(t)
	target := appliedSnapshot(t, p, before, desired)
	plan, err := p.makePlan(desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := p.verification(t.Context(), plan, target, target)
	if !errors.Is(err, ErrNotConverged) || verification.GetFirewallZone().GetConverged() || verification.GetDisposition() != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_UNKNOWN {
		t.Fatal("kernel readback manufactured allow/deny packet proof")
	}
	target.Observation.GetFirewallZone().PersistentReady = false
	verification, err = p.verification(t.Context(), plan, target, target)
	if !errors.Is(err, ErrNotConverged) || verification.GetFirewallZone().GetPersistentMatches() {
		t.Fatal("missing installed reboot helper reported persistent")
	}
}

func TestApprovedAdoptionRestoresExactBaselineAndRetainDoesNotDelete(t *testing.T) {
	p, _, absent, desired := providerFixture(t)
	baseline := appliedSnapshot(t, p, absent, desired)
	owner := proto.CloneOf(p.config.Ownership)
	owner.Policy.Mode = resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION
	owner.Policy.AdoptionApprovalId = proto.String(uuid.NewString())
	p.config.Ownership = owner
	p.config.ActionID = uuid.NewString()
	changed := proto.CloneOf(desired)
	changed.GetFirewallZone().DefaultEgress = resourcev1.FirewallVerdict_FIREWALL_VERDICT_ACCEPT
	applied := appliedSnapshot(t, p, baseline, changed)
	ledger := &agentv1.ResourceOwnershipLedger{State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED, Owner: owner, Baseline: baseline, LastApplied: applied}
	restored, err := targetSnapshot(changed.GetFirewallZone(), applied, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE, owner, p.config.Native, p.config.ActionID, p.config.DeploymentID, p.config.DeviceID, p.config.EnrollmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(restored, baseline) {
		t.Fatal("approved adoption did not restore exact typed original baseline")
	}
	retained := proto.CloneOf(ledger)
	retained.Owner.Policy.Release = resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN
	kept, err := targetSnapshot(changed.GetFirewallZone(), applied, retained, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE, retained.GetOwner(), p.config.Native, p.config.ActionID, p.config.DeploymentID, p.config.DeviceID, p.config.EnrollmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(kept, applied) {
		t.Fatal("retain changed owned objects")
	}
}

func TestRebootReceiptPermitsOnlyExactOwnedReplay(t *testing.T) {
	p, _, absent, desired := providerFixture(t)
	before := appliedSnapshot(t, p, absent, desired)
	after := proto.CloneOf(before)
	boot := uuid.NewString()
	after.Observation.Metadata.BootId = boot
	after.Firewall.Persistent.AppliedBootId = boot
	after.Firewall.PersistenceFile.File.Inode++
	after.Firewall.PersistenceFile.NativeIdentitySha256 = bytes.Repeat([]byte{8}, 32)
	after.Firewall.NetworkNamespaceSha256 = bytes.Repeat([]byte{7}, 32)
	after.Observation.GetFirewallZone().NetworkNamespaceSha256 = bytes.Clone(after.Firewall.GetNetworkNamespaceSha256())
	content, err := (proto.MarshalOptions{Deterministic: true}).Marshal(after.Firewall.Persistent)
	if err != nil {
		t.Fatal(err)
	}
	after.Firewall.PersistenceContent = content
	digest := sha256.Sum256(content)
	after.Firewall.PersistenceFile.File.Sha256 = digest[:]
	after.Observation.GetFirewallZone().PersistentSha256 = digest[:]
	if !journal.FirewallOwnershipMatches(before, after) {
		t.Fatal("exact installed-helper reboot receipt lost ownership")
	}
	after.Firewall.Rules[0].RawExpressionsSha256[0] ^= 1
	if journal.FirewallOwnershipMatches(before, after) {
		t.Fatal("reboot bypassed exact expression ownership")
	}
}

func TestPendingStateNeverBecomesForwardReplayAuthority(t *testing.T) {
	p, _, before, desired := providerFixture(t)
	target := appliedSnapshot(t, p, before, desired)
	content, err := pendingContent(before, target, p.config.ActionID)
	if err != nil {
		t.Fatal(err)
	}
	pending := &agentv1.FirewallPersistentState{}
	if err := proto.Unmarshal(content, pending); err != nil {
		t.Fatal(err)
	}
	if pending.GetPhase() != agentv1.FirewallPersistencePhase_FIREWALL_PERSISTENCE_PHASE_PENDING || target.GetFirewall().GetPersistent().GetPhase() != agentv1.FirewallPersistencePhase_FIREWALL_PERSISTENCE_PHASE_COMMITTED {
		t.Fatal("pending marker mutated committed target")
	}
	configuration, err := messageDigest(p.config.Native)
	if err != nil {
		t.Fatal(err)
	}
	if err := replayStateValid(pending, desired.GetRef().GetCanonicalKey(), configuration); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal("uncertain marker authorized boot forward replay")
	}
	if err := replayStateValid(target.GetFirewall().GetPersistent(), desired.GetRef().GetCanonicalKey(), configuration); err != nil {
		t.Fatal(err)
	}
	configuration[0] ^= 1
	if err := replayStateValid(target.GetFirewall().GetPersistent(), desired.GetRef().GetCanonicalKey(), configuration); !errors.Is(err, ErrConflict) {
		t.Fatal("changed root configuration authorized replay")
	}
	releaseMarker, err := pendingContent(target, before, p.config.ActionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(releaseMarker, pending); err != nil {
		t.Fatal(err)
	}
	if pending.GetDesired().GetPresence() != resourcev1.Presence_PRESENCE_ABSENT {
		t.Fatal("release marker could recreate target after crash")
	}
}

func TestGuardIsMandatoryBeforeNativeEffects(t *testing.T) {
	called := false
	if err := ApplyNative(t.Context(), nil, nil, nil, func(context.Context) error { called = true; return nil }); !errors.Is(err, ErrUnsupported) || called {
		t.Fatal("missing independent guard reached native authority")
	}
}

func TestConfirmationReceiptMayPrecedeFinalReadback(t *testing.T) {
	p, _, before, desired := providerFixture(t)
	now := time.Now()
	before.Observation.Metadata.ObservedAt = timestamppb.New(now.Add(-2 * time.Second))
	target := appliedSnapshot(t, p, before, desired)
	target.Observation.Metadata.ObservedAt = timestamppb.New(now)
	plan, err := p.makePlan(desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.GetSafety().GetConfirmation() != resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_CONNECTIVITY {
		t.Fatal("plan omitted connectivity confirmation")
	}
	// This trusted-callback fixture tests timing only, not authentication or packets.
	receipt := &resourcev1.ProbeReceipt{ProbeId: uuid.NewString(), ObservedAt: timestamppb.New(now.Add(-time.Second)), EvidenceSha256: bytes.Repeat([]byte{5}, 32), Passed: true}
	p.config.NativeProbe = func(context.Context, *resourcev1.FirewallZoneDesired, *resourcev1.ResourceObservation) (*resourcev1.ProbeReceipt, *resourcev1.ProbeReceipt, error) {
		return proto.CloneOf(receipt), proto.CloneOf(receipt), nil
	}
	if verification, err := p.verification(t.Context(), plan, target, target); err != nil || !verification.GetFirewallZone().GetConverged() {
		t.Fatalf("fresh pre-readback confirmation rejected: %v", err)
	}
	receipt.ObservedAt = timestamppb.New(now.Add(-2 * time.Minute))
	if _, err := p.verification(t.Context(), plan, target, target); !errors.Is(err, ErrConflict) {
		t.Fatal("stale connectivity proof accepted")
	}
}

func TestRollbackCrashWindowsAreOwnedAndNeverForwardReplay(t *testing.T) {
	p, _, before, desired := providerFixture(t)
	target := appliedSnapshot(t, p, before, desired)
	if complete, err := rollbackDecision(before, before, target, nil, p.config.Native, "before"); err != nil || !complete {
		t.Fatal("pre-effect guard could not close without mutation")
	}
	if complete, err := rollbackDecision(before, before, target, nil, p.config.Native, "pending"); err != nil || complete {
		t.Fatal("pre-kernel pending marker could not restore only persistence")
	}
	if complete, err := rollbackDecision(target, before, target, nil, p.config.Native, "pending"); err != nil || complete {
		t.Fatal("post-kernel lost Applied receipt prevented exact typed inverse")
	}
	drift := proto.CloneOf(target)
	drift.Firewall.Rules[0].RawExpressionsSha256[0] ^= 1
	if _, err := rollbackDecision(drift, before, target, target, p.config.Native, "pending"); !errors.Is(err, ErrConflict) {
		t.Fatal("recorded raw expression drift permitted rollback")
	}
	// An existing adopted baseline permits reboot restoration only with an exact
	// supervisor-classified pending/target file, never an unrelated current file.
	baseline := target
	p.config.ActionID = uuid.NewString()
	changed := proto.CloneOf(desired)
	changed.GetFirewallZone().DefaultEgress = resourcev1.FirewallVerdict_FIREWALL_VERDICT_ACCEPT
	target = appliedSnapshot(t, p, baseline, changed)
	reboot := proto.CloneOf(before)
	reboot.Observation.Metadata.BootId = uuid.NewString()
	if _, err := rollbackDecision(reboot, baseline, target, nil, p.config.Native, "unrelated"); !errors.Is(err, ErrConflict) {
		t.Fatal("reboot absence adopted unrelated persistence")
	}
	if complete, err := rollbackDecision(reboot, baseline, target, nil, p.config.Native, "pending"); err != nil || complete {
		t.Fatal("owned interrupted reboot could not restore baseline")
	}
	drift = proto.CloneOf(target)
	drift.Firewall.Userdata[0] ^= 1
	if _, err := rollbackDecision(drift, baseline, target, nil, p.config.Native, "pending"); !errors.Is(err, ErrConflict) {
		t.Fatal("changed native generation permitted rollback")
	}
}
