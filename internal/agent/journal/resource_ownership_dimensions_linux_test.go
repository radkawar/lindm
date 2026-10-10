package journal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestAccountOwnershipAdditiveEdgesPreserveUnrelatedMembership(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := accountResourceRecord(t, f, resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP)
	before := ownershipSnapshot(record)
	before.Observation.GetLocalGroup().Exists = true
	before.Observation.GetLocalGroup().Gid = proto.Uint32(1200)
	before.Observation.GetLocalGroup().Members = []string{"unmanaged"}
	edge := &resourcev1.MemberEdgeChange{User: "managed", Group: "same", Present: true}
	record.NativePlan.GetLocalGroup().MemberEdges = []*resourcev1.MemberEdgeChange{edge}
	before.AccountMemberEdges = []*resourcev1.MemberEdgeChange{proto.CloneOf(edge)}
	ledger := &agentv1.ResourceOwnershipLedger{Baseline: proto.CloneOf(before), OwnedDimensions: []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_GROUP_MEMBERS}}
	if err := beginAccountEdges(ledger, record, before, false); err != nil {
		t.Fatal(err)
	}
	after := proto.CloneOf(before)
	after.Observation.GetLocalGroup().Members = []string{"unmanaged", "managed"}
	ledger.BeforeEffect = before
	if err := completeAccountEdges(ledger, record, after); err != nil {
		t.Fatal(err)
	}
	ledger.LastApplied = after
	if len(ledger.GetOwnedMemberEdges()) != 1 || ledger.GetOwnedMemberEdges()[0].GetBaselinePresent() || !ledger.GetOwnedMemberEdges()[0].GetLastAppliedPresent() {
		t.Fatal("membership ownership was not captured per changed edge")
	}
	current := proto.CloneOf(after)
	current.Observation.GetLocalGroup().Members = []string{"managed", "new_external"}
	if !ownershipLedgerMatches(ledger, current) {
		t.Fatal("unrelated membership changes prevented safe additive release")
	}
	current.Observation.GetLocalGroup().Members = []string{"new_external"}
	if ownershipLedgerMatches(ledger, current) {
		t.Fatal("owned edge drift did not refuse release")
	}
	current = proto.CloneOf(after)
	current.AccountPrivate.NativeGeneration = uuid.NewString()
	if ownershipLedgerMatches(ledger, current) {
		t.Fatal("account ABA replacement inherited old edge ownership")
	}
}

func TestAccountOwnershipAgingAndPasswordDimensions(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := accountResourceRecord(t, f, resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER)
	last := ownershipSnapshot(record)
	user := last.Observation.GetLocalUser()
	user.Exists, user.Uid = true, proto.Uint32(1200)
	user.PasswordLocked = proto.Bool(true)
	user.Aging = &resourcev1.PasswordAging{MinDays: proto.Uint32(1), MaxDays: proto.Uint32(90)}
	last.AccountPrivate.PasswordToken = proto.String("!$6$protected_hash")
	current := proto.CloneOf(last)
	current.Observation.GetLocalUser().Aging.MaxDays = proto.Uint32(120)
	minDimension := []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_MIN}
	if !ownershipDimensionsMatch(last, current, minDimension) {
		t.Fatal("unmanaged aging maximum blocked minimum restoration")
	}
	current.Observation.GetLocalUser().Aging.MinDays = proto.Uint32(2)
	if ownershipDimensionsMatch(last, current, minDimension) {
		t.Fatal("managed aging drift allowed restoration")
	}
	current = proto.CloneOf(last)
	current.AccountPrivate.PasswordToken = proto.String("!$6$external_new_password")
	if ownershipDimensionsMatch(last, current, []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_PASSWORD_LOCK}) {
		t.Fatal("locked boolean concealed private password baseline replacement")
	}
}

func TestManagedFileOwnershipDimensionIsolationAndCustody(t *testing.T) {
	content := []byte("baseline")
	digest := sha256.Sum256(content)
	file := &resourcev1.ManagedFileObservation{Path: "/etc/example.conf", Exists: true, File: &resourcev1.FileIdentity{Path: "/etc/example.conf", Device: 1, Inode: 2, Mode: 0644, Sha256: digest[:]}, AncestrySha256: make([]byte, 32), NativeIdentitySha256: bytes.Repeat([]byte{1}, 32), SecurityMetadataSha256: bytes.Repeat([]byte{2}, 32)}
	last := &agentv1.ResourceOwnershipSnapshot{Observation: &resourcev1.ResourceObservation{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, CanonicalKey: file.GetPath()}, Observed: &resourcev1.ResourceObservation_ManagedFile{ManagedFile: file}}, ManagedFileContent: content, ManagedFileXattrs: []*agentv1.NativeFileXattr{{Name: "user.label", Value: []byte("preserved")}}}
	current := proto.CloneOf(last)
	current.ManagedFileContent = []byte("external-content")
	current.Observation.GetManagedFile().File.Sha256 = bytes.Repeat([]byte{9}, 32)
	current.Observation.GetManagedFile().File.Uid = 2000
	dimension := []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_MODE}
	if !ownershipDimensionsMatch(last, current, dimension) {
		t.Fatal("mode-only release would overwrite unmanaged content or uid")
	}
	current.Observation.GetManagedFile().File.Mode = 0600
	if ownershipDimensionsMatch(last, current, dimension) {
		t.Fatal("mode drift accepted for release")
	}
	for _, mutate := range []func(*agentv1.ResourceOwnershipSnapshot){
		func(s *agentv1.ResourceOwnershipSnapshot) { s.Observation.GetManagedFile().NativeIdentitySha256[0]++ },
		func(s *agentv1.ResourceOwnershipSnapshot) { s.Observation.GetManagedFile().SecurityMetadataSha256[0]++ },
		func(s *agentv1.ResourceOwnershipSnapshot) { s.ManagedFileXattrs[0].Value = []byte("external") },
	} {
		current = proto.CloneOf(last)
		mutate(current)
		if ownershipDimensionsMatch(last, current, dimension) {
			t.Fatal("native identity/security drift bypassed per-dimension release fence")
		}
	}
	current = proto.CloneOf(last)
	current.ManagedFileXattrs[0].Name = "security.capability"
	if privateOwnershipSnapshotValid(current) {
		t.Fatal("unreviewed privilege xattr admitted to restore ledger")
	}
}

func TestPreparationOwnershipReservationIsDurableAndReleased(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := pendingPackageRecord(t, f)
	if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, record); err != nil {
		t.Fatal(err)
	}
	if count, err := f.store.queries.CountResourceOwnershipReservations(t.Context()); err != nil || count != 1 {
		t.Fatalf("preparation lacked durable undo capacity: %d %v", count, err)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), f.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	next := proto.CloneOf(record)
	next.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED
	next.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_EXPIRED
	next.CompletedAt = proto.CloneOf(record.GetIntent().GetExpiresAt())
	next.PreparationOutcome = &agentv1.ResourcePreparationOutcome{Preparation: proto.CloneOf(record.GetIntent().GetPreparation()), Failure: next.GetFailure()}
	if _, err := reopened.UpdateResourceAction(t.Context(), 1, 1, 2, next); err != nil {
		t.Fatal(err)
	}
	if count, err := reopened.queries.CountResourceOwnershipReservations(t.Context()); err != nil || count != 0 {
		t.Fatalf("terminated stage leaked undo reservation: %d %v", count, err)
	}
}

func TestPreparationOwnershipCapacityAndMissingReservationFailClosed(t *testing.T) {
	t.Run("capacity", func(t *testing.T) {
		f := newServiceJournalFixture(t)
		if _, err := f.store.db.Exec("UPDATE resource_ownership_usage SET record_count = 256"); err != nil {
			t.Fatal(err)
		}
		record := pendingPackageRecord(t, f)
		if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, record); !errors.Is(err, ErrResourceOwnershipCapacity) {
			t.Fatalf("native staging admitted without undo capacity: %v", err)
		}
		if _, _, err := f.store.LoadResourceAction(t.Context(), record.GetIntent().GetActionId()); !errors.Is(err, ErrResourceActionNotFound) {
			t.Fatal("capacity refusal partially committed preparation")
		}
	})
	t.Run("missing", func(t *testing.T) {
		f := newServiceJournalFixture(t)
		if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, pendingPackageRecord(t, f)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.db.Exec("DELETE FROM resource_ownership_reservations"); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Close(); err != nil {
			t.Fatal(err)
		}
		if store, err := Open(t.Context(), f.directory); !errors.Is(err, ErrRecoveryHold) {
			if store != nil {
				_ = store.Close()
			}
			t.Fatalf("lost preparation undo reservation reopened: %v", err)
		}
	})
}

func TestAccountNewDimensionAfterOwnedNumericIdentityChange(t *testing.T) {
	f := newServiceJournalFixture(t)
	for _, kind := range []resourcev1.ResourceKind{resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP} {
		baseline := ownershipSnapshot(accountResourceRecord(t, f, kind))
		numeric := agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_UID
		added := agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_SHELL
		if kind == resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER {
			baseline.Observation.GetLocalUser().Exists = true
			baseline.Observation.GetLocalUser().Uid = proto.Uint32(1200)
			baseline.Observation.GetLocalUser().Shell = "/bin/sh"
		} else {
			baseline.Observation.GetLocalGroup().Exists = true
			baseline.Observation.GetLocalGroup().Gid = proto.Uint32(1200)
			numeric = agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_GROUP_GID
			added = agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_GROUP_MEMBERS
		}
		applied := proto.CloneOf(baseline)
		if kind == resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER {
			applied.Observation.GetLocalUser().Uid = proto.Uint32(1300)
		} else {
			applied.Observation.GetLocalGroup().Gid = proto.Uint32(1300)
		}
		ledger := &agentv1.ResourceOwnershipLedger{Baseline: baseline, LastApplied: applied, OwnedDimensions: []agentv1.ResourceOwnedDimension{numeric}}
		current := proto.CloneOf(applied)
		if !baselineOwnershipDimensionMatches(ledger, current, added) {
			t.Fatal("owned numeric transition prevented acquiring an unchanged field")
		}
		if kind == resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER {
			current.Observation.GetLocalUser().Uid = proto.Uint32(1400)
		} else {
			current.Observation.GetLocalGroup().Gid = proto.Uint32(1400)
		}
		if baselineOwnershipDimensionMatches(ledger, current, added) {
			t.Fatal("foreign numeric identity bypassed latest applied identity fence")
		}
		current = proto.CloneOf(applied)
		current.AccountPrivate.NativeGeneration = uuid.NewString()
		if baselineOwnershipDimensionMatches(ledger, current, added) {
			t.Fatal("native generation replacement bypassed baseline fence")
		}
		ledger.OwnedDimensions = nil
		if baselineOwnershipDimensionMatches(ledger, applied, added) {
			t.Fatal("unowned numeric transition inherited unrelated baseline")
		}
	}
}

func TestCreatedAccountAcquiresDimensionFromLastApplied(t *testing.T) {
	f := newServiceJournalFixture(t)
	baseline := ownershipSnapshot(accountResourceRecord(t, f, resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER))
	baseline.Observation.GetLocalUser().Exists = false
	created := proto.CloneOf(baseline)
	created.Observation.GetLocalUser().Exists = true
	created.Observation.GetLocalUser().Uid = proto.Uint32(24002)
	created.Observation.GetLocalUser().Shell = "/bin/sh"
	ledger := &agentv1.ResourceOwnershipLedger{Baseline: baseline, LastApplied: created, OwnedDimensions: []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OBJECT}}
	shell := agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_SHELL
	if !newOwnershipDimensionMatches(ledger, proto.CloneOf(created), shell) {
		t.Fatal("created account could not manage a field it set at creation")
	}
	foreign := proto.CloneOf(created)
	foreign.Observation.GetLocalUser().Shell = "/bin/zsh"
	if newOwnershipDimensionMatches(ledger, foreign, shell) {
		t.Fatal("foreign edit after creation was adopted")
	}
	ledger.OwnedDimensions = nil
	if newOwnershipDimensionMatches(ledger, proto.CloneOf(created), shell) {
		t.Fatal("unowned object used last applied instead of the absent baseline")
	}
}

func TestCreateOnlyPackageIgnoresOtherDNFVersionlockEntries(t *testing.T) {
	intent := &agentv1.ResourceExecutionIntent{Ownership: &agentv1.ResourceOwnershipBinding{Policy: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY}}}
	snapshot := func(name string) *agentv1.ResourceOwnershipSnapshot {
		return &agentv1.ResourceOwnershipSnapshot{Observation: &resourcev1.ResourceObservation{
			Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: "rpm/crash/aarch64"},
			Observed: &resourcev1.ResourceObservation_NativePackage{NativePackage: &resourcev1.NativePackageObservation{
				Package:     &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, NativeName: "crash", Architecture: "aarch64"},
				PinFile:     &resourcev1.FileIdentity{Path: "/etc/dnf/versionlock.toml"},
				PinContents: []byte("version = '1.0'\n[[packages]]\nname = '" + name + "'\n[[packages.conditions]]\nkey = 'evr'\ncomparator = '='\nvalue = '0:1.0-1'\n"),
			}},
		}}
	}
	if !ownershipAcquisitionAllowed(intent, snapshot("proof")) {
		t.Fatal("another package's shared versionlock entry blocked creation")
	}
	if ownershipAcquisitionAllowed(intent, snapshot("crash")) {
		t.Fatal("existing versionlock entry for the package was acquired without adoption")
	}
}
