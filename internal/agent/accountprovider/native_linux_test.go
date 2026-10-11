//go:build linux

package accountprovider

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestObserveRequiresFreshActualNSSReceipt(t *testing.T) {
	p := testProvider()
	d := groupDesired(nil)
	snapshot := fixtureSnapshot(true)
	snapshot.Observation.Metadata.Backend = proto.CloneOf(p.backend)
	snapshot.Observation.Metadata.BootId = p.boot
	snapshot.Observation.Metadata.ExecutorIncarnation = p.config.ExecutorIncarnation
	snapshot.AccountNssReceipt = &resourcev1.ProbeReceipt{ProbeId: uuid.NewString(), ObservedAt: timestamppb.Now(), Passed: true, EvidenceSha256: bytes.Repeat([]byte{4}, 32)}
	p.readDB = func() (*localDB, error) { return fixtureDB(), nil }
	p.config.NativeObserve = func(context.Context, *resourcev1.ResourceDesiredState) (*agentv1.ResourceOwnershipSnapshot, error) {
		return proto.CloneOf(snapshot), nil
	}
	got, receipt, _, err := p.observe(context.Background(), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got.GetAccountNssReceipt(), receipt) || !proto.Equal(receipt, snapshot.GetAccountNssReceipt()) {
		t.Fatal("NSS evidence was fabricated or replaced")
	}
	snapshot.AccountNssReceipt.Passed = false
	_, _, _, err = p.observe(context.Background(), d, nil)
	requireError(t, err)
	snapshot.AccountNssReceipt.Passed = true
	snapshot.AccountNssReceipt.ObservedAt = timestamppb.New(time.Now().Add(-time.Hour))
	_, _, _, err = p.observe(context.Background(), d, nil)
	requireError(t, err)
}
func TestObserveRefusesNumericReuseBeforeAssociatingJournalGeneration(t *testing.T) {
	p := testProvider()
	d := groupDesired(nil)
	before := fixtureSnapshot(true)
	snapshot := proto.CloneOf(before)
	snapshot.Observation.GetLocalGroup().Gid = proto.Uint32(2999)
	snapshot.Observation.Metadata.Backend = proto.CloneOf(p.backend)
	snapshot.Observation.Metadata.BootId = p.boot
	snapshot.Observation.Metadata.ExecutorIncarnation = p.config.ExecutorIncarnation
	snapshot.AccountNssReceipt = &resourcev1.ProbeReceipt{ProbeId: uuid.NewString(), ObservedAt: timestamppb.Now(), Passed: true, EvidenceSha256: bytes.Repeat([]byte{4}, 32)}
	p.readDB = func() (*localDB, error) { return fixtureDB(), nil }
	p.config.NativeObserve = func(context.Context, *resourcev1.ResourceDesiredState) (*agentv1.ResourceOwnershipSnapshot, error) {
		return snapshot, nil
	}
	_, _, _, err := p.observe(context.Background(), d, appliedLedger(before, before, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_GROUP_GID))
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("UID/GID replacement = %v", err)
	}
}
func TestNSSSupplementaryDirectoryMembershipIsNotLocal(t *testing.T) {
	p := testProvider()
	db := fixtureDB()
	user := fixtureSnapshot(false).Observation.GetLocalUser()
	p.run = func(_ context.Context, _ []byte, _ string, args ...string) ([]byte, error) {
		if args[0] == "initgroups" {
			return []byte("alice 2000 2003 9999\n"), nil
		}
		for _, row := range db.groups {
			if row[0] == args[1] || row[2] == args[1] {
				return []byte(strings.Join(row, ":") + "\n"), nil
			}
		}
		return nil, errors.New("missing")
	}
	_, err := p.verifyGroups(context.Background(), db, user)
	requireError(t, err)
}
func TestUserRemovalAndHomeChangeNeverRequestDataDeletionOrMove(t *testing.T) {
	before := fixtureSnapshot(false)
	target := proto.CloneOf(before)
	target.Observation.GetLocalUser().Exists = false
	target.Observation.GetLocalUser().Groups = nil
	r := &agentv1.NativeResourceTransactionRequest{Before: before, Target: target, Plan: &resourcev1.ResourcePlan{Ref: before.Observation.Ref}}
	commands, err := nativeCommands(r, fixtureDB())
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 1 || commands[0].tool != "/usr/sbin/userdel" || !slices.Equal(commands[0].args, []string{"--", "alice"}) {
		t.Fatal("removal included a data or recursive effect")
	}
	target = proto.CloneOf(before)
	target.Observation.GetLocalUser().Home.Path = "/home/renamed"
	r.Target = target
	commands, err = nativeCommands(r, fixtureDB())
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 1 || !slices.Equal(commands[0].args, []string{"--home", "/home/renamed", "--", "alice"}) {
		t.Fatal("home pointer update moved or changed existing data")
	}
}
func TestMemberCommandPreservesUnownedLocalEdges(t *testing.T) {
	before := fixtureSnapshot(true)
	target := proto.CloneOf(before)
	target.Observation.GetLocalGroup().Members = []string{"alice", "external"}
	r := &agentv1.NativeResourceTransactionRequest{Before: before, Target: target, Plan: &resourcev1.ResourcePlan{Ref: before.Observation.Ref}}
	commands, err := nativeCommands(r, fixtureDB())
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 1 || !slices.Equal(commands[0].args, []string{"--groups", "engineers,external", "--", "alice"}) {
		t.Fatal("group change overwrote unrelated user membership")
	}
}

// A hashed password is only ever the authenticated delivery of exactly the
// referenced secret, in the declared algorithm; anything else is refused.
func TestHashedPasswordRequiresMatchingDelivery(t *testing.T) {
	p := testProvider()
	d := userDesired()
	ref := &resourcev1.SecretRef{SecretId: uuid.NewString(), Version: 1, Purpose: resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH, SubjectBindingId: uuid.NewString()}
	d.GetLocalUser().Password = &resourcev1.PasswordState{State: &resourcev1.PasswordState_Hashed{Hashed: &resourcev1.HashedPasswordPolicy{Hash: ref, Algorithm: resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_SHA512_CRYPT}}}
	if err := p.validateDesired(d); err != nil {
		t.Fatal(err)
	}
	_, _, err := p.target(context.Background(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, fixtureSnapshot(false), fixtureDB(), nil)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("hashed password without delivery = %v", err)
	}
	for name, hash := range map[string]string{"algorithm": yescryptHash, "shape": "$6$not-a-hash"} {
		p.config.Secrets = staticHash(t, ref, hash)
		if _, _, err := p.target(context.Background(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, fixtureSnapshot(false), fixtureDB(), nil); !errors.Is(err, ErrUnsafe) {
			t.Fatalf("%s mismatch accepted: %v", name, err)
		}
	}
	other := proto.CloneOf(ref)
	other.Version = 2
	p.config.Secrets = staticHash(t, other, sha512Hash)
	if _, _, err := p.target(context.Background(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, fixtureSnapshot(false), fixtureDB(), nil); err == nil {
		t.Fatal("delivery of another secret version accepted")
	}
}
func TestHomeMetadataRejectsSymlinkWithoutTouchingData(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(home, "kept")
	if err := os.WriteFile(data, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}
	_, err := homeMetadata(link)
	requireError(t, err)
	got, err := os.ReadFile(data)
	if err != nil || string(got) != "preserve" {
		t.Fatal("read-only metadata touched user data")
	}
}
func TestReleaseIgnoresNSSReceiptAndDesiredHomeEvidence(t *testing.T) {
	baseline := fixtureSnapshot(true)
	baseline.Observation.GetLocalGroup().Exists = false
	baseline.Observation.GetLocalGroup().Gid = nil
	baseline.Observation.GetLocalGroup().Members = nil
	applied := fixtureSnapshot(true)
	applied.AccountPrivate = proto.CloneOf(baseline.AccountPrivate)
	current := proto.CloneOf(applied)
	current.AccountNssReceipt = &resourcev1.ProbeReceipt{ProbeId: uuid.NewString(), ObservedAt: timestamppb.Now(), Passed: true, EvidenceSha256: bytes.Repeat([]byte{4}, 32)}
	target, _, err := releaseTarget(current, appliedLedger(baseline, applied, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OBJECT))
	if err != nil {
		t.Fatal(err)
	}
	if target.Observation.GetLocalGroup().GetExists() {
		t.Fatal("owned object was not released")
	}
}
func TestCreatedGroupReleaseIncludesOwnedEdges(t *testing.T) {
	baseline := fixtureSnapshot(true)
	baseline.Observation.GetLocalGroup().Exists = false
	baseline.Observation.GetLocalGroup().Gid = nil
	baseline.Observation.GetLocalGroup().Members = nil
	after := proto.CloneOf(baseline)
	after.Observation.GetLocalGroup().Exists = true
	after.Observation.GetLocalGroup().Gid = proto.Uint32(2000)
	after.Observation.GetLocalGroup().Members = []string{"alice"}
	ledger := appliedLedger(baseline, after, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OBJECT)
	ledger.OwnedMemberEdges = []*agentv1.ResourceOwnedMemberEdge{{User: "alice", Group: "engineers", LastAppliedPresent: true}}
	target, edges, err := releaseTarget(after, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if target.Observation.GetLocalGroup().GetExists() || len(edges) != 1 || edges[0].GetPresent() {
		t.Fatal("owned object release did not remove its owned membership")
	}
}
func TestAbsentUserOwnsNoDimensions(t *testing.T) {
	snapshot := fixtureSnapshot(false)
	snapshot.Observation.GetLocalUser().Exists = false
	snapshot.Observation.GetLocalUser().Aging = nil
	if got := dimensions(snapshot, snapshot); len(got) != 0 {
		t.Fatal("absence acquired dimensions")
	}
}
func TestNativeAccountRootOptionSelectedBeforeEffects(t *testing.T) {
	commands := []command{{tool: "/usr/sbin/usermod", args: []string{"--uid", "2002", "--", "alice"}}, {tool: "/usr/bin/chage", args: []string{"--maxdays", "90", "--", "alice"}}}
	calls := 0
	run := func(_ context.Context, _ []byte, path string, args ...string) ([]byte, error) {
		calls++
		if !slices.Equal(args, []string{"--help"}) {
			t.Fatal("capability discovery attempted an effect")
		}
		if path == "/usr/bin/chage" {
			return []byte("  -R, --root CHROOT_DIR\\n"), nil
		}
		return []byte("  -P, --prefix PREFIX_DIR\\n"), nil
	}
	options, err := nativeToolOptions(context.Background(), run, commands)
	if err != nil {
		t.Fatal(err)
	}
	if options["/usr/bin/chage"] != "--root" || options["/usr/sbin/usermod"] != "--prefix" || calls != 2 {
		t.Fatal("native containment option selection changed")
	}
	prefixCommands(commands, "/run/lindm/test/account-root", options)
	if !slices.Equal(commands[0].args[:2], []string{"--prefix", "/run/lindm/test/account-root"}) || !slices.Equal(commands[1].args[:2], []string{"--root", "/run/lindm/test/account-root"}) {
		t.Fatal("native utility could escape account-only view")
	}
	_, err = nativeToolOptions(context.Background(), func(context.Context, []byte, string, ...string) ([]byte, error) {
		return []byte("unsupported native interface"), nil
	}, commands)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatal("missing containment interface was silently accepted")
	}
}
