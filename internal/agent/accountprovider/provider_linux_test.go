//go:build linux

package accountprovider

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/admissiondetail"
)

func TestAdditiveGroupReleasePreservesUnownedEdges(t *testing.T) {
	baseline := fixtureSnapshot(true)
	after := proto.CloneOf(baseline)
	after.Observation.GetLocalGroup().Members = []string{"alice", "external"}
	ledger := appliedLedger(baseline, after, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_GROUP_MEMBERS)
	ledger.OwnedMemberEdges = []*agentv1.ResourceOwnedMemberEdge{{User: "alice", Group: "engineers", BaselinePresent: false, LastAppliedPresent: true}}
	current := proto.CloneOf(after)
	current.Observation.GetLocalGroup().Members = append(current.Observation.GetLocalGroup().Members, "later")
	target, edges, err := releaseTarget(current, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(target.Observation.GetLocalGroup().GetMembers(), []string{"external", "later"}) || len(edges) != 1 || edges[0].GetPresent() || edges[0].GetUser() != "alice" {
		t.Fatal("release changed unowned membership")
	}
	current.Observation.GetLocalGroup().Members = []string{"external", "later"}
	_, _, err = releaseTarget(current, ledger)
	requireError(t, err)
}
func TestUserReleaseRestoresOnlyChangedAgingAndShell(t *testing.T) {
	baseline := fixtureSnapshot(false)
	after := proto.CloneOf(baseline)
	after.Observation.GetLocalUser().Shell = "/bin/bash"
	after.Observation.GetLocalUser().Aging.MinDays = proto.Uint32(2)
	ledger := appliedLedger(baseline, after, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_SHELL, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_AGING_MIN)
	current := proto.CloneOf(after)
	current.Observation.GetLocalUser().Aging.MaxDays = proto.Uint32(120)
	current.AccountPrivate.PasswordToken = proto.String("$6$changed-by-user")
	target, _, err := releaseTarget(current, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if target.Observation.GetLocalUser().GetShell() != "/bin/sh" || target.Observation.GetLocalUser().GetAging().GetMinDays() != 0 || target.Observation.GetLocalUser().GetAging().GetMaxDays() != 120 || target.AccountPrivate.GetPasswordToken() != current.AccountPrivate.GetPasswordToken() {
		t.Fatal("release overwrote an unowned field")
	}
	current.Observation.GetLocalUser().Shell = "/bin/zsh"
	_, _, err = releaseTarget(current, ledger)
	requireError(t, err)
}
func TestPasswordReleaseRequiresExactPrivateBaseline(t *testing.T) {
	baseline := fixtureSnapshot(false)
	after := proto.CloneOf(baseline)
	after.AccountPrivate.PasswordToken = proto.String("!" + baseline.AccountPrivate.GetPasswordToken())
	after.Observation.GetLocalUser().PasswordLocked = proto.Bool(true)
	ledger := appliedLedger(baseline, after, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_PASSWORD_LOCK)
	target, _, err := releaseTarget(after, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if target.AccountPrivate.GetPasswordToken() != baseline.AccountPrivate.GetPasswordToken() {
		t.Fatal("private token not restored")
	}
	after.AccountPrivate.PasswordToken = proto.String("!$6$another-password")
	_, _, err = releaseTarget(after, ledger)
	requireError(t, err)
}
func TestIdentityGenerationAndOwnedObjectDriftRefused(t *testing.T) {
	baseline := fixtureSnapshot(true)
	baseline.Observation.GetLocalGroup().Exists = false
	baseline.Observation.GetLocalGroup().Gid = nil
	baseline.Observation.GetLocalGroup().Members = nil
	after := fixtureSnapshot(true)
	after.AccountPrivate = proto.CloneOf(baseline.AccountPrivate)
	ledger := appliedLedger(baseline, after, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OBJECT)
	current := proto.CloneOf(after)
	current.AccountPrivate.NativeGeneration = uuid.NewString()
	_, _, err := releaseTarget(current, ledger)
	requireError(t, err)
	current = proto.CloneOf(after)
	current.Observation.GetLocalGroup().Members = append(current.Observation.GetLocalGroup().Members, "unowned")
	_, _, err = releaseTarget(current, ledger)
	requireError(t, err)
}
func TestExactMembershipRequiresCompleteApproval(t *testing.T) {
	p := testProvider()
	desired := groupDesired(&resourcev1.MemberSet{Mode: resourcev1.SetMode_SET_MODE_EXACT, LocalUserNames: []string{"alice"}})
	requireError(t, p.validateDesired(desired))
	p.config.Ownership.Policy.CompleteMembershipDimension = true
	if err := p.validateDesired(desired); err != nil {
		t.Fatal(err)
	}
}
func TestProtectedAccountsAndNumericCollisionsRefused(t *testing.T) {
	p := testProvider()
	for _, name := range []string{"root", "admin", "lindm-agent", "sudo", "wheel"} {
		d := groupDesired(nil)
		d.Ref.CanonicalKey = name
		d.GetLocalGroup().Name = name
		requireError(t, p.validateDesired(d))
	}
	db := fixtureDB()
	d := groupDesired(nil)
	d.GetLocalGroup().Gid = proto.Uint32(2003)
	_, _, err := p.target(context.Background(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, fixtureSnapshot(true), db, nil)
	requireError(t, err)
	u := userDesired()
	u.GetLocalUser().Uid = proto.Uint32(2002)
	_, _, err = p.target(context.Background(), u, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, fixtureSnapshot(false), db, nil)
	requireError(t, err)
	d = groupDesired(&resourcev1.MemberSet{Mode: resourcev1.SetMode_SET_MODE_ADDITIVE, LocalUserNames: []string{"root"}})
	_, _, err = p.target(context.Background(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, fixtureSnapshot(true), db, nil)
	requireError(t, err)
}
func TestAbsentDoesNotDeleteAdoptedObject(t *testing.T) {
	p := testProvider()
	before := fixtureSnapshot(false)
	d := userDesired()
	d.GetLocalUser().Presence = resourcev1.Presence_PRESENCE_ABSENT
	ledger := appliedLedger(before, before, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_SHELL)
	_, _, err := p.target(context.Background(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, fixtureDB(), ledger)
	requireError(t, err)
}
func TestCreateOnlyExistingAccountRequiresAdoption(t *testing.T) {
	p := testProvider()
	p.config.Ownership.Policy = &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED}
	before := fixtureSnapshot(false)
	if !exists(before.GetObservation()) {
		t.Fatal("fixture account absent")
	}
	_, err := p.plan(context.Background(), userDesired(), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, fixtureDB(), nil)
	if !errors.Is(err, ErrAdoptionRequired) || !errors.Is(err, ErrConflict) || admissiondetail.Of(err) != "existing_account" {
		t.Fatalf("existing account acquired under CREATE_ONLY: %v", err)
	}
}
func TestChangedDimensionsDoNotAcquireSatisfiedFields(t *testing.T) {
	before := fixtureSnapshot(false)
	after := proto.CloneOf(before)
	after.Observation.GetLocalUser().Shell = "/bin/bash"
	got := dimensions(before, after)
	want := []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_SHELL}
	if !slices.Equal(got, want) {
		t.Fatalf("owned dimensions = %v", got)
	}
	if got := dimensions(before, before); len(got) != 0 {
		t.Fatal("already satisfied state acquired ownership")
	}
}
func TestNewUsersLockedWithoutHomeCopy(t *testing.T) {
	p := testProvider()
	before := fixtureSnapshot(false)
	u := before.Observation.GetLocalUser()
	u.Exists = false
	u.Uid = nil
	u.Gid = nil
	u.Groups = nil
	u.Home = nil
	u.PasswordLocked = nil
	u.Aging = nil
	u.UidGeneration = nil
	before.AccountPrivate.PasswordToken = nil
	db := fixtureDB()
	delete(db.users, "alice")
	d := userDesired()
	user := d.GetLocalUser()
	user.Uid = proto.Uint32(2010)
	user.PrimaryGroup = proto.String("engineers")
	user.HomeDirectory = proto.String(filepath.Join(t.TempDir(), "preserved"))
	user.Shell = &resourcev1.LoginShell{InstalledShell: "/bin/sh"}
	before.AccountPrivate.DesiredHome = &resourcev1.HomeMetadata{Path: user.GetHomeDirectory()}
	target, _, err := p.target(context.Background(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !target.Observation.GetLocalUser().GetPasswordLocked() || target.AccountPrivate.GetPasswordToken() != "!" || target.Observation.GetLocalUser().GetHome().GetExists() {
		t.Fatal("creation did not preserve data and default locked")
	}
	request := &agentv1.NativeResourceTransactionRequest{Before: before, Target: target, Plan: &resourcev1.ResourcePlan{Ref: d.Ref, Plan: &resourcev1.ResourcePlan_LocalUser{LocalUser: &resourcev1.LocalUserPlan{Desired: user}}}}
	commands, err := nativeCommands(request, db)
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) == 0 || commands[0].tool != "/usr/sbin/useradd" {
		t.Fatal("missing typed creation")
	}
	for _, command := range commands {
		for _, arg := range command.args {
			if arg == "-m" || arg == "--create-home" || arg == "--move-home" || arg == "--remove" || arg == "-r" {
				t.Fatal("recursive data effect requested")
			}
		}
	}
}
func TestNSSMismatchAndDirectoryObjectsRefused(t *testing.T) {
	local := strings.Split("alice:x:2001:2000::/home/alice:/bin/sh", ":")
	p := testProvider()
	p.run = func(context.Context, []byte, string, ...string) ([]byte, error) {
		return []byte("alice:x:9999:2000::/home/alice:/bin/sh\n"), nil
	}
	_, err := p.nss(context.Background(), "passwd", "alice", local)
	requireError(t, err)
	_, err = p.nss(context.Background(), "passwd", "alice", nil)
	requireError(t, err)
	calls := 0
	p.run = func(context.Context, []byte, string, ...string) ([]byte, error) {
		calls++
		if calls == 1 {
			return []byte(strings.Join(local, ":") + "\n"), nil
		}
		return []byte("other:x:2001:2000::/home/other:/bin/sh\n"), nil
	}
	_, err = p.nss(context.Background(), "passwd", "alice", local)
	requireError(t, err)
}
func TestNativeSignedGateAndUnknownNeverRetry(t *testing.T) {
	commands := []command{{tool: "/usr/sbin/groupadd", args: []string{"--gid", "2100", "--", "engineers"}}, {tool: "/usr/sbin/groupmod", args: []string{"--gid", "2101", "--", "engineers"}}}
	for _, test := range []struct {
		name                 string
		stale, deny, fail    bool
		wantCalls, wantGates int
	}{{"stale", true, false, false, 0, 0}, {"denied", false, true, false, 0, 1}, {"interrupted", false, false, true, 1, 1}, {"allowed", false, false, false, 2, 1}} {
		t.Run(test.name, func(t *testing.T) {
			calls, gates := 0, 0
			revision := bytes.Repeat([]byte{1}, 32)
			readDB := func() (*localDB, error) {
				got := bytes.Clone(revision)
				if test.stale {
					got[0] = 2
				}
				return &localDB{revision: got}, nil
			}
			gate := func(context.Context) error {
				gates++
				if test.deny {
					return errors.New("signed authority denied")
				}
				return nil
			}
			run := func(context.Context, []byte, string, ...string) ([]byte, error) {
				if gates != 1 {
					t.Fatal("native effect before signed authority")
				}
				calls++
				if test.fail {
					return nil, errors.New("native interruption")
				}
				return nil, nil
			}
			err := runCommands(context.Background(), commands, revision, gate, run, readDB)
			if calls != test.wantCalls || gates != test.wantGates {
				t.Fatalf("calls=%d gates=%d", calls, gates)
			}
			if test.fail && !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatal("interruption lost UNKNOWN")
			}
			if !test.stale && !test.deny && !test.fail && err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestDatabaseParserRejectsAmbiguousLocalRecords(t *testing.T) {
	for _, data := range []string{"alice:x:2001:2000::/home/alice:/bin/sh\nalice:x:2002:2000::/home/alice:/bin/sh\n", "+::::::\n", "alice:x:2001\n"} {
		_, err := parseRecords([]byte(data), 7)
		requireError(t, err)
	}
}
func TestAgingAccountLockRestoresExpiryDimension(t *testing.T) {
	before := fixtureSnapshot(false)
	after := proto.CloneOf(before)
	mergeAging(after.Observation.GetLocalUser().Aging, &resourcev1.PasswordAging{AccountLocked: proto.Bool(true)})
	dims := dimensions(before, after)
	if !slices.Equal(dims, []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_ACCOUNT_LOCK}) {
		t.Fatalf("dimensions %v", dims)
	}
	ledger := appliedLedger(before, after, dims...)
	restored, _, err := releaseTarget(after, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(restored.Observation.GetLocalUser().GetAging(), before.Observation.GetLocalUser().GetAging()) {
		t.Fatal("account unlock did not restore exact expiry")
	}
}
func TestActiveUserUIDChangeRefusedBeforeNativeEffect(t *testing.T) {
	p := testProvider()
	before := fixtureSnapshot(false)
	before.Observation.GetLocalUser().HasProcesses = true
	d := userDesired()
	d.GetLocalUser().Uid = proto.Uint32(2999)
	_, _, err := p.target(context.Background(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, fixtureDB(), nil)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("active UID change = %v", err)
	}
}
