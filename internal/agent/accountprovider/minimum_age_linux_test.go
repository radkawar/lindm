//go:build linux

package accountprovider

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// shadow 4.20 (Tumbleweed 4.20.3, Arch 4.20.0; platform Quirks.NoPasswordMinAge)
// removed chage --mindays, and its useradd, chage, chpasswd and usermod
// --lock/--unlock/--password leave sp_min empty in every entry they write. The
// provider never asks for a minimum there and expects it absent after any
// rewrite.
func TestShadowWithoutMinimumAgeNeverSetsIt(t *testing.T) {
	p := testProvider()
	p.minimumAgeRemoved = true
	noMinimum := func(commands []command) {
		t.Helper()
		for _, command := range commands {
			if slices.Contains(command.args, "--mindays") {
				t.Fatalf("%s %v asks the native shadow for a minimum age", command.tool, command.args)
			}
		}
	}

	// Creation: useradd leaves sp_min empty and chage sets only the rest.
	absent := fixtureSnapshot(false)
	u := absent.Observation.GetLocalUser()
	u.Exists, u.Uid, u.Gid, u.Groups, u.Home, u.PasswordLocked, u.Aging, u.UidGeneration = false, nil, nil, nil, nil, nil, nil, nil
	absent.AccountPrivate.PasswordToken = nil
	db := fixtureDB()
	delete(db.users, "alice")
	d := userDesired()
	user := d.GetLocalUser()
	user.Uid = proto.Uint32(2010)
	user.PrimaryGroup = proto.String("engineers")
	user.HomeDirectory = proto.String(filepath.Join(t.TempDir(), "home"))
	user.Shell = &resourcev1.LoginShell{InstalledShell: "/bin/sh"}
	absent.AccountPrivate.DesiredHome = &resourcev1.HomeMetadata{Path: user.GetHomeDirectory()}
	created, _, err := p.target(t.Context(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, absent, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if created.Observation.GetLocalUser().GetAging().MinDays != nil || created.Observation.GetLocalUser().GetAging().GetMaxDays() != 99999 {
		t.Fatalf("creation expects aging %v", created.Observation.GetLocalUser().GetAging())
	}
	commands, err := nativeCommands(&agentv1.NativeResourceTransactionRequest{Before: absent, Target: created, Plan: &resourcev1.ResourcePlan{Ref: d.Ref, Plan: &resourcev1.ResourcePlan_LocalUser{LocalUser: &resourcev1.LocalUserPlan{Desired: user}}}}, db, false)
	if err != nil {
		t.Fatal(err)
	}
	noMinimum(commands)
	if len(commands) != 2 || commands[1].tool != "/usr/bin/chage" {
		t.Fatalf("creation commands %v", commands)
	}

	// An existing entry keeps its legacy minimum until a rewrite clears it.
	existing := fixtureSnapshot(false)
	for _, tc := range []struct {
		name      string
		desired   func(*resourcev1.LocalUserDesired)
		keepsMin  bool
		wantChage []string
	}{
		{"maximum-age-chage", func(u *resourcev1.LocalUserDesired) { u.Aging = &resourcev1.PasswordAging{MaxDays: proto.Uint32(90)} }, false, []string{"--maxdays", "90", "--", "alice"}},
		{"password-lock", func(u *resourcev1.LocalUserDesired) {
			u.Password = &resourcev1.PasswordState{State: &resourcev1.PasswordState_Locked{Locked: &resourcev1.LockedPassword{}}}
		}, false, nil},
		{"shell-only", func(u *resourcev1.LocalUserDesired) { u.Shell = &resourcev1.LoginShell{InstalledShell: "/bin/bash"} }, true, nil},
	} {
		d := userDesired()
		tc.desired(d.GetLocalUser())
		target, _, err := p.target(t.Context(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, existing, fixtureDB(), nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := target.Observation.GetLocalUser().GetAging().MinDays; (got != nil) != tc.keepsMin || tc.keepsMin && *got != 0 {
			t.Fatalf("%s: expected minimum %v", tc.name, got)
		}
		commands, err := nativeCommands(&agentv1.NativeResourceTransactionRequest{Before: existing, Target: target, Plan: &resourcev1.ResourcePlan{Ref: d.Ref, Plan: &resourcev1.ResourcePlan_LocalUser{LocalUser: &resourcev1.LocalUserPlan{Desired: d.GetLocalUser()}}}}, fixtureDB(), false)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		noMinimum(commands)
		chage := slices.IndexFunc(commands, func(c command) bool { return c.tool == "/usr/bin/chage" })
		if (chage >= 0) != (tc.wantChage != nil) || chage >= 0 && !slices.Equal(commands[chage].args, tc.wantChage) {
			t.Fatalf("%s: commands %v", tc.name, commands)
		}
	}

	d = userDesired()
	d.GetLocalUser().Aging = &resourcev1.PasswordAging{MinDays: proto.Uint32(1)}
	if _, _, err := p.target(t.Context(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, existing, fixtureDB(), nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("desired minimum age on a shadow without one: %v", err)
	}
}
