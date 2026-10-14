// SPDX-License-Identifier: Apache-2.0

package dispatch

import (
	"bytes"
	"testing"

	"lindm/internal/device/core"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

func TestLockActionPermissionAndDigest(t *testing.T) {
	lock := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{}}}
	baseline, err := core.ActionDigest(lock)
	if err != nil {
		t.Fatal(err)
	}
	for _, selection := range []*agentv1.LockSessionsAction{
		{TerminateSessions: true},
		{Usernames: []string{"alice"}},
		{AllHumanAccounts: true},
	} {
		spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: selection}}
		if DeviceActionPermission(spec) != identity.PermissionLockDevice || DestructiveDeviceAction(spec) {
			t.Fatal("expanded lock bypassed the privileged configurable lock policy")
		}
		digest, err := core.ActionDigest(spec)
		if err != nil || bytes.Equal(baseline, digest) {
			t.Fatalf("lock options absent from immutable digest: %v", err)
		}
	}
	release := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseLock{ReleaseLock: &agentv1.ReleaseLockAction{LockActionId: uuid.NewString()}}}
	if DeviceActionPermission(release) != identity.PermissionReleaseLockDevice || DestructiveDeviceAction(release) {
		t.Fatal("release acquired lock or destructive permission instead of its own grant")
	}
	first, err := core.ActionDigest(release)
	if err != nil {
		t.Fatal(err)
	}
	release.GetReleaseLock().LockActionId = uuid.NewString()
	second, err := core.ActionDigest(release)
	if err != nil || bytes.Equal(first, second) {
		t.Fatalf("release reference absent from immutable digest: %v", err)
	}
}

func TestLockActionSelectionValidation(t *testing.T) {
	rules, err := protovalidate.New(protovalidate.WithMessages(&agentv1.DeviceActionSpec{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, selection := range []*agentv1.LockSessionsAction{
		{}, {TerminateSessions: true}, {Usernames: []string{"alice"}}, {AllHumanAccounts: true},
	} {
		if err := rules.Validate(selection); err != nil {
			t.Fatalf("valid selection rejected: %v", err)
		}
	}
	for _, selection := range []*agentv1.LockSessionsAction{
		{AllHumanAccounts: true, Usernames: []string{"alice"}},
		{Usernames: []string{"alice", "alice"}},
		{Usernames: []string{"--root"}},
	} {
		if err := rules.Validate(selection); err == nil {
			t.Fatal("ambiguous or unsafe account selection accepted")
		}
	}
	for _, id := range []string{"", uuid.Nil.String(), "not-an-action"} {
		if err := rules.Validate(&agentv1.ReleaseLockAction{LockActionId: id}); err == nil {
			t.Fatal("invalid original lock identity accepted")
		}
	}
}

func TestReleaseLockUnknownExceptionIsExact(t *testing.T) {
	original, generation := uuid.New(), uuid.New()
	release := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseLock{ReleaseLock: &agentv1.ReleaseLockAction{LockActionId: original.String()}}}
	for _, tc := range []struct {
		name       string
		spec       *agentv1.DeviceActionSpec
		state      agentv1.DeviceActionState
		generation uuid.UUID
		want       bool
	}{
		{"original lock", &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{}}}, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN, generation, true},
		{"matching inverse", release, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN, generation, true},
		{"different inverse", &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseLock{ReleaseLock: &agentv1.ReleaseLockAction{LockActionId: uuid.NewString()}}}, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN, generation, false},
		{"unrelated action", &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Quarantine{Quarantine: &agentv1.QuarantineAction{}}}, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN, generation, false},
		{"running inverse", release, agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING, generation, false},
		{"queued inverse", release, agentv1.DeviceActionState_DEVICE_ACTION_STATE_QUEUED, generation, false},
		{"older generation", release, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN, uuid.New(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			intent, err := proto.Marshal(&agentv1.DeviceActionIntent{Spec: tc.spec})
			if err != nil {
				t.Fatal(err)
			}
			status, err := proto.Marshal(&agentv1.DeviceActionStatus{State: tc.state})
			if err != nil {
				t.Fatal(err)
			}
			open := devicedb.DeviceAction{ID: original, GenerationID: tc.generation, OutcomeUnknown: true, StartGrantEnvelope: []byte("persisted-grant"), IntentDocument: intent, StatusDocument: status}
			got, err := releaseSupersedesUnknownLock(open, generation, release)
			if err != nil || got != tc.want {
				t.Fatalf("explicit inverse admitted=%v; want %v: %v", got, tc.want, err)
			}
			open.StatusDocument = nil
			if got, err := releaseSupersedesUnknownLock(open, generation, release); err != nil || got {
				t.Fatalf("grant-only unknown admitted inverse: %v", err)
			}
		})
	}
}
