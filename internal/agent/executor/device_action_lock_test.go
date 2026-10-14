// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestReleaseLockRestartNeverRestoresAgain(t *testing.T) {
	f := newDeviceActionFixture(t)
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseLock{ReleaseLock: &agentv1.ReleaseLockAction{LockActionId: uuid.NewString()}}}
	intent := f.actionIntent(t, 1, spec)
	f.actionPrepare(t, intent)
	grant := f.actionGrant(t, intent)
	record, _ := deviceActionRow(t, f.svc, intent.GetActionId())
	if _, err := f.svc.consumeDeviceAction(t.Context(), record, grant, false); err != nil {
		t.Fatal(err)
	}
	f.reopenActions(t)
	awaitDeviceAction(t, f.svc, intent.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
	actionStart(t, f.svc, intent.GetActionId(), grant)
	if f.actionNative.applies.Load() != 0 || f.actionNative.effects.Load() != 0 {
		t.Fatal("replayed possibly completed account restoration after crash")
	}
	response, err := f.svc.GetDeviceAction(t.Context(), connect.NewRequest(&agentv1.GetDeviceActionRequest{ActionId: intent.GetActionId()}))
	if err != nil || response.Msg.GetStatus().GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
		t.Fatalf("lost durable unknown outcome: %v", err)
	}
}

func TestAccountLockPartialEffectRemainsUnknown(t *testing.T) {
	f := newDeviceActionFixture(t)
	f.actionNative.failAfterEffect = true
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{Usernames: []string{"employee"}}}}
	intent := f.actionIntent(t, 1, spec)
	f.actionPrepare(t, intent)
	grant := f.actionGrant(t, intent)
	actionStart(t, f.svc, intent.GetActionId(), grant)
	awaitDeviceAction(t, f.svc, intent.GetActionId(), agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
	f.reopenActions(t)
	actionStart(t, f.svc, intent.GetActionId(), grant)
	if f.actionNative.effects.Load() != 1 {
		t.Fatal("replayed account mutation after ambiguous result")
	}
}
